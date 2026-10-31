"""Read-only access to the crt.sh ``certwatch`` PostgreSQL database.

crt.sh exposes its database to anyone as a read-only replica::

    psql -h crt.sh -p 5432 -U guest certwatch

Every SQL statement the service runs lives in this module. The queries only
depend on these parts of the certwatch schema (https://github.com/crtsh/certwatch_db):

- ``certificate (id, issuer_ca_id, certificate)`` - every cert and precert, as DER.
  Range partitioned by year on notAfter, see ``NOTAFTER_KEY``.
- ``ca (id, name)`` - every issuing CA (a name + key pair).
- ``ca_certificate (certificate_id, ca_id)`` - which certificates belong to a CA (one CA each).
- ``ct_log (id, name, url, operator)`` and ``ct_log_entry (certificate_id, ct_log_id,
  entry_id, entry_timestamp)`` - where and when each cert was logged.
- ``crl_revoked (ca_id, serial_number, reason_code, revocation_date)`` - CRL revocations.
- ``certificate_and_identities`` - a view of each certificate's identities (name type, value).
- The indexed functions crt.sh's own web UI searches with: ``digest()`` (pgcrypto),
  ``identities()`` (full text search), and ``x509_serialNumber``,
  ``x509_subjectKeyIdentifier``, ``x509_publicKey``, ``x509_name``, ``x509_notBefore``,
  and ``x509_notAfter`` (libx509pq).

Everything else about a certificate is parsed from its DER by ``crtshsvc.norm``.

crt.sh is slow per round trip (often 20s+ for a trivial query, PgBouncer queues
clients), much more than per row. So each operation is one query: every query that
returns certificates is wrapped by ``_withMeta``, which adds the crt.sh metadata
(issuer CA name, CA membership, CT log entries, CRL revocation) with correlated
subqueries, like crt.sh's own ``certificate_lifecycle`` view. Lookups a query
depends on (an issuer's name, a pivot's source certificate) are subqueries too.

``CrtshDb`` is the only class that talks to PostgreSQL, over a single queued
connection (crt.sh allows one per client, see its docstring). Tests swap it for a
fake with the same methods.
"""


import asyncio
import logging
import random
import re
from typing import Any

import asyncpg


logger = logging.getLogger(__name__)


DEFAULT_DSN = "postgresql://guest@crt.sh:5432/certwatch"
"""crt.sh's public, read-only, password-less database."""

NAME_TYPES = {
    "dns": ["san:dNSName", "2.5.4.3"],
    "cn": ["2.5.4.3"],
    "org": ["2.5.4.10"],
    "ou": ["2.5.4.11"],
    "email": ["san:rfc822Name", "1.2.840.113549.1.9.1"],
    "ip": ["san:iPAddress"],
    "uri": ["san:uniformResourceIdentifier"],
}
"""The certificate_and_identities NAME_TYPEs (as crt.sh's web_apis uses them) of each search field."""

NOTAFTER_KEY = "coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp)"
"""The expression ``certificate`` is range partitioned (by year) on."""

LOOKUPS = {
    "id": "{c}.ID = ANY({p}::bigint[])",
    "sha256": "digest({c}.CERTIFICATE, 'sha256') = ANY({p}::bytea[])",
    "sha1": "digest({c}.CERTIFICATE, 'sha1') = ANY({p}::bytea[])",
    "serial": "x509_serialNumber({c}.CERTIFICATE) = ANY({p}::bytea[])",
    "ski": "x509_subjectKeyIdentifier({c}.CERTIFICATE) = ANY({p}::bytea[])",
    "spki": "digest(x509_publicKey({c}.CERTIFICATE), 'sha256') = ANY({p}::bytea[])",
    "spkisha1": "digest(x509_publicKey({c}.CERTIFICATE), 'sha1') = ANY({p}::bytea[])",
    "subjectsha1": "digest(x509_name({c}.CERTIFICATE), 'sha1') = ANY({p}::bytea[])",
}
"""Certificate lookup kinds, mapped to the (indexed) condition that finds them in table ``{c}``."""

RELATED = {
    "key": "digest(x509_publicKey({c}.CERTIFICATE), 'sha256')",
    "subject": "digest(x509_name({c}.CERTIFICATE), 'sha1')",
    "serial": "x509_serialNumber({c}.CERTIFICATE)",
    "ski": "x509_subjectKeyIdentifier({c}.CERTIFICATE)",
    "siblings": "{c}.ISSUER_CA_ID",
}
"""Pivots, mapped to the indexed expression related certificates share."""

META = """SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der{extra},
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID"""
"""The crt.sh metadata of the certificates in ``m``, see ``_withMeta``."""

# Errors that mean the connection is gone (crt.sh's PgBouncer drops idle clients with
# "client_idle_timeout"), the query is retried on a new connection.
CONN_ERRORS = (
    asyncpg.exceptions.ConnectionDoesNotExistError,
    asyncpg.exceptions.InterfaceError,
    ConnectionError,
    OSError,
)

# Messages from crt.sh's PgBouncer (or Postgres) that mean "reconnect", or "back off, then reconnect".
RECONNECT_MESGS = ("client_idle_timeout", "server conn crashed", "server_login_retry",
                   "query_wait_timeout", "terminating connection")
BACKOFF_MESGS = ("max_client_conn", "too many connections", "the database system is starting up",
                 "the database system is in recovery mode", "cannot connect now")


class CrtshDbError(Exception):
    """A query to the crt.sh database failed."""

    def __init__(self, mesg: str):
        super().__init__(mesg)
        self.mesg = mesg


def _mesgIn(err: BaseException, mesgs: tuple[str, ...]) -> bool:
    text = str(err).lower()
    return any(mesg in text for mesg in mesgs)


class Params:
    """Collects a query's positional arguments, handing out their ``$n`` placeholders."""

    def __init__(self):
        self.args: list[Any] = []

    def add(self, valu: Any) -> str:
        self.args.append(valu)
        return f"${len(self.args)}"


def _lookup(params: Params, lookups: dict[str, list]) -> str:
    """The condition matching any of ``lookups`` ({kind: [values]}), on the table alias ``{c}``."""

    conds = []
    for kind, valus in lookups.items():
        if kind not in LOOKUPS:
            raise CrtshDbError(f"Unknown lookup type {kind}, expected one of: {', '.join(LOOKUPS)}")
        conds.append(LOOKUPS[kind].replace("{p}", params.add(list(valus))))
    return "(" + " OR ".join(conds) + ")"


def _alias(cond: str, alias: str = "c") -> str:
    return cond.replace("{c}", alias)


def _filters(params: Params, valid: bool = False, since: int | None = None,
             until: int | None = None) -> list[str]:
    """The validity conditions shared by searches, on ``certificate c``.

    ``since``/``until`` are epoch millis bounds on notBefore.

    ``certificate`` is partitioned by year on ``NOTAFTER_KEY``, so every bound that
    implies a minimum notAfter is also applied to that expression, which lets
    PostgreSQL skip whole partitions (crt.sh's own expiry filter does the same).
    """

    clauses = []
    if valid:
        clauses.append(f"{NOTAFTER_KEY} >= date_trunc('year', now() AT TIME ZONE 'UTC')")
        clauses.append("x509_notAfter(c.CERTIFICATE) >= now() AT TIME ZONE 'UTC'")
    if since is not None:
        param = params.add(since / 1000)
        clauses.append(f"x509_notBefore(c.CERTIFICATE) >= to_timestamp({param}) AT TIME ZONE 'UTC'")
        # A certificate can't expire before it was issued.
        clauses.append(f"{NOTAFTER_KEY} >= to_timestamp({param}) AT TIME ZONE 'UTC'")
    if until is not None:
        param = params.add(until / 1000)
        clauses.append(f"x509_notBefore(c.CERTIFICATE) < to_timestamp({param}) AT TIME ZONE 'UTC'")
    return clauses


def _withMeta(inner: str, extra: tuple[str, ...] = (), ctes: str = "") -> str:
    """Wrap a query of certificates (``ID``, ``ISSUER_CA_ID``, ``CERTIFICATE``, and any ``extra``
    columns) to return them with their crt.sh metadata, in one round trip.

    The certificates are materialized first, so the metadata is only looked up for the
    rows the query returns (after its LIMIT). ``ctes`` are more CTEs ``inner`` uses.
    """

    cols = "".join(f", m.{col} AS {col.lower()}" for col in extra)
    prefix = f"{ctes}, " if ctes else ""
    return f"WITH {prefix}m AS MATERIALIZED ({inner})\n{META.format(extra=cols)}"


def _issuerName(params: Params, name: str) -> str:
    """The IDs of the CAs whose name contains ``name``."""
    return f"SELECT ca.ID FROM ca WHERE ca.NAME ILIKE {params.add('%' + likeEscape(name) + '%')} LIMIT 1000"


def tsquery(text: str) -> str:
    """Clean up text for ``plainto_tsquery('certwatch', ...)``.

    Wildcards and LIKE patterns aren't meaningful to full text search, so a
    leading ``*.``/``%.`` and any other ``%``/``*`` are removed.
    """

    text = re.sub(r"^[*%]+\.?", "", text.strip())
    return text.replace("%", " ").replace("*", " ").strip()


def likeEscape(text: str) -> str:
    """Escape text so it's matched literally in a LIKE/ILIKE pattern."""

    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class CrtshDb:
    """A single, queued connection to the crt.sh database.

    crt.sh's database sits behind PgBouncer, which only allows one connection per
    client and drops idle clients quickly (``client_idle_timeout``). So:

    - Every query runs on one connection, queued behind an ``asyncio.Lock`` (FIFO).
    - The connection is opened on first use (the service starts even when crt.sh is
      unreachable) and kept alive with ``SELECT 1`` every ``keepalive`` seconds while
      it's in use. After ``idle`` seconds without a query it's closed, freeing the
      single slot (ex. for psql from the same IP).
    - A dropped connection is reopened and the query retried. Reconnecting right after
      a drop is often refused (``max_client_conn``) until crt.sh notices the old one
      is gone, so connecting backs off (with jitter) for up to ``connect_timeout`` seconds.
    - Queries have no timeout unless ``timeout`` is set, crt.sh can be very slow.

    Every query method returns rows as plain dicts.
    """

    def __init__(self, dsn: str = DEFAULT_DSN, timeout: float | None = None, retries: int = 3,
                 keepalive: float = 10, idle: float = 300, connect_timeout: float = 300,
                 backoff: float = 1.0, statement_timeout: float = 0, connect=None):
        self.dsn = dsn
        self.timeout = timeout or None
        self.statement_timeout = statement_timeout
        self.retries = retries
        self.keepalive = keepalive
        self.idle = idle
        self.connect_timeout = connect_timeout
        self.backoff = backoff
        self._connectFn = connect or asyncpg.connect

        self._conn: asyncpg.Connection | None = None
        self._lock = asyncio.Lock()
        self._lastUsed = 0.0
        self._keeper: asyncio.Task | None = None

    # ---- Connection management ----

    async def _connectOnce(self) -> asyncpg.Connection:
        # PgBouncer may pool by transaction, so no prepared statements are cached, and
        # the read-only replica means statements run outside explicit transactions.
        conn = await self._connectFn(self.dsn, statement_cache_size=0, timeout=30)

        # crt.sh's default statement_timeout cancels big queries (chains, wide searches) that
        # finish fine given time, so the session's is set (0 is no limit). It's a SET, not a
        # startup parameter, since PgBouncer rejects startup parameters it doesn't know.
        try:
            await conn.execute(f"SET statement_timeout = {int(self.statement_timeout * 1000)}")
        except asyncpg.PostgresError as err:
            logger.warning("Unable to set the crt.sh statement_timeout, using the server's: %s", err)
        return conn

    async def _connect(self) -> asyncpg.Connection:
        """Open the connection, backing off while crt.sh refuses it."""

        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.connect_timeout
        delay = self.backoff
        while True:
            try:
                conn = await self._connectOnce()
                logger.debug("Connected to the crt.sh database.")
                return conn
            except Exception as err:
                transient = (_mesgIn(err, BACKOFF_MESGS + RECONNECT_MESGS)
                             or isinstance(err, (*CONN_ERRORS, asyncio.TimeoutError,
                                                 asyncpg.exceptions.CannotConnectNowError,
                                                 asyncpg.exceptions.TooManyConnectionsError)))
                if not transient or loop.time() + delay > deadline:
                    raise CrtshDbError(f"Unable to connect to the crt.sh database: {err}") from err
                logger.info("crt.sh refused the connection (%s), retrying in %.1fs.", err, delay)
                await asyncio.sleep(delay + random.uniform(0, delay))
                delay = min(delay * 2, 30 * self.backoff)

    async def _ensure(self) -> asyncpg.Connection:
        """The open connection, (re)connecting if needed. Must hold the lock."""

        if self._conn is None or self._conn.is_closed():
            self._conn = await self._connect()
            if self._keeper is None or self._keeper.done():
                self._keeper = asyncio.get_running_loop().create_task(self._keepalive())
        return self._conn

    async def _drop(self) -> None:
        """Close the connection without raising. Must hold the lock."""

        conn, self._conn = self._conn, None
        if conn is not None and not conn.is_closed():
            try:
                await asyncio.wait_for(conn.close(), timeout=5)
            except Exception:
                conn.terminate()

    async def _keepalive(self) -> None:
        """Ping the connection so PgBouncer doesn't drop it, until it's been idle too long."""

        loop = asyncio.get_running_loop()
        while True:  # Until the connection is dropped, or close() cancels this.
            await asyncio.sleep(self.keepalive)
            if self._lock.locked():
                continue  # A query is running, the connection isn't idle.
            async with self._lock:
                if self._conn is None or self._conn.is_closed():
                    return
                if loop.time() - self._lastUsed >= self.idle:
                    logger.debug("Closing the idle crt.sh connection.")
                    await self._drop()
                    return
                try:
                    await self._conn.fetchval("SELECT 1", timeout=30)
                except Exception as err:
                    # Reconnect lazily on the next query.
                    logger.debug("crt.sh keepalive failed, dropping the connection: %s", err)
                    await self._drop()
                    return

    async def close(self) -> None:
        """Close the connection and stop the keepalive."""

        if self._keeper is not None:
            self._keeper.cancel()
            self._keeper = None
        async with self._lock:
            await self._drop()

    async def fetch(self, sql: str, *args) -> list[dict]:
        """Queue a query, run it (reconnecting and retrying when the connection drops), and
        return its rows as dicts."""

        loop = asyncio.get_running_loop()
        async with self._lock:
            for attempt in range(self.retries + 1):
                conn = await self._ensure()
                self._lastUsed = loop.time()
                try:
                    rows = await conn.fetch(sql, *args, timeout=self.timeout)
                    return [dict(row) for row in rows]
                except asyncpg.exceptions.QueryCanceledError as err:
                    raise CrtshDbError(
                        f"crt.sh canceled the query (statement timeout), try a narrower search: {err}"
                    ) from err
                except asyncio.TimeoutError as err:
                    # The connection is mid-query, it can't be reused.
                    await self._drop()
                    raise CrtshDbError(f"crt.sh query timed out after {self.timeout}s.") from err
                except asyncpg.exceptions.SerializationError as err:
                    # The replica canceled the query to apply replication, just retry it.
                    retry = err
                except Exception as err:
                    if not (isinstance(err, CONN_ERRORS) or _mesgIn(err, RECONNECT_MESGS + BACKOFF_MESGS)):
                        if isinstance(err, asyncpg.PostgresError):
                            raise CrtshDbError(f"crt.sh query failed: {err}") from err
                        raise
                    retry = err
                    await self._drop()
                finally:
                    self._lastUsed = loop.time()

                if attempt >= self.retries:
                    raise CrtshDbError(f"crt.sh query failed: {retry}") from retry
                logger.warning("crt.sh query failed (attempt %d), retrying: %s", attempt + 1, retry)
        raise CrtshDbError("crt.sh query failed.")  # pragma: no cover

    # ---- Certificates, each returned with its metadata (see _withMeta) ----

    async def certs(self, lookups: dict[str, list], limit: int = 100) -> list[dict]:
        """Certificates matching any of ``lookups`` ({kind: [values]}, see ``LOOKUPS``)."""

        params = Params()
        cond = _alias(_lookup(params, lookups))
        inner = (f"SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE {cond} "
                 f"LIMIT {params.add(limit)}")
        return await self.fetch(_withMeta(inner), *params.args)

    async def certsByIdentity(self, text: str, like: str | None = None,
                              nametypes: list[str] | None = None, caids: list[int] | None = None,
                              issuer: str | None = None, valid: bool = False,
                              since: int | None = None, until: int | None = None,
                              limit: int = 1000) -> list[dict]:
        """Search certificate identities (subject attributes and SANs) like crt.sh does.

        ``text`` is full text searched with the indexed ``identities()``. With ``like``
        (an ILIKE pattern) and/or ``nametypes`` (see ``NAME_TYPES``), each candidate's
        individual identities are also matched in the ``certificate_and_identities``
        view before the limit is applied, exactly like crt.sh's own search, so the
        limit counts real matches. ``caids`` and ``issuer`` (a CA name) narrow the
        issuer. Like crt.sh, the results are an arbitrary subset (not the newest)
        when there are more than ``limit``.
        """

        params = Params()
        clauses = [f"plainto_tsquery('certwatch', {params.add(tsquery(text))}) @@ identities(c.CERTIFICATE)"]
        if like is not None:
            clauses.append(f"c.NAME_VALUE ILIKE {params.add(like)}")
        if nametypes:
            clauses.append(f"c.NAME_TYPE = ANY({params.add(list(nametypes))}::text[])")
        if caids:
            clauses.append(f"c.ISSUER_CA_ID = ANY({params.add(list(caids))}::int[])")
        if issuer:
            clauses.append(f"c.ISSUER_CA_ID IN ({_issuerName(params, issuer)})")
        clauses.extend(_filters(params, valid, since, until))
        where = " AND ".join(clauses)
        limit = params.add(limit)

        if like is None and not nametypes:
            # Only the full text search, no need to parse every candidate's identities.
            inner = f"SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE {where} LIMIT {limit}"
        else:
            # A certificate has a row per matching identity, group them back into one.
            inner = ("SELECT sub.CERTIFICATE_ID AS ID, sub.ISSUER_CA_ID, sub.CERTIFICATE FROM ("
                     "SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE "
                     f"FROM certificate_and_identities c WHERE {where} LIMIT {limit}"
                     ") sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE")
        return await self.fetch(_withMeta(inner), *params.args)

    async def certsByIssuer(self, caids: list[int] | None = None, issuer: str | None = None,
                            cert: dict[str, list] | None = None, valid: bool = False,
                            since: int | None = None, until: int | None = None,
                            limit: int = 1000) -> list[dict]:
        """The newest ``limit`` certificates issued by each CA.

        The CAs are crt.sh ``caids``, the CAs named like ``issuer``, and/or the CA that
        the certificate ``cert`` ({kind: [values]}) belongs to.

        Each CA is joined LATERAL with ``ISSUER_CA_ID = <the CA>``: crt.sh runs PostgreSQL
        12, which can only walk the ``(ISSUER_CA_ID, x509_notBefore)`` index newest first
        for a single CA. With ``= ANY(...)`` it reads and sorts every certificate the CAs
        ever issued, which times out for big CAs.
        """

        params = Params()
        sources = []
        if caids:
            sources.append(f"SELECT unnest({params.add(list(caids))}::int[]) AS CA_ID")
        if issuer:
            sources.append(f"SELECT ID AS CA_ID FROM ({_issuerName(params, issuer)}) named")
        if cert:
            cond = _alias(_lookup(params, cert), "s")
            sources.append("SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = "
                           f"(SELECT s.ID FROM certificate s WHERE {cond} LIMIT 1)")
        if not sources:
            raise CrtshDbError("A CA ID, CA name, or CA certificate is required.")

        clauses = ["c.ISSUER_CA_ID = cas.CA_ID", *_filters(params, valid, since, until)]
        inner = (f"SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM ({' UNION '.join(sources)}) cas "
                 "CROSS JOIN LATERAL (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c "
                 f"WHERE {' AND '.join(clauses)} "
                 f"ORDER BY x509_notBefore(c.CERTIFICATE) DESC LIMIT {params.add(limit)}) c")
        return await self.fetch(_withMeta(inner), *params.args)

    async def related(self, by: str, cert: dict[str, list], valid: bool = False,
                      limit: int = 100) -> list[dict]:
        """Certificates that share ``by`` (see ``RELATED``) with the certificate ``cert``
        ({kind: [values]}), excluding the certificate itself.

        The source certificate's value is a subquery, so this is one round trip.
        ``siblings`` (the same issuing CA) are the newest first.
        """

        if by not in RELATED:
            raise CrtshDbError(f"Unknown pivot {by}, expected one of: {', '.join(RELATED)}")

        params = Params()
        cond = _lookup(params, cert)
        source = f"(SELECT {_alias(RELATED[by], 's')} FROM certificate s WHERE {_alias(cond, 's')} LIMIT 1)"
        clauses = [f"{_alias(RELATED[by])} = {source}", f"NOT {_alias(cond)}",
                   *_filters(params, valid)]
        order = "ORDER BY x509_notBefore(c.CERTIFICATE) DESC " if by == "siblings" else ""
        inner = (f"SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c "
                 f"WHERE {' AND '.join(clauses)} {order}LIMIT {params.add(limit)}")
        return await self.fetch(_withMeta(inner), *params.args)

    async def chain(self, cert: dict[str, list], maxdepth: int = 10, maxrows: int = 500) -> list[dict]:
        """Every certificate in the chains of ``cert`` ({kind: [values]}), in one recursive query.

        Rows include ``child_id`` (the certificate this one may have issued, null for the
        leaf) and ``depth`` (0 for the leaf). A certificate can be a row more than once,
        once per child. Self-issued roots (certificates belonging to the CA that issued
        them) end a chain.

        CAs cross-sign each other (ex. Sectigo's, USERTrust's, and AAA's roots), so each
        row tracks its path and never revisits a certificate on it. ``maxrows`` caps the
        rows, the recursion stops once it's reached.
        """

        params = Params()
        cond = _alias(_lookup(params, cert))
        ctes = ("RECURSIVE chain AS ("
                "(SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE, NULL::bigint AS CHILD_ID, 0 AS DEPTH, "
                f"ARRAY[c.ID] AS PATH FROM certificate c WHERE {cond} LIMIT 1) "
                "UNION ALL "
                "SELECT p.ID, p.ISSUER_CA_ID, p.CERTIFICATE, ch.ID, ch.DEPTH + 1, ch.PATH || p.ID FROM chain ch "
                "JOIN ca_certificate cac ON cac.CA_ID = ch.ISSUER_CA_ID "
                "JOIN certificate p ON p.ID = cac.CERTIFICATE_ID "
                f"WHERE ch.DEPTH < {params.add(maxdepth)} AND NOT p.ID = ANY(ch.PATH) AND NOT EXISTS ("
                "SELECT 1 FROM ca_certificate r WHERE r.CERTIFICATE_ID = ch.ID AND r.CA_ID = ch.ISSUER_CA_ID))")
        inner = f"SELECT ID, ISSUER_CA_ID, CERTIFICATE, CHILD_ID, DEPTH FROM chain LIMIT {params.add(maxrows)}"
        return await self.fetch(_withMeta(inner, extra=("CHILD_ID", "DEPTH"), ctes=ctes), *params.args)

    # ---- CAs ----

    async def cas(self, caids: list[int] | None = None, name: str | None = None,
                  certs: bool = False, limit: int = 100) -> list[dict]:
        """CAs by ID or name (a substring of the CA's DN) and their certificates.

        Returns a row per CA certificate (``ca_id``, ``ca_name``, and ``id``, which is
        null for a CA crt.sh has no certificate for). With ``certs``, the rows are the
        CA certificates with their metadata, like the other certificate queries.
        """

        params = Params()
        conds = []
        if caids:
            conds.append(f"ca.ID = ANY({params.add(list(caids))}::int[])")
        if name:
            conds.append(f"ca.NAME ILIKE {params.add('%' + likeEscape(name) + '%')}")
        if not conds:
            raise CrtshDbError("A CA name or ID is required.")

        ctes = (f"cas AS MATERIALIZED (SELECT ca.ID, ca.NAME FROM ca WHERE {' OR '.join(conds)} "
                f"ORDER BY ca.ID LIMIT {params.add(limit)})")
        if not certs:
            sql = (f"WITH {ctes} SELECT cas.ID AS ca_id, cas.NAME AS ca_name, cac.CERTIFICATE_ID AS id "
                   "FROM cas LEFT JOIN ca_certificate cac ON cac.CA_ID = cas.ID")
            return await self.fetch(sql, *params.args)

        inner = ("SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE, cas.ID AS CA_ID, cas.NAME AS CA_NAME FROM cas "
                 "LEFT JOIN ca_certificate cac ON cac.CA_ID = cas.ID "
                 "LEFT JOIN certificate c ON c.ID = cac.CERTIFICATE_ID")
        return await self.fetch(_withMeta(inner, extra=("CA_ID", "CA_NAME"), ctes=ctes), *params.args)

    # ---- Escape hatch ----

    async def raw(self, sql: str, args: list | None = None) -> list[dict]:
        """Run any SQL. The guest account is read-only, so this can't change anything."""

        return await self.fetch(sql, *(args or ()))
