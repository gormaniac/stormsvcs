"""Read-only access to the crt.sh ``certwatch`` PostgreSQL database.

crt.sh exposes its database to anyone as a read-only replica::

    psql -h crt.sh -p 5432 -U guest certwatch

Every SQL statement the service runs lives in this module. The queries only
depend on these parts of the certwatch schema (https://github.com/crtsh/certwatch_db):

- ``certificate (id, issuer_ca_id, certificate)`` - every cert and precert, as DER.
  Range partitioned by year on notAfter, see ``NOTAFTER_KEY``.
- ``ca (id, name, public_key)`` - every issuing CA (a name + key pair).
- ``ca_certificate (certificate_id, ca_id)`` - which certificates belong to a CA (one CA each).
- ``ct_log (id, name, url, operator)`` and ``ct_log_entry (certificate_id, ct_log_id,
  entry_id, entry_timestamp)`` - where and when each cert was logged.
- ``crl_revoked (ca_id, serial_number, reason_code, revocation_date)`` - CRL revocations.
- The indexed functions crt.sh's own web UI searches with: ``digest()`` (pgcrypto),
  ``identities()`` (full text search), and ``x509_serialNumber``,
  ``x509_subjectKeyIdentifier``, ``x509_publicKey``, ``x509_name``, ``x509_notBefore``,
  and ``x509_notAfter`` (libx509pq).

Everything else about a certificate is parsed from its DER by ``crtshsvc.norm``.

``certificate_identity`` is a stub view that only raises an error, and the
``certificate_and_identities`` view parses every certificate it touches, so
searches use the indexed ``identities()`` full text search on ``certificate``.

``CrtshDb`` is the only class that talks to PostgreSQL, over a single queued
connection (crt.sh allows one per client, see its docstring). Tests swap it for a
fake with the same methods.
"""


import asyncio
import logging
import random
import re
from collections.abc import Iterable
from typing import Any

import asyncpg


logger = logging.getLogger(__name__)


DEFAULT_DSN = "postgresql://guest@crt.sh:5432/certwatch"
"""crt.sh's public, read-only, password-less database."""

CERT_COLS = "c.ID AS id, c.ISSUER_CA_ID AS issuer_ca_id, c.CERTIFICATE AS der"

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

# Unique (or near unique) certificate identifiers and the indexed expression crt.sh matches them on.
LOOKUPS = {
    "id": "c.ID = ANY($1::bigint[])",
    "sha256": "digest(c.CERTIFICATE, 'sha256') = ANY($1::bytea[])",
    "sha1": "digest(c.CERTIFICATE, 'sha1') = ANY($1::bytea[])",
    "serial": "x509_serialNumber(c.CERTIFICATE) = ANY($1::bytea[])",
    "ski": "x509_subjectKeyIdentifier(c.CERTIFICATE) = ANY($1::bytea[])",
    "spki": "digest(x509_publicKey(c.CERTIFICATE), 'sha256') = ANY($1::bytea[])",
    "spkisha1": "digest(x509_publicKey(c.CERTIFICATE), 'sha1') = ANY($1::bytea[])",
    "subjectsha1": "digest(x509_name(c.CERTIFICATE), 'sha1') = ANY($1::bytea[])",
}
"""Certificate lookup kinds, mapped to the WHERE clause that finds them."""

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


def _filters(valid: bool = False, since: int | None = None, until: int | None = None,
             argn: int = 1) -> tuple[list[str], list[Any]]:
    """Build the validity WHERE clauses shared by searches. Returns (clauses, args).

    ``since``/``until`` are epoch millis bounds on notBefore. ``argn`` is the
    number of the first positional argument to use.

    ``certificate`` is partitioned by year on ``NOTAFTER_KEY``, so every bound that
    implies a minimum notAfter is also applied to that expression, which lets
    PostgreSQL skip whole partitions (crt.sh's own expiry filter does the same).
    """

    clauses, args = [], []
    if valid:
        clauses.append(f"{NOTAFTER_KEY} >= date_trunc('year', now() AT TIME ZONE 'UTC')")
        clauses.append("x509_notAfter(c.CERTIFICATE) >= now() AT TIME ZONE 'UTC'")
    if since is not None:
        args.append(since / 1000)
        argnum = argn + len(args) - 1
        clauses.append(f"x509_notBefore(c.CERTIFICATE) >= to_timestamp(${argnum}) AT TIME ZONE 'UTC'")
        # A certificate can't expire before it was issued.
        clauses.append(f"{NOTAFTER_KEY} >= to_timestamp(${argnum}) AT TIME ZONE 'UTC'")
    if until is not None:
        args.append(until / 1000)
        clauses.append(f"x509_notBefore(c.CERTIFICATE) < to_timestamp(${argn + len(args) - 1}) "
                       "AT TIME ZONE 'UTC'")
    return clauses, args


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
                 backoff: float = 1.0, connect=None):
        self.dsn = dsn
        self.timeout = timeout or None
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
        self._closed = False

    # ---- Connection management ----

    async def _connectOnce(self) -> asyncpg.Connection:
        # PgBouncer may pool by transaction, so no prepared statements are cached, and
        # the read-only replica means statements run outside explicit transactions.
        return await self._connectFn(self.dsn, statement_cache_size=0, timeout=30)

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
        while not self._closed:
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

        self._closed = True
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


    # ---- Certificates ----

    async def certs(self, kind: str, valus: Iterable, limit: int = 100) -> list[dict]:
        """Find certificates by a unique identifier (see ``LOOKUPS``)."""

        if kind not in LOOKUPS:
            raise CrtshDbError(f"Unknown lookup type {kind}, expected one of: {', '.join(LOOKUPS)}")
        sql = f"SELECT {CERT_COLS} FROM certificate c WHERE {LOOKUPS[kind]} LIMIT $2"
        return await self.fetch(sql, list(valus), limit)

    async def certsByIdentity(self, text: str, like: str | None = None,
                              nametypes: list[str] | None = None, caids: list[int] | None = None,
                              valid: bool = False, since: int | None = None,
                              until: int | None = None, limit: int = 1000) -> list[dict]:
        """Search certificate identities (subject attributes and SANs) like crt.sh does.

        ``text`` is full text searched with the indexed ``identities()``. With ``like``
        (an ILIKE pattern) and/or ``nametypes`` (see ``NAME_TYPES``), each candidate's
        individual identities are also matched in the ``certificate_and_identities``
        view before the limit is applied, exactly like crt.sh's own search, so the
        limit counts real matches. Like crt.sh, the results are an arbitrary subset
        (not the newest) when there are more than ``limit``.
        """

        args: list[Any] = [tsquery(text)]
        clauses = ["plainto_tsquery('certwatch', $1) @@ identities(c.CERTIFICATE)"]
        if like is not None:
            args.append(like)
            clauses.append(f"c.NAME_VALUE ILIKE ${len(args)}")
        if nametypes:
            args.append(list(nametypes))
            clauses.append(f"c.NAME_TYPE = ANY(${len(args)}::text[])")
        if caids:
            args.append(list(caids))
            clauses.append(f"c.ISSUER_CA_ID = ANY(${len(args)}::int[])")
        more, margs = _filters(valid, since, until, argn=len(args) + 1)
        clauses.extend(more)
        args.extend(margs)
        args.append(limit)
        where = " AND ".join(clauses)

        if like is None and not nametypes:
            # Only the full text search, no need to parse every candidate's identities.
            sql = f"SELECT {CERT_COLS} FROM certificate c WHERE {where} LIMIT ${len(args)}"
        else:
            # A certificate has a row per matching identity, group them back into one.
            sql = ("SELECT sub.CERTIFICATE_ID AS id, sub.ISSUER_CA_ID AS issuer_ca_id, "
                   "sub.CERTIFICATE AS der FROM ("
                   "SELECT c.CERTIFICATE_ID, c.ISSUER_CA_ID, c.CERTIFICATE "
                   f"FROM certificate_and_identities c WHERE {where} LIMIT ${len(args)}"
                   ") sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE")
        return await self.fetch(sql, *args)

    async def certsByIssuer(self, caids: list[int], valid: bool = False, since: int | None = None,
                            until: int | None = None, limit: int = 1000) -> list[dict]:
        """Certificates issued by any of the CAs, newest first."""

        clauses = ["c.ISSUER_CA_ID = ANY($1::int[])"]
        more, margs = _filters(valid, since, until, argn=2)
        clauses.extend(more)
        args = [list(caids), *margs, limit]
        sql = (f"SELECT {CERT_COLS} FROM certificate c WHERE {' AND '.join(clauses)} "
               f"ORDER BY x509_notBefore(c.CERTIFICATE) DESC LIMIT ${len(args)}")
        return await self.fetch(sql, *args)

    async def caCerts(self, caids: list[int]) -> list[dict]:
        """The certificates for CAs (roots, intermediates, and cross-signs). Rows include ``ca_id``."""

        sql = (f"SELECT {CERT_COLS}, cac.CA_ID AS ca_id FROM ca_certificate cac "
               "JOIN certificate c ON c.ID = cac.CERTIFICATE_ID WHERE cac.CA_ID = ANY($1::int[])")
        return await self.fetch(sql, list(caids))

    # ---- Metadata ----

    async def certCas(self, certids: list[int]) -> list[dict]:
        """The CAs that CA certificates belong to, as ``certificate_id``, ``ca_id`` rows."""

        sql = ("SELECT cac.CERTIFICATE_ID AS certificate_id, cac.CA_ID AS ca_id "
               "FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = ANY($1::bigint[])")
        return await self.fetch(sql, list(certids))

    async def cas(self, caids: list[int]) -> list[dict]:
        """CAs by ID, as ``id``, ``name`` rows."""

        sql = "SELECT ca.ID AS id, ca.NAME AS name FROM ca WHERE ca.ID = ANY($1::int[])"
        return await self.fetch(sql, list(caids))

    async def casByName(self, name: str, limit: int = 100) -> list[dict]:
        """CAs whose name (an issuer DN) contains ``name``, case insensitive."""

        pattern = "%" + likeEscape(name) + "%"
        sql = ("SELECT ca.ID AS id, ca.NAME AS name FROM ca WHERE ca.NAME ILIKE $1 "
               "ORDER BY ca.ID LIMIT $2")
        return await self.fetch(sql, pattern, limit)

    async def ctlog(self, certids: list[int]) -> list[dict]:
        """The CT log entries of certificates."""

        sql = ("SELECT ctle.CERTIFICATE_ID AS certificate_id, ctle.ENTRY_ID AS entry_id, "
               "ctle.ENTRY_TIMESTAMP AS entry_timestamp, ctl.NAME AS log_name, "
               "ctl.URL AS log_url, ctl.OPERATOR AS log_operator "
               "FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID "
               "WHERE ctle.CERTIFICATE_ID = ANY($1::bigint[]) ORDER BY ctle.ENTRY_TIMESTAMP")
        return await self.fetch(sql, list(certids))

    async def revoked(self, pairs: list[tuple[int, bytes]]) -> list[dict]:
        """CRL revocations for (issuer CA ID, serial number bytes) pairs."""

        if not pairs:
            return []
        sql = ("SELECT cr.CA_ID AS ca_id, cr.SERIAL_NUMBER AS serial_number, "
               "cr.REASON_CODE AS reason_code, cr.REVOCATION_DATE AS revocation_date "
               "FROM crl_revoked cr "
               "JOIN unnest($1::int[], $2::bytea[]) AS p(ca_id, serial) "
               "ON cr.CA_ID = p.ca_id AND cr.SERIAL_NUMBER = p.serial")
        return await self.fetch(sql, [p[0] for p in pairs], [p[1] for p in pairs])

    # ---- Escape hatch ----

    async def raw(self, sql: str, args: list | None = None) -> list[dict]:
        """Run any SQL. The guest account is read-only, so this can't change anything."""

        return await self.fetch(sql, *(args or ()))
