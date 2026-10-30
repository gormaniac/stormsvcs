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

``CrtshDb`` is the only class that talks to PostgreSQL. Tests swap it for a fake
with the same methods.
"""


import asyncio
import logging
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

NOTAFTER_KEY ="coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp)"
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

# Errors worth retrying: the replica cancels queries that conflict with replication,
# and crt.sh drops connections when it's overloaded.
RETRY_ERRORS = (
    asyncpg.exceptions.SerializationError,
    asyncpg.exceptions.ConnectionDoesNotExistError,
    asyncpg.exceptions.CannotConnectNowError,
    asyncpg.exceptions.TooManyConnectionsError,
    asyncpg.exceptions.InterfaceError,
    ConnectionError,
    OSError,
    asyncio.TimeoutError,
)


class CrtshDbError(Exception):
    """A query to the crt.sh database failed."""

    def __init__(self, mesg: str):
        super().__init__(mesg)
        self.mesg = mesg


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
    """A small pool of connections to the crt.sh database.

    Connections are opened on first use, so the service starts even when crt.sh
    is unreachable. Every method returns rows as plain dicts.
    """

    def __init__(self, dsn: str = DEFAULT_DSN, poolsize: int = 2, timeout: float = 120,
                 retries: int = 2):
        self.dsn = dsn
        self.poolsize = poolsize
        self.timeout = timeout
        self.retries = retries
        self._pool: asyncpg.Pool | None = None
        self._lock = asyncio.Lock()

    async def pool(self) -> asyncpg.Pool:
        """Get (creating it if needed) the connection pool."""

        async with self._lock:
            if self._pool is None:
                try:
                    # crt.sh is a hot standby replica, statements are run outside transactions
                    # and prepared statements aren't cached since most queries are one-offs.
                    self._pool = await asyncpg.create_pool(
                        self.dsn, min_size=0, max_size=self.poolsize,
                        command_timeout=self.timeout, statement_cache_size=0,
                        timeout=min(self.timeout, 30),
                    )
                except Exception as err:
                    raise CrtshDbError(f"Unable to connect to the crt.sh database: {err}") from err
            return self._pool

    async def close(self) -> None:
        """Close the connection pool."""

        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def fetch(self, sql: str, *args) -> list[dict]:
        """Run a query (retrying transient failures) and return its rows as dicts."""

        for attempt in range(self.retries + 1):
            try:
                pool = await self.pool()
                async with pool.acquire() as conn:
                    rows = await conn.fetch(sql, *args)
                return [dict(row) for row in rows]
            except CrtshDbError:
                raise
            except asyncpg.exceptions.QueryCanceledError as err:
                raise CrtshDbError(
                    f"crt.sh canceled the query (statement timeout), try a narrower search: {err}"
                ) from err
            except RETRY_ERRORS as err:
                if attempt >= self.retries:
                    raise CrtshDbError(f"crt.sh query failed: {err}") from err
                logger.warning("crt.sh query failed (attempt %d), retrying: %s", attempt + 1, err)
                await asyncio.sleep(2 ** attempt)
            except asyncpg.PostgresError as err:
                raise CrtshDbError(f"crt.sh query failed: {err}") from err
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
