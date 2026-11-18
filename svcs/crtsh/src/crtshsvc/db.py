"""Read-only access to the crt.sh ``certwatch`` PostgreSQL database.

crt.sh exposes its database to anyone as a read-only replica::

    psql -h crt.sh -p 5432 -U guest certwatch

Every SQL statement the service runs lives in this module. The queries only
depend on these parts of the certwatch schema (https://github.com/crtsh/certwatch_db):

- ``certificate (id, issuer_ca_id, certificate)`` - every cert and precert, as DER.
  Range partitioned on notAfter (recent partitions are quarterly), see ``NOTAFTER_KEY``.
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
import json
import logging
import math
import random
import re
import struct
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
"""The expression ``certificate`` is range partitioned on (by notAfter, ``infinity`` when unset).

crt.sh's recent partitions are quarterly (ex. ``c2027q1`` holds notAfter in 2027 Q1), older ones
are wider. A condition on exactly this expression lets PostgreSQL skip whole partitions, so
``_filters`` writes every notAfter bound on it too.
"""

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
RECONNECT_MESGS = (
    "client_idle_timeout",
    "server conn crashed",
    "server_login_retry",
    "query_wait_timeout",
    "terminating connection",
)
BACKOFF_MESGS = (
    "max_client_conn",
    "too many connections",
    "the database system is starting up",
    "the database system is in recovery mode",
    "cannot connect now",
)


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


# The functions that take session level advisory locks, which a ROLLBACK doesn't release.
# Any mention of their names is refused, not only calls (``name(``), since comments can sit
# between a function and its parenthesis (``pg_advisory_lock/**/(1)``). An identifier can't
# be split by a comment, and quoted names (``"pg_advisory_lock"(1)``) contain the name, so
# only Unicode escaped names (``U&"pg\0061dvisory_lock"``) can hide one; those are refused.
SESSION_LOCK_RE = re.compile(
    r'(?<![a-z0-9_$])pg_(try_)?advisory_lock(_shared)?(?![a-z0-9_$])|\bu&"', re.IGNORECASE
)


def _literal(valu: Any) -> str:
    """Render a query argument of the service's own queries as an SQL literal (see ``_inline``).

    Only the types the query methods pass are accepted. Strings are escape string literals
    (``E'...'``) with every backslash and quote escaped, so the literal ends where it should
    whatever ``standard_conforming_strings`` is (asyncpg always uses UTF-8, which never has a
    quote or backslash byte inside a multibyte character). Bytes are hex digits only.
    """

    if valu is None:
        return "NULL"
    if isinstance(valu, bool):
        return "TRUE" if valu else "FALSE"
    if isinstance(valu, int):
        return str(int(valu))
    if isinstance(valu, float):
        if not math.isfinite(valu):
            raise CrtshDbError(f"Invalid query argument {valu!r}.")
        return f"'{float(valu)!r}'::float8"
    if isinstance(valu, str):
        if "\x00" in valu:
            raise CrtshDbError("Query arguments can't contain NUL characters.")
        return "E'" + valu.replace("\\", "\\\\").replace("'", "''") + "'"
    if isinstance(valu, (bytes, bytearray, memoryview)):
        return f"E'\\\\x{bytes(valu).hex()}'::bytea"
    if isinstance(valu, (list, tuple)):
        if any(isinstance(v, (list, tuple)) for v in valu):
            raise CrtshDbError("Nested lists can't be query arguments.")
        # An empty ARRAY[] has no type, '{}' takes the cast every list parameter has.
        return "ARRAY[" + ", ".join(_literal(v) for v in valu) + "]" if valu else "'{}'"
    raise CrtshDbError(f"Unsupported query argument type {type(valu).__name__}.")


PARAM_RE = re.compile(r"\$(\d+)\b")


def _inline(sql: str, args: tuple) -> str:
    """The service's own query ``sql`` with its ``$n`` parameters replaced by literals.

    Only for SQL the query methods build: user text only ever reaches it as arguments, so
    every ``$n`` in it is a parameter (never inside a string or comment). One pass, so a
    literal is never rescanned. Raw SQL is never inlined, its parameters stay parameters.
    """

    def sub(match: re.Match) -> str:
        num = int(match.group(1))
        if not 1 <= num <= len(args):
            raise CrtshDbError(f"Query parameter ${num} has no argument.")
        return _literal(args[num - 1])

    return PARAM_RE.sub(sub, sql)


COPY_SIG = b"PGCOPY\n\xff\r\n\x00"

BYTEA_COLS = frozenset({"der"})
"""The bytea columns the service's own queries return (JSON renders bytea as ``\\x<hex>``)."""


def _copyRows(data: bytes) -> list[dict]:
    """Parse a binary ``COPY`` of one text column of JSON objects (see ``CrtshDb._copy``)."""

    if data[:11] != COPY_SIG:
        raise CrtshDbError("crt.sh sent an invalid COPY header.")
    (extlen,) = struct.unpack_from("!I", data, 15)
    pos = 19 + extlen
    rows = []
    while True:
        (count,) = struct.unpack_from("!h", data, pos)
        pos += 2
        if count == -1:
            return rows
        if count != 1:
            raise CrtshDbError(f"crt.sh sent a COPY row of {count} columns, expected 1.")
        (size,) = struct.unpack_from("!i", data, pos)
        pos += 4
        if size < 0 or pos + size > len(data):
            raise CrtshDbError("crt.sh sent a truncated COPY row.")
        row = json.loads(data[pos : pos + size].decode())
        pos += size
        for key in BYTEA_COLS & row.keys():
            if isinstance(row[key], str):
                row[key] = bytes.fromhex(row[key][2:])  # Drop the \x.
        rows.append(row)


# admin.sql (rawQuery) queries, as one statement, see CrtshDb.raw. The raw query is the only
# text in it that isn't ours, so the protections are ordered by the plan, not by statements:
# - crtsh_q's WHERE is an uncorrelated subquery, so it's an InitPlan in a One-Time Filter that
#   runs before the raw query is scanned. It evaluates crtsh_pre: a snapshot of the session's
#   settings, and transaction_read_only on for the rest of the statement.
# - The final WHERE is the same, so crtsh_undo runs before any row is returned: it counts
#   crtsh_q (running the raw query to completion, into the CTE's tuplestore), then releases
#   every session advisory lock and sets back every session setting the raw query changed.
#   Both run even when the raw query returns no rows. Then crtsh_q's rows are returned.
RAW_SQL = """WITH crtsh_pre AS MATERIALIZED (
    SELECT set_config('transaction_read_only', 'on', true) AS ro,
           array_agg(name) AS names, array_agg(setting) AS vals FROM pg_settings),
crtsh_q AS MATERIALIZED (SELECT * FROM (
{sql}
) q WHERE (SELECT crtsh_pre.ro FROM crtsh_pre) IS NOT NULL LIMIT {limit}),
crtsh_undo AS MATERIALIZED (
    SELECT pg_advisory_unlock_all() AS unlocked, (
        SELECT count(set_config(b.name, b.val, false)) FROM crtsh_pre p
        CROSS JOIN LATERAL unnest(p.names, p.vals) AS b(name, val)
        JOIN pg_settings a ON a.name = b.name
        WHERE a.setting IS DISTINCT FROM b.val AND b.name NOT LIKE 'transaction%') AS restored
    FROM (SELECT count(*) FROM crtsh_q) n)
SELECT crtsh_q.* FROM crtsh_q WHERE (SELECT crtsh_undo.restored FROM crtsh_undo) IS NOT NULL"""


def _alias(cond: str, alias: str = "c") -> str:
    return cond.replace("{c}", alias)


def _filters(
    params: Params,
    valid: bool = False,
    since: int | None = None,
    until: int | None = None,
    expires_after: int | None = None,
    expires_before: int | None = None,
) -> list[str]:
    """The validity conditions shared by searches, on ``certificate c``.

    ``since``/``until`` are epoch millis bounds on notBefore, ``expires_after`` (inclusive)
    and ``expires_before`` (exclusive) on notAfter. A certificate without a notAfter never
    expires, so it never matches ``expires_before``.

    ``certificate`` is partitioned on ``NOTAFTER_KEY``, so every bound that implies a
    notAfter bound is also applied to that expression, which lets PostgreSQL skip whole
    partitions (crt.sh's own expiry filter does the same). Both expiry bounds can pin a
    search to one partition (ex. 2027-01-01 to 2027-04-01 for ``c2027q1``).
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
    if expires_after is not None:
        param = params.add(expires_after / 1000)
        clauses.append(f"x509_notAfter(c.CERTIFICATE) >= to_timestamp({param}) AT TIME ZONE 'UTC'")
        clauses.append(f"{NOTAFTER_KEY} >= to_timestamp({param}) AT TIME ZONE 'UTC'")
    if expires_before is not None:
        param = params.add(expires_before / 1000)
        clauses.append(f"x509_notAfter(c.CERTIFICATE) < to_timestamp({param}) AT TIME ZONE 'UTC'")
        clauses.append(f"{NOTAFTER_KEY} < to_timestamp({param}) AT TIME ZONE 'UTC'")
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


def tsquery(text: str) -> tuple[str, list[str]]:
    """Split search text into plain words for ``plainto_tsquery('certwatch', ...)`` and prefixes.

    Returns ``(plain, prefixes)``. A word with a trailing ``*`` (ex. ``microsoft*``) is a
    prefix, see ``prefixQuery``. Other wildcards and LIKE patterns aren't meaningful to full
    text search, so a leading ``*.``/``%.`` and any other ``%``/``*`` are removed (a ``*``
    inside a word splits it). A prefix with nothing to index (ex. ``-*``) is dropped.
    """

    text = re.sub(r"^[*%]+\.?", "", text.strip()).replace("%", " ")
    plain, prefixes = [], []
    for word in text.split():
        if word.endswith("*") and any(c.isalnum() for c in word.rstrip("*").split("*")[-1]):
            *rest, word = word.rstrip("*").split("*")
            plain.extend(rest)
            prefixes.append(word)
        else:
            plain.append(word.replace("*", " "))
    return " ".join(" ".join(plain).split()), prefixes


def prefixQuery(words: list[str]) -> str:
    """A ``tsquery`` literal matching indexed words that start with each of ``words``.

    Each word is quoted as one operand (``'word':*``, its quotes and backslashes escaped), so
    no user text is ever read as tsquery syntax (``&|!():<>``). The literal is cast straight to
    ``tsquery``, not passed to ``to_tsquery``: ``to_tsquery`` runs a quoted operand through the
    text parser again, so ``'foo-bar':*`` became the phrase ``'foo-bar':* <-> 'foo':* <->
    'bar':*``, which never matches crt.sh's ``identities()`` (it strips word positions) and
    misses hosts indexed as one word (``microsoft-support.ph``). The certwatch config only
    lowercases words, so lowercasing here gives the same lexeme.
    """

    quoted = ("'" + w.lower().replace("\\", "\\\\").replace("'", "''") + "':*" for w in words)
    return " & ".join(quoted)


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
    - crt.sh's PgBouncer pools by **statement**: each statement may run on a different server
      connection, and explicit transactions (``BEGIN``, savepoints) are refused ("transaction
      blocks not allowed in statement pooling mode", and the client is disconnected). A
      session ``SET`` lands on whichever server connection ran it (and stays there, for
      other clients). So every query is a single round trip with no explicit transaction,
      which also works behind transaction or session pooling and against plain PostgreSQL.
    - The service's own queries are one simple-query message: ``SET LOCAL statement_timeout``,
      ``SET TRANSACTION READ ONLY``, and the query as a ``COPY ... TO STDOUT`` (see ``_copy``).
      The statements of one message run in one implicit transaction on one server
      connection, so the timeout and read-only mode apply to the query and end with it.
      Startup parameters don't work: PgBouncer rejects ``statement_timeout`` ("unsupported
      startup parameter"), ignores it if it's in ``ignore_startup_parameters``, and can't
      track it (PostgreSQL doesn't report it). A ``set_config()`` inside the query only
      affects later statements.
    - ``timeout`` (client side, None for none) is a backstop for a query the server never
      cancels, keep it longer than ``statement_timeout``.
    - A query the server cancels for its statement timeout is retried ``timeout_retries``
      times, ``timeout_delay`` seconds later: a heavy search can time out on crt.sh's cold
      cache and finish when rerun. Nothing else that cancels a query is retried.

    Every query method returns rows as plain dicts.
    """

    def __init__(
        self,
        dsn: str = DEFAULT_DSN,
        timeout: float | None = None,
        retries: int = 3,
        keepalive: float = 10,
        idle: float = 300,
        connect_timeout: float = 300,
        backoff: float = 1.0,
        statement_timeout: float = 0,
        timeout_retries: int = 1,
        timeout_delay: float = 5,
        connect=None,
    ):
        self.dsn = dsn
        self.timeout = timeout or None
        self.statement_timeout = statement_timeout
        self.retries = retries
        self.timeout_retries = timeout_retries
        self.timeout_delay = timeout_delay
        self.keepalive = keepalive
        self.idle = idle
        self.connect_timeout = connect_timeout
        self.backoff = backoff
        self._connectFn = connect or asyncpg.connect

        self._conn: asyncpg.Connection | None = None
        self._lock = asyncio.Lock()
        self._lastUsed = 0.0
        self._keeper: asyncio.Task | None = None
        self._useCopy = True  # False once the server refuses the SETs of _copy (see _run).

    # ---- Connection management ----

    async def _connectOnce(self) -> asyncpg.Connection:
        # PgBouncer pools by statement, so no prepared statements are cached. Settings are
        # made per query (see _run), PgBouncer rejects startup parameters it doesn't know.
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
                transient = _mesgIn(err, BACKOFF_MESGS + RECONNECT_MESGS) or isinstance(
                    err,
                    (
                        *CONN_ERRORS,
                        asyncio.TimeoutError,
                        asyncpg.exceptions.CannotConnectNowError,
                        asyncpg.exceptions.TooManyConnectionsError,
                    ),
                )
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

    def _kill(self, conn: asyncpg.Connection) -> None:
        """Terminate the connection immediately, ex. when a query on it was cancelled midway."""

        self._conn = None
        conn.terminate()

    async def _run(
        self, conn: asyncpg.Connection, sql: str, args: tuple, raw: bool = False
    ) -> list[dict]:
        """Run one query in a single round trip, with no explicit transaction (see the class
        docstring), returning its rows as dicts.

        The service's own queries run with ``_copy``, which sets their statement_timeout and
        read-only mode. If the server refuses those SETs (or this asyncpg can't run ``_copy``)
        they're run as a plain query from then on, under the server's statement_timeout.

        ``raw`` queries (``RAW_SQL``, see ``raw``) keep their parameters, so they're a plain
        extended protocol query, under the server's statement_timeout. If one fails, the
        session advisory locks it took before failing are released with a follow-up
        ``pg_advisory_unlock_all()``, which only reaches the same server connection outside
        PgBouncer's statement pooling (see ``raw``).
        """

        if raw:
            try:
                rows = await conn.fetch(sql, *args, timeout=self.timeout)
            except asyncpg.PostgresError:
                await self._unlockAll(conn)
                raise
            return [dict(row) for row in rows]

        if self._useCopy and not hasattr(getattr(conn, "_protocol", None), "copy_out"):
            # asyncpg's protocol changed, see _copy.
            logger.warning("Unable to COPY with this asyncpg, using crt.sh's statement_timeout.")
            self._useCopy = False
        if self._useCopy:
            try:
                return await self._copy(conn, sql, args)
            except (
                asyncpg.exceptions.InsufficientPrivilegeError,
                asyncpg.exceptions.CantChangeRuntimeParamError,
                asyncpg.exceptions.UndefinedObjectError,
            ) as err:
                if "parameter" not in str(err):
                    raise
                logger.warning(
                    "Unable to set the crt.sh statement_timeout, using the server's: %s", err
                )
                self._useCopy = False
        rows = await conn.fetch(sql, *args, timeout=self.timeout)
        return [dict(row) for row in rows]

    def _copyStmt(self, sql: str, args: tuple) -> str:
        """The simple-query message ``_copy`` sends for one of the service's own queries."""

        return (
            f"SET LOCAL statement_timeout = {int(self.statement_timeout * 1000)}; "
            "SET LOCAL bytea_output = hex; SET TRANSACTION READ ONLY; "
            "COPY (SELECT row_to_json(crtsh_r)::text FROM (\n"
            f"{_inline(sql, args)}\n) crtsh_r) TO STDOUT (FORMAT binary)"
        )

    async def _copy(self, conn: asyncpg.Connection, sql: str, args: tuple) -> list[dict]:
        """Run one of the service's own queries with its own statement_timeout, read-only.

        asyncpg's ``fetch`` uses the extended protocol, one statement per message, and its
        simple-query ``execute`` discards rows. The only simple-query path that returns data
        is ``COPY ... TO STDOUT``, so the query's rows are copied out as one JSON object each
        (``row_to_json``, binary format, so nothing is escaped), in the same message as the
        ``SET LOCAL``\\s. Its arguments are inlined as literals (``_inline``), a simple query
        has no parameters. Only the service's own SQL takes this path, never raw SQL.

        It's asyncpg's protocol level ``copy_out`` (what ``Connection.copy_from_query`` uses),
        since the public method wraps the statement itself. The tests run it against
        PostgreSQL and PgBouncer (see tests/test_pg.py).
        """

        buf = bytearray()

        async def sink(data):
            buf.extend(data)

        await conn._protocol.copy_out(self._copyStmt(sql, args), sink, self.timeout)
        return _copyRows(bytes(buf))

    async def _unlockAll(self, conn: asyncpg.Connection) -> None:
        """Best effort: release the session advisory locks a failed raw query took (ex.
        through dynamic SQL, like ``query_to_xml('SELECT pg_advisory_lock(1)', ...)``).

        A raw query that succeeds releases them itself (see ``RAW_SQL``). One that fails
        can't, so this runs ``pg_advisory_unlock_all()`` next, which reaches the same server
        connection directly or behind session pooling, but behind transaction or statement
        pooling it may land on another one. If it fails the connection is dropped, which
        ends the session (and its locks) outside of PgBouncer.
        """

        try:
            await asyncio.wait_for(conn.execute("SELECT pg_advisory_unlock_all()"), timeout=30)
        except Exception as err:
            logger.debug(
                "Unable to release crt.sh advisory locks, dropping the connection: %s", err
            )
            await self._drop()

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

    async def fetch(self, sql: str, *args, raw: bool = False) -> list[dict]:
        """Queue a query, run it (reconnecting and retrying when the connection drops), and
        return its rows as dicts. ``raw`` is for ``raw``'s wrapped queries (see ``_run``)."""

        loop = asyncio.get_running_loop()
        canceled = 0
        async with self._lock:
            attempt = 0
            while attempt <= self.retries:
                conn = await self._ensure()
                self._lastUsed = loop.time()
                try:
                    return await self._run(conn, sql, args, raw=raw)
                except asyncio.CancelledError:
                    # The caller went away mid-query, the connection is mid-query and can't be reused.
                    self._kill(conn)
                    raise
                except asyncpg.exceptions.QueryCanceledError as err:
                    # A heavy query can time out on crt.sh's cold cache and finish when rerun.
                    # Only the server's statement timeout is retried, not other cancels (57014
                    # is also "canceling statement due to user request").
                    if "statement timeout" not in str(err) or canceled >= self.timeout_retries:
                        raise CrtshDbError(
                            f"crt.sh canceled the query (statement timeout), try a narrower search: {err}"
                        ) from err
                    canceled += 1
                    delay = self.timeout_delay
                    logger.warning(
                        "crt.sh canceled the query (statement timeout), retrying in %.0fs (%d of %d), "
                        "its cache may be warm now: %s",
                        delay,
                        canceled,
                        self.timeout_retries,
                        err,
                    )
                    await asyncio.sleep(delay)
                    continue
                except TimeoutError as err:
                    # The connection is mid-query, it can't be reused.
                    await self._drop()
                    raise CrtshDbError(f"crt.sh query timed out after {self.timeout}s.") from err
                except asyncpg.exceptions.SerializationError as err:
                    # The replica canceled the query to apply replication, just retry it.
                    retry = err
                except Exception as err:
                    if not (
                        isinstance(err, CONN_ERRORS)
                        or _mesgIn(err, RECONNECT_MESGS + BACKOFF_MESGS)
                    ):
                        if isinstance(err, asyncpg.PostgresError):
                            raise CrtshDbError(f"crt.sh query failed: {err}") from err
                        # Not from the database, so the connection's state is unknown.
                        await self._drop()
                        raise
                    retry = err
                    await self._drop()
                finally:
                    self._lastUsed = loop.time()

                if attempt >= self.retries:
                    raise CrtshDbError(f"crt.sh query failed: {retry}") from retry
                logger.warning("crt.sh query failed (attempt %d), retrying: %s", attempt + 1, retry)
                attempt += 1
        raise CrtshDbError("crt.sh query failed.")  # pragma: no cover

    # ---- Certificates, each returned with its metadata (see _withMeta) ----

    async def certs(self, lookups: dict[str, list], limit: int = 100) -> list[dict]:
        """Certificates matching any of ``lookups`` ({kind: [values]}, see ``LOOKUPS``)."""

        params = Params()
        cond = _alias(_lookup(params, lookups))
        inner = (
            f"SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE {cond} "
            f"LIMIT {params.add(limit)}"
        )
        return await self.fetch(_withMeta(inner), *params.args)

    async def certsByIdentity(
        self,
        text: str,
        like: str | None = None,
        nametypes: list[str] | None = None,
        caids: list[int] | None = None,
        issuer: str | None = None,
        valid: bool = False,
        since: int | None = None,
        until: int | None = None,
        limit: int = 1000,
        expires_after: int | None = None,
        expires_before: int | None = None,
    ) -> list[dict]:
        """Search certificate identities (subject attributes and SANs) like crt.sh does.

        ``text`` is full text searched with the indexed ``identities()``. With ``like``
        (an ILIKE pattern) and/or ``nametypes`` (see ``NAME_TYPES``), each candidate's
        individual identities are also matched in the ``certificate_and_identities``
        view before the limit is applied, exactly like crt.sh's own search, so the
        limit counts real matches. Like crt.sh, the results are an arbitrary subset
        (not the newest) when there are more than ``limit``.

        A word of ``text`` with a trailing ``*`` is a prefix (see ``tsquery``): it
        matches any indexed word that starts with it.

        ``caids`` and ``issuer`` (a CA name) narrow the issuer, but only after the
        limit: the candidates are found first, then filtered by issuer, like crt.sh's
        own search. Nothing indexes a word and an issuer together, so filtering by
        issuer inside the limit makes PostgreSQL recheck every certificate with the
        word until enough are from the issuer, which never finishes for common words
        (ex. "microsoft" matches hundreds of millions of certificates, few from Let's
        Encrypt).
        """

        params = Params()
        plain, prefixes = tsquery(text)
        queries = []
        if plain or not prefixes:
            queries.append(f"plainto_tsquery('certwatch', {params.add(plain)})")
        if prefixes:
            queries.append(f"{params.add(prefixQuery(prefixes))}::tsquery")
        query = queries[0] if len(queries) == 1 else f"({' && '.join(queries)})"
        clauses = [f"{query} @@ identities(c.CERTIFICATE)"]
        if like is not None:
            clauses.append(f"c.NAME_VALUE ILIKE {params.add(like)}")
        if nametypes:
            clauses.append(f"c.NAME_TYPE = ANY({params.add(list(nametypes))}::text[])")
        clauses.extend(_filters(params, valid, since, until, expires_after, expires_before))
        where = " AND ".join(clauses)
        limit = params.add(limit)

        if like is None and not nametypes:
            # Only the full text search, no need to parse every candidate's identities.
            cand = f"SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE {where} LIMIT {limit}"
            group = ""
        else:
            # A certificate has a row per matching identity, they're grouped back into one.
            cand = (
                "SELECT c.CERTIFICATE_ID AS ID, c.ISSUER_CA_ID, c.CERTIFICATE "
                f"FROM certificate_and_identities c WHERE {where} LIMIT {limit}"
            )
            group = " GROUP BY cand.ID, cand.ISSUER_CA_ID, cand.CERTIFICATE"

        issuers = []
        if caids:
            issuers.append(f"cand.ISSUER_CA_ID = ANY({params.add(list(caids))}::int[])")
        if issuer:
            issuers.append(f"cand.ISSUER_CA_ID IN ({_issuerName(params, issuer)})")

        if not issuers and not group:
            return await self.fetch(_withMeta(cand), *params.args)

        # The candidates are materialized so the issuer filter isn't planned into their scan.
        filt = f" WHERE {' AND '.join(issuers)}" if issuers else ""
        inner = f"SELECT cand.ID, cand.ISSUER_CA_ID, cand.CERTIFICATE FROM cand{filt}{group}"
        return await self.fetch(
            _withMeta(inner, ctes=f"cand AS MATERIALIZED ({cand})"), *params.args
        )

    async def certsByIssuer(
        self,
        caids: list[int] | None = None,
        issuer: str | None = None,
        cert: dict[str, list] | None = None,
        valid: bool = False,
        since: int | None = None,
        until: int | None = None,
        limit: int = 1000,
        expires_after: int | None = None,
        expires_before: int | None = None,
    ) -> list[dict]:
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
            sources.append(
                "SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = "
                f"(SELECT s.ID FROM certificate s WHERE {cond} LIMIT 1)"
            )
        if not sources:
            raise CrtshDbError("A CA ID, CA name, or CA certificate is required.")

        clauses = [
            "c.ISSUER_CA_ID = cas.CA_ID",
            *_filters(params, valid, since, until, expires_after, expires_before),
        ]
        inner = (
            f"SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM ({' UNION '.join(sources)}) cas "
            "CROSS JOIN LATERAL (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c "
            f"WHERE {' AND '.join(clauses)} "
            f"ORDER BY x509_notBefore(c.CERTIFICATE) DESC LIMIT {params.add(limit)}) c"
        )
        return await self.fetch(_withMeta(inner), *params.args)

    async def related(
        self, by: str, cert: dict[str, list], valid: bool = False, limit: int = 100
    ) -> list[dict]:
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
        clauses = [
            f"{_alias(RELATED[by])} = {source}",
            f"NOT {_alias(cond)}",
            *_filters(params, valid),
        ]
        order = "ORDER BY x509_notBefore(c.CERTIFICATE) DESC " if by == "siblings" else ""
        inner = (
            f"SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c "
            f"WHERE {' AND '.join(clauses)} {order}LIMIT {params.add(limit)}"
        )
        return await self.fetch(_withMeta(inner), *params.args)

    async def chain(
        self, cert: dict[str, list], maxdepth: int = 10, maxrows: int = 500
    ) -> list[dict]:
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
        ctes = (
            "RECURSIVE chain AS ("
            "(SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE, NULL::bigint AS CHILD_ID, 0 AS DEPTH, "
            f"ARRAY[c.ID] AS PATH FROM certificate c WHERE {cond} LIMIT 1) "
            "UNION ALL "
            "SELECT p.ID, p.ISSUER_CA_ID, p.CERTIFICATE, ch.ID, ch.DEPTH + 1, ch.PATH || p.ID FROM chain ch "
            "JOIN ca_certificate cac ON cac.CA_ID = ch.ISSUER_CA_ID "
            "JOIN certificate p ON p.ID = cac.CERTIFICATE_ID "
            f"WHERE ch.DEPTH < {params.add(maxdepth)} AND NOT p.ID = ANY(ch.PATH) AND NOT EXISTS ("
            "SELECT 1 FROM ca_certificate r WHERE r.CERTIFICATE_ID = ch.ID AND r.CA_ID = ch.ISSUER_CA_ID))"
        )
        inner = f"SELECT ID, ISSUER_CA_ID, CERTIFICATE, CHILD_ID, DEPTH FROM chain LIMIT {params.add(maxrows)}"
        return await self.fetch(
            _withMeta(inner, extra=("CHILD_ID", "DEPTH"), ctes=ctes), *params.args
        )

    # ---- CAs ----

    async def cas(
        self,
        caids: list[int] | None = None,
        name: str | None = None,
        certs: bool = False,
        limit: int = 100,
    ) -> list[dict]:
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

        ctes = (
            f"cas AS MATERIALIZED (SELECT ca.ID, ca.NAME FROM ca WHERE {' OR '.join(conds)} "
            f"ORDER BY ca.ID LIMIT {params.add(limit)})"
        )
        if not certs:
            sql = (
                f"WITH {ctes} SELECT cas.ID AS ca_id, cas.NAME AS ca_name, cac.CERTIFICATE_ID AS id "
                "FROM cas LEFT JOIN ca_certificate cac ON cac.CA_ID = cas.ID"
            )
            return await self.fetch(sql, *params.args)

        inner = (
            "SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE, cas.ID AS CA_ID, cas.NAME AS CA_NAME FROM cas "
            "LEFT JOIN ca_certificate cac ON cac.CA_ID = cas.ID "
            "LEFT JOIN certificate c ON c.ID = cac.CERTIFICATE_ID"
        )
        return await self.fetch(
            _withMeta(inner, extra=("CA_ID", "CA_NAME"), ctes=ctes), *params.args
        )

    # ---- Escape hatch ----

    async def raw(self, sql: str, args: list | None = None, limit: int = 1000) -> list[dict]:
        """Run a single query that returns rows, returning at most ``limit`` of them.

        The query is wrapped in ``RAW_SQL`` (as ``SELECT * FROM (<sql>) q LIMIT <limit>``),
        so it must be a SELECT, VALUES, TABLE, or WITH ... SELECT query. That bounds the rows
        held in memory, and rejects statements that change the session (``SET``, ``COMMIT``)
        or data (a data-modifying ``WITH`` must be at the top level).

        It's one statement, for PgBouncer's statement pooling (see ``_run``), so there's no
        transaction to roll back. Instead the wrapper, in the same statement:

        - Sets ``transaction_read_only`` before the query runs, so functions that write (ex.
          ``nextval``, ``lo_create``) fail, and the query can't turn it back off.
        - Snapshots the session's settings first and sets back any the query changed (ex.
          ``set_config('search_path', ..., false)``) before returning its rows. A query that
          fails aborts its (implicit) transaction, which undoes them. Placeholder settings a
          query creates (``set_config('x.y', ...)``) aren't removed.
        - Releases every session advisory lock (``pg_advisory_unlock_all()``) after the query
          and before returning its rows, even ones taken through dynamic SQL (ex.
          ``query_to_xml``) or by a query that returns no rows. As a first line, queries that
          name the functions that take them are refused. A query that takes one and then
          fails can't release it in its statement, so a follow-up ``pg_advisory_unlock_all()``
          is sent (see ``_unlockAll``). Directly or behind session pooling it reaches the same
          session. Behind statement (crt.sh) or transaction pooling it may not, and the lock
          stays on that PgBouncer server connection until PgBouncer closes it; the service's
          own queries never take advisory locks, so they aren't affected.

        These run in the statement the raw SQL is part of, so they guard against mistakes and
        dynamic SQL, not deliberately malformed SQL (ex. unbalanced parentheses that
        restructure the wrapper). On crt.sh the guest role and its read-only replica are what
        keep data from changing. Point ``crtsh:dsn`` at a writable account only if every user
        allowed to run admin.sql may write.

        Raw queries keep their ``$n`` parameters, so they run as a plain (extended protocol)
        query under the server's own statement_timeout (30s on crt.sh), not the service's.
        """

        args = list(args or ())
        sql = re.sub(r"[\s;]+$", "", sql.strip())
        if not sql:
            raise CrtshDbError("No SQL to run.")
        if SESSION_LOCK_RE.search(sql):
            raise CrtshDbError(
                "Session advisory locks (pg_advisory_lock) would outlive the query, "
                "use the pg_advisory_xact_lock functions. Queries can't mention their "
                'names or use Unicode escaped identifiers (U&"...").'
            )
        wrapped = RAW_SQL.format(sql=sql, limit=f"${len(args) + 1}")
        return await self.fetch(wrapped, *args, int(limit), raw=True)
