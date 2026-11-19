"""Pytests for CrtshDb's connection handling, against fake connections.

crt.sh's PgBouncer allows one connection per client, drops idle clients
(client_idle_timeout), and refuses quick reconnects (max_client_conn).
"""

import asyncio
import base64
import json
import pathlib
import re
import struct

import asyncpg
import pytest
from cryptography import x509

from crtshsvc.db import (
    LOOKUPS,
    NAME_TYPES,
    NOTAFTER_KEY,
    PARAM_RE,
    RAW_SQL,
    CrtshDb,
    CrtshDbError,
    _copyRows,
    _inline,
    _literal,
    likeEscape,
    prefixQuery,
    tsquery,
)

from .fakecrtsh import PKI, identityText, tsTokens


class FakeRecord:
    """Like asyncpg.Record: iterating gives the values (not the keys), indexed by position or name."""

    def __init__(self, **items):
        self._items = items

    def __iter__(self):
        return iter(self._items.values())

    def __len__(self):
        return len(self._items)

    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self._items.values())[key]
        return self._items[key]

    def get(self, key, default=None):
        return self._items.get(key, default)

    def keys(self):
        return iter(self._items.keys())

    def values(self):
        return iter(self._items.values())

    def items(self):
        return iter(self._items.items())


# Statements that open an explicit transaction block, which PgBouncer's statement pooling
# refuses (and then disconnects the client). A SET LOCAL sent on its own isn't refused by
# PostgreSQL, but outside a transaction it does nothing, so the fakes refuse it too.
TXN_RE = re.compile(
    r"(^|;)\s*(BEGIN|START\s+TRANSACTION|SAVEPOINT|ROLLBACK|COMMIT)\b", re.IGNORECASE
)
SET_LOCAL_RE = re.compile(r"^\s*SET\s+LOCAL\b", re.IGNORECASE)

# The simple-query message CrtshDb._copy sends for the service's own queries.
COPY_RE = re.compile(
    r"SET statement_timeout = (\d+); SET LOCAL bytea_output = hex; "
    r"SET TRANSACTION READ ONLY; COPY \(SELECT row_to_json\(crtsh_r\)::text FROM \(\n"
    r"(.*)\n\) crtsh_r\) TO STDOUT \(FORMAT binary\); RESET statement_timeout",
    re.DOTALL,
)


def copyData(rows: list[dict]) -> bytes:
    """A binary COPY of one text column holding each row as JSON, as PostgreSQL sends it."""

    data = bytearray(b"PGCOPY\n\xff\r\n\x00" + struct.pack("!II", 0, 0))
    for row in rows:
        text = json.dumps(row).encode()
        data += struct.pack("!hi", 1, len(text)) + text
    return bytes(data + struct.pack("!h", -1))


class FakeProtocol:
    """The protocol level copy_out CrtshDb._copy uses."""

    def __init__(self, conn):
        self.conn = conn

    async def copy_out(self, stmt, sink, timeout):
        conn, server = self.conn, self.conn.server
        conn.refuse(stmt)
        server.messages.append(stmt)
        match = COPY_RE.fullmatch(stmt)
        assert match, stmt
        if server.setfail:
            raise asyncpg.exceptions.InsufficientPrivilegeError(
                'permission denied to set parameter "statement_timeout"'
            )
        server.timeouts.append(int(match.group(1)))
        rows = await conn.run(match.group(2))
        # PostgreSQL sends a CopyData message per row, asyncpg may hand them over in chunks.
        data = copyData(rows)
        for pos in range(0, len(data), 7):
            await sink(data[pos : pos + 7])
        return f"COPY {len(rows)}"


class FakeConn:
    """A fake asyncpg connection behind PgBouncer's statement pooling, running scripted results.

    Each message must be one statement, or one implicit transaction (a simple query of
    several statements): explicit transaction blocks are refused, like crt.sh's PgBouncer.
    """

    def __init__(self, server, num: int):
        self.server = server
        self.num = num
        self.closed = False
        self.pings = 0
        self._protocol = FakeProtocol(self)

    def is_closed(self) -> bool:
        return self.closed

    async def close(self):
        if self.server.closefail:
            raise OSError("close failed")
        self.closed = True
        self.server.open -= 1

    def terminate(self):
        self.closed = True
        self.server.open -= 1
        self.server.terminated += 1

    def refuse(self, sql: str):
        """Refuse a transaction block like PgBouncer's statement pooling, disconnecting."""

        assert not self.closed
        if self.server.statement and (
            TXN_RE.search(sql) or (SET_LOCAL_RE.match(sql) and ";" not in sql)
        ):
            self.server.refused.append(sql)
            self.closed = True
            self.server.open -= 1
            raise asyncpg.exceptions.ProtocolViolationError(
                "transaction blocks not allowed in statement pooling mode"
            )

    async def run(self, sql) -> list[dict]:
        assert not self.closed
        assert not self.server.busy, "Queries must never overlap on the single connection."
        self.server.busy = True
        try:
            await asyncio.sleep(self.server.delay)
            self.server.queries.append((self.num, sql))
            if self.server.errors:
                err = self.server.errors.pop(0)
                if err is not None:
                    raise err
            return [{"sql": sql, "conn": self.num}]
        finally:
            self.server.busy = False

    async def fetch(self, sql, *args, timeout=None):
        self.refuse(sql)
        self.server.fetched.append(sql)
        return [FakeRecord(**row) for row in await self.run(sql)]

    async def execute(self, sql):
        self.refuse(sql)
        self.server.executed.append(sql)
        if sql in self.server.failon:
            raise OSError("connection lost")

    async def fetchval(self, sql, timeout=None):
        self.refuse(sql)
        if self.server.pingfail:
            raise asyncpg.exceptions.ProtocolViolationError("client_idle_timeout")
        self.pings += 1
        self.server.pings += 1
        return 1


class FakeServer:
    """Hands out FakeConns, refusing connections like crt.sh's PgBouncer."""

    def __init__(
        self, refusals: int = 0, refusal: str = "no more connections allowed (max_client_conn)"
    ):
        self.refusals = refusals
        self.refusal = refusal
        self.conns: list[FakeConn] = []
        self.queries: list[tuple[int, str]] = []
        self.errors: list[BaseException | None] = []
        self.open = 0
        self.busy = False
        self.pings = 0
        self.attempts = 0
        self.delay = 0.01
        self.closefail = False
        self.pingfail = False
        self.terminated = 0
        self.statement = True  # PgBouncer's statement pooling, like crt.sh.
        self.messages: list[str] = []  # The COPY messages of the service's own queries.
        self.timeouts: list[int] = []  # Their statement_timeouts, in ms.
        self.fetched: list[str] = []  # Extended protocol queries (raw, or without COPY).
        self.executed: list[str] = []
        self.refused: list[str] = []
        self.setfail = False
        self.failon: set[str] = set()

    async def connect(self, dsn, **kwargs):
        self.attempts += 1
        assert kwargs["statement_cache_size"] == 0
        assert "server_settings" not in kwargs, "PgBouncer rejects unknown startup parameters."
        if self.refusals:
            self.refusals -= 1
            raise asyncpg.exceptions.ProtocolViolationError(self.refusal)
        assert self.open == 0, "Only one connection may be open at a time."
        self.open += 1
        conn = FakeConn(self, len(self.conns))
        self.conns.append(conn)
        return conn


def makeDb(server: FakeServer, **kwargs) -> CrtshDb:
    opts = {"keepalive": 60, "idle": 300, "connect_timeout": 5, "backoff": 0.01}
    opts.update(kwargs)
    return CrtshDb(connect=server.connect, **opts)


async def test_queued_single_connection():
    server = FakeServer()
    db = makeDb(server)
    try:
        rows = await asyncio.gather(*(db.fetch(f"SELECT {i}") for i in range(10)))
        assert [r[0]["sql"] for r in rows] == [f"SELECT {i}" for i in range(10)]
        # One connection, queries run in the order they were queued.
        assert len(server.conns) == 1
        assert [q[1] for q in server.queries] == [f"SELECT {i}" for i in range(10)]
    finally:
        await db.close()
    assert server.open == 0


async def test_reconnect_after_idle_timeout():
    server = FakeServer()
    db = makeDb(server)
    try:
        await db.fetch("SELECT 1")
        # PgBouncer dropped the idle client, the query is retried on a new connection.
        server.errors = [asyncpg.exceptions.ProtocolViolationError("client_idle_timeout")]
        rows = await db.fetch("SELECT 2")
        assert rows == [{"sql": "SELECT 2", "conn": 1}]
        assert len(server.conns) == 2
        assert server.conns[0].closed

        server.errors = [asyncpg.exceptions.ConnectionDoesNotExistError("connection was closed")]
        assert (await db.fetch("SELECT 3"))[0]["conn"] == 2
    finally:
        await db.close()


async def test_connect_backoff():
    # Reconnecting right away is refused with max_client_conn until crt.sh notices.
    server = FakeServer(refusals=3)
    db = makeDb(server)
    try:
        assert (await db.fetch("SELECT 1"))[0]["conn"] == 0
        assert server.attempts == 4
    finally:
        await db.close()

    server = FakeServer(refusals=1000)
    db = makeDb(server, connect_timeout=0.2)
    with pytest.raises(CrtshDbError, match="max_client_conn"):
        await db.fetch("SELECT 1")
    await db.close()

    # Errors that aren't transient fail right away.
    server = FakeServer(refusals=1, refusal='password authentication failed for user "guest"')
    db = makeDb(server)
    with pytest.raises(CrtshDbError, match="password authentication"):
        await db.fetch("SELECT 1")
    assert server.attempts == 1
    await db.close()


async def test_retries():
    server = FakeServer()
    db = makeDb(server, retries=2)
    try:
        # Replication conflicts are retried on the same connection.
        server.errors = [
            asyncpg.exceptions.SerializationError("canceling statement due to conflict")
        ]
        assert (await db.fetch("SELECT 1"))[0]["conn"] == 0

        # Too many drops in a row give up.
        server.errors = [asyncpg.exceptions.ProtocolViolationError("client_idle_timeout")] * 3
        with pytest.raises(CrtshDbError, match="client_idle_timeout"):
            await db.fetch("SELECT 2")

        # SQL errors aren't retried.
        server.errors = [asyncpg.exceptions.UndefinedTableError('relation "nope" does not exist')]
        with pytest.raises(CrtshDbError, match="nope"):
            await db.fetch("SELECT * FROM nope")
    finally:
        await db.close()


async def test_retry_statement_timeout(caplog):
    # A heavy query can time out on crt.sh's cold cache and finish when rerun, so a statement
    # timeout is retried once (crtsh:timeout:retries), after timeout_delay, on the same connection.
    server = FakeServer()
    db = makeDb(server, timeout_delay=0.01)
    timeout = asyncpg.exceptions.QueryCanceledError("canceling statement due to statement timeout")
    try:
        server.errors = [timeout]
        assert (await db.fetch("SELECT 1"))[0]["conn"] == 0
        # The canceled query's implicit transaction ended with it, there's nothing to end.
        assert len(server.conns) == 1 and server.executed == [] and len(server.messages) == 2
        assert "retrying in 0s (1 of 1)" in caplog.text

        # Twice in a row is the normal error.
        server.errors = [timeout, timeout]
        with pytest.raises(CrtshDbError, match="canceled the query \\(statement timeout\\)"):
            await db.fetch("SELECT 2")
        assert not server.errors

        # Other cancels aren't retried, the connection stays usable.
        server.errors = [
            asyncpg.exceptions.QueryCanceledError("canceling statement due to user request"),
            None,
        ]
        with pytest.raises(CrtshDbError, match="user request"):
            await db.fetch("SELECT 3")
        assert server.errors == [None]

        # Nor are timeouts without retries, and they don't use up connection retries.
        db.timeout_retries = 0
        server.errors = [timeout]
        with pytest.raises(CrtshDbError, match="statement timeout"):
            await db.fetch("SELECT 4")
        db.timeout_retries, db.retries = 1, 0
        server.errors = [timeout]
        assert (await db.fetch("SELECT 5"))[0]["conn"] == 0
    finally:
        await db.close()


async def test_keepalive_and_idle_close():
    server = FakeServer()
    db = makeDb(server, keepalive=0.02, idle=0.15)
    try:
        await db.fetch("SELECT 1")
        await asyncio.sleep(0.08)
        assert server.pings >= 2
        assert server.open == 1

        # Idle too long, the connection is closed to free crt.sh's single slot.
        await asyncio.sleep(0.25)
        assert server.open == 0
        pings = server.pings
        await asyncio.sleep(0.05)
        assert server.pings == pings

        # The next query reconnects.
        assert (await db.fetch("SELECT 2"))[0]["conn"] == 1
    finally:
        await db.close()
    assert server.open == 0


async def test_statement_pooling():
    # crt.sh's PgBouncer pools by statement: explicit transactions are refused and the client
    # is disconnected (the fakes model it, like the old BEGIN READ ONLY; SET LOCAL prelude got).
    server = FakeServer()
    db = makeDb(server, statement_timeout=90)
    try:
        conn = await db._ensure()
        for sql in ("BEGIN READ ONLY; SET LOCAL statement_timeout = 0", "SAVEPOINT raw"):
            with pytest.raises(
                asyncpg.exceptions.ProtocolViolationError, match="statement pooling"
            ):
                await conn.execute(sql)
            assert conn.is_closed()
            conn = await db._ensure()
        with pytest.raises(asyncpg.exceptions.ProtocolViolationError, match="statement pooling"):
            await conn.fetch("SET LOCAL statement_timeout = 0")
        server.refused.clear()
        db._conn = None

        # So every query is one message, without a transaction block, and nothing else is
        # sent: the service's own queries set their statement_timeout (SET, then RESET) and read-only
        # mode in the same simple query as their COPY.
        assert (await db.fetch("SELECT 1"))[0]["sql"] == "SELECT 1"
        assert server.messages == [db._copyStmt("SELECT 1", ())]
        assert server.timeouts == [90000]
        assert server.executed == server.fetched == server.refused == []
        # A dropped connection is retried with the same single message.
        server.errors = [asyncpg.exceptions.ProtocolViolationError("client_idle_timeout")]
        await db.fetch("SELECT 2")
        assert server.timeouts == [90000, 90000, 90000]
        assert server.executed == server.fetched == server.refused == []
    finally:
        await db.close()


async def test_statement_timeout():
    # The default is no limit, and the arguments are inlined (a simple query has no parameters).
    server = FakeServer()
    db = makeDb(server)
    try:
        await db.fetch("SELECT $1::text, $2", "it's", 5)
        assert server.timeouts == [0]
        assert server.queries[-1][1] == "SELECT E'it''s'::text, 5"
    finally:
        await db.close()

    # A server that refuses the SETs is still used, without them, under its own timeout.
    server = FakeServer()
    server.setfail = True
    db = makeDb(server)
    try:
        assert (await db.fetch("SELECT $1", 1))[0]["conn"] == 0
        assert len(server.messages) == 1 and server.fetched == ["SELECT $1"]
        await db.fetch("SELECT 2")
        assert len(server.messages) == 1 and server.fetched == ["SELECT $1", "SELECT 2"]
        assert len(server.conns) == 1
    finally:
        await db.close()


async def test_no_copy_out(caplog):
    # An asyncpg without the protocol level copy_out gets plain queries.
    server = FakeServer()
    db = makeDb(server)
    try:
        conn = await db._ensure()
        del conn._protocol
        assert (await db.fetch("SELECT 1"))[0]["sql"] == "SELECT 1"
        assert server.fetched == ["SELECT 1"] and server.messages == []
        assert "Unable to COPY with this asyncpg" in caplog.text
    finally:
        await db.close()


async def test_query_errors():
    # A failed query ends its own implicit transaction, the connection is reused as is.
    server = FakeServer()
    db = makeDb(server)
    try:
        server.errors = [asyncpg.exceptions.UndefinedTableError('relation "nope" does not exist')]
        with pytest.raises(CrtshDbError, match="nope"):
            await db.fetch("SELECT * FROM nope")
        assert (await db.fetch("SELECT 1"))[0]["conn"] == 0

        # crt.sh canceling the query (statement timeout) too.
        server.errors = [asyncpg.exceptions.QueryCanceledError("canceling statement")]
        with pytest.raises(CrtshDbError, match="statement timeout"):
            await db.fetch("SELECT 2")
        assert (await db.fetch("SELECT 3"))[0]["conn"] == 0
        assert server.executed == server.refused == [] and len(server.conns) == 1

        # Only a refused SET (a "parameter") turns off the COPY, not other privilege errors.
        server.errors = [asyncpg.exceptions.InsufficientPrivilegeError("permission denied for ca")]
        with pytest.raises(CrtshDbError, match="permission denied for ca"):
            await db.fetch("SELECT * FROM ca")
        assert db._useCopy
    finally:
        await db.close()


def test_literals():
    assert _literal(None) == "NULL"
    assert _literal(True) == "TRUE" and _literal(False) == "FALSE"
    assert _literal(2**40) == "1099511627776" and _literal(-1) == "-1"
    assert _literal(1.5) == "'1.5'::float8" and _literal(1e20) == "'1e+20'::float8"
    # Escape strings with every backslash and quote escaped, whatever standard_conforming_strings is.
    assert _literal("it's \\' $1") == "E'it''s \\\\'' $1'"
    assert _literal(b"\x00\xff") == "E'\\\\x00ff'::bytea"
    assert _literal([1, 2]) == "ARRAY[1, 2]" and _literal([]) == "'{}'"
    assert _literal([b"\x01", None]) == "ARRAY[E'\\\\x01'::bytea, NULL]"
    for valu in (float("nan"), float("inf"), "a\x00b", [[1]], {1: 2}, object()):
        with pytest.raises(CrtshDbError):
            _literal(valu)

    # Every $n is replaced once (a literal is never rescanned), $10 isn't $1 then a 0.
    args = tuple(range(1, 11))
    assert _inline("$1 $10 $2", args) == "1 10 2"
    assert _inline("$1 $2", ("$2", "x")) == "E'$2' E'x'"
    with pytest.raises(CrtshDbError, match=r"\$3 has no argument"):
        _inline("$3", (1, 2))


def test_copy_rows():
    rows = [{"id": 1, "der": "\\x00ff", "caids": [1, 2], "n": None}, {"id": 2, "name": "\\x01"}]
    assert _copyRows(copyData(rows)) == [
        {"id": 1, "der": b"\x00\xff", "caids": [1, 2], "n": None},
        {"id": 2, "name": "\\x01"},  # Only the bytea columns are decoded.
    ]
    assert _copyRows(copyData([])) == []
    # A CA without a certificate (cas(certs=True)) has a null DER.
    assert _copyRows(copyData([{"der": None}])) == [{"der": None}]
    two = copyData([]).replace(b"\xff\xff", struct.pack("!hi", 2, 0) + b"\xff\xff")
    with pytest.raises(CrtshDbError, match="2 columns"):
        _copyRows(two)
    for data in (b"nope", copyData(rows)[:-10]):
        with pytest.raises((CrtshDbError, struct.error)):
            _copyRows(data)


async def test_cancel_drops_connection():
    # A query cancelled midway leaves the connection mid-query, so it's terminated.
    server = FakeServer()
    server.delay = 5
    db = makeDb(server)
    try:
        task = asyncio.get_running_loop().create_task(db.fetch("SELECT pg_sleep(60)"))
        await asyncio.sleep(0.2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert db._conn is None and server.terminated == 1 and server.open == 0

        # The next query gets a new connection.
        server.delay = 0.01
        assert (await db.fetch("SELECT 1"))[0]["conn"] == 1
    finally:
        await db.close()


async def test_keepalive_edges():
    # The keepalive skips its ping while a query is running.
    server = FakeServer()
    server.delay = 0.1
    db = makeDb(server, keepalive=0.02)
    try:
        await db.fetch("SELECT 1")
        assert server.pings == 0
        server.delay = 0.01

        # The connection died under the keepalive, it stops until the next query.
        server.conns[0].closed = True
        server.open -= 1
        await asyncio.sleep(0.06)
        assert db._keeper.done()
        assert (await db.fetch("SELECT 2"))[0]["conn"] == 1

        # A failed ping drops the connection.
        server.pingfail = True
        await asyncio.sleep(0.06)
        assert server.open == 0 and db._conn is None
    finally:
        await db.close()


async def test_drop_edges():
    # Closing a connection that won't close cleanly terminates it.
    server = FakeServer()
    db = makeDb(server)
    await db.fetch("SELECT 1")
    server.closefail = True
    await db.close()
    assert server.terminated == 1 and server.open == 0

    # Client side timeouts drop the connection, it's mid-query.
    server = FakeServer()
    db = makeDb(server, timeout=1)
    server.errors = [TimeoutError()]
    with pytest.raises(CrtshDbError, match="timed out after 1s"):
        await db.fetch("SELECT 1")
    assert db._conn is None and server.conns[0].closed
    await db.close()

    # Errors that aren't from the database are bugs, they're raised as-is, and the
    # connection (in an unknown state) is dropped.
    server = FakeServer()
    db = makeDb(server)
    server.errors = [ValueError("bug")]
    with pytest.raises(ValueError, match="bug"):
        await db.fetch("SELECT 1")
    assert db._conn is None and server.open == 0
    await db.close()


class Recorder(CrtshDb):
    """A CrtshDb that records the SQL it would run."""

    def __init__(self, rows=None):
        super().__init__()
        self.queries: list[tuple[str, tuple]] = []
        self.raws: list[bool] = []
        self.rows = rows or []

    async def fetch(self, sql, *args, raw=False):
        self.queries.append((sql, args))
        self.raws.append(raw)
        if not raw:
            # The service's own queries are inlined into a COPY, every $n must have an argument.
            assert not PARAM_RE.search(_inline(sql, args))
        return self.rows

    @property
    def sql(self) -> str:
        return self.queries[-1][0]

    @property
    def args(self) -> tuple:
        return self.queries[-1][1]


def assertMeta(sql: str, extra: str = ""):
    """The query returns its certificates with their metadata, in one round trip."""

    assert " m AS MATERIALIZED (" in sql
    assert f"SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der{extra}," in sql
    assert "ca.NAME AS issuer_name" in sql
    assert (
        "ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids"
        in sql
    )
    assert "FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID" in sql
    assert "cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)" in sql
    assert sql.endswith("FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID")


async def test_sql_certs():
    db = Recorder()
    for kind, cond in LOOKUPS.items():
        await db.certs({kind: [b"\x01"]}, limit=5)
        assertMeta(db.sql)
        assert (
            f"SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE "
            f"({cond.format(c='c', p='$1')}) LIMIT $2"
        ) in db.sql
        assert db.args == ([b"\x01"], 5)

    # Several kinds are one query.
    await db.certs({"id": [1], "sha256": [b"\x02"]}, limit=3)
    assert len(db.queries) == len(LOOKUPS) + 1
    assert (
        "WHERE (c.ID = ANY($1::bigint[]) OR digest(c.CERTIFICATE, 'sha256') = ANY($2::bytea[])) LIMIT $3"
        in db.sql
    )
    assert db.args == ([1], [b"\x02"], 3)

    with pytest.raises(CrtshDbError, match="Unknown lookup type"):
        await db.certs({"nope": [1]})


async def test_sql_identity():
    db = Recorder()

    # Full text search alone queries the certificate table.
    await db.certsByIdentity("*.vertex.link", limit=10)
    assertMeta(db.sql)
    assert (
        "(SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE "
        "plainto_tsquery('certwatch', $1) @@ identities(c.CERTIFICATE) LIMIT $2)"
    ) in db.sql
    assert db.args == ("vertex.link", 10)

    # Identity matching goes through certificate_and_identities, like crt.sh's own search.
    await db.certsByIdentity(
        "vertex.link",
        like="%vertex.link",
        nametypes=NAME_TYPES["dns"],
        caids=[2, 3],
        issuer="Let's_Encrypt",
        valid=True,
        since=1000,
        until=2000,
        limit=50,
    )
    sql = db.sql
    assertMeta(sql)
    assert "FROM certificate_and_identities c WHERE" in sql
    assert "c.NAME_VALUE ILIKE $2 AND c.NAME_TYPE = ANY($3::text[])" in sql
    assert f"{NOTAFTER_KEY} >= date_trunc('year', now() AT TIME ZONE 'UTC')" in sql
    assert "x509_notBefore(c.CERTIFICATE) >= to_timestamp($4) AT TIME ZONE 'UTC'" in sql
    assert f"{NOTAFTER_KEY} >= to_timestamp($4) AT TIME ZONE 'UTC'" in sql
    assert "x509_notBefore(c.CERTIFICATE) < to_timestamp($5) AT TIME ZONE 'UTC'" in sql
    # The issuer filters the materialized candidates, it isn't part of their scan: nothing
    # indexes a word and an issuer together, so a common word and a rare issuer would recheck
    # every certificate with the word.
    cand = sql.split("cand AS MATERIALIZED (", 1)[1].split("LIMIT $6)", 1)[0]
    assert "ISSUER_CA_ID =" not in cand and "ISSUER_CA_ID IN" not in cand
    assert (
        "SELECT cand.ID, cand.ISSUER_CA_ID, cand.CERTIFICATE FROM cand WHERE "
        "cand.ISSUER_CA_ID = ANY($7::int[]) AND "
        # The issuer's name is a subquery, not another round trip.
        "cand.ISSUER_CA_ID IN (SELECT ca.ID FROM ca WHERE ca.NAME ILIKE $8 LIMIT 1000) "
        "GROUP BY cand.ID, cand.ISSUER_CA_ID, cand.CERTIFICATE"
    ) in sql
    assert db.args == (
        "vertex.link",
        "%vertex.link",
        ["san:dNSName", "2.5.4.3"],
        1.0,
        2.0,
        50,
        [2, 3],
        "%Let's\\_Encrypt%",
    )

    # Identities without an issuer are still grouped from the candidates.
    await db.certsByIdentity("vertex.link", like="%vertex.link", limit=5)
    assert "FROM cand GROUP BY cand.ID" in db.sql
    assert "FROM cand WHERE" not in db.sql

    # Full text search alone with an issuer.
    await db.certsByIdentity("vertex.link", issuer="Sectigo", limit=5)
    assert (
        "cand AS MATERIALIZED (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE "
        "plainto_tsquery('certwatch', $1) @@ identities(c.CERTIFICATE) LIMIT $2)"
    ) in db.sql
    assert "FROM cand WHERE cand.ISSUER_CA_ID IN (SELECT ca.ID" in db.sql
    assert "GROUP BY" not in db.sql.split("FROM cand", 1)[1].split("SELECT m.ID", 1)[0]

    # Expiry bounds are on notAfter, and on the partition key so partitions are pruned, inside
    # the candidates' LIMIT. The issuer still filters after it.
    await db.certsByIdentity(
        "vertex.link", issuer="Sectigo", expires_after=1000, expires_before=2000, limit=5
    )
    cand = db.sql.split("cand AS MATERIALIZED (", 1)[1].split(" LIMIT $4)", 1)[0]
    assert (
        "x509_notAfter(c.CERTIFICATE) >= to_timestamp($2) AT TIME ZONE 'UTC' AND "
        f"{NOTAFTER_KEY} >= to_timestamp($2) AT TIME ZONE 'UTC' AND "
        "x509_notAfter(c.CERTIFICATE) < to_timestamp($3) AT TIME ZONE 'UTC' AND "
        f"{NOTAFTER_KEY} < to_timestamp($3) AT TIME ZONE 'UTC'"
    ) in cand
    assert "FROM cand WHERE cand.ISSUER_CA_ID IN (SELECT ca.ID" in db.sql
    assert db.args == ("vertex.link", 1.0, 2.0, 5, "%Sectigo%")
    await db.certsByIdentity("vertex.link", expires_before=2000, limit=5)
    assert f"{NOTAFTER_KEY} < to_timestamp($2) AT TIME ZONE 'UTC'" in db.sql
    assert f"{NOTAFTER_KEY} >=" not in db.sql

    # A prefix is a tsquery literal (not to_tsquery, see prefixQuery), quoted so no user text
    # is tsquery syntax.
    await db.certsByIdentity("microsoft*", valid=True, limit=5)
    assert (
        "WHERE $1::tsquery @@ identities(c.CERTIFICATE) AND "
        f"{NOTAFTER_KEY} >= date_trunc('year', now() AT TIME ZONE 'UTC')"
    ) in db.sql
    assert db.args == ("'microsoft':*", 5)
    # With plain words, both are required.
    await db.certsByIdentity("login micro*", like="%micro%", since=1000, limit=5)
    assert (
        "(plainto_tsquery('certwatch', $1) && $2::tsquery) @@ identities(c.CERTIFICATE)"
        " AND c.NAME_VALUE ILIKE $3 AND x509_notBefore(c.CERTIFICATE) >= to_timestamp($4)"
    ) in db.sql
    assert db.args == ("login", "'micro':*", "%micro%", 1.0, 5)
    await db.certsByIdentity("x') | !('y\\*", limit=5)
    assert db.args == ("x') |", "'!(''y\\\\':*", 5)

    # Name types alone still check each identity.
    await db.certsByIdentity("Sectigo", nametypes=["2.5.4.10"])
    assert "certificate_and_identities" in db.sql


async def test_sql_issuer():
    db = Recorder()
    edb = Recorder()
    await edb.certsByIssuer(caids=[2], expires_after=1000, expires_before=2000, limit=10)
    assert (
        f"{NOTAFTER_KEY} >= to_timestamp($2) AT TIME ZONE 'UTC' AND "
        "x509_notAfter(c.CERTIFICATE) < to_timestamp($3) AT TIME ZONE 'UTC' AND "
        f"{NOTAFTER_KEY} < to_timestamp($3) AT TIME ZONE 'UTC' ORDER BY"
    ) in edb.sql

    await db.certsByIssuer(
        caids=[2, 3], issuer="Sectigo", cert={"sha256": [b"\x01"]}, valid=True, until=2000, limit=10
    )
    sql = db.sql
    assert len(db.queries) == 1
    assertMeta(sql)
    # Every CA source in one query, each CA is LATERAL joined so its index is walked newest first.
    assert "FROM (SELECT unnest($1::int[]) AS CA_ID UNION " in sql
    assert (
        "SELECT ID AS CA_ID FROM (SELECT ca.ID FROM ca WHERE ca.NAME ILIKE $2 LIMIT 1000) named UNION "
        in sql
    )
    assert (
        "SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = "
        "(SELECT s.ID FROM certificate s WHERE (digest(s.CERTIFICATE, 'sha256') = ANY($3::bytea[])) LIMIT 1)"
    ) in sql
    assert (
        ") cas CROSS JOIN LATERAL (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c "
        in sql
    )
    assert "WHERE c.ISSUER_CA_ID = cas.CA_ID AND " in sql
    assert "ANY($1::int[])" not in sql.split("LATERAL")[1]
    assert "ORDER BY x509_notBefore(c.CERTIFICATE) DESC LIMIT $5) c" in sql
    assert db.args == ([2, 3], "%Sectigo%", [b"\x01"], 2.0, 10)

    with pytest.raises(CrtshDbError, match="CA ID, CA name, or CA certificate"):
        await db.certsByIssuer()


async def test_sql_related():
    db = Recorder()
    await db.related("key", {"id": [10]}, valid=True, limit=5)
    sql = db.sql
    assertMeta(sql)
    # The source certificate's key is a subquery, and the source itself is excluded.
    assert (
        "WHERE digest(x509_publicKey(c.CERTIFICATE), 'sha256') = (SELECT digest(x509_publicKey(s.CERTIFICATE), "
        "'sha256') FROM certificate s WHERE (s.ID = ANY($1::bigint[])) LIMIT 1) "
        "AND NOT (c.ID = ANY($1::bigint[])) AND "
    ) in sql
    assert "x509_notAfter(c.CERTIFICATE) >= now() AT TIME ZONE 'UTC'" in sql
    assert "ORDER BY" not in sql.split("MATERIALIZED")[1].split("SELECT m.ID")[0]
    assert db.args == ([10], 5)

    await db.related("siblings", {"sha1": [b"\x01"]})
    assert "WHERE c.ISSUER_CA_ID = (SELECT s.ISSUER_CA_ID FROM certificate s" in db.sql
    assert "ORDER BY x509_notBefore(c.CERTIFICATE) DESC LIMIT $2" in db.sql

    for by, expr in (
        ("subject", "digest(x509_name(c.CERTIFICATE), 'sha1')"),
        ("serial", "x509_serialNumber(c.CERTIFICATE)"),
        ("ski", "x509_subjectKeyIdentifier(c.CERTIFICATE)"),
    ):
        await db.related(by, {"id": [1]})
        assert f"WHERE {expr} = (SELECT " in db.sql

    with pytest.raises(CrtshDbError, match="Unknown pivot"):
        await db.related("nope", {"id": [1]})


async def test_sql_chain():
    db = Recorder()
    await db.chain({"sha256": [b"\x01"]}, maxdepth=4)
    sql = db.sql
    assertMeta(sql, extra=", m.CHILD_ID AS child_id, m.DEPTH AS depth")
    assert sql.startswith(
        "WITH RECURSIVE chain AS ((SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE, "
        "NULL::bigint AS CHILD_ID, 0 AS DEPTH, ARRAY[c.ID] AS PATH FROM certificate c WHERE "
        "(digest(c.CERTIFICATE, 'sha256') = ANY($1::bytea[])) LIMIT 1) UNION ALL "
    )
    # Cross-signing CAs can cycle, a certificate is never revisited on its path.
    assert (
        "SELECT p.ID, p.ISSUER_CA_ID, p.CERTIFICATE, ch.ID, ch.DEPTH + 1, ch.PATH || p.ID FROM chain ch"
        in sql
    )
    assert (
        "JOIN ca_certificate cac ON cac.CA_ID = ch.ISSUER_CA_ID JOIN certificate p ON p.ID = cac.CERTIFICATE_ID"
        in sql
    )
    # Self-issued roots end the chain.
    assert (
        "WHERE ch.DEPTH < $2 AND NOT p.ID = ANY(ch.PATH) AND NOT EXISTS (SELECT 1 FROM ca_certificate r "
        "WHERE r.CERTIFICATE_ID = ch.ID AND r.CA_ID = ch.ISSUER_CA_ID))"
    ) in sql
    assert (
        ", m AS MATERIALIZED (SELECT ID, ISSUER_CA_ID, CERTIFICATE, CHILD_ID, DEPTH FROM chain LIMIT $3)"
        in sql
    )
    assert db.args == ([b"\x01"], 4, 500)


async def test_sql_cas():
    db = Recorder()
    await db.cas(caids=[2], name="Let's 100%", limit=5)
    assert db.sql == (
        "WITH cas AS MATERIALIZED (SELECT ca.ID, ca.NAME FROM ca WHERE ca.ID = ANY($1::int[]) "
        "OR ca.NAME ILIKE $2 ORDER BY ca.ID LIMIT $3) SELECT cas.ID AS ca_id, cas.NAME AS "
        "ca_name, cac.CERTIFICATE_ID AS id FROM cas LEFT JOIN ca_certificate cac ON cac.CA_ID = cas.ID"
    )
    assert db.args == ([2], "%Let's 100\\%%", 5)

    await db.cas(name="x", certs=True)
    assertMeta(db.sql, extra=", m.CA_ID AS ca_id, m.CA_NAME AS ca_name")
    assert db.sql.startswith(
        "WITH cas AS MATERIALIZED (SELECT ca.ID, ca.NAME FROM ca WHERE ca.NAME ILIKE $1 "
    )
    assert "LEFT JOIN certificate c ON c.ID = cac.CERTIFICATE_ID" in db.sql

    with pytest.raises(CrtshDbError, match="name or ID"):
        await db.cas()


async def test_sql_raw():
    # Raw SQL is wrapped so it can only be a query, and its rows are capped.
    db = Recorder()
    await db.raw("SELECT $1", [1])
    assert db.queries[-1] == (RAW_SQL.format(sql="SELECT $1", limit="$2"), (1, 1000))
    assert "SELECT * FROM (\nSELECT $1\n) q WHERE (SELECT crtsh_pre.ro" in db.sql
    await db.raw("SELECT 1 -- a comment;\n ;", limit=5)
    assert db.queries[-1] == (RAW_SQL.format(sql="SELECT 1 -- a comment", limit="$1"), (5,))
    with pytest.raises(CrtshDbError, match="No SQL"):
        await db.raw(" ; ")
    # Raw queries keep their parameters (they're never inlined), the others are COPYs.
    assert db.raws == [True, True]
    await db.cas(name="Test")
    assert db.raws[-1] is False

    # Session advisory locks outlive the rollback, so they're refused.
    for sql in (
        "SELECT pg_advisory_lock(1)",
        "select PG_TRY_ADVISORY_LOCK_SHARED (1, 2)",
        'SELECT pg_catalog."pg_advisory_lock"(1)',
        # Comments and whitespace between the name and its parenthesis.
        "SELECT pg_advisory_lock/**/(1)",
        "SELECT pg_advisory_lock /* a /* nested */ comment */ (1)",
        "SELECT pg_try_advisory_lock\n-- a comment\n\t (1)",
        "SELECT pg_advisory_lock_shared\n\n(1)",
        'SELECT "pg_advisory_lock"/**/(1)',
        # Unicode escaped names (U&"pg\0061dvisory_lock"), in either case.
        r'SELECT U&"pg\0061dvisory_lock"(1)',
        "SELECT u&\"pg!0061dvisory_lock\" UESCAPE '!' (1)",
    ):
        with pytest.raises(CrtshDbError, match="advisory locks"):
            await db.raw(sql)
    # Other advisory lock functions, and names that only contain a refused one, are fine.
    await db.raw("SELECT pg_advisory_xact_lock(1), pg_advisory_unlock(1)")
    await db.raw("SELECT pg_try_advisory_xact_lock_shared(1) AS pg_advisory_lock_count")
    await db.raw('SELECT "u&x" FROM t')


async def test_raw_single_statement():
    # A raw query is one extended protocol statement (RAW_SQL undoes what it changed, inside
    # it), with nothing before or after it.
    server = FakeServer()
    db = makeDb(server, statement_timeout=60)
    try:
        rows = await db.raw("SELECT set_config('search_path', 'pg_catalog', false)")
        assert rows == [{"sql": rows[0]["sql"], "conn": 0}]
        assert server.fetched == [rows[0]["sql"]] and rows[0]["sql"].startswith("WITH crtsh_pre")
        assert server.executed == server.messages == server.refused == []

        # A failed raw query can't release the session locks it took in its statement, so
        # they're released by the next one (behind statement pooling, maybe on another server
        # connection), and the connection is reused.
        server.errors = [asyncpg.exceptions.DivisionByZeroError("division by zero")]
        with pytest.raises(CrtshDbError, match="division by zero"):
            await db.raw("SELECT 1/0")
        assert server.executed == ["SELECT pg_advisory_unlock_all()"]
        assert db._conn is not None and server.refused == []

        # If that fails, the connection is dropped (which ends the session outside PgBouncer).
        server.failon = {"SELECT pg_advisory_unlock_all()"}
        server.errors = [asyncpg.exceptions.DivisionByZeroError("division by zero")]
        with pytest.raises(CrtshDbError, match="division by zero"):
            await db.raw("SELECT 1/0")
        assert db._conn is None and server.open == 0
        server.failon = set()
        assert (await db.fetch("SELECT 1"))[0]["conn"] == 1
    finally:
        await db.close()


def test_tsquery():
    assert tsquery(" *.vertex.link ") == ("vertex.link", [])
    assert tsquery("%.vertex.link") == ("vertex.link", [])
    assert tsquery("a%b*c") == ("a b c", [])
    # Only a trailing * makes a prefix, and only of a word with something to index.
    assert tsquery("microsoft*") == ("", ["microsoft"])
    assert tsquery("*.microsoft*") == ("", ["microsoft"])
    assert tsquery("login.Microsoft** corp") == ("corp", ["login.Microsoft"])
    assert tsquery("a*b* c") == ("a c", ["b"])
    assert tsquery("-* *") == ("-", [])
    assert prefixQuery(["Microsoft", "it's", "a\\b", "x') | !(y"]) == (
        "'microsoft':* & 'it''s':* & 'a\\\\b':* & 'x'') | !(y':*"
    )
    # Punctuation stays in the one lexeme, it isn't split into a phrase.
    assert prefixQuery(["Microsoft-Sup"]) == "'microsoft-sup':*"
    assert likeEscape("a_b%c\\") == "a\\_b\\%c\\\\"


def test_identity_text():
    # The fakes index what crt.sh's identities() (certwatch_db fnc/identities.fnc) does: each
    # identity longest first, the reverse of names that aren't domains, an email's domain and
    # reverse, and every parent domain down to the TLD with the first parent's reverse
    # (unless that's already in the text, as "knil." is after the email).
    assert identityText(PKI.certs[10]).split(" ") == [
        ":2001:db8:0:0:0:0:0:1",
        "1:0:0:0:0:0:8bd:1002:",
        "https://vertex.link/",
        "/knil.xetrev//:sptth",
        "the", "vertex", "project", "tcejorp", "xetrev", "eht",
        "visi@vertex.link", "vertex.link", "knil.xetrev@isiv", "link",
        "www.vertex.link", "vertex.link", "knil.xetrev", "link",
        "*.vertex.link", "vertex.link", "knil.xetrev", "link",
        "engineering", "gnireenigne",
        "vertex.link", "link",
        "1.2.3.4", "4.3.2.1",
        "us", "su",
    ]  # fmt: skip


# crt.sh's live identities() tokens (strip(identities(CERTIFICATE)) on the live certwatch DB) for
# a test certificate with every identity type and two real certificates (crt.sh IDs 29550673 and
# 30258460), captured 2026-11-17 for the identities() port (identityText) and tsTokens().
LIVE_IDENTITIES = json.loads(
    (pathlib.Path(__file__).parent / "data" / "live_identities.json").read_text()
)["certs"]


@pytest.mark.parametrize("live", LIVE_IDENTITIES, ids=lambda live: live["name"])
def test_identity_tokens_live(live):
    cert = x509.load_der_x509_certificate(base64.b64decode(live["der"]))
    assert tsTokens(identityText(cert)) == set(live["tokens"])


def test_ts_tokens():
    # PostgreSQL's default parser, as to_tsvector('simple', ...) gives them.
    cases = {
        # An @ whose domain has no dot isn't an email address; : separates words.
        "knil.xetrev@ecila 1111:0:0:0074:6062:": {"knil.xetrev", "ecila", "1111", "0", "0074", "6062"},
        "visi@mail.vertex.link a+b@x.com": {"visi@mail.vertex.link", "a", "b@x.com"},
        # A URL is its host/path, host and path; a reversed one is a file path and its scheme.
        "https://vertex.link:8443/a?b=1": {"vertex.link:8443/a?b=1", "vertex.link:8443", "/a?b=1"},
        "htap/knil.xetrev.iru//:sptth": {"htap/knil.xetrev.iru", "sptth"},
        # (A ./ or ~/ only starts a path at the start of a token, not after a blank.)
        "a.b/c ./x ~/y /etc/passwd": {"a.b/c", "/x", "/y", "/etc/passwd"},
        "./x": {"./x"},
        # Hosts need a TLD of 2+ letters, else they're file paths (or numbers).
        "a.b foo.com1 1.2.3.com 1.1.861.291 1e5.com": {
            "a.b", "foo.com1", "1.2.3.com", "1.1.861.291", "1e5", "com",
        },
        "Let's Encrypt, AT&T Inc. &amp;": {"let", "s", "encrypt", "at", "t", "inc"},
        "Foo-Bar co-op.coop a-b-12 x -5": {
            "foo-bar", "foo", "bar", "co-op.coop", "a-b", "a", "b", "12", "x", "-5",
        },
        "über-straße 株式会社 naïve2": {"über-straße", "über", "straße", "株式会社", "naïve2"},
    }  # fmt: skip
    for text, tokens in cases.items():
        assert tsTokens(text) == tokens, text
