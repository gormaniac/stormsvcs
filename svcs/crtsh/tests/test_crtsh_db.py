"""Pytests for CrtshDb's connection handling, against fake connections.

crt.sh's PgBouncer allows one connection per client, drops idle clients
(client_idle_timeout), and refuses quick reconnects (max_client_conn).
"""

import asyncio

import asyncpg
import pytest

from crtshsvc.db import (CERT_COLS, LOOKUPS, NAME_TYPES, NOTAFTER_KEY, CrtshDb, CrtshDbError,
                         likeEscape, tsquery)


class FakeConn:
    """A fake asyncpg connection that runs scripted results."""

    def __init__(self, server, num: int):
        self.server = server
        self.num = num
        self.closed = False
        self.pings = 0

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

    async def fetch(self, sql, *args, timeout=None):
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

    async def fetchval(self, sql, timeout=None):
        if self.server.pingfail:
            raise asyncpg.exceptions.ProtocolViolationError("client_idle_timeout")
        self.pings += 1
        self.server.pings += 1
        return 1


class FakeServer:
    """Hands out FakeConns, refusing connections like crt.sh's PgBouncer."""

    def __init__(self, refusals: int = 0, refusal: str = "no more connections allowed (max_client_conn)"):
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

    async def connect(self, dsn, **kwargs):
        self.attempts += 1
        assert kwargs["statement_cache_size"] == 0
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
        server.errors = [asyncpg.exceptions.SerializationError("canceling statement due to conflict")]
        assert (await db.fetch("SELECT 1"))[0]["conn"] == 0

        # Too many drops in a row give up.
        server.errors = [asyncpg.exceptions.ProtocolViolationError("client_idle_timeout")] * 3
        with pytest.raises(CrtshDbError, match="client_idle_timeout"):
            await db.fetch("SELECT 2")

        # SQL errors aren't retried.
        server.errors = [asyncpg.exceptions.UndefinedTableError('relation "nope" does not exist')]
        with pytest.raises(CrtshDbError, match="nope"):
            await db.fetch("SELECT * FROM nope")
        server.errors = [asyncpg.exceptions.QueryCanceledError("canceling statement due to statement timeout")]
        with pytest.raises(CrtshDbError, match="statement timeout"):
            await db.fetch("SELECT 3")
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
    server.errors = [asyncio.TimeoutError()]
    with pytest.raises(CrtshDbError, match="timed out after 1s"):
        await db.fetch("SELECT 1")
    assert db._conn is None and server.conns[0].closed
    await db.close()

    # Errors that aren't from the database are bugs, they're raised as-is.
    server = FakeServer()
    db = makeDb(server)
    server.errors = [ValueError("bug")]
    with pytest.raises(ValueError, match="bug"):
        await db.fetch("SELECT 1")
    await db.close()


class Recorder(CrtshDb):
    """A CrtshDb that records the SQL it would run."""

    def __init__(self, rows=None):
        super().__init__()
        self.queries: list[tuple[str, tuple]] = []
        self.rows = rows or []

    async def fetch(self, sql, *args):
        self.queries.append((sql, args))
        return self.rows


async def test_sql_certs():
    db = Recorder()
    for kind, clause in LOOKUPS.items():
        await db.certs(kind, [b"\x01"], limit=5)
        sql, args = db.queries[-1]
        assert sql == f"SELECT {CERT_COLS} FROM certificate c WHERE {clause} LIMIT $2"
        assert args == ([b"\x01"], 5)

    with pytest.raises(CrtshDbError, match="Unknown lookup type"):
        await db.certs("nope", [1])


async def test_sql_identity():
    db = Recorder()

    # Full text search alone queries the certificate table.
    await db.certsByIdentity("*.vertex.link", limit=10)
    sql, args = db.queries[-1]
    assert sql == (f"SELECT {CERT_COLS} FROM certificate c WHERE "
                   "plainto_tsquery('certwatch', $1) @@ identities(c.CERTIFICATE) LIMIT $2")
    assert args == ("vertex.link", 10)

    # Identity matching goes through certificate_and_identities, like crt.sh's own search.
    await db.certsByIdentity("vertex.link", like="%vertex.link", nametypes=NAME_TYPES["dns"],
                             caids=[2, 3], valid=True, since=1000, until=2000, limit=50)
    sql, args = db.queries[-1]
    assert "FROM certificate_and_identities c WHERE" in sql
    assert "c.NAME_VALUE ILIKE $2 AND c.NAME_TYPE = ANY($3::text[])" in sql
    assert "c.ISSUER_CA_ID = ANY($4::int[])" in sql
    assert f"{NOTAFTER_KEY} >= date_trunc('year', now() AT TIME ZONE 'UTC')" in sql
    assert "x509_notBefore(c.CERTIFICATE) >= to_timestamp($5) AT TIME ZONE 'UTC'" in sql
    assert f"{NOTAFTER_KEY} >= to_timestamp($5) AT TIME ZONE 'UTC'" in sql
    assert "x509_notBefore(c.CERTIFICATE) < to_timestamp($6) AT TIME ZONE 'UTC'" in sql
    assert "LIMIT $7) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE" in sql
    assert args == ("vertex.link", "%vertex.link", ["san:dNSName", "2.5.4.3"], [2, 3], 1.0, 2.0, 50)

    # Name types alone still check each identity.
    await db.certsByIdentity("Sectigo", nametypes=["2.5.4.10"])
    assert "certificate_and_identities" in db.queries[-1][0]


async def test_sql_issuer():
    db = Recorder(rows=[{"id": 1}])
    rows = await db.certsByIssuer([2, 3], valid=True, until=2000, limit=10)
    # One query per CA, so PostgreSQL 12 can walk the index newest first.
    assert len(db.queries) == 2 and len(rows) == 2
    sql, args = db.queries[0]
    assert sql.startswith(f"SELECT {CERT_COLS} FROM certificate c WHERE c.ISSUER_CA_ID = $1 AND ")
    assert "ANY" not in sql
    assert sql.endswith("ORDER BY x509_notBefore(c.CERTIFICATE) DESC LIMIT $3")
    assert args == (2, 2.0, 10)
    assert db.queries[1][1] == (3, 2.0, 10)


async def test_sql_meta():
    db = Recorder()
    await db.caCerts([2])
    assert "FROM ca_certificate cac JOIN certificate c ON c.ID = cac.CERTIFICATE_ID" in db.queries[-1][0]
    assert db.queries[-1][1] == ([2],)

    await db.certCas([10])
    assert "WHERE cac.CERTIFICATE_ID = ANY($1::bigint[])" in db.queries[-1][0]

    await db.cas([1])
    assert db.queries[-1] == ("SELECT ca.ID AS id, ca.NAME AS name FROM ca WHERE ca.ID = ANY($1::int[])", ([1],))

    await db.casByName("Let's 100%_\\", limit=5)
    assert db.queries[-1][1] == ("%Let's 100\\%\\_\\\\%", 5)

    await db.ctlog([10])
    assert "JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID" in db.queries[-1][0]

    count = len(db.queries)
    assert await db.revoked([]) == []
    assert len(db.queries) == count
    await db.revoked([(2, b"\x01"), (3, b"\x02")])
    assert "JOIN unnest($1::int[], $2::bytea[]) AS p(ca_id, serial)" in db.queries[-1][0]
    assert db.queries[-1][1] == ([2, 3], [b"\x01", b"\x02"])

    await db.raw("SELECT $1", [1])
    assert db.queries[-1] == ("SELECT $1", (1,))
    await db.raw("SELECT 1")
    assert db.queries[-1] == ("SELECT 1", ())


def test_tsquery():
    assert tsquery(" *.vertex.link ") == "vertex.link"
    assert tsquery("%.vertex.link") == "vertex.link"
    assert tsquery("a%b*c") == "a b c"
    assert likeEscape("a_b%c\\") == "a\\_b\\%c\\\\"
