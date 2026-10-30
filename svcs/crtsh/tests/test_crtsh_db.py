"""Pytests for CrtshDb's connection handling, against fake connections.

crt.sh's PgBouncer allows one connection per client, drops idle clients
(client_idle_timeout), and refuses quick reconnects (max_client_conn).
"""

import asyncio

import asyncpg
import pytest

from crtshsvc.db import CrtshDb, CrtshDbError


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
        self.closed = True
        self.server.open -= 1

    def terminate(self):  # pragma: no cover
        self.closed = True

    async def fetch(self, sql, *args, timeout=None):
        assert not self.closed
        assert not self.server.busy, "Queries must never overlap on the single connection."
        self.server.busy = True
        try:
            await asyncio.sleep(0.01)
            self.server.queries.append((self.num, sql))
            if self.server.errors:
                err = self.server.errors.pop(0)
                if err is not None:
                    raise err
            return [{"sql": sql, "conn": self.num}]
        finally:
            self.server.busy = False

    async def fetchval(self, sql, timeout=None):
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
