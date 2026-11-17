"""Pytests for CrtshDb's connection handling, against fake connections.

crt.sh's PgBouncer allows one connection per client, drops idle clients
(client_idle_timeout), and refuses quick reconnects (max_client_conn).
"""

import asyncio
import base64
import json
import pathlib

import asyncpg
import pytest
from cryptography import x509

from crtshsvc.db import (
    LOOKUPS,
    NAME_TYPES,
    NOTAFTER_KEY,
    CrtshDb,
    CrtshDbError,
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
            return [FakeRecord(sql=sql, conn=self.num)]
        finally:
            self.server.busy = False

    async def execute(self, sql):
        assert not self.closed
        self.server.executed.append(sql)
        if self.server.setfail and "SET" in sql:
            raise asyncpg.exceptions.InsufficientPrivilegeError(
                "permission denied to set parameter"
            )
        if self.server.rollbackfail and sql == "ROLLBACK":
            raise OSError("connection lost")
        if sql in self.server.failon:
            raise OSError("connection lost")

    async def fetchval(self, sql, timeout=None):
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
        self.executed: list[str] = []
        self.setfail = False
        self.rollbackfail = False
        self.failon: set[str] = set()

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
        assert len(server.conns) == 1 and "ROLLBACK" in server.executed
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


BEGIN = "BEGIN READ ONLY; SET LOCAL statement_timeout = {}"
RAW_END = ["SAVEPOINT raw", "SELECT pg_advisory_unlock_all()", "ROLLBACK"]


async def test_statement_timeout():
    # crt.sh's default statement_timeout cancels big queries, so every query sets its own,
    # with SET LOCAL in a read-only transaction (a session SET is lost behind transaction pooling).
    server = FakeServer()
    db = makeDb(server, statement_timeout=90)
    try:
        await db.fetch("SELECT 1")
        assert server.executed == [BEGIN.format(90000), "COMMIT"]
        # A dropped connection's transaction is rolled back, and the retry sets it again.
        server.executed.clear()
        server.errors = [asyncpg.exceptions.ProtocolViolationError("client_idle_timeout")]
        await db.fetch("SELECT 2")
        assert server.executed == [BEGIN.format(90000), "ROLLBACK", BEGIN.format(90000), "COMMIT"]
        assert len(server.conns) == 2
    finally:
        await db.close()

    # The default is no limit, and a server that refuses the SET is still used, without it.
    server = FakeServer()
    server.setfail = True
    db = makeDb(server)
    try:
        assert (await db.fetch("SELECT 1"))[0]["conn"] == 0
        assert server.executed == [BEGIN.format(0), "ROLLBACK", "BEGIN READ ONLY", "COMMIT"]
        server.executed.clear()
        await db.fetch("SELECT 2")
        assert server.executed == ["BEGIN READ ONLY", "COMMIT"]
    finally:
        await db.close()

    # A refused SET whose ROLLBACK fails drops the connection, and the query is retried.
    server = FakeServer()
    server.setfail = True
    server.rollbackfail = True
    db = makeDb(server)
    try:
        assert (await db.fetch("SELECT 1"))[0]["conn"] == 1
    finally:
        await db.close()


async def test_transaction_errors():
    # A failed query rolls its transaction back, and the connection is reused.
    server = FakeServer()
    db = makeDb(server)
    try:
        server.errors = [asyncpg.exceptions.UndefinedTableError('relation "nope" does not exist')]
        with pytest.raises(CrtshDbError, match="nope"):
            await db.fetch("SELECT * FROM nope")
        assert server.executed[-1] == "ROLLBACK"
        assert (await db.fetch("SELECT 1"))[0]["conn"] == 0

        # crt.sh canceling the query (statement timeout) rolls back too.
        server.errors = [asyncpg.exceptions.QueryCanceledError("canceling statement")]
        with pytest.raises(CrtshDbError, match="statement timeout"):
            await db.fetch("SELECT 2")
        assert server.executed[-1] == "ROLLBACK"
        assert (await db.fetch("SELECT 3"))[0]["conn"] == 0

        # A ROLLBACK that fails drops the connection.
        server.rollbackfail = True
        server.errors = [asyncpg.exceptions.UndefinedTableError('relation "nope" does not exist')]
        with pytest.raises(CrtshDbError, match="nope"):
            await db.fetch("SELECT * FROM nope")
        assert db._conn is None and server.open == 0
    finally:
        await db.close()


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
        self.commits: list[bool] = []
        self.rows = rows or []

    async def fetch(self, sql, *args, commit=True):
        self.queries.append((sql, args))
        self.commits.append(commit)
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

    # A prefix is a to_tsquery operand, quoted so no user text is tsquery syntax.
    await db.certsByIdentity("microsoft*", valid=True, limit=5)
    assert (
        "WHERE to_tsquery('certwatch', $1) @@ identities(c.CERTIFICATE) AND "
        f"{NOTAFTER_KEY} >= date_trunc('year', now() AT TIME ZONE 'UTC')"
    ) in db.sql
    assert db.args == ("'microsoft':*", 5)
    # With plain words, both are required.
    await db.certsByIdentity("login micro*", like="%micro%", since=1000, limit=5)
    assert (
        "(plainto_tsquery('certwatch', $1) && to_tsquery('certwatch', $2)) @@ identities(c.CERTIFICATE)"
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
    assert db.queries[-1] == ("SELECT * FROM (\nSELECT $1\n) q LIMIT $2", (1, 1000))
    await db.raw("SELECT 1 -- a comment;\n ;", limit=5)
    assert db.queries[-1] == ("SELECT * FROM (\nSELECT 1 -- a comment\n) q LIMIT $1", (5,))
    with pytest.raises(CrtshDbError, match="No SQL"):
        await db.raw(" ; ")
    # Raw queries are rolled back, the other queries are committed.
    assert db.commits == [False, False]
    await db.cas(name="Test")
    assert db.commits[-1] is True

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


async def test_raw_rolls_back():
    # A raw query's transaction is rolled back, undoing any session setting it changed
    # (ex. set_config(..., false)) before the connection is reused.
    server = FakeServer()
    db = makeDb(server, statement_timeout=60)
    try:
        rows = await db.raw("SELECT set_config('search_path', 'pg_catalog', false)")
        assert rows == [{"sql": rows[0]["sql"], "conn": 0}]
        # Session advisory locks outlive the rollback, so they're released in the transaction
        # first (behind PgBouncer's transaction pooling, a later one may be on another backend).
        assert server.executed == [BEGIN.format(60000), *RAW_END]
        await db.fetch("SELECT 1")
        assert server.executed[-1] == "COMMIT"
        assert "SAVEPOINT raw" not in server.executed[-2:]

        # A failed raw query is rolled back to the savepoint (its transaction is aborted) to
        # release the locks it took before failing.
        server.executed.clear()
        server.errors = [asyncpg.exceptions.DivisionByZeroError("division by zero")]
        with pytest.raises(CrtshDbError, match="division by zero"):
            await db.raw("SELECT 1/0")
        assert server.executed == [
            BEGIN.format(60000),
            "SAVEPOINT raw",
            "ROLLBACK TO SAVEPOINT raw",
            "SELECT pg_advisory_unlock_all()",
            "ROLLBACK",
        ]
        assert db._conn is not None

        # If the locks can't be released, the connection is dropped, which releases them.
        for errors in ([], [asyncpg.exceptions.DivisionByZeroError("division by zero")]):
            server.failon = {"SELECT pg_advisory_unlock_all()"}
            server.errors = list(errors)
            server.executed.clear()
            if errors:
                with pytest.raises(CrtshDbError, match="division by zero"):
                    await db.raw("SELECT 1/0")
            else:
                assert len(await db.raw("SELECT 1")) == 1
            assert db._conn is None and server.open == 0
            assert "ROLLBACK" not in server.executed
            server.failon = set()
            assert (await db.fetch("SELECT 1"))[0]["conn"] == len(server.conns) - 1
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
    assert prefixQuery(["microsoft", "it's", "a\\b", "x') | !(y"]) == (
        "'microsoft':* & 'it''s':* & 'a\\\\b':* & 'x'') | !(y':*"
    )
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
