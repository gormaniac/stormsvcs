"""Pytests for CrtshDb's connection handling, against fake connections.

crt.sh's PgBouncer allows one connection per client, drops idle clients
(client_idle_timeout), and refuses quick reconnects (max_client_conn).
"""

import asyncio

import asyncpg
import pytest

from crtshsvc.db import (
    LOOKUPS,
    NAME_TYPES,
    NOTAFTER_KEY,
    CrtshDb,
    CrtshDbError,
    likeEscape,
    tsquery,
)


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

    async def execute(self, sql):
        self.server.executed.append(sql)
        if self.server.setfail:
            raise asyncpg.exceptions.InsufficientPrivilegeError(
                "permission denied to set parameter"
            )

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
        server.errors = [
            asyncpg.exceptions.QueryCanceledError("canceling statement due to statement timeout")
        ]
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


async def test_statement_timeout():
    # crt.sh's default statement_timeout cancels big queries, every connection sets its own.
    server = FakeServer()
    db = makeDb(server, statement_timeout=90)
    try:
        await db.fetch("SELECT 1")
        assert server.executed == ["SET statement_timeout = 90000"]
        server.errors = [asyncpg.exceptions.ProtocolViolationError("client_idle_timeout")]
        await db.fetch("SELECT 2")
        assert server.executed == ["SET statement_timeout = 90000"] * 2
    finally:
        await db.close()

    # The default is no limit, and a server that refuses the SET is still used.
    server = FakeServer()
    server.setfail = True
    db = makeDb(server)
    try:
        assert (await db.fetch("SELECT 1"))[0]["conn"] == 0
        assert server.executed == ["SET statement_timeout = 0"]
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
    assert "c.ISSUER_CA_ID = ANY($4::int[])" in sql
    # The issuer's name is a subquery, not another round trip.
    assert "c.ISSUER_CA_ID IN (SELECT ca.ID FROM ca WHERE ca.NAME ILIKE $5 LIMIT 1000)" in sql
    assert f"{NOTAFTER_KEY} >= date_trunc('year', now() AT TIME ZONE 'UTC')" in sql
    assert "x509_notBefore(c.CERTIFICATE) >= to_timestamp($6) AT TIME ZONE 'UTC'" in sql
    assert f"{NOTAFTER_KEY} >= to_timestamp($6) AT TIME ZONE 'UTC'" in sql
    assert "x509_notBefore(c.CERTIFICATE) < to_timestamp($7) AT TIME ZONE 'UTC'" in sql
    assert "LIMIT $8) sub GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE" in sql
    assert db.args == (
        "vertex.link",
        "%vertex.link",
        ["san:dNSName", "2.5.4.3"],
        [2, 3],
        "%Let's\\_Encrypt%",
        1.0,
        2.0,
        50,
    )

    # Name types alone still check each identity.
    await db.certsByIdentity("Sectigo", nametypes=["2.5.4.10"])
    assert "certificate_and_identities" in db.sql


async def test_sql_issuer():
    db = Recorder()
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
    db = Recorder()
    await db.raw("SELECT $1", [1])
    assert db.queries[-1] == ("SELECT $1", (1,))
    await db.raw("SELECT 1")
    assert db.queries[-1] == ("SELECT 1", ())


def test_tsquery():
    assert tsquery(" *.vertex.link ") == "vertex.link"
    assert tsquery("%.vertex.link") == "vertex.link"
    assert tsquery("a%b*c") == "a b c"
    assert likeEscape("a_b%c\\") == "a\\_b\\%c\\\\"
