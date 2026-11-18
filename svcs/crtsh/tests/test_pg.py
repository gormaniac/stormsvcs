"""Run CrtshSvc's real SQL against a PostgreSQL stub of crt.sh. Skipped unless enabled.

    SLIB_CRTSH_PGDSN=postgresql://postgres@127.0.0.1:5432/certwatch uv run pytest tests/test_pg.py

The database's public schema is replaced with the stub (see ``tests.pgstub``), loaded
with the fake PKI, so this checks every query parses, plans, and returns what the
FakeCrtshDb-backed tests expect, through asyncpg.
"""

import base64
import copy
import datetime
import os
import re

import asyncpg
import pytest
import synapse.tests.utils as s_tests
from cryptography import x509

from crtshsvc import CrtshSvc
from crtshsvc.db import CrtshDbError, Params, _filters, prefixQuery, tsquery

from . import pgstub
from .fakecrtsh import PKI, identityText, tsTokens
from .test_crtsh_db import LIVE_IDENTITIES

DSN = os.environ.get("SLIB_CRTSH_PGDSN")

pytestmark = pytest.mark.skipif(not DSN, reason="Set SLIB_CRTSH_PGDSN to run the PostgreSQL tests.")


async def ids(genr) -> list[int]:
    return [d["crtsh"]["id"] async for d in genr]


class TestPostgres(s_tests.SynTest):
    async def test_queries(self):
        await pgstub.load(DSN)
        async with self.getTestCell(CrtshSvc, conf={"crtsh:dsn": DSN}) as svc:
            # Lookups, with every kind of identifier, and the metadata.
            leaf = (await svc.lookup(None, [10]))[0]
            assert leaf["crtsh"]["issuer"] == {
                "id": 2,
                "name": "C=US, O=Test Trust, CN=Test Issuing CA 1",
            }
            assert [e["log"] for e in leaf["crtsh"]["ctlog"]] == ["Test Log A", "Test Log B"]
            assert leaf["crtsh"]["logged"] == [e["time"] for e in leaf["crtsh"]["ctlog"]]
            assert leaf["crtsh"]["caids"] == [] and leaf["crtsh"]["revoked"] is None
            for kind, valu in (
                ("sha256", leaf["sha256"]),
                ("sha1", leaf["sha1"]),
                ("serial", leaf["serial"]),
                ("ski", leaf["ski"]),
                ("spki", leaf["pubkey"]["sha256"]),
                ("spkisha1", leaf["pubkey"]["sha1"]),
                ("subjectsha1", leaf["subject"]["sha1"]),
            ):
                assert 10 in [c["crtsh"]["id"] for c in await svc.lookup(kind, valu)], kind
            assert [
                c["crtsh"]["id"]
                for c in await svc.lookup(None, [10, PKI.sha256(2), PKI.sha256(13)])
            ] == [10, 2, 13]
            assert (await svc.lookup("id", 2))[0]["crtsh"]["caids"] == [2]
            revoked = (await svc.lookup("id", 11))[0]["crtsh"]["revoked"]
            assert revoked["reason"] == "keyCompromise"
            assert await svc.get(999) is None

            # Searches.
            # Expiry bounds on notAfter, through the partition key.
            def notafter(certid):
                return int(PKI.certs[certid].not_valid_after_utc.timestamp() * 1000)

            assert await ids(svc.searchGenr(dns="vertex.link", expires_after=notafter(11))) == [11]
            assert await ids(svc.searchGenr(dns="vertex.link", expires_before=notafter(11))) == [
                10,
                9,
                15,
                12,
            ]
            assert await ids(svc.issuedGenr(caids=[2], expires_after=notafter(11))) == [11]
            assert await ids(
                svc.searchGenr(
                    cn="vert*", issuer="Issuing", expires_after=notafter(10), expires_before=2**52
                )
            ) == [10, 9, 11]
            # A trailing * is a prefix ('vert':*::tsquery), no user text is tsquery syntax.
            assert await ids(svc.searchGenr(cn="vert*")) == [10, 9, 15, 11, 12]
            assert await ids(svc.searchGenr(cn="vert*", valid=True, since=0)) == [10, 9, 11]
            assert await ids(svc.searchGenr(org="The Vert*", issuer="Issuing")) == [
                10,
                9,
                15,
                11,
                12,
            ]
            assert await ids(svc.searchGenr(cn="ertex*")) == []
            assert await ids(svc.searchGenr(cn="x') | !('y\\* & z:*")) == []
            assert await ids(svc.searchGenr(identity="test trust", caids=[1])) == [2, 1]
            assert await ids(svc.searchGenr(dns="vertex.link")) == [10, 9, 15, 11, 12]
            assert await ids(svc.searchGenr(dns="www.vertex.link", exact=True)) == [10, 9, 15]
            assert await ids(svc.searchGenr(dns="vertex.link", valid=True, precerts=False)) == [
                10,
                11,
            ]
            assert await ids(svc.searchGenr(dns="vertex.link", org="vertex", cn="old")) == [11]
            assert await ids(svc.searchGenr(ip="1.2.3.4")) == [10, 9]
            assert await ids(svc.searchGenr(ip="2001:db8::1")) == [10, 9]
            assert await ids(svc.searchGenr(email="visi@vertex.link")) == [10, 9]
            assert await ids(svc.searchGenr(uri="https://vertex.link/")) == [10, 9]
            assert await ids(svc.searchGenr(ou="Engineering")) == [10, 9, 15]
            assert await ids(svc.searchGenr(subject="O=Example Inc")) == [14]
            assert await ids(svc.searchGenr(identity="shop.example.com")) == [14]
            assert await ids(svc.searchGenr(dns="vertex.link", issuer="Issuing CA")) == [
                10,
                9,
                15,
                11,
                12,
            ]
            assert await ids(svc.searchGenr(dns="vertex.link", caids=[1])) == []
            assert await ids(svc.searchGenr(dns="vertex.link", since=0, until=2**42)) == [
                10,
                9,
                15,
                11,
                12,
            ]
            assert await ids(svc.searchGenr(issuer="Root R1")) == [2, 1]
            assert await ids(svc.searchGenr(issuer="nope")) == []

            # Issued, with every kind of CA source in one query.
            assert await ids(svc.issuedGenr(caids=[2])) == [14, 10, 9, 15, 11, 12, 13]
            assert await ids(svc.issuedGenr(caids=[1, 3])) == [4, 2, 3, 1]
            assert await ids(svc.issuedGenr(valu=PKI.sha256(4), precerts=False, limit=3)) == [
                14,
                10,
                15,
            ]
            assert await ids(svc.issuedGenr(valu=2, kind="id", valid=True, since=0)) == [
                14,
                10,
                9,
                11,
            ]
            with pytest.raises(Exception, match="may not be a CA"):
                await ids(svc.issuedGenr(valu=10))

            # Pivots.
            assert await ids(svc.pivotGenr(4, "issued", limit=2)) == [14, 13]
            assert await ids(svc.pivotGenr(10, "siblings", valid=True, precerts=False)) == [14, 11]
            assert await ids(svc.pivotGenr(10, "key")) == [9, 15]
            assert await ids(svc.pivotGenr(10, "subject")) == [9, 15]
            assert await ids(svc.pivotGenr(10, "serial")) == [9]
            assert await ids(svc.pivotGenr(10, "ski")) == [9, 15]
            with pytest.raises(Exception, match="Unable to pivot by key"):
                await ids(svc.pivotGenr(13, "key"))

            # Chains, in one recursive query.
            chain = await svc.chain(PKI.sha256(10))
            sha = {cid: PKI.sha256(cid) for cid in (10, 2, 4, 1, 3)}
            assert [c["crtsh"]["id"] for c in chain["certs"]] == [10, 2, 4, 1, 3]
            assert chain["paths"] == [[sha[10], sha[2], sha[1]], [sha[10], sha[4], sha[3]]]
            assert [c["crtsh"]["id"] for c in (await svc.chain(10, maxdepth=1))["certs"]] == [
                10,
                2,
                4,
            ]
            assert (await svc.chain(1))["links"] == []

            # CAs.
            cas = await svc.cas(name="Test")
            assert [(ca["id"], ca["certs"]) for ca in cas] == [(1, [1]), (2, [2, 4]), (3, [3])]
            cas = await svc.cas(caids=[2], certs=True)
            assert [c["crtsh"]["id"] for c in cas[0]["certs"]] == [2, 4]

            rows = await svc.rawQuery("SELECT ID, NAME FROM ca WHERE ID = $1", [1])
            assert rows == [{"id": 1, "name": "C=US, O=Test Trust, CN=Test Root R1"}]
            assert len(await svc.rawQuery("SELECT ID FROM certificate;", limit=2)) == 2
            # Raw SQL can't change the session or any data, even with a writable account.
            for sql in (
                "SET statement_timeout = 0",
                "COMMIT",
                "DELETE FROM ca RETURNING *",
                "WITH d AS (DELETE FROM ca RETURNING *) SELECT * FROM d",
            ):
                with pytest.raises(CrtshDbError):
                    await svc.rawQuery(sql)
            assert len(await svc.rawQuery("SELECT ID FROM ca")) == 3
            # The connection is still usable after those errors.
            assert (await svc.rawQuery("VALUES (1)")) == [{"column1": 1}]

            # Functions that change the session from inside a query are undone (the raw query's
            # transaction is rolled back), so they can't change the settings of later queries.
            settings = (
                "SELECT current_setting('search_path') AS sp, "
                "current_setting('statement_timeout') AS st, "
                "current_setting('default_transaction_read_only') AS ro"
            )
            before = await svc.db.fetch(settings)
            for sql in (
                "SELECT set_config('search_path', 'pg_catalog', false)",
                "SELECT set_config('statement_timeout', '1', false)",
                "SELECT set_config('default_transaction_read_only', 'off', false)",
            ):
                await svc.rawQuery(sql)
            assert await svc.db.fetch(settings) == before
            assert len(await svc.lookup(None, [10])) == 1
            # Session advisory locks outlive a rollback, so they're refused.
            for sql in (
                "SELECT pg_advisory_lock(1)",
                'SELECT pg_catalog."pg_try_advisory_lock_shared" (1, 2)',
                "SELECT pg_advisory_lock/**/(1)",
                "SELECT pg_advisory_lock\n-- a comment\n(1)",
                r'SELECT U&"pg\0061dvisory_lock"(1)',
            ):
                with pytest.raises(CrtshDbError, match="advisory"):
                    await svc.rawQuery(sql)
            # Transaction level ones are released with the rollback.
            sql = "SELECT 1 AS ok FROM (SELECT pg_advisory_xact_lock(1)) l"
            assert await svc.rawQuery(sql) == [{"ok": 1}]
            locks = "SELECT count(*) AS n FROM pg_locks WHERE locktype = 'advisory'"
            assert await svc.db.fetch(locks) == [{"n": 0}]
            # Dynamic SQL gets past the name check, so the session locks a raw query takes are
            # released before its rollback, whether it succeeds or fails after taking them.
            dyn = "query_to_xml('SELECT pg_advisory_' || 'lock(7)', false, false, '')"
            assert await svc.rawQuery(f"SELECT {dyn} IS NOT NULL AS ok") == [{"ok": True}]
            assert await svc.db.fetch(locks) == [{"n": 0}]
            # Even when it returns no rows.
            assert await svc.rawQuery(f"SELECT 1 AS ok WHERE {dyn} IS NULL") == []
            assert await svc.db.fetch(locks) == [{"n": 0}]
            # A query that fails can't release them in its statement, a follow-up statement does.
            # (pg_locks shows every backend's locks, but behind PgBouncer's statement pooling the
            # follow-up only reaches the same server connection while nothing else uses the pool.)
            conn = svc.db._conn
            with pytest.raises(CrtshDbError, match="division by zero"):
                await svc.rawQuery(f"SELECT {dyn} IS NOT NULL, (random() * 0)::int / 0")
            assert await svc.db.fetch(locks) == [{"n": 0}]
            # The connection is still usable, it wasn't dropped.
            assert (await svc.rawQuery("VALUES (1)")) == [{"column1": 1}]
            assert svc.db._conn is conn

            # Neither the service's queries nor raw ones can write, even with a writable account.
            for query in (svc.db.fetch, svc.rawQuery):
                with pytest.raises(CrtshDbError, match="read-only transaction"):
                    await query("SELECT nextval('ca_id_seq')")
            # The service's queries inline their arguments as literals (a simple query has no
            # parameters), which round trip exactly, whatever they contain.
            text = "it's \\ a 'test' $1 E'x' \\' ); SELECT pg_sleep(5); -- \u00e9\u682a"
            args = (text, b"\x00\xff'\\", [1, 2**40], 1.5, [], [b"\x01", None], True, None)
            rows = await svc.db.fetch(
                "SELECT $1::text AS t, $2::bytea AS der, $3::bigint[] AS a, $4::float8 AS f, "
                "$5::text[] AS e, $6::bytea[] IS NOT NULL AS b, $7::bool AS y, $8::int AS n",
                *args,
            )
            assert rows == [
                {
                    "t": text,
                    "der": args[1],
                    "a": args[2],
                    "f": 1.5,
                    "e": [],
                    "b": True,
                    "y": True,
                    "n": None,
                }
            ]

    async def test_cycles(self):
        # CAs that cross-sign each other: CA 2 (certs 2, 4) is signed by CA 3, whose certificate
        # (14) is signed by CA 2. Without the path check the recursion bounces between them.
        pki = copy.copy(PKI)
        pki.cacerts = {1: 1, 2: 2, 4: 2, 14: 3}
        await pgstub.load(DSN, pki)
        conf = {"crtsh:dsn": DSN, "crtsh:statement:timeout": 30}
        async with self.getTestCell(CrtshSvc, conf=conf) as svc:
            chain = await svc.chain(10)
            assert [c["crtsh"]["id"] for c in chain["certs"]] == [10, 2, 4, 1, 14]
            assert all(len(path) == len(set(path)) for path in chain["paths"])
            assert len(await svc.db.chain({"id": [10]}, maxrows=3)) == 3
            # The service's queries set their own statement_timeout (SET LOCAL), read-only, in
            # the same message as the query, so it doesn't outlast it (raw queries, which keep
            # their parameters, run under the server's).
            settings = (
                "SELECT current_setting('statement_timeout') AS st, "
                "current_setting('transaction_read_only') AS ro"
            )
            assert await svc.db.fetch(settings) == [{"st": "30s", "ro": "on"}]
            assert await svc.rawQuery(settings) == [{"st": "0", "ro": "on"}]

    async def test_statement_timeout(self):
        # The statement_timeout applies to the query itself, behind PgBouncer's statement
        # pooling too (a session SET, or set_config() in the query, wouldn't).
        await pgstub.load(DSN)
        conf = {"crtsh:dsn": DSN, "crtsh:statement:timeout": 0.2, "crtsh:timeout:retries": 0}
        async with self.getTestCell(CrtshSvc, conf=conf) as svc:
            with pytest.raises(CrtshDbError, match="statement timeout"):
                await svc.db.fetch("SELECT pg_sleep(1)")
            assert await svc.db.fetch("SELECT pg_sleep(0.01) IS NULL AS ok") == [{"ok": False}]
            assert svc.db._useCopy

    async def test_identity_tokens(self):
        # The fakes decide which certificates a search matches with tsTokens; check it makes the
        # words PostgreSQL does of every certificate's identities() text (crt.sh's certwatch
        # config is a copy of simple), and of search text as plainto_tsquery parses it.
        texts = [identityText(c) for c in PKI.certs.values() if c is not None]
        for live in LIVE_IDENTITIES:
            der = base64.b64decode(live["der"])
            texts.append(identityText(x509.load_der_x509_certificate(der)))
        conn = await asyncpg.connect(DSN, statement_cache_size=0)
        try:
            for text in texts:
                words = await conn.fetchval(
                    "SELECT tsvector_to_array(to_tsvector('simple', $1))", text
                )
                assert tsTokens(text) == set(words), text
            for text in ("*.vertex.link", "visi@vertex.link", "https://vertex.link/", "Test Trust"):
                query = await conn.fetchval(
                    "SELECT querytree(plainto_tsquery('simple', $1))", tsquery(text)[0]
                )
                words = {w.strip("'") for w in query.split(" & ")}
                assert tsTokens(tsquery(text)[0]) == words, text
            # A prefix with punctuation matches the one word crt.sh indexes for it, in a
            # position-stripped vector like identities() returns (to_tsquery made a phrase of
            # it, which never matched).
            for text, prefix, match in (
                ("microsoft-support.ph", "Microsoft-Sup", True),
                ("foo-bar x", "foo-bar", True),
                ("bar foo x", "foo-bar", False),
                ("login.microsoftonline.com microsoftonline.com com", "microsoft", True),
            ):
                found = await conn.fetchval(
                    "SELECT strip(to_tsvector('simple', $1)) @@ $2::tsquery",
                    text,
                    prefixQuery([prefix]),
                )
                assert found is match, (text, prefix)
            # What to_tsquery made of the same operand: a phrase a stripped vector never matches.
            assert not await conn.fetchval(
                "SELECT strip(to_tsvector('simple', 'foo-bar x')) @@ to_tsquery('simple', $1)",
                prefixQuery(["foo-bar"]),
            )
        finally:
            await conn.close()

    async def test_partition_pruning(self):
        # The expiry bounds are on the partition key, so PostgreSQL only scans the partitions in
        # range (the stub's are yearly; crt.sh's recent ones are quarterly, ex. c2027q1).
        await pgstub.load(DSN)
        params = Params()
        after = int(datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC).timestamp() * 1000)
        before = int(datetime.datetime(2030, 4, 1, tzinfo=datetime.UTC).timestamp() * 1000)
        conds = _filters(params, expires_after=after, expires_before=before)
        conn = await asyncpg.connect(DSN, statement_cache_size=0)
        try:
            rows = await conn.fetch(
                f"EXPLAIN SELECT c.ID FROM certificate c WHERE {' AND '.join(conds)}", *params.args
            )
        finally:
            await conn.close()
        scanned = set(re.findall(r"on (certificate_\w+)", "\n".join(r[0] for r in rows)))
        assert scanned == {"certificate_2030"}, scanned
