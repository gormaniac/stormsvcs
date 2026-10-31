"""Run CrtshSvc's real SQL against a PostgreSQL stub of crt.sh. Skipped unless enabled.

    SLIB_CRTSH_PGDSN=postgresql://postgres@127.0.0.1:5432/certwatch uv run pytest tests/test_pg.py

The database's public schema is replaced with the stub (see ``tests.pgstub``), loaded
with the fake PKI, so this checks every query parses, plans, and returns what the
FakeCrtshDb-backed tests expect, through asyncpg.
"""

import copy
import os

import pytest
import synapse.tests.utils as s_tests

from crtshsvc import CrtshSvc

from . import pgstub
from .fakecrtsh import PKI


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
            assert leaf["crtsh"]["issuer"] == {"id": 2, "name": "C=US, O=Test Trust, CN=Test Issuing CA 1"}
            assert [e["log"] for e in leaf["crtsh"]["ctlog"]] == ["Test Log A", "Test Log B"]
            assert leaf["crtsh"]["logged"] == [e["time"] for e in leaf["crtsh"]["ctlog"]]
            assert leaf["crtsh"]["caids"] == [] and leaf["crtsh"]["revoked"] is None
            for kind, valu in (("sha256", leaf["sha256"]), ("sha1", leaf["sha1"]), ("serial", leaf["serial"]),
                               ("ski", leaf["ski"]), ("spki", leaf["pubkey"]["sha256"]),
                               ("spkisha1", leaf["pubkey"]["sha1"]), ("subjectsha1", leaf["subject"]["sha1"])):
                assert 10 in [c["crtsh"]["id"] for c in await svc.lookup(kind, valu)], kind
            assert [c["crtsh"]["id"] for c in await svc.lookup(None, [10, PKI.sha256(2), PKI.sha256(13)])] == [10, 2, 13]
            assert (await svc.lookup("id", 2))[0]["crtsh"]["caids"] == [2]
            revoked = (await svc.lookup("id", 11))[0]["crtsh"]["revoked"]
            assert revoked["reason"] == "keyCompromise"
            assert await svc.get(999) is None

            # Searches.
            assert await ids(svc.searchGenr(dns="vertex.link")) == [10, 9, 15, 11, 12]
            assert await ids(svc.searchGenr(dns="www.vertex.link", exact=True)) == [10, 9, 15]
            assert await ids(svc.searchGenr(dns="vertex.link", valid=True, precerts=False)) == [10, 11]
            assert await ids(svc.searchGenr(dns="vertex.link", org="vertex", cn="old")) == [11]
            assert await ids(svc.searchGenr(ip="1.2.3.4")) == [10, 9]
            assert await ids(svc.searchGenr(ip="2001:db8::1")) == [10, 9]
            assert await ids(svc.searchGenr(email="visi@vertex.link")) == [10, 9]
            assert await ids(svc.searchGenr(uri="https://vertex.link/")) == [10, 9]
            assert await ids(svc.searchGenr(ou="Engineering")) == [10, 9, 15]
            assert await ids(svc.searchGenr(subject="O=Example Inc")) == [14]
            assert await ids(svc.searchGenr(identity="shop.example.com")) == [14]
            assert await ids(svc.searchGenr(dns="vertex.link", issuer="Issuing CA")) == [10, 9, 15, 11, 12]
            assert await ids(svc.searchGenr(dns="vertex.link", caids=[1])) == []
            assert await ids(svc.searchGenr(dns="vertex.link", since=0, until=2 ** 42)) == [10, 9, 15, 11, 12]
            assert await ids(svc.searchGenr(issuer="Root R1")) == [2, 1]
            assert await ids(svc.searchGenr(issuer="nope")) == []

            # Issued, with every kind of CA source in one query.
            assert await ids(svc.issuedGenr(caids=[2])) == [14, 10, 9, 15, 11, 12, 13]
            assert await ids(svc.issuedGenr(caids=[1, 3])) == [4, 2, 3, 1]
            assert await ids(svc.issuedGenr(valu=PKI.sha256(4), precerts=False, limit=3)) == [14, 10, 15]
            assert await ids(svc.issuedGenr(valu=2, kind="id", valid=True, since=0)) == [14, 10, 9, 11]
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
            assert [c["crtsh"]["id"] for c in (await svc.chain(10, maxdepth=1))["certs"]] == [10, 2, 4]
            assert (await svc.chain(1))["links"] == []

            # CAs.
            cas = await svc.cas(name="Test")
            assert [(ca["id"], ca["certs"]) for ca in cas] == [(1, [1]), (2, [2, 4]), (3, [3])]
            cas = await svc.cas(caids=[2], certs=True)
            assert [c["crtsh"]["id"] for c in cas[0]["certs"]] == [2, 4]

            rows = await svc.rawQuery("SELECT ID, NAME FROM ca WHERE ID = $1", [1])
            assert rows == [{"id": 1, "name": "C=US, O=Test Trust, CN=Test Root R1"}]

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
            assert (await svc.rawQuery("SHOW statement_timeout"))[0]["statement_timeout"] == "30s"
