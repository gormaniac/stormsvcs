"""Pytests for CrtshSvc (and its Telepath API) against a FakeCrtshDb."""

import contextlib
import copy
import datetime
import importlib
import runpy
import sys
from unittest import mock

import pytest
import synapse.tests.utils as s_tests

from crtshsvc import CrtshSvc, norm
from crtshsvc import svc as s_svc
from crtshsvc.db import CrtshDbError

from .fakecrtsh import PKI, FakeCrtshDb


@contextlib.asynccontextmanager
async def svcCtx(test, conf: dict | None = None, fake: FakeCrtshDb | None = None):
    async with test.getTestCell(CrtshSvc, conf=conf) as svc:
        await svc.db.close()
        svc.db = fake or FakeCrtshDb()
        yield svc, svc.db


async def ids(genr) -> list[int]:
    return [d["crtsh"]["id"] async for d in genr]


def test_main():
    with mock.patch.object(CrtshSvc, "execmain", new=mock.AsyncMock()) as execmain:
        with mock.patch.object(sys, "argv", ["crtshsvc", "/vertex/storage"]):
            runpy.run_module("crtshsvc", run_name="__main__")
    execmain.assert_awaited_once_with(["/vertex/storage"])

    # Importing it doesn't start the service.
    with mock.patch.object(CrtshSvc, "execmain", new=mock.AsyncMock()) as execmain:
        importlib.import_module("crtshsvc.__main__")
    execmain.assert_not_called()


def test_helpers():
    assert s_svc._serialVariants(b"\x00\xf0\x0d") == [b"\xf0\x0d", b"\x00\xf0\x0d"]
    assert s_svc._serialVariants(b"\x00\x00\x0d") == [b"\x0d", b"\x00\x00\x0d"]
    assert s_svc._serialVariants(b"\x00") == [b"\x00"]
    assert s_svc._serialVariants(b"\x0d") == [b"\x0d"]

    assert s_svc.identityQuery("subject", " CN=x ") == ("x", None)
    assert s_svc.identityQuery("subject", "C=US, O=The Vertex Project+OU=Eng, 1.2.3=x") == (
        "US The Vertex Project Eng x", None)
    assert s_svc.identityQuery("ip", "1.2.3.4") == ("1.2.3.4", "1.2.3.4")
    assert s_svc.identityQuery("ip", "2001:db8::1") == (
        ":2001:DB8:0:0:0:0:0:1", ":2001:DB8:0:0:0:0:0:1")
    with pytest.raises(CrtshDbError, match="Invalid IP"):
        s_svc.identityQuery("ip", "nope")
    assert s_svc.identityQuery("dns", "*.vertex_link") == ("*.vertex_link", "%vertex\\_link")
    assert s_svc.identityQuery("dns", "vertex.link", exact=True) == ("vertex.link", "vertex.link")
    assert s_svc.identityQuery("org", "Vertex") == ("Vertex", "%Vertex%")

    assert s_svc.lookupValu("id", "12") == [12]
    with pytest.raises(CrtshDbError, match="Invalid crt.sh ID"):
        s_svc.lookupValu("id", "x")
    with pytest.raises(CrtshDbError, match="Unknown lookup type"):
        s_svc.lookupValu("nope", "x")
    with pytest.raises(CrtshDbError, match="expected a hex string"):
        s_svc.lookupValu("ski", "0x")
    with pytest.raises(CrtshDbError, match="expected a hex string"):
        s_svc.lookupValu("ski", "zz")
    with pytest.raises(CrtshDbError, match="expected 64 hex characters"):
        s_svc.lookupValu("sha256", "aa")
    with pytest.raises(CrtshDbError, match="even number"):
        s_svc.lookupValu("ski", "abc")
    assert s_svc.lookupValu("ski", "AB:CD") == [b"\xab\xcd"]
    assert s_svc.lookupValu("serial", "0xF00D") == [b"\xf0\x0d", b"\x00\xf0\x0d"]

    assert s_svc.guessKind(5) == "id"
    assert s_svc.guessKind("12345") == "id"
    assert s_svc.guessKind("a" * 64) == "sha256"
    assert s_svc.guessKind("AA:" * 19 + "AA") == "sha1"
    for valu in ("abc", "1" * 30, "zz"):
        with pytest.raises(CrtshDbError, match="Unable to tell"):
            s_svc.guessKind(valu)

    row = s_svc._safeRow({"b": b"\x01", "m": memoryview(b"\x02"), "a": bytearray(b"\x03"),
                          "t": datetime.datetime(1970, 1, 1), "l": [1, (b"\x04",)],
                          "n": None, "s": "x", "f": 1.5, "o": complex(1, 2)})
    assert row == {"b": "01", "m": "02", "a": "03", "t": 0, "l": [1, ["04"]], "n": None,
                   "s": "x", "f": 1.5, "o": "(1+2j)"}

    assert s_svc._preferredParent({"notbefore": 5}, []) is None
    child = {"notbefore": 5}
    early = {"notbefore": 0, "notafter": 4}
    covers = {"notbefore": 0, "notafter": 10}
    later = {"notbefore": 0, "notafter": 20}
    precert = {"notbefore": 0, "notafter": 30, "precert": True}
    assert s_svc._preferredParent(child, [early, covers]) is covers
    assert s_svc._preferredParent(child, [covers, later, precert]) is later
    assert s_svc._preferredParent({}, [{}]) == {}

    links = [
        {"child": "a", "parent": "b", "preferred": False},
        {"child": "a", "parent": "c", "preferred": True},
        {"child": "c", "parent": "a", "preferred": True},  # A loop is never followed.
    ]
    assert s_svc._paths("a", links) == [["a", "c"], ["a", "b"]]
    assert s_svc._paths("a", links, maxpaths=1) == [["a", "c"]]
    assert s_svc._paths("z", links) == [["z"]]


class TestCrtshSvc(s_tests.SynTest):

    async def test_lookup(self):
        async with svcCtx(self) as (svc, fake):
            # Duplicates (here, by ID and SHA-256) are only returned once.
            certs = await svc.lookup(None, [10, PKI.sha256(2), PKI.sha256(10)])
            assert [c["crtsh"]["id"] for c in certs] == [10, 2]
            assert fake.called("certs") == 2

            # The metadata of every certificate.
            leaf = certs[0]
            assert leaf["crtsh"]["issuer"] == {"id": 2, "name": "C=US, O=Test Trust, CN=Test Issuing CA 1"}
            assert [e["log"] for e in leaf["crtsh"]["ctlog"]] == ["Test Log A", "Test Log B"]
            assert leaf["crtsh"]["logged"] == [e["time"] for e in leaf["crtsh"]["ctlog"]]
            assert leaf["crtsh"]["caids"] == []
            assert leaf["crtsh"]["revoked"] is None
            assert certs[1]["crtsh"]["caids"] == [2]
            assert certs[1]["crtsh"]["logged"] is None

            # Serials match the precert and cert, newest (then highest ID) first.
            assert [c["crtsh"]["id"] for c in await svc.lookup("serial", "5a0b1c2d3e4f")] == [10, 9]
            # The limit is applied by crt.sh, which returns ties in any order.
            assert len(await svc.lookup("serial", "5a0b1c2d3e4f", limit=1)) == 1
            assert await svc.lookup("sha1", "00" * 20) == []

            revoked = (await svc.lookup("id", 11))[0]["crtsh"]["revoked"]
            assert revoked["reason"] == "keyCompromise" and revoked["code"] == 1

            junk = (await svc.lookup("id", "13"))[0]
            assert junk["error"] and junk["crtsh"]["issuer"]["name"]

            with pytest.raises(CrtshDbError, match="Unable to tell"):
                await svc.lookup(None, "nope")

    async def test_get(self):
        async with svcCtx(self) as (svc, fake):
            assert (await svc.get(10))["sha256"] == PKI.sha256(10)
            assert fake.last("certs")["limit"] == 1
            assert (await svc.get(PKI.sha256(10)))["crtsh"]["id"] == 10
            assert (await svc.get("5a0b1c2d3e4f", kind="serial"))["crtsh"]["id"] == 10
            assert fake.last("certs")["limit"] == 100
            assert await svc.get(999) is None

    async def test_limit(self):
        async with svcCtx(self, conf={"crtsh:limit": 3}) as (svc, fake):
            assert svc._limit(None) == 3
            assert svc._limit(-1) == 3
            assert svc._limit(2) == 2
            assert svc._limit(10) == 3

    async def test_search(self):
        async with svcCtx(self) as (svc, fake):
            # Subdomains, wildcards, and the domain itself, but not notvertex.link.
            assert await ids(svc.searchGenr(dns="vertex.link")) == [14, 10, 9, 15, 11, 12][1:]
            call = fake.last("certsByIdentity")
            assert call["like"] == "%vertex.link"
            assert call["nametypes"] == ["san:dNSName", "2.5.4.3"]
            assert call["limit"] == 500

            assert await ids(svc.searchGenr(dns="www.vertex.link", exact=True)) == [10, 9, 15]
            assert await ids(svc.searchGenr(dns="vertex.link", valid=True, precerts=False)) == [10, 11]
            assert await ids(svc.searchGenr(dns="vertex.link", limit=2)) == [10, 9]
            assert await ids(svc.searchGenr(dns="vertex.link", org="vertex", cn="old")) == [11]
            assert await ids(svc.searchGenr(ip="2001:db8::1")) == [10, 9]
            assert await ids(svc.searchGenr(email="visi")) == [10, 9]
            assert await ids(svc.searchGenr(uri="https://vertex.link/")) == [10, 9]
            assert await ids(svc.searchGenr(ou="Engineering")) == [10, 9, 15]
            assert await ids(svc.searchGenr(subject="O=Example Inc")) == [14]
            assert fake.last("certsByIdentity")["text"] == "Example Inc"
            assert fake.last("certsByIdentity")["like"] is None
            assert await ids(svc.searchGenr(identity="shop")) == [14]

            # Issuers by name are resolved to crt.sh CA IDs.
            assert await ids(svc.searchGenr(dns="vertex.link", issuer="Issuing CA")) == [10, 9, 15, 11, 12]
            assert fake.last("casByName")["name"] == "Issuing CA"
            assert fake.last("certsByIdentity")["caids"] == [2]
            assert await ids(svc.searchGenr(dns="vertex.link", caids=[1])) == []
            assert await ids(svc.searchGenr(issuer="nope")) == []

            # An issuer alone lists what it issued.
            assert await ids(svc.searchGenr(issuer="Root R1")) == [2, 1]
            assert fake.last("certsByIssuer")["caids"] == [1]
            assert await ids(svc.searchGenr(caids=[2], since=0, until=2 ** 60, valid=True,
                                            limit=1)) == [14]

            with pytest.raises(CrtshDbError, match="at least one"):
                await ids(svc.searchGenr(dns=""))

    async def test_search_batches(self):
        # Metadata is fetched for each batch of results.
        async with svcCtx(self) as (svc, fake):
            with mock.patch.object(s_svc, "DETAIL_BATCH", 2):
                assert len(await ids(svc.searchGenr(dns="vertex.link"))) == 5
            assert fake.called("ctlog") == 3

    async def test_issued(self):
        async with svcCtx(self) as (svc, fake):
            assert await ids(svc.issuedGenr(caids=[2])) == [14, 10, 9, 15, 11, 12]
            # Roots are issued by their own CA.
            assert await ids(svc.issuedGenr(caids=[1, 3])) == [4, 2, 3, 1]
            assert fake.called("certsByIssuer") == 2

            # A CA certificate's CA, and all of the CA's certificates are equal.
            assert await ids(svc.issuedGenr(valu=PKI.sha256(4), precerts=False, limit=3)) == [14, 10, 15]
            assert fake.last("certsByIssuer")["caids"] == [2]
            assert await ids(svc.issuedGenr(valu=2, kind="id", valid=True)) == [14, 10, 9, 11]

            with pytest.raises(CrtshDbError, match="may not be a CA"):
                await ids(svc.issuedGenr(valu=10))
            with pytest.raises(CrtshDbError, match="CA ID or certificate is required"):
                await ids(svc.issuedGenr())
            with pytest.raises(CrtshDbError, match="no certificate"):
                await ids(svc.issuedGenr(valu=999))

    async def test_pivot(self):
        async with svcCtx(self) as (svc, fake):
            assert await ids(svc.pivotGenr(4, "issued", limit=1)) == [14]
            assert await ids(svc.pivotGenr(10, "siblings")) == [14, 9, 15, 11, 12]
            assert await ids(svc.pivotGenr(10, "siblings", valid=True, precerts=False)) == [14, 11]
            assert await ids(svc.pivotGenr(10, "key")) == [9, 15]
            assert fake.last("certs")["kind"] == "spki"
            assert await ids(svc.pivotGenr(10, "subject")) == [9, 15]
            assert await ids(svc.pivotGenr(10, "serial")) == [9]
            assert await ids(svc.pivotGenr(10, "ski", limit=1)) == [9]
            assert await ids(svc.pivotGenr(PKI.sha256(13), "siblings", limit=1)) == [14]

            with pytest.raises(CrtshDbError, match="Unknown pivot"):
                await ids(svc.pivotGenr(10, "nope"))
            with pytest.raises(CrtshDbError, match="Unable to pivot by key"):
                await ids(svc.pivotGenr(13, "key"))

            noski = norm.certDetails(PKI.row(10))
            noski["ski"] = None
            with mock.patch.object(norm, "certDetails", return_value=noski):
                with pytest.raises(CrtshDbError, match="no ski"):
                    await ids(svc.pivotGenr(10, "ski"))

    async def test_chain(self):
        async with svcCtx(self) as (svc, fake):
            chain = await svc.chain(PKI.sha256(10))
            sha = {cid: PKI.sha256(cid) for cid in (10, 2, 4, 1, 3)}
            assert chain["leaf"] == sha[10]
            assert [c["crtsh"]["id"] for c in chain["certs"]] == [10, 2, 4, 1, 3]
            assert chain["certs"][1]["crtsh"]["caids"] == [2]
            # The intermediate cross-signed by E2 expires first, R1's is preferred.
            assert chain["links"] == [
                {"child": sha[10], "parent": sha[2], "preferred": True},
                {"child": sha[10], "parent": sha[4], "preferred": False},
                {"child": sha[2], "parent": sha[1], "preferred": True},
                {"child": sha[4], "parent": sha[3], "preferred": True},
            ]
            assert chain["paths"] == [[sha[10], sha[2], sha[1]], [sha[10], sha[4], sha[3]]]

            # A root is its own chain.
            chain = await svc.chain(1)
            assert chain["links"] == [] and chain["paths"] == [[PKI.sha256(1)]]

            # Limits on the size of the graph.
            chain = await svc.chain(10, maxcerts=2)
            assert [c["crtsh"]["id"] for c in chain["certs"]] == [10, 2]
            assert len(chain["links"]) == 1
            chain = await svc.chain(10, maxdepth=1)
            assert [c["crtsh"]["id"] for c in chain["certs"]] == [10, 2, 4]

            with pytest.raises(CrtshDbError, match="no certificate"):
                await svc.chain(999)

        # crt.sh doesn't know the issuer's certificate.
        pki = copy.copy(PKI)
        pki.cacerts = {}
        async with svcCtx(self, fake=FakeCrtshDb(pki)) as (svc, fake):
            chain = await svc.chain(10)
            assert [c["crtsh"]["id"] for c in chain["certs"]] == [10]
            assert chain["links"] == []

    async def test_cas(self):
        async with svcCtx(self) as (svc, fake):
            cas = await svc.cas(name="Test")
            assert [(ca["id"], ca["certs"]) for ca in cas] == [(1, [1]), (2, [2, 4]), (3, [3])]
            cas = await svc.cas(caids=["2"], certs=True)
            assert [c["crtsh"]["id"] for c in cas[0]["certs"]] == [2, 4]
            assert cas[0]["name"] == "C=US, O=Test Trust, CN=Test Issuing CA 1"
            assert await svc.cas(name="nope") == []
            with pytest.raises(CrtshDbError, match="name or ID"):
                await svc.cas()

    async def test_raw(self):
        async with svcCtx(self) as (svc, fake):
            rows = await svc.rawQuery("SELECT 1", [1])
            assert rows[0]["key"] == "0102" and rows[0]["ids"] == [1, "ff"]
            with pytest.raises(CrtshDbError, match="nope"):
                await svc.rawQuery("SELECT * FROM nope")

    async def test_api(self):
        async with svcCtx(self) as (svc, fake):
            async with svc.getLocalProxy() as prox:
                retn = await prox.get(10)
                assert retn["status"] and retn["data"]["crtsh"]["id"] == 10
                retn = await prox.lookup("nope", 1)
                assert retn == {"status": False, "mesg": "Unknown lookup type nope, expected one of: "
                                "id, sha256, sha1, serial, ski, spki, spkisha1, subjectsha1",
                                "data": None}

                items = [i async for i in prox.searchGenr(dns="vertex.link", limit=2)]
                assert [i["data"]["crtsh"]["id"] for i in items] == [10, 9]
                items = [i async for i in prox.pivotGenr(10, "nope")]
                assert items == [{"status": False, "data": None,
                                  "mesg": "Unknown pivot nope, expected one of: "
                                          "issued, siblings, key, subject, serial, ski"}]
                assert [i["data"]["crtsh"]["id"] async for i in prox.issuedGenr(caids=[1])] == [2, 1]

    async def test_db_conf(self):
        conf = {"crtsh:dsn": "postgresql://u@db.example:5433/certs", "crtsh:timeout": 5,
                "crtsh:retries": 1, "crtsh:keepalive": 2, "crtsh:idle": 3,
                "crtsh:connect:timeout": 4}
        async with self.getTestCell(CrtshSvc, conf=conf) as svc:
            db = svc.db
            assert (db.dsn, db.timeout, db.retries, db.keepalive, db.idle, db.connect_timeout) == (
                "postgresql://u@db.example:5433/certs", 5, 1, 2, 3, 4)
