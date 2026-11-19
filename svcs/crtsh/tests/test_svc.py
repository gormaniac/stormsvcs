"""Pytests for CrtshSvc (and its Telepath API) against a FakeCrtshDb."""

import contextlib
import copy
import datetime
import hashlib
import importlib
import runpy
import sys
from unittest import mock

import pytest
import synapse.exc as s_exc
import synapse.tests.utils as s_tests
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from crtshsvc import CrtshSvc, norm
from crtshsvc import svc as s_svc
from crtshsvc.db import DEFAULT_DSN, CrtshDbError, dsnSecrets

from .fakecrtsh import DAY, NOW, PKI, FakeCrtshDb, makeCert, name


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
        "US The Vertex Project Eng x",
        None,
    )
    assert s_svc.identityQuery("ip", "1.2.3.4") == ("1.2.3.4", "1.2.3.4")
    assert s_svc.identityQuery("ip", "2001:db8::1") == (
        ":2001:DB8:0:0:0:0:0:1",
        ":2001:DB8:0:0:0:0:0:1",
    )
    with pytest.raises(CrtshDbError, match="Invalid IP"):
        s_svc.identityQuery("ip", "nope")
    # Leading wildcards and dots are dropped from domains, they match subdomains anyway...
    assert s_svc.identityQuery("dns", "*.vertex_link") == ("vertex_link", "%vertex\\_link")
    assert s_svc.identityQuery("dns", ".vertex.link") == ("vertex.link", "%vertex.link")
    # Except exact ones: crt.sh holds a wildcard identity as-is, so *.vertex.link must match it.
    assert s_svc.identityQuery("dns", "*.vertex.link", exact=True) == (
        "*.vertex.link",
        "*.vertex.link",
    )
    assert s_svc.identityQuery("dns", "*.vertex_link", exact=True) == (
        "*.vertex_link",
        "*.vertex\\_link",
    )
    assert s_svc.identityQuery("dns", "vertex.link", exact=True) == ("vertex.link", "vertex.link")
    assert s_svc.identityQuery("org", "Vertex") == ("Vertex", "%Vertex%")
    # A trailing * is a prefix: the text keeps it (see db.tsquery), the pattern is a substring.
    assert s_svc.identityQuery("dns", "*.vert_ex*") == ("vert_ex*", "%vert\\_ex%")
    assert s_svc.identityQuery("org", " The Vert** ") == ("The Vert*", "%The Vert%")
    assert s_svc.identityQuery("subject", "O=Vert*") == ("Vert*", None)
    with pytest.raises(CrtshDbError, match="can't be exact"):
        s_svc.identityQuery("cn", "vert*", exact=True)
    assert not s_svc.isPrefix("*") and not s_svc.isPrefix("a -*") and s_svc.isPrefix("a.b*")

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

    row = s_svc._safeRow(
        {
            "b": b"\x01",
            "m": memoryview(b"\x02"),
            "a": bytearray(b"\x03"),
            "t": datetime.datetime(1970, 1, 1),  # noqa: DTZ001 - as the database returns them
            "l": [1, (b"\x04",)],
            "n": None,
            "s": "x",
            "f": 1.5,
            "o": complex(1, 2),
        }
    )
    assert row == {
        "b": "01",
        "m": "02",
        "a": "03",
        "t": 0,
        "l": [1, ["04"]],
        "n": None,
        "s": "x",
        "f": 1.5,
        "o": "(1+2j)",
    }

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
            # Every kind of identifier is looked up in one query.
            assert fake.called("certs") == 1
            assert set(fake.last("certs")["lookups"]) == {"id", "sha256"}

            # The metadata of every certificate.
            leaf = certs[0]
            assert leaf["crtsh"]["issuer"] == {
                "id": 2,
                "name": "C=US, O=Test Trust, CN=Test Issuing CA 1",
            }
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
            assert svc._limit(2) == 2
            assert svc._limit("2") == 2
            assert svc._limit(10) == 3
            # 0 and negative limits are errors, not the max.
            for limit in (0, -1):
                with pytest.raises(CrtshDbError, match="at least 1"):
                    svc._limit(limit)
            for limit in ("zz", True, [1]):
                with pytest.raises(CrtshDbError, match="Invalid limit"):
                    svc._limit(limit)

    async def test_search(self):
        async with svcCtx(self) as (svc, fake):
            # Subdomains, wildcards, and the domain itself, but not notvertex.link.
            assert await ids(svc.searchGenr(dns="vertex.link")) == [14, 10, 9, 15, 11, 12][1:]
            call = fake.last("certsByIdentity")
            assert call["like"] == "%vertex.link"
            assert call["nametypes"] == ["san:dNSName", "2.5.4.3"]
            assert call["limit"] == 500

            assert await ids(svc.searchGenr(dns="www.vertex.link", exact=True)) == [10, 9, 15]
            assert await ids(svc.searchGenr(dns="vertex.link", valid=True, precerts=False)) == [
                10,
                11,
            ]
            assert await ids(svc.searchGenr(dns="vertex.link", limit=2)) == [10, 9]
            assert await ids(svc.searchGenr(dns="vertex.link", org="vertex", cn="old")) == [11]
            assert await ids(svc.searchGenr(ip="2001:db8::1")) == [10, 9]
            assert await ids(svc.searchGenr(email="visi@vertex.link")) == [10, 9]
            # crt.sh's full text search matches whole words, domains, and addresses (CRTSH-02).
            assert await ids(svc.searchGenr(email="visi")) == []
            assert await ids(svc.searchGenr(cn="old")) == []
            assert await ids(svc.searchGenr(cn="vertex.link")) == [10, 9, 15, 11, 12]
            assert await ids(svc.searchGenr(uri="https://vertex.link/")) == [10, 9]
            assert await ids(svc.searchGenr(ou="Engineering")) == [10, 9, 15]
            assert await ids(svc.searchGenr(subject="O=Example Inc")) == [14]
            assert fake.last("certsByIdentity")["text"] == "Example Inc"
            assert fake.last("certsByIdentity")["like"] is None
            assert await ids(svc.searchGenr(identity="shop.example.com")) == [14]

            # Issuers by name are matched in the same query.
            assert await ids(svc.searchGenr(dns="vertex.link", issuer="Issuing CA")) == [
                10,
                9,
                15,
                11,
                12,
            ]
            assert fake.last("certsByIdentity")["issuer"] == "Issuing CA"
            assert fake.last("certsByIdentity")["caids"] is None
            # The issuer filters the candidates afterwards, so every candidate is fetched.
            assert fake.last("certsByIdentity")["limit"] == 10000
            assert await ids(svc.searchGenr(dns="vertex.link", caids=[1])) == []
            assert await ids(svc.searchGenr(issuer="nope")) == []

            # An issuer alone lists what it issued.
            assert await ids(svc.searchGenr(issuer="Root R1")) == [2, 1]
            assert fake.last("certsByIssuer")["issuer"] == "Root R1"
            assert await ids(svc.searchGenr(caids=[2], precerts=False, limit=2)) == [14, 10]
            assert fake.last("certsByIssuer")["limit"] == 4
            assert await ids(
                svc.searchGenr(caids=[2], since=0, until=2**60, valid=True, limit=1)
            ) == [14]

            with pytest.raises(CrtshDbError, match="at least one"):
                await ids(svc.searchGenr(dns=""))

    async def test_search_exact_wildcard(self):
        """An exact wildcard search finds a certificate whose only DNS name is the wildcard."""

        key = ec.generate_private_key(ec.SECP256R1())
        der = makeCert(
            name("Wildcard Test"),
            key,
            name("Test Issuing CA 1"),
            key,
            16,
            NOW - DAY,
            NOW + 10 * DAY,
            sans=[x509.DNSName("*.wild.vertex.link")],
        )
        pki = copy.copy(PKI)
        pki.rows = [*PKI.rows, {"id": 16, "issuer_ca_id": 2, "der": der}]
        pki.certs = {**PKI.certs, 16: x509.load_der_x509_certificate(der)}
        async with svcCtx(self, fake=FakeCrtshDb(pki)) as (svc, fake):
            assert await ids(svc.searchGenr(dns="*.wild.vertex.link", exact=True)) == [16]
            assert fake.last("certsByIdentity")["like"] == "*.wild.vertex.link"
            # Exact is the whole name: the wildcard isn't the domain, nor the other way around.
            assert await ids(svc.searchGenr(dns="wild.vertex.link", exact=True)) == []
            assert await ids(svc.searchGenr(dns="*.vertex.link", exact=True)) == [10, 9]
            # Not exact, the wildcard is a name under the domain.
            assert await ids(svc.searchGenr(dns="wild.vertex.link")) == [16]

    async def test_search_issuer_after_limit(self):
        # Like crt.sh, an issuer filters the full text search's candidates (up to the limit), it
        # doesn't find more. The CA certificates with "Test Trust" are, in crt.sh ID order, 1 and
        # 3 (the roots, CAs 1 and 3), then 2 (issued by CA 1) and 4 (by CA 3).
        fake = FakeCrtshDb()
        assert [r["id"] for r in await fake.certsByIdentity("Test Trust", limit=2)] == [1, 3]
        found = await fake.certsByIdentity("Test Trust", caids=[1], limit=10)
        assert [r["id"] for r in found] == [1, 2]
        found = await fake.certsByIdentity("Test Trust", caids=[1], limit=2)
        assert [r["id"] for r in found] == [1]
        assert await fake.certsByIdentity("Test Trust", issuer="Root E2", limit=1) == []

    async def test_search_expires(self):
        def notafter(certid):
            return int(PKI.certs[certid].not_valid_after_utc.timestamp() * 1000)

        async with svcCtx(self) as (svc, fake):
            # notAfter bounds: expires after is inclusive, expires before exclusive.
            assert await ids(svc.searchGenr(dns="vertex.link", expires_after=notafter(11))) == [11]
            call = fake.last("certsByIdentity")
            assert (call["expires_after"], call["expires_before"]) == (notafter(11), None)
            assert await ids(svc.searchGenr(dns="vertex.link", expires_before=notafter(11))) == [
                10,
                9,
                15,
                12,
            ]
            assert await ids(
                svc.searchGenr(
                    dns="vertex.link",
                    expires_after=str(notafter(10)),
                    expires_before=notafter(11),
                    valid=True,
                    since=0,
                )
            ) == [10, 9]
            # The issuer listing too, and pivots by issued (through issuedGenr).
            assert await ids(svc.searchGenr(caids=[2], expires_before=notafter(10) + 1)) == [
                10,
                9,
                15,
                12,
            ]
            assert fake.last("certsByIssuer")["expires_before"] == notafter(10) + 1
            assert await ids(svc.issuedGenr(caids=[2], expires_after=notafter(11))) == [11]
            assert fake.last("certsByIssuer")["expires_after"] == notafter(11)

            for after, before in ((2000, 2000), (3000, 2000)):
                with pytest.raises(CrtshDbError, match="expires after time must be before"):
                    await ids(
                        svc.searchGenr(
                            dns="vertex.link", expires_after=after, expires_before=before
                        )
                    )
            with pytest.raises(CrtshDbError, match="expires after time must be before"):
                await ids(svc.issuedGenr(caids=[2], expires_after=2, expires_before=1))
            with pytest.raises(CrtshDbError, match="Invalid expires_before"):
                await ids(svc.searchGenr(dns="vertex.link", expires_before="soon"))

    async def test_search_prefix(self):
        async with svcCtx(self) as (svc, fake):
            # A trailing * matches indexed words that start with it (crt.sh indexes every parent
            # domain, so vert* matches vertex.link and so www.vertex.link).
            assert await ids(svc.searchGenr(cn="vert*")) == [10, 9, 15, 11, 12]
            call = fake.last("certsByIdentity")
            assert (call["text"], call["like"]) == ("vert*", "%vert%")
            assert await ids(svc.searchGenr(dns="*.vertex.l*", valid=True)) == [10, 9, 11]
            assert fake.last("certsByIdentity")["text"] == "vertex.l*"
            assert await ids(svc.searchGenr(org="The Vert*", ou="Engin*")) == [10, 9, 15]
            assert fake.last("certsByIdentity")["text"] == "The Vert*"
            assert await ids(svc.searchGenr(subject="O=Exam*")) == [14]
            assert fake.last("certsByIdentity")["text"] == "Exam*"
            assert await ids(svc.searchGenr(email="visi@vert*")) == [10, 9]
            # No suffix or substring search: ertex* isn't a word's start, nor is ink* (the
            # reversed names crt.sh indexes, ex. knil.xetrev, don't count for a field either).
            assert await ids(svc.searchGenr(cn="ertex*")) == []
            assert await ids(svc.searchGenr(dns="knil*")) == []
            assert fake.last("certsByIdentity")["text"] == "knil*"
            # A * alone isn't a prefix.
            assert await ids(svc.searchGenr(cn="*")) == []
            with pytest.raises(CrtshDbError, match="can't be exact"):
                await ids(svc.searchGenr(cn="vert*", exact=True))
            with pytest.raises(CrtshDbError, match="can't be exact"):
                await ids(svc.searchGenr(dns="www.vertex.link", org="vert*", exact=True))
            # A prefix of a common word can hit crt.sh's statement timeout: the usual error.
            fake.fail = "crt.sh query failed: canceling statement due to statement timeout"
            with pytest.raises(CrtshDbError, match="statement timeout"):
                await ids(svc.searchGenr(cn="micro*", issuer="Let's Encrypt", valid=True))

    async def test_round_trips(self):
        # crt.sh is slow per query, every operation is a single query.
        async with svcCtx(self) as (svc, fake):
            sha1 = hashlib.sha1(PKI.row(10)["der"]).hexdigest()
            for call in (
                lambda: svc.lookup(None, [10, PKI.sha256(2), sha1]),
                lambda: ids(svc.searchGenr(dns="vertex.link", issuer="Issuing", valid=True)),
                lambda: ids(svc.searchGenr(issuer="Issuing", caids=[1])),
                lambda: ids(svc.issuedGenr(caids=[1, 3], valu=PKI.sha256(4))),
                lambda: ids(svc.pivotGenr(10, "key")),
                lambda: ids(svc.pivotGenr(4, "issued")),
                lambda: svc.chain(10),
                lambda: svc.cas(name="Test", certs=True),
            ):
                calls = len(fake.calls)
                await call()
                assert len(fake.calls) == calls + 1, fake.calls[calls:]

    async def test_issued(self):
        async with svcCtx(self) as (svc, fake):
            # Unparsable certificates are included, unless a validity filter drops them.
            assert await ids(svc.issuedGenr(caids=[2])) == [14, 10, 9, 15, 11, 12, 13]
            # Roots are issued by their own CA.
            assert await ids(svc.issuedGenr(caids=[1, 3])) == [4, 2, 3, 1]
            assert fake.called("certsByIssuer") == 2
            assert fake.last("certsByIssuer")["caids"] == [1, 3]

            # A CA certificate's CA, and all of the CA's certificates are equal.
            assert await ids(svc.issuedGenr(valu=PKI.sha256(4), precerts=False, limit=3)) == [
                14,
                10,
                15,
            ]
            assert fake.last("certsByIssuer")["cert"] == {"sha256": [bytes.fromhex(PKI.sha256(4))]}
            assert fake.last("certsByIssuer")["caids"] is None
            assert await ids(svc.issuedGenr(valu=2, kind="id", valid=True)) == [14, 10, 9, 11]

            # Only an empty result looks the certificate up, to explain why.
            calls = fake.called("certs")
            with pytest.raises(CrtshDbError, match="may not be a CA"):
                await ids(svc.issuedGenr(valu=10))
            assert fake.called("certs") == calls + 1
            # A CA that issued nothing (in the time range) isn't an error.
            assert await ids(svc.issuedGenr(valu=3, kind="id", since=2**60)) == []
            # Neither is one given by ID too.
            assert await ids(svc.issuedGenr(caids=[99], valu=10)) == []
            with pytest.raises(CrtshDbError, match="CA ID or certificate is required"):
                await ids(svc.issuedGenr())
            with pytest.raises(CrtshDbError, match="no certificate"):
                await ids(svc.issuedGenr(valu=999))

    async def test_pivot(self):
        async with svcCtx(self) as (svc, fake):
            assert await ids(svc.pivotGenr(4, "issued", limit=2)) == [14, 13]
            assert await ids(svc.pivotGenr(10, "siblings")) == [14, 9, 15, 11, 12, 13]
            assert await ids(svc.pivotGenr(10, "siblings", valid=True, precerts=False)) == [14, 11]
            assert await ids(svc.pivotGenr(10, "key")) == [9, 15]
            assert fake.last("related") == {
                "by": "key",
                "cert": {"id": [10]},
                "valid": False,
                "limit": 100,
            }
            assert await ids(svc.pivotGenr(10, "key", precerts=False)) == [15]
            assert fake.last("related")["limit"] == 200
            assert await ids(svc.pivotGenr(10, "subject")) == [9, 15]
            assert await ids(svc.pivotGenr(10, "serial")) == [9]
            assert await ids(svc.pivotGenr(10, "ski", limit=1)) == [9]
            assert await ids(svc.pivotGenr(PKI.sha256(13), "siblings", limit=1)) == [14]

            with pytest.raises(CrtshDbError, match="Unknown pivot"):
                await ids(svc.pivotGenr(10, "nope"))
            with pytest.raises(CrtshDbError, match="Unable to pivot by key"):
                await ids(svc.pivotGenr(13, "key"))

            with pytest.raises(CrtshDbError, match="no certificate"):
                await ids(svc.pivotGenr(999, "siblings"))

            # Nothing related isn't an error, unless there's nothing to pivot on.
            with mock.patch.object(fake, "related", new=mock.AsyncMock(return_value=[])):
                assert await ids(svc.pivotGenr(10, "ski")) == []
                assert await ids(svc.pivotGenr(13, "siblings")) == []
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

        # A certificate in more than one chain is returned once per child.
        async with svcCtx(self) as (svc, fake):
            rows = await fake.chain({"id": [10]})
            assert [r["id"] for r, _ in svc._parse(rows + rows)] == [r["id"] for r in rows]

        # CAs that cross-sign each other: CA 2 (certs 2, 4) is signed by CA 3, whose certificate
        # (14) is signed by CA 2. The chain never revisits a certificate on its path.
        pki = copy.copy(PKI)
        pki.cacerts = {1: 1, 2: 2, 4: 2, 14: 3}
        async with svcCtx(self, fake=FakeCrtshDb(pki)) as (svc, fake):
            chain = await svc.chain(10)
            assert [c["crtsh"]["id"] for c in chain["certs"]] == [10, 2, 4, 1, 14]
            assert all(len(path) == len(set(path)) for path in chain["paths"])
            assert [PKI.sha256(c) for c in (10, 4, 14, 2, 1)] in chain["paths"]
            rows = await fake.chain({"id": [10]}, maxrows=3)
            assert len(rows) == 3

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

        # A CA crt.sh has no certificate for.
        pki = copy.copy(PKI)
        pki.cacerts = {1: 1}
        async with svcCtx(self, fake=FakeCrtshDb(pki)) as (svc, fake):
            for certs in (True, False):
                cas = await svc.cas(caids=[3, 1], certs=certs)
                assert [(ca["id"], len(ca["certs"])) for ca in cas] == [(1, 1), (3, 0)]
            with pytest.raises(CrtshDbError, match="name or ID"):
                await svc.cas()

    async def test_raw(self):
        async with svcCtx(self) as (svc, fake):
            rows = await svc.rawQuery("SELECT 1", [1])
            assert rows[0]["key"] == "0102" and rows[0]["ids"] == [1, "ff"]
            assert fake.last("raw")["limit"] == 1000
            await svc.rawQuery("SELECT 1", limit=5000)
            assert fake.last("raw")["limit"] == 1000
            await svc.rawQuery("SELECT 1", limit=5)
            assert fake.last("raw")["limit"] == 5
            with pytest.raises(CrtshDbError, match="nope"):
                await svc.rawQuery("SELECT * FROM nope")
            with pytest.raises(CrtshDbError, match="Invalid args"):
                await svc.rawQuery("SELECT $1", "x")

    async def test_api(self):
        async with svcCtx(self) as (svc, fake):
            async with svc.getLocalProxy() as prox:
                retn = await prox.get(10)
                assert retn["status"] and retn["data"]["crtsh"]["id"] == 10
                retn = await prox.lookup("nope", 1)
                assert retn == {
                    "status": False,
                    "mesg": "Unknown lookup type nope, expected one of: "
                    "id, sha256, sha1, serial, ski, spki, spkisha1, subjectsha1",
                    "data": None,
                }

                items = [i async for i in prox.searchGenr(dns="vertex.link", limit=2)]
                assert [i["data"]["crtsh"]["id"] for i in items] == [10, 9]
                items = [i async for i in prox.pivotGenr(10, "nope")]
                assert items == [
                    {
                        "status": False,
                        "data": None,
                        "mesg": "Unknown pivot nope, expected one of: "
                        "issued, siblings, key, subject, serial, ski",
                    }
                ]
                assert [i["data"]["crtsh"]["id"] async for i in prox.issuedGenr(caids=[1])] == [
                    2,
                    1,
                ]

    async def test_search_ip(self):
        """IPs are matched in canonical form, and exactly (CRTSH-03)."""

        async with svcCtx(self) as (svc, fake):
            assert await ids(svc.searchGenr(ip="2001:0db8::1")) == [10, 9]
            assert await ids(svc.searchGenr(ip="2001:db8:0:0:0:0:0:1")) == [10, 9]
            assert await ids(svc.searchGenr(ip=" 1.2.3.4 ")) == [10, 9]
            # A substring of an IP is a different IP.
            assert await ids(svc.searchGenr(ip="1.2.3.4", dns="vertex.link")) == [10, 9]
            assert await ids(svc.searchGenr(ip="1.2.3.40", dns="vertex.link")) == []
            with pytest.raises(CrtshDbError, match="Invalid IP"):
                await ids(svc.searchGenr(ip="nope", dns="vertex.link"))

    async def test_search_leading_dot(self):
        """A leading dot or wildcard on --dns matches like the bare domain (CRTSH-09)."""

        async with svcCtx(self) as (svc, fake):
            expect = await ids(svc.searchGenr(dns="vertex.link"))
            assert expect
            assert await ids(svc.searchGenr(dns=".vertex.link")) == expect
            assert await ids(svc.searchGenr(dns="*.vertex.link")) == expect
            assert fake.last("certsByIdentity")["text"] == "vertex.link"

    async def test_bad_args(self):
        """Bad argument types are CrtshDbErrors, and the API wraps any error (CRTSH-04)."""

        async with svcCtx(self) as (svc, fake):
            with pytest.raises(CrtshDbError, match="Invalid CA ID"):
                await ids(svc.searchGenr(caids=["x"]))
            with pytest.raises(CrtshDbError, match="Invalid limit"):
                await svc.lookup(None, 10, limit="zz")
            with pytest.raises(CrtshDbError, match="Invalid since"):
                await ids(svc.searchGenr(dns="vertex.link", since="yesterday"))
            with pytest.raises(CrtshDbError, match="Invalid CA ID"):
                await svc.cas(caids=["x"])
            with pytest.raises(CrtshDbError, match="Invalid maxdepth"):
                await svc.chain(10, maxdepth="x")
            # A single CA ID, even 0, is a list of one.
            await ids(svc.searchGenr(caids=0))
            assert fake.last("certsByIssuer")["caids"] == [0]

            async with svc.getLocalProxy() as prox:
                retn = await prox.lookup(None, 10, limit="zz")
                assert retn == {
                    "status": False,
                    "mesg": "Invalid limit, expected an integer: zz",
                    "data": None,
                }
                items = [i async for i in prox.searchGenr(caids=["x"])]
                assert items == [
                    {"status": False, "mesg": "Invalid CA ID, expected an integer: x", "data": None}
                ]

                # Unexpected errors (ex. from the database driver) are status=False too.
                async def boom(*args, **kwargs):
                    raise RuntimeError("driver exploded")

                svc.db.certs = boom
                svc.db.certsByIdentity = boom
                with self.getLoggerStream("stormlibpp.svc") as stream:
                    retn = await prox.get(10)
                stream.seek(0)
                logs = stream.read()
                assert "Unexpected error in CrtshCellApi.get" in logs and "driver exploded" in logs
                assert retn == {
                    "status": False,
                    "mesg": "Unexpected error: RuntimeError: driver exploded",
                    "data": None,
                }
                items = [i async for i in prox.searchGenr(dns="vertex.link")]
                assert items == [
                    {
                        "status": False,
                        "mesg": "Unexpected error: RuntimeError: driver exploded",
                        "data": None,
                    }
                ]

    async def test_db_conf(self):
        conf = {
            "crtsh:dsn": "postgresql://u@db.example:5433/certs",
            "crtsh:timeout": 5,
            "crtsh:retries": 1,
            "crtsh:keepalive": 2,
            "crtsh:idle": 3,
            "crtsh:connect:timeout": 4,
            "crtsh:statement:timeout": 6,
            "crtsh:timeout:retries": 0,
        }
        # The defaults bound every query, crt.sh cancels it before the client gives up.
        async with self.getTestCell(CrtshSvc) as svc:
            assert (svc.db.timeout, svc.db.statement_timeout) == (660, 600)
            assert svc.db.timeout_retries == 1

        async with self.getTestCell(CrtshSvc, conf=conf) as svc:
            db = svc.db
            assert (
                db.dsn,
                db.timeout,
                db.retries,
                db.keepalive,
                db.idle,
                db.connect_timeout,
                db.statement_timeout,
                db.timeout_retries,
            ) == ("postgresql://u@db.example:5433/certs", 5, 1, 2, 3, 4, 6, 0)

    async def test_conf_minimums(self):
        # Numeric options can't be set below what makes sense, ex. a limit of 0 (LIMIT 0).
        bad = {
            "crtsh:timeout": -1,
            "crtsh:statement:timeout": -1,
            "crtsh:retries": -1,
            "crtsh:timeout:retries": -1,
            "crtsh:keepalive": 0,
            "crtsh:idle": 0,
            "crtsh:connect:timeout": -1,
            "crtsh:limit": 0,
            "crtsh:sql:limit": 0,
            "crtsh:candidates": 0,
        }
        for opt, valu in bad.items():
            with pytest.raises(s_exc.BadConfValu):
                async with self.getTestCell(CrtshSvc, conf={opt: valu}):
                    pass  # pragma: no cover
        # 0 still means none for the timeouts and retries.
        conf = {
            "crtsh:timeout": 0,
            "crtsh:statement:timeout": 0,
            "crtsh:retries": 0,
            "crtsh:connect:timeout": 0,
            "crtsh:limit": 1,
            "crtsh:sql:limit": 1,
            "crtsh:candidates": 1,
        }
        async with self.getTestCell(CrtshSvc, conf=conf) as svc:
            assert (svc.db.timeout, svc.db.statement_timeout, svc.db.retries) == (None, 0, 0)

    async def test_api_rawquery(self):
        # The message counts the rows, and says when they're the limit (the fake returns one).
        async with svcCtx(self, conf={"crtsh:sql:limit": 1}) as (svc, fake):
            async with svc.getLocalProxy() as prox:
                retn = await prox.rawQuery("SELECT 1", limit=100)
                assert retn["status"] and retn["data"][0]["id"] == 1
                assert retn["mesg"] == "1 rows (the limit of 1, there may be more)"
                assert fake.last("raw")["limit"] == 1
        async with svcCtx(self) as (svc, fake):
            async with svc.getLocalProxy() as prox:
                assert (await prox.rawQuery("SELECT 1"))["mesg"] == "1 rows"
                assert fake.last("raw")["limit"] == 1000
                retn = await prox.rawQuery("SELECT 1", limit=0)
                assert retn == {
                    "status": False,
                    "mesg": "Invalid limit 0, it must be at least 1.",
                    "data": None,
                }
                retn = await prox.rawQuery("SELECT * FROM nope")
                assert not retn["status"] and "nope" in retn["mesg"]

    async def test_redact_dsn_password(self):
        assert dsnSecrets(DEFAULT_DSN) == [] and dsnSecrets(None) == []
        assert dsnSecrets("postgresql://u:p%40ss@h/db?sslmode=require&password=q+r") == [
            "p%40ss",
            "p@ss",
            "q r",
            "q+r",
        ]
        assert dsnSecrets("host=h password='a b\\'c' user=u") == ["a b'c"]
        assert dsnSecrets("host=h password=zz user=u") == ["zz"]

        # A custom DSN's password never reaches Storm in an error message.
        dsn = "postgresql://mirror:s3cr%40t@db.example/certwatch"
        async with svcCtx(self, conf={"crtsh:dsn": dsn}) as (svc, fake):
            fake.fail = f"unable to connect to {dsn} (password s3cr@t rejected)"
            async with svc.getLocalProxy() as prox:
                retn = await prox.get(10)
                assert retn["mesg"] == (
                    "unable to connect to postgresql://mirror:<redacted>@db.example/certwatch "
                    "(password <redacted> rejected)"
                )
                items = [i async for i in prox.searchGenr(dns="vertex.link")]
                assert "s3cr" not in items[0]["mesg"] and "<redacted>" in items[0]["mesg"]
                retn = await prox.rawQuery("SELECT 1")
                assert "s3cr" not in retn["mesg"] and "<redacted>" in retn["mesg"]
