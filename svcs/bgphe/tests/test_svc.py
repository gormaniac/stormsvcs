"""Tests for the slib.bgphe service and its Telepath API."""

import base64
import datetime

import synapse.tests.utils as s_tests

from bgphesvc import svc as b_svc
from bgphesvc.svc import BgpHeSvcError

from . import fakebgphe as fb
from .test_norm import selfSigned


async def collect(genr):
    items = [item async for item in genr]
    return [i["cert"] for i in items if i["type"] == "cert"], items[-1]


class TestBgpHeSvc(s_tests.SynTest):
    async def test_certs(self):
        async with fb.bgpheSvc(self) as (core, svc, fake):
            certs, summary = await collect(svc.certs("GORMO.co."))
            assert len(certs) == 12
            assert summary == {
                "type": "summary",
                "domain": "gormo.co",
                "total": 12,
                "returned": 12,
                "skipped": 0,
                "invalid": 0,
                "pages": 1,
                "more": False,
            }
            assert sum(1 for c in certs if c["precert"]) == 1

            certs, summary = await collect(svc.certs("gormo.co", precerts=False))
            assert len(certs) == 11 and summary["skipped"] == 1

            certs, summary = await collect(svc.certs("nope.com"))
            assert certs == [] and summary["total"] == 0 and summary["pages"] == 1

            with self.raises(BgpHeSvcError):
                await collect(svc.certs("bad domain"))
            for limit in (0, -1, True, "5"):
                with self.raises(BgpHeSvcError):
                    await collect(svc.certs("gormo.co", limit=limit))

    async def test_certs_pages(self):
        async with fb.bgpheSvc(self) as (core, svc, fake):
            fake.state["pagesize"] = 5

            # Pages are only requested until the limit is reached.
            fake.requests.clear()
            certs, summary = await collect(svc.certs("gormo.co", limit=7))
            assert len(certs) == 7
            assert summary["pages"] == 2 and summary["more"] is True
            assert fake.requests == [
                "/certs/api/domain?domain=gormo.co",
                "/certs/api/domain?domain=gormo.co&page=2",
            ]

            # A limit on a page boundary, with pages left, has more.
            certs, summary = await collect(svc.certs("gormo.co", limit=10))
            assert summary["pages"] == 2 and summary["more"] is True

            fake.requests.clear()
            certs, summary = await collect(svc.certs("gormo.co", limit=1000))
            assert len(certs) == 12
            assert summary["pages"] == 3 and summary["more"] is False
            assert len(fake.requests) == 3

            # Limits are capped at MAX_CERTS.
            certs, summary = await collect(svc.certs("gormo.co", limit=10**9))
            assert len(certs) == 12

    async def test_certs_filters(self):
        async with fb.bgpheSvc(self) as (core, svc, fake):
            items = fake.state["certs"]["gormo.co"]
            der = selfSigned()
            fake.state["certs"]["mix.com"] = [
                # Duplicates (bgp.he.net returns a certificate once per CT log shard).
                items[0],
                items[0],
                {"certificate_der": None},
                {"certificate_der": base64.b64encode(der).decode()},
                "nope",
            ]
            certs, summary = await collect(svc.certs("mix.com"))
            assert len(certs) == 2
            assert summary["invalid"] == 2

            # The self-signed certificate is valid 2025-2099, the gormo.co one is expired.
            certs, summary = await collect(svc.certs("mix.com", valid=True))
            assert [c["subject"]["dn"] for c in certs] == ["CN=test.example.com"]
            assert summary["skipped"] == 1

        now = int(datetime.datetime.now(datetime.UTC).timestamp() * 1000)
        assert b_svc.isValid({"notafter": now + 1000}, now)
        assert not b_svc.isValid({"notafter": None}, now)
        assert not b_svc.isValid({"notbefore": now + 1, "notafter": now + 1000}, now)

    async def test_lookups(self):
        async with fb.bgpheSvc(self) as (core, svc, fake):
            data = await svc.subdomains("gormo.co")
            assert len(data["domains"]) == 4

            data = await svc.hosts("8.8.8.1/24")
            assert data["prefix"] == "8.8.8.0/24"
            assert fake.requests[-1] == "/certs/api/certificates/by-prefix?prefix=8.8.8.0&len=24"
            data = await svc.hosts("2001:4860:4860::8888")
            assert data["entries"][0]["version"] == 6

            data = await svc.whoisDomain("microsoft.com")
            assert data["fqdn"] == "microsoft.com"
            assert data["text"].lstrip().startswith("Domain Name: MICROSOFT.COM")
            assert data["rec"]["registrant"] == "Microsoft Corporation"

            data = await svc.whoisAsn("AS28000")
            assert data["asn"] == 28000
            assert "Majó" in data["text"]
            assert data["rec"]["registry"] == "lacnic"

            data = await svc.prefixes(15169)
            assert data["v4"] == 4 and data["v6"] == 2 and data["asn"] == 15169

            for meth, valu in (
                (svc.subdomains, "nope"),
                (svc.hosts, "nope"),
                (svc.whoisDomain, ""),
                (svc.whoisAsn, "ASX"),
                (svc.prefixes, -5),
            ):
                with self.raises(BgpHeSvcError):
                    await meth(valu)

    async def test_api(self):
        async with fb.bgpheSvc(self) as (core, svc, fake):
            async with svc.getLocalProxy() as prox:
                retn = await prox.whoisAsn(15169)
                assert retn["status"] is True and retn["data"]["rec"]["name"] == "GOOGLE"

                retn = await prox.whoisAsn(99)
                assert retn == {
                    "status": False,
                    "mesg": "bgp.he.net returned HTTP 400 for /whois/as99: unallocated asn",
                    "data": None,
                }

                retn = await prox.hosts("nope")
                assert retn["status"] is False and retn["mesg"] == "Invalid IP or CIDR: 'nope'"

                items = [item async for item in prox.certs("gormo.co", limit=2)]
                assert [i["status"] for i in items] == [True, True, True]
                assert items[-1]["data"]["type"] == "summary"

                fake.state["errors"]["/certs/api/domain"] = [400]
                items = [item async for item in prox.certs("gormo.co")]
                assert len(items) == 1 and items[0]["status"] is False
                assert "fake error 400" in items[0]["mesg"]

                # Unexpected errors are raised, not returned.
                async def boom(*args, **kwargs):
                    raise RuntimeError("boom")

                svc.client.whoisAsn = boom
                with self.raises(Exception):
                    await prox.whoisAsn(15169)

                async def boomGenr(*args, **kwargs):
                    raise RuntimeError("boom")
                    yield  # pragma: no cover

                svc.certs = boomGenr
                with self.raises(Exception):
                    [item async for item in prox.certs("gormo.co")]
