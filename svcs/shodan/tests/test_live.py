"""Live tests against the real Shodan APIs. Skipped unless explicitly enabled.

    # Keyless APIs only (InternetDB and CVEDB).
    SLIB_SHODAN_LIVE=1 uv run pytest tests/test_live.py

    # Also the API key based APIs (uses a little query credit, never scan credits).
    SLIB_SHODAN_LIVE=1 SHODAN_API_KEY=<key> uv run pytest tests/test_live.py

These assert on the shape of Shodan's responses and that they model cleanly,
not on specific values, since Shodan's data changes constantly.
"""

import base64
import contextlib
import hashlib
import os

import pytest
import synapse.tests.utils as s_tests

from shodansvc import ShodanSvc, norm
from shodansvc.client import ShodanApiError


LIVE = os.environ.get("SLIB_SHODAN_LIVE") == "1"
APIKEY = os.environ.get("SHODAN_API_KEY")

pytestmark = pytest.mark.skipif(not LIVE, reason="Set SLIB_SHODAN_LIVE=1 to run live Shodan tests.")
needkey = pytest.mark.skipif(
    not APIKEY, reason="Set SHODAN_API_KEY to run live tests of keyed APIs."
)


@contextlib.asynccontextmanager
async def liveSvc(test, apikey=None):
    conf = {"shodan:apikey": apikey}
    async with test.getTestCoreProxSvc(ShodanSvc, ssvc_conf=conf) as (core, prox, svc):
        yield core, svc


class TestLiveKeyless(s_tests.SynTest):
    async def test_internetdb(self):
        async with liveSvc(self) as (core, svc):
            data = await svc.normInternetDb("8.8.8.8")
            assert data["ip"] == "8.8.8.8"
            assert 53 in data["ports"]

            # Without a key, slib.shodan.host falls back to InternetDB.
            msgs = await core.stormlist("slib.shodan.host --ip 8.8.8.8 --yield")
            self.stormHasNoErr(msgs)
            self.stormIsInWarn("falling back to InternetDB", msgs)
            assert len(await core.nodes("inet:server=tcp://8.8.8.8:53")) == 1

            # IPs InternetDB hasn't seen are a 404, reported as a warning.
            msgs = await core.stormlist("slib.shodan.host --ip 192.0.2.1 --internetdb")
            self.stormIsInWarn(
                "InternetDB lookup of 192.0.2.1 failed: No information available", msgs
            )

    async def test_cvedb_cve(self):
        async with liveSvc(self) as (core, svc):
            msgs = await core.stormlist("slib.shodan.cve --cve CVE-2021-44228 --yield")
            self.stormHasNoErr(msgs)
            vuln = (await core.nodes("risk:vuln:cve=cve-2021-44228"))[0]
            assert vuln.get("cvss:v3_1:score") == 10.0
            assert vuln.get("cve:references")
            assert vuln.get("timeline:published") is not None
            assert "rep.shodan.kev" in vuln.tags

            msgs = await core.stormlist("slib.shodan.cve --cve CVE-1999-99999")
            self.stormIsInWarn("No information available", msgs)

    async def test_cvedb_advisories(self):
        async with liveSvc(self) as (core, svc):
            msgs = await core.stormlist(
                "slib.shodan.cve --cve GHSA-jfh8-c2jp-5v3q --cve EUVD-2021-1252 --yield"
            )
            self.stormHasNoErr(msgs)

            vuln = (await core.nodes("risk:vuln:cve=cve-2021-44228"))[0]
            assert "ghsa-jfh8-c2jp-5v3q" in vuln.get("names")
            assert vuln.get("cwes")

            # EUVD-2021-1252 is linked to CVE-2020-12118.
            vuln = (await core.nodes("risk:vuln:cve=cve-2020-12118"))[0]
            assert "euvd-2021-1252" in vuln.get("names")

    async def test_cvedb_search(self):
        async with liveSvc(self) as (core, svc):
            msgs = await core.stormlist("slib.shodan.cve --product log4j --kev --count")
            self.stormHasNoErr(msgs)
            self.stormIsInPrint("matching CVEs", msgs)

            msgs = await core.stormlist(
                "slib.shodan.cve --product log4j --kev --epss --limit 3 --yield"
            )
            self.stormHasNoErr(msgs)
            nodes = [m for m in msgs if m[0] == "node"]
            assert 0 < len(nodes) <= 3

            # CVEDB returns short CPEs, they must be padded to be valid it:sec:cpe nodes.
            msgs = await core.stormlist("slib.shodan.cpe nginx --limit 3 --yield")
            self.stormHasNoErr(msgs)
            assert len([m for m in msgs if m[0] == "node"]) == 3

            msgs = await core.stormlist(
                "[ it:sec:cpe='cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*' ] | slib.shodan.enrich --yield"
            )
            self.stormHasNoErr(msgs)
            assert len(await core.nodes("risk:vuln:cve=cve-2021-44228")) == 1


@needkey
class TestLiveKeyed(s_tests.SynTest):
    async def test_host(self):
        async with liveSvc(self, apikey=APIKEY) as (core, svc):
            msgs = await core.stormlist("slib.shodan.host --ip 8.8.8.8 --yield")
            self.stormHasNoErr(msgs)
            assert len(await core.nodes("inet:ipv4=8.8.8.8 -> inet:server")) >= 2
            assert (await core.nodes("inet:ipv4=8.8.8.8"))[0].get("asn") == 15169

    async def test_free_endpoints(self):
        # These don't use query or scan credits.
        async with liveSvc(self, apikey=APIKEY) as (core, svc):
            for query in (
                "slib.shodan.info",
                "slib.shodan.ref ports",
                "slib.shodan.ref filters",
                "slib.shodan.ref triggers",
                "slib.shodan.ref providers",
                'slib.shodan.search "port:22" --count --facets country:3',
                'slib.shodan.search "apache port:8080" --tokens',
                "slib.shodan.alert.list",
                "slib.shodan.notifier.list",
                "slib.shodan.scan.status",
            ):
                msgs = await core.stormlist(query)
                self.stormHasNoErr(msgs)
                assert not [m for m in msgs if m[0] == "warn"], (query, msgs)

    async def test_dns(self):
        async with liveSvc(self, apikey=APIKEY) as (core, svc):
            msgs = await core.stormlist("[ inet:fqdn=dns.google ] | slib.shodan.dns.lookup --yield")
            self.stormHasNoErr(msgs)
            assert len(await core.nodes("inet:dns:a:fqdn=dns.google")) >= 1

    async def test_form_endpoints(self):
        # These only read their arguments from a form body, query params are silently ignored
        # (POST /shodan/scan then fails with "Private IPs not allowed: "). Invalid arguments
        # prove Shodan parsed them, without submitting a scan or creating a notifier.
        async with liveSvc(self, apikey=APIKEY) as (_core, svc):
            with self.raises(ShodanApiError) as cm:
                await svc.scan(["not-an-ip"])
            assert cm.exception.mesg == "Empty list of IPs"

            with self.raises(ShodanApiError) as cm:
                await svc.scanInternet(1, "not-a-protocol")
            assert cm.exception.mesg == "Unknown protocol"

            with self.raises(ShodanApiError) as cm:
                await svc.notifierCreate("webhook", {})
            assert cm.exception.mesg == "Invalid arguments for the provider"

    async def test_host_softvers(self):
        async with liveSvc(self, apikey=APIKEY) as (core, _svc):
            msgs = await core.stormlist("slib.shodan.host --ip 45.33.32.156")
            self.stormHasNoErr(msgs)
            # scanme.nmap.org's banners list OS CPEs (ex. Ubuntu's) next to OpenSSH's and Apache's.
            # A banner's product/version must never be applied to an OS CPE.
            assert await core.nodes("it:prod:softver")
            nodes = await core.nodes("it:prod:softver:cpe^='cpe:2.3:o:'")
            assert all(n.get("name") is None and n.get("vers") is None for n in nodes)

    async def test_banner_hash_and_ssh_key(self):
        async with liveSvc(self, apikey=APIKEY) as (core, svc):
            # scanme.nmap.org, which Nmap allows scanning, has long had SSH on port 22.
            host = await svc.host("45.33.32.156")
            banners = host["data"]
            assert banners
            for banner in banners:
                # Shodan's banner hash is a MurmurHash3 of the banner's text.
                assert norm.bannerHash(banner["data"]) == banner["hash"], banner["port"]

            ssh = [b for b in banners if b.get("ssh")]
            assert ssh
            key = norm.normSshKey(ssh[0]["ssh"])
            blob = base64.b64decode(key["text"].split()[1])
            fprint = hashlib.md5(blob).hexdigest()
            assert ":".join(fprint[i : i + 2] for i in range(0, 32, 2)) == ssh[0]["ssh"]["fingerprint"]

            # The free count API supports searching by the hash.
            count = await svc.count(f"hash:{ssh[0]['hash']}")
            assert count["total"] >= 1

            msgs = await core.stormlist("slib.shodan.host --ip 45.33.32.156")
            self.stormHasNoErr(msgs)
            nodes = await core.nodes("inet:server=tcp://45.33.32.156:22 -> inet:servfile -> file:bytes")
            assert [n.ndef[1] for n in nodes] == [f"sha256:{key['sha256']}"]
