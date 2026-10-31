"""Live tests against the real abuse.ch APIs. Skipped unless explicitly enabled.

    # The keyless datasets only (Feodo Tracker and SSL Blacklist).
    SLIB_ABUSECH_LIVE=1 uv run pytest tests/test_live.py

    # Also the Auth-Key based APIs (read only, nothing is submitted).
    SLIB_ABUSECH_LIVE=1 ABUSECH_AUTH_KEY=<key> uv run pytest tests/test_live.py

These assert on the shape of abuse.ch's responses and that they model cleanly,
not on specific values, since abuse.ch's data changes constantly.
"""

import contextlib
import os

import pytest
import synapse.tests.utils as s_tests

from abusechsvc import AbuseChSvc


LIVE = os.environ.get("SLIB_ABUSECH_LIVE") == "1"
APIKEY = os.environ.get("ABUSECH_AUTH_KEY")

pytestmark = pytest.mark.skipif(not LIVE, reason="Set SLIB_ABUSECH_LIVE=1 to run live abuse.ch tests.")
needkey = pytest.mark.skipif(not APIKEY, reason="Set ABUSECH_AUTH_KEY to run live tests of the keyed APIs.")


@contextlib.asynccontextmanager
async def liveSvc(test, apikey=None):
    conf = {"abusech:apikey": apikey, "abusech:ratelimit": 2}
    async with test.getTestCoreProxSvc(AbuseChSvc, ssvc_conf=conf) as (core, prox, svc):
        yield core, svc


class TestLiveDatasets(s_tests.SynTest):

    async def test_feodo(self):
        async with liveSvc(self) as (core, svc):
            c2s = [c async for c in svc.feodoBlocklist(limit=5)]
            for c2 in c2s:
                assert c2["ip"] and c2["port"]
            msgs = await core.stormlist("slib.abusech.feodo --limit 5")
            self.stormHasNoErr(msgs)
            self.stormHasNoWarnErr(msgs)

    async def test_deprecated(self):
        # SSLBL's C2 IP lists were deprecated, and now only hold a notice saying so.
        async with liveSvc(self) as (core, svc):
            text = (await svc.client.fetch("sslbl", "sslipblacklist.csv"))[0].decode()
            assert "has been deprecated" in text

    async def test_sslbl(self):
        async with liveSvc(self) as (core, svc):
            certs = [c async for c in svc.sslblBlocklist("certs", limit=5)]
            assert certs and all(len(c["sha1"]) == 40 for c in certs)
            for kind in ("certs", "ja3"):
                msgs = await core.stormlist(f"slib.abusech.sslbl {kind} --limit 5")
                self.stormHasNoWarnErr(msgs)


@needkey
class TestLiveKeyed(s_tests.SynTest):

    async def test_bazaar(self):
        async with liveSvc(self, APIKEY) as (core, svc):
            samples = await svc.normBazaarRecent("100")
            assert samples and samples[0]["sha256"]
            msgs = await core.stormlist(f"slib.abusech.bazaar.lookup --hash {samples[0]['sha256']} --yield")
            self.stormHasNoWarnErr(msgs)
            assert len([m for m in msgs if m[0] == "node"]) == 1
            # Broad tags like exe make abuse.ch time out ("Query execution time exceeded threshold").
            msgs = await core.stormlist("slib.abusech.bazaar.search tag guloader --limit 5")
            self.stormHasNoWarnErr(msgs)
            msgs = await core.stormlist("slib.abusech.bazaar.cscb")
            self.stormHasNoWarnErr(msgs)

    async def test_bulk(self):
        # The smallest export (~400 KB), built and ingested in bulk.
        async with liveSvc(self, APIKEY) as (core, svc):
            msgs = await core.stormlist("slib.abusech.bazaar.export recent --bulk")
            self.stormIsInPrint("Ingested", msgs)
            assert not [m for m in msgs if m[0] == "err"]
            assert await core.count("file:bytes") > 0

    async def test_urlhaus(self):
        async with liveSvc(self, APIKEY) as (core, svc):
            urls = await svc.normUrlhausRecent("urls", limit=3)
            assert urls and urls[0]["url"]
            msgs = await core.stormlist(f"slib.abusech.urlhaus.lookup --url {urls[0]['url']} --yield")
            self.stormHasNoWarnErr(msgs)
            msgs = await core.stormlist("slib.abusech.urlhaus.search recent-payloads --limit 3")
            self.stormHasNoWarnErr(msgs)

    async def test_threatfox(self):
        async with liveSvc(self, APIKEY) as (core, svc):
            iocs = await svc.normThreatfox("recent", 1, limit=10)
            assert iocs and iocs[0]["ioc"]
            msgs = await core.stormlist("slib.abusech.threatfox.search recent 1 --limit 10")
            self.stormHasNoWarnErr(msgs)
            msgs = await core.stormlist("slib.abusech.threatfox.ref types")
            self.stormHasNoWarnErr(msgs)

    async def test_yaraify(self):
        async with liveSvc(self, APIKEY) as (core, svc):
            rules = await svc.normYaraifyRecentRules()
            assert isinstance(rules, list)
            msgs = await core.stormlist("slib.abusech.yaraify.rules --recent")
            self.stormHasNoWarnErr(msgs)

    async def test_fplist(self):
        async with liveSvc(self, APIKEY) as (core, svc):
            fps = await svc.normFplist()
            assert isinstance(fps, list)
