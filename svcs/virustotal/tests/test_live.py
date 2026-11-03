"""Live tests against the real VirusTotal API. Skipped unless explicitly enabled.

    SLIB_VT_LIVE=1 VT_API_KEY=<key> uv run pytest tests/test_live.py -s

These run through the service with its default (Public API) limits, so they never send more
than 4 requests a minute: the ~12 requests here take about 3 minutes. They're read-only (no
submissions, rescans, comments, or votes), and assert on the shape of VirusTotal's responses,
since its data changes constantly.
"""

import os
import time

import pytest
import synapse.tests.utils as s_tests

from vtsvc import VtSvc
from vtsvc.quota import keyId

LIVE = os.environ.get("SLIB_VT_LIVE") == "1" and os.environ.get("VT_API_KEY")

pytestmark = pytest.mark.skipif(
    not LIVE, reason="Set SLIB_VT_LIVE=1 and VT_API_KEY to run live VirusTotal tests."
)

WANNACRY = "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"


class TestLive(s_tests.SynTest):
    async def test_live(self):
        key = os.environ["VT_API_KEY"]
        conf = {"vt:apikey": key}
        async with self.getTestCoreProxSvc(VtSvc, ssvc_conf=conf) as (core, prox, svc):
            start = time.monotonic()

            async def run(query, nodes=False):
                msgs = await core.stormlist(query)
                for m in msgs:
                    if m[0] in ("print", "warn", "err"):
                        print(m[0], m[1].get("mesg"))
                self.stormHasNoWarnErr(msgs)
                return msgs

            await run(f"slib.vt.enrich --hash {WANNACRY} --behaviour")
            assert len(await core.nodes(f"file:bytes=sha256:{WANNACRY} -> it:av:scan:result")) > 10
            assert await core.count(f"file:bytes=sha256:{WANNACRY} -(uses)> it:mitre:attack:technique")
            assert await core.count(f"file:bytes=sha256:{WANNACRY} -> it:app:yara:match")

            await run("slib.vt.enrich --fqdn example.com --ip 8.8.8.8 --url http://www.eicar.org/download/eicar.com.txt")
            assert await core.count("inet:dns:a:fqdn=example.com")
            assert await core.count("inet:whois:rec:fqdn=example.com")
            assert (await core.nodes("inet:ipv4=8.8.8.8"))[0].get("asn") == 15169

            await run("inet:fqdn=example.com | slib.vt.related --rel resolutions --limit 5")
            await run("inet:fqdn=example.com | slib.vt.related --rel historical_whois --limit 2")
            assert await core.count("inet:whois:rec:fqdn=example.com") >= 2
            msgs = await run("inet:ipv4=8.8.8.8 | slib.vt.related --rel historical_ssl_certificates --limit 2")
            assert await core.count("inet:tls:servercert:server=tcp://8.8.8.8:443") >= 2, msgs
            await run(f"file:bytes=sha256:{WANNACRY} | slib.vt.related --rel contacted_domains --limit 3")
            await run(f"file:bytes=sha256:{WANNACRY} | slib.vt.comments --limit 3")
            nodes = await core.nodes("slib.vt.search 8.8.8.8")
            assert [n.ndef[0] for n in nodes] == ["inet:ipv4"]
            await run("slib.vt.quota --remote")

            # Looking something up again is answered from the cache.
            used = svc.limiter.counts(keyId(key))["day"]
            await run("slib.vt.enrich --fqdn example.com")
            assert svc.limiter.counts(keyId(key))["day"] == used

            # The service never sent more than 4 requests in a minute.
            assert used == 12
            assert time.monotonic() - start >= 60 * (used - 4) / 4 - 1
