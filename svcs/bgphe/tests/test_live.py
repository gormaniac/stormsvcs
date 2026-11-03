"""Live tests against the real bgp.he.net. Skipped unless explicitly enabled.

    SLIB_BGPHE_LIVE=1 uv run pytest tests/test_live.py

These make one request to each endpoint (a single page of certificates), and assert on the shape
of the responses, since bgp.he.net's data changes constantly.
"""

import os

import aiohttp
import pytest

from bgphesvc import certs, norm, whois
from bgphesvc.client import BgpHeApiError, BgpHeClient

LIVE = os.environ.get("SLIB_BGPHE_LIVE") == "1"

pytestmark = pytest.mark.skipif(not LIVE, reason="Set SLIB_BGPHE_LIVE=1 to run live bgp.he.net tests.")


async def test_live_endpoints():
    async with aiohttp.ClientSession(trust_env=True) as session:
        cli = BgpHeClient(session)

        data = await cli.certsByDomain("vertex.link")
        assert data["pagination"]["page_size"] == 200
        parsed = [certs.heCert(item) for item in data["certificates"]]
        assert parsed and all(c is not None and not c.get("error") for c in parsed)
        assert any("vertex.link" in c["identities"]["fqdns"] for c in parsed)

        subs = norm.normSubdomains("vertex.link", await cli.certDomains("vertex.link"))
        assert "vertex.link" in [row["fqdn"] for row in subs["domains"]]

        hosts = norm.normHosts(norm.normPrefix("8.8.8.8"), await cli.certsByPrefix("8.8.8.8", 32))
        assert hosts["entries"][0]["ip"] == "8.8.8.8"
        assert hosts["entries"][0]["fqdns"]

        rec = whois.parseDomain("vertex.link", await cli.whoisDomain("vertex.link"))
        assert rec["created"] and rec["nameservers"]

        rec = whois.parseAsn(15169, await cli.whoisAsn(15169))
        assert rec["name"] == "GOOGLE" and rec["orgname"] == "Google LLC"

        rows = norm.normPrefixes(await cli.prefixesOriginated(15169))
        assert any(row["prefix"] == "8.8.8.0/24" for row in rows)

        with pytest.raises(BgpHeApiError, match="unallocated asn"):
            await cli.whoisAsn(4294967294)
