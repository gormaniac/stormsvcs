"""Live tests against the real Malpedia API. Skipped unless explicitly enabled.

    SLIB_MALPEDIA_LIVE=1 uv run pytest tests/test_live.py

These only make a few small, read-only requests (never the bulk endpoints, so never a full
pull), and assert on the shape of Malpedia's responses, since its data changes constantly.
"""

import os

import aiohttp
import pytest

from malpediasvc import norm
from malpediasvc.client import MalpediaClient

LIVE = os.environ.get("SLIB_MALPEDIA_LIVE") == "1"

pytestmark = pytest.mark.skipif(not LIVE, reason="Set SLIB_MALPEDIA_LIVE=1 to run live Malpedia tests.")


async def test_live_small_endpoints():
    async with aiohttp.ClientSession(trust_env=True) as session:
        cli = MalpediaClient(session)

        version = await cli.version()
        assert isinstance(version["version"], int)
        assert version["date"]

        found = await cli.findActor("fancy bear")
        assert any(item["name"] == "apt28" for item in found)

        fam = await cli.getFamily("win.xagent")
        rec = norm.normFamily("win.xagent", fam)
        assert rec["name"] == "X-Agent"
        assert "APT28" in rec["unresolved"]

        rules = norm.yaraTlpRules(await cli.getYaraFamily("win.xagent"))
        assert rules
        for tlp, filename, text in rules:
            yara = norm.normYara(filename, text, tlp=tlp, family="win.xagent")
            assert yara["name"]
            assert yara["tlp"] == "white"

        bibs, errors = norm.parseBib(await cli.getBibFamily("win.xagent"))
        assert bibs and not errors
        assert all(rec["title"] for rec in bibs.values())
