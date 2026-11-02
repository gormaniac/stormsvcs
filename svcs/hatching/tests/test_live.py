"""Live tests against the real Hatching Triage API. Skipped unless an API key is given.

    HATCHING_LIVE_APIKEY=<key> uv run pytest tests/test_live.py

    # A private cloud or self-hosted instance.
    HATCHING_LIVE_APIKEY=<key> HATCHING_LIVE_URL=https://private.tria.ge uv run pytest tests/test_live.py

These are read only (nothing is submitted, changed, or deleted). They assert on the shape of
Triage's responses and that a public sample models cleanly, not on specific values.
"""

import contextlib
import os

import pytest
import synapse.tests.utils as s_tests

from hatchingsvc import HatchingSvc


APIKEY = os.environ.get("HATCHING_LIVE_APIKEY")
URL = os.environ.get("HATCHING_LIVE_URL", "https://tria.ge")

pytestmark = pytest.mark.skipif(not APIKEY, reason="Set HATCHING_LIVE_APIKEY to run live Triage tests.")


@contextlib.asynccontextmanager
async def liveSvc(test):
    conf = {"hatching:apikey": APIKEY, "hatching:url": URL}
    async with test.getTestCoreProxSvc(HatchingSvc, ssvc_conf=conf) as (core, prox, svc):
        yield core, svc


class TestLive(s_tests.SynTest):

    async def test_search_and_model(self):
        async with liveSvc(self) as (core, svc):
            samples = await svc.search("family:emotet", limit=5)
            assert samples and all("id" in s and "status" in s for s in samples)

            sid = next(s["id"] for s in samples if s["status"] == "reported")
            info = await svc.sample(sid)
            assert info["id"] == sid and info["tasks"]

            overview = await svc.overview(sid)
            assert "analysis" in overview and "sample" in overview

            result = await svc.normSample(sid, tasks=True)
            assert result["id"] == sid and result["score"] and result["tasks"]
            assert result["file"]["sha256"] and result["signatures"]

            msgs = await core.stormlist(f"slib.hatching.enrich --sample {sid} --tasks --yield")
            self.stormHasNoErr(msgs)
            assert [m for m in msgs if m[0] == "node"]

    async def test_profiles_and_rules(self):
        async with liveSvc(self) as (core, svc):
            assert isinstance(await svc.profiles(), list)
            assert isinstance(await svc.rules(), list)

    async def test_resources_geolocations_stats(self):
        async with liveSvc(self) as (core, svc):
            resources = await svc.resources()
            assert resources and all("tags" in r for r in resources)
            assert isinstance(await svc.geolocations(), list)
            assert "samples_submitted" in await svc.stats()
