"""Live tests against the real ANY.RUN API. Skipped unless explicitly enabled.

    SLIB_ANYRUN_LIVE=1 SLIB_ANYRUN_APIKEY=<key> uv run pytest tests/test_live.py

These only make read-only requests (no submissions, deletes, or YARA searches), and assert on
the shape of ANY.RUN's responses, since its data changes constantly. The TI tests also need a
TI license and are skipped (not failed) when the key doesn't have one. Set SLIB_ANYRUN_TASK to
a task your key can read to also check reports, IOCs, and downloads.
"""

import os

import aiohttp
import pytest

from anyrunsvc import norm
from anyrunsvc.client import AnyRunApiError, AnyRunClient

LIVE = os.environ.get("SLIB_ANYRUN_LIVE") == "1"
APIKEY = os.environ.get("SLIB_ANYRUN_APIKEY")
TASK = os.environ.get("SLIB_ANYRUN_TASK")

pytestmark = pytest.mark.skipif(
    not (LIVE and APIKEY), reason="Set SLIB_ANYRUN_LIVE=1 and SLIB_ANYRUN_APIKEY to run live ANY.RUN tests."
)

NO_LICENSE = ("NO_TI_LICENSE_ERROR", "API_LOOKUP_DISABLED_ERROR", "LICENSE_REQUIRED_ERROR")


async def test_live_sandbox():
    async with aiohttp.ClientSession(trust_env=True) as session:
        cli = AnyRunClient(session, APIKEY)

        _, data = await cli.request("get", "/v1/user")
        assert "api" in data["data"]["limits"]

        _, data = await cli.request("get", "/v1/environment")
        assert data["data"]["environments"]

        _, data = await cli.request("get", "/v1/analysis", params={"limit": 5})
        for item in data["data"]["tasks"]:
            assert norm.normTask(item)["uuid"]

        with pytest.raises(AnyRunApiError) as exc:
            await AnyRunClient(session, "wrong").request("get", "/v1/user")
        assert exc.value.status in (401, 403)


@pytest.mark.skipif(not TASK, reason="Set SLIB_ANYRUN_TASK to a task UUID the key can read.")
async def test_live_task():
    async with aiohttp.ClientSession(trust_env=True) as session:
        cli = AnyRunClient(session, APIKEY)
        _, data = await cli.request("get", f"/v1/analysis/{TASK}")
        rep = norm.normReport(data["data"])
        assert rep["uuid"] == TASK and rep["verdict"] in (10, 30, 40)
        assert rep["file"] or rep["url"]

        _, iocs = await cli.request("get", f"/report/{TASK}/ioc/json")
        assert isinstance(iocs, list)

        events = []
        async for event in cli.events(f"/v1/analysis/monitor/{TASK}"):
            events.append(norm.normStatus(event))
            break
        assert events and events[0]["state"] in ("completed", "failed", "running", "preparing", "unknown")


async def test_live_lookup():
    async with aiohttp.ClientSession(trust_env=True) as session:
        cli = AnyRunClient(session, APIKEY)
        try:
            _, data = await cli.request(
                "post", "/v1/intelligence/api/search", json_data={"query": 'domainName:"google.com"'}
            )
        except AnyRunApiError as err:
            if err.code in NO_LICENSE:
                pytest.skip(f"The key has no TI Lookup license ({err.code}).")
            raise
        ret = norm.normLookup(data)
        assert "summary" in data and isinstance(ret["tasks"], list)
