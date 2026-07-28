"""Pytests for ipapi's request queue and rate-limit handling."""

import asyncio
import pathlib
from unittest import mock

import synapse.tests.utils as s_tests
import vcr

from ipapi.svc import IpApiSvc, _RateLimited


CASSETTE_DIR = pathlib.Path(__file__).parent / "vcr_cassettes"


class TestIpApiSvcQueue(s_tests.SynTest):
    """Test suite for IpApiSvc's queued, rate-limited queryIp()."""

    async def test_query_success(self):
        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:

                async def fake_query(ipaddr):
                    return {"status": "success", "query": ipaddr}, {}

                with mock.patch.object(svc, "_query", fake_query):
                    retn = await svc.queryIp("1.2.3.4")

                assert retn["status"] is True
                assert retn["data"]["query"] == "1.2.3.4"

    async def test_query_business_failure(self):
        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:

                async def fake_query(ipaddr):
                    return {"status": "fail", "message": "reserved range"}, {}

                with mock.patch.object(svc, "_query", fake_query):
                    retn = await svc.queryIp("10.0.0.1")

                assert retn["status"] is False
                assert retn["data"] is None

    async def test_fifo_order(self):
        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:

                seen = []

                async def fake_query(ipaddr):
                    seen.append(ipaddr)
                    return {"status": "success", "query": ipaddr}, {}

                ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]

                with mock.patch.object(svc, "_query", fake_query):
                    tasks = []
                    for ip in ips:
                        tasks.append(asyncio.create_task(svc.queryIp(ip)))
                        # Let each task run up to the point where it enqueues
                        # its request, before creating the next one, so the
                        # queue order matches submission order.
                        await asyncio.sleep(0)

                    results = await asyncio.gather(*tasks)

                assert seen == ips
                assert [r["data"]["query"] for r in results] == ips

    async def test_preemptive_throttle_on_zero_remaining(self):
        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:

                call_times = []

                async def fake_query(ipaddr):
                    call_times.append(asyncio.get_running_loop().time())
                    if ipaddr == "1.1.1.1":
                        return (
                            {"status": "success", "query": ipaddr},
                            {"X-Rl": "0", "X-Ttl": "0.2"},
                        )
                    return {"status": "success", "query": ipaddr}, {}

                with mock.patch.object(svc, "_query", fake_query):
                    task1 = asyncio.create_task(svc.queryIp("1.1.1.1"))
                    await asyncio.sleep(0)
                    task2 = asyncio.create_task(svc.queryIp("2.2.2.2"))

                    await asyncio.gather(task1, task2)

                assert len(call_times) == 2
                assert call_times[1] - call_times[0] >= 0.15

    async def test_429_retry(self):
        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:

                calls = []

                async def fake_query(ipaddr):
                    calls.append(ipaddr)
                    if len(calls) == 1:
                        raise _RateLimited(ttl="0.05")
                    return {"status": "success", "query": ipaddr}, {}

                with mock.patch.object(svc, "_query", fake_query):
                    retn = await svc.queryIp("5.5.5.5")

                assert retn["status"] is True
                assert calls == ["5.5.5.5", "5.5.5.5"]

    async def test_fini_cancels_pending(self):
        with self.getTestDir() as dirn:
            svc = await IpApiSvc.anit(dirn)

            async def fake_query(ipaddr):
                await asyncio.sleep(10)
                return {"status": "success", "query": ipaddr}, {}

            with mock.patch.object(svc, "_query", fake_query):
                task = asyncio.create_task(svc.queryIp("6.6.6.6"))
                await asyncio.sleep(0)

                await svc.fini()

                with self.raises(asyncio.CancelledError):
                    await task


class TestIpApiSvcQueryHttp(s_tests.SynTest):
    """Test suite for IpApiSvc._query()'s real HTTP request/response handling."""

    async def test_query_parses_success_response(self):
        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:
                with vcr.use_cassette(str(CASSETTE_DIR / "ipapi_query_success.yaml")):
                    data, headers = await svc._query("8.8.8.8")

                assert data["status"] == "success"
                assert data["query"] == "8.8.8.8"
                assert data["as_"] == "AS15169 Google LLC"
                assert "as" not in data
                assert data["isp"] == "Google LLC"
                assert data["lat"] == 39.03
                assert data["lon"] == -77.5
                assert data["hosting"] is True

                assert headers["X-Rl"] == "44"
                assert headers["X-Ttl"] == "60"

    async def test_query_raises_on_429(self):
        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:
                with vcr.use_cassette(str(CASSETTE_DIR / "ipapi_query_ratelimited.yaml")):
                    with self.raises(_RateLimited) as cm:
                        await svc._query("9.9.9.9")

                assert cm.exception.ttl == "5"
