"""Pytests for ipapi's request queue and rate-limit handling."""

import asyncio
import pathlib
import runpy
import sys
from unittest import mock

import aiohttp
import synapse.tests.utils as s_tests
import vcr

import ipapi.svc as s_ipapi
from ipapi.svc import (
    BATCH_SIZE,
    DEFAULT_RL_TTL,
    HTTP_TIMEOUT,
    MAX_RL_RETRIES,
    IpApiSvc,
    _RateLimited,
    shapeData,
)


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

    async def test_multiple_429_retries(self):
        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:
                calls = []

                async def fake_query(ipaddr):
                    calls.append(ipaddr)
                    if len(calls) < 3:
                        raise _RateLimited(ttl="0.01")
                    return {"status": "success", "query": ipaddr}, {}

                with mock.patch.object(svc, "_query", fake_query):
                    retn = await svc.queryIp("7.7.7.7")

                assert retn["status"] is True
                assert calls == ["7.7.7.7", "7.7.7.7", "7.7.7.7"]

    async def test_shape_data(self):
        data = shapeData({"as": "AS15169 Google LLC", "query": "8.8.8.8"})
        assert data["as_"] == "AS15169 Google LLC"
        assert data["asnum"] == 15169
        assert data["asorg"] == "Google LLC"
        assert "as" not in data

        # Only the number, no org name.
        data = shapeData({"as": "AS64512"})
        assert data["asnum"] == 64512
        assert data["asorg"] == ""

        # An "S" or "A" at the start of the org name must survive, unlike str.strip("AS").
        data = shapeData({"as": "AS7018 SAS Networks"})
        assert data["asnum"] == 7018
        assert data["asorg"] == "SAS Networks"

        for as_ in ("", None, "not-a-valid-asn-format"):
            data = shapeData({"as": as_})
            assert data["asnum"] is None
            assert data["asorg"] == ""

        data = shapeData({})
        assert data["as_"] == ""
        assert data["asnum"] is None

    async def test_checkratelimit_ignores_non_numeric_header(self):
        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:
                slept = []
                with mock.patch.object(svc, "_sleepTtl", mock.AsyncMock(side_effect=slept.append)):
                    await svc._checkRateLimit({"X-Rl": "not-a-number", "X-Ttl": "5"})

                assert slept == []

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
                retn = await task

            assert retn["status"] is False
            assert retn["data"] is None
            assert "shutting down" in retn["mesg"]

    async def test_fini_drains_queued(self):
        """Requests still waiting in the queue (behind a slow one) are all cancelled on fini."""

        with self.getTestDir() as dirn:
            svc = await IpApiSvc.anit(dirn)

            async def fake_query(ipaddr):
                await asyncio.sleep(10)
                return {"status": "success", "query": ipaddr}, {}

            with mock.patch.object(svc, "_query", fake_query):
                tasks = []
                for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3"):
                    tasks.append(asyncio.create_task(svc.queryIp(ip)))
                    await asyncio.sleep(0)

                # A queued item whose future is already cancelled is skipped by the drain.
                done = asyncio.get_running_loop().create_future()
                done.cancel()
                svc.queue.put_nowait(s_ipapi._QueueItem("json", "4.4.4.4", done))

                await asyncio.sleep(0)
                assert svc.queue.qsize() == 3

                await svc.fini()
                retns = await asyncio.gather(*tasks)

            assert svc.queue.empty()
            for retn in retns:
                assert retn["status"] is False
                assert "shutting down" in retn["mesg"]

    async def test_caller_cancel_propagates(self):
        """A caller cancelling its own queryIp() gets a CancelledError, and the worker
        skips the cancelled request without breaking later ones."""

        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:
                gate = asyncio.Event()
                seen = []

                async def fake_query(ipaddr):
                    seen.append(ipaddr)
                    if ipaddr == "1.1.1.1":
                        await gate.wait()
                    return {"status": "success", "query": ipaddr}, {}

                with mock.patch.object(svc, "_query", fake_query):
                    task1 = asyncio.create_task(svc.queryIp("1.1.1.1"))
                    await asyncio.sleep(0)
                    task2 = asyncio.create_task(svc.queryIp("2.2.2.2"))
                    await asyncio.sleep(0)

                    # Cancel the queued (not yet worked) request.
                    task2.cancel()
                    with self.raises(asyncio.CancelledError):
                        await task2

                    # Cancel the in-flight request too.
                    task1.cancel()
                    with self.raises(asyncio.CancelledError):
                        await task1
                    gate.set()

                    retn = await svc.queryIp("3.3.3.3")

                assert retn["status"] is True
                assert "2.2.2.2" not in seen

    async def test_workqueue_generic_exception(self):
        """An unexpected exception in the worker is returned as a status=False retn and
        the worker keeps working the queue."""

        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:
                calls = []
                orig = svc._processQuery

                async def fake_process(ipaddr):
                    calls.append(ipaddr)
                    if len(calls) == 1:
                        raise RuntimeError("worker boom")
                    return await orig(ipaddr)

                async def fake_query(ipaddr):
                    return {"status": "success", "query": ipaddr}, {}

                with (
                    mock.patch.object(svc, "_processQuery", fake_process),
                    mock.patch.object(svc, "_query", fake_query),
                ):
                    retn = await svc.queryIp("1.1.1.1")
                    assert retn["status"] is False
                    assert retn["data"] is None
                    assert "RuntimeError: worker boom" in retn["mesg"]

                    retn = await svc.queryIp("2.2.2.2")
                    assert retn["status"] is True

    async def test_429_retries_capped(self):
        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:
                calls = []

                async def fake_query(ipaddr):
                    calls.append(ipaddr)
                    raise _RateLimited(ttl="0")

                with mock.patch.object(svc, "_query", fake_query):
                    retn = await svc.queryIp("8.8.8.8")

                assert retn["status"] is False
                assert retn["data"] is None
                assert "rate limiting" in retn["mesg"]
                assert len(calls) == MAX_RL_RETRIES + 1

    async def test_query_timeout(self):
        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:
                assert svc.sess.timeout.total == HTTP_TIMEOUT

                async def fake_query(ipaddr):
                    raise asyncio.TimeoutError()

                with mock.patch.object(svc, "_query", fake_query):
                    retn = await svc.queryIp("8.8.8.8")

                assert retn["status"] is False
                assert "Timed out" in retn["mesg"]

    async def test_query_unexpected_exception(self):
        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:

                async def fake_query(ipaddr):
                    raise ValueError("bad json")

                with mock.patch.object(svc, "_query", fake_query):
                    retn = await svc.queryIp("8.8.8.8")

                assert retn["status"] is False
                assert "ValueError: bad json" in retn["mesg"]

    async def test_sleepttl_fallback(self):
        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:
                sleep = mock.AsyncMock()
                with mock.patch.object(s_ipapi.asyncio, "sleep", sleep):
                    await svc._sleepTtl(None)
                    await svc._sleepTtl("not-a-number")
                    await svc._sleepTtl("2.5")
                    await svc._sleepTtl("0")

                assert [c.args[0] for c in sleep.await_args_list] == [
                    DEFAULT_RL_TTL,
                    DEFAULT_RL_TTL,
                    2.5,
                ]

    async def test_checkratelimit_remaining(self):
        """Only sleep when no requests are left in the window, not when one is."""

        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:
                slept = []
                with mock.patch.object(svc, "_sleepTtl", mock.AsyncMock(side_effect=slept.append)):
                    await svc._checkRateLimit({})
                    await svc._checkRateLimit({"X-Rl": "1", "X-Ttl": "5"})
                    assert slept == []

                    await svc._checkRateLimit({"X-Rl": "0", "X-Ttl": "5"})
                    assert slept == ["5"]


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
                assert data["asnum"] == 15169
                assert data["asorg"] == "Google LLC"
                assert data["reverse"] == "dns.google"
                assert "as" not in data
                assert data["isp"] == "Google LLC"
                assert data["lat"] == 39.03
                assert data["lon"] == -77.5
                assert data["hosting"] is True

                assert headers["X-Rl"] == "44"
                assert headers["X-Ttl"] == "60"

    async def test_query_success_without_as_field(self):
        """A success body missing the "as" field entirely must not KeyError -
        it falls back to "", ip-api.com's own value for IPs with no ASN."""

        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:
                with vcr.use_cassette(str(CASSETTE_DIR / "ipapi_query_success_noas.yaml")):
                    data, headers = await svc._query("192.0.2.1")

                assert data["status"] == "success"
                assert data["as_"] == ""
                assert data["asnum"] is None
                assert data["asorg"] == ""

    async def test_query_returns_failure_response(self):
        """An HTTP 200 "fail" body has no "as" key - _query() must return it
        intact (no KeyError) so _processQuery() can report the failure."""

        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:
                with vcr.use_cassette(str(CASSETTE_DIR / "ipapi_query_fail.yaml")):
                    data, headers = await svc._query("134744072")

                assert data["status"] == "fail"
                assert data["message"] == "invalid query"
                assert "as_" not in data

    async def test_query_raises_on_429(self):
        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:
                with vcr.use_cassette(str(CASSETTE_DIR / "ipapi_query_ratelimited.yaml")):
                    with self.raises(_RateLimited) as cm:
                        await svc._query("9.9.9.9")

                assert cm.exception.ttl == "5"

    async def test_query_raises_on_server_error(self):
        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:
                with vcr.use_cassette(str(CASSETTE_DIR / "ipapi_query_servererror.yaml")):
                    with self.raises(aiohttp.ClientError):
                        await svc._query("1.2.3.4")

    async def test_processquery_returns_error_on_http_error(self):
        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:

                async def fake_query(ipaddr):
                    raise aiohttp.ClientError("boom")

                with mock.patch.object(svc, "_query", fake_query):
                    retn = await svc.queryIp("1.2.3.4")

                assert retn["status"] is False
                assert retn["data"] is None
                assert "HTTP error" in retn["mesg"]

    async def test_query_not_json(self):
        """A non-JSON 200 response is returned as a status=False retn, not raised."""

        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:
                with vcr.use_cassette(str(CASSETTE_DIR / "ipapi_query_notjson.yaml")):
                    retn = await svc.queryIp("8.8.8.8")

                assert retn["status"] is False
                assert retn["data"] is None
                assert "8.8.8.8" in retn["mesg"]

    async def test_query_pro_key(self):
        """With an API key, queries go to the HTTPS pro endpoint with the key."""

        with self.getTestDir() as dirn:
            conf = {"ipapi:apikey": "testkey"}
            async with await IpApiSvc.anit(dirn, conf=conf) as svc:
                assert svc._url("/batch").startswith("https://pro.ip-api.com/batch?key=testkey&")

                with vcr.use_cassette(str(CASSETTE_DIR / "ipapi_query_pro.yaml")) as cass:
                    retn = await svc.queryIp("8.8.8.8")
                    assert cass.play_count == 1

                assert retn["status"] is True
                assert retn["data"]["asnum"] == 15169

    async def test_free_url(self):
        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:
                assert svc.apikey is None
                assert svc._url("/json/8.8.8.8").startswith("http://ip-api.com/json/8.8.8.8?")


class TestIpApiSvcBatch(s_tests.SynTest):
    """Test suite for IpApiSvc.queryIps()'s use of the /batch endpoint."""

    async def test_batch_http(self):
        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:
                ips = ["8.8.8.8", "10.0.0.1", "1.1.1.1"]
                with vcr.use_cassette(str(CASSETTE_DIR / "ipapi_batch_success.yaml")) as cass:
                    retn = await svc.queryIps(ips)
                    assert cass.play_count == 1
                    assert cass.requests[0].method == "POST"

                assert retn["status"] is True
                assert len(retn["data"]) == 3

                first, second, third = retn["data"]
                assert first["status"] is True
                assert first["data"]["asnum"] == 15169
                assert "as" not in first["data"]

                assert second["status"] is False
                assert second["data"] is None
                assert "private range" in second["mesg"]

                assert third["status"] is True
                assert third["data"]["asorg"] == "Cloudflare, Inc."

    async def test_batch_not_list(self):
        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:
                with vcr.use_cassette(str(CASSETTE_DIR / "ipapi_batch_notlist.yaml")):
                    retn = await svc.queryIps(["8.8.8.8", "1.1.1.1"])

                assert retn["status"] is True
                assert [r["status"] for r in retn["data"]] == [False, False]
                assert "TypeError" in retn["data"][0]["mesg"]

    async def test_batch_chunks(self):
        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:
                sizes = []

                async def fake_batch(ipaddrs):
                    sizes.append(len(ipaddrs))
                    # A short response - the missing results are failures.
                    if len(ipaddrs) < BATCH_SIZE:
                        ipaddrs = ipaddrs[:-1]
                    return [{"status": "success", "query": ip} for ip in ipaddrs], {}

                ips = [f"10.0.{i // 256}.{i % 256}" for i in range(250)]
                with mock.patch.object(svc, "_queryBatch", fake_batch):
                    retn = await svc.queryIps(ips)

                assert sizes == [100, 100, 50]
                assert retn["status"] is True
                assert len(retn["data"]) == 250
                assert [r["data"]["query"] for r in retn["data"][:249]] == ips[:249]
                assert retn["data"][249]["status"] is False
                assert "no result" in retn["data"][249]["mesg"]

    async def test_batch_chunk_failure(self):
        """A chunk that fails entirely fails each of its IPs, other chunks still succeed."""

        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:
                calls = []

                async def fake_batch(ipaddrs):
                    calls.append(ipaddrs)
                    if len(calls) == 1:
                        raise aiohttp.ClientError("boom")
                    return [{"status": "success", "query": ip} for ip in ipaddrs], {}

                ips = [f"10.0.0.{i}" for i in range(150)]
                with mock.patch.object(svc, "_queryBatch", fake_batch):
                    retn = await svc.queryIps(ips)

                assert retn["status"] is True
                assert all(r["status"] is False for r in retn["data"][:100])
                assert "HTTP error" in retn["data"][0]["mesg"]
                assert all(r["status"] is True for r in retn["data"][100:])

    async def test_batch_429_capped(self):
        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:
                calls = []

                async def fake_batch(ipaddrs):
                    calls.append(ipaddrs)
                    raise _RateLimited(ttl="0")

                with mock.patch.object(svc, "_queryBatch", fake_batch):
                    retn = await svc.queryIps(["1.1.1.1", "2.2.2.2"])

                assert len(calls) == MAX_RL_RETRIES + 1
                assert [r["status"] for r in retn["data"]] == [False, False]
                assert "rate limiting" in retn["data"][0]["mesg"]

    async def test_batch_shutdown(self):
        with self.getTestDir() as dirn:
            svc = await IpApiSvc.anit(dirn)

            async def fake_batch(ipaddrs):
                await asyncio.sleep(10)

            with mock.patch.object(svc, "_queryBatch", fake_batch):
                task = asyncio.create_task(svc.queryIps(["1.1.1.1", "2.2.2.2"]))
                await asyncio.sleep(0)
                await svc.fini()
                retn = await task

            assert [r["status"] for r in retn["data"]] == [False, False]
            assert "shutting down" in retn["data"][0]["mesg"]

    async def test_batch_bad_input(self):
        with self.getTestDir() as dirn:
            async with await IpApiSvc.anit(dirn) as svc:
                for bad in ("8.8.8.8", ["8.8.8.8", 5], None):
                    retn = await svc.queryIps(bad)
                    assert retn["status"] is False
                    assert retn["data"] is None

                retn = await svc.queryIps([])
                assert retn["status"] is True
                assert retn["data"] == []


class TestIpApiMain(s_tests.SynTest):
    """Test suite for the ipapi package's __main__ entrypoint."""

    def test_main(self):
        execmain = mock.AsyncMock()
        with (
            mock.patch.object(IpApiSvc, "execmain", execmain),
            mock.patch.object(sys, "argv", ["ipapi", "/vertex/storage"]),
        ):
            sys.modules.pop("ipapi.__main__", None)
            runpy.run_module("ipapi", run_name="__main__")

        execmain.assert_awaited_once_with(["/vertex/storage"])
