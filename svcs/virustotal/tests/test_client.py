"""Tests for the VirusTotal transport (vtsvc.client)."""

import aiohttp
import pytest
import synapse.tests.utils as s_tests

from vtsvc import client as c
from vtsvc.quota import QuotaLimiter, VtQuotaError

from . import fakevt as fv
from .test_quota import Kv


def cli(session, fake, **kwargs):
    lim = QuotaLimiter(Kv(), minute=0, day=0, month=0)
    return c.VtClient(session, lim, url=fake.url, backoff=0, **kwargs)


class TestClient(s_tests.SynTest):
    async def test_errors(self):
        async with fv.FakeVt() as fake, aiohttp.ClientSession() as sess:
            vt = cli(sess, fake)
            with pytest.raises(c.NoApiKeyError):
                await vt.request("get", "/domains/example.com", apikey=None)
            with pytest.raises(c.NotFoundError) as exc:
                await vt.request("get", "/files/" + "0" * 64, apikey=fv.APIKEY)
            assert exc.value.code == 404 and exc.value.error == "NotFoundError"
            with pytest.raises(c.VtApiError) as exc:
                await vt.request("get", "/domains/example.com", apikey="bad")
            assert "rejected the API key" in exc.value.mesg
            with pytest.raises(VtQuotaError):
                await vt.request("get", "/domains/example.com", apikey="429")
            # The key isn't in error messages.
            assert "bad" not in str(exc.value.mesg).replace("rejected", "")
            with pytest.raises(c.VtApiError):
                await vt.request("post", "/urls", apikey=fv.APIKEY, form={"a": 1}, json_data={})

            fake.status["/domains/example.com"] = 503
            with pytest.raises(c.VtApiError) as exc:
                await vt.request("get", "/domains/example.com", apikey=fv.APIKEY)
            assert exc.value.code == 503
            assert len(fake.requests) == 6

        async with aiohttp.ClientSession() as sess:
            vt = c.VtClient(sess, QuotaLimiter(Kv(), minute=0), url="http://127.0.0.1:1/api/v3")
            with pytest.raises(c.VtApiError) as exc:
                await vt.request("get", "/x", apikey=fv.APIKEY)
            assert "Unable to connect" in exc.value.mesg

    async def test_cache(self):
        async with fv.FakeVt() as fake, aiohttp.ClientSession() as sess:
            vt = cli(sess, fake, cache=c.TtlCache(60, 2))
            for _ in range(3):
                await vt.request("get", "/domains/example.com", apikey=fv.APIKEY, cache=True)
            assert len(fake.requests) == 1
            # Per key, per params, and only when asked.
            await vt.request("get", "/domains/example.com", apikey=fv.OTHERKEY, cache=True)
            await vt.request("get", "/domains/example.com", apikey=fv.APIKEY)
            assert len(fake.requests) == 3
            assert len(vt.cache) == 2

    def test_ttlcache(self):
        now = [0.0]
        cache = c.TtlCache(10, 2, clock=lambda: now[0])
        cache.set("a", 1)
        cache.set("b", 2)
        assert cache.get("a") == 1
        cache.set("c", 3)
        assert cache.get("b") is None  # LRU evicted
        now[0] = 11
        assert cache.get("a") is None
        assert c.TtlCache(0, 10).get("x") is None

    def test_params(self):
        assert c.normParams({"a": True, "b": None, "c": [1, 2]}) == {"a": "true", "c": "1,2"}
        with pytest.raises(c.VtApiError):
            c.normParams(["x"])
        assert c.errInfo(500, None, "") == (None, "HTTP 500")
        assert c.errInfo(502, None, "Bad gateway") == (None, "Bad gateway (HTTP 502)")
