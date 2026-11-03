"""Tests for the Public API rate limiter (vtsvc.quota)."""

import datetime

import pytest
import synapse.tests.utils as s_tests

from vtsvc import quota
from vtsvc.quota import QuotaLimiter, VtQuotaError

KEY = "k" * 64

# 2026-11-03 23:58:00 UTC
T0 = datetime.datetime(2026, 11, 3, 23, 58, tzinfo=datetime.UTC).timestamp()


class Clock:
    """A fake clock whose sleep() just moves time forward."""

    def __init__(self, now=T0):
        self.now = now
        self.slept = []

    def __call__(self):
        return self.now

    async def sleep(self, secs):
        self.slept.append(round(secs, 3))
        self.now += secs


class Kv(dict):
    """A dict with the SafeKeyVal API the limiter uses."""

    def set(self, key, valu):
        self[key] = valu

    def pop(self, key, default=None):
        return super().pop(key, default)


def limiter(kv=None, clock=None, **kwargs):
    clock = clock or Clock()
    return QuotaLimiter(kv if kv is not None else Kv(), clock=clock, sleep=clock.sleep, **kwargs), clock


class TestQuota(s_tests.SynTest):
    async def test_minute_window(self):
        lim, clock = limiter()
        for _ in range(4):
            await lim.acquire(KEY)
        assert clock.slept == []

        # The 5th waits until the 1st is out of the window (a minute, plus a second of slack).
        clock.now += 10
        await lim.acquire(KEY)
        assert clock.slept == [51.0]
        assert lim.counts(quota.keyId(KEY))["minute"] == 1

    async def test_minute_spacing(self):
        # Requests are never more than 4 in any 60 second window.
        lim, clock = limiter()
        times = []
        for _ in range(20):
            await lim.acquire(KEY)
            times.append(clock.now)
        for i in range(len(times) - 4):
            assert times[i + 4] - times[i] >= 60

    async def test_daily_limit(self):
        lim, clock = limiter(minute=0, day=3)
        for _ in range(3):
            await lim.acquire(KEY)
        with pytest.raises(VtQuotaError) as exc:
            await lim.acquire(KEY)
        assert "daily quota (3 requests)" in exc.value.mesg
        assert "00:00 UTC (in 0h 2m)" in exc.value.mesg

        # It resets at 00:00 UTC, and the old day's counter is pruned.
        clock.now += 180
        await lim.acquire(KEY)
        kid = quota.keyId(KEY)
        assert lim.counts(kid)["day"] == 1
        assert [k for k in lim.kv if ":day:" in k] == [f"{kid}:day:2026-11-04"]

    async def test_monthly_limit(self):
        lim, clock = limiter(minute=0, day=0, month=2)
        await lim.acquire(KEY)
        await lim.acquire(KEY)
        with pytest.raises(VtQuotaError) as exc:
            await lim.acquire(KEY)
        assert "monthly quota (2 requests)" in exc.value.mesg

    async def test_per_key(self):
        lim, clock = limiter(minute=0, day=1)
        await lim.acquire(KEY)
        await lim.acquire("other")
        with pytest.raises(VtQuotaError):
            await lim.acquire(KEY)
        # Keys aren't stored, only their hashes.
        assert not any(KEY in k for k in lim.kv)

    async def test_maxwait(self):
        lim, clock = limiter(maxwait=30)
        for _ in range(4):
            await lim.acquire(KEY)
        with pytest.raises(VtQuotaError) as exc:
            await lim.acquire(KEY)
        assert "4 requests per minute" in exc.value.mesg
        # It failed without sleeping, or counting the request.
        assert clock.slept == []
        assert lim.counts(quota.keyId(KEY))["minute"] == 4

    async def test_not_enforced(self):
        lim, clock = limiter(enforce=False, day=1)
        for _ in range(10):
            await lim.acquire(KEY)
        assert clock.slept == []
        # Still counted.
        assert lim.counts(quota.keyId(KEY)) == {"minute": 4, "day": 10, "month": 10}

    async def test_persisted(self):
        # A new limiter (ex. after a restart) sees the old one's requests.
        kv = Kv()
        clock = Clock()
        lim, _ = limiter(kv=kv, clock=clock)
        for _ in range(4):
            await lim.acquire(KEY)
        lim2, _ = limiter(kv=kv, clock=clock)
        await lim2.acquire(KEY)
        assert clock.slept == [61.0]

    async def test_cooldown(self):
        lim, clock = limiter()
        lim.cooldown(KEY, 30)
        await lim.acquire(KEY)
        assert clock.slept == [30.0]
        status = lim.status(KEY)
        assert status["enforced"] is True
        assert status["used"]["day"] == 1
        assert status["limits"] == {"minute": 4, "day": 500, "month": 15500}

    async def test_slab_persisted(self):
        # The limiter works with a real SafeKeyVal.
        with self.getTestDir() as dirn:
            import synapse.lib.lmdbslab as s_lmdbslab

            async with await s_lmdbslab.Slab.anit(dirn + "/slab") as slab:
                clock = Clock()
                lim, _ = limiter(kv=slab.getSafeKeyVal("q"), clock=clock, day=2)
                await lim.acquire(KEY)
                await lim.acquire(KEY)
                with pytest.raises(VtQuotaError):
                    await lim.acquire(KEY)
