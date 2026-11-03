"""Enforce VirusTotal's Public (community) API request limits.

VirusTotal's Public API allows 4 requests per minute, 500 per day (reset at 00:00 UTC), and
15.5K per month, per API key. Going over them gets the key's requests rejected (HTTP 429), and
VirusTotal's terms forbid working around them. So, unless the service is configured for a
premium key (``vt:community`` is false), every request to VirusTotal first reserves a slot here:

- The per minute limit is a sliding window of the last request times. A request waits (in
  FIFO order) until the window has room, up to a max wait.
- The daily and monthly limits are counters. A request over either fails immediately, it would
  otherwise wait for hours.

Every request is counted (even when limits aren't enforced) and the counts are persisted, so a
restart neither resets the daily/monthly counts nor allows a burst over the minute limit.
Counts are kept per API key, keyed by a hash of the key so keys are never stored here.
"""

import asyncio
import datetime
import hashlib
import time
from collections.abc import Callable
from typing import Any

# VirusTotal's Public API limits.
MINUTE_LIMIT = 4
DAY_LIMIT = 500
MONTH_LIMIT = 15500

# The length of the per minute window, in seconds: a minute, plus a second of slack for clock
# differences between the service and VirusTotal.
WINDOW = 61.0

# How long, in seconds, to hold off all requests for a key after VirusTotal answers HTTP 429.
COOLDOWN = 60.0


class VtQuotaError(Exception):
    """A request would go over (or VirusTotal says it went over) an API quota."""

    def __init__(self, mesg: str):
        super().__init__(mesg)
        self.mesg = mesg


def keyId(apikey: str) -> str:
    """A short, non reversible, identifier for an API key."""

    return hashlib.sha256(apikey.encode()).hexdigest()[:16]


def _utcnow(now: float) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(now, datetime.UTC)


def dayKey(now: float) -> str:
    """The UTC day (YYYY-MM-DD) a time is in. VirusTotal resets daily quotas at 00:00 UTC."""

    return _utcnow(now).strftime("%Y-%m-%d")


def monthKey(now: float) -> str:
    """The UTC month (YYYY-MM) a time is in."""

    return _utcnow(now).strftime("%Y-%m")


def nextDay(now: float) -> float:
    """The epoch time of the next 00:00 UTC."""

    day = _utcnow(now).date() + datetime.timedelta(days=1)
    return datetime.datetime(day.year, day.month, day.day, tzinfo=datetime.UTC).timestamp()


class QuotaLimiter:
    """Reserve VirusTotal request slots, per API key, within the configured limits.

    Parameters
    ----------
    kv : SafeKeyVal
        Where the counts are persisted (a Cell slab SafeKeyVal).
    enforce : bool
        Whether to enforce the limits (``vt:community``). Requests are counted either way.
    minute, day, month : int
        The limits. 0 disables a limit.
    maxwait : float
        The most seconds a request waits for room in the per minute window before failing.
        0 waits as long as it takes.
    clock, sleep : callable, optional
        Overrides for ``time.time`` and ``asyncio.sleep``, for tests.
    """

    def __init__(
        self,
        kv,
        enforce: bool = True,
        minute: int = MINUTE_LIMIT,
        day: int = DAY_LIMIT,
        month: int = MONTH_LIMIT,
        maxwait: float = 600.0,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], Any] | None = None,
    ):
        self.kv = kv
        self.enforce = enforce
        self.minute = minute
        self.day = day
        self.month = month
        self.maxwait = maxwait
        self.clock = clock or time.time
        self.sleep = sleep or asyncio.sleep
        self._locks: dict[str, asyncio.Lock] = {}

    def _lock(self, kid: str) -> asyncio.Lock:
        lock = self._locks.get(kid)
        if lock is None:
            lock = self._locks[kid] = asyncio.Lock()
        return lock

    def _recent(self, kid: str, now: float) -> list[float]:
        """The times of the requests in the current minute window."""

        return [t for t in self.kv.get(f"{kid}:recent", ()) if t > now - WINDOW]

    def counts(self, kid: str, now: float | None = None) -> dict:
        """The request counts for a key: in the last minute, today (UTC), and this month."""

        now = self.clock() if now is None else now
        return {
            "minute": len(self._recent(kid, now)),
            "day": self.kv.get(f"{kid}:day:{dayKey(now)}", 0),
            "month": self.kv.get(f"{kid}:month:{monthKey(now)}", 0),
        }

    def _checkTotals(self, kid: str, now: float) -> None:
        """Raise if the key has used its daily or monthly quota."""

        if not self.enforce:
            return
        counts = self.counts(kid, now)
        if self.day and counts["day"] >= self.day:
            wait = int(nextDay(now) - now)
            raise VtQuotaError(
                f"The VirusTotal daily quota ({self.day} requests) for this API key is used up, "
                f"it resets at 00:00 UTC (in {wait // 3600}h {wait % 3600 // 60}m)."
            )
        if self.month and counts["month"] >= self.month:
            raise VtQuotaError(
                f"The VirusTotal monthly quota ({self.month} requests) for this API key is used up."
            )

    def _windowWait(self, kid: str, now: float) -> float:
        """Seconds until the key may send another request under the per minute limit."""

        if not self.enforce:
            return 0.0
        wait = 0.0
        cooldown = self.kv.get(f"{kid}:cooldown", 0.0)
        if cooldown > now:
            wait = cooldown - now
        if self.minute:
            recent = sorted(self._recent(kid, now))
            if len(recent) >= self.minute:
                # The window has room once the oldest request that's in the way ages out.
                wait = max(wait, recent[-self.minute] + WINDOW - now)
        return wait

    def _record(self, kid: str, now: float) -> None:
        """Count a request."""

        keep = max(self.minute, MINUTE_LIMIT)
        recent = sorted(self._recent(kid, now))[-(keep - 1) :] if keep > 1 else []
        recent.append(now)
        self.kv.set(f"{kid}:recent", recent)

        day = f"{kid}:day:{dayKey(now)}"
        month = f"{kid}:month:{monthKey(now)}"
        self.kv.set(day, self.kv.get(day, 0) + 1)
        self.kv.set(month, self.kv.get(month, 0) + 1)
        self._prune(kid, now)

    def _prune(self, kid: str, now: float) -> None:
        """Drop counters from earlier days and months."""

        keep = {f"{kid}:day:{dayKey(now)}", f"{kid}:month:{monthKey(now)}"}
        for name in list(self.kv.keys()):
            if name.startswith((f"{kid}:day:", f"{kid}:month:")) and name not in keep:
                self.kv.pop(name)

    async def acquire(self, apikey: str) -> None:
        """Wait for (and take) a request slot for an API key.

        Raises
        ------
        VtQuotaError
            If the key's daily or monthly quota is used up, or there wasn't room in the per
            minute window within ``maxwait`` seconds.
        """

        kid = keyId(apikey)
        start = self.clock()
        self._checkTotals(kid, start)

        # The lock queues waiters in FIFO order, so a burst of calls is spread out evenly.
        async with self._lock(kid):
            while True:
                now = self.clock()
                self._checkTotals(kid, now)
                wait = self._windowWait(kid, now)
                if wait <= 0:
                    break
                if self.maxwait and (now - start) + wait > self.maxwait:
                    raise VtQuotaError(
                        f"Timed out waiting for room under the VirusTotal rate limit of "
                        f"{self.minute} requests per minute (vt:limit:maxwait is "
                        f"{self.maxwait:g}s). Try again later, or with fewer nodes."
                    )
                await self.sleep(wait)

            self._record(kid, self.clock())

    def cooldown(self, apikey: str, secs: float = COOLDOWN) -> None:
        """Hold off a key's requests for a while, ex. after VirusTotal answers HTTP 429."""

        kid = keyId(apikey)
        self.kv.set(f"{kid}:cooldown", self.clock() + secs)

    def status(self, apikey: str) -> dict:
        """The limits, the key's request counts, and when it can next send a request."""

        kid = keyId(apikey)
        now = self.clock()
        return {
            "enforced": self.enforce,
            "limits": {"minute": self.minute, "day": self.day, "month": self.month},
            "used": self.counts(kid, now),
            "wait": round(self._windowWait(kid, now), 1),
            "resets": int(nextDay(now) * 1000),
        }
