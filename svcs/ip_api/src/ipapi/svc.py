"""The slib.ipapi service."""


import asyncio
from collections.abc import Mapping
from typing import NamedTuple, TypedDict

import aiohttp
from stormlibpp.telepath import TelepathRetn
import synapse.lib.cell as s_cell

from .api import IpApiCellApi


# The ip-api.com response headers that describe the current rate limit window.
RL_REMAINING_HEADER = "X-Rl"
RL_TTL_HEADER = "X-Ttl"

# Fallback sleep duration, in seconds, used when the rate limit is hit but
# ip-api.com didn't return a usable X-Ttl header.
DEFAULT_RL_TTL = 60.0


class IpData(TypedDict):
    """The results of a single ip-api.com query, either successful or unsuccessful."""

    query: str          # "24.48.0.1"
    status: str         # "success"
    country: str        # "Canada"
    countryCode: str    # "CA"
    region: str         # "QC"
    regionName: str     # "Quebec"
    city: str           # "Montreal"
    zip: str            # "H1K"
    lat: float          # 45.6085
    lon: float          # -73.5493
    timezone: str       # "America/Toronto"
    isp: str            # "Le Groupe Videotron Ltee"
    org: str            # "Videotron Ltee"
    as_: str            # "AS5769 Videotron Ltee" - this is really "as" in the data
    asname: str         # "VIDEOTRON"
    mobile: bool        # false
    proxy: bool         # false
    hosting: bool       # false


class IpRetn(TelepathRetn):
    """A TelepathRetn that describes the result of an ip-api.com query."""
    
    data: IpData | None


class _RateLimited(Exception):
    """Raised internally when ip-api.com responds with an HTTP 429."""

    def __init__(self, ttl: str | None):
        super().__init__(f"Rate limited by ip-api.com, ttl={ttl}")
        self.ttl = ttl


class _QueueItem(NamedTuple):
    """A single pending ip-api.com query, waiting to be worked by the queue worker."""

    ipaddr: str
    fut: asyncio.Future


class IpApiSvc(s_cell.Cell):
    """The Cell implementation for the slib.ipapi service."""

    cellapi = IpApiCellApi

    # TODO - Do we want to implement a JsonStor here?
    confdefs = {}

    async def __anit__(self, dirn, *args, **kwargs):
        await s_cell.Cell.__anit__(self, dirn, *args, **kwargs)

        # Queries are queued here and worked FIFO by _workQueue() so that we
        # never exceed the ip-api.com rate limit of 45 requests/minute.
        self.queue: asyncio.Queue[_QueueItem] = asyncio.Queue()
        self._queueTask = self.schedCoro(self._workQueue())
        self.onfini(self._finiQueue)

    async def _finiQueue(self):
        """Stop the queue worker and unblock any callers still waiting on a result."""

        self._queueTask.cancel()

        while not self.queue.empty():
            item = self.queue.get_nowait()
            if not item.fut.cancelled():
                item.fut.cancel()

    async def _query(self, ipaddr: str) -> tuple[dict, Mapping[str, str]]:
        """Query ip-api.com for information about the given IP address.

        Returns the parsed JSON body and the response headers. Raises
        _RateLimited if ip-api.com responds with an HTTP 429.
        """

        url = (
            f"http://ip-api.com/json/{ipaddr}?fields=status,message,country,countryCode,region,"
            "regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query"
        )

        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                if resp.status == 429:
                    raise _RateLimited(ttl=resp.headers.get(RL_TTL_HEADER))

                if resp.status != 200:
                    resp.raise_for_status()

                data = await resp.json()

                return IpData(as_=data.pop('as'), **data), resp.headers

    async def _sleepTtl(self, ttl_raw: str | None):
        """Sleep for the duration given by an X-Ttl header value, falling back
        to DEFAULT_RL_TTL if the value is missing or unparseable."""

        try:
            secs = float(ttl_raw)
        except (TypeError, ValueError):
            secs = DEFAULT_RL_TTL

        if secs > 0:
            await asyncio.sleep(secs)

    async def _checkRateLimit(self, headers: Mapping[str, str]):
        """Preemptively sleep until the rate limit window resets if ip-api.com
        reports that we have no requests remaining."""

        remaining_raw = headers.get(RL_REMAINING_HEADER)
        if remaining_raw is None:
            return

        try:
            remaining = int(remaining_raw)
        except ValueError:
            return

        if remaining <= 1:
            await self._sleepTtl(headers.get(RL_TTL_HEADER))

    async def _processQuery(self, ipaddr: str) -> IpRetn:
        """Query ip-api.com for a single IP address, retrying after any rate
        limit window if ip-api.com responds with an HTTP 429."""

        while True:
            try:
                data, headers = await self._query(ipaddr)
            except _RateLimited as e:
                await self._sleepTtl(e.ttl)
                continue
            except aiohttp.ClientError as e:
                return IpRetn(
                    data=None,
                    status=False,
                    mesg=(
                        "An HTTP error occurred while trying to query ip-api.com "
                        f"for IP address: {ipaddr} - {e}"
                    ),
                )

            await self._checkRateLimit(headers)

            if data.get("status") != "success":
                return IpRetn(
                    data=None,
                    status=False,
                    mesg=(
                        f"ip-api.com returned a {data.get('status')} status for "
                        f"IP address: {ipaddr} - {data.get('message')}"
                    ),
                )

            return IpRetn(
                data=data,
                status=True,
                mesg=f"Successfully queried ip-api.com for IP address: {ipaddr}",
            )

    async def _workQueue(self):
        """Work the query queue FIFO, one request at a time, so the ip-api.com
        rate limit is always respected across all queryIp() callers."""

        while True:
            item = await self.queue.get()

            try:
                retn = await self._processQuery(item.ipaddr)
            except asyncio.CancelledError:
                if not item.fut.cancelled():
                    item.fut.cancel()
                raise
            except Exception as e:
                if not item.fut.cancelled():
                    item.fut.set_exception(e)
            else:
                if not item.fut.cancelled():
                    item.fut.set_result(retn)
            finally:
                self.queue.task_done()

    async def queryIp(self, ipaddr: str) -> IpRetn:
        """Query information about the given IP address.

        The request is queued and worked FIFO by the queue worker so that
        the ip-api.com rate limit is respected across all callers.
        """

        fut = asyncio.get_running_loop().create_future()
        await self.queue.put(_QueueItem(ipaddr, fut))

        try:
            return await fut
        except asyncio.CancelledError:
            task = asyncio.current_task()
            if task is not None and task.cancelling():
                # Our own task was cancelled by the caller - must propagate.
                fut.cancel()
                raise

            # fut was cancelled internally (service shutdown / worker died).
            return IpRetn(
                data=None,
                status=False,
                mesg=f"slib.ipapi service is shutting down, query for {ipaddr} was cancelled",
            )