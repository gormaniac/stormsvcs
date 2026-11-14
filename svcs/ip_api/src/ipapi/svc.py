"""The slib.ipapi service."""

import asyncio
import re
from collections.abc import Mapping
from typing import Any, NamedTuple, NotRequired, TypedDict

import aiohttp
import synapse.lib.cell as s_cell
from stormlibpp.telepath import TelepathRetn

from .api import IpApiCellApi

# The ip-api.com response headers that describe the current rate limit window.
RL_REMAINING_HEADER = "X-Rl"
RL_TTL_HEADER = "X-Ttl"

# Fallback sleep duration, in seconds, used when the rate limit is hit but
# ip-api.com didn't return a usable X-Ttl header.
DEFAULT_RL_TTL = 60.0

# How many times a query is retried after an HTTP 429 before giving up.
MAX_RL_RETRIES = 3

# The total time, in seconds, a single ip-api.com request may take.
HTTP_TIMEOUT = 30.0

# The most IPs ip-api.com accepts in a single /batch request.
BATCH_SIZE = 100

# The fields requested from ip-api.com, for both the /json and /batch endpoints.
FIELDS = (
    "status,message,country,countryCode,region,regionName,city,lat,lon,"
    "isp,org,as,asname,reverse,mobile,proxy,hosting,query"
)

# The free endpoints (no API key, plain HTTP only) and the pro endpoints (API key, HTTPS).
FREE_URL = "http://ip-api.com"
PRO_URL = "https://pro.ip-api.com"

# Matches ip-api.com's "as" field, ex. "AS15169 Google LLC" -> ("15169", "Google LLC").
AS_REGEX = re.compile(r"^AS(\d+)\s*(.*)$")


class IpData(TypedDict):
    """The results of a single ip-api.com query, either successful or unsuccessful."""

    query: str  # "24.48.0.1"
    status: str  # "success"
    message: NotRequired[str]  # "reserved range" - only set when status is "fail"
    country: str  # "Canada"
    countryCode: str  # "CA"
    region: str  # "QC"
    regionName: str  # "Quebec"
    city: str  # "Montreal"
    lat: float  # 45.6085
    lon: float  # -73.5493
    isp: str  # "Le Groupe Videotron Ltee"
    org: str  # "Videotron Ltee"
    as_: str  # "AS5769 Videotron Ltee" - this is really "as" in the data
    asname: str  # "VIDEOTRON"
    asnum: int | None  # 5769 - parsed from "as", None when the IP has no ASN
    asorg: str  # "Videotron Ltee" - parsed from "as", "" when the IP has no ASN
    reverse: str  # "modemcable001.0-48-24.mc.videotron.ca"
    mobile: bool  # false
    proxy: bool  # false
    hosting: bool  # false


class IpRetn(TelepathRetn):
    """A TelepathRetn that describes the result of an ip-api.com query."""

    data: IpData | None


class IpBatchRetn(TelepathRetn):
    """A TelepathRetn that describes the results of an ip-api.com batch query.

    data holds one IpRetn per queried IP, in the order the IPs were given.
    """

    data: list[IpRetn] | None


class _RateLimited(Exception):
    """Raised internally when ip-api.com responds with an HTTP 429."""

    def __init__(self, ttl: str | None):
        super().__init__(f"Rate limited by ip-api.com, ttl={ttl}")
        self.ttl = ttl


class _QueueItem(NamedTuple):
    """A single pending ip-api.com request, waiting to be worked by the queue worker.

    kind is "json" for a single IP (arg is the IP string) or "batch" for a
    batch request (arg is a list of up to BATCH_SIZE IP strings).
    """

    kind: str
    arg: Any
    fut: asyncio.Future


def shapeData(data: dict) -> IpData:
    """Rename ip-api.com's "as" key to "as_" and parse it into asnum/asorg.

    ip-api.com uses "" for IPs with no ASN, so default to that rather than
    crashing if the field is ever absent entirely.
    """

    as_ = data.pop("as", "") or ""
    asnum = None
    asorg = ""

    match = AS_REGEX.match(as_)
    if match is not None:
        asnum = int(match.group(1))
        asorg = match.group(2).strip()

    return IpData(as_=as_, asnum=asnum, asorg=asorg, **data)


class IpApiSvc(s_cell.Cell):
    """The Cell implementation for the slib.ipapi service."""

    cellapi = IpApiCellApi

    confdefs = {
        "ipapi:apikey": {
            "type": ["string", "null"],
            "default": None,
            "description": (
                "An ip-api.com pro API key. When set, queries use the HTTPS "
                "pro.ip-api.com endpoints, which have no rate limit. When unset, "
                "the free (non-commercial use only) HTTP endpoints are used."
            ),
        },
    }

    async def __anit__(self, dirn, *args, **kwargs):
        await s_cell.Cell.__anit__(self, dirn, *args, **kwargs)

        self.apikey: str | None = self.conf.get("ipapi:apikey")

        # One session for the cell's lifetime - queries all go to the same
        # host, so reuse its connection instead of building a session each time.
        self.sess = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT))
        self.onfini(self.sess.close)

        # Queries are queued here and worked FIFO by _workQueue() so that we
        # never exceed the ip-api.com rate limits (45/minute for /json, 15/minute for /batch).
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

    def _url(self, path: str) -> str:
        """Build the ip-api.com URL for the given path, ex. "/json/8.8.8.8" or "/batch"."""

        if self.apikey:
            return f"{PRO_URL}{path}?key={self.apikey}&fields={FIELDS}"
        return f"{FREE_URL}{path}?fields={FIELDS}"

    @staticmethod
    def _checkResp(resp: aiohttp.ClientResponse):
        """Raise _RateLimited on an HTTP 429, or an aiohttp error on any other non-200."""

        if resp.status == 429:
            raise _RateLimited(ttl=resp.headers.get(RL_TTL_HEADER))

        if resp.status != 200:
            resp.raise_for_status()

    async def _query(self, ipaddr: str) -> tuple[dict, Mapping[str, str]]:
        """Query ip-api.com for information about the given IP address.

        Returns the parsed JSON body and the response headers. Raises
        _RateLimited if ip-api.com responds with an HTTP 429.
        """

        async with self.sess.get(self._url(f"/json/{ipaddr}")) as resp:
            self._checkResp(resp)

            data = await resp.json()

            if data.get("status") != "success":
                # Failure responses only carry status/message/query - no "as"
                # key to rename. Return as-is for _processQuery() to handle.
                return data, resp.headers

            return shapeData(data), resp.headers

    async def _queryBatch(self, ipaddrs: list[str]) -> tuple[list[dict], Mapping[str, str]]:
        """Query ip-api.com's /batch endpoint for up to BATCH_SIZE IP addresses.

        Returns the parsed JSON body (one result per IP, in order) and the response
        headers. Raises _RateLimited if ip-api.com responds with an HTTP 429.
        """

        async with self.sess.post(self._url("/batch"), json=list(ipaddrs)) as resp:
            self._checkResp(resp)

            body = await resp.json()
            if not isinstance(body, list):
                raise TypeError(f"Expected a list from ip-api.com's /batch, got: {body!r}")

            results = []
            for data in body:
                if isinstance(data, dict) and data.get("status") == "success":
                    data = shapeData(data)
                results.append(data)

            return results, resp.headers

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

        if remaining <= 0:
            await self._sleepTtl(headers.get(RL_TTL_HEADER))

    @staticmethod
    def _toRetn(ipaddr: str, data: Any) -> IpRetn:
        """Turn a single ip-api.com result into an IpRetn."""

        if not isinstance(data, dict) or data.get("status") != "success":
            status = data.get("status") if isinstance(data, dict) else None
            message = data.get("message") if isinstance(data, dict) else data
            return IpRetn(
                data=None,
                status=False,
                mesg=(
                    f"ip-api.com returned a {status} status for IP address: {ipaddr} - {message}"
                ),
            )

        return IpRetn(
            data=data,
            status=True,
            mesg=f"Successfully queried ip-api.com for IP address: {ipaddr}",
        )

    async def _request(self, kind: str, arg: Any) -> tuple[Any, Mapping[str, str]]:
        """Make a single /json or /batch request, retrying up to MAX_RL_RETRIES
        times after any rate limit window if ip-api.com responds with an HTTP 429."""

        retries = 0
        while True:
            try:
                if kind == "batch":
                    return await self._queryBatch(arg)
                return await self._query(arg)
            except _RateLimited as e:
                if retries >= MAX_RL_RETRIES:
                    raise
                retries += 1
                await self._sleepTtl(e.ttl)

    async def _processQuery(self, ipaddr: str) -> IpRetn:
        """Query ip-api.com for a single IP address, returning an IpRetn for any error."""

        try:
            data, headers = await self._request("json", ipaddr)
        except Exception as e:
            return IpRetn(data=None, status=False, mesg=self._errMesg(e, ipaddr))

        await self._checkRateLimit(headers)

        return self._toRetn(ipaddr, data)

    async def _processBatch(self, ipaddrs: list[str]) -> IpBatchRetn:
        """Query ip-api.com's /batch endpoint for up to BATCH_SIZE IP addresses,
        returning an IpBatchRetn for any error."""

        desc = f"{len(ipaddrs)} IP addresses ({ipaddrs[0]}, ...)"
        try:
            results, headers = await self._request("batch", ipaddrs)
        except Exception as e:
            return IpBatchRetn(data=None, status=False, mesg=self._errMesg(e, desc))

        await self._checkRateLimit(headers)

        retns = []
        for i, ipaddr in enumerate(ipaddrs):
            data = results[i] if i < len(results) else "no result in the batch response"
            retns.append(self._toRetn(ipaddr, data))

        return IpBatchRetn(
            data=retns,
            status=True,
            mesg=f"Successfully batch queried ip-api.com for {desc}",
        )

    @staticmethod
    def _errMesg(exc: Exception, desc: str) -> str:
        """Build the error message for a request that raised the given exception."""

        if isinstance(exc, _RateLimited):
            return (
                f"ip-api.com is still rate limiting requests after {MAX_RL_RETRIES} retries, "
                f"gave up querying for {desc}"
            )

        if isinstance(exc, aiohttp.ClientError):
            return f"An HTTP error occurred while trying to query ip-api.com for {desc} - {exc}"

        if isinstance(exc, asyncio.TimeoutError):
            return f"Timed out after {HTTP_TIMEOUT}s querying ip-api.com for {desc}"

        return (
            f"An unexpected error occurred while trying to query ip-api.com for {desc} - "
            f"{type(exc).__name__}: {exc}"
        )

    async def _workQueue(self):
        """Work the query queue FIFO, one request at a time, so the ip-api.com
        rate limits are always respected across all queryIp()/queryIps() callers."""

        while True:
            item = await self.queue.get()

            if item.fut.cancelled():
                # The caller gave up before its turn, don't spend a request on it.
                self.queue.task_done()
                continue

            try:
                if item.kind == "batch":
                    retn = await self._processBatch(item.arg)
                else:
                    retn = await self._processQuery(item.arg)
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

    async def _enqueue(self, kind: str, arg: Any, desc: str) -> TelepathRetn:
        """Queue a request for the worker and wait for its result.

        Returns a status=False TelepathRetn if the service shuts down, or the
        worker fails, before the request is done.
        """

        fut = asyncio.get_running_loop().create_future()
        await self.queue.put(_QueueItem(kind, arg, fut))

        try:
            return await fut
        except asyncio.CancelledError:
            task = asyncio.current_task()
            if task is not None and task.cancelling():
                # Our own task was cancelled by the caller - must propagate.
                fut.cancel()
                raise

            # fut was cancelled internally (service shutdown / worker died).
            return TelepathRetn(
                data=None,
                status=False,
                mesg=f"slib.ipapi service is shutting down, query for {desc} was cancelled",
            )
        except Exception as e:
            return TelepathRetn(data=None, status=False, mesg=self._errMesg(e, desc))

    async def queryIp(self, ipaddr: str) -> IpRetn:
        """Query information about the given IP address.

        The request is queued and worked FIFO by the queue worker so that
        the ip-api.com rate limit is respected across all callers.
        """

        return await self._enqueue("json", ipaddr, ipaddr)

    async def queryIps(self, ipaddrs: list[str]) -> IpBatchRetn:
        """Query information about many IP addresses using ip-api.com's /batch endpoint.

        The IPs are sent in chunks of BATCH_SIZE, each queued and worked FIFO like
        queryIp(). data holds one IpRetn per IP, in the given order - a chunk that
        fails entirely gives each of its IPs a status=False IpRetn with the error.
        """

        if not isinstance(ipaddrs, list | tuple) or not all(isinstance(i, str) for i in ipaddrs):
            return IpBatchRetn(
                data=None, status=False, mesg="queryIps requires a list of IP address strings"
            )

        retns: list[IpRetn] = []
        for start in range(0, len(ipaddrs), BATCH_SIZE):
            chunk = list(ipaddrs[start : start + BATCH_SIZE])
            retn = await self._enqueue("batch", chunk, f"{len(chunk)} IP addresses")

            if retn["status"]:
                retns.extend(retn["data"])
            else:
                retns.extend(IpRetn(data=None, status=False, mesg=retn["mesg"]) for _ in chunk)

        return IpBatchRetn(
            data=retns,
            status=True,
            mesg=f"Batch queried ip-api.com for {len(ipaddrs)} IP addresses",
        )
