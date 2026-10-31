"""An asyncio HTTP transport for all of Shodan's APIs.

Shodan exposes several APIs on different hosts. This module handles the
differences between them (which ones need an API key, which ones are rate
limited, how errors are reported, how streams are read) so the rest of the
service can call any endpoint the same way.
"""

import asyncio
import json
from collections.abc import AsyncIterator, Mapping
from typing import Any

import aiohttp

# The base URL of every Shodan API, keyed by the name used throughout the service.
BASE_URLS = {
    "api": "https://api.shodan.io",
    "stream": "https://stream.shodan.io",
    "trends": "https://trends.shodan.io",
    "internetdb": "https://internetdb.shodan.io",
    "cvedb": "https://cvedb.shodan.io",
}

# APIs that require the "key" query param.
KEYED_APIS = frozenset(("api", "stream", "trends"))

# APIs that share Shodan's 1 request/second API key rate limit.
RATE_LIMITED_APIS = frozenset(("api", "trends"))

# How many times to retry a request that receives an HTTP 429.
MAX_RETRIES = 3


class ShodanApiError(Exception):
    """Shodan returned an error, or could not be reached."""

    def __init__(self, mesg: str, code: int | None = None):
        super().__init__(mesg)
        self.mesg = mesg
        self.code = code


class NoApiKeyError(ShodanApiError):
    """A keyed Shodan API was called without an API key available."""


def normParam(valu: Any) -> str:
    """Convert a Python value into the string form Shodan expects in a query param."""

    if isinstance(valu, bool):
        return "true" if valu else "false"
    if isinstance(valu, Mapping):
        # Ex. POST /shodan/scan's {ip: [[port, protocol], ...]} form of "ips".
        return json.dumps(valu)
    if isinstance(valu, (list, tuple, set)):
        return ",".join(str(v) for v in valu)
    return str(valu)


def normParams(params: Mapping[str, Any] | None) -> dict[str, str]:
    """Normalize a dict of query params, dropping any that are None."""

    if not params:
        return {}
    if not isinstance(params, Mapping):
        raise ShodanApiError(f"Expected a dict of params, got {type(params).__name__}: {params!r}")
    return {k: normParam(v) for k, v in params.items() if v is not None}


def errMesg(code: int, data: Any, text: str, keyed: bool = True) -> str:
    """Pull the most useful error message out of a Shodan error response.

    The main API uses ``{"error": ...}`` while InternetDB/CVEDB (FastAPI) use
    ``{"detail": ...}``. Fall back to the raw body and finally the HTTP status.
    """

    if isinstance(data, dict):
        for key in ("error", "detail", "message"):
            valu = data.get(key)
            # Some endpoints (ex. the Streaming API) wrap an HTML error page in the JSON.
            if valu and not str(valu).lstrip().startswith("<"):
                return str(valu)

    if text and not text.lstrip().startswith(("<", "{")):
        return text.strip()[:500]

    # Shodan returns an empty body or an HTML page for these, both for bad keys and
    # for valid keys whose plan doesn't include the API (ex. the Streaming API).
    # The keyless APIs can't have key problems, ex. a 403 there is an IP/WAF block.
    if not keyed:
        return f"HTTP {code}"
    if code == 401:
        return "Shodan rejected the API key: it is invalid, or its plan doesn't include this API (HTTP 401)"
    if code == 403:
        return "Access denied: the API key's plan doesn't include this API (HTTP 403)"

    return f"HTTP {code}"


class RateLimiter:
    """Space out calls so no more than ``rate`` happen per second."""

    def __init__(self, rate: float):
        self.interval = 1.0 / rate if rate and rate > 0 else 0.0
        self._lock = asyncio.Lock()
        self._last: float | None = None

    async def wait(self) -> None:
        if not self.interval:
            return

        async with self._lock:
            loop = asyncio.get_running_loop()
            if self._last is not None:
                delta = self._last + self.interval - loop.time()
                if delta > 0:
                    await asyncio.sleep(delta)
            self._last = loop.time()


class ShodanClient:
    """The transport used to talk to every Shodan API.

    Parameters
    ----------
    session : aiohttp.ClientSession
        The session to send requests with. The caller owns its lifecycle.
    urls : dict, optional
        Overrides for ``BASE_URLS`` (useful for proxies, mirrors, and tests).
    rate : float, optional
        Max requests/second for the rate limited APIs. Defaults to 1.0.
    timeout : float, optional
        Total timeout, in seconds, for a single non-streaming request.
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        urls: Mapping[str, str] | None = None,
        rate: float = 1.0,
        timeout: float = 60.0,
    ):
        self.session = session
        self.urls = dict(BASE_URLS)
        if urls:
            self.urls.update(urls)
        self.limiter = RateLimiter(rate)
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    def _prep(self, base: str, path: str, apikey: str | None, params) -> tuple[str, dict]:
        if base not in self.urls:
            raise ShodanApiError(f"Unknown Shodan API: {base}")

        params = normParams(params)
        if base in KEYED_APIS:
            if not apikey:
                raise NoApiKeyError(
                    "No Shodan API key is configured. Add a 'shodan' vault or run "
                    "slib.shodan.admin.apikey to set a service-wide key."
                )
            params["key"] = apikey

        return self.urls[base].rstrip("/") + path, params

    async def request(
        self,
        method: str,
        path: str,
        *,
        base: str = "api",
        apikey: str | None = None,
        params: Mapping[str, Any] | None = None,
        json_data: Any = None,
        form: Mapping[str, Any] | None = None,
    ) -> Any:
        """Send a request to a Shodan API and return the parsed JSON body.

        ``form`` is sent as a form encoded body. Some endpoints (ex. ``POST /shodan/scan``)
        only read their arguments from the body and silently ignore query params.

        Raises
        ------
        ShodanApiError
            If Shodan can't be reached, returns an error, or returns invalid JSON.
        """

        if json_data is not None and form is not None:
            raise ShodanApiError("A request can't have both a JSON body and a form body.")

        url, params = self._prep(base, path, apikey, params)
        data = normParams(form) if form is not None else None

        for attempt in range(MAX_RETRIES + 1):
            if base in RATE_LIMITED_APIS:
                await self.limiter.wait()

            try:
                async with self.session.request(
                    method.upper(),
                    url,
                    params=params,
                    json=json_data,
                    data=data,
                    timeout=self.timeout,
                ) as resp:
                    text = await resp.text()
                    code = resp.status
            except (aiohttp.ClientError, TimeoutError) as err:
                raise ShodanApiError(f"Unable to connect to Shodan ({base}): {err}") from err

            if code == 429 and attempt < MAX_RETRIES:
                await asyncio.sleep(2**attempt)
                continue
            break

        try:
            data = json.loads(text) if text else None
        except ValueError:
            data = None
            if code < 400:
                raise ShodanApiError(f"Unable to parse the JSON response from {url}", code=code)

        if code >= 400 or (isinstance(data, dict) and "error" in data):
            raise ShodanApiError(errMesg(code, data, text, keyed=base in KEYED_APIS), code=code)

        return data

    async def stream(
        self,
        path: str,
        *,
        apikey: str | None = None,
        params: Mapping[str, Any] | None = None,
        limit: int = 100,
        timeout: float = 60.0,
    ) -> AsyncIterator[dict]:
        """Read banners from the Shodan Streaming API.

        Streams never end on their own, so this stops after ``limit`` banners
        (0 for no limit) or ``timeout`` seconds (0 for no timeout), whichever
        comes first.
        """

        params = dict(params or {})
        if timeout:
            # Heartbeats keep idle connections alive, but we want to stop on idle.
            params["heartbeat"] = False

        url, params = self._prep("stream", path, apikey, params)

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout if timeout else None
        ctimeout = aiohttp.ClientTimeout(total=None, sock_read=timeout or None)

        count = 0
        try:
            async with self.session.get(url, params=params, timeout=ctimeout) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    try:
                        data = json.loads(text)
                    except ValueError:
                        data = None
                    raise ShodanApiError(errMesg(resp.status, data, text), code=resp.status)

                async for line in resp.content:
                    line = line.strip()
                    if line:
                        try:
                            yield json.loads(line)
                        except ValueError:
                            continue
                        count += 1
                        if limit and count >= limit:
                            return

                    if deadline is not None and loop.time() >= deadline:
                        return

        except TimeoutError:
            # Hitting the read timeout just means the stream went quiet.
            return
        except aiohttp.ClientError as err:
            raise ShodanApiError(f"Unable to connect to the Shodan Streaming API: {err}") from err
