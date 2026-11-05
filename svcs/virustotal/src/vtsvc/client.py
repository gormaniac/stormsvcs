"""An asyncio HTTP transport for the VirusTotal API v3.

Every request goes through the ``QuotaLimiter`` (see ``vtsvc.quota``) before it's sent, so the
service never goes over a Public API key's limits. Successful GETs can also be cached for a
while, which saves quota when the same object is looked up again soon after.
"""

import asyncio
import json
import time
from collections import OrderedDict
from collections.abc import Mapping
from typing import Any

import aiohttp

from .quota import QuotaLimiter, VtQuotaError, keyId

BASE_URL = "https://www.virustotal.com/api/v3"

# VirusTotal error codes (``error.code``) worth retrying, and how many times to retry them.
TRANSIENT = frozenset(("TransientError", "DeadlineExceededError"))
MAX_RETRIES = 2


class VtApiError(Exception):
    """VirusTotal returned an error, or could not be reached."""

    def __init__(self, mesg: str, code: int | None = None, error: str | None = None):
        super().__init__(mesg)
        self.mesg = mesg
        self.code = code
        self.error = error


class NoApiKeyError(VtApiError):
    """A request was made without an API key available."""


class NotFoundError(VtApiError):
    """VirusTotal doesn't have the requested object (HTTP 404, NotFoundError)."""


def normParam(valu: Any) -> str:
    """Convert a Python value into the string form VirusTotal expects in a query param."""

    if isinstance(valu, bool):
        return "true" if valu else "false"
    if isinstance(valu, (list, tuple, set)):
        return ",".join(str(v) for v in valu)
    return str(valu)


def normParams(params: Mapping[str, Any] | None) -> dict[str, str]:
    """Normalize a dict of query params, dropping any that are None."""

    if not params:
        return {}
    if not isinstance(params, Mapping):
        raise VtApiError(f"Expected a dict of params, got {type(params).__name__}: {params!r}")
    return {k: normParam(v) for k, v in params.items() if v is not None}


def errInfo(code: int, data: Any, text: str) -> tuple[str | None, str]:
    """The VirusTotal error code and message of an error response.

    Errors look like ``{"error": {"code": "NotFoundError", "message": "..."}}``.
    """

    if isinstance(data, dict) and isinstance(data.get("error"), dict):
        err = data["error"]
        name = err.get("code") or None
        mesg = err.get("message") or name or f"HTTP {code}"
        return name, f"{mesg} ({name}, HTTP {code})" if name else mesg
    if text and not text.lstrip().startswith(("<", "{")):
        return None, f"{text.strip()[:500]} (HTTP {code})"
    return None, f"HTTP {code}"


class TtlCache:
    """A small LRU cache whose entries expire after ``ttl`` seconds."""

    def __init__(self, ttl: float, size: int, clock=time.monotonic):
        self.ttl = ttl
        self.size = size
        self.clock = clock
        self._data: OrderedDict = OrderedDict()

    def get(self, key):
        if not self.ttl or not self.size:
            return None
        item = self._data.get(key)
        if item is None:
            return None
        expires, valu = item
        if expires < self.clock():
            self._data.pop(key, None)
            return None
        self._data.move_to_end(key)
        return valu

    def set(self, key, valu) -> None:
        if not self.ttl or not self.size:
            return
        self._data[key] = (self.clock() + self.ttl, valu)
        self._data.move_to_end(key)
        while len(self._data) > self.size:
            self._data.popitem(last=False)

    def clear(self) -> None:
        self._data.clear()

    def __len__(self) -> int:
        return len(self._data)


class VtClient:
    """The transport used to talk to the VirusTotal API.

    Parameters
    ----------
    session : aiohttp.ClientSession
        The session to send requests with. The caller owns its lifecycle.
    limiter : QuotaLimiter
        Reserves a slot for every request sent.
    url : str, optional
        The API's base URL (useful for proxies and tests).
    timeout : float, optional
        Total timeout, in seconds, for a single request.
    cache : TtlCache, optional
        Where cacheable GET responses are kept.
    backoff : float, optional
        The base, in seconds, of the exponential backoff between retries of transient errors.
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        limiter: QuotaLimiter,
        url: str = BASE_URL,
        timeout: float = 120.0,
        cache: TtlCache | None = None,
        backoff: float = 5.0,
    ):
        self.session = session
        self.limiter = limiter
        self.url = url.rstrip("/")
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.cache = cache if cache is not None else TtlCache(0, 0)
        self.backoff = backoff

    def _url(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            # Ex. the one time upload URL from GET /files/upload_url.
            return path
        if not path.startswith("/"):
            path = "/" + path
        return self.url + path

    async def request(
        self,
        method: str,
        path: str,
        *,
        apikey: str | None,
        params: Mapping[str, Any] | None = None,
        json_data: Any = None,
        form: Mapping[str, Any] | None = None,
        data: Any = None,
        cache: bool = False,
    ) -> Any:
        """Send a request to VirusTotal and return the parsed JSON body.

        ``form`` is sent as a URL encoded form, ``data`` as-is (ex. an ``aiohttp.FormData``
        multipart upload). ``cache`` allows a successful GET to be answered from, and saved
        to, the response cache.

        Raises
        ------
        NoApiKeyError
            Without an API key.
        VtQuotaError
            If the request would go over the key's quota, or VirusTotal says it did.
        NotFoundError
            If VirusTotal doesn't have the object.
        VtApiError
            If VirusTotal can't be reached, returns any other error, or returns invalid JSON.
        """

        if not apikey:
            raise NoApiKeyError(
                "No VirusTotal API key is configured. Run slib.vt.apikey to set your own key, "
                "or slib.vt.admin.apikey to set a service-wide key."
            )

        bodies = [b for b in (json_data, form, data) if b is not None]
        if len(bodies) > 1:
            raise VtApiError("A request can only have one body (json_data, form, or data).")

        method = method.upper()
        url = self._url(path)
        params = normParams(params)
        cache = cache and method == "GET"
        ckey = (keyId(apikey), url, tuple(sorted(params.items())))
        if cache:
            hit = self.cache.get(ckey)
            if hit is not None:
                return hit

        body = normParams(form) if form is not None else data
        headers = {"x-apikey": apikey, "accept": "application/json"}

        for attempt in range(MAX_RETRIES + 1):
            await self.limiter.acquire(apikey)
            try:
                async with self.session.request(
                    method,
                    url,
                    params=params,
                    json=json_data,
                    data=body,
                    headers=headers,
                    timeout=self.timeout,
                ) as resp:
                    text = await resp.text()
                    code = resp.status
            except (aiohttp.ClientError, TimeoutError) as err:
                raise VtApiError(f"Unable to connect to VirusTotal: {err}") from err

            try:
                parsed = json.loads(text) if text else None
            except ValueError:
                parsed = None
                if code < 400:
                    raise VtApiError(
                        f"Unable to parse the JSON response from {method} {path}", code=code
                    )

            if code < 400:
                if cache:
                    self.cache.set(ckey, parsed)
                return parsed

            name, mesg = errInfo(code, parsed, text)
            if (name in TRANSIENT or code in (502, 503, 504)) and attempt < MAX_RETRIES:
                await asyncio.sleep(self.backoff * 2**attempt)
                continue
            break

        if code == 429:
            # Don't retry, VirusTotal's quota is gone (or another client is using the key).
            self.limiter.cooldown(apikey)
            raise VtQuotaError(f"VirusTotal rejected the request for going over a quota: {mesg}")
        if code == 404 or name == "NotFoundError":
            raise NotFoundError(mesg, code=code, error=name)
        if code == 401:
            mesg = f"VirusTotal rejected the API key: {mesg}"
        elif code == 403:
            mesg = (
                f"VirusTotal denied access, this may need a premium (VT Enterprise) API key: {mesg}"
            )
        raise VtApiError(mesg, code=code, error=name)
