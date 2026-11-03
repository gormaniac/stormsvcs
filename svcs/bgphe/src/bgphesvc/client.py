"""A minimal asyncio client for the JSON endpoints behind Hurricane Electric's BGP Toolkit.

bgp.he.net has no documented API. These are the endpoints its own web pages call, none of
them need an account or a key:

========================================================  =========================================
Endpoint                                                  What it returns
========================================================  =========================================
``/certs/api/domain?domain=<fqdn>&page=<n>``              CT log certificates (with DER) for a
                                                          domain, 200 per page.
``/certs/api/list?domain=<fqdn>``                         The domain and its subdomains, with how
                                                          many certificates each has.
``/certs/api/certificates/by-prefix?prefix=<ip>&len=<n>`` IPs in a prefix, each with the hostnames
                                                          (from certificates) that resolve to it.
``/whois/dns/<fqdn>``                                     A domain's raw whois text.
``/whois/as<asn>``                                        An ASN's raw RIR whois text.
``/super-lg/report/api/v1/prefixes/originated/<asn>``     The prefixes an ASN originates.
========================================================  =========================================

bgp.he.net is a free community resource, so the client is deliberately polite: requests are
serialized and spaced at least ``interval`` seconds apart, a ``User-Agent`` identifies the
service, and failed requests are retried a few times with an exponential backoff.
"""

import asyncio
import datetime
import email.utils
import json
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote, urlencode

import aiohttp

BASE_URL = "https://bgp.he.net"
"""The base URL of bgp.he.net."""

USER_AGENT = "slib.bgphe (Synapse Storm Service; https://github.com/gormaniac/stormsvcs)"
"""The User-Agent sent with every request."""

MAX_RETRIES = 3
"""How many times to retry a request that fails with a retryable error."""

RETRY_CODES = frozenset((429, 500, 502, 503, 504))
"""HTTP status codes that are worth retrying."""

MAX_RETRY_AFTER = 300
"""The longest Retry-After (in seconds) the client honors before giving up on a retry."""

MAX_BODY = 64 * 1024 * 1024
"""The largest response body (in bytes) the client accepts.

A page of certificates (200, with their DER) is ~3MB, the largest whois records are well under
1MB, and the prefixes of the biggest ASNs are a few MB.
"""

CERT_PAGE_SIZE = 200
"""The number of certificates in each page of ``/certs/api/domain`` (fixed by bgp.he.net)."""


class BgpHeApiError(Exception):
    """bgp.he.net returned an error, or could not be reached."""

    def __init__(self, mesg: str, code: int | None = None):
        super().__init__(mesg)
        self.mesg = mesg
        self.code = code


def seg(valu: Any) -> str:
    """Quote a value for use as a single URL path segment."""

    return quote(str(valu), safe="")


class Throttle:
    """Serialize requests and space them at least ``interval`` seconds apart."""

    def __init__(self, interval: float):
        self.interval = max(float(interval or 0), 0.0)
        self._lock = asyncio.Lock()
        self._last: float | None = None

    async def wait(self) -> None:
        """Wait until the next request is allowed, then record it as sent."""

        async with self._lock:
            loop = asyncio.get_running_loop()
            if self._last is not None and self.interval:
                delta = self._last + self.interval - loop.time()
                if delta > 0:
                    await asyncio.sleep(delta)
            self._last = loop.time()


class BgpHeClient:
    """The transport used to talk to bgp.he.net.

    Parameters
    ----------
    session : aiohttp.ClientSession
        The session to send requests with. The caller owns its lifecycle.
    url : str, optional
        The base URL (useful for proxies and tests).
    interval : float, optional
        The minimum number of seconds between two requests.
    timeout : float, optional
        Total timeout, in seconds, for a single request.
    backoff : float, optional
        The base, in seconds, of the exponential backoff between retries.
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        url: str = BASE_URL,
        interval: float = 1.0,
        timeout: float = 60.0,
        backoff: float = 2.0,
    ):
        self.session = session
        self.url = (url or BASE_URL).rstrip("/")
        self.throttle = Throttle(interval)
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.backoff = max(float(backoff or 0), 0.0)
        # The number of requests sent, so callers and tests can see the cost of a call.
        self.count = 0

    async def _send(self, path: str, params: Mapping[str, Any] | None = None) -> tuple[int, bytes]:
        """GET a path and return (status, body), retrying transient failures.

        Error responses (HTTP 4xx/5xx) are returned, not raised, so callers can read the
        ``{"error": ...}`` body bgp.he.net sends with them.
        """

        url = self.url + path
        if params:
            url += "?" + urlencode(params)
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate",
        }

        for attempt in range(MAX_RETRIES + 1):
            await self.throttle.wait()
            self.count += 1
            try:
                async with self.session.get(url, headers=headers, timeout=self.timeout) as resp:
                    size = resp.content_length
                    if size is not None and size > MAX_BODY:
                        raise BgpHeApiError(
                            f"The response from {path} is too large ({size} bytes).",
                            code=resp.status,
                        )
                    chunks = []
                    total = 0
                    async for chunk in resp.content.iter_chunked(1024 * 1024):
                        total += len(chunk)
                        if total > MAX_BODY:
                            raise BgpHeApiError(
                                f"The response from {path} is too large (over {MAX_BODY} bytes).",
                                code=resp.status,
                            )
                        chunks.append(chunk)
                    body = b"".join(chunks)
                    code = resp.status
                    retryafter = retryAfter(resp.headers.get("Retry-After"))
            except (aiohttp.ClientError, TimeoutError) as err:
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(self.backoff * 2**attempt)
                    continue
                raise BgpHeApiError(f"Unable to connect to bgp.he.net ({path}): {err}") from err

            if code in RETRY_CODES and attempt < MAX_RETRIES:
                # Honor a Retry-After, never retry sooner than it asks.
                wait = self.backoff * 2**attempt
                if retryafter is not None:
                    if retryafter > MAX_RETRY_AFTER:
                        raise BgpHeApiError(
                            f"bgp.he.net asked to wait {retryafter:.0f} seconds before retrying "
                            f"{path} (HTTP {code}), not retrying.",
                            code=code,
                        )
                    wait = max(wait, retryafter)
                await asyncio.sleep(wait)
                continue

            return code, body

        # The loop always returns or raises, this keeps type checkers happy.
        raise BgpHeApiError(f"Unable to request {path} from bgp.he.net.")  # pragma: no cover

    async def getJson(self, path: str, params: Mapping[str, Any] | None = None) -> dict:
        """GET a path and return its JSON object, raising BgpHeApiError for any error."""

        code, body = await self._send(path, params)
        text = body.decode("utf-8", errors="replace") if body else ""
        try:
            data = json.loads(text) if text else None
        except ValueError:
            data = None

        if code >= 400:
            raise BgpHeApiError(errMesg(path, code, data, text), code=code)
        if not isinstance(data, Mapping):
            raise BgpHeApiError(f"Unexpected response from {path}: expected a JSON object.", code)
        if data.get("error"):
            raise BgpHeApiError(f"bgp.he.net returned an error for {path}: {data['error']}", code)
        if data.get("success") is False:
            raise BgpHeApiError(f"bgp.he.net reported the request to {path} failed.", code)
        return dict(data)

    # ---- Endpoints ----

    async def certsByDomain(self, domain: str, page: int = 1) -> dict:
        """GET /certs/api/domain - a page of the certificates for a domain.

        Returns ``{"certificates": [...], "pagination": {...}, ...}``.
        """

        params = {"domain": domain}
        if page > 1:
            params["page"] = page
        data = await self.getJson("/certs/api/domain", params)
        if not isinstance(data.get("certificates"), list):
            raise BgpHeApiError("Unexpected response from /certs/api/domain: no certificates.")
        return data

    async def certDomains(self, domain: str) -> dict:
        """GET /certs/api/list - a domain and its subdomains, with their certificate counts.

        Returns ``{"domains": [{"domain": ..., "certificate_count": ...}], ...}``.
        """

        data = await self.getJson("/certs/api/list", {"domain": domain})
        if not isinstance(data.get("domains"), list):
            raise BgpHeApiError("Unexpected response from /certs/api/list: no domains.")
        return data

    async def certsByPrefix(self, addr: str, length: int) -> dict:
        """GET /certs/api/certificates/by-prefix - the certificate hostnames on IPs in a prefix.

        Returns ``{"entries": [{"ip": ..., "hostnames": [...]}], "has_more": ..., ...}``.
        """

        params = {"prefix": addr, "len": length}
        data = await self.getJson("/certs/api/certificates/by-prefix", params)
        if not isinstance(data.get("entries"), list):
            raise BgpHeApiError("Unexpected response from /certs/api/certificates/by-prefix.")
        return data

    async def whoisDomain(self, domain: str) -> str:
        """GET /whois/dns/<domain> - a domain's raw whois text."""

        data = await self.getJson(f"/whois/dns/{seg(domain)}")
        return _reqText(data, "/whois/dns")

    async def whoisAsn(self, asn: int) -> str:
        """GET /whois/as<asn> - an ASN's raw whois text, from its RIR."""

        data = await self.getJson(f"/whois/as{int(asn)}")
        return _reqText(data, "/whois/as")

    async def prefixesOriginated(self, asn: int) -> list[dict]:
        """GET /super-lg/report/api/v1/prefixes/originated/<asn> - the prefixes an ASN originates.

        Returns ``[{"Prefix": ..., "Count": ..., "Total": ...}]``.
        """

        path = f"/super-lg/report/api/v1/prefixes/originated/{int(asn)}"
        data = await self.getJson(path)
        prefixes = data.get("prefixes")
        if prefixes is None:
            return []
        if not isinstance(prefixes, list):
            raise BgpHeApiError(f"Unexpected response from {path}: prefixes isn't a list.")
        return prefixes


def _reqText(data: Mapping, path: str) -> str:
    text = data.get("data")
    if not isinstance(text, str):
        raise BgpHeApiError(f"Unexpected response from {path}: no whois data.")
    return text


def retryAfter(valu: str | None) -> float | None:
    """The seconds a Retry-After header asks to wait (seconds or an HTTP date), or None."""

    if not valu:
        return None
    valu = valu.strip()
    try:
        return max(float(valu), 0.0)
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(valu)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.UTC)
    return max((when - datetime.datetime.now(datetime.UTC)).total_seconds(), 0.0)


def errMesg(path: str, code: int, data: Any, text: str) -> str:
    """Build an error message from a bgp.he.net error response."""

    if isinstance(data, Mapping):
        for key in ("error", "message", "detail"):
            if data.get(key):
                return f"bgp.he.net returned HTTP {code} for {path}: {data[key]}"
    if code == 404:
        return f"bgp.he.net returned HTTP 404 for {path}: not found."
    if text and not text.lstrip().startswith("<"):
        return f"bgp.he.net returned HTTP {code} for {path}: {text.strip()[:300]}"
    return f"bgp.he.net returned HTTP {code} for {path}."
