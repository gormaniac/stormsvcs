"""An asyncio HTTP transport for every abuse.ch API and dataset.

abuse.ch runs a separate API (or set of downloadable datasets) for each of its
platforms, and each one is called a little differently: MalwareBazaar and URLhaus
take form data, ThreatFox, YARAify, and the Hunting API take JSON bodies, file
submissions are multipart, and the blocklists/exports are plain files. This module
handles those differences (and abuse.ch's ``query_status`` error convention) so the
rest of the service can call any endpoint the same way.
"""


import asyncio
import io
import json
import zipfile
from collections.abc import Mapping
from typing import Any

import aiohttp
import pyzipper


BASE_URLS = {
    # MalwareBazaar
    "bazaar": "https://mb-api.abuse.ch/api/v1",
    "bazaar:export": "https://bazaar.abuse.ch/export",
    # URLhaus
    "urlhaus": "https://urlhaus-api.abuse.ch/v1",
    "urlhaus:submit": "https://urlhaus.abuse.ch/api",
    "urlhaus:export": "https://urlhaus.abuse.ch/downloads",
    # ThreatFox
    "threatfox": "https://threatfox-api.abuse.ch/api/v1",
    "threatfox:export": "https://threatfox.abuse.ch/export",
    # YARAify
    "yaraify": "https://yaraify-api.abuse.ch/api/v1",
    "yaraify:export": "https://yaraify-api.abuse.ch",
    # Hunting (the false positive list)
    "hunting": "https://hunting-api.abuse.ch/api/v1",
    # Feodo Tracker and SSL Blacklist only publish datasets.
    "feodo": "https://feodotracker.abuse.ch/downloads",
    "sslbl": "https://sslbl.abuse.ch/blacklist",
}
"""The base URL of every abuse.ch API and dataset host, keyed by the name used throughout the service."""

KEYED_APIS = frozenset(("bazaar", "urlhaus", "urlhaus:submit", "threatfox", "yaraify", "hunting"))
"""The APIs that require an abuse.ch Auth-Key. The datasets send one when it's available."""

OK_STATUSES = frozenset((
    "ok", "queued", "inserted", "updated", "success", "processing",
))
"""``query_status`` values that mean a request succeeded."""

MAX_RETRIES = 3
"""How many times to retry a request that receives an HTTP 429 or 503."""

ZIP_PASSWORD = b"infected"
"""The password abuse.ch uses for every zip of malware samples."""


class AbuseChApiError(Exception):
    """abuse.ch returned an error, or could not be reached."""

    def __init__(self, mesg: str, code: int | None = None, status: str | None = None):
        super().__init__(mesg)
        self.mesg = mesg
        self.code = code
        self.status = status


class NoApiKeyError(AbuseChApiError):
    """A keyed abuse.ch API was called without an Auth-Key available."""


def isNotFound(status: str | None) -> bool:
    """Whether an abuse.ch ``query_status`` means the query matched nothing.

    Each platform words this differently (``no_results``, ``no_result``,
    ``hash_not_found``, ``tag_not_found``, ``unknown_hash``, ...).
    """

    if not status:
        return False
    status = status.lower()
    if status in ("unknown_query", "unknown_selector"):
        return False
    return status.startswith(("no_result", "unknown_")) or status.endswith("not_found")


def normForm(data: Mapping[str, Any] | None) -> dict[str, str]:
    """Normalize form data for abuse.ch, dropping None values and stringifying the rest."""

    if not data:
        return {}
    retn = {}
    for key, valu in data.items():
        if valu is None:
            continue
        if isinstance(valu, bool):
            valu = "1" if valu else "0"
        elif isinstance(valu, (list, tuple, set)):
            valu = ",".join(str(v) for v in valu)
        retn[key] = str(valu)
    return retn


def normJson(data: Mapping[str, Any] | None) -> dict[str, Any]:
    """Drop None values from a JSON body, abuse.ch rejects some empty fields."""

    if not data:
        return {}
    return {k: v for k, v in data.items() if v is not None}


def errMesg(code: int, data: Any, text: str) -> str:
    """Pull the most useful error message out of an abuse.ch response."""

    if isinstance(data, dict):
        for key in ("query_status", "error", "detail", "message"):
            valu = data.get(key)
            if valu and not str(valu).lstrip().startswith("<"):
                return str(valu)

    if text and not text.lstrip().startswith(("<", "{")):
        return text.strip()[:500]

    if code in (401, 403):
        return "Invalid or missing abuse.ch Auth-Key"

    return f"HTTP {code}"


def unzip(byts: bytes, password: bytes | None = ZIP_PASSWORD, maxsize: int = 0) -> list[tuple[str, bytes]]:
    """Extract every file from a zip, trying abuse.ch's password when one is needed.

    MalwareBazaar's zips are AES encrypted, which the standard library can't
    decrypt, so ``pyzipper`` is used (it also handles ZipCrypto and plain zips).
    Returns a list of ``(name, bytes)``. Raises ``AbuseChApiError`` on failure.
    """

    try:
        with pyzipper.AESZipFile(io.BytesIO(byts)) as zfd:
            if password:
                zfd.setpassword(password)
            retn = []
            for info in zfd.infolist():
                if info.is_dir():
                    continue
                if maxsize and info.file_size > maxsize:
                    raise AbuseChApiError(
                        f"{info.filename} is {info.file_size} bytes, larger than the max of {maxsize}."
                    )
                retn.append((info.filename, zfd.read(info)))
            return retn
    except (zipfile.BadZipFile, pyzipper.BadZipFile) as err:
        raise AbuseChApiError(f"Unable to unzip the response: {err}") from err
    except RuntimeError as err:
        # zipfile raises RuntimeError for a bad/missing password.
        raise AbuseChApiError(f"Unable to decrypt the zip: {err}") from err


class RateLimiter:
    """Space out calls so no more than ``rate`` happen per second."""

    def __init__(self, rate: float):
        self.interval = 1.0 / rate if rate and rate > 0 else 0.0
        self._lock = asyncio.Lock()
        self._last: float | None = None

    async def wait(self) -> None:
        """Wait until the next call is allowed."""

        if not self.interval:
            return

        async with self._lock:
            loop = asyncio.get_running_loop()
            if self._last is not None:
                delta = self._last + self.interval - loop.time()
                if delta > 0:
                    await asyncio.sleep(delta)
            self._last = loop.time()


class AbuseChClient:
    """The transport used to talk to every abuse.ch API.

    Parameters
    ----------
    session : aiohttp.ClientSession
        The session to send requests with. The caller owns its lifecycle.
    urls : dict, optional
        Overrides for ``BASE_URLS`` (useful for proxies, mirrors, and tests).
    rate : float, optional
        Max requests/second sent to abuse.ch, shared by every API. 0 disables it.
    timeout : float, optional
        Total timeout, in seconds, for a single request.
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        urls: Mapping[str, str] | None = None,
        rate: float = 5.0,
        timeout: float = 120.0,
    ):
        self.session = session
        self.urls = dict(BASE_URLS)
        if urls:
            self.urls.update(urls)
        self.limiter = RateLimiter(rate)
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    def url(self, base: str, path: str = "") -> str:
        """Build the full URL for a path on one of the abuse.ch APIs."""

        if base not in self.urls:
            raise AbuseChApiError(f"Unknown abuse.ch API: {base}")
        return self.urls[base].rstrip("/") + "/" + path.lstrip("/")

    def headers(self, base: str, apikey: str | None) -> dict[str, str]:
        """The headers for a request, requiring an Auth-Key for the keyed APIs."""

        if base in KEYED_APIS and not apikey:
            raise NoApiKeyError(
                "No abuse.ch Auth-Key is configured. Get one for free at https://auth.abuse.ch/ "
                "then run slib.abusech.apikey (or slib.abusech.admin.apikey for a service-wide key)."
            )
        return {"Auth-Key": apikey} if apikey else {}

    async def send(
        self,
        method: str,
        base: str,
        path: str = "",
        *,
        apikey: str | None = None,
        params: Mapping[str, Any] | None = None,
        form: Mapping[str, Any] | None = None,
        json_data: Any = None,
        files: Mapping[str, tuple[str, bytes]] | None = None,
    ) -> tuple[int, bytes, str]:
        """Send a request and return its ``(HTTP status, body, content type)``.

        ``files`` is a dict of ``{field: (filename, bytes)}`` sent as multipart,
        with any ``form`` fields alongside them.
        """

        url = self.url(base, path)
        headers = self.headers(base, apikey)

        for attempt in range(MAX_RETRIES + 1):
            await self.limiter.wait()

            kwargs: dict[str, Any] = {"headers": headers, "timeout": self.timeout}
            if params:
                kwargs["params"] = normForm(params)
            if files:
                mpart = aiohttp.FormData()
                for key, valu in normForm(form).items():
                    mpart.add_field(key, valu)
                for key, (name, byts) in files.items():
                    mpart.add_field(key, byts, filename=name, content_type="application/octet-stream")
                kwargs["data"] = mpart
            elif form is not None:
                kwargs["data"] = normForm(form)
            elif json_data is not None:
                kwargs["json"] = json_data

            try:
                async with self.session.request(method.upper(), url, **kwargs) as resp:
                    body = await resp.read()
                    code = resp.status
                    ctype = resp.headers.get("Content-Type", "")
            except (TimeoutError, aiohttp.ClientError) as err:
                raise AbuseChApiError(f"Unable to connect to abuse.ch ({base}): {err}") from err

            if code in (429, 503) and attempt < MAX_RETRIES:
                await asyncio.sleep(2 ** attempt)
                continue
            return code, body, ctype

        raise AbuseChApiError(f"Gave up on {url} after {MAX_RETRIES} retries")  # pragma: no cover

    async def query(
        self,
        base: str,
        path: str = "",
        *,
        method: str = "post",
        apikey: str | None = None,
        params: Mapping[str, Any] | None = None,
        form: Mapping[str, Any] | None = None,
        json_data: Any = None,
        files: Mapping[str, tuple[str, bytes]] | None = None,
    ) -> dict | None:
        """Call an abuse.ch API that returns JSON with a ``query_status``.

        Returns the parsed response, or ``None`` when ``query_status`` says the
        query matched nothing.

        Raises
        ------
        AbuseChApiError
            If abuse.ch can't be reached, returns an HTTP error, invalid JSON, or
            a ``query_status`` that isn't a success or a "not found".
        """

        code, body, _ = await self.send(method, base, path, apikey=apikey, params=params, form=form,
                                        json_data=json_data, files=files)
        text = body.decode("utf-8", "replace")
        try:
            data = json.loads(text) if text.strip() else None
        except ValueError:
            data = None
            if code < 400:
                raise AbuseChApiError(f"Unable to parse the JSON response from {base}", code=code)

        status = data.get("query_status") if isinstance(data, dict) else None
        if isNotFound(status):
            return None

        if code >= 400:
            raise AbuseChApiError(errMesg(code, data, text), code=code, status=status)

        if status is not None and str(status).lower() not in OK_STATUSES:
            raise AbuseChApiError(f"abuse.ch {base}: {status}", code=code, status=status)

        return data

    async def fetch(
        self,
        base: str,
        path: str = "",
        *,
        method: str = "get",
        apikey: str | None = None,
        params: Mapping[str, Any] | None = None,
        form: Mapping[str, Any] | None = None,
        json_data: Any = None,
    ) -> tuple[bytes, str]:
        """Download a file (a dataset, sample, or rule) and return ``(bytes, content type)``.

        Some download endpoints answer errors with a JSON ``query_status``
        instead of an HTTP error, those are raised too. A "not found" status
        returns empty bytes.
        """

        code, body, ctype = await self.send(method, base, path, apikey=apikey, params=params,
                                            form=form, json_data=json_data)

        data = None
        if "json" in ctype or body[:1] == b"{":
            try:
                data = json.loads(body)
            except ValueError:
                data = None

        status = data.get("query_status") if isinstance(data, dict) else None
        if isNotFound(status):
            return b"", ctype

        if code >= 400:
            raise AbuseChApiError(errMesg(code, data, body.decode("utf-8", "replace")), code=code,
                                  status=status)

        if status is not None and str(status).lower() not in OK_STATUSES:
            raise AbuseChApiError(f"abuse.ch {base}: {status}", code=code, status=status)

        return body, ctype
