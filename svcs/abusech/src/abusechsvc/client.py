"""An asyncio HTTP transport for every abuse.ch API and dataset.

abuse.ch runs a separate API (or set of downloadable datasets) for each of its
platforms, and each one is called a little differently: MalwareBazaar and URLhaus
take form data, ThreatFox, YARAify, and the Hunting API take JSON bodies, file
submissions are multipart, and the blocklists/exports are plain files. This module
handles those differences (and abuse.ch's ``query_status`` error convention) so the
rest of the service can call any endpoint the same way.
"""

import asyncio
import email.utils
import io
import json
import time
import zipfile
from collections.abc import AsyncIterator, Mapping
from typing import Any
from urllib.parse import quote

import aiohttp
import pyzipper

BASE_URLS = {
    # MalwareBazaar
    "bazaar": "https://mb-api.abuse.ch/api/v1",
    "bazaar:export": "https://mb-api.abuse.ch/v2/files/exports",
    # URLhaus
    "urlhaus": "https://urlhaus-api.abuse.ch/v1",
    "urlhaus:submit": "https://urlhaus.abuse.ch/api",
    "urlhaus:export": "https://urlhaus-api.abuse.ch/v2/files/exports",
    # ThreatFox
    "threatfox": "https://threatfox-api.abuse.ch/api/v1",
    "threatfox:export": "https://threatfox-api.abuse.ch/v2/files/exports",
    # YARAify
    "yaraify": "https://yaraify-api.abuse.ch/api/v1",
    "yaraify:export": "https://yaraify.abuse.ch",
    # Hunting (the false positive list)
    "hunting": "https://hunting-api.abuse.ch/api/v1",
    # Feodo Tracker and SSL Blacklist only publish datasets.
    "feodo": "https://feodotracker.abuse.ch/downloads",
    "sslbl": "https://sslbl.abuse.ch/blacklist",
}
"""
The base URL of every abuse.ch API and dataset host, keyed by the name used throughout the service.
"""

KEYED_APIS = frozenset(
    (
        "bazaar",
        "bazaar:export",
        "urlhaus",
        "urlhaus:submit",
        "urlhaus:export",
        "threatfox",
        "threatfox:export",
        "yaraify",
        "hunting",
    )
)
"""The APIs that require an abuse.ch Auth-Key. The other datasets send one when it's available."""

EXPORT_APIS = frozenset(("bazaar:export", "urlhaus:export", "threatfox:export"))
"""The exports that take the Auth-Key in the URL path (``<base>/<Auth-Key>/<file>``)."""

OK_STATUSES = frozenset(
    (
        "ok",
        "queued",
        "inserted",
        "updated",
        "success",
        "processing",
        # Harmless outcomes of writes: the sample/value was already there.
        "exists",
        "file_already_known",
    )
)
"""``query_status`` values that mean a request succeeded."""

AUTH_STATUSES = frozenset(
    ("unknown_auth_key", "invalid_auth_key", "auth_key_required", "unauthorized")
)
"""``query_status`` values that mean the Auth-Key was missing or rejected."""

STATUS_MAX = 1024 * 1024
"""How much of a streamed download's error (or JSON status) response is read to report it."""

MAX_RETRIES = 3
"""How many times to retry a request that failed in a way that may be temporary."""

RETRY_CODES = frozenset((429, 503))
"""HTTP statuses that mean the request wasn't processed, so every request is retried."""

RETRY_CODES_IDEMPOTENT = frozenset((500, 502, 504))
"""HTTP statuses that may be temporary, retried only for requests that are safe to repeat.

A write (ex. a submission) that got a 500 or a gateway error may still have been processed.
"""

MAX_RETRY_WAIT = 60.0
"""The longest a ``Retry-After`` header can make a retry wait, in seconds."""

ZIP_PASSWORD = b"infected"
"""The password abuse.ch uses for every zip of malware samples."""


class AbuseChApiError(Exception):
    """abuse.ch returned an error, or could not be reached."""

    def __init__(self, mesg: str, code: int | None = None, status: str | None = None):
        """``code`` is the HTTP status and ``status`` the ``query_status``, when known."""

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
    if status in AUTH_STATUSES or status in (
        "unknown_query",
        "unknown_selector",
        "unknown_operation",
        "unknown_key",
    ):
        return False
    return status.startswith(("no_result", "unknown_")) or status.endswith("not_found")


def scrubKey(text: str, apikey: str | None) -> str:
    """Replace an Auth-Key in ``text``, raw or URL-quoted, with ``<auth-key>``.

    The export APIs take the key in the URL path, and abuse.ch's error pages and HTTP
    libraries' errors can echo the URL back.
    """

    if not apikey:
        return text
    for valu in sorted({apikey, quote(apikey, safe="")}, key=len, reverse=True):
        text = text.replace(valu, "<auth-key>")
    return text


def scrubError(err: AbuseChApiError, apikey: str | None) -> AbuseChApiError:
    """Scrub an Auth-Key out of an ``AbuseChApiError``'s message, in place, and return it."""

    err.mesg = scrubKey(err.mesg, apikey)
    err.args = (err.mesg, *err.args[1:])
    return err


def retryAfter(valu: str | None) -> float | None:
    """The seconds to wait from a ``Retry-After`` header (seconds or an HTTP date), or None.

    The wait is capped at ``MAX_RETRY_WAIT``.
    """

    if not valu:
        return None
    valu = valu.strip()
    try:
        secs = float(valu)
    except ValueError:
        try:
            when = email.utils.parsedate_to_datetime(valu)
        except (TypeError, ValueError):
            return None
        if when is None:
            return None
        secs = when.timestamp() - time.time()
    return max(0.0, min(secs, MAX_RETRY_WAIT))


def checkStatus(base: str, code: int, data: Any, text: str, notfound: bool) -> bool:
    """Raise for an error response. Returns True if the response means "not found".

    Auth failures always raise. A "not found" raises too when ``notfound`` is False, which
    writes use so a missing sample isn't reported as a successful update.
    """

    status = data.get("query_status") if isinstance(data, dict) else None
    if code in (401, 403) or (status and str(status).lower() in AUTH_STATUSES):
        mesg = errMesg(code, data, text) if code >= 400 else statusMesg(data)
        raise AbuseChApiError(
            f"abuse.ch {base}: {mesg} (check your Auth-Key)", code=code, status=status
        )

    if isNotFound(status):
        if notfound:
            return True
        raise AbuseChApiError(f"abuse.ch {base}: {statusMesg(data)}", code=code, status=status)

    if code >= 400:
        raise AbuseChApiError(errMesg(code, data, text), code=code, status=status)

    if status is not None and str(status).lower() not in OK_STATUSES:
        raise AbuseChApiError(f"abuse.ch {base}: {statusMesg(data)}", code=code, status=status)

    return False


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


def statusMesg(data: Mapping[str, Any]) -> str:
    """Describe a ``query_status``, with abuse.ch's explanation when ``data`` is a string.

    Errors like timeouts come back as ``{"query_status": "error", "data": "Query execution ..."}``.
    """

    status = str(data.get("query_status"))
    detail = data.get("data")
    if isinstance(detail, str) and detail.strip() and not detail.lstrip().startswith("<"):
        return f"{status}: {detail.strip()[:500]}"
    return status


def errMesg(code: int, data: Any, text: str) -> str:
    """Pull the most useful error message out of an abuse.ch response."""

    if isinstance(data, dict):
        if data.get("query_status") and not str(data["query_status"]).lstrip().startswith("<"):
            return statusMesg(data)
        for key in ("error", "detail", "message"):
            valu = data.get(key)
            if valu and not str(valu).lstrip().startswith("<"):
                return str(valu)

    if text and not text.lstrip().startswith(("<", "{")):
        return text.strip()[:500]

    if code in (401, 403):
        return "Invalid or missing abuse.ch Auth-Key"

    return f"HTTP {code}"


def unzip(
    byts: bytes, password: bytes | None = ZIP_PASSWORD, maxsize: int = 0
) -> list[tuple[str, bytes]]:
    """Extract every file from a zip, trying abuse.ch's password when one is needed.

    MalwareBazaar's zips are AES encrypted, which the standard library can't
    decrypt, so ``pyzipper`` is used (it also handles ZipCrypto and plain zips).
    ``maxsize`` (0 for no limit) caps each file and the total of every file, so a small zip
    can't expand into more memory than that (a zip bomb). Returns a list of ``(name, bytes)``.
    Raises ``AbuseChApiError`` on failure.
    """

    try:
        with pyzipper.AESZipFile(io.BytesIO(byts)) as zfd:
            if password:
                zfd.setpassword(password)
            retn = []
            total = 0
            for info in zfd.infolist():
                if info.is_dir():
                    continue
                total += info.file_size
                if maxsize and info.file_size > maxsize:
                    raise AbuseChApiError(
                        f"{info.filename} is {info.file_size} bytes, "
                        f"larger than the max of {maxsize}."
                    )
                if maxsize and total > maxsize:
                    raise AbuseChApiError(
                        f"The zip's files are over {total} bytes, larger than the max of {maxsize}."
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
        """Allow ``rate`` calls per second, 0 (or less) for no limit."""

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
    maxsize : int, optional
        The max size, in bytes, of a response body read into memory. 0 disables it.
        ``stream()`` isn't capped, its caller decides where the bytes go.
    backoff : float, optional
        The base wait, in seconds, between retries (doubled each time) when abuse.ch doesn't
        send a ``Retry-After``. 0 retries right away (for tests).
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        urls: Mapping[str, str] | None = None,
        rate: float = 5.0,
        timeout: float = 120.0,
        maxsize: int = 0,
        backoff: float = 1.0,
    ):
        """See the class docstring for the parameters."""

        self.session = session
        self.urls = dict(BASE_URLS)
        if urls:
            self.urls.update(urls)
        self.limiter = RateLimiter(rate)
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.maxsize = maxsize
        self.backoff = backoff

    def _retryWait(self, attempt: int, resp: aiohttp.ClientResponse | None = None) -> float:
        """How long to wait before retry ``attempt`` (0 based), honoring ``Retry-After``."""

        if resp is not None:
            wait = retryAfter(resp.headers.get("Retry-After"))
            if wait is not None:
                return wait if self.backoff else 0.0
        return self.backoff * 2**attempt

    @staticmethod
    def _retryable(code: int, idempotent: bool) -> bool:
        """Whether a response with this HTTP status should be retried."""

        return code in RETRY_CODES or (idempotent and code in RETRY_CODES_IDEMPOTENT)

    @staticmethod
    def _retryableError(err: Exception, idempotent: bool) -> bool:
        """Whether a transport error should be retried.

        Failing to connect means nothing was sent, so it's always safe. Timeouts and dropped
        connections may happen after abuse.ch processed the request, so only idempotent
        requests retry them.
        """

        if isinstance(err, aiohttp.ClientConnectorError):
            return True
        return idempotent and isinstance(err, (TimeoutError, aiohttp.ClientConnectionError))

    async def _readBody(self, resp: aiohttp.ClientResponse, base: str) -> bytes:
        """Read a response body, refusing one larger than ``maxsize``."""

        if self.maxsize and (resp.content_length or 0) > self.maxsize:
            raise AbuseChApiError(
                f"abuse.ch {base}: The response is {resp.content_length} bytes, larger than the "
                f"max of {self.maxsize}."
            )
        buf = bytearray()
        async for byts in resp.content.iter_chunked(1024 * 1024):
            buf.extend(byts)
            if self.maxsize and len(buf) > self.maxsize:
                raise AbuseChApiError(
                    f"abuse.ch {base}: The response is larger than the max of {self.maxsize} bytes."
                )
        return bytes(buf)

    @staticmethod
    async def _readHead(resp: aiohttp.ClientResponse, size: int) -> tuple[bytes, bool]:
        """Read up to ``size`` bytes of a body, returning ``(bytes, whether it hit EOF)``.

        One ``read()`` returns whatever has arrived, so this reads until EOF or ``size``.
        """

        buf = bytearray()
        while len(buf) < size:
            byts = await resp.content.read(size - len(buf))
            if not byts:
                return bytes(buf), True
            buf.extend(byts)
        return bytes(buf), resp.content.at_eof()

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
                "then run slib.abusech.apikey (or slib.abusech.admin.apikey for a service-wide "
                "key)."
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
        idempotent: bool = True,
    ) -> tuple[int, bytes, str]:
        """Send a request and return its ``(HTTP status, body, content type)``.

        ``files`` is a dict of ``{field: (filename, bytes)}`` sent as multipart,
        with any ``form`` fields alongside them. Requests that failed in a way that may be
        temporary are retried (see ``_retryable``), ``idempotent=False`` (writes, and every
        upload) only retries the failures that mean abuse.ch didn't process the request.
        The body is capped at ``maxsize``.
        """

        idempotent = idempotent and not files

        headers = self.headers(base, apikey)
        if base in EXPORT_APIS:
            path = f"{quote(apikey, safe='')}/{path.lstrip('/')}"
        url = self.url(base, path)

        for attempt in range(MAX_RETRIES + 1):
            await self.limiter.wait()

            kwargs: dict[str, Any] = {"headers": headers, "timeout": self.timeout}
            if params:
                kwargs["params"] = normForm(params)
            if files:
                mpart = aiohttp.FormData()
                for key, valu in normForm(form).items():
                    # abuse.ch's upload APIs expect their options as a JSON part.
                    ctype = "application/json" if key == "json_data" else None
                    mpart.add_field(key, valu, content_type=ctype)
                for key, (name, byts) in files.items():
                    mpart.add_field(
                        key, byts, filename=name, content_type="application/octet-stream"
                    )
                kwargs["data"] = mpart
            elif form is not None:
                kwargs["data"] = normForm(form)
            elif json_data is not None:
                kwargs["json"] = json_data

            try:
                async with self.session.request(method.upper(), url, **kwargs) as resp:
                    code = resp.status
                    ctype = resp.headers.get("Content-Type", "")
                    if self._retryable(code, idempotent) and attempt < MAX_RETRIES:
                        await asyncio.sleep(self._retryWait(attempt, resp))
                        continue
                    body = await self._readBody(resp, base)
            except AbuseChApiError as err:
                raise scrubError(err, apikey) from None
            except (TimeoutError, aiohttp.ClientError) as err:
                if self._retryableError(err, idempotent) and attempt < MAX_RETRIES:
                    await asyncio.sleep(self._retryWait(attempt))
                    continue
                # Some errors include the URL, which has the Auth-Key for the exports.
                mesg = scrubKey(str(err), apikey)
                raise AbuseChApiError(f"Unable to connect to abuse.ch ({base}): {mesg}") from err

            return code, body, ctype

        raise AbuseChApiError(  # pragma: no cover
            scrubKey(f"Gave up on {url} after {MAX_RETRIES} retries", apikey)
        )

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
        notfound: bool = True,
        idempotent: bool = True,
    ) -> dict | None:
        """Call an abuse.ch API that returns JSON with a ``query_status``.

        Returns the parsed response, or ``None`` when ``query_status`` says the
        query matched nothing (``notfound=False`` raises instead, see ``checkStatus``).

        Raises
        ------
        AbuseChApiError
            If abuse.ch can't be reached, returns an HTTP error, invalid JSON, or
            a ``query_status`` that isn't a success or a "not found".
        """

        code, body, _ = await self.send(
            method,
            base,
            path,
            apikey=apikey,
            params=params,
            form=form,
            json_data=json_data,
            files=files,
            idempotent=idempotent,
        )
        text = body.decode("utf-8", "replace")
        try:
            data = json.loads(text) if text.strip() else None
        except ValueError:
            data = None
            if code < 400:
                raise AbuseChApiError(f"Unable to parse the JSON response from {base}", code=code)

        try:
            if checkStatus(base, code, data, text, notfound):
                return None
        except AbuseChApiError as err:
            raise scrubError(err, apikey) from None
        return data

    async def stream(
        self, base: str, path: str, *, apikey: str | None = None, chunk: int = 1024 * 1024
    ) -> AsyncIterator[bytes]:
        """Stream a (large) dataset's raw bytes, as abuse.ch serves them (zipped or not).

        Exports can be hundreds of MB, so the body is read in chunks with only a read timeout
        (no total timeout). Error responses (JSON statuses or HTTP errors) are raised. Failures
        that may be temporary are retried until the first byte is yielded.
        """

        headers = self.headers(base, apikey)
        if base in EXPORT_APIS:
            path = f"{quote(apikey, safe='')}/{path.lstrip('/')}"
        url = self.url(base, path)
        timeout = aiohttp.ClientTimeout(
            total=None, sock_connect=self.timeout.total, sock_read=self.timeout.total
        )

        started = False
        for attempt in range(MAX_RETRIES + 1):
            await self.limiter.wait()
            try:
                async with self.session.get(url, headers=headers, timeout=timeout) as resp:
                    ctype = resp.headers.get("Content-Type", "")
                    if self._retryable(resp.status, True) and attempt < MAX_RETRIES:
                        await asyncio.sleep(self._retryWait(attempt, resp))
                        continue
                    if resp.status >= 400 or "json" in ctype:
                        # Errors (HTTP errors, or a JSON query_status) are small: read up to
                        # STATUS_MAX and raise like any other response. A JSON body that's
                        # larger is a dataset (ex. ThreatFox's recent.json), streamed below.
                        body, eof = await self._readHead(resp, STATUS_MAX)
                        if eof or resp.status >= 400:
                            data = None
                            try:
                                data = json.loads(body) if body.strip() else None
                            except ValueError:
                                pass
                            try:
                                checkStatus(
                                    base,
                                    resp.status,
                                    data,
                                    body.decode("utf-8", "replace"),
                                    notfound=False,
                                )
                            except AbuseChApiError as err:
                                raise scrubError(err, apikey) from None
                        if body:
                            started = True
                            yield body
                        if eof:
                            return
                    async for byts in resp.content.iter_chunked(chunk):
                        started = True
                        yield byts
                    return
            except (TimeoutError, aiohttp.ClientError) as err:
                # Only retried before the first byte, a partial download can't be resumed.
                if not started and self._retryableError(err, True) and attempt < MAX_RETRIES:
                    await asyncio.sleep(self._retryWait(attempt))
                    continue
                mesg = scrubKey(str(err), apikey)
                raise AbuseChApiError(f"Unable to download from abuse.ch ({base}): {mesg}") from err

        raise AbuseChApiError(  # pragma: no cover
            scrubKey(f"Gave up on {url} after {MAX_RETRIES} retries", apikey)
        )

    async def download(
        self, base: str, path: str, fd: Any, *, apikey: str | None = None, maxsize: int = 0
    ) -> int:
        """Stream a (large) dataset into a writable binary file object (see ``stream()``).

        ``maxsize`` (0 for no limit) stops the download once it's larger than that. Returns
        the number of bytes written.
        """

        size = 0
        async for byts in self.stream(base, path, apikey=apikey):
            size += len(byts)
            if maxsize and size > maxsize:
                raise AbuseChApiError(
                    f"abuse.ch {base}: {path} is larger than the max of {maxsize} bytes."
                )
            fd.write(byts)
        return size

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
        idempotent: bool = True,
    ) -> tuple[bytes, str]:
        """Download a file (a dataset, sample, or rule) and return ``(bytes, content type)``.

        Some download endpoints answer errors with a JSON ``query_status``
        instead of an HTTP error, those are raised too. A "not found" status
        returns empty bytes.
        """

        code, body, ctype = await self.send(
            method,
            base,
            path,
            apikey=apikey,
            params=params,
            form=form,
            json_data=json_data,
            idempotent=idempotent,
        )

        data = None
        if "json" in ctype or body[:1] == b"{":
            try:
                data = json.loads(body)
            except ValueError:
                data = None

        try:
            if checkStatus(base, code, data, body.decode("utf-8", "replace"), notfound=True):
                return b"", ctype
        except AbuseChApiError as err:
            raise scrubError(err, apikey) from None
        return body, ctype
