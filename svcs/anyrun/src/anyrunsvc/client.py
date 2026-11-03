"""An asyncio HTTP transport for the ANY.RUN Sandbox and Threat Intelligence APIs.

Built from ANY.RUN's OpenAPI specs (https://files.any.run/schema/SandboxV1.json and
https://files.any.run/schema/TIV1.json, rendered at https://any.run/api-documentation/) and
checked against the official ``anyrun-sdk`` for the parts the specs don't cover.

ANY.RUN's endpoints live on three hosts with several response shapes:

- ``https://api.any.run/v1/...`` - the Sandbox API (``{"error", "data"}`` envelopes) and the
  Threat Intelligence APIs (bare objects: TI Lookup, YARA Search, and TAXII 2.1 feeds).
- ``https://api.any.run/report/...`` - task reports (IOCs, AI summaries, STIX/MISP/...).
- ``https://content.any.run/tasks/...`` - downloads (samples, PCAPs, dropped files).

Every endpoint takes the same ``Authorization: API-Key <key>`` header. Errors come back in four
shapes (``{error, message}``, ``{message, code}``, TAXII's ``{status, message}`` and
``{title, description}``, and NestJS's ``{statusCode, message: [...]}``), ``errMesg`` reads them all.
"""

import asyncio
import datetime
import io
import json
import zipfile
from collections.abc import AsyncIterator, Mapping
from typing import Any
from urllib.parse import quote, urlsplit

import aiohttp
import pyzipper
import yarl

BASE_URL = "https://api.any.run"
"""The API host (``/v1/...`` and ``/report/...``)."""

CONTENT_URL = "https://content.any.run"
"""The host task files (samples, PCAPs, dropped files) are downloaded from."""

APP_URL = "https://app.any.run"
"""The web app, task links are ``{APP_URL}/tasks/{uuid}``."""

USER_AGENT = "slib.anyrun (Synapse Storm Service; https://github.com/gormaniac/stormsvcs)"

CONNECTOR = "slib.anyrun"
"""The ``x-anyrun-connector`` header value, how ANY.RUN identifies an integration."""

ZIP_PASSWORD = b"infected"
"""The password ANY.RUN's sample zips are encrypted with."""

MAX_RETRY_WAIT = 60
"""The longest wait (in seconds) for a 429's ``nextAvailableRequestDate`` before giving up."""

MAX_RETRIES = 2
"""How many times a rate limited (429) request is retried."""

MAX_BODY = 64 * 1024 * 1024
"""The largest JSON response (in bytes) the client reads into memory."""


class AnyRunApiError(Exception):
    """ANY.RUN returned an error, or couldn't be reached.

    ``mesg`` is returned to Storm, ``status`` is the HTTP status and ``code`` the API's error
    code (ex. ``NO_TI_LICENSE_ERROR``), when there is one.
    """

    def __init__(self, mesg: str, status: int | None = None, code: str | None = None):
        super().__init__(mesg)
        self.mesg = mesg
        self.status = status
        self.code = code


def authHeader(apikey: str) -> str:
    """The ``Authorization`` value for a key (keys that already have a scheme are kept)."""

    apikey = apikey.strip()
    if apikey.lower().startswith(("api-key ", "basic ")):
        return apikey
    return f"API-Key {apikey}"


def seg(valu: Any) -> str:
    """Quote a value for use as a single URL path segment."""

    return quote(str(valu).strip(), safe="")


def paramValu(valu: Any) -> str:
    """A query param value as ANY.RUN expects it (lowercase booleans)."""

    if isinstance(valu, bool):
        return "true" if valu else "false"
    return str(valu)


def query(params: Mapping[str, Any] | None) -> str:
    """Build a query string, skipping None values.

    Keys keep their ``[`` and ``]`` (TAXII's ``match[type]``), values are fully percent-encoded
    so base64 ``next`` cursors (``+/=``) survive.
    """

    parts = []
    for key, valu in (params or {}).items():
        if valu is None:
            continue
        parts.append(f"{quote(str(key), safe='[]')}={quote(paramValu(valu), safe='')}")
    return "&".join(parts)


def errMesg(status: int, data: Any, text: str = "") -> tuple[str, str | None]:
    """The (message, code) of an error response, whatever its shape."""

    code = None
    mesg = None
    if isinstance(data, dict):
        code = data.get("code")
        mesg = data.get("message") or data.get("description") or data.get("title")
        if isinstance(mesg, list):
            mesg = "; ".join(str(m) for m in mesg)
        errs = data.get("validationErrors")
        if isinstance(errs, list) and errs:
            details = "; ".join(
                f"{e.get('field')}: {e.get('error')}" if isinstance(e, dict) else str(e)
                for e in errs
            )
            mesg = f"{mesg} ({details})" if mesg else details
    if not mesg:
        mesg = text.strip()[:200] if text and text.strip() else None
    mesg = f"ANY.RUN: {mesg or 'error'} (HTTP {status}"
    if code:
        mesg += f", {code}"
    return mesg + ")", code


def retryWait(data: Any, now: datetime.datetime | None = None) -> float | None:
    """Seconds until a 429's ``nextAvailableRequestDate``, or None if it doesn't say."""

    if not isinstance(data, dict) or not data.get("nextAvailableRequestDate"):
        return None
    try:
        when = datetime.datetime.fromisoformat(str(data["nextAvailableRequestDate"]))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.UTC)
    now = now or datetime.datetime.now(datetime.UTC)
    return max((when - now).total_seconds(), 0.0)


def loads(body: bytes) -> Any:
    """Parse a JSON body, or None if it isn't JSON."""

    if not body:
        return None
    try:
        return json.loads(body)
    except ValueError:
        return None


def isZip(byts: bytes) -> bool:
    """Whether bytes look like a zip archive."""

    return byts[:4] in (b"PK\x03\x04", b"PK\x05\x06")


def unzip(byts: bytes, maxsize: int = 0) -> list[tuple[str, bytes]]:
    """Extract the files of a zip, with ANY.RUN's password when one is needed.

    ``pyzipper`` handles AES, ZipCrypto, and plain zips. Returns ``(name, bytes)`` pairs.
    """

    try:
        with pyzipper.AESZipFile(io.BytesIO(byts)) as zfd:
            zfd.setpassword(ZIP_PASSWORD)
            retn = []
            for info in zfd.infolist():
                if info.is_dir():
                    continue
                if maxsize and info.file_size > maxsize:
                    raise AnyRunApiError(
                        f"{info.filename} is {info.file_size} bytes, larger than the max of "
                        f"{maxsize}."
                    )
                retn.append((info.filename, zfd.read(info)))
            return retn
    except (zipfile.BadZipFile, pyzipper.BadZipFile) as err:
        raise AnyRunApiError(f"Unable to unzip the download: {err}") from err
    except RuntimeError as err:
        # zipfile raises RuntimeError for a bad or missing password.
        raise AnyRunApiError(f"Unable to decrypt the download: {err}") from err


class AnyRunClient:
    """The transport for a single API key.

    Parameters
    ----------
    session : aiohttp.ClientSession
        The session to send requests with. The caller owns its lifecycle.
    apikey : str
        The ANY.RUN API key (with or without the ``API-Key`` prefix).
    url : str, optional
        The API host.
    content : str, optional
        The download host. Only URLs on this host (or ``url``) are ever sent the API key.
    timeout : float, optional
        Total timeout, in seconds, for a single request. Downloads and event streams only use
        it to connect.
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        apikey: str,
        url: str = BASE_URL,
        content: str = CONTENT_URL,
        timeout: float = 60.0,
    ):
        self.session = session
        self.url = (url or BASE_URL).rstrip("/")
        self.content = (content or CONTENT_URL).rstrip("/")
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.streamtimeout = aiohttp.ClientTimeout(total=None, sock_connect=timeout, sock_read=None)
        self.headers = {
            "Authorization": authHeader(apikey),
            "User-Agent": USER_AGENT,
            "x-anyrun-connector": CONNECTOR,
        }

    def _url(self, path: str, params: Mapping[str, Any] | None = None) -> yarl.URL:
        """An API URL (path is relative to the API host, or a full URL on a trusted host)."""

        if path.startswith(("http://", "https://")):
            url = path
            self.checkHost(url)
        else:
            url = self.url + ("" if path.startswith("/") else "/") + path
        qstr = query(params)
        if qstr:
            url += ("&" if "?" in url else "?") + qstr
        return yarl.URL(url, encoded=True)

    def checkHost(self, url: str) -> None:
        """Refuse to send the API key anywhere but ANY.RUN's API and content hosts."""

        host = urlsplit(url).netloc.lower()
        allowed = {urlsplit(self.url).netloc.lower(), urlsplit(self.content).netloc.lower()}
        if host not in allowed:
            raise AnyRunApiError(f"Refusing to send the API key to {host}, not an ANY.RUN host.")

    async def request(
        self,
        method: str,
        path: str,
        params: Mapping[str, Any] | None = None,
        json_data: Any = None,
        form: aiohttp.FormData | None = None,
    ) -> tuple[int, Any]:
        """Send a request and return (status, parsed JSON).

        Non-2xx responses raise ``AnyRunApiError``. A 429 that says when to come back
        (TI Lookup's ``nextAvailableRequestDate``) is retried if that's soon enough.
        """

        url = self._url(path, params)
        for attempt in range(MAX_RETRIES + 1):
            try:
                async with self.session.request(
                    method.upper(),
                    url,
                    headers=self.headers,
                    json=json_data,
                    data=form,
                    timeout=self.timeout,
                ) as resp:
                    if resp.content_length is not None and resp.content_length > MAX_BODY:
                        raise AnyRunApiError(
                            f"ANY.RUN's response is too large ({resp.content_length} bytes).",
                            status=resp.status,
                        )
                    body = await resp.content.read(MAX_BODY + 1)
                    status = resp.status
            except (aiohttp.ClientError, TimeoutError) as err:
                raise AnyRunApiError(f"Unable to connect to ANY.RUN: {err!r}") from err

            if len(body) > MAX_BODY:
                raise AnyRunApiError("ANY.RUN's response is too large.", status=status)

            data = loads(body)
            if status == 429 and attempt < MAX_RETRIES:
                wait = retryWait(data)
                if wait is not None and wait <= MAX_RETRY_WAIT:
                    await asyncio.sleep(wait)
                    continue

            if not 200 <= status < 300:
                mesg, code = errMesg(status, data, body.decode("utf8", "replace"))
                raise AnyRunApiError(mesg, status=status, code=code)

            if data is None and body.strip():
                raise AnyRunApiError(f"ANY.RUN returned a non-JSON response (HTTP {status}).")
            return status, data

        raise AnyRunApiError("ANY.RUN rate limited the request.", status=429)  # pragma: no cover

    async def _raiseFor(self, resp: aiohttp.ClientResponse) -> None:
        """Raise an AnyRunApiError for an unsuccessful streaming response."""

        if 200 <= resp.status < 300:
            return
        body = await resp.content.read(65536)
        mesg, code = errMesg(resp.status, loads(body), body.decode("utf8", "replace"))
        raise AnyRunApiError(mesg, status=resp.status, code=code)

    async def stream(self, path: str, chunksize: int = 1024 * 1024) -> AsyncIterator[bytes]:
        """GET a download and yield its body in chunks."""

        url = self._url(path)
        try:
            async with self.session.get(
                url, headers=self.headers, timeout=self.streamtimeout
            ) as resp:
                await self._raiseFor(resp)
                async for chunk in resp.content.iter_chunked(chunksize):
                    yield chunk
        except (aiohttp.ClientError, TimeoutError) as err:
            raise AnyRunApiError(f"Unable to download from ANY.RUN: {err!r}") from err

    async def events(self, path: str) -> AsyncIterator[dict]:
        """GET a server-sent event stream and yield each ``data:`` line's JSON object."""

        url = self._url(path)
        headers = dict(self.headers, Accept="text/event-stream")
        try:
            async with self.session.get(url, headers=headers, timeout=self.streamtimeout) as resp:
                await self._raiseFor(resp)
                ctype = resp.headers.get("Content-Type", "")
                if "json" in ctype:
                    # An error (or a single status) sent as plain JSON instead of a stream.
                    data = loads(await resp.content.read(MAX_BODY))
                    if isinstance(data, dict):
                        yield data
                    return
                # Lines can be longer than aiohttp's line buffer, so split them ourselves.
                buf = b""
                async for chunk in resp.content.iter_any():
                    buf += chunk
                    *lines, buf = buf.split(b"\n")
                    for line in lines:
                        item = sseData(line)
                        if item is not None:
                            yield item
                item = sseData(buf)
                if item is not None:
                    yield item
        except (aiohttp.ClientError, TimeoutError) as err:
            raise AnyRunApiError(f"Lost the ANY.RUN event stream: {err!r}") from err


def sseData(line: bytes) -> dict | None:
    """The JSON object of an SSE ``data:`` line, or None for any other line."""

    line = line.strip()
    if not line.startswith(b"data:"):
        return None
    data = loads(line[5:].strip())
    return data if isinstance(data, dict) else None
