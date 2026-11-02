"""A minimal asyncio client for Malpedia's public REST API.

Only the endpoints documented with "Access limitation: none" at
https://malpedia.caad.fkie.fraunhofer.de/usage/api are implemented, and only the ones this
service needs. MISP (``/api/get/misp``), sample, ApiScout, and scan endpoints are left out on
purpose. No API token is ever sent.

Malpedia is a free community resource run by Fraunhofer FKIE, so the client is deliberately
polite: requests are serialized and spaced at least ``interval`` seconds apart, a
``User-Agent`` identifies the service, and failed requests are retried a few times with an
exponential backoff instead of hammering the server.
"""

import asyncio
import io
import json
import zipfile
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

import aiohttp

# The base URL of Malpedia's REST API.
BASE_URL = "https://malpedia.caad.fkie.fraunhofer.de/api"

# The URL of Malpedia's website, used to link to actor and family pages.
SITE_URL = "https://malpedia.caad.fkie.fraunhofer.de"

# The User-Agent sent with every request.
USER_AGENT = "slib.malpedia (Synapse Storm Service; https://github.com/gormaniac/stormsvcs)"

# The TLPs Malpedia publishes YARA rules under. Unregistered users only get tlp_white.
YARA_TLPS = ("tlp_white", "tlp_green", "tlp_amber")

# How many times to retry a request that fails with a retryable error.
MAX_RETRIES = 3

# HTTP status codes that are worth retrying.
RETRY_CODES = frozenset((429, 500, 502, 503, 504))

# The largest response body (in bytes) the client accepts. The biggest public endpoint
# (/api/get/yara/tlp_white/zip) is ~4MB today, this leaves plenty of room to grow.
MAX_BODY = 256 * 1024 * 1024


class MalpediaApiError(Exception):
    """Malpedia returned an error, or could not be reached."""

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


class MalpediaClient:
    """The transport used to talk to Malpedia's REST API.

    Parameters
    ----------
    session : aiohttp.ClientSession
        The session to send requests with. The caller owns its lifecycle.
    url : str, optional
        The API's base URL (useful for proxies, mirrors, and tests).
    interval : float, optional
        The minimum number of seconds between two requests.
    timeout : float, optional
        Total timeout, in seconds, for a single request. The bulk endpoints are several MB
        and can take Malpedia a while to generate.
    backoff : float, optional
        The base, in seconds, of the exponential backoff between retries.
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        url: str = BASE_URL,
        interval: float = 2.0,
        timeout: float = 300.0,
        backoff: float = 5.0,
    ):
        self.session = session
        self.url = (url or BASE_URL).rstrip("/")
        self.throttle = Throttle(interval)
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.backoff = max(float(backoff or 0), 0.0)
        # The number of requests sent, so callers can report their cost.
        self.count = 0

    async def _send(self, path: str) -> tuple[int, bytes, str]:
        """GET a path and return (status, body, content type), retrying transient failures."""

        url = self.url + path
        headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "gzip, deflate"}

        for attempt in range(MAX_RETRIES + 1):
            await self.throttle.wait()
            self.count += 1
            try:
                async with self.session.get(url, headers=headers, timeout=self.timeout) as resp:
                    size = resp.content_length
                    if size is not None and size > MAX_BODY:
                        raise MalpediaApiError(
                            f"The response from {path} is too large ({size} bytes).",
                            code=resp.status,
                        )
                    # read(n) returns whatever is buffered (up to n), so read until EOF.
                    chunks = []
                    total = 0
                    async for chunk in resp.content.iter_chunked(1024 * 1024):
                        total += len(chunk)
                        if total > MAX_BODY:
                            raise MalpediaApiError(
                                f"The response from {path} is too large (over {MAX_BODY} bytes).",
                                code=resp.status,
                            )
                        chunks.append(chunk)
                    body = b"".join(chunks)
                    code = resp.status
                    ctype = resp.content_type or ""
            except (aiohttp.ClientError, TimeoutError) as err:
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(self.backoff * 2**attempt)
                    continue
                raise MalpediaApiError(f"Unable to connect to Malpedia ({path}): {err}") from err

            if code in RETRY_CODES and attempt < MAX_RETRIES:
                await asyncio.sleep(self.backoff * 2**attempt)
                continue

            if code >= 400:
                raise MalpediaApiError(errMesg(path, code, body), code=code)

            return code, body, ctype

        # The loop always returns or raises, this keeps type checkers happy.
        raise MalpediaApiError(f"Unable to request {path} from Malpedia.")  # pragma: no cover

    async def getJson(self, path: str) -> Any:
        """GET a path and return its parsed JSON body."""

        code, body, _ = await self._send(path)
        try:
            return json.loads(body.decode("utf-8")) if body else None
        except (UnicodeDecodeError, ValueError) as err:
            raise MalpediaApiError(
                f"Unable to parse the JSON response from {path}", code=code
            ) from err

    async def getText(self, path: str) -> str:
        """GET a path and return its body as text."""

        _, body, _ = await self._send(path)
        return body.decode("utf-8", errors="replace")

    async def getBytes(self, path: str) -> bytes:
        """GET a path and return its raw body."""

        _, body, _ = await self._send(path)
        return body

    # ---- Endpoints ----

    async def version(self) -> dict:
        """GET /api/get/version - the current Malpedia version, ``{"version": int, "date": str}``."""
        data = await self.getJson("/get/version")
        if not isinstance(data, Mapping) or "version" not in data:
            raise MalpediaApiError(f"Unexpected response from /get/version: {data!r}"[:500])
        return dict(data)

    async def listActors(self) -> list[str]:
        """GET /api/list/actors - every actor ID."""
        return _reqList(await self.getJson("/list/actors"), "/list/actors")

    async def listFamilies(self) -> list[str]:
        """GET /api/list/families - every family ID."""
        return _reqList(await self.getJson("/list/families"), "/list/families")

    async def getActors(self) -> dict:
        """GET /api/get/actors - every actor, keyed by its display name (not its ID)."""
        return _reqDict(await self.getJson("/get/actors"), "/get/actors")

    async def getFamilies(self) -> dict:
        """GET /api/get/families - every family, keyed by its ID."""
        return _reqDict(await self.getJson("/get/families"), "/get/families")

    async def getActor(self, actor: str) -> dict:
        """GET /api/get/actor/<actor_id> - an actor, including its families."""
        return _reqDict(await self.getJson(f"/get/actor/{seg(actor)}"), "/get/actor")

    async def getFamily(self, family: str) -> dict:
        """GET /api/get/family/<family_id>"""
        return _reqDict(await self.getJson(f"/get/family/{seg(family)}"), "/get/family")

    async def getReferences(self) -> dict:
        """GET /api/get/references - every library URL and the actors/families it's tagged with."""
        data = _reqDict(await self.getJson("/get/references"), "/get/references")
        refs = data.get("references")
        if not isinstance(refs, Mapping):
            raise MalpediaApiError("Unexpected response from /get/references: no references.")
        return data

    async def getBib(self) -> str:
        """GET /api/get/bib - the whole library as BibTeX."""
        return await self.getText("/get/bib")

    async def getBibActor(self, actor: str) -> str:
        """GET /api/get/bib/actor/<actor_id> - an actor's library entries as BibTeX."""
        return await self.getText(f"/get/bib/actor/{seg(actor)}")

    async def getBibFamily(self, family: str) -> str:
        """GET /api/get/bib/family/<family_id> - a family's library entries as BibTeX."""
        return await self.getText(f"/get/bib/family/{seg(family)}")

    async def findActor(self, needle: str) -> list:
        """GET /api/find/actor/<needle> - actors with a name or synonym containing needle."""
        return _reqList(await self.getJson(f"/find/actor/{seg(needle)}"), "/find/actor")

    async def findFamily(self, needle: str) -> list:
        """GET /api/find/family/<needle> - families with a name or alt name containing needle."""
        return _reqList(await self.getJson(f"/find/family/{seg(needle)}"), "/find/family")

    async def listYara(self) -> dict:
        """GET /api/list/yara - ``{family: [{"path": ..., "tlp": ...}]}`` for every rule."""
        return _reqDict(await self.getJson("/list/yara"), "/list/yara")

    async def getYaraFamily(self, family: str) -> dict:
        """GET /api/get/yara/<family_id> - ``{tlp: {filename: text}}`` for a family."""
        return _reqDict(await self.getJson(f"/get/yara/{seg(family)}"), "/get/yara")

    async def getYaraAfter(self, date: str) -> dict:
        """GET /api/get/yara/after/<yyyy-mm-dd> - ``{tlp: {filename: text}}`` updated after date."""
        return _reqDict(await self.getJson(f"/get/yara/after/{seg(date)}"), "/get/yara/after")

    async def getYaraTlp(self, tlp: str) -> dict:
        """GET /api/get/yara/<tlp>/zip - every rule with a TLP, as ``{filename: text}``."""

        if tlp not in YARA_TLPS:
            raise MalpediaApiError(f"Unknown YARA TLP {tlp!r}, use one of {', '.join(YARA_TLPS)}.")
        body = await self.getBytes(f"/get/yara/{seg(tlp)}/zip")
        return unzipRules(body)


def unzipRules(body: bytes) -> dict[str, str]:
    """Read the ``.yar`` files out of a Malpedia YARA zip, as ``{filename: text}``."""

    if not body:
        return {}
    try:
        zfile = zipfile.ZipFile(io.BytesIO(body))
    except zipfile.BadZipFile as err:
        raise MalpediaApiError(f"Malpedia returned an invalid YARA zip: {err}") from err

    rules = {}
    with zfile:
        for info in zfile.infolist():
            if info.is_dir():
                continue
            name = info.filename.rsplit("/", 1)[-1]
            if not name.endswith(".yar"):
                continue
            try:
                rules[name] = zfile.read(info).decode("utf-8", errors="replace")
            except (zipfile.BadZipFile, OSError, RuntimeError) as err:
                raise MalpediaApiError(f"Unable to read {name} from the YARA zip: {err}") from err
    return rules


def errMesg(path: str, code: int, body: bytes) -> str:
    """Build an error message from a Malpedia error response."""

    text = body.decode("utf-8", errors="replace") if body else ""
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if isinstance(data, Mapping):
        for key in ("detail", "error", "message"):
            if data.get(key):
                return f"Malpedia returned HTTP {code} for {path}: {data[key]}"
    if code == 404:
        return f"Malpedia returned HTTP 404 for {path}: not found."
    if text and not text.lstrip().startswith("<"):
        return f"Malpedia returned HTTP {code} for {path}: {text.strip()[:300]}"
    return f"Malpedia returned HTTP {code} for {path}."


def _reqDict(data: Any, path: str) -> dict:
    if not isinstance(data, Mapping):
        raise MalpediaApiError(f"Unexpected response from {path}: expected an object.")
    return dict(data)


def _reqList(data: Any, path: str) -> list:
    if not isinstance(data, list):
        raise MalpediaApiError(f"Unexpected response from {path}: expected a list.")
    return data
