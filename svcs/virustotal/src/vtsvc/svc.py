"""The slib.vt service.

Every VirusTotal API v3 endpoint the Public (community) API offers has a method on ``VtSvc``.
The ``get*``/``rel*`` style methods return VirusTotal's JSON as-is, the ``norm*`` variants
normalize it for modeling (see ``vtsvc.norm``). Methods raise ``VtApiError`` or ``VtQuotaError``
on failure, and ``VtCellApi`` wraps them in the standard ``TelepathRetn`` convention for Storm.

Every request is rate limited per API key (see ``vtsvc.quota``) to the Public API's limits,
unless ``vt:community`` is false.
"""

import asyncio
import logging
from typing import Any
from urllib.parse import quote

import aiohttp
import synapse.lib.cell as s_cell

from . import norm
from .api import VtCellApi
from .client import BASE_URL, NotFoundError, TtlCache, VtApiError, VtClient
from .quota import DAY_LIMIT, MINUTE_LIMIT, MONTH_LIMIT, QuotaLimiter

logger = logging.getLogger(__name__)

# The collections of each object type that can be looked up.
COLLECTIONS = {
    "file": "files",
    "url": "urls",
    "domain": "domains",
    "ip_address": "ip_addresses",
}

# The relationships of each collection that a Public API key can read. Others (ex. a file's
# execution_parents) need a premium key. With vt:community false, every relationship is allowed.
PUBLIC_RELS = {
    "files": (
        "comments", "votes", "graphs", "collections", "behaviours", "bundled_files",
        "contacted_domains", "contacted_ips", "contacted_urls", "dropped_files",
        "execution_parents", "pe_resource_children", "pe_resource_parents",
    ),
    "urls": (
        "comments", "votes", "graphs", "collections", "related_comments",
        "last_serving_ip_address", "network_location",
    ),
    "domains": (
        "comments", "votes", "graphs", "collections", "related_comments", "resolutions",
        "subdomains", "siblings", "parent", "immediate_parent", "communicating_files",
        "referrer_files", "historical_whois", "historical_ssl_certificates",
    ),
    "ip_addresses": (
        "comments", "votes", "graphs", "collections", "related_comments", "resolutions",
        "communicating_files", "referrer_files", "historical_whois",
        "historical_ssl_certificates",
    ),
}  # fmt: skip

# The most objects a relationship (or search) page can have.
MAX_PAGE = 40

# Uploads bigger than this need a one time upload URL (GET /files/upload_url).
DIRECT_UPLOAD_MAX = 32 * 1024 * 1024

# The biggest file VirusTotal accepts.
UPLOAD_MAX = 650 * 1024 * 1024

# The votes VirusTotal accepts.
VERDICTS = ("harmless", "malicious")


class VtSvcError(VtApiError):
    """A service level error, ex. bad arguments."""


def _seg(valu: Any) -> str:
    """Quote a value for use as a single URL path segment."""

    return quote(str(valu), safe="")


class VtSvc(s_cell.Cell):
    """The Cell implementation for the slib.vt service."""

    cellapi = VtCellApi

    confdefs = {
        "vt:apikey": {
            "type": ["string", "null"],
            "default": None,
            "description": (
                "A VirusTotal API key used when neither the calling user (slib.vt.apikey) nor "
                "the service's stored key (slib.vt.admin.apikey) provides one."
            ),
        },
        "vt:community": {
            "type": "boolean",
            "default": True,
            "description": (
                "The API keys are free VirusTotal Community (Public API) keys: enforce the "
                "Public API's limits (vt:limit:minute, vt:limit:day, vt:limit:month) per key, "
                "and only allow the relationships a Public API key can read. Set it to false "
                "for premium keys."
            ),
        },
        "vt:limit:minute": {
            "type": "integer",
            "default": MINUTE_LIMIT,
            "minimum": 0,
            "description": "Max requests per minute, per API key, when vt:community is true.",
        },
        "vt:limit:day": {
            "type": "integer",
            "default": DAY_LIMIT,
            "minimum": 0,
            "description": (
                "Max requests per UTC day, per API key, when vt:community is true. 0 for no limit."
            ),
        },
        "vt:limit:month": {
            "type": "integer",
            "default": MONTH_LIMIT,
            "minimum": 0,
            "description": (
                "Max requests per UTC month, per API key, when vt:community is true. "
                "0 for no limit."
            ),
        },
        "vt:limit:maxwait": {
            "type": "number",
            "default": 600,
            "minimum": 0,
            "description": (
                "The most seconds a request waits for room under vt:limit:minute before it "
                "fails. 0 waits as long as it takes."
            ),
        },
        "vt:cache:ttl": {
            "type": "number",
            "default": 3600,
            "minimum": 0,
            "description": (
                "Seconds that successful lookups are cached, so looking the same thing up "
                "again doesn't use quota. 0 disables the cache."
            ),
        },
        "vt:cache:size": {
            "type": "integer",
            "default": 1000,
            "minimum": 0,
            "description": "The most responses kept in the cache.",
        },
        "vt:verdict:malicious": {
            "type": "integer",
            "default": 3,
            "minimum": 1,
            "description": (
                "The number of engines that must detect something for its overall verdict to "
                "be malicious (fewer detections are suspicious)."
            ),
        },
        "vt:timeout": {
            "type": "number",
            "default": 120,
            "minimum": 1,
            "description": "Timeout, in seconds, for a single VirusTotal request.",
        },
        "vt:url": {
            "type": "string",
            "default": BASE_URL,
            "description": "The base URL of the VirusTotal API v3.",
        },
    }

    async def __anit__(self, dirn, *args, **kwargs):
        await s_cell.Cell.__anit__(self, dirn, *args, **kwargs)

        self.vtinfo = self.slab.getSafeKeyVal("slib:vt")
        self.community = self.conf.get("vt:community")
        self.malicious = self.conf.get("vt:verdict:malicious")

        self.limiter = QuotaLimiter(
            self.slab.getSafeKeyVal("slib:vt:quota"),
            enforce=self.community,
            minute=self.conf.get("vt:limit:minute"),
            day=self.conf.get("vt:limit:day"),
            month=self.conf.get("vt:limit:month"),
            maxwait=self.conf.get("vt:limit:maxwait"),
        )

        self.session = aiohttp.ClientSession(trust_env=True)
        self.onfini(self.session.close)

        self.client = VtClient(
            self.session,
            self.limiter,
            url=self.conf.get("vt:url"),
            timeout=self.conf.get("vt:timeout"),
            cache=TtlCache(self.conf.get("vt:cache:ttl"), self.conf.get("vt:cache:size")),
        )

    # ---- API key management ----

    def getApiKey(self, apikey: str | None = None) -> str | None:
        """Resolve the API key to use: the caller's, then the stored key, then the config."""

        return apikey or self.vtinfo.get("apikey") or self.conf.get("vt:apikey")

    async def setApiKey(self, apikey: str | None) -> bool:
        """Set (or clear, with None/empty) the service-wide VirusTotal API key."""

        if apikey:
            self.vtinfo.set("apikey", apikey)
        else:
            self.vtinfo.pop("apikey")
        return True

    async def hasApiKey(self) -> bool:
        return bool(self.getApiKey())

    async def _api(self, method: str, path: str, apikey=None, cache: bool = False, **kwargs):
        return await self.client.request(
            method, path, apikey=self.getApiKey(apikey), cache=cache, **kwargs
        )

    async def rawRequest(
        self,
        method: str,
        path: str,
        params=None,
        json_data=None,
        form=None,
        apikey=None,
    ):
        """Send an arbitrary request to the VirusTotal API. An escape hatch for new endpoints.

        It's still rate limited like every other request.
        """

        return await self._api(
            method, path, apikey=apikey, params=params, json_data=json_data, form=form
        )

    # ---- Quotas ----

    async def quota(self, remote: bool = False, apikey=None) -> dict:
        """The service's limits and the key's request counts.

        ``remote`` also asks VirusTotal for the key's quotas (``GET /users/{key}/overall_quotas``),
        which is one request.
        """

        key = self.getApiKey(apikey)
        if not key:
            raise VtSvcError("No VirusTotal API key is configured.")
        ret = self.limiter.status(key)
        ret["cached"] = len(self.client.cache)
        if remote:
            data = await self._api("get", f"/users/{_seg(key)}/overall_quotas", apikey=key)
            ret["remote"] = {
                name: (valu.get("user") or {})
                for name, valu in ((data or {}).get("data") or {}).items()
                if name.startswith("api_requests_")
            }
        return ret

    # ---- Objects ----

    def _coll(self, kind: str) -> str:
        coll = COLLECTIONS.get(kind) or (kind if kind in COLLECTIONS.values() else None)
        if coll is None:
            raise VtSvcError(f"Unknown VirusTotal object type: {kind}")
        return coll

    def _ident(self, kind: str, ident: str) -> str:
        """The path segment that identifies an object (URLs are identified by their base64)."""

        if not ident:
            raise VtSvcError(f"No {kind} was given.")
        if self._coll(kind) == "urls" and "://" in ident:
            return norm.urlId(ident)
        return ident

    async def getObject(self, kind: str, ident: str, cache: bool = True, apikey=None) -> dict:
        """GET /{collection}/{id} - a file (hash), URL, domain, or IP address report."""

        coll = self._coll(kind)
        path = f"/{coll}/{_seg(self._ident(kind, ident))}"
        return await self._api("get", path, apikey=apikey, cache=cache)

    async def lookup(self, kind: str, ident: str, cache: bool = True, apikey=None) -> dict | None:
        """A normalized report for an object, or None if VirusTotal doesn't have it."""

        try:
            data = await self.getObject(kind, ident, cache=cache, apikey=apikey)
        except NotFoundError:
            return None
        return norm.normObject((data or {}).get("data") or {}, malicious=self.malicious)

    def rels(self, coll: str) -> tuple:
        """The relationships of a collection the service allows."""

        return PUBLIC_RELS.get(self._coll(coll), ())

    async def getRelated(
        self,
        kind: str,
        ident: str,
        rel: str,
        limit: int = 10,
        cursor: str | None = None,
        cache: bool = True,
        apikey=None,
    ) -> dict:
        """GET /{collection}/{id}/{relationship} - one page of related objects."""

        coll = self._coll(kind)
        if self.community and rel not in self.rels(coll):
            raise VtSvcError(
                f"The {rel} relationship of {coll} isn't available to VirusTotal Public API "
                f"keys. Available: {', '.join(self.rels(coll))}."
            )
        limit = max(1, min(int(limit), MAX_PAGE))
        path = f"/{coll}/{_seg(self._ident(kind, ident))}/{_seg(rel)}"
        return await self._api(
            "get", path, apikey=apikey, cache=cache, params={"limit": limit, "cursor": cursor}
        )

    async def related(
        self,
        kind: str,
        ident: str,
        rel: str,
        limit: int = 10,
        cache: bool = True,
        apikey=None,
    ) -> dict:
        """Up to ``limit`` normalized related objects, paging as needed.

        Returns ``{"items": [...], "count": <total VirusTotal has>, "requests": <n>}``. Each page
        is one request (40 objects at most).
        """

        items = []
        cursor = None
        count = None
        requests = 0
        while len(items) < limit:
            try:
                data = await self.getRelated(
                    kind,
                    ident,
                    rel,
                    limit=min(limit - len(items), MAX_PAGE),
                    cursor=cursor,
                    cache=cache,
                    apikey=apikey,
                )
            except NotFoundError:
                break
            requests += 1
            data = data or {}
            page = data.get("data") or []
            if isinstance(page, dict):
                # Singular relationships (ex. a domain's parent) return one object.
                page = [page]
            items.extend(norm.normObjects(page, malicious=self.malicious))
            meta = data.get("meta") or {}
            count = meta.get("count", count)
            cursor = meta.get("cursor")
            if not cursor or not page:
                break
        return {
            "items": items[:limit],
            "count": count,
            "requests": requests,
            "edge": norm.relEdge(self._coll(kind), rel),
        }

    async def comments(self, kind: str, ident: str, limit: int = 10, apikey=None) -> dict:
        """An object's comments, normalized. See ``related()``."""

        return await self.related(kind, ident, "comments", limit=limit, apikey=apikey)

    async def addComment(self, kind: str, ident: str, text: str, apikey=None) -> dict:
        """POST /{collection}/{id}/comments - add a comment (words starting with # are tags)."""

        if not text or not text.strip():
            raise VtSvcError("A comment needs some text.")
        coll = self._coll(kind)
        path = f"/{coll}/{_seg(self._ident(kind, ident))}/comments"
        body = {"data": {"type": "comment", "attributes": {"text": text}}}
        data = await self._api("post", path, apikey=apikey, json_data=body)
        return norm.normComment((data or {}).get("data") or {}) or {}

    async def addVote(self, kind: str, ident: str, verdict: str, apikey=None) -> dict:
        """POST /{collection}/{id}/votes - vote an object harmless or malicious."""

        if verdict not in VERDICTS:
            raise VtSvcError(f"A vote's verdict must be one of: {', '.join(VERDICTS)}.")
        coll = self._coll(kind)
        path = f"/{coll}/{_seg(self._ident(kind, ident))}/votes"
        body = {"data": {"type": "vote", "attributes": {"verdict": verdict}}}
        data = await self._api("post", path, apikey=apikey, json_data=body)
        return (data or {}).get("data") or {}

    # ---- Submissions and analyses ----

    async def rescan(self, kind: str, ident: str, apikey=None) -> dict:
        """POST /{collection}/{id}/analyse - ask VirusTotal to analyze an object again.

        Returns the analysis's ``{"type": "analysis", "id": ...}`` descriptor.
        """

        coll = self._coll(kind)
        path = f"/{coll}/{_seg(self._ident(kind, ident))}/analyse"
        data = await self._api("post", path, apikey=apikey)
        return (data or {}).get("data") or {}

    async def submitUrl(self, url: str, apikey=None) -> dict:
        """POST /urls - submit a URL for analysis. Returns the analysis descriptor."""

        if not url:
            raise VtSvcError("No URL was given.")
        data = await self._api("post", "/urls", apikey=apikey, form={"url": url})
        return (data or {}).get("data") or {}

    async def submitFile(
        self, chunks: list[bytes], name: str | None = None, password: str | None = None, apikey=None
    ) -> dict:
        """POST /files - upload a file (as a list of chunks, as read from an Axon).

        Files over 32MB are uploaded to a one time upload URL (an extra request). Returns the
        analysis descriptor.
        """

        byts = b"".join(chunks)
        if not byts:
            raise VtSvcError("The file is empty.")
        if len(byts) > UPLOAD_MAX:
            raise VtSvcError(
                f"The file is {len(byts)} bytes, larger than VirusTotal's max of {UPLOAD_MAX}."
            )

        path = "/files"
        if len(byts) > DIRECT_UPLOAD_MAX:
            data = await self._api("get", "/files/upload_url", apikey=apikey)
            path = (data or {}).get("data")
            if not path:
                raise VtSvcError("VirusTotal didn't return an upload URL.")

        form = aiohttp.FormData()
        form.add_field("file", byts, filename=name or "sample")
        if password:
            form.add_field("password", password)
        data = await self._api("post", path, apikey=apikey, data=form)
        return (data or {}).get("data") or {}

    async def analysis(self, ident: str, apikey=None) -> dict:
        """GET /analyses/{id} - an analysis's status and results, normalized."""

        data = await self._api("get", f"/analyses/{_seg(ident)}", apikey=apikey) or {}
        return norm.normAnalysis(
            data.get("data") or {}, meta=data.get("meta"), malicious=self.malicious
        )

    async def waitAnalysis(
        self, ident: str, timeout: float = 600, interval: float = 60, apikey=None
    ) -> dict:
        """Poll an analysis until it completes or ``timeout`` seconds pass.

        Every poll is a request, so with a Public API key the interval is at least 15 seconds.
        Returns the last normalized analysis, check ``done``.
        """

        interval = max(interval, 15.0 if self.community else 1.0)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            info = await self.analysis(ident, apikey=apikey)
            if info.get("done") or loop.time() + interval > deadline:
                return info
            await asyncio.sleep(interval)

    # ---- Files ----

    async def behaviour(self, sha256: str, apikey=None) -> dict | None:
        """GET /files/{id}/behaviour_summary - what the sandboxes saw a file do, normalized.

        Returns None if VirusTotal has no behaviour reports for the file.
        """

        try:
            data = await self._api(
                "get", f"/files/{_seg(sha256)}/behaviour_summary", apikey=apikey, cache=True
            )
        except NotFoundError:
            return None
        summary = (data or {}).get("data")
        if not summary:
            return None
        return norm.normBehaviour(summary)

    # ---- Search and reference data ----

    async def search(self, query: str, limit: int = 10, apikey=None) -> dict:
        """GET /search - look up a hash, URL, domain, IP, or comment text.

        This is the basic search (not VT Intelligence search), it returns the matching
        objects. Returns ``{"items": [...], "count": n}``.
        """

        limit = max(1, min(int(limit), MAX_PAGE))
        data = await self._api(
            "get", "/search", apikey=apikey, cache=True, params={"query": query, "limit": limit}
        )
        data = data or {}
        items = norm.normObjects(data.get("data") or [], malicious=self.malicious)
        return {"items": items, "count": (data.get("meta") or {}).get("count", len(items))}

    async def threatCategories(self, apikey=None) -> list:
        """GET /popular_threat_categories"""

        data = await self._api("get", "/popular_threat_categories", apikey=apikey, cache=True)
        return (data or {}).get("data") or []

    async def attackTechnique(self, tid: str, apikey=None) -> dict:
        """GET /attack_techniques/{id}"""

        data = await self._api("get", f"/attack_techniques/{_seg(tid)}", apikey=apikey, cache=True)
        return (data or {}).get("data") or {}
