"""The slib.shodan service.

Every Shodan API endpoint has a method on ``ShodanSvc``. These methods return
Shodan's data as-is (or normalized, for the ``norm*`` variants) and raise
``ShodanApiError`` on failure. ``ShodanCellApi`` wraps them in the standard
``TelepathRetn`` convention for Storm.
"""

import hashlib
import json
import re
import time
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import quote, urlencode

import aiohttp
import synapse.lib.cell as s_cell

from . import norm
from .api import ShodanCellApi
from .client import BASE_URLS, ShodanApiError, ShodanClient

# Streaming API endpoints and whether they take a comma separated list of values.
STREAM_KINDS = {
    "banners": False,
    "asn": True,
    "countries": True,
    "ports": True,
    "tags": True,
    "vulns": True,
    "custom": False,
    "alert": False,
}

# The default number of results Shodan returns per search page.
SEARCH_PAGE_SIZE = 100

# Saved queries per page of Shodan's query directory.
DIRECTORY_PAGE_SIZE = 10

# The ip facet size countIps() asks for before it knows the plan's limit: the most facet values
# Shodan has published it returns (https://book.shodan.io/changelog/2025-11-06/). A plan with a
# lower limit gets FACET_LIMIT_RE's error, and the request is retried with that limit.
COUNT_IP_SIZE = 131072

# How long a key's learned facet limit is trusted, in seconds, so a plan change is picked up.
FACET_LIMIT_TTL = 86400

# Shodan's error for a facet size over the plan's limit, ex.
# "Facet size too big for current subscription (limit: 1000)".
FACET_LIMIT_RE = re.compile(r"Facet size too big.*\(limit: (\d+)\)")


def _streamPath(
    kind: str, values=None, query: str | None = None, aid: str | None = None
) -> tuple[str, dict]:
    """Build the path and params of a Streaming API endpoint (without the API key)."""

    if kind not in STREAM_KINDS:
        raise ShodanApiError(
            f"Unknown stream type {kind}, expected one of: {', '.join(STREAM_KINDS)}"
        )

    params = {}
    path = f"/shodan/{kind}"
    if STREAM_KINDS[kind]:
        if not values:
            raise ShodanApiError(f"The {kind} stream requires at least one value.")
        if isinstance(values, (list, tuple)):
            values = ",".join(str(v) for v in values)
        path = f"{path}/{quote(str(values), safe=',')}"
    elif kind == "custom":
        if not query:
            raise ShodanApiError("The custom stream requires a query.")
        params["query"] = query
    elif kind == "alert" and aid:
        path = f"{path}/{_seg(aid)}"

    return path, params


def _seg(valu: Any) -> str:
    """Quote a value for use as a single URL path segment."""

    return quote(str(valu), safe="")


def _directoryText(q: dict) -> str:
    """The lower-cased text a directory query is matched on: title, query, description, tags."""

    tags = q.get("tags") or []
    vals = [q.get("title"), q.get("query"), q.get("description"), *tags]
    return "\n".join(str(v) for v in vals if v).lower()


class ShodanSvc(s_cell.Cell):
    """The Cell implementation for the slib.shodan service."""

    cellapi = ShodanCellApi

    confdefs = {
        "shodan:apikey": {
            "type": ["string", "null"],
            "default": None,
            "description": (
                "A Shodan API key used when neither the calling user nor the service's "
                "stored key (set with slib.shodan.admin.apikey) provides one."
            ),
        },
        "shodan:ratelimit": {
            "type": "number",
            "default": 1.0,
            "description": "Max requests/second sent to Shodan's API key based APIs.",
        },
        "shodan:timeout": {
            "type": "number",
            "default": 60,
            "description": "Timeout, in seconds, for a single Shodan API request.",
        },
        "shodan:urls": {
            "type": "object",
            "default": {},
            "description": (
                "Overrides for Shodan API base URLs, keyed by api, stream, trends, "
                "internetdb, or cvedb."
            ),
        },
    }

    async def __anit__(self, dirn, *args, **kwargs):
        await s_cell.Cell.__anit__(self, dirn, *args, **kwargs)

        self.shodaninfo = self.slab.getSafeKeyVal("slib:shodan")

        self.session = aiohttp.ClientSession(trust_env=True)
        self.onfini(self.session.close)

        # The facet size limit of each API key's plan, and when it was learned, keyed by the
        # SHA-256 of the key. Only ever kept in memory, and never holds a key itself. See countIps().
        self.facetlimits: dict[str, tuple[int, float]] = {}

        self.client = ShodanClient(
            self.session,
            urls=self.conf.get("shodan:urls"),
            rate=self.conf.get("shodan:ratelimit"),
            timeout=self.conf.get("shodan:timeout"),
        )

    # ---- API key management ----

    def getApiKey(self, apikey: str | None = None) -> str | None:
        """Resolve the API key to use: the caller's, then the stored key, then the config."""

        return apikey or self.shodaninfo.get("apikey") or self.conf.get("shodan:apikey")

    async def setApiKey(self, apikey: str | None) -> bool:
        """Set (or clear, with None/empty) the service-wide Shodan API key."""

        if apikey:
            self.shodaninfo.set("apikey", apikey)
        else:
            self.shodaninfo.pop("apikey")
        return True

    async def hasApiKey(self) -> bool:
        return bool(self.getApiKey())

    async def _api(
        self,
        method: str,
        path: str,
        apikey=None,
        base="api",
        params=None,
        json_data=None,
        form=None,
    ):
        return await self.client.request(
            method,
            path,
            base=base,
            apikey=self.getApiKey(apikey),
            params=params,
            json_data=json_data,
            form=form,
        )

    async def rawRequest(
        self,
        method: str,
        path: str,
        base: str = "api",
        params=None,
        json_data=None,
        apikey=None,
        form=None,
    ):
        """Send an arbitrary request to a Shodan API. An escape hatch for new endpoints."""

        if not path.startswith("/"):
            path = "/" + path
        return await self._api(
            method, path, apikey=apikey, base=base, params=params, json_data=json_data, form=form
        )

    # ---- Search methods ----

    async def host(self, ip: str, history: bool = False, minify: bool = False, apikey=None) -> dict:
        """GET /shodan/host/{ip}"""
        return await self._api(
            "get", f"/shodan/host/{_seg(ip)}", apikey, params={"history": history, "minify": minify}
        )

    async def normHost(
        self, ip: str, history: bool = False, minify: bool = False, apikey=None
    ) -> dict:
        """Like ``host()`` but normalized for modeling."""
        return norm.normHost(await self.host(ip, history=history, minify=minify, apikey=apikey))

    async def count(self, query: str, facets=None, apikey=None) -> dict:
        """GET /shodan/host/count"""
        return await self._api(
            "get", "/shodan/host/count", apikey, params={"query": query, "facets": facets}
        )

    async def countIps(self, query: str, size: int | None = None, facets=None, apikey=None) -> dict:
        """List the IPs matching a query with the free count API's ``ip`` facet (no query credits).

        ``size`` is the number of IPs to ask for, defaulting to the most the key's plan allows. The
        plan's limit is learned from Shodan's error when a key asks for too many, then cached in
        memory for ``FACET_LIMIT_TTL`` seconds, so later calls with that key need a single request.
        A ``size`` over the cached limit is still asked for, in case the plan changed.

        ``facets`` are extra facets (a comma separated str or a list) returned for printing only.

        Returns ``{"ips": [str, ...], "size": int, "limit": int | None, "full": bool,
        "lowered": bool, "facets": {...}}``. ``limit`` is the plan's limit, if known. ``full`` is
        true when the IPs fill the size asked for, so the query likely matches more IPs than were
        returned. ``lowered`` is true when ``size`` was over the plan's limit and was lowered to
        it. The ``ip`` facet's counts are dropped.
        """

        if size is not None and size < 1:
            raise ShodanApiError(f"The number of IPs to count must be at least 1, not {size}.")

        key = self.getApiKey(apikey)
        keyhash = hashlib.sha256(key.encode()).hexdigest() if key else None
        limit = None
        cached = self.facetlimits.get(keyhash)
        if cached is not None and time.monotonic() - cached[1] < FACET_LIMIT_TTL:
            limit = cached[0]

        asked = size or limit or COUNT_IP_SIZE
        lowered = False

        if isinstance(facets, str):
            facets = facets.split(",")
        # Any ip facet given is replaced by the sized one.
        extra = [f.strip() for f in facets or () if f.strip() and f.strip().split(":")[0] != "ip"]

        def facetstr(n: int) -> str:
            return ",".join([f"ip:{n}", *extra])

        try:
            data = await self.count(query, facets=facetstr(asked), apikey=apikey)
        except ShodanApiError as err:
            match = FACET_LIMIT_RE.search(err.mesg)
            # A limit at or over the size asked for means another facet was too big.
            if match is None or int(match.group(1)) >= asked:
                raise
            limit = int(match.group(1))
            self.facetlimits[keyhash] = (limit, time.monotonic())
            lowered = size is not None
            asked = limit
            data = await self.count(query, facets=facetstr(asked), apikey=apikey)
        else:
            # A size over the cached limit worked, so the plan changed: forget the old limit.
            if limit is not None and asked > limit:
                self.facetlimits.pop(keyhash, None)
                limit = None

        facetdata = dict((data or {}).get("facets") or {})
        ips = [
            str(v["value"]) for v in facetdata.pop("ip", None) or () if v.get("value") is not None
        ]

        return {
            "ips": ips,
            "size": asked,
            "limit": limit,
            "full": len(ips) >= asked,
            "lowered": lowered,
            "facets": facetdata,
        }

    async def search(
        self, query: str, page: int = 1, facets=None, minify: bool = True, fields=None, apikey=None
    ) -> dict:
        """GET /shodan/host/search - a single page of results."""
        return await self._api(
            "get",
            "/shodan/host/search",
            apikey,
            params={
                "query": query,
                "page": page,
                "facets": facets,
                "minify": minify,
                "fields": fields,
            },
        )

    async def searchGenr(
        self, query: str, limit: int = 100, minify: bool = True, page: int = 1, apikey=None
    ) -> AsyncIterator[dict]:
        """Page through /shodan/host/search, yielding normalized banners.

        Each page of 100 results uses one Shodan query credit. ``limit=0`` pages
        until results run out.
        """

        count = 0
        while True:
            data = await self.search(query, page=page, minify=minify, apikey=apikey)
            matches = data.get("matches") or []
            if not matches:
                return

            for match in matches:
                yield norm.normBanner(match)
                count += 1
                if limit and count >= limit:
                    return

            if page * SEARCH_PAGE_SIZE >= (data.get("total") or 0):
                return
            page += 1

    async def searchFacets(self, apikey=None) -> list:
        """GET /shodan/host/search/facets"""
        return await self._api("get", "/shodan/host/search/facets", apikey)

    async def searchFilters(self, apikey=None) -> list:
        """GET /shodan/host/search/filters"""
        return await self._api("get", "/shodan/host/search/filters", apikey)

    async def searchTokens(self, query: str, apikey=None) -> dict:
        """GET /shodan/host/search/tokens"""
        return await self._api("get", "/shodan/host/search/tokens", apikey, params={"query": query})

    # ---- On-demand scanning ----

    async def ports(self, apikey=None) -> list:
        """GET /shodan/ports"""
        return await self._api("get", "/shodan/ports", apikey)

    async def protocols(self, apikey=None) -> dict:
        """GET /shodan/protocols"""
        return await self._api("get", "/shodan/protocols", apikey)

    async def services(self, apikey=None) -> dict:
        """GET /shodan/services"""
        return await self._api("get", "/shodan/services", apikey)

    async def scan(self, ips, force: bool = False, apikey=None) -> dict:
        """POST /shodan/scan

        ``ips`` is a list of IPs/CIDRs, or a dict of ``{ip: [[port, protocol], ...]}``.
        Shodan only reads the arguments from a form body, it ignores query params.
        """
        if isinstance(ips, dict):
            ips = json.dumps(ips)
        return await self._api("post", "/shodan/scan", apikey, form={"ips": ips, "force": force})

    async def scanInternet(self, port: int, protocol: str, apikey=None) -> dict:
        """POST /shodan/scan/internet (form body, like POST /shodan/scan)"""
        return await self._api(
            "post", "/shodan/scan/internet", apikey, form={"port": port, "protocol": protocol}
        )

    async def scans(self, page: int = 1, apikey=None) -> dict:
        """GET /shodan/scans

        Shodan includes the ``api_key`` that submitted each scan, which is removed so a key (ex. the
        service-wide one) is never readable from Storm.
        """
        data = await self._api("get", "/shodan/scans", apikey, params={"page": page})
        for scan in (data or {}).get("matches") or ():
            if isinstance(scan, dict):
                scan.pop("api_key", None)
        if isinstance(data, dict):
            data.pop("api_key", None)
        return data

    async def scanStatus(self, scanid: str, apikey=None) -> dict:
        """GET /shodan/scan/{id} (without any ``api_key``, see scans())"""
        data = await self._api("get", f"/shodan/scan/{_seg(scanid)}", apikey)
        if isinstance(data, dict):
            data.pop("api_key", None)
        return data

    async def apiUrl(self, path: str, base: str = "api") -> str:
        """The public URL of a Shodan API endpoint, without the API key.

        Recorded as the ``:api:url`` of an ``it:exec:query``. Like streamUrl(), it always uses
        Shodan's public base URL, even when ``shodan:urls`` overrides it.
        """
        if base not in BASE_URLS:
            raise ShodanApiError(f"Unknown Shodan API: {base}")
        return BASE_URLS[base] + path

    # ---- Network alerts ----

    async def alertCreate(self, name: str, ips: list, expires: int = 0, apikey=None) -> dict:
        """POST /shodan/alert"""
        body = {"name": name, "filters": {"ip": list(ips)}, "expires": expires}
        return await self._api("post", "/shodan/alert", apikey, json_data=body)

    async def alertEdit(self, aid: str, ips: list, apikey=None) -> dict:
        """POST /shodan/alert/{id}"""
        body = {"filters": {"ip": list(ips)}}
        return await self._api("post", f"/shodan/alert/{_seg(aid)}", apikey, json_data=body)

    async def alertInfo(self, aid: str | None = None, include_expired: bool = True, apikey=None):
        """GET /shodan/alert/{id}/info or GET /shodan/alert/info"""
        path = f"/shodan/alert/{_seg(aid)}/info" if aid else "/shodan/alert/info"
        return await self._api("get", path, apikey, params={"include_expired": include_expired})

    async def alertDelete(self, aid: str, apikey=None) -> dict:
        """DELETE /shodan/alert/{id}"""
        return await self._api("delete", f"/shodan/alert/{_seg(aid)}", apikey)

    async def alertTriggers(self, apikey=None) -> list:
        """GET /shodan/alert/triggers"""
        return await self._api("get", "/shodan/alert/triggers", apikey)

    async def alertTriggerEnable(self, aid: str, trigger: str, apikey=None) -> dict:
        """PUT /shodan/alert/{id}/trigger/{trigger}"""
        return await self._api("put", f"/shodan/alert/{_seg(aid)}/trigger/{_seg(trigger)}", apikey)

    async def alertTriggerDisable(self, aid: str, trigger: str, apikey=None) -> dict:
        """DELETE /shodan/alert/{id}/trigger/{trigger}"""
        return await self._api(
            "delete", f"/shodan/alert/{_seg(aid)}/trigger/{_seg(trigger)}", apikey
        )

    async def alertTriggerIgnore(self, aid: str, trigger: str, service: str, apikey=None) -> dict:
        """PUT /shodan/alert/{id}/trigger/{trigger}/ignore/{ip:port}"""
        path = (
            f"/shodan/alert/{_seg(aid)}/trigger/{_seg(trigger)}/ignore/{quote(service, safe=':/,')}"
        )
        return await self._api("put", path, apikey)

    async def alertTriggerUnignore(self, aid: str, trigger: str, service: str, apikey=None) -> dict:
        """DELETE /shodan/alert/{id}/trigger/{trigger}/ignore/{ip:port}"""
        path = (
            f"/shodan/alert/{_seg(aid)}/trigger/{_seg(trigger)}/ignore/{quote(service, safe=':/,')}"
        )
        return await self._api("delete", path, apikey)

    async def alertNotifierAdd(self, aid: str, nid: str, apikey=None) -> dict:
        """PUT /shodan/alert/{id}/notifier/{notifier_id}"""
        return await self._api("put", f"/shodan/alert/{_seg(aid)}/notifier/{_seg(nid)}", apikey)

    async def alertNotifierDel(self, aid: str, nid: str, apikey=None) -> dict:
        """DELETE /shodan/alert/{id}/notifier/{notifier_id}"""
        return await self._api("delete", f"/shodan/alert/{_seg(aid)}/notifier/{_seg(nid)}", apikey)

    # ---- Notifiers ----

    async def notifiers(self, apikey=None) -> dict:
        """GET /notifier"""
        return await self._api("get", "/notifier", apikey)

    async def notifierProviders(self, apikey=None) -> dict:
        """GET /notifier/provider"""
        return await self._api("get", "/notifier/provider", apikey)

    async def notifierCreate(
        self, provider: str, args: dict, desc: str | None = None, apikey=None
    ) -> dict:
        """POST /notifier (form body, like POST /shodan/scan)"""
        form = dict(args or {})
        form["provider"] = provider
        form["description"] = desc
        return await self._api("post", "/notifier", apikey, form=form)

    async def notifierGet(self, nid: str, apikey=None) -> dict:
        """GET /notifier/{id}"""
        return await self._api("get", f"/notifier/{_seg(nid)}", apikey)

    async def notifierEdit(self, nid: str, args: dict, apikey=None) -> dict:
        """PUT /notifier/{id}"""
        return await self._api("put", f"/notifier/{_seg(nid)}", apikey, params=dict(args or {}))

    async def notifierDelete(self, nid: str, apikey=None) -> dict:
        """DELETE /notifier/{id}"""
        return await self._api("delete", f"/notifier/{_seg(nid)}", apikey)

    # ---- Directory ----

    async def queries(
        self,
        page: int = 1,
        sort: str = "timestamp",
        order: str = "desc",
        pages: int = 1,
        apikey=None,
    ) -> dict:
        """GET /shodan/query, for ``pages`` pages (10 queries each) starting at ``page``.

        Returns Shodan's ``total`` and the ``matches`` of every page fetched. Each page is
        one request, so a large ``pages`` is slow (the directory is ~700 pages).
        """

        return await self._directoryPages(
            "/shodan/query", {"sort": sort, "order": order}, page, pages, apikey
        )

    async def queriesSearch(self, query: str, page: int = 1, pages: int = 1, apikey=None) -> dict:
        """GET /shodan/query/search, or match directory pages here when it's unavailable.

        Shodan's directory search has returned 503 ("Query search unavailable at the moment")
        since at least 2026-11. On a 5xx, this lists ``pages`` pages of the directory (see
        ``queries``) and keeps the queries with ``query`` in their title, query, description,
        or tags (ignoring case). ``fallback`` is Shodan's error when that happens, else None.
        """

        try:
            data = await self._directoryPages(
                "/shodan/query/search", {"query": query}, page, pages, apikey
            )
            data["fallback"] = None
            return data
        except ShodanApiError as err:
            if err.code is None or err.code < 500:
                raise
            fallback = err.mesg

        data = await self.queries(page=page, pages=pages, apikey=apikey)
        needle = query.lower()
        matches = [q for q in data["matches"] if needle in _directoryText(q)]
        return {
            "total": len(matches),
            "matches": matches,
            "fallback": fallback,
            "scanned": len(data["matches"]),
            "directoryTotal": data["total"],
        }

    async def _directoryPages(
        self, path: str, params: dict, page: int, pages: int, apikey=None
    ) -> dict:
        """Fetch ``pages`` pages of a directory endpoint, stopping early when they run out."""

        total = None
        matches: list[dict] = []
        for num in range(page, page + max(pages, 1)):
            data = await self._api("get", path, apikey, params=dict(params, page=num)) or {}
            total = data.get("total")
            batch = data.get("matches") or []
            matches.extend(batch)
            if not batch or num * DIRECTORY_PAGE_SIZE >= (total or 0):
                break
        return {"total": total, "matches": matches}

    async def queriesTags(self, size: int = 10, apikey=None) -> dict:
        """GET /shodan/query/tags"""
        return await self._api("get", "/shodan/query/tags", apikey, params={"size": size})

    # ---- Bulk data ----

    async def datasets(self, apikey=None) -> list:
        """GET /shodan/data"""
        return await self._api("get", "/shodan/data", apikey)

    async def datasetFiles(self, dataset: str, apikey=None) -> list:
        """GET /shodan/data/{dataset}"""
        return await self._api("get", f"/shodan/data/{_seg(dataset)}", apikey)

    # ---- Organization ----

    async def org(self, apikey=None) -> dict:
        """GET /org"""
        return await self._api("get", "/org", apikey)

    async def orgMemberAdd(self, user: str, notify: bool = True, apikey=None) -> dict:
        """PUT /org/member/{user}"""
        return await self._api(
            "put", f"/org/member/{_seg(user)}", apikey, params={"notify": notify}
        )

    async def orgMemberDel(self, user: str, apikey=None) -> dict:
        """DELETE /org/member/{user}"""
        return await self._api("delete", f"/org/member/{_seg(user)}", apikey)

    # ---- Account, API status, and utility ----

    async def profile(self, apikey=None) -> dict:
        """GET /account/profile"""
        return await self._api("get", "/account/profile", apikey)

    async def apiInfo(self, apikey=None) -> dict:
        """GET /api-info"""
        return await self._api("get", "/api-info", apikey)

    async def myip(self, apikey=None) -> str:
        """GET /tools/myip"""
        return await self._api("get", "/tools/myip", apikey)

    async def httpHeaders(self, apikey=None) -> dict:
        """GET /tools/httpheaders"""
        return await self._api("get", "/tools/httpheaders", apikey)

    # ---- DNS ----

    async def dnsDomain(
        self,
        domain: str,
        history: bool = False,
        rtype: str | None = None,
        page: int = 1,
        apikey=None,
    ) -> dict:
        """GET /dns/domain/{domain} - a single page."""
        return await self._api(
            "get",
            f"/dns/domain/{_seg(domain)}",
            apikey,
            params={
                "history": history or None,
                "type": rtype,
                "page": page,
            },
        )

    async def dnsDomainAll(
        self,
        domain: str,
        history: bool = False,
        rtype: str | None = None,
        maxpages: int = 10,
        apikey=None,
    ) -> dict:
        """Page through /dns/domain/{domain}, merging all pages into one normalized result."""

        retn = {
            "domain": domain.lower(),
            "tags": [],
            "subdomains": [],
            "records": [],
            "more": False,
        }
        page = 1
        while True:
            data = await self.dnsDomain(
                domain, history=history, rtype=rtype, page=page, apikey=apikey
            )
            retn["tags"] = data.get("tags") or retn["tags"]
            retn["subdomains"].extend(data.get("subdomains") or [])
            retn["records"].extend(norm.normDnsRecords(data))
            retn["more"] = bool(data.get("more"))

            if not retn["more"] or (maxpages and page >= maxpages):
                break
            page += 1

        retn["subdomains"] = sorted(set(retn["subdomains"]))
        return retn

    async def dnsResolve(self, hostnames: list, apikey=None) -> dict:
        """GET /dns/resolve"""
        return await self._api("get", "/dns/resolve", apikey, params={"hostnames": list(hostnames)})

    async def dnsReverse(self, ips: list, apikey=None) -> dict:
        """GET /dns/reverse"""
        return await self._api("get", "/dns/reverse", apikey, params={"ips": list(ips)})

    # ---- Trends ----

    async def trendsSearch(self, query: str, facets=None, apikey=None) -> dict:
        """GET trends.shodan.io/api/v1/search"""
        return await self._api(
            "get",
            "/api/v1/search",
            apikey,
            base="trends",
            params={"query": query, "facets": facets},
        )

    async def trendsFacets(self, apikey=None) -> list:
        """GET trends.shodan.io/api/v1/search/facets"""
        return await self._api("get", "/api/v1/search/facets", apikey, base="trends")

    async def trendsFilters(self, apikey=None) -> list:
        """GET trends.shodan.io/api/v1/search/filters"""
        return await self._api("get", "/api/v1/search/filters", apikey, base="trends")

    # ---- Local helpers (no API calls) ----

    async def bannerHash(self, text: str) -> int:
        """Calculate Shodan's banner ``hash`` for banner text, for use in ``hash:<n>`` searches."""
        return norm.bannerHash(text)

    async def fileHash(self, chunks: list[bytes], kind: str) -> int:
        """Calculate Shodan's ``favicon`` or ``html`` hash of a file, given its bytes in chunks.

        Storm reads files from the Axon at most 1 MiB at a time, so it sends the chunks as-is.
        """
        if kind not in norm.FILE_HASH_FILTERS:
            kinds = ", ".join(norm.FILE_HASH_FILTERS)
            raise ShodanApiError(f"Unknown file hash kind {kind!r}, expected one of: {kinds}")
        return norm.fileHash(b"".join(chunks), kind)

    # ---- InternetDB (free, no API key) ----

    async def internetdb(self, ip: str) -> dict:
        """GET internetdb.shodan.io/{ip}"""
        return await self.client.request("get", f"/{_seg(ip)}", base="internetdb")

    async def normInternetDb(self, ip: str) -> dict:
        """Like ``internetdb()`` but normalized to the same shape as ``normHost()``."""
        return norm.normInternetDb(await self.internetdb(ip))

    # ---- CVEDB (free, no API key) ----

    async def cve(self, cveid: str) -> dict:
        """GET cvedb.shodan.io/cve/{cve_id}"""
        return await self.client.request("get", f"/cve/{_seg(cveid.upper())}", base="cvedb")

    async def normCve(self, cveid: str) -> dict:
        return norm.normCve(await self.cve(cveid))

    async def ghsa(self, ghsaid: str) -> dict:
        """GET cvedb.shodan.io/ghsa/{ghsa_id}"""
        return await self.client.request("get", f"/ghsa/{_seg(ghsaid.upper())}", base="cvedb")

    async def euvd(self, euvdid: str) -> dict:
        """GET cvedb.shodan.io/euvd/{euvd_id}"""
        return await self.client.request("get", f"/euvd/{_seg(euvdid.upper())}", base="cvedb")

    async def normVuln(self, vulnid: str) -> dict:
        """Look up a CVE, GHSA, or EUVD ID in CVEDB, normalized to the ``normCve`` shape."""

        vulnid = vulnid.strip()
        prefix = vulnid.upper().split("-", 1)[0]
        if prefix == "GHSA":
            return norm.normAdvisory(await self.ghsa(vulnid))
        if prefix == "EUVD":
            return norm.normAdvisory(await self.euvd(vulnid))
        return norm.normCve(await self.cve(vulnid))

    async def cves(
        self,
        cpe23: str | None = None,
        product: str | None = None,
        is_kev: bool = False,
        sort_by_epss: bool = False,
        skip: int = 0,
        limit: int = 1000,
        start_date: str | None = None,
        end_date: str | None = None,
        count: bool = False,
    ) -> dict:
        """GET cvedb.shodan.io/cves

        Returns ``{"cves": [...]}`` with each CVE normalized, or ``{"total": n}`` with ``count``.
        """
        params = {
            "cpe23": cpe23,
            "product": product,
            "skip": skip,
            "limit": limit,
            "start_date": start_date,
            "end_date": end_date,
            "is_kev": is_kev or None,
            "sort_by_epss": sort_by_epss or None,
            "count": count or None,
        }
        data = await self.client.request("get", "/cves", base="cvedb", params=params)
        if "cves" in data:
            data["cves"] = [norm.normCve(c) for c in data["cves"] or []]
        return data

    async def cpes(
        self, product: str, skip: int = 0, limit: int = 1000, count: bool = False
    ) -> dict:
        """GET cvedb.shodan.io/cpes

        CVEDB returns shortened CPE 2.3 strings, they're padded so Synapse accepts them.
        """
        data = await self.client.request(
            "get",
            "/cpes",
            base="cvedb",
            params={
                "product": product,
                "skip": skip,
                "limit": limit,
                "count": count or None,
            },
        )
        if "cpes" in data:
            data["cpes"] = norm.normCpes(data["cpes"])
        return data

    # ---- Streaming ----

    async def streamUrl(
        self, kind: str = "banners", values=None, query: str | None = None, aid: str | None = None
    ) -> str:
        """The public URL of a Streaming API endpoint, without the API key.

        Recorded as the ``:api:url`` of the stream's ``it:exec:query``. It always uses Shodan's
        public base URL, even when ``shodan:urls`` overrides it, so internal hosts aren't recorded.
        """

        path, params = _streamPath(kind, values=values, query=query, aid=aid)
        url = BASE_URLS["stream"] + path
        if params:
            url = f"{url}?{urlencode(params)}"
        return url

    async def stream(
        self,
        kind: str = "banners",
        values=None,
        query: str | None = None,
        aid: str | None = None,
        limit: int = 100,
        timeout: float = 60,
        apikey=None,
    ) -> AsyncIterator[dict]:
        """Read normalized banners from a Shodan Streaming API endpoint.

        ``kind`` is one of ``STREAM_KINDS``. ``values`` is required for the list
        based kinds (asn, countries, ports, tags, vulns), ``query`` for custom,
        and ``aid`` optionally narrows the alert stream to a single alert.
        """

        path, params = _streamPath(kind, values=values, query=query, aid=aid)
        async for banner in self.client.stream(
            path, apikey=self.getApiKey(apikey), params=params, limit=limit, timeout=timeout
        ):
            yield norm.normBanner(banner)
