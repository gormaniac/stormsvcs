"""The slib.abusech service.

Every abuse.ch API endpoint and dataset has a method on ``AbuseChSvc``. Methods
named after an endpoint return abuse.ch's data as-is, the ``norm*`` variants
return it normalized for modeling (see ``abusechsvc.norm``). Every method raises
``AbuseChApiError`` on failure, ``AbuseChCellApi`` wraps them in the standard
``TelepathRetn`` convention for Storm.

The platforms, and the base URL names (see ``abusechsvc.client.BASE_URLS``) they use:

* MalwareBazaar - ``bazaar``, ``bazaar:export``
* URLhaus - ``urlhaus``, ``urlhaus:submit``, ``urlhaus:export``
* ThreatFox - ``threatfox``, ``threatfox:export``
* YARAify - ``yaraify``, ``yaraify:export``
* Feodo Tracker - ``feodo``
* SSL Blacklist - ``sslbl``
* Hunting (false positive list) - ``hunting``
"""


import hashlib
import json
from collections.abc import AsyncIterator, Iterable
from typing import Any
from urllib.parse import quote

import aiohttp
import synapse.lib.cell as s_cell

from . import norm
from .api import AbuseChCellApi
from .client import AbuseChApiError, AbuseChClient, unzip


BAZAAR_SEARCHES = {
    "tag": ("get_taginfo", "tag", True),
    "signature": ("get_siginfo", "signature", True),
    "filetype": ("get_file_type", "file_type", True),
    "clamav": ("get_clamavinfo", "clamav", True),
    "imphash": ("get_imphash", "imphash", True),
    "tlsh": ("get_tlsh", "tlsh", True),
    "telfhash": ("get_telfhash", "telfhash", True),
    "gimphash": ("get_gimphash", "gimphash", True),
    "dhash": ("get_dhash_icon", "dhash_icon", True),
    "yara": ("get_yarainfo", "yara_rule", True),
    "issuer": ("get_issuerinfo", "issuer_cn", False),
    "subject": ("get_subjectinfo", "subject_cn", False),
}
"""MalwareBazaar searches: name -> (query, the query's field, whether it takes a limit)."""

YARAIFY_SEARCHES = {
    "yara": "get_yara",
    "clamav": "get_clamav",
    "imphash": "get_imphash",
    "gimphash": "get_gimphash",
    "dhash": "get_dhash_icon",
    "tlsh": "get_tlsh",
    "telfhash": "get_telfhash",
}
"""YARAify searches: name -> query. Each takes a ``search_term`` and ``result_max``."""

BAZAAR_EXPORTS = {
    "recent": "recent.csv",
    "full": "full.csv.zip",
}
"""MalwareBazaar CSV exports: name -> file. ``recent`` is the last 48 hours."""

BAZAAR_CSV = ("first_seen_utc", "sha256_hash", "md5_hash", "sha1_hash", "reporter", "file_name",
              "file_type_guess", "mime_type", "signature", "clamav", "vtpercent", "imphash", "ssdeep", "tlsh")
"""The columns of the MalwareBazaar CSV export."""

URLHAUS_EXPORTS = {
    "recent": "recent.csv",
    "online": "online.csv",
    "full": "full.csv.zip",
}
"""URLhaus CSV exports: name -> file. ``recent`` is the last 30 days, ``full`` the last 90 days and every online URL."""

URLHAUS_CSV = ("id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter")
"""The columns of the URLhaus CSV exports."""

THREATFOX_EXPORTS = {
    "recent": "recent.json",
    "full": "full.json.zip",
}
"""ThreatFox JSON exports: name -> file. ``recent`` is the last 48 hours."""

FEODO_BLOCKLISTS = {
    "all": "ipblocklist.json",
    "recommended": "ipblocklist_recommended.txt",
    "aggressive": "ipblocklist_aggressive.csv",
}
"""Feodo Tracker blocklists: name -> file."""

SSLBL_BLOCKLISTS = {
    "certs": "sslblacklist.csv",
    "ips": "sslipblacklist.csv",
    "ips-aggressive": "sslipblacklist_aggressive.csv",
    "ja3": "ja3_fingerprints.csv",
}
"""SSL Blacklist blocklists: name -> file."""

RAW_BASES = ("bazaar", "urlhaus", "urlhaus:submit", "threatfox", "yaraify", "hunting")
"""The APIs that ``rawRequest`` can send JSON/form requests to."""


def _seg(valu: Any) -> str:
    """Quote a value for use as a single URL path segment."""

    return quote(str(valu), safe="")


def hashType(valu: str) -> str:
    """The type of a hex hash by its length (md5, sha1, sha256, or sha3_384)."""

    htype = {32: "md5", 40: "sha1", 64: "sha256", 96: "sha3_384"}.get(len(valu or ""))
    if htype is None or not norm.isHex(valu):
        raise AbuseChApiError(f"Not an MD5, SHA1, SHA256, or SHA3-384 hash: {valu}")
    return htype


def _data(resp: dict | None, default: Any = None) -> Any:
    """The ``data`` of an abuse.ch response, or a default when it's empty or missing."""

    if not resp:
        return default
    data = resp.get("data")
    return default if data in (None, "") else data


class AbuseChSvc(s_cell.Cell):
    """The Cell implementation for the slib.abusech service."""

    cellapi = AbuseChCellApi

    confdefs = {
        "abusech:apikey": {
            "type": ["string", "null"],
            "default": None,
            "description": (
                "An abuse.ch Auth-Key (from https://auth.abuse.ch/) used when neither the calling "
                "user nor the service's stored key (set with slib.abusech.admin.apikey) provides one."
            ),
        },
        "abusech:ratelimit": {
            "type": "number",
            "default": 5.0,
            "description": "Max requests/second sent to abuse.ch, across every platform. 0 disables it.",
        },
        "abusech:timeout": {
            "type": "number",
            "default": 120,
            "description": "Timeout, in seconds, for a single abuse.ch request.",
        },
        "abusech:maxsize": {
            "type": "integer",
            "default": 67108864,
            "description": "The max size, in bytes, of a file downloaded from or submitted to abuse.ch.",
        },
        "abusech:urls": {
            "type": "object",
            "default": {},
            "description": (
                "Overrides for abuse.ch base URLs, keyed by bazaar, bazaar:export, urlhaus, urlhaus:submit, "
                "urlhaus:export, threatfox, threatfox:export, yaraify, yaraify:export, hunting, feodo, or sslbl."
            ),
        },
    }

    async def __anit__(self, dirn, *args, **kwargs):
        await s_cell.Cell.__anit__(self, dirn, *args, **kwargs)

        self.abuseinfo = self.slab.getSafeKeyVal("slib:abusech")

        self.session = aiohttp.ClientSession(trust_env=True)
        self.onfini(self.session.close)

        self.maxsize = self.conf.get("abusech:maxsize")
        self.client = AbuseChClient(
            self.session,
            urls=self.conf.get("abusech:urls"),
            rate=self.conf.get("abusech:ratelimit"),
            timeout=self.conf.get("abusech:timeout"),
        )

    # ---- Auth-Key management ----

    def getApiKey(self, apikey: str | None = None) -> str | None:
        """Resolve the Auth-Key to use: the caller's, then the stored key, then the config."""

        return apikey or self.abuseinfo.get("apikey") or self.conf.get("abusech:apikey")

    async def setApiKey(self, apikey: str | None) -> bool:
        """Set (or clear, with None/empty) the service-wide abuse.ch Auth-Key."""

        if apikey:
            self.abuseinfo.set("apikey", apikey)
        else:
            self.abuseinfo.pop("apikey")
        return True

    async def hasApiKey(self) -> bool:
        """Whether the service has a stored or configured Auth-Key."""

        return bool(self.getApiKey())

    async def _query(self, base: str, path: str = "", apikey=None, **kwargs) -> dict | None:
        return await self.client.query(base, path, apikey=self.getApiKey(apikey), **kwargs)

    async def _fetch(self, base: str, path: str = "", apikey=None, **kwargs) -> tuple[bytes, str]:
        return await self.client.fetch(base, path, apikey=self.getApiKey(apikey), **kwargs)

    async def _fetchText(self, base: str, path: str, apikey=None) -> str:
        """Download a dataset as text, unzipping it if it's a zip."""

        byts, _ = await self._fetch(base, path, apikey=apikey)
        if byts[:2] == b"PK":
            files = unzip(byts, password=None)
            byts = b"\n".join(b for _, b in files)
        return byts.decode("utf-8", "replace")

    def _sample(self, files: list[tuple[str, bytes]]) -> dict | None:
        """Describe a downloaded sample (the first file in its zip) for Storm."""

        if not files:
            return None
        name, byts = files[0]
        return {
            "name": name,
            "size": len(byts),
            "sha256": hashlib.sha256(byts).hexdigest(),
            "bytes": byts,
        }

    async def _download(self, base: str, path: str = "", apikey=None, **kwargs) -> dict | None:
        """Download a zipped sample and return it unzipped (see ``_sample``), or None if it isn't available."""

        byts, ctype = await self._fetch(base, path, apikey=apikey, **kwargs)
        if not byts:
            return None
        if len(byts) > self.maxsize:
            raise AbuseChApiError(f"The download is {len(byts)} bytes, larger than the max of {self.maxsize}.")
        if byts[:2] != b"PK":
            raise AbuseChApiError(f"abuse.ch did not return a zip ({ctype or 'unknown content type'}).")
        return self._sample(unzip(byts, maxsize=self.maxsize))

    def _join(self, chunks: Iterable[bytes]) -> bytes:
        byts = b"".join(chunks)
        if len(byts) > self.maxsize:
            raise AbuseChApiError(f"The file is {len(byts)} bytes, larger than the max of {self.maxsize}.")
        return byts

    async def rawRequest(self, base: str, path: str = "", method: str = "post", form=None,
                         json_data=None, params=None, apikey=None) -> Any:
        """Send an arbitrary request to an abuse.ch API and return its parsed JSON. An escape hatch."""

        if base not in RAW_BASES:
            raise AbuseChApiError(f"rawRequest only supports the {', '.join(RAW_BASES)} APIs.")
        if form is None and json_data is None and method.lower() == "post":
            form = {}
        return await self._query(base, path, apikey=apikey, method=method, form=form,
                                 json_data=json_data, params=params)

    # ---- MalwareBazaar ----

    async def bazaarQuery(self, query: str, fields: dict | None = None, apikey=None) -> dict | None:
        """POST a ``query`` (with any other form fields) to the MalwareBazaar API."""

        return await self._query("bazaar", apikey=apikey, form=dict(fields or {}, query=query))

    async def bazaarInfo(self, sha: str, apikey=None) -> dict | None:
        """``get_info`` - Everything MalwareBazaar knows about a sample (by MD5, SHA1, SHA256, or SHA3-384)."""

        hashType(sha)
        data = _data(await self.bazaarQuery("get_info", {"hash": sha.lower()}, apikey=apikey), [])
        return data[0] if data else None

    async def normBazaarInfo(self, sha: str, apikey=None) -> dict | None:
        """Like ``bazaarInfo()`` but normalized."""

        data = await self.bazaarInfo(sha, apikey=apikey)
        return norm.normSample(data) if data else None

    async def bazaarSearch(self, by: str, valu: str, limit: int = 100, apikey=None) -> list:
        """Search MalwareBazaar samples. ``by`` is one of ``BAZAAR_SEARCHES`` (max 1000 results)."""

        if by not in BAZAAR_SEARCHES:
            raise AbuseChApiError(f"Unknown MalwareBazaar search: {by}")
        query, field, haslimit = BAZAAR_SEARCHES[by]
        fields = {field: valu}
        if haslimit:
            fields["limit"] = max(1, min(int(limit or 1000), 1000))
        return _data(await self.bazaarQuery(query, fields, apikey=apikey), [])

    async def normBazaarSearch(self, by: str, valu: str, limit: int = 100, apikey=None) -> list[dict]:
        """Like ``bazaarSearch()`` but normalized."""

        return norm.normSamples(await self.bazaarSearch(by, valu, limit=limit, apikey=apikey))[:limit or None]

    async def bazaarRecent(self, selector: str = "time", apikey=None) -> list:
        """``get_recent`` - The samples added in the last hour (``time``) or the latest 100 (``100``)."""

        if str(selector) not in ("time", "100"):
            raise AbuseChApiError("The get_recent selector must be 'time' or '100'.")
        return _data(await self.bazaarQuery("get_recent", {"selector": str(selector)}, apikey=apikey), [])

    async def normBazaarRecent(self, selector: str = "time", apikey=None) -> list[dict]:
        """Like ``bazaarRecent()`` but normalized."""

        return norm.normSamples(await self.bazaarRecent(selector, apikey=apikey))

    async def bazaarCscb(self, apikey=None) -> list:
        """``get_cscb`` - The Code Signing Certificate Blocklist."""

        return _data(await self.bazaarQuery("get_cscb", apikey=apikey), [])

    async def normBazaarCscb(self, apikey=None) -> list[dict]:
        """Like ``bazaarCscb()`` but normalized into certs."""

        certs = (norm.normCert(c, blocklist=True) for c in await self.bazaarCscb(apikey=apikey))
        return [c for c in certs if c]

    async def bazaarFile(self, sha256: str, apikey=None) -> dict | None:
        """``get_file`` - Download a sample, returning ``{name, size, sha256, bytes}`` (unzipped)."""

        if hashType(sha256) != "sha256":
            raise AbuseChApiError("MalwareBazaar downloads require a SHA256 hash.")
        return await self._download("bazaar", method="post", apikey=apikey,
                                    form={"query": "get_file", "sha256_hash": sha256.lower()})

    async def bazaarUpload(self, chunks: list[bytes], name: str, anonymous: bool = False,
                           tags: list | None = None, delivery_method: str | None = None,
                           references: dict | None = None, context: dict | None = None,
                           apikey=None) -> dict | None:
        """Submit a sample to MalwareBazaar.

        ``chunks`` are the file's bytes (in pieces, as read from an Axon).
        ``references`` and ``context`` are passed through as MalwareBazaar's
        ``references`` (ex. ``{"links": [...]}``) and ``context`` (ex. ``{"comment": ...}``).
        """

        body = {
            "anonymous": 1 if anonymous else 0,
            "tags": list(tags or []),
            "delivery_method": delivery_method,
            "references": references or None,
            "context": context or None,
        }
        body = {k: v for k, v in body.items() if v not in (None, [])}
        return await self._query("bazaar", apikey=apikey, form={"json_data": json.dumps(body)},
                                 files={"file": (name or "sample", self._join(chunks))})

    async def bazaarUpdate(self, sha256: str, key: str, valu: str, apikey=None) -> dict | None:
        """``update`` - Add a value (ex. a tag or a link) to a sample you submitted."""

        return await self.bazaarQuery("update", {"sha256_hash": sha256.lower(), "key": key, "value": valu},
                                      apikey=apikey)

    async def bazaarComment(self, sha256: str, comment: str, apikey=None) -> dict | None:
        """``add_comment`` - Comment on a sample."""

        return await self.bazaarQuery("add_comment", {"sha256_hash": sha256.lower(), "comment": comment},
                                      apikey=apikey)

    async def bazaarExport(self, kind: str = "recent", limit: int = 0, apikey=None) -> AsyncIterator[dict]:
        """Yield normalized samples from a MalwareBazaar CSV export (see ``BAZAAR_EXPORTS``)."""

        if kind not in BAZAAR_EXPORTS:
            raise AbuseChApiError(f"Unknown MalwareBazaar export: {kind}")
        text = await self._fetchText("bazaar:export", BAZAAR_EXPORTS[kind], apikey=apikey)
        count = 0
        for row in norm.parseCsv(text, BAZAAR_CSV):
            sample = norm.normSample(row)
            if sample:
                yield sample
                count += 1
                if limit and count >= limit:
                    return

    # ---- URLhaus ----

    async def urlhausUrl(self, url: str, apikey=None) -> dict | None:
        """``/url/`` - Look up a URL."""

        return await self._query("urlhaus", "url/", apikey=apikey, form={"url": url})

    async def urlhausUrlId(self, urlid: str | int, apikey=None) -> dict | None:
        """``/urlid/`` - Look up a URL by its URLhaus ID."""

        return await self._query("urlhaus", "urlid/", apikey=apikey, form={"urlid": str(urlid)})

    async def normUrlhausUrl(self, url: str | None = None, urlid: str | int | None = None,
                             apikey=None) -> dict | None:
        """Like ``urlhausUrl()``/``urlhausUrlId()`` but normalized."""

        if urlid is not None:
            data = await self.urlhausUrlId(urlid, apikey=apikey)
        else:
            data = await self.urlhausUrl(url, apikey=apikey)
        return norm.normUrl(data) if data else None

    async def urlhausHost(self, host: str, apikey=None) -> dict | None:
        """``/host/`` - Look up a host (FQDN or IP) and the URLs URLhaus has seen on it."""

        return await self._query("urlhaus", "host/", apikey=apikey, form={"host": host})

    async def normUrlhausHost(self, host: str, apikey=None) -> dict | None:
        """Like ``urlhausHost()`` but normalized."""

        data = await self.urlhausHost(host, apikey=apikey)
        return norm.normUrlhausHost(data) if data else None

    async def urlhausPayload(self, sha: str, apikey=None) -> dict | None:
        """``/payload/`` - Look up a payload by MD5 or SHA256."""

        htype = hashType(sha)
        if htype not in ("md5", "sha256"):
            raise AbuseChApiError("URLhaus payload lookups require an MD5 or SHA256 hash.")
        return await self._query("urlhaus", "payload/", apikey=apikey, form={f"{htype}_hash": sha.lower()})

    async def normUrlhausPayload(self, sha: str, apikey=None) -> dict | None:
        """Like ``urlhausPayload()`` but normalized."""

        data = await self.urlhausPayload(sha, apikey=apikey)
        return norm.normUrlhausPayload(data) if data else None

    async def urlhausTag(self, tag: str, apikey=None) -> dict | None:
        """``/tag/`` - The URLs with a tag."""

        return await self._query("urlhaus", "tag/", apikey=apikey, form={"tag": tag})

    async def urlhausSignature(self, signature: str, apikey=None) -> dict | None:
        """``/signature/`` - The URLs (and payloads) for a malware signature."""

        return await self._query("urlhaus", "signature/", apikey=apikey, form={"signature": signature})

    async def normUrlhausSearch(self, by: str, valu: str, limit: int = 0, apikey=None) -> dict:
        """Normalized ``urlhausTag()`` (``by=tag``) or ``urlhausSignature()`` (``by=signature``).

        Returns ``{first_seen, last_seen, url_count, payload_count, urls}``.
        """

        if by == "tag":
            data = await self.urlhausTag(valu, apikey=apikey)
        elif by == "signature":
            data = await self.urlhausSignature(valu, apikey=apikey)
        else:
            raise AbuseChApiError(f"Unknown URLhaus search: {by}")
        data = data or {}
        urls = norm.normUrls(data.get("urls"))
        return {
            "first_seen": norm.ts(data.get("firstseen")),
            "last_seen": norm.ts(data.get("lastseen")),
            "url_count": norm.toInt(data.get("url_count")),
            "payload_count": norm.toInt(data.get("payload_count")),
            "urls": urls[:limit] if limit else urls,
        }

    async def urlhausRecentUrls(self, limit: int | None = None, apikey=None) -> dict | None:
        """``/urls/recent/`` - URLs added in the last 3 days (max 1000), or the latest ``limit``."""

        path = f"urls/recent/limit/{int(limit)}/" if limit else "urls/recent/"
        return await self._query("urlhaus", path, method="get", apikey=apikey)

    async def urlhausRecentPayloads(self, limit: int | None = None, apikey=None) -> dict | None:
        """``/payloads/recent/`` - Payloads seen in the last 3 days (max 1000), or the latest ``limit``."""

        path = f"payloads/recent/limit/{int(limit)}/" if limit else "payloads/recent/"
        return await self._query("urlhaus", path, method="get", apikey=apikey)

    async def normUrlhausRecent(self, kind: str = "urls", limit: int | None = None, apikey=None) -> list[dict]:
        """Normalized ``urlhausRecentUrls()`` (``kind=urls``) or ``urlhausRecentPayloads()`` (``kind=payloads``)."""

        if kind == "urls":
            return norm.normUrls((await self.urlhausRecentUrls(limit, apikey=apikey) or {}).get("urls"))
        if kind == "payloads":
            return norm.normSamples((await self.urlhausRecentPayloads(limit, apikey=apikey) or {}).get("payloads"))
        raise AbuseChApiError(f"Unknown URLhaus recent list: {kind}")

    async def urlhausDownload(self, sha256: str, apikey=None) -> dict | None:
        """``/download/{sha256}/`` - Download a payload, returning ``{name, size, sha256, bytes}`` (unzipped)."""

        if hashType(sha256) != "sha256":
            raise AbuseChApiError("URLhaus downloads require a SHA256 hash.")
        return await self._download("urlhaus", f"download/{_seg(sha256.lower())}/", method="get", apikey=apikey)

    async def urlhausSubmit(self, urls: list[str], threat: str = "malware_download", tags: list | None = None,
                            anonymous: bool = False, apikey=None) -> str:
        """Report malware URLs to URLhaus. Returns URLhaus' response message."""

        body = {
            "anonymous": "1" if anonymous else "0",
            "submission": [{"url": u, "threat": threat, "tags": list(tags or [])} for u in urls],
        }
        byts, _ = await self._fetch("urlhaus:submit", method="post", apikey=apikey, json_data=body)
        return byts.decode("utf-8", "replace").strip()

    async def urlhausExport(self, kind: str = "recent", limit: int = 0, apikey=None) -> AsyncIterator[dict]:
        """Yield normalized URLs from a URLhaus CSV export (see ``URLHAUS_EXPORTS``)."""

        if kind not in URLHAUS_EXPORTS:
            raise AbuseChApiError(f"Unknown URLhaus export: {kind}")
        text = await self._fetchText("urlhaus:export", URLHAUS_EXPORTS[kind], apikey=apikey)
        count = 0
        for row in norm.parseCsv(text, URLHAUS_CSV):
            url = norm.normUrl(row)
            if url:
                yield url
                count += 1
                if limit and count >= limit:
                    return

    # ---- ThreatFox ----

    async def threatfoxQuery(self, query: str, body: dict | None = None, apikey=None) -> dict | None:
        """POST a ``query`` (with any other JSON fields) to the ThreatFox API."""

        return await self._query("threatfox", apikey=apikey, json_data=dict(body or {}, query=query))

    async def threatfoxRecent(self, days: int = 1, apikey=None) -> list:
        """``get_iocs`` - IOCs added in the last ``days`` (1-7)."""

        days = max(1, min(int(days), 7))
        return _data(await self.threatfoxQuery("get_iocs", {"days": days}, apikey=apikey), [])

    async def threatfoxIoc(self, iocid: int | str, apikey=None) -> dict | None:
        """``ioc`` - An IOC by its ThreatFox ID."""

        return _data(await self.threatfoxQuery("ioc", {"id": int(iocid)}, apikey=apikey))

    async def threatfoxSearch(self, term: str, exact: bool = False, apikey=None) -> list:
        """``search_ioc`` - Search IOCs by value."""

        return _data(await self.threatfoxQuery("search_ioc", {"search_term": term, "exact_match": bool(exact)},
                                               apikey=apikey), [])

    async def threatfoxHash(self, sha: str, apikey=None) -> list:
        """``search_hash`` - IOCs associated with a malware sample (MD5 or SHA256)."""

        return _data(await self.threatfoxQuery("search_hash", {"hash": sha.lower()}, apikey=apikey), [])

    async def threatfoxTag(self, tag: str, limit: int = 100, apikey=None) -> list:
        """``taginfo`` - IOCs with a tag (max 1000)."""

        limit = max(1, min(int(limit or 1000), 1000))
        return _data(await self.threatfoxQuery("taginfo", {"tag": tag, "limit": limit}, apikey=apikey), [])

    async def threatfoxMalware(self, malware: str, limit: int = 100, apikey=None) -> list:
        """``malwareinfo`` - IOCs for a malware family (max 1000)."""

        limit = max(1, min(int(limit or 1000), 1000))
        return _data(await self.threatfoxQuery("malwareinfo", {"malware": malware, "limit": limit},
                                               apikey=apikey), [])

    async def normThreatfox(self, by: str, valu: Any = None, limit: int = 100, exact: bool = False,
                            apikey=None) -> list[dict]:
        """Normalized IOCs from any ThreatFox IOC query.

        ``by`` is ``recent`` (``valu`` is days), ``id``, ``search``, ``hash``, ``tag``, or ``malware``.
        """

        if by == "recent":
            items = await self.threatfoxRecent(valu or 1, apikey=apikey)
        elif by == "id":
            items = norm.lst(await self.threatfoxIoc(valu, apikey=apikey))
        elif by == "search":
            items = await self.threatfoxSearch(valu, exact=exact, apikey=apikey)
        elif by == "hash":
            items = await self.threatfoxHash(valu, apikey=apikey)
        elif by == "tag":
            items = await self.threatfoxTag(valu, limit=limit, apikey=apikey)
        elif by == "malware":
            items = await self.threatfoxMalware(valu, limit=limit, apikey=apikey)
        else:
            raise AbuseChApiError(f"Unknown ThreatFox query: {by}")
        iocs = norm.normIocs(items if isinstance(items, list) else [])
        return iocs[:limit] if limit and by not in ("id",) else iocs

    async def threatfoxTypes(self, apikey=None) -> dict:
        """``types`` - The IOC and threat types ThreatFox supports."""

        return _data(await self.threatfoxQuery("types", apikey=apikey), {})

    async def threatfoxTagList(self, apikey=None) -> dict:
        """``tag_list`` - Every tag in ThreatFox."""

        return _data(await self.threatfoxQuery("tag_list", apikey=apikey), {})

    async def threatfoxMalwareList(self, apikey=None) -> dict:
        """``malware_list`` - Every malware family in ThreatFox."""

        return _data(await self.threatfoxQuery("malware_list", apikey=apikey), {})

    async def threatfoxLabel(self, malware: str, platform: str | None = None, apikey=None) -> list:
        """``get_label`` - Find the ThreatFox malware label for a family name."""

        return _data(await self.threatfoxQuery("get_label", {"malware": malware, "platform": platform},
                                               apikey=apikey), [])

    async def threatfoxSubmit(self, threat_type: str, ioc_type: str, malware: str, iocs: list[str],
                              confidence: int = 50, reference: str | None = None, comment: str | None = None,
                              tags: list | None = None, anonymous: bool = False, compromised: bool = False,
                              apikey=None) -> dict | None:
        """``submit_ioc`` - Share IOCs with ThreatFox."""

        body = {
            "threat_type": threat_type,
            "ioc_type": ioc_type,
            "malware": malware,
            "confidence_level": max(0, min(int(confidence), 100)),
            "is_compromised": bool(compromised),
            "reference": reference,
            "comment": comment,
            "anonymous": 1 if anonymous else 0,
            "tags": list(tags or []),
            "iocs": list(iocs),
        }
        return await self.threatfoxQuery("submit_ioc", {k: v for k, v in body.items() if v is not None},
                                         apikey=apikey)

    async def threatfoxExport(self, kind: str = "recent", limit: int = 0, apikey=None) -> AsyncIterator[dict]:
        """Yield normalized IOCs from a ThreatFox JSON export (see ``THREATFOX_EXPORTS``)."""

        if kind not in THREATFOX_EXPORTS:
            raise AbuseChApiError(f"Unknown ThreatFox export: {kind}")
        text = await self._fetchText("threatfox:export", THREATFOX_EXPORTS[kind], apikey=apikey)
        try:
            data = json.loads(text) if text.strip() else {}
        except ValueError as err:
            raise AbuseChApiError(f"Unable to parse the ThreatFox {kind} export: {err}") from err
        for count, ioc in enumerate(norm.normThreatFoxExport(data), start=1):
            yield ioc
            if limit and count >= limit:
                return

    # ---- YARAify ----

    async def yaraifyQuery(self, query: str, body: dict | None = None, apikey=None) -> dict | None:
        """POST a ``query`` (with any other JSON fields) to the YARAify API."""

        return await self._query("yaraify", apikey=apikey, json_data=dict(body or {}, query=query))

    async def yaraifyHash(self, sha: str, malpedia: str | None = None, apikey=None) -> dict | None:
        """``lookup_hash`` - A file's metadata and scan results (by MD5, SHA1, SHA256, or SHA3-384)."""

        hashType(sha)
        body = {"search_term": sha.lower(), "malpedia-token": malpedia}
        return _data(await self.yaraifyQuery("lookup_hash", {k: v for k, v in body.items() if v}, apikey=apikey))

    async def normYaraifyHash(self, sha: str, malpedia: str | None = None, apikey=None) -> dict | None:
        """Like ``yaraifyHash()`` but normalized."""

        data = await self.yaraifyHash(sha, malpedia=malpedia, apikey=apikey)
        return norm.normYaraifyFile(data) if isinstance(data, dict) else None

    async def yaraifySearch(self, by: str, valu: str, limit: int = 25, apikey=None) -> list:
        """Search YARAify files. ``by`` is one of ``YARAIFY_SEARCHES``."""

        if by not in YARAIFY_SEARCHES:
            raise AbuseChApiError(f"Unknown YARAify search: {by}")
        body = {"search_term": valu, "result_max": max(1, int(limit or 1000))}
        data = _data(await self.yaraifyQuery(YARAIFY_SEARCHES[by], body, apikey=apikey), [])
        return data if isinstance(data, list) else norm.lst(data)

    async def normYaraifySearch(self, by: str, valu: str, limit: int = 25, apikey=None) -> list[dict]:
        """Like ``yaraifySearch()`` but normalized."""

        items = await self.yaraifySearch(by, valu, limit=limit, apikey=apikey)
        files = [norm.normYaraifyFile(i) for i in items if isinstance(i, dict)]
        files = [f for f in files if f]
        # Files from a YARA search matched that rule, even if the result doesn't say so.
        if by == "yara":
            for file in files:
                if valu not in {r["name"] for r in file["rules"]}:
                    file["rules"].append(norm.normRule({"rule_name": valu}))
        return files[:limit] if limit else files

    async def yaraifyRecentRules(self, apikey=None) -> list:
        """``recent_yararules`` - Recently deployed YARA rules."""

        return _data(await self.yaraifyQuery("recent_yararules", apikey=apikey), [])

    async def normYaraifyRecentRules(self, text: bool = True, apikey=None) -> list[dict]:
        """Like ``yaraifyRecentRules()`` but normalized, with each rule's text (see ``_ruleText``)."""

        rules = norm.normRules(await self.yaraifyRecentRules(apikey=apikey))
        return await self._ruleText(rules, apikey=apikey) if text else rules

    async def yaraifyDeployedRules(self, apikey=None) -> list:
        """``show_deployed_yara_rules`` - The YARA rules you've deployed for live hunting."""

        return _data(await self.yaraifyQuery("show_deployed_yara_rules", apikey=apikey), [])

    async def normYaraifyDeployedRules(self, text: bool = True, apikey=None) -> list[dict]:
        """Like ``yaraifyDeployedRules()`` but normalized, with each rule's text (see ``_ruleText``)."""

        rules = norm.normRules(await self.yaraifyDeployedRules(apikey=apikey))
        return await self._ruleText(rules, apikey=apikey) if text else rules

    async def _ruleText(self, rules: list[dict], apikey=None) -> list[dict]:
        """Fill in the text of rules listed without it, by downloading each one (``get_yara_rule``).

        Only rules whose author shares them (TLP:WHITE) can be downloaded, the
        rest keep their metadata only.
        """

        for rule in rules:
            if rule["text"] or not rule["uuid"]:
                continue
            try:
                downloads = await self.yaraifyRule(rule["uuid"], apikey=apikey)
            except AbuseChApiError:
                continue
            match = [d for d in downloads if d["name"] == rule["name"]] or downloads[:1]
            if match:
                rule["text"] = match[0]["text"]
        return rules

    async def yaraifyDeleteRule(self, uuid: str, apikey=None) -> Any:
        """``delete_yara_rule`` - Delete one of your deployed YARA rules."""

        resp = await self.yaraifyQuery("delete_yara_rule", {"yarahub_uuid": uuid}, apikey=apikey)
        return _data(resp, (resp or {}).get("query_status"))

    async def yaraifyResults(self, task_id: str, malpedia: str | None = None, apikey=None) -> Any:
        """``get_results`` - The results of a scan task, or ``"queued"`` while it's still running."""

        body = {"task_id": task_id, "malpedia-token": malpedia}
        return _data(await self.yaraifyQuery("get_results", {k: v for k, v in body.items() if v}, apikey=apikey))

    async def normYaraifyResults(self, task_id: str, malpedia: str | None = None, apikey=None) -> dict | None:
        """Like ``yaraifyResults()`` but normalized: ``{status, task_id, file}``."""

        data = await self.yaraifyResults(task_id, malpedia=malpedia, apikey=apikey)
        if data is None:
            return None
        if not isinstance(data, dict):
            return {"status": str(data), "task_id": task_id, "file": None}
        return {"status": "done", "task_id": task_id, "file": norm.normYaraifyFile(data)}

    async def yaraifyTasks(self, identifier: str, status: str = "processed", apikey=None) -> list:
        """``list_tasks`` - The tasks submitted with an identifier (``queued`` or ``processed``)."""

        return _data(await self.yaraifyQuery("list_tasks", {"identifier": identifier, "task_status": status},
                                             apikey=apikey), [])

    async def normYaraifyTasks(self, identifier: str, status: str = "processed", apikey=None) -> list[dict]:
        """Like ``yaraifyTasks()`` but normalized."""

        tasks = (norm.normTask(t) for t in await self.yaraifyTasks(identifier, status, apikey=apikey))
        return [t for t in tasks if t]

    async def yaraifyIdentifier(self, apikey=None) -> Any:
        """``generate_identifier`` - Generate a new (private) identifier to track scans with."""

        return _data(await self.yaraifyQuery("generate_identifier", apikey=apikey))

    async def yaraifyRescan(self, sha: str, apikey=None) -> Any:
        """``rescan_file`` - Rescan a known file. Returns ``{task_id}``."""

        hashType(sha)
        return _data(await self.yaraifyQuery("rescan_file", {"hash": sha.lower()}, apikey=apikey))

    async def yaraifyScan(self, chunks: list[bytes], name: str, identifier: str | None = None,
                          clamav_scan: bool = True, unpack: bool = False, share_file: bool = False,
                          skip_known: bool = False, skip_noisy: bool = False, apikey=None) -> Any:
        """Submit a file to YARAify for scanning. Returns ``{task_id}``."""

        opts = {
            "identifier": identifier,
            "clamav_scan": int(bool(clamav_scan)),
            "unpack": int(bool(unpack)),
            "share_file": int(bool(share_file)),
            "skip_known": int(bool(skip_known)),
            "skip_noisy": int(bool(skip_noisy)),
        }
        resp = await self._query("yaraify", apikey=apikey,
                                 form={"json_data": json.dumps({k: v for k, v in opts.items() if v is not None})},
                                 files={"file": (name or "sample", self._join(chunks))})
        return _data(resp)

    async def yaraifyDeploy(self, text: str, name: str = "rule.yar", apikey=None) -> Any:
        """Deploy a YARA rule to YARAify for live hunting."""

        resp = await self._query("yaraify", apikey=apikey, form={},
                                 files={"yara_file": (name, text.encode("utf-8"))})
        return _data(resp, (resp or {}).get("query_status"))

    async def yaraifyRule(self, uuid: str, apikey=None) -> list[dict]:
        """``get_yara_rule`` - Download a YARAhub rule by its UUID, returning the normalized rule(s)."""

        byts, _ = await self._fetch("yaraify", method="post", apikey=apikey,
                                    json_data={"query": "get_yara_rule", "uuid": uuid})
        if not byts:
            return []
        if byts[:2] == b"PK":
            byts = b"\n".join(b for _, b in unzip(byts, password=None))
        rules = norm.parseYara(byts.decode("utf-8", "replace"))
        if len(rules) == 1:
            rules[0]["uuid"] = rules[0]["uuid"] or uuid.lower()
        return rules

    async def yaraifyFile(self, sha256: str, apikey=None) -> dict | None:
        """``get_file`` - Download a (shared) file, returning ``{name, size, sha256, bytes}`` (unzipped)."""

        if hashType(sha256) != "sha256":
            raise AbuseChApiError("YARAify downloads require a SHA256 hash.")
        return await self._download("yaraify", method="post", apikey=apikey,
                                    json_data={"query": "get_file", "sha256_hash": sha256.lower()})

    async def yaraifyUnpacked(self, sha256: str, apikey=None) -> dict | None:
        """``get_unpacked`` - Download a file YARAify unpacked, returning ``{name, size, sha256, bytes}`` (unzipped)."""

        if hashType(sha256) != "sha256":
            raise AbuseChApiError("YARAify downloads require a SHA256 hash.")
        return await self._download("yaraify", method="post", apikey=apikey,
                                    json_data={"query": "get_unpacked", "sha256_hash": sha256.lower()})

    async def yaraifyRulesExport(self, limit: int = 0, apikey=None) -> AsyncIterator[dict]:
        """Yield every TLP:CLEAR YARAhub rule, normalized, from YARAify's rule export."""

        byts, _ = await self._fetch("yaraify:export", "yarahub/yaraify-rules.zip", apikey=apikey)
        files = unzip(byts, password=None) if byts[:2] == b"PK" else [("rules.yar", byts)]
        count = 0
        for _, rbyts in files:
            for rule in norm.parseYara(rbyts.decode("utf-8", "replace")):
                yield rule
                count += 1
                if limit and count >= limit:
                    return

    # ---- Feodo Tracker ----

    async def feodoBlocklist(self, kind: str = "all", limit: int = 0, apikey=None) -> AsyncIterator[dict]:
        """Yield normalized C2 servers from a Feodo Tracker blocklist (see ``FEODO_BLOCKLISTS``).

        The recommended list only has IPs, so its entries are filled in from the full list.
        """

        if kind not in FEODO_BLOCKLISTS:
            raise AbuseChApiError(f"Unknown Feodo Tracker blocklist: {kind}")

        if kind == "aggressive":
            text = await self._fetchText("feodo", FEODO_BLOCKLISTS[kind], apikey=apikey)
            items = (norm.normFeodo(r) for r in norm.parseCsv(text, norm.FEODO_CSV))
        else:
            text = await self._fetchText("feodo", FEODO_BLOCKLISTS["all"], apikey=apikey)
            try:
                rows = json.loads(text) if text.strip() else []
            except ValueError as err:
                raise AbuseChApiError(f"Unable to parse the Feodo Tracker blocklist: {err}") from err
            items = [norm.normFeodo(r) for r in norm.lst(rows)]
            if kind == "recommended":
                ips = set(norm.parseLines(await self._fetchText("feodo", FEODO_BLOCKLISTS[kind], apikey=apikey)))
                known = {i["ip"] for i in items if i}
                items = [i for i in items if i and i["ip"] in ips]
                items += [norm.normC2(ip, None) for ip in sorted(ips - known)]

        count = 0
        for item in items:
            if item:
                yield item
                count += 1
                if limit and count >= limit:
                    return

    # ---- SSL Blacklist ----

    async def sslblBlocklist(self, kind: str = "certs", limit: int = 0, apikey=None) -> AsyncIterator[dict]:
        """Yield normalized entries from an SSL Blacklist blocklist (see ``SSLBL_BLOCKLISTS``).

        ``certs`` yields certs, ``ips``/``ips-aggressive`` yield C2 servers, ``ja3`` yields JA3 fingerprints.
        """

        if kind not in SSLBL_BLOCKLISTS:
            raise AbuseChApiError(f"Unknown SSL Blacklist blocklist: {kind}")
        text = await self._fetchText("sslbl", SSLBL_BLOCKLISTS[kind], apikey=apikey)

        if kind == "certs":
            items = (norm.normSslblCert(r) for r in norm.parseCsv(text, norm.SSLBL_CERT_CSV))
        elif kind == "ja3":
            items = (norm.normJa3(r) for r in norm.parseCsv(text, norm.SSLBL_JA3_CSV))
        else:
            items = (norm.normSslblIp(r) for r in norm.parseCsv(text, norm.SSLBL_IP_CSV))

        count = 0
        for item in items:
            if item:
                yield item
                count += 1
                if limit and count >= limit:
                    return

    # ---- Hunting ----

    async def fplist(self, apikey=None) -> Any:
        """``get_fplist`` - The abuse.ch false positive list."""

        return _data(await self._query("hunting", apikey=apikey, json_data={"query": "get_fplist", "format": "json"}),
                     {})

    async def normFplist(self, platform: str | None = None, apikey=None) -> list[dict]:
        """Like ``fplist()`` but normalized, optionally only the entries for one platform."""

        fps = norm.normFpList(await self.fplist(apikey=apikey))
        if platform:
            platform = norm.normTag(platform)
            fps = [f for f in fps if f["platform"] == platform]
        return fps
