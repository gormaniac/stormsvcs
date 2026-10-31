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

import asyncio
import hashlib
import io
import json
import logging
import os
import re
import shutil
import tempfile
import time
import zipfile
from collections.abc import AsyncIterator, Iterable, Iterator
from typing import Any
from urllib.parse import quote

import aiohttp
import synapse.lib.cell as s_cell

import synapse.common as s_common
import synapse.lib.msgpack as s_msgpack

from . import bulk, norm
from .api import AbuseChCellApi
from .client import AbuseChApiError, AbuseChClient, unzip

logger = logging.getLogger(__name__)


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
    "serial": ("get_certificate", "serial_number", False),
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
    "yara": "yara_rules.json",
}
"""MalwareBazaar exports: name -> file. ``recent`` is the last 48 hours, ``yara`` the YARA rule statistics."""

BAZAAR_CSV = (
    "first_seen_utc",
    "sha256_hash",
    "md5_hash",
    "sha1_hash",
    "reporter",
    "file_name",
    "file_type_guess",
    "mime_type",
    "signature",
    "clamav",
    "vtpercent",
    "imphash",
    "ssdeep",
    "tlsh",
)
"""The columns of the MalwareBazaar CSV export."""

URLHAUS_EXPORTS = {
    "recent": "recent.csv",
    "online": "online.csv",
    "full": "full.csv.zip",
    "payloads": "payload.csv.zip",
}
"""URLhaus CSV exports: name -> file. ``recent`` is the last 30 days, ``full`` the last 90 days and every
online URL, and ``payloads`` every payload URLhaus collected (with the URL that served it)."""

URLHAUS_CSV = (
    "id",
    "dateadded",
    "url",
    "url_status",
    "last_online",
    "threat",
    "tags",
    "urlhaus_link",
    "reporter",
)
"""The columns of the URLhaus CSV exports."""

THREATFOX_EXPORTS = {
    "recent": "recent.json",
    "full": "full.json.zip",
}
"""ThreatFox JSON exports: name -> file. ``recent`` is the last 48 hours."""

FEODO_BLOCKLISTS = {
    "all": "ipblocklist.json",
    "recommended": "ipblocklist_recommended.json",
    "aggressive": "ipblocklist_aggressive.csv",
}
"""Feodo Tracker blocklists: name -> file."""

SSLBL_BLOCKLISTS = {
    "certs": "sslblacklist.csv",
    "ja3": "ja3_fingerprints.csv",
}
"""SSL Blacklist blocklists: name -> file. The botnet C2 IP lists were deprecated on 2025-01-03."""

BAZAAR_UPDATE_KEYS = (
    "add_tag",
    "remove_tag",
    "urlhaus",
    "any_run",
    "joe_sandbox",
    "malpedia",
    "twitter",
    "links",
    "dropped_by_md5",
    "dropped_by_sha256",
    "dropped_by_malware",
    "dropping_md5",
    "dropping_sha256",
    "dropping_malware",
    "comment",
)
"""The keys MalwareBazaar's ``update`` query accepts."""

BULK_EXPORTS = {
    ("bazaar", "recent"): ("bazaar:export", BAZAAR_EXPORTS["recent"]),
    ("bazaar", "full"): ("bazaar:export", BAZAAR_EXPORTS["full"]),
    ("urlhaus", "recent"): ("urlhaus:export", URLHAUS_EXPORTS["recent"]),
    ("urlhaus", "online"): ("urlhaus:export", URLHAUS_EXPORTS["online"]),
    ("urlhaus", "full"): ("urlhaus:export", URLHAUS_EXPORTS["full"]),
    ("urlhaus", "payloads"): ("urlhaus:export", URLHAUS_EXPORTS["payloads"]),
    ("threatfox", "recent"): ("threatfox:export", THREATFOX_EXPORTS["recent"]),
    ("threatfox", "full"): ("threatfox:export", THREATFOX_EXPORTS["full"]),
}
"""The exports that can be bulk imported: (platform, kind) -> (base, file)."""

BULK_BATCH = 1000
"""How many export records are built before their nodes are written to the job's .nodes file."""

BULK_IDLE = 6 * 60 * 60 * 1000
"""Bulk import jobs untouched for this long (ms) are removed, ex. when the Storm side was cancelled."""

RAW_BASES = ("bazaar", "urlhaus", "urlhaus:submit", "threatfox", "yaraify", "hunting")
"""The APIs that ``rawRequest`` can send JSON/form requests to."""


def _sha256File(path: str) -> str:
    """The SHA256 of a file, read in chunks."""

    sha = hashlib.sha256()
    with open(path, "rb") as fd:
        for byts in iter(lambda: fd.read(1024 * 1024), b""):
            sha.update(byts)
    return sha.hexdigest()


def parseThreatfox(byts: bytes, kind: str) -> list[dict]:
    """Parse a ThreatFox JSON export (zipped or not) into normalized IOCs."""

    if byts[:2] == b"PK":
        byts = b"\n".join(b for _, b in unzip(byts, password=None))
    try:
        data = json.loads(byts) if byts.strip() else {}
    except ValueError as err:
        raise AbuseChApiError(f"Unable to parse the ThreatFox {kind} export: {err}") from err
    return list(norm.normThreatFoxExport(data))


def _readThreatfox(path: str, kind: str) -> list[dict]:
    with open(path, "rb") as fd:
        return parseThreatfox(fd.read(), kind)


def urlhausReader(kind: str) -> tuple[tuple[str, ...], Any]:
    """The CSV columns and row normalizer of a URLhaus export."""

    if kind == "payloads":
        return norm.URLHAUS_PAYLOAD_CSV, norm.normUrlhausPayloadRow
    return URLHAUS_CSV, norm.normUrl


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

        # Bulk import jobs stage their files here, in the service's own storage. Any left over
        # from a previous run (ex. a restart mid-import) are removed.
        self.bulkdir = os.path.join(self.dirn, "tmp", "bulk")
        shutil.rmtree(self.bulkdir, ignore_errors=True)
        os.makedirs(self.bulkdir, exist_ok=True)
        self.bulkjobs: dict[str, dict] = {}
        self._bulkmodel = None
        self.schedCoro(self._bulkPruneLoop())

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

    async def maxSize(self) -> int:
        """The max size, in bytes, of a file downloaded from or submitted to abuse.ch."""

        return self.maxsize

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
        text = byts.decode("utf-8", "replace")
        # Retired datasets are replaced with a comment saying so (ex. SSLBL's IP lists).
        head = text[:2048]
        match = re.search(r"^#.*\bhas been deprecated\b.*$", head, re.MULTILINE | re.IGNORECASE)
        if match:
            raise AbuseChApiError(f"abuse.ch {base}: {path} {match.group(0).strip('# ').strip()}")
        return text

    async def _downloadBytes(self, base: str, path: str, apikey=None) -> bytes:
        """Download a dataset into memory (unzipped), with only a read timeout. For datasets of a few MB."""

        buf = io.BytesIO()
        await self.client.download(base, path, buf, apikey=self.getApiKey(apikey))
        byts = buf.getvalue()
        if byts[:2] == b"PK":
            byts = b"\n".join(b for _, b in unzip(byts, password=None))
        return byts

    @staticmethod
    def _fileLines(fd: Any, base: str, path: str) -> Iterator[str]:
        """Yield the lines of a downloaded dataset file, from inside it when it's a zip."""

        fd.seek(0)
        if fd.read(2) == b"PK":
            fd.seek(0)
            try:
                zfd = zipfile.ZipFile(fd)
            except zipfile.BadZipFile as err:
                raise AbuseChApiError(f"Unable to unzip {path}: {err}") from err
            names = [i.filename for i in zfd.infolist() if not i.is_dir()]
            streams = (
                io.TextIOWrapper(zfd.open(n), encoding="utf-8", errors="replace") for n in names
            )
        else:
            fd.seek(0)
            streams = iter([io.TextIOWrapper(fd, encoding="utf-8", errors="replace")])

        for stream in streams:
            for num, line in enumerate(stream):
                # Retired datasets are replaced with a comment saying so (ex. SSLBL's IP lists).
                if (
                    num < 20
                    and line.startswith("#")
                    and re.search(r"\bhas been deprecated\b", line, re.IGNORECASE)
                ):
                    raise AbuseChApiError(f"abuse.ch {base}: {path} {line.strip('#').strip()}")
                yield line.rstrip("\r\n")

    async def _csvRows(
        self, base: str, path: str, fields: tuple[str, ...], apikey=None
    ) -> AsyncIterator[dict]:
        """Stream the rows of a (possibly huge, possibly zipped) CSV dataset.

        The dataset is downloaded into a temporary file, then parsed line by line (from inside the
        zip, when it's zipped) with one CSV reader, so quoted fields that span lines parse correctly
        and exports of several GB never have to fit in memory.
        """

        with tempfile.TemporaryFile() as fd:
            await self.client.download(base, path, fd, apikey=self.getApiKey(apikey))
            for num, row in enumerate(norm.parseCsvLines(self._fileLines(fd, base, path), fields)):
                yield row
                if num % 1000 == 999:
                    await asyncio.sleep(0)

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
            raise AbuseChApiError(
                f"The download is {len(byts)} bytes, larger than the max of {self.maxsize}."
            )
        if byts[:2] != b"PK":
            raise AbuseChApiError(
                f"abuse.ch did not return a zip ({ctype or 'unknown content type'})."
            )
        return self._sample(unzip(byts, maxsize=self.maxsize))

    def _join(self, chunks: Iterable[bytes]) -> bytes:
        byts = b"".join(chunks)
        if len(byts) > self.maxsize:
            raise AbuseChApiError(
                f"The file is {len(byts)} bytes, larger than the max of {self.maxsize}."
            )
        return byts

    async def rawRequest(
        self,
        base: str,
        path: str = "",
        method: str = "post",
        form=None,
        json_data=None,
        params=None,
        apikey=None,
    ) -> Any:
        """Send an arbitrary request to an abuse.ch API and return its parsed JSON. An escape hatch."""

        if base not in RAW_BASES:
            raise AbuseChApiError(f"rawRequest only supports the {', '.join(RAW_BASES)} APIs.")
        if form is None and json_data is None and method.lower() == "post":
            form = {}
        return await self._query(
            base, path, apikey=apikey, method=method, form=form, json_data=json_data, params=params
        )

    # ---- MalwareBazaar ----

    async def bazaarQuery(self, query: str, fields: dict | None = None, apikey=None) -> dict | None:
        """POST a ``query`` (with any other form fields) to the MalwareBazaar API."""

        return await self._query("bazaar", apikey=apikey, form=dict(fields or {}, query=query))

    async def bazaarInfo(self, sha: str, apikey=None) -> dict | None:
        """``get_info`` - Everything MalwareBazaar knows about a sample (by MD5, SHA1, or SHA256)."""

        if hashType(sha) == "sha3_384":
            raise AbuseChApiError("MalwareBazaar lookups require an MD5, SHA1, or SHA256 hash.")
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

    async def normBazaarSearch(
        self, by: str, valu: str, limit: int = 100, apikey=None
    ) -> list[dict]:
        """Like ``bazaarSearch()`` but normalized."""

        return norm.normSamples(await self.bazaarSearch(by, valu, limit=limit, apikey=apikey))[
            : limit or None
        ]

    async def bazaarRecent(self, selector: str = "time", apikey=None) -> list:
        """``get_recent`` - The samples added in the last hour (``time``) or the latest 100 (``100``)."""

        if str(selector) not in ("time", "100"):
            raise AbuseChApiError("The get_recent selector must be 'time' or '100'.")
        return _data(
            await self.bazaarQuery("get_recent", {"selector": str(selector)}, apikey=apikey), []
        )

    async def normBazaarRecent(self, selector: str = "time", apikey=None) -> list[dict]:
        """Like ``bazaarRecent()`` but normalized."""

        return norm.normSamples(await self.bazaarRecent(selector, apikey=apikey))

    async def bazaarDetections(self, hours: int = 48, apikey=None) -> list:
        """``recent_detections`` - Samples with new detections in the last ``hours`` (1-168)."""

        hours = max(1, min(int(hours or 48), 168))
        return _data(
            await self.bazaarQuery("recent_detections", {"hours": hours}, apikey=apikey), []
        )

    async def normBazaarDetections(self, hours: int = 48, apikey=None) -> list[dict]:
        """Like ``bazaarDetections()`` but normalized."""

        return norm.normSamples(await self.bazaarDetections(hours, apikey=apikey))

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
        return await self._download(
            "bazaar",
            method="post",
            apikey=apikey,
            form={"query": "get_file", "sha256_hash": sha256.lower()},
        )

    async def bazaarUpload(
        self,
        chunks: list[bytes],
        name: str,
        anonymous: bool = False,
        tags: list | None = None,
        delivery_method: str | None = None,
        references: dict | None = None,
        context: dict | None = None,
        apikey=None,
    ) -> dict | None:
        """Submit a sample to MalwareBazaar.

        ``chunks`` are the file's bytes (in pieces, as read from an Axon).
        ``references`` and ``context`` are passed through as MalwareBazaar's
        ``references`` (ex. ``{"links": [...], "any_run": [...]}``) and ``context`` (ex.
        ``{"comment": ..., "dropped_by_sha256": [...]}``). Values other than comments are sent as lists.
        """

        def lists(valus: dict | None) -> dict | None:
            if not valus:
                return None
            return {
                k: v if k == "comment" else list(v) if isinstance(v, (list, tuple)) else [v]
                for k, v in valus.items()
                if v
            }

        body = {
            "anonymous": 1 if anonymous else 0,
            "tags": list(tags or []),
            "delivery_method": delivery_method,
            "references": lists(references),
            "context": lists(context),
        }
        body = {k: v for k, v in body.items() if v not in (None, [])}
        return await self._query(
            "bazaar",
            apikey=apikey,
            form={"json_data": json.dumps(body)},
            files={"file": (name or "sample", self._join(chunks))},
            notfound=False,
        )

    async def bazaarUpdate(self, sha256: str, key: str, valu: str, apikey=None) -> dict | None:
        """``update`` - Add a value to a sample you submitted. ``key`` is one of ``BAZAAR_UPDATE_KEYS``."""

        if key not in BAZAAR_UPDATE_KEYS:
            raise AbuseChApiError(
                f"Unknown MalwareBazaar update key {key}, use one of: {', '.join(BAZAAR_UPDATE_KEYS)}"
            )
        return await self._query(
            "bazaar",
            apikey=apikey,
            notfound=False,
            form={"query": "update", "sha256_hash": sha256.lower(), "key": key, "value": valu},
        )

    async def bazaarComment(self, sha256: str, comment: str, apikey=None) -> dict | None:
        """``add_comment`` - Comment on a sample."""

        return await self._query(
            "bazaar",
            apikey=apikey,
            notfound=False,
            form={"query": "add_comment", "sha256_hash": sha256.lower(), "comment": comment},
        )

    async def bazaarExport(
        self, kind: str = "recent", limit: int = 0, apikey=None
    ) -> AsyncIterator[dict]:
        """Yield normalized samples from a MalwareBazaar CSV export (see ``BAZAAR_EXPORTS``).

        The ``yara`` export yields normalized YARA rules instead.
        """

        if kind not in BAZAAR_EXPORTS:
            raise AbuseChApiError(f"Unknown MalwareBazaar export: {kind}")
        if kind == "yara":
            text = await self._fetchText("bazaar:export", BAZAAR_EXPORTS[kind], apikey=apikey)
            try:
                items = norm.normYaraStats(json.loads(text) if text.strip() else {})
            except ValueError as err:
                raise AbuseChApiError(
                    f"Unable to parse the MalwareBazaar YARA rule statistics: {err}"
                ) from err
            for count, rule in enumerate(items, start=1):
                yield rule
                if limit and count >= limit:
                    return
            return

        # The full export is hundreds of MB, so it's streamed.
        count = 0
        async for row in self._csvRows(
            "bazaar:export", BAZAAR_EXPORTS[kind], BAZAAR_CSV, apikey=apikey
        ):
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

    async def normUrlhausUrl(
        self, url: str | None = None, urlid: str | int | None = None, apikey=None
    ) -> dict | None:
        """Like ``urlhausUrl()``/``urlhausUrlId()`` but normalized."""

        if urlid is not None:
            data = await self.urlhausUrlId(urlid, apikey=apikey)
        else:
            data = await self.urlhausUrl(url, apikey=apikey)
        return norm.normUrl(data) if data else None

    async def urlhausHost(self, host: str, apikey=None) -> dict | None:
        """``/host/`` - Look up a host (FQDN or IPv4) and the URLs URLhaus has seen on it."""

        if ":" in host:
            raise AbuseChApiError("URLhaus host lookups only support FQDNs and IPv4 addresses.")
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
        return await self._query(
            "urlhaus", "payload/", apikey=apikey, form={f"{htype}_hash": sha.lower()}
        )

    async def normUrlhausPayload(self, sha: str, apikey=None) -> dict | None:
        """Like ``urlhausPayload()`` but normalized."""

        data = await self.urlhausPayload(sha, apikey=apikey)
        return norm.normUrlhausPayload(data) if data else None

    async def urlhausTag(self, tag: str, apikey=None) -> dict | None:
        """``/tag/`` - The URLs with a tag."""

        return await self._query("urlhaus", "tag/", apikey=apikey, form={"tag": tag})

    async def urlhausSignature(self, signature: str, apikey=None) -> dict | None:
        """``/signature/`` - The URLs (and payloads) for a malware signature."""

        return await self._query(
            "urlhaus", "signature/", apikey=apikey, form={"signature": signature}
        )

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
        if by == "signature":
            # Signature results don't repeat the signature on each payload.
            for url in urls:
                for pay in url["payloads"]:
                    if not pay["signature"]:
                        pay["signature"] = valu
                        pay["families"] = list(dict.fromkeys(norm.normTags(valu) + pay["families"]))
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

    async def normUrlhausRecent(
        self, kind: str = "urls", limit: int | None = None, apikey=None
    ) -> list[dict]:
        """Normalized ``urlhausRecentUrls()`` (``kind=urls``) or ``urlhausRecentPayloads()`` (``kind=payloads``)."""

        if kind == "urls":
            return norm.normUrls(
                (await self.urlhausRecentUrls(limit, apikey=apikey) or {}).get("urls")
            )
        if kind == "payloads":
            return norm.normSamples(
                (await self.urlhausRecentPayloads(limit, apikey=apikey) or {}).get("payloads")
            )
        raise AbuseChApiError(f"Unknown URLhaus recent list: {kind}")

    async def urlhausDownload(self, sha256: str, apikey=None) -> dict | None:
        """``/download/{sha256}/`` - Download a payload, returning ``{name, size, sha256, bytes}`` (unzipped)."""

        if hashType(sha256) != "sha256":
            raise AbuseChApiError("URLhaus downloads require a SHA256 hash.")
        return await self._download(
            "urlhaus", f"download/{_seg(sha256.lower())}/", method="get", apikey=apikey
        )

    async def urlhausSubmit(
        self,
        urls: list[str],
        threat: str = "malware_download",
        tags: list | None = None,
        anonymous: bool = False,
        apikey=None,
    ) -> str:
        """Report malware URLs to URLhaus. Returns URLhaus' response message."""

        body = {
            "anonymous": "1" if anonymous else "0",
            "submission": [{"url": u, "threat": threat, "tags": list(tags or [])} for u in urls],
        }
        byts, _ = await self._fetch("urlhaus:submit", method="post", apikey=apikey, json_data=body)
        return byts.decode("utf-8", "replace").strip()

    async def urlhausExport(
        self, kind: str = "recent", limit: int = 0, apikey=None
    ) -> AsyncIterator[dict]:
        """Yield normalized URLs from a URLhaus CSV export (see ``URLHAUS_EXPORTS``)."""

        if kind not in URLHAUS_EXPORTS:
            raise AbuseChApiError(f"Unknown URLhaus export: {kind}")
        # The payloads export is GBs, so the exports are streamed.
        fields, normrow = urlhausReader(kind)
        count = 0
        async for row in self._csvRows(
            "urlhaus:export", URLHAUS_EXPORTS[kind], fields, apikey=apikey
        ):
            url = normrow(row)
            if url:
                yield url
                count += 1
                if limit and count >= limit:
                    return

    # ---- ThreatFox ----

    async def threatfoxQuery(
        self, query: str, body: dict | None = None, apikey=None
    ) -> dict | None:
        """POST a ``query`` (with any other JSON fields) to the ThreatFox API."""

        return await self._query(
            "threatfox", apikey=apikey, json_data=dict(body or {}, query=query)
        )

    async def threatfoxRecent(self, days: int = 1, apikey=None) -> list:
        """``get_iocs`` - IOCs added in the last ``days`` (1-7)."""

        days = max(1, min(int(days), 7))
        return _data(await self.threatfoxQuery("get_iocs", {"days": days}, apikey=apikey), [])

    async def threatfoxIoc(self, iocid: int | str, apikey=None) -> dict | None:
        """``ioc`` - An IOC by its ThreatFox ID."""

        resp = await self.threatfoxQuery("ioc", {"id": int(iocid)}, apikey=apikey)
        # This query returns the IOC itself, without the usual {"query_status", "data"} wrapper.
        if resp and "data" not in resp and resp.get("ioc"):
            return {k: v for k, v in resp.items() if k != "query_status"}
        return _data(resp)

    async def threatfoxSearch(self, term: str, exact: bool = False, apikey=None) -> list:
        """``search_ioc`` - Search IOCs by value."""

        return _data(
            await self.threatfoxQuery(
                "search_ioc", {"search_term": term, "exact_match": bool(exact)}, apikey=apikey
            ),
            [],
        )

    async def threatfoxHash(self, sha: str, apikey=None) -> list:
        """``search_hash`` - IOCs associated with a malware sample (MD5 or SHA256)."""

        if hashType(sha) not in ("md5", "sha256"):
            raise AbuseChApiError("ThreatFox hash searches require an MD5 or SHA256 hash.")
        return _data(
            await self.threatfoxQuery("search_hash", {"hash": sha.lower()}, apikey=apikey), []
        )

    async def threatfoxTag(self, tag: str, limit: int = 100, apikey=None) -> list:
        """``taginfo`` - IOCs with a tag (max 1000)."""

        limit = max(1, min(int(limit or 1000), 1000))
        return _data(
            await self.threatfoxQuery("taginfo", {"tag": tag, "limit": limit}, apikey=apikey), []
        )

    async def threatfoxMalware(self, malware: str, limit: int = 100, apikey=None) -> list:
        """``malwareinfo`` - IOCs for a malware family (max 1000)."""

        limit = max(1, min(int(limit or 1000), 1000))
        return _data(
            await self.threatfoxQuery(
                "malwareinfo", {"malware": malware, "limit": limit}, apikey=apikey
            ),
            [],
        )

    async def normThreatfox(
        self, by: str, valu: Any = None, limit: int = 100, exact: bool = False, apikey=None
    ) -> list[dict]:
        """Normalized IOCs from any ThreatFox IOC query.

        ``by`` is ``recent`` (``valu`` is days), ``id``, ``search``, ``hash``, ``tag``, ``malware``,
        ``ip`` (IOCs for an IP, ex. its ``ip:port`` C2s), or ``file`` (IOCs associated with a sample,
        plus the sample's own hash IOC). ``limit`` 0 returns everything ThreatFox returns.
        """

        if by == "ip":
            # Exact searches only match whole IOC values, and IPs are listed as ip:port.
            ip = str(valu).strip()
            items = await self.threatfoxSearch(ip, exact=False, apikey=apikey)
            iocs = [
                i
                for i in norm.normIocs(items)
                if i["ioc"] == ip or (i["obs"] or {}).get("ip") == ip
            ]
            return iocs[:limit] if limit else iocs
        if by == "file":
            sha = str(valu).strip().lower()
            items = await self.threatfoxSearch(sha, exact=True, apikey=apikey)
            if hashType(sha) in ("md5", "sha256"):
                items = list(items) + list(await self.threatfoxHash(sha, apikey=apikey))
            iocs, ids = [], set()
            for ioc in norm.normIocs(items):
                if ioc["id"] not in ids:
                    ids.add(ioc["id"])
                    iocs.append(ioc)
            return iocs[:limit] if limit else iocs

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

        return _data(
            await self.threatfoxQuery(
                "get_label", {"malware": malware, "platform": platform}, apikey=apikey
            ),
            [],
        )

    async def threatfoxSubmit(
        self,
        threat_type: str,
        ioc_type: str,
        malware: str,
        iocs: list[str],
        confidence: int = 50,
        reference: str | None = None,
        comment: str | None = None,
        tags: list | None = None,
        anonymous: bool = False,
        compromised: bool = False,
        apikey=None,
    ) -> dict | None:
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
        return await self._query(
            "threatfox",
            apikey=apikey,
            notfound=False,
            json_data=dict({k: v for k, v in body.items() if v is not None}, query="submit_ioc"),
        )

    async def threatfoxExport(
        self, kind: str = "recent", limit: int = 0, apikey=None
    ) -> AsyncIterator[dict]:
        """Yield normalized IOCs from a ThreatFox JSON export (see ``THREATFOX_EXPORTS``)."""

        if kind not in THREATFOX_EXPORTS:
            raise AbuseChApiError(f"Unknown ThreatFox export: {kind}")
        # A few MB, downloaded with a read timeout only, since slow links take longer than the request timeout.
        byts = await self._downloadBytes("threatfox:export", THREATFOX_EXPORTS[kind], apikey=apikey)
        iocs = await asyncio.to_thread(parseThreatfox, byts, kind)
        for count, ioc in enumerate(iocs, start=1):
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
        return _data(
            await self.yaraifyQuery(
                "lookup_hash", {k: v for k, v in body.items() if v}, apikey=apikey
            )
        )

    async def normYaraifyHash(
        self, sha: str, malpedia: str | None = None, apikey=None
    ) -> dict | None:
        """Like ``yaraifyHash()`` but normalized."""

        data = await self.yaraifyHash(sha, malpedia=malpedia, apikey=apikey)
        return norm.normYaraifyFile(data) if isinstance(data, dict) else None

    async def yaraifySearch(self, by: str, valu: str, limit: int = 25, apikey=None) -> list:
        """Search YARAify files. ``by`` is one of ``YARAIFY_SEARCHES``."""

        if by not in YARAIFY_SEARCHES:
            raise AbuseChApiError(f"Unknown YARAify search: {by}")
        # result_max is capped at 1000, larger values are silently treated as the default (25).
        body = {"search_term": valu, "result_max": max(1, min(int(limit or 1000), 1000))}
        data = _data(await self.yaraifyQuery(YARAIFY_SEARCHES[by], body, apikey=apikey), [])
        return data if isinstance(data, list) else norm.lst(data)

    async def normYaraifySearch(
        self, by: str, valu: str, limit: int = 25, apikey=None
    ) -> list[dict]:
        """Like ``yaraifySearch()`` but normalized."""

        items = await self.yaraifySearch(by, valu, limit=limit, apikey=apikey)
        files = [norm.normYaraifyFile(i) for i in items if isinstance(i, dict)]
        files = [f for f in files if f]
        # Files from a YARA search matched that rule, even if the result doesn't say so.
        # Likewise files from a ClamAV search matched that signature.
        if by == "yara":
            for file in files:
                if valu not in {r["name"] for r in file["rules"]}:
                    file["rules"].append(norm.normRule({"rule_name": valu}))
        elif by == "clamav":
            for file in files:
                if valu not in file["clamav"]:
                    file["clamav"].append(valu)
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

        resp = await self._query(
            "yaraify",
            apikey=apikey,
            notfound=False,
            json_data={"query": "delete_yara_rule", "yarahub_uuid": uuid},
        )
        return _data(resp, (resp or {}).get("query_status"))

    async def yaraifyResults(self, task_id: str, malpedia: str | None = None, apikey=None) -> Any:
        """``get_results`` - The results of a scan task, or ``"queued"`` while it's still running."""

        body = {"task_id": task_id, "malpedia-token": malpedia}
        try:
            return _data(
                await self.yaraifyQuery(
                    "get_results", {k: v for k, v in body.items() if v}, apikey=apikey
                )
            )
        except AbuseChApiError as err:
            # Unknown tasks come back as {"query_status": "error", "data": "unknown_task_id"}.
            if "unknown_task_id" in err.mesg:
                return None
            raise

    async def normYaraifyResults(
        self, task_id: str, malpedia: str | None = None, apikey=None
    ) -> dict | None:
        """Like ``yaraifyResults()`` but normalized: ``{status, task_id, file}``."""

        data = await self.yaraifyResults(task_id, malpedia=malpedia, apikey=apikey)
        if data is None:
            return None
        if not isinstance(data, dict):
            return {"status": str(data), "task_id": task_id, "file": None}
        return {"status": "done", "task_id": task_id, "file": norm.normYaraifyFile(data)}

    async def yaraifyTasks(self, identifier: str, status: str = "processed", apikey=None) -> list:
        """``list_tasks`` - The tasks submitted with an identifier (``queued``, ``processed``, or None for all)."""

        body = {"identifier": identifier, "task_status": status}
        data = _data(
            await self.yaraifyQuery(
                "list_tasks", {k: v for k, v in body.items() if v}, apikey=apikey
            ),
            [],
        )
        # No matches come back as {"query_status": "ok", "data": "no results"}.
        return data if isinstance(data, list) else []

    async def normYaraifyTasks(
        self, identifier: str, status: str = "processed", apikey=None
    ) -> list[dict]:
        """Like ``yaraifyTasks()`` but normalized."""

        tasks = (
            norm.normTask(t) for t in await self.yaraifyTasks(identifier, status, apikey=apikey)
        )
        return [t for t in tasks if t]

    async def yaraifyIdentifier(self, apikey=None) -> Any:
        """``generate_identifier`` - Generate a new (private) identifier to track scans with."""

        return _data(await self.yaraifyQuery("generate_identifier", apikey=apikey))

    async def yaraifyRescan(self, sha: str, apikey=None) -> Any:
        """``rescan_file`` - Rescan a known file. Returns ``{task_id}``."""

        hashType(sha)
        return _data(await self.yaraifyQuery("rescan_file", {"hash": sha.lower()}, apikey=apikey))

    async def yaraifyScan(
        self,
        chunks: list[bytes],
        name: str,
        identifier: str | None = None,
        clamav_scan: bool = True,
        unpack: bool = False,
        share_file: bool = False,
        skip_known: bool = False,
        skip_noisy: bool = False,
        apikey=None,
    ) -> Any:
        """Submit a file to YARAify for scanning. Returns ``{task_id}``."""

        opts = {
            "identifier": identifier,
            "clamav_scan": int(bool(clamav_scan)),
            "unpack": int(bool(unpack)),
            "share_file": int(bool(share_file)),
            "skip_known": int(bool(skip_known)),
            "skip_noisy": int(bool(skip_noisy)),
        }
        resp = await self._query(
            "yaraify",
            apikey=apikey,
            notfound=False,
            form={"json_data": json.dumps({k: v for k, v in opts.items() if v is not None})},
            files={"file": (name or "sample", self._join(chunks))},
        )
        return _data(resp)

    async def yaraifyDeploy(self, text: str, name: str = "rule.yar", apikey=None) -> Any:
        """Deploy a YARA rule to YARAify for live hunting."""

        resp = await self._query(
            "yaraify",
            apikey=apikey,
            form={},
            notfound=False,
            files={"yara_file": (name, text.encode("utf-8"))},
        )
        return _data(resp, (resp or {}).get("query_status"))

    async def yaraifyRule(self, uuid: str, apikey=None) -> list[dict]:
        """``get_yara_rule`` - Download a YARAhub rule by its UUID, returning the normalized rule(s)."""

        byts, _ = await self._fetch(
            "yaraify",
            method="post",
            apikey=apikey,
            json_data={"query": "get_yara_rule", "uuid": uuid},
        )
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
        return await self._download(
            "yaraify",
            method="post",
            apikey=apikey,
            json_data={"query": "get_file", "sha256_hash": sha256.lower()},
        )

    async def yaraifyUnpacked(self, sha256: str, apikey=None) -> dict | None:
        """``get_unpacked`` - Download a file YARAify unpacked, returning ``{name, size, sha256, bytes}`` (unzipped)."""

        if hashType(sha256) != "sha256":
            raise AbuseChApiError("YARAify downloads require a SHA256 hash.")
        return await self._download(
            "yaraify",
            method="post",
            apikey=apikey,
            json_data={"query": "get_unpacked", "sha256_hash": sha256.lower()},
        )

    async def yaraifyRulesExport(self, limit: int = 0, apikey=None) -> AsyncIterator[dict]:
        """Yield every TLP:CLEAR YARAhub rule, normalized, from YARAify's rule export."""

        buf = io.BytesIO()
        await self.client.download(
            "yaraify:export", "yarahub/yaraify-rules.zip", buf, apikey=self.getApiKey(apikey)
        )
        byts = buf.getvalue()
        files = unzip(byts, password=None) if byts[:2] == b"PK" else [("rules.yar", byts)]
        count = 0
        for _, rbyts in files:
            for rule in norm.parseYara(rbyts.decode("utf-8", "replace")):
                yield rule
                count += 1
                if limit and count >= limit:
                    return

    # ---- Feodo Tracker ----

    async def feodoBlocklist(
        self, kind: str = "all", limit: int = 0, apikey=None
    ) -> AsyncIterator[dict]:
        """Yield normalized C2 servers from a Feodo Tracker blocklist (see ``FEODO_BLOCKLISTS``)."""

        if kind not in FEODO_BLOCKLISTS:
            raise AbuseChApiError(f"Unknown Feodo Tracker blocklist: {kind}")

        if kind == "aggressive":
            text = await self._fetchText("feodo", FEODO_BLOCKLISTS[kind], apikey=apikey)
            items = (norm.normFeodo(r) for r in norm.parseCsv(text, norm.FEODO_CSV))
        else:
            text = await self._fetchText("feodo", FEODO_BLOCKLISTS[kind], apikey=apikey)
            try:
                rows = json.loads(text) if text.strip() else []
            except ValueError as err:
                raise AbuseChApiError(
                    f"Unable to parse the Feodo Tracker blocklist: {err}"
                ) from err
            items = [norm.normFeodo(r) for r in norm.lst(rows)]

        count = 0
        for item in items:
            if item:
                yield item
                count += 1
                if limit and count >= limit:
                    return

    # ---- SSL Blacklist ----

    async def sslblBlocklist(
        self, kind: str = "certs", limit: int = 0, apikey=None
    ) -> AsyncIterator[dict]:
        """Yield normalized entries from an SSL Blacklist blocklist (see ``SSLBL_BLOCKLISTS``).

        ``certs`` yields certs and ``ja3`` yields JA3 fingerprints.
        """

        if kind not in SSLBL_BLOCKLISTS:
            raise AbuseChApiError(f"Unknown SSL Blacklist blocklist: {kind}")
        text = await self._fetchText("sslbl", SSLBL_BLOCKLISTS[kind], apikey=apikey)

        if kind == "certs":
            items = (norm.normSslblCert(r) for r in norm.parseCsv(text, norm.SSLBL_CERT_CSV))
        else:
            items = (norm.normJa3(r) for r in norm.parseCsv(text, norm.SSLBL_JA3_CSV))

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

        resp = await self._query(
            "hunting", apikey=apikey, json_data={"query": "get_fplist", "format": "json"}
        )
        if resp is None:
            return {}
        # The list is the response itself (a dict keyed by entry ID), not wrapped in "data".
        if "data" in resp:
            return _data(resp, {})
        return {k: v for k, v in resp.items() if k != "query_status"}

    async def normFplist(self, platform: str | None = None, apikey=None) -> list[dict]:
        """Like ``fplist()`` but normalized, optionally only the entries for one platform."""

        fps = norm.normFpList(await self.fplist(apikey=apikey))
        if platform:
            platform = norm.normTag(platform)
            fps = [f for f in fps if f["platform"] == platform]
        return fps

    # ---- Bulk imports ----
    #
    # A bulk import moves an export through these steps, driven by the slib.abusech.priv.bulk
    # Storm module: bulkPull() streams the export into the Cortex's Axon; bulkStart() and
    # bulkStage() copy it from the Axon into a job dir in the service's storage; bulkBuild()
    # turns its records into a syn.nodes .nodes file (see abusechsvc.bulk); bulkNodes() streams
    # that file back into the Axon, where the Cortex ingests it; and bulkDone() removes the job.

    def _bulkExport(self, plat: str, kind: str) -> tuple[str, str]:
        info = BULK_EXPORTS.get((plat, kind))
        if info is None:
            raise AbuseChApiError(f"The {plat} {kind} export can't be bulk imported.")
        return info

    def _bulkJob(self, jobid: str) -> dict:
        job = self.bulkjobs.get(jobid)
        if job is None:
            raise AbuseChApiError(f"Unknown bulk import job: {jobid}")
        job["touched"] = s_common.now()
        return job

    def _bulkPrune(self, idle: int = BULK_IDLE) -> list[str]:
        """Remove jobs untouched for ``idle`` ms. The Storm side removes its job when it finishes or
        fails, but not when it's cancelled (ex. a killed background query). Returns the removed job IDs."""

        cutoff = s_common.now() - idle
        stale = [jobid for jobid, job in self.bulkjobs.items() if job["touched"] < cutoff]
        for jobid in stale:
            job = self.bulkjobs.pop(jobid)
            shutil.rmtree(job["dirn"], ignore_errors=True)
            logger.warning(
                "Removed the idle %s %s bulk import job %s", job["plat"], job["kind"], jobid
            )
        return stale

    async def _bulkPruneLoop(self) -> None:
        while not await self.waitfini(timeout=600):
            self._bulkPrune()

    async def bulkExports(self) -> list[list[str]]:
        """The (platform, kind) of every export that can be bulk imported."""

        return [list(k) for k in BULK_EXPORTS]

    async def bulkPull(self, plat: str, kind: str, apikey=None) -> AsyncIterator[bytes]:
        """Stream an export's raw bytes (as abuse.ch serves them, zipped or not), to save in an Axon."""

        base, path = self._bulkExport(plat, kind)
        async for byts in self.client.stream(base, path, apikey=self.getApiKey(apikey)):
            yield byts

    async def bulkStart(self, plat: str, kind: str, sha256: str) -> str:
        """Start a bulk import job for an export file (by its SHA256 in the Axon). Returns the job ID."""

        self._bulkExport(plat, kind)
        if norm.lower(sha256) is None or not norm.isHex(sha256, 64):
            raise AbuseChApiError(f"Not a SHA256 hash: {sha256}")
        jobid = s_common.guid()
        dirn = os.path.join(self.bulkdir, jobid)
        os.makedirs(dirn)
        self.bulkjobs[jobid] = {
            "plat": plat,
            "kind": kind,
            "sha256": sha256.lower(),
            "dirn": dirn,
            "source": os.path.join(dirn, "source"),
            "nodes": os.path.join(dirn, "export.nodes"),
            "size": 0,
            "started": s_common.now(),
            "touched": s_common.now(),
        }
        return jobid

    async def bulkStage(self, jobid: str, byts: bytes) -> int:
        """Append a chunk of the export file (read from the Axon) to the job's copy. Returns the size so far."""

        job = self._bulkJob(jobid)
        with open(job["source"], "ab") as fd:  # noqa: ASYNC230 - a small append per chunk
            fd.write(byts)
        job["size"] += len(byts)
        return job["size"]

    def _bulkRecords(self, job: dict, fd: Any) -> Iterator[tuple[str, dict | None]]:
        """Yield (record type, normalized record) for each row of a staged CSV export file."""

        plat, kind = job["plat"], job["kind"]
        base, path = BULK_EXPORTS[(plat, kind)]
        lines = self._fileLines(fd, base, path)
        if plat == "bazaar":
            for row in norm.parseCsvLines(lines, BAZAAR_CSV):
                yield "sample", norm.normSample(row)
        else:
            fields, normrow = urlhausReader(kind)
            for row in norm.parseCsvLines(lines, fields):
                yield "url", normrow(row)

    async def bulkBuild(
        self, jobid: str, prefix: str | None = None, batch: int = BULK_BATCH
    ) -> AsyncIterator[dict]:
        """Build the nodes for a staged export into the job's .nodes file, yielding progress.

        ``prefix`` is the tag prefix (null when tagging is disabled). Yields
        ``{"rows", "nodes"}`` after each batch, then ``{"done": True, "rows", "skipped", "nodes",
        "size", "builder", "seconds"}``.
        """

        job = self._bulkJob(jobid)

        # Hashing a multi-GB file in a thread keeps the service responsive.
        sha256 = await asyncio.to_thread(_sha256File, job["source"])
        if sha256 != job["sha256"]:
            raise AbuseChApiError(
                f"The staged file's SHA256 {sha256} doesn't match {job['sha256']}."
            )

        if self._bulkmodel is None:
            self._bulkmodel = bulk.buildModel()
        builder = bulk.NodeBuilder(self._bulkmodel, prefix)

        start = time.monotonic()
        rows = skipped = count = 0
        plat = job["plat"]

        # ThreatFox exports are one JSON document, parsed in a thread to keep the service responsive.
        iocs = None
        if plat == "threatfox":
            iocs = await asyncio.to_thread(_readThreatfox, job["source"], job["kind"])

        with open(job["nodes"], "wb") as out:  # noqa: ASYNC230 - written a batch at a time

            def write(nodes):
                out.writelines(s_msgpack.en(nodedef) for nodedef in nodes)
                return len(nodes)

            with open(job["source"], "rb") as fd:  # noqa: ASYNC230 - read a record at a time
                records = (
                    (("ioc", ioc) for ioc in iocs)
                    if iocs is not None
                    else self._bulkRecords(job, fd)
                )
                for rtype, rec in records:
                    rows += 1
                    if rtype == "sample":
                        ndef = builder.sample(rec, plat)
                    elif rtype == "url":
                        ndef = builder.url(rec, plat)
                    else:
                        ndef = builder.ioc(rec, plat)
                    if ndef is None:
                        skipped += 1

                    if rows % batch == 0:
                        count += write(builder.flush())
                        job["touched"] = s_common.now()
                        yield {"rows": rows, "nodes": count}
                    if rows % 100 == 0:
                        await asyncio.sleep(0)

            count += write(builder.finish())

        yield {
            "done": True,
            "rows": rows,
            "skipped": skipped,
            "nodes": count,
            "size": os.path.getsize(job["nodes"]),
            "builder": bulk.BUILDER_VERSION,
            "seconds": round(time.monotonic() - start, 1),
        }

    async def bulkNodes(self, jobid: str, chunk: int = 1024 * 1024) -> AsyncIterator[bytes]:
        """Stream a job's .nodes file, to save in an Axon."""

        job = self._bulkJob(jobid)
        with open(job["nodes"], "rb") as fd:  # noqa: ASYNC230 - read a chunk at a time
            for byts in iter(lambda: fd.read(chunk), b""):
                job["touched"] = s_common.now()
                yield byts
                await asyncio.sleep(0)

    async def bulkDone(self, jobid: str) -> bool:
        """Remove a job and its files."""

        job = self.bulkjobs.pop(jobid, None)
        if job is not None:
            shutil.rmtree(job["dirn"], ignore_errors=True)
        return True
