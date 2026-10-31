"""Download and unpack open source Snort rule feeds.

A feed is a URL serving Snort rules, either a plain ``.rules`` file or an archive (``.tar.gz``,
``.tar``, ``.zip``, or ``.gz``) of them. Every ``*.rules`` file in an archive is read, except those
matching one of the feed's ``exclude`` patterns.
"""

import fnmatch
import gzip
import hashlib
import io
import os
import re
import tarfile
import zipfile
from collections.abc import Iterator
from typing import Any, TypedDict

import aiohttp
import synapse.common as s_common

from . import rules as s_rules


class FeedError(Exception):
    """Raised when a feed can't be downloaded or unpacked."""

    def __init__(self, mesg: str) -> None:
        super().__init__(mesg)
        self.mesg = mesg


class FeedDef(TypedDict):
    """The definition of a rule feed."""

    name: str
    url: str
    engine: int
    enabled: bool
    exclude: list[str]
    desc: str


DEFAULT_FEEDS: tuple[FeedDef, ...] = (
    FeedDef(
        name="snort3-community",
        url="https://www.snort.org/downloads/community/snort3-community-rules.tar.gz",
        engine=s_rules.ENGINE_SNORT3,
        enabled=True,
        exclude=[],
        desc="The Snort 3 Community Ruleset from Cisco Talos (GPLv2).",
    ),
    FeedDef(
        name="et-open",
        url="https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz",
        engine=s_rules.ENGINE_SNORT2,
        enabled=True,
        exclude=["emerging-deleted.rules"],
        desc="The Proofpoint Emerging Threats Open ruleset (BSD/GPLv2), Snort 2.9 syntax.",
    ),
)
"""The feeds a new service starts with. Admins can add, change, disable, or remove feeds."""

FEED_NAME_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-_.")


def normFeed(fdef: dict[str, Any]) -> FeedDef:
    """Validate and normalize a feed definition (filling in defaults).

    Raises
    ------
    FeedError
        If the definition is invalid.
    """

    name = str(fdef.get("name") or "").strip().lower()
    if not name or not set(name) <= FEED_NAME_CHARS:
        raise FeedError(
            f"Invalid feed name {name!r}, use lowercase letters, numbers, '-', '_', and '.'."
        )

    url = str(fdef.get("url") or "").strip()
    if not url.startswith(("https://", "http://")):
        raise FeedError(f"Invalid feed URL {url!r}, it must be an http(s) URL.")

    engine = fdef.get("engine", s_rules.ENGINE_SNORT3)
    try:
        engine = int(engine)
    except (TypeError, ValueError):
        engine = None
    if engine not in s_rules.ENGINES:
        raise FeedError(
            f"Invalid feed engine {fdef.get('engine')!r}, use one of: "
            f"{', '.join(map(str, s_rules.ENGINES))}."
        )

    exclude = fdef.get("exclude") or []
    if isinstance(exclude, str):
        exclude = [exclude]

    return FeedDef(
        name=name,
        url=url,
        engine=engine,
        enabled=bool(fdef.get("enabled", True)),
        exclude=[str(e) for e in exclude],
        desc=str(fdef.get("desc") or ""),
    )


def _wanted(path: str, exclude: list[str]) -> bool:
    base = os.path.basename(path)
    if not base.endswith(".rules"):
        return False
    return not any(fnmatch.fnmatch(base, pat) or fnmatch.fnmatch(path, pat) for pat in exclude)


def _read(fobj: Any, size: int, maxsize: int, total: list[int]) -> bytes:
    total[0] += size
    if total[0] > maxsize:
        raise FeedError(f"The feed unpacks to more than the max size of {maxsize} bytes.")
    return fobj.read()


def unpack(
    byts: bytes, exclude: list[str] | None = None, maxsize: int = 512 * 1024 * 1024
) -> Iterator[tuple[str, str]]:
    """Yield (file name, text) of every rules file in a downloaded feed.

    Archives are read in memory, nothing is written to disk.

    Raises
    ------
    FeedError
        If the archive is corrupt or unpacks to more than ``maxsize`` bytes.
    """

    exclude = exclude or []
    total = [0]

    try:
        if byts[:2] == b"\x1f\x8b":
            fobj = io.BytesIO(byts)
            if tarfile.is_tarfile(fobj):
                fobj.seek(0)
                yield from _untar(fobj, exclude, maxsize, total)
                return
            with gzip.open(io.BytesIO(byts)) as gz:
                byts = gz.read(maxsize + 1)
            if len(byts) > maxsize:
                raise FeedError(f"The feed unpacks to more than the max size of {maxsize} bytes.")

        if byts[:4] == b"PK\x03\x04":
            with zipfile.ZipFile(io.BytesIO(byts)) as zfd:
                for info in zfd.infolist():
                    if info.is_dir() or not _wanted(info.filename, exclude):
                        continue
                    with zfd.open(info) as member:
                        yield (
                            info.filename,
                            _read(member, info.file_size, maxsize, total).decode(
                                "utf-8", errors="replace"
                            ),
                        )
            return

        fobj = io.BytesIO(byts)
        if len(byts) > 512 and tarfile.is_tarfile(fobj):
            fobj.seek(0)
            yield from _untar(fobj, exclude, maxsize, total)
            return
    except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError) as err:
        raise FeedError(f"Unable to unpack the feed: {err}") from err

    yield "feed.rules", byts.decode("utf-8", errors="replace")


def _untar(
    fobj: Any, exclude: list[str], maxsize: int, total: list[int]
) -> Iterator[tuple[str, str]]:
    with tarfile.open(fileobj=fobj) as tfd:
        for member in tfd:
            if not member.isfile() or not _wanted(member.name, exclude):
                continue
            extracted = tfd.extractfile(member)
            if extracted is None:
                continue
            yield (
                member.name,
                _read(extracted, member.size, maxsize, total).decode("utf-8", errors="replace"),
            )


def ruleGuid(feed: str, gid: int, sid: int) -> str:
    """The deterministic ``it:app:snort:rule`` guid of a feed's rule."""

    return s_common.guid(("slib.snort.rule", feed, gid, sid))


def rulesetGuid(feed: str) -> str:
    """The deterministic ``meta:ruleset`` guid of a feed."""

    return s_common.guid(("slib.snort.ruleset", feed))


def parseFeed(fdef: FeedDef, byts: bytes, maxsize: int) -> dict[str, Any]:
    """Parse a downloaded feed into the records Storm models as ``it:app:snort:rule`` nodes.

    A sid that appears more than once in a feed (ex. in two files) keeps the highest rev.

    Returns
    -------
    dict
        ``rules`` - the rule records, ``errors`` - (file, line, error) of rules that couldn't
        be parsed, ``files`` - the rules files read.
    """

    found: dict[tuple[int, int], dict[str, Any]] = {}
    errors = []
    files = []
    for fname, text in unpack(byts, exclude=fdef["exclude"], maxsize=maxsize):
        files.append(fname)
        for rule, lineno, err in s_rules.parseRules(text):
            if rule is None:
                errors.append((fname, lineno, err))
                continue
            key = (rule["gid"], rule["sid"])
            prev = found.get(key)
            if prev is not None and prev["rev"] > rule["rev"]:
                continue
            found[key] = ruleRecord(fdef, rule, fname)

    if not files:
        raise FeedError("The feed has no .rules files.")

    return {"rules": list(found.values()), "errors": errors, "files": files}


def ruleRecord(fdef: FeedDef, rule: s_rules.Rule, fname: str | None = None) -> dict[str, Any]:
    """The record Storm models for one of a feed's rules."""

    return {
        "guid": ruleGuid(fdef["name"], rule["gid"], rule["sid"]),
        "id": s_rules.ruleId(rule),
        "gid": rule["gid"],
        "sid": rule["sid"],
        "rev": rule["rev"],
        "engine": fdef["engine"],
        "text": rule["text"],
        "enabled": rule["enabled"],
        "msg": rule["msg"],
        "classtype": rule["classtype"],
        "refs": rule["refs"],
        "family": rule["family"],
        "created": rule["created"],
        "updated": rule["updated"],
        "file": os.path.basename(fname) if fname else None,
    }


_CVE = re.compile(r"^(?:cve-)?(\d{4}-\d{4,})$", re.IGNORECASE)
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_URLHOST = re.compile(
    r"^[a-z][a-z0-9+.-]*://"
    r"(?:\[[0-9a-f:.]+\]|\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9_-]+(?:\.[a-z0-9_-]+)*\.[a-z][a-z0-9-]*)"
    # Synapse reads the host up to the first "/".
    r"(?::\d{1,5})?(?:/\S*)?$",
    re.IGNORECASE,
)


def refUrl(valu: str) -> str | None:
    """A rule's URL reference as a URL (http:// if it has no scheme), or None if it's malformed.

    Feeds have typos Synapse can't model as an inet:url (ex. "url,example.com/x" or
    "www,example.com"), those are skipped.
    """

    valu = valu.strip()
    while valu.lower().startswith("url,"):
        valu = valu[4:].strip()
    if not _SCHEME.match(valu):
        valu = f"http://{valu}"
    if not _URLHOST.match(valu):
        return None
    return valu


def refEdges(refs: list[list[str]]) -> list[tuple[str, tuple[str, str]]]:
    """The light edges (verb, ndef) for a rule's references (see slib.snort.model.refs).

    CVEs the rule detects, and the URLs and hashes it refers to. Malformed values are skipped.
    """

    edges = []
    for scheme, valu in refs:
        valu = str(valu).strip()
        if scheme == "cve" and (match := _CVE.match(valu)):
            edges.append(("detects", ("it:sec:cve", f"cve-{match.group(1)}".lower())))
        elif scheme == "url" and (url := refUrl(valu)):
            edges.append(("refs", ("inet:url", url)))
        elif (
            scheme in ("md5", "sha256")
            and _HEX.match(valu)
            and len(valu) == (32 if scheme == "md5" else 64)
        ):
            edges.append(("refs", (f"hash:{scheme}", valu.lower())))
    return edges


def ruleNodeDef(rec: dict[str, Any]) -> tuple[tuple[str, str], dict[str, Any]]:
    """A syn.nodes node definition for a feed's rule record, for bulk ingest of new rules."""

    props: dict[str, Any] = {
        "id": rec["id"],
        "text": rec["text"],
        "engine": rec["engine"],
        "version": str(rec["rev"]),
        "enabled": rec["enabled"],
    }
    for prop, key in (
        ("name", "msg"),
        ("family", "family"),
        ("created", "created"),
        ("updated", "updated"),
    ):
        if rec.get(key) is not None:
            props[prop] = rec[key]
    return (("it:app:snort:rule", rec["guid"]), {"props": props, "edges": refEdges(rec["refs"])})


async def download(
    session: aiohttp.ClientSession,
    url: str,
    maxsize: int,
    timeout: float,
    etag: str | None = None,
    modified: str | None = None,
) -> dict[str, Any]:
    """Download a feed.

    ``etag`` and ``modified`` (from a previous download) make the request conditional.

    Returns
    -------
    dict
        ``status`` (the HTTP status, 304 if the feed is unchanged), ``byts`` (None if unchanged),
        ``sha256``, ``etag``, and ``modified``.

    Raises
    ------
    FeedError
        On a request error, a non 200/304 response, or a feed larger than ``maxsize``.
    """

    headers = {}
    if etag:
        headers["If-None-Match"] = etag
    if modified:
        headers["If-Modified-Since"] = modified

    try:
        async with session.get(
            url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)
        ) as resp:
            if resp.status == 304:
                return {
                    "status": 304,
                    "byts": None,
                    "sha256": None,
                    "etag": etag,
                    "modified": modified,
                }
            if resp.status != 200:
                raise FeedError(f"Downloading {url} failed with HTTP {resp.status}.")

            buf = io.BytesIO()
            async for chunk in resp.content.iter_chunked(1024 * 1024):
                buf.write(chunk)
                if buf.tell() > maxsize:
                    raise FeedError(
                        f"The feed at {url} is larger than the max size of {maxsize} bytes."
                    )
            byts = buf.getvalue()
            return {
                "status": 200,
                "byts": byts,
                "sha256": hashlib.sha256(byts).hexdigest(),
                "etag": resp.headers.get("ETag"),
                "modified": resp.headers.get("Last-Modified"),
            }
    except (aiohttp.ClientError, TimeoutError) as err:
        raise FeedError(f"Downloading {url} failed: {err or type(err).__name__}") from err
