"""Download and unpack rule feeds (Snort 2.x, Snort 3, and Suricata).

A feed is a URL serving rules for one engine, either a plain ``.rules`` file or an archive
(``.tar.gz``, ``.tar``, ``.zip``, or ``.gz``) of them. Every ``*.rules`` file in an archive is
read, except those matching one of the feed's ``exclude`` patterns.

A feed's URL can reference secrets, ex. a Talos oinkcode, as ``${name}``. Secrets are only in the
service's config (``pcap:feeds:secrets``), so Storm users never see them, and URLs are shown with
the placeholders (see ``feedUrl``).
"""

import fnmatch
import gzip
import hashlib
import io
import os
import re
import tarfile
import urllib.parse
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
    engine: str
    enabled: bool
    exclude: list[str]
    desc: str


def _abusech(name: str, url: str, desc: str) -> FeedDef:
    return FeedDef(
        name=name,
        url=url,
        engine=s_rules.ENGINE_SURICATA,
        enabled=False,
        exclude=[],
        desc=f"{desc} from abuse.ch (CC0), Suricata syntax. Off by default.",
    )


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
        url="https://rules.emergingthreats.net/open/suricata-8.0/emerging.rules.tar.gz",
        engine=s_rules.ENGINE_SURICATA,
        enabled=True,
        exclude=["emerging-deleted.rules"],
        desc="The Proofpoint Emerging Threats Open ruleset (MIT), Suricata 8 syntax.",
    ),
    _abusech(
        "abusech-sslbl",
        "https://sslbl.abuse.ch/blacklist/sslblacklist_tls_cert.tar.gz",
        "The SSL Blacklist (malicious TLS certificates)",
    ),
    _abusech(
        "abusech-sslbl-c2",
        "https://sslbl.abuse.ch/blacklist/sslipblacklist.tar.gz",
        "The SSL Blacklist botnet C2 IPs",
    ),
    _abusech(
        "abusech-feodo",
        "https://feodotracker.abuse.ch/downloads/feodotracker.tar.gz",
        "The Feodo Tracker botnet C2 IPs",
    ),
    _abusech(
        "abusech-urlhaus",
        "https://urlhaus.abuse.ch/downloads/urlhaus_suricata.tar.gz",
        "The URLhaus malware URLs",
    ),
)
"""The feeds a new service starts with. Admins can add, change, disable, or remove feeds.

Talos Registered and Subscriber rules need an oinkcode and have their own license terms, add
them with a URL that references the oinkcode as a secret (see the README)."""

_SECRET = re.compile(r"\$\{([a-zA-Z0-9_.:-]+)\}")


def hostAllowed(host: str, patterns: list[str]) -> bool:
    """Whether a host matches one of a secret's hosts, ex. ``snort.org`` or ``*.snort.org``."""

    host = (host or "").lower().rstrip(".")
    for pattern in patterns:
        pattern = str(pattern).lower().rstrip(".")
        if pattern.startswith("*."):
            if host.endswith(pattern[1:]):
                return True
        elif host == pattern:
            return True
    return False


def feedUrl(url: str, secrets: dict[str, dict] | None = None) -> str:
    """A feed's URL with its ``${name}`` secrets filled in.

    Each secret is ``{"value": ..., "hosts": [...]}`` and is only sent to its hosts, so a feed
    URL (which Cortex admins set) can't send it anywhere else.

    Raises
    ------
    FeedError
        If the URL references a secret that isn't in the service's config, or that isn't
        allowed to be sent to the URL's host.
    """

    secrets = secrets or {}
    host = urllib.parse.urlsplit(_SECRET.sub("x", url)).hostname or ""

    def fill(match: re.Match) -> str:
        name = match.group(1)
        secret = secrets.get(name)
        if not isinstance(secret, dict) or "value" not in secret:
            raise FeedError(
                f"The feed's URL needs the secret ${{{name}}}, set it in the "
                'service\'s pcap:feeds:secrets config as {"value": ..., "hosts": [...]}.'
            )
        if not hostAllowed(host, secret.get("hosts") or []):
            raise FeedError(f"The secret ${{{name}}} isn't allowed to be sent to {host}.")
        return urllib.parse.quote(str(secret["value"]), safe="")

    return _SECRET.sub(fill, url)


def redact(text: str, secrets: dict[str, dict] | None = None) -> str:
    """Replace any secret's value in text (ex. an error message) with its placeholder."""

    for name, secret in (secrets or {}).items():
        valu = secret.get("value") if isinstance(secret, dict) else None
        if valu:
            text = text.replace(str(valu), f"${{{name}}}")
            text = text.replace(urllib.parse.quote(str(valu), safe=""), f"${{{name}}}")
    return text


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

    try:
        engine = s_rules.normEngine(fdef.get("engine"))
    except s_rules.RuleError as err:
        raise FeedError(f"Invalid feed engine: {err.mesg}") from None

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
    """The deterministic rule node (``it:app:snort:rule`` or ``it:app:suricata:rule``) guid of a
    feed's rule."""

    return s_common.guid(("slib.pcap.rule", feed, gid, sid))


def rulesetGuid(feed: str) -> str:
    """The deterministic ``meta:ruleset`` guid of a feed."""

    return s_common.guid(("slib.pcap.ruleset", feed))


def parseFeed(fdef: FeedDef, byts: bytes, maxsize: int) -> dict[str, Any]:
    """Parse a downloaded feed into the records Storm models as rule nodes.

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
        "engineid": s_rules.SNORT_ENGINE_IDS.get(fdef["engine"]),
        "form": s_rules.FORMS[fdef["engine"]],
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
    """The light edges (verb, ndef) for a rule's references (see slib.pcap.model.ruleRefs).

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
        "version": str(rec["rev"]),
        "enabled": rec["enabled"],
    }
    keys = [("name", "msg"), ("created", "created"), ("updated", "updated")]
    if rec["form"] == "it:app:snort:rule":
        # Only Snort rules have an engine and a family.
        props["engine"] = s_rules.SNORT_ENGINE_IDS[rec["engine"]]
        keys.append(("family", "family"))
    for prop, key in keys:
        if rec.get(key) is not None:
            props[prop] = rec[key]
    return ((rec["form"], rec["guid"]), {"props": props, "edges": refEdges(rec["refs"])})


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
