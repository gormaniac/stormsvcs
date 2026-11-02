"""Normalize Malpedia API data into the records the slib.malpedia Storm package models.

Every record is a plain dict of JSON/msgpack safe values with a stable ``key``. The service
stores the records, diffs them between pulls, and hands Storm only the ones that changed.

Record kinds (see ``KINDS``):

- ``news`` - a library article (``media:news``), keyed by a hash of its URL. Built from the
  ``/api/get/bib`` BibTeX (title, authors, date, publisher) joined with ``/api/get/references``
  (the actors and families the article is tagged with) and the families' ``library_entries``.
- ``actor`` - a threat actor (``risk:threat``), keyed by its Malpedia ID (ex. ``apt28``).
- ``family`` - a malware family (``risk:tool:software``), keyed by its Malpedia ID (ex.
  ``win.xagent``), with the actors it's attributed to.
- ``yara`` - a YARA rule (``it:app:yara:rule``), keyed by its file name (ex.
  ``win.xagent_w0.yar``).
"""

import datetime
import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from typing import Any

from . import bib as s_bib
from .client import SITE_URL

# The record kinds, in the order Storm models them.
KINDS = ("news", "actor", "family", "yara")

# Matches a tag part, the same as Synapse's syn:tag:part normalization.
_TAGPARTRE = re.compile(r"\w+")

# A MITRE ATT&CK group ID.
_MITRERE = re.compile(r"^G\d{4}$")

# A YARA rule file name: <family>_<suffix>.yar (ex. win.xagent_w0.yar, win.xagent_auto.yar).
_YARAFILERE = re.compile(r"^(?P<family>.+?)_(?P<suffix>auto|[a-z]\d+)\.yar$")

# The first rule declared in a YARA file.
_RULERE = re.compile(r"^\s*(?:(?:private|global)\s+)*rule\s+([A-Za-z_]\w*)", re.MULTILINE)

# A string meta value in a YARA rule's meta section.
_METARE = re.compile(r'(?<![\w$])([A-Za-z_]\w*)\s*=\s*"((?:[^"\\\n]|\\.)*)"')

# The TLP directories Malpedia uses, mapped to the TLP names used in tags.
_TLPS = {
    "tlp_white": "white",
    "tlp_clear": "clear",
    "tlp_green": "green",
    "tlp_amber": "amber",
    "tlp_red": "red",
}

# Actor meta keys that hold sectors the actor targets.
_SECTOR_KEYS = ("targeted-sector", "cfr-target-category")


def recHash(rec: Any) -> str:
    """A stable hash of a record, used to tell when it changed."""

    byts = json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(byts.encode("utf-8")).hexdigest()


def urlKey(url: str) -> str:
    """The record key of a news article, a hash of its URL (URLs can exceed LMDB key limits)."""

    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def tagPart(text: str) -> str | None:
    """Normalize text into a tag part like Synapse's syn:tag:part does, or None if empty."""

    parts = _TAGPARTRE.findall(str(text).lower().strip())
    return "_".join(parts) or None


def tagPath(text: str) -> str | None:
    """Normalize a dotted ID (ex. ``win.xagent``) into a dotted tag path, or None if empty."""

    parts = [p for p in (tagPart(part) for part in str(text).split(".")) if p]
    return ".".join(parts) or None


def actorTag(actor: str) -> str | None:
    """The tag suffix (under the tag prefix) for an actor, ex. ``threat.apt28``."""

    part = tagPart(actor)
    return f"threat.{part}" if part else None


def familyTag(family: str) -> str | None:
    """The tag suffix (under the tag prefix) for a family, ex. ``mal.win.xagent``."""

    path = tagPath(family)
    return f"mal.{path}" if path else None


def _str(valu: Any) -> str | None:
    """A stripped string, or None for empty/non-string values."""

    if valu is None or isinstance(valu, (dict, list, tuple, set)):
        return None
    valu = " ".join(str(valu).split())
    return valu or None


def _strs(valu: Any) -> list[str]:
    """A sorted, de-duplicated list of strings from a string or list of strings."""

    if valu is None:
        return []
    if isinstance(valu, str):
        valu = [valu]
    if not isinstance(valu, Iterable) or isinstance(valu, Mapping):
        return []
    return sorted({s for s in (_str(v) for v in valu) if s})


def _text(valu: Any) -> str | None:
    """A stripped multi-line string, or None."""

    if not isinstance(valu, str):
        return None
    valu = valu.strip()
    return valu or None


def normDate(text: Any) -> str | None:
    """Normalize Malpedia's dates (YYYY, YYYY-MM, YYYY-MM-DD, YYYYMMDD) to ISO, or None."""

    text = _str(text)
    if text is None:
        return None
    match = re.fullmatch(r"(\d{4})(?:-?(\d{2})(?:-?(\d{2}))?)?", text)
    if match is None:
        return None
    year, month, day = match.groups()
    try:
        datetime.date(int(year), int(month or 1), int(day or 1))
    except ValueError:
        return None
    if day:
        return f"{year}-{month}-{day}"
    if month:
        return f"{year}-{month}"
    return year


def splitAuthors(text: Any) -> list[str]:
    """Split a BibTeX author field (``A and B and C``) into names, keeping their order."""

    text = _str(text)
    if text is None:
        return []
    names = []
    for name in re.split(r"\s+and\s+", text):
        name = name.strip(" ,")
        if name and name not in names:
            names.append(name)
    return names


# ---- Actors ----


def actorSlug(name: str) -> str:
    """Malpedia's actor ID for an actor display name (``APT 28`` -> ``apt_28``)."""

    return name.lower().replace(" ", "_").replace("/", "_")


def _alnum(text: str) -> str:
    return re.sub(r"[\W_]+", "", str(text).lower())


class ActorIndex:
    """Resolve actor names and synonyms (ex. a family's ``attribution``) to actor IDs.

    Resolution order: an exact display name, a unique case/punctuation insensitive display
    name, then a unique case/punctuation insensitive synonym. Ambiguous names don't resolve.
    """

    def __init__(self, actors: Iterable[Mapping]):
        self.exact: dict[str, str] = {}
        self.names: dict[str, set[str]] = {}
        self.synonyms: dict[str, set[str]] = {}
        for actor in actors:
            aid = actor["id"]
            if actor.get("name"):
                self.exact.setdefault(actor["name"], aid)
                self.names.setdefault(_alnum(actor["name"]), set()).add(aid)
            self.names.setdefault(_alnum(aid), set()).add(aid)
            for alias in actor.get("aliases") or ():
                self.synonyms.setdefault(_alnum(alias), set()).add(aid)

    def resolve(self, name: str) -> str | None:
        """The actor ID for a name, or None if it doesn't (uniquely) resolve."""

        if not name:
            return None
        if name in self.exact:
            return self.exact[name]
        key = _alnum(name)
        if not key:
            return None
        ids = self.names.get(key, set())
        if len(ids) == 1:
            return next(iter(ids))
        if ids:
            return None
        ids = self.synonyms.get(key, set())
        if len(ids) == 1:
            return next(iter(ids))
        return None


def normActor(aid: str, data: Mapping) -> dict:
    """Normalize an actor from ``/api/get/actors`` (or ``/api/get/actor/<id>``).

    ``aid`` is the actor's Malpedia ID (``/api/get/actors`` is keyed by display name).
    """

    meta = data.get("meta") if isinstance(data.get("meta"), Mapping) else {}
    name = _str(data.get("value")) or aid
    aliases = [a for a in _strs(meta.get("synonyms")) if a.lower() != name.lower()]

    country = _str(meta.get("country"))
    if country is not None:
        country = country.lower() if re.fullmatch(r"[A-Za-z]{2}", country) else None

    sectors = set()
    for key in _SECTOR_KEYS:
        sectors.update(_strs(meta.get(key)))

    mitre = sorted({s.upper() for s in _strs(meta.get("synonyms")) if _MITRERE.match(s.upper())})

    return {
        "key": aid,
        "id": aid,
        "name": name,
        "uuid": _str(data.get("uuid")),
        "desc": _text(data.get("description")),
        "aliases": aliases,
        "country": country,
        "sectors": sorted(sectors),
        "mitre": mitre[0] if len(mitre) == 1 else None,
        "tag": actorTag(aid),
        "url": f"{SITE_URL}/actor/{aid}",
    }


def resolveActorIds(actors: Mapping, ids: Iterable[str]) -> tuple[dict[str, Mapping], list[str]]:
    """Match ``/api/get/actors`` (keyed by display name) to ``/api/list/actors`` IDs.

    Returns
    -------
    tuple
        ``({actor_id: actor_data}, [display names that didn't match an ID])``
    """

    ids = set(ids)
    byalnum: dict[str, set[str]] = {}
    for aid in ids:
        byalnum.setdefault(_alnum(aid), set()).add(aid)

    matched: dict[str, Mapping] = {}
    unmatched = []
    for name, data in actors.items():
        if not isinstance(data, Mapping):
            continue
        aid = actorSlug(name)
        if aid not in ids:
            cands = byalnum.get(_alnum(name), set()) - set(matched)
            aid = next(iter(cands)) if len(cands) == 1 else None
        if aid is None or aid in matched:
            unmatched.append(name)
            continue
        matched[aid] = data
    return matched, unmatched


# ---- Families ----


def normFamily(fid: str, data: Mapping, index: ActorIndex | None = None) -> dict:
    """Normalize a family from ``/api/get/families`` (or ``/api/get/family/<id>``)."""

    name = _str(data.get("common_name")) or fid
    aliases = [a for a in _strs(data.get("alt_names")) if a.lower() != name.lower()]

    actors = set()
    unresolved = []
    for attr in _strs(data.get("attribution")):
        aid = index.resolve(attr) if index is not None else None
        if aid is None:
            unresolved.append(attr)
        else:
            actors.add(aid)

    platform = fid.split(".", 1)[0] if "." in fid else None

    return {
        "key": fid,
        "id": fid,
        "name": name,
        "platform": platform,
        "uuid": _str(data.get("uuid")),
        "desc": _text(data.get("description")),
        "aliases": aliases,
        "updated": normDate(data.get("updated")),
        "actors": sorted(actors),
        "unresolved": unresolved,
        "library": _strs(data.get("library_entries")),
        "tag": familyTag(fid),
        "url": f"{SITE_URL}/details/{fid}",
    }


def addActorLinks(families: Mapping[str, dict], actors: Mapping[str, Mapping]) -> None:
    """Add actor -> family ``uses`` relations from the actors' ``related`` lists.

    Malpedia's actors list related MISP galaxy clusters by UUID. A ``uses`` relation that
    points at a family's UUID means the actor uses the family.
    """

    byuuid = {fam["uuid"]: fam for fam in families.values() if fam.get("uuid")}
    for aid, data in actors.items():
        related = data.get("related")
        if not isinstance(related, list):
            continue
        for rel in related:
            if not isinstance(rel, Mapping) or rel.get("type") != "uses":
                continue
            fam = byuuid.get(rel.get("dest-uuid"))
            if fam is not None and aid not in fam["actors"]:
                fam["actors"] = sorted({*fam["actors"], aid})


def withActorTags(fam: dict) -> dict:
    """Add the ``[actor_id, tag suffix]`` pairs Storm needs to link a family to its actors."""

    fam["actortags"] = [[aid, actorTag(aid)] for aid in fam["actors"] if actorTag(aid)]
    return fam


# ---- News ----


def normBib(entry: Mapping) -> dict | None:
    """Normalize a parsed BibTeX entry (see ``bib.parse``), or None if it has no URL."""

    fields = entry.get("fields") or {}
    url = _str(fields.get("url"))
    if url is None:
        return None
    return {
        "url": url,
        "key": entry.get("key"),
        "type": entry.get("type"),
        "title": _str(fields.get("title")),
        "authors": splitAuthors(fields.get("author")),
        "published": normDate(fields.get("date")),
        "publisher": _str(fields.get("organization")) or _str(fields.get("institution")),
        "language": _str(fields.get("language")),
        "added": normDate(fields.get("urldate")),
    }


def parseBib(text: str) -> tuple[dict[str, dict], list[str]]:
    """Parse a Malpedia BibTeX export into ``{url: bib record}``, merging duplicate URLs.

    Returns
    -------
    tuple
        ``({url: record}, errors)``. A record's ``keys`` lists every entry key with its URL.
    """

    entries, errors = s_bib.parse(text)
    byurl: dict[str, dict] = {}
    for entry in entries:
        rec = normBib(entry)
        if rec is None:
            errors.append(f"Skipped the BibTeX entry {entry.get('key')}: it has no url.")
            continue
        key = rec.pop("key")
        have = byurl.get(rec["url"])
        if have is None:
            rec["keys"] = [key] if key else []
            byurl[rec["url"]] = rec
            continue
        if key and key not in have["keys"]:
            have["keys"] = sorted({*have["keys"], key})
        for name, valu in rec.items():
            if have.get(name) in (None, []) and valu not in (None, []):
                have[name] = valu
    return byurl, errors


def newsRecord(url: str, bibrec: Mapping | None, actors: Iterable[str], families: Iterable[str]):
    """Build a news record from its BibTeX record (if any) and the actors/families it's about."""

    bibrec = bibrec or {}
    actors = sorted(set(actors))
    families = sorted(set(families))
    return {
        "key": urlKey(url),
        "url": url,
        "keys": list(bibrec.get("keys") or []),
        "type": bibrec.get("type"),
        "title": bibrec.get("title"),
        "authors": list(bibrec.get("authors") or []),
        "published": bibrec.get("published"),
        "publisher": bibrec.get("publisher"),
        "language": bibrec.get("language"),
        "added": bibrec.get("added"),
        "actors": [[a, actorTag(a)] for a in actors if actorTag(a)],
        "families": [[f, familyTag(f)] for f in families if familyTag(f)],
    }


def buildNews(
    bibs: Mapping[str, Mapping],
    references: Mapping[str, Any],
    families: Mapping[str, Mapping] | None = None,
) -> dict[str, dict]:
    """Join the library's BibTeX, its references, and the families' library entries.

    Parameters
    ----------
    bibs : dict
        ``{url: bib record}`` from ``parseBib``.
    references : dict
        The ``references`` dict from ``/api/get/references``: ``{url: [{"type", "id"}, ...]}``.
    families : dict, optional
        ``{family_id: family record}``, whose ``library`` bib keys tag articles too.

    Returns
    -------
    dict
        ``{news key: news record}`` for every URL in the bib or the references.
    """

    links: dict[str, tuple[set, set]] = {}

    def link(url: str) -> tuple[set, set]:
        return links.setdefault(url, (set(), set()))

    for url in bibs:
        link(url)

    for url, tags in references.items():
        url = _str(url)
        if url is None:
            continue
        actors, fams = link(url)
        if not isinstance(tags, list):
            continue
        for tag in tags:
            if not isinstance(tag, Mapping) or not _str(tag.get("id")):
                continue
            if tag.get("type") == "actor":
                actors.add(_str(tag["id"]))
            elif tag.get("type") == "family":
                fams.add(_str(tag["id"]))

    if families:
        bykey = {key: url for url, rec in bibs.items() for key in rec.get("keys") or ()}
        for fid, fam in families.items():
            for key in fam.get("library") or ():
                url = bykey.get(key)
                if url is not None:
                    link(url)[1].add(fid)

    news = {}
    for url, (actors, fams) in links.items():
        rec = newsRecord(url, bibs.get(url), actors, fams)
        news[rec["key"]] = rec
    return news


# ---- YARA ----


def tlpName(tlp: Any) -> str | None:
    """Normalize a Malpedia TLP (``tlp_white``, ``TLP:WHITE``, ``white``) to ``white``."""

    text = _str(tlp)
    if text is None:
        return None
    text = text.lower().replace(":", "_").replace("-", "_")
    if not text.startswith("tlp_"):
        text = f"tlp_{text}"
    return _TLPS.get(text)


def yaraFamily(filename: str) -> str | None:
    """The family ID from a YARA rule file name (``win.xagent_w0.yar`` -> ``win.xagent``)."""

    match = _YARAFILERE.match(filename)
    return match.group("family") if match else None


def yaraMeta(text: str) -> dict[str, str]:
    """The string values in a YARA rule's meta section (the first value of each name)."""

    start = re.search(r"\bmeta\s*:", text)
    if start is None:
        return {}
    stop = re.compile(r"\b(?:strings|condition)\s*:").search(text, start.end())
    section = text[start.end() : stop.start() if stop else len(text)]
    meta: dict[str, str] = {}
    for name, valu in _METARE.findall(section):
        meta.setdefault(name.lower(), valu.replace('\\"', '"').replace("\\\\", "\\"))
    return meta


def normYara(
    filename: str,
    text: str,
    tlp: str | None = None,
    family: str | None = None,
    families: Mapping[str, Mapping] | None = None,
) -> dict | None:
    """Normalize a YARA rule file, or None if it doesn't look like a rule.

    Parameters
    ----------
    filename : str
        The rule's file name, ex. ``win.xagent_w0.yar``.
    text : str
        The rule text.
    tlp : str, optional
        The TLP directory it was published under, ex. ``tlp_white``. Falls back to the rule's
        ``malpedia_sharing`` meta.
    family : str, optional
        The family ID, parsed from the file name if not given.
    families : dict, optional
        ``{family_id: family record}`` to name the family the rule detects.
    """

    text = text if isinstance(text, str) else ""
    if not text.strip():
        return None
    match = _RULERE.search(text)
    if match is None:
        return None

    meta = yaraMeta(text)
    family = family or yaraFamily(filename)
    fam = (families or {}).get(family) if family else None
    tlpname = tlpName(tlp) or tlpName(meta.get("malpedia_sharing"))
    suffix = _YARAFILERE.match(filename)

    return {
        "key": filename,
        "file": filename,
        "name": match.group(1),
        "text": text,
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "family": family,
        "familyname": fam["name"] if fam else None,
        "familytag": familyTag(family) if family else None,
        "tlp": tlpname,
        "auto": bool(suffix and suffix.group("suffix") == "auto"),
        "desc": _str(meta.get("description")),
        "author": _str(meta.get("author")),
        "created": normDate(meta.get("date")),
        "updated": normDate(meta.get("malpedia_version")),
        "url": _str(meta.get("malpedia_reference"))
        or (f"{SITE_URL}/details/{family}" if family else None),
        "license": _str(meta.get("malpedia_license")),
    }


def yaraTlpRules(data: Mapping) -> list[tuple[str, str, str]]:
    """Flatten ``{tlp: {filename: text}}`` (from ``/api/get/yara/*``) to (tlp, filename, text)."""

    rules = []
    for tlp, files in (data or {}).items():
        if not isinstance(files, Mapping):
            continue
        for filename, text in files.items():
            if isinstance(filename, str) and isinstance(text, str):
                rules.append((tlp, filename.rsplit("/", 1)[-1], text))
    return rules


def yaraListing(data: Mapping) -> dict[str, tuple[str, str]]:
    """Flatten ``/api/list/yara`` to ``{filename: (family, tlp)}``."""

    listing = {}
    for family, files in (data or {}).items():
        if not isinstance(files, list):
            continue
        for item in files:
            if not isinstance(item, Mapping) or not _str(item.get("path")):
                continue
            filename = item["path"].rsplit("/", 1)[-1]
            tlp = item.get("tlp")
            if not tlp:
                parts = item["path"].strip("/").split("/")
                tlp = parts[-2] if len(parts) >= 2 else None
            listing[filename] = (family, tlp)
    return listing
