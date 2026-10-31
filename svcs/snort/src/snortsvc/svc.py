"""The slib.snort service.

The Cortex is the source of truth for the rules: every enabled ``it:app:snort:rule`` with
``:text`` is pushed to the service (see ``pushStart``/``pushRules``/``pushDone`` and
``ruleUpdate``), which saves them and builds a Snort 3 rules file from every rule Snort can load.
PCAPs are matched against that rules file, the alerts are grouped into hits (one per rule and
flow) for Storm to model.

The service also downloads open source rule feeds (see ``snortsvc.feeds``). It doesn't use the
feeds' rules directly, Storm models them as ``it:app:snort:rule`` nodes (so they can be enabled,
disabled, and queried like any other rule) and then pushes the enabled rules back to the service.

Every method raises ``SnortSvcError`` (or ``SnortError``/``FeedError``) on failure,
``SnortCellApi`` wraps them in the standard ``TelepathRetn`` convention for Storm.
"""

import asyncio
import binascii
import contextlib
import hashlib
import json
import logging
import os
import shutil
from collections.abc import AsyncIterator
from typing import Any

import aiohttp
import synapse.common as s_common
import synapse.exc as s_exc
import synapse.lib.cell as s_cell
import synapse.lib.coro as s_coro
import synapse.lib.msgpack as s_msgpack
import synapse.telepath as s_telepath

from . import engine as s_engine
from . import feeds as s_feeds
from . import rules as s_rules
from .api import SnortCellApi

logger = logging.getLogger(__name__)


UPLOAD_IDLE = 60 * 60 * 1000
"""Staged PCAP uploads and rule pushes untouched for this long (ms) are removed."""

FEED_BATCH = 500
"""How many rule records ``feedChanges`` yields at a time."""


class SnortSvcError(Exception):
    """Raised for invalid requests to the service."""

    def __init__(self, mesg: str) -> None:
        super().__init__(mesg)
        self.mesg = mesg


def _prepare(entries: dict[str, tuple[str, int]]) -> dict[str, Any]:
    """Parse the pushed rules and pick one rule per gid:sid (run in an executor).

    Returns a dict of ``snort2``/``snort3`` (guid -> text), ``meta`` (guid -> (gid, sid, rev)),
    and ``errors`` (guid -> error).
    """

    snort2: dict[str, str] = {}
    snort3: dict[str, str] = {}
    meta: dict[str, tuple[int, int, int]] = {}
    errors: dict[str, str] = {}
    best: dict[tuple[int, int], str] = {}

    for guid in sorted(entries):
        text, engine = entries[guid]
        try:
            rule = s_rules.parseRule(text, enabled=True)
        except s_rules.RuleError as err:
            errors[guid] = err.mesg
            continue

        key = (rule["gid"], rule["sid"])
        meta[guid] = (rule["gid"], rule["sid"], rule["rev"])
        prev = best.get(key)
        if prev is not None:
            # Keep the highest rev, or the first guid (they are sorted) on a tie.
            if meta[prev][2] >= rule["rev"]:
                errors[guid] = (
                    f"Duplicate gid:sid {s_rules.ruleKey(*key)}, it:app:snort:rule={prev} "
                    f"(rev {meta[prev][2]}) is used instead."
                )
                continue
            errors[prev] = (
                f"Duplicate gid:sid {s_rules.ruleKey(*key)}, it:app:snort:rule={guid} "
                f"(rev {rule['rev']}) is used instead."
            )
            snort2.pop(prev, None)
            snort3.pop(prev, None)

        best[key] = guid
        if engine == s_rules.ENGINE_SNORT2:
            snort2[guid] = rule["text"]
        else:
            snort3[guid] = rule["text"]

    return {"snort2": snort2, "snort3": snort3, "meta": meta, "errors": errors}


def _ends(src: str, sport: Any, dst: str, dport: Any) -> dict[str, Any]:
    """The per-endpoint IP and port fields of a hit or flow."""

    return {
        "srcip": src or None,
        "srcport": sport,
        "dstip": dst or None,
        "dstport": dport,
        "ipv6": ":" in src or ":" in dst,
    }


def _writeJson(path: str, valu: Any) -> None:
    with open(path, "w", encoding="utf-8") as fd:
        json.dump(valu, fd)


def _writeFeed(path: str, recs: list[dict[str, Any]]) -> None:
    """Save a feed's parsed rule records (msgpack), replacing the last ones."""

    tmp = path + ".tmp"
    with open(tmp, "wb") as fd:
        fd.writelines(s_msgpack.en(rec) for rec in recs)
    os.replace(tmp, path)


def _readFeed(path: str) -> list[dict[str, Any]]:
    with open(path, "rb") as fd:
        return list(s_msgpack.iterfd(fd))


def _addr(proto: str, ip: str, port: Any) -> str:
    """An ``inet:addr`` (ex. ``tcp://1.2.3.4:80``) for an endpoint in an alert."""

    host = f"[{ip}]" if ":" in ip else ip
    if proto in ("tcp", "udp") and port is not None:
        return f"{proto}://{host}:{port}"
    if proto in ("tcp", "udp", "icmp"):
        return f"{proto}://{host}"
    return f"host://{host}"


IP_PROTOS = {"tcp": 6, "udp": 17, "icmp": 1}
"""IP protocol numbers by the protocol names Snort uses in alerts."""


class HitGrouper:
    """Group Snort's alerts for a PCAP into hits, one per rule and flow.

    Parameters
    ----------
    sha256 : str
        The PCAP's SHA256, part of every hit and flow guid so they are unique to the PCAP.
    index : dict
        The loaded rules, gid:sid -> {"guid": ..., "rev": ...}.
    """

    def __init__(self, sha256: str, index: dict[str, dict]) -> None:
        self.sha256 = sha256
        self.index = index
        self.hits: dict[tuple, dict[str, Any]] = {}
        self.flows: dict[tuple, dict[str, Any]] = {}
        self.unknown: dict[str, int] = {}

    @staticmethod
    def _time(alert: dict[str, Any]) -> int | None:
        secs = alert.get("seconds")
        if secs is None:
            return None
        usecs = 0
        stamp = str(alert.get("timestamp") or "")
        if "." in stamp:
            frac = stamp.rsplit(".", 1)[1]
            if frac.isdigit():
                usecs = int(frac[:6].ljust(6, "0"))
        return int(secs) * 1000 + usecs // 1000

    def add(self, alert: dict[str, Any]) -> None:
        """Add one of Snort's alerts."""

        key = s_rules.ruleKey(int(alert.get("gid", 1)), int(alert.get("sid", 0)))
        rinfo = self.index.get(key)
        if rinfo is None:
            self.unknown[key] = self.unknown.get(key, 0) + 1
            return

        proto = str(alert.get("proto") or "ip").lower()
        src, sport = str(alert.get("src_addr") or ""), alert.get("src_port")
        dst, dport = str(alert.get("dst_addr") or ""), alert.get("dst_port")
        if proto not in ("tcp", "udp"):
            sport = dport = None
        tick = self._time(alert)

        # The flow is from the client to the server, the alert is for a packet in either direction.
        if alert.get("dir") == "S2C":
            fkey = (proto, dst, dport, src, sport)
        else:
            fkey = (proto, src, sport, dst, dport)

        flow = self.flows.get(fkey)
        if flow is None:
            flow = self.flows[fkey] = {
                "guid": s_common.guid(("slib.snort.flow", self.sha256, *fkey)),
                "src": _addr(proto, fkey[1], fkey[2]),
                "dst": _addr(proto, fkey[3], fkey[4]),
                "proto": IP_PROTOS.get(proto),
                "time": tick,
                "last": tick,
                **_ends(*fkey[1:]),
            }
        elif tick is not None:
            flow["time"] = tick if flow["time"] is None else min(flow["time"], tick)
            flow["last"] = tick if flow["last"] is None else max(flow["last"], tick)

        hkey = (key, proto, src, sport, dst, dport)
        hit = self.hits.get(hkey)
        if hit is None:
            self.hits[hkey] = {
                "guid": s_common.guid(
                    ("slib.snort.hit", self.sha256, rinfo["guid"], proto, src, sport, dst, dport)
                ),
                "rule": rinfo["guid"],
                "key": key,
                "rev": int(alert.get("rev", rinfo["rev"])),
                "msg": alert.get("msg"),
                "action": alert.get("action"),
                "src": _addr(proto, src, sport),
                "dst": _addr(proto, dst, dport),
                "flow": flow["guid"],
                "time": tick,
                "last": tick,
                "count": 1,
                **_ends(src, sport, dst, dport),
            }
            return

        hit["count"] += 1
        if tick is not None:
            hit["time"] = tick if hit["time"] is None else min(hit["time"], tick)
            hit["last"] = tick if hit["last"] is None else max(hit["last"], tick)

    def results(self, alerts: int) -> dict[str, Any]:
        """The scan results: the hits, the flows they reference, and alert counts."""

        return {
            "sha256": self.sha256,
            "alerts": alerts,
            "hits": sorted(
                self.hits.values(), key=lambda h: (h["time"] or 0, h["key"], h["src"], h["dst"])
            ),
            "flows": sorted(
                self.flows.values(), key=lambda f: (f["time"] or 0, f["src"], f["dst"])
            ),
            "unknown": self.unknown,
        }


class SnortSvc(s_cell.Cell):
    """The Cell implementation for the slib.snort service."""

    cellapi = SnortCellApi

    confdefs = {
        "snort:bin": {
            "type": "string",
            "default": "snort",
            "description": "The Snort 3 binary, a path or a name on the PATH.",
        },
        "snort:snort2lua": {
            "type": "string",
            "default": "snort2lua",
            "description": "The snort2lua binary, converts Snort 2.x rules (engine 2) to Snort 3.",
        },
        "snort:conf": {
            "type": ["string", "null"],
            "default": None,
            "description": (
                "The base Snort config (snort.lua). Defaults to the snort.lua installed with "
                "Snort. Relative includes are found in the config's directory."
            ),
        },
        "snort:vars": {
            "type": "object",
            "default": s_engine.DEFAULT_VARS,
            "description": (
                "Snort variables to set in the base config, ex. HOME_NET and EXTERNAL_NET. Only "
                "variables the base config assigns can be set."
            ),
        },
        "snort:args": {
            "type": "array",
            "items": {"type": "string"},
            "default": [],
            "description": "Extra arguments for every Snort run.",
        },
        "snort:timeout": {
            "type": "number",
            "default": 900,
            "description": "Seconds before a Snort run (a rule build or a PCAP scan) is killed.",
        },
        "snort:workers": {
            "type": "integer",
            "default": 2,
            "minimum": 1,
            "description": "The max number of PCAPs scanned at once.",
        },
        "snort:maxsize": {
            "type": "integer",
            "default": 1073741824,
            "description": "The max size, in bytes, of a PCAP the service will scan.",
        },
        "snort:axon": {
            "type": ["string", "null"],
            "default": None,
            "description": (
                "A Telepath URL for the Axon the Cortex uses. When set, the service reads PCAPs "
                "from the Axon itself, otherwise Storm streams them to the service."
            ),
        },
        "snort:feeds": {
            "type": "array",
            "items": {"type": "object"},
            "default": [dict(f) for f in s_feeds.DEFAULT_FEEDS],
            "description": (
                "The rule feeds the service starts with, each a {name, url, engine, enabled, "
                "exclude, desc}. Only read the first time the service starts, after that feeds "
                "are managed with slib.snort.admin.feed."
            ),
        },
        "snort:feeds:interval": {
            "type": "number",
            "default": 24,
            "description": "Hours between feed downloads (a sync downloads a feed when it's due).",
        },
        "snort:feeds:timeout": {
            "type": "number",
            "default": 300,
            "description": "Seconds before a feed download times out.",
        },
        "snort:feeds:maxsize": {
            "type": "integer",
            "default": 268435456,
            "description": "The max size, in bytes, of a feed (and of the rules it unpacks to).",
        },
    }

    async def __anit__(self, dirn, *args, **kwargs):
        await s_cell.Cell.__anit__(self, dirn, *args, **kwargs)

        self.snortinfo = self.slab.getSafeKeyVal("slib:snort:info")
        self.corpus = self.slab.getSafeKeyVal("slib:snort:rules")
        self.ruleerrs = self.slab.getSafeKeyVal("slib:snort:errors")
        self.feeddefs = self.slab.getSafeKeyVal("slib:snort:feeds")
        self.feedinfo = self.slab.getSafeKeyVal("slib:snort:feedinfo")

        if not self.snortinfo.get("feeds:seeded"):
            for fdef in self.conf.get("snort:feeds"):
                fdef = s_feeds.normFeed(fdef)
                self.feeddefs.set(fdef["name"], dict(fdef))
            self.snortinfo.set("feeds:seeded", True)

        self.rulesdir = os.path.join(self.dirn, "snort", "rules")
        self.feeddir = os.path.join(self.dirn, "snort", "feeds")
        self.tmpdir = os.path.join(self.dirn, "snort", "tmp")
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        for path in (self.rulesdir, self.feeddir, self.tmpdir):
            os.makedirs(path, exist_ok=True)

        self.snort = s_engine.Snort(
            os.path.join(self.dirn, "snort", "conf"),
            binpath=self.conf.get("snort:bin"),
            s2lpath=self.conf.get("snort:snort2lua"),
            conf=self.conf.get("snort:conf"),
            snortvars=self.conf.get("snort:vars"),
            args=self.conf.get("snort:args"),
            timeout=self.conf.get("snort:timeout"),
        )

        self.maxsize = self.conf.get("snort:maxsize")
        self.axonurl = self.conf.get("snort:axon")
        self.buildlock = asyncio.Lock()
        self.scansema = asyncio.Semaphore(self.conf.get("snort:workers"))
        self.pushes: dict[str, dict[str, Any]] = {}
        self.uploads: dict[str, dict[str, Any]] = {}
        self.inuse: dict[str, int] = {}

        # The loaded rules: (rules file, gid:sid -> {guid, rev}).
        self.active: tuple[str, dict[str, dict]] | None = self._loadActive()
        self.snortvers: str | None = None

        self.session = aiohttp.ClientSession(trust_env=True)
        self.onfini(self.session.close)

        self.schedCoro(self._pruneLoop())
        if self.active is None and self.snortinfo.get("rules:count"):
            # Rules were pushed, but the rules file is gone (ex. a new volume), rebuild it.
            self.schedCoro(self._initBuild())

    # ---- State ----

    def _loadActive(self) -> tuple[str, dict[str, dict]] | None:
        name = self.snortinfo.get("rules:active")
        if not name:
            return None
        path = os.path.join(self.rulesdir, name)
        ipath = path + ".index.json"
        if not os.path.exists(path):
            return None
        try:
            with open(ipath, encoding="utf-8") as fd:
                return path, json.load(fd)
        except (OSError, ValueError):
            return None

    async def _initBuild(self) -> None:
        try:
            await self._build()
        except Exception:  # pragma: no cover - logged for the operator
            logger.exception("Unable to rebuild the Snort rules at startup.")

    def _prune(self, idle: int = UPLOAD_IDLE) -> list[str]:
        """Remove rule pushes and PCAP uploads untouched for ``idle`` ms. Returns their IDs."""

        cutoff = s_common.now() - idle
        stale = []
        for iden, push in list(self.pushes.items()):
            if push["touched"] < cutoff:
                self.pushes.pop(iden)
                stale.append(iden)
        for iden, upload in list(self.uploads.items()):
            if upload["touched"] < cutoff:
                self._dropUpload(iden)
                stale.append(iden)
        return stale

    async def _pruneLoop(self) -> None:
        while not await self.waitfini(timeout=600):
            self._prune()

    async def _snortVersion(self) -> str | None:
        if self.snortvers is None and self.snort.available():
            try:
                self.snortvers = await self.snort.version()
            except s_engine.SnortError as err:
                logger.warning("Unable to get the Snort version: %s", err.mesg)
        return self.snortvers

    async def status(self) -> dict[str, Any]:
        """The service's status: Snort's version, and the rules that are loaded."""

        return {
            "snort": await self._snortVersion(),
            "available": self.snort.available(),
            "axon": bool(self.axonurl),
            "rules": self.snortinfo.get("rules:count", 0),
            "loaded": len(self.active[1]) if self.active else 0,
            "invalid": self.snortinfo.get("rules:invalid", 0),
            "built": self.snortinfo.get("rules:built"),
            "took": self.snortinfo.get("rules:took"),
            "pushed": self.snortinfo.get("rules:pushed"),
            "building": self.buildlock.locked(),
            "error": self.snortinfo.get("rules:error"),
        }

    async def hasAxon(self) -> bool:
        """Whether the service reads PCAPs from an Axon itself (``snort:axon`` is set)."""

        return bool(self.axonurl)

    # ---- Rules ----

    async def _build(self) -> dict[str, Any]:
        """Build a new rules file from every pushed rule and load it. Returns the build summary."""

        async with self.buildlock:
            start = s_common.now()
            entries = {guid: (valu[0], valu[1]) for guid, valu in self.corpus.items()}
            prep = await s_coro.executor(_prepare, entries)
            errors: dict[str, str] = prep["errors"]

            converted, cerrs = await self.snort.convert(prep["snort2"])
            errors.update(cerrs)
            rules3 = dict(prep["snort3"])
            rules3.update(converted)

            name = f"rules-{s_common.guid()}.rules"
            path = os.path.join(self.rulesdir, name)
            try:
                valid, verrs = await self.snort.validate(rules3, path)
            except s_engine.SnortError as err:
                self.snortinfo.set("rules:error", err.mesg)
                with contextlib.suppress(OSError):
                    os.remove(path)
                raise
            errors.update(verrs)

            index = {}
            for guid in valid:
                gid, sid, rev = prep["meta"][guid]
                index[s_rules.ruleKey(gid, sid)] = {"guid": guid, "rev": rev}

            await s_coro.executor(_writeJson, path + ".index.json", index)

            await self.ruleerrs.truncate()
            for guid, mesg in errors.items():
                self.ruleerrs.set(guid, mesg)

            old = self.active
            self.active = (path, index)
            took = s_common.now() - start
            self.snortinfo.set("rules:active", name)
            self.snortinfo.set("rules:count", len(entries))
            self.snortinfo.set("rules:invalid", len(errors))
            self.snortinfo.set("rules:built", s_common.now())
            self.snortinfo.set("rules:took", took)
            self.snortinfo.pop("rules:error")
            if old is not None:
                self._release(old[0], drop=True)

            logger.info(
                "Built the Snort rules: %d rules, %d loaded, %d invalid, in %d ms",
                len(entries),
                len(index),
                len(errors),
                took,
            )
            return {
                "rules": len(entries),
                "loaded": len(index),
                "invalid": len(errors),
                "took": took,
                "changed": True,
            }

    def _release(self, path: str, drop: bool = False) -> None:
        """Release a rules file used by a scan, removing it once it's unused and not active."""

        if drop:
            self.inuse.setdefault(path, 0)
        else:
            self.inuse[path] = self.inuse.get(path, 1) - 1
        if self.inuse.get(path, 0) <= 0 and (self.active is None or self.active[0] != path):
            self.inuse.pop(path, None)
            for fpath in (path, path + ".index.json"):
                with contextlib.suppress(OSError):
                    os.remove(fpath)

    def _needsBuild(self) -> bool:
        """Whether the rules file must be built even if the rules didn't change (ex. the last
        build failed)."""

        return self.active is None or bool(self.snortinfo.get("rules:error"))

    @staticmethod
    def _normRule(item: Any) -> tuple[str, str, int]:
        try:
            guid, text, engine = item
        except (TypeError, ValueError) as err:
            raise SnortSvcError(
                f"Rules must be pushed as (guid, text, engine), got: {item!r}"
            ) from err
        if not s_common.isguid(guid):
            raise SnortSvcError(f"Invalid it:app:snort:rule guid: {guid!r}")
        if not isinstance(text, str) or not text.strip():
            raise SnortSvcError(f"it:app:snort:rule={guid} has no :text.")
        engine = s_rules.ENGINE_SNORT3 if engine is None else engine
        if engine not in s_rules.ENGINES:
            raise SnortSvcError(
                f"it:app:snort:rule={guid} has an unsupported :engine {engine!r} "
                f"(the service supports {', '.join(map(str, s_rules.ENGINES))})."
            )
        return guid, text, engine

    async def pushStart(self) -> str:
        """Start a push of every enabled rule in the Cortex. Returns the push ID.

        Send the rules with ``pushRules`` then call ``pushDone``, which replaces the service's rules
        with the pushed rules.
        """

        iden = s_common.guid()
        self.pushes[iden] = {"rules": {}, "touched": s_common.now()}
        return iden

    def _reqPush(self, iden: str) -> dict[str, Any]:
        push = self.pushes.get(iden)
        if push is None:
            raise SnortSvcError(f"Unknown rule push: {iden}")
        push["touched"] = s_common.now()
        return push

    async def pushRules(self, iden: str, rules: list) -> int:
        """Add a batch of (guid, text, engine) rules to a push. Returns the rules pushed so far."""

        push = self._reqPush(iden)
        for item in rules:
            guid, text, engine = self._normRule(item)
            push["rules"][guid] = (text, engine)
        return len(push["rules"])

    async def pushCancel(self, iden: str) -> bool:
        """Cancel a push, the service's rules are unchanged."""

        return self.pushes.pop(iden, None) is not None

    async def pushDone(self, iden: str, force: bool = False) -> dict[str, Any]:
        """Replace the service's rules with the pushed rules, and rebuild them if they changed."""

        push = self._reqPush(iden)
        self.pushes.pop(iden, None)
        rules = push["rules"]

        current = {guid: (valu[0], valu[1]) for guid, valu in self.corpus.items()}
        self.snortinfo.set("rules:pushed", s_common.now())
        if not force and current == rules and not self._needsBuild():
            return {
                "rules": len(rules),
                "loaded": len(self.active[1]),
                "invalid": self.snortinfo.get("rules:invalid", 0),
                "took": 0,
                "changed": False,
            }

        for guid in current:
            if guid not in rules:
                self.corpus.delete(guid)
        for guid, (text, engine) in rules.items():
            if current.get(guid) != (text, engine):
                self.corpus.set(guid, (text, engine))
        return await self._build()

    async def ruleUpdate(
        self, rules: list | None = None, dels: list | None = None
    ) -> dict[str, Any]:
        """Add/update some (guid, text, engine) rules and remove some rules (by guid), then rebuild.

        Returns the build summary, with ``errors`` (guid -> error) for the given rules that
        couldn't be loaded.
        """

        changed = False
        guids = []
        for item in rules or ():
            guid, text, engine = self._normRule(item)
            guids.append(guid)
            if self.corpus.get(guid) != (text, engine):
                self.corpus.set(guid, (text, engine))
                changed = True
        for guid in dels or ():
            if self.corpus.pop(guid) is not None:
                changed = True

        if changed or self._needsBuild():
            summary = await self._build()
        else:
            summary = {
                "rules": self.snortinfo.get("rules:count", 0),
                "loaded": len(self.active[1]),
                "invalid": self.snortinfo.get("rules:invalid", 0),
                "took": 0,
                "changed": False,
            }

        summary["errors"] = {
            guid: mesg for guid in guids if (mesg := self.ruleerrs.get(guid)) is not None
        }
        return summary

    async def rebuild(self) -> dict[str, Any]:
        """Rebuild the rules file from the service's rules (ex. after Snort is upgraded)."""

        return await self._build()

    async def ruleErrors(self, guids: list[str] | None = None) -> dict[str, str]:
        """The errors of rules Snort couldn't load (guid -> error), optionally for some rules."""

        if guids is not None:
            return {guid: mesg for guid in guids if (mesg := self.ruleerrs.get(guid)) is not None}
        return dict(self.ruleerrs.items())

    async def ruleInfo(self, guid: str) -> dict[str, Any]:
        """Whether a rule was pushed to the service, is loaded, and its error if it isn't."""

        pushed = self.corpus.get(guid)
        error = self.ruleerrs.get(guid)
        return {
            "pushed": pushed is not None,
            "loaded": pushed is not None and error is None and self.active is not None,
            "error": error,
        }

    async def ruleParse(self, text: str) -> dict[str, Any]:
        """Parse rule text into the metadata Storm models (see ``snortsvc.rules.parseRule``)."""

        try:
            rule = s_rules.parseRule(text)
        except s_rules.RuleError as err:
            raise SnortSvcError(err.mesg) from err
        rule = dict(rule)
        rule["id"] = s_rules.ruleId(rule)
        rule["guid"] = s_common.guid(("slib.snort.custom", rule["gid"], rule["sid"]))
        return rule

    async def ruleCheck(self, text: str, engine: int | None = None) -> str | None:
        """Check if Snort can load a rule. Returns the error, or None if it's valid."""

        engine = s_rules.ENGINE_SNORT3 if engine is None else engine
        if engine not in s_rules.ENGINES:
            engines = ", ".join(map(str, s_rules.ENGINES))
            raise SnortSvcError(f"Unsupported engine {engine!r}, use one of: {engines}.")
        return await self.snort.check(text, engine)

    # ---- Feeds ----

    def _reqFeed(self, name: str) -> s_feeds.FeedDef:
        fdef = self.feeddefs.get(str(name).lower())
        if fdef is None:
            raise SnortSvcError(f"Unknown feed: {name}")
        return fdef

    def _feedPath(self, name: str) -> str:
        return os.path.join(self.feeddir, f"{name}.mpk")

    def _snapDir(self, name: str) -> str:
        return os.path.join(self.feeddir, "synced", name)

    def _snapPath(self, name: str, view: str) -> str:
        if not s_common.isguid(view):
            raise SnortSvcError(f"Invalid view iden: {view!r}")
        return os.path.join(self._snapDir(name), f"{view}.mpk")

    def _feedInfo(self, name: str, view: str | None = None) -> dict[str, Any]:
        """A feed's state, with ``synced`` (the sha256 last synced into ``view``)."""

        info = self.feedinfo.get(name, {})
        info["synced"] = info.get("views", {}).get(view, {}).get("sha256") if view else None
        return info

    def _dropSync(self, name: str) -> None:
        """Forget what was synced into each view, the next sync of the feed is a full sync."""

        shutil.rmtree(self._snapDir(name), ignore_errors=True)

    async def feeds(self, view: str | None = None) -> list[dict[str, Any]]:
        """Every feed's definition, its ruleset guid, and the state of its last download (and
        sync into ``view``)."""

        retn = []
        for name, fdef in self.feeddefs.items():
            retn.append(
                {**fdef, "ruleset": s_feeds.rulesetGuid(name), "info": self._feedInfo(name, view)}
            )
        return retn

    async def feedAdd(self, fdef: dict[str, Any]) -> dict[str, Any]:
        """Add (or replace) a feed."""

        try:
            fdef = s_feeds.normFeed(fdef)
        except s_feeds.FeedError as err:
            raise SnortSvcError(err.mesg) from err
        prev = self.feeddefs.get(fdef["name"])
        self.feeddefs.set(fdef["name"], dict(fdef))
        if prev is not None and (prev["url"], prev["engine"], prev["exclude"]) != (
            fdef["url"],
            fdef["engine"],
            fdef["exclude"],
        ):
            # The feed's content will be different, download it again on the next sync.
            self.feedinfo.pop(fdef["name"])
            self._dropSync(fdef["name"])
        return {**fdef, "ruleset": s_feeds.rulesetGuid(fdef["name"])}

    async def feedDel(self, name: str) -> dict[str, Any]:
        """Remove a feed (its nodes stay in the Cortex). Returns the removed feed's definition."""

        fdef = self._reqFeed(name)
        self.feeddefs.delete(fdef["name"])
        self.feedinfo.pop(fdef["name"])
        with contextlib.suppress(OSError):
            os.remove(self._feedPath(fdef["name"]))
        self._dropSync(fdef["name"])
        return {**fdef, "ruleset": s_feeds.rulesetGuid(fdef["name"])}

    async def feedEnable(self, name: str, enabled: bool = True) -> dict[str, Any]:
        """Enable or disable a feed (disabled feeds aren't downloaded or synced)."""

        fdef = self._reqFeed(name)
        fdef["enabled"] = bool(enabled)
        self.feeddefs.set(fdef["name"], fdef)
        return {**fdef, "ruleset": s_feeds.rulesetGuid(fdef["name"])}

    async def feedPull(
        self, name: str, force: bool = False, view: str | None = None
    ) -> dict[str, Any]:
        """Download a feed, if it's due (see ``snort:feeds:interval``) or ``force`` is set.

        The feed's parsed rules are saved by the service, Storm reads them with ``feedChanges``.

        Returns
        -------
        dict
            The feed's state, with ``pulled`` (the last download), ``sha256`` (of the download),
            ``synced`` (the sha256 last synced into ``view``, see ``feedSynced``), ``count``
            (rules), ``errors`` (unparsable rules), and ``skipped`` (true if it wasn't due).
        """

        fdef = self._reqFeed(name)
        info = self._feedInfo(fdef["name"], view)
        info.pop("synced")
        now = s_common.now()
        interval = int(self.conf.get("snort:feeds:interval") * 3600 * 1000)
        have = os.path.exists(self._feedPath(fdef["name"]))

        if not force and have and info.get("pulled") and now - info["pulled"] < interval:
            return {**self._feedInfo(fdef["name"], view), "skipped": True}

        try:
            resp = await s_feeds.download(
                self.session,
                fdef["url"],
                maxsize=self.conf.get("snort:feeds:maxsize"),
                timeout=self.conf.get("snort:feeds:timeout"),
                etag=info.get("etag") if have and not force else None,
                modified=info.get("modified") if have and not force else None,
            )
        except s_feeds.FeedError as err:
            info["error"] = err.mesg
            info["failed"] = now
            self.feedinfo.set(fdef["name"], info)
            raise

        info["pulled"] = now
        info.pop("error", None)
        info.pop("failed", None)
        if resp["status"] == 304:
            self.feedinfo.set(fdef["name"], info)
            return {**self._feedInfo(fdef["name"], view), "skipped": False}

        try:
            parsed = await s_coro.executor(
                s_feeds.parseFeed, fdef, resp["byts"], self.conf.get("snort:feeds:maxsize")
            )
        except s_feeds.FeedError as err:
            info["error"] = err.mesg
            info["failed"] = now
            self.feedinfo.set(fdef["name"], info)
            raise

        await s_coro.executor(_writeFeed, self._feedPath(fdef["name"]), parsed["rules"])

        info.update(
            {
                "sha256": resp["sha256"],
                "etag": resp["etag"],
                "modified": resp["modified"],
                "count": len(parsed["rules"]),
                "enabled": sum(1 for r in parsed["rules"] if r["enabled"]),
                "errors": len(parsed["errors"]),
                "files": len(parsed["files"]),
            }
        )
        self.feedinfo.set(fdef["name"], info)
        if parsed["errors"]:
            logger.warning(
                "The %s feed has %d rules that couldn't be parsed, ex. %s",
                fdef["name"],
                len(parsed["errors"]),
                parsed["errors"][:3],
            )
        return {**self._feedInfo(fdef["name"], view), "skipped": False}

    async def feedChanges(
        self, name: str, view: str, full: bool = False, size: int = FEED_BATCH
    ) -> AsyncIterator[dict[str, Any]]:
        """Yield the changes to sync into ``view`` from a feed's last download, in batches.

        Changes are relative to the last download synced into the view (see ``feedSynced``). If
        there isn't one, or ``full`` is set, every rule is yielded and ``full`` is true, Storm then
        finds the rules that left the feed itself.

        Yields
        ------
        dict
            ``full``, ``upsert`` (rule records to add or update, each with a ``nodedef`` for bulk
            ingest), and ``removed`` (the guids of rules that left the feed).
        """

        fdef = self._reqFeed(name)
        path = self._feedPath(fdef["name"])
        if not os.path.exists(path):
            raise SnortSvcError(f"The {fdef['name']} feed hasn't been downloaded yet.")

        recs = await s_coro.executor(_readFeed, path)
        snap = self._snapPath(fdef["name"], view)
        removed: list[str] = []
        if not full and os.path.exists(snap):
            old = {rec["guid"]: rec for rec in await s_coro.executor(_readFeed, snap)}
            guids = {rec["guid"] for rec in recs}
            removed = [guid for guid in old if guid not in guids]
            recs = [rec for rec in recs if old.get(rec["guid"]) != rec]
        else:
            full = True

        for rec in recs:
            rec["nodedef"] = s_feeds.ruleNodeDef(rec)

        yield {"full": full, "upsert": recs[:size], "removed": removed}
        for idx in range(size, len(recs), size):
            await asyncio.sleep(0)
            yield {"full": full, "upsert": recs[idx : idx + size], "removed": []}

    async def feedSynced(self, name: str, sha256: str, view: str) -> dict[str, Any]:
        """Record that a feed's download (by its sha256) was synced into a view."""

        fdef = self._reqFeed(name)
        info = self.feedinfo.get(fdef["name"], {})
        if info.get("sha256") != sha256:
            raise SnortSvcError(f"The {fdef['name']} feed was downloaded again during the sync.")

        snap = self._snapPath(fdef["name"], view)
        os.makedirs(os.path.dirname(snap), exist_ok=True)
        await s_coro.executor(shutil.copyfile, self._feedPath(fdef["name"]), snap)

        info.setdefault("views", {})[view] = {"sha256": sha256, "at": s_common.now()}
        self.feedinfo.set(fdef["name"], info)
        return self._feedInfo(fdef["name"], view)

    # ---- Scanning ----

    def _reqActive(self) -> tuple[str, dict[str, dict]]:
        if self.active is None:
            raise SnortSvcError(
                "No rules are loaded in the service yet, push them with slib.snort.sync."
            )
        if not self.active[1]:
            raise SnortSvcError(
                "None of the rules pushed to the service are valid, see slib.snort.rule.errors."
            )
        return self.active

    async def _scanFile(self, path: str, sha256: str) -> dict[str, Any]:
        with open(path, "rb") as fd:  # noqa: ASYNC230 - reads 4 bytes
            if not s_engine.isPcap(fd.read(4)):
                raise SnortSvcError(f"file:bytes={sha256} is not a PCAP or PCAPNG file.")

        async with self.scansema:
            rulespath, index = self._reqActive()
            self.inuse[rulespath] = self.inuse.get(rulespath, 0) + 1
            try:
                grouper = HitGrouper(sha256, index)
                count, warnings = await self.snort.scan(rulespath, path, grouper.add)
            finally:
                self._release(rulespath)
        results = grouper.results(count)
        results["warnings"] = warnings
        return results

    async def scanStart(self) -> str:
        """Start a PCAP upload (when Storm streams the PCAP to the service). Returns its ID.

        Send the PCAP with ``scanChunk`` then call ``scanRun``.
        """

        iden = s_common.guid()
        path = os.path.join(self.tmpdir, f"{iden}.pcap")
        self.uploads[iden] = {
            "path": path,
            "size": 0,
            "sha256": hashlib.sha256(),
            "touched": s_common.now(),
        }
        open(path, "wb").close()  # noqa: ASYNC230 - creates an empty file
        return iden

    def _reqUpload(self, iden: str) -> dict[str, Any]:
        upload = self.uploads.get(iden)
        if upload is None:
            raise SnortSvcError(f"Unknown PCAP upload: {iden}")
        upload["touched"] = s_common.now()
        return upload

    def _dropUpload(self, iden: str) -> None:
        upload = self.uploads.pop(iden, None)
        if upload is not None:
            with contextlib.suppress(OSError):
                os.remove(upload["path"])

    async def scanChunk(self, iden: str, byts: bytes) -> int:
        """Append a chunk of the PCAP to an upload. Returns the size so far."""

        upload = self._reqUpload(iden)
        upload["size"] += len(byts)
        if upload["size"] > self.maxsize:
            self._dropUpload(iden)
            raise SnortSvcError(
                f"The PCAP is larger than the service's max size of {self.maxsize} bytes."
            )
        upload["sha256"].update(byts)
        with open(upload["path"], "ab") as fd:  # noqa: ASYNC230 - a small append per chunk
            fd.write(byts)
        return upload["size"]

    async def scanRun(self, iden: str) -> dict[str, Any]:
        """Scan an uploaded PCAP, then remove it. Returns the results (``HitGrouper.results``)."""

        upload = self._reqUpload(iden)
        try:
            return await self._scanFile(upload["path"], upload["sha256"].hexdigest())
        finally:
            self._dropUpload(iden)

    async def scanAxon(self, sha256: str) -> dict[str, Any]:
        """Scan a PCAP in the Axon (``snort:axon``) by its SHA256. Returns the scan results."""

        if not self.axonurl:
            raise SnortSvcError("The service isn't configured with an Axon (snort:axon).")
        try:
            sha256b = binascii.unhexlify(sha256)
        except (binascii.Error, TypeError) as err:
            raise SnortSvcError(f"Not a SHA256 hash: {sha256}") from err
        if len(sha256b) != 32:
            raise SnortSvcError(f"Not a SHA256 hash: {sha256}")

        path = os.path.join(self.tmpdir, f"{s_common.guid()}.pcap")
        try:
            size = 0
            with open(path, "wb") as fd:  # noqa: ASYNC230 - small writes, one per Axon chunk
                async with s_telepath.withTeleEnv(), await s_telepath.openurl(self.axonurl) as axon:
                    if not await axon.has(sha256b):
                        raise SnortSvcError(f"file:bytes={sha256} is not in the Axon.")
                    async for byts in axon.get(sha256b):
                        size += len(byts)
                        if size > self.maxsize:
                            raise SnortSvcError(
                                f"The PCAP is larger than the max size of {self.maxsize} bytes."
                            )
                        fd.write(byts)
            return await self._scanFile(path, sha256.lower())
        except s_exc.SynErr as err:
            raise SnortSvcError(
                f"Unable to read file:bytes={sha256} from the Axon: {err.get('mesg') or err}"
            ) from err
        finally:
            with contextlib.suppress(OSError):
                os.remove(path)
