"""Rule management for the slib.pcap service: the rules pushed from the Cortex, and rule feeds.

The Cortex is the source of truth for the rules: every enabled ``it:app:snort:rule`` and
``it:app:suricata:rule`` with ``:text`` is pushed to the service (see ``pushStart``/
``pushRules``/``pushDone`` and ``ruleUpdate``), which saves them and builds a rules file for each
engine from every rule the engine can load (Snort for Snort 2.x and 3 rules, Suricata for
Suricata rules).

The service also downloads rule feeds (see ``pcapsvc.feeds``). It doesn't use the feeds' rules
directly, Storm models them as rule nodes (so they can be enabled, disabled, and queried like
any other rule) and then pushes the enabled rules back to the service.

``RuleMixin`` is mixed into ``PcapSvc``, it expects the Cell's ``slab``, ``conf``, ``dirn``, and
the ``snort`` and ``suricata`` engines.
"""


import asyncio
import contextlib
import json
import logging
import os
import shutil
from collections.abc import AsyncIterator
from typing import Any

import synapse.common as s_common
import synapse.lib.coro as s_coro
import synapse.lib.msgpack as s_msgpack

from . import feeds as p_feeds
from . import rules as p_rules

logger = logging.getLogger(__name__)


PUSH_IDLE = 60 * 60 * 1000
"""Rule pushes untouched for this long (ms) are removed."""

FEED_BATCH = 500
"""How many rule records ``feedChanges`` yields at a time."""


class RuleSvcError(Exception):
    """Raised for invalid rule and feed requests."""

    def __init__(self, mesg: str) -> None:
        super().__init__(mesg)
        self.mesg = mesg


def _prepare(entries: dict[str, tuple[str, str]]) -> dict[str, Any]:
    """Parse the pushed rules and pick one rule per engine and gid:sid (run in an executor).

    Snort 2.x and Snort 3 rules share Snort's gid:sid namespace, Suricata has its own.

    Returns a dict of ``rules`` (engine -> guid -> text), ``meta`` (guid -> (gid, sid, rev)),
    and ``errors`` (guid -> error).
    """

    rules: dict[str, dict[str, str]] = {engine: {} for engine in p_rules.ENGINES}
    meta: dict[str, tuple[int, int, int]] = {}
    errors: dict[str, str] = {}
    best: dict[tuple[str, int, int], str] = {}

    for guid in sorted(entries):
        text, engine = entries[guid]
        try:
            rule = p_rules.parseRule(text, enabled=True)
        except p_rules.RuleError as err:
            errors[guid] = err.mesg
            continue

        space = "suricata" if engine == p_rules.ENGINE_SURICATA else "snort"
        key = (space, rule["gid"], rule["sid"])
        meta[guid] = (rule["gid"], rule["sid"], rule["rev"])
        prev = best.get(key)
        if prev is not None:
            # Keep the highest rev, or the first guid (they are sorted) on a tie.
            gidsid = p_rules.ruleKey(*key[1:])
            if meta[prev][2] >= rule["rev"]:
                errors[guid] = (f"Duplicate {space} gid:sid {gidsid}, rule {prev} "
                                f"(rev {meta[prev][2]}) is used instead.")
                continue
            errors[prev] = (f"Duplicate {space} gid:sid {gidsid}, rule {guid} "
                            f"(rev {rule['rev']}) is used instead.")
            for byeng in rules.values():
                byeng.pop(prev, None)

        best[key] = guid
        rules[engine][guid] = rule["text"]

    return {"rules": rules, "meta": meta, "errors": errors}


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


class RuleMixin:
    """Rule and feed management, mixed into ``PcapSvc``."""

    async def _initRules(self) -> None:
        self.ruleinfo = self.slab.getSafeKeyVal("slib:pcap:ruleinfo")
        self.corpus = self.slab.getSafeKeyVal("slib:pcap:rules")
        self.ruleerrs = self.slab.getSafeKeyVal("slib:pcap:ruleerrs")
        self.feeddefs = self.slab.getSafeKeyVal("slib:pcap:feeds")
        self.feedinfo = self.slab.getSafeKeyVal("slib:pcap:feedinfo")

        if not self.ruleinfo.get("feeds:seeded"):
            for fdef in self.conf.get("pcap:feeds"):
                fdef = p_feeds.normFeed(fdef)
                self.feeddefs.set(fdef["name"], dict(fdef))
            self.ruleinfo.set("feeds:seeded", True)

        self.rulesdir = os.path.join(self.dirn, "rules", "active")
        self.feeddir = os.path.join(self.dirn, "rules", "feeds")
        for path in (self.rulesdir, self.feeddir):
            os.makedirs(path, exist_ok=True)

        self.buildlock = asyncio.Lock()
        self.pushes: dict[str, dict[str, Any]] = {}
        self.inuse: dict[str, int] = {}
        # The loaded rules of each engine ("snort", "suricata"): (rules file, gid:sid -> info).
        self.active: dict[str, tuple[str, dict[str, dict]]] = self._loadActive()

        if self.ruleinfo.get("rules:count") and \
                set(self.ruleinfo.get("rules:active") or ()) - set(self.active):
            # Rules were pushed, but rules files are gone (ex. a new volume), rebuild them.
            self.schedCoro(self._initBuild())

    # ---- State ----

    def _loadActive(self) -> dict[str, tuple[str, dict[str, dict]]]:
        active = {}
        for engine, name in (self.ruleinfo.get("rules:active") or {}).items():
            path = os.path.join(self.rulesdir, name)
            if not os.path.exists(path):
                continue
            try:
                with open(path + ".index.json", encoding="utf-8") as fd:
                    active[engine] = (path, json.load(fd))
            except (OSError, ValueError):
                continue
        return active

    async def _initBuild(self) -> None:
        try:
            await self._build()
        except Exception:  # pragma: no cover - logged for the operator
            logger.exception("Unable to rebuild the rules at startup.")

    def _prunePushes(self, idle: int = PUSH_IDLE) -> list[str]:
        """Remove rule pushes untouched for ``idle`` ms. Returns their IDs."""

        cutoff = s_common.now() - idle
        stale = [iden for iden, push in self.pushes.items() if push["touched"] < cutoff]
        for iden in stale:
            self.pushes.pop(iden)
        return stale

    def _ruleSummary(self, changed: bool, took: int = 0) -> dict[str, Any]:
        return {
            "rules": self.ruleinfo.get("rules:count", 0),
            "loaded": sum(len(idx) for _, idx in self.active.values()),
            "engines": {eng: len(idx) for eng, (_, idx) in self.active.items()},
            "invalid": self.ruleinfo.get("rules:invalid", 0),
            "took": took,
            "changed": changed,
        }

    async def ruleStatus(self) -> dict[str, Any]:
        """The rules the service has: pushed, loaded (per engine), invalid, and the last build."""

        return {
            **self._ruleSummary(False),
            "built": self.ruleinfo.get("rules:built"),
            "took": self.ruleinfo.get("rules:took"),
            "pushed": self.ruleinfo.get("rules:pushed"),
            "building": self.buildlock.locked(),
            "error": self.ruleinfo.get("rules:error"),
        }

    # ---- Building ----

    async def _buildSnort(self, rules: dict[str, dict[str, str]], name: str,
                          errors: dict[str, str]) -> list[str] | None:
        """Build the Snort rules file. Returns the valid guids, or None without Snort."""

        snort2, snort3 = rules[p_rules.ENGINE_SNORT2], rules[p_rules.ENGINE_SNORT3]
        if not self.snort.available():
            for guid in (*snort2, *snort3):
                errors[guid] = "The service doesn't have Snort, so Snort rules can't be run."
            return None
        converted, cerrs = await self.snort.convert(snort2)
        errors.update(cerrs)
        texts = dict(snort3)
        texts.update(converted)
        valid, verrs = await self.snort.validate(texts, os.path.join(self.rulesdir, name))
        errors.update(verrs)
        return valid

    async def _buildSuricata(self, rules: dict[str, dict[str, str]], name: str,
                             errors: dict[str, str]) -> list[str] | None:
        """Build the Suricata rules file. Returns the valid guids, or None without Suricata."""

        texts = rules[p_rules.ENGINE_SURICATA]
        if not self.suricata.available():
            for guid in texts:
                errors[guid] = "The service doesn't have Suricata, so Suricata rules can't be run."
            return None
        valid, verrs = await self.suricata.validate(texts, os.path.join(self.rulesdir, name))
        errors.update(verrs)
        return valid

    async def _build(self) -> dict[str, Any]:
        """Build new rules files from every pushed rule and load them. Returns a summary."""

        async with self.buildlock:
            start = s_common.now()
            entries = {guid: (valu[0], valu[1]) for guid, valu in self.corpus.items()}
            prep = await s_coro.executor(_prepare, entries)
            errors: dict[str, str] = prep["errors"]
            bid = s_common.guid()

            built: dict[str, list[str] | None] = {}
            try:
                built["snort"] = await self._buildSnort(prep["rules"], f"snort-{bid}.rules",
                                                        errors)
                built["suricata"] = await self._buildSuricata(
                    prep["rules"], f"suricata-{bid}.rules", errors)
            except Exception as err:
                mesg = getattr(err, "mesg", None) or str(err)
                self.ruleinfo.set("rules:error", mesg)
                for engine in ("snort", "suricata"):
                    with contextlib.suppress(OSError):
                        os.remove(os.path.join(self.rulesdir, f"{engine}-{bid}.rules"))
                raise

            old = self.active
            active, names = {}, {}
            for engine, valid in built.items():
                if valid is None:
                    continue
                index = {}
                for guid in valid:
                    gid, sid, rev = prep["meta"][guid]
                    index[p_rules.ruleKey(gid, sid)] = {"guid": guid, "rev": rev}
                name = f"{engine}-{bid}.rules"
                path = os.path.join(self.rulesdir, name)
                await s_coro.executor(_writeJson, path + ".index.json", index)
                active[engine] = (path, index)
                names[engine] = name

            await self.ruleerrs.truncate()
            for guid, mesg in errors.items():
                self.ruleerrs.set(guid, mesg)

            self.active = active
            took = s_common.now() - start
            self.ruleinfo.set("rules:active", names)
            self.ruleinfo.set("rules:count", len(entries))
            self.ruleinfo.set("rules:invalid", len(errors))
            self.ruleinfo.set("rules:built", s_common.now())
            self.ruleinfo.set("rules:took", took)
            self.ruleinfo.pop("rules:error")
            for engine, (path, _) in old.items():
                if active.get(engine, (None,))[0] != path:
                    self._release(path, drop=True)

            summary = self._ruleSummary(True, took)
            logger.info("Built the rules: %d rules, %d loaded, %d invalid, in %d ms",
                        summary["rules"], summary["loaded"], summary["invalid"], took)
            return summary

    def _acquire(self, engine: str) -> tuple[str, dict[str, dict]] | None:
        """Use an engine's loaded rules for a run (see ``_release``), None if it has none."""

        active = self.active.get(engine)
        if active is None or not active[1]:
            return None
        self.inuse[active[0]] = self.inuse.get(active[0], 0) + 1
        return active

    def _release(self, path: str, drop: bool = False) -> None:
        """Release a rules file used by a run, removing it once it's unused and not active."""

        if drop:
            self.inuse.setdefault(path, 0)
        else:
            self.inuse[path] = self.inuse.get(path, 1) - 1
        isactive = any(path == act[0] for act in self.active.values())
        if self.inuse.get(path, 0) <= 0 and not isactive:
            self.inuse.pop(path, None)
            for fpath in (path, path + ".index.json"):
                with contextlib.suppress(OSError):
                    os.remove(fpath)

    def _needsBuild(self) -> bool:
        """Whether the rules must be built even if they didn't change (ex. the last build
        failed)."""

        hasrules = next(iter(self.corpus.keys()), None) is not None
        missing = set(self.ruleinfo.get("rules:active") or ()) - set(self.active)
        return (hasrules and (not self.active or bool(missing))) or \
            bool(self.ruleinfo.get("rules:error"))

    # ---- Pushes ----

    @staticmethod
    def _normRule(item: Any) -> tuple[str, str, str]:
        """Validate a pushed (guid, form, text, engine) rule. Returns (guid, text, engine)."""

        try:
            guid, form, text, engine = item
        except (TypeError, ValueError) as err:
            raise RuleSvcError(
                f"Rules must be pushed as (guid, form, text, engine), got: {item!r}") from err
        if not s_common.isguid(guid):
            raise RuleSvcError(f"Invalid rule guid: {guid!r}")
        if not isinstance(text, str) or not text.strip():
            raise RuleSvcError(f"{form}={guid} has no :text.")
        try:
            engine = p_rules.ruleEngine(form, engine)
        except p_rules.RuleError as err:
            raise RuleSvcError(f"{form}={guid}: {err.mesg}") from None
        return guid, text, engine

    async def pushStart(self) -> str:
        """Start a push of every enabled rule in the Cortex. Returns the push ID.

        Send the rules with ``pushRules`` then call ``pushDone``, which replaces the service's
        rules with the pushed rules.
        """

        self._prunePushes()
        iden = s_common.guid()
        self.pushes[iden] = {"rules": {}, "touched": s_common.now()}
        return iden

    def _reqPush(self, iden: str) -> dict[str, Any]:
        push = self.pushes.get(iden)
        if push is None:
            raise RuleSvcError(f"Unknown rule push: {iden}")
        push["touched"] = s_common.now()
        return push

    async def pushRules(self, iden: str, rules: list) -> int:
        """Add a batch of (guid, form, text, engine) rules to a push. Returns the rules pushed
        so far."""

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
        self.ruleinfo.set("rules:pushed", s_common.now())
        if not force and current == rules and not self._needsBuild():
            return self._ruleSummary(False)

        for guid in current:
            if guid not in rules:
                self.corpus.delete(guid)
        for guid, (text, engine) in rules.items():
            if current.get(guid) != (text, engine):
                self.corpus.set(guid, (text, engine))
        return await self._build()

    async def ruleUpdate(self, rules: list | None = None,
                         dels: list | None = None) -> dict[str, Any]:
        """Add/update some (guid, form, text, engine) rules and remove some rules (by guid),
        then rebuild.

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
            summary = self._ruleSummary(False)

        summary["errors"] = {
            guid: mesg for guid in guids if (mesg := self.ruleerrs.get(guid)) is not None
        }
        return summary

    async def rebuild(self) -> dict[str, Any]:
        """Rebuild the rules files from the service's rules (ex. after an engine upgrade)."""

        return await self._build()

    async def ruleErrors(self, guids: list[str] | None = None) -> dict[str, str]:
        """The errors of rules the engines couldn't load (guid -> error)."""

        if guids is not None:
            return {guid: mesg for guid in guids if (mesg := self.ruleerrs.get(guid)) is not None}
        return dict(self.ruleerrs.items())

    async def ruleInfo(self, guid: str) -> dict[str, Any]:
        """Whether a rule was pushed to the service, is loaded, and its error if it isn't."""

        pushed = self.corpus.get(guid)
        error = self.ruleerrs.get(guid)
        return {
            "pushed": pushed is not None,
            "engine": pushed[1] if pushed else None,
            "loaded": pushed is not None and error is None and bool(self.active),
            "error": error,
        }

    async def ruleParse(self, text: str, engine: str | None = None) -> dict[str, Any]:
        """Parse rule text into the metadata Storm models (see ``pcapsvc.rules.parseRule``).

        The rule's guid is unique to its engine and gid:sid, so adding the same rule again
        updates the same node.
        """

        try:
            engine = p_rules.normEngine(engine)
            rule = p_rules.parseRule(text)
        except p_rules.RuleError as err:
            raise RuleSvcError(err.mesg) from err
        rule = dict(rule)
        rule["id"] = p_rules.ruleId(rule)
        rule["engine"] = engine
        rule["form"] = p_rules.FORMS[engine]
        space = "suricata" if engine == p_rules.ENGINE_SURICATA else "snort"
        rule["guid"] = s_common.guid(("slib.pcap.custom", space, rule["gid"], rule["sid"]))
        return rule

    async def ruleCheck(self, text: str, engine: str | None = None) -> str | None:
        """Check if an engine can load a rule. Returns the error, or None if it's valid."""

        try:
            engine = p_rules.normEngine(engine)
        except p_rules.RuleError as err:
            raise RuleSvcError(err.mesg) from err
        if engine == p_rules.ENGINE_SURICATA:
            if not self.suricata.available():
                raise RuleSvcError("The service doesn't have Suricata.")
            return await self.suricata.check(text)
        if not self.snort.available():
            raise RuleSvcError("The service doesn't have Snort.")
        return await self.snort.check(text, engine)

    # ---- Feeds ----

    def _reqFeed(self, name: str) -> p_feeds.FeedDef:
        fdef = self.feeddefs.get(str(name).lower())
        if fdef is None:
            raise RuleSvcError(f"Unknown feed: {name}")
        return fdef

    def _feedPath(self, name: str) -> str:
        return os.path.join(self.feeddir, f"{name}.mpk")

    def _snapDir(self, name: str) -> str:
        return os.path.join(self.feeddir, "synced", name)

    def _snapPath(self, name: str, view: str) -> str:
        if not s_common.isguid(view):
            raise RuleSvcError(f"Invalid view iden: {view!r}")
        return os.path.join(self._snapDir(name), f"{view}.mpk")

    def _feedInfo(self, name: str, view: str | None = None) -> dict[str, Any]:
        """A feed's state, with ``synced`` (the sha256 last synced into ``view``)."""

        info = self.feedinfo.get(name, {})
        info["synced"] = info.get("views", {}).get(view, {}).get("sha256") if view else None
        return info

    def _dropSync(self, name: str) -> None:
        """Forget what was synced into each view, the next sync of the feed is a full sync."""

        shutil.rmtree(self._snapDir(name), ignore_errors=True)

    def _feedOut(self, fdef: p_feeds.FeedDef) -> dict[str, Any]:
        return {**fdef, "form": p_rules.FORMS[fdef["engine"]],
                "ruleset": p_feeds.rulesetGuid(fdef["name"])}

    async def feeds(self, view: str | None = None) -> list[dict[str, Any]]:
        """Every feed's definition, its ruleset guid, and the state of its last download (and
        sync into ``view``). URLs keep their ``${secret}`` placeholders."""

        return [{**self._feedOut(fdef), "info": self._feedInfo(name, view)}
                for name, fdef in self.feeddefs.items()]

    async def feedAdd(self, fdef: dict[str, Any]) -> dict[str, Any]:
        """Add (or replace) a feed."""

        try:
            fdef = p_feeds.normFeed(fdef)
        except p_feeds.FeedError as err:
            raise RuleSvcError(err.mesg) from err
        prev = self.feeddefs.get(fdef["name"])
        self.feeddefs.set(fdef["name"], dict(fdef))
        if prev is not None and (prev["url"], prev["engine"], prev["exclude"]) != (
                fdef["url"], fdef["engine"], fdef["exclude"]):
            # The feed's content will be different, download it again on the next sync.
            self.feedinfo.pop(fdef["name"])
            self._dropSync(fdef["name"])
        return self._feedOut(fdef)

    async def feedDel(self, name: str) -> dict[str, Any]:
        """Remove a feed (its nodes stay in the Cortex). Returns the removed feed."""

        fdef = self._reqFeed(name)
        self.feeddefs.delete(fdef["name"])
        self.feedinfo.pop(fdef["name"])
        with contextlib.suppress(OSError):
            os.remove(self._feedPath(fdef["name"]))
        self._dropSync(fdef["name"])
        return self._feedOut(fdef)

    async def feedEnable(self, name: str, enabled: bool = True) -> dict[str, Any]:
        """Enable or disable a feed (disabled feeds aren't downloaded or synced)."""

        fdef = self._reqFeed(name)
        fdef["enabled"] = bool(enabled)
        self.feeddefs.set(fdef["name"], fdef)
        return self._feedOut(fdef)

    async def feedPull(self, name: str, force: bool = False,
                       view: str | None = None) -> dict[str, Any]:
        """Download a feed, if it's due (see ``pcap:feeds:interval``) or ``force`` is set.

        The feed's parsed rules are saved by the service, Storm reads them with
        ``feedChanges``.

        Returns
        -------
        dict
            The feed's state, with ``pulled`` (the last download), ``sha256`` (of the
            download), ``synced`` (the sha256 last synced into ``view``, see ``feedSynced``),
            ``count`` (rules), ``errors`` (unparsable rules), and ``skipped`` (true if it
            wasn't due).
        """

        fdef = self._reqFeed(name)
        info = self._feedInfo(fdef["name"], view)
        info.pop("synced")
        now = s_common.now()
        interval = int(self.conf.get("pcap:feeds:interval") * 3600 * 1000)
        have = os.path.exists(self._feedPath(fdef["name"]))

        if not force and have and info.get("pulled") and now - info["pulled"] < interval:
            return {**self._feedInfo(fdef["name"], view), "skipped": True}

        secrets = self.conf.get("pcap:feeds:secrets")
        try:
            url = p_feeds.feedUrl(fdef["url"], secrets)
            resp = await p_feeds.download(
                self.session, url,
                maxsize=self.conf.get("pcap:feeds:maxsize"),
                timeout=self.conf.get("pcap:feeds:timeout"),
                etag=info.get("etag") if have and not force else None,
                modified=info.get("modified") if have and not force else None,
            )
        except p_feeds.FeedError as err:
            err.mesg = p_feeds.redact(err.mesg, secrets)
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
                p_feeds.parseFeed, fdef, resp["byts"], self.conf.get("pcap:feeds:maxsize"))
        except p_feeds.FeedError as err:
            info["error"] = err.mesg
            info["failed"] = now
            self.feedinfo.set(fdef["name"], info)
            raise

        await s_coro.executor(_writeFeed, self._feedPath(fdef["name"]), parsed["rules"])

        info.update({
            "sha256": resp["sha256"],
            "etag": resp["etag"],
            "modified": resp["modified"],
            "count": len(parsed["rules"]),
            "enabled": sum(1 for r in parsed["rules"] if r["enabled"]),
            "errors": len(parsed["errors"]),
            "files": len(parsed["files"]),
        })
        self.feedinfo.set(fdef["name"], info)
        if parsed["errors"]:
            logger.warning("The %s feed has %d rules that couldn't be parsed, ex. %s",
                           fdef["name"], len(parsed["errors"]), parsed["errors"][:3])
        return {**self._feedInfo(fdef["name"], view), "skipped": False}

    async def feedChanges(self, name: str, view: str, full: bool = False,
                          size: int = FEED_BATCH) -> AsyncIterator[dict[str, Any]]:
        """Yield the changes to sync into ``view`` from a feed's last download, in batches.

        Changes are relative to the last download synced into the view (see ``feedSynced``).
        If there isn't one, or ``full`` is set, every rule is yielded and ``full`` is true,
        Storm then finds the rules that left the feed itself.

        Yields
        ------
        dict
            ``full``, ``upsert`` (rule records to add or update, each with a ``nodedef`` for
            bulk ingest), and ``removed`` (the guids of rules that left the feed).
        """

        fdef = self._reqFeed(name)
        path = self._feedPath(fdef["name"])
        if not os.path.exists(path):
            raise RuleSvcError(f"The {fdef['name']} feed hasn't been downloaded yet.")

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
            rec["nodedef"] = p_feeds.ruleNodeDef(rec)

        yield {"full": full, "upsert": recs[:size], "removed": removed}
        for idx in range(size, len(recs), size):
            await asyncio.sleep(0)
            yield {"full": full, "upsert": recs[idx: idx + size], "removed": []}

    async def feedSynced(self, name: str, sha256: str, view: str) -> dict[str, Any]:
        """Record that a feed's download (by its sha256) was synced into a view."""

        fdef = self._reqFeed(name)
        info = self.feedinfo.get(fdef["name"], {})
        if info.get("sha256") != sha256:
            raise RuleSvcError(f"The {fdef['name']} feed was downloaded again during the sync.")

        snap = self._snapPath(fdef["name"], view)
        os.makedirs(os.path.dirname(snap), exist_ok=True)
        await s_coro.executor(shutil.copyfile, self._feedPath(fdef["name"]), snap)

        info.setdefault("views", {})[view] = {"sha256": sha256, "at": s_common.now()}
        self.feedinfo.set(fdef["name"], info)
        return self._feedInfo(fdef["name"], view)
