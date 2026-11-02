"""The slib.malpedia service.

The service keeps a local, normalized snapshot of Malpedia's public data (the library,
actors, families, and YARA rules) in its slab, and tracks which version of every record has
been modeled into each Cortex view. Storm asks the service for the records that changed since
the view's last sync, models them, and reports back what it modeled.

Upstream traffic is kept to a minimum:

- A pull first asks ``/api/get/version`` (a few bytes). If Malpedia hasn't changed since the
  last pull, that's the only request.
- Otherwise the bulk endpoints are pulled once each (bib, references, actors, families, the
  actor and YARA listings, and the YARA rules updated since the last pull): ~8 requests.
- Only the very first pull downloads every YARA rule (one zip).
- Pulls are skipped entirely within ``malpedia:pull:minage`` hours of the last check, and
  serialized, so concurrent syncs never pull twice.

Modeling a view (even a brand new one) never touches Malpedia, it reads the snapshot.
"""

import asyncio
import datetime
import logging
import random
from collections.abc import AsyncIterator, Iterable, Mapping
from typing import Any

import aiohttp
import synapse.common as s_common
import synapse.lib.cell as s_cell
import synapse.lib.coro as s_coro

from . import norm
from .api import MalpediaCellApi
from .client import MalpediaApiError, MalpediaClient

logger = logging.getLogger(__name__)

# One hour, in milliseconds.
HOUR = 60 * 60 * 1000

# The number of records sent to Storm in each batch of changes.
BATCH_SIZE = 250

# The most per-entity requests a pull makes to fill gaps in the bulk data (actors missing from
# /api/get/actors, YARA rules missing from /api/get/yara/after). Past this, the gaps are left
# for the next pull (actors) or filled with one bulk request (YARA).
MAX_GAP_REQUESTS = 25

# A pull is refused (unless forced) if a bulk endpoint returns fewer than this fraction of the
# records already in the snapshot. Malpedia doesn't delete much, so a big drop is far more
# likely to be an upstream glitch than real deletions.
SHRINK_RATIO = 0.5

# The guard only applies to kinds with at least this many records.
SHRINK_MIN = 20

# The kinds with records that can be removed by a shrinking pull.
_GUARDED = ("news", "actor", "family", "yara")


class MalpediaSvcError(Exception):
    """A service operation failed."""

    def __init__(self, mesg: str):
        super().__init__(mesg)
        self.mesg = mesg


def _today() -> datetime.date:
    return datetime.datetime.now(datetime.UTC).date()


def _kvkeys(kv) -> Iterable[str]:
    """The keys of a SafeKeyVal (which isn't a dict, it can only be iterated with keys())."""

    return kv.keys()


def _listify(valu: Any) -> Any:
    """Turn (nested) tuples into lists, so values from msgpack compare equal to fresh ones."""

    if isinstance(valu, (list, tuple)):
        return [_listify(v) for v in valu]
    return valu


def dropDiff(old: Mapping | None, new: Mapping) -> dict:
    """What a record lost since ``old``: removed list items and changed/removed scalars.

    Storm uses this to undo edits it made for the old record (ex. an article that's no longer
    tagged with an actor loses that actor's tag and edge).
    """

    if not old:
        return {}
    drop = {}
    for name, oldv in old.items():
        newv = new.get(name)
        # Stored records come back from msgpack with tuples instead of lists.
        if isinstance(oldv, (list, tuple)):
            newl = [_listify(v) for v in newv] if isinstance(newv, (list, tuple)) else []
            gone = [item for item in (_listify(v) for v in oldv) if item not in newl]
            if gone:
                drop[name] = gone
        elif oldv is not None and oldv != newv:
            drop[name] = oldv
    return drop


class MalpediaSvc(s_cell.Cell):
    """The Cell implementation for the slib.malpedia service."""

    cellapi = MalpediaCellApi

    confdefs = {
        "malpedia:url": {
            "type": "string",
            "default": "https://malpedia.caad.fkie.fraunhofer.de/api",
            "description": "The base URL of Malpedia's REST API.",
        },
        "malpedia:interval": {
            "type": "number",
            "default": 2.0,
            "minimum": 0,
            "description": "The minimum number of seconds between two requests to Malpedia.",
        },
        "malpedia:timeout": {
            "type": "number",
            "default": 300,
            "minimum": 1,
            "description": "Timeout, in seconds, for a single Malpedia request.",
        },
        "malpedia:backoff": {
            "type": "number",
            "default": 5.0,
            "minimum": 0,
            "description": "The base, in seconds, of the exponential backoff between retries.",
        },
        "malpedia:pull:minage": {
            "type": "number",
            "default": 12,
            "minimum": 0,
            "description": (
                "Hours after a check of Malpedia's version before the next sync checks again. "
                "Syncs within this window model the local snapshot without any requests. "
                "Forced syncs ignore it."
            ),
        },
        "malpedia:autosync": {
            "type": "boolean",
            "default": True,
            "description": (
                "When the service is first added to a Cortex, schedule the daily "
                "slib.malpedia.sync cron job and start the initial sync."
            ),
        },
    }

    async def __anit__(self, dirn, *args, **kwargs):
        await s_cell.Cell.__anit__(self, dirn, *args, **kwargs)

        self.info = self.slab.getSafeKeyVal("slib:malpedia:info")
        self.snap = self.slab.getSafeKeyVal("slib:malpedia:snap")
        self.views = self.slab.getSafeKeyVal("slib:malpedia:views")
        self.viewinfo = self.slab.getSafeKeyVal("slib:malpedia:viewinfo")

        self.pulllock = asyncio.Lock()
        self._actorcache: dict[str, dict] | None = None

        self.session = aiohttp.ClientSession(trust_env=True)
        self.onfini(self.session.close)

        self.client = MalpediaClient(
            self.session,
            url=self.conf.get("malpedia:url"),
            interval=self.conf.get("malpedia:interval"),
            timeout=self.conf.get("malpedia:timeout"),
            backoff=self.conf.get("malpedia:backoff"),
        )

    # ---- Storage helpers ----

    def _snapkv(self, kind: str):
        self._reqKind(kind)
        return self.snap.getSubKeyVal(f"{kind}:")

    def _viewkv(self, view: str, kind: str):
        self._reqKind(kind)
        self._reqView(view)
        return self.views.getSubKeyVal(f"{view}:{kind}:")

    @staticmethod
    def _reqKind(kind: str) -> None:
        if kind not in norm.KINDS:
            raise MalpediaSvcError(f"Unknown record kind {kind!r}, use one of {norm.KINDS}.")

    @staticmethod
    def _reqView(view: str) -> None:
        if not isinstance(view, str) or not s_common.isguid(view):
            raise MalpediaSvcError(f"Invalid view iden: {view!r}")

    def _snapRecs(self, kind: str) -> dict[str, dict]:
        return {key: item["rec"] for key, item in self._snapkv(kind).items()}

    def _snapActors(self) -> dict[str, dict]:
        """The snapshot's actor records, cached in memory until the next pull changes them.

        Callers must not modify the returned dict.
        """

        if self._actorcache is None:
            self._actorcache = self._snapRecs("actor")
        return self._actorcache

    def _counts(self) -> dict[str, int]:
        return {kind: sum(1 for _ in _kvkeys(self._snapkv(kind))) for kind in norm.KINDS}

    # ---- Pulling from Malpedia ----

    async def pull(self, force: bool = False) -> dict:
        """Pull Malpedia's data into the snapshot, if it changed.

        Parameters
        ----------
        force : bool
            Check Malpedia even if it was checked within ``malpedia:pull:minage`` hours, pull
            the bulk data even if Malpedia's version didn't change, and apply the pull even if
            it would remove a large share of the snapshot.

        Returns
        -------
        dict
            A summary: whether it ``pulled`` (and if not, the ``reason``), the Malpedia
            ``version``, the ``requests`` sent, per-kind ``added``/``updated``/``removed``
            counts, and ``warnings``.
        """

        async with self.pulllock:
            try:
                summary = await self._pull(force=force)
            except (MalpediaApiError, MalpediaSvcError) as err:
                # The next sync retries, even within malpedia:pull:minage hours.
                self.info.set("failed", err.mesg)
                raise
            except Exception as err:
                # Nothing is stored until the end of a pull, so the snapshot is still intact.
                logger.exception("slib.malpedia: The pull failed unexpectedly.")
                mesg = f"The pull failed unexpectedly: {err!r}"
                self.info.set("failed", mesg)
                raise MalpediaSvcError(mesg) from err
            self.info.pop("failed")
            return summary

    async def _pull(self, force: bool = False) -> dict:
        now = s_common.now()
        start = self.client.count
        complete = self.info.get("complete", False)
        summary = {
            "pulled": False,
            "reason": None,
            "initial": not complete,
            "version": self.info.get("version"),
            "date": self.info.get("date"),
            "requests": 0,
            "added": {},
            "updated": {},
            "removed": {},
            "warnings": [],
        }

        minage = self.conf.get("malpedia:pull:minage") * HOUR
        checked = self.info.get("checked")
        failed = self.info.get("failed")
        if not force and complete and not failed and checked is not None and now - checked < minage:
            summary["reason"] = "checked recently"
            return summary

        version = await self.client.version()
        summary["requests"] = self.client.count - start

        if not force and complete and version.get("version") == self.info.get("version"):
            # Only a successful check counts, a failed pull is retried by the next sync.
            self.info.set("checked", now)
            summary["reason"] = "unchanged"
            return summary

        raw = await self._fetch(complete, summary)
        new = await s_coro.executor(self._build, raw, summary["warnings"])

        if not force:
            self._reqNoShrink(new)

        for kind in norm.KINDS:
            added, updated, removed = await self._store(kind, new[kind])
            summary["added"][kind] = added
            summary["updated"][kind] = updated
            summary["removed"][kind] = removed

        self.info.set("version", version.get("version"))
        self.info.set("date", version.get("date"))
        self.info.set("pulled", now)
        self.info.set("checked", now)
        self.info.set("yaradate", _today().isoformat())
        self.info.set("complete", True)

        summary["pulled"] = True
        summary["version"] = version.get("version")
        summary["date"] = version.get("date")
        summary["requests"] = self.client.count - start
        self.info.set("last", summary)
        self.info.set("requests", self.info.get("requests", 0) + summary["requests"])
        return summary

    async def _fetch(self, complete: bool, summary: dict) -> dict:
        """Request everything a pull needs from Malpedia. Raises before anything is stored."""

        warns = summary["warnings"]
        raw = {
            "actorids": await self.client.listActors(),
            "actors": await self.client.getActors(),
            "families": await self.client.getFamilies(),
            "references": (await self.client.getReferences()).get("references") or {},
            "bib": await self.client.getBib(),
            "yaralist": await self.client.listYara(),
            "extra_actors": {},
        }

        # Actors /api/get/actors is missing (it's keyed by display name, the IDs come from
        # /api/list/actors) are requested one by one, up to a limit.
        matched, unmatched = norm.resolveActorIds(raw["actors"], raw["actorids"])
        missing = sorted(set(raw["actorids"]) - set(matched))
        snapactors = self._snapActors()
        # Actors that are still listed, but couldn't be requested, keep their last known
        # record. Otherwise they'd look removed until a later pull got them.
        raw["kept_actors"] = {}
        for i, aid in enumerate(missing):
            if i < MAX_GAP_REQUESTS:
                try:
                    raw["extra_actors"][aid] = await self.client.getActor(aid)
                    continue
                except MalpediaApiError as err:
                    warns.append(f"Unable to get the actor {aid}: {err.mesg}")
            if aid in snapactors:
                raw["kept_actors"][aid] = snapactors[aid]
        if len(missing) > MAX_GAP_REQUESTS:
            warns.append(
                f"{len(missing) - MAX_GAP_REQUESTS} actors were not in /api/get/actors and "
                "were not requested individually (they keep their last known data), they'll be "
                "retried on the next pull."
            )
        if unmatched:
            warns.append(
                f"{len(unmatched)} actors in /api/get/actors have no matching actor ID: "
                + ", ".join(unmatched[:20])
            )

        listing = norm.yaraListing(raw["yaralist"])
        have = self._snapRecs("yara")
        # _build runs in a thread, so it gets the stored rules here instead of reading the slab.
        raw["haveyara"] = have

        if not complete or not have:
            # The first pull gets every rule in one request.
            raw["yara"] = {"full": True, "rules": []}
            rules = await self.client.getYaraTlp("tlp_white")
            for filename, text in rules.items():
                family, tlp = listing.get(filename, (None, "tlp_white"))
                raw["yara"]["rules"].append((tlp or "tlp_white", filename, text, family))
            return raw

        # After that, only the rules updated since the last pull (with a day of overlap, the
        # endpoint takes a date and Malpedia's clock isn't ours).
        since = self.info.get("yaradate") or _today().isoformat()
        since = (datetime.date.fromisoformat(since) - datetime.timedelta(days=1)).isoformat()
        raw["yara"] = {"full": False, "rules": []}
        for tlp, filename, text in norm.yaraTlpRules(await self.client.getYaraAfter(since)):
            family = listing.get(filename, (None, None))[0]
            raw["yara"]["rules"].append((tlp, filename, text, family))

        # New rules that the listing has but "after" didn't return (ex. an older rule that was
        # just published) are requested by family.
        got = {rule[1] for rule in raw["yara"]["rules"]}
        gaps = sorted(
            {
                fam
                for name, (fam, _) in listing.items()
                if name not in have and name not in got and fam
            }
        )
        if len(gaps) > MAX_GAP_REQUESTS:
            # Cheaper to get every rule at once.
            raw["yara"] = {"full": True, "rules": []}
            for filename, text in (await self.client.getYaraTlp("tlp_white")).items():
                family, tlp = listing.get(filename, (None, "tlp_white"))
                raw["yara"]["rules"].append((tlp or "tlp_white", filename, text, family))
            return raw

        for family in gaps:
            try:
                data = await self.client.getYaraFamily(family)
            except MalpediaApiError as err:
                warns.append(f"Unable to get the YARA rules for {family}: {err.mesg}")
                continue
            for tlp, filename, text in norm.yaraTlpRules(data):
                raw["yara"]["rules"].append((tlp, filename, text, family))

        return raw

    def _build(self, raw: dict, warns: list[str]) -> dict[str, dict[str, dict]]:
        """Normalize a pull's raw data into ``{kind: {key: record}}``.

        This runs in a thread, so it must not touch the slab, everything it needs is in raw.
        """

        matched, _ = norm.resolveActorIds(raw["actors"], raw["actorids"])
        matched.update(raw["extra_actors"])

        actors = {aid: norm.normActor(aid, data) for aid, data in matched.items()}
        for aid, rec in raw.get("kept_actors", {}).items():
            actors.setdefault(aid, rec)
        index = norm.ActorIndex(actors.values())

        families = {}
        for fid, data in raw["families"].items():
            if isinstance(data, Mapping) and isinstance(fid, str) and fid:
                families[fid] = norm.normFamily(fid, data, index)
        norm.addActorLinks(families, matched)
        for fam in families.values():
            norm.withActorTags(fam)

        unresolved = sorted({name for fam in families.values() for name in fam["unresolved"]})
        if unresolved:
            warns.append(
                f"{len(unresolved)} family attributions don't resolve to exactly one actor "
                "(not linked): " + ", ".join(unresolved[:20])
            )

        bibs, errors = norm.parseBib(raw["bib"])
        warns.extend(errors[:20])
        news = norm.buildNews(bibs, raw["references"], families)

        # YARA: rebuild every stored rule (its family's name may have changed) and add the
        # pulled ones. A full pull replaces the set, otherwise the listing is the source of
        # truth for which rules still exist.
        listing = norm.yaraListing(raw["yaralist"])
        texts = {}
        if not raw["yara"]["full"]:
            for key, rec in raw["haveyara"].items():
                texts[key] = (
                    f"tlp_{rec['tlp']}" if rec.get("tlp") else None,
                    key,
                    rec["text"],
                    rec.get("family"),
                )
        for tlp, filename, text, family in raw["yara"]["rules"]:
            texts[filename] = (tlp, filename, text, family)

        if listing:
            gone = [name for name in texts if name not in listing]
            for name in gone:
                texts.pop(name)
        elif texts:
            warns.append("/api/list/yara was empty, no YARA rules were removed.")

        yara = {}
        for tlp, filename, text, family in texts.values():
            lfam, ltlp = listing.get(filename, (None, None))
            rec = norm.normYara(
                filename, text, tlp=ltlp or tlp, family=lfam or family, families=families
            )
            if rec is None:
                warns.append(f"Skipped the YARA file {filename}: it has no rule.")
                continue
            yara[filename] = rec

        return {"news": news, "actor": actors, "family": families, "yara": yara}

    def _reqNoShrink(self, new: Mapping[str, Mapping]) -> None:
        """Refuse a pull that would remove a large share of the snapshot."""

        for kind in _GUARDED:
            have = sum(1 for _ in _kvkeys(self._snapkv(kind)))
            if have >= SHRINK_MIN and len(new[kind]) < have * SHRINK_RATIO:
                raise MalpediaSvcError(
                    f"Malpedia returned {len(new[kind])} {kind} records, but the snapshot has "
                    f"{have}. Refusing to remove that many, this is likely an upstream problem. "
                    "Use a forced sync to apply it anyway."
                )

    async def _store(self, kind: str, recs: Mapping[str, dict]) -> tuple[int, int, int]:
        """Replace a kind's snapshot records. Returns (added, updated, removed) counts."""

        kv = self._snapkv(kind)
        added = updated = removed = 0
        if kind == "actor":
            self._actorcache = None

        for key in list(_kvkeys(kv)):
            if key not in recs:
                kv.delete(key)
                removed += 1
                await asyncio.sleep(0)

        for i, (key, rec) in enumerate(recs.items()):
            rhash = norm.recHash(rec)
            have = kv.get(key)
            if have is not None and have.get("hash") == rhash:
                continue
            kv.set(key, {"hash": rhash, "rec": rec})
            if have is None:
                added += 1
            else:
                updated += 1
            if i % 500 == 0:
                await asyncio.sleep(0)

        return added, updated, removed

    # ---- Modeling a view ----

    async def changes(
        self, view: str, kind: str, full: bool = False, size: int = BATCH_SIZE
    ) -> AsyncIterator[dict]:
        """Yield batches of the records that changed since a view's last sync.

        Each batch is ``{"kind", "total", "upsert": [...], "removed": [...]}``. An upsert item
        is ``{"key", "hash", "new", "rec", "drop"}`` (``drop`` is what the record lost since the
        view's version, see ``dropDiff``). A removed item is ``{"key", "rec"}`` with the view's
        version of a record that's no longer in Malpedia.

        Parameters
        ----------
        full : bool
            Send every record, not only the changed ones (re-model the whole view).
        """

        snap = self._snapkv(kind)
        vkv = self._viewkv(view, kind)
        size = max(1, min(int(size or BATCH_SIZE), 5000))

        keys = []
        for key, item in snap.items():
            have = vkv.get(key)
            if full or have is None or have.get("hash") != item["hash"]:
                keys.append(key)
        removed = [key for key in _kvkeys(vkv) if snap.get(key) is None]
        total = len(keys) + len(removed)

        for i in range(0, len(keys), size):
            batch = {"kind": kind, "total": total, "upsert": [], "removed": []}
            for key in keys[i : i + size]:
                item = snap.get(key)
                if item is None:
                    continue
                old = vkv.get(key)
                oldrec = old.get("rec") if old else None
                batch["upsert"].append(
                    {
                        "key": key,
                        "hash": item["hash"],
                        "new": old is None,
                        "rec": item["rec"],
                        "drop": dropDiff(oldrec, item["rec"]),
                    }
                )
            yield batch

        for i in range(0, len(removed), size):
            batch = {"kind": kind, "total": total, "upsert": [], "removed": []}
            for key in removed[i : i + size]:
                old = vkv.get(key)
                if old is not None:
                    batch["removed"].append({"key": key, "rec": old.get("rec")})
            yield batch

    async def synced(
        self,
        view: str,
        kind: str,
        done: Iterable | None = None,
        removed: Iterable[str] | None = None,
    ) -> int:
        """Record that a view modeled records.

        Parameters
        ----------
        done : list
            ``[key, hash]`` pairs of the modeled records. A record is only marked synced if
            the snapshot still has that version (a pull may have changed it meanwhile).
        removed : list
            Keys of removed records the view handled.

        Returns
        -------
        int
            How many records were marked.
        """

        snap = self._snapkv(kind)
        vkv = self._viewkv(view, kind)
        count = 0
        for pair in done or ():
            if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                raise MalpediaSvcError(f"Expected [key, hash] pairs, got {pair!r}"[:300])
            key, rhash = pair
            item = snap.get(key)
            if item is not None and item["hash"] == rhash:
                vkv.set(key, item)
                count += 1
        for key in removed or ():
            if snap.get(key) is None and vkv.pop(key) is not None:
                count += 1
        return count

    async def viewSynced(self, view: str) -> dict:
        """Record that a view finished a sync, returns the view's sync info."""

        self._reqView(view)
        info = {
            "synced": s_common.now(),
            "version": self.info.get("version"),
            "date": self.info.get("date"),
        }
        self.viewinfo.set(view, info)
        return info

    async def resetView(self, view: str) -> bool:
        """Forget what a view has synced, so its next sync models every record."""

        self._reqView(view)
        await self.views.truncate(f"{view}:")
        self.viewinfo.pop(view)
        return True

    # ---- Status and lookups ----

    async def status(self, view: str | None = None) -> dict:
        """The service's state, and a view's sync state if one is given."""

        info = {
            "version": self.info.get("version"),
            "date": self.info.get("date"),
            "complete": self.info.get("complete", False),
            "pulled": self.info.get("pulled"),
            "checked": self.info.get("checked"),
            "requests": self.info.get("requests", 0),
            "failed": self.info.get("failed"),
            "last": self.info.get("last"),
            "counts": self._counts(),
            "minage": self.conf.get("malpedia:pull:minage"),
            "view": None,
        }
        if view is not None:
            self._reqView(view)
            vinfo = dict(self.viewinfo.get(view) or {})
            vinfo["counts"] = {
                kind: sum(1 for _ in _kvkeys(self._viewkv(view, kind))) for kind in norm.KINDS
            }
            info["view"] = vinfo
        return info

    async def record(self, kind: str, key: str) -> dict | None:
        """A record from the snapshot (news can be looked up by URL), or None."""

        if kind == "news" and not (len(key) == 64 and all(c in "0123456789abcdef" for c in key)):
            key = norm.urlKey(key)
        item = self._snapkv(kind).get(key)
        return item["rec"] if item else None

    async def find(self, kind: str, needle: str) -> list:
        """Search Malpedia's actor or family names and synonyms (``/api/find/*``)."""

        if not needle or not str(needle).strip():
            raise MalpediaSvcError("A search needs a non-empty string.")
        if kind == "actor":
            results = await self.client.findActor(str(needle).strip())
        elif kind == "family":
            results = await self.client.findFamily(str(needle).strip())
        else:
            raise MalpediaSvcError(f"Can only search actors or families, not {kind!r}.")
        out = []
        for item in results:
            if not isinstance(item, Mapping) or not item.get("name"):
                continue
            item = dict(item)
            have = self._snapkv(kind).get(item["name"])
            item["known"] = have is not None
            if have is not None and not item.get("common_name"):
                item["common_name"] = have["rec"].get("name")
            out.append(item)
        return out

    async def refresh(self, kind: str, ident: str) -> dict:
        """Get an actor or family straight from Malpedia, normalized for modeling.

        This doesn't change the snapshot, the next pull does that. It's for checking in on
        one entity (ex. after a new article mentions it) between daily pulls.

        Returns
        -------
        dict
            ``{"actor": [items], "family": [items], "yara": [items], "news": [items]}`` with
            items shaped like ``changes()`` upserts (``drop`` is always empty, a refresh only
            adds).
        """

        ident = str(ident or "").strip()
        if not ident:
            raise MalpediaSvcError("A refresh needs an actor or family ID.")

        def item(rec: dict) -> dict:
            return {
                "key": rec["key"],
                "hash": norm.recHash(rec),
                "new": False,
                "rec": rec,
                "drop": {},
            }

        snapactors = dict(self._snapActors())
        out = {"actor": [], "family": [], "yara": [], "news": []}
        warns = []

        if kind == "actor":
            data = await self.client.getActor(ident)
            actor = norm.normActor(ident, data)
            snapactors[ident] = actor
            index = norm.ActorIndex(snapactors.values())
            out["actor"].append(item(actor))
            fams = data.get("families") if isinstance(data.get("families"), Mapping) else {}
            for fid, fdata in fams.items():
                if isinstance(fdata, Mapping):
                    fam = norm.normFamily(fid, fdata, index)
                    # The actor's page lists the family, so it's linked even if the family's
                    # attribution names don't resolve.
                    fam["actors"] = sorted({*fam["actors"], ident})
                    out["family"].append(item(norm.withActorTags(fam)))
            bibtext = await self.client.getBibActor(ident)
            bibs, errors = norm.parseBib(bibtext)
            warns.extend(errors)
            for url, bibrec in bibs.items():
                out["news"].append(item(norm.newsRecord(url, bibrec, [ident], [])))

        elif kind == "family":
            data = await self.client.getFamily(ident)
            index = norm.ActorIndex(snapactors.values())
            fam = norm.withActorTags(norm.normFamily(ident, data, index))
            out["family"].append(item(fam))
            for tlp, filename, text in norm.yaraTlpRules(await self.client.getYaraFamily(ident)):
                rec = norm.normYara(filename, text, tlp=tlp, family=ident, families={ident: fam})
                if rec is not None:
                    out["yara"].append(item(rec))
            bibtext = await self.client.getBibFamily(ident)
            bibs, errors = norm.parseBib(bibtext)
            warns.extend(errors)
            for url, bibrec in bibs.items():
                out["news"].append(item(norm.newsRecord(url, bibrec, [], [ident])))

        else:
            raise MalpediaSvcError(f"Can only refresh an actor or family, not {kind!r}.")

        out["warnings"] = warns
        return out

    # ---- Scheduling ----

    async def schedInfo(self) -> dict:
        """Whether to schedule syncs when the service is added, and the daily sync time.

        The time is picked at random once per service (and kept), so deployments don't all
        hit Malpedia at the same minute.
        """

        when = self.info.get("schedtime")
        if when is None:
            rand = random.SystemRandom()
            when = (rand.randrange(0, 24), rand.randrange(1, 60))
            self.info.set("schedtime", when)
        hour, minute = when
        return {
            "autosync": self.conf.get("malpedia:autosync"),
            "hour": hour,
            "minute": minute,
            "period": f"daily@{hour:02d}:{minute:02d}",
        }
