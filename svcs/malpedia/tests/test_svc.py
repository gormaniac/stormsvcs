"""Tests for the slib.malpedia service: pulling, the snapshot, and per-view change tracking."""

import asyncio
import datetime
from unittest import mock

import synapse.common as s_common
import synapse.tests.utils as s_tests

from malpediasvc import norm
from malpediasvc import svc as m_svc
from malpediasvc.svc import MalpediaSvcError

from . import fakemalpedia as fm

VIEW = "a" * 32
VIEW2 = "b" * 32

# The requests an initial pull makes.
INITIAL = [
    "/api/get/version",
    "/api/list/actors",
    "/api/get/actors",
    "/api/get/families",
    "/api/get/references",
    "/api/get/bib",
    "/api/list/yara",
    "/api/get/actor/turla",
    "/api/get/yara/tlp_white/zip",
]


async def drain(svc, view, kind, full=False, size=250):
    """All the batches of changes for a view, merged into one."""
    merged = {"upsert": [], "removed": [], "total": 0}
    async for batch in svc.changes(view, kind, full=full, size=size):
        merged["upsert"].extend(batch["upsert"])
        merged["removed"].extend(batch["removed"])
        merged["total"] = batch["total"]
    return merged


async def syncView(svc, view):
    """Mark every change as synced in a view, like Storm does. Returns the changes."""
    out = {}
    for kind in norm.KINDS:
        changes = await drain(svc, view, kind)
        done = [[item["key"], item["hash"]] for item in changes["upsert"]]
        gone = [item["key"] for item in changes["removed"]]
        await svc.synced(view, kind, done=done, removed=gone)
        out[kind] = changes
    await svc.viewSynced(view)
    return out


class TestMalpediaPull(s_tests.SynTest):
    async def test_initial_and_unchanged(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            summary = await svc.pull()
            assert summary["pulled"] is True
            assert summary["initial"] is True
            assert summary["version"] == 26601
            assert summary["requests"] == len(INITIAL)
            assert fake.requests == INITIAL
            assert summary["added"] == {"news": 5, "actor": 4, "family": 3, "yara": 3}
            assert summary["removed"] == {"news": 0, "actor": 0, "family": 0, "yara": 0}
            assert any("Hidden Bear" in w and "Nobody Knows" in w for w in summary["warnings"])

            status = await svc.status()
            assert status["complete"] is True
            assert status["counts"] == {"news": 5, "actor": 4, "family": 3, "yara": 3}
            assert status["requests"] == len(INITIAL)
            assert status["last"]["version"] == 26601
            assert status["view"] is None

            # Malpedia didn't change, only its version is requested.
            summary = await svc.pull()
            assert summary == {**summary, "pulled": False, "reason": "unchanged", "requests": 1}
            assert fake.requests[len(INITIAL):] == ["/api/get/version"]

            # Within malpedia:pull:minage hours of a check, nothing is requested at all.
            svc.conf["malpedia:pull:minage"] = 12
            summary = await svc.pull()
            assert summary["pulled"] is False
            assert summary["reason"] == "checked recently"
            assert summary["requests"] == 0
            assert len(fake.requests) == len(INITIAL) + 1

            # Unless it's forced, which pulls the bulk data even though the version is the same,
            # and every YARA rule again (MALP-04).
            summary = await svc.pull(force=True)
            assert summary["pulled"] is True
            assert summary["initial"] is False
            assert summary["yarafull"] is True
            assert summary["added"] == {"news": 0, "actor": 0, "family": 0, "yara": 0}
            assert summary["updated"] == {"news": 0, "actor": 0, "family": 0, "yara": 0}
            assert fake.countPaths("/api/get/yara/tlp_white/zip") == 2
            assert fake.countPaths("/api/get/yara/after/") == 0
            assert fake.countPaths("/api/get/misp") == 0

    async def test_incremental(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            await svc.pull()
            await syncView(svc, VIEW)
            start = len(fake.requests)

            state = fake.state
            state["version"] = {"version": 26602, "date": "2026-10-31T10:00:00Z"}
            # A new alias, a removed actor, a re-attributed family, an unlinked article, a
            # removed rule, an updated rule, and new rules that "after" did and didn't return.
            state["families"]["win.xagent"]["alt_names"].append("Sofacy Agent")
            state["actors"].pop("[Vault 7/8]")
            state["actorids"].remove("[vault_7_8]")
            state["families"]["win.wannacryptor"]["attribution"] = []
            state["references"][fm.URL_SEDNIT] = state["references"][fm.URL_SEDNIT][:1]
            state["yara"]["tlp_white"].pop("win.xagent_auto.yar")
            text = fm.YARA_WANNA_W0.replace("20170515", "20261031")
            state["yara"]["tlp_white"]["win.wannacryptor_w0.yar"] = ("win.wannacryptor", text)
            state["yara"]["tlp_white"]["win.wannacryptor_w1.yar"] = (
                "win.wannacryptor", fm.YARA_WANNA_W0.replace("win_wannacryptor_w0", "win_wannacryptor_w1"))
            state["yara"]["tlp_white"]["win.sedreco_w0.yar"] = (
                "win.sedreco", fm.YARA_WANNA_W0.replace("win_wannacryptor_w0", "win_sedreco_w0"))
            state["yara_after"] = {"tlp_white": ["win.wannacryptor_w0.yar", "win.wannacryptor_w1.yar"]}

            summary = await svc.pull()
            assert summary["pulled"] is True
            assert summary["version"] == 26602
            yesterday = (datetime.datetime.now(datetime.UTC).date() - datetime.timedelta(days=1)).isoformat()
            assert fake.requests[start:] == [
                "/api/get/version",
                "/api/list/actors",
                "/api/get/actors",
                "/api/get/families",
                "/api/get/references",
                "/api/get/bib",
                "/api/list/yara",
                "/api/get/actor/turla",
                f"/api/get/yara/after/{yesterday}",
                # The new rule "after" didn't return is requested with its family's rules.
                "/api/get/yara/win.sedreco",
            ]
            assert summary["added"] == {"news": 0, "actor": 0, "family": 0, "yara": 2}
            assert summary["updated"] == {"news": 1, "actor": 0, "family": 2, "yara": 1}
            assert summary["removed"] == {"news": 0, "actor": 1, "family": 0, "yara": 1}

            changes = await syncView(svc, VIEW)
            news = changes["news"]["upsert"]
            assert len(news) == 1
            assert news[0]["rec"]["url"] == fm.URL_SEDNIT
            assert news[0]["new"] is False
            assert news[0]["drop"] == {"actors": [["apt28", "threat.apt28"]]}

            fams = {item["key"]: item for item in changes["family"]["upsert"]}
            assert set(fams) == {"win.xagent", "win.wannacryptor"}
            assert fams["win.xagent"]["drop"] == {}
            assert list(fams["win.xagent"]["rec"]["aliases"]) == ["Sofacy Agent", "chopstick", "splm"]
            # Only the fields Storm undoes are in the drop diff.
            assert fams["win.wannacryptor"]["drop"] == {"actortags": [["lazarus_group", "threat.lazarus_group"]]}

            assert [item["key"] for item in changes["actor"]["removed"]] == ["[vault_7_8]"]
            assert changes["actor"]["removed"][0]["rec"]["name"] == "[Vault 7/8]"

            yara = {item["key"]: item for item in changes["yara"]["upsert"]}
            assert set(yara) == {"win.wannacryptor_w0.yar", "win.wannacryptor_w1.yar", "win.sedreco_w0.yar"}
            # A new rule text doesn't need anything undone (and the old text isn't sent).
            assert yara["win.wannacryptor_w0.yar"]["drop"] == {}
            assert yara["win.wannacryptor_w0.yar"]["rec"]["updated"] == "2026-10-31"
            assert yara["win.sedreco_w0.yar"]["rec"]["familyname"] == "Sedreco"
            assert [item["key"] for item in changes["yara"]["removed"]] == ["win.xagent_auto.yar"]

            # Synced views have nothing left to do.
            for kind in norm.KINDS:
                assert (await drain(svc, VIEW, kind))["total"] == 0

    async def test_family_rename_updates_rules(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            await svc.pull()
            fake.state["version"]["version"] += 1
            fake.state["families"]["win.xagent"]["common_name"] = "XAgent"
            await svc.pull()
            rec = await svc.record("yara", "win.xagent_w0.yar")
            assert rec["familyname"] == "XAgent"

    async def test_yara_gaps_use_the_zip(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            await svc.pull()
            fake.state["version"]["version"] += 1
            for i in range(m_svc.MAX_GAP_REQUESTS + 1):
                fake.state["yara"]["tlp_white"][f"win.new{i}_w0.yar"] = (
                    f"win.new{i}", f"rule win_new{i}_w0 {{ condition: true }}")
            summary = await svc.pull()
            assert summary["added"]["yara"] == m_svc.MAX_GAP_REQUESTS + 1
            assert fake.countPaths("/api/get/yara/tlp_white/zip") == 2
            assert fake.countPaths("/api/get/yara/win.new") == 0

    async def test_empty_yara_listing(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            await svc.pull()
            fake.state["version"]["version"] += 1
            fake.state["yara"] = {}
            summary = await svc.pull()
            assert summary["removed"]["yara"] == 0
            assert "/api/list/yara was empty, no YARA rules were removed." in summary["warnings"]

    async def test_missing_actors(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            fake.state["actorids"].extend(["gone1", "gone2"])
            fake.state["actors"]["Unknown Name"] = {"value": "Unknown Name", "meta": {}}
            summary = await svc.pull()
            assert any("Unable to get the actor gone1" in w for w in summary["warnings"])
            assert any("have no matching actor ID: Unknown Name" in w for w in summary["warnings"])
            assert summary["added"]["actor"] == 4

            # An actor that's still listed but can't be requested keeps its last known data,
            # it isn't removed.
            fake.state["version"]["version"] += 1
            fake.state["errors"]["/api/get/actor/turla"] = [500] * 10
            summary = await svc.pull()
            assert any("Unable to get the actor turla" in w for w in summary["warnings"])
            assert summary["removed"]["actor"] == 0
            assert (await svc.record("actor", "turla"))["name"] == "Turla"
            fake.state["errors"].clear()

            # Same for actors past the per-pull request limit.
            fake.state["version"]["version"] += 1
            with mock.patch.object(m_svc, "MAX_GAP_REQUESTS", 0):
                summary = await svc.pull()
            assert summary["removed"]["actor"] == 0
            assert summary["updated"]["actor"] == 0
            assert (await svc.record("actor", "turla"))["name"] == "Turla"

            # An actor that's no longer listed is removed.
            fake.state["version"]["version"] += 1
            fake.state["actorids"].remove("turla")
            summary = await svc.pull()
            assert summary["removed"]["actor"] == 1

            fake.state["version"]["version"] += 1
            fake.state["actorids"].append("turla")
            with mock.patch.object(m_svc, "MAX_GAP_REQUESTS", 1):
                summary = await svc.pull()
            assert any("weren't requested" in w or "were not requested" in w for w in summary["warnings"])

    async def test_failures_keep_the_snapshot(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            await svc.pull()
            status = await svc.status()

            fake.state["version"]["version"] += 1
            fake.state["errors"]["/api/get/bib"] = [500] * 10
            with self.raises(m_svc.MalpediaApiError):
                await svc.pull()
            after = await svc.status()
            assert after["version"] == status["version"]
            assert after["counts"] == status["counts"]
            # A failed pull isn't a check, the next sync tries again even within minage.
            assert after["checked"] == status["checked"]
            svc.conf["malpedia:pull:minage"] = 12
            fake.state["errors"].clear()
            summary = await svc.pull()
            assert summary["pulled"] is True

            # Unexpected errors don't leak raw exceptions to Storm.
            fake.state["version"]["version"] += 1

            def boom(*args):
                raise KeyError("boom")

            with mock.patch.object(svc, "_build", boom):
                with self.raises(MalpediaSvcError) as exc:
                    await svc.pull(force=True)
            assert "unexpectedly" in exc.exception.mesg

    async def test_shrink_guard(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            patch = mock.patch.object(m_svc, "SHRINK_MIN", 2)
            patch.start()
            self.addCleanup(patch.stop)
            await svc.pull()
            fake.state["version"]["version"] += 1
            fake.state["families"] = {"win.xagent": fake.state["families"]["win.xagent"]}
            with self.raises(MalpediaSvcError) as exc:
                await svc.pull()
            assert "Refusing to remove" in exc.exception.mesg
            assert (await svc.status())["counts"]["family"] == 3

            # The same version isn't downloaded again just to be refused again.
            start = len(fake.requests)
            with self.raises(MalpediaSvcError) as exc:
                await svc.pull()
            assert "was refused because it removes too much" in exc.exception.mesg
            assert fake.requests[start:] == ["/api/get/version"]
            assert "was refused" in (await svc.status())["failed"]

            summary = await svc.pull(force=True)
            assert summary["removed"]["family"] == 2
            assert (await svc.status())["failed"] is None


class TestMalpediaViews(s_tests.SynTest):
    async def test_changes(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            await svc.pull()

            # A new view gets everything, in batches.
            batches = [b async for b in svc.changes(VIEW, "news", size=2)]
            assert [len(b["upsert"]) for b in batches] == [2, 2, 1]
            assert all(b["total"] == 5 for b in batches)
            assert all(item["new"] and item["drop"] == {} for b in batches for item in b["upsert"])

            # Only records marked with the snapshot's hash count as synced.
            items = batches[0]["upsert"]
            count = await svc.synced(VIEW, "news", done=[[items[0]["key"], items[0]["hash"]], [items[1]["key"], "stale"], ["nokey", "x"]])
            assert count == 1
            assert (await drain(svc, VIEW, "news"))["total"] == 4
            # Other views are independent.
            assert (await drain(svc, VIEW2, "news"))["total"] == 5

            await syncView(svc, VIEW)
            assert (await drain(svc, VIEW, "news"))["total"] == 0
            # --full sends everything again, with the view's old version for the drop diff.
            full = await drain(svc, VIEW, "news", full=True)
            assert full["total"] == 5
            assert all(not item["new"] and item["drop"] == {} for item in full["upsert"])

            status = await svc.status(view=VIEW)
            assert status["view"]["counts"] == {"news": 5, "actor": 4, "family": 3, "yara": 3}
            assert status["view"]["version"] == 26601
            assert status["view"]["synced"] is not None

            assert await svc.resetView(VIEW) is True
            status = await svc.status(view=VIEW)
            assert status["view"] == {"counts": {"news": 0, "actor": 0, "family": 0, "yara": 0}}
            # The other view's state is untouched.
            await syncView(svc, VIEW2)
            await svc.resetView(VIEW)
            assert (await drain(svc, VIEW2, "actor"))["total"] == 0

            # Removed keys are only dropped if the snapshot doesn't have them.
            assert await svc.synced(VIEW2, "actor", removed=["apt28", "nokey"]) == 0
            with self.raises(MalpediaSvcError):
                await svc.synced(VIEW2, "actor", done=["notapair"])

    async def test_bad_args(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            with self.raises(MalpediaSvcError):
                [b async for b in svc.changes("notaview", "news")]
            with self.raises(MalpediaSvcError):
                [b async for b in svc.changes(VIEW, "nope")]
            with self.raises(MalpediaSvcError):
                await svc.status(view="x")
            with self.raises(MalpediaSvcError):
                await svc.viewSynced("x")
            with self.raises(MalpediaSvcError):
                await svc.resetView("x")
            with self.raises(MalpediaSvcError):
                await svc.record("nope", "x")

    async def test_lookups(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            assert await svc.record("actor", "apt28") is None
            await svc.pull()
            assert (await svc.record("actor", "apt28"))["name"] == "APT28"
            assert (await svc.record("news", fm.URL_SEDNIT))["title"] == "Sednit reloaded: Back in the trenches"
            assert (await svc.record("news", norm.urlKey(fm.URL_SEDNIT)))["url"] == fm.URL_SEDNIT
            assert (await svc.record("news", fm.URL_SEDNIT + "?"))["url"] == fm.URL_SEDNIT
            assert await svc.record("news", "?") is None

            found = await svc.find("actor", " fancy ")
            assert found == [{"name": "apt28", "common_name": "APT28", "synonyms": fake.state["actors"]["APT28"]["meta"]["synonyms"], "known": True}]
            found = await svc.find("family", "wcry")
            assert found == [{"name": "win.wannacryptor", "alt_names": ["WannaCry", "Wcry"], "known": True, "common_name": "WannaCryptor"}]
            with self.raises(MalpediaSvcError):
                await svc.find("yara", "x")
            with self.raises(MalpediaSvcError):
                await svc.find("actor", "  ")

            info = await svc.schedInfo()
            assert info["autosync"] is False
            assert 0 <= info["hour"] < 24 and 1 <= info["minute"] < 60
            assert info["period"] == f"daily@{info['hour']:02d}:{info['minute']:02d}"
            assert await svc.schedInfo() == info

    async def test_refresh(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            await svc.pull()
            start = len(fake.requests)

            data = await svc.refresh("actor", "apt28")
            assert fake.requests[start:] == ["/api/get/actor/apt28", "/api/get/bib/actor/apt28"]
            assert [i["rec"]["id"] for i in data["actor"]] == ["apt28"]
            fams = {i["rec"]["id"]: i["rec"] for i in data["family"]}
            assert set(fams) == {"win.xagent"}
            assert fams["win.xagent"]["actortags"] == [["apt28", "threat.apt28"]]
            assert [i["rec"]["url"] for i in data["news"]] == [fm.URL_SEDNIT]
            assert data["news"][0]["rec"]["actors"] == [["apt28", "threat.apt28"]]
            assert all(i["drop"] == {} for k in ("actor", "family", "news") for i in data[k])

            start = len(fake.requests)
            data = await svc.refresh("family", "win.xagent")
            assert fake.requests[start:] == ["/api/get/family/win.xagent", "/api/get/yara/win.xagent", "/api/get/bib/family/win.xagent"]
            assert data["family"][0]["rec"]["actors"] == ["apt28"]
            assert {i["rec"]["file"] for i in data["yara"]} == {"win.xagent_w0.yar", "win.xagent_auto.yar"}
            assert {i["rec"]["url"] for i in data["news"]} == {fm.URL_SEDNIT, fm.URL_XAGENT_PDF}

            # Refreshing doesn't change the snapshot.
            assert (await drain(svc, VIEW, "family"))["total"] == 3

            with self.raises(MalpediaSvcError):
                await svc.refresh("yara", "x")
            with self.raises(MalpediaSvcError):
                await svc.refresh("actor", " ")
            with self.raises(m_svc.MalpediaApiError):
                await svc.refresh("family", "win.nope")

    async def test_api(self):
        # The Telepath API wraps results and expected errors in a TelepathRetn.
        async with fm.FakeMalpedia() as fake:
            from malpediasvc import MalpediaSvc

            with self.getTestDir() as dirn:
                async with await MalpediaSvc.anit(dirn, conf=fm.svcConf(fake)) as svc:
                    async with svc.getLocalProxy() as prox:
                        retn = await prox.pull()
                        assert retn["status"] is True
                        assert retn["data"]["pulled"] is True

                        retn = await prox.record("nope", "x")
                        assert retn["status"] is False
                        assert "Unknown record kind" in retn["mesg"]

                        fake.state["errors"]["/api/get/family/win.nope"] = [404]
                        retn = await prox.refresh("family", "win.nope")
                        assert retn == {"status": False, "mesg": "Malpedia returned HTTP 404 for /get/family/win.nope: fake error 404", "data": None}

                        batches = [b async for b in prox.changes(VIEW, "actor")]
                        assert batches[0]["status"] is True
                        assert batches[0]["data"]["total"] == 4

                        batches = [b async for b in prox.changes("bad", "actor")]
                        assert batches == [{"status": False, "mesg": "Invalid view iden: 'bad'", "data": None}]

                        retn = await prox.status(VIEW)
                        assert retn["status"] is True
                        assert s_common.isguid(VIEW)


class TestMalpediaAuditFixes(s_tests.SynTest):
    async def test_refresh_ids(self):
        # MALP-03: Malpedia accepts IDs in any case, the refresh uses the snapshot's form.
        async with fm.malpediaSvc(self) as (core, svc, fake):
            await svc.pull()
            start = len(fake.requests)
            data = await svc.refresh("actor", " APT28 ")
            assert fake.requests[start] == "/api/get/actor/apt28"
            assert data["id"] == "apt28"
            assert [i["rec"]["key"] for i in data["actor"]] == ["apt28"]
            data = await svc.refresh("family", "WIN.XAgent")
            assert data["id"] == "win.xagent"
            assert [i["rec"]["key"] for i in data["family"]] == ["win.xagent"]
            # Unknown IDs are lowercased too (Malpedia's IDs are lowercase).
            assert svc._normId("actor", "New_Actor") == "new_actor"
            for bad in ("a b", "a/b", "a?b", "x" * (m_svc.MAX_ID_LEN + 1), "", None):
                with self.raises(MalpediaSvcError):
                    await svc.refresh("actor", bad)

    async def test_yara_full_refetch(self):
        # MALP-04: the "after" watermark misses rules edited without a new version date, so
        # every rule is downloaded again every malpedia:yara:fullage days.
        async with fm.malpediaSvc(self) as (core, svc, fake):
            await svc.pull()
            assert fake.countPaths("/api/get/yara/tlp_white/zip") == 1
            assert (await svc.status())["yarafull"] is not None

            # A rule's text changes, but its version date doesn't, so "after" skips it.
            text = fm.YARA_XAGENT_W0.replace("all of them", "any of them")
            fake.state["yara"]["tlp_white"]["win.xagent_w0.yar"] = ("win.xagent", text)
            fake.state["version"]["version"] += 1
            summary = await svc.pull()
            assert summary["yarafull"] is False
            assert fake.countPaths("/api/get/yara/tlp_white/zip") == 1
            assert (await svc.record("yara", "win.xagent_w0.yar"))["text"] == fm.YARA_XAGENT_W0

            # Once the last full download is old enough, the next pull gets the zip.
            svc.info.set("yarafull", s_common.now() - 8 * m_svc.DAY)
            fake.state["version"]["version"] += 1
            summary = await svc.pull()
            assert summary["yarafull"] is True
            assert summary["updated"]["yara"] == 1
            assert fake.countPaths("/api/get/yara/tlp_white/zip") == 2
            assert (await svc.record("yara", "win.xagent_w0.yar"))["text"] == text

            # 0 turns the periodic download off.
            svc.conf["malpedia:yara:fullage"] = 0
            svc.info.set("yarafull", 0)
            fake.state["version"]["version"] += 1
            assert (await svc.pull())["yarafull"] is False
            assert fake.countPaths("/api/get/yara/tlp_white/zip") == 2

    async def test_gaps_are_retried(self):
        # MALP-05: a pull that couldn't fill a gap pulls again on the next check, even if
        # Malpedia's version didn't change.
        async with fm.malpediaSvc(self) as (core, svc, fake):
            fake.state["errors"]["/api/get/actor/turla"] = [500] * 10
            summary = await svc.pull()
            assert summary["gaps"] == 1
            assert (await svc.status())["gaps"] == 1
            assert await svc.record("actor", "turla") is None

            fake.state["errors"].clear()
            summary = await svc.pull()
            assert summary["pulled"] is True
            assert summary["gaps"] == 0
            assert (await svc.record("actor", "turla"))["name"] == "Turla"
            # Now the version check is enough again.
            assert (await svc.pull())["reason"] == "unchanged"

            # A 404 isn't a gap, retrying wouldn't help.
            fake.state["actorids"].append("gone")
            fake.state["version"]["version"] += 1
            summary = await svc.pull()
            assert summary["gaps"] == 0
            assert any("Unable to get the actor gone" in w for w in summary["warnings"])

            # A failed request for a family's new YARA rules is a gap too.
            fake.state["version"]["version"] += 1
            fake.state["yara"]["tlp_white"]["win.sedreco_w0.yar"] = (
                "win.sedreco", fm.YARA_WANNA_W0.replace("win_wannacryptor_w0", "win_sedreco_w0"))
            fake.state["errors"]["/api/get/yara/win.sedreco"] = [500] * 10
            summary = await svc.pull()
            assert summary["gaps"] == 1
            assert any("Unable to get the YARA rules for win.sedreco" in w for w in summary["warnings"])
            assert await svc.record("yara", "win.sedreco_w0.yar") is None
            fake.state["errors"].clear()
            summary = await svc.pull()
            assert summary["pulled"] is True
            assert (await svc.record("yara", "win.sedreco_w0.yar"))["family"] == "win.sedreco"

    async def test_gap_requests_rotate(self):
        # Past the per-pull limit, each pull requests different missing actors (new ones
        # first, then the ones requested longest ago), instead of the same ones every time.
        async with fm.malpediaSvc(self) as (core, svc, fake):
            for aid in ("xa", "xb", "xc"):
                fake.state["actorids"].append(aid)
                fake.state["actor"][aid] = {"value": aid.upper(), "meta": {}, "description": ""}
            with mock.patch.object(m_svc, "MAX_GAP_REQUESTS", 2):
                summary = await svc.pull()
                assert summary["gaps"] == 2
                assert fake.countPaths("/api/get/actor/") == 2
                assert await svc.record("actor", "xb") is None

                # The gaps make the next check pull again, and it gets the other two.
                summary = await svc.pull()
                assert fake.countPaths("/api/get/actor/") == 4
                for aid in ("turla", "xa", "xb", "xc"):
                    assert await svc.record("actor", aid) is not None, aid

                # Then the ones requested longest ago.
                start = len(fake.requests)
                await svc.pull()
                got = sorted(r for r in fake.requests[start:] if r.startswith("/api/get/actor/"))
                assert got == ["/api/get/actor/turla", "/api/get/actor/xa"]

    async def test_skipped_yara_file(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            fake.state["yara"]["tlp_white"]["win.xagent_w9.yar"] = ("win.xagent", "/* no rule here */")
            summary = await svc.pull()
            assert "Skipped the YARA file win.xagent_w9.yar: it has no rule." in summary["warnings"]
            assert await svc.record("yara", "win.xagent_w9.yar") is None

    async def test_long_keys(self):
        # MALP-08: keys too long for the slab are handled, not raised as BadArg.
        async with fm.malpediaSvc(self) as (core, svc, fake):
            await svc.pull()
            assert await svc.record("actor", "x" * 600) is None
            assert await svc.synced(VIEW, "actor", done=[["x" * 600, "h"]], removed=["y" * 600]) == 0

            async def findActor(needle):
                return [{"name": "x" * 600}, "not a dict", {"name": "apt28"}]

            with mock.patch.object(svc.client, "findActor", findActor):
                found = await svc.find("actor", "x")
            assert [(f["name"][:5], f["known"]) for f in found] == [("xxxxx", False), ("apt28", True)]

            async with svc.getLocalProxy() as prox:
                retn = await prox.record("actor", "x" * 600)
                assert retn == {"status": True, "mesg": "", "data": None}

    async def test_store_lock(self):
        # MALP-12: changes() never reads the snapshot while a pull is writing it.
        async with fm.malpediaSvc(self) as (core, svc, fake):
            await svc.pull()
            await svc.storelock.acquire()
            task = asyncio.create_task(drain(svc, VIEW, "actor"))
            await asyncio.sleep(0.1)
            assert not task.done()
            svc.storelock.release()
            assert (await task)["total"] == 4

            # The records are hashed in _build (in a thread), not while storing.
            raw = {"actorids": [], "actors": {}, "families": {}, "references": {}, "bib": "",
                   "yaralist": {}, "extra_actors": {}, "yara": {"full": True, "rules": []}, "haveyara": {}}
            built = svc._build(raw, [])
            assert built == {"news": {}, "actor": {}, "family": {}, "yara": {}}

    async def test_changes_key_removed_between_batches(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            await svc.pull()
            genr = svc.changes(VIEW, "actor", size=2)
            first = await genr.__anext__()
            assert len(first["upsert"]) == 2
            # A pull removes a record before its batch is built.
            rest = [k for k in svc._snapRecs("actor") if k not in {i["key"] for i in first["upsert"]}]
            svc._snapkv("actor").delete(rest[0])
            second = await genr.__anext__()
            assert [i["key"] for i in second["upsert"]] == rest[1:]

    async def test_interrupted_store(self):
        # MALP-12: a pull interrupted while writing the snapshot is repaired by the next one.
        async with fm.FakeMalpedia() as fake:
            from malpediasvc import MalpediaSvc

            with self.getTestDir() as dirn:
                async with await MalpediaSvc.anit(dirn, conf=fm.svcConf(fake)) as svc:
                    await svc.pull()
                    svc.info.set("storing", True)
                async with await MalpediaSvc.anit(dirn, conf=fm.svcConf(fake)) as svc:
                    status = await svc.status()
                    assert status["version"] is None
                    assert status["yarafull"] is None
                    assert svc.info.get("storing") is None
                    # The same Malpedia version is pulled (and every YARA rule) again.
                    summary = await svc.pull()
                    assert summary["pulled"] is True
                    assert summary["yarafull"] is True

    async def test_view_info(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            assert await svc.viewInfo(VIEW) == {}
            info = await svc.viewSynced(VIEW, tags={"prefix": "rep.x", "tlp": "tlp", "other": 1})
            assert info["tags"] == {"prefix": "rep.x", "tlp": "tlp"}
            # A sync that doesn't say keeps the last known prefixes.
            info = await svc.viewSynced(VIEW)
            assert info["tags"] == {"prefix": "rep.x", "tlp": "tlp"}
            assert (await svc.viewInfo(VIEW))["tags"] == {"prefix": "rep.x", "tlp": "tlp"}
            with self.raises(MalpediaSvcError):
                await svc.viewInfo("x")
