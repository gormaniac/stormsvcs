"""Tests for the slib.malpedia service: pulling, the snapshot, and per-view change tracking."""

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
            # but never the whole YARA zip again.
            summary = await svc.pull(force=True)
            assert summary["pulled"] is True
            assert summary["initial"] is False
            assert summary["added"] == {"news": 0, "actor": 0, "family": 0, "yara": 0}
            assert summary["updated"] == {"news": 0, "actor": 0, "family": 0, "yara": 0}
            assert fake.countPaths("/api/get/yara/tlp_white/zip") == 1
            assert fake.countPaths("/api/get/yara/after/") == 1
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
            yesterday = (datetime.datetime.now(datetime.timezone.utc).date() - datetime.timedelta(days=1)).isoformat()
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
            assert fams["win.wannacryptor"]["drop"]["actors"] == ["lazarus_group"]
            assert fams["win.wannacryptor"]["drop"]["actortags"] == [["lazarus_group", "threat.lazarus_group"]]

            assert [item["key"] for item in changes["actor"]["removed"]] == ["[vault_7_8]"]
            assert changes["actor"]["removed"][0]["rec"]["name"] == "[Vault 7/8]"

            yara = {item["key"]: item for item in changes["yara"]["upsert"]}
            assert set(yara) == {"win.wannacryptor_w0.yar", "win.wannacryptor_w1.yar", "win.sedreco_w0.yar"}
            assert yara["win.wannacryptor_w0.yar"]["drop"] == {"updated": "2017-05-15", "text": fm.YARA_WANNA_W0,
                                                               "sha256": yara["win.wannacryptor_w0.yar"]["drop"]["sha256"]}
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

            summary = await svc.pull(force=True)
            assert summary["removed"]["family"] == 2


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
