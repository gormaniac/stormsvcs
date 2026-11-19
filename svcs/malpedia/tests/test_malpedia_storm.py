"""Pytests for the slib.malpedia Storm package (commands, modules, modeling, and perms)."""

import asyncio
import pathlib
from unittest import mock

import synapse.tests.utils as s_tests
from stormlibpp.testing import assertMainHelp, assertVersionsMatch

from malpediasvc import __version__, defs
from malpediasvc import svc as m_svc
from malpediasvc.defs import PKGDEFS, SVC_GUID, SVC_NAME

from . import fakemalpedia as fm

CMDS = tuple(cmd["name"] for cmd in PKGDEFS[0]["commands"])
MODS = tuple(mod["name"] for mod in PKGDEFS[0]["modules"])

THREAT = 'risk:threat=(malpedia, "{}")'
TOOL = 'risk:tool:software=(malpedia, "{}")'
RULE = 'it:app:yara:rule=(malpedia, "{}")'


async def nodeset(core, query, opts=None):
    """Return the set of (form, repr) for the nodes a query lifts."""
    return {(node.form.name, node.repr()) for node in await core.nodes(query, opts=opts)}


async def count(core, query, opts=None):
    return len(await core.nodes(query, opts=opts))


async def syncJobs(core):
    """How many cron jobs run slib.malpedia.sync on a schedule."""
    q = '$n = (0) for $c in $lib.cron.list() { if ($c.pack().query = "slib.malpedia.sync") { $n = ($n + 1) } } return($n)'
    return await core.callStorm(q)


def getNews(url):
    return f"media:news:url={url!r}"


class TestMalpediaStormPkg(s_tests.SynTest):
    def test_versions_match(self):
        # The version lives in pyproject.toml (the image tag), __init__.py, the package yaml,
        # and the service's uv.lock entry.
        assert assertVersionsMatch(pathlib.Path(__file__).parents[1]) == __version__

    def test_main_help(self):
        assertMainHelp("malpediasvc")

    async def test_api_unexpected_error(self):
        # An error that isn't a MalpediaApiError or MalpediaSvcError reaches Storm as
        # status=False, not as a raw exception.
        async with fm.malpediaSvc(self) as (core, svc, fake):

            async def boom(*args, **kwargs):
                raise RuntimeError("boom")

            async def boomGenr(*args, **kwargs):
                raise RuntimeError("boom")
                yield  # pragma: no cover

            svc.status = boom
            svc.changes = boomGenr
            errretn = {
                "status": False,
                "mesg": "Unexpected error: RuntimeError: boom",
                "data": None,
            }
            async with svc.getLocalProxy() as prox:
                with self.getLoggerStream("stormlibpp.svc") as stream:
                    self.eq(errretn, await prox.status())
                stream.seek(0)
                assert "Unexpected error in MalpediaCellApi.status." in stream.read()
                self.eq([errretn], [b async for b in prox.changes("a" * 32, "actor")])

    async def test_pkg(self):
        assert len(CMDS) == 7

        async with fm.malpediaSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("service.list")
            self.stormIsInPrint(f"true (svc) ({SVC_NAME} @ {__version__})", msgs)

            for cmd in CMDS:
                assert cmd in core.stormcmds, cmd

            for cdef in PKGDEFS[0]["commands"]:
                assert "forms" not in cdef, cdef["name"]
                for cmdinput in cdef.get("cmdinputs", ()):
                    assert core.model.form(cmdinput["form"]) is not None, (cdef["name"], cmdinput)

            for mod in MODS:
                msgs = await core.stormlist(f"$mod = $lib.import({mod})")
                self.stormHasNoErr(msgs)

            # The service add event creates the meta:source and default tag settings.
            nodes = await core.nodes(f"meta:source={SVC_GUID}")
            assert len(nodes) == 1
            assert nodes[0].get("name") == "malpedia"
            assert nodes[0].get("type") == "slib.malpedia"
            msgs = await core.stormlist("slib.malpedia.admin.tags")
            self.stormIsInPrint("prefix=rep.malpedia tlp=rep.malpedia.tlp", msgs)

            # Without autosync, the setup job doesn't schedule anything or contact Malpedia.
            for _ in range(100):
                jobs = await core.callStorm(
                    "$l = ([]) for $c in $lib.cron.list() { $l.append($c.pack()) } return($l)"
                )
                if jobs and jobs[0].get("lastresult"):
                    break
                await asyncio.sleep(0.1)
            assert [(j["name"], j["lastresult"]) for j in jobs] == [
                ("slib.malpedia (initial setup and sync)", "finished successfully with 0 nodes")
            ]
            msgs = await core.stormlist("slib.malpedia.admin.schedule")
            self.stormIsInPrint("There is no sync cron job", msgs)
            assert await syncJobs(core) == 0
            assert fake.requests == []

    async def test_autosync(self):
        async with fm.malpediaSvc(self, **{"malpedia:autosync": True}) as (core, svc, fake):
            # The initial sync runs in the background, as a one time cron job.
            for _ in range(600):
                if await count(core, "it:app:yara:rule"):
                    msgs = await core.stormlist("slib.malpedia.status")
                    if any(
                        "This view was synced" in m[1].get("mesg", "")
                        for m in msgs
                        if m[0] == "print"
                    ):
                        break
                await asyncio.sleep(0.1)
            assert await count(core, "media:news") == 5
            assert await count(core, "it:app:yara:rule") == 3
            assert fake.countPaths("/api/get/yara/tlp_white/zip") == 1

            # And a daily sync is scheduled at the service's random time.
            info = await svc.schedInfo()
            iden = await core.callStorm('return($lib.globals.get("slib:malpedia:cron"))')
            job = await core.callStorm(
                "return($lib.cron.get($iden).pack())", opts={"vars": {"iden": iden}}
            )
            assert job["query"] == "slib.malpedia.sync"
            assert job["enabled"] is True
            assert job["recur"] is True
            reqs, incunit, incval = job["recs"][0]
            assert (reqs, incunit, incval) == (
                {"hour": info["hour"], "minute": info["minute"]},
                "day",
                1,
            )
            msgs = await core.stormlist("slib.malpedia.admin.schedule")
            self.stormIsInPrint(f"cron {iden} (enabled) runs slib.malpedia.sync", msgs)


class TestMalpediaStormSync(s_tests.SynTest):
    async def test_sync(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.malpedia.status")
            self.stormIsInPrint("Malpedia hasn't been pulled yet", msgs)
            self.stormIsInPrint("This view hasn't been synced yet", msgs)

            msgs = await core.stormlist("slib.malpedia.sync")
            self.stormHasNoErr(msgs)
            self.stormIsInPrint(
                "Pulled Malpedia version 26601 (2026-10-30T16:25:07Z) with 9 requests", msgs
            )
            self.stormIsInPrint("added news=5, actor=4, family=3, yara=3", msgs)
            self.stormIsInWarn(
                "family attributions don't resolve to exactly one actor (not linked): Hidden Bear, Nobody Knows",
                msgs,
            )
            self.stormIsInPrint("Modeling 5 news records.", msgs)

            source = f"meta:source={SVC_GUID}"

            # ---- News ----
            nodes = await core.nodes(getNews(fm.URL_SEDNIT))
            assert len(nodes) == 1
            news = nodes[0]
            assert news.get("title") == "sednit reloaded: back in the trenches"
            assert news.get("published") == 1773100800000
            assert news.get("publisher:name") == "eset research"
            assert news.get("ext:id") == "research:20260310:sednit:86e9801"
            for tag in ("rep.malpedia.threat.apt28", "rep.malpedia.mal.win.xagent"):
                assert tag in news.tags
            assert await nodeset(core, getNews(fm.URL_SEDNIT) + " -(refs)> *") == {
                ("risk:threat", (await core.nodes(THREAT.format("apt28")))[0].repr()),
                ("risk:tool:software", (await core.nodes(TOOL.format("win.xagent")))[0].repr()),
            }
            assert (
                await count(
                    core, getNews(fm.URL_SEDNIT) + " :publisher -> ou:org +:name='eset research'"
                )
                == 1
            )
            assert (
                await count(
                    core, getNews(fm.URL_SEDNIT) + " :authors -> ps:contact +:name='eset research'"
                )
                == 1
            )
            names = {
                n.get("name")
                for n in await core.nodes(getNews(fm.URL_XAGENT_PDF) + " :authors -> ps:contact")
            }
            assert names == {"fireeye", "jane doe"}
            # Tagged with the family through the family's library entries.
            assert (
                await count(
                    core,
                    getNews(fm.URL_XAGENT_PDF)
                    + " +#rep.malpedia.mal.win.xagent -(refs)> risk:tool:software",
                )
                == 1
            )
            # In the references but not the bib, so it only has a URL.
            nodes = await core.nodes(getNews(fm.URL_NOBIB))
            assert nodes[0].get("title") is None
            assert "rep.malpedia.mal.win.sedreco" in nodes[0].tags
            # In the bib, not tagged with anything.
            nodes = await core.nodes(getNews(fm.URL_PLAIN))
            assert nodes[0].get("title") == "a plain report"
            assert not [t for t in nodes[0].tags if t.startswith("rep.")]
            assert await count(core, f"{source} -(seen)> media:news") == 5

            # ---- Actors ----
            nodes = await core.nodes(THREAT.format("apt28"))
            apt28 = nodes[0]
            assert apt28.get("name") == "apt28"
            assert apt28.get("org:name") == "apt28"
            assert apt28.get("org:names") == (
                "apt 28",
                "fancy bear",
                "g0007",
                "hidden bear",
                "sofacy",
            )
            assert apt28.get("desc") == "The Sofacy Group is a cyber espionage group."
            assert apt28.get("country:code") == "ru"
            assert apt28.get("mitre:attack:group") == "G0007"
            assert apt28.get("ext:id") == "apt28"
            assert apt28.get("ext:ids") == ("5b4ee3ea-eee3-4c8e-8323-85ae32658754",)
            assert apt28.get("tag") == "rep.malpedia.threat.apt28"
            assert apt28.get("reporter:name") == "malpedia"
            assert "rep.malpedia.threat.apt28" in apt28.tags
            assert (
                await count(core, THREAT.format("apt28") + " :reporter -> ou:org +:name=malpedia")
                == 1
            )
            assert (
                await count(core, THREAT.format("apt28") + " :country -> pol:country +:iso2=ru")
                == 1
            )
            assert {
                n.get("name")
                for n in await core.nodes(THREAT.format("apt28") + " -(targets)> ou:industry")
            } == {"military", "government"}
            nodes = await core.nodes("syn:tag=rep.malpedia.threat.apt28")
            assert nodes[0].get("title") == "APT28"
            assert (
                nodes[0].get("doc")
                == "Malpedia: https://malpedia.caad.fkie.fraunhofer.de/actor/apt28"
            )
            # Odd IDs make valid tags.
            nodes = await core.nodes(THREAT.format("[vault_7_8]"))
            assert nodes[0].get("tag") == "rep.malpedia.threat.vault_7_8"
            assert nodes[0].get("desc") is None
            # An actor only /api/get/actor/<id> had.
            assert (
                await count(core, THREAT.format("turla") + " +:desc='A Russian espionage group.'")
                == 1
            )
            assert await count(core, f"{source} -(seen)> risk:threat") == 4

            # ---- Families ----
            nodes = await core.nodes(TOOL.format("win.xagent"))
            xagent = nodes[0]
            assert xagent.get("id") == "win.xagent"
            assert xagent.get("soft:name") == "x-agent"
            assert xagent.get("soft:names") == ("chopstick", "splm")
            assert xagent.get("tag") == "rep.malpedia.mal.win.xagent"
            assert xagent.get("desc") is None
            assert "rep.malpedia.mal.win.xagent" in xagent.tags
            assert await nodeset(core, "risk:threat -(uses)> risk:tool:software") == {
                ("risk:tool:software", xagent.repr()),
                ("risk:tool:software", (await core.nodes(TOOL.format("win.sedreco")))[0].repr()),
                (
                    "risk:tool:software",
                    (await core.nodes(TOOL.format("win.wannacryptor")))[0].repr(),
                ),
            }
            assert await count(core, THREAT.format("apt28") + " -(uses)> risk:tool:software") == 2
            assert (
                await count(
                    core,
                    THREAT.format("lazarus_group")
                    + " -(uses)> risk:tool:software:id=win.wannacryptor",
                )
                == 1
            )

            # ---- YARA ----
            nodes = await core.nodes(RULE.format("win.xagent_w0.yar"))
            rule = nodes[0]
            assert rule.get("name") == "win_xagent_w0"
            assert rule.get("text") == fm.YARA_XAGENT_W0
            assert rule.get("ext:id") == "win.xagent_w0.yar"
            assert rule.get("url") == "https://malpedia.caad.fkie.fraunhofer.de/details/win.xagent"
            assert rule.get("family") == "x-agent"
            assert rule.get("created") == 1434672000000
            assert rule.get("updated") == 1494979200000
            assert rule.get("enabled") is None
            for tag in ("rep.malpedia.tlp.white", "rep.malpedia.mal.win.xagent"):
                assert tag in rule.tags
            assert (
                await count(
                    core,
                    RULE.format("win.xagent_w0.yar")
                    + " :author -> ps:contact +:name='florian roth'",
                )
                == 1
            )
            assert (
                await count(
                    core,
                    RULE.format("win.xagent_w0.yar")
                    + " -(detects)> risk:tool:software:id=win.xagent",
                )
                == 1
            )
            assert await count(core, "meta:ruleset=(malpedia, yara) -(has)> it:app:yara:rule") == 3
            assert await count(core, "#rep.malpedia.mal.win.xagent +it:app:yara:rule") == 2

            msgs = await core.stormlist("slib.malpedia.status")
            self.stormIsInPrint("Malpedia version 26601 (2026-10-30T16:25:07Z)", msgs)
            self.stormIsInPrint(
                "The service has news=5, actor=4, family=3, yara=3 (9 requests to Malpedia so far).",
                msgs,
            )
            self.stormIsInPrint("This view was synced", msgs)
            self.stormIsInPrint("Last pull warning:", msgs)

            # Syncing again only asks for Malpedia's version, and changes nothing.
            nodecount = await core.callStorm("return($lib.view.get().getFormCounts())")
            msgs = await core.stormlist("slib.malpedia.sync")
            self.stormHasNoErr(msgs)
            self.stormIsInPrint("Malpedia is unchanged since the last pull (version 26601).", msgs)
            self.stormNotInPrint("Modeling", msgs)
            assert fake.requests[-1] == "/api/get/version"
            assert await core.callStorm("return($lib.view.get().getFormCounts())") == nodecount

    async def test_sync_incremental(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))

            state = fake.state
            state["version"] = {"version": 26602, "date": "2026-10-31T10:00:00Z"}
            state["families"]["win.xagent"]["alt_names"].append("Sofacy Agent")
            state["families"]["win.xagent"]["description"] = "A backdoor."
            state["families"]["win.wannacryptor"]["description"] = ""
            state["actors"].pop("[Vault 7/8]")
            state["actorids"].remove("[vault_7_8]")
            state["actors"]["APT28"]["meta"]["synonyms"].remove("G0007")
            state["actors"]["APT28"]["meta"]["country"] = None
            state["actors"]["APT28"]["meta"]["targeted-sector"] = []
            state["actors"]["APT28"]["meta"]["cfr-target-category"] = ["Government"]
            state["families"]["win.wannacryptor"]["attribution"] = []
            state["references"][fm.URL_SEDNIT] = state["references"][fm.URL_SEDNIT][:1]
            state["yara"]["tlp_white"].pop("win.xagent_auto.yar")
            text = fm.YARA_WANNA_W0.replace("20170515", "20261031")
            state["yara"]["tlp_white"]["win.wannacryptor_w0.yar"] = ("win.wannacryptor", text)
            state["yara_after"] = {"tlp_white": ["win.wannacryptor_w0.yar"]}
            # An analyst's edits to an article and a tag's doc survive.
            await core.nodes(getNews(fm.URL_SEDNIT) + " [ :title='my title' ]")
            await core.nodes("syn:tag=rep.malpedia.mal.win.xagent [ :doc='our notes' ]")

            msgs = await core.stormlist("slib.malpedia.sync")
            self.stormHasNoErr(msgs)
            self.stormIsInPrint("Pulled Malpedia version 26602", msgs)

            # The article isn't about APT28 anymore.
            news = (await core.nodes(getNews(fm.URL_SEDNIT)))[0]
            assert "rep.malpedia.threat.apt28" not in news.tags
            # Its only threat tag is gone, so the parent tag is too.
            assert "rep.malpedia.threat" not in news.tags
            assert "rep.malpedia.mal.win.xagent" in news.tags
            assert news.get("title") == "my title"
            assert await nodeset(core, getNews(fm.URL_SEDNIT) + " -(refs)> *") == {
                ("risk:tool:software", (await core.nodes(TOOL.format("win.xagent")))[0].repr()),
            }

            # Lazarus doesn't use WannaCryptor anymore, and its description is gone.
            assert await count(core, THREAT.format("lazarus_group") + " -(uses)> *") == 0
            assert (await core.nodes(TOOL.format("win.wannacryptor")))[0].get("desc") is None
            xagent = (await core.nodes(TOOL.format("win.xagent")))[0]
            assert xagent.get("soft:names") == ("chopstick", "sofacy agent", "splm")
            assert xagent.get("desc") == "A backdoor."
            tagnode = (await core.nodes("syn:tag=rep.malpedia.mal.win.xagent"))[0]
            assert tagnode.get("doc") == "our notes"
            assert tagnode.get("title") == "X-Agent"

            apt28 = (await core.nodes(THREAT.format("apt28")))[0]
            assert apt28.get("mitre:attack:group") is None
            assert apt28.get("country") is None and apt28.get("country:code") is None
            assert {
                n.get("name")
                for n in await core.nodes(THREAT.format("apt28") + " -(targets)> ou:industry")
            } == {"government"}

            # Removed records are tagged, not deleted.
            vault = (await core.nodes(THREAT.format("[vault_7_8]")))[0]
            assert "rep.malpedia.removed" in vault.tags
            rule = (await core.nodes(RULE.format("win.xagent_auto.yar")))[0]
            assert "rep.malpedia.removed" in rule.tags
            assert await count(core, "meta:ruleset=(malpedia, yara) -(has)> it:app:yara:rule") == 2
            rule = (await core.nodes(RULE.format("win.wannacryptor_w0.yar")))[0]
            assert rule.get("updated") == 1793404800000
            assert rule.get("text") == text

            # A removed record that comes back loses the removed tag.
            state["version"]["version"] += 1
            state["actors"]["[Vault 7/8]"] = fm.initialState()["actors"]["[Vault 7/8]"]
            state["actorids"].append("[vault_7_8]")
            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))
            vault = (await core.nodes(THREAT.format("[vault_7_8]")))[0]
            assert "rep.malpedia.removed" not in vault.tags

            # A family's rules move to another family.
            state["version"]["version"] += 1
            state["yara"]["tlp_white"]["win.wannacryptor_w0.yar"] = ("win.sedreco", text)
            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))
            rule = (await core.nodes(RULE.format("win.wannacryptor_w0.yar")))[0]
            assert "rep.malpedia.mal.win.wannacryptor" not in rule.tags
            assert "rep.malpedia.mal.win.sedreco" in rule.tags
            assert rule.get("family") == "sedreco"
            assert await nodeset(
                core, RULE.format("win.wannacryptor_w0.yar") + " -(detects)> *"
            ) == {
                ("risk:tool:software", (await core.nodes(TOOL.format("win.sedreco")))[0].repr()),
            }

            # An article Malpedia dropped loses its Malpedia tags and edges.
            state["version"]["version"] += 1
            state["references"].pop(fm.URL_NOBIB)
            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))
            nodes = await core.nodes(getNews(fm.URL_NOBIB))
            assert "rep.malpedia.mal.win.sedreco" not in nodes[0].tags
            assert await count(core, getNews(fm.URL_NOBIB) + " -(refs)> *") == 0

    async def test_sync_existing_news(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            # Articles other sources already have keep their props, Malpedia only fills gaps.
            await core.nodes(
                f"[ media:news=* :url={fm.URL_WANNACRY!r} :title='wannacry!' :publisher:name=talos ]"
            )
            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))
            nodes = await core.nodes(getNews(fm.URL_WANNACRY))
            assert len(nodes) == 1
            assert nodes[0].get("title") == "wannacry!"
            assert nodes[0].get("publisher:name") == "talos"
            assert nodes[0].get("published") == 1493596800000
            assert nodes[0].get("ext:id") == "talos:20170512:wannacry:aaaa111"
            assert "rep.malpedia.threat.lazarus_group" in nodes[0].tags
            # Its :publisher:name is another org, so Malpedia's publisher org isn't linked.
            assert nodes[0].get("publisher") is None
            # Articles without a publisher name get Malpedia's.
            nodes = await core.nodes(getNews(fm.URL_SEDNIT))
            assert nodes[0].get("publisher:name") == "eset research"
            assert (
                await count(
                    core, getNews(fm.URL_SEDNIT) + " :publisher -> ou:org +:name='eset research'"
                )
                == 1
            )

    async def test_sync_views(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))
            start = len(fake.requests)

            # A new, empty view gets everything from the service's snapshot, without any requests.
            layr = (await core.addLayer())["iden"]
            view = (await core.addView({"layers": [layr]}))["iden"]
            opts = {"view": view}
            assert await count(core, "risk:threat", opts=opts) == 0
            msgs = await core.stormlist("slib.malpedia.sync --no-pull", opts=opts)
            self.stormHasNoErr(msgs)
            self.stormIsInPrint("Modeling 5 news records.", msgs)
            assert await count(core, "risk:threat", opts=opts) == 4
            assert await count(core, "it:app:yara:rule", opts=opts) == 3
            assert len(fake.requests) == start

            # --full models everything again, reset makes the next sync do the same.
            msgs = await core.stormlist("slib.malpedia.sync --no-pull --full", opts=opts)
            self.stormIsInPrint("Modeling 4 actor records.", msgs)
            msgs = await core.stormlist("slib.malpedia.admin.reset", opts=opts)
            self.stormIsInWarn("use --yes to confirm", msgs)
            msgs = await core.stormlist("slib.malpedia.admin.reset --yes", opts=opts)
            self.stormIsInPrint("Reset this view", msgs)
            msgs = await core.stormlist("slib.malpedia.status", opts=opts)
            self.stormIsInPrint("This view hasn't been synced yet", msgs)
            msgs = await core.stormlist("slib.malpedia.sync --no-pull", opts=opts)
            self.stormIsInPrint("Modeling 3 yara records.", msgs)
            assert len(fake.requests) == start

    async def test_sync_pull_failure(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            fake.state["errors"]["/api/get/version"] = [500] * 10
            msgs = await core.stormlist("slib.malpedia.sync")
            self.stormIsInWarn(
                "Pulling Malpedia failed, syncing the service's last pull instead: Malpedia returned HTTP 500",
                msgs,
            )
            assert await count(core, "risk:threat") == 0
            msgs = await core.stormlist("slib.malpedia.status")
            self.stormIsInWarn("The last pull failed (the next sync retries it)", msgs)

            fake.state["errors"].clear()
            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))

            # A failed pull models the last good pull's changes, ex. into a new view.
            fake.state["version"]["version"] += 1
            fake.state["errors"]["/api/get/bib"] = [500] * 10
            layr = (await core.addLayer())["iden"]
            view = (await core.addView({"layers": [layr]}))["iden"]
            msgs = await core.stormlist("slib.malpedia.sync", opts={"view": view})
            self.stormIsInWarn("Pulling Malpedia failed", msgs)
            assert await count(core, "risk:threat", opts={"view": view}) == 4

    async def test_bad_records(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            # Unparseable values don't break the sync.
            fake.state["references"]["not a url"] = [{"type": "family", "id": "win.xagent"}]
            fake.state["bib"].append(
                (
                    "online",
                    "bad:date:1",
                    "x",
                    "Bad date",
                    "sometime",
                    "Org",
                    "https://example.com/bad",
                )
            )
            fake.state["actors"]["APT28"]["meta"]["synonyms"].append("x" * 300)
            msgs = await core.stormlist("slib.malpedia.sync")
            self.stormHasNoErr(msgs)
            nodes = await core.nodes(getNews("https://example.com/bad"))
            assert nodes[0].get("published") is None
            assert await count(core, "media:news") == 6
            # The invalid URL is skipped (and not retried, it'd never work).
            self.stormIsInPrint(
                " news     | 7         | 6         | 0         | 0         | 1         | 0 ", msgs
            )
            msgs = await core.stormlist("slib.malpedia.sync")
            self.stormIsInPrint(" news     | 0         | 0 ", msgs)

    async def test_tag_prefix(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            msgs = await core.stormlist(
                "slib.malpedia.admin.tags --prefix 'rep.MP' --tlp-prefix tlp"
            )
            self.stormIsInPrint("prefix=rep.mp tlp=tlp", msgs)
            msgs = await core.stormlist("slib.malpedia.admin.tags --prefix '...'")
            self.stormIsInWarn("Invalid tag prefix", msgs)
            self.stormIsInPrint("prefix=rep.mp tlp=tlp", msgs)

            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))
            assert await count(core, "#rep.mp.threat.apt28") == 2
            assert await count(core, "#tlp.white") == 3
            assert (await core.nodes(THREAT.format("apt28")))[0].get("tag") == "rep.mp.threat.apt28"

    async def test_refresh(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))

            # Malpedia changed, but the daily pull hasn't run yet.
            fake.state["families"]["win.xagent"]["alt_names"].append("New Name")
            fake.state["yara"]["tlp_white"]["win.xagent_w9.yar"] = (
                "win.xagent",
                fm.YARA_WANNA_W0.replace("win_wannacryptor_w0", "win_xagent_w9"),
            )
            fake.state["bib"].append(
                (
                    "online",
                    "new:2026:xagent:1",
                    "Someone",
                    "New X-Agent",
                    "2026-10-31",
                    "Org",
                    "https://example.com/new-xagent",
                )
            )
            fake.state["families"]["win.xagent"]["library_entries"].append("new:2026:xagent:1")

            start = len(fake.requests)
            nodes = await core.nodes("slib.malpedia.refresh --family win.xagent --yield")
            assert [n.ndef for n in nodes] == [
                (await core.nodes(TOOL.format("win.xagent")))[0].ndef
            ]
            assert nodes[0].get("soft:names") == ("chopstick", "new name", "splm")
            assert fake.requests[start:] == [
                "/api/get/family/win.xagent",
                "/api/get/yara/win.xagent",
                "/api/get/bib/family/win.xagent",
            ]
            assert (
                await count(
                    core,
                    RULE.format("win.xagent_w9.yar")
                    + " -(detects)> risk:tool:software:id=win.xagent",
                )
                == 1
            )
            assert (
                await count(
                    core,
                    getNews("https://example.com/new-xagent") + " +#rep.malpedia.mal.win.xagent",
                )
                == 1
            )

            msgs = await core.stormlist("risk:threat:ext:id=apt28 | slib.malpedia.refresh")
            self.stormHasNoErr(msgs)
            self.stormIsInPrint("Modeled news=1, actor=1, family=1, yara=0.", msgs)

            # Inbound nodes are passed through, unless --yield is used.
            nodes = await core.nodes("risk:tool:software:id=win.sedreco | slib.malpedia.refresh")
            assert [n.get("id") for n in nodes] == ["win.sedreco"]
            nodes = await core.nodes("risk:threat:ext:id=apt28 | slib.malpedia.refresh --yield")
            assert [n.get("ext:id") for n in nodes] == ["apt28"]

            # Nodes that aren't from Malpedia are skipped.
            await core.nodes("[ risk:threat=* :name=other ]")
            msgs = await core.stormlist("risk:threat:name=other | slib.malpedia.refresh")
            self.stormIsInWarn("isn't a Malpedia actor or family", msgs)
            assert await count(core, "risk:threat:name=other | slib.malpedia.refresh --yield") == 0
            assert await count(core, "risk:threat:name=other | slib.malpedia.refresh") == 1

            msgs = await core.stormlist("slib.malpedia.refresh --family win.nope --actor apt28")
            self.stormIsInWarn(
                "Unable to refresh family win.nope: Malpedia returned HTTP 404", msgs
            )
            self.stormIsInPrint("Modeled news=1, actor=1, family=1, yara=0.", msgs)

    async def test_search(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.malpedia.search bear")
            self.stormHasNoErr(msgs)
            self.stormIsInPrint("2 actors match bear:", msgs)
            self.stormIsInPrint("No families match bear.", msgs)
            assert await count(core, "slib.malpedia.search bear --yield") == 0

            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))
            msgs = await core.stormlist("slib.malpedia.search wcry --families")
            self.stormIsInPrint("1 families match wcry:", msgs)
            self.stormIsInPrint("win.wannacryptor", msgs)
            self.stormIsInPrint("WannaCryptor", msgs)
            self.stormNotInPrint("actors match", msgs)
            nodes = await core.nodes("slib.malpedia.search bear --yield")
            assert {n.get("ext:id") for n in nodes} == {"apt28", "lazarus_group"}
            nodes = await core.nodes("slib.malpedia.search agent --actors --families --yield")
            assert {n.get("id") for n in nodes} == {"win.xagent"}

    async def test_schedule(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.malpedia.admin.schedule --period daily@03:17")
            self.stormIsInPrint("slib.malpedia.sync now runs daily@03:17", msgs)
            self.stormIsInPrint("(enabled) runs slib.malpedia.sync", msgs)
            iden = await core.callStorm('return($lib.globals.get("slib:malpedia:cron"))')

            # A new period replaces the job.
            msgs = await core.stormlist("slib.malpedia.admin.schedule --period daily@04:41")
            iden2 = await core.callStorm('return($lib.globals.get("slib:malpedia:cron"))')
            assert iden2 != iden
            assert await syncJobs(core) == 1

            msgs = await core.stormlist("slib.malpedia.admin.schedule --disable")
            self.stormIsInPrint("(disabled) runs slib.malpedia.sync", msgs)
            msgs = await core.stormlist("slib.malpedia.admin.schedule --enable")
            self.stormIsInPrint("(enabled) runs slib.malpedia.sync", msgs)
            msgs = await core.stormlist("slib.malpedia.admin.schedule --enable --disable")
            self.stormIsInWarn("Use --enable or --disable, not both.", msgs)
            msgs = await core.stormlist("slib.malpedia.admin.schedule --period nonsense")
            self.stormIsInWarn("Unable to schedule slib.malpedia.sync with period nonsense", msgs)

            msgs = await core.stormlist("slib.malpedia.admin.schedule --delete")
            self.stormIsInPrint("Deleted the sync cron job.", msgs)
            assert await syncJobs(core) == 0
            msgs = await core.stormlist("slib.malpedia.admin.schedule --delete")
            self.stormIsInPrint("There is no sync cron job.", msgs)
            msgs = await core.stormlist("slib.malpedia.admin.schedule --enable")
            self.stormIsInWarn("There is no sync cron job, create one with --period.", msgs)

            # A job deleted outside of the command is noticed.
            await core.stormlist("slib.malpedia.admin.schedule --period daily@03:17")
            await core.callStorm('$lib.cron.del($lib.globals.get("slib:malpedia:cron"))')
            msgs = await core.stormlist("slib.malpedia.admin.schedule")
            self.stormIsInPrint("There is no sync cron job", msgs)

    async def test_perms(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            visi = await core.auth.addUser("visi")
            opts = {"user": visi.iden}

            for cmd in (
                "slib.malpedia.sync",
                "slib.malpedia.search x",
                "slib.malpedia.status",
                "slib.malpedia.refresh --actor apt28",
                "slib.malpedia.admin.tags",
                "slib.malpedia.admin.schedule",
                "slib.malpedia.admin.reset --yes",
            ):
                await self.asyncraises(Exception, core.nodes(cmd, opts=opts))

            # Users can search and see the status without access to the service itself.
            await visi.addRule((True, ("slib", "malpedia", "user")))
            self.stormHasNoErr(await core.stormlist("slib.malpedia.search bear", opts=opts))
            self.stormHasNoErr(await core.stormlist("slib.malpedia.status", opts=opts))
            msgs = await core.stormlist("slib.malpedia.sync", opts=opts)
            self.stormIsInErr("requires permission: slib.malpedia.sync", msgs)

            # Syncing needs permission to add Malpedia's nodes to the view's layer.
            await visi.addRule((True, ("slib", "malpedia", "sync")))
            msgs = await core.stormlist("slib.malpedia.sync", opts=opts)
            self.stormIsInErr("it needs permission to add media:news nodes to its layer", msgs)
            msgs = await core.stormlist("slib.malpedia.refresh --actor apt28", opts=opts)
            self.stormIsInErr("it needs permission to add media:news nodes to its layer", msgs)

            # Then the edits run as root, so the user doesn't need every other permission
            # (tags, edges, ou:org, ps:contact, syn:tag...).
            for form in ("media:news", "risk:threat", "risk:tool:software", "it:app:yara:rule"):
                await visi.addRule((True, ("node", "add", form)))
            msgs = await core.stormlist("slib.malpedia.sync", opts=opts)
            self.stormHasNoErr(msgs)
            assert await count(core, "risk:threat") == 4
            self.stormHasNoErr(
                await core.stormlist("slib.malpedia.refresh --actor apt28", opts=opts)
            )

            # Forcing a pull is for admins, but there's nothing to force without a pull.
            msgs = await core.stormlist("slib.malpedia.sync --force --no-pull", opts=opts)
            self.stormHasNoErr(msgs)
            self.stormIsInWarn("--force does nothing with --no-pull", msgs)
            self.stormIsInPrint("Modeled the changes into this view", msgs)
            msgs = await core.stormlist("slib.malpedia.sync --force", opts=opts)
            self.stormIsInErr(
                "slib.malpedia.sync --force needs the slib.malpedia.admin permission.", msgs
            )
            await visi.addRule((True, ("slib", "malpedia", "admin")))
            msgs = await core.stormlist("slib.malpedia.sync --force", opts=opts)
            self.stormHasNoErr(msgs)
            self.stormIsInPrint("Pulled Malpedia version 26601", msgs)
            self.stormHasNoErr(await core.stormlist("slib.malpedia.admin.tags", opts=opts))
            self.stormHasNoErr(await core.stormlist("slib.malpedia.admin.reset --yes", opts=opts))


async def syncSummary(core, opts=None, **kwargs):
    """Run slib.malpedia.priv.sync.sync() and return its summary."""
    q = "return($lib.import(slib.malpedia.priv.sync).sync(full=$full, pull=$pull))"
    vars = {"full": kwargs.get("full", False), "pull": kwargs.get("pull", True)}
    return await core.callStorm(q, opts={**(opts or {}), "vars": vars})


class TestMalpediaStormAuditFixes(s_tests.SynTest):
    async def test_seen_in_new_view(self):
        # MALP-01: the meta:source is created in a view that doesn't have it, so every node
        # gets its -(seen)> edge.
        async with fm.malpediaSvc(self) as (core, svc, fake):
            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))
            layr = (await core.addLayer())["iden"]
            view = (await core.addView({"layers": [layr]}))["iden"]
            opts = {"view": view}
            assert await count(core, f"meta:source={SVC_GUID}", opts=opts) == 0
            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync --no-pull", opts=opts))
            nodes = await core.nodes(f"meta:source={SVC_GUID}", opts=opts)
            assert nodes[0].get("name") == "malpedia"
            for form, num in (
                ("media:news", 5),
                ("risk:threat", 4),
                ("risk:tool:software", 3),
                ("it:app:yara:rule", 3),
            ):
                assert (
                    await count(core, f"meta:source={SVC_GUID} -(seen)> {form}", opts=opts) == num
                ), form

    async def test_removed_missing_nodes(self):
        # MALP-02: a removed record whose node isn't in the view (ex. an analyst deleted it)
        # is done, not a failure on every sync.
        async with fm.malpediaSvc(self) as (core, svc, fake):
            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))
            await core.nodes(RULE.format("win.xagent_auto.yar") + " | delnode --force")
            await core.nodes(THREAT.format("[vault_7_8]") + " | delnode --force")
            await core.nodes(TOOL.format("win.sedreco") + " | delnode --force")
            await core.nodes(getNews(fm.URL_PLAIN) + " | delnode --force")

            state = fake.state
            state["version"]["version"] += 1
            state["yara"]["tlp_white"].pop("win.xagent_auto.yar")
            state["actors"].pop("[Vault 7/8]")
            state["actorids"].remove("[vault_7_8]")
            state["families"].pop("win.sedreco")
            state["references"].pop(fm.URL_NOBIB)
            state["actors"]["APT28"]["related"] = []
            state["bib"] = [e for e in state["bib"] if e[6] != fm.URL_PLAIN]

            summary = await syncSummary(core)
            assert not summary["errors"]
            for kind in ("news", "actor", "family", "yara"):
                assert summary["kinds"][kind]["failed"] == 0, kind
            # Two articles were removed (the plain report, and the article only Sedreco had).
            assert {k: c["removed"] for k, c in summary["kinds"].items()} == {
                "news": 2,
                "actor": 1,
                "family": 1,
                "yara": 1,
            }
            # Nothing is left to retry, and nothing was recreated.
            summary = await syncSummary(core, pull=False)
            assert all(c["total"] == 0 for c in summary["kinds"].values())
            assert await count(core, RULE.format("win.xagent_auto.yar")) == 0
            assert await count(core, getNews(fm.URL_PLAIN)) == 0

    async def test_refresh_case(self):
        # MALP-03: IDs are normalized, so no duplicate risk:threat is made for APT28.
        async with fm.malpediaSvc(self) as (core, svc, fake):
            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))
            nodes = await core.nodes("slib.malpedia.refresh --actor APT28 --yield")
            assert [n.get("ext:id") for n in nodes] == ["apt28"]
            nodes = await core.nodes("slib.malpedia.refresh --family WIN.XAGENT --yield")
            assert [n.get("id") for n in nodes] == ["win.xagent"]
            assert await count(core, "risk:threat") == 4
            assert await count(core, "risk:tool:software") == 3
            msgs = await core.stormlist("slib.malpedia.refresh --actor 'a b'")
            self.stormIsInWarn("Unable to refresh actor a b: Invalid Malpedia actor ID", msgs)

    async def test_refresh_limits(self):
        # MALP-06: a refresh asks for at most 25 actors and families, and each one only once.
        async with fm.malpediaSvc(self) as (core, svc, fake):
            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))

            args = " ".join(f"--actor a{i}" for i in range(26))
            start = len(fake.requests)
            msgs = await core.stormlist(f"slib.malpedia.refresh {args}")
            self.stormIsInWarn(
                "Not refreshing 26 actors and families at once, the limit is 25.", msgs
            )
            assert len(fake.requests) == start
            # Unless an admin uses --no-limit.
            msgs = await core.stormlist(f"slib.malpedia.refresh {args} --no-limit")
            self.stormHasNoErr(msgs)
            self.stormIsInWarn("Unable to refresh actor a", msgs)
            assert fake.countPaths("/api/get/actor/a") == 26

            # Inbound nodes: duplicates are refreshed once, and the rest are skipped past the limit.
            start = len(fake.requests)
            q = "risk:threat:ext:id=apt28 risk:threat:ext:id=apt28 | slib.malpedia.refresh"
            nodes = await core.nodes(q)
            assert len(nodes) == 2
            assert fake.requests[start:].count("/api/get/actor/apt28") == 1
            assert len(await core.nodes(q + " --yield")) == 1

            await core.nodes(
                "for $i in $lib.range(30) { [ risk:threat=(fake, $i) :reporter:name=malpedia :ext:id=`fake{$i}` ] }"
            )
            start = len(fake.requests)
            msgs = await core.stormlist("risk:threat:ext:id^=fake | slib.malpedia.refresh")
            self.stormIsInWarn("Refreshed 25 actors and families, skipping the rest.", msgs)
            assert fake.countPaths("/api/get/actor/fake") == 25

            visi = await core.auth.addUser("visi")
            await visi.addRule((True, ("slib", "malpedia", "sync")))
            for form in ("media:news", "risk:threat", "risk:tool:software", "it:app:yara:rule"):
                await visi.addRule((True, ("node", "add", form)))
            msgs = await core.stormlist(
                "slib.malpedia.refresh --actor apt28 --no-limit", opts={"user": visi.iden}
            )
            self.stormIsInErr("--no-limit needs the slib.malpedia.admin permission", msgs)

    async def test_module_checks(self):
        # Anyone with slib.malpedia.sync can import slib.malpedia.priv.sync, so its functions
        # check the same permissions and limits as the commands.
        async with fm.malpediaSvc(self) as (core, svc, fake):
            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))
            visi = await core.auth.addUser("visi")
            await visi.addRule((True, ("slib", "malpedia", "sync")))
            opts = {"user": visi.iden}
            mod = "$sync = $lib.import(slib.malpedia.priv.sync) "

            async def raises(query, mesg):
                with self.raises(Exception) as cm:
                    await core.callStorm(mod + query, opts=opts)
                assert mesg in str(cm.exception), str(cm.exception)

            # Modeling as root needs permission to add the nodes.
            start = len(fake.requests)
            await raises(
                "return($sync.sync(pull=(false)))", "needs permission to add media:news nodes"
            )
            await raises(
                "return($sync.refresh((apt28,), ([])))", "needs permission to add media:news nodes"
            )
            for form in ("media:news", "risk:threat", "risk:tool:software", "it:app:yara:rule"):
                await visi.addRule((True, ("node", "add", form)))

            # Forced pulls and refreshes past the limit are for admins.
            await raises(
                "return($sync.pull(force=(true)))",
                "--force needs the slib.malpedia.admin permission",
            )
            await raises(
                "return($sync.sync(force=(true)))",
                "--force needs the slib.malpedia.admin permission",
            )
            ids = [f"a{i}" for i in range(26)]
            q = "return($sync.refresh($ids, ([])))"
            with self.raises(Exception) as cm:
                await core.callStorm(mod + q, opts={**opts, "vars": {"ids": ids}})
            assert "Not refreshing 26 actors and families at once, the limit is 25." in str(
                cm.exception
            )
            q = "return($sync.refresh($ids, ([]), nolimit=(true)))"
            with self.raises(Exception) as cm:
                await core.callStorm(mod + q, opts={**opts, "vars": {"ids": ids}})
            assert "--no-limit needs the slib.malpedia.admin permission" in str(cm.exception)
            assert fake.requests[start:] == []

            # Within the limit, it works.
            summary = await core.callStorm(mod + "return($sync.refresh((apt28,), ([])))", opts=opts)
            assert summary["counts"]["actor"] == 1
            summary = await core.callStorm(mod + "return($sync.sync(pull=(false)))", opts=opts)
            assert summary["error"] is None

    async def test_refresh_no_input(self):
        # MALP-20: a refresh with nothing to refresh says so.
        async with fm.malpediaSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.malpedia.refresh")
            self.stormHasNoErr(msgs)
            self.stormIsInWarn("Nothing to refresh.", msgs)
            assert fake.requests == []
            # A mix of nodes from Malpedia and others.
            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))
            await core.nodes("[ risk:threat=* :name=other ]")
            msgs = await core.stormlist(
                "risk:threat:name=other risk:threat:ext:id=apt28 | slib.malpedia.refresh"
            )
            self.stormIsInWarn("isn't a Malpedia actor or family", msgs)
            self.stormIsInPrint("Modeled news=1, actor=1, family=1, yara=0.", msgs)
            self.stormNotInWarn("Nothing to refresh", msgs)

    async def test_service_del(self):
        # MALP-07: deleting the service deletes its cron jobs.
        async with fm.malpediaSvc(self) as (core, svc, fake):
            await core.stormlist("slib.malpedia.admin.schedule --period daily@03:17")
            assert await syncJobs(core) == 1
            jobs = await core.callStorm(
                "$l = ([]) for $c in $lib.cron.list() { $l.append($c.pack().name) } return($l)"
            )
            assert "slib.malpedia (initial setup and sync)" in jobs

            iden = core.getStormSvc(SVC_NAME).iden
            await core.nodes(f"service.del {iden}")
            for _ in range(100):
                jobs = await core.callStorm("return($lib.cron.list())")
                if not jobs:
                    break
                await asyncio.sleep(0.1)
            assert not jobs
            assert await core.callStorm('return($lib.globals.get("slib:malpedia:cron"))') is None
            # The tag settings are kept for when it's added again.
            assert (
                await core.callStorm('return($lib.globals.get("slib:malpedia:tag:prefix"))')
                == "rep.malpedia"
            )

    async def test_readd_no_duplicate_jobs(self):
        # The add event deletes setup jobs left behind, and the setup job adopts a sync cron
        # job left behind (ex. by a service.del that couldn't delete it) instead of adding one.
        async with fm.malpediaSvc(self) as (core, svc, fake):
            await core.stormlist("slib.malpedia.admin.schedule --period daily@03:17")
            iden = await core.callStorm('return($lib.globals.get("slib:malpedia:cron"))')
            await core.callStorm('$lib.globals.pop("slib:malpedia:cron")')

            svc.conf["malpedia:autosync"] = True
            q = "return($lib.import(slib.malpedia.priv.admin).autoSchedule())"
            assert await core.callStorm(q) is True
            assert await syncJobs(core) == 1
            assert await core.callStorm('return($lib.globals.get("slib:malpedia:cron"))') == iden

            # The add event again (as for a re-added service) leaves one setup job.
            await core.runStormSvcEvent(core.getStormSvc(SVC_NAME).iden, "add")
            q = "$l = ([]) for $c in $lib.cron.list() { $l.append($c.pack().name) } return($l)"
            names = await core.callStorm(q)
            assert names.count("slib.malpedia (initial setup and sync)") == 1
            for _ in range(600):
                if await count(core, "it:app:yara:rule"):
                    break
                await asyncio.sleep(0.1)
            assert await syncJobs(core) == 1

    async def test_reset_tags_removed(self):
        # Records Malpedia removed between a view's reset and its next sync are still tagged.
        async with fm.malpediaSvc(self) as (core, svc, fake):
            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))
            self.stormHasNoErr(await core.stormlist("slib.malpedia.admin.reset --yes"))
            fake.state["version"]["version"] += 1
            fake.state["actors"].pop("[Vault 7/8]")
            fake.state["actorids"].remove("[vault_7_8]")
            msgs = await core.stormlist("slib.malpedia.sync")
            self.stormHasNoErr(msgs)
            self.stormIsInPrint("Modeling 4 actor records.", msgs)
            vault = (await core.nodes(THREAT.format("[vault_7_8]")))[0]
            assert "rep.malpedia.removed" in vault.tags
            apt28 = (await core.nodes(THREAT.format("apt28")))[0]
            assert "rep.malpedia.removed" not in apt28.tags

    async def test_prefix_change_cleans_old_tags(self):
        # MALP-09: after a prefix change, the next sync re-models every record and removes the
        # tags it added under the old prefix.
        async with fm.malpediaSvc(self) as (core, svc, fake):
            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))
            assert await count(core, "#rep.malpedia.threat.apt28") == 2

            msgs = await core.stormlist("slib.malpedia.admin.tags --prefix rep.mp --tlp-prefix tlp")
            self.stormIsInPrint("models every record again", msgs)
            # An article that loses an actor while the prefix changes loses the old tag too.
            fake.state["version"]["version"] += 1
            fake.state["references"][fm.URL_SEDNIT] = fake.state["references"][fm.URL_SEDNIT][:1]

            msgs = await core.stormlist("slib.malpedia.sync")
            self.stormHasNoErr(msgs)
            self.stormIsInPrint("The tag prefixes changed since this view's last sync", msgs)
            self.stormIsInPrint("Modeling 5 news records.", msgs)
            # The old tags are gone, parents included.
            assert await count(core, "#rep.malpedia") == 0
            assert await count(core, "#rep.mp.threat.apt28") == 1
            assert await count(core, "#rep.mp.mal.win.xagent") == 5
            assert await count(core, "#tlp.white") == 3
            news = (await core.nodes(getNews(fm.URL_SEDNIT)))[0]
            assert "rep.mp.threat.apt28" not in news.tags

            # The next sync is incremental again.
            msgs = await core.stormlist("slib.malpedia.sync")
            self.stormNotInPrint("Modeling", msgs)
            self.stormNotInPrint("tag prefixes changed", msgs)

    async def test_prefix_change_with_failures(self):
        # The new tag prefixes aren't recorded until every record was modeled with them, so a
        # record that failed still loses its old tags on a later sync.
        async with fm.malpediaSvc(self) as (core, svc, fake):
            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))
            view = await core.callStorm("return($lib.view.get().iden)")
            self.stormHasNoErr(
                await core.stormlist("slib.malpedia.admin.tags --prefix rep.mp --tlp-prefix tlp")
            )

            changes = svc.changes

            async def broken(view, kind, **kwargs):
                async for batch in changes(view, kind, **kwargs):
                    for item in batch["upsert"]:
                        if kind == "actor" and item["key"] == "apt28":
                            item["rec"] = None
                    yield batch

            with mock.patch.object(svc, "changes", broken):
                summary = await syncSummary(core, pull=False)
            assert summary["retagged"] is True
            assert summary["kinds"]["actor"]["failed"] == 1
            assert (await svc.viewInfo(view))["tags"]["prefix"] == "rep.malpedia"
            assert await count(core, "risk:threat#rep.malpedia.threat.apt28") == 1

            # The next sync models every record again, and APT28 loses its old tags.
            summary = await syncSummary(core, pull=False)
            assert summary["retagged"] is True
            assert summary["kinds"]["actor"]["failed"] == 0
            assert await count(core, "#rep.malpedia") == 0
            assert await count(core, "risk:threat#rep.mp.threat.apt28") == 1
            assert (await svc.viewInfo(view))["tags"] == {"prefix": "rep.mp", "tlp": "tlp"}
            assert (await syncSummary(core, pull=False))["retagged"] is False

    async def test_modeling(self):
        # MALP-13: :soft, :ext:ids from other sources, and -(refs)> instead of -(about)>.
        async with fm.malpediaSvc(self) as (core, svc, fake):
            await core.nodes("[ risk:threat=(malpedia, apt28) :ext:ids=(other-id,) ]")
            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))
            apt28 = (await core.nodes(THREAT.format("apt28")))[0]
            assert apt28.get("ext:ids") == ("5b4ee3ea-eee3-4c8e-8323-85ae32658754", "other-id")
            assert (
                await count(
                    core, TOOL.format("win.xagent") + " :soft -> it:prod:soft +:name=x-agent"
                )
                == 1
            )

            # A changed UUID replaces only Malpedia's.
            fake.state["version"]["version"] += 1
            fake.state["actors"]["APT28"]["uuid"] = "11111111-0000-0000-0000-000000000000"
            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))
            apt28 = (await core.nodes(THREAT.format("apt28")))[0]
            assert apt28.get("ext:ids") == ("11111111-0000-0000-0000-000000000000", "other-id")

            # -(about)> edges from older versions are replaced by -(refs)> edges.
            await core.nodes(
                getNews(fm.URL_SEDNIT)
                + " [ -(refs)> { "
                + THREAT.format("apt28")
                + " } +(about)> { "
                + THREAT.format("apt28")
                + " } ]"
            )
            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync --full --no-pull"))
            assert await count(core, "media:news -(about)> *") == 0
            assert await count(core, getNews(fm.URL_SEDNIT) + " -(refs)> risk:threat") == 1

            # MALP-14: values that don't normalize are dropped one by one.
            q = "return($lib.import(slib.malpedia.model).tryNorms(ou:name, $items))"
            assert await core.callStorm(
                q, opts={"vars": {"items": ["A", {"x": 1}, " B ", "   "]}}
            ) == ("a", "b")

    async def test_industries(self):
        # MALP-15: removing a sector never creates its ou:industry.
        async with fm.malpediaSvc(self) as (core, svc, fake):
            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))
            await core.nodes("ou:industry:name=military | delnode --force")
            fake.state["version"]["version"] += 1
            fake.state["actors"]["APT28"]["meta"]["targeted-sector"] = []
            fake.state["actors"]["APT28"]["meta"]["cfr-target-category"] = ["Government"]
            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))
            assert await count(core, "ou:industry:name=military") == 0
            assert {
                n.get("name")
                for n in await core.nodes(THREAT.format("apt28") + " -(targets)> ou:industry")
            } == {"government"}

    async def test_duplicate_news(self):
        # MALP-16: with several media:news for one URL, the same (oldest) one is always used.
        async with fm.malpediaSvc(self) as (core, svc, fake):
            first = (await core.nodes(f"[ media:news=* :url={fm.URL_SEDNIT!r} ]"))[0]
            await asyncio.sleep(0.01)
            second = (await core.nodes(f"[ media:news=* :url={fm.URL_SEDNIT!r} ]"))[0]
            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))
            nodes = {n.ndef: n for n in await core.nodes(getNews(fm.URL_SEDNIT))}
            assert "rep.malpedia.threat.apt28" in nodes[first.ndef].tags
            assert "rep.malpedia.threat.apt28" not in nodes[second.ndef].tags
            # The one $lib.gen.newsByUrl() makes wins over the others.
            await core.callStorm("$lib.gen.newsByUrl($u)", opts={"vars": {"u": fm.URL_WANNACRY}})
            n = await core.callStorm(
                "return($lib.import(slib.malpedia.model).getNews($u))",
                opts={"vars": {"u": fm.URL_WANNACRY}},
            )
            assert n is not None

    async def test_tag_prefix_validation(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            for bad in ("'a b'", "''", "'rep..x'", "'#rep'"):
                msgs = await core.stormlist(f"slib.malpedia.admin.tags --prefix {bad}")
                self.stormIsInWarn("Invalid tag prefix", msgs)
            msgs = await core.stormlist("slib.malpedia.admin.tags --tlp-prefix 'a b'")
            self.stormIsInWarn("The tlp prefix wasn't changed.", msgs)
            self.stormIsInPrint("prefix=rep.malpedia tlp=rep.malpedia.tlp", msgs)

    async def test_error_paths(self):
        async with fm.malpediaSvc(self) as (core, svc, fake):
            # A search that fails.
            fake.state["errors"]["/api/find/actor/bear"] = [500] * 10
            msgs = await core.stormlist("slib.malpedia.search bear --actors")
            self.stormIsInWarn("Searching the actors failed: Malpedia returned HTTP 500", msgs)

            self.stormHasNoErr(await core.stormlist("slib.malpedia.sync"))
            # Within malpedia:pull:minage hours of the last check.
            svc.conf["malpedia:pull:minage"] = 12
            msgs = await core.stormlist("slib.malpedia.sync")
            self.stormIsInPrint("Malpedia was checked recently, not pulling it again yet.", msgs)
            svc.conf["malpedia:pull:minage"] = 0

            async def boom(*args, **kwargs):
                raise m_svc.MalpediaSvcError("boom")

            # The service failing mid-sync.
            with mock.patch.object(svc, "synced", boom):
                msgs = await core.stormlist("slib.malpedia.sync --full --no-pull")
            self.stormIsInWarn("The sync stopped early, the next sync will continue it: boom", msgs)

            with mock.patch.object(svc, "resetView", boom):
                msgs = await core.stormlist("slib.malpedia.admin.reset --yes")
            self.stormIsInWarn("Unable to reset this view: boom", msgs)

            with mock.patch.object(svc, "schedInfo", boom):
                msgs = await core.stormlist(
                    "$lib.print($lib.import(slib.malpedia.priv.admin).autoSchedule())"
                )
            self.stormIsInWarn("Unable to read the sync schedule: boom", msgs)
            self.stormIsInPrint("false", msgs)

            # A record that fails to model is counted, and reported.
            q = """
                $sync = $lib.import(slib.malpedia.priv.sync)
                $s = ({"kinds": {"nope": {"failed": 0, "removed": 0}}, "errors": []})
                $batch = ({"upsert": [{"key": "k", "hash": "h", "new": true, "rec": {}}], "removed": [{"key": "r", "rec": {}}]})
                $mesg = $sync._batch($lib.view.get().iden, nope, $batch, $lib.import(slib.malpedia.model).conf(), $s)
                return(($s, $mesg))
            """
            summary, mesg = await core.callStorm(q)
            assert summary["kinds"]["nope"]["failed"] == 2
            assert summary["errors"][0].startswith(
                "nope k: Unknown slib.malpedia record kind: nope"
            )
            assert "Unknown record kind 'nope'" in mesg

    def test_readmes_match(self):
        # The package's README (shown in the Cortex) is a copy of the service's README.
        svcdir = pathlib.Path(__file__).parents[1]
        pkgreadme = svcdir / "src" / "malpediasvc" / "pkgproto" / "README.md"
        assert pkgreadme.read_text() == (svcdir / "README.md").read_text(), (
            "Copy README.md to src/malpediasvc/pkgproto/README.md"
        )

    def test_readme_names_every_command(self):
        readme = (pathlib.Path(__file__).parents[1] / "README.md").read_text()
        for cmd in CMDS:
            assert f"`{cmd}" in readme, cmd

    def test_storm_str(self):
        # MALP-18: the add event's query is a real Storm string literal, not a Python repr.
        assert defs.stormStr('a "b" \\c') == '"a \\"b\\" \\\\c"'
        with self.raises(ValueError):
            defs.stormStr("é")
        assert defs.stormStr(defs.AUTO_QUERY) in defs.SVC_EVTS["add"]["storm"]

    async def test_storm_str_parses(self):
        async with self.getTestCore() as core:
            for text in ('a "b" \\c', defs.AUTO_QUERY, "it's"):
                assert await core.callStorm(f"return({defs.stormStr(text)})") == text
