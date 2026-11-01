"""Pytests for the slib.pcap rules: feeds, syncing them into the Cortex, pushing the rules to the
service, custom rules, and the rule matches (hits) in captures.

Ported from the slib.snort service. Tests that push rules to the service or match captures run
Snort, see tests.engines. The feed sync (modeling the feeds in the Cortex) doesn't, those run
everywhere with --no-push.
"""

import asyncio
import contextlib
import pathlib

import synapse.common as s_common
import synapse.tests.utils as s_tests
from pcapsvc import PcapSvc, __version__
from pcapsvc import feeds as s_feeds
from pcapsvc.defs import CRON_GLOBAL, PKGDEFS, SVC_GUID, SVC_NAME
from pcapsvc.rulesvc import RuleSvcError, _prepare

from . import pcaps
from .engines import needs
from .fakefeeds import SNORT3_RULES, needsnort, snortSvc, tarGz

CMDS = tuple(cmd["name"] for cmd in PKGDEFS[0]["commands"])
MODS = tuple(mod["name"] for mod in PKGDEFS[0]["modules"])

S3 = "test-snort3"
ET = "test-et"


def rule(feed, sid, gid=1):
    """The guid of a feed's rule."""
    return s_feeds.ruleGuid(feed, gid, sid)


async def count(core, query, opts=None):
    return len(await core.nodes(query, opts=opts))


async def putPcap(core, byts=None):
    """Save a PCAP in the Axon and make its file:bytes node. Returns its sha256."""
    byts = pcaps.samplePcap() if byts is None else byts
    size, sha256b = await core.axon.put(byts)
    sha256 = s_common.ehex(sha256b)
    await core.nodes(f"[ file:bytes=sha256:{sha256} :size={size} ]")
    return sha256


class TestPkg(s_tests.SynTest):
    """The package loads, the service registers, and the versions match."""

    async def test_pkg(self):
        async with snortSvc(self) as (core, svc, feeds):
            msgs = await core.stormlist("service.list")
            self.stormIsInPrint(f"true (svc) ({SVC_NAME} @ {__version__})", msgs)

            for cmd in CMDS:
                assert cmd in core.stormcmds, cmd
            for mod in MODS:
                self.stormHasNoErr(await core.stormlist(f"$mod = $lib.import({mod})"))

            # The add event made the meta:source and the sync cron job.
            assert await count(core, f"meta:source={SVC_GUID} +:name=slib.pcap") == 1
            iden = await core.callStorm(f"return($lib.globals.get({CRON_GLOBAL}))")
            cron = await core.callStorm(
                "return($lib.cron.get($iden).pprint())", opts={"vars": {"iden": iden}}
            )
            assert cron["enabled"] == "Y" and cron["query"] == "slib.pcap.sync"

            # The service's feeds came from its config.
            assert sorted(f["name"] for f in await svc.feeds()) == sorted([S3, ET])

            # Removing the service removes the cron job.
            await core.nodes(f"service.del {core.getStormSvcs()[0].iden}")
            # The del event runs in the background.
            for _ in range(100):
                if await core.callStorm(f"return($lib.globals.get({CRON_GLOBAL}))") is None:
                    break
                await asyncio.sleep(0.05)
            assert await core.callStorm(f"return($lib.globals.get({CRON_GLOBAL}))") is None
            assert not await core.callStorm("return($lib.cron.list())")

    async def test_status_without_rules(self):
        conf = {"snort:bin": "/nonexistent/snort", "suricata:bin": "/nonexistent/suricata"}
        async with snortSvc(self, conf=conf) as (core, svc, feeds):
            msgs = await core.stormlist("slib.pcap.status")
            self.stormIsInPrint("snort: not installed", msgs)
            self.stormIsInPrint("suricata: not installed", msgs)
            self.stormIsInPrint("Rules: 0 loaded of 0 pushed (no engines), 0 invalid", msgs)
            self.stormIsInWarn("The service has no Axon (axon:url)", msgs)
            self.stormIsInPrint("Sync schedule: cron", msgs)

            sha256 = await putPcap(core)
            msgs = await core.stormlist(f"slib.pcap.flows {sha256} --hits")
            self.stormIsInWarn("No rules are loaded in the service yet", msgs)

            # Without Snort, its rules are pushed but can't be loaded.
            await core.nodes(
                '[ it:app:snort:rule=* :text="alert tcp any any -> any any ( sid:1; )" :enabled=(true) ]'
            )
            msgs = await core.stormlist("slib.pcap.sync --no-feeds")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("the service loaded 0 of 1 rules (no engines)", msgs)
            msgs = await core.stormlist("slib.pcap.rule.errors")
            self.stormIsInPrint("The service doesn't have Snort, so Snort rules can't be run.", msgs)
            msgs = await core.stormlist("slib.pcap.status")
            self.stormIsInPrint("Rules: 0 loaded of 1 pushed (no engines), 1 invalid", msgs)

            # The rules are built again once an engine is there, even though they didn't change.
            assert svc._needsBuild()


class TestFeedSync(s_tests.SynTest):
    """Syncing the feeds into the Cortex (no push, so no Snort needed)."""

    async def test_sync_feeds(self):
        async with snortSvc(self) as (core, svc, feeds):
            msgs = await core.stormlist("slib.pcap.sync --no-push")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint(f"{S3}: synced 6 rules (6 added, 0 updated, 0 removed).", msgs)
            self.stormIsInPrint(f"{ET}: synced 3 rules (3 added, 0 updated, 0 removed).", msgs)

            rsguid = s_feeds.rulesetGuid(S3)
            nodes = await core.nodes(f"meta:ruleset={rsguid}")
            assert nodes[0].get("name") == S3 and nodes[0].get("desc") == "A Snort 3 test feed."
            assert nodes[0].get("type") == "slib.pcap.feed."
            assert await count(core, f"meta:ruleset={rsguid} -(has)> it:app:snort:rule") == 6
            assert (
                await count(
                    core, f"meta:ruleset={s_feeds.rulesetGuid(ET)} -(has)> it:app:snort:rule"
                )
                == 3
            )

            node = (await core.nodes(f"it:app:snort:rule={rule(S3, 1000001)}"))[0]
            assert node.get("id") == "1000001" and node.get("name") == "SLIB TEST beacon URI"
            assert node.get("engine") == 3 and node.get("enabled") == 1
            assert node.repr("version") == "2.0.0"
            assert node.get("text").startswith(
                'alert http any any -> any any ( msg:"SLIB TEST beacon URI";'
            )
            assert (
                await count(
                    core,
                    f"it:app:snort:rule={rule(S3, 1000001)} -(detects)> it:sec:cve=cve-2021-44228",
                )
                == 1
            )
            assert (
                await count(
                    core,
                    f"it:app:snort:rule={rule(S3, 1000001)} -(refs)> inet:url=http://example.com/beacon",
                )
                == 1
            )

            # Commented out rules are disabled.
            node = (await core.nodes(f"it:app:snort:rule={rule(S3, 1000004)}"))[0]
            assert node.get("enabled") == 0 and not node.get("text").startswith("#")

            # ET style metadata, and the excluded file.
            node = (await core.nodes(f"it:app:snort:rule={rule(ET, 2000001)}"))[0]
            assert node.get("engine") == 2 and node.repr("version") == "4.0.0"
            assert node.get("family") == "slibtest"
            assert node.repr("created").startswith("2021/11/01") and node.repr(
                "updated"
            ).startswith("2024/03/05")
            assert (
                await count(core, f"it:app:snort:rule={rule(ET, 2000001)} -(refs)> hash:md5") == 1
            )
            assert await count(core, "it:app:snort:rule:id=2000099") == 0

            # The feeds aren't due again, so nothing is downloaded.
            nreqs = len(feeds.requests)
            msgs = await core.stormlist("slib.pcap.sync --no-push")
            self.stormIsInPrint(f"{S3}: up to date", msgs)
            assert len(feeds.requests) == nreqs

            # A forced sync downloads again (conditionally) and resyncs, with nothing changed.
            msgs = await core.stormlist("slib.pcap.sync --no-push --force")
            self.stormIsInPrint(f"{S3}: synced 6 rules (0 added, 0 updated, 0 removed).", msgs)
            assert len(feeds.requests) == nreqs + 2

            # A user's choice to disable a rule sticks across syncs.
            await core.nodes(f"it:app:snort:rule={rule(S3, 1000002)} [ :enabled=(false) ]")

            # The feed changes: a rule is updated, one is removed, and one is added.
            text = SNORT3_RULES.replace("sid:1000003; rev:1;", "sid:1000003; rev:2; nocase;")
            text = "\n".join(line for line in text.splitlines() if "sid:1000006" not in line)
            text += '\nalert tcp any any -> any any ( msg:"SLIB TEST new"; content:"new"; sid:1000007; rev:1; )\n'
            feeds.files["/snort3.tar.gz"] = tarGz({"rules/snort3-test.rules": text})

            msgs = await core.stormlist(f"slib.pcap.sync --no-push --force --feed {S3}")
            self.stormIsInPrint(f"{S3}: synced 6 rules (1 added, 1 updated, 1 removed).", msgs)
            self.stormNotInPrint(ET, msgs)

            node = (await core.nodes(f"it:app:snort:rule={rule(S3, 1000003)}"))[0]
            assert node.repr("version") == "2.0.0" and "nocase" in node.get("text")
            assert (await core.nodes(f"it:app:snort:rule={rule(S3, 1000002)}"))[0].get(
                "enabled"
            ) == 0

            gone = (await core.nodes(f"it:app:snort:rule={rule(S3, 1000006)}"))[0]
            assert gone.get("enabled") == 0
            assert (
                await count(core, f"it:app:snort:rule={rule(S3, 1000006)} <(has)- meta:ruleset")
                == 0
            )
            assert (
                await count(
                    core,
                    f"it:app:snort:rule={rule(S3, 1000007)} +:enabled=(true) <(has)- meta:ruleset",
                )
                == 1
            )

            # A rule that rejoins its feed gets the feed's enabled state again.
            feeds.files["/snort3.tar.gz"] = tarGz({"rules/snort3-test.rules": SNORT3_RULES})
            msgs = await core.stormlist(f"slib.pcap.sync --no-push --force --feed {S3}")
            self.stormIsInPrint(f"{S3}: synced 6 rules (0 added, 2 updated, 1 removed).", msgs)
            assert (await core.nodes(f"it:app:snort:rule={rule(S3, 1000006)}"))[0].get(
                "enabled"
            ) == 1

            # Unknown and failing feeds.
            msgs = await core.stormlist("slib.pcap.sync --no-push --feed nope")
            self.stormIsInWarn("Unknown feed: nope", msgs)
            feeds.files.pop("/et.tar.gz")
            msgs = await core.stormlist(f"slib.pcap.sync --no-push --force --feed {ET}")
            self.stormIsInWarn(f"Syncing the {ET} feed failed: Downloading", msgs)
            msgs = await core.stormlist("slib.pcap.feed.list")
            self.stormIsInWarn(f"The last download of {ET} failed", msgs)

    async def test_sync_incremental(self):
        conf = {"pcap:feeds:interval": 0}
        async with snortSvc(self, conf=conf) as (core, svc, feeds):
            msgs = await core.stormlist(f"slib.pcap.sync --no-push --feed {S3}")
            self.stormIsInPrint(f"{S3}: synced 6 rules (6 added, 0 updated, 0 removed).", msgs)

            # Only the feed's changes are synced: a rule is updated, one is removed, one is added.
            text = SNORT3_RULES.replace("sid:1000003; rev:1;", "sid:1000003; rev:2; nocase;")
            text = "\n".join(line for line in text.splitlines() if "sid:1000006" not in line)
            text += (
                '\nalert tcp any any -> any any ( msg:"new"; content:"new"; sid:1000007; rev:1; )\n'
            )
            feeds.files["/snort3.tar.gz"] = tarGz({"rules/snort3-test.rules": text})

            # An edit to a feed rule's text isn't overwritten until the feed changes it.
            await core.nodes(f"it:app:snort:rule={rule(S3, 1000002)} [ :text=edited ]")

            msgs = await core.stormlist(f"slib.pcap.sync --no-push --feed {S3}")
            self.stormIsInPrint(
                f"{S3}: synced the feed's changes (1 added, 1 updated, 1 removed), it has 6 rules.",
                msgs,
            )
            assert (await core.nodes(f"it:app:snort:rule={rule(S3, 1000003)}"))[0].repr(
                "version"
            ) == "2.0.0"
            assert (await core.nodes(f"it:app:snort:rule={rule(S3, 1000006)}"))[0].get(
                "enabled"
            ) == 0
            assert (
                await count(core, f"it:app:snort:rule={rule(S3, 1000006)} <(has)- meta:ruleset")
                == 0
            )
            assert (
                await count(
                    core, f"it:app:snort:rule={rule(S3, 1000007)} +:enabled=1 <(has)- meta:ruleset"
                )
                == 1
            )
            assert (await core.nodes(f"it:app:snort:rule={rule(S3, 1000002)}"))[0].get(
                "text"
            ) == "edited"

            # Nothing changed.
            msgs = await core.stormlist(f"slib.pcap.sync --no-push --feed {S3}")
            self.stormIsInPrint(f"{S3}: downloaded, the feed is unchanged.", msgs)

            # --force is a full sync, which restores the edited text.
            msgs = await core.stormlist(f"slib.pcap.sync --no-push --force --feed {S3}")
            self.stormIsInPrint(f"{S3}: synced 6 rules (0 added, 1 updated, 0 removed).", msgs)
            assert (await core.nodes(f"it:app:snort:rule={rule(S3, 1000002)}"))[0].get(
                "text"
            ) != "edited"

            # Another view hasn't synced the feed, so it gets a full sync.
            view = await core.callStorm("return($lib.view.get().fork().iden)")
            opts = {"view": view}
            msgs = await core.stormlist("slib.pcap.feed.list", opts=opts)
            self.stormIsInPrint("no", msgs)
            msgs = await core.stormlist(f"slib.pcap.sync --no-push --feed {S3}", opts=opts)
            self.stormIsInPrint(f"{S3}: synced 6 rules (0 added, 0 updated, 0 removed).", msgs)
            msgs = await core.stormlist(f"slib.pcap.sync --no-push --feed {S3}", opts=opts)
            self.stormIsInPrint(f"{S3}: downloaded, the feed is unchanged.", msgs)

            # Changing the feed forgets what was synced.
            await core.nodes(f"slib.pcap.admin.feed add {S3} {feeds.url}/snort3.tar.gz")
            msgs = await core.stormlist(f"slib.pcap.sync --no-push --feed {S3}")
            self.stormIsInPrint(f"{S3}: synced 6 rules (0 added, 0 updated, 0 removed).", msgs)

            # Malformed references are skipped.
            feeds.files["/snort3.tar.gz"] = tarGz(
                {
                    "rules/a.rules": 'alert tcp any any -> any any ( msg:"x"; reference:url,bad url; reference:cve,nope; sid:42; )'
                }
            )
            msgs = await core.stormlist(f"slib.pcap.sync --no-push --feed {S3}")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("(1 added, 0 updated, 6 removed)", msgs)
            assert await count(core, f"it:app:snort:rule={rule(S3, 42)} -(refs)> *") == 0

    async def test_feed_admin(self):
        async with snortSvc(self) as (core, svc, feeds):
            msgs = await core.stormlist("slib.pcap.feed.list")
            self.stormIsInPrint("downloaded", msgs)
            self.stormIsInPrint(S3, msgs)
            self.stormIsInPrint(f"{feeds.url}/snort3.tar.gz", msgs)

            msgs = await core.stormlist(
                f"slib.pcap.admin.feed add extra {feeds.url}/extra.rules --exclude '*.bad' --desc Extra"
            )
            self.stormIsInPrint("Added the extra feed", msgs)
            feeds.files["/extra.rules"] = (
                b'alert tcp any any -> any any ( msg:"extra"; content:"x"; sid:3000001; )\n'
            )
            msgs = await core.stormlist("slib.pcap.sync --no-push --feed extra")
            self.stormIsInPrint("extra: synced 1 rules (1 added, 0 updated, 0 removed).", msgs)

            msgs = await core.stormlist("slib.pcap.admin.feed disable extra")
            self.stormIsInPrint("Disabled the extra feed", msgs)
            msgs = await core.stormlist("slib.pcap.sync --no-push")
            self.stormNotInPrint("extra", msgs)
            await core.nodes("slib.pcap.admin.feed enable extra")
            assert [f["enabled"] for f in await svc.feeds() if f["name"] == "extra"] == [True]

            # Changing a feed's URL downloads it again on the next sync.
            await core.nodes(f"slib.pcap.admin.feed add extra {feeds.url}/extra2.rules")
            feeds.files["/extra2.rules"] = feeds.files["/extra.rules"]
            msgs = await core.stormlist("slib.pcap.sync --no-push --feed extra")
            self.stormIsInPrint("extra: synced 1 rules (0 added, 0 updated, 0 removed).", msgs)

            nodes = await core.nodes("slib.pcap.feed.list --yield")
            assert {n.get("name") for n in nodes} == {S3, ET, "extra"}

            msgs = await core.stormlist("slib.pcap.admin.feed del extra")
            self.stormIsInPrint("Removed the extra feed", msgs)
            assert await count(core, "it:app:snort:rule:id=3000001") == 1

            msgs = await core.stormlist("slib.pcap.admin.feed add bad")
            self.stormIsInWarn("A URL is required", msgs)
            msgs = await core.stormlist("slib.pcap.admin.feed add bad ftp://x")
            self.stormIsInWarn("Invalid feed URL", msgs)
            msgs = await core.stormlist("slib.pcap.admin.feed del nope")
            self.stormIsInWarn("Unknown feed: nope", msgs)

    async def test_schedule(self):
        async with snortSvc(self) as (core, svc, feeds):
            msgs = await core.stormlist("slib.pcap.admin.schedule")
            self.stormIsInPrint("(enabled) runs slib.pcap.sync", msgs)
            old = await core.callStorm(f"return($lib.globals.get({CRON_GLOBAL}))")

            msgs = await core.stormlist('slib.pcap.admin.schedule --period "daily@03:30"')
            self.stormIsInPrint("slib.pcap.sync now runs daily@03:30", msgs)
            new = await core.callStorm(f"return($lib.globals.get({CRON_GLOBAL}))")
            assert new != old
            assert [c["iden"] for c in await core.callStorm("return($lib.cron.list())")] == [new]

            msgs = await core.stormlist("slib.pcap.admin.schedule --disable")
            self.stormIsInPrint("(disabled) runs slib.pcap.sync", msgs)
            msgs = await core.stormlist("slib.pcap.admin.schedule --enable")
            self.stormIsInPrint("(enabled) runs slib.pcap.sync", msgs)

            msgs = await core.stormlist('slib.pcap.admin.schedule --period "nope"')
            self.stormIsInWarn("Unable to schedule slib.pcap.sync", msgs)
            msgs = await core.stormlist("slib.pcap.admin.schedule --enable --disable")
            self.stormIsInWarn("not both", msgs)

            await core.callStorm("$lib.cron.del($iden)", opts={"vars": {"iden": new}})
            msgs = await core.stormlist("slib.pcap.admin.schedule --disable")
            self.stormIsInWarn("There is no sync cron job", msgs)
            msgs = await core.stormlist("slib.pcap.status")
            self.stormIsInPrint("Sync schedule: none", msgs)

    async def test_perms(self):
        async with snortSvc(self) as (core, svc, feeds):
            user = await core.auth.addUser("visi")
            opts = {"user": user.iden}

            for query in (
                "slib.pcap.status",
                "slib.pcap.sync --no-push",
                "slib.pcap.admin.feed disable x",
                "slib.pcap.rule.add 'alert tcp any any -> any any (sid:1;)'",
            ):
                msgs = await core.stormlist(query, opts=opts)
                self.stormIsInErr("requires permission", msgs)

            await user.addRule((True, ("slib", "pcap", "user")))
            msgs = await core.stormlist("slib.pcap.status", opts=opts)
            self.stormHasNoErr(msgs)
            self.stormIsInPrint("Rules: 0 loaded", msgs)

            # Syncing edits nodes as root, but only in views the user can add rules to.
            await user.addRule((True, ("slib", "pcap", "sync")))
            msgs = await core.stormlist(f"slib.pcap.sync --no-push --feed {S3}", opts=opts)
            self.stormIsInErr("needs permission to add it:app:snort:rule", msgs)
            self.len(0, await core.nodes("it:app:snort:rule"))
            await user.addRule((True, ("node", "add", "it:app:snort:rule")))
            await user.addRule((True, ("node", "add", "it:app:suricata:rule")))
            msgs = await core.stormlist(f"slib.pcap.sync --no-push --feed {S3}", opts=opts)
            self.stormHasNoWarnErr(msgs)
            assert await count(core, "it:app:snort:rule") == 6


class TestPrepare(s_tests.SynTest):
    def test_prepare(self):
        text = 'alert tcp any any -> any any ( msg:"x"; content:"a"; sid:{sid}; rev:{rev}; )'
        guids = sorted(s_common.guid() for _ in range(6))
        prep = _prepare(
            {
                guids[0]: (text.format(sid=1, rev=1), "snort3"),
                guids[1]: (text.format(sid=1, rev=2), "snort3"),
                guids[2]: (text.format(sid=2, rev=1), "snort2"),
                guids[3]: ("not a rule", "snort3"),
                # Suricata has its own gid:sid space.
                guids[4]: (text.format(sid=1, rev=1), "suricata"),
                # Snort 2 and 3 rules share one.
                guids[5]: (text.format(sid=2, rev=3), "snort3"),
            }
        )
        assert prep["rules"]["snort3"] == {guids[1]: text.format(sid=1, rev=2),
                                           guids[5]: text.format(sid=2, rev=3)}
        assert prep["rules"]["snort2"] == {}
        assert prep["rules"]["suricata"] == {guids[4]: text.format(sid=1, rev=1)}
        assert set(prep["errors"]) == {guids[0], guids[2], guids[3]}
        assert f"rule {guids[1]} (rev 2) is used instead" in prep["errors"][guids[0]]
        assert "Duplicate snort gid:sid 1:2" in prep["errors"][guids[2]]
        assert prep["meta"][guids[2]] == (1, 2, 1)

        # Ties go to the first guid.
        prep = _prepare(
            {guids[1]: (text.format(sid=1, rev=1), "snort3"),
             guids[0]: (text.format(sid=1, rev=1), "snort3")}
        )
        assert list(prep["rules"]["snort3"]) == [guids[0]] and list(prep["errors"]) == [guids[1]]


class TestSvcApi(s_tests.SynTest):
    """Service methods' input validation (no engine needed)."""

    async def test_errors(self):
        async with self.getTestCell(PcapSvc, conf={"pcap:feeds": []}) as svc:
            iden = await svc.pushStart()
            snort = "it:app:snort:rule"
            for bad, mesg in (
                (("nope", snort, "alert", "snort3"), "Invalid rule guid"),
                ((s_common.guid(), snort, "", "snort3"), "has no :text"),
                ((s_common.guid(), snort, "alert", 7), "Unsupported rule engine"),
                ((s_common.guid(), "inet:fqdn", "alert", "snort3"), "inet:fqdn"),
                (("x",), "pushed as (guid, form, text, engine)"),
            ):
                with self.raises(RuleSvcError) as cm:
                    await svc.pushRules(iden, [bad])
                assert mesg in cm.exception.mesg, cm.exception.mesg

            assert await svc.pushCancel(iden)
            with self.raises(RuleSvcError):
                await svc.pushRules(iden, [])

            with self.raises(RuleSvcError):
                await svc.feedPull("nope")
            with self.raises(RuleSvcError):
                await svc.ruleParse("nope")
            with self.raises(RuleSvcError):
                await svc.ruleCheck("alert", engine=9)

            # Stale pushes are pruned.
            iden = await svc.pushStart()
            assert svc._prunePushes(idle=-1000) == [iden]

            rule = await svc.ruleParse('alert tcp any any -> any any (msg:"x"; sid:5; rev:2;)')
            assert rule["id"] == "5"
            assert rule["guid"] == s_common.guid(("slib.pcap.custom", "snort", 1, 5))
            rule = await svc.ruleParse('alert tcp any any -> any any (msg:"x"; sid:5; rev:2;)',
                                       engine="suricata")
            assert rule["guid"] == s_common.guid(("slib.pcap.custom", "suricata", 1, 5))


@contextlib.asynccontextmanager
async def axonSvc(test):
    """A Cortex with slib.pcap added, the service reading PCAPs from the Cortex's Axon itself."""

    async with test.getTestAxon() as axon:
        url = axon.getLocalUrl()
        async with test.getTestCoreAndProxy(conf={"axon": url}) as (core, prox):
            async with test.getTestCell(
                PcapSvc, conf={"pcap:feeds": [], "axon:url": url}
            ) as svc:
                await test.addSvcToCore(svc, core)
                yield core, svc


@needsnort
class TestSnortRules(s_tests.SynTest):
    """Pushing rules and matching captures, with Snort."""

    async def test_sync_and_scan(self):
        async with snortSvc(self) as (core, svc, feeds):
            msgs = await core.stormlist("slib.pcap.sync")
            self.stormHasNoErr(msgs)
            # 7 enabled rules: 5 Snort 3 rules (1 invalid) + 2 converted Snort 2 rules.
            self.stormIsInPrint("the service loaded 6 of 7 rules", msgs)

            status = await svc.ruleStatus()
            assert status["loaded"] == 6 and status["invalid"] == 1
            assert status["engines"] == {"snort": 6, "suricata": 0}
            assert (await svc.status())["engines"]["snort"]["version"].startswith("3.")

            msgs = await core.stormlist("slib.pcap.rule.errors")
            self.stormIsInPrint(
                f"it:app:snort:rule={rule(S3, 1000005)} (sid 1000005): unknown rule keyword: foobar",
                msgs,
            )
            nodes = await core.nodes("slib.pcap.rule.errors --yield")
            assert [n.ndef[1] for n in nodes] == [rule(S3, 1000005)]

            # Nothing changed, so the service doesn't rebuild.
            msgs = await core.stormlist("slib.pcap.sync")
            self.stormIsInPrint("the service's 7 rules are unchanged", msgs)
            msgs = await core.stormlist("slib.pcap.sync --no-feeds --force")
            self.stormIsInPrint("the service loaded 6 of 7 rules", msgs)

            sha256 = await putPcap(core)
            msgs = await core.stormlist(f"file:bytes=sha256:{sha256} | slib.pcap.flows --hits")
            self.stormHasNoErr(msgs)
            self.stormIsInPrint("Modeled 3 flows (9 rule matches)", msgs)
            # The HTTP bodies would have been saved to an Axon.
            self.stormIsInWarn("2 files in", msgs)
            msgs = await core.stormlist(f"file:bytes=sha256:{sha256} | slib.pcap.flows --hits --no-files")
            self.stormHasNoWarnErr(msgs)

            # Every rule that matched: 2 HTTP sessions x (URI, host, response body, user agent) + the UDP ping.
            hits = await core.nodes("it:app:snort:hit")
            assert len(hits) == 9
            byrule = {}
            for hit in hits:
                byrule.setdefault(hit.get("rule"), []).append(hit)
            assert {r: len(h) for r, h in byrule.items()} == {
                rule(S3, 1000001): 2,
                rule(S3, 1000002): 2,
                rule(S3, 1000003): 1,
                rule(ET, 2000001): 2,
                rule(ET, 2000002): 2,
            }

            udp = byrule[rule(S3, 1000003)][0]
            assert (
                udp.get("src") == "udp://10.1.1.10:5353"
                and udp.get("dst") == "udp://198.51.100.7:9999"
            )
            assert udp.get("src:ipv4") == 0x0A01010A and udp.get("src:port") == 5353
            assert udp.get("dst:port") == 9999 and udp.repr("version") == "1.0.0"
            assert udp.get("time") == udp.get(".seen")[0]

            # The response body rule fires on the server's packet, hits are per flow, so its
            # endpoints are still the flow's client -> server.
            resp = [h for h in byrule[rule(ET, 2000001)] if h.get("dst") == "tcp://203.0.113.5:80"]
            assert len(resp) == 2 and all(h.get("src").startswith("tcp://10.1.1.1") for h in resp)
            flows = await core.nodes(f"it:app:snort:hit={resp[0].ndef[1]} -> inet:flow")
            assert (
                flows[0].get("src").startswith("tcp://10.1.1.1")
                and flows[0].get("dst") == "tcp://203.0.113.5:80"
            )
            assert flows[0].get("ip:proto") == 6 and flows[0].get("dst:port") == 80

            assert await count(core, f"file:bytes=sha256:{sha256} -(refs)> it:app:snort:hit") == 9
            assert await count(core, f"file:bytes=sha256:{sha256} -(refs)> inet:flow") == 3
            assert await count(core, f"meta:source={SVC_GUID} -(seen)> it:app:snort:hit") == 9

            # Re-scanning updates the same nodes, and --yield yields the hits.
            nodes = await core.nodes(f"file:bytes=sha256:{sha256} | slib.pcap.flows --hits --yield")
            assert len(nodes) == 9 and {n.form.name for n in nodes} == {"it:app:snort:hit"}
            assert await count(core, "it:app:snort:hit") == 9
            assert await count(core, "inet:flow") == 3

            # Disabling a rule removes it from the service.
            msgs = await core.stormlist(
                f"it:app:snort:rule={rule(S3, 1000002)} | slib.pcap.rule.disable"
            )
            self.stormIsInPrint("the service loaded 5 of 6 rules", msgs)
            assert (await core.nodes(f"it:app:snort:rule={rule(S3, 1000002)}"))[0].get(
                "enabled"
            ) == 0
            nodes = await core.nodes(f"file:bytes=sha256:{sha256} | slib.pcap.flows --hits --yield")
            assert len(nodes) == 7

            # Enabling a feed's disabled rule (and a broken one) pushes it.
            msgs = await core.stormlist(
                "it:app:snort:rule:id*in=(1000002, 1000004) | slib.pcap.rule.enable"
            )
            self.stormIsInPrint("the service loaded 7 of 8 rules", msgs)
            msgs = await core.stormlist(
                f"it:app:snort:rule={rule(S3, 1000005)} | slib.pcap.rule.enable"
            )
            self.stormIsInPrint("are unchanged", msgs)
            self.stormIsInWarn(
                f"it:app:snort:rule={rule(S3, 1000005)} couldn't be loaded: unknown rule keyword",
                msgs,
            )
            nodes = await core.nodes(f"file:bytes=sha256:{sha256} | slib.pcap.flows --hits --yield")
            assert len(nodes) == 11

            # A truncated PCAP scans the packets Snort could read, and an EXE isn't a PCAP.
            short = await putPcap(core, pcaps.samplePcap()[:-30])
            msgs = await core.stormlist(f"file:bytes=sha256:{short} | slib.pcap.flows --hits")
            self.stormIsInPrint("(10 rule matches)", msgs)
            self.stormIsInWarn("truncated", msgs)

            exe = await putPcap(core, b"MZ" + b"\x00" * 100)
            msgs = await core.stormlist(f"file:bytes=sha256:{exe} | slib.pcap.flows --hits")
            self.stormIsInWarn("The file is not a pcap or pcapng file", msgs)

            msgs = await core.stormlist(f"[ file:bytes=sha256:{'00' * 32} ] | slib.pcap.flows --hits")
            self.stormIsInWarn("is not in the Axon", msgs)
            msgs = await core.stormlist("[ file:bytes=* ] | slib.pcap.flows --hits")
            self.stormIsInWarn("it needs to be a file:bytes with a :sha256", msgs)
            msgs = await core.stormlist("[ inet:fqdn=vertex.link ] | slib.pcap.flows --hits")
            self.stormIsInWarn("Unable to analyze inet:fqdn vertex.link", msgs)

            msgs = await core.stormlist("slib.pcap.status")
            self.stormIsInPrint("Rules: 7 loaded of 8 pushed (snort 7, suricata 0), 1 invalid", msgs)

    async def test_custom_rules(self):
        async with snortSvc(self, conf={"pcap:feeds": []}) as (core, svc, feeds):
            text = 'alert udp any any -> any 9999 ( msg:"Custom UDP"; content:"UDP-PING"; reference:cve,2024-0001; sid:1000003; rev:5; )'
            msgs = await core.stormlist(f"slib.pcap.rule.add '{text}'")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("(sid 1000003, rev 5): Custom UDP", msgs)
            self.stormIsInPrint("the service loaded 1 of 1 rules", msgs)

            guid = s_common.guid(("slib.pcap.custom", "snort", 1, 1000003))
            node = (await core.nodes(f"it:app:snort:rule={guid}"))[0]
            assert (
                node.get("enabled") == 1
                and node.get("engine") == 3
                and node.repr("version") == "5.0.0"
            )
            assert (
                await count(core, f"it:app:snort:rule={guid} -(detects)> it:sec:cve=cve-2024-0001")
                == 1
            )

            # A Snort 2 rule, and a disabled one.
            snort2 = 'alert udp any any -> any 9999 (msg:"Snort2 UDP"; content:"SLIBSNORT"; sid:1000020; rev:1;)'
            nodes = await core.nodes(f"slib.pcap.rule.add --engine snort2 '{snort2}' --yield")
            assert nodes[0].get("engine") == 2
            msgs = await core.stormlist(
                "slib.pcap.rule.add --disabled 'alert tcp any any -> any any ( content:\"x\"; sid:1000021; )'"
            )
            self.stormIsInPrint("are unchanged", msgs)

            sha256 = await putPcap(core)
            nodes = await core.nodes(f"file:bytes=sha256:{sha256} | slib.pcap.flows --hits --yield")
            assert sorted(n.get("rule") for n in nodes) == sorted(
                (guid, s_common.guid(("slib.pcap.custom", "snort", 1, 1000020)))
            )

            # A rule with the same gid:sid and a higher rev replaces the other one in the service.
            await core.nodes(
                f'[ it:app:snort:rule=* :enabled=(true) :text="{text.replace("rev:5", "rev:6").replace(chr(34), chr(92) + chr(34))}" ]'
            )
            msgs = await core.stormlist("slib.pcap.sync")
            self.stormIsInPrint("the service loaded 2 of 3 rules", msgs)
            errs = await svc.ruleErrors()
            assert list(errs) == [guid] and "Duplicate snort gid:sid 1:1000003" in errs[guid]

            msgs = await core.stormlist("slib.pcap.rule.add 'not a rule'")
            self.stormIsInWarn("Parsing the rule failed: Not a Snort rule", msgs)

            # Rules without text, or with an engine the service can't run, aren't pushed.
            await core.nodes(
                "[ it:app:snort:rule=* :enabled=(true) :engine=1 :text='alert tcp any any -> any any (sid:9;)' ]"
            )
            await core.nodes("[ it:app:snort:rule=* :enabled=(true) ]")
            msgs = await core.stormlist("it:app:snort:rule -:text | slib.pcap.rule.enable")
            self.stormIsInWarn("has no :text", msgs)
            msgs = await core.stormlist("it:app:snort:rule:engine=1 | slib.pcap.rule.enable")
            self.stormIsInWarn("has an unsupported :engine (1)", msgs)
            msgs = await core.stormlist("slib.pcap.sync")
            self.stormIsInPrint("the service's 3 rules are unchanged", msgs)

    async def test_rule_check(self):
        async with snortSvc(self, conf={"pcap:feeds": []}) as (core, svc, feeds):
            msgs = await core.stormlist(
                "slib.pcap.rule.check --text 'alert tcp any any -> any any ( content:\"a\"; sid:1; )'"
            )
            self.stormIsInPrint("The rule is valid.", msgs)
            msgs = await core.stormlist(
                "slib.pcap.rule.check --text 'alert tcp any any -> any any ( nope:1; sid:1; )'"
            )
            self.stormIsInWarn("The rule is invalid: unknown rule keyword: nope", msgs)
            msgs = await core.stormlist(
                "slib.pcap.rule.check --engine snort2 --text 'alert tcp any any -> any 80 (content:\"a\"; http_uri; sid:1;)'"
            )
            self.stormIsInPrint("The rule is valid.", msgs)

            await core.nodes(
                "[ it:app:snort:rule=* :id=good :text='alert tcp any any -> any any ( content:\"a\"; sid:1; )' ]"
            )
            await core.nodes(
                "[ it:app:snort:rule=* :id=bad :text='alert tcp any any -> any any ( content:\"a; sid:1; )' ]"
            )
            await core.nodes("[ it:app:snort:rule=* :id=empty ]")
            msgs = await core.stormlist("it:app:snort:rule | slib.pcap.rule.check")
            self.stormIsInPrint("is valid.", msgs)
            self.stormIsInWarn("is invalid: The rule has an unterminated quoted string.", msgs)
            self.stormIsInWarn("has no :text", msgs)

            # Checking doesn't change the service's rules.
            assert (await svc.ruleStatus())["rules"] == 0

            msgs = await core.stormlist("slib.pcap.rule.errors")
            self.stormIsInPrint("The engines loaded every rule.", msgs)

    async def test_axon_mode(self):
        async with axonSvc(self) as (core, svc):
            await core.nodes(
                'slib.pcap.rule.add \'alert udp any any -> any 9999 ( msg:"UDP"; content:"SLIBSNORT"; sid:1; )\''
            )
            msgs = await core.stormlist("slib.pcap.status")
            self.stormIsInPrint("Axon: PCAPs are read from the Axon by the service", msgs)

            sha256 = await putPcap(core)
            nodes = await core.nodes(f"file:bytes=sha256:{sha256} | slib.pcap.flows --hits --yield")
            assert len(nodes) == 1

            msgs = await core.stormlist(f"[ file:bytes=sha256:{'00' * 32} ] | slib.pcap.flows --hits")
            self.stormIsInWarn("is not in the Axon", msgs)

    async def test_restart(self):
        with self.getTestDir() as dirn:
            async with self.getTestCoreAndProxy() as (core, prox):
                async with self.getTestCell(PcapSvc, dirn=dirn, conf={"pcap:feeds": []}) as svc:
                    await self.addSvcToCore(svc, core)
                    await core.nodes(
                        "slib.pcap.rule.add 'alert udp any any -> any 9999 ( content:\"SLIBSNORT\"; sid:1; )'"
                    )
                    path = svc.active["snort"][0]

                # The rules are loaded again at startup.
                async with self.getTestCell(PcapSvc, dirn=dirn, conf={"pcap:feeds": []}) as svc:
                    assert svc.active["snort"][0] == path and list(svc.active["snort"][1]) == ["1:1"]

                # The rules file is rebuilt if it's gone.
                pathlib.Path(path).unlink()
                async with self.getTestCell(PcapSvc, dirn=dirn, conf={"pcap:feeds": []}) as svc:
                    async with svc.buildlock:
                        pass
                    for _ in range(100):
                        if svc.active.get("snort"):
                            break
                        await svc.waitfini(timeout=0.1)
                    assert list(svc.active["snort"][1]) == ["1:1"]
                    assert svc.active["snort"][0] != path


SU = "test-suricata"


@needs("suricata")
class TestSuricataRules(s_tests.SynTest):
    """Suricata rules: a feed, custom rules from the graph, and their matches."""

    async def test_suricata_feed(self):
        async with snortSvc(self, conf={"pcap:feeds": [], "snort:enabled": False}) as \
                (core, svc, feeds):
            msgs = await core.stormlist(
                f"slib.pcap.admin.feed add {SU} {feeds.url}/suricata.tar.gz --engine suricata"
            )
            self.stormIsInPrint(f"Added the {SU} feed", msgs)
            msgs = await core.stormlist("slib.pcap.sync")
            self.stormHasNoErr(msgs)
            self.stormIsInPrint(f"{SU}: synced 5 rules (5 added, 0 updated, 0 removed).", msgs)
            # 4 enabled, 1 of them Suricata can't load.
            self.stormIsInPrint("the service loaded 3 of 4 rules (snort 0, suricata 3)", msgs)

            node = (await core.nodes(f"it:app:suricata:rule={rule(SU, 4000001)}"))[0]
            assert node.get("id") == "4000001" and node.get("name") == "SLIB SURI beacon URI"
            assert node.get("enabled") == 1 and node.repr("version") == "2.0.0"
            assert await count(core, f"it:app:suricata:rule={rule(SU, 4000001)} "
                                     "-(detects)> it:sec:cve=cve-2021-44228") == 1
            assert (await core.nodes(f"it:app:suricata:rule={rule(SU, 4000005)}"))[0].get(
                "enabled") == 0
            assert await count(core, f"meta:ruleset={s_feeds.rulesetGuid(SU)} "
                                     "-(has)> it:app:suricata:rule") == 5

            msgs = await core.stormlist("slib.pcap.rule.errors")
            self.stormIsInPrint(f"it:app:suricata:rule={rule(SU, 4000004)} (sid 4000004)", msgs)

            sha256 = await putPcap(core)
            msgs = await core.stormlist(f"slib.pcap.flows {sha256} --hits --no-files")
            self.stormHasNoWarnErr(msgs)
            # 2 HTTP sessions x (URI, host) + the UDP ping, one match per flow and rule.
            self.stormIsInPrint("Modeled 3 flows (5 rule matches)", msgs)
            matches = await core.nodes("it:app:suricata:matched")
            byrule = {}
            for match in matches:
                byrule.setdefault(match.get("rule"), []).append(match)
            assert {r: len(m) for r, m in byrule.items()} == {
                rule(SU, 4000001): 2, rule(SU, 4000002): 2, rule(SU, 4000003): 1,
            }
            udp = byrule[rule(SU, 4000003)][0]
            assert udp.repr("version") == "1.0.0"
            flow = (await core.nodes(f"it:app:suricata:matched={udp.ndef[1]} :target -> inet:flow"))[0]
            assert flow.get("dst") == "udp://198.51.100.7:9999"
            assert flow.get("raw")["hits"][0]["rule"] == rule(SU, 4000003)

            # Matching again updates the same nodes, and --hits --yield yields them.
            nodes = await core.nodes(f"slib.pcap.flows {sha256} --hits --no-files --yield")
            assert len(nodes) == 5 and {n.form.name for n in nodes} == {"it:app:suricata:matched"}
            assert await count(core, "it:app:suricata:matched") == 5

            # Without rules (or with --no-rules) Suricata still runs, for its protocol details.
            msgs = await core.stormlist(f"slib.pcap.flows {sha256} --hits --no-rules --no-files")
            self.stormIsInPrint("Modeled 3 flows (0 rule matches)", msgs)

    async def test_suricata_warnings(self):
        async with snortSvc(self, conf={"pcap:feeds": [], "snort:enabled": False}) as \
                (core, svc, feeds):
            for text in (
                'alert http any any -> any any (msg:"fine"; http.uri; content:"/x"; sid:7001;)',
                'pass tcp any any -> any 80 (msg:"pass"; content:"x"; sid:7002;)',
                'alert http any any -> any any (msg:"pcre"; pcre:"/a+b/"; sid:7003;)',
            ):
                msgs = await core.stormlist(f"slib.pcap.rule.add --engine suricata '{text}'")
                self.stormHasNoWarnErr(msgs)
            pass_ = s_common.guid(("slib.pcap.custom", "suricata", 1, 7002))
            pcre = s_common.guid(("slib.pcap.custom", "suricata", 1, 7003))
            assert set(await svc.ruleWarnings()) == {pass_, pcre}

            msgs = await core.stormlist("slib.pcap.rule.errors")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("The engines loaded every rule.", msgs)
            self.stormIsInPrint(f"it:app:suricata:rule={pass_} (sid 7002) warning: It's a pass rule", msgs)
            self.stormIsInPrint(f"it:app:suricata:rule={pcre} (sid 7003) warning: It has a pcre", msgs)
            self.stormIsInPrint("2 loaded rules have warnings.", msgs)
            msgs = await core.stormlist("slib.pcap.rule.errors --no-warnings")
            self.stormNotInPrint("warning:", msgs)

            # Rules that aren't loaded anymore don't have warnings.
            await core.nodes(f"it:app:suricata:rule={pass_} | slib.pcap.rule.disable")
            assert set(await svc.ruleWarnings()) == {pcre}

    async def test_suricata_custom(self):
        async with snortSvc(self, conf={"pcap:feeds": []}) as (core, svc, feeds):
            text = ('alert udp any any -> any 9999 (msg:"Custom Suricata UDP"; content:"UDP-PING"; '
                    'sid:1000003; rev:5;)')
            msgs = await core.stormlist(f"slib.pcap.rule.add --engine suricata '{text}'")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("(sid 1000003, rev 5): Custom Suricata UDP", msgs)
            guid = s_common.guid(("slib.pcap.custom", "suricata", 1, 1000003))
            node = (await core.nodes(f"it:app:suricata:rule={guid}"))[0]
            assert node.get("enabled") == 1 and node.repr("version") == "5.0.0"

            # The same gid:sid as a Snort rule is fine, they're separate.
            snort = text.replace("Custom Suricata UDP", "Custom Snort UDP")
            msgs = await core.stormlist(f"slib.pcap.rule.add '{snort}'")
            self.stormHasNoWarnErr(msgs)

            msgs = await core.stormlist("slib.pcap.rule.check --engine suricata --text "
                                        "'alert http any any -> any any (http.nope; sid:1;)'")
            self.stormIsInWarn("The rule is invalid", msgs)
            msgs = await core.stormlist(f"it:app:suricata:rule={guid} | slib.pcap.rule.check")
            self.stormIsInPrint("is valid.", msgs)

            sha256 = await putPcap(core)
            nodes = await core.nodes(f"slib.pcap.flows {sha256} --hits --no-files --yield")
            forms = sorted(n.form.name for n in nodes)
            if svc.snort.available():
                assert forms == ["it:app:snort:hit", "it:app:suricata:matched"]
            else:
                assert forms == ["it:app:suricata:matched"]

            # Disabled rules are removed from the service.
            msgs = await core.stormlist(f"it:app:suricata:rule={guid} | slib.pcap.rule.disable")
            self.stormHasNoWarnErr(msgs)
            nodes = await core.nodes(f"slib.pcap.flows {sha256} --hits --no-files --yield")
            assert "it:app:suricata:matched" not in {n.form.name for n in nodes}

