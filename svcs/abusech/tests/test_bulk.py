"""Pytests for bulk imports: the Python node builder, the service's bulk jobs, and the Storm --bulk mode."""

import os

import synapse.lib.msgpack as s_msgpack
import synapse.tests.utils as s_tests

from abusechsvc import bulk, norm
from abusechsvc.client import AbuseChApiError

from abusechsvc.svc import BULK_IDLE

from . import fakeabusech as fd
from .fakeabusech import abusechSvc


async def dumpNodes(core) -> dict:
    """Every node in a Cortex as {ndef: (props without .created, tags, {(verb, n2 ndef)})}."""

    nodes = await core.nodes(".created")
    idens = {n.iden(): n.ndef for n in nodes}
    retn = {}
    for node in nodes:
        edges = set()
        async for verb, n2iden in node.iterEdgesN1():
            edges.add((verb, idens.get(n2iden)))
        props = {k: v for k, v in node.props.items() if k != ".created"}
        retn[node.ndef] = (props, dict(node.tags), edges)
    return retn


async def importNodes(test, query) -> tuple[dict, list]:
    """Run an export command in a new Cortex, returning its nodes and any warnings/errors."""

    async with abusechSvc(test) as (core, svc, fake):
        msgs = await core.stormlist(query)
        bad = [
            m
            for m in msgs
            if m[0] == "err"
            or (
                m[0] == "warn"
                and "background" not in m[1]["mesg"]
                and "may take a while" not in m[1]["mesg"]
            )
        ]
        return await dumpNodes(core), bad


class TestBuilder(s_tests.SynTest):
    def test_model(self):
        model = bulk.buildModel()
        assert model.form("inet:url") is not None
        assert (
            model.prop("file:bytes:_tlsh") is not None
            and model.prop("file:bytes:_sha3_384") is not None
        )

    def test_builder(self):
        builder = bulk.NodeBuilder(bulk.buildModel(), "rep.abusech")

        # Invalid values are skipped, like Storm's ?= edits.
        assert builder.node("inet:ipv4", "not an ip") is None
        assert builder.node("inet:url", None) is None
        assert builder.guid("it:av:scan:result", {"verdict": "nope"}) is None
        ndef = builder.node("inet:fqdn", "A.com")
        assert ndef == ("inet:fqdn", "a.com")
        builder.prop(ndef, "nope", 1)
        builder.prop(ndef, ".seen", "nope")
        builder.prop(None, "x", 1)

        # Tags with an invalid interval aren't added (like +?#tag=ival), valid ones merge.
        builder.tag(ndef, "rep.x", "2026-01-02", "2026-01-01")
        builder.tag(ndef, "bad tag!")
        builder.tag(ndef, "rep.y", "2026-01-01")
        builder.tag(ndef, "rep.y", "2026-02-01")
        builder.tag(ndef, "rep.z")
        builder.tag(None, "rep.z")
        builder.tags(ndef, "urlhaus", None)
        tags = dict(builder.flush())[ndef]["tags"]
        assert "rep.x" not in tags and "rep.z" in tags and tags["rep.z"] == (None, None)
        assert tags["rep.y"][0] < tags["rep.y"][1] and tags["rep.y"][1] > 1767225600000

        # Without a tag prefix, nothing is tagged and families are keyed by name.
        builder = bulk.NodeBuilder(bulk.buildModel(), None)
        builder.tags(("inet:fqdn", "a.com"), "urlhaus", ["x"])
        tool = builder.family(
            "bazaar", "Emotet", "emotet", ["Heodo"], "win.emotet", "https://malpedia/x"
        )
        nodes = dict(builder.finish())
        assert nodes[tool]["props"]["soft:names"] == ("emotet", "heodo")
        assert nodes[tool]["props"]["id"] == "win.emotet"
        assert builder.family("bazaar", None) is None

        # Files without a SHA256 get a guid:, and samples/IOCs/URLs without a value are skipped.
        assert builder.fileNode({"md5": "a" * 32}, "bazaar")[1].startswith("guid:")
        assert builder.fileNode({"sha3_384": "a" * 96}, "bazaar")[1].startswith("guid:")
        assert builder.fileNode({}, "bazaar") is None
        assert builder.sample(None, "bazaar") is None
        assert builder.url(None) is None and builder.url({"url": "not a url"}) is None
        assert builder.ioc(None) is None and builder.ioc({"obs": None}) is None
        assert builder.reporter(None, ("inet:fqdn", "a.com"), "urlhaus") is None
        assert builder.refNode(None, ("inet:fqdn", "a.com"), "urlhaus") is None

    def test_arrays(self):
        # Array values only accumulate across batches for held nodes (families); the rest are
        # dropped once their batch is flushed, so memory doesn't grow with the export.
        builder = bulk.NodeBuilder(bulk.buildModel(), "rep.abusech")
        file = builder.node("file:bytes", "sha256:" + "a" * 64)
        builder.addArray(file, "ssdeeps", "3:a:b")
        tool = builder.family("bazaar", "Emotet", "emotet", ["Heodo"])
        builder.flush()
        assert list(builder.arrays) == [(tool, "soft:names")]
        builder.family("bazaar", "Emotet", "emotet", ["Geodo"])
        builder.addArray(file, "ssdeeps", "3:c:d")
        nodes = dict(builder.finish())
        assert nodes[file]["props"]["ssdeeps"] == ("3:c:d",)
        assert nodes[tool]["props"]["soft:names"] == ("emotet", "geodo", "heodo")

    def test_time_pair(self):
        assert norm.timePair("2026-02-01", "2026-01-01") == ("2026-01-01", "2026-02-01")
        assert norm.timePair("2026-01-01", None) == ("2026-01-01", None)
        assert (
            norm.normUrl(
                {"url": "http://a/", "dateadded": "2026-02-01", "last_online": "2026-01-01"}
            )["added"]
            == "2026-01-01"
        )
        c2 = norm.normC2("1.2.3.4", 443, first_seen="2026-02-01 10:00:00", last_online="2026-01-01")
        assert c2["first_seen"] < c2["last_online"]


class TestBulkSvc(s_tests.SynTest):
    async def test_jobs(self):
        async with abusechSvc(self) as (core, svc, fake):
            assert ["threatfox", "full"] in await svc.bulkExports()

            byts = b"".join([b async for b in svc.bulkPull("bazaar", "recent")])
            assert byts == fd.BAZAAR_CSV.encode()
            assert fake.last()["path"] == "/bazaar_export/testkey/recent.csv"
            with self.raises(AbuseChApiError):
                [b async for b in svc.bulkPull("bazaar", "yara")]
            with self.raises(AbuseChApiError):
                [b async for b in svc.bulkPull("bazaar", "recent", apikey="badkey")]

            with self.raises(AbuseChApiError):
                await svc.bulkStart("bazaar", "recent", "nothex")
            with self.raises(AbuseChApiError):
                await svc.bulkStage("nope", b"x")

            import hashlib

            jobid = await svc.bulkStart("bazaar", "recent", hashlib.sha256(byts).hexdigest())
            assert await svc.bulkStage(jobid, byts[:100]) == 100
            assert await svc.bulkStage(jobid, byts[100:]) == len(byts)

            items = [i async for i in svc.bulkBuild(jobid, prefix="rep.abusech", batch=1)]
            assert items[0] == {"rows": 1, "nodes": items[0]["nodes"]}
            done = items[-1]
            assert (
                done["done"]
                and done["rows"] == 2
                and done["skipped"] == 0
                and done["builder"] == bulk.BUILDER_VERSION
            )
            nodes = b"".join([b async for b in svc.bulkNodes(jobid, chunk=100)])
            assert len(nodes) == done["size"] and "sha256" not in done
            packed = [i for _, i in s_msgpack.Unpk().feed(nodes)]
            assert len(packed) == done["nodes"]
            assert ("file:bytes", f"sha256:{fd.SHA256}") in [tuple(p[0]) for p in packed]

            dirn = svc.bulkjobs[jobid]["dirn"]
            assert await svc.bulkDone(jobid) and not os.path.exists(dirn)
            assert await svc.bulkDone(jobid)

            # A staged file that doesn't match its SHA256 isn't built.
            jobid = await svc.bulkStart("urlhaus", "recent", "a" * 64)
            await svc.bulkStage(jobid, b"nope")
            with self.raises(AbuseChApiError):
                [i async for i in svc.bulkBuild(jobid)]
            await svc.bulkDone(jobid)

            # Jobs left behind (ex. by a cancelled import) are removed once idle; active ones are kept.
            old = await svc.bulkStart("urlhaus", "recent", "a" * 64)
            new = await svc.bulkStart("urlhaus", "recent", "b" * 64)
            olddirn = svc.bulkjobs[old]["dirn"]
            svc.bulkjobs[old]["touched"] -= BULK_IDLE + 1
            await svc.bulkStage(new, b"x")
            assert svc._bulkPrune() == [old]
            assert old not in svc.bulkjobs and not os.path.exists(olddirn)
            assert new in svc.bulkjobs
            await svc.bulkDone(new)

            # ThreatFox exports, zipped or not, build from the staged JSON.
            byts = b"".join([b async for b in svc.bulkPull("threatfox", "full")])
            jobid = await svc.bulkStart("threatfox", "full", hashlib.sha256(byts).hexdigest())
            await svc.bulkStage(jobid, byts)
            done = [i async for i in svc.bulkBuild(jobid, prefix="rep.abusech")][-1]
            assert done["rows"] > 0 and done["nodes"] > done["rows"]
            await svc.bulkDone(jobid)


class TestBulkStorm(s_tests.SynTest):
    async def test_parity(self):
        # Bulk imports create exactly the nodes the Storm model does, for every export record shape.
        for plat, kind in (
            ("bazaar", "recent"),
            ("urlhaus", "recent"),
            ("urlhaus", "payloads"),
            ("threatfox", "full"),
        ):
            storm, sbad = await importNodes(self, f"slib.abusech.{plat}.export {kind}")
            bulked, bbad = await importNodes(self, f"slib.abusech.{plat}.export {kind} --bulk")
            assert not sbad and not bbad, (plat, kind, sbad, bbad)
            assert len(storm) > 10, (plat, kind)
            assert storm == bulked, (
                plat,
                kind,
                {k for k in set(storm) | set(bulked) if storm.get(k) != bulked.get(k)},
            )

    async def test_datasets(self):
        async with abusechSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.abusech.urlhaus.export recent --bulk")
            self.stormIsInWarn(
                "run them in the background, ex. background { slib.abusech.urlhaus.export recent --bulk }",
                msgs,
            )
            self.stormIsInPrint("Ingested 5 nodes", msgs)
            assert (
                await core.count(
                    "inet:url=http://csv.example.com/x.exe +#rep.abusech.urlhaus.agenttesla"
                )
                == 1
            )

            sets = await core.callStorm("return($lib.globals.get(slib:abusech:datasets))")
            info = sets["urlhaus:recent"]
            assert info["size"] == len(fd.URLHAUS_CSV) and info["file"] == "urlhaus:recent"
            assert (
                info["nodes"]["count"] == 5
                and info["nodes"]["rows"] == 1
                and info["nodes"]["builder"] == 1
            )
            assert await core.axon.has(bytes.fromhex(info["sha256"]))
            assert await core.axon.has(bytes.fromhex(info["nodes"]["sha256"]))
            # The job is cleaned up.
            assert not svc.bulkjobs and not os.listdir(svc.bulkdir)

            # Recent exports can't be pulled again within an hour.
            pulls = len(fake.queries("urlhaus_export"))
            msgs = await core.stormlist("slib.abusech.urlhaus.export recent --bulk")
            self.stormIsInWarn(
                "rerun with --reuse to import that pull again, or --repull to pull a new one", msgs
            )
            assert len(fake.queries("urlhaus_export")) == pulls

            # --reuse imports the last pull again, --repull pulls a new one.
            msgs = await core.stormlist("slib.abusech.urlhaus.export recent --bulk --reuse")
            self.stormIsInPrint("Ingested 5 nodes", msgs)
            assert len(fake.queries("urlhaus_export")) == pulls
            msgs = await core.stormlist("slib.abusech.urlhaus.export recent --bulk --repull")
            self.stormIsInPrint("Pulled the recent export", msgs)
            assert len(fake.queries("urlhaus_export")) == pulls + 1

            # An hour later, recent exports are pulled again.
            sets = await core.callStorm("return($lib.globals.get(slib:abusech:datasets))")
            sets["urlhaus:recent"]["time"] -= 3600001
            await core.callStorm(
                "$lib.globals.set(slib:abusech:datasets, $s)", opts={"vars": {"s": sets}}
            )
            msgs = await core.stormlist("slib.abusech.urlhaus.export recent --bulk")
            self.stormIsInPrint("Pulled the recent export", msgs)
            assert len(fake.queries("urlhaus_export")) == pulls + 2

            # Full exports reuse their last pull until --repull.
            await core.nodes("slib.abusech.threatfox.export full --bulk")
            pulls = len(fake.queries("threatfox_export"))
            msgs = await core.stormlist("slib.abusech.threatfox.export full --bulk")
            self.stormIsInPrint("Using the full export pulled at", msgs)
            self.stormIsInPrint("Ingested", msgs)
            assert len(fake.queries("threatfox_export")) == pulls
            await core.nodes("slib.abusech.threatfox.export full --bulk --repull")
            assert len(fake.queries("threatfox_export")) == pulls + 1

            # A pull that's gone from the Axon must be pulled again.
            sets = await core.callStorm("return($lib.globals.get(slib:abusech:datasets))")
            await core.axon.del_(bytes.fromhex(sets["threatfox:full"]["sha256"]))
            msgs = await core.stormlist("slib.abusech.threatfox.export full --bulk")
            self.stormIsInWarn("is no longer in the Axon, rerun with --repull", msgs)

    async def test_options(self):
        async with abusechSvc(self) as (core, svc, fake):
            msgs = await core.stormlist("slib.abusech.bazaar.export recent --bulk --reuse")
            self.stormIsInWarn("There's no previous recent pull to reuse", msgs)
            msgs = await core.stormlist("slib.abusech.bazaar.export recent --bulk --reuse --repull")
            self.stormIsInErr("Use --reuse or --repull, not both", msgs)
            msgs = await core.stormlist("slib.abusech.bazaar.export recent --repull")
            self.stormIsInErr("--reuse and --repull are only used with --bulk", msgs)
            msgs = await core.stormlist("slib.abusech.bazaar.export yara --bulk")
            self.stormIsInErr("The yara export can't be bulk imported", msgs)

            # Failures are reported and the job is cleaned up.
            fake.overrides[("bazaar:export", "testkey/recent.csv")] = (500, "Internal error")
            msgs = await core.stormlist("slib.abusech.bazaar.export recent --bulk")
            self.stormIsInWarn("The bulk import failed", msgs)
            assert not svc.bulkjobs

    async def test_stale(self):
        async with abusechSvc(self) as (core, svc, fake):
            await core.nodes("slib.abusech.threatfox.export full --bulk")
            msgs = await core.stormlist("slib.abusech.threatfox.export full --bulk")
            self.stormNotInWarn("days old", msgs)

            # Reused full pulls more than a day old come with a warning.
            sets = await core.callStorm("return($lib.globals.get(slib:abusech:datasets))")
            sets["threatfox:full"]["time"] -= 3 * 86400000
            await core.callStorm(
                "$lib.globals.set(slib:abusech:datasets, $s)", opts={"vars": {"s": sets}}
            )
            msgs = await core.stormlist("slib.abusech.threatfox.export full --bulk")
            self.stormIsInWarn("That pull is 3 days old", msgs)
            self.stormIsInPrint("Ingested", msgs)

    async def test_perms(self):
        async with abusechSvc(self) as (core, svc, fake):
            user = await core.auth.addUser("analyst")
            opts = {"user": user.iden}
            await user.addRule((True, ("slib", "abusech", "user")))
            await user.addRule((True, ("node", "add")))
            await user.addRule((True, ("node", "prop", "set")))
            await user.addRule((True, ("node", "tag", "add")))
            await user.addRule((True, ("node", "edge", "add")))

            msgs = await core.stormlist("slib.abusech.urlhaus.export recent --bulk", opts=opts)
            self.stormIsInErr("permission", msgs)

            # The bulk perm is enough to pull and build, but ingesting needs the node perm on the layer.
            await user.addRule((True, ("slib", "abusech", "bulk")))
            msgs = await core.stormlist("slib.abusech.urlhaus.export recent --bulk", opts=opts)
            self.stormIsInWarn("The bulk import failed", msgs)
            assert not svc.bulkjobs

            await user.addRule((True, ("node",)))
            msgs = await core.stormlist(
                "slib.abusech.urlhaus.export recent --bulk --reuse", opts=opts
            )
            self.stormIsInPrint("Ingested 5 nodes", msgs)
            # The datasets global is written for the user, who can't otherwise set globals.
            msgs = await core.stormlist("$lib.globals.set(x, y)", opts=opts)
            self.stormIsInErr("permission", msgs)

            # The bulk module only exposes run(), which does every step itself.
            for name in ("setDataset", "stage", "bulk"):
                msgs = await core.stormlist(
                    f"$lib.import(slib.abusech.priv.bulk).{name}()", opts=opts
                )
                assert [m for m in msgs if m[0] == "err"], name
            msgs = await core.stormlist("$lib.import(slib.abusech.bulk)", opts=opts)
            self.stormIsInErr("slib.abusech.bulk", msgs)
