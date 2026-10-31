"""Pytests for the slib.capa Storm package (commands, modules, modeling, the rule import, perms)."""

import pathlib
import tomllib

import synapse.tests.utils as s_tests

from capasvc import __version__
from capasvc.defs import PKGDEFS, SVC_GUID, SVC_NAME
from capasvc.rules import ruleGuid, rulesetGuid

from .capatest import MATCHED, RULES_VERSION, SAMPLE_SHA256, capaSvc, putSample


FILE = f"file:bytes:sha256={SAMPLE_SHA256}"
SCAN = f"{FILE} | slib.capa.scan --format sc64"
TAGS = {
    "rep.capa.testing.slib_capa",
    "rep.capa.testing.ops.xor",
    "rep.capa.testing.ops.ret",
}
USER_PERM = ("slib", "capa", "user")
ADMIN_PERM = ("slib", "capa", "admin")


def leafTags(node) -> set[str]:
    tags = set(node.tags)
    return {t for t in tags if not any(o.startswith(t + ".") for o in tags)}


class TestCapaStormPkg(s_tests.SynTest):

    def test_versions_match(self):
        pyproject = pathlib.Path(__file__).parent.parent / "pyproject.toml"
        with pyproject.open("rb") as fd:
            assert tomllib.load(fd)["project"]["version"] == __version__
        assert PKGDEFS[0]["version"] == __version__

    async def test_pkg(self):
        async with capaSvc(self) as (core, svc, axon):
            msgs = await core.stormlist("service.list")
            self.stormIsInPrint(f"true (svc) ({SVC_NAME} @ {__version__})", msgs)

            for cmd in PKGDEFS[0]["commands"]:
                assert cmd["name"] in core.stormcmds
                # The "forms" key is deprecated and removed in Synapse 3.0.0, use "cmdinputs".
                assert "forms" not in cmd, cmd["name"]
                for cmdinput in cmd.get("cmdinputs", ()):
                    assert core.model.form(cmdinput["form"]) is not None, (cmd["name"], cmdinput)

            for mod in PKGDEFS[0]["modules"]:
                self.stormHasNoErr(await core.stormlist(f"$mod = $lib.import({mod['name']})"))

            assert len(await core.nodes(f"meta:source={SVC_GUID}")) == 1

            msgs = await core.stormlist("slib.capa.info")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("capa: 10.0.0", msgs)
            self.stormIsInPrint(
                f"rules: {RULES_VERSION} (6 rules, 1 library rules, 4 namespaces)", msgs
            )
            self.stormIsInPrint(f"rules sha256: {svc.capaRules.sha256}", msgs)
            self.stormIsInPrint("rules imported: true", msgs)
            self.stormIsInPrint("tags: enabled=true prefix=rep.capa", msgs)
            self.stormIsInPrint("tag docs imported: true", msgs)

            nodes = await core.nodes("slib.capa.info --yield")
            assert [n.ndef for n in nodes] == [("meta:ruleset", rulesetGuid(RULES_VERSION))]


class TestCapaStormSync(s_tests.SynTest):

    async def test_onload_import(self):
        async with capaSvc(self) as (core, svc, axon):
            rules = await core.nodes("meta:rule")
            assert len(rules) == 6
            assert {n.ndef[1] for n in rules} == {ruleGuid(n) for n in svc.capaRules.rules}

            sets = await core.nodes("meta:ruleset")
            assert len(sets) == 1
            rset = sets[0]
            assert rset.ndef[1] == rulesetGuid(RULES_VERSION)
            assert rset.get("name") == "capa-rules vtest"
            assert rset.get("type") == "capa."
            assert "capa 10.0.0" in rset.get("desc")
            data = await rset.getData("slib:capa")
            assert data["sha256"] == svc.capaRules.sha256 and data["rules"] == 6
            assert len(await core.nodes("meta:ruleset -(has)> meta:rule")) == 6

            rule = (await core.nodes(f"meta:rule={ruleGuid('contain slib-capa test marker')}"))[0]
            assert rule.get("name") == "contain slib-capa test marker"
            assert rule.get("type") == "capa."
            desc = rule.get("desc")
            assert desc.startswith("The file contains the slib.capa test marker string.")
            assert "MBC:\n- Anti-Static Analysis::Executable Code Obfuscation [B0032]" in desc
            assert rule.get("text").startswith("rule:\n  meta:\n")
            assert rule.get("url") == "https://example.com/rules/vtest/testing/contain-marker.yml"
            meta = await rule.getData("slib:capa")
            assert meta["namespace"] == "testing/slib-capa"
            assert meta["references"] == ("https://github.com/gormaniac/stormsvcs",)

            techs = await core.nodes(f"meta:rule={rule.ndef[1]} -(refs)> it:mitre:attack:technique")
            assert {n.ndef[1] for n in techs} == {"T1027", "T1059.001"}

            authors = await core.nodes(f"meta:rule={rule.ndef[1]} :author -> ps:contact")
            assert len(authors) == 1 and authors[0].get("email") == "test@example.com"

            lib = (await core.nodes(f"meta:rule={ruleGuid('contain ret')}"))[0]
            assert lib.get("type") == "capa.lib."
            assert "capa library rule" in lib.get("desc")

            nodes = await core.nodes(f"meta:source={SVC_GUID} -(seen)> meta:rule")
            assert len(nodes) == 6

            # Every namespace (and the namespaces above them) is a documented tag.
            tags = {n.ndef[1]: n for n in await core.nodes("syn:tag^=rep.capa")}
            assert set(tags) == {
                "rep.capa", "rep.capa.testing", "rep.capa.testing.never",
                "rep.capa.testing.ops", "rep.capa.testing.ops.ret", "rep.capa.testing.ops.xor",
                "rep.capa.testing.slib_capa",
            }
            assert tags["rep.capa"].get("title") == "capa"
            xor = tags["rep.capa.testing.ops.xor"]
            assert xor.get("title") == "capa: testing/ops/xor"
            assert xor.get("doc").endswith("Rules:\n- contain xor")

    async def test_sync(self):
        async with capaSvc(self) as (core, svc, axon):
            # Already imported, so nothing happens.
            msgs = await core.stormlist("slib.capa.admin.sync")
            self.stormHasNoWarnErr(msgs)
            self.stormNotInPrint("Importing", msgs)
            assert [n.ndef[0] for n in await core.nodes("slib.capa.admin.sync")] == ["meta:ruleset"]

            # Edits are restored with --force.
            guid = ruleGuid("contain xor")
            await core.nodes(f"meta:rule={guid} [ :desc=edited ]")
            await core.nodes("syn:tag=rep.capa.testing.ops.xor [ :doc=edited ]")
            msgs = await core.stormlist("slib.capa.admin.sync --force")
            self.stormIsInPrint("slib.capa: Imported 6 capa rules (vtest).", msgs)
            self.stormIsInPrint("slib.capa: Imported the docs of 7 rep.capa tags.", msgs)
            assert (await core.nodes(f"meta:rule={guid}"))[0].get("desc") != "edited"
            assert (await core.nodes("syn:tag=rep.capa.testing.ops.xor"))[0].get("doc") != "edited"

            # --reload has the service reload the rules from disk.
            msgs = await core.stormlist("slib.capa.admin.sync --reload")
            self.stormHasNoWarnErr(msgs)

            # A new version of the rules is imported into its own ruleset.
            svc.capaRules.version = "vtest2"
            svc.capaRules.sha256 = "00" * 32
            msgs = await core.stormlist("slib.capa.admin.sync")
            self.stormIsInPrint("Imported 6 capa rules (vtest2)", msgs)
            query = f"meta:ruleset={rulesetGuid('vtest2')} -(has)> meta:rule"
            assert len(await core.nodes(query)) == 6
            assert len(await core.nodes("meta:rule")) == 6

            # The onload runs whenever the package loads, it imports what changed.
            svc.capaRules.sha256 = "11" * 32
            msgs = await core.stormlist("$lib.import(slib.capa.sync).onload()")
            self.stormIsInPrint("Imported 6 capa rules (vtest2)", msgs)
            await core.nodes("$lib.globals.set('slib:capa:sync:tags', $lib.null)")
            msgs = await core.stormlist("$lib.import(slib.capa.sync).onload()")
            self.stormNotInPrint("Importing", msgs)
            self.stormIsInPrint("Imported the docs of 7 rep.capa tags.", msgs)

            # Already imported messages are printed with debug.
            msgs = await core.stormlist("slib.capa.admin.sync", opts={"debug": True})
            self.stormIsInPrint("The capa rules (vtest2) are already imported.", msgs)
            self.stormIsInPrint("The rep.capa tags are already imported.", msgs)

    async def test_sync_errors(self):
        async with capaSvc(self, conf={"capa:rules": None}) as (core, svc, axon):
            assert len(await core.nodes("meta:rule")) == 0

            msgs = await core.stormlist("slib.capa.admin.sync")
            self.stormIsInWarn("Getting the capa rules info failed: The slib.capa service has no "
                               "capa:rules directory configured.", msgs)
            assert len(await core.nodes("slib.capa.admin.sync")) == 0

            msgs = await core.stormlist("slib.capa.admin.sync --reload")
            self.stormIsInWarn("Reloading the capa rules failed", msgs)

            msgs = await core.stormlist("slib.capa.info --yield")
            self.stormIsInWarn("Getting the capa rules info failed", msgs)
            assert not [m for m in msgs if m[0] == "node"]

            msgs = await core.stormlist("slib.capa.admin.tags --prefix my.capa")
            self.stormIsInWarn("Getting the capa rules info failed", msgs)
            self.stormIsInPrint("slib.capa tags: enabled=true prefix=my.capa", msgs)

            # Generator errors are reported.
            msgs = await core.stormlist(
                "$util = $lib.import(slib.capa.util) $priv = $lib.import(slib.capa.priv.user) "
                "for $retn in $priv.rules() { $util.failed($retn, test) }"
            )
            self.stormIsInWarn("slib.capa: test failed: The slib.capa service has no", msgs)


class TestCapaStormScan(s_tests.SynTest):

    async def test_scan(self):
        async with capaSvc(self) as (core, svc, axon):
            await putSample(core, axon)

            msgs = await core.stormlist(SCAN)
            self.stormHasNoWarnErr(msgs)
            nodes = [m[1] for m in msgs if m[0] == "node"]
            assert [n[0] for n in nodes] == [("file:bytes", f"sha256:{SAMPLE_SHA256}")]

            file = (await core.nodes(FILE))[0]
            assert leafTags(file) == TAGS

            matched = await core.nodes(f"{FILE} <(matches)- meta:rule")
            assert sorted(n.get("name") for n in matched) == MATCHED
            assert len(await core.nodes(f"meta:source={SVC_GUID} -(seen)> file:bytes")) == 1

            data = await file.getData("slib:capa")
            assert data["capa"] == "10.0.0"
            assert data["rules"] == {"version": RULES_VERSION, "sha256": svc.capaRules.sha256}
            assert (data["format"], data["arch"], data["flavor"]) == ("sc64", "amd64", "static")
            assert [m["rule"] for m in data["matches"]] == MATCHED
            xor = [m for m in data["matches"] if m["rule"] == "contain xor"][0]
            assert xor == {
                "rule": "contain xor", "guid": ruleGuid("contain xor"),
                "namespace": "testing/ops/xor", "count": 1, "addrs": ("0x690000",),
            }

            # Scanning again is skipped.
            msgs = await core.stormlist(SCAN)
            self.stormIsInPrint("already scanned with these rules", msgs)
            assert len([m for m in msgs if m[0] == "node"]) == 1

            # Unless forced, --yield yields the matched rules.
            nodes = await core.nodes(SCAN + " --force --yield")
            assert sorted(n.get("name") for n in nodes) == MATCHED
            assert all(n.ndef[0] == "meta:rule" for n in nodes)

            # Rules from a scan are modeled even if they weren't imported.
            await core.nodes("meta:rule | delnode --force")
            await core.nodes(SCAN + " --force")
            assert len(await core.nodes("meta:rule")) == 4

            # The module API.
            msgs = await core.stormlist(
                f"{FILE} $capa = $lib.import(slib.capa.lib) "
                "$lib.print($capa.scanned($node)) "
                "for $r in $capa.scan($node, fmt=sc64, force=(true)) { $lib.print($r.props.name) }"
            )
            self.stormIsInPrint("true", msgs)
            self.stormIsInPrint("contain xor", msgs)

    async def test_scan_tags(self):
        async with capaSvc(self) as (core, svc, axon):
            await putSample(core, axon)

            msgs = await core.stormlist("slib.capa.admin.tags --prefix My.Capa")
            self.stormIsInPrint("slib.capa: Imported the docs of 7 my.capa tags.", msgs)
            self.stormIsInPrint("slib.capa tags: enabled=true prefix=my.capa", msgs)
            assert len(await core.nodes("syn:tag^=my.capa +:doc")) == 7

            await core.nodes(SCAN)
            file = (await core.nodes(FILE))[0]
            assert leafTags(file) == {t.replace("rep.capa", "my.capa") for t in TAGS}

            await core.nodes(f"{FILE} [ -#my ]")
            msgs = await core.stormlist("slib.capa.admin.tags --disable")
            self.stormIsInPrint("enabled=false prefix=my.capa", msgs)
            await core.nodes(SCAN + " --force")
            assert not (await core.nodes(FILE))[0].tags
            assert len(await core.nodes(f"{FILE} <(matches)- meta:rule")) == 4

            msgs = await core.stormlist("slib.capa.admin.tags --enable")
            self.stormIsInPrint("enabled=true prefix=my.capa", msgs)

            msgs = await core.stormlist("slib.capa.admin.tags --enable --disable")
            self.stormIsInErr("Use --enable or --disable, not both.", msgs)

    async def test_scan_errors(self):
        async with capaSvc(self) as (core, svc, axon):
            # Not a file:bytes.
            msgs = await core.stormlist("[ test:str=a ] | slib.capa.scan")
            self.stormIsInWarn("Only file:bytes nodes can be scanned, skipping test:str=a.", msgs)
            assert [m[1][0] for m in msgs if m[0] == "node"] == [("test:str", "a")]
            assert not await core.nodes("[ test:str=a ] | slib.capa.scan --yield")

            # No :sha256.
            msgs = await core.stormlist("[ file:bytes=* ] | slib.capa.scan")
            self.stormIsInWarn("it has no :sha256", msgs)

            # Not in the Axon.
            msgs = await core.stormlist(f"[ file:bytes=sha256:{SAMPLE_SHA256} ] | slib.capa.scan")
            self.stormIsInWarn(f"Scanning {SAMPLE_SHA256} failed: The file {SAMPLE_SHA256} is not "
                               "in the Axon.", msgs)
            assert [m[0] for m in msgs].count("node") == 1

            # Not a format capa supports.
            sha256 = await putSample(core, axon, b"hello world")
            msgs = await core.stormlist(f"file:bytes:sha256={sha256} | slib.capa.scan")
            self.stormIsInWarn("The file is not a format capa supports", msgs)
            node = (await core.nodes(f"file:bytes:sha256={sha256}"))[0]
            assert await node.getData("slib:capa") is None

    async def test_scan_no_rules(self):
        async with capaSvc(self, conf={"capa:rules": None}) as (core, svc, axon):
            await putSample(core, axon)
            msgs = await core.stormlist(SCAN)
            self.stormIsInWarn("Getting the capa rules info failed", msgs)
            self.stormIsInWarn(f"Scanning {SAMPLE_SHA256} failed: The slib.capa service has no "
                               "capa:rules directory configured.", msgs)

            query = f"{FILE} $lib.print($lib.import(slib.capa.lib).scanned($node))"
            msgs = await core.stormlist(query)
            self.stormIsInPrint("false", msgs)

    async def test_perms(self):
        async with capaSvc(self) as (core, svc, axon):
            await putSample(core, axon)

            user = await core.auth.addUser("visi")
            opts = {"user": user.iden}

            msgs = await core.stormlist(SCAN, opts=opts)
            self.stormIsInErr("slib.capa.user", msgs)
            msgs = await core.stormlist("slib.capa.info", opts=opts)
            self.stormIsInErr("slib.capa.user", msgs)

            await user.addRule((True, USER_PERM))
            await user.addRule((True, ("node",)))
            msgs = await core.stormlist(SCAN, opts=opts)
            self.stormHasNoWarnErr(msgs)
            assert leafTags((await core.nodes(FILE))[0]) == TAGS
            self.stormHasNoWarnErr(await core.stormlist("slib.capa.info", opts=opts))

            # Admin commands need the admin perm.
            for query in ("slib.capa.admin.sync", "slib.capa.admin.tags --disable"):
                msgs = await core.stormlist(query, opts=opts)
                self.stormIsInErr("slib.capa.admin", msgs)

            await user.addRule((True, ADMIN_PERM))
            msgs = await core.stormlist("slib.capa.admin.sync --force", opts=opts)
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("Imported 6 capa rules", msgs)
