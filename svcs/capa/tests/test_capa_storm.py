"""Pytests for the slib.capa Storm package (commands, modules, modeling, the rule import, perms)."""

import pathlib
import subprocess
import sys
from unittest import mock

import synapse.lib.stormtypes as s_stormtypes
import synapse.tests.utils as s_tests
from stormlibpp.testing import assertMainHelp, assertVersionsMatch

from capasvc import __version__
from capasvc.api import CapaSvcError
from capasvc.defs import PKGDEFS, SVC_GUID, SVC_NAME
from capasvc.rules import ruleGuid, rulesetGuid

from .capatest import MATCHED, RULES_VERSION, SAMPLE_SHA256, capaSvc, putSample
from .test_custom import MARKER, customRule


FILE = f"file:bytes:sha256={SAMPLE_SHA256}"
SCAN = f"{FILE} | slib.capa.scan --format sc64"
TAGS = {
    "rep.capa.testing.slib_capa",
    "rep.capa.testing.ops.xor",
    "rep.capa.testing.ops.ret",
}
SVCDIR = pathlib.Path(__file__).parents[1]
USER_PERM = ("slib", "capa", "user")
ADMIN_PERM = ("slib", "capa", "admin")


def leafTags(node) -> set[str]:
    tags = set(node.tags)
    return {t for t in tags if not any(o.startswith(t + ".") for o in tags)}


class TestCapaStormPkg(s_tests.SynTest):
    def test_versions_match(self):
        # The version lives in pyproject.toml (the image tag), __init__.py, the package yaml,
        # and the service's uv.lock entry.
        assert assertVersionsMatch(SVCDIR) == __version__

    def test_main_help(self):
        assertMainHelp("capasvc")

    def test_readmes_match(self):
        # The package's README (shown in the Cortex) is a copy of the service's README.
        pkgreadme = SVCDIR / "src" / "capasvc" / "pkgproto" / "README.md"
        assert pkgreadme.read_text() == (SVCDIR / "README.md").read_text(), (
            "Copy README.md to src/capasvc/pkgproto/README.md"
        )

    def test_readme_commands(self):
        # The README documents every command.
        readme = (SVCDIR / "README.md").read_text()
        for cmd in PKGDEFS[0]["commands"]:
            assert f"`{cmd['name']}" in readme, cmd["name"]

    def test_storm_lint(self):
        # The package's Storm passes Synapse's Storm linter (CI runs it too, see storm_lint).
        proc = subprocess.run(
            [sys.executable, "-m", "synapse.tools.storm.lint", str(SVCDIR / "src")],
            capture_output=True,
            text=True,
            cwd=SVCDIR,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr

    async def test_api_unexpected_error(self):
        # An error that isn't a CapaSvcError or CapaRulesError reaches Storm as status=False,
        # not as a raw exception.
        async with capaSvc(self) as (core, svc, axon):

            async def boom(*args, **kwargs):
                raise RuntimeError("boom")

            async def boomgenr(*args, **kwargs):
                raise RuntimeError("boom")
                yield  # pragma: no cover

            svc.rulesInfo = boom
            svc.rules = boomgenr
            unexpected = {
                "status": False,
                "mesg": "Unexpected error: RuntimeError: boom",
                "data": None,
            }
            async with svc.getLocalProxy() as prox:
                with self.getLoggerStream("stormlibpp.svc") as stream:
                    self.eq(unexpected, await prox.rulesInfo())
                stream.seek(0)
                self.isin("Unexpected error in CapaCellApi.rulesInfo.", stream.read())

                self.eq([unexpected], [r async for r in prox.rules()])

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
                "rep.capa",
                "rep.capa.testing",
                "rep.capa.testing.never",
                "rep.capa.testing.ops",
                "rep.capa.testing.ops.ret",
                "rep.capa.testing.ops.xor",
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

            # A new version of the rules is imported into its own ruleset, even with the
            # same rule files.
            svc.capaRules.version = "vtest2"
            msgs = await core.stormlist("slib.capa.admin.sync")
            self.stormIsInPrint("Imported 6 capa rules (vtest2)", msgs)
            query = f"meta:ruleset={rulesetGuid('vtest2')} -(has)> meta:rule"
            assert len(await core.nodes(query)) == 6
            assert len(await core.nodes("meta:rule")) == 6

            # The onload runs whenever the package loads, it imports what changed.
            svc.capaRules.urlfmt = "https://example.com/{path}"
            msgs = await core.stormlist("$lib.import(slib.capa.sync).onload()")
            self.stormIsInPrint("Imported 6 capa rules (vtest2)", msgs)
            await core.nodes("$lib.globals.set('slib:capa:sync:tags', $lib.null)")
            msgs = await core.stormlist("$lib.import(slib.capa.sync).onload()")
            self.stormNotInPrint("Importing", msgs)
            self.stormIsInPrint("Imported the docs of 7 rep.capa tags.", msgs)

            # A skipped import doesn't edit the ruleset, it's only lifted.
            await core.nodes(f"meta:ruleset={rulesetGuid('vtest2')} [ :desc=edited ]")
            await core.nodes("slib.capa.admin.sync")
            node = (await core.nodes(f"meta:ruleset={rulesetGuid('vtest2')}"))[0]
            assert node.get("desc") == "edited"

            # Already imported messages are printed with debug.
            msgs = await core.stormlist("slib.capa.admin.sync", opts={"debug": True})
            self.stormIsInPrint("The capa rules (vtest2) are already imported.", msgs)
            self.stormIsInPrint("The rep.capa tags are already imported.", msgs)

            # A missing ruleset is imported again.
            await core.nodes(f"meta:ruleset={rulesetGuid('vtest2')} | delnode --force")
            msgs = await core.stormlist("slib.capa.admin.sync")
            self.stormIsInPrint("Imported 6 capa rules (vtest2)", msgs)
            assert len(await core.nodes(f"meta:ruleset={rulesetGuid('vtest2')} -(has)> *")) == 6

    async def test_sync_errors(self):
        async with capaSvc(self, conf={"capa:rules": None}) as (core, svc, axon):
            assert len(await core.nodes("meta:rule")) == 0

            msgs = await core.stormlist("slib.capa.admin.sync")
            self.stormIsInWarn(
                "Getting the capa rules info failed: The slib.capa service has no "
                "capa:rules directory configured.",
                msgs,
            )
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
            assert data["rules"] == {
                "version": RULES_VERSION,
                "sha256": svc.capaRules.sha256,
                "custom": None,
            }
            assert (data["format"], data["arch"], data["flavor"]) == ("sc64", "amd64", "static")
            assert [m["rule"] for m in data["matches"]] == MATCHED
            xor = [m for m in data["matches"] if m["rule"] == "contain xor"][0]
            assert xor == {
                "rule": "contain xor",
                "guid": ruleGuid("contain xor"),
                "namespace": "testing/ops/xor",
                "count": 1,
                "addrs": ("0x690000",),
            }

            # Scanning again is skipped.
            msgs = await core.stormlist(SCAN)
            self.stormIsInPrint("already scanned with these rules", msgs)
            assert len([m for m in msgs if m[0] == "node"]) == 1

            # Unless forced, --yield yields the matched rules.
            nodes = await core.nodes(SCAN + " --force --yield")
            assert sorted(n.get("name") for n in nodes) == MATCHED
            assert all(n.ndef[0] == "meta:rule" for n in nodes)

            # Scans link the imported rules, they don't rebuild them.
            guid = ruleGuid("contain xor")
            await core.nodes(f"meta:rule={guid} [ :desc=edited ]")
            await core.nodes(SCAN + " --force")
            assert (await core.nodes(f"meta:rule={guid}"))[0].get("desc") == "edited"

            # Rules from a scan are modeled if they weren't imported.
            await core.nodes("meta:rule | delnode --force")
            await core.nodes(SCAN + " --force")
            assert len(await core.nodes("meta:rule")) == 4
            node = (await core.nodes(f"meta:rule={guid}"))[0]
            assert node.get("desc") == svc.capaRules.rules["contain xor"]["desc"]

            # A scan removes the results of an earlier scan: capa match edges and the tags it
            # applied. Other rules and tags are left alone, even under the prefix.
            await core.nodes(
                f"{FILE} [ +#rep.capa.mine +#other.tag "
                "<(matches)+ { [ meta:rule=* :type=capa :name=stale ] } "
                "<(matches)+ { [ meta:rule=* :type=yara :name=other ] } ]"
            )
            await core.nodes(SCAN + " --force")
            file = (await core.nodes(FILE))[0]
            assert leafTags(file) == TAGS | {"other.tag", "rep.capa.mine"}
            data = await file.getData("slib:capa")
            assert data["prefix"] == "rep.capa" and set(data["tags"]) == TAGS
            names = {n.get("name") for n in await core.nodes(f"{FILE} <(matches)- meta:rule")}
            assert names == set(MATCHED) | {"other"}

            # The module API.
            msgs = await core.stormlist(
                f"{FILE} $capa = $lib.import(slib.capa.lib) "
                "$lib.print(`sc64={$capa.scanned($node, fmt=sc64)}`) "
                "$lib.print(`auto={$capa.scanned($node)}`) "
                "for $r in $capa.scan($node, fmt=sc64, force=(true)) { $lib.print($r.props.name) }"
            )
            self.stormIsInPrint("sc64=true", msgs)
            self.stormIsInPrint("auto=false", msgs)
            self.stormIsInPrint("contain xor", msgs)

            # A different --format or --os is scanned again, without --force.
            file = (await core.nodes(FILE))[0]
            assert (await file.getData("slib:capa"))["options"] == {"format": "sc64", "os": "auto"}
            msgs = await core.stormlist(SCAN)
            self.stormIsInPrint("already scanned", msgs)
            msgs = await core.stormlist(SCAN + " --os windows")
            self.stormNotInPrint("already scanned", msgs)
            file = (await core.nodes(FILE))[0]
            data = await file.getData("slib:capa")
            assert data["options"] == {"format": "sc64", "os": "windows"}

            # Results from before the options were saved count as the defaults.
            data = dict(data)
            data.pop("options")
            await file.setData("slib:capa", data)
            query = f"{FILE} $lib.print($lib.import(slib.capa.lib).scanned($node))"
            msgs = await core.stormlist(query)
            self.stormIsInPrint("true", msgs)

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

            # With tagging disabled, a re-scan still removes the tags the last scan applied.
            msgs = await core.stormlist("slib.capa.admin.tags --disable")
            self.stormIsInPrint("enabled=false prefix=my.capa", msgs)
            await core.nodes(SCAN + " --force")
            assert not (await core.nodes(FILE))[0].tags
            assert len(await core.nodes(f"{FILE} <(matches)- meta:rule")) == 4

            msgs = await core.stormlist("slib.capa.admin.tags --enable")
            self.stormIsInPrint("enabled=true prefix=my.capa", msgs)

            # A new prefix: the re-scan removes the tags under the old one.
            await core.nodes(SCAN + " --force")
            await core.nodes("slib.capa.admin.tags --prefix rep.capa")
            await core.nodes(SCAN + " --force")
            file = (await core.nodes(FILE))[0]
            assert leafTags(file) == TAGS
            assert not [t for t in file.tags if t.startswith("my")]

            msgs = await core.stormlist("slib.capa.admin.tags --enable --disable")
            self.stormIsInErr("Use --enable or --disable, not both.", msgs)

    async def test_scan_shared_prefix(self):
        # A prefix shared with other tags (ex. "rep"), only the tags capa applied are removed.
        async with capaSvc(self) as (core, svc, axon):
            await putSample(core, axon)
            await core.nodes("slib.capa.admin.tags --prefix rep")
            await core.nodes(f"{FILE} [ +#rep.vt.malicious +#rep.testing.mine ]")

            await core.nodes(SCAN)
            capatags = {t.replace("rep.capa", "rep") for t in TAGS}
            assert leafTags((await core.nodes(FILE))[0]) == capatags | {
                "rep.vt.malicious",
                "rep.testing.mine",
            }

            # The next scan matches fewer rules: their tags, and the parents left empty, go.
            runCapa = svc._runCapa

            async def onlyXor(*args):
                doc = await runCapa(*args)
                doc["rules"] = {k: v for k, v in doc["rules"].items() if k == "contain xor"}
                return doc

            svc._runCapa = onlyXor
            await core.nodes(SCAN + " --force")
            file = (await core.nodes(FILE))[0]
            assert leafTags(file) == {"rep.testing.ops.xor", "rep.vt.malicious", "rep.testing.mine"}
            assert "rep.testing.slib_capa" not in file.tags

            # Nothing matches: every capa tag goes, the shared ones stay.
            async def nothing(*args):
                doc = await runCapa(*args)
                doc["rules"] = {}
                return doc

            svc._runCapa = nothing
            await core.nodes(SCAN + " --force")
            file = (await core.nodes(FILE))[0]
            assert set(file.tags) == {
                "rep",
                "rep.vt",
                "rep.vt.malicious",
                "rep.testing",
                "rep.testing.mine",
            }

            # With only capa tags, the prefix and its parents are removed too.
            await core.nodes(f"{FILE} [ -#rep ]")
            svc._runCapa = runCapa
            await core.nodes("slib.capa.admin.tags --prefix rep.capa")
            await core.nodes(SCAN + " --force")
            svc._runCapa = nothing
            await core.nodes(SCAN + " --force")
            assert not (await core.nodes(FILE))[0].tags

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
            self.stormIsInWarn(
                f"Scanning {SAMPLE_SHA256} failed: The file {SAMPLE_SHA256} is not in the Axon.",
                msgs,
            )
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
            sha256 = await putSample(core, axon, b"another file")
            msgs = await core.stormlist(
                f"file:bytes:sha256*in=({SAMPLE_SHA256}, {sha256}) | slib.capa.scan --format sc64"
            )
            warns = [m[1]["mesg"] for m in msgs if m[0] == "warn"]
            # One warning for the rules info, and one per file for the scan.
            assert len([w for w in warns if "Getting the capa rules info failed" in w]) == 1
            assert len([w for w in warns if "no capa:rules directory configured" in w]) == 3
            self.stormIsInWarn(
                f"Scanning {SAMPLE_SHA256} failed: The slib.capa service has no "
                "capa:rules directory configured.",
                msgs,
            )

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


class TestCapaStormCustom(s_tests.SynTest):
    async def addCustom(self, core, text, type="capa.custom"):
        """Make a custom rule meta:rule, returns its guid."""

        opts = {"vars": {"text": text, "type": type}}
        nodes = await core.nodes("[ meta:rule=* :name=mine :type=$type :text=$text ]", opts=opts)
        return nodes[0].ndef[1]

    async def test_custom(self):
        async with capaSvc(self) as (core, svc, axon):
            await putSample(core, axon)
            guid = await self.addCustom(core, MARKER)

            msgs = await core.stormlist("slib.capa.info")
            self.stormIsInPrint("custom rules: 1 (0 skipped)", msgs)
            self.stormIsInPrint(f"custom marker rule (meta:rule={guid})", msgs)

            msgs = await core.stormlist(SCAN)
            self.stormHasNoWarnErr(msgs)
            file = (await core.nodes(FILE))[0]
            assert leafTags(file) == TAGS | {"rep.capa.custom.marker"}
            names = {n.ndef[1] for n in await core.nodes(f"{FILE} <(matches)- meta:rule")}
            assert guid in names and len(names) == 5
            data = await file.getData("slib:capa")
            assert data["rules"]["custom"]
            assert {
                "rule": "custom marker rule",
                "guid": guid,
                "namespace": "custom/marker",
                "count": 1,
                "addrs": (),
            } in data["matches"]

            # The custom rule node is the user's, scans and syncs don't edit it.
            node = (await core.nodes(f"meta:rule={guid}"))[0]
            assert node.get("name") == "mine" and node.get("desc") is None
            await core.nodes("slib.capa.admin.sync --force")
            node = (await core.nodes(f"meta:rule={guid}"))[0]
            assert node.get("name") == "mine" and node.get("text") == MARKER

            # Scanning again with the same custom rules is skipped.
            msgs = await core.stormlist(SCAN)
            self.stormIsInPrint("already scanned with these rules", msgs)

            # An edited custom rule is used by the next scan, which re-scans the file.
            opts = {"vars": {"text": customRule("custom marker rule", "string: newp")}}
            await core.nodes(f"meta:rule={guid} [ :text=$text ]", opts=opts)
            msgs = await core.stormlist(SCAN)
            self.stormNotInPrint("already scanned", msgs)
            file = (await core.nodes(FILE))[0]
            assert leafTags(file) == TAGS
            assert len(await core.nodes(f"{FILE} <(matches)- meta:rule")) == 4

            # So is a new custom rule type below capa.custom, and a deleted rule is dropped.
            other = await self.addCustom(core, customRule("team rule"), type="capa.custom.team")
            await core.nodes(f"meta:rule={guid} | delnode")
            await core.nodes(SCAN)
            names = {n.ndef[1] for n in await core.nodes(f"{FILE} <(matches)- meta:rule")}
            assert other in names and guid not in names

            # Without custom rules, the next scan re-scans with only the official rules.
            await core.nodes(f"meta:rule={other} | delnode --force")
            msgs = await core.stormlist(SCAN)
            self.stormNotInPrint("already scanned", msgs)
            assert leafTags((await core.nodes(FILE))[0]) == TAGS
            msgs = await core.stormlist("slib.capa.info")
            self.stormIsInPrint("custom rules: 0", msgs)

    async def test_custom_skipped(self):
        async with capaSvc(self) as (core, svc, axon):
            await putSample(core, axon)

            # An official rule with the same name wins, the custom rule node stays.
            shadowed = await self.addCustom(core, customRule("contain xor"))
            invalid = await self.addCustom(core, "rule:\n  meta:\n    name: bad\n")
            await core.nodes("[ meta:rule=* :type=capa.custom :name=notext ]")
            await core.nodes("[ meta:rule=* :type=yara :text=newp ]")

            msgs = await core.stormlist(SCAN)
            self.stormIsInWarn(
                f"Skipping the custom capa rule meta:rule={shadowed}, an official "
                "capa rule has the same name: contain xor",
                msgs,
            )
            self.stormIsInWarn(
                f"Skipping the custom capa rule meta:rule={invalid}: Invalid capa rule", msgs
            )
            assert len([m for m in msgs if m[0] == "warn"]) == 2
            # The scan still works, with only the official rules.
            file = (await core.nodes(FILE))[0]
            assert leafTags(file) == TAGS
            assert (await file.getData("slib:capa"))["rules"]["custom"] is None
            assert len(await core.nodes(f"meta:rule={shadowed}")) == 1

            msgs = await core.stormlist("slib.capa.info")
            self.stormIsInPrint("custom rules: 0 (2 skipped)", msgs)

            # A custom rule capa can't load with the official rules fails the scans.
            await core.nodes(f"meta:rule={shadowed} | delnode")
            await core.nodes(f"meta:rule={invalid} | delnode")
            await self.addCustom(core, customRule("needs", "match: newp rule"))
            msgs = await core.stormlist(SCAN + " --force")
            self.stormIsInWarn("capa can't use the custom rules", msgs)

    async def test_custom_module_once(self):
        # The module's scan() sends the view's custom rules once per runtime, not per file.
        async with capaSvc(self) as (core, svc, axon):
            await putSample(core, axon)
            await putSample(core, axon, b"another file")
            await self.addCustom(core, MARKER)

            custom = svc.custom
            calls = []

            async def counted(rules):
                calls.append(rules)
                return await custom(rules)

            svc.custom = counted
            msgs = await core.stormlist(
                "$capa = $lib.import(slib.capa.lib) "
                "file:bytes for $r in $capa.scan($node, fmt=sc64) { $lib.print($r.props.name) }"
            )
            self.stormIsInPrint("mine", msgs)  # The custom rule node's own :name.
            assert len(calls) == 1

    async def test_custom_perms(self):
        async with capaSvc(self) as (core, svc, axon):
            await putSample(core, axon)
            guid = await self.addCustom(core, MARKER)

            user = await core.auth.addUser("visi")
            await user.addRule((True, USER_PERM))
            await user.addRule((True, ("node",)))
            msgs = await core.stormlist(SCAN, opts={"user": user.iden})
            self.stormHasNoWarnErr(msgs)
            names = {n.ndef[1] for n in await core.nodes(f"{FILE} <(matches)- meta:rule")}
            assert guid in names


class TestCapaStormModel(s_tests.SynTest):
    async def test_mbc(self):
        # MBC behaviors and methods are ou:technique nodes the rules -(refs)>.
        async with capaSvc(self) as (core, svc, axon):
            guid = ruleGuid("contain slib-capa test marker")
            techs = await core.nodes(f"meta:rule={guid} -(refs)> ou:technique")
            byid = {n.get("ext:id"): n for n in techs}
            assert set(byid) == {"B0032", "B0001.025"}
            assert all(n.get("reporter:name") == "mbc" for n in techs)
            assert byid["B0032"].get("name") == "executable code obfuscation"
            assert byid["B0032"].get("parent") is None
            assert byid["B0001.025"].get("name") == "software breakpoints"

            parent = await core.nodes(f"ou:technique={byid['B0001.025'].ndef[1]} :parent -> *")
            assert len(parent) == 1
            assert parent[0].get("ext:id") == "B0001"
            assert parent[0].get("name") == "debugger detection"
            assert len(await core.nodes("ou:technique")) == 3
            assert len(await core.nodes(f"meta:source={SVC_GUID} -(seen)> ou:technique")) == 3

            # A re-import reuses the nodes, and keeps a :name another source set.
            await core.nodes("ou:technique:ext:id=B0032 [ :name='my name' ]")
            await core.nodes("slib.capa.admin.sync --force")
            assert len(await core.nodes("ou:technique")) == 3
            node = (await core.nodes("ou:technique:ext:id=B0032"))[0]
            assert node.get("name") == "my name"

    async def test_mbc_existing(self):
        async with capaSvc(self, onload=False) as (core, svc, axon):
            await core.nodes("[ ou:technique=* :ext:id=B0032 :reporter:name=mbc :name=theirs ]")
            await core.nodes("slib.capa.admin.sync --force")
            nodes = await core.nodes("ou:technique:ext:id=B0032")
            assert len(nodes) == 1 and nodes[0].get("name") == "theirs"
            guid = ruleGuid("contain slib-capa test marker")
            refs = await core.nodes(f"meta:rule={guid} -(refs)> ou:technique:ext:id=B0032")
            assert [n.ndef for n in refs] == [nodes[0].ndef]

    async def test_refs_follow_mappings(self):
        # A rule's ATT&CK and MBC edges follow its current mappings when it's modeled again
        # (ex. a rules update), and its other -(refs)> edges are left alone.
        async with capaSvc(self) as (core, svc, axon):
            q = """
                $model = $lib.import(slib.capa.model)
                $r = ({
                    "guid": $guid, "name": "remapped", "type": "capa", "techniques": $tids,
                    "mbc": $mbc, "meta": ({}), "authors": ([]),
                })
                yield $model.rule($r)
            """
            guid = "c" * 32
            first = {
                "guid": guid,
                "tids": ["T1027", "T1497"],
                "mbc": [
                    {"id": "B0032", "name": "obfuscation", "parent": None},
                    {"id": "B0009", "name": "virtual machine detection", "parent": None},
                ],
            }
            await core.nodes(q, opts={"vars": first})
            await core.nodes(f"meta:rule={guid} [ +(refs)> {{ [ inet:fqdn=example.com ] }} ]")
            # Another source's ou:technique the rule refs isn't one of its MBC mappings.
            await core.nodes(
                f"meta:rule={guid} [ +(refs)> {{ [ ou:technique=* :ext:id=B0009 :reporter:name=x ] }} ]"
            )

            second = {
                "guid": guid,
                "tids": ["T1027"],
                "mbc": [{"id": "B0032", "name": "obfuscation", "parent": None}],
            }
            await core.nodes(q, opts={"vars": second})

            tids = {n.ndef[1] for n in await core.nodes(f"meta:rule={guid} -(refs)> it:mitre:attack:technique")}
            assert tids == {"T1027"}
            techs = await core.nodes(f"meta:rule={guid} -(refs)> ou:technique")
            assert {(n.get("reporter:name"), n.get("ext:id")) for n in techs} == {
                ("mbc", "B0032"),
                ("x", "B0009"),
            }
            assert len(await core.nodes(f"meta:rule={guid} -(refs)> inet:fqdn")) == 1
            # The nodes themselves are kept.
            assert len(await core.nodes("ou:technique:ext:id=B0009")) == 2
            assert len(await core.nodes("it:mitre:attack:technique=T1497")) == 1

    async def test_contacts(self):
        async with capaSvc(self) as (core, svc, axon):
            # An email author is the contact's :email, as before.
            guid = ruleGuid("contain slib-capa test marker")
            authors = await core.nodes(f"meta:rule={guid} :author -> ps:contact")
            assert len(authors) == 1 and authors[0].get("email") == "test@example.com"
            assert authors[0].get("user") is None and authors[0].get("name") is None

            # A handle is the contact's :user, a name its :name.
            q = """
                $model = $lib.import(slib.capa.model)
                $r = ({
                    "guid": $guid, "name": "handles", "type": "capa", "techniques": ([]),
                    "mbc": ([]), "meta": ({}), "authors": ([$author]),
                })
                yield $model.rule($r)
                :author -> ps:contact
            """
            nodes = await core.nodes(
                q, opts={"vars": {"guid": "a" * 32, "author": {"user": "visi"}}}
            )
            assert len(nodes) == 1
            assert nodes[0].get("user") == "visi" and nodes[0].get("name") is None
            nodes = await core.nodes(
                q, opts={"vars": {"guid": "b" * 32, "author": {"name": "jane doe"}}}
            )
            assert nodes[0].get("name") == "jane doe" and nodes[0].get("user") is None


class TestCapaStormFixes(s_tests.SynTest):
    async def test_unmatch_other_taxonomies(self):
        # A rescan only removes the edges of capa rules (capa, capa.*), not of other rule types
        # that start with "capa" (ex. capability).
        async with capaSvc(self) as (core, svc, axon):
            await putSample(core, axon)
            await core.nodes(
                f"{FILE} [ <(matches)+ {{ [ meta:rule=* :type=capability.x :name=other ] }} "
                "<(matches)+ { [ meta:rule=* :type=capa.custom.old :name=stale ] } ]"
            )
            await core.nodes(SCAN)
            names = {n.get("name") for n in await core.nodes(f"{FILE} <(matches)- meta:rule")}
            assert names == set(MATCHED) | {"other"}

    async def test_custom_type_prefix(self):
        # Only capa.custom (and the types below it) are custom rules, not capa.customer.
        async with capaSvc(self) as (core, svc, axon):
            opts = {"vars": {"text": MARKER}}
            await core.nodes(
                "[ meta:rule=* :name=mine :type=capa.customer :text=$text ]", opts=opts
            )
            msgs = await core.stormlist("slib.capa.info")
            self.stormIsInPrint("custom rules: 0", msgs)

    async def test_rescan_on_tag_change(self):
        # A file scanned with other tag settings is scanned again without --force.
        async with capaSvc(self) as (core, svc, axon):
            await putSample(core, axon)
            await core.nodes(SCAN)
            msgs = await core.stormlist(SCAN)
            self.stormIsInPrint("already scanned", msgs)

            await core.nodes("slib.capa.admin.tags --prefix my.capa")
            msgs = await core.stormlist(SCAN)
            self.stormNotInPrint("already scanned", msgs)
            file = (await core.nodes(FILE))[0]
            assert leafTags(file) == {t.replace("rep.capa", "my.capa") for t in TAGS}
            msgs = await core.stormlist(SCAN)
            self.stormIsInPrint("already scanned", msgs)

            # Turning tagging off (and on) is a change too.
            await core.nodes("slib.capa.admin.tags --disable")
            msgs = await core.stormlist(SCAN)
            self.stormNotInPrint("already scanned", msgs)
            assert not (await core.nodes(FILE))[0].tags
            msgs = await core.stormlist(SCAN)
            self.stormIsInPrint("already scanned", msgs)

            await core.nodes("slib.capa.admin.tags --enable")
            msgs = await core.stormlist(SCAN)
            self.stormNotInPrint("already scanned", msgs)
            assert leafTags((await core.nodes(FILE))[0]) == {
                t.replace("rep.capa", "my.capa") for t in TAGS
            }

    async def test_tags_prefix_invalid(self):
        async with capaSvc(self) as (core, svc, axon):
            for prefix in ("", "a b", "my..capa", "#nope"):
                msgs = await core.stormlist(
                    "slib.capa.admin.tags --prefix $p --disable", opts={"vars": {"p": prefix}}
                )
                self.stormIsInErr("isn't a valid tag name", msgs)

            # Nothing changed, not even --disable.
            msgs = await core.stormlist("slib.capa.admin.tags")
            self.stormIsInPrint("slib.capa tags: enabled=true prefix=rep.capa", msgs)

            # Case and surrounding space are normalized.
            msgs = await core.stormlist("slib.capa.admin.tags --prefix ' My.Capa '")
            self.stormIsInPrint("prefix=my.capa", msgs)

    async def test_scan_lazy_init(self):
        # An empty pipeline doesn't send the custom rules or get the rules info.
        async with capaSvc(self) as (core, svc, axon):
            await core.nodes("[ meta:rule=* :name=mine :type=capa.custom :text=$t ]",
                             opts={"vars": {"t": MARKER}})
            calls = {"custom": 0, "rulesInfo": 0}
            custom, rulesInfo = svc.custom, svc.rulesInfo

            async def countCustom(rules):
                calls["custom"] += 1
                return await custom(rules)

            async def countInfo():
                calls["rulesInfo"] += 1
                return await rulesInfo()

            svc.custom = countCustom
            svc.rulesInfo = countInfo

            msgs = await core.stormlist(f"file:bytes:sha256={'0' * 64} | slib.capa.scan")
            self.stormHasNoWarnErr(msgs)
            msgs = await core.stormlist("[ test:str=a ] | slib.capa.scan")
            assert calls == {"custom": 0, "rulesInfo": 0}

            # With files, once for all of them.
            await putSample(core, axon)
            await putSample(core, axon, b"another file")
            msgs = await core.stormlist("file:bytes | slib.capa.scan --format sc64")
            assert calls == {"custom": 1, "rulesInfo": 1}

            # --force doesn't need the rules info.
            await core.stormlist("file:bytes | slib.capa.scan --format sc64 --force")
            assert calls == {"custom": 2, "rulesInfo": 1}

    async def test_onload_not_ready(self):
        # The onload gives up (with a warning) if the service isn't ready within 300 seconds.
        async with capaSvc(self) as (core, svc, axon):
            waits = []

            async def notReady(self, name, timeout=None):
                waits.append((name, timeout))
                return False

            with mock.patch.object(s_stormtypes.LibService, "_libSvcWait", notReady):
                msgs = await core.stormlist("$lib.import(slib.capa.sync).onload()")
            assert waits == [("slib.capa", 300)]
            self.stormIsInWarn(
                "slib.capa: The service wasn't ready, the capa rules weren't imported. "
                "Run slib.capa.admin.sync.",
                msgs,
            )
            self.stormNotInPrint("Importing", msgs)

    async def test_sync_rules_fails_midway(self):
        # A rules generator that fails partway through warns, and the import isn't recorded,
        # so the next sync imports the rules again.
        async with capaSvc(self) as (core, svc, axon):
            await core.nodes("meta:rule | delnode --force")
            rules = svc.rules

            async def failing(names=None):
                count = 0
                async for rule in rules(names=names):
                    if count == 2:
                        raise CapaSvcError("the rules went away")
                    count += 1
                    yield rule

            svc.rules = failing
            msgs = await core.stormlist("slib.capa.admin.sync --force")
            self.stormIsInWarn(
                "slib.capa: Importing the capa rules failed: the rules went away", msgs
            )
            self.stormNotInPrint("Imported 6 capa rules", msgs)
            assert len(await core.nodes("meta:rule")) == 2
            # Still yields the ruleset.
            assert [n.ndef[0] for n in await core.nodes("slib.capa.admin.sync --force")] == [
                "meta:ruleset"
            ]
            msgs = await core.stormlist("slib.capa.info")
            self.stormIsInPrint("rules imported: false", msgs)

            svc.rules = rules
            msgs = await core.stormlist("slib.capa.admin.sync")
            self.stormIsInPrint("Imported 6 capa rules", msgs)
            assert len(await core.nodes("meta:rule")) == 6
