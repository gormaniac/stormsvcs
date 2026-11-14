"""Pytests for yarastorm."""

import hashlib
import io
import os
import pathlib
import tomllib
from unittest import mock

import synapse.common as s_common
import synapse.exc as s_exc
import synapse.tests.utils as s_tests
import yara_x
from stormlibpp.node import StormNode

import yarastorm.svc as y_svc
from yarastorm import YaraSvc, __version__
from yarastorm.defs import PKGDEFS, SVC_GUID, SVC_NAME
from yarastorm.svc import YaraRules

SVCDIR = pathlib.Path(__file__).parent.parent

CMDS = (
    f"{SVC_NAME}.check",
    f"{SVC_NAME}.disable",
    f"{SVC_NAME}.enable",
    f"{SVC_NAME}.scan",
    f"{SVC_NAME}.sync",
)
MODS = (f"{SVC_NAME}.lib", f"{SVC_NAME}.ingest")

TRUE_RULE = "rule dummy { condition: true }"
HIT_RULE = 'rule hit { strings: $a = "test" condition: $a }'


def ruleQuery(iden: str, text: str, name: str = "rule") -> str:
    """Storm that makes an it:app:yara:rule node."""
    return f"[ it:app:yara:rule={iden} :text={text!r} :name={name} ]"


def packed(iden: str, text: str | None = TRUE_RULE, form: str = "it:app:yara:rule"):
    """A packed node, as Storm's $node.pack() would send it to the service."""
    props = {} if text is None else {"text": text}
    return StormNode(form, iden, props=props).pack()


class TestYaraStorm(s_tests.SynTest):
    """Test suite for the yarastorm service."""

    def test_versions_match(self):
        # The version lives in pyproject.toml, __init__.py, the package yaml, and uv.lock.
        with (SVCDIR / "pyproject.toml").open("rb") as fd:
            assert tomllib.load(fd)["project"]["version"] == __version__
        assert PKGDEFS[0]["version"] == __version__
        with (SVCDIR / "uv.lock").open("rb") as fd:
            pkgs = tomllib.load(fd)["package"]
        assert [p["version"] for p in pkgs if p["name"] == "yarastorm"] == [__version__]

    def test_ingest_srcguid(self):
        # slib.yara.ingest hard codes the service's meta:source guid.
        mod = next(m for m in PKGDEFS[0]["modules"] if m["name"] == f"{SVC_NAME}.ingest")
        assert f'$srcguid = "{SVC_GUID}"' in mod["storm"]

    async def test_svc_starts(self):
        async with self.getTestCoreProxSvc(YaraSvc) as (core, prox, svc):
            msgs = await core.stormlist("service.list")
            self.stormIsInPrint(f"true (svc) ({SVC_NAME} @ {__version__})", msgs)

            # The add event makes the service's meta:source.
            nodes = await core.nodes(f"meta:source={SVC_GUID}")
            self.len(1, nodes)
            self.eq(SVC_NAME, nodes[0].get("name"))

    async def test_pkg(self):
        async with self.getTestCoreProxSvc(YaraSvc) as (core, prox, svc):
            for cmd in CMDS:
                assert cmd in core.stormcmds

            for cdef in PKGDEFS[0]["commands"]:
                assert "forms" not in cdef, cdef["name"]
                for cmdinput in cdef.get("cmdinputs", ()):
                    assert core.model.form(cmdinput["form"]) is not None, cdef["name"]

            for mod in MODS:
                assert mod in core.stormmods
                msgs = await core.stormlist(f"$mod = $lib.import({mod})")
                self.stormHasNoErr(msgs)

            msgs = await core.stormlist(f"$svc = $lib.service.get({SVC_NAME})")
            self.stormHasNoErr(msgs)

    async def test_cmd_yara_check(self):
        async with self.getTestCoreProxSvc(YaraSvc) as (core, prox, svc):
            await core.nodes('[ it:app:yara:rule=* :text="test" :name="bad"]')
            await core.nodes(f"[ it:app:yara:rule=* :text={TRUE_RULE!r} :name=dummy ]")
            await core.nodes("[ it:app:yara:rule=* :name=empty ]")

            msgs = await core.stormlist(f"it:app:yara:rule:name=dummy | {SVC_NAME}.check")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("is a valid Yara rule!", msgs)

            msgs = await core.stormlist(f"it:app:yara:rule:name=bad | {SVC_NAME}.check")
            self.stormHasNoErr(msgs)
            self.stormIsInWarn("is not a valid Yara rule", msgs)

            msgs = await core.stormlist(f"it:app:yara:rule:name=empty | {SVC_NAME}.check")
            self.stormHasNoErr(msgs)
            self.stormIsInWarn("has no :text to compile", msgs)

            # Other forms are skipped with a warning.
            msgs = await core.stormlist(f"[ inet:fqdn=vertex.link ] | {SVC_NAME}.check")
            self.stormHasNoErr(msgs)
            self.stormIsInWarn("only supports it:app:yara:rule nodes, skipping inet:fqdn", msgs)

            # Checking a rule must not save it to the service.
            self.len(0, svc.rules.rules)

    async def test_cmd_yara_enable(self):
        async with self.getTestCoreProxSvc(YaraSvc) as (core, prox, svc):
            rule_id = s_common.guid()
            await core.nodes(ruleQuery(rule_id, TRUE_RULE))
            msgs = await core.stormlist(f"it:app:yara:rule={rule_id} | {SVC_NAME}.enable")
            self.stormHasNoWarnErr(msgs)

            self.len(1, await core.nodes(f"it:app:yara:rule={rule_id} +:enabled=(true)"))
            self.nn(svc.rules.get(rule_id))

            # A rule that doesn't compile is not enabled.
            bad_id = s_common.guid()
            await core.nodes(ruleQuery(bad_id, "test", "bad"))
            msgs = await core.stormlist(f"it:app:yara:rule={bad_id} | {SVC_NAME}.enable")
            self.stormHasNoErr(msgs)
            self.stormIsInWarn("Unable to enable", msgs)
            self.len(0, await core.nodes(f"it:app:yara:rule={bad_id} +:enabled=(true)"))
            self.none(svc.rules.get(bad_id))

            msgs = await core.stormlist(f"[ inet:fqdn=vertex.link ] | {SVC_NAME}.enable")
            self.stormHasNoErr(msgs)
            self.stormIsInWarn("only supports it:app:yara:rule nodes", msgs)

    async def test_cmd_yara_disable(self):
        async with self.getTestCoreProxSvc(YaraSvc) as (core, prox, svc):
            rule_id = s_common.guid()
            await core.nodes(ruleQuery(rule_id, TRUE_RULE))
            await core.stormlist(f"it:app:yara:rule={rule_id} | {SVC_NAME}.enable")
            self.nn(svc.rules.get(rule_id))

            msgs = await core.stormlist(f"it:app:yara:rule={rule_id} | {SVC_NAME}.disable")
            self.stormHasNoWarnErr(msgs)
            self.len(1, await core.nodes(f"it:app:yara:rule={rule_id} +:enabled=(false)"))
            self.none(svc.rules.get(rule_id))

            # Disabling a rule the service doesn't have is fine.
            msgs = await core.stormlist(f"it:app:yara:rule={rule_id} | {SVC_NAME}.disable")
            self.stormHasNoWarnErr(msgs)

            msgs = await core.stormlist(f"[ inet:fqdn=vertex.link ] | {SVC_NAME}.disable")
            self.stormHasNoErr(msgs)
            self.stormIsInWarn("only supports it:app:yara:rule nodes", msgs)

    async def test_cmd_perms(self):
        async with self.getTestCoreProxSvc(YaraSvc) as (core, prox, svc):
            rule_id = s_common.guid()
            await core.nodes(ruleQuery(rule_id, TRUE_RULE))

            user = await core.auth.addUser("lowuser")
            await user.addRule((True, ("service", "get")))
            await user.addRule((True, ("node",)))
            opts = {"user": user.iden}

            for cmd in ("enable", "disable"):
                msgs = await core.stormlist(
                    f"it:app:yara:rule={rule_id} | {SVC_NAME}.{cmd}", opts=opts
                )
                self.stormHasNoErr(msgs)
                self.stormIsInWarn(f"{SVC_NAME}.{cmd} requires the slib.yara.admin", msgs)

            msgs = await core.stormlist(f"{SVC_NAME}.sync", opts=opts)
            self.stormHasNoErr(msgs)
            self.stormIsInWarn("requires the slib.yara.admin permission", msgs)

            self.len(0, svc.rules.rules)
            self.len(0, await core.nodes(f"it:app:yara:rule={rule_id} +:enabled"))

            # Calling the module directly raises.
            q = f"it:app:yara:rule={rule_id} $lib.import({SVC_NAME}.lib).enableRule($node)"
            msgs = await core.stormlist(q, opts=opts)
            self.stormIsInErr("requires the slib.yara.admin permission", msgs)

            # With the permission the user can enable rules.
            await user.addRule((True, ("slib", "yara", "admin")))
            q = f"it:app:yara:rule={rule_id} | {SVC_NAME}.enable"
            msgs = await core.stormlist(q, opts=opts)
            self.stormHasNoWarnErr(msgs)
            self.nn(svc.rules.get(rule_id))

    async def test_cmd_yara_sync(self):
        async with self.getTestAxon() as axon:
            _, sha256 = await axon.put(b"test")
            conf = {"axon_url": axon.getLocalUrl()}
            async with self.getTestCoreProxSvc(YaraSvc, ssvc_conf=conf) as (core, prox, svc):
                # Enabled in the Cortex directly, so the service doesn't have it.
                direct = s_common.guid()
                await core.nodes(ruleQuery(direct, "rule miss { condition: false }"))
                await core.nodes(f"it:app:yara:rule={direct} [ :enabled=(true) ]")

                # In the service but not enabled in the Cortex.
                stale = s_common.guid()
                svc.rules.add(stale, yara_x.compile(TRUE_RULE))

                # Enabled but doesn't compile.
                broken = s_common.guid()
                await core.nodes(ruleQuery(broken, "nope"))
                await core.nodes(f"it:app:yara:rule={broken} [ :enabled=(true) ]")

                msgs = await core.stormlist(f"{SVC_NAME}.sync")
                self.stormHasNoErr(msgs)
                self.stormIsInWarn(f"Unable to sync it:app:yara:rule={broken}", msgs)
                self.stormIsInPrint("1 compiled, 1 removed, 1 failed", msgs)
                self.eq([direct], sorted(svc.rules.rules))

                # A :text change is picked up by the next sync.
                await core.nodes(f"it:app:yara:rule={direct} [ :text={HIT_RULE!r} ]")
                await core.nodes(f"[ file:bytes={sha256.hex()} ]")
                msgs = await core.stormlist(f"file:bytes | {SVC_NAME}.scan")
                self.stormNotInPrint("matched", msgs)

                await core.nodes(f"it:app:yara:rule={broken} [ -:enabled ]")
                msgs = await core.stormlist(f"{SVC_NAME}.sync")
                self.stormHasNoWarnErr(msgs)
                self.stormIsInPrint("1 compiled, 0 removed, 0 failed", msgs)
                msgs = await core.stormlist(f"file:bytes | {SVC_NAME}.scan")
                self.stormIsInPrint(f"it:app:yara:rule={direct} matched", msgs)

    async def test_cmd_yara_scan(self):
        async with self.getTestAxon() as axon:
            _, sha256 = await axon.put(b"test")
            conf = {"axon_url": axon.getLocalUrl()}
            async with self.getTestCoreProxSvc(YaraSvc, ssvc_conf=conf) as (core, prox, svc):
                # No rules in the service.
                await core.nodes(f"[ file:bytes={sha256.hex()} ]")
                msgs = await core.stormlist(f"file:bytes | {SVC_NAME}.scan")
                self.stormIsInWarn("has no rules to scan with", msgs)

                hit = s_common.guid()
                miss = s_common.guid()
                await core.nodes(ruleQuery(hit, HIT_RULE, "hit"))
                await core.nodes(ruleQuery(miss, "rule miss { condition: false }", "miss"))
                msgs = await core.stormlist(f"it:app:yara:rule | {SVC_NAME}.enable")
                self.stormHasNoWarnErr(msgs)

                msgs = await core.stormlist(f"file:bytes | {SVC_NAME}.scan")
                self.stormHasNoWarnErr(msgs)
                self.stormIsInPrint(f"it:app:yara:rule={hit} matched", msgs)
                self.stormNotInPrint(f"it:app:yara:rule={miss}", msgs)

                nodes = await core.nodes(f"it:app:yara:match:rule={hit}")
                self.len(1, nodes)
                self.eq(f"sha256:{sha256.hex()}", nodes[0].get("file"))
                self.nn(nodes[0].get(".seen"))
                self.len(0, await core.nodes(f"it:app:yara:match:rule={miss}"))
                self.len(
                    1, await core.nodes(f"meta:source={SVC_GUID} -(seen)> it:app:yara:match")
                )

                # $lib.debug prints the rules that didn't match.
                msgs = await core.stormlist(f"file:bytes | {SVC_NAME}.scan", opts={"debug": True})
                self.stormHasNoWarnErr(msgs)
                self.stormIsInPrint(f"it:app:yara:rule={miss} did not match", msgs)

                # Disabled rules are no longer used to scan.
                await core.nodes(f"it:app:yara:rule={hit} | {SVC_NAME}.disable")
                msgs = await core.stormlist(f"file:bytes | {SVC_NAME}.scan")
                self.stormNotInPrint("matched", msgs)

    async def test_cmd_yara_scan_guid_file(self):
        async with self.getTestAxon() as axon:
            _, sha256 = await axon.put(b"test")
            conf = {"axon_url": axon.getLocalUrl()}
            async with self.getTestCoreProxSvc(YaraSvc, ssvc_conf=conf) as (core, prox, svc):
                hit = s_common.guid()
                await core.nodes(ruleQuery(hit, HIT_RULE, "hit"))
                await core.nodes(f"it:app:yara:rule | {SVC_NAME}.enable")

                # The match points at the scanned node, not a sha256 file:bytes.
                nodes = await core.nodes(f"[ file:bytes=* :sha256={sha256.hex()} ]")
                fileval = nodes[0].ndef[1]
                assert fileval.startswith("guid:")
                msgs = await core.stormlist(f"file:bytes={fileval} | {SVC_NAME}.scan")
                self.stormHasNoWarnErr(msgs)
                nodes = await core.nodes(f"it:app:yara:match:rule={hit}")
                self.len(1, nodes)
                self.eq(fileval, nodes[0].get("file"))

                # file:bytes without a :sha256 and other forms are skipped with a warning.
                msgs = await core.stormlist(f"[ file:bytes=* ] | {SVC_NAME}.scan")
                self.stormHasNoErr(msgs)
                self.stormIsInWarn("has no :sha256 and can't be scanned", msgs)

                msgs = await core.stormlist(f"[ inet:fqdn=vertex.link ] | {SVC_NAME}.scan")
                self.stormHasNoErr(msgs)
                self.stormIsInWarn("only supports file:bytes nodes, skipping inet:fqdn", msgs)

    async def test_cmd_yara_scan_errors(self):
        async with self.getTestAxon() as axon:
            _, empty = await axon.put(b"")
            conf = {"axon_url": axon.getLocalUrl()}
            async with self.getTestCoreProxSvc(YaraSvc, ssvc_conf=conf) as (core, prox, svc):
                rule_id = s_common.guid()
                svc.rules.add(rule_id, yara_x.compile(TRUE_RULE))

                await core.nodes(f"[ file:bytes={hashlib.sha256(b'nope').hexdigest()} ]")
                msgs = await core.stormlist(f"file:bytes | {SVC_NAME}.scan")
                self.stormHasNoErr(msgs)
                self.stormIsInWarn("are not in the Axon", msgs)

                # An empty file is treated as missing.
                await core.nodes(f"file:bytes | delnode | [ file:bytes={empty.hex()} ]")
                msgs = await core.stormlist(f"file:bytes | {SVC_NAME}.scan")
                self.stormHasNoErr(msgs)
                self.stormIsInWarn("are not in the Axon", msgs)

                # A rule that can't be loaded is reported for that rule.
                xsha = hashlib.sha256(b"x").hexdigest()
                await core.nodes(f"file:bytes | delnode | [ file:bytes={xsha} ]")
                await axon.put(b"x")
                svc.rules.rules[rule_id] = None
                msgs = await core.stormlist(f"file:bytes | {SVC_NAME}.scan")
                self.stormHasNoErr(msgs)
                self.stormIsInWarn(f"with it:app:yara:rule={rule_id}: Couldn't load", msgs)

    async def test_scan_no_axon(self):
        async with self.getTestCoreProxSvc(YaraSvc) as (core, prox, svc):
            await core.nodes(f"[ file:bytes={hashlib.sha256(b'x').hexdigest()} ]")
            msgs = await core.stormlist(f"file:bytes | {SVC_NAME}.scan")
            self.stormHasNoErr(msgs)
            self.stormIsInWarn("has no axon_url configured", msgs)

    async def test_matchfile_errors(self):
        url = "tcp://127.0.0.1:1/"
        with mock.patch.object(y_svc, "AXON_TIMEOUT", 0.1):
            async with self.getTestCell(YaraSvc, conf={"axon_url": url}) as svc:
                retns = [r async for r in svc.matchFile(hashlib.sha256(b"x").hexdigest())]
                self.len(1, retns)
                self.false(retns[0]["status"])
                self.isin("Unable to connect to the Axon", retns[0]["mesg"])

                for bad in ("zz" * 32, "abcd", None):
                    retns = [r async for r in svc.matchFile(bad)]
                    self.false(retns[0]["status"])
                    self.isin("Invalid sha256", retns[0]["mesg"])

        async with self.getTestAxon() as axon:
            _, sha256 = await axon.put(b"0123456789")
            conf = {"axon_url": axon.getLocalUrl(), "max_size": 5}
            async with self.getTestCell(YaraSvc, conf=conf) as svc:
                retns = [r async for r in svc.matchFile(sha256.hex())]
                self.false(retns[0]["status"])
                self.isin("more than the 5 byte max", retns[0]["mesg"])

                retns = [r async for r in svc.matchFile(hashlib.sha256(b"no").hexdigest())]
                self.isin("are not in the Axon", retns[0]["mesg"])

                svc.maxsize = 100
                self.eq(b"0123456789", await svc._getBytes(sha256.hex()))

    async def test_svc_rule_validation(self):
        async with self.getTestCell(YaraSvc) as svc:
            ruledir = svc.rules.ruledir
            sentinel = os.path.join(svc.dirn, "sentinel")
            with open(sentinel, "w") as fd:
                fd.write("keep me")
            async with svc.getLocalProxy() as prox:
                # Path traversal attempts are refused.
                for bad in ("../sentinel", "/etc/passwd", "rule1", ""):
                    retn = await prox.removeRule(bad)
                    self.false(retn["status"])
                    self.isin("Invalid it:app:yara:rule guid", retn["mesg"])

                    retn = await prox.compileRule(packed(bad))
                    self.false(retn["status"])
                self.true(os.path.exists(sentinel))

                retn = await prox.compileRule(packed(s_common.guid(), form="inet:fqdn"))
                self.false(retn["status"])
                self.isin("Expected an it:app:yara:rule node", retn["mesg"])

                retn = await prox.compileRule(packed(s_common.guid(), text=None))
                self.false(retn["status"])
                self.isin("has no :text to compile", retn["mesg"])

                retn = await prox.compileRule("nope")
                self.false(retn["status"])

                # Removing a rule the service doesn't have succeeds.
                retn = await prox.removeRule(s_common.guid())
                self.true(retn["status"])
                self.false(retn["data"])

                rule_id = s_common.guid()
                self.true((await prox.compileRule(packed(rule_id)))["status"])
                self.eq([rule_id], (await prox.listRules())["data"])
                self.eq(1, (await prox.getRuleCount())["data"])
                retn = await prox.removeRule(rule_id)
                self.true(retn["status"])
                self.true(retn["data"])
                self.eq(0, (await prox.getRuleCount())["data"])
                self.eq([], os.listdir(ruledir))

    async def test_api_perms(self):
        async with self.getTestCell(YaraSvc) as svc:
            await svc.auth.addUser("lowuser")
            rule_id = s_common.guid()
            async with svc.getLocalProxy(user="lowuser") as prox:
                retn = await prox.compileRule(packed(rule_id))
                self.false(retn["status"])
                self.isin("needs the slib.yara.admin permission", retn["mesg"])

                retn = await prox.removeRule(rule_id)
                self.false(retn["status"])
                self.isin("needs the slib.yara.admin permission", retn["mesg"])

                # Checking a rule and reading the rules don't need it.
                self.true((await prox.compileRule(packed(rule_id), True))["status"])
                self.eq(0, (await prox.getRuleCount())["data"])
                self.len(0, svc.rules.rules)

    async def test_svc_starts_with_corrupt_rule(self):
        with self.getTestDir() as dirn:
            ruledir = os.path.join(dirn, "rules")
            os.makedirs(ruledir)
            good = s_common.guid()
            YaraRules(ruledir).add(good, yara_x.compile(TRUE_RULE))
            with open(os.path.join(ruledir, s_common.guid()), "wb") as fd:
                fd.write(b"not a rule")

            async with self.getTestCell(YaraSvc, dirn=dirn) as svc:
                self.eq([good], list(svc.rules.rules))

    def test_rules_persist(self):
        with self.getTestDir() as dirn:
            rule_id = s_common.guid()
            rules = YaraRules(dirn)
            rules.add(rule_id, yara_x.compile(TRUE_RULE))
            self.nn(rules.get(rule_id))
            # Rules are written via a temp file that's moved into place.
            self.eq([rule_id], os.listdir(dirn))

            # A new instance loads previously saved rules from disk.
            rules = YaraRules(dirn)
            self.isin(rule_id, rules.rules)
            self.len(1, rules.get(rule_id).scan(b"x").matching_rules)

            self.true(rules.remove(rule_id))
            self.none(rules.get(rule_id))
            self.len(0, YaraRules(dirn).rules)

            # Removing a rule that isn't on disk (FileNotFoundError) is fine.
            self.false(rules.remove(rule_id))

            # A rule file added on disk after load is loaded on demand.
            other = s_common.guid()
            YaraRules(dirn).add(other, yara_x.compile(TRUE_RULE))
            self.nn(rules.get(other))

    def test_rules_load_skips(self):
        with self.getTestDir() as dirn:
            buf = io.BytesIO()
            yara_x.compile(TRUE_RULE).serialize_into(buf)
            byts = buf.getvalue()

            good = s_common.guid()
            with open(os.path.join(dirn, good), "wb") as fd:
                fd.write(byts)

            # Corrupt rules are skipped, and get() returns None for them.
            corrupt = s_common.guid()
            with open(os.path.join(dirn, corrupt), "wb") as fd:
                fd.write(b"garbage")

            # Rules in sub directories and non-guid files are not rules.
            os.makedirs(os.path.join(dirn, "sub"))
            with open(os.path.join(dirn, "sub", s_common.guid()), "wb") as fd:
                fd.write(byts)
            with open(os.path.join(dirn, "notaguid"), "wb") as fd:
                fd.write(byts)
            os.makedirs(os.path.join(dirn, s_common.guid()))

            with self.getLoggerStream("yarastorm.svc") as stream:
                rules = YaraRules(dirn)
            stream.seek(0)
            self.isin("Skipping unreadable", stream.read())
            self.eq([good], list(rules.rules))
            self.none(rules.get(corrupt))
            self.none(rules.get("notaguid"))
            self.none(rules.get("../sub"))

    def test_rules_bad_ids(self):
        with self.getTestDir() as dirn:
            rules = YaraRules(os.path.join(dirn, "rules"))
            compiled = yara_x.compile(TRUE_RULE)
            for bad in ("../escape", "/tmp/x", "rule1", None):
                with self.raises(s_exc.BadArg):
                    rules.add(bad, compiled)
                with self.raises(s_exc.BadArg):
                    rules.remove(bad)
                self.none(rules.get(bad))
            self.false(os.path.exists(os.path.join(dirn, "escape")))
