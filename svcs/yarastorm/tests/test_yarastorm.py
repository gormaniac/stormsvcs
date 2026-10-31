"""Pytests for yarastorm."""

import binascii
import hashlib

import synapse.common as s_common
import synapse.tests.utils as s_tests
import yara_x
from yarastorm import __version__, YaraSvc
from yarastorm.svc import YaraRules
from yarastorm.defs import SVC_NAME


CMDS = (
    f"{SVC_NAME}.check",
    f"{SVC_NAME}.disable",
    f"{SVC_NAME}.enable",
    f"{SVC_NAME}.scan",
)
MODS = (f"{SVC_NAME}.lib",)


class TestYaraStorm(s_tests.SynTest):
    """Test suite for the yarastorm service."""

    async def test_svc_starts(self):
        async with self.getTestCoreProxSvc(YaraSvc) as (core, prox, svc):
            msgs = await core.stormlist("service.list")
            self.stormIsInPrint(f"true (svc) ({SVC_NAME} @ {__version__})", msgs)

    async def test_pkg_cmds_exist(self):
        async with self.getTestCoreProxSvc(YaraSvc) as (core, prox, svc):
            for cmd in CMDS:
                assert cmd in core.stormcmds

    async def test_pkg_mods_exist(self):
        async with self.getTestCoreProxSvc(YaraSvc) as (core, prox, svc):
            for mod in MODS:
                assert mod in core.stormmods

    async def test_pkg_mods_import(self):
        async with self.getTestCoreProxSvc(YaraSvc) as (core, prox, svc):
            for mod in MODS:
                msgs = await core.stormlist(f"$mod = $lib.import({mod})")
                self.stormHasNoErr(msgs)

    async def test_svc_import(self):
        async with self.getTestCoreProxSvc(YaraSvc) as (core, prox, svc):
            msgs = await core.stormlist(f"$svc = $lib.service.get({SVC_NAME})")
            self.stormHasNoErr(msgs)

    async def test_cmd_yara_check(self):
        async with self.getTestCoreProxSvc(YaraSvc) as (core, prox, svc):
            await core.nodes('[ it:app:yara:rule=* :text="test" :name="bad"]')
            await core.nodes(
                '[ it:app:yara:rule=* :text="rule dummy { condition: true }" :name="dummy"]'
            )

            msgs = await core.stormlist(f"it:app:yara:rule:name=dummy | {SVC_NAME}.check")
            self.stormHasNoWarnErr(msgs)
            self.stormIsInPrint("is a valid Yara rule!", msgs)

            msgs = await core.stormlist(f"it:app:yara:rule:name=bad | {SVC_NAME}.check")
            self.stormHasNoErr(msgs)
            self.stormIsInWarn("is not a valid Yara rule", msgs)

            # Checking a rule must not save it to the service.
            self.len(0, svc.rules.rules)

    async def test_cmd_yara_enable(self):
        async with self.getTestCoreProxSvc(YaraSvc) as (core, prox, svc):
            rule_id = s_common.guid()
            await core.nodes(
                f'[ it:app:yara:rule={rule_id} :text="rule dummy {{ condition: true }}" :name="dummy"]'
            )
            msgs = await core.stormlist(f"it:app:yara:rule={rule_id} | {SVC_NAME}.enable")
            self.stormHasNoWarnErr(msgs)

            self.len(1, await core.nodes(f"it:app:yara:rule={rule_id} +:enabled=(true)"))
            self.nn(svc.rules.get(rule_id))

            # A rule that doesn't compile is not enabled.
            bad_id = s_common.guid()
            await core.nodes(f'[ it:app:yara:rule={bad_id} :text="test" :name="bad"]')
            msgs = await core.stormlist(f"it:app:yara:rule={bad_id} | {SVC_NAME}.enable")
            self.stormHasNoErr(msgs)
            self.stormIsInWarn("Unable to enable", msgs)
            self.len(0, await core.nodes(f"it:app:yara:rule={bad_id} +:enabled=(true)"))
            self.none(svc.rules.get(bad_id))

    async def test_cmd_yara_disable(self):
        async with self.getTestCoreProxSvc(YaraSvc) as (core, prox, svc):
            rule_id = s_common.guid()
            await core.nodes(
                f'[ it:app:yara:rule={rule_id} :text="rule dummy {{ condition: true }}" :name="dummy"]'
            )
            await core.stormlist(f"it:app:yara:rule={rule_id} | {SVC_NAME}.enable")
            self.nn(svc.rules.get(rule_id))

            msgs = await core.stormlist(f"it:app:yara:rule={rule_id} | {SVC_NAME}.disable")
            self.stormHasNoWarnErr(msgs)
            self.len(1, await core.nodes(f"it:app:yara:rule={rule_id} +:enabled=(false)"))
            self.none(svc.rules.get(rule_id))

    async def test_cmd_yara_scan(self):
        async with self.getTestAxon() as axon:
            _, sha256 = await axon.put(b"test")
            conf = {"axon_url": axon.getLocalUrl()}
            async with self.getTestCoreProxSvc(YaraSvc, ssvc_conf=conf) as (core, prox, svc):
                hit = s_common.guid()
                miss = s_common.guid()
                await core.nodes(
                    f'[ it:app:yara:rule={hit} :text="rule hit {{ strings: $a = \\"test\\" condition: $a }}" :name="hit"]'
                )
                await core.nodes(
                    f'[ it:app:yara:rule={miss} :text="rule miss {{ condition: false }}" :name="miss"]'
                )
                msgs = await core.stormlist(f"it:app:yara:rule | {SVC_NAME}.enable")
                self.stormHasNoWarnErr(msgs)

                await core.nodes(f"[ file:bytes={sha256.hex()} ]")
                msgs = await core.stormlist(f"file:bytes | {SVC_NAME}.scan")
                self.stormHasNoWarnErr(msgs)
                self.stormIsInPrint(f"it:app:yara:rule={hit} matched", msgs)
                self.stormNotInPrint(f"it:app:yara:rule={miss} matched", msgs)

                nodes = await core.nodes(f"it:app:yara:match:rule={hit}")
                self.len(1, nodes)
                self.eq(f"sha256:{sha256.hex()}", nodes[0].get("file"))
                self.len(0, await core.nodes(f"it:app:yara:match:rule={miss}"))

                # Disabled rules are no longer used to scan.
                await core.nodes(f"it:app:yara:rule={hit} | {SVC_NAME}.disable")
                msgs = await core.stormlist(f"file:bytes | {SVC_NAME}.scan")
                self.stormNotInPrint("matched", msgs)

    async def test_cmd_yara_scan_missing_bytes(self):
        async with self.getTestAxon() as axon:
            conf = {"axon_url": axon.getLocalUrl()}
            async with self.getTestCoreProxSvc(YaraSvc, ssvc_conf=conf) as (core, prox, svc):
                await core.nodes(f"[ file:bytes={hashlib.sha256(b'nope').hexdigest()} ]")
                msgs = await core.stormlist(f"file:bytes | {SVC_NAME}.scan")
                self.stormHasNoErr(msgs)
                self.stormIsInWarn("are not in the Axon", msgs)

    async def test_rules_persist(self):
        with self.getTestDir() as dirn:
            rules = YaraRules(dirn)
            rules.add("rule1", yara_x.compile("rule dummy { condition: true }"))
            self.nn(rules.get("rule1"))

            # A new instance loads previously saved rules from disk.
            rules = YaraRules(dirn)
            self.isin("rule1", rules.rules)
            self.len(1, rules.get("rule1").scan(b"x").matching_rules)

            rules.remove("rule1")
            self.none(rules.get("rule1"))
            self.len(0, YaraRules(dirn).rules)
