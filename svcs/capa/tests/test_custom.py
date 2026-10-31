"""Pytests for custom capa rules (capasvc.custom, and CapaSvc.custom/scan with them)."""

import os
from unittest import mock

import pytest
import synapse.common as s_common
import synapse.tests.utils as s_tests

from capasvc import CapaSvc
from capasvc.api import CapaSvcError
from capasvc.custom import CUSTOM_RULE_TYPE, CustomRules
from capasvc.rules import CapaRules

from .capatest import RULES, RULES_VERSION, SAMPLE, SAMPLE_SHA256, svcConf


def customRule(name: str, feature: str = 'string: "slib-capa-test-marker"',
               namespace: str = "custom/marker", extra: str = "") -> str:
    """The YAML of a custom capa rule."""

    return (
        "rule:\n"
        "  meta:\n"
        f"    name: {name}\n"
        f"    namespace: {namespace}\n"
        "    authors:\n"
        "      - custom@example.com\n"
        f"{extra}"
        "    scopes:\n"
        "      static: file\n"
        "      dynamic: file\n"
        "  features:\n"
        f"    - {feature}\n"
    )


MARKER = customRule("custom marker rule")


class TestCustomRules:

    def official(self):
        return CapaRules(RULES, RULES_VERSION)

    def test_rules(self, tmp_path):
        official = self.official()
        guid = s_common.guid()
        cset = CustomRules(official, [{"guid": guid, "text": MARKER}], str(tmp_path))

        assert cset.errors == [] and cset.shadowed == []
        rec = cset.records["custom marker rule"]
        assert rec["guid"] == guid
        assert rec["type"] == CUSTOM_RULE_TYPE and rec["custom"] is True
        assert rec["tag"] == "custom.marker"
        assert rec["url"] is None and rec["path"] is None
        assert rec["text"] == MARKER
        assert cset.info() == {
            "key": cset.key,
            "rules": [{"guid": guid, "name": "custom marker rule"}],
            "errors": [],
            "shadowed": [],
        }

        # Saved to disk under the set's key.
        assert cset.path == os.path.join(str(tmp_path), cset.key)
        with open(os.path.join(cset.path, f"{guid}.yml")) as fd:
            assert fd.read() == MARKER

        # The key only depends on the rules, not their order, and the set is only saved once.
        other = s_common.guid()
        rules = [{"guid": guid, "text": MARKER},
                 {"guid": other, "text": customRule("another rule")}]
        one = CustomRules(official, rules, str(tmp_path))
        two = CustomRules(official, list(reversed(rules)), str(tmp_path))
        assert one.key == two.key != cset.key
        assert sorted(os.listdir(tmp_path)) == sorted([cset.key, one.key])

        # capa caches the custom and official rules together.
        assert cset.cacheName(str(tmp_path)) != official.cacheName(str(tmp_path))

    def test_skipped(self, tmp_path):
        official = self.official()
        guids = [s_common.guid() for _ in range(6)]
        cset = CustomRules(official, [
            {"guid": guids[0], "text": MARKER},
            {"guid": guids[1], "text": customRule("custom marker rule")},  # Same name.
            {"guid": guids[2], "text": customRule("contain xor")},  # An official rule's name.
            {"guid": guids[3], "text": "rule:\n  meta:\n    name: bad\n"},
            {"guid": guids[4], "text": None},
            {"guid": "newp", "text": MARKER},
        ], str(tmp_path))

        assert list(cset.records) == ["custom marker rule"]
        assert cset.shadowed == [{"guid": guids[2], "name": "contain xor"}]
        errors = {e["guid"]: e["mesg"] for e in cset.errors}
        dupe = sorted(guids[:2])
        assert errors[dupe[1]] == (
            f"Another custom rule (meta:rule={dupe[0]}) has the same name: custom marker rule"
        )
        assert errors[guids[3]].startswith("Invalid capa rule:")
        assert errors[guids[4]] == "The rule has no :text."
        assert errors["newp"] == "Not a meta:rule guid."

    def test_save_race(self, tmp_path):
        # Another registration of the same set saved it between the check and the rename.
        official = self.official()
        rules = [{"guid": s_common.guid(), "text": MARKER}]
        rename = os.rename

        def racing(src, dst):
            rename(src, f"{src}.copy")
            os.makedirs(dst)
            raise OSError("exists")

        with mock.patch("os.rename", side_effect=racing):
            cset = CustomRules(official, rules, str(tmp_path))
        assert os.path.isdir(cset.path)

        # A rename that fails for another reason is raised.
        with mock.patch("os.rename", side_effect=OSError("newp")):
            with pytest.raises(OSError, match="newp"):
                CustomRules(official, [{"guid": s_common.guid(), "text": MARKER}], str(tmp_path))

    def test_empty(self, tmp_path):
        cset = CustomRules(self.official(), [], str(tmp_path))
        assert cset.key is None and cset.path is None and cset.cacheName(str(tmp_path)) is None
        assert os.listdir(tmp_path) == []


class TestCapaSvcCustom(s_tests.SynTest):

    async def test_scan_custom(self):
        async with self.getTestAxon() as axon:
            await axon.put(SAMPLE)
            async with self.getTestCell(CapaSvc, svcConf(axon)) as svc:
                guid = s_common.guid()
                # Custom rules can use the official rules, ex. a library rule.
                ret = customRule("custom ret rule", feature="match: contain ret",
                                 namespace="custom/ops/ret").replace(
                    "      static: file\n      dynamic: file\n",
                    "      static: function\n      dynamic: unsupported\n",
                )
                info = await svc.custom([
                    {"guid": guid, "text": MARKER},
                    {"guid": s_common.guid(), "text": ret},
                    {"guid": s_common.guid(), "text": customRule("never", "string: newp")},
                ])
                assert len(info["rules"]) == 3 and not info["errors"]

                res = await svc.scan(SAMPLE_SHA256, fmt="sc64", custom=info["key"])
                assert res["rules"]["custom"] == info["key"]
                bynames = {m["rule"]["name"]: m for m in res["matches"]}
                assert "contain xor" in bynames  # The official rules still match.
                assert bynames["custom marker rule"]["rule"]["guid"] == guid
                assert bynames["custom marker rule"]["rule"]["type"] == "capa.custom"
                assert bynames["custom ret rule"]["addrs"] == ["0x690000"]
                assert "never" not in bynames

                # capa's cache of the official and custom rules is kept, other caches aren't.
                cset = svc.customSets[info["key"]]
                assert sorted(os.listdir(svc.cachedir)) == sorted([
                    svc.capaRules.cacheName(svc.cachedir), cset.cacheName(svc.cachedir),
                ])

                # Sending the same rules again reuses the set.
                again = await svc.custom([
                    {"guid": guid, "text": MARKER},
                    {"guid": cset.records["custom ret rule"]["guid"], "text": ret},
                    {"guid": cset.records["never"]["guid"],
                     "text": customRule("never", "string: newp")},
                ])
                assert again["key"] == info["key"] and svc.customSets[info["key"]] is cset

                # Scans without the key only use the official rules.
                res = await svc.scan(SAMPLE_SHA256, fmt="sc64")
                assert res["rules"]["custom"] is None
                assert "custom marker rule" not in {m["rule"]["name"] for m in res["matches"]}

                # A reload forgets the sets, Storm sends them again.
                await svc.reload()
                with self.raises(CapaSvcError) as cm:
                    await svc.scan(SAMPLE_SHA256, fmt="sc64", custom=info["key"])
                assert "Unknown custom capa rules" in cm.exception.mesg

    async def test_custom_errors(self):
        async with self.getTestAxon() as axon:
            await axon.put(SAMPLE)
            async with self.getTestCell(CapaSvc, svcConf(axon)) as svc:
                with self.raises(CapaSvcError) as cm:
                    await svc.custom("newp")
                assert "must be a list" in cm.exception.mesg

                # Nothing usable, so no key.
                info = await svc.custom([{"guid": "newp", "text": MARKER}, "newp"])
                assert info["key"] is None and len(info["errors"]) == 2

                # A custom rule capa can't load with the official rules fails the scans with it.
                info = await svc.custom([
                    {"guid": s_common.guid(), "text": customRule("x", "match: newp rule")},
                ])
                for _ in range(2):
                    with self.raises(CapaSvcError) as cm:
                        await svc.scan(SAMPLE_SHA256, fmt="sc64", custom=info["key"])
                    assert cm.exception.mesg.startswith("capa can't use the custom rules: ")
                    assert "newp rule" in cm.exception.mesg

        async with self.getTestCell(CapaSvc, {}) as svc:
            with self.raises(CapaSvcError) as cm:
                await svc.custom([])
            assert "no capa:rules directory configured" in cm.exception.mesg

    async def test_custom_restart(self):
        # Saved sets don't outlive the service.
        with self.getTestDir() as dirn:
            async with self.getTestCell(CapaSvc, svcConf(), dirn=dirn) as svc:
                info = await svc.custom([{"guid": s_common.guid(), "text": MARKER}])
                assert os.listdir(svc.customdir) == [info["key"]]
            async with self.getTestCell(CapaSvc, svcConf(), dirn=dirn) as svc:
                assert os.listdir(svc.customdir) == [] and not svc.customSets

    async def test_api(self):
        async with self.getTestCell(CapaSvc, svcConf()) as svc:
            async with svc.getLocalProxy() as prox:
                retn = await prox.custom([{"guid": s_common.guid(), "text": MARKER}])
                assert retn["status"] and retn["data"]["key"]
                retn = await prox.custom("newp")
                assert not retn["status"] and "must be a list" in retn["mesg"]
