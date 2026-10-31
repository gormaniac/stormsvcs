"""Pytests for capasvc.rules, loading capa rules and building their Synapse records."""

import os
import shutil

import pytest

from capasvc import rules as s_rules

from .capatest import RULES, RULES_VERSION


def loadRules(path=RULES, urlfmt="https://example.com/rules/{version}/{path}"):
    return s_rules.CapaRules(path, RULES_VERSION, urlfmt)


class TestHelpers:
    def test_tags(self):
        assert s_rules.nsTag("anti-analysis/anti-debugging") == "anti_analysis.anti_debugging"
        assert s_rules.nsTag("host-interaction/process/create") == "host_interaction.process.create"
        assert s_rules.nsTag("Data-Manipulation//Encoding ") == "data_manipulation.encoding"
        assert s_rules.nsTag("") is None
        assert s_rules.nsTag(None) is None
        assert s_rules.nsTag("///") is None
        assert s_rules.tagPart(" a-b c ") == "a_b_c"
        assert s_rules.tagPart("---") == ""
        assert s_rules.tagPart("Über") == "über"

    def test_contact(self):
        assert s_rules.contact("Visi@Vertex.Link ") == {"email": "visi@vertex.link"}
        assert s_rules.contact("@_re_fox") == {"name": "@_re_fox"}
        assert s_rules.contact("BitsOfBinary") == {"name": "bitsofbinary"}

    def test_techniques(self):
        assert s_rules.techniques(
            [
                "Defense Evasion::Obfuscated Files or Information [T1027]",
                "Execution::Command and Scripting Interpreter::PowerShell [T1059.001]",
                "Defense Evasion::Obfuscated Files or Information [T1027]",
                "Not an ATT&CK technique",
            ]
        ) == ["T1027", "T1059.001"]

    def test_guids(self):
        assert s_rules.ruleGuid("a") == s_rules.ruleGuid("a")
        assert s_rules.ruleGuid("a") != s_rules.ruleGuid("b")
        assert s_rules.rulesetGuid("v1") != s_rules.rulesetGuid("v2")

    def test_ruleMeta(self):
        assert s_rules.ruleMeta({"a": (1, {2}), "b": {"c": None}, "d": object}) == {
            "a": [1, [2]],
            "b": {"c": None},
            "d": str(object),
        }

    def test_ruleDoc(self):
        doc = s_rules.ruleDoc(
            {
                "name": "x",
                "namespace": "a/b",
                "description": "Does a thing.",
                "authors": ["a@b.c"],
                "scopes": {"static": "function", "dynamic": "call"},
                "att&ck": ["Execution [T1059]"],
                "references": "https://example.com",
                "lib": True,
            }
        )
        assert doc.startswith("Does a thing.\n\nThis is a capa library rule.")
        assert "Namespace: a/b" in doc
        assert "Scopes: static: function, dynamic: call" in doc
        assert "Authors: a@b.c" in doc
        assert "ATT&CK:\n- Execution [T1059]" in doc
        assert "References:\n- https://example.com" in doc
        assert "MBC" not in doc
        assert s_rules.ruleDoc({"name": "x"}) == ""


class TestCapaRules:
    def test_load(self):
        rules = loadRules()
        assert sorted(rules.rules) == [
            "contain a string that is never there",
            "contain marker without a namespace",
            "contain ret",
            "contain slib-capa test marker",
            "contain xor",
            "return from a function",
        ]

        info = rules.info()
        assert info["path"] == os.path.abspath(RULES)
        assert info["version"] == RULES_VERSION
        assert len(info["sha256"]) == 64
        assert info["ruleset"] == s_rules.rulesetGuid(RULES_VERSION)
        assert info["rules"] == 6
        assert info["lib"] == 1
        assert info["namespaces"] == 4

        rec = rules.rules["contain slib-capa test marker"]
        assert rec["guid"] == s_rules.ruleGuid("contain slib-capa test marker")
        assert rec["namespace"] == "testing/slib-capa"
        assert rec["tag"] == "testing.slib_capa"
        assert rec["type"] == "capa"
        assert rec["lib"] is False
        assert rec["path"] == "testing/contain-marker.yml"
        assert rec["url"] == "https://example.com/rules/vtest/testing/contain-marker.yml"
        assert rec["text"].startswith("rule:\n  meta:\n    name: contain slib-capa test marker")
        assert rec["desc"].startswith("The file contains the slib.capa test marker string.")
        assert "MBC:\n- Anti-Static Analysis::Executable Code Obfuscation [B0032]" in rec["desc"]
        assert "Examples:\n- 0123456789abcdef0123456789abcdef:0x1000" in rec["desc"]
        assert rec["authors"] == [{"email": "test@example.com"}, {"name": "@visi"}]
        assert rec["techniques"] == ["T1027", "T1059.001"]
        assert rec["meta"]["att&ck"][0].endswith("[T1027]")

        lib = rules.rules["contain ret"]
        assert lib["lib"] is True and lib["type"] == "capa.lib" and lib["tag"] is None

        nons = rules.rules["contain marker without a namespace"]
        assert nons["namespace"] is None and nons["tag"] is None

        # The same rules always have the same hash, which is the hash of the files on disk.
        assert loadRules().sha256 == rules.sha256 == s_rules.rulesSha256(RULES)

        # The sync key changes with the version and URLs too.
        keys = {
            rules.info()["key"],
            loadRules(urlfmt="").info()["key"],
            s_rules.CapaRules(RULES, "vother", None).info()["key"],
            s_rules.CapaRules(RULES, "vother", "").info()["key"],
        }
        assert len(keys) == 3

    def test_rulesStat(self, tmp_path):
        rules = loadRules()
        assert rules.stat == s_rules.rulesStat(RULES)

        shutil.copytree(RULES, tmp_path / "rules")
        stat = s_rules.rulesStat(str(tmp_path / "rules"))
        os.utime(tmp_path / "rules" / "testing" / "never.yml", ns=(1, 1))
        assert s_rules.rulesStat(str(tmp_path / "rules")) != stat

        with pytest.raises(s_rules.CapaRulesError, match="does not exist"):
            s_rules.rulesStat(str(tmp_path / "newp"))

        # A rule file that can't be stat'd (ex. a broken symlink).
        (tmp_path / "rules" / "broken.yml").symlink_to(tmp_path / "newp.yml")
        with pytest.raises(s_rules.CapaRulesError, match="Unable to read the capa rules"):
            s_rules.rulesStat(str(tmp_path / "rules"))

    def test_url_template(self):
        with pytest.raises(s_rules.CapaRulesError, match="may only use"):
            loadRules(urlfmt="https://x/{name}")
        rules = loadRules(urlfmt="https://x/{path}")
        assert rules.rules["contain xor"]["url"] == "https://x/testing/ops/xor.yml"

    def test_no_urls(self):
        rules = loadRules(urlfmt="")
        assert all(r["url"] is None for r in rules.rules.values())

    def test_namespaces_tags(self):
        rules = loadRules()
        assert rules.namespaces() == {
            "testing/never": ["contain a string that is never there"],
            "testing/ops/ret": ["return from a function"],
            "testing/ops/xor": ["contain xor"],
            "testing/slib-capa": ["contain slib-capa test marker"],
        }

        tags = {t["tag"]: t for t in rules.tagRecords()}
        assert sorted(tags) == [
            "",
            "testing",
            "testing.never",
            "testing.ops",
            "testing.ops.ret",
            "testing.ops.xor",
            "testing.slib_capa",
        ]
        assert tags[""]["title"] == "capa"
        assert "capa-rules vtest" in tags[""]["doc"]
        assert tags["testing.ops.xor"]["title"] == "capa: testing/ops/xor"
        assert tags["testing.ops.xor"]["namespace"] == "testing/ops/xor"
        assert tags["testing.ops.xor"]["doc"] == (
            "Files that matched a capa rule in the testing/ops/xor namespace.\n\n"
            "Rules:\n- contain xor"
        )
        assert tags["testing.ops"]["doc"] == (
            "Files that matched a capa rule in the testing/ops namespace.\n\n"
            "Plus 2 rules in the namespaces below this one."
        )
        assert "Plus 4 rules" in tags["testing"]["doc"]

    def test_errors(self, tmp_path):
        with pytest.raises(s_rules.CapaRulesError, match="does not exist"):
            loadRules(str(tmp_path / "newp"))

        with pytest.raises(s_rules.CapaRulesError, match="has no rules"):
            loadRules(str(tmp_path))

        shutil.copytree(RULES, tmp_path / "dup")
        shutil.copy(tmp_path / "dup" / "testing" / "never.yml", tmp_path / "dup" / "never2.yml")
        with pytest.raises(s_rules.CapaRulesError, match="Duplicate capa rule name"):
            loadRules(str(tmp_path / "dup"))

        notutf8 = tmp_path / "notutf8"
        notutf8.mkdir()
        (notutf8 / "rule.yml").write_bytes(b"rule:\n  meta:\n    name: \xff\xfe\n")
        with pytest.raises(s_rules.CapaRulesError, match="Unable to read the capa rule rule.yml"):
            loadRules(str(notutf8))

        bad = tmp_path / "bad"
        bad.mkdir()
        (bad / "bad.yml").write_text("rule:\n  meta:\n    name: bad\n  features:\n    - newp: 1\n")
        with pytest.raises(s_rules.CapaRulesError, match="Invalid capa rule bad.yml"):
            loadRules(str(bad))


class TestRulesVersion:
    def test_versions_match(self):
        """The bundled rules (Dockerfile) and RULES_VERSION match the version of capa."""

        import capa.version

        from capasvc.defs import RULES_VERSION

        assert RULES_VERSION == f"v{capa.version.__version__}"

        dockerfile = os.path.join(os.path.dirname(__file__), "..", "docker", "prod", "Dockerfile")
        with open(dockerfile) as fd:
            assert f"ARG CAPA_VERSION={RULES_VERSION}\n" in fd.read()
