"""Pytests for pcapsvc.engine. Most of these run Snort, see fakefeeds.needsnort."""

import os

import pytest
import synapse.tests.utils as s_tests
from pcapsvc import snort as s_engine
from pcapsvc import rules as s_rules

from . import pcaps
from .fakefeeds import SNORT2_RULES, SNORT3_RULES, needsnort


def rulesByKey(text: str) -> dict[str, str]:
    """{sid: text} of the enabled rules in a rules file."""
    return {str(r["sid"]): r["text"] for r, _, _ in s_rules.parseRules(text) if r and r["enabled"]}


def test_precheck():
    assert (
        s_engine.precheck('alert tcp any any -> any any ( msg:"a (b"; content:"x\\"y"; sid:1; )')
        is None
    )
    assert s_engine.precheck("alert tcp any any -> any any ( sid:1; ) # a comment") is None
    assert "single line" in s_engine.precheck("alert tcp any any -> any any (\nsid:1; )")
    assert "unterminated" in s_engine.precheck(
        'alert tcp any any -> any any ( content:"abc; sid:1; )'
    )
    assert "after its closing" in s_engine.precheck(
        "alert tcp any any -> any any ( sid:1; ) alert tcp any any -> any any ( sid:2; )"
    )
    assert "balanced" in s_engine.precheck("alert tcp any any -> any any ( sid:1; ")
    assert "balanced" in s_engine.precheck("alert tcp any any -> any any sid:1;")


def test_is_pcap():
    assert s_engine.isPcap(pcaps.samplePcap()[:4])
    assert s_engine.isPcap(b"\x0a\x0d\x0d\x0a....")
    assert not s_engine.isPcap(b"MZ\x90\x00")


class TestSnortConf(s_tests.SynTest):
    def test_write_conf(self):
        with self.getTestDir() as dirn:
            base = os.path.join(dirn, "base", "snort.lua")
            os.makedirs(os.path.dirname(base))
            with open(base, "w") as fd:
                fd.write("HOME_NET = 'any'\nEXTERNAL_NET = 'any'\ninclude 'snort_defaults.lua'\n")

            snort = s_engine.Snort(
                os.path.join(dirn, "work"),
                conf=base,
                snortvars={"HOME_NET": "[10.0.0.0/8]", "EXTERNAL_NET": "!$HOME_NET"},
            )
            path = snort.writeConf()
            with open(path) as fd:
                text = fd.read()
            assert "HOME_NET = '[10.0.0.0/8]'\n" in text
            assert "EXTERNAL_NET = '!$HOME_NET'\n" in text
            assert "include 'snort_defaults.lua'" in text
            assert snort.incpath == os.path.dirname(base)

            with pytest.raises(s_engine.SnortError, match="doesn't set HTTP_PORTS"):
                s_engine.Snort(dirn, conf=base, snortvars={"HTTP_PORTS": "80"}).writeConf()
            with pytest.raises(s_engine.SnortError, match="Invalid Snort variable"):
                s_engine.Snort(dirn, conf=base, snortvars={"home_net": "x"}).writeConf()
            with pytest.raises(s_engine.SnortError, match="Unable to read"):
                s_engine.Snort(dirn, conf=os.path.join(dirn, "nope.lua")).writeConf()
            with pytest.raises(s_engine.SnortError, match="Unable to find the snort binary"):
                s_engine.Snort(dirn, binpath="/nonexistent/snort").writeConf()

    async def test_no_snort(self):
        with self.getTestDir() as dirn:
            snort = s_engine.Snort(
                dirn,
                binpath="/nonexistent/snort",
                s2lpath="/nonexistent/snort2lua",
                conf=os.path.join(dirn, "x.lua"),
            )
            assert not snort.available()
            with pytest.raises(s_engine.SnortError, match="Unable to (run|find)"):
                await snort.version()
            with pytest.raises(s_engine.SnortError, match="Unable to (run|find)"):
                await snort.convert({"a": "alert tcp any any -> any any (sid:1;)"})


@needsnort
class TestSnort(s_tests.SynTest):
    async def test_version(self):
        with self.getTestDir() as dirn:
            vers = await s_engine.Snort(dirn).version()
            assert vers.startswith("3.")

    async def test_validate(self):
        with self.getTestDir() as dirn:
            snort = s_engine.Snort(dirn)
            rules = rulesByKey(SNORT3_RULES)
            rules["unbalanced"] = (
                'alert tcp any any -> any any ( msg:"x"; content:"abc; sid:1000010; )'
            )
            rules["pcre"] = 'alert tcp any any -> any any ( msg:"x"; pcre:"/(abc/"; sid:1000011; )'

            path = os.path.join(dirn, "test.rules")
            valid, errors = await snort.validate(rules, path)
            assert valid == ["1000001", "1000002", "1000003", "1000006"]
            assert set(errors) == {"1000005", "unbalanced", "pcre"}
            assert "foobar" in errors["1000005"]
            assert "unterminated" in errors["unbalanced"]
            assert "pcre" in errors["pcre"]
            with open(path) as fd:
                assert len(fd.read().splitlines()) == 4

            assert await snort.validate({}, path) == ([], {})

    async def test_validate_conf_error(self):
        with self.getTestDir() as dirn:
            base = os.path.join(dirn, "bad.lua")
            with open(base, "w") as fd:
                fd.write("HOME_NET = 'any'\nEXTERNAL_NET = 'any'\nthis is not lua\n")
            snort = s_engine.Snort(dirn, conf=base)
            with pytest.raises(s_engine.SnortError, match="failed to load"):
                await snort.validate(rulesByKey(SNORT3_RULES), os.path.join(dirn, "x.rules"))

    async def test_convert(self):
        with self.getTestDir() as dirn:
            snort = s_engine.Snort(dirn)
            rules = rulesByKey(SNORT2_RULES)
            rules["bad"] = (
                'alert tcp any any -> any any (msg:"x"; content:"a"; fast_pattern; isdataat:!1,relative; fast_pattern; sid:2000010;)'
            )
            rules["unparsable"] = "not a rule"
            converted, errors = await snort.convert(rules)
            assert set(converted) == {"2000001", "2000002"}
            assert "http_header;" in converted["2000002"]
            assert converted["2000002"].index("http_header") < converted["2000002"].index(
                "SlibSnortTest"
            )
            assert set(errors) == {"bad", "unparsable"}
            # snort2lua's reason.
            assert errors["bad"] == (
                "Unable to convert the Snort 2 rule to Snort 3: unknown_option=fast_pattern"
            )
            assert await snort.convert({}) == ({}, {})

    async def test_check(self):
        with self.getTestDir() as dirn:
            snort = s_engine.Snort(dirn)
            assert await snort.check('alert tcp any any -> any any ( content:"a"; sid:1; )') is None
            assert "foobar" in await snort.check(
                "alert tcp any any -> any any ( foobar:1; sid:1; )"
            )
            assert "Not a Snort rule" in await snort.check("nope")
            assert (
                await snort.check(SNORT2_RULES.splitlines()[1], engine=s_rules.ENGINE_SNORT2)
                is None
            )

    async def test_scan(self):
        with self.getTestDir() as dirn:
            snort = s_engine.Snort(dirn)
            path = os.path.join(dirn, "test.rules")
            await snort.validate(rulesByKey(SNORT3_RULES), path)

            pcap = os.path.join(dirn, "sample.pcap")
            with open(pcap, "wb") as fd:
                fd.write(pcaps.samplePcap())

            alerts = []
            assert await snort.scan(path, pcap, alerts.append) == (5, [])
            assert sorted(a["sid"] for a in alerts) == [1000001, 1000001, 1000002, 1000002, 1000003]
            udp = [a for a in alerts if a["sid"] == 1000003][0]
            assert (
                udp["proto"] == "UDP" and udp["src_addr"] == "10.1.1.10" and udp["dst_port"] == 9999
            )
            assert udp["seconds"] == 1790856000 and udp["msg"] == "SLIB TEST UDP ping"

            bad = os.path.join(dirn, "bad.pcap")
            with open(bad, "wb") as fd:
                fd.write(b"\xd4\xc3\xb2\xa1garbage")
            with pytest.raises(s_engine.SnortError, match="failed to read the PCAP"):
                await snort.scan(path, bad, alerts.append)

            # A truncated PCAP returns the alerts for the packets Snort read, with a warning.
            trunc = os.path.join(dirn, "trunc.pcap")
            with open(trunc, "wb") as fd:
                fd.write(pcaps.samplePcap()[:-30])
            alerts = []
            count, warnings = await snort.scan(path, trunc, alerts.append)
            assert count == 4 and len(warnings) == 1 and "truncated" in warnings[0]
