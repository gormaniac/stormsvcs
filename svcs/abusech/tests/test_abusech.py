"""Pytests for the slib.abusech service's HTTP client, normalization, and Cell/Telepath methods."""

import asyncio
import json

import aiohttp
import synapse.tests.utils as s_tests

from abusechsvc import norm
from abusechsvc.client import (
    AbuseChApiError,
    AbuseChClient,
    NoApiKeyError,
    RateLimiter,
    errMesg,
    isNotFound,
    normForm,
    normJson,
    statusMesg,
    unzip,
)

from . import fakeabusech as fake_data
from .fakeabusech import FakeAbuseCh, abusechSvc, mkzip


SHA256 = fake_data.SHA256
MD5 = fake_data.MD5


# (AbuseChSvc method, args, kwargs, HTTP method, path, query/field to check, expected values)
# Each entry checks the request the service sent to the fake abuse.ch server.
FORM_ENDPOINTS = (
    ("bazaarInfo", (SHA256,), {}, "/bazaar", {"query": "get_info", "hash": SHA256}),
    ("bazaarSearch", ("tag", "exe"), {"limit": 5}, "/bazaar", {"query": "get_taginfo", "tag": "exe", "limit": "5"}),
    ("bazaarSearch", ("signature", "Emotet"), {}, "/bazaar", {"query": "get_siginfo", "signature": "Emotet", "limit": "100"}),
    ("bazaarSearch", ("filetype", "exe"), {}, "/bazaar", {"query": "get_file_type", "file_type": "exe"}),
    ("bazaarSearch", ("clamav", "Win.Trojan"), {}, "/bazaar", {"query": "get_clamavinfo", "clamav": "Win.Trojan"}),
    ("bazaarSearch", ("imphash", "abc"), {}, "/bazaar", {"query": "get_imphash", "imphash": "abc"}),
    ("bazaarSearch", ("tlsh", "T1"), {}, "/bazaar", {"query": "get_tlsh", "tlsh": "T1"}),
    ("bazaarSearch", ("telfhash", "t1"), {}, "/bazaar", {"query": "get_telfhash", "telfhash": "t1"}),
    ("bazaarSearch", ("gimphash", "g1"), {}, "/bazaar", {"query": "get_gimphash", "gimphash": "g1"}),
    ("bazaarSearch", ("dhash", "d1"), {}, "/bazaar", {"query": "get_dhash_icon", "dhash_icon": "d1"}),
    ("bazaarSearch", ("yara", "rule1"), {"limit": 5000}, "/bazaar", {"query": "get_yarainfo", "yara_rule": "rule1", "limit": "1000"}),
    ("bazaarSearch", ("issuer", "CA"), {}, "/bazaar", {"query": "get_issuerinfo", "issuer_cn": "CA"}),
    ("bazaarSearch", ("subject", "Corp"), {}, "/bazaar", {"query": "get_subjectinfo", "subject_cn": "Corp"}),
    ("bazaarRecent", ("100",), {}, "/bazaar", {"query": "get_recent", "selector": "100"}),
    ("bazaarCscb", (), {}, "/bazaar", {"query": "get_cscb"}),
    ("bazaarUpdate", (SHA256, "add_tag", "x"), {}, "/bazaar", {"query": "update", "sha256_hash": SHA256, "key": "add_tag", "value": "x"}),
    ("bazaarSearch", ("serial", "0a1b2c3d"), {}, "/bazaar", {"query": "get_certificate", "serial_number": "0a1b2c3d"}),
    ("bazaarDetections", (500,), {}, "/bazaar", {"query": "recent_detections", "hours": "168"}),
    ("bazaarComment", (SHA256, "hi"), {}, "/bazaar", {"query": "add_comment", "sha256_hash": SHA256, "comment": "hi"}),
    ("urlhausUrl", ("http://a.com/x",), {}, "/urlhaus/url/", {"url": "http://a.com/x"}),
    ("urlhausUrlId", (105821,), {}, "/urlhaus/urlid/", {"urlid": "105821"}),
    ("urlhausHost", ("1.2.3.4",), {}, "/urlhaus/host/", {"host": "1.2.3.4"}),
    ("urlhausPayload", (MD5,), {}, "/urlhaus/payload/", {"md5_hash": MD5}),
    ("urlhausPayload", (SHA256,), {}, "/urlhaus/payload/", {"sha256_hash": SHA256}),
    ("urlhausTag", ("Mozi",), {}, "/urlhaus/tag/", {"tag": "Mozi"}),
    ("urlhausSignature", ("Mozi",), {}, "/urlhaus/signature/", {"signature": "Mozi"}),
)

JSON_ENDPOINTS = (
    ("threatfoxRecent", (30,), {}, "/threatfox", {"query": "get_iocs", "days": 7}),
    ("threatfoxIoc", ("41",), {}, "/threatfox", {"query": "ioc", "id": 41}),
    ("threatfoxSearch", ("gaga.com",), {"exact": True}, "/threatfox", {"query": "search_ioc", "search_term": "gaga.com", "exact_match": True}),
    ("threatfoxHash", (SHA256,), {}, "/threatfox", {"query": "search_hash", "hash": SHA256}),
    ("threatfoxTag", ("Emotet",), {"limit": 10}, "/threatfox", {"query": "taginfo", "tag": "Emotet", "limit": 10}),
    ("threatfoxMalware", ("win.dridex",), {}, "/threatfox", {"query": "malwareinfo", "malware": "win.dridex", "limit": 100}),
    ("threatfoxTypes", (), {}, "/threatfox", {"query": "types"}),
    ("threatfoxTagList", (), {}, "/threatfox", {"query": "tag_list"}),
    ("threatfoxMalwareList", (), {}, "/threatfox", {"query": "malware_list"}),
    ("threatfoxLabel", ("cobalt",), {"platform": "win"}, "/threatfox", {"query": "get_label", "malware": "cobalt", "platform": "win"}),
    ("threatfoxSubmit", ("botnet_cc", "domain", "win.dridex", ["a.com"]), {"confidence": 150, "tags": ["x"]}, "/threatfox",
     {"query": "submit_ioc", "threat_type": "botnet_cc", "ioc_type": "domain", "malware": "win.dridex", "iocs": ["a.com"],
      "confidence_level": 100, "tags": ["x"], "anonymous": 0, "is_compromised": False}),
    ("yaraifyHash", (SHA256,), {"malpedia": "tok"}, "/yaraify", {"query": "lookup_hash", "search_term": SHA256, "malpedia-token": "tok"}),
    ("yaraifySearch", ("yara", "Rule"), {"limit": 5}, "/yaraify", {"query": "get_yara", "search_term": "Rule", "result_max": 5}),
    ("yaraifySearch", ("yara", "Rule"), {"limit": 5000}, "/yaraify", {"query": "get_yara", "result_max": 1000}),
    ("yaraifySearch", ("clamav", "Sig"), {}, "/yaraify", {"query": "get_clamav", "search_term": "Sig"}),
    ("yaraifySearch", ("imphash", "x"), {}, "/yaraify", {"query": "get_imphash"}),
    ("yaraifySearch", ("gimphash", "x"), {}, "/yaraify", {"query": "get_gimphash"}),
    ("yaraifySearch", ("dhash", "x"), {}, "/yaraify", {"query": "get_dhash_icon"}),
    ("yaraifySearch", ("tlsh", "x"), {}, "/yaraify", {"query": "get_tlsh"}),
    ("yaraifySearch", ("telfhash", "x"), {}, "/yaraify", {"query": "get_telfhash"}),
    ("yaraifyRecentRules", (), {}, "/yaraify", {"query": "recent_yararules"}),
    ("yaraifyResults", ("task1",), {}, "/yaraify", {"query": "get_results", "task_id": "task1"}),
    ("yaraifyTasks", ("ident",), {"status": "queued"}, "/yaraify", {"query": "list_tasks", "identifier": "ident", "task_status": "queued"}),
    ("yaraifyIdentifier", (), {}, "/yaraify", {"query": "generate_identifier"}),
    ("yaraifyRescan", (SHA256,), {}, "/yaraify", {"query": "rescan_file", "hash": SHA256}),
    ("yaraifyRule", ("11111111-2222-3333-4444-555555555555",), {}, "/yaraify",
     {"query": "get_yara_rule", "uuid": "11111111-2222-3333-4444-555555555555"}),
    ("yaraifyDeployedRules", (), {}, "/yaraify", {"query": "show_deployed_yara_rules"}),
    ("yaraifyDeleteRule", ("6a6d2b48-1234-4cde-9f00-112233445566",), {}, "/yaraify",
     {"query": "delete_yara_rule", "yarahub_uuid": "6a6d2b48-1234-4cde-9f00-112233445566"}),
    ("fplist", (), {}, "/hunting", {"query": "get_fplist", "format": "json"}),
)


class TestNorm(s_tests.SynTest):
    """The normalization of abuse.ch responses (no Cortex needed)."""

    def test_helpers(self):
        assert norm.ts("2026-01-01 00:00:00 UTC") == "2026-01-01 00:00:00"
        assert norm.ts("") is None
        assert norm.ts("0") is None
        assert norm.lst(None) == []
        assert norm.lst(["a", None, ""]) == ["a"]
        assert norm.lst("a") == ["a"]
        assert norm.lst("  ") == []
        assert norm.splitList("a, b,,None") == ["a", "b"]
        assert norm.toInt("12") == 12
        assert norm.toInt("16.6%") == 16
        assert norm.toInt("x") is None
        assert norm.toFloat("1.5") == 1.5
        assert norm.toFloat(None) is None
        assert norm.toBool("true") and norm.toBool(1) and not norm.toBool("0") and not norm.toBool(None)
        assert norm.isHex("abc") and not norm.isHex("xyz") and not norm.isHex(None)
        assert norm.isHex("a" * 32, 32) and not norm.isHex("a" * 31, 32)
        assert norm.lower(" AbC ") == "abc"
        assert norm.lower("") is None

    def test_tags(self):
        assert norm.normTag("Cobalt Strike") == "cobalt_strike"
        assert norm.normTag("win.cobalt_strike") == "win_cobalt_strike"
        assert norm.normTag("32-bit") == "32_bit"
        assert norm.normTag("!!!") is None
        assert norm.normTag(None) is None
        assert norm.normTags("Emotet,exe, Emotet") == ["emotet", "exe"]
        assert norm.normTags(["A B", None]) == ["a_b"]

    def test_verdict(self):
        assert norm.verdict("Malicious activity") == 40
        assert norm.verdict("MALICIOUS") == 40
        assert norm.verdict("suspicious") == 30
        assert norm.verdict("No threats detected") == 10
        assert norm.verdict("whatever") is None
        assert norm.verdict(None) is None
        assert norm.verdict(True) == 40
        assert norm.verdict(False) == 10
        assert norm.verdict(80) == 40
        assert norm.verdict(50) == 30
        assert norm.verdict(10) == 20
        assert norm.verdict(0) == 10

    def test_observable(self):
        obs = norm.normObservable("ip:port", "1.2.3.4:443")
        assert obs == {"form": "inet:server", "valu": "1.2.3.4:443", "ip": "1.2.3.4", "ipform": "inet:ipv4", "port": 443}
        obs = norm.normObservable("ip:port", "[2001:db8::1]:8443")
        assert obs["ip"] == "2001:db8::1" and obs["ipform"] == "inet:ipv6" and obs["port"] == 8443
        assert norm.normObservable("ip:port", "1.2.3.4:x") is None
        assert norm.normObservable("domain", "Evil.COM.")["valu"] == "evil.com"
        assert norm.normObservable("url", "http://a.com/x")["form"] == "inet:url"
        assert norm.normObservable("md5_hash", "A" * 32) == {"form": "file:bytes", "valu": "a" * 32, "hashes": {"md5": "a" * 32}}
        assert norm.normObservable("sha256_hash", "a" * 64)["hashes"] == {"sha256": "a" * 64}
        assert norm.normObservable("sha1_hash", "a" * 40)["hashes"] == {"sha1": "a" * 40}
        assert norm.normObservable("sha3_384_hash", "a" * 96)["hashes"] == {"sha3_384": "a" * 96}
        assert norm.normObservable("md5_hash", "a" * 10) is None
        assert norm.normObservable("ip", "1.2.3.4")["form"] == "inet:ipv4"
        assert norm.normObservable("ip", "2001:db8::1")["form"] == "inet:ipv6"
        assert norm.normObservable("email", "A@B.com") == {"form": "inet:email", "valu": "a@b.com"}
        assert norm.normObservable("ja3", "a" * 32) == {"form": "hash:md5", "valu": "a" * 32}
        assert norm.normObservable("weird", "x") is None
        assert norm.normObservable("url", None) is None
        # Guessing the type from the value.
        assert norm.normObservable(None, "http://a.com")["form"] == "inet:url"
        assert norm.normObservable(None, "1.2.3.4:80")["form"] == "inet:server"
        assert norm.normObservable(None, "1.2.3.4")["form"] == "inet:ipv4"
        assert norm.normObservable(None, "a.com")["form"] == "inet:fqdn"
        assert norm.normObservable(None, "a" * 64)["form"] == "file:bytes"
        assert norm.normHost("1.2.3.4")["form"] == "inet:ipv4"
        assert norm.normHost("a.com")["form"] == "inet:fqdn"
        assert norm.normHost(None) is None

    def test_bazaar_sample(self):
        s = norm.normSample(fake_data.BAZAAR_INFO)
        assert s["sha256"] == SHA256 and s["md5"] == MD5 and s["sha1"] == fake_data.SHA1
        assert s["sha3_384"] == fake_data.SHA3
        assert s["size"] == 1234567
        assert s["name"] == "invoice.exe" and s["names"] == ["invoice.exe"]
        assert s["mime"] == "application/x-dosexec"
        assert s["type"] == "exe"
        assert s["first_seen"] == "2026-10-01 12:00:00" and s["last_seen"] == "2026-10-02 08:30:00"
        assert s["signature"] == "AgentTesla"
        assert s["families"] == ["agenttesla", "guloader"]
        assert s["tags"] == ["agenttesla", "exe"]
        assert s["reporter"] == "abuse_ch"
        assert s["origin_country"] == "de"
        assert s["delivery_method"] == "email_attachment"
        assert s["imphash"] == "f34d5f2d4577ed6d9ceec516c1f5a744"
        assert s["tlsh"] == "t1a2b3c4d5e6f7"
        assert s["ssdeep"] == "24576:abcdefg:hijklmn"
        assert s["dhash_icon"] == "e8e8b2b2b2b2e8e8"
        assert s["telfhash"] is None and s["gimphash"] is None
        assert s["clamav"] == ["Win.Trojan.AgentTesla-1234"]

        assert s["rules"] == [{
            "name": "AgentTesla_Strings", "uuid": None, "author": "abuse.ch", "desc": "Detects AgentTesla",
            "url": "https://bazaar.abuse.ch/browse/signature/AgentTesla/", "date": None, "time": None, "tlp": None,
            "sharing_tlp": None, "refmd5": None, "license": None, "family": None, "text": None,
        }]

        cert = s["certs"][0]
        assert cert["sha256"] == "b" * 64 and cert["serial"] == "00c8f5d1e1a2b3c4d5"
        assert cert["subject"] == "Evil Corp LLC" and cert["issuer"] == "Sectigo RSA Code Signing CA"
        assert cert["notbefore"] == "2026-01-01 00:00:00" and cert["notafter"] == "2027-01-01 00:00:00"
        assert cert["blocklisted"] is True and cert["reason"] == "Used to sign AgentTesla"

        # Every vendor in the live vendor_intel has its own reader.
        scans = {sc["vendor"]: sc for sc in s["scans"]}
        assert set(scans) == {"any.run", "triage", "reversinglabs", "unpacme", "yoroi_yomi", "spamhaus_hbl",
                              "filescan-io", "cape", "cert-pl_mwdb", "kaspersky", "docguard"}
        assert scans["any.run"]["signame"] == "agenttesla"
        assert scans["any.run"]["verdict"] == 40
        assert scans["any.run"]["link"] == "https://app.any.run/tasks/1234"
        assert scans["any.run"]["time"] == "2026-10-01 12:05:00"
        assert "trojan" in scans["any.run"]["categories"]
        # Triage scores are 1-10.
        assert scans["triage"]["score"] == 100.0 and scans["triage"]["verdict"] == 40
        assert "AgentTesla" in scans["triage"]["categories"] and "Reads local data" in scans["triage"]["categories"]
        assert scans["triage"]["c2s"] == [
            {"c2": "c2.example.org:587", "obs": {"form": "inet:fqdn", "valu": "c2.example.org"},
             "host": "c2.example.org", "port": 587, "url": "tcp://c2.example.org:587",
             "family": "agenttesla", "family_tag": "agenttesla"},
            {"c2": "9.8.7.6:2929", "obs": {"form": "inet:server", "valu": "9.8.7.6:2929", "ip": "9.8.7.6",
                                           "ipform": "inet:ipv4", "port": 2929},
             "host": "9.8.7.6", "port": 2929, "url": "tcp://9.8.7.6:2929",
             "family": "agenttesla", "family_tag": "agenttesla"},
        ]
        assert scans["reversinglabs"]["signame"] == "Win32.Trojan.AgentTesla"
        assert scans["reversinglabs"]["count"] == 50 and scans["reversinglabs"]["malicious"] == 40
        assert scans["reversinglabs"]["verdict"] == 40 and scans["reversinglabs"]["time"] == "2026-10-01 12:00:00"
        # UnpacMe lists the sample itself, which isn't a child of itself.
        assert scans["unpacme"]["children"] == [
            {"sha256": fake_data.UNPACKED, "md5": "9" * 32, "sha1": "8" * 40, "families": ["agenttesla"]},
        ]
        assert scans["unpacme"]["verdict"] == 40
        # Verdicts that aren't detections: "Legit File", "suspicious", "NO_THREAT", and 0-1 scores.
        assert scans["yoroi_yomi"]["verdict"] == 10 and scans["yoroi_yomi"]["signame"] is None
        assert scans["yoroi_yomi"]["score"] == 10.0
        assert scans["spamhaus_hbl"]["verdict"] == 30 and scans["spamhaus_hbl"]["signame"] is None
        assert scans["filescan-io"]["verdict"] == 10 and scans["filescan-io"]["score"] == 0.0
        assert scans["cape"]["signame"] == "AgentTesla" and scans["cape"]["verdict"] == 40
        assert scans["cert-pl_mwdb"]["signame"] is None and scans["cert-pl_mwdb"]["verdict"] is None
        assert scans["cert-pl_mwdb"]["link"] == "https://mwdb.cert.pl/sample/x/"
        assert scans["kaspersky"]["verdict"] == 40 and scans["kaspersky"]["time"] == "2026-10-01T12:00:00"
        assert scans["docguard"]["verdict"] == 40 and scans["docguard"]["urls"] == ["http://docguard.example.net/payload.bin"]
        assert scans["docguard"]["categories"] == ["JS File - Malicious"]

        assert s["attrs"] == ["magika.pebin", "format.pe", "arch.amd64", "ole.encrypted", "ole.vba_macros"]

        assert s["links"] == [{"context": "twitter", "url": "https://twitter.com/abuse_ch/status/1"}]
        assert s["related"] == [{"rel": "dropped_by", "sha256": fake_data.DROPPER}]
        assert s["notes"] == [
            "comment: Seen in a phishing campaign",
            "trid: 44.6% (.EXE) Win64 Executable (generic) (6522/11/2)",
            "ole: format: MS Excel 97-2003, container: OLE, application: Microsoft Excel, maldoc score: 9",
            "olevba Suspicious: Hex Strings - Hex-encoded strings were detected",
        ]
        assert [c["text"] for c in s["comments"]] == ["Delivered via a fake invoice.", "Confirmed AgentTesla."]
        assert s["comments"][1] == {"id": "1", "time": "2026-10-01 13:00:00", "author": "Analyst",
                                    "text": "Confirmed AgentTesla."}

    def test_sample_edges(self):
        assert norm.normSample({"file_name": "x"}) is None
        assert norm.normSample("nope") is None
        assert norm.normSamples([{"md5_hash": "a" * 32}, {}]) == [{**norm.emptySample(), "md5": "a" * 32}]

        # Anonymous reporters, "n/a" values, and the CSV export's columns.
        s = norm.normSample({"sha256_hash": "a" * 64, "reporter": "anonymous", "file_name": "n/a",
                             "signature": "n/a", "imphash": "n/a", "vtpercent": "10.5", "clamav": "A, B",
                             "file_type_guess": "exe", "mime_type": "application/zip", "first_seen_utc": "2026-01-01"})
        assert s["reporter"] is None and s["name"] is None and s["signature"] is None and s["imphash"] is None
        assert s["clamav"] == ["A", "B"]
        assert s["type"] == "exe" and s["mime"] == "application/zip" and s["first_seen"] == "2026-01-01"
        assert s["scans"][0]["vendor"] == "virustotal" and s["scans"][0]["verdict"] == 40

        s = norm.normSample({"md5_hash": "a" * 32, "reporter": "x", "anonymous": 1, "imphash": "notahash",
                             "ole_information": [], "comments": ["plain"], "file_name": "na",
                             "tlsh": "a" * 70})
        assert s["reporter"] is None and s["imphash"] is None and s["notes"] == [] and s["name"] is None
        # TLSHs are always versioned, some endpoints drop the T1.
        assert s["tlsh"] == "t1" + "a" * 70
        assert norm.normTlsh("T1" + "A" * 70) == "T1" + "A" * 70
        assert s["comments"] == [{"id": None, "time": None, "author": None, "text": "plain"}]

        info = norm.normFileInfo([{"context": "dropping_md5", "value": "a" * 32}, {"context": "x", "value": None}, "bad"])
        assert info["related"] == [{"rel": "dropping", "md5": "a" * 32}]
        assert norm.normVendors(None) == [] and norm.normVendors({"x": ["bad", {}]}) == []

        # Triage's 1-10 scale, Intezer's verdict and family, and vendors MalwareBazaar adds later.
        assert [norm.normVendors({"Triage": {"score": str(n)}})[0]["verdict"] for n in (9, 7, 3)] == [40, 30, 10]
        assert norm.normVendors({"Triage": {"score": None}})[0]["verdict"] is None
        sc = norm.normVendors({"Intezer": {"verdict": "suspicious", "family_name": "RustDesk"}})[0]
        assert sc["signame"] == "RustDesk" and sc["verdict"] == 30
        sc = norm.normVendors({"Intezer": {"family_name": {"name": "Emotet"}}})[0]
        assert sc["signame"] == "Emotet" and sc["verdict"] == 40
        sc = norm.normVendors({"NewVendor": {"malware_family": "Fam1", "verdict": "Odd", "link": "https://x/1"}})[0]
        assert sc["vendor"] == "newvendor" and sc["signame"] == "Fam1" and sc["verdict"] == 40
        assert sc["link"] == "https://x/1"
        assert norm.normVendors({"Kaspersky": {"verdict": "NotCategorized", "detections": [{"detection_name": "HEUR:x"}]}})[0]["signame"] == "HEUR:x"
        assert norm.normC2Config({"c2": "http://a.com/gate.php"})["url"] is None
        assert norm.normC2Config({"c2": ""}) is None and norm.normC2Config("x") is None
        assert norm.normC2Config({"c2": "a" * 64}) is None
        assert norm.normOle(None) == {"attrs": [], "notes": []}

    def test_certs_rules(self):
        cert = norm.normCert(fake_data.CSCB[0], blocklist=True)
        assert cert["sha256"] == "1" * 64 and cert["serial"] == "0a1b2c3d" and cert["blocklisted"]
        assert cert["time"] == "2026-09-01 10:00:00" and cert["reason"] == "Malware signing (Emotet)"
        assert norm.normCert({"thumbprint": "a" * 40})["sha1"] == "a" * 40
        assert norm.normCert({"serial_number": "AA:BB"})["serial"] == "aabb"
        assert norm.normCert({"subject_cn": "x"}) is None
        assert norm.normCert("x") is None
        assert not norm.normCert({"serial_number": "aa", "cscb_listed": False})["blocklisted"]

        rule = norm.normRule({"rule_name": " r1 ", "reference": "ditekSHen", "description": "d"})
        assert rule["url"] is None and rule["desc"] == "d\n\nReference: ditekSHen"
        assert norm.normRule({"rule_name": "r", "reference": "ditekSHen"})["desc"] == "Reference: ditekSHen"
        # Matches of non-public rules are masked as "xxx".
        assert norm.normRule({"rule_name": "xxx", "yarahub_uuid": "xxx"}) is None
        assert norm.normRule({"rule_name": "r", "yarahub_uuid": "xxx"})["uuid"] is None
        rule = norm.normRule(fake_data.YARAIFY_RECENT_RULES[1] | {"yarahub_reference_md5": "A" * 32})
        assert rule["sharing_tlp"] == "red" and rule["refmd5"] == "a" * 32
        assert norm.normYaraStats(fake_data.BAZAAR_YARA_STATS)[0] == {
            "name": "unixredflags3", "uuid": None, "author": "Tim Brown @timb_machine", "desc": "Hunts for UNIX red flags",
            "url": None, "date": None, "time": "2026-10-31 04:27:16", "tlp": None, "sharing_tlp": None, "refmd5": None,
            "license": None, "family": None, "text": None}
        assert norm.normRule({"author": "x"}) is None
        assert norm.normRule("x") is None
        assert norm.normRules([{"rule_name": "a"}, None]) == [norm.normRule({"rule_name": "a"})]

        rules = norm.parseYara(fake_data.YARA_RULE_TEXT)
        assert [r["name"] for r in rules] == ["win_agent_tesla_auto", "helper_rule"]
        assert rules[0]["author"] == "Felix Bilstein"
        assert rules[0]["desc"] == "Detects win.agent_tesla."
        assert rules[0]["uuid"] == "6a6d2b48-1234-4cde-9f00-112233445566"
        assert rules[0]["url"] == "https://malpedia.caad.fkie.fraunhofer.de/details/win.agent_tesla"
        assert rules[0]["family"] == "win.agent_tesla"
        assert rules[0]["text"].startswith("rule win_agent_tesla_auto {") and rules[0]["text"].endswith("}")
        assert rules[1]["text"].startswith("private rule helper_rule")
        assert norm.parseYara("no rules here") == []

    def test_yaraify(self):
        f = norm.normYaraifyFile(fake_data.YARAIFY_FILE)
        assert f["sha256"] == SHA256 and f["sha3_384"] == fake_data.SHA3 and f["gimphash"] == "abcdef0123"
        assert f["names"] == ["invoice.exe", "invoice2.exe"]
        assert [r["name"] for r in f["rules"]] == ["win_agent_tesla_auto"]
        rule = f["rules"][0]
        assert rule["tlp"] == "white" and rule["license"] == "CC BY-NC 4.0" and rule["family"] == "win.agent_tesla"
        assert rule["uuid"] == "6a6d2b48-1234-4cde-9f00-112233445566"
        assert f["clamav"] == ["Win.Packed.Generic-1"]
        # The masked "xxx" match is dropped.
        assert f["unpacked"] == [{"sha256": fake_data.UNPACKED, "md5": "9" * 32, "name": "unpacked.bin",
                                  "rules": [norm.normRule({"rule_name": "AgentTesla_Unpacked", "author": "abuse.ch"})]}]
        assert f["tasks"] == ["cfa49f83-6d98-11ed-a71a-42010aa4000b"]
        assert norm.normYaraifyFile("x") is None
        assert norm.normYaraifyFile({"metadata": {}}) is None

        # get_results puts the task's results at the top level.
        f = norm.normYaraifyFile(fake_data.YARAIFY_RESULTS)
        assert f["sha256"] == SHA256 and [r["name"] for r in f["rules"]] == ["win_agent_tesla_auto"]
        assert f["clamav"] == ["Win.Packed.Generic-1"] and f["unpacked"][0]["sha256"] == fake_data.UNPACKED
        task = norm.normTask(fake_data.YARAIFY_RESULTS)
        assert task["clamav_scan"] is True and task["unpack"] is True and task["share_file"] is False

        task = norm.normTask(dict(fake_data.YARAIFY_FILE["tasks"][0], sha256_hash=SHA256))
        assert task["sha256"] == SHA256 and task["clamav_scan"] and task["unpack"] and task["share_file"]
        assert task["time"] == "2026-10-01 12:00:00"
        # list_tasks rows don't include the task parameters, so they aren't made up.
        task = norm.normTask({"task_id": "t", "sha256_hash": SHA256, "md5_hash": MD5.upper(), "task_status": "processed"})
        assert task["md5"] == MD5 and task["clamav_scan"] is None and task["unpack"] is None
        assert task["status"] == "processed"
        assert norm.normTask("x") is None
        task = norm.normTask({"unpacked_results": [{"unpacked_sha256": "bad"}, "x"]})
        assert task["unpacked"] == [] and task["sample"] is None

    def test_urlhaus(self):
        u = norm.normUrl(fake_data.URLHAUS_URL)
        assert u["id"] == "105821" and u["url"] == "http://evil.example.com/bins/mozi.m"
        assert u["status"] == "online" and u["threat"] == "malware_download"
        assert u["host"] == {"form": "inet:fqdn", "valu": "evil.example.com"}
        assert u["added"] == "2026-10-01 10:00:00" and u["last_online"] == "2026-10-03 10:00:00"
        assert u["tags"] == ["elf", "mozi"] and u["reporter"] == "lrz_urlhaus" and u["larted"]
        assert u["reference"] == "https://urlhaus.abuse.ch/url/105821/"
        assert u["blacklists"] == ["spamhaus_dbl.abused_legit_malware"]
        pay = u["payloads"][0]
        assert pay["sha256"] == fake_data.PAYLOAD and pay["md5"] == fake_data.PAYLOAD_MD5
        assert pay["size"] == 307960 and pay["name"] == "mozi.m" and pay["type"] == "elf"
        assert pay["families"] == ["mozi"] and pay["seen"] == "2026-10-01" and pay["magika"] == "elf"
        vt = pay["scans"][0]
        assert vt["vendor"] == "virustotal" and vt["count"] == 60 and vt["malicious"] == 10 and vt["verdict"] == 40
        assert vt["link"] == "https://www.virustotal.com/gui/file/x"
        assert norm.normUrl({"id": 1}) is None

        h = norm.normUrlhausHost(fake_data.URLHAUS_HOST)
        assert h["host"] == {"form": "inet:ipv4", "valu": "1.2.3.4"} and h["url_count"] == 1
        assert h["blacklists"] == [] and h["urls"][0]["reporter"] is None and h["urls"][0]["takedown"] == 3600
        assert norm.normUrlhausHost({}) is None

        p = norm.normUrlhausPayload(fake_data.URLHAUS_PAYLOAD)
        assert p["sha256"] == fake_data.PAYLOAD and p["last_seen"] == "2026-10-03 10:00:00"
        assert p["urls"][0]["url"] == "http://evil.example.com/bins/mozi.m" and p["urls"][0]["seen"] == "2026-10-01"
        # The filename is only on each URL, and those dates are the payload's on the URL, not the URL's.
        assert p["names"] == ["mozi.m"] and p["name"] == "mozi.m"
        assert p["urls"][0]["added"] is None and p["urls"][0]["last_online"] is None
        assert norm.normUrlhausPayload({}) is None

        # Signature lookups attach the payload to each URL, dated on that URL.
        u = norm.normUrls(fake_data.URLHAUS_SIGNATURE["urls"])[0]
        assert u["payloads"][0]["sha256"] == fake_data.PAYLOAD
        assert u["payloads"][0]["scans"][0]["verdict"] == 10
        assert u["added"] is None and u["payloads"][0]["seen"] == "2026-10-01 10:00:00"

        u = norm.normUrlhausPayloadRow(norm.parseCsv(fake_data.URLHAUS_PAYLOAD_CSV, norm.URLHAUS_PAYLOAD_CSV)[0])
        assert u["url"] == "http://evil.example.com/bins/mozi.m" and u["payloads"][0]["sha256"] == fake_data.PAYLOAD
        assert u["payloads"][0]["type"] == "elf" and u["payloads"][0]["seen"] == "2026-10-01 10:00:00"
        assert norm.normUrlhausPayloadRow({"url": None}) is None

        assert norm.normBlacklists(None) == []
        assert norm.normVirusTotal(None) is None
        assert norm.normVirusTotal({"result": None})["verdict"] is None

    def test_threatfox(self):
        i = norm.normIoc(fake_data.THREATFOX_IOC)
        assert i["id"] == "41" and i["ioc"] == "gaga.com" and i["ioc_type"] == "domain"
        assert i["threat_type"] == "botnet_cc" and i["malware"] == "win.dridex"
        assert i["family"] == "Dridex" and i["family_tag"] == "dridex" and i["aliases"] == []
        assert i["confidence"] == 50 and i["first_seen"] == "2026-10-01 07:00:00" and i["last_seen"] is None
        assert i["reference"] == "https://twitter.com/abuse_ch/status/2" and i["reporter"] == "abuse_ch"
        assert i["tags"] == ["exe", "test"] and i["comment"] == "Dridex C2 seen in the wild."
        assert i["credits"] == [{"from": "abuse_ch", "amount": 5}]
        assert i["obs"] == {"form": "inet:fqdn", "valu": "gaga.com"}
        assert i["pattern"] == "[domain-name:value = 'gaga.com']"
        assert i["samples"][0]["sha256"] == SHA256 and i["samples"][0]["seen"] == "2026-10-01 07:00:00"
        # The sample's time and MalwareBazaar link are kept.
        assert i["samples"][0]["first_seen"] == "2026-10-01 07:00:00"
        assert i["samples"][0]["links"] == [{"context": "malware_bazaar", "url": f"https://bazaar.abuse.ch/sample/{SHA256}/"}]
        assert i["sightings"] is None and norm.normIoc(dict(fake_data.THREATFOX_IOC, sightings=3))["sightings"] == 3

        i = norm.normIoc(fake_data.THREATFOX_IPPORT)
        assert i["aliases"] == ["Agentemis", "BEACON", "CobaltStrike"] and i["reporter"] is None
        assert i["obs"]["form"] == "inet:server" and i["obs"]["port"] == 443
        assert i["pattern"] == ("[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = "
                                "'5.6.7.8' AND network-traffic:dst_port = 443]")
        assert norm.normIoc(fake_data.THREATFOX_HASH)["pattern"] == f"[file:hashes.'SHA-256' = '{SHA256}']"
        assert norm.normIoc(fake_data.THREATFOX_URL)["pattern"] == "[url:value = 'http://c2.example.org/gate.php']"
        assert norm.stixPattern("weird", "x", None) is None
        assert norm.stixPattern("url", "http://a/'x", None) == "[url:value = 'http://a/\\'x']"
        assert norm.normIoc({"ioc": "x"}) is None
        assert norm.normIoc("x") is None
        for placeholder in ("Unknown malware", "Unknown Stealer", "Unknown Loader", "Unknown RAT", "None"):
            i = norm.normIoc({"ioc": "a.com", "ioc_type": "domain", "malware_printable": placeholder})
            assert i["family"] is None and i["family_tag"] is None, placeholder
        assert norm.normIoc({"ioc": "a.com", "ioc_type": "domain", "malware_printable": "UnknownFamily"})["family"] == "UnknownFamily"
        i = norm.normIoc({"ioc": "a@b.com", "ioc_type": "envelope_from"})
        assert i["obs"] == {"form": "inet:email", "valu": "a@b.com"}
        assert i["pattern"] == "[email-message:sender_ref.value = 'a@b.com']"
        assert norm.normIoc({"ioc": "a@b.com", "ioc_type": "body_from"})["pattern"] == "[email-message:from_ref.value = 'a@b.com']"
        assert norm.normIoc({"ioc": "a" * 96, "ioc_type": "sha3_384_hash"})["obs"]["hashes"] == {"sha3_384": "a" * 96}

        iocs = norm.normThreatFoxExport(fake_data.THREATFOX_EXPORT)
        assert len(iocs) == 1
        i = iocs[0]
        assert i["id"] == "50" and i["ioc"] == "export.example.com" and i["family"] == "QakBot"
        assert i["malware"] == "win.qakbot" and i["aliases"] == ["Qbot", "QuakBot"] and i["tags"] == ["qakbot", "ta570"]
        assert i["first_seen"] == "2026-10-01 00:00:00" and i["reporter"] == "abuse_ch"
        assert norm.normThreatFoxExport([fake_data.THREATFOX_IOC])[0]["id"] == "41"

    def test_blocklists(self):
        c2 = norm.normFeodo(fake_data.FEODO_JSON[0])
        assert c2 == {
            "ip": "50.16.16.211", "ipform": "inet:ipv4", "port": 8080, "family": "QakBot", "family_tag": "qakbot",
            "status": "online", "first_seen": "2026-08-01 00:00:00", "last_online": "2026-10-01",
            "hostname": "ec2.example.com", "asn": 14618, "as_name": "AMAZON-AES", "country": "us", "source": "feodo",
        }
        rows = norm.parseCsv(fake_data.FEODO_AGGRESSIVE, norm.FEODO_CSV)
        assert rows == [{"first_seen_utc": "2026-01-01 00:00:00", "dst_ip": "80.1.2.3", "dst_port": "447",
                         "c2_status": "offline", "last_online": "2026-02-01", "malware": "TrickBot"}]
        assert norm.normFeodo(rows[0])["port"] == 447
        assert norm.normFeodo("x") is None
        assert norm.normC2(None, 1) is None
        assert norm.normC2("a.com", 1) is None
        assert norm.normC2("1.2.3.4", None, family="unknown")["family"] is None

        certs = [norm.normSslblCert(r) for r in norm.parseCsv(fake_data.SSLBL_CERTS, norm.SSLBL_CERT_CSV)]
        assert certs[0] == {"sha1": "1" * 40, "time": "2026-10-01 00:00:00", "reason": "Dridex C&C",
                            "family": "Dridex", "family_tag": "dridex"}
        assert certs[1]["family"] == "AsyncRAT"
        assert norm.normSslblCert({"sha1": "bad"}) is None


        ja3 = [norm.normJa3(r) for r in norm.parseCsv(fake_data.SSLBL_JA3, norm.SSLBL_JA3_CSV)][0]
        assert ja3 == {"ja3": "51c64c77e60f3980eea90869b68c58a8", "first_seen": "2017-07-14 18:08:15",
                       "last_seen": "2019-07-27 20:42:54", "reason": "Dridex", "family": "Dridex", "family_tag": "dridex"}
        assert norm.normJa3({"ja3_md5": "x"}) is None
        assert norm.reasonFamily(None) is None
        assert norm.reasonFamily("C&C") is None

        assert norm.parseLines("# comment\n1.2.3.4\n\n5.6.7.8\n") == ["1.2.3.4", "5.6.7.8"]

        # CSV exports with an un-commented header.
        rows = norm.parseCsv("id,url\n1,http://a\n", ("id", "url"))
        assert rows == [{"id": "1", "url": "http://a"}]

    def test_fplist(self):
        fps = norm.normFpList(fake_data.FPLIST)
        # A sample's per-hash rows are merged, and entries without a value are skipped.
        assert len(fps) == 3
        assert fps[0] == {"obs": {"form": "file:bytes", "valu": "0" * 32,
                                  "hashes": {"md5": "0" * 32, "sha1": "0" * 40, "sha256": "0" * 64, "sha3_384": "0" * 96}},
                          "time": "2026-01-01 00:00:00", "platform": "malwarebazaar", "removed_by": "admin",
                          "notes": "Legitimate installer"}
        assert fps[1]["obs"] == {"form": "inet:fqdn", "valu": "legit.example.com"}
        assert fps[2]["obs"]["hashes"] == {"sha3_384": "1" * 96}
        # Two samples removed at the same time with the same notes aren't merged.
        row = {"time_stamp": "t", "platform": "p", "entry_type": "md5", "removed_by": "a", "removal_notes": "n"}
        fps = norm.normFpList([dict(row, entry_value="a" * 32), dict(row, entry_value="b" * 32)])
        assert [f["obs"]["hashes"] for f in fps] == [{"md5": "a" * 32}, {"md5": "b" * 32}]
        assert norm.normFpList([{"entry_type": "x", "entry_value": "y"}, "bad"]) == []


class TestClient(s_tests.SynTest):
    """The abuse.ch HTTP transport."""

    def test_helpers(self):
        for status in ("no_results", "no_result", "hash_not_found", "tag_not_found", "unknown_hash", "file_not_found"):
            assert isNotFound(status), status
        for status in ("ok", "illegal_hash", None, ""):
            assert not isNotFound(status), status

        assert normForm(None) == {}
        assert normForm({"a": True, "b": False, "c": [1, 2], "d": None, "e": 5}) == {"a": "1", "b": "0", "c": "1,2", "e": "5"}
        assert normJson({"a": None, "b": 0}) == {"b": 0}
        assert normJson(None) == {}

        assert errMesg(400, {"query_status": "illegal_hash"}, "") == "illegal_hash"
        assert errMesg(400, {"query_status": "error", "data": "Too slow."}, "") == "error: Too slow."
        assert statusMesg({"query_status": "error", "data": "Query execution time exceeded threshold."}) == \
            "error: Query execution time exceeded threshold."
        assert statusMesg({"query_status": "error", "data": []}) == "error"
        assert statusMesg({"query_status": "error", "data": "<html>"}) == "error"
        assert errMesg(500, {"error": "<html>"}, "<html>") == "HTTP 500"
        assert errMesg(500, None, "Server exploded") == "Server exploded"
        assert errMesg(401, None, "") == "Invalid or missing abuse.ch Auth-Key"
        assert errMesg(502, None, "") == "HTTP 502"

    def test_unzip(self):
        byts = mkzip({"a.txt": b"hello", "b.txt": b"world"}, b"infected")
        assert unzip(byts) == [("a.txt", b"hello"), ("b.txt", b"world")]
        assert unzip(mkzip({"c": b"x"}), password=None) == [("c", b"x")]

        with self.raises(AbuseChApiError):
            unzip(b"not a zip")
        with self.raises(AbuseChApiError):
            unzip(byts, password=b"wrong")
        with self.raises(AbuseChApiError):
            unzip(byts, maxsize=2)

    async def test_ratelimit(self):
        limiter = RateLimiter(20)
        loop = asyncio.get_running_loop()
        start = loop.time()
        for _ in range(3):
            await limiter.wait()
        assert loop.time() - start >= 0.09
        await RateLimiter(0).wait()

    async def test_client(self):
        async with FakeAbuseCh() as fake, aiohttp.ClientSession() as sess:
            client = AbuseChClient(sess, urls=fake.urls, rate=0)

            with self.raises(AbuseChApiError):
                client.url("nope")
            with self.raises(NoApiKeyError):
                await client.query("bazaar", form={"query": "get_info"})

            # The datasets don't need a key.
            byts, _ = await client.fetch("feodo", "ipblocklist.json")
            assert json.loads(byts) == fake_data.FEODO_JSON
            assert fake.last()["authkey"] is None

            data = await client.query("bazaar", apikey="k", form={"query": "get_info", "hash": SHA256})
            assert data["data"][0]["sha256_hash"] == SHA256
            assert fake.last()["authkey"] == "k"
            assert await client.query("bazaar", apikey="k", form={"query": "get_info", "hash": "x"}) is None

            with self.raises(AbuseChApiError) as cm:
                await client.query("bazaar", apikey="k", form={"query": "bogus"})
            assert cm.exception.status == "unknown_query"

            fake.overrides[("bazaar", "err")] = (500, "Internal error")
            with self.raises(AbuseChApiError) as cm:
                await client.query("bazaar", apikey="k", form={"query": "err"})
            assert cm.exception.code == 500 and cm.exception.mesg == "Internal error"

            fake.overrides[("bazaar", "html")] = (200, "<html>nope</html>")
            with self.raises(AbuseChApiError):
                await client.query("bazaar", apikey="k", form={"query": "html"})

            fake.overrides[("bazaar", "empty")] = (200, "")
            assert await client.query("bazaar", apikey="k", form={"query": "empty"}) is None

            # fetch() raises JSON errors, and returns nothing for "not found".
            fake.overrides[("bazaar", "ferr")] = (200, {"query_status": "illegal_sha256_hash"})
            with self.raises(AbuseChApiError):
                await client.fetch("bazaar", method="post", apikey="k", form={"query": "ferr"})
            assert (await client.fetch("bazaar", method="post", apikey="k",
                                       form={"query": "get_file", "sha256_hash": "x"}))[0] == b""
            with self.raises(AbuseChApiError):
                await client.fetch("feodo", "missing")

            # 429s are retried.
            calls = []

            async def flaky(request):
                calls.append(1)
                if len(calls) < 2:
                    return aiohttp.web.Response(status=429)
                return aiohttp.web.json_response({"query_status": "ok", "data": []})

            fake.overrides.clear()
            orig = fake._bazaar
            fake._bazaar = lambda req, info, path, query: flaky(req)
            import abusechsvc.client as s_client
            sleep = asyncio.sleep
            s_client.asyncio.sleep = lambda secs: sleep(0)
            try:
                assert await client.query("bazaar", apikey="k", form={"query": "x"}) == {"query_status": "ok", "data": []}
            finally:
                s_client.asyncio.sleep = sleep
                fake._bazaar = orig
            assert len(calls) == 2

    async def test_client_unreachable(self):
        async with aiohttp.ClientSession() as sess:
            client = AbuseChClient(sess, urls={"feodo": "http://127.0.0.1:1"}, rate=0, timeout=5)
            with self.raises(AbuseChApiError):
                await client.fetch("feodo", "x")

    async def test_client_export_key(self):
        async with FakeAbuseCh() as fake, aiohttp.ClientSession() as sess:
            client = AbuseChClient(sess, urls=fake.urls, rate=0)
            with self.raises(NoApiKeyError):
                await client.fetch("urlhaus:export", "recent.csv")
            byts, _ = await client.fetch("urlhaus:export", "recent.csv", apikey="abc")
            assert byts.startswith(b"####")
            assert fake.last()["path"] == "/urlhaus_export/abc/recent.csv"

        async with aiohttp.ClientSession() as sess:
            client = AbuseChClient(sess, urls={"bazaar:export": "http://127.0.0.1:1/x"}, rate=0, timeout=5)
            with self.raises(AbuseChApiError) as cm:
                await client.fetch("bazaar:export", "recent.csv", apikey="secretkey")
            assert "secretkey" not in cm.exception.mesg


class TestSvc(s_tests.SynTest):
    """The AbuseChSvc methods send the right requests and normalize the responses."""

    async def test_endpoints(self):
        async with abusechSvc(self) as (core, svc, fake):
            for meth, args, kwargs, path, expect in FORM_ENDPOINTS + JSON_ENDPOINTS:
                await getattr(svc, meth)(*args, **kwargs)
                req = fake.last()
                assert req["path"].startswith(path), (meth, req["path"])
                assert req["authkey"] == "testkey", meth
                body = req["json"] if req["json"] is not None else req["form"]
                for key, valu in expect.items():
                    assert body.get(key) == valu, (meth, key, body.get(key))

            await svc.urlhausRecentUrls()
            assert fake.last()["path"] == "/urlhaus/urls/recent/" and fake.last()["method"] == "GET"
            await svc.urlhausRecentUrls(limit=3)
            assert fake.last()["path"] == "/urlhaus/urls/recent/limit/3/"
            await svc.urlhausRecentPayloads()
            assert fake.last()["path"] == "/urlhaus/payloads/recent/"
            await svc.urlhausRecentPayloads(limit=3)
            assert fake.last()["path"] == "/urlhaus/payloads/recent/limit/3/"

            assert await svc.rawRequest("threatfox", json_data={"query": "types"}) == {
                "query_status": "ok", "data": fake_data.THREATFOX_TYPES}
            await svc.rawRequest("urlhaus", "urls/recent/", method="get")
            assert fake.last()["method"] == "GET"
            assert (await svc.rawRequest("bazaar", form={"query": "get_cscb"}))["data"] == fake_data.CSCB
            with self.raises(AbuseChApiError):
                await svc.rawRequest("bazaar")
            assert fake.last()["form"] == {}
            with self.raises(AbuseChApiError):
                await svc.rawRequest("feodo")

    async def test_bazaar(self):
        async with abusechSvc(self) as (core, svc, fake):
            assert (await svc.bazaarInfo(SHA256))["sha256_hash"] == SHA256
            assert await svc.bazaarInfo("a" * 64) is None
            assert await svc.normBazaarInfo("a" * 64) is None
            assert (await svc.normBazaarInfo(SHA256))["signature"] == "AgentTesla"
            with self.raises(AbuseChApiError):
                await svc.bazaarInfo("nothex")

            assert len(await svc.normBazaarSearch("tag", "exe", limit=1)) == 1
            assert len(await svc.normBazaarSearch("tag", "exe")) == 2
            assert await svc.bazaarSearch("tag", "nothing") == []
            with self.raises(AbuseChApiError):
                await svc.bazaarSearch("bogus", "x")
            await svc.bazaarSearch("issuer", "CA", limit=5)
            assert "limit" not in fake.last()["form"]

            # MalwareBazaar doesn't look up SHA3-384s.
            with self.raises(AbuseChApiError):
                await svc.bazaarInfo(fake_data.SHA3)
            assert len(await svc.normBazaarDetections()) == 1
            assert fake.last()["form"] == {"query": "recent_detections", "hours": "48"}

            # Updates and comments on unknown samples fail instead of reporting success.
            with self.raises(AbuseChApiError) as cm:
                await svc.bazaarUpdate("a" * 64, "add_tag", "x")
            assert "hash_not_found" in cm.exception.mesg
            with self.raises(AbuseChApiError):
                await svc.bazaarComment("a" * 64, "x")
            with self.raises(AbuseChApiError):
                await svc.bazaarUpdate(SHA256, "tags", "x")

            rules = [r async for r in svc.bazaarExport("yara")]
            assert [r["name"] for r in rules] == ["unixredflags3", "pe_imphash"]
            assert fake.last()["path"] == "/bazaar_export/testkey/yara_rules.json"

            assert len(await svc.normBazaarRecent()) == 2
            assert fake.last()["form"]["selector"] == "time"
            with self.raises(AbuseChApiError):
                await svc.bazaarRecent("bogus")

            certs = await svc.normBazaarCscb()
            assert certs[0]["blocklisted"] and certs[0]["sha256"] == "1" * 64

            # Downloads are unzipped (with abuse.ch's AES zip password).
            sample = await svc.bazaarFile(fake_data.SAMPLE_SHA256)
            assert sample["bytes"] == fake_data.SAMPLE_BYTES and sample["sha256"] == fake_data.SAMPLE_SHA256
            assert sample["size"] == len(fake_data.SAMPLE_BYTES)
            assert fake.last()["form"] == {"query": "get_file", "sha256_hash": fake_data.SAMPLE_SHA256}
            assert await svc.bazaarFile("a" * 64) is None
            with self.raises(AbuseChApiError):
                await svc.bazaarFile(MD5)

            fake.overrides[("bazaar", "get_file")] = (200, b"not a zip")
            with self.raises(AbuseChApiError):
                await svc.bazaarFile("a" * 64)
            svc.maxsize = 2
            with self.raises(AbuseChApiError):
                await svc.bazaarFile("a" * 64)
            with self.raises(AbuseChApiError):
                await svc.bazaarUpload([b"abc"], "x")
            svc.maxsize = 1024
            fake.overrides.clear()

            resp = await svc.bazaarUpload([b"MZ", b"data"], "x.exe", anonymous=True, tags=["exe"],
                                          delivery_method="email_attachment", context={"comment": "hi"})
            assert resp == {"query_status": "inserted"}
            req = fake.last()
            assert req["files"]["file"] == ("x.exe", b"MZdata")
            assert json.loads(req["form"]["json_data"]) == {
                "anonymous": 1, "tags": ["exe"], "delivery_method": "email_attachment", "context": {"comment": "hi"}}
            await svc.bazaarUpload([b"MZ"], "x.exe", references={"links": "https://a/1", "any_run": ["https://b/2"]},
                                   context={"comment": "hi", "dropped_by_sha256": SHA256})
            assert json.loads(fake.last()["form"]["json_data"]) == {
                "anonymous": 0, "references": {"links": ["https://a/1"], "any_run": ["https://b/2"]},
                "context": {"comment": "hi", "dropped_by_sha256": [SHA256]}}
            fake.overrides[("bazaar", "")] = (200, {"query_status": "file_already_known"})
            fake.overrides.clear()

            rows = [s async for s in svc.bazaarExport()]
            assert [r["sha256"] for r in rows] == [SHA256, "b" * 64]
            # The exports take the Auth-Key in the URL path.
            assert fake.last()["path"] == "/bazaar_export/testkey/recent.csv"
            assert fake.last()["exportkey"] == "testkey"
            assert len([s async for s in svc.bazaarExport("full", limit=1)]) == 1
            assert fake.last()["path"] == "/bazaar_export/testkey/full.csv.zip"
            with self.raises(AbuseChApiError):
                [s async for s in svc.bazaarExport("bogus")]

    async def test_urlhaus(self):
        async with abusechSvc(self) as (core, svc, fake):
            assert (await svc.normUrlhausUrl(url=fake_data.URLHAUS_URL["url"]))["id"] == "105821"
            assert (await svc.normUrlhausUrl(urlid=105821))["id"] == "105821"
            assert await svc.normUrlhausUrl(url="http://nope") is None
            assert (await svc.normUrlhausHost("1.2.3.4"))["url_count"] == 1
            assert await svc.normUrlhausHost("9.9.9.9") is None
            # URLhaus host lookups don't support IPv6.
            with self.raises(AbuseChApiError):
                await svc.urlhausHost("2001:db8::1")
            # Signature results get the family, it's not repeated on each payload.
            res = await svc.normUrlhausSearch("signature", "Mozi")
            pay = res["urls"][0]["payloads"][0]
            assert pay["signature"] == "Mozi" and pay["families"] == ["mozi"]
            urls = [u async for u in svc.urlhausExport("payloads")]
            assert [(u["url"], u["payloads"][0]["sha256"]) for u in urls] == [(fake_data.URLHAUS_URL["url"], fake_data.PAYLOAD)]
            assert fake.last()["path"] == "/urlhaus_export/testkey/payload.csv.zip"
            assert (await svc.normUrlhausPayload(fake_data.PAYLOAD))["urls"]
            assert await svc.normUrlhausPayload("a" * 64) is None
            with self.raises(AbuseChApiError):
                await svc.urlhausPayload(fake_data.SHA1)

            res = await svc.normUrlhausSearch("tag", "Mozi", limit=1)
            assert res["url_count"] == 2 and len(res["urls"]) == 1 and res["first_seen"] == "2026-01-01 00:00:00"
            res = await svc.normUrlhausSearch("signature", "Mozi")
            assert res["payload_count"] == 1 and res["urls"][0]["payloads"][0]["sha256"] == fake_data.PAYLOAD
            with self.raises(AbuseChApiError):
                await svc.normUrlhausSearch("bogus", "x")

            assert (await svc.normUrlhausRecent("urls"))[0]["id"] == "105821"
            assert (await svc.normUrlhausRecent("payloads", limit=5))[0]["sha256"] == fake_data.PAYLOAD
            with self.raises(AbuseChApiError):
                await svc.normUrlhausRecent("bogus")

            sample = await svc.urlhausDownload(fake_data.SAMPLE_SHA256)
            assert sample["bytes"] == fake_data.SAMPLE_BYTES
            assert fake.last()["path"] == f"/urlhaus/download/{fake_data.SAMPLE_SHA256}/"
            with self.raises(AbuseChApiError):
                await svc.urlhausDownload("a" * 64)
            with self.raises(AbuseChApiError):
                await svc.urlhausDownload(MD5)

            resp = await svc.urlhausSubmit(["http://a.com/x"], tags=["exe"], anonymous=True)
            assert resp == "Your submission has been accepted"
            assert fake.last()["json"] == {"anonymous": "1", "submission": [
                {"url": "http://a.com/x", "threat": "malware_download", "tags": ["exe"]}]}
            assert fake.last()["authkey"] == "testkey"

            urls = [u async for u in svc.urlhausExport()]
            assert urls[0]["url"] == "http://csv.example.com/x.exe" and urls[0]["tags"] == ["exe", "agenttesla"]
            assert urls[0]["reference"] == "https://urlhaus.abuse.ch/url/4000/" and urls[0]["reporter"] == "reporter1"
            assert fake.last()["path"] == "/urlhaus_export/testkey/recent.csv"
            assert len([u async for u in svc.urlhausExport("online", limit=1)]) == 1
            assert len([u async for u in svc.urlhausExport("full")]) == 1
            assert fake.last()["path"] == "/urlhaus_export/testkey/full.csv.zip"
            with self.raises(AbuseChApiError):
                [u async for u in svc.urlhausExport("bogus")]

    async def test_threatfox(self):
        async with abusechSvc(self) as (core, svc, fake):
            assert len(await svc.normThreatfox("recent", 2)) == 2
            assert fake.last()["json"]["days"] == 2
            assert len(await svc.normThreatfox("recent", limit=1)) == 1
            # The ioc query returns the IOC unwrapped.
            iocs = await svc.normThreatfox("id", 41)
            assert iocs[0]["id"] == "41" and iocs[0]["sightings"] == 3
            assert (await svc.threatfoxIoc(41))["ioc"] == "gaga.com"
            assert await svc.normThreatfox("id", 99) == []
            assert len(await svc.normThreatfox("recent", 1, limit=0)) == 2

            # IPs are found by a wildcard search, filtered to the IP.
            iocs = await svc.normThreatfox("ip", "5.6.7.8")
            assert [i["ioc"] for i in iocs] == ["5.6.7.8:443"]
            assert fake.last()["json"] == {"query": "search_ioc", "search_term": "5.6.7.8", "exact_match": False}
            assert await svc.normThreatfox("ip", "5.6.7.80") == []

            # Files find their own hash IOC and the IOCs associated with them, without duplicates.
            iocs = await svc.normThreatfox("file", SHA256)
            assert sorted(i["id"] for i in iocs) == ["41", "44"]
            assert fake.queries("threatfox")[-2:] == ["search_ioc", "search_hash"]
            await svc.normThreatfox("file", fake_data.SHA1)
            assert fake.queries("threatfox")[-1] == "search_ioc"
            with self.raises(AbuseChApiError):
                await svc.threatfoxHash(fake_data.SHA1)
            assert (await svc.normThreatfox("search", "gaga.com", exact=True))[0]["ioc"] == "gaga.com"
            assert len(await svc.normThreatfox("hash", SHA256)) == 2
            assert len(await svc.normThreatfox("tag", "x")) == 2
            assert len(await svc.normThreatfox("malware", "x")) == 2
            with self.raises(AbuseChApiError):
                await svc.normThreatfox("bogus", "x")

            assert await svc.threatfoxTypes() == fake_data.THREATFOX_TYPES

            iocs = [i async for i in svc.threatfoxExport()]
            assert iocs[0]["ioc"] == "export.example.com"
            assert fake.last()["path"] == "/threatfox_export/testkey/recent.json"
            assert len([i async for i in svc.threatfoxExport("full", limit=1)]) == 1
            with self.raises(AbuseChApiError):
                [i async for i in svc.threatfoxExport("bogus")]
            fake.overrides[("threatfox:export", "testkey/recent.json")] = (200, "not json")
            with self.raises(AbuseChApiError):
                [i async for i in svc.threatfoxExport()]

    async def test_yaraify(self):
        async with abusechSvc(self) as (core, svc, fake):
            f = await svc.normYaraifyHash(SHA256)
            assert f["sha256"] == SHA256 and f["unpacked"]
            assert "malpedia-token" not in fake.last()["json"]
            assert await svc.normYaraifyHash("a" * 64) is None

            files = await svc.normYaraifySearch("yara", "MyRule")
            assert files[0]["rules"][0]["name"] == "MyRule"
            files = await svc.normYaraifySearch("clamav", "Sig", limit=1)
            assert files[0]["rules"] == [] and files[0]["clamav"] == ["Sig"]

            # get_results, unknown tasks, and list_tasks without any matches.
            res = await svc.normYaraifyResults("task1")
            assert res["status"] == "done" and res["file"]["clamav"] == ["Win.Packed.Generic-1"]
            assert [r["name"] for r in res["file"]["rules"]] == ["win_agent_tesla_auto"]
            assert await svc.normYaraifyResults("unknown-task") is None
            fake.overrides[("yaraify", "list_tasks")] = (200, {"query_status": "ok", "data": "no results"})
            assert await svc.normYaraifyTasks("ident") == []
            fake.overrides.clear()
            await svc.yaraifyTasks("ident", status=None)
            assert fake.last()["json"] == {"query": "list_tasks", "identifier": "ident"}
            with self.raises(AbuseChApiError):
                await svc.yaraifySearch("bogus", "x")

            # Listed rules don't include their text, it's downloaded for each shared rule.
            rules = await svc.normYaraifyRecentRules()
            assert [(r["name"], r["desc"]) for r in rules] == [("New_Rule_1", "A new rule"), ("Private_Rule", None)]
            assert rules[0]["text"] == fake_data.NEW_RULE_TEXT.strip()
            assert rules[1]["text"] is None
            assert fake.queries("yaraify")[-3:] == ["recent_yararules", "get_yara_rule", "get_yara_rule"]
            rules = await svc.normYaraifyRecentRules(text=False)
            assert rules[0]["text"] is None and fake.queries("yaraify")[-1] == "recent_yararules"

            rules = await svc.normYaraifyDeployedRules()
            assert [r["name"] for r in rules] == ["New_Rule_1"] and rules[0]["text"]
            assert await svc.yaraifyDeleteRule("6a6d2b48-1234-4cde-9f00-112233445566") == "YARA rule deleted"
            with self.raises(AbuseChApiError) as cm:
                await svc.yaraifyDeleteRule("nope")
            assert cm.exception.mesg == "abuse.ch yaraify: error: Unknown YARA rule"
            res = await svc.normYaraifyResults("task1")
            assert res["status"] == "done" and res["file"]["sha256"] == SHA256
            assert (await svc.normYaraifyResults("queued-task"))["status"] == "queued"
            assert (await svc.normYaraifyTasks("ident"))[0]["sha256"] == SHA256
            assert await svc.yaraifyIdentifier() == {"identifier": "abcdef-identifier"}
            assert (await svc.yaraifyRescan(SHA256))["task_id"].startswith("2222")

            resp = await svc.yaraifyScan([b"MZ", b"x"], "a.exe", identifier="ident", unpack=True)
            assert resp == {"task_id": "11111111-aaaa-bbbb-cccc-000000000001"}
            req = fake.last()
            assert req["files"]["file"] == ("a.exe", b"MZx")
            assert json.loads(req["form"]["json_data"]) == {
                "identifier": "ident", "clamav_scan": 1, "unpack": 1, "share_file": 0, "skip_known": 0, "skip_noisy": 0}

            assert await svc.yaraifyDeploy("rule x { condition: true }") == "Rule deployed"
            assert fake.last()["files"]["yara_file"] == ("rule.yar", b"rule x { condition: true }")

            rules = await svc.yaraifyRule("6a6d2b48-1234-4cde-9f00-112233445566")
            assert [r["name"] for r in rules] == ["win_agent_tesla_auto", "helper_rule"]
            # The UUID only applies to every rule when the download has one rule.
            assert rules[0]["uuid"] == "6a6d2b48-1234-4cde-9f00-112233445566" and rules[1]["uuid"] is None
            fake.overrides[("yaraify", "get_yara_rule")] = (200, mkzip({"r.yar": b"rule zipped { condition: true }"}))
            rules = await svc.yaraifyRule("u2")
            assert [(r["name"], r["uuid"]) for r in rules] == [("zipped", "u2")]
            fake.overrides[("yaraify", "get_yara_rule")] = (200, {"query_status": "no_results"})
            assert await svc.yaraifyRule("u3") == []
            fake.overrides.clear()
            with self.raises(AbuseChApiError):
                await svc.yaraifyRule("unknown-uuid")
            fake.overrides.clear()

            sample = await svc.yaraifyFile(fake_data.SAMPLE_SHA256)
            assert sample["bytes"] == fake_data.SAMPLE_BYTES
            assert await svc.yaraifyFile("a" * 64) is None
            with self.raises(AbuseChApiError):
                await svc.yaraifyFile(MD5)

            sample = await svc.yaraifyUnpacked(fake_data.SAMPLE_SHA256)
            assert sample["bytes"] == fake_data.SAMPLE_BYTES
            assert fake.last("/yaraify")["json"] == {"query": "get_unpacked", "sha256_hash": fake_data.SAMPLE_SHA256}
            assert await svc.yaraifyUnpacked("a" * 64) is None
            with self.raises(AbuseChApiError):
                await svc.yaraifyUnpacked(MD5)

            rules = [r async for r in svc.yaraifyRulesExport()]
            assert [r["name"] for r in rules] == ["win_agent_tesla_auto", "helper_rule"]
            assert fake.last()["path"] == "/yaraify_export/yarahub/yaraify-rules.zip"
            assert len([r async for r in svc.yaraifyRulesExport(limit=1)]) == 1

    async def test_blocklists(self):
        async with abusechSvc(self) as (core, svc, fake):
            c2s = [c async for c in svc.feodoBlocklist()]
            assert [c["ip"] for c in c2s] == ["50.16.16.211", "60.1.2.3"]
            c2s = [c async for c in svc.feodoBlocklist("recommended")]
            assert [(c["ip"], c["port"], c["family"]) for c in c2s] == [("50.16.16.211", 8080, "QakBot")]
            assert fake.last()["path"] == "/feodo/ipblocklist_recommended.json"
            c2s = [c async for c in svc.feodoBlocklist("aggressive", limit=1)]
            assert c2s[0]["family"] == "TrickBot"
            assert len([c async for c in svc.feodoBlocklist(limit=1)]) == 1
            with self.raises(AbuseChApiError):
                [c async for c in svc.feodoBlocklist("bogus")]
            fake.overrides[("feodo", "ipblocklist.json")] = (200, "not json")
            with self.raises(AbuseChApiError):
                [c async for c in svc.feodoBlocklist()]

            certs = [c async for c in svc.sslblBlocklist()]
            assert [c["sha1"] for c in certs] == ["1" * 40, "2" * 40]
            assert len([c async for c in svc.sslblBlocklist(limit=1)]) == 1
            # The IP lists were deprecated, and a deprecated dataset is an error instead of empty.
            with self.raises(AbuseChApiError):
                [c async for c in svc.sslblBlocklist("ips")]
            fake.overrides[("sslbl", "sslblacklist.csv")] = (200, fake_data.SSLBL_IPS)
            with self.raises(AbuseChApiError) as cm:
                [c async for c in svc.sslblBlocklist("certs")]
            assert "has been deprecated on 2025-01-03" in cm.exception.mesg
            fake.overrides.clear()
            ja3s = [c async for c in svc.sslblBlocklist("ja3")]
            assert ja3s[0]["family"] == "Dridex"
            with self.raises(AbuseChApiError):
                [c async for c in svc.sslblBlocklist("bogus")]

            # The list isn't wrapped in {"query_status", "data"}.
            assert await svc.fplist() == fake_data.FPLIST
            fps = await svc.normFplist()
            assert len(fps) == 3
            fps = await svc.normFplist(platform="URLhaus")
            assert [f["obs"]["valu"] for f in fps] == ["legit.example.com"]
            fake.overrides[("hunting", "get_fplist")] = (200, {"query_status": "ok", "data": {"1": fake_data.FPLIST["5"]}})
            assert len(await svc.normFplist()) == 1
            fake.overrides[("hunting", "get_fplist")] = (200, {"query_status": "no_results"})
            assert await svc.fplist() == {}

    async def test_apikey(self):
        async with abusechSvc(self, apikey=None) as (core, svc, fake):
            assert not await svc.hasApiKey()
            with self.raises(NoApiKeyError):
                await svc.bazaarInfo(SHA256)

            # The caller's key wins over the stored key, which wins over the config.
            await svc.bazaarInfo(SHA256, apikey="userkey")
            assert fake.last()["authkey"] == "userkey"

            await svc.setApiKey("storedkey")
            assert await svc.hasApiKey()
            await svc.bazaarInfo(SHA256)
            assert fake.last()["authkey"] == "storedkey"

            await svc.setApiKey(None)
            assert not await svc.hasApiKey()

            # A rejected key is an error everywhere, not an empty result.
            for coro in (svc.bazaarInfo(SHA256, apikey="badkey"), svc.normUrlhausUrl(url="http://a", apikey="badkey"),
                         svc.normThreatfox("id", 41, apikey="badkey"), svc.fplist(apikey="badkey"),
                         svc.urlhausDownload(fake_data.SAMPLE_SHA256, apikey="badkey"),
                         svc.urlhausSubmit(["http://a.com/x"], apikey="badkey")):
                with self.raises(AbuseChApiError) as cm:
                    await coro
                assert "unknown_auth_key" in cm.exception.mesg and "check your Auth-Key" in cm.exception.mesg
            with self.raises(AbuseChApiError):
                [s async for s in svc.bazaarExport(apikey="badkey")]

    async def test_cellapi(self):
        async with abusechSvc(self) as (core, svc, fake):
            async with svc.getLocalProxy() as prox:
                retn = await prox.normBazaarInfo(SHA256)
                assert retn["status"] and retn["data"]["sha256"] == SHA256

                retn = await prox.bazaarInfo("nothex")
                assert not retn["status"] and "Not an MD5" in retn["mesg"]

                items = [i async for i in prox.feodoBlocklist()]
                assert all(i["status"] for i in items) and len(items) == 2

                items = [i async for i in prox.feodoBlocklist("bogus")]
                assert len(items) == 1 and not items[0]["status"]

                retn = await prox.setApiKey("x")
                assert retn["status"] and "Set" in retn["mesg"]
                retn = await prox.setApiKey(None)
                assert "Cleared" in retn["mesg"]
                assert (await prox.hasApiKey())["data"] is True  # The config key.
