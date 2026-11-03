"""Tests for vtsvc.norm, against real (trimmed) VirusTotal responses."""

from vtsvc import norm

from . import fakevt as fv


def test_file():
    f = norm.normObject(fv.load("file_wannacry")["data"])
    assert f["type"] == "file"
    assert f["sha256"] == fv.WANNACRY
    assert f["name"] == "lhdfrgui.exe"
    assert f["compiled"] == 1290243788000
    assert f["first_seen"] == 1494579471000
    assert f["scan"]["verdict"] == norm.MALICIOUS
    assert f["scan"]["counts"] == {"total": 75, "malicious": 68, "suspicious": 0, "benign": 3, "unknown": 4}
    assert f["threat"] == {
        "label": "trojan.wannacry/wanna",
        "names": ["wannacry", "wanna", "wannacrypt"],
        "categories": ["trojan", "ransomware", "worm"],
    }
    assert "verdict.malicious" in f["vtags"]
    assert "family.wannacry" in f["vtags"] and "family.wanna" not in f["vtags"]
    sb = {s["name"]: s for s in f["sandboxes"]}
    assert sb["C2AE"]["signame"] == "WannaCry"
    assert sb["C2AE"]["categories"] == ["ransom"]
    assert f["yara"][0]["name"] == "WannaCry_Ransomware"
    assert f["yara"][0]["time"] == 1793680201000
    assert f["ids"][0]["id"] == "1:2024291"
    assert f["ids"][0]["text"].startswith("alert dns")

    e = norm.normObject(fv.load("file_eicar")["data"])
    assert e["sigma"][0]["name"] == "User with Privileges Logon"
    assert e["compiled"] is None


def test_verdicts():
    assert norm.verdict(None) is None
    assert norm.verdict({"malicious": 0, "undetected": 3}) == norm.BENIGN
    assert norm.verdict({"malicious": 0, "suspicious": 1}) == norm.SUSPICIOUS
    assert norm.verdict({"malicious": 2}) == norm.SUSPICIOUS
    assert norm.verdict({"malicious": 3}) == norm.MALICIOUS
    assert norm.verdict({"malicious": 1}, malicious=1) == norm.MALICIOUS
    assert norm.verdict({"timeout": 3}) == norm.UNKNOWN
    eng = norm.normEngine("X", {"category": "undetected", "result": None})
    assert eng["verdict"] == norm.BENIGN and eng["signame"] is None
    eng = norm.normEngine("X", {"category": "type-unsupported"})
    assert eng["verdict"] == norm.UNKNOWN


def test_network():
    d = norm.normObject(fv.load("domain")["data"])
    assert d["fqdn"] == "example.com"
    assert {r["type"] for r in d["dns"]} == {"A", "AAAA", "NS", "TXT", "SOA"}
    soa = [r for r in d["dns"] if r["type"] == "SOA"][0]
    assert soa["email"] == "dns.cloudflare.com"
    assert d["whois"]["registrar"].startswith("RESERVED")
    assert d["cert"]["sans"] == ["example.com"]
    assert d["cert"]["sha256"] == "85ca6ab068e9bcce88b6c4aa3c47f7d17228134a457f870d3800e6223a0df07a"
    assert d["vtags"] == ["verdict.benign"]

    i = norm.normObject(fv.load("ip")["data"])
    assert (i["ip"], i["version"], i["asn"], i["country"]) == ("8.8.8.8", 4, 15169, "us")
    assert i["https"] == "tcp://8.8.8.8:443"
    assert i["network"] == "8.8.8.0/24"

    u = norm.normObject(fv.load("url")["data"])
    assert u["url"] == fv.EICAR_URL
    assert u["final"] == "https://www.eicar.org/download/eicar.com.txt"
    assert u["content_sha256"] == fv.EICAR
    assert "family.mal_htmlgen_a" in u["vtags"]


def test_related_objects():
    res = norm.normObjects(fv.load("domain_resolutions")["data"])
    assert res[0] == {
        "type": "resolution", "id": "8.47.69.5example.com", "fqdn": "example.com",
        "ip": "8.47.69.5", "version": 4, "time": 1791826907000, "resolver": "CAPE Sandbox",
    }
    com = norm.normObjects(fv.load("file_comments")["data"])
    assert com[0]["text"] == "lgtm" and com[0]["time"] == 1789789529000
    assert norm.normObject({"type": "graph", "id": "g1"}) == {"type": "graph", "id": "g1"}
    assert norm.normObject({}) is None
    w = norm.normObject({"type": "whois", "id": "w", "attributes": {"last_updated": 1, "whois_map": {"Registrar": "X", "Creation Date": "2020-01-01T00:00:00Z"}}})
    assert w["created"] == 1577836800000 and w["registrar"] == "X" and w["asof"] == 1000
    assert norm.normObject({"type": "whois", "attributes": {}}) is None
    cert = norm.normObject({"type": "ssl_cert", "id": "c", "attributes": {"thumbprint_sha256": "A" * 64, "extensions": {"subject_alternative_name": ["*.x.com", "x.com"]}}})
    assert cert["sha256"] == "a" * 64 and cert["sans"] == ["x.com"]


def test_behaviour():
    b = norm.normBehaviour(fv.load("file_behaviour_summary")["data"])
    assert b["vtags"][:2] == ["behaviour.ransom", "behaviour.malware"]
    assert "behaviour.direct_cpu_clock_access" in b["vtags"]
    # wpad isn't an FQDN.
    fqdns = [d["fqdn"] for d in b["dns"]]
    assert fqdns[0] == "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
    assert "wpad" not in fqdns
    assert b["traffic"][0] == {"server": "tcp://104.16.167.228:80"}
    assert len(b["dropped"]) == 3
    assert all(t.startswith("T") for t in b["techniques"])
    assert norm.normBehaviour(None)["dns"] == []


def test_helpers():
    assert norm.urlId(fv.EICAR_URL) == "aHR0cDovL3d3dy5laWNhci5vcmcvZG93bmxvYWQvZWljYXIuY29tLnR4dA"
    assert norm.server("::1", 443) == "tcp://[::1]:443"
    assert norm.server("nope", 443) is None
    assert norm.tagPart("Trojan.Win32/Foo Bar") == "trojan_win32_foo_bar"
    assert norm.tagPart("!!") is None
    assert norm.ms("1700000000") == 1700000000000
    assert norm.ms(True) is None and norm.ms("x") is None
    assert norm.relEdge("files", "contacted_ips") == {"verb": "refs", "dir": "out"}
    assert norm.relEdge("domains", "resolutions") is None
