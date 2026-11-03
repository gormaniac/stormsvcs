"""Tests for anyrunsvc.norm and the client's helpers."""

import datetime

import pytest

from anyrunsvc import client as c_client
from anyrunsvc import norm

from . import fakeanyrun as fa


def test_helpers():
    assert norm.tagPart("Agent Tesla!") == "agent_tesla"
    assert norm.tagPart("  ") is None
    assert norm.tagStrs(["a", {"tag": "b", "users": True}, {"tag": ""}, 5, "a"]) == ["a", "b"]
    assert norm.tagNames(["Agent-Tesla", {"tag": "RAT"}]) == ["agent_tesla", "rat"]

    # ISO strings and epoch seconds/millis/micros, small offsets aren't times.
    msecs = 1793448000000
    assert norm.toMsecs("2026-10-31T12:00:00.000Z") == msecs
    assert norm.toMsecs("2026-10-31T12:00:00") == msecs
    assert norm.toMsecs(msecs) == msecs
    assert norm.toMsecs(msecs // 1000) == msecs
    assert norm.toMsecs(msecs * 1000) == msecs
    assert norm.toMsecs(str(msecs)) == msecs
    assert norm.toMsecs(12345) is None
    assert norm.toMsecs("nope") is None
    assert norm.toMsecs(True) is None
    assert norm.ival(10) == [10, 11]
    assert norm.ival(10, 20) == [10, 20]
    assert norm.ival(None, 20) is None

    assert norm.verdictText("Malicious activity") == 40
    assert norm.verdictText("suspicious activity") == 30
    assert norm.verdictText("No threats detected") == 10
    assert norm.verdictText("other") is None
    assert norm.verdictLevel(2) == 40
    assert norm.verdictLevel("1") == 30
    # 0 is "no info" in TI Lookup, not benign.
    assert norm.verdictLevel(0) is None
    assert norm.verdictLevel(None) is None

    assert norm.ttp("t1059.001") == "T1059.001"
    assert norm.ttp("1082") == "T1082"
    assert norm.ttp("TA0001") is None

    assert norm.c2Urls("c2.example.com:587, 1.2.3.4:80; [2001:db8::1]:443 bad/host") == [
        "tcp://c2.example.com:587",
        "tcp://1.2.3.4:80",
        "tcp://[2001:db8::1]:443",
    ]
    assert norm.c2Urls(["https://x.example.com/a", "x.example.com"]) == [
        "https://x.example.com/a",
        "tcp://x.example.com",
    ]
    assert norm.c2Urls(None) == []

    assert norm.taskId(f"https://app.any.run/tasks/{fa.TASK.upper()}") == fa.TASK
    assert norm.taskId("nope") is None
    assert norm.hashes({"md5": "A" * 32, "sha256": "bad", "ssdeep": "3:a:b"}) == {
        "md5": "a" * 32,
        "ssdeep": "3:a:b",
    }
    assert norm.basename("C:\\a\\b.exe") == "b.exe"

    assert norm.lookupField("1.2.3.4") == "destinationIP"
    assert norm.lookupField("2001:db8::1") == "destinationIP"
    assert norm.lookupField(fa.SAMPLE_SHA256) == "sha256"
    assert norm.lookupField(fa.SAMPLE_MD5) == "md5"
    assert norm.lookupField("http://x.example.com/") == "url"
    assert norm.lookupField("x.example.com") == "domainName"
    assert norm.lookupField("not an indicator") is None
    assert norm.lookupQuery("url", 'http://a/"b\\') == 'url:"http://a/\\"b\\\\"'


def test_client_helpers():
    assert c_client.authHeader("abc") == "API-Key abc"
    assert c_client.authHeader("API-Key abc") == "API-Key abc"
    assert c_client.authHeader("Basic abc") == "Basic abc"

    # Brackets in keys stay, values (ex. base64 cursors) are fully encoded, None is dropped.
    assert c_client.query({"match[type]": "indicator", "next": "a+b/c=", "x": None, "t": True}) == (
        "match[type]=indicator&next=a%2Bb%2Fc%3D&t=true"
    )

    # Every error shape.
    assert c_client.errMesg(404, {"error": True, "message": "Task not found"}) == (
        "ANY.RUN: Task not found (HTTP 404)",
        None,
    )
    mesg, code = c_client.errMesg(
        400,
        {
            "message": "The query syntax is incorrect.",
            "code": "WRONG_QUERY_ERROR",
            "validationErrors": [{"field": "query", "error": "query should not be empty"}],
        },
    )
    assert code == "WRONG_QUERY_ERROR"
    assert mesg == (
        "ANY.RUN: The query syntax is incorrect. (query: query should not be empty) "
        "(HTTP 400, WRONG_QUERY_ERROR)"
    )
    assert c_client.errMesg(404, {"title": "Not Found", "description": "No collection."})[0] == (
        "ANY.RUN: No collection. (HTTP 404)"
    )
    assert c_client.errMesg(401, {"status": "error", "message": "Auth required."})[0] == (
        "ANY.RUN: Auth required. (HTTP 401)"
    )
    assert c_client.errMesg(
        400, {"statusCode": 400, "message": ["offset must be a number"], "error": "Bad Request"}
    )[0] == ("ANY.RUN: offset must be a number (HTTP 400)")
    assert c_client.errMesg(502, None, "<html>Bad gateway</html>")[0] == (
        "ANY.RUN: <html>Bad gateway</html> (HTTP 502)"
    )
    assert c_client.errMesg(500, None, "")[0] == "ANY.RUN: error (HTTP 500)"

    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    assert c_client.retryWait({"nextAvailableRequestDate": "2026-01-01T00:00:30.000Z"}, now) == 30
    assert c_client.retryWait({"nextAvailableRequestDate": "2025-01-01T00:00:00Z"}, now) == 0
    assert c_client.retryWait({"nextAvailableRequestDate": "nope"}, now) is None
    assert c_client.retryWait({}, now) is None

    assert c_client.sseData(b'data: {"a": 1}') == {"a": 1}
    assert c_client.sseData(b"id: 1") is None
    assert c_client.sseData(b"data: [1]") is None

    byts = fa.zipped("a.bin", b"hello")
    assert c_client.isZip(byts)
    assert c_client.unzip(byts) == [("a.bin", b"hello")]
    with pytest.raises(c_client.AnyRunApiError):
        c_client.unzip(b"PK\x03\x04garbage")
    with pytest.raises(c_client.AnyRunApiError, match="larger than the max"):
        c_client.unzip(byts, maxsize=2)


def test_norm_report():
    data = norm.normReport(fa.fileReport("https://content.any.run"))
    assert data["uuid"] == fa.TASK
    assert data["link"] == f"https://app.any.run/tasks/{fa.TASK}"
    assert data["kind"] == "file" and data["url"] is None
    assert data["file"] == {
        "md5": fa.SAMPLE_MD5,
        "sha1": fa.SAMPLE_SHA1,
        "sha256": fa.SAMPLE_SHA256,
        "ssdeep": fa.SAMPLE_SSDEEP,
        "name": "invoice.exe",
        "mime": "application/x-dosexec",
    }
    assert data["time"] == 1793448000000
    assert data["ival"] == [1793448000000, 1793448060000]
    assert data["verdict"] == 40 and data["threat"] == "Malicious activity" and data["score"] == 100
    assert data["tags"] == ["agenttesla", "stealer", "my-tag"]
    assert data["families"] == ["AgentTesla"]
    assert data["tagnames"] == ["agenttesla", "stealer", "my_tag"]
    assert data["ttps"] == ["T1555", "T1059.003"]
    assert data["mutexes"] == ["Global\\AgentMutex1"]
    assert data["env"].startswith("Windows 10")
    assert data["errors"] == []

    (config,) = data["configs"]
    assert config["family"] == "AgentTesla"
    assert config["servers"] == ["tcp://c2.evil.example.com:587", "tcp://198.51.100.7:8080"]
    assert config["hosts"] == ["c2.evil.example.com", "198.51.100.7"]

    main, child = data["procs"]
    assert main["uuid"] == fa.PROC_MAIN and main["main"] and main["pid"] == 4321
    assert main["parent"] is None and main["exitcode"] == 0 and main["user"] == "admin"
    assert main["time"] == 1793448001000 and main["exited"] == 1793448050000
    assert child["parent"] == fa.PROC_MAIN and not child["main"]

    (dns,) = data["dns"]
    assert dns["name"] == "c2.evil.example.com"
    assert dns["ips"] == [
        {"ip": "203.0.113.10", "ipver": "ipv4"},
        {"ip": "2001:db8::10", "ipver": "ipv6"},
    ]

    (http,) = data["http"]
    assert http["url"] == "http://c2.evil.example.com/gate.php" and http["method"] == "POST"
    assert http["server"] == "tcp://203.0.113.10:80" and http["code"] == 200
    assert http["headers"] == [["user-agent", "Mozilla/5.0"]] and http["proc"] == fa.PROC_MAIN

    (flow,) = data["flows"]
    assert flow["server"] == "tcp://203.0.113.10:443" and flow["proto"] == "tcp"
    assert flow["cc"] == "us" and flow["asn"] == 64500 and flow["ja3"].startswith("a0e9")
    assert flow["time"] == 1793448007000 and flow["proc"] == fa.PROC_MAIN

    # The repeated alert is dropped.
    (alert,) = data["alerts"]
    assert alert["sid"] == 2030171 and alert["msg"].startswith("ET MALWARE")
    assert alert["src"] == "tcp://10.0.2.15:49712" and alert["dst"] == "tcp://203.0.113.10:80"

    # Files without a SHA256 are kept by path.
    file, nosha = data["files"]
    assert file["sha256"] == fa.DROPPED_SHA256 and file["name"] == "payload.dll"
    assert file["path"] == "C:\\Users\\admin\\AppData\\Roaming\\payload.dll"
    assert file["proc"] == fa.PROC_MAIN and file["threat"] == "high"
    assert nosha["sha256"] is None and nosha["md5"] == "d41d8cd98f00b204e9800998ecf8427e"
    assert nosha["path"] == "C:\\Users\\admin\\notes.txt" and nosha["threat"] == "unknown"

    # File operations: the CREATE of a file in modified.files and the CLOSE aren't repeated,
    # a rename is a del and an add, a FileDrop is an add with its hashes, and reads are skipped.
    ops = [(o["op"], o["path"].rsplit("\\", 1)[-1], o["threat"]) for o in data["fileops"]]
    assert ops == [
        ("write", "notes.txt", "unknown"),
        ("del", "invoice.exe", None),
        ("del", "a.tmp", None),
        ("add", "b.exe", None),
        ("add", "second.bin", None),
    ]
    drop = data["fileops"][-1]
    assert drop["file"]["sha256"] == fa.DROP2_SHA256 and drop["file"]["name"] == "second.bin"
    assert drop["proc"] == fa.PROC_MAIN and drop["time"] == 1793448019000
    assert all(o["file"] is None for o in data["fileops"][:-1])

    # Registry operations from modified.registry and the incidents, without repeats or reads.
    regs = {(o["op"], o["path"]): o for o in data["regops"]}
    run = f"{fa.RUNKEY}\\Updater"
    assert list(regs) == [
        ("set", run),
        ("set", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware"),
        ("del", "HKEY_CURRENT_USER\\SOFTWARE\\Old"),
        ("set", "HKEY_CURRENT_USER\\SOFTWARE\\Agent\\Count"),
        ("del", "HKEY_CURRENT_USER\\SOFTWARE\\Agent\\Old"),
    ]
    # The HKCU abbreviation is expanded, and the type comes from the incident event.
    assert regs[("set", run)]["str"] == "C:\\Users\\admin\\AppData\\Roaming\\payload.dll"
    assert regs[("set", run)]["type"] == "REG_SZ" and regs[("set", run)]["key"] == fa.RUNKEY
    assert regs[("set", run)]["proc"] == fa.PROC_MAIN and regs[("set", run)]["time"] == 1793448011000
    assert regs[("set", "HKEY_CURRENT_USER\\SOFTWARE\\Agent\\Count")]["int"] == 16
    # An untyped integer value.
    dis = regs[("set", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware")]
    assert dis["int"] == 1 and dis["str"] is None
    old = regs[("del", "HKEY_CURRENT_USER\\SOFTWARE\\Old")]
    assert old["name"] is None and old["proc"] == fa.PROC_CHILD

    # Screenshots (offsets from the task's start) and the video.
    assert data["screens"] == [
        {"uuid": fa.SCREEN1, "time": 1793448005000, "offset": 5},
        {"uuid": fa.SCREEN2, "time": 1793448030000, "offset": 30},
    ]
    assert data["video"] is True

    # Reads, only when asked for.
    data = norm.normReport(fa.fileReport("https://content.any.run"), reads=True)
    assert [o["path"] for o in data["fileops"] if o["op"] == "read"] == ["C:\\Windows\\win.ini"]
    (get,) = [o for o in data["regops"] if o["op"] == "get"]
    assert get["path"] == "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid"


def test_norm_registry_helpers():
    assert norm.regKey("hkcu\\Software\\Run\\") == "HKEY_CURRENT_USER\\Software\\Run"
    assert norm.regKey("\\REGISTRY\\MACHINE\\SOFTWARE") == "HKEY_LOCAL_MACHINE\\SOFTWARE"
    assert norm.regKey("\\REGISTRY\\USER\\S-1-5-21") == "HKEY_USERS\\S-1-5-21"
    assert norm.regKey("HKEY_local_machine\\X") == "HKEY_LOCAL_MACHINE\\X"
    assert norm.regKey("HKLM") == "HKEY_LOCAL_MACHINE"
    # Only whole hive names are expanded.
    assert norm.regKey("HKLMX\\a") == "HKLMX\\a"
    assert norm.regKey("") is None and norm.regKey(None) is None

    assert norm.regOp("write") == "set" and norm.regOp("Set value") == "set"
    assert norm.regOp("delete value") == "del" and norm.regOp("RemoveKey") == "del"
    assert norm.regOp("read") == "get" and norm.regOp("QueryValue") == "get"
    assert norm.regOp("unknown") is None and norm.regOp(None) is None

    assert norm.regValue("0x10", "REG_DWORD") == (16, None)
    assert norm.regValue("12") == (12, None)
    assert norm.regValue("1", "REG_SZ") == (None, "1")
    assert norm.regValue("nope", "REG_QWORD") == (None, "nope")
    assert norm.regValue("") == (None, None)

    # The default value's name isn't appended to the key.
    report = {"modified": {"registry": [{"key": "HKLM\\A", "name": "(Default)", "value": "x", "operation": "write", "process": "1", "time": 1}]}}
    (op,) = norm.normRegOps(report, norm._Procs([]))
    assert op["path"] == "HKEY_LOCAL_MACHINE\\A" and op["str"] == "x"

    assert norm.threatLevel("HIGH") == "high" and norm.threatLevel(None) is None


def test_norm_report_url_and_partial():
    data = norm.normReport(fa.urlReport())
    assert data["kind"] == "url" and data["url"] == fa.URL and data["file"] is None
    assert data["verdict"] == 30 and data["tagnames"] == ["phishing"]
    assert data["ival"] == [1793350800000, 1793350800001]

    # A download task models its file and the URL it came from.
    report = fa.fileReport("https://content.any.run")
    report["analysis"]["content"]["mainObject"].update(type="download", url="https://x.example.com/a.exe")
    data = norm.normReport(report)
    assert data["kind"] == "download" and data["url"] == "https://x.example.com/a.exe"
    assert data["file"]["sha256"] == fa.SAMPLE_SHA256 and data["file"]["name"] is None

    # A nearly empty (still running) report doesn't fail.
    data = norm.normReport({"status": "running", "analysis": {"uuid": fa.TASK}})
    assert data["uuid"] == fa.TASK and data["file"] is None and data["procs"] == []
    assert data["errors"] == [f"Task {fa.TASK} is running, its report may be incomplete."]
    assert data["verdict"] is None


def test_norm_status():
    status = norm.normStatus(fa.statusEvent(fa.TASK, 40))
    assert status["state"] == "running" and status["status"] == 40 and not status["completed"]
    assert status["uuid"] == fa.TASK and status["verdict"] == "Malicious activity"
    assert status["threats"] == ["AgentTesla"] and status["tags"] == ["agenttesla"]

    assert norm.normStatus(fa.statusEvent(fa.TASK, 10))["state"] == "preparing"
    assert norm.normStatus(fa.statusEvent(fa.TASK, -1))["state"] == "failed"
    assert norm.normStatus(fa.statusEvent(fa.TASK, 100))["completed"]
    assert norm.normStatus(fa.statusEvent(fa.TASK, 99, completed=True))["state"] == "completed"

    # Message only events.
    queued = norm.normStatus({"error": False, "message": "Task is queued and awaits execution."})
    assert queued["state"] == "queued" and queued["uuid"] is None
    assert norm.normStatus({"error": False, "message": "Task will be launched soon."})["state"] == "preparing"
    assert norm.normStatus({"error": True, "message": "Pre-launch error occurred."})["state"] == "failed"
    assert (
        norm.normStatus({"error": False, "message": "Task status is unknown or the task was canceled"})["state"]
        == "unknown"
    )


def test_norm_lookup():
    data = norm.normLookup(fa.lookupResponse())
    assert data["verdict"] == 40 and data["level"] == 2 and not data["empty"]
    assert data["lastseen"] == 1793448000000
    assert data["tags"] == ["agenttesla", "stealer"] and data["threats"] == ["agenttesla"]
    assert data["tagnames"] == ["agenttesla", "stealer"]
    assert data["ips"] == [
        {"ip": "203.0.113.10", "ipver": "ipv4", "verdict": 40, "threats": ["agenttesla"], "malconf": True, "time": 1793448000000}
    ]
    assert data["fqdns"][0]["fqdn"] == "c2.evil.example.com" and data["fqdns"][0]["malconf"]
    assert data["urls"][0]["url"] == "http://c2.evil.example.com/gate.php"
    assert data["files"][0]["sha256"] == fa.SAMPLE_SHA256 and data["files"][0]["name"] == "invoice.exe"
    # Newest first.
    assert [t["uuid"] for t in data["tasks"]] == [fa.TASK, fa.URLTASK]
    assert data["tasks"][0]["hashes"]["sha256"] == fa.SAMPLE_SHA256
    assert data["mutexes"] == ["Global\\AgentMutex1"]
    assert data["ttps"] == ["T1555", "T1082", "T1071"]
    assert data["alerts"][0]["sid"] == 2030171
    assert data["countries"] == ["us"] and data["ports"] == [587, 443]
    assert data["totals"] == {"totalTasks": 2, "totalRelatedFiles": 1}

    empty = norm.normLookup(fa.emptyLookup())
    assert empty["empty"] and empty["verdict"] is None and empty["ival"] is None


def test_norm_yara_and_stix():
    match, nohash = fa.yaraMatches()
    assert norm.normYaraMatch(nohash) is None
    item = norm.normYaraMatch(match)
    assert item["sha256"] == fa.MATCH_SHA256 and item["name"] == "invoice_2026.exe"
    assert item["size"] == 245760 and item["task"] == fa.TASK
    assert item["tags"] == ["trojan", "AgentTesla"]
    assert item["first"] < item["last"]

    ip, fqdn, ident, url, cidr, file = (norm.normStix(o) for o in fa.stixObjects())
    assert ip["observables"] == [{"kind": "ipv4", "value": "203.0.113.10"}]
    assert ip["labels"] == ["malicious-activity"] and ip["tagnames"] == ["malicious_activity"]
    assert ip["ival"][0] == 1793318400000 and ip["verdict"] == 40
    assert fqdn["observables"] == [{"kind": "fqdn", "value": "c2.evil.example.com"}]
    assert ident is None
    assert url["observables"] == [{"kind": "url", "value": "http://c2.evil.example.com/gate.php"}]
    # CIDRs aren't single IPs.
    assert cidr is None
    assert file["observables"] == [{"kind": "sha256", "value": fa.SAMPLE_SHA256}]

    assert norm.stixObservables({"type": "ipv6-addr", "value": "2001:db8::1"}) == [("ipv6", "2001:db8::1")]
    assert norm.stixObservables({"type": "file", "hashes": {"MD5": fa.SAMPLE_MD5}}) == [("md5", fa.SAMPLE_MD5)]
    assert norm.stixObservables(
        {"type": "indicator", "pattern": "[url:value = 'http://a/it\\'s'] OR [domain-name:value = 'b.com']"}
    ) == [("url", "http://a/it's"), ("fqdn", "b.com")]
    assert norm.normStix("nope") is None


def test_norm_task():
    task = norm.normTask(fa.history()[0])
    assert task["uuid"] == fa.TASK and task["time"] == 1793448000000
    assert task["hashes"]["sha256"] == fa.SAMPLE_SHA256 and task["tags"] == ["agenttesla"]
