"""A fake ANY.RUN API server for tests.

Serves ANY.RUN's Sandbox, report, content, TI Lookup, YARA Search, and TAXII endpoints with
response shapes copied from ANY.RUN's OpenAPI specs (SandboxV1.json and TIV1.json), including
their error bodies, from mutable state. It records every request so tests can assert on exactly
what the service sent.
"""

import base64
import contextlib
import hashlib
import io
import json

import pyzipper
from aiohttp import web

APIKEY = "testkey"

TASK = "0cf223f2-530e-4a50-b68f-563045268648"
URLTASK = "7b9d2e4a-1c3f-4e5a-9b8d-6f0e2a4c1d3b"
QUEUED = "7261f5d1-0939-4abe-8761-b598d46cfc8d"
NEWTASK = "5a1e0c3d-2b4f-4c6e-8d9a-0b1c2d3e4f50"
YARA_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

SAMPLE = b"MZ fake sample bytes for slib.anyrun"
SAMPLE_SHA256 = hashlib.sha256(SAMPLE).hexdigest()
SAMPLE_SHA1 = hashlib.sha1(SAMPLE).hexdigest()
SAMPLE_MD5 = hashlib.md5(SAMPLE).hexdigest()
SAMPLE_SSDEEP = "3:abcdefghijklmno:pqrstuvwxyz"

DROPPED = b"dropped payload bytes"
DROPPED_SHA256 = hashlib.sha256(DROPPED).hexdigest()
DROPPED_MD5 = hashlib.md5(DROPPED).hexdigest()

PCAP = b"\xd4\xc3\xb2\xa1fake pcap"

URL = "http://evil.example.com/landing"

PROC_MAIN = "c3f1a2b4-0001-4a5b-8c9d-000000000001"
PROC_CHILD = "c3f1a2b4-0002-4a5b-8c9d-000000000002"

SCREEN1 = "5c0e0000-0000-4000-8000-000000000001"
SCREEN2 = "5c0e0000-0000-4000-8000-000000000002"
JPEG1 = b"\xff\xd8\xff\xe0 fake jpeg 1"
JPEG2 = b"\xff\xd8\xff\xe0 fake jpeg 2"
VIDEO = b"\x00\x00\x00\x18ftypmp42 fake video"

DROP2 = b"second dropped payload"
DROP2_SHA256 = hashlib.sha256(DROP2).hexdigest()
DROP2_MD5 = hashlib.md5(DROP2).hexdigest()

RUNKEY = "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

MATCH_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

YARA_RULE = 'rule grimresources {\n  strings:\n    $s1 = "loadXML"\n  condition:\n    $s1\n}'


def zipped(name: str, byts: bytes) -> bytes:
    """An AES zip (password "infected") holding one file, like ANY.RUN's sample downloads."""

    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zfd:
        zfd.setpassword(b"infected")
        zfd.writestr(name, byts)
    return buf.getvalue()


def fileReport(url: str) -> dict:
    """The data of GET /v1/analysis/{TASK}: a malicious file task (SandboxV1 TaskReportDto)."""

    content = f"{url}/tasks/{TASK}/download"
    return {
        "status": "done",
        "analysis": {
            "uuid": TASK,
            "permanentUrl": f"https://app.any.run/tasks/{TASK}",
            "duration": 60,
            "creation": 1793448000000,
            "creationText": "2026-10-31T12:00:00.000Z",
            "stopExec": 1793448060000,
            "stopExecText": "2026-10-31T12:01:00.000Z",
            "reports": {"IOC": f"https://api.any.run/report/{TASK}/ioc/json"},
            "tags": ["agenttesla", {"tag": "stealer", "users": False}, {"tag": "my-tag", "users": True}],
            "sandbox": {"name": "ANY.RUN - Malware Sandbox", "plan": {"name": "Hunter"}},
            "options": {"timeout": 60, "privacy": "bylink", "privateSample": False, "network": True},
            "scores": {
                "verdict": {"score": 100, "threatLevel": 2, "threatLevelText": "Malicious activity"},
                "specs": {"malwareConfig": True, "stealing": True},
            },
            "content": {
                "mainObject": {
                    "type": "file",
                    "permanentUrl": f"{content}/files/{PROC_MAIN}/ab12",
                    "filename": "C:\\Users\\admin\\AppData\\Local\\Temp\\invoice.exe",
                    "basename": "invoice.exe",
                    "hashes": {
                        "md5": SAMPLE_MD5,
                        "sha1": SAMPLE_SHA1,
                        "sha256": SAMPLE_SHA256,
                        "ssdeep": SAMPLE_SSDEEP,
                    },
                    "info": {"ext": "exe", "file": "PE32 executable (GUI) Intel 80386", "mime": "application/x-dosexec"},
                },
                "pcap": {"present": True, "permanentUrl": f"{content}/pcap"},
                "video": {"present": True, "permanentUrl": f"{content}/mp4"},
                "screenshots": [
                    {
                        "uuid": SCREEN1,
                        "time": 5,
                        "permanentUrl": f"{content}/screens/{SCREEN1}/image.jpeg",
                        "thumbnailUrl": f"{content}/thumbnails/{SCREEN1}/image.jpeg",
                    },
                    {
                        "uuid": SCREEN2,
                        "time": 30,
                        "permanentUrl": f"{content}/screens/{SCREEN2}/image.jpeg",
                        "thumbnailUrl": f"{content}/thumbnails/{SCREEN2}/image.jpeg",
                    },
                ],
                "dumps": [],
            },
        },
        "environments": {"os": {"title": "Windows 10 Professional (build: 19044, 64 bit)", "bitness": 64}},
        "counters": {"processes": {"total": 2, "monitored": 2, "suspicious": 0, "malicious": 1}},
        "processes": [
            {
                "pid": 4321,
                "ppid": 1000,
                "uuid": PROC_MAIN,
                "important": True,
                "image": "C:\\Users\\admin\\AppData\\Local\\Temp\\invoice.exe",
                "commandLine": '"C:\\Users\\admin\\AppData\\Local\\Temp\\invoice.exe"',
                "mainProcess": True,
                "times": {"start": 1793448001000, "terminate": 1793448050000},
                "context": {"userName": "admin", "integrityLevel": "MEDIUM"},
                "scores": {"verdict": {"score": 100, "threatLevel": 2, "threatLevelText": "Malicious activity"}},
                "threatName": "AgentTesla",
                "status": "Exited",
                "exitCode": 0,
                "synchronization": [
                    {"time": 1793448002000, "name": "Global\\AgentMutex1", "type": "mutex", "operation": "create"},
                    {"time": 1793448002000, "name": "SomeEvent", "type": "event", "operation": "create"},
                ],
            },
            {
                "pid": 5555,
                "ppid": 4321,
                "uuid": PROC_CHILD,
                "parentUUID": PROC_MAIN,
                "important": False,
                "image": "C:\\Windows\\System32\\cmd.exe",
                "commandLine": "cmd.exe /c whoami",
                "times": {"start": 1793448003000},
                "status": "Exited",
                "synchronization": [
                    {"time": 1793448004000, "name": "IgnoredMutex", "type": "mutex", "operation": "create"}
                ],
            },
        ],
        "network": {
            "dnsRequests": [
                {"time": 1793448005000, "domain": "c2.evil.example.com", "ips": ["203.0.113.10", "2001:db8::10"], "reputation": "malicious"},
            ],
            "httpRequests": [
                {
                    "time": 1793448006000,
                    "method": "POST",
                    "host": "c2.evil.example.com",
                    "url": "http://c2.evil.example.com/gate.php",
                    "ip": "203.0.113.10",
                    "port": 80,
                    "user-agent": "Mozilla/5.0",
                    "status": "Completed",
                    "httpCode": 200,
                    "process": PROC_MAIN,
                    "reputation": "malicious",
                }
            ],
            "connections": [
                {
                    "ip": "203.0.113.10",
                    "port": 443,
                    "protocol": "TCP",
                    "country": "US",
                    "asn": "AS64500 Example Net",
                    "time": "2026-10-31T12:00:07.000Z",
                    "process": PROC_MAIN,
                    "reputation": "malicious",
                    "tlsFingerprint": {"ja3": "a0e9f5d64349fb13191bc781f81f42e1", "jarm": "2ad2ad0002ad2ad"},
                }
            ],
            "threats": [
                {
                    "time": "2026-10-31T12:00:08.000Z",
                    "srcip": "10.0.2.15",
                    "dstip": "203.0.113.10",
                    "srcport": 49712,
                    "dstport": 80,
                    "sid": 2030171,
                    "class": "A Network Trojan was detected",
                    "msg": "ET MALWARE AgentTesla Exfil Via HTTP",
                    "priority": 1,
                    "process": PROC_MAIN,
                },
                {
                    "time": "2026-10-31T12:00:08.000Z",
                    "srcip": "10.0.2.15",
                    "dstip": "203.0.113.10",
                    "srcport": 49712,
                    "dstport": 80,
                    "sid": 2030171,
                    "class": "A Network Trojan was detected",
                    "msg": "ET MALWARE AgentTesla Exfil Via HTTP",
                    "priority": 1,
                    "process": PROC_MAIN,
                },
            ],
        },
        "modified": {
            "files": [
                {
                    "time": 1793448009000,
                    "filename": "C:\\Users\\admin\\AppData\\Roaming\\payload.dll",
                    "size": len(DROPPED),
                    "type": "executable",
                    "threatLevel": "HIGH",
                    "process": PROC_MAIN,
                    "permanentUrl": f"{content}/files/{PROC_CHILD}/cd34",
                    "info": {"file": "PE32 DLL", "mime": "application/x-dosexec"},
                    "hashes": {"md5": DROPPED_MD5, "sha256": DROPPED_SHA256},
                },
                {
                    "time": 1793448010000,
                    "filename": "C:\\Users\\admin\\notes.txt",
                    "size": 5,
                    "threatLevel": "UNKNOWN",
                    "process": PROC_MAIN,
                    "hashes": {"md5": "d41d8cd98f00b204e9800998ecf8427e"},
                },
            ],
            "registry": [
                {
                    "key": "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "name": "Updater",
                    "value": "C:\\Users\\admin\\AppData\\Roaming\\payload.dll",
                    "operation": "write",
                    "process": PROC_MAIN,
                    "time": 1793448011000,
                },
                {
                    "key": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
                    "name": "DisableAntiSpyware",
                    "value": "1",
                    "operation": "write",
                    "process": PROC_MAIN,
                    "time": 1793448012000,
                },
                {
                    "key": "HKEY_CURRENT_USER\\SOFTWARE\\Old",
                    "name": "",
                    "value": "",
                    "operation": "delete key",
                    "process": PROC_CHILD,
                    "time": 1793448013000,
                },
            ],
        },
        "incidents": [
            {
                "threatLevel": 2,
                "title": "Changes the autorun value in the registry",
                "desc": "",
                "process": PROC_MAIN,
                "events": [
                    # The same write as modified.registry, with the value's type.
                    {"_id": "e1", "time": "2026-10-31T12:00:11.000Z", "operation": "write", "key": RUNKEY,
                     "name": "Updater", "value": "C:\\Users\\admin\\AppData\\Roaming\\payload.dll",
                     "typeValue": "REG_SZ"},
                    {"_id": "e2", "time": "2026-10-31T12:00:11.500Z", "operation": "write",
                     "key": "HKEY_CURRENT_USER\\SOFTWARE\\Agent", "name": "Count", "value": "0x10",
                     "typeValue": "REG_DWORD"},
                    {"_id": "e3", "time": "2026-10-31T12:00:11.600Z", "operation": "delete value",
                     "key": "HKEY_CURRENT_USER\\SOFTWARE\\Agent", "name": "Old", "value": ""},
                    {"_id": "e4", "time": "2026-10-31T12:00:11.700Z", "operation": "read",
                     "key": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography", "name": "MachineGuid",
                     "value": "abc", "typeValue": "REG_SZ"},
                ],
            },
            {
                "threatLevel": 1,
                "title": "Drops and changes files",
                "desc": "",
                "process": PROC_MAIN,
                "events": [
                    # Already in modified.files, so it's not modeled again.
                    {"_id": "f1", "time": "2026-10-31T12:00:09.000Z", "operation": "CREATE", "device": "C:",
                     "object": "", "name": "C:\\Users\\admin\\AppData\\Roaming\\payload.dll", "status": 0},
                    {"_id": "f2", "time": "2026-10-31T12:00:14.000Z", "operation": "WRITE", "device": "C:",
                     "object": "", "name": "C:\\Users\\admin\\notes.txt", "status": 0},
                    {"_id": "f3", "time": "2026-10-31T12:00:15.000Z", "operation": "DELETE", "device": "C:",
                     "object": "", "name": "C:\\Users\\admin\\AppData\\Local\\Temp\\invoice.exe", "status": 0},
                    {"_id": "f4", "time": "2026-10-31T12:00:16.000Z", "operation": "WRITE", "device": "C:",
                     "object": "", "name": "C:\\Users\\admin\\a.tmp", "newname": "C:\\Users\\admin\\b.exe",
                     "status": 0},
                    {"_id": "f5", "time": "2026-10-31T12:00:17.000Z", "operation": "READ", "device": "C:",
                     "object": "", "name": "C:\\Windows\\win.ini", "status": 0},
                    {"_id": "f6", "time": "2026-10-31T12:00:18.000Z", "operation": "CLOSE", "device": "C:",
                     "object": "", "name": "C:\\Windows\\win.ini", "status": 0},
                    {"_id": "f7", "time": "2026-10-31T12:00:19.000Z", "filename": "C:\\Users\\admin\\second.bin",
                     "contentType": "application/octet-stream", "size": len(DROP2), "md5": DROP2_MD5,
                     "sha1": hashlib.sha1(DROP2).hexdigest(), "sha256": DROP2_SHA256},
                ],
            },
        ],
        "mitre": [
            {"id": "T1555", "name": "Credentials from Password Stores", "phases": ["Credential Access"]},
            {"id": "T1059.003", "name": "Windows Command Shell", "phases": ["Execution"]},
        ],
        "malconf": [
            {
                "config": {
                    "C2": "c2.evil.example.com:587, 198.51.100.7:8080",
                    "Keys": {},
                    "Options": {"Protocol": "smtp"},
                    "Strings": [],
                },
                "family": "AgentTesla",
                "processPID": 4321,
                "processTime": 1793448001000,
            }
        ],
        "debugStrings": [],
    }


def urlReport() -> dict:
    """The data of GET /v1/analysis/{URLTASK}: a suspicious URL task."""

    return {
        "status": "done",
        "analysis": {
            "uuid": URLTASK,
            "permanentUrl": f"https://app.any.run/tasks/{URLTASK}",
            "creationText": "2026-10-30T09:00:00.000Z",
            "tags": ["phishing"],
            "options": {"privateSample": False},
            "scores": {"verdict": {"score": 60, "threatLevel": 1, "threatLevelText": "Suspicious activity"}},
            "content": {
                "mainObject": {
                    "type": "url",
                    "url": URL,
                    "basename": URL,
                    "hashes": {"md5": "0" * 32, "sha256": "1" * 64},
                }
            },
        },
        "processes": [],
        "network": {"dnsRequests": [], "httpRequests": [], "connections": [], "threats": []},
        "modified": {"files": []},
        "mitre": [],
        "malconf": [],
    }


def history() -> list[dict]:
    """GET /v1/analysis tasks (SandboxV1 TaskHistoryDto)."""

    return [
        {
            "uuid": TASK,
            "verdict": "Malicious activity",
            "name": "invoice.exe",
            "related": f"https://app.any.run/tasks/{TASK}",
            "json": f"https://api.any.run/report/{TASK}/summary/json",
            "misp": f"https://api.any.run/report/{TASK}/summary/misp",
            "tags": ["agenttesla"],
            "date": "2026-10-31T12:00:00.000Z",
            "hashes": {"md5": SAMPLE_MD5, "sha1": SAMPLE_SHA1, "sha256": SAMPLE_SHA256, "ssdeep": SAMPLE_SSDEEP},
        },
        {
            "uuid": URLTASK,
            "verdict": "Suspicious activity",
            "name": URL,
            "related": f"https://app.any.run/tasks/{URLTASK}",
            "json": f"https://api.any.run/report/{URLTASK}/summary/json",
            "misp": f"https://api.any.run/report/{URLTASK}/summary/misp",
            "tags": [],
            "date": "2026-10-30T09:00:00.000Z",
            "hashes": {"md5": "0" * 32},
        },
    ]


def lookupResponse() -> dict:
    """POST /v1/intelligence/api/search for the C2 domain (TIV1 ResponseApiDto)."""

    return {
        "summary": {
            "threatLevel": 2,
            "lastSeen": "2026-10-31T12:00:00.000Z",
            "detectedType": "domain",
            "isTrial": False,
            "tags": ["agenttesla", "stealer"],
            "details": [{"type": "domain", "threatLevel": 2, "lastSeen": "2026-10-31T12:00:00.000Z", "count": 3}],
        },
        "destinationPort": [587, 443],
        "destinationIPgeo": ["us"],
        "destinationIpAsn": [{"asn": "example net", "date": "2026-10-31T12:00:00.000Z"}],
        "relatedTasks": [f"https://app.any.run/tasks/{TASK}"],
        "threatName": [{"threatName": "agenttesla", "count": 3}],
        "submissionCountries": [{"countryName": "DE", "count": 2}],
        "industries": [],
        "relatedIncidents": [
            {"task": f"https://app.any.run/tasks/{TASK}", "time": "2026-10-31T12:00:00.000Z", "MITRE": ["1555", "1082"], "threatName": ["agenttesla"]}
        ],
        "destinationIP": [
            {"destinationIP": "203.0.113.10", "date": "2026-10-31T12:00:00.000Z", "threatLevel": 2, "threatName": ["agenttesla"], "isMalconf": True},
            {"destinationIP": "not-an-ip", "threatLevel": 0},
        ],
        "relatedFiles": [
            {
                "task": f"https://app.any.run/tasks/{TASK}",
                "time": "2026-10-31T12:00:00.000Z",
                "fileName": "C:\\Users\\admin\\AppData\\Local\\Temp\\invoice.exe",
                "hashes": {"md5": SAMPLE_MD5, "sha1": SAMPLE_SHA1, "sha256": SAMPLE_SHA256},
            }
        ],
        "relatedDNS": [
            {"domainName": "c2.evil.example.com", "threatName": ["agenttesla"], "threatLevel": 2, "date": "2026-10-31T12:00:00.000Z", "isMalconf": True},
        ],
        "relatedURLs": [
            {"url": "http://c2.evil.example.com/gate.php", "date": "2026-10-31T12:00:00.000Z", "threatLevel": 2, "threatName": ["agenttesla"], "isMalconf": False},
        ],
        "sourceTasks": [
            {
                "uuid": URLTASK,
                "related": f"https://app.any.run/tasks/{URLTASK}",
                "date": "2026-10-30T09:00:00.000Z",
                "threatLevel": 1,
                "tags": [],
                "mainObject": {"type": "url", "name": URL, "hashes": {}},
            },
            {
                "uuid": TASK,
                "related": f"https://app.any.run/tasks/{TASK}",
                "date": "2026-10-31T12:00:00.000Z",
                "threatLevel": 2,
                "tags": ["agenttesla"],
                "mainObject": {"type": "file", "name": "invoice.exe", "hashes": {"sha256": SAMPLE_SHA256, "md5": SAMPLE_MD5}},
            },
        ],
        "relatedSynchronizationObjects": [
            {"syncObjectTime": "2026-10-31T12:00:00.000Z", "syncObjectType": "MUTEX", "syncObjectOperation": "CREATE", "syncObjectName": "Global\\AgentMutex1", "task": TASK}
        ],
        "relatedNetworkThreats": [
            {"suricataClass": "A Network Trojan was detected", "suricataID": "2030171", "suricataMessage": "ET MALWARE AgentTesla Exfil Via HTTP", "MITRE": ["1071"], "suricataThreatLevel": "malicious", "task": TASK}
        ],
        "totalTasks": 2,
        "totalRelatedFiles": 1,
    }


def emptyLookup() -> dict:
    """A TI Lookup with no results."""

    return {
        "summary": {"threatLevel": None, "tags": []},
        "relatedIncidents": [],
        "destinationIP": [],
        "relatedFiles": [],
        "relatedDNS": [],
        "relatedURLs": [],
        "sourceTasks": [],
        "relatedSynchronizationObjects": [],
        "relatedNetworkThreats": [],
    }


def yaraMatches() -> list[dict]:
    """GET /v1/intelligence/yara-lookup/search/{id} matches (TIV1 MatchedSampleDto)."""

    return [
        {
            "firstSeen": "2026-01-15T08:30:00.000Z",
            "lastSeen": "2026-05-04T14:22:00.000Z",
            "hashes": {"sha256": MATCH_SHA256, "md5": "d41d8cd98f00b204e9800998ecf8427e"},
            "download": f"https://content.any.run/tasks/{TASK}/download/files/x/",
            "tasks": [f"https://app.any.run/tasks/{TASK}"],
            "filePartName": "invoice_2026.exe",
            "fileFullName": "C:\\Users\\admin\\Downloads\\invoice_2026.exe",
            "fileSize": 245760,
            "fileExt": ".exe",
            "relatedTags": ["trojan", "AgentTesla"],
            "discoveringEntryId": "60f1e2d3c4b5a69788796a5b",
            "task": "60f1e2d3c4b5a69788796a5c",
            "taskUUID": TASK,
        },
        {"hashes": {"md5": "d41d8cd98f00b204e9800998ecf8427e"}, "taskUUID": TASK},
    ]


def stixObjects() -> list[dict]:
    """TAXII 2.1 objects from the full collection."""

    base = {"spec_version": "2.1", "created": "2026-10-30T00:00:00.000Z", "modified": "2026-10-31T00:00:00.000Z"}
    return [
        dict(base, type="indicator", id="indicator--1", pattern="[ipv4-addr:value = '203.0.113.10']",
             pattern_type="stix", valid_from="2026-10-30T00:00:00.000Z", labels=["malicious-activity"]),
        dict(base, type="indicator", id="indicator--2", pattern="[domain-name:value = 'C2.Evil.Example.com']",
             pattern_type="stix", valid_from="2026-10-30T00:00:00.000Z", labels=["malicious-activity"]),
        dict(base, type="identity", id="identity--1", name="ANY.RUN"),
        dict(base, type="indicator", id="indicator--3", pattern="[url:value = 'http://c2.evil.example.com/gate.php']",
             pattern_type="stix", valid_from="2026-10-30T00:00:00.000Z"),
        dict(base, type="indicator", id="indicator--4", pattern="[ipv4-addr:value = '198.51.100.0/24']",
             pattern_type="stix"),
        dict(base, type="indicator", id="indicator--5",
             pattern=f"[file:hashes.'SHA-256' = '{SAMPLE_SHA256}']", pattern_type="stix"),
    ]


class FakeAnyRun:
    """The fake ANY.RUN server. ``state`` can be changed between requests."""

    def __init__(self):
        self.url = None
        self.requests = []
        self.runner = None
        self.state = {
            "history": history(),
            # More task reports, by task ID.
            "reports": {},
            "lookup": lookupResponse(),
            # Submissions are queued (202) instead of started (201).
            "queue": False,
            # The monitor events of tasks, by task ID. Defaults to a single "completed" event.
            "events": {},
            # How many polls of a YARA search return "processing" before "done".
            "yara_polls": 1,
            "yara_matches": yaraMatches(),
            "stix": stixObjects(),
            "stix_page": 2,
            # Return a 429 with nextAvailableRequestDate this many times from TI Lookup.
            "lookup_429": 0,
        }
        self.yarapolls = 0

    def reports(self) -> dict:
        ret = {TASK: fileReport(self.url), URLTASK: urlReport()}
        ret.update(self.state["reports"])
        return ret

    def record(self, request: web.Request, body) -> None:
        self.requests.append(
            {
                "method": request.method,
                "path": request.path,
                "query": dict(request.query),
                "rawquery": request.raw_path.partition("?")[2],
                "headers": dict(request.headers),
                "body": body,
            }
        )

    def paths(self, method: str | None = None) -> list[str]:
        return [r["path"] for r in self.requests if method is None or r["method"] == method]

    @staticmethod
    def js(data, status=200):
        return web.Response(text=json.dumps(data), status=status, content_type="application/json")

    @staticmethod
    def sandboxErr(mesg, status):
        return web.Response(
            text=json.dumps({"error": True, "message": mesg}), status=status, content_type="application/json"
        )

    async def handle(self, request: web.Request) -> web.StreamResponse:
        body = None
        if request.content_type == "application/json":
            body = await request.json()
        elif request.content_type == "multipart/form-data":
            body = {}
            async for part in await request.multipart():
                data = await part.read()
                body[part.name] = {"filename": part.filename, "data": data} if part.filename else data.decode()
        self.record(request, body)

        path = request.path
        auth = request.headers.get("Authorization", "")
        if auth.lower() != f"api-key {APIKEY}":
            if path.startswith("/v1/intelligence") or path.startswith("/v1/feeds"):
                return self.js(
                    {"message": "Invalid API key. Please use your correct API key for this request.", "code": "API_KEY_ERROR"},
                    status=401,
                )
            return self.sandboxErr("Wrong authorization data", 403)

        method = request.method
        parts = [p for p in path.split("/") if p]
        reports = self.reports()

        # ---- Sandbox ----
        if path == "/v1/user" and method == "GET":
            return self.js({"error": False, "data": {"limits": {"web": {"minute": -1, "hour": -1, "day": -1, "month": -1}, "api": {"minute": -1, "hour": -1, "day": -1, "month": 250}, "parallels": {"total": 1, "available": 1}}}})
        if path == "/v1/user/presets":
            return self.js([{"_id": "QiRRnjH9JNnbmevtH", "name": "Default", "os": "Windows", "version": "10", "bitness": 64, "timeout": 60, "privacy": "byteam"}])
        if path == "/v1/environment":
            return self.js({"error": False, "data": {"environments": [
                {"build": 22000, "variant": "professional", "version": "11", "type": "complete", "os": "windows", "software": {"ie": {}, "apps": [], "upps": []}, "bitness": 64},
                {"build": 22042, "variant": "ubuntu", "version": "22.04.2", "type": "complete", "os": "linux", "software": {"ie": {}, "apps": [], "upps": []}, "bitness": 64},
            ]}})
        if path == "/v1/analysis" and method == "GET":
            skip = int(request.query.get("skip", 0))
            limit = int(request.query.get("limit", 25))
            return self.js({"error": False, "data": {"tasks": self.state["history"][skip : skip + limit]}})
        if path == "/v1/analysis" and method == "POST":
            if self.state["queue"]:
                return self.js(
                    {"error": "false,", "message": "Task is queued and awaits execution. To track its status, call GET /v1/analysis/monitor/{queueTaskId}.", "data": {"queueTaskId": QUEUED}},
                    status=202,
                )
            if isinstance(body, dict) and body.get("opt_privacy_type") == "public":
                return self.sandboxErr("Users with the branded reports feature enabled cannot create public tasks.", 400)
            return self.js({"error": False, "data": {"taskid": NEWTASK}}, status=201)
        if len(parts) == 4 and parts[:2] == ["v1", "analysis"] and parts[2] in ("addtime", "stop", "delete"):
            task = parts[3]
            if task not in reports:
                return self.sandboxErr("Task not found", 404)
            if parts[2] == "delete":
                return self.js({"error": False, "message": "Delete task successful"}, status=202)
            if parts[2] == "stop":
                return self.sandboxErr(f"Task {task} has already been completed", 400)
            return self.js({"error": False, "message": "Add time in task successful"}, status=202)
        if len(parts) == 4 and parts[:3] == ["v1", "analysis", "monitor"]:
            return await self.monitor(request, parts[3])
        if len(parts) == 3 and parts[:2] == ["v1", "analysis"]:
            if parts[2] not in reports:
                return self.sandboxErr("Task not found", 404)
            return self.js({"error": False, "data": reports[parts[2]]})

        # ---- Reports ----
        if parts[:1] == ["report"] and len(parts) >= 3:
            task = parts[1]
            if task not in reports:
                return self.sandboxErr("Task not found", 404)
            if parts[2:] == ["ioc", "json"]:
                return self.js([
                    {"category": "Main object", "type": "sha256", "name": "invoice.exe", "ioc": SAMPLE_SHA256, "reputation": 2},
                    {"category": "DNS requests", "type": "domain", "ioc": "c2.evil.example.com", "reputation": 2},
                    {"category": "Connections", "type": "ip", "ioc": "8.8.8.8", "reputation": 0},
                ])
            if parts[2:] == ["ai"]:
                return self.js({"aiSummary": {"Verdict": "Malicious. An AgentTesla stealer."}})
            if parts[2] == "summary" and len(parts) == 4:
                return self.js({"format": parts[3], "task": task})

        # ---- Content ----
        if parts[:1] == ["tasks"] and len(parts) >= 4 and parts[2] == "download":
            task = parts[1]
            if task not in reports:
                return web.Response(status=404, text="Not found")
            if parts[3] == "mp4":
                return web.Response(body=VIDEO, content_type="video/mp4")
            if parts[3] == "screens" and parts[5:] == ["image.jpeg"]:
                byts = {SCREEN1: JPEG1, SCREEN2: JPEG2}.get(parts[4])
                if byts is None:
                    return web.Response(status=404, text="Not found")
                return web.Response(body=byts, content_type="image/jpeg")
            if parts[3] == "pcap":
                return web.Response(body=PCAP, content_type="application/octet-stream")
            if parts[3:] == ["files", PROC_MAIN, "ab12"]:
                return web.Response(body=zipped(SAMPLE_SHA256, SAMPLE), content_type="application/zip")
            if parts[3:] == ["files", PROC_CHILD, "cd34"]:
                return web.Response(body=DROPPED, content_type="application/octet-stream")
            return web.Response(status=404, text="Not found")

        # ---- TI Lookup ----
        if path == "/v1/intelligence/api/search" and method == "POST":
            if self.state["lookup_429"]:
                self.state["lookup_429"] -= 1
                return self.js(
                    {"message": "Too many requests. Try later.", "code": "TOO_MANY_REQUESTS", "nextAvailableRequestDate": "2020-01-01T00:00:00.000Z"},
                    status=429,
                )
            query = (body or {}).get("query")
            if not query:
                return self.js(
                    {"message": "The query syntax is incorrect.", "code": "WRONG_QUERY_ERROR", "validationErrors": [{"field": "query", "error": "query should not be empty"}]},
                    status=400,
                )
            if "nothing" in query:
                return self.js(emptyLookup())
            return self.js(self.state["lookup"])

        # ---- YARA Search ----
        if path == "/v1/intelligence/yara-lookup/search" and method == "POST":
            if "rule" not in (body or {}).get("query", ""):
                return self.js({"message": "Invalid YARA rule. Please review: ...", "code": "WRONG_QUERY_ERROR"}, status=400)
            self.yarapolls = 0
            return self.js(self.jobInfo("new"))
        if parts[:4] == ["v1", "intelligence", "yara-lookup", "search"] and len(parts) >= 5:
            if parts[4] != YARA_ID:
                return self.js({"message": "Not found.", "code": "NOT_FOUND"}, status=404)
            if parts[5:] == ["count"]:
                self.yarapolls += 1
                status = "done" if self.yarapolls > self.state["yara_polls"] else "processing"
                found = len(self.state["yara_matches"]) if status == "done" else 0
                return self.js({"foundMatches": found, "searchInfo": self.jobInfo(status)})
            if method == "DELETE":
                return self.js(self.jobInfo("cancelled"))
            offset = int(request.query.get("offset", 0))
            limit = int(request.query.get("limit", 100))
            matches = self.state["yara_matches"][offset : offset + limit]
            return self.js({"searchInfo": self.jobInfo("done"), "matches": matches})

        # ---- TAXII ----
        if path == "/v1/feeds/taxii2/api1/collections/":
            return self.js({"collections": [{"id": "3dce855a-c044-5d49-9334-533c24678c5a", "title": "full", "description": "All indicators", "can_read": True, "can_write": False}]})
        if parts[:5] == ["v1", "feeds", "taxii2", "api1", "collections"] and parts[6:] == ["objects"]:
            if parts[5] != "3dce855a-c044-5d49-9334-533c24678c5a":
                return self.js({"title": "Not Found", "description": f"Collection with ID '{parts[5]}' could not be found."}, status=404)
            objs = self.state["stix"]
            # The cursor is base64 like ANY.RUN's, ex. "Mg==" for 2.
            cursor = request.query.get("next")
            start = int(base64.b64decode(cursor)) if cursor else 0
            size = min(int(request.query.get("limit", 10)), self.state["stix_page"])
            page = objs[start : start + size]
            more = start + size < len(objs)
            ret = {"type": "bundle", "id": "bundle--1", "spec_version": "2.1", "objects": page, "more": more}
            if more:
                ret["next"] = base64.b64encode(str(start + size).encode()).decode()
            return web.Response(text=json.dumps(ret), content_type="application/taxii+json", charset="utf-8")

        return self.sandboxErr("Not found", 404)

    def jobInfo(self, status: str) -> dict:
        return {
            "query": YARA_RULE,
            "queryId": YARA_ID,
            "ruleName": "grimresources",
            "status": status,
            "created": "2026-10-31T10:15:00.000Z",
        }

    async def monitor(self, request: web.Request, task: str) -> web.StreamResponse:
        events = self.state["events"].get(task)
        if events is None:
            if task not in self.reports():
                return self.sandboxErr("Task not found", 404)
            events = [statusEvent(task, 100, completed=True)]
        resp = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await resp.prepare(request)
        for event in events:
            await resp.write(b"id: 1\n")
            await resp.write(b"data: " + json.dumps(event).encode() + b"\n\n")
        await resp.write_eof()
        return resp

    async def __aenter__(self):
        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", self.handle)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]  # pylint: disable=W0212
        self.url = f"http://127.0.0.1:{port}"
        return self

    async def __aexit__(self, *args):
        await self.runner.cleanup()


def statusEvent(task: str, status: int, completed: bool = False, verdict: str = "Malicious activity") -> dict:
    """A monitor event describing a task (SandboxV1 TaskStatusDto)."""

    return {
        "task": {
            "uuid": task,
            "status": status,
            "remaining": max(0, 60 - status),
            "times": {"startExec": "2026-10-31T12:00:00.000Z", "timeout": 60},
            "public": {"objects": {"runType": "file"}, "maxAddedTimeReached": False},
            "tags": ["agenttesla"],
            "usersTags": [],
            "scores": {"verdict": {"threat_level": 2, "text": verdict}, "specs": {}},
            "threats": ["AgentTesla"],
        },
        "completed": completed,
        "error": False,
    }


def svcConf(fake: FakeAnyRun, apikey: str | None = APIKEY, **kwargs) -> dict:
    conf = {
        "anyrun:url": fake.url,
        "anyrun:content_url": fake.url,
        "anyrun:apikey": apikey,
        "anyrun:poll": 0.01,
    }
    conf.update(kwargs)
    return conf


@contextlib.asynccontextmanager
async def anyrunSvc(test, apikey: str | None = APIKEY, **conf):
    """Yield (core, svc, fake) - a Cortex with slib.anyrun added, pointed at a FakeAnyRun."""

    from anyrunsvc import AnyRunSvc

    async with FakeAnyRun() as fake:
        sconf = svcConf(fake, apikey=apikey, **conf)
        async with test.getTestCoreProxSvc(AnyRunSvc, ssvc_conf=sconf) as (core, prox, svc):
            yield core, svc, fake

