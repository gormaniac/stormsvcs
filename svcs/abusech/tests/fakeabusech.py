"""A fake abuse.ch HTTP server for tests.

Serves canned responses for every abuse.ch API and dataset under a per-API path
prefix (ex. ``/bazaar/`` for MalwareBazaar, ``/urlhaus/url/`` for URLhaus) and
records every request so tests can assert exactly what the service sent.

The canned data is trimmed from (and shaped like) real abuse.ch responses.
"""


import contextlib
import hashlib
import io
import json
from typing import Any

import pyzipper
from aiohttp import web


SHA256 = "094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d"
MD5 = "f1f1e1d1c1b1a1918171615141312111"
SHA1 = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d"
SHA3 = "c" * 96
DROPPER = "d" * 64
UNPACKED = "e" * 64
PAYLOAD = "12c8aec5766ac3e6f26f2505e2f4a8f2" + "7" * 32
PAYLOAD_MD5 = "4" * 32
SAMPLE_BYTES = b"MZ this is not really malware"
SAMPLE_SHA256 = hashlib.sha256(SAMPLE_BYTES).hexdigest()

BAZAAR_INFO = {
    "sha256_hash": SHA256,
    "sha3_384_hash": SHA3,
    "sha1_hash": SHA1,
    "md5_hash": MD5,
    "first_seen": "2026-10-01 12:00:00",
    "last_seen": "2026-10-02 08:30:00",
    "file_name": "invoice.exe",
    "file_size": 1234567,
    "file_type_mime": "application/x-dosexec",
    "file_type": "exe",
    "reporter": "abuse_ch",
    "originator": None,
    "anonymous": 0,
    "signature": "AgentTesla",
    "imphash": "f34d5f2d4577ed6d9ceec516c1f5a744",
    "tlsh": "T1A2B3C4D5E6F7",
    "telfhash": None,
    "gimphash": None,
    "ssdeep": "24576:abcdefg:hijklmn",
    "dhash_icon": "e8e8b2b2b2b2e8e8",
    "comment": "Delivered via a fake invoice.",
    "archive_pw": None,
    "delivery_method": "email_attachment",
    "origin_country": "DE",
    "tags": ["AgentTesla", "exe"],
    "intelligence": {
        "clamav": ["Win.Trojan.AgentTesla-1234"],
        "downloads": "42",
        "uploads": "1",
        "mail": {"Generic": "12"},
    },
    "code_sign": [
        {
            "subject_cn": "Evil Corp LLC",
            "issuer_cn": "Sectigo RSA Code Signing CA",
            "algorithm": "sha256WithRSAEncryption",
            "valid_from": "2026-01-01 00:00:00",
            "valid_to": "2027-01-01 00:00:00",
            "serial_number": "00c8f5d1e1a2b3c4d5",
            "cscb_listed": True,
            "cscb_reason": "Used to sign AgentTesla",
            "thumbprint": "b" * 64,
            "thumbprint_algorithm": "sha256",
        },
    ],
    "file_information": [
        {"context": "twitter", "value": "https://twitter.com/abuse_ch/status/1"},
        {"context": "dropped_by_sha256", "value": DROPPER},
        {"context": "dropped_by_malware", "value": "GuLoader"},
        {"context": "comment", "value": "Seen in a phishing campaign"},
    ],
    "yara_rules": [
        {
            "rule_name": "AgentTesla_Strings",
            "author": "abuse.ch",
            "description": "Detects AgentTesla",
            "reference": "https://bazaar.abuse.ch/browse/signature/AgentTesla/",
        },
    ],
    "vendor_intel": {
        "ANY.RUN": [
            {
                "malware_family": "agenttesla",
                "verdict": "Malicious activity",
                "file_name": "invoice.exe",
                "date": "2026-10-01 12:05:00",
                "tags": ["agenttesla", "trojan"],
                "analysis_url": "https://app.any.run/tasks/1234",
            },
        ],
        "Triage": {
            "malware_family": "agenttesla",
            "score": "10",
            "link": "https://tria.ge/reports/1234/",
            "tags": ["family:agenttesla", "keylogger"],
            "signatures": [{"signature": "AgentTesla", "score": "10"}],
        },
        "ReversingLabs": {
            "threat_name": "Win32.Trojan.AgentTesla",
            "status": "MALICIOUS",
            "first_seen": "2026-10-01 12:00:00",
            "scanner_count": "50",
            "scanner_match": "40",
            "scanner_percent": "80.0",
            "report_link": "https://a1000.reversinglabs.com/1234",
        },
        "UnpacMe": [
            {
                "sha256_hash": UNPACKED,
                "md5_hash": "9" * 32,
                "sha1_hash": "8" * 40,
                "detections": ["AgentTesla"],
                "link": "https://www.unpac.me/results/1234",
            },
        ],
    },
    "comments": [
        {"id": "1", "date_added": "2026-10-01 13:00:00", "twitter_handle": "analyst", "display_name": "Analyst",
         "comment": "Confirmed AgentTesla."},
    ],
}

BAZAAR_LIST = [
    {
        "sha256_hash": SHA256, "sha3_384_hash": SHA3, "sha1_hash": SHA1, "md5_hash": MD5,
        "first_seen": "2026-10-01 12:00:00", "last_seen": None, "file_name": "invoice.exe",
        "file_size": 1234567, "file_type_mime": "application/x-dosexec", "file_type": "exe",
        "reporter": "abuse_ch", "anonymous": 0, "signature": "AgentTesla",
        "imphash": "f34d5f2d4577ed6d9ceec516c1f5a744", "tlsh": "T1A2B3C4D5E6F7", "telfhash": None,
        "gimphash": None, "ssdeep": "24576:abcdefg:hijklmn", "dhash_icon": None,
        "tags": ["AgentTesla", "exe"], "code_sign": [], "intelligence": {"clamav": None, "downloads": "1",
                                                                           "uploads": "1", "mail": None},
    },
    {
        "sha256_hash": "f" * 64, "sha1_hash": "f" * 40, "md5_hash": "f" * 32,
        "first_seen": "2026-10-03 00:00:00", "file_name": "loader.dll", "file_size": 2048,
        "file_type_mime": "application/x-dosexec", "file_type": "dll", "reporter": "anonymous",
        "anonymous": 1, "signature": None, "tags": ["dll"],
    },
]

CSCB = [
    {
        "time_stamp": "2026-09-01 10:00:00",
        "serial_number": "0a1b2c3d",
        "thumbprint": "1" * 64,
        "thumbprint_algorithm": "sha256",
        "subject_cn": "Bad Signer Ltd",
        "issuer_cn": "DigiCert Code Signing CA",
        "cscb_reason": "Malware signing (Emotet)",
        "valid_from": "2026-01-01 00:00:00",
        "valid_to": "2027-01-01 00:00:00",
    },
]

URLHAUS_URL = {
    "query_status": "ok",
    "id": "105821",
    "urlhaus_reference": "https://urlhaus.abuse.ch/url/105821/",
    "url": "http://evil.example.com/bins/mozi.m",
    "url_status": "online",
    "host": "evil.example.com",
    "date_added": "2026-10-01 10:00:00 UTC",
    "last_online": "2026-10-03 10:00:00 UTC",
    "threat": "malware_download",
    "blacklists": {"spamhaus_dbl": "abused_legit_malware", "surbl": "not listed"},
    "reporter": "lrz_urlhaus",
    "larted": "true",
    "takedown_time_seconds": None,
    "tags": ["elf", "Mozi"],
    "payloads": [
        {
            "firstseen": "2026-10-01",
            "filename": "mozi.m",
            "file_type": "elf",
            "response_size": "307960",
            "response_md5": PAYLOAD_MD5,
            "response_sha256": PAYLOAD,
            "urlhaus_download": f"https://urlhaus-api.abuse.ch/v1/download/{PAYLOAD}/",
            "signature": "Mozi",
            "virustotal": {"result": "10 / 60", "percent": "16.67", "link": "https://www.virustotal.com/gui/file/x"},
            "imphash": None,
            "ssdeep": "6144:abc:def",
            "tlsh": "T1FFFF",
            "magika": "elf",
        },
    ],
}

URLHAUS_HOST = {
    "query_status": "ok",
    "urlhaus_reference": "https://urlhaus.abuse.ch/host/1.2.3.4/",
    "host": "1.2.3.4",
    "firstseen": "2026-09-01 00:00:00 UTC",
    "url_count": "1",
    "blacklists": {"spamhaus_dbl": "not listed", "surbl": "not listed"},
    "urls": [
        {
            "id": "2000",
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/2000/",
            "url": "http://1.2.3.4/i",
            "url_status": "offline",
            "date_added": "2026-09-01 00:00:00 UTC",
            "threat": "malware_download",
            "reporter": "anonymous",
            "larted": "false",
            "takedown_time_seconds": "3600",
            "tags": ["32-bit", "mirai"],
        },
    ],
}

URLHAUS_PAYLOAD = {
    "query_status": "ok",
    "md5_hash": PAYLOAD_MD5,
    "sha256_hash": PAYLOAD,
    "file_type": "elf",
    "file_size": "307960",
    "signature": "Mozi",
    "firstseen": "2026-10-01 10:00:00",
    "lastseen": "2026-10-03 10:00:00",
    "url_count": "1",
    "urlhaus_download": f"https://urlhaus-api.abuse.ch/v1/download/{PAYLOAD}/",
    "virustotal": None,
    "imphash": None,
    "ssdeep": "6144:abc:def",
    "tlsh": "T1FFFF",
    "magika": "elf",
    "urls": [
        {
            "url_id": "105821",
            "url": "http://evil.example.com/bins/mozi.m",
            "url_status": "online",
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/105821/",
            "filename": "mozi.m",
            "firstseen": "2026-10-01",
            "lastseen": None,
        },
    ],
}

URLHAUS_TAG = {
    "query_status": "ok",
    "firstseen": "2026-01-01 00:00:00 UTC",
    "lastseen": "2026-10-01 00:00:00 UTC",
    "url_count": "2",
    "urls": [
        {"url_id": "3000", "url": "http://bad.example.net/a.sh", "url_status": "online",
         "urlhaus_reference": "https://urlhaus.abuse.ch/url/3000/", "dateadded": "2026-10-01 00:00:00 UTC",
         "threat": "malware_download"},
        {"url_id": "3001", "url": "http://bad.example.net/b.sh", "url_status": "offline",
         "urlhaus_reference": "https://urlhaus.abuse.ch/url/3001/", "dateadded": "2026-09-01 00:00:00 UTC",
         "threat": "malware_download"},
    ],
}

URLHAUS_SIGNATURE = {
    "query_status": "ok",
    "firstseen": "2026-01-01 00:00:00 UTC",
    "lastseen": "2026-10-01 00:00:00 UTC",
    "url_count": "1",
    "payload_count": "1",
    "urls": [
        {"url_id": "105821", "url": "http://evil.example.com/bins/mozi.m", "url_status": "online",
         "urlhaus_reference": "https://urlhaus.abuse.ch/url/105821/", "filename": "mozi.m",
         "firstseen": "2026-10-01 10:00:00", "lastseen": None, "file_type": "elf", "file_size": "307960",
         "md5_hash": PAYLOAD_MD5, "sha256_hash": PAYLOAD,
         "virustotal": {"result": "0 / 60", "percent": "0.00", "link": "https://www.virustotal.com/gui/file/y"},
         "imphash": None, "ssdeep": None, "tlsh": None},
    ],
}

URLHAUS_RECENT_URLS = {"query_status": "ok", "urls": [dict(URLHAUS_URL, payloads=None)]}
URLHAUS_RECENT_PAYLOADS = {
    "query_status": "ok",
    "payloads": [{"md5_hash": PAYLOAD_MD5, "sha256_hash": PAYLOAD, "file_type": "elf", "file_size": "307960",
                  "signature": "Mozi", "firstseen": "2026-10-01 10:00:00", "urlhaus_download": "x",
                  "virustotal": None, "imphash": None, "ssdeep": None, "tlsh": None}],
}

THREATFOX_IOC = {
    "id": "41",
    "ioc": "gaga.com",
    "threat_type": "botnet_cc",
    "threat_type_desc": "Indicator that identifies a botnet command&control server (C&C)",
    "ioc_type": "domain",
    "ioc_type_desc": "Domain that is used for botnet Command&control (C&C)",
    "malware": "win.dridex",
    "malware_printable": "Dridex",
    "malware_alias": None,
    "malware_malpedia": "https://malpedia.caad.fkie.fraunhofer.de/details/win.dridex",
    "confidence_level": 50,
    "first_seen": "2026-10-01 07:00:00 UTC",
    "last_seen": None,
    "reference": "https://twitter.com/abuse_ch/status/2",
    "reporter": "abuse_ch",
    "comment": "Dridex C2 seen in the wild.",
    "tags": ["exe", "test"],
    "credits": [{"credits_from": "abuse_ch", "credits_amount": 5}],
    "malware_samples": [
        {"time_stamp": "2026-10-01 07:00:00 UTC", "md5_hash": MD5, "sha256_hash": SHA256,
         "malware_bazaar": f"https://bazaar.abuse.ch/sample/{SHA256}/"},
    ],
}

THREATFOX_IPPORT = {
    "id": "42",
    "ioc": "5.6.7.8:443",
    "threat_type": "botnet_cc",
    "threat_type_desc": "C2",
    "ioc_type": "ip:port",
    "malware": "win.cobalt_strike",
    "malware_printable": "Cobalt Strike",
    "malware_alias": "Agentemis,BEACON,CobaltStrike",
    "malware_malpedia": "https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike",
    "confidence_level": 100,
    "first_seen": "2026-10-02 00:00:00 UTC",
    "last_seen": "2026-10-03 00:00:00 UTC",
    "reference": None,
    "reporter": "anonymous",
    "tags": ["CobaltStrike", "cs-watermark-987654321"],
}

THREATFOX_URL = {
    "id": "43", "ioc": "http://c2.example.org/gate.php", "threat_type": "botnet_cc", "ioc_type": "url",
    "malware": "win.lokipws", "malware_printable": "Loki Password Stealer (PWS)", "malware_alias": "Burkina,Loki",
    "confidence_level": 75, "first_seen": "2026-10-02 00:00:00 UTC", "last_seen": None, "reporter": "x",
    "tags": None,
}

THREATFOX_HASH = {
    "id": "44", "ioc": SHA256, "threat_type": "payload", "ioc_type": "sha256_hash",
    "malware": "win.agent_tesla", "malware_printable": "Agent Tesla", "malware_alias": None,
    "confidence_level": 100, "first_seen": "2026-10-01 00:00:00 UTC", "last_seen": None, "reporter": "x",
    "tags": ["AgentTesla"],
}

THREATFOX_TYPES = {
    "1": {"ioc_type": "ip:port", "fk_threat_type": "botnet_cc", "description": "ip:port combination"},
    "2": {"ioc_type": "domain", "fk_threat_type": "botnet_cc", "description": "Domain"},
}
THREATFOX_TAGS = {"Emotet": {"first_seen": "2021-03-08 00:00:00", "last_seen": "2026-10-01 00:00:00", "color": "#ff0000"}}
THREATFOX_MALWARE = {"win.dridex": {"malware_printable": "Dridex", "malware_alias": None}}
THREATFOX_LABEL = [{"malware": "win.cobalt_strike", "malware_printable": "Cobalt Strike", "malware_alias": "BEACON"}]

YARAIFY_FILE = {
    "metadata": {
        "file_name": "invoice.exe", "file_size": 1234567, "file_type_mime": "application/x-dosexec",
        "first_seen": "2026-10-01 12:00:00", "last_seen": "2026-10-02 12:00:00", "sightings": 3,
        "sha256_hash": SHA256, "md5_hash": MD5, "sha1_hash": SHA1, "sha3_384": SHA3,
        "imphash": "f34d5f2d4577ed6d9ceec516c1f5a744", "ssdeep": "24576:abcdefg:hijklmn", "tlsh": "T1A2B3C4D5E6F7",
        "telfhash": None, "gimphash": "abcdef0123", "dhash_icon": None,
    },
    "tasks": [
        {
            "time_stamp": "2026-10-01 12:00:00",
            "task_id": "cfa49f83-6d98-11ed-a71a-42010aa4000b",
            "file_name": "invoice2.exe",
            "task_parameters": {"clamav_scan": True, "unpack": True, "share_file": True},
            "static_results": [
                {
                    "rule_name": "win_agent_tesla_auto",
                    "author": "Felix Bilstein - yara-signator at cocacoding dot com",
                    "description": "Detects win.agent_tesla.",
                    "reference": "https://malpedia.caad.fkie.fraunhofer.de/details/win.agent_tesla",
                    "tlp": "TLP:WHITE",
                    "yarahub_uuid": "6a6d2b48-1234-4cde-9f00-112233445566",
                    "yarahub_license": "CC BY-NC 4.0",
                    "malpedia_family": "win.agent_tesla",
                },
            ],
            "clamav_results": ["Win.Packed.Generic-1"],
            "unpacker_results": [
                {
                    "unpacked_file_name": "unpacked.bin",
                    "unpacked_md5": "9" * 32,
                    "unpacked_sha256": UNPACKED,
                    "unpacked_yara_matches": [{"rule_name": "AgentTesla_Unpacked", "author": "abuse.ch"}],
                },
            ],
        },
    ],
}

YARAIFY_SEARCH = [
    {"file_name": "x.exe", "sha256_hash": "a" * 64, "md5_hash": "a" * 32, "sha1_hash": "a" * 40,
     "first_seen": "2026-10-01 00:00:00", "file_size": 100},
]

YARA_RULE_TEXT = """rule win_agent_tesla_auto {
    meta:
        author = "Felix Bilstein"
        description = "Detects win.agent_tesla."
        yarahub_uuid = "6a6d2b48-1234-4cde-9f00-112233445566"
        yarahub_reference_link = "https://malpedia.caad.fkie.fraunhofer.de/details/win.agent_tesla"
        date = "2026-01-01"
        malpedia_family = "win.agent_tesla"
    strings:
        $a = "AgentTesla"
    condition:
        $a
}

private rule helper_rule {
    condition:
        true
}
"""

YARAIFY_RECENT_RULES = [
    {"time_stamp": "2026-10-01 00:00:00", "rule_name": "New_Rule_1", "author": "someone",
     "yarahub_uuid": "11111111-2222-3333-4444-555555555555", "yarahub_rule_matching_tlp": "TLP:WHITE"},
]

FPLIST = {
    "1": {"time_stamp": "2026-01-01 00:00:00 UTC", "platform": "MalwareBazaar", "entry_type": "sha256_hash",
          "entry_value": "0" * 64, "removed_by": "admin", "removal_notes": "Legitimate installer"},
    "2": {"time_stamp": "2026-01-02 00:00:00 UTC", "platform": "URLhaus", "entry_type": "domain",
          "entry_value": "legit.example.com", "removed_by": "admin", "removal_notes": None},
}

FEODO_JSON = [
    {"ip_address": "50.16.16.211", "port": 8080, "status": "online", "hostname": "ec2.example.com",
     "as_number": 14618, "as_name": "AMAZON-AES", "country": "US", "first_seen": "2026-08-01 00:00:00",
     "last_online": "2026-10-01", "malware": "QakBot"},
    {"ip_address": "60.1.2.3", "port": 443, "status": "offline", "hostname": None, "as_number": 4134,
     "as_name": "CHINANET", "country": "CN", "first_seen": "2026-07-01 00:00:00", "last_online": "2026-08-01",
     "malware": "Emotet"},
]
FEODO_RECOMMENDED = "# Feodo Tracker recommended\n50.16.16.211\n70.1.2.3\n"
FEODO_AGGRESSIVE = (
    "################################################################\n"
    '# first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware\n'
    '"2026-01-01 00:00:00","80.1.2.3","447","offline","2026-02-01","TrickBot"\n'
)

SSLBL_CERTS = (
    "# abuse.ch SSLBL SSL Certificate Blacklist (SHA1 Fingerprints)\n"
    "# Listingdate,SHA1,Listingreason\n"
    "2026-10-01 00:00:00,1111111111111111111111111111111111111111,Dridex C&C\n"
    "2026-09-01 00:00:00,2222222222222222222222222222222222222222,AsyncRAT C&C\n"
)
SSLBL_IPS = (
    "# abuse.ch SSLBL Botnet C2 IP Blacklist (CSV)\n"
    "# Firstseen,DstIP,DstPort\n"
    "2026-10-01 00:00:00,90.1.2.3,443\n"
)
SSLBL_JA3 = (
    "# ja3_md5,Firstseen,Lastseen,Listingreason\n"
    "51c64c77e60f3980eea90869b68c58a8,2017-07-14 18:08:15,2019-07-27 20:42:54,Dridex\n"
)

BAZAAR_CSV = (
    '################################################################\n'
    '# "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess",'
    '"mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh"\n'
    f'"2026-10-01 12:00:00", "{SHA256}", "{MD5}", "{SHA1}", "abuse_ch", "invoice.exe", "exe", '
    '"application/x-dosexec", "AgentTesla", "Win.Trojan.AgentTesla-1234", "65.5", '
    '"f34d5f2d4577ed6d9ceec516c1f5a744", "24576:abcdefg:hijklmn", "T1A2B3C4D5E6F7"\n'
    f'"2026-10-01 13:00:00", "{"b" * 64}", "{"b" * 32}", "{"b" * 40}", "anonymous", "a.zip", "zip", '
    '"application/zip", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a"\n'
)

URLHAUS_CSV = (
    "################################################################\n"
    "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
    '"4000","2026-10-01 00:00:00","http://csv.example.com/x.exe","online","2026-10-02 00:00:00",'
    '"malware_download","exe,AgentTesla","https://urlhaus.abuse.ch/url/4000/","reporter1"\n'
)

THREATFOX_EXPORT = {
    "50": [{"ioc_value": "export.example.com", "ioc_type": "domain", "threat_type": "botnet_cc",
            "fk_malware": "win.qakbot", "malware_alias": "Qbot,QuakBot", "malware_printable": "QakBot",
            "first_seen_utc": "2026-10-01 00:00:00", "last_seen_utc": None, "confidence_level": 75,
            "reference": None, "tags": "QakBot,TA570", "anonymous": "0", "reporter": "abuse_ch"}],
}


def mkzip(files: dict[str, bytes], password: bytes | None = None) -> bytes:
    """Build a zip (AES encrypted when there's a password, like abuse.ch's sample zips)."""

    buf = io.BytesIO()
    if password:
        with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zfd:
            zfd.setpassword(password)
            for name, byts in files.items():
                zfd.writestr(name, byts)
    else:
        with pyzipper.ZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED) as zfd:
            for name, byts in files.items():
                zfd.writestr(name, byts)
    return buf.getvalue()


def ok(data: Any = None, **kwargs) -> dict:
    retn = {"query_status": "ok"}
    if data is not None:
        retn["data"] = data
    retn.update(kwargs)
    return retn


class FakeAbuseCh:
    """An aiohttp server that pretends to be every abuse.ch API."""

    def __init__(self):
        self.requests: list[dict] = []
        self.runner = None
        self.port = None
        # Override a response with (status, body) keyed by (base, query or path).
        self.overrides: dict[tuple[str, str], tuple[int, Any]] = {}

    @property
    def urls(self) -> dict[str, str]:
        base = f"http://127.0.0.1:{self.port}"
        names = ("bazaar", "bazaar:export", "urlhaus", "urlhaus:submit", "urlhaus:export", "threatfox",
                 "threatfox:export", "yaraify", "yaraify:export", "hunting", "feodo", "sslbl")
        return {name: f"{base}/{name.replace(':', '_')}" for name in names}

    async def _record(self, request: web.Request) -> dict:
        info = {
            "method": request.method,
            "path": request.path,
            "query": dict(request.query),
            "authkey": request.headers.get("Auth-Key"),
            "form": {},
            "json": None,
            "files": {},
        }
        ctype = request.headers.get("Content-Type", "")
        if ctype.startswith("multipart/"):
            reader = await request.multipart()
            async for part in reader:
                if part.filename:
                    info["files"][part.name] = (part.filename, await part.read())
                else:
                    info["form"][part.name] = await part.text()
        elif "json" in ctype:
            info["json"] = await request.json()
        elif request.method == "POST":
            info["form"] = dict(await request.post())
        self.requests.append(info)
        return info

    def _json(self, data: Any, status: int = 200) -> web.Response:
        return web.Response(status=status, text=json.dumps(data), content_type="application/json")

    async def _handle(self, request: web.Request) -> web.StreamResponse:
        info = await self._record(request)
        parts = request.path.lstrip("/").split("/", 1)
        base = parts[0].replace("_", ":")
        path = parts[1] if len(parts) > 1 else ""
        query = info["form"].get("query") or (info["json"] or {}).get("query") or path

        override = self.overrides.get((base, query))
        if override is not None:
            status, body = override
            if isinstance(body, (bytes, str)):
                return web.Response(status=status, body=body)
            return self._json(body, status=status)

        if info["authkey"] is None and base in ("bazaar", "urlhaus", "threatfox", "yaraify", "hunting"):
            return self._json({"query_status": "unauthorized"}, status=401)

        handler = getattr(self, f"_{base.replace(':', '_')}")
        return await handler(request, info, path, query)

    async def _bazaar(self, request, info, path, query):
        form = info["form"]
        if "json_data" in form and "file" in info["files"]:
            return self._json({"query_status": "inserted"})
        match query:
            case "get_info":
                if form.get("hash") in (SHA256, MD5, SHA1, SHA3):
                    return self._json(ok([BAZAAR_INFO]))
                return self._json({"query_status": "hash_not_found"})
            case "get_taginfo" | "get_siginfo" | "get_file_type" | "get_clamavinfo" | "get_imphash" | \
                 "get_tlsh" | "get_telfhash" | "get_gimphash" | "get_dhash_icon" | "get_yarainfo" | \
                 "get_issuerinfo" | "get_subjectinfo" | "get_recent":
                if "nothing" in form.values():
                    return self._json({"query_status": "no_results"})
                return self._json(ok(BAZAAR_LIST))
            case "get_cscb":
                return self._json(ok(CSCB))
            case "get_file":
                if form.get("sha256_hash") == SAMPLE_SHA256:
                    return web.Response(body=mkzip({f"{SAMPLE_SHA256}.exe": SAMPLE_BYTES}, b"infected"),
                                        content_type="application/zip")
                return self._json({"query_status": "file_not_found"})
            case "update" | "add_comment":
                return self._json({"query_status": "success"})
        return self._json({"query_status": "unknown_query"})

    async def _bazaar_export(self, request, info, path, query):
        if path.startswith("csv/full"):
            return web.Response(body=mkzip({"full.csv": BAZAAR_CSV.encode()}), content_type="application/zip")
        return web.Response(text=BAZAAR_CSV)

    async def _urlhaus(self, request, info, path, query):
        form = info["form"]
        if path == "url/":
            if form.get("url") == URLHAUS_URL["url"]:
                return self._json(URLHAUS_URL)
            return self._json({"query_status": "no_results"})
        if path == "urlid/":
            return self._json(URLHAUS_URL if form.get("urlid") == "105821" else {"query_status": "no_results"})
        if path == "host/":
            if form.get("host") == "1.2.3.4":
                return self._json(URLHAUS_HOST)
            return self._json({"query_status": "no_results"})
        if path == "payload/":
            if PAYLOAD in form.values() or PAYLOAD_MD5 in form.values():
                return self._json(URLHAUS_PAYLOAD)
            return self._json({"query_status": "no_results"})
        if path == "tag/":
            return self._json(URLHAUS_TAG)
        if path == "signature/":
            return self._json(URLHAUS_SIGNATURE)
        if path.startswith("urls/recent"):
            return self._json(URLHAUS_RECENT_URLS)
        if path.startswith("payloads/recent"):
            return self._json(URLHAUS_RECENT_PAYLOADS)
        if path.startswith("download/"):
            sha = path.split("/")[1]
            if sha == SAMPLE_SHA256:
                return web.Response(body=mkzip({SAMPLE_SHA256: SAMPLE_BYTES}, b"infected"),
                                    content_type="application/zip")
            return web.Response(status=404, text="Not found")
        return self._json({"query_status": "unknown"}, status=404)

    async def _urlhaus_submit(self, request, info, path, query):
        return web.Response(text="Your submission has been accepted")

    async def _urlhaus_export(self, request, info, path, query):
        if path == "csv/":
            return web.Response(body=mkzip({"csv.txt": URLHAUS_CSV.encode()}), content_type="application/zip")
        return web.Response(text=URLHAUS_CSV)

    async def _threatfox(self, request, info, path, query):
        body = info["json"] or {}
        match query:
            case "get_iocs":
                return self._json(ok([THREATFOX_IOC, THREATFOX_IPPORT]))
            case "ioc":
                return self._json(ok(THREATFOX_IOC) if body.get("id") == 41 else {"query_status": "no_result"})
            case "search_ioc":
                term = body.get("search_term")
                for item in (THREATFOX_IOC, THREATFOX_IPPORT, THREATFOX_URL):
                    if item["ioc"] == term:
                        return self._json(ok([item]))
                return self._json({"query_status": "no_result"})
            case "search_hash":
                if body.get("hash") in (SHA256, MD5):
                    return self._json(ok([THREATFOX_IOC, THREATFOX_HASH]))
                return self._json({"query_status": "no_result"})
            case "taginfo" | "malwareinfo":
                return self._json(ok([THREATFOX_URL, THREATFOX_IPPORT]))
            case "types":
                return self._json(ok(THREATFOX_TYPES))
            case "tag_list":
                return self._json(ok(THREATFOX_TAGS))
            case "malware_list":
                return self._json(ok(THREATFOX_MALWARE))
            case "get_label":
                return self._json(ok(THREATFOX_LABEL))
            case "submit_ioc":
                return self._json(ok({"ok": body.get("iocs"), "ignored": [], "duplicated": []}))
        return self._json({"query_status": "unknown_query"})

    async def _threatfox_export(self, request, info, path, query):
        text = json.dumps(THREATFOX_EXPORT)
        if path.startswith("json/full"):
            return web.Response(body=mkzip({"full.json": text.encode()}), content_type="application/zip")
        return web.Response(text=text, content_type="application/json")

    async def _yaraify(self, request, info, path, query):
        if "yara_file" in info["files"]:
            return self._json({"query_status": "ok", "data": "Rule deployed"})
        if "file" in info["files"]:
            return self._json(ok({"task_id": "11111111-aaaa-bbbb-cccc-000000000001"}, query_status="queued"))
        body = info["json"] or {}
        match query:
            case "lookup_hash":
                if body.get("search_term") in (SHA256, MD5, SHA1):
                    return self._json(ok(YARAIFY_FILE))
                return self._json({"query_status": "hash_not_found"})
            case "get_yara" | "get_clamav" | "get_imphash" | "get_gimphash" | "get_dhash_icon" | "get_tlsh" | \
                 "get_telfhash":
                return self._json(ok(YARAIFY_SEARCH))
            case "recent_yararules":
                return self._json(ok(YARAIFY_RECENT_RULES))
            case "get_results":
                if body.get("task_id") == "queued-task":
                    return self._json(ok("queued"))
                return self._json(ok(YARAIFY_FILE))
            case "list_tasks":
                return self._json(ok([dict(YARAIFY_FILE["tasks"][0], sha256_hash=SHA256)]))
            case "generate_identifier":
                return self._json(ok({"identifier": "abcdef-identifier"}))
            case "rescan_file":
                return self._json(ok({"task_id": "22222222-aaaa-bbbb-cccc-000000000002"}, query_status="queued"))
            case "get_yara_rule":
                return web.Response(text=YARA_RULE_TEXT)
            case "get_file":
                if body.get("sha256_hash") == SAMPLE_SHA256:
                    return web.Response(body=mkzip({SAMPLE_SHA256: SAMPLE_BYTES}, b"infected"),
                                        content_type="application/zip")
                return self._json({"query_status": "file_not_found"})
        return self._json({"query_status": "unknown_query"})

    async def _yaraify_export(self, request, info, path, query):
        return web.Response(body=mkzip({"win_agent_tesla_auto.yar": YARA_RULE_TEXT.encode()}),
                            content_type="application/zip")

    async def _hunting(self, request, info, path, query):
        return self._json(ok(FPLIST))

    async def _feodo(self, request, info, path, query):
        match path:
            case "ipblocklist.json":
                return self._json(FEODO_JSON)
            case "ipblocklist_recommended.txt":
                return web.Response(text=FEODO_RECOMMENDED)
            case "ipblocklist_aggressive.csv":
                return web.Response(text=FEODO_AGGRESSIVE)
        return web.Response(status=404)

    async def _sslbl(self, request, info, path, query):
        match path:
            case "sslblacklist.csv":
                return web.Response(text=SSLBL_CERTS)
            case "sslipblacklist.csv" | "sslipblacklist_aggressive.csv":
                return web.Response(text=SSLBL_IPS)
            case "ja3_fingerprints.csv":
                return web.Response(text=SSLBL_JA3)
        return web.Response(status=404)

    async def __aenter__(self):
        app = web.Application(client_max_size=1024 ** 3)
        app.router.add_route("*", "/{tail:.*}", self._handle)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.port = site._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *args):
        await self.runner.cleanup()

    def last(self, path: str | None = None) -> dict:
        """The most recent request (to a path prefix, if given)."""

        for req in reversed(self.requests):
            if path is None or req["path"].startswith(path):
                return req
        raise AssertionError(f"No request to {path}")

    def queries(self, base: str) -> list[str]:
        """The ``query`` of every request sent to an API."""

        retn = []
        for req in self.requests:
            if req["path"].startswith(f"/{base}"):
                retn.append(req["form"].get("query") or (req["json"] or {}).get("query") or req["path"])
        return retn


@contextlib.asynccontextmanager
async def abusechSvc(test, apikey: str | None = "testkey"):
    """Yield (core, svc, fake) - a Cortex with slib.abusech added, pointed at a FakeAbuseCh."""

    from abusechsvc import AbuseChSvc

    async with FakeAbuseCh() as fake:
        conf = {"abusech:urls": fake.urls, "abusech:ratelimit": 0, "abusech:apikey": apikey}
        async with test.getTestCoreProxSvc(AbuseChSvc, ssvc_conf=conf) as (core, prox, svc):
            yield core, svc, fake
