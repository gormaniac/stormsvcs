"""Normalize raw abuse.ch responses into flat dicts that are easy to model in Storm.

Every abuse.ch platform describes the same things (files, URLs, hosts, C2
servers, YARA rules, certificates) with slightly different field names and
formats. Reshaping them here into a few shared shapes keeps the Storm modeling
code short, and lets it be unit tested without a Cortex. The shapes are:

* sample - a file (``normSample``), used by MalwareBazaar, YARAify, URLhaus, and ThreatFox.
* rule - a YARA rule (``normRule``).
* cert - an X.509 (code signing or TLS) certificate (``normCert``).
* scan - an AV/sandbox/vendor verdict on a file (``normVendors``, ``normVirusTotal``).
* url - a URLhaus URL (``normUrl``).
* ioc - a ThreatFox IOC (``normIoc``).
* c2 - a C2 server from a blocklist (``normFeodo``).
* obs - an observable (``normObservable``) - a value typed into the Synapse form it models as.
"""


import csv
import ipaddress
import re
from collections.abc import Iterable, Iterator
from typing import Any


HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
TAG_RE = re.compile(r"[^a-z0-9_]+")

VERDICTS = {
    "benign": 10, "clean": 10, "legit": 10, "legit file": 10, "no threat": 10, "no threats": 10,
    "no threats detected": 10, "whitelisted": 10, "trusted": 10, "known": 10,
    "unknown": 20, "notcategorized": 20, "not categorized": 20, "informational": 20, "informative": 20,
    "no specific threat": 20, "not suspicious": 20,
    "suspicious": 30, "suspicious file": 30, "suspicious activity": 30, "likely malicious": 30,
    "malicious": 40, "malicious file": 40, "malicious activity": 40, "malware": 40, "known malware": 40,
}
"""Vendor verdict strings (lower case, with ``_`` as spaces) mapped to Synapse's ``it:av:scan:result:verdict`` levels."""

FAMILY_KEYS = ("malware_family", "family_name", "threat_name", "family", "malware")
VERDICT_KEYS = ("verdict", "status", "threat_level", "classification", "detection")
LINK_KEYS = ("analysis_url", "report_link", "link", "url", "permalink", "report", "web_link")
SCORE_KEYS = ("score", "threatlevel", "maliciousness", "scanner_percent", "confidence")
TIME_KEYS = ("date", "first_seen", "analysis_date", "time_stamp", "timestamp")
"""Keys used to read vendors MalwareBazaar adds that ``VENDORS`` doesn't know yet."""


# ---- Generic value helpers ----


def ts(valu: Any) -> str | None:
    """Make an abuse.ch timestamp parseable by Synapse's time type.

    abuse.ch uses ``2024-01-01 12:00:00`` with an occasional `` UTC`` suffix.
    """

    if valu in (None, "", 0, "0"):
        return None
    valu = str(valu).strip()
    for suffix in (" UTC", "UTC", "Z", "+00:00"):
        if valu.endswith(suffix):
            valu = valu[: -len(suffix)].strip()
    return valu or None


def timePair(first: str | None, last: str | None) -> tuple[str | None, str | None]:
    """Order a (first, last) pair of ``ts()`` times.

    abuse.ch sometimes reports a last seen before the first seen. Left as is, the pair is an
    invalid interval and Storm drops every tag set with it.
    """

    if first and last and last < first:
        return last, first
    return first, last


def lst(valu: Any) -> list:
    """Make a value a list, dropping nulls and empty strings."""

    if valu is None:
        return []
    if isinstance(valu, (list, tuple, set)):
        return [v for v in valu if v not in (None, "")]
    if isinstance(valu, str) and not valu.strip():
        return []
    return [valu]


def splitList(valu: Any, sep: str = ",") -> list[str]:
    """Split a separated string (or pass through a list) into a list of stripped strings."""

    if isinstance(valu, str):
        return [v.strip() for v in valu.split(sep) if v.strip() and v.strip().lower() != "none"]
    return [str(v).strip() for v in lst(valu) if str(v).strip()]


def toInt(valu: Any) -> int | None:
    """Parse an int abuse.ch may have sent as a string. Returns None if it isn't one."""

    try:
        return int(float(str(valu).strip().rstrip("%")))
    except (TypeError, ValueError):
        return None


def toFloat(valu: Any) -> float | None:
    """Parse a float abuse.ch may have sent as a string. Returns None if it isn't one."""

    try:
        return float(str(valu).strip().rstrip("%"))
    except (TypeError, ValueError):
        return None


def toBool(valu: Any) -> bool:
    """Parse abuse.ch's many boolean formats (true, "true", 1, "1", "yes")."""

    if isinstance(valu, str):
        return valu.strip().lower() in ("1", "true", "yes", "y")
    return bool(valu)


def isHex(valu: Any, size: int | None = None) -> bool:
    """Whether a value is a hex string (of ``size`` characters, if given)."""

    if not isinstance(valu, str) or not HEX_RE.match(valu):
        return False
    return size is None or len(valu) == size


def lower(valu: Any) -> str | None:
    """Lower case and strip a string value, returning None for empty values."""

    if valu in (None, ""):
        return None
    valu = str(valu).strip().lower()
    return valu or None


def normTag(valu: Any) -> str | None:
    """Normalize a value into a single Synapse tag segment (ex. "Cobalt Strike" -> "cobalt_strike")."""

    if valu in (None, ""):
        return None
    valu = TAG_RE.sub("_", str(valu).strip().lower()).strip("_")
    valu = re.sub("_+", "_", valu)
    return valu or None


def normTags(valus: Any) -> list[str]:
    """Normalize a list (or comma separated string) of values into unique tag segments."""

    retn = []
    for valu in splitList(valus):
        tag = normTag(valu)
        if tag and tag not in retn:
            retn.append(tag)
    return retn


def verdict(valu: Any) -> int | None:
    """Map a vendor's verdict (a string or a 0-100 score) to a Synapse verdict level."""

    if valu in (None, ""):
        return None
    if isinstance(valu, bool):
        return 40 if valu else 10
    if isinstance(valu, (int, float)):
        if valu >= 70:
            return 40
        if valu >= 30:
            return 30
        return 20 if valu > 0 else 10
    valu = str(valu).strip().lower().replace("_", " ")
    if valu in VERDICTS:
        return VERDICTS[valu]
    if re.match(r"^(no|not|non)\b", valu):
        return 10
    for word, level in (("malic", 40), ("suspic", 30), ("legit", 10), ("clean", 10), ("benign", 10)):
        if word in valu:
            return level
    return None


def parseCsv(text: str, fields: tuple[str, ...]) -> list[dict]:
    """Parse an abuse.ch CSV export, skipping its ``#`` comment/header lines."""

    return list(parseCsvLines(text.splitlines(), fields))


def parseCsvLines(lines: Iterable[str], fields: tuple[str, ...]) -> Iterator[dict]:
    """Like ``parseCsv`` but streaming, over an iterable of lines (ex. a file too large to load)."""

    # The reader needs the line endings to keep newlines inside quoted fields.
    data = (line + "\n" for line in lines if line.strip() and not line.lstrip().startswith("#"))
    for row in csv.reader(data, skipinitialspace=True):
        if not row:
            continue
        # The URLhaus/MalwareBazaar exports sometimes include an un-commented header.
        if row[0].strip().lower() == fields[0]:
            continue
        yield {k: (v.strip() if v.strip() not in ("", "n/a", "None") else None) for k, v in zip(fields, row)}


def parseLines(text: str) -> list[str]:
    """Parse a plain text blocklist (one value per line, ``#`` comments)."""

    return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


# ---- Observables ----


def ipAddr(valu: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse an IPv4/IPv6 address, or None if the value isn't one."""

    try:
        return ipaddress.ip_address(valu)
    except ValueError:
        return None


def serverUrl(host: str, port: int | None) -> str | None:
    """A ``tcp://host:port`` URL, bracketing IPv6 hosts."""

    if not port:
        return None
    ip = ipAddr(host)
    host = f"[{ip}]" if ip and ip.version == 6 else host.lower()
    return f"tcp://{host}:{port}"


def normObservable(kind: str | None, valu: Any) -> dict | None:
    """Type an abuse.ch value into the Synapse form it should be modeled as.

    ``kind`` is an abuse.ch IOC/entry type (``ip:port``, ``domain``, ``url``,
    ``md5_hash``, ...), or None to guess from the value. Returns a dict with
    ``form`` and ``valu``, plus ``ip``/``port`` for servers and the hash fields for
    files, or None if the value can't be typed.
    """

    if valu in (None, ""):
        return None
    valu = str(valu).strip()
    kind = (kind or "").lower()

    if kind in ("md5_hash", "md5", "sha1_hash", "sha1", "sha256_hash", "sha256", "sha3_384_hash",
                "sha3_384", "hash", "file", "") and isHex(valu):
        hashes = {32: "md5", 40: "sha1", 64: "sha256", 96: "sha3_384"}
        htype = hashes.get(len(valu))
        if htype:
            return {"form": "file:bytes", "valu": valu.lower(), "hashes": {htype: valu.lower()}}
        return None

    if kind in ("url",) or (not kind and "://" in valu):
        return {"form": "inet:url", "valu": valu}

    # A bare IP, which an IPv6 address could otherwise be mistaken for an ip:port.
    ip = ipAddr(valu)
    if kind in ("ip", "ipv4", "ipv6", "ip_address", "ip-addr") or (not kind and ip):
        if not ip:
            return None
        return {"form": "inet:ipv6" if ip.version == 6 else "inet:ipv4", "valu": str(ip)}

    if kind in ("ip:port", "ip_port", "ipport") or (not kind and re.match(r"^(\[[0-9a-fA-F:.]+\]|[0-9.]+):\d+$", valu)):
        host, _, port = valu.rpartition(":")
        ip = ipAddr(host.strip("[]"))
        port = toInt(port)
        if ip is None or port is None:
            return None
        form = "inet:ipv6" if ip.version == 6 else "inet:ipv4"
        return {"form": "inet:server", "valu": valu, "ip": str(ip), "ipform": form, "port": port}

    if kind in ("domain", "fqdn", "hostname", "host") or not kind:
        return {"form": "inet:fqdn", "valu": valu.lower().rstrip(".")}

    if kind in ("email", "envelope_from", "body_from"):
        return {"form": "inet:email", "valu": valu.lower()}

    if kind in ("ja3", "ja3_md5", "ja3_fingerprint") and isHex(valu, 32):
        return {"form": "hash:md5", "valu": valu.lower()}

    return None


def normHost(valu: str | None) -> dict | None:
    """Type a URLhaus/Feodo host (an FQDN or IP) as an observable."""

    if not valu:
        return None
    return normObservable("ip" if re.match(r"^[0-9.]+$|:", valu) else "domain", valu)


# ---- Files ----


def normRule(rule: dict) -> dict | None:
    """Normalize a YARA rule from MalwareBazaar, YARAify, or a rule download."""

    if not isinstance(rule, dict):
        return None

    name = rule.get("rule_name") or rule.get("name") or rule.get("yara_rule_name")
    # YARAify replaces matches of non-public rules with "xxx".
    if not name or name.strip().lower() == "xxx":
        return None

    reference = rule.get("reference") or rule.get("yarahub_reference_link") or rule.get("yara_rule_reference")
    desc = (rule.get("description") or rule.get("yara_rule_description") or "").strip() or None
    if isinstance(reference, str) and reference.strip() and "://" not in reference:
        desc = f"{desc}\n\nReference: {reference.strip()}" if desc else f"Reference: {reference.strip()}"
    uuid = lower(rule.get("yarahub_uuid") or rule.get("uuid"))
    refmd5 = lower(rule.get("yarahub_reference_md5"))
    sharing = rule.get("yarahub_rule_sharing_tlp")
    return {
        "name": name.strip(),
        "uuid": uuid if uuid and uuid != "xxx" else None,
        "author": (rule.get("author") or rule.get("yara_rule_author") or "").strip() or None,
        "desc": desc,
        "url": reference if isinstance(reference, str) and "://" in reference else None,
        "date": ts(rule.get("date")),
        "time": ts(rule.get("time_stamp") or rule.get("last_hit_utc")),
        "tlp": normTag(re.sub(r"(?i)^tlp:", "", rule.get("tlp") or rule.get("yarahub_rule_matching_tlp") or "")),
        "sharing_tlp": normTag(re.sub(r"(?i)^tlp:", "", sharing or "")),
        "refmd5": refmd5 if isHex(refmd5, 32) else None,
        "license": rule.get("yarahub_license"),
        "family": lower(rule.get("malpedia_family")),
        "text": rule.get("rule") or rule.get("text") or rule.get("yara_rule"),
    }


def normRules(rules: Any) -> list[dict]:
    return [r for r in (normRule(r) for r in lst(rules)) if r]


def normCert(cert: dict, blocklist: bool = False) -> dict | None:
    """Normalize a MalwareBazaar ``code_sign`` entry or a code signing certificate blocklist entry.

    ``blocklist`` marks the cert as listed on the Code Signing Certificate Blocklist (CSCB).
    """

    if not isinstance(cert, dict):
        return None

    thumb = lower(cert.get("thumbprint"))
    algo = lower(cert.get("thumbprint_algorithm")) or {40: "sha1", 64: "sha256", 32: "md5"}.get(len(thumb or ""))
    serial = lower(cert.get("serial_number") or cert.get("serial"))
    if serial:
        serial = serial.replace(":", "")

    retn = {
        "md5": None,
        "sha1": None,
        "sha256": None,
        "serial": serial if isHex(serial) else None,
        "subject": cert.get("subject_cn") or cert.get("subject"),
        "issuer": cert.get("issuer_cn") or cert.get("issuer"),
        "notbefore": ts(cert.get("valid_from")),
        "notafter": ts(cert.get("valid_to")),
        "algo": cert.get("algorithm"),
        "blocklisted": blocklist or toBool(cert.get("cscb_listed")),
        "reason": cert.get("cscb_reason") or cert.get("reason"),
        "time": ts(cert.get("time_stamp")),
    }
    if thumb and algo in ("md5", "sha1", "sha256") and isHex(thumb):
        retn[algo] = thumb

    if not (retn["sha256"] or retn["sha1"] or retn["md5"] or retn["serial"]):
        return None
    return retn


def normVirusTotal(vt: dict | None) -> dict | None:
    """Normalize URLhaus's ``virustotal`` field (``{"result": "10 / 60", "percent": "16.67", "link": ...}``)."""

    if not isinstance(vt, dict):
        return None

    hits = total = None
    result = vt.get("result")
    if isinstance(result, str) and "/" in result:
        hits, _, total = result.partition("/")
        hits, total = toInt(hits), toInt(total)

    percent = toFloat(vt.get("percent"))
    level = None
    if hits is not None:
        level = 40 if hits > 0 else 10

    return {
        "vendor": "virustotal",
        "verdict": level,
        "signame": None,
        "score": percent,
        "link": vt.get("link"),
        "time": None,
        "categories": [],
        "count": total,
        "malicious": hits,
        "children": [],
    }


def _firstKey(info: dict, keys: tuple[str, ...]) -> Any:
    for key in keys:
        valu = info.get(key)
        if valu not in (None, "", [], {}):
            return valu
    return None


def _scan(vendor: str, *, verdict_: int | None = None, signame: Any = None, score: float | None = None,
          link: Any = None, time: Any = None, categories: Any = None, count: Any = None,
          malicious: Any = None, children: list | None = None, c2s: list | None = None,
          urls: list | None = None) -> dict:
    """The normalized scan shape. A vendor naming a family, without a verdict, detected the file."""

    if isinstance(signame, list):
        signame = signame[0] if signame else None
    if isinstance(signame, dict):
        signame = signame.get("name")
    signame = str(signame).strip() if signame not in (None, "") else None
    if verdict_ is None and signame:
        verdict_ = 40

    cats = []
    for cat in lst(categories):
        if isinstance(cat, dict):
            cat = cat.get("signature") or cat.get("name")
        if isinstance(cat, str) and cat.strip() and cat.strip() not in cats:
            cats.append(cat.strip())

    return {
        "vendor": vendor.lower(),
        "verdict": verdict_,
        "signame": signame,
        "score": score,
        "link": link if isinstance(link, str) and "://" in link else None,
        "time": ts(time),
        "categories": cats,
        "count": toInt(count),
        "malicious": toInt(malicious),
        "children": children or [],
        "c2s": c2s or [],
        "urls": [u for u in lst(urls) if isinstance(u, str) and "://" in u],
    }


def _scaled(valu: Any, scale: float) -> float | None:
    """A score scaled to 0-100."""

    valu = toFloat(valu)
    return None if valu is None else valu * scale


def _triageVerdict(score: float | None) -> int | None:
    """Triage scores are 1-10: 8-10 is malicious, 6-7 suspicious, and 1-5 likely benign."""

    if score is None:
        return None
    if score >= 8:
        return 40
    if score >= 6:
        return 30
    return 10


def normC2Config(cfg: Any, family: str | None = None) -> dict | None:
    """Normalize a sandbox's extracted malware config C2 (ex. Triage's ``{"extraction": "c2", "c2": "host:port"}``)."""

    if not isinstance(cfg, dict):
        return None
    c2 = cfg.get("c2") or cfg.get("value")
    if not isinstance(c2, str) or not c2.strip():
        return None
    c2 = c2.strip()
    obs = normObservable(None, c2)
    if obs is None or obs["form"] == "file:bytes":
        return None
    host, port = c2, None
    if obs["form"] == "inet:server":
        host, port = obs["ip"], obs["port"]
    elif obs["form"] == "inet:fqdn" and re.search(r":\d+$", c2):
        host, _, port = c2.rpartition(":")
        port = toInt(port)
        obs = normObservable("domain", host)
    fam = cfg.get("family") or family
    return {
        "c2": c2,
        "obs": obs,
        "host": host.lower(),
        "port": port,
        "url": None if obs["form"] == "inet:url" else serverUrl(host, port),
        "family": fam,
        "family_tag": normTag(fam),
    }


def _children(items: Any) -> list[dict]:
    retn = []
    for child in lst(items):
        if isinstance(child, dict):
            sha256 = lower(child.get("sha256_hash") or child.get("sha256"))
            if isHex(sha256, 64):
                retn.append({
                    "sha256": sha256,
                    "md5": lower(child.get("md5_hash")),
                    "sha1": lower(child.get("sha1_hash")),
                    "families": normTags(child.get("detections")),
                })
    return retn


def _detections(valu: Any) -> list[str]:
    """Detection names from a list of strings or ``{"detection_name"/"name": ...}`` dicts."""

    retn = []
    for det in lst(valu):
        if isinstance(det, dict):
            det = det.get("detection_name") or det.get("name") or det.get("detection")
        if isinstance(det, str) and det.strip():
            retn.append(det.strip())
    return retn


def _vendorAnyRun(info):
    return _scan("any.run", verdict_=verdict(info.get("verdict")), signame=info.get("malware_family"),
                 link=info.get("analysis_url"), time=info.get("date"), categories=info.get("tags"))


def _vendorFamilyLink(vendor):
    # CAPE and CERT-PL's MWDB only report a detected family (or null) and a link.
    def func(info):
        return _scan(vendor, signame=info.get("detection"), link=info.get("link"))
    return func


def _vendorYoroi(info):
    return _scan("yoroi_yomi", verdict_=verdict(info.get("detection")), score=_scaled(info.get("score"), 100))


def _vendorIntezer(info):
    return _scan("intezer", verdict_=verdict(info.get("verdict")), signame=info.get("family_name"),
                 link=info.get("analysis_url"))


def _vendorTriage(info):
    score = toFloat(info.get("score"))
    family = info.get("malware_family")
    c2s = [c for c in (normC2Config(c, family) for c in lst(info.get("malware_config"))) if c]
    return _scan("triage", verdict_=_triageVerdict(score), signame=family, score=_scaled(score, 10),
                 link=info.get("link"), categories=lst(info.get("tags")) + lst(info.get("signatures")), c2s=c2s)


def _vendorReversingLabs(info):
    return _scan("reversinglabs", verdict_=verdict(info.get("status")), signame=info.get("threat_name"),
                 score=toFloat(info.get("scanner_percent")), link=info.get("report_link"),
                 time=info.get("first_seen"), count=info.get("scanner_count"),
                 malicious=info.get("scanner_match"))


def _vendorSpamhaus(info):
    return _scan("spamhaus_hbl", verdict_=verdict(info.get("detection")), link=info.get("link"))


def _vendorUnpacMe(info):
    children = _children([info])
    families = [f for c in children for f in c["families"]]
    return _scan("unpacme", verdict_=40 if families else None, signame=_detections(info.get("detections")),
                 link=info.get("link"), children=children)


def _vendorFileScan(info):
    return _scan("filescan-io", verdict_=verdict(info.get("verdict")), score=_scaled(info.get("threatlevel"), 100),
                 link=info.get("report_link"))


def _vendorKaspersky(info):
    dets = _detections(info.get("detections"))
    return _scan("kaspersky", verdict_=verdict(info.get("verdict")), signame=dets, link=info.get("report_link"),
                 time=info.get("first_seen"), categories=dets[1:])


def _vendorDocGuard(info):
    return _scan("docguard", verdict_=verdict(info.get("verdict")), categories=[info.get("filetype")],
                 urls=info.get("urls"))


def _vendorGeneric(vendor, info):
    """A vendor ``VENDORS`` doesn't know, read with the common key names."""

    return _scan(vendor, verdict_=verdict(_firstKey(info, VERDICT_KEYS)), signame=_firstKey(info, FAMILY_KEYS),
                 score=toFloat(_firstKey(info, SCORE_KEYS)), link=_firstKey(info, LINK_KEYS),
                 time=_firstKey(info, TIME_KEYS), categories=info.get("tags"),
                 count=info.get("scanner_count"), malicious=info.get("scanner_match"),
                 children=_children(lst(info.get("unpacked")) + lst(info.get("children"))))


VENDORS = {
    "any.run": _vendorAnyRun,
    "cape": _vendorFamilyLink("cape"),
    "cert-pl_mwdb": _vendorFamilyLink("cert-pl_mwdb"),
    "yoroi_yomi": _vendorYoroi,
    "intezer": _vendorIntezer,
    "triage": _vendorTriage,
    "reversinglabs": _vendorReversingLabs,
    "spamhaus_hbl": _vendorSpamhaus,
    "unpacme": _vendorUnpacMe,
    "filescan-io": _vendorFileScan,
    "kaspersky": _vendorKaspersky,
    "docguard": _vendorDocGuard,
}
"""The vendors in MalwareBazaar's ``vendor_intel``, keyed by lower case name, and how to read each one."""


def _vendorScan(vendor: str, info: dict) -> dict:
    """Normalize one vendor's entry in MalwareBazaar's ``vendor_intel``."""

    func = VENDORS.get(vendor.lower())
    return func(info) if func else _vendorGeneric(vendor, info)


def normVendors(intel: Any) -> list[dict]:
    """Normalize MalwareBazaar's ``vendor_intel`` (``{vendor: dict | [dict, ...]}``) into scans."""

    retn = []
    if not isinstance(intel, dict):
        return retn
    for vendor, infos in intel.items():
        for info in lst(infos):
            if isinstance(info, dict) and info:
                retn.append(_vendorScan(vendor, info))
    return retn


def normFileInfo(infos: Any) -> dict:
    """Normalize MalwareBazaar's ``file_information`` context list.

    Returns ``links`` (URLs that reference the sample, ex. sandbox reports),
    ``related`` (other samples, ex. ``dropped_by_sha256``), ``families`` (ex.
    ``dropped_by_malware``), and ``notes`` (any other context).
    """

    retn = {"links": [], "related": [], "families": [], "notes": []}
    for info in lst(infos):
        if not isinstance(info, dict):
            continue
        ctx = (info.get("context") or "").lower()
        for valu in splitList(info.get("value"), sep="\n"):
            if "://" in valu:
                retn["links"].append({"context": ctx, "url": valu})
            elif isHex(valu) and len(valu) in (32, 40, 64):
                htype = {32: "md5", 40: "sha1", 64: "sha256"}[len(valu)]
                rel = re.sub(r"_(md5|sha1|sha256)(_hash)?$", "", ctx) or "related"
                retn["related"].append({"rel": rel, htype: valu.lower()})
            elif ctx.endswith("malware"):
                retn["families"].extend(normTags(valu))
            else:
                retn["notes"].append(f"{ctx}: {valu}" if ctx else valu)
    return retn


def normComments(comments: Any) -> list[dict]:
    """Normalize MalwareBazaar's ``comments`` list."""

    retn = []
    for cmt in lst(comments):
        if isinstance(cmt, dict) and cmt.get("comment"):
            retn.append({
                "id": str(cmt.get("id")) if cmt.get("id") is not None else None,
                "time": ts(cmt.get("date_added")),
                "author": cmt.get("display_name") or cmt.get("twitter_handle"),
                "text": cmt["comment"],
            })
        elif isinstance(cmt, str) and cmt.strip():
            retn.append({"id": None, "time": None, "author": None, "text": cmt.strip()})
    return retn


def emptySample() -> dict:
    """The normalized sample shape, with every field empty."""

    return {
        "sha256": None, "md5": None, "sha1": None, "sha3_384": None,
        "size": None, "name": None, "names": [], "mime": None, "type": None,
        "first_seen": None, "last_seen": None,
        "signature": None, "families": [], "tags": [],
        "reporter": None, "origin_country": None, "delivery_method": None,
        "imphash": None, "tlsh": None, "telfhash": None, "gimphash": None, "ssdeep": None,
        "dhash_icon": None, "magika": None, "archive_pw": None,
        "clamav": [], "rules": [], "certs": [], "scans": [],
        "links": [], "related": [], "notes": [], "comments": [], "attrs": [],
    }


def normSample(data: dict) -> dict | None:
    """Normalize a sample from any abuse.ch platform.

    Handles MalwareBazaar ``get_info``/search results (and its CSV export),
    YARAify ``metadata``, URLhaus payloads, and ThreatFox/URLhaus hash lookups.
    Returns None without at least one hash.
    """

    if not isinstance(data, dict):
        return None

    retn = emptySample()
    for htype, keys in (
        ("sha256", ("sha256_hash", "sha256", "response_sha256")),
        ("md5", ("md5_hash", "md5", "response_md5")),
        ("sha1", ("sha1_hash", "sha1")),
        ("sha3_384", ("sha3_384_hash", "sha3_384")),
    ):
        valu = lower(_firstKey(data, keys))
        if isHex(valu):
            retn[htype] = valu

    if not (retn["sha256"] or retn["md5"] or retn["sha1"]):
        return None

    retn["size"] = toInt(data.get("file_size") or data.get("response_size"))
    name = data.get("file_name") or data.get("filename")
    if isinstance(name, str) and name.strip() and name.strip().lower() not in ("n/a", "na", "unknown", "none"):
        retn["name"] = name.strip()
        retn["names"] = [name.strip()]
    retn["mime"] = lower(data.get("file_type_mime") or data.get("mime_type"))
    retn["type"] = lower(data.get("file_type") or data.get("file_type_guess"))
    retn["first_seen"], retn["last_seen"] = timePair(
        ts(data.get("first_seen") or data.get("firstseen") or data.get("first_seen_utc")),
        ts(data.get("last_seen") or data.get("lastseen")),
    )

    signature = data.get("signature")
    if isinstance(signature, str) and signature.strip() and signature.lower() not in ("none", "n/a"):
        retn["signature"] = signature.strip()
        retn["families"] = normTags(signature)

    retn["tags"] = normTags(data.get("tags"))
    reporter = data.get("reporter")
    if reporter and str(reporter).lower() != "anonymous" and not toBool(data.get("anonymous")):
        retn["reporter"] = str(reporter)
    retn["origin_country"] = lower(data.get("origin_country"))
    retn["delivery_method"] = normTag(data.get("delivery_method"))

    for key in ("imphash", "tlsh", "telfhash", "gimphash", "ssdeep", "dhash_icon", "magika", "archive_pw"):
        valu = data.get(key)
        if isinstance(valu, str) and valu.strip() and valu.strip().lower() not in ("n/a", "none", "null"):
            retn[key] = valu.strip()
    if retn["imphash"] and not isHex(retn["imphash"], 32):
        retn["imphash"] = None
    for key in ("tlsh", "telfhash", "gimphash", "dhash_icon"):
        if retn[key]:
            retn[key] = retn[key].lower()
    retn["tlsh"] = normTlsh(retn["tlsh"])

    # Tag segments describing the file (ex. "magika.pebin", "arch.x86", "ole.vba_macros").
    for key, prefix in (("magika", "magika"), ("file_format", "format"), ("file_arch", "arch")):
        tag = normTag(data.get(key))
        if tag:
            retn["attrs"].append(f"{prefix}.{tag}")

    intel = data.get("intelligence") or {}
    clamav = intel.get("clamav") if isinstance(intel, dict) else None
    retn["clamav"] = splitList(clamav if clamav is not None else data.get("clamav"))

    retn["rules"] = normRules(data.get("yara_rules"))
    retn["certs"] = [c for c in (normCert(c) for c in lst(data.get("code_sign"))) if c]
    retn["scans"] = normVendors(data.get("vendor_intel"))

    vt = normVirusTotal(data.get("virustotal"))
    if vt:
        retn["scans"].append(vt)
    vtpercent = toFloat(data.get("vtpercent"))
    if vtpercent is not None and vt is None:
        retn["scans"].append({
            "vendor": "virustotal", "verdict": 40 if vtpercent > 0 else 10, "signame": None,
            "score": vtpercent, "link": None, "time": None, "categories": [], "count": None,
            "malicious": None, "children": [],
        })

    finfo = normFileInfo(data.get("file_information"))
    retn["links"] = finfo["links"]
    retn["related"] = finfo["related"]
    retn["notes"] = finfo["notes"]
    retn["families"] = list(dict.fromkeys(retn["families"] + finfo["families"]))
    for trid in lst(data.get("trid")):
        retn["notes"].append(f"trid: {trid}")
    ole = normOle(data.get("ole_information"))
    retn["attrs"].extend(ole["attrs"])
    retn["notes"].extend(ole["notes"])

    # Unpackers list the sample itself alongside the files they unpacked.
    for scan in retn["scans"]:
        scan["children"] = [c for c in scan["children"] if c["sha256"] != retn["sha256"]]

    retn["comments"] = normComments(data.get("comments"))
    comment = data.get("comment")
    if isinstance(comment, str) and comment.strip():
        retn["comments"].insert(0, {"id": None, "time": retn["first_seen"], "author": retn["reporter"],
                                    "text": comment.strip()})

    return retn


def normTlsh(valu: str | None) -> str | None:
    """Normalize a TLSH to its versioned form (``t1`` + 70 hex chars), some endpoints drop the ``T1``."""

    if valu and len(valu) == 70 and isHex(valu):
        return "t1" + valu
    return valu


def normOle(ole: Any) -> dict:
    """Normalize MalwareBazaar's ``ole_information`` (``{"oleid": {...}, "olevba": [...]}``).

    Returns ``attrs`` (tag segments, ex. ``ole.vba_macros``, ``ole.encrypted``) and ``notes``
    (the document's format, application, author, maldoc score, and olevba findings).
    """

    retn = {"attrs": [], "notes": []}
    if not isinstance(ole, dict):
        return retn

    oleid = ole.get("oleid") or {}
    if isinstance(oleid, dict):
        for key, valu in oleid.items():
            if valu is True and normTag(key):
                retn["attrs"].append(f"ole.{normTag(key)}")
        parts = []
        for key, label in (("file_format", "format"), ("container_format", "container"),
                           ("application_name", "application"), ("author", "author"),
                           ("external_relationships", "external relationships"),
                           ("maldoc_score", "maldoc score")):
            if oleid.get(key) not in (None, ""):
                parts.append(f"{label}: {oleid[key]}")
        if parts:
            retn["notes"].append("ole: " + ", ".join(parts))

    for item in lst(ole.get("olevba")):
        if isinstance(item, dict):
            retn["notes"].append(
                f"olevba {item.get('type') or ''}: {item.get('keyword') or ''} - {item.get('description') or ''}".strip()
            )
    return retn


def normSamples(items: Any) -> list[dict]:
    return [s for s in (normSample(i) for i in lst(items)) if s]


# ---- YARAify ----


def normTask(task: dict) -> dict | None:
    """Normalize a YARAify scan task (from ``lookup_hash``, ``get_results``, or ``list_tasks``)."""

    if not isinstance(task, dict):
        return None

    params = task.get("task_parameters") or {}
    unpacked = []
    for unp in lst(task.get("unpacker_results") or task.get("unpacked_results") or task.get("unpack_results")):
        if not isinstance(unp, dict):
            continue
        sha256 = lower(unp.get("unpacked_sha256"))
        if not isHex(sha256, 64):
            continue
        unpacked.append({
            "sha256": sha256,
            "md5": lower(unp.get("unpacked_md5")),
            "name": unp.get("unpacked_file_name"),
            "rules": normRules(unp.get("unpacked_yara_matches")),
        })

    sample = normSample(task.get("metadata") or {}) if task.get("metadata") else None
    params = params or task.get("yaraify_parameters") or {}

    def param(key):
        valu = params.get(key, task.get(key))
        return None if valu is None else toBool(valu)

    return {
        "task_id": task.get("task_id"),
        "time": ts(task.get("time_stamp")),
        "status": task.get("task_status") or task.get("status"),
        "name": task.get("file_name"),
        "sha256": lower(task.get("sha256_hash")) or (sample["sha256"] if sample else None),
        "md5": lower(task.get("md5_hash")) or (sample["md5"] if sample else None),
        "clamav_scan": param("clamav_scan"),
        "unpack": param("unpack"),
        "share_file": param("share_file"),
        "rules": normRules(task.get("static_results")),
        "clamav": splitList(task.get("clamav_results")),
        "unpacked": unpacked,
        "sample": sample,
    }


def normYaraifyFile(data: dict) -> dict | None:
    """Normalize a YARAify ``lookup_hash`` (or ``get_results``) response's data.

    The task results are merged into the sample: every task's YARA matches and
    ClamAV results, with unpacked files as ``unpacked``.
    """

    if not isinstance(data, dict):
        return None

    sample = normSample(data.get("metadata") or data)
    if sample is None:
        return None

    taskitems = lst(data.get("tasks"))
    if not taskitems and any(k in data for k in ("static_results", "clamav_results", "unpack_results",
                                                    "unpacker_results")):
        taskitems = [data]
    tasks = [t for t in (normTask(t) for t in taskitems) if t]
    unpacked = []
    for task in tasks:
        for rule in task["rules"]:
            if rule["name"] not in {r["name"] for r in sample["rules"]}:
                sample["rules"].append(rule)
        for sig in task["clamav"]:
            if sig not in sample["clamav"]:
                sample["clamav"].append(sig)
        if task["name"] and task["name"] not in sample["names"]:
            sample["names"].append(task["name"])
        unpacked.extend(task["unpacked"])

    sample["unpacked"] = unpacked
    sample["tasks"] = [t["task_id"] for t in tasks if t["task_id"]]
    return sample


# ---- URLhaus ----


def normBlacklists(bls: Any) -> list[str]:
    """Normalize URLhaus's ``blacklists`` (``{"spamhaus_dbl": "...", "surbl": "..."}``) to tag segments.

    Only listings are returned (ex. ``spamhaus_dbl.abused_legit_malware``, ``surbl.listed``).
    """

    retn = []
    if not isinstance(bls, dict):
        return retn
    for name, valu in bls.items():
        valu = normTag(valu)
        if valu and valu not in ("not_listed", "unlisted", "none"):
            retn.append(f"{normTag(name)}.{valu}")
    return retn


def normUrl(data: dict) -> dict | None:
    """Normalize a URLhaus URL (``/url/``, ``/urls/recent/``, host/tag/signature URLs, the CSV export)."""

    if not isinstance(data, dict) or not data.get("url"):
        return None

    payloads = []
    for pay in lst(data.get("payloads")):
        sample = normSample(pay)
        if sample:
            sample["seen"] = ts(pay.get("firstseen"))
            sample["last"] = None
            payloads.append(sample)

    # Signature lookups and the payload export attach the payload to each URL instead.
    # Their firstseen/lastseen date the payload on the URL, not the URL itself.
    sample = normSample(data) if (data.get("sha256_hash") or data.get("md5_hash")) else None
    if sample:
        sample["seen"] = ts(data.get("firstseen"))
        sample["last"] = ts(data.get("lastseen"))
        payloads.append(sample)

    status = lower(data.get("url_status"))
    host = data.get("host") or None
    return {
        "id": str(data.get("id") or data.get("url_id") or "") or None,
        "url": data["url"].strip(),
        "status": status,
        "host": normHost(host) if host else None,
        "added": timePair(ts(data.get("date_added") or data.get("dateadded")), ts(data.get("last_online")))[0],
        "last_online": timePair(ts(data.get("date_added") or data.get("dateadded")), ts(data.get("last_online")))[1],
        "threat": normTag(data.get("threat")),
        "tags": normTags(data.get("tags")),
        "reporter": data.get("reporter") if data.get("reporter") not in (None, "anonymous") else None,
        "larted": toBool(data.get("larted")),
        "takedown": toInt(data.get("takedown_time_seconds")),
        "reference": data.get("urlhaus_reference") or data.get("urlhaus_link"),
        "blacklists": normBlacklists(data.get("blacklists")),
        "payloads": payloads,
    }


def normUrls(items: Any) -> list[dict]:
    return [u for u in (normUrl(i) for i in lst(items)) if u]


def normUrlhausHost(data: dict) -> dict | None:
    """Normalize a URLhaus ``/host/`` response."""

    if not isinstance(data, dict) or not data.get("host"):
        return None
    return {
        "host": normHost(data["host"]),
        "first_seen": ts(data.get("firstseen")),
        "url_count": toInt(data.get("url_count")),
        "reference": data.get("urlhaus_reference"),
        "blacklists": normBlacklists(data.get("blacklists")),
        "urls": normUrls(data.get("urls")),
    }


def normUrlhausPayload(data: dict) -> dict | None:
    """Normalize a URLhaus ``/payload/`` response: the sample plus the URLs that served it."""

    sample = normSample(data)
    if sample is None:
        return None
    sample["urls"] = []
    for item in lst(data.get("urls")):
        url = normUrl(item)
        if url:
            url["seen"] = ts(item.get("firstseen"))
            url["last_seen"] = ts(item.get("lastseen"))
            name = item.get("filename")
            if isinstance(name, str) and name.strip() and name.strip().lower() not in ("n/a", "na"):
                sample["names"] = list(dict.fromkeys(sample["names"] + [name.strip()]))
            sample["urls"].append(url)
    if sample["name"] is None and sample["names"]:
        sample["name"] = sample["names"][0]
    return sample


URLHAUS_PAYLOAD_CSV = ("firstseen", "url", "filetype", "md5", "sha256")
"""The columns of the URLhaus collected payloads export (``payload.csv.zip``)."""


def normUrlhausPayloadRow(row: dict) -> dict | None:
    """Normalize a URLhaus collected payloads export row into a URL with its payload."""

    if not row.get("url"):
        return None
    return normUrl({"url": row["url"], "md5_hash": row.get("md5"), "sha256_hash": row.get("sha256"),
                    "file_type": row.get("filetype"), "firstseen": row.get("firstseen")})


# ---- ThreatFox ----


STIX_PATTERNS = {
    "url": "[url:value = '{valu}']",
    "domain": "[domain-name:value = '{valu}']",
    "md5_hash": "[file:hashes.MD5 = '{valu}']",
    "sha1_hash": "[file:hashes.'SHA-1' = '{valu}']",
    "sha256_hash": "[file:hashes.'SHA-256' = '{valu}']",
    "sha3_384_hash": "[file:hashes.'SHA3-384' = '{valu}']",
    "envelope_from": "[email-message:sender_ref.value = '{valu}']",
    "body_from": "[email-message:from_ref.value = '{valu}']",
}


def stixPattern(ioc_type: str, valu: str, obs: dict | None) -> str | None:
    """Build the STIX 2.1 pattern for a ThreatFox IOC."""

    valu = valu.replace("\\", "\\\\").replace("'", "\\'")
    if ioc_type == "ip:port" and obs:
        addr = "ipv6-addr" if obs["ipform"] == "inet:ipv6" else "ipv4-addr"
        return (f"[network-traffic:dst_ref.type = '{addr}' AND network-traffic:dst_ref.value = "
                f"'{obs['ip']}' AND network-traffic:dst_port = {obs['port']}]")
    tmpl = STIX_PATTERNS.get(ioc_type)
    return tmpl.format(valu=valu) if tmpl else None


def normIoc(data: dict) -> dict | None:
    """Normalize a ThreatFox IOC (from any ThreatFox query or the JSON export)."""

    if not isinstance(data, dict):
        return None

    valu = data.get("ioc") or data.get("ioc_value")
    ioc_type = lower(data.get("ioc_type"))
    if not valu or not ioc_type:
        return None
    valu = str(valu).strip()

    obs = normObservable(ioc_type, valu)

    samples = []
    for samp in lst(data.get("malware_samples")):
        sample = normSample(samp)
        if sample:
            sample["seen"] = ts(samp.get("time_stamp"))
            sample["first_seen"] = sample["first_seen"] or sample["seen"]
            link = samp.get("malware_bazaar")
            if isinstance(link, str) and "://" in link:
                sample["links"].append({"context": "malware_bazaar", "url": link})
            samples.append(sample)

    seen = timePair(ts(data.get("first_seen") or data.get("first_seen_utc")),
                    ts(data.get("last_seen") or data.get("last_seen_utc")))

    family = data.get("malware_printable") or data.get("fk_malware")
    # ThreatFox uses placeholders like "Unknown malware" and "Unknown Stealer" for unattributed IOCs.
    if not isinstance(family, str) or not family.strip() or re.match(r"(?i)^(unknown\b|none$)", family.strip()):
        family = None
    aliases = splitList(data.get("malware_alias"))
    malware = lower(data.get("malware") or data.get("fk_malware"))

    return {
        "id": str(data.get("id")) if data.get("id") is not None else None,
        "ioc": valu,
        "ioc_type": ioc_type,
        "ioc_type_desc": data.get("ioc_type_desc"),
        "threat_type": normTag(data.get("threat_type")),
        "threat_type_desc": data.get("threat_type_desc"),
        "malware": malware,
        "family": family.strip() if family else None,
        "family_tag": normTag(family),
        "aliases": aliases,
        "malpedia": data.get("malware_malpedia"),
        "confidence": toInt(data.get("confidence_level")),
        "first_seen": seen[0],
        "last_seen": seen[1],
        "reference": data.get("reference") if isinstance(data.get("reference"), str) and "://" in data.get("reference", "") else None,
        "reporter": data.get("reporter") if data.get("reporter") not in (None, "anonymous") and not toBool(data.get("anonymous")) else None,
        "tags": normTags(data.get("tags")),
        "comment": (data.get("comment") or "").strip() or None,
        "compromised": toBool(data.get("is_compromised")),
        "sightings": toInt(data.get("sightings")),
        "credits": [
            {"from": c.get("credits_from"), "amount": toInt(c.get("credits_amount"))}
            for c in lst(data.get("credits")) if isinstance(c, dict)
        ],
        "obs": obs,
        "pattern": stixPattern(ioc_type, valu, obs),
        "samples": samples,
    }


def normIocs(items: Any) -> list[dict]:
    return [i for i in (normIoc(i) for i in lst(items)) if i]


def normYaraStats(data: Any) -> list[dict]:
    """Normalize MalwareBazaar's YARA rule statistics export (``{"<rank>": [{yara_rule_name, ...}]}``) into rules."""

    items = []
    for recs in (data.values() if isinstance(data, dict) else [data]):
        items.extend(r for r in lst(recs) if isinstance(r, dict))
    return normRules(items)


def normThreatFoxExport(data: Any) -> list[dict]:
    """Normalize ThreatFox's JSON export (``{"<id>": [{ioc_value, ...}], ...}``) into IOCs."""

    items = []
    if isinstance(data, dict):
        for iocid, recs in data.items():
            for rec in lst(recs):
                if isinstance(rec, dict):
                    items.append(dict(rec, id=rec.get("id", iocid)))
    else:
        items = lst(data)
    return normIocs(items)


# ---- Blocklists (Feodo Tracker and SSL Blacklist) ----


def normC2(ip: str | None, port: Any, *, family: str | None = None, status: str | None = None,
           first_seen: str | None = None, last_online: str | None = None, hostname: str | None = None,
           asn: Any = None, as_name: str | None = None, country: str | None = None,
           source: str = "feodo") -> dict | None:
    """The normalized shape of a botnet C2 server from a blocklist."""

    if not ip:
        return None
    port = toInt(port)
    host = normHost(ip)
    if host is None or host["form"] not in ("inet:ipv4", "inet:ipv6"):
        return None
    return {
        "ip": host["valu"],
        "ipform": host["form"],
        "port": port,
        "family": family.strip() if family and family.strip().lower() not in ("none", "unknown") else None,
        "family_tag": normTag(family) if family and family.strip().lower() not in ("none", "unknown") else None,
        "status": lower(status),
        "first_seen": ts(first_seen),
        "last_online": ts(last_online),
        "hostname": lower(hostname),
        "asn": toInt(asn),
        "as_name": as_name,
        "country": lower(country),
        "source": source,
    }


FEODO_CSV = ("first_seen_utc", "dst_ip", "dst_port", "c2_status", "last_online", "malware")
"""The columns of the Feodo Tracker CSV blocklists."""


def normFeodo(data: dict) -> dict | None:
    """Normalize a Feodo Tracker C2 from the JSON or CSV blocklist."""

    if not isinstance(data, dict):
        return None
    return normC2(
        data.get("ip_address") or data.get("dst_ip"),
        data.get("port") or data.get("dst_port"),
        family=data.get("malware"),
        status=data.get("status") or data.get("c2_status"),
        first_seen=data.get("first_seen") or data.get("first_seen_utc"),
        last_online=data.get("last_online"),
        hostname=data.get("hostname"),
        asn=data.get("as_number"),
        as_name=data.get("as_name"),
        country=data.get("country"),
    )


SSLBL_CERT_CSV = ("listingdate", "sha1", "listingreason")
SSLBL_JA3_CSV = ("ja3_md5", "firstseen", "lastseen", "listingreason")


def reasonFamily(reason: str | None) -> str | None:
    """Pull the malware family out of an SSLBL listing reason (ex. "Dridex C&C" -> "Dridex")."""

    if not reason:
        return None
    family = re.sub(r"\s*(C&C|C2|malware distribution|botnet).*$", "", reason, flags=re.IGNORECASE).strip()
    return family or None


def normSslblCert(row: dict) -> dict | None:
    """Normalize an SSLBL certificate blacklist row."""

    sha1 = lower(row.get("sha1"))
    if not isHex(sha1, 40):
        return None
    family = reasonFamily(row.get("listingreason"))
    return {
        "sha1": sha1,
        "time": ts(row.get("listingdate")),
        "reason": row.get("listingreason"),
        "family": family,
        "family_tag": normTag(family),
    }


def normJa3(row: dict) -> dict | None:
    """Normalize an SSLBL JA3 fingerprint blacklist row."""

    ja3 = lower(row.get("ja3_md5"))
    if not isHex(ja3, 32):
        return None
    family = reasonFamily(row.get("listingreason"))
    return {
        "ja3": ja3,
        "first_seen": ts(row.get("firstseen")),
        "last_seen": ts(row.get("lastseen")),
        "reason": row.get("listingreason"),
        "family": family,
        "family_tag": normTag(family),
    }


# ---- Hunting ----


def normFp(data: dict) -> dict | None:
    """Normalize an entry on the abuse.ch false positive list."""

    if not isinstance(data, dict):
        return None
    obs = normObservable(data.get("entry_type"), data.get("entry_value"))
    if obs is None:
        return None
    return {
        "obs": obs,
        "time": ts(data.get("time_stamp")),
        "platform": normTag(data.get("platform")),
        "removed_by": data.get("removed_by"),
        "notes": data.get("removal_notes"),
    }


def normFpList(data: Any) -> list[dict]:
    """Normalize the false positive list (a dict keyed by ID, or a list).

    A sample is listed once per hash type (MD5, SHA1, SHA256, SHA3-384), on consecutive
    rows with the same time, platform, and notes. Those rows are merged into one file entry.
    """

    items = data.values() if isinstance(data, dict) else lst(data)
    retn = []
    last = None
    for fp in (normFp(i) for i in items):
        if fp is None:
            continue
        key = (fp["time"], fp["platform"], fp["removed_by"], fp["notes"])
        if fp["obs"]["form"] == "file:bytes" and last is not None and last[0] == key:
            hashes = last[1]["obs"]["hashes"]
            htype, valu = next(iter(fp["obs"]["hashes"].items()))
            if htype not in hashes:
                hashes[htype] = valu
                continue
        retn.append(fp)
        last = (key, fp) if fp["obs"]["form"] == "file:bytes" else None
    return retn


# ---- YARA rule text ----


META_RE = re.compile(r'^\s*([A-Za-z0-9_]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|(\S+))', re.MULTILINE)
RULE_RE = re.compile(r"^\s*(?:(?:private|global)\s+)*rule\s+([A-Za-z0-9_]+)", re.MULTILINE)


def parseYara(text: str) -> list[dict]:
    """Split YARA rule text into normalized rules, pulling metadata out of each rule's ``meta:`` section."""

    retn = []
    starts = [m for m in RULE_RE.finditer(text)]
    for idx, match in enumerate(starts):
        end = starts[idx + 1].start() if idx + 1 < len(starts) else len(text)
        body = text[match.start():end].strip()
        meta = {}
        msect = re.search(r"\bmeta\s*:(.*?)(?:\bstrings\s*:|\bcondition\s*:)", body, re.DOTALL)
        if msect:
            for mm in META_RE.finditer(msect.group(1)):
                meta.setdefault(mm.group(1).lower(), mm.group(2) if mm.group(2) is not None else mm.group(3))
        rule = normRule(dict(meta, rule_name=match.group(1), rule=body))
        if rule:
            retn.append(rule)
    return retn
