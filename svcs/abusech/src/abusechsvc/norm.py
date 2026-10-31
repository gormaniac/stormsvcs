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
* c2 - a C2 server from a blocklist (``normFeodo``, ``normSslblIp``).
* obs - an observable (``normObservable``) - a value typed into the Synapse form it models as.
"""


import csv
import io
import re
from typing import Any


HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
TAG_RE = re.compile(r"[^a-z0-9_]+")

VERDICTS = {
    "benign": 10, "clean": 10, "no_threats": 10, "no threats detected": 10, "whitelisted": 10,
    "unknown": 20, "no specific threat": 20, "not_suspicious": 20, "informative": 20,
    "suspicious": 30, "likely_malicious": 30, "low": 30,
    "malicious": 40, "malware": 40, "high": 40, "known_malware": 40, "threat": 40,
}
"""Vendor verdict strings mapped to Synapse's ``it:av:scan:result:verdict`` levels."""

FAMILY_KEYS = ("malware_family", "family_name", "threat_name", "family", "detection", "detections", "malware")
SCORE_SCALES = {"triage": 10}
"""Vendors whose scores aren't 0-100, mapped to the multiplier that makes them 0-100."""
VERDICT_KEYS = ("verdict", "status", "threat_level", "threatlevel", "classification")
LINK_KEYS = ("analysis_url", "report_link", "link", "url", "permalink", "report", "web_link")
SCORE_KEYS = ("score", "threatlevel", "maliciousness", "scanner_percent", "confidence")
TIME_KEYS = ("date", "first_seen", "analysis_date", "time_stamp", "timestamp")


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
    valu = str(valu).strip().lower()
    if valu in VERDICTS:
        return VERDICTS[valu]
    for word, level in sorted(VERDICTS.items(), key=lambda i: -i[1]):
        if word in valu:
            return level
    return None


def parseCsv(text: str, fields: tuple[str, ...]) -> list[dict]:
    """Parse an abuse.ch CSV export, skipping its ``#`` comment/header lines."""

    lines = [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    rows = []
    for row in csv.reader(io.StringIO("\n".join(lines)), skipinitialspace=True):
        if not row:
            continue
        # The URLhaus/MalwareBazaar exports sometimes include an un-commented header.
        if row[0].strip().lower() == fields[0]:
            continue
        rows.append({k: (v.strip() if v.strip() not in ("", "n/a", "None") else None)
                     for k, v in zip(fields, row)})
    return rows


def parseLines(text: str) -> list[str]:
    """Parse a plain text blocklist (one value per line, ``#`` comments)."""

    return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


# ---- Observables ----


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

    if kind in ("ip:port", "ip_port", "ipport") or (not kind and re.match(r"^\[?[0-9a-fA-F:.]+\]?:\d+$", valu)):
        host, _, port = valu.rpartition(":")
        host = host.strip("[]")
        port = toInt(port)
        if not host or port is None:
            return None
        form = "inet:ipv6" if ":" in host else "inet:ipv4"
        return {"form": "inet:server", "valu": valu, "ip": host, "ipform": form, "port": port}

    if kind in ("ip", "ipv4", "ipv6", "ip_address", "ip-addr") or (not kind and re.match(r"^[0-9.]+$|^[0-9a-fA-F:]+:[0-9a-fA-F:]*$", valu)):
        return {"form": "inet:ipv6" if ":" in valu else "inet:ipv4", "valu": valu}

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

    name = rule.get("rule_name") or rule.get("name")
    if not name:
        return None

    reference = rule.get("reference") or rule.get("yarahub_reference_link")
    return {
        "name": name.strip(),
        "uuid": lower(rule.get("yarahub_uuid") or rule.get("uuid")),
        "author": (rule.get("author") or "").strip() or None,
        "desc": (rule.get("description") or "").strip() or None,
        "url": reference if isinstance(reference, str) and "://" in reference else None,
        "date": ts(rule.get("date")),
        "time": ts(rule.get("time_stamp")),
        "tlp": normTag(re.sub(r"(?i)^tlp:", "", rule.get("tlp") or rule.get("yarahub_rule_matching_tlp") or "")),
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


def _vendorScan(vendor: str, info: dict) -> dict:
    """Normalize one vendor's entry in MalwareBazaar's ``vendor_intel``."""

    family = _firstKey(info, FAMILY_KEYS)
    if isinstance(family, list):
        family = family[0] if family else None
    if isinstance(family, dict):
        family = family.get("name")

    raw_verdict = _firstKey(info, VERDICT_KEYS)
    score = toFloat(_firstKey(info, SCORE_KEYS))
    level = verdict(raw_verdict)
    if level is None and score is not None:
        level = verdict(score * SCORE_SCALES.get(vendor.lower(), 1))
    # A vendor naming a malware family detected the file as malicious.
    if family and (level is None or level < 40):
        level = 40

    link = _firstKey(info, LINK_KEYS)
    link = link if isinstance(link, str) and "://" in link else None

    categories = normTags(info.get("tags"))
    for sig in lst(info.get("signatures")):
        name = sig.get("signature") if isinstance(sig, dict) else sig
        if name and isinstance(name, str):
            categories.append(name)
    if isinstance(raw_verdict, str) and verdict(raw_verdict) is None:
        categories.append(raw_verdict)

    # UnpacMe and similar unpackers list the files they unpacked.
    children = []
    for child in lst(info.get("unpacked")) + lst(info.get("children")):
        if isinstance(child, dict):
            sha256 = lower(child.get("sha256_hash") or child.get("sha256"))
            if isHex(sha256, 64):
                children.append({
                    "sha256": sha256,
                    "md5": lower(child.get("md5_hash")),
                    "sha1": lower(child.get("sha1_hash")),
                    "families": normTags(child.get("detections")),
                })
    sha256 = lower(info.get("sha256_hash"))
    if isHex(sha256, 64):
        children.append({"sha256": sha256, "md5": lower(info.get("md5_hash")),
                         "sha1": lower(info.get("sha1_hash")), "families": normTags(info.get("detections"))})

    return {
        "vendor": vendor.lower(),
        "verdict": level,
        "signame": str(family).strip() if family else None,
        "score": score,
        "link": link,
        "time": ts(_firstKey(info, TIME_KEYS)),
        "categories": list(dict.fromkeys(c for c in categories if c)),
        "count": toInt(info.get("scanner_count")),
        "malicious": toInt(info.get("scanner_match")),
        "children": children,
    }


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
        "links": [], "related": [], "notes": [], "comments": [],
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
    if isinstance(name, str) and name.strip() and name.strip().lower() not in ("n/a", "unknown"):
        retn["name"] = name.strip()
        retn["names"] = [name.strip()]
    retn["mime"] = lower(data.get("file_type_mime") or data.get("mime_type"))
    retn["type"] = lower(data.get("file_type") or data.get("file_type_guess"))
    retn["first_seen"] = ts(data.get("first_seen") or data.get("firstseen") or data.get("first_seen_utc"))
    retn["last_seen"] = ts(data.get("last_seen") or data.get("lastseen"))

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
    for ole in lst(data.get("ole_information")):
        retn["notes"].append(f"ole: {ole}" if not isinstance(ole, dict) else
                             "ole: " + ", ".join(f"{k}={v}" for k, v in ole.items()))

    retn["comments"] = normComments(data.get("comments"))
    comment = data.get("comment")
    if isinstance(comment, str) and comment.strip():
        retn["comments"].insert(0, {"id": None, "time": retn["first_seen"], "author": retn["reporter"],
                                    "text": comment.strip()})

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
    return {
        "task_id": task.get("task_id"),
        "time": ts(task.get("time_stamp")),
        "status": task.get("task_status") or task.get("status"),
        "name": task.get("file_name"),
        "sha256": lower(task.get("sha256_hash")) or (sample["sha256"] if sample else None),
        "clamav_scan": toBool(params.get("clamav_scan", task.get("clamav_scan"))),
        "unpack": toBool(params.get("unpack", task.get("unpack"))),
        "share_file": toBool(params.get("share_file", task.get("share_file"))),
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

    tasks = [t for t in (normTask(t) for t in lst(data.get("tasks"))) if t]
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
            payloads.append(sample)

    # Tag and signature lookups attach the payload to each URL instead.
    sample = normSample(data) if (data.get("sha256_hash") or data.get("md5_hash")) else None
    if sample:
        sample["seen"] = sample["first_seen"]
        payloads.append(sample)

    status = lower(data.get("url_status"))
    host = data.get("host") or None
    return {
        "id": str(data.get("id") or data.get("url_id") or "") or None,
        "url": data["url"].strip(),
        "status": status,
        "host": normHost(host) if host else None,
        "added": ts(data.get("date_added") or data.get("dateadded") or data.get("firstseen")),
        "last_online": ts(data.get("last_online") or data.get("lastseen")),
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
            if item.get("filename"):
                sample["names"] = list(dict.fromkeys(sample["names"] + [item["filename"]]))
            sample["urls"].append(url)
    return sample


# ---- ThreatFox ----


STIX_PATTERNS = {
    "url": "[url:value = '{valu}']",
    "domain": "[domain-name:value = '{valu}']",
    "md5_hash": "[file:hashes.MD5 = '{valu}']",
    "sha1_hash": "[file:hashes.'SHA-1' = '{valu}']",
    "sha256_hash": "[file:hashes.'SHA-256' = '{valu}']",
    "sha3_384_hash": "[file:hashes.'SHA3-384' = '{valu}']",
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
            samples.append(sample)

    family = data.get("malware_printable") or data.get("fk_malware")
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
        "family": family if family and family.lower() not in ("unknown malware", "none") else None,
        "family_tag": normTag(family) if family and family.lower() not in ("unknown malware", "none") else None,
        "aliases": aliases,
        "malpedia": data.get("malware_malpedia"),
        "confidence": toInt(data.get("confidence_level")),
        "first_seen": ts(data.get("first_seen") or data.get("first_seen_utc")),
        "last_seen": ts(data.get("last_seen") or data.get("last_seen_utc")),
        "reference": data.get("reference") if isinstance(data.get("reference"), str) and "://" in data.get("reference", "") else None,
        "reporter": data.get("reporter") if data.get("reporter") not in (None, "anonymous") and not toBool(data.get("anonymous")) else None,
        "tags": normTags(data.get("tags")),
        "comment": (data.get("comment") or "").strip() or None,
        "compromised": toBool(data.get("is_compromised")),
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
SSLBL_IP_CSV = ("firstseen", "dstip", "dstport")
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


def normSslblIp(row: dict) -> dict | None:
    """Normalize an SSLBL botnet C2 IP blacklist row."""

    return normC2(row.get("dstip"), row.get("dstport"), first_seen=row.get("firstseen"),
                  last_online=row.get("firstseen"), source="sslbl")


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
    """Normalize the false positive list (a dict keyed by ID, or a list)."""

    items = data.values() if isinstance(data, dict) else lst(data)
    return [f for f in (normFp(i) for i in items) if f]


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
