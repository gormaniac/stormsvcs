"""Normalize VirusTotal API v3 objects into flat dicts for the Storm model.

Every ``norm*`` function takes a VirusTotal object (``{"id", "type", "attributes", ...}``) and
returns a dict that ``slib.vt.model`` turns into nodes. Times are epoch millis, lists are capped
so one object can't create thousands of nodes, and the AV verdicts are derived here so Storm
doesn't have to.
"""

import base64
import datetime
import ipaddress
import re
from collections.abc import Iterable, Mapping
from typing import Any

# Synapse's it:av:scan:result:verdict values.
BENIGN = 10
UNKNOWN = 20
SUSPICIOUS = 30
MALICIOUS = 40

# A VirusTotal engine result category's verdict. Engines that scanned and found nothing
# ("undetected") are benign, the others (type-unsupported, timeout, failure...) unknown.
CATEGORY_VERDICTS = {
    "malicious": MALICIOUS,
    "suspicious": SUSPICIOUS,
    "harmless": BENIGN,
    "undetected": BENIGN,
}

# The most items of each list in an object that are normalized.
MAX_NAMES = 50
MAX_ITEMS = 100

# The VirusTotal object types that are normalized, and how they're modeled.
OBJ_TYPES = ("file", "domain", "ip_address", "url", "resolution", "comment", "analysis")


def ms(valu: Any) -> int | None:
    """An epoch seconds int (or numeric string) as epoch millis."""

    if valu is None or valu == "" or isinstance(valu, bool):
        return None
    try:
        return int(float(valu) * 1000)
    except (TypeError, ValueError):
        return None


def _attrs(obj: Mapping | None) -> dict:
    if not isinstance(obj, Mapping):
        return {}
    return obj.get("attributes") or {}


def _list(valu: Any, cap: int = MAX_ITEMS) -> list:
    if not isinstance(valu, (list, tuple)):
        return []
    return list(valu)[:cap]


def _str(valu: Any) -> str | None:
    if valu is None:
        return None
    valu = str(valu).strip()
    return valu or None


def urlId(url: str) -> str:
    """The VirusTotal identifier of a URL: its unpadded, URL safe, base64."""

    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def ipVersion(ip: str) -> int | None:
    """4 or 6 for an IP address, or None if it isn't one."""

    try:
        return ipaddress.ip_address(ip).version
    except ValueError:
        return None


def server(ip: str, port: int, proto: str = "tcp") -> str | None:
    """An inet:server value (ex. ``tcp://1.2.3.4:443`` or ``tcp://[::1]:443``)."""

    vers = ipVersion(ip)
    if vers is None:
        return None
    host = f"[{ip}]" if vers == 6 else ip
    return f"{proto}://{host}:{port}"


def verdict(stats: Mapping | None, malicious: int = 3) -> int | None:
    """The overall verdict of a multi engine scan from its ``last_analysis_stats``.

    Malicious when at least ``malicious`` engines say so, suspicious when any engine detects
    it, benign when engines ran and none did, unknown when none ran.
    """

    if not stats:
        return None
    mal = stats.get("malicious") or 0
    sus = stats.get("suspicious") or 0
    if mal >= max(malicious, 1):
        return MALICIOUS
    if mal or sus:
        return SUSPICIOUS
    if (stats.get("harmless") or 0) + (stats.get("undetected") or 0):
        return BENIGN
    return UNKNOWN


def counts(stats: Mapping | None) -> dict | None:
    """Engine counts (``multi:count:*``) from ``last_analysis_stats``."""

    if not stats:
        return None
    total = sum(v for v in stats.values() if isinstance(v, int))
    mal = stats.get("malicious") or 0
    sus = stats.get("suspicious") or 0
    ben = (stats.get("harmless") or 0) + (stats.get("undetected") or 0)
    return {
        "total": total,
        "malicious": mal,
        "suspicious": sus,
        "benign": ben,
        "unknown": max(total - mal - sus - ben, 0),
    }


def normEngine(name: str, res: Mapping) -> dict:
    """One engine's result from ``last_analysis_results``."""

    cat = res.get("category")
    return {
        "name": _str(res.get("engine_name")) or name,
        "version": _str(res.get("engine_version")),
        "update": _str(res.get("engine_update")),
        "category": cat,
        "verdict": CATEGORY_VERDICTS.get(cat, UNKNOWN),
        "signame": _str(res.get("result")) if cat in ("malicious", "suspicious") else None,
    }


def normScan(attrs: Mapping, malicious: int = 3) -> dict | None:
    """The latest multi engine scan of a file, URL, domain, or IP.

    ``engines`` has every engine's result, the model only uses the detections by default.
    """

    stats = attrs.get("last_analysis_stats")
    results = attrs.get("last_analysis_results") or {}
    if not stats and not results:
        return None

    engines = [normEngine(name, res) for name, res in sorted(results.items()) if res]
    return {
        "time": ms(attrs.get("last_analysis_date")),
        "verdict": verdict(stats, malicious=malicious),
        "counts": counts(stats),
        "engines": engines,
        "detections": sum(1 for e in engines if e["verdict"] >= SUSPICIOUS),
    }


def normVotes(attrs: Mapping) -> dict:
    votes = attrs.get("total_votes") or {}
    return {"harmless": votes.get("harmless") or 0, "malicious": votes.get("malicious") or 0}


def tagPart(valu: Any) -> str | None:
    """A string as a valid Synapse tag part (lowercase, with runs of other chars as ``_``)."""

    valu = _str(valu)
    if not valu:
        return None
    part = re.sub(r"[^a-z0-9_]+", "_", valu.lower()).strip("_")
    return part or None


VERDICT_TAGS = {MALICIOUS: "malicious", SUSPICIOUS: "suspicious", BENIGN: "benign"}


def objTags(
    scan: Mapping | None, tags: Iterable = (), families: Iterable = (), categories: Iterable = ()
) -> list[str]:
    """The tags (relative to the slib.vt tag prefix) for an object.

    ``verdict.<verdict>`` from its latest scan, ``tag.<tag>`` for VirusTotal's tags,
    ``family.<name>`` for threat names, and ``category.<category>`` for threat categories.
    """

    ret = []
    if scan and VERDICT_TAGS.get(scan.get("verdict")):
        ret.append(f"verdict.{VERDICT_TAGS[scan['verdict']]}")
    for prefix, vals in (("tag", tags), ("family", families), ("category", categories)):
        for valu in vals:
            part = tagPart(valu)
            if part and f"{prefix}.{part}" not in ret:
                ret.append(f"{prefix}.{part}")
    return ret


def _common(obj: Mapping, kind: str, malicious: int) -> dict:
    attrs = _attrs(obj)
    return {
        "type": kind,
        "id": obj.get("id"),
        "scan": normScan(attrs, malicious=malicious),
        "tags": [t for t in _list(attrs.get("tags")) if _str(t)],
        "reputation": attrs.get("reputation"),
        "votes": normVotes(attrs),
        "modified": ms(attrs.get("last_modification_date")),
    }


# ---- Files ----


def threatClass(attrs: Mapping) -> dict:
    """VirusTotal's popular threat classification: the label, names, and categories."""

    ptc = attrs.get("popular_threat_classification") or {}
    names = [_str(i.get("value")) for i in _list(ptc.get("popular_threat_name")) if i]
    cats = [_str(i.get("value")) for i in _list(ptc.get("popular_threat_category")) if i]
    return {
        "label": _str(ptc.get("suggested_threat_label")),
        "names": [n for n in names if n],
        "categories": [c for c in cats if c],
    }


def normSandbox(name: str, valu: Mapping) -> dict:
    cat = valu.get("category")
    names = [n for n in (_str(n) for n in _list(valu.get("malware_names"))) if n]
    classes = [c.lower() for c in (_str(c) for c in _list(valu.get("malware_classification"))) if c]
    return {
        "name": _str(valu.get("sandbox_name")) or name,
        "category": cat,
        "verdict": {"harmless": BENIGN, "undetected": BENIGN}.get(
            cat, CATEGORY_VERDICTS.get(cat, UNKNOWN)
        ),
        "signame": names[0] if names else None,
        "names": names,
        "categories": classes,
        "confidence": valu.get("confidence"),
    }


def normYara(res: Mapping) -> dict | None:
    name = _str(res.get("rule_name"))
    if not name:
        return None
    return {
        "name": name,
        "ruleset": _str(res.get("ruleset_name")),
        "ruleset_id": _str(res.get("ruleset_id")),
        "author": _str(res.get("author")),
        "desc": _str(res.get("description")),
        "url": _str(res.get("source")),
        "time": ms(res.get("match_date")),
    }


def normIds(res: Mapping) -> dict | None:
    rid = _str(res.get("rule_id"))
    msg = _str(res.get("rule_msg"))
    if not rid and not msg:
        return None
    return {
        "id": rid,
        "name": msg,
        "category": _str(res.get("rule_category")),
        "severity": _str(res.get("alert_severity")),
        "source": _str(res.get("rule_source")),
        "url": _str(res.get("rule_url")),
        "text": _str(res.get("rule_raw")),
    }


def normSigma(res: Mapping) -> dict | None:
    rid = _str(res.get("rule_id"))
    if not rid:
        return None
    return {
        "id": rid,
        "name": _str(res.get("rule_title")),
        "desc": _str(res.get("rule_description")),
        "level": _str(res.get("rule_level")),
        "author": _str(res.get("rule_author")),
        "source": _str(res.get("rule_source")),
    }


def _sha256(valu: Any) -> str | None:
    valu = _str(valu)
    if valu and len(valu) == 64:
        return valu.lower()
    return None


def normFile(obj: Mapping, malicious: int = 3) -> dict:
    """A VirusTotal file object."""

    attrs = _attrs(obj)
    pe = attrs.get("pe_info") or {}
    names = [n for n in (_str(n) for n in _list(attrs.get("names"), MAX_NAMES)) if n]
    name = _str(attrs.get("meaningful_name")) or (names[0] if names else None)

    ret = _common(obj, "file", malicious)
    ret.update(
        {
            "sha256": _sha256(attrs.get("sha256")) or _sha256(obj.get("id")),
            "sha1": _str(attrs.get("sha1")),
            "md5": _str(attrs.get("md5")),
            "size": attrs.get("size"),
            "ssdeep": _str(attrs.get("ssdeep")),
            "tlsh": _str(attrs.get("tlsh")),
            "vhash": _str(attrs.get("vhash")),
            "authentihash": _str(attrs.get("authentihash")),
            "imphash": _str(pe.get("imphash")),
            "compiled": ms(pe.get("timestamp")),
            "name": name,
            "names": names,
            "magic": _str(attrs.get("magic")),
            "filetype": _str(attrs.get("type_description")),
            "type_tag": _str(attrs.get("type_tag")),
            "first_seen": ms(attrs.get("first_submission_date")),
            "last_seen": ms(attrs.get("last_submission_date")),
            "first_seen_itw": ms(attrs.get("first_seen_itw_date")),
            "times_submitted": attrs.get("times_submitted"),
            "threat": threatClass(attrs),
            "sandboxes": [
                normSandbox(k, v)
                for k, v in sorted((attrs.get("sandbox_verdicts") or {}).items())
                if isinstance(v, Mapping)
            ],
            "yara": [r for r in map(normYara, _list(attrs.get("crowdsourced_yara_results"))) if r],
            "ids": [r for r in map(normIds, _list(attrs.get("crowdsourced_ids_results"))) if r],
            "sigma": [r for r in map(normSigma, _list(attrs.get("sigma_analysis_results"))) if r],
            "signature": attrs.get("signature_info") or None,
        }
    )
    threat = ret["threat"]
    ret["vtags"] = objTags(ret["scan"], ret["tags"], threat["names"][:1], threat["categories"])
    return ret


# ---- Network objects ----


def _dn(parts: Mapping | None) -> str | None:
    if not parts:
        return None
    return ", ".join(f"{k}={v}" for k, v in parts.items())


def normCert(cert: Mapping | None, time: Any = None) -> dict | None:
    """A ``last_https_certificate``."""

    if not cert or not _sha256(cert.get("thumbprint_sha256")):
        return None
    validity = cert.get("validity") or {}
    ext = cert.get("extensions") or {}
    subject = cert.get("subject") or {}
    issuer = cert.get("issuer") or {}
    # Wildcard names (*.example.com) aren't FQDNs.
    sans = [
        s.lower()
        for s in (_str(s) for s in _list(ext.get("subject_alternative_name")))
        if s and "*" not in s
    ]
    serial = _str(cert.get("serial_number"))
    return {
        "sha256": cert["thumbprint_sha256"].lower(),
        "sha1": _str(cert.get("thumbprint")),
        "serial": serial.lower() if serial else None,
        "subject": _dn(subject),
        "subject_cn": _str(subject.get("CN")),
        "issuer": _dn(issuer),
        "notbefore": _str(validity.get("not_before")),
        "notafter": _str(validity.get("not_after")),
        "selfsigned": subject == issuer if subject else None,
        "sans": sans,
        "crls": [u for u in (_str(u) for u in _list(ext.get("crl_distribution_points"))) if u],
        "time": ms(time),
    }


def normWhois(attrs: Mapping) -> dict | None:
    text = _str(attrs.get("whois"))
    if not text:
        return None
    return {"text": text, "asof": ms(attrs.get("whois_date"))}


# The DNS record types in last_dns_records that are modeled.
DNS_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")


def normDnsRecord(rec: Mapping) -> dict | None:
    rtype = _str(rec.get("type"))
    valu = _str(rec.get("value"))
    if rtype not in DNS_TYPES or not valu:
        return None
    ret = {"type": rtype, "value": valu.rstrip(".") if rtype != "TXT" else valu}
    if rtype == "SOA":
        ret["email"] = _str(rec.get("rname"))
    return ret


def _isoMs(valu: Any) -> int | None:
    """An ISO 8601 time (ex. whois_map's ``2020-01-01T00:00:00Z``) as epoch millis."""

    valu = _str(valu)
    if not valu:
        return None
    try:
        dt = datetime.datetime.fromisoformat(valu.split("|")[0].strip())
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.UTC)
    return int(dt.timestamp() * 1000)


def normHistWhois(obj: Mapping) -> dict | None:
    """A whois object from the ``historical_whois`` relationship.

    VirusTotal only returns the parsed ``whois_map``, so the text is rebuilt from it.
    """

    attrs = _attrs(obj)
    wmap = attrs.get("whois_map") or {}
    if not wmap:
        return None
    lower = {str(k).lower(): v for k, v in wmap.items()}
    return {
        "type": "whois",
        "id": obj.get("id"),
        "text": "\n".join(f"{k}: {v}" for k, v in wmap.items()),
        "asof": ms(attrs.get("last_updated")) or ms(attrs.get("first_seen_date")),
        "registrar": _str(lower.get("registrar")),
        "created": _isoMs(lower.get("creation date")),
        "expires": _isoMs(lower.get("registry expiry date") or lower.get("expiry date")),
        "updated": _isoMs(lower.get("updated date")),
    }


def normDomain(obj: Mapping, malicious: int = 3) -> dict:
    """A VirusTotal domain object."""

    attrs = _attrs(obj)
    ret = _common(obj, "domain", malicious)
    whois = normWhois(attrs)
    if whois:
        whois.update(
            {
                "registrar": _str(attrs.get("registrar")),
                "created": ms(attrs.get("creation_date")),
                "expires": ms(attrs.get("expiration_date")),
                "updated": ms(attrs.get("last_update_date")),
            }
        )
    cats = attrs.get("categories") or {}
    ret.update(
        {
            "fqdn": (obj.get("id") or "").lower() or None,
            "whois": whois,
            "dns": [r for r in map(normDnsRecord, _list(attrs.get("last_dns_records"))) if r],
            "dns_time": ms(attrs.get("last_dns_records_date")),
            "cert": normCert(
                attrs.get("last_https_certificate"), attrs.get("last_https_certificate_date")
            ),
            "jarm": _str(attrs.get("jarm")),
            "categories": sorted({c.lower() for c in (_str(c) for c in cats.values()) if c}),
            "first_seen": ms(attrs.get("first_seen_date")),
        }
    )
    ret["vtags"] = objTags(ret["scan"], ret["tags"])
    return ret


def normIp(obj: Mapping, malicious: int = 3) -> dict:
    """A VirusTotal IP address object."""

    attrs = _attrs(obj)
    ip = obj.get("id")
    ret = _common(obj, "ip_address", malicious)
    ret.update(
        {
            "ip": ip,
            "version": ipVersion(ip) if ip else None,
            "asn": attrs.get("asn"),
            "as_owner": _str(attrs.get("as_owner")),
            "country": (_str(attrs.get("country")) or "").lower() or None,
            "network": _str(attrs.get("network")),
            "rir": _str(attrs.get("regional_internet_registry")),
            "whois": normWhois(attrs),
            "jarm": _str(attrs.get("jarm")),
            "cert": normCert(
                attrs.get("last_https_certificate"), attrs.get("last_https_certificate_date")
            ),
            "https": server(ip, 443) if ip else None,
            "first_seen": ms(attrs.get("first_seen_date")),
        }
    )
    ret["vtags"] = objTags(ret["scan"], ret["tags"])
    return ret


def normUrl(obj: Mapping, malicious: int = 3) -> dict:
    """A VirusTotal URL object."""

    attrs = _attrs(obj)
    url = _str(attrs.get("url"))
    final = _str(attrs.get("last_final_url"))
    chain = [u for u in (_str(u) for u in _list(attrs.get("redirection_chain"))) if u]
    cats = attrs.get("categories") or {}
    ret = _common(obj, "url", malicious)
    ret.update(
        {
            "url": url,
            "final": final if final and final != url else None,
            "redirects": chain,
            "title": _str(attrs.get("title")),
            "code": attrs.get("last_http_response_code"),
            "content_sha256": _sha256(attrs.get("last_http_response_content_sha256")),
            "content_size": attrs.get("last_http_response_content_length"),
            "threat_names": [t for t in (_str(t) for t in _list(attrs.get("threat_names"))) if t],
            "categories": sorted({c.lower() for c in (_str(c) for c in cats.values()) if c}),
            "first_seen": ms(attrs.get("first_submission_date")),
            "last_seen": ms(attrs.get("last_submission_date")),
            "times_submitted": attrs.get("times_submitted"),
            "links": [u for u in (_str(u) for u in _list(attrs.get("outgoing_links"))) if u],
        }
    )
    ret["vtags"] = objTags(ret["scan"], ret["tags"], ret["threat_names"])
    return ret


def normResolution(obj: Mapping) -> dict | None:
    """A DNS resolution object (ex. from the ``resolutions`` relationship)."""

    attrs = _attrs(obj)
    ip = _str(attrs.get("ip_address"))
    fqdn = _str(attrs.get("host_name"))
    if not ip or not fqdn:
        return None
    return {
        "type": "resolution",
        "id": obj.get("id"),
        "fqdn": fqdn.lower().rstrip("."),
        "ip": ip,
        "version": ipVersion(ip),
        "time": ms(attrs.get("date")),
        "resolver": _str(attrs.get("resolver")),
    }


def normComment(obj: Mapping) -> dict | None:
    """A comment object."""

    attrs = _attrs(obj)
    text = _str(attrs.get("text"))
    if not text:
        return None
    return {
        "type": "comment",
        "id": obj.get("id"),
        "text": text,
        "time": ms(attrs.get("date")),
        "tags": [t for t in _list(attrs.get("tags")) if _str(t)],
        "votes": attrs.get("votes") or {},
    }


def normAnalysis(obj: Mapping, meta: Mapping | None = None, malicious: int = 3) -> dict:
    """An analysis object (from a submission or rescan), with what it analyzed."""

    attrs = _attrs(obj)
    meta = meta or {}
    stats = attrs.get("stats")
    results = attrs.get("results") or {}
    engines = [normEngine(name, res) for name, res in sorted(results.items()) if res]
    fileinfo = meta.get("file_info") or {}
    urlinfo = meta.get("url_info") or {}
    return {
        "type": "analysis",
        "id": obj.get("id"),
        "status": attrs.get("status"),
        "time": ms(attrs.get("date")),
        "done": attrs.get("status") == "completed",
        "scan": {
            "time": ms(attrs.get("date")),
            "verdict": verdict(stats, malicious=malicious),
            "counts": counts(stats),
            "engines": engines,
            "detections": sum(1 for e in engines if e["verdict"] >= SUSPICIOUS),
        }
        if stats
        else None,
        "sha256": _sha256(fileinfo.get("sha256")),
        "md5": _str(fileinfo.get("md5")),
        "sha1": _str(fileinfo.get("sha1")),
        "size": fileinfo.get("size"),
        "url": _str(urlinfo.get("url")),
    }


def normObject(obj: Mapping, malicious: int = 3) -> dict | None:
    """Normalize any supported VirusTotal object, or return a stub for other types."""

    kind = obj.get("type") if isinstance(obj, Mapping) else None
    if kind == "file":
        return normFile(obj, malicious=malicious)
    if kind == "domain":
        return normDomain(obj, malicious=malicious)
    if kind == "ip_address":
        return normIp(obj, malicious=malicious)
    if kind == "url":
        return normUrl(obj, malicious=malicious)
    if kind == "resolution":
        return normResolution(obj)
    if kind == "comment":
        return normComment(obj)
    if kind == "analysis":
        return normAnalysis(obj, malicious=malicious)
    if kind == "whois":
        return normHistWhois(obj)
    if kind == "ssl_cert":
        cert = normCert(_attrs(obj))
        if cert:
            cert.update({"type": "ssl_cert", "id": obj.get("id")})
        return cert
    if kind:
        return {"type": kind, "id": obj.get("id")}
    return None


# How the objects of a relationship are linked to the object they're related to, keyed by
# (collection, relationship): (verb, direction). "out" is <object> -(verb)> <related>, "in" is
# <related> -(verb)> <object>. Relationships that aren't listed get no edge, ex. a domain's
# resolutions (inet:dns:a nodes) or subdomains (inet:fqdn nodes) are linked by their props.
REL_EDGES = {
    ("files", "contacted_domains"): ("refs", "out"),
    ("files", "contacted_ips"): ("refs", "out"),
    ("files", "contacted_urls"): ("refs", "out"),
    ("files", "dropped_files"): ("refs", "out"),
    ("files", "bundled_files"): ("refs", "out"),
    ("files", "pe_resource_children"): ("refs", "out"),
    ("files", "pe_resource_parents"): ("refs", "in"),
    ("files", "execution_parents"): ("refs", "in"),
    ("domains", "communicating_files"): ("refs", "in"),
    ("domains", "referrer_files"): ("refs", "in"),
    ("ip_addresses", "communicating_files"): ("refs", "in"),
    ("ip_addresses", "referrer_files"): ("refs", "in"),
    ("urls", "last_serving_ip_address"): ("refs", "out"),
}


def relEdge(coll: str, rel: str) -> dict | None:
    """The edge that links a relationship's objects to the object, see ``REL_EDGES``."""

    edge = REL_EDGES.get((coll, rel))
    if edge is None:
        return None
    return {"verb": edge[0], "dir": edge[1]}


def normObjects(objs: Iterable[Mapping], malicious: int = 3) -> list[dict]:
    return [n for n in (normObject(o, malicious=malicious) for o in objs) if n]


# ---- File behaviour ----

# The most items of each behaviour list that are normalized.
MAX_BEHAVIOUR = 50


def _strs(valu: Any, cap: int = MAX_BEHAVIOUR) -> list[str]:
    seen = []
    for item in _list(valu, cap * 4):
        item = _str(item)
        if item and item not in seen:
            seen.append(item)
        if len(seen) >= cap:
            break
    return seen


def normBehaviour(data: Mapping | None) -> dict:
    """A file's ``behaviour_summary``: what the sandboxes saw it do.

    Only the parts that are modeled are kept, each capped at ``MAX_BEHAVIOUR`` items.
    """

    data = data or {}

    dns = []
    for item in _list(data.get("dns_lookups"), MAX_BEHAVIOUR):
        host = _str(item.get("hostname")) if isinstance(item, Mapping) else None
        if not host or "." not in host:
            continue
        ips = [ip for ip in _strs(item.get("resolved_ips"), 20) if ipVersion(ip)]
        dns.append({"fqdn": host.lower().rstrip("."), "ips": ips})

    traffic = []
    for item in _list(data.get("ip_traffic"), MAX_BEHAVIOUR * 4):
        if not isinstance(item, Mapping):
            continue
        ip = _str(item.get("destination_ip"))
        port = item.get("destination_port")
        proto = (_str(item.get("transport_layer_protocol")) or "tcp").lower()
        if not ip or not ipVersion(ip) or not isinstance(port, int) or proto not in ("tcp", "udp"):
            continue
        ent = {"server": server(ip, port, proto)}
        if ent not in traffic:
            traffic.append(ent)
        if len(traffic) >= MAX_BEHAVIOUR:
            break

    http = []
    for item in _list(data.get("http_conversations"), MAX_BEHAVIOUR):
        url = _str(item.get("url")) if isinstance(item, Mapping) else None
        if url:
            http.append({"url": url, "method": _str(item.get("request_method"))})

    techniques = []
    for item in _list(data.get("mitre_attack_techniques"), MAX_ITEMS):
        tid = _str(item.get("id")) if isinstance(item, Mapping) else None
        if tid and tid.upper().startswith("T") and tid.upper() not in techniques:
            techniques.append(tid.upper())

    dropped = []
    for item in _list(data.get("files_dropped"), MAX_ITEMS * 10):
        sha256 = _sha256(item.get("sha256")) if isinstance(item, Mapping) else None
        if sha256 and sha256 not in [d["sha256"] for d in dropped]:
            dropped.append({"sha256": sha256, "path": _str(item.get("path"))})
        if len(dropped) >= MAX_BEHAVIOUR:
            break

    verdicts = [v.lower() for v in _strs(data.get("verdicts"))]
    tags = [t.lower() for t in _strs(data.get("tags"))]
    vtags = []
    for valu in verdicts + tags:
        part = tagPart(valu)
        if part and f"behaviour.{part}" not in vtags:
            vtags.append(f"behaviour.{part}")
    return {
        "verdicts": verdicts,
        "tags": tags,
        "vtags": vtags,
        "dns": dns,
        "traffic": traffic,
        "http": http,
        "techniques": techniques,
        "mutexes": _strs(data.get("mutexes_created")),
        "dropped": dropped,
    }
