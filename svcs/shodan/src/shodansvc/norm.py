"""Normalize raw Shodan responses into flat dicts that are easy to model in Storm.

Shodan banners are large, deeply nested, and vary by module. Doing the
reshaping here keeps the Storm modeling code short, and lets it be unit tested
without a Cortex.
"""

import re
from typing import Any

# The max length of banner text stored in an inet:banner node.
MAX_BANNER_LEN = 16384


def _ts(valu: str | None) -> str | None:
    """Make a Shodan timestamp parseable by Synapse's time type.

    Shodan uses ``2024-01-01T00:00:00.123456`` (no zone, UTC). Synapse
    handles that, but not the occasional trailing ``+00:00``.
    """

    if not valu:
        return None
    return valu.replace("+00:00", "").rstrip("Z")


def _list(valu: Any) -> list:
    if valu is None:
        return []
    if isinstance(valu, (list, tuple, set)):
        return [v for v in valu if v not in (None, "")]
    return [valu]


def normCpe(cpe: str) -> str:
    """Pad a CPE 2.3 string to all 13 components, as Synapse's it:sec:cpe requires.

    Shodan's banners use shortened CPEs like ``cpe:2.3:a:f5:nginx:1.25.3``.
    CPE 2.2 URIs (``cpe:/a:...``) are returned as-is.
    """

    cpe = cpe.strip()
    if not cpe.lower().startswith("cpe:2.3:"):
        return cpe

    parts = cpe.split(":")
    if len(parts) < 13:
        parts.extend(["*"] * (13 - len(parts)))
    return ":".join(parts)


def normCpes(cpes: Any) -> list[str]:
    return [normCpe(c) for c in _list(cpes) if isinstance(c, str)]


def _cpeInfo(cpe: str) -> tuple[str | None, str | None]:
    """Return the (part, version) of a CPE 2.3 or 2.2 string. Wildcard versions are None."""

    # CPE 2.3 escapes colons inside a component as "\:".
    parts = re.split(r"(?<!\\):", cpe)
    if cpe.lower().startswith("cpe:2.3:"):
        part = parts[2] if len(parts) > 2 else None
        vers = parts[5] if len(parts) > 5 else None
    else:
        part = parts[1].lstrip("/") if len(parts) > 1 else None
        vers = parts[4] if len(parts) > 4 else None
    if vers in ("", "*", "-"):
        vers = None
    return part, vers


def normSoftvers(cpes: list[str], product: str | None, version: str | None) -> list[dict]:
    """Pair a banner's CPEs with its product/version, for modeling it:prod:softver nodes.

    Banners list every CPE Shodan detected, ex. ``["cpe:2.3:a:openbsd:openssh:6.6.1p1",
    "cpe:2.3:o:canonical:ubuntu_linux"]``, but the product/version only describe one of
    them. They're only paired with the application CPE whose version matches, so OS CPEs
    and version-less CPEs (shared by every version) don't get another product's name and
    version. When no CPE matches, the product/version get their own entry without a CPE.
    """

    # Prefer a CPE whose version is the banner's exact version, then one whose version is a
    # prefix of it at a word boundary (ex. "6.6.1p1" for "6.6.1p1 Ubuntu 2ubuntu2.13", but
    # not "1.1" for "1.18.0").
    match = None
    if product and version:
        lvers = str(version).lower()
        candidates = []
        for cpe in cpes:
            part, vers = _cpeInfo(cpe)
            if part == "a" and vers:
                candidates.append((cpe, vers.lower()))

        exact = [cpe for cpe, vers in candidates if vers == lvers]
        prefix = [
            cpe
            for cpe, vers in candidates
            if len(lvers) > len(vers)
            and lvers.startswith(vers)
            and not (lvers[len(vers)].isalnum() or lvers[len(vers)] == ".")
        ]
        match = (exact or prefix or [None])[0]

    retn = []
    for cpe in cpes:
        if cpe == match:
            retn.append({"cpe": cpe, "product": product, "version": version})
        else:
            retn.append({"cpe": cpe, "product": None, "version": None})

    if product and match is None:
        retn.append({"cpe": None, "product": product, "version": version})

    return retn


def normVulns(vulns: Any) -> list[dict]:
    """Normalize the ``vulns`` field into a list of dicts.

    Banners use ``{"CVE-X": {"cvss": 9.8, "verified": false, "summary": ...}}``,
    host and InternetDB results use ``["CVE-X", ...]``.
    """

    retn = []
    if isinstance(vulns, dict):
        for cve, info in vulns.items():
            info = info if isinstance(info, dict) else {}
            retn.append(
                {
                    "cve": cve.upper(),
                    "cvss": info.get("cvss"),
                    "verified": bool(info.get("verified", False)),
                    "summary": info.get("summary"),
                }
            )
    else:
        for cve in _list(vulns):
            retn.append({"cve": str(cve).upper(), "cvss": None, "verified": False, "summary": None})

    return [v for v in retn if v["cve"].startswith("CVE-")]


def normLocation(loc: dict | None) -> dict | None:
    if not loc:
        return None

    lat = loc.get("latitude")
    lon = loc.get("longitude")

    return {
        "city": loc.get("city"),
        "region": loc.get("region_code"),
        "country": loc.get("country_name"),
        "country_code": (loc.get("country_code") or "").lower() or None,
        "lat": lat,
        "lon": lon,
        "latlong": (lat, lon) if lat is not None and lon is not None else None,
    }


def normCert(ssl: dict | None) -> dict | None:
    """Normalize the ``ssl`` field of a banner into a flat cert dict."""

    if not ssl:
        return None

    cert = ssl.get("cert") or {}
    fprint = cert.get("fingerprint") or {}
    if not fprint.get("sha256"):
        return None

    subject = cert.get("subject") or {}
    issuer = cert.get("issuer") or {}

    def _dn(parts: dict) -> str | None:
        if not parts:
            return None
        return ", ".join(f"{k}={v}" for k, v in parts.items())

    serial = cert.get("serial")
    if isinstance(serial, int):
        # Synapse wants the serial as a hex string.
        serial = format(serial, "x")

    jarm = ssl.get("jarm")
    ja3s = ssl.get("ja3s")

    return {
        "sha256": fprint.get("sha256"),
        "sha1": fprint.get("sha1"),
        "subject": _dn(subject),
        "subject_cn": subject.get("CN"),
        "issuer": _dn(issuer),
        "issuer_cn": issuer.get("CN"),
        "serial": str(serial) if serial is not None else None,
        "notbefore": _certTime(cert.get("issued")),
        "notafter": _certTime(cert.get("expires")),
        "selfsigned": subject == issuer if subject else None,
        "sigalg": cert.get("sig_alg"),
        "version": cert.get("version"),
        "expired": cert.get("expired"),
        "jarm": jarm,
        "ja3s": ja3s,
        "versions": _list(ssl.get("versions")),
    }


def _certTime(valu: str | None) -> str | None:
    """Convert an ASN.1 time (``20240101000000Z``) into ``2024/01/01 00:00:00``."""

    if not valu or len(valu) < 14:
        return None
    return f"{valu[0:4]}/{valu[4:6]}/{valu[6:8]} {valu[8:10]}:{valu[10:12]}:{valu[12:14]}"


def normBanner(banner: dict) -> dict:
    """Normalize a single Shodan banner (from host lookups, search, or streams)."""

    shodan = banner.get("_shodan") or {}
    http = banner.get("http") or {}
    ssh = banner.get("ssh") or {}

    text = banner.get("data") or ""
    if len(text) > MAX_BANNER_LEN:
        text = text[:MAX_BANNER_LEN]

    cpes = normCpes(banner.get("cpe23")) or normCpes(banner.get("cpe"))

    return {
        "ip": banner.get("ip_str"),
        "port": banner.get("port"),
        "transport": (banner.get("transport") or "tcp").lower(),
        "timestamp": _ts(banner.get("timestamp")),
        "module": shodan.get("module"),
        "crawler": shodan.get("crawler"),
        "id": shodan.get("id"),
        "product": banner.get("product"),
        "version": banner.get("version"),
        "info": banner.get("info"),
        "os": banner.get("os"),
        "cpes": cpes,
        "softvers": normSoftvers(cpes, banner.get("product"), banner.get("version")),
        "data": text,
        "hostnames": [h.lower() for h in _list(banner.get("hostnames"))],
        "domains": [d.lower() for d in _list(banner.get("domains"))],
        "tags": _list(banner.get("tags")),
        "vulns": normVulns(banner.get("vulns")),
        "asn": banner.get("asn"),
        "org": banner.get("org"),
        "isp": banner.get("isp"),
        "location": normLocation(banner.get("location")),
        "cert": normCert(banner.get("ssl")),
        "http": {
            "title": http.get("title"),
            "server": http.get("server"),
            "host": http.get("host"),
            "status": http.get("status"),
            "favicon": (http.get("favicon") or {}).get("hash"),
        }
        if http
        else None,
        "ssh": {
            "type": ssh.get("type"),
            "fingerprint": ssh.get("fingerprint"),
            "key": ssh.get("key"),
        }
        if ssh
        else None,
    }


def normHost(host: dict) -> dict:
    """Normalize a ``/shodan/host/{ip}`` response."""

    banners = [normBanner(b) for b in host.get("data") or []]

    # Hosts report vulns as a list, banners report detailed vuln dicts - prefer
    # the details when a banner has them.
    vulns = {v["cve"]: v for v in normVulns(host.get("vulns"))}
    for banner in banners:
        for vuln in banner["vulns"]:
            vulns[vuln["cve"]] = vuln

    return {
        "ip": host.get("ip_str"),
        "asn": host.get("asn"),
        "org": host.get("org"),
        "isp": host.get("isp"),
        "os": host.get("os"),
        "last_update": _ts(host.get("last_update")),
        "hostnames": [h.lower() for h in _list(host.get("hostnames"))],
        "domains": [d.lower() for d in _list(host.get("domains"))],
        "tags": _list(host.get("tags")),
        "ports": sorted(set(_list(host.get("ports")))),
        "cpes": [],
        "vulns": list(vulns.values()),
        "location": normLocation(host),
        "banners": banners,
    }


def normInternetDb(data: dict) -> dict:
    """Normalize an InternetDB response so it can share the host modeling code."""

    return {
        "ip": data.get("ip"),
        "asn": None,
        "org": None,
        "isp": None,
        "os": None,
        "last_update": None,
        "hostnames": [h.lower() for h in _list(data.get("hostnames"))],
        "domains": [],
        "tags": _list(data.get("tags")),
        "ports": sorted(set(_list(data.get("ports")))),
        "cpes": normCpes(data.get("cpes")),
        "vulns": normVulns(data.get("vulns")),
        "location": None,
        "banners": [],
    }


def normDnsRecords(data: dict) -> list[dict]:
    """Normalize a ``/dns/domain/{domain}`` response into a list of DNS records."""

    domain = (data.get("domain") or "").lower()
    retn = []
    for rec in data.get("data") or []:
        sub = rec.get("subdomain") or ""
        fqdn = f"{sub}.{domain}" if sub else domain
        retn.append(
            {
                "fqdn": fqdn.lower(),
                "type": (rec.get("type") or "").upper(),
                "value": rec.get("value"),
                "seen": _ts(rec.get("last_seen")),
            }
        )
    return retn


def _refs(refs: Any) -> list[str]:
    """Reference URLs, which are strings in CVEs and ``{"type": ..., "url": ...}`` dicts in GHSAs."""

    urls = [r.get("url") if isinstance(r, dict) else r for r in _list(refs)]
    return [u for u in urls if isinstance(u, str) and "://" in u]


def normCve(data: dict) -> dict:
    """Normalize a CVEDB CVE (``/cve/{id}`` or an item from ``/cves``).

    Also accepts the ``cve`` object nested in GHSA/EUVD responses, which uses
    ``id`` instead of ``cve_id``.
    """

    # GHSA/EUVD IDs that CVEDB has linked to this CVE.
    aliases = []
    for key in ("ghsa", "euvd"):
        info = data.get(key) or {}
        if info.get("id"):
            aliases.append(info["id"].upper())

    return {
        "cve": (data.get("cve_id") or data.get("id") or "").upper(),
        "aliases": aliases,
        "summary": data.get("summary"),
        "cvss": data.get("cvss"),
        "cvss_version": data.get("cvss_version"),
        "cvss_v2": data.get("cvss_v2"),
        "cvss_v3": data.get("cvss_v3"),
        "cvss_v4": data.get("cvss_v4"),
        "epss": data.get("epss"),
        "ranking_epss": data.get("ranking_epss"),
        "kev": bool(data.get("kev")),
        "propose_action": data.get("propose_action"),
        "ransomware_campaign": data.get("ransomware_campaign"),
        "references": _refs(data.get("references")),
        "published": _ts(data.get("published_time")),
        "cpes": normCpes(data.get("cpes")),
        "cwes": [],
    }


def normAdvisory(data: dict) -> dict:
    """Normalize a CVEDB ``/ghsa/{id}`` or ``/euvd/{id}`` response into the ``normCve`` shape.

    When CVEDB links the advisory to a CVE the CVE's details are used, with the
    advisory's ID(s) as aliases. Otherwise ``cve`` is empty and the advisory's own
    details are used.
    """

    advid = (data.get("euvd_id") or data.get("id") or "").upper()

    if data.get("cve"):
        retn = normCve(data["cve"])
    else:
        retn = normCve(
            {
                "summary": data.get("summary") or data.get("description"),
                "cvss": data.get("cvss"),
                "epss": data.get("epss"),
                "published_time": data.get("published_time"),
            }
        )

    aliases = [advid]
    for key in ("ghsa", "euvd"):
        info = data.get(key) or {}
        if info.get("id"):
            aliases.append(info["id"].upper())
    retn["aliases"] = sorted(set(retn["aliases"] + aliases))

    retn["references"] = sorted(set(retn["references"] + _refs(data.get("references"))))
    retn["cwes"] = [c.upper() for c in _list(data.get("cwe_ids")) if isinstance(c, str)]
    if not retn["summary"]:
        retn["summary"] = data.get("summary") or data.get("description")

    return retn
