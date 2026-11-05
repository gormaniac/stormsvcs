"""Normalize the values sent to bgp.he.net, and the simpler (non-whois, non-cert) responses."""

import ipaddress
import re
from collections.abc import Iterable, Mapping
from typing import Any

MAX_ASN = 2**32 - 1
"""The largest (4 byte) ASN."""

FQDN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{1,63}$")
"""A (lowercase, IDNA encoded) FQDN with at least two labels."""


class BadValu(ValueError):
    """A value can't be sent to bgp.he.net."""

    def __init__(self, mesg: str):
        super().__init__(mesg)
        self.mesg = mesg


def normFqdn(valu: Any) -> str | None:
    """Normalize an FQDN (lowercase, IDNA, no trailing dot or wildcard), or None if invalid."""

    if not isinstance(valu, str):
        return None
    text = valu.strip().lower().rstrip(".").removeprefix("*.")
    if not text:
        return None
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return text if FQDN_RE.match(text) else None


def normDomain(valu: Any) -> str:
    """Normalize a domain to query bgp.he.net for, raising BadValu if it's invalid."""

    fqdn = normFqdn(valu)
    if fqdn is None:
        raise BadValu(f"Invalid domain: {valu!r}")
    return fqdn


def normAsn(valu: Any) -> int:
    """Normalize an ASN (ex. 15169, "15169", "AS15169"), raising BadValu if it's invalid."""

    if isinstance(valu, bool):
        raise BadValu(f"Invalid ASN: {valu!r}")
    if isinstance(valu, int):
        asn = valu
    elif isinstance(valu, str):
        text = valu.strip().upper().removeprefix("AS")
        if not text.isdigit():
            raise BadValu(f"Invalid ASN: {valu!r}")
        asn = int(text)
    else:
        raise BadValu(f"Invalid ASN: {valu!r}")
    if not 0 <= asn <= MAX_ASN:
        raise BadValu(f"Invalid ASN: {valu!r}")
    return asn


def normPrefix(valu: Any) -> dict:
    """Normalize an IP or CIDR to query bgp.he.net for, raising BadValu if it's invalid.

    Returns ``{"addr": ..., "len": ..., "cidr": ..., "version": 4|6}``. An IP is its /32
    (or /128). Host bits in a CIDR are dropped (``10.1.2.3/8`` is ``10.0.0.0/8``).
    """

    if not isinstance(valu, str):
        raise BadValu(f"Invalid IP or CIDR: {valu!r}")
    try:
        net = ipaddress.ip_network(valu.strip(), strict=False)
    except ValueError as err:
        raise BadValu(f"Invalid IP or CIDR: {valu!r}") from err
    return {
        "addr": str(net.network_address),
        "len": net.prefixlen,
        "cidr": str(net),
        "version": net.version,
    }


def _int(valu: Any) -> int | None:
    if isinstance(valu, bool):
        return None
    if isinstance(valu, int):
        return valu
    if isinstance(valu, float) and valu.is_integer():
        return int(valu)
    return None


def normPrefixes(rows: Iterable[Any]) -> list[dict]:
    """Normalize the rows from ``/super-lg/.../prefixes/originated``.

    Each row is ``{"Prefix": "8.8.4.0/24", "Count": 1061, "Total": 1065}``. bgp.he.net
    doesn't document ``Count`` and ``Total``, they look like the route's visibility: how many
    of the Super Looking Glass's peers see the prefix originated by the ASN, out of how many
    peers carry the prefix at all.

    Returns ``[{"prefix": ..., "version": 4|6, "count": ..., "total": ...}]``, IPv4 first.
    Rows that aren't valid networks are dropped.
    """

    out = {}
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        try:
            net = ipaddress.ip_network(str(row.get("Prefix", "")).strip(), strict=False)
        except ValueError:
            continue
        cidr = str(net)
        if cidr in out:
            continue
        out[cidr] = {
            "prefix": cidr,
            "version": net.version,
            "count": _int(row.get("Count")),
            "total": _int(row.get("Total")),
            "_key": (net.version, net.network_address.packed, net.prefixlen),
        }
    retn = sorted(out.values(), key=lambda row: row["_key"])
    for row in retn:
        del row["_key"]
    return retn


def normHosts(prefix: dict, data: Mapping) -> dict:
    """Normalize a ``/certs/api/certificates/by-prefix`` response.

    Returns ``{"prefix", "entries": [{"ip", "version", "fqdns"}], "ips", "hostnames",
    "truncated"}``. ``hostnames`` is bgp.he.net's total, which can be (much) more than the
    hostnames returned, when ``truncated`` is set.
    """

    entries = []
    for entry in data.get("entries") or ():
        if not isinstance(entry, Mapping):
            continue
        try:
            addr = ipaddress.ip_address(str(entry.get("ip", "")).strip())
        except ValueError:
            continue
        fqdns = []
        for host in entry.get("hostnames") or ():
            fqdn = normFqdn(host)
            if fqdn and fqdn not in fqdns:
                fqdns.append(fqdn)
        entries.append({"ip": str(addr), "version": addr.version, "fqdns": sorted(fqdns)})

    entries.sort(key=lambda e: (e["version"], ipaddress.ip_address(e["ip"]).packed))
    return {
        "prefix": prefix["cidr"],
        "entries": entries,
        "ips": _int(data.get("total_ips")),
        "hostnames": _int(data.get("total_hostnames")),
        "truncated": bool(data.get("has_more")),
    }


def normSubdomains(domain: str, data: Mapping) -> dict:
    """Normalize a ``/certs/api/list`` response.

    Returns ``{"domain", "domains": [{"fqdn", "certs"}], "certs", "truncated"}``, most
    certificates first. ``certs`` is bgp.he.net's count of the certificates for all of the
    domains. bgp.he.net limits how many (subdomain, certificate) rows it reads per CT log
    shard, so ``truncated`` means some subdomains (or certificates) may be missing.
    """

    domains = {}
    for row in data.get("domains") or ():
        if not isinstance(row, Mapping):
            continue
        fqdn = normFqdn(row.get("domain"))
        if fqdn is None:
            continue
        count = _int(row.get("certificate_count")) or 0
        domains[fqdn] = max(domains.get(fqdn, 0), count)

    rows = [{"fqdn": fqdn, "certs": count} for fqdn, count in domains.items()]
    rows.sort(key=lambda row: (-row["certs"], row["fqdn"]))
    return {
        "domain": domain,
        "domains": rows,
        "certs": _int(data.get("total_certificates")),
        "truncated": bool(data.get("truncated")),
    }
