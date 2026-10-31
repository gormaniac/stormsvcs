"""Normalize Hatching Triage reports for modeling in Storm.

``normSample`` flattens a sample's metadata, overview and static reports, and behavioral
task reports into plain, consistently shaped values (normalized tags, C2 URLs, host:port
splits, millisecond times, verdicts, etc.). It doesn't build nodes; the Storm package
(``slib.hatching.model``) models the result.
"""


import datetime
import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit


TTPRE = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)
"""MITRE ATT&CK technique IDs."""

URLRE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def tagPart(valu: Any) -> str | None:
    """Normalize a value into a single tag part (lowercase letters, numbers, and ``_``)."""

    if valu is None:
        return None
    part = re.sub(r"[^a-z0-9_]+", "_", str(valu).strip().lower()).strip("_")
    return part or None


def tagName(tag: str) -> str | None:
    """The tag (below the prefix) for a Triage tag (ex. ``family:emotet`` -> ``emotet``)."""

    if not tag:
        return None
    if tag.startswith("family:"):
        return tagPart(tag[7:])
    parts = [tagPart(p) for p in tag.split(":")]
    if not all(parts):
        return None
    return ".".join(parts)


def families(tags: list[str] | None) -> list[str]:
    """The malware families in a list of Triage tags."""

    return [t[7:] for t in tags or [] if t.startswith("family:") and t[7:]]


def toMsecs(valu: Any) -> int | None:
    """An ISO 8601 time string (or datetime) as epoch millis."""

    if not valu:
        return None
    if isinstance(valu, str):
        try:
            valu = datetime.datetime.fromisoformat(valu.replace("Z", "+00:00"))
        except ValueError:
            return None
    if isinstance(valu, datetime.datetime):
        if valu.tzinfo is None:
            valu = valu.replace(tzinfo=datetime.timezone.utc)
        return int(valu.timestamp() * 1000)
    return None


def verdict(score: int | None) -> int | None:
    """Map a Triage score (1-10) to an ``it:av:scan:result:verdict``.

    Triage scores 1-5 as likely benign, 6-7 as suspicious, and 8-10 as (likely) malicious.
    """

    if not score:
        return None
    if score >= 8:
        return 40
    if score >= 6:
        return 30
    return 10


def ipVersion(valu: str | None) -> str | None:
    """``ipv4`` or ``ipv6`` for an IP, or None if it isn't one."""

    if not valu:
        return None
    try:
        addr = ipaddress.ip_address(valu)
    except ValueError:
        return None
    return f"ipv{addr.version}"


def splitHostPort(valu: str) -> tuple[str | None, int | None]:
    """Split ``host:port``, ``[v6]:port``, or a bare host."""

    valu = valu.strip()
    if valu.startswith("["):
        host, _, rest = valu[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else None
    elif valu.count(":") == 1:
        host, port = valu.split(":")
    else:
        host, port = valu, None
    try:
        return host or None, int(port) if port else None
    except ValueError:
        return host or None, None


def c2Url(valu: str) -> str | None:
    """Normalize a C2 entry from a malware config (a URL, or ``host:port``) into a URL."""

    if not valu or not isinstance(valu, str):
        return None
    valu = valu.strip()
    if URLRE.match(valu):
        return valu
    host, port = splitHostPort(valu)
    if not host:
        return None
    if ipVersion(host) == "ipv6":
        host = f"[{host}]"
    return f"tcp://{host}:{port}" if port else f"tcp://{host}"


def urlHost(url: str) -> str | None:
    """The host of a URL."""

    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def cmdLine(cmd: Any) -> str | None:
    """A process command line, which Triage reports as a string or a list of args."""

    if isinstance(cmd, list):
        return " ".join(str(c) for c in cmd) or None
    return cmd or None


def basename(path: str | None) -> str | None:
    """The last part of a Windows or POSIX path."""

    if not path:
        return None
    return path.replace("\\", "/").rsplit("/", 1)[-1] or None


def uniq(items) -> list:
    """The unique, truthy, items of an iterable, in order."""

    ret = []
    for item in items:
        if item and item not in ret:
            ret.append(item)
    return ret


def ttps(items: list | None) -> list[str]:
    return [t.upper() for t in items or [] if isinstance(t, str) and TTPRE.match(t)]


def normConfig(config: dict) -> dict:
    """A malware config: its C2 servers as URLs (and their hosts), mutexes, and decoys."""

    servers = uniq(c2Url(c) for c in config.get("c2") or [])
    return {
        "family": (config.get("family") or "").lower() or None,
        "servers": servers,
        "hosts": uniq(urlHost(s) for s in servers),
        "mutexes": uniq(m for m in config.get("mutex") or [] if isinstance(m, str)),
        "decoys": uniq(d for d in config.get("decoy") or [] if isinstance(d, str) and URLRE.match(d)),
        "campaign": config.get("campaign"),
        "botnet": config.get("botnet"),
        "version": config.get("version"),
        "raw": config,
    }


def normExtracts(ret: dict, extracts: list[dict] | None) -> None:
    """Add the configs, droppers, and ransom notes of a report's ``extracted`` section."""

    for extract in extracts or []:
        if extract.get("config"):
            config = normConfig(extract["config"])
            if config not in ret["configs"]:
                ret["configs"].append(config)
        if extract.get("dropper"):
            dropper = extract["dropper"]
            item = {
                "family": (dropper.get("family") or "").lower() or None,
                "language": dropper.get("language"),
                "urls": uniq(u.get("url") for u in dropper.get("urls") or []),
            }
            if item not in ret["droppers"]:
                ret["droppers"].append(item)
        if extract.get("ransom_note"):
            note = extract["ransom_note"]
            item = {
                "family": (note.get("family") or "").lower() or None,
                "emails": uniq(note.get("emails") or []),
                "urls": uniq(note.get("urls") or []),
                "wallets": uniq(note.get("wallets") or []),
            }
            if item not in ret["ransom"]:
                ret["ransom"].append(item)


def normTask(name: str, report: dict) -> dict:
    """A behavioral task report: its processes, network activity, and dropped files.

    Processes are referenced by Triage's ``procid`` (unique within the task) and flows by
    their ``id``, so Storm can derive stable guids from ``(sample, task, kind, id)``.
    """

    procids = {p.get("procid") for p in report.get("processes") or [] if p.get("procid") is not None}

    procs = []
    for proc in report.get("processes") or []:
        if proc.get("procid") is None:
            continue
        parent = proc.get("procid_parent")
        procs.append({
            "procid": proc["procid"],
            "parent": parent if parent in procids else None,
            "pid": proc.get("pid"),
            "cmd": cmdLine(proc.get("cmd")),
            "path": proc.get("image"),
            "orig": bool(proc.get("orig")),
        })

    network = report.get("network") or {}
    flows = []
    for flow in network.get("flows") or []:
        dst = flow.get("dst")
        if not dst or flow.get("id") is None:
            continue
        proto = (flow.get("proto") or "tcp").lower()
        host, port = splitHostPort(dst)
        ipver = ipVersion(host)
        flows.append({
            "id": flow["id"],
            "server": f"{proto}://{dst}" if ipver else None,
            "proto": proto,
            "ip": host if ipver else None,
            "ipver": ipver,
            "port": port,
            "procid": flow.get("procid") if flow.get("procid") in procids else None,
            "txbytes": flow.get("tx_bytes"),
            "rxbytes": flow.get("rx_bytes"),
            "domain": flow.get("domain"),
        })
    flowids = {f["id"] for f in flows}

    dns, answers, http = [], [], []
    requests = network.get("requests") or []
    for req in requests:
        flow = req.get("flow")
        if req.get("dns_request"):
            for domain in req["dns_request"].get("domains") or []:
                dns.append({"flow": flow, "index": req.get("index"), "name": domain})
        if req.get("dns_response"):
            for ans in req["dns_response"].get("answers") or []:
                rtype = (ans.get("type") or "").lower()
                if rtype in ("a", "aaaa", "cname") and ans.get("name") and ans.get("value"):
                    answers.append({"type": rtype, "name": ans["name"], "value": ans["value"]})
        if req.get("http_request"):
            code = None
            for resp in requests:
                if (resp.get("http_response") and resp.get("flow") == flow
                        and (resp.get("index") or 0) > (req.get("index") or 0)):
                    try:
                        code = int(resp["http_response"].get("status"))
                    except (TypeError, ValueError):
                        code = None
                    break
            http.append({
                "flow": flow if flow in flowids else None,
                "index": req.get("index"),
                "method": req["http_request"].get("method"),
                "url": req["http_request"].get("url"),
                "code": code,
            })

    files = []
    for dump in report.get("dumped") or []:
        # Memory dumps (regions) aren't files.
        if not dump.get("sha256") or dump.get("kind") == "region":
            continue
        files.append({
            "name": dump.get("name"),
            "sha256": dump["sha256"].lower(),
            "md5": dump.get("md5"),
            "sha1": dump.get("sha1"),
            "sha512": dump.get("sha512"),
            "size": dump.get("size"),
            "path": dump.get("path"),
            "basename": basename(dump.get("path")),
            "procid": dump.get("procid") if dump.get("procid") in procids else None,
        })

    return {
        "name": name,
        "procs": procs,
        "flows": flows,
        "dns": dns,
        "answers": uniq(answers),
        "http": http,
        "files": files,
    }


def normSample(info: dict, overview: dict, static: dict | None = None,
               tasks: dict[str, dict] | None = None) -> dict:
    """Normalize a sample's metadata, reports, and (optionally) behavioral task reports.

    Parameters
    ----------
    info : dict
        The sample's metadata (GET /samples/{id}).
    overview : dict
        The overview report.
    static : dict | None
        The static report, used for the sample's MIME type.
    tasks : dict | None
        Behavioral task reports, keyed by task name.
    """

    sample = overview.get("sample") or {}
    analysis = overview.get("analysis") or {}

    first = toMsecs(sample.get("submitted") or info.get("submitted"))
    last = toMsecs(sample.get("completed") or info.get("completed")) or first

    sha256 = (sample.get("sha256") or "").lower() or None
    mime = None
    for item in (static or {}).get("files") or []:
        if sha256 and (item.get("sha256") or "").lower() == sha256:
            mime = item.get("mime")
            break

    rawtags = list(analysis.get("tags") or [])
    fams = [f.lower() for f in analysis.get("family") or []] + [f.lower() for f in families(rawtags)]
    techs = []
    for sig in overview.get("signatures") or []:
        techs += ttps(sig.get("ttp"))
    for target in overview.get("targets") or []:
        for sig in target.get("signatures") or []:
            techs += ttps(sig.get("ttp"))
    for task in overview.get("tasks") or []:
        techs += ttps(task.get("ttp"))

    urls, hosts = [], []
    for iocs in [sample.get("iocs")] + [t.get("iocs") for t in overview.get("targets") or []]:
        urls += (iocs or {}).get("urls") or []
        hosts += (iocs or {}).get("domains") or []
        hosts += (iocs or {}).get("ips") or []

    ret = {
        "id": info["id"],
        "kind": info.get("kind"),
        "status": info.get("status"),
        "score": analysis.get("score"),
        "verdict": verdict(analysis.get("score")),
        "time": last,
        "ival": [first, max(last, first + 1)] if first else None,
        "url": (info.get("url") or sample.get("target")) if info.get("kind") == "url" else None,
        "file": {
            "sha256": sha256,
            "md5": sample.get("md5"),
            "sha1": sample.get("sha1"),
            "sha512": sample.get("sha512"),
            "size": sample.get("size"),
            "name": basename(sample.get("target") or info.get("filename")),
            "mime": mime,
        } if sha256 and info.get("kind") != "url" else None,
        "rawtags": rawtags,
        "tags": [],
        "categories": uniq(t.lower() for t in rawtags if not t.startswith("family:")),
        "families": [],
        "ttps": [],
        "iocs": {"urls": uniq(urls), "hosts": uniq(h.lower().rstrip(".") for h in hosts if h)},
        "configs": [],
        "droppers": [],
        "ransom": [],
        "tasks": [],
    }
    normExtracts(ret, overview.get("extracted"))

    for name, report in (tasks or {}).items():
        tanalysis = report.get("analysis") or {}
        ret["rawtags"] += tanalysis.get("tags") or []
        fams += [f.lower() for f in families(tanalysis.get("tags"))]
        techs += ttps(tanalysis.get("ttp"))
        for sig in report.get("signatures") or []:
            techs += ttps(sig.get("ttp"))
        normExtracts(ret, report.get("extracted"))
        ret["tasks"].append(normTask(name, report))

    fams += [c["family"] for c in ret["configs"]] + [r["family"] for r in ret["ransom"]]
    ret["families"] = sorted(set(f for f in fams if f))
    ret["ttps"] = sorted(set(techs))
    ret["rawtags"] = uniq(ret["rawtags"])
    ret["tags"] = uniq([tagName(t) for t in ret["rawtags"]] + [tagPart(f) for f in ret["families"]])
    ret["categories"] = uniq(t.lower() for t in ret["rawtags"] if not t.startswith("family:"))
    return ret
