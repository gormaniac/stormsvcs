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

EMAILRE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


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
            # Python 3.11+ parses the "Z" suffix.
            valu = datetime.datetime.fromisoformat(valu)
        except ValueError:
            return None
    if isinstance(valu, datetime.datetime):
        if valu.tzinfo is None:
            valu = valu.replace(tzinfo=datetime.UTC)
        msecs = int(valu.timestamp() * 1000)
        # Unset Go times are serialized as 0001-01-01T00:00:00Z.
        return msecs if msecs > 0 else None
    return None


def verdict(score: int | None) -> int | None:
    """Map a Triage score (1-10) to an ``it:av:scan:result:verdict``.

    Triage scores 1 as no malicious behavior, 2-4 as likely benign, 5-7 as suspicious, and
    8-10 as (likely) malicious (https://tria.ge/docs/scoring/).
    """

    try:
        score = int(score)
    except (TypeError, ValueError):
        return None
    if score <= 0:
        return None
    if score >= 8:
        return 40
    if score >= 5:
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


def rrType(rtype: str | None) -> str | None:
    """A DNS record type without its class (Triage reports ex. "IN A" for an A record)."""

    parts = (rtype or "").split()
    return parts[-1].upper() if parts else None


def uniq(items) -> list:
    """The unique, truthy, items of an iterable, in order."""

    ret = []
    for item in items:
        if item and item not in ret:
            ret.append(item)
    return ret


def ttps(items: list | None) -> list[str]:
    """The valid ATT&CK technique IDs in a list, uppercased."""

    return [t.upper() for t in items or [] if isinstance(t, str) and TTPRE.match(t)]


def strs(items: Any) -> list[str]:
    """The unique, non-empty, stripped strings of a list (or a single string)."""

    if isinstance(items, str):
        items = [items]
    if not isinstance(items, list):
        return []
    return uniq(i.strip() for i in items if isinstance(i, str))


def lower(valu: Any) -> str | None:
    """A lowercased string, or None if it's empty (or not a string)."""

    if not isinstance(valu, str):
        return None
    return valu.strip().lower() or None


def hostPortUrl(proto: str, host: Any, port: Any = None) -> str | None:
    """A ``proto://host:port`` URL (IPv6 hosts bracketed), or None without a host."""

    if not host or not isinstance(host, str):
        return None
    host = host.strip()
    if ipVersion(host) == "ipv6":
        host = f"[{host}]"
    try:
        port = int(port) if port else None
    except (TypeError, ValueError):
        port = None
    return f"{proto}://{host}:{port}" if port else f"{proto}://{host}"


def decoyUrl(valu: str) -> str | None:
    """A decoy from a malware config as a URL. Decoys are often bare ``host/path`` values."""

    valu = valu.strip()
    if not valu:
        return None
    if URLRE.match(valu):
        return valu
    if urlHost(f"http://{valu}"):
        return f"http://{valu}"
    return None


def normCreds(items: Any) -> list[dict]:
    """Stolen or embedded credentials (``extracted[].credentials`` or a config's credentials).

    Returns ``[{protocol, host, port, url, username, password, email, emailto}]``.
    """

    if isinstance(items, dict):
        items = [items]
    ret = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        user = item.get("username") or None
        passwd = item.get("password") or None
        if not user and not passwd:
            continue
        proto = lower(item.get("protocol"))
        host = lower(item.get("host"))
        cred = {
            "protocol": proto,
            "host": host,
            "port": item.get("port") or None,
            "url": hostPortUrl(proto, host, item.get("port")) if proto and host else None,
            "username": user,
            "password": passwd,
            # Credentials used to log in with an email address.
            "email": lower(user) if isinstance(user, str) and EMAILRE.match(user) else None,
            "emailto": lower(item.get("email_to")),
        }
        if cred not in ret:
            ret.append(cred)
    return ret


def normConfig(config: dict) -> dict:
    """A malware config: its C2 servers as URLs (and their hosts), mutexes, decoys, listeners,
    DNS resolvers, wallets, and credentials."""

    servers = uniq(c2Url(c) for c in config.get("c2") or [])

    listens = []
    if config.get("listen_addr") or config.get("listen_port"):
        listens.append(
            hostPortUrl("tcp", config.get("listen_addr") or "0.0.0.0", config.get("listen_port"))
        )

    resolvers = []
    for item in strs(config.get("dns")):
        host, port = splitHostPort(item)
        if ipVersion(host):
            resolvers.append(hostPortUrl("udp", host, port or 53))

    return {
        "family": lower(config.get("family")),
        "servers": servers,
        "hosts": uniq(urlHost(s) for s in servers),
        "mutexes": strs(config.get("mutex")),
        "decoys": uniq(decoyUrl(d) for d in strs(config.get("decoy"))),
        "listens": uniq(listens),
        "resolvers": uniq(resolvers),
        "wallets": strs(config.get("wallet")),
        "creds": normCreds(config.get("credentials")),
        "campaign": config.get("campaign") or None,
        "botnet": config.get("botnet") or None,
        "version": config.get("version") or None,
        "raw": config,
    }


def normExtracts(ret: dict, extracts: list[dict] | None) -> None:
    """Add the configs, droppers, and ransom notes of a report's ``extracted`` section."""

    for extract in extracts or []:
        for cred in normCreds(extract.get("credentials")):
            if cred not in ret["creds"]:
                ret["creds"].append(cred)
        if extract.get("config"):
            config = normConfig(extract["config"])
            if config not in ret["configs"]:
                ret["configs"].append(config)
        if extract.get("dropper"):
            dropper = extract["dropper"]
            item = {
                "family": lower(dropper.get("family")),
                "language": dropper.get("language"),
                "urls": uniq(u.get("url") for u in dropper.get("urls") or []),
            }
            if item not in ret["droppers"]:
                ret["droppers"].append(item)
        if extract.get("ransom_note"):
            note = extract["ransom_note"]
            item = {
                "family": lower(note.get("family")),
                "emails": uniq(lower(e) for e in strs(note.get("emails"))),
                "urls": strs(note.get("urls")),
                "wallets": strs(note.get("wallets")),
            }
            if item not in ret["ransom"]:
                ret["ransom"].append(item)


def normSigs(ret: dict, sigs: list[dict] | None) -> None:
    """Add a report's signatures to ``ret["signatures"]`` (unique by label/name, highest score)."""

    for sig in sigs or []:
        name = sig.get("name") or sig.get("label")
        if not name or not isinstance(name, str):
            continue
        key = (sig.get("label") or name).lower()
        cur = ret["signatures"].get(key)
        score = sig.get("score") if isinstance(sig.get("score"), int) else None
        if cur is None:
            ret["signatures"][key] = cur = {
                "key": key,
                "name": name,
                "score": score,
                "verdict": verdict(score),
                "categories": [],
                "ttps": [],
                "desc": sig.get("desc") or None,
            }
        elif score is not None and (cur["score"] is None or score > cur["score"]):
            cur["score"] = score
            cur["verdict"] = verdict(score)
        cur["categories"] = uniq(
            cur["categories"]
            + [t.lower() for t in strs(sig.get("tags")) if not t.startswith("family:")]
        )
        cur["ttps"] = uniq(cur["ttps"] + ttps(sig.get("ttp")))


def headers(items: Any) -> list[list[str]]:
    """``Name: value`` HTTP header lines as ``[name, value]`` pairs (names lowercased)."""

    ret = []
    for line in strs(items):
        name, sep, valu = line.partition(":")
        if sep and name.strip():
            pair = [name.strip().lower(), valu.strip()]
            if pair not in ret:
                ret.append(pair)
    return ret


def normTask(name: str, report: dict) -> dict:
    """A behavioral task report: its processes, network activity, and dropped files.

    Processes are referenced by Triage's ``procid`` (unique within the task) and flows by
    their ``id``, so Storm can derive stable guids from ``(sample, task, kind, id)``.
    """

    procids = {
        p.get("procid") for p in report.get("processes") or [] if p.get("procid") is not None
    }

    # The file this task ran (for archives, the member that was picked).
    task = report.get("task") or {}
    target = (
        task.get("sha256") or (report.get("sample") or {}).get("sha256") or ""
    ).lower() or None
    tname = (basename(task.get("target")) or "").lower()

    procs = []
    for proc in report.get("processes") or []:
        if proc.get("procid") is None:
            continue
        parent = proc.get("procid_parent")
        image = proc.get("image")
        procs.append(
            {
                "procid": proc["procid"],
                "parent": parent if parent in procids else None,
                "pid": proc.get("pid"),
                "cmd": cmdLine(proc.get("cmd")),
                "path": image,
                # Triage sets orig on every process in the sample's tree (or none of them),
                # so the processes that ran the task's file are found by their image's name.
                "orig": bool(proc.get("orig")),
                "sample": bool(tname) and (basename(image) or "").lower() == tname,
            }
        )

    network = report.get("network") or {}
    flows = []
    for flow in network.get("flows") or []:
        dst = flow.get("dst")
        if not dst or flow.get("id") is None:
            continue
        proto = (flow.get("proto") or "tcp").lower()
        host, port = splitHostPort(dst)
        ipver = ipVersion(host)
        srchost, srcport = splitHostPort(flow.get("src") or "")
        srcver = ipVersion(srchost)
        flows.append(
            {
                "id": flow["id"],
                "server": hostPortUrl(proto, host, port) if ipver else None,
                "client": hostPortUrl(proto, srchost, srcport) if srcver else None,
                "proto": proto,
                "ip": host if ipver else None,
                "ipver": ipver,
                "port": port,
                "procid": flow.get("procid") if flow.get("procid") in procids else None,
                "txbytes": flow.get("tx_bytes"),
                "rxbytes": flow.get("rx_bytes"),
                "txcount": flow.get("tx_packets"),
                "rxcount": flow.get("rx_packets"),
                "protocols": uniq(p.lower() for p in strs(flow.get("protocols"))),
                "domain": lower(flow.get("domain")),
                "sni": lower(flow.get("tls_sni")),
                "ja3": lower(flow.get("tls_ja3")),
                "ja3s": lower(flow.get("tls_ja3s")),
            }
        )
    flowids = {f["id"] for f in flows}
    servers = {f["id"]: f["server"] for f in flows}

    # Triage's geolocation of the IPs, at the time of the analysis.
    ips = []
    for addr, info in (network.get("ips") or {}).items():
        if not isinstance(info, dict) or not ipVersion(addr):
            continue
        asn = str(info.get("asn") or "").upper().removeprefix("AS")
        ips.append(
            {
                "ip": addr,
                "ipver": ipVersion(addr),
                "asn": int(asn) if asn.isdigit() else None,
                "cc": lower(info.get("cc")),
            }
        )

    dns, answers, http = [], [], []
    requests = network.get("requests") or []
    for req in requests:
        flow = req.get("flow")
        if req.get("dns_request"):
            dnsreq = req["dns_request"]
            questions = [q for q in dnsreq.get("questions") or [] if q.get("name")]
            if not questions:
                questions = [{"name": d} for d in strs(dnsreq.get("domains"))]
            for quest in questions:
                dns.append(
                    {
                        "flow": flow,
                        "index": req.get("index"),
                        "name": (lower(quest["name"]) or "").rstrip(".") or None,
                        "type": rrType(quest.get("type")),
                        "server": servers.get(flow),
                    }
                )
        if req.get("dns_response"):
            for ans in req["dns_response"].get("answers") or []:
                rtype = (rrType(ans.get("type")) or "").lower()
                if rtype in ("a", "aaaa", "cname") and ans.get("name") and ans.get("value"):
                    answers.append({"type": rtype, "name": ans["name"], "value": ans["value"]})
        if req.get("http_request"):
            code, reason, rheaders = None, None, []
            for resp in requests:
                if (
                    resp.get("http_response")
                    and resp.get("flow") == flow
                    and (resp.get("index") or 0) > (req.get("index") or 0)
                ):
                    httpresp = resp["http_response"]
                    try:
                        code = int(httpresp.get("status"))
                    except (TypeError, ValueError):
                        code = None
                    # The status line, ex. "HTTP/1.1 200 OK".
                    parts = (httpresp.get("response") or "").split(" ", 2)
                    if len(parts) == 3 and parts[0].upper().startswith("HTTP/"):
                        reason = parts[2].strip() or None
                    rheaders = headers(httpresp.get("headers"))
                    break
            http.append(
                {
                    "flow": flow if flow in flowids else None,
                    "index": req.get("index"),
                    "method": req["http_request"].get("method"),
                    "url": req["http_request"].get("url"),
                    "headers": headers(req["http_request"].get("headers")),
                    "server": servers.get(flow),
                    "code": code,
                    "reason": reason,
                    "rheaders": rheaders,
                }
            )

    files = []
    for dump in report.get("dumped") or []:
        # Memory dumps (regions) aren't files.
        if not dump.get("sha256") or dump.get("kind") == "region":
            continue
        files.append(
            {
                "name": dump.get("name"),
                "sha256": dump["sha256"].lower(),
                "md5": dump.get("md5"),
                "sha1": dump.get("sha1"),
                "sha512": dump.get("sha512"),
                "ssdeep": dump.get("ssdeep") or None,
                "size": dump.get("size"),
                "path": dump.get("path"),
                "basename": basename(dump.get("path")),
                "procid": dump.get("procid") if dump.get("procid") in procids else None,
            }
        )

    return {
        "name": name,
        "target": target,
        "procs": procs,
        "flows": flows,
        "ips": ips,
        "dns": dns,
        "answers": uniq(answers),
        "http": http,
        "files": files,
    }


def normSample(
    info: dict, overview: dict, static: dict | None = None, tasks: dict[str, dict] | None = None
) -> dict:
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

    rawtags = strs(analysis.get("tags"))
    fams = [f.lower() for f in analysis.get("family") or []] + [
        f.lower() for f in families(rawtags)
    ]
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
        urls += strs((iocs or {}).get("urls"))
        hosts += strs((iocs or {}).get("domains"))
        hosts += strs((iocs or {}).get("ips"))

    # The files in an archive (or other container) that were analyzed, besides the sample itself.
    members = []
    for target in overview.get("targets") or []:
        tsha = (target.get("sha256") or "").lower()
        if not tsha or tsha == sha256 or any(m["sha256"] == tsha for m in members):
            continue
        tfams = uniq(
            [f.lower() for f in strs(target.get("family"))]
            + [f.lower() for f in families(strs(target.get("tags")))]
        )
        members.append(
            {
                "sha256": tsha,
                "md5": target.get("md5"),
                "sha1": target.get("sha1"),
                "sha512": target.get("sha512"),
                "ssdeep": target.get("ssdeep") or None,
                "size": target.get("size"),
                "path": target.get("target"),
                "name": basename(target.get("target")),
                "score": target.get("score"),
                "tags": uniq(
                    [tagName(t) for t in strs(target.get("tags"))] + [tagPart(f) for f in tfams]
                ),
            }
        )

    # Analysis failures Triage reported, ex. a task that couldn't run.
    errors = []
    for report in [overview, static or {}] + list((tasks or {}).values()):
        for err in report.get("errors") or []:
            if isinstance(err, dict) and (err.get("reason") or err.get("task")):
                mesg = f"Triage reported a failure in {err.get('task') or 'the analysis'}: "
                mesg += err.get("reason") or "unknown reason"
                if mesg not in errors:
                    errors.append(mesg)

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
            "ssdeep": sample.get("ssdeep") or None,
            "size": sample.get("size"),
            "name": basename(sample.get("target") or info.get("filename")),
            "mime": mime,
        }
        if sha256 and info.get("kind") != "url"
        else None,
        "members": members if info.get("kind") != "url" else [],
        "rawtags": rawtags,
        "tags": [],
        "categories": uniq(t.lower() for t in rawtags if not t.startswith("family:")),
        "families": [],
        "ttps": [],
        "iocs": {"urls": uniq(urls), "hosts": uniq(h.lower().rstrip(".") for h in hosts if h)},
        "signatures": {},
        "configs": [],
        "creds": [],
        "droppers": [],
        "ransom": [],
        "tasks": [],
        "reported": errors,
    }
    normExtracts(ret, overview.get("extracted"))
    normSigs(ret, overview.get("signatures"))
    for target in overview.get("targets") or []:
        normSigs(ret, target.get("signatures"))

    for name, report in (tasks or {}).items():
        tanalysis = report.get("analysis") or {}
        ret["rawtags"] += tanalysis.get("tags") or []
        fams += [f.lower() for f in families(tanalysis.get("tags"))]
        techs += ttps(tanalysis.get("ttp"))
        for sig in report.get("signatures") or []:
            techs += ttps(sig.get("ttp"))
        normSigs(ret, report.get("signatures"))
        normExtracts(ret, report.get("extracted"))
        ret["tasks"].append(normTask(name, report))

    for config in ret["configs"]:
        for cred in config["creds"]:
            if cred not in ret["creds"]:
                ret["creds"].append(cred)
    ret["signatures"] = sorted(
        ret["signatures"].values(), key=lambda s: (-(s["score"] or 0), s["key"])
    )

    fams += [c["family"] for c in ret["configs"]] + [r["family"] for r in ret["ransom"]]
    ret["families"] = sorted({f for f in fams if f})
    ret["ttps"] = sorted(set(techs))
    ret["rawtags"] = uniq(ret["rawtags"])
    ret["tags"] = uniq([tagName(t) for t in ret["rawtags"]] + [tagPart(f) for f in ret["families"]])
    ret["categories"] = uniq(t.lower() for t in ret["rawtags"] if not t.startswith("family:"))
    return ret
