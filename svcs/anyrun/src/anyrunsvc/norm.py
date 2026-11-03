"""Normalize ANY.RUN responses for modeling in Storm.

The functions here flatten a task report (``normReport``), a TI Lookup (``normLookup``), YARA
Search matches (``normYaraMatch``), TAXII feed objects (``normStix``), task statuses
(``normStatus``), and history entries (``normTask``) into plain, consistently shaped values
(normalized tags, epoch millis, verdicts, C2 URLs, IP versions...). Nothing here builds nodes;
the Storm package (``slib.anyrun.model``) models the results.

Field names follow ANY.RUN's OpenAPI specs (see client.py). Every reader is defensive: the
specs mark few fields as required, and several (ex. the report's int64 times) don't document
their units.
"""

import datetime
import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

TTPRE = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)
"""MITRE ATT&CK technique IDs."""

URLRE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)

TASKRE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
"""A task UUID (alone or in an app.any.run link)."""

HASHRE = re.compile(r"^[0-9a-fA-F]+$")

HASHLENS = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}

VERDICT_TEXTS = {
    "no threats detected": 10,
    "suspicious activity": 30,
    "malicious activity": 40,
}
"""ANY.RUN's ``threatLevelText`` values as ``it:av:scan:result:verdict`` values."""

THREAT_LEVELS = {1: 30, 2: 40}
"""ANY.RUN's numeric threat levels (0 no threat/no info, 1 suspicious, 2 malicious) as verdicts.

0 isn't mapped: TI Lookup uses it for "no info", which isn't a benign verdict.
"""

STIX_COMPARE = re.compile(
    r"(ipv4-addr|ipv6-addr|domain-name|url|file)\s*:\s*"
    r"(value|hashes\s*\.\s*'?(?:SHA-256|SHA-1|MD5|SHA256|SHA1)'?)\s*=\s*'((?:\\'|[^'])*)'",
    re.IGNORECASE,
)
"""An equality comparison in a STIX pattern, ex. ``[ipv4-addr:value = '1.2.3.4']``."""

STIX_KINDS = {"ipv4-addr": "ipv4", "ipv6-addr": "ipv6", "domain-name": "fqdn", "url": "url"}

HIVES = {
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE",
    "\\REGISTRY\\MACHINE": "HKEY_LOCAL_MACHINE",
    "HKCU": "HKEY_CURRENT_USER",
    "HKEY_CURRENT_USER": "HKEY_CURRENT_USER",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKEY_CLASSES_ROOT": "HKEY_CLASSES_ROOT",
    "HKU": "HKEY_USERS",
    "HKEY_USERS": "HKEY_USERS",
    "\\REGISTRY\\USER": "HKEY_USERS",
    "HKCC": "HKEY_CURRENT_CONFIG",
    "HKEY_CURRENT_CONFIG": "HKEY_CURRENT_CONFIG",
}
"""Registry hive names and abbreviations (upper case) as their full names."""

DEFAULT_VALUES = ("", "(default)", "@")
"""Registry value names that mean a key's default value."""

FILE_OPS = {"CREATE": "add", "WRITE": "write", "DELETE": "del", "READ": "read"}
"""ANY.RUN's file operations (incident events) as it:exec:file:<op> forms. CLOSE isn't modeled."""

REG_OPS = {"write": "set", "delete key": "del", "delete value": "del", "read": "get"}
"""ANY.RUN's registry operations (incident events) as it:exec:reg:<op> forms."""

READ_OPS = ("read", "get")
"""File and registry operations that are only normalized when reads are asked for."""


# ---- Generic helpers ----


def tagPart(valu: Any) -> str | None:
    """Normalize a value into a single tag part (lowercase letters, numbers, and ``_``)."""

    if valu is None:
        return None
    part = re.sub(r"[^a-z0-9_]+", "_", str(valu).strip().lower()).strip("_")
    return part or None


def tagNames(tags: Any) -> list[str]:
    """ANY.RUN tags (strings, or ``{"tag", "users"}`` dicts) as unique tag parts."""

    return uniq(tagPart(t) for t in tagStrs(tags))


def tagStrs(tags: Any) -> list[str]:
    """ANY.RUN tags (strings, or ``{"tag", "users"}`` dicts) as unique strings."""

    ret = []
    for item in tags if isinstance(tags, list) else ():
        if isinstance(item, dict):
            item = item.get("tag")
        if isinstance(item, str) and item.strip():
            ret.append(item.strip())
    return uniq(ret)


def uniq(items) -> list:
    """The unique, truthy, items of an iterable, in order."""

    seen = set()
    ret = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        ret.append(item)
    return ret


def uniqNoCase(items) -> list[str]:
    """The unique (ignoring case), non-empty, stripped strings of an iterable, in order."""

    seen = set()
    ret = []
    for item in items:
        if not isinstance(item, str) or not item.strip():
            continue
        item = item.strip()
        if item.lower() in seen:
            continue
        seen.add(item.lower())
        ret.append(item)
    return ret


def toMsecs(valu: Any) -> int | None:
    """An ISO 8601 string or an epoch time (seconds, millis, or micros) as epoch millis.

    The report's int64 times don't document their unit, so it's inferred from the magnitude.
    Small numbers (ex. offsets from the start of a task) return None.
    """

    if valu is None or isinstance(valu, bool):
        return None
    if isinstance(valu, (int, float)):
        if valu >= 1e14:  # micros
            return int(valu // 1000)
        if valu >= 1e11:  # millis
            return int(valu)
        if valu >= 1e8:  # seconds
            return int(valu * 1000)
        return None
    if isinstance(valu, str):
        valu = valu.strip()
        if not valu:
            return None
        if re.fullmatch(r"\d+(\.\d+)?", valu):
            return toMsecs(float(valu))
        try:
            # Python 3.11+ parses the "Z" suffix.
            when = datetime.datetime.fromisoformat(valu)
        except ValueError:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=datetime.UTC)
        msecs = int(when.timestamp() * 1000)
        return msecs if msecs > 0 else None
    return None


def ival(start: int | None, end: int | None = None) -> list[int] | None:
    """A ``[min, max)`` interval for tags, or None without a start."""

    if start is None:
        return None
    if end is None or end <= start:
        end = start + 1
    return [start, end]


def verdictText(text: Any) -> int | None:
    """An ANY.RUN verdict text (ex. ``Malicious activity``) as an ``it:av:scan:result:verdict``."""

    if not isinstance(text, str):
        return None
    return VERDICT_TEXTS.get(text.strip().lower())


def verdictLevel(level: Any) -> int | None:
    """An ANY.RUN numeric threat level (1 suspicious, 2 malicious) as a verdict."""

    try:
        return THREAT_LEVELS.get(int(level))
    except (TypeError, ValueError):
        return None


def ipVersion(valu: Any) -> str | None:
    """``ipv4`` or ``ipv6`` for an IP, or None if it isn't one."""

    if not valu or not isinstance(valu, str):
        return None
    try:
        addr = ipaddress.ip_address(valu.strip().strip("[]"))
    except ValueError:
        return None
    return f"ipv{addr.version}"


def toInt(valu: Any) -> int | None:
    """An int, or None if the value isn't one."""

    if valu is None or isinstance(valu, bool):
        return None
    try:
        return int(valu)
    except (TypeError, ValueError):
        return None


def port(valu: Any) -> int | None:
    """A valid TCP/UDP port, or None."""

    valu = toInt(valu)
    return valu if valu is not None and 0 < valu < 65536 else None


def proto(valu: Any) -> str:
    """A flow's protocol for a ``proto://host:port`` URL (``tcp`` unless it's ``udp``)."""

    return "udp" if isinstance(valu, str) and valu.strip().lower() == "udp" else "tcp"


def hostPortUrl(scheme: str, host: Any, portnum: Any = None) -> str | None:
    """A ``scheme://host:port`` URL (IPv6 hosts bracketed), or None without a host."""

    if not host or not isinstance(host, str):
        return None
    host = host.strip()
    if ipVersion(host) == "ipv6":
        host = f"[{host.strip('[]')}]"
    portnum = port(portnum)
    return f"{scheme}://{host}:{portnum}" if portnum else f"{scheme}://{host}"


def splitHostPort(valu: str) -> tuple[str | None, int | None]:
    """Split ``host:port``, ``[v6]:port``, or a bare host."""

    valu = valu.strip()
    if valu.startswith("["):
        host, _, rest = valu[1:].partition("]")
        portnum = rest[1:] if rest.startswith(":") else None
    elif valu.count(":") == 1:
        host, portnum = valu.split(":")
    else:
        host, portnum = valu, None
    return host or None, port(portnum)


def c2Urls(valu: Any) -> list[str]:
    """The C2 servers of a malware config's ``C2`` value (URLs or ``host:port``, maybe several)."""

    items = valu if isinstance(valu, list) else re.split(r"[\s,;|]+", str(valu or ""))
    ret = []
    for item in items:
        if not isinstance(item, str) or not item.strip():
            continue
        item = item.strip()
        if URLRE.match(item):
            ret.append(item)
            continue
        host, portnum = splitHostPort(item)
        if not host or not re.fullmatch(r"[0-9A-Za-z.:_-]+", host):
            continue
        ret.append(hostPortUrl("tcp", host, portnum))
    return uniq(ret)


def urlHost(url: Any) -> str | None:
    """The host of a URL."""

    try:
        return urlsplit(str(url)).hostname
    except ValueError:
        return None


def basename(path: Any) -> str | None:
    """The last part of a Windows or POSIX path."""

    if not path or not isinstance(path, str):
        return None
    return path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] or None


def ttp(valu: Any) -> str | None:
    """An ATT&CK technique ID (``T1059``, ``T1059.001``, or TI's bare ``1059``), or None."""

    if valu is None:
        return None
    valu = str(valu).strip().upper()
    if re.fullmatch(r"\d{4}(\.\d{3})?", valu):
        valu = f"T{valu}"
    return valu if TTPRE.match(valu) else None


def hashType(valu: Any) -> str | None:
    """md5, sha1, sha256, or sha512 for a hex hash, or None."""

    if not isinstance(valu, str) or not HASHRE.match(valu):
        return None
    return HASHLENS.get(len(valu))


def hashes(item: Any) -> dict:
    """The (lowercased, valid) md5/sha1/sha256/ssdeep of a ``hashes`` dict."""

    if not isinstance(item, dict):
        return {}
    ret = {}
    for name in ("md5", "sha1", "sha256"):
        valu = item.get(name)
        if hashType(valu) == name:
            ret[name] = valu.lower()
    if isinstance(item.get("ssdeep"), str) and item["ssdeep"].count(":") == 2:
        ret["ssdeep"] = item["ssdeep"]
    return ret


def taskId(valu: Any) -> str | None:
    """A task UUID from a UUID or an app.any.run link, or None."""

    if not valu:
        return None
    match = TASKRE.search(str(valu))
    return match.group(0).lower() if match else None


def dget(data: Any, *path: str) -> Any:
    """``data[path[0]][path[1]]...``, or None if any step is missing."""

    for key in path:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def dlist(data: Any, *path: str) -> list:
    """The list at a path, or an empty list."""

    valu = dget(data, *path)
    return [v for v in valu if v is not None] if isinstance(valu, list) else []


# ---- Tasks ----


def normTask(item: dict) -> dict:
    """A task history entry (GET /v1/analysis)."""

    uuid = taskId(item.get("uuid")) or taskId(item.get("related"))
    return {
        "uuid": uuid,
        "link": f"https://app.any.run/tasks/{uuid}" if uuid else None,
        "name": item.get("name"),
        "verdict": item.get("verdict"),
        "time": toMsecs(item.get("date")),
        "date": item.get("date"),
        "tags": tagStrs(item.get("tags")),
        "hashes": hashes(item.get("hashes")),
    }


def taskState(status: Any) -> str:
    """A task's state for its numeric status (ANY.RUN's documented ranges)."""

    status = toInt(status)
    if status is None:
        return "unknown"
    if status < 0:
        return "failed"
    if status >= 100:
        return "completed"
    if status > 20:
        return "running"
    return "preparing"


def normStatus(event: dict) -> dict:
    """A task monitor event (GET /v1/analysis/monitor/{uuid}).

    Events either describe the task (``{"task": {...}, "completed", "error"}``) or just carry
    a message (queued, launching, failed...).
    """

    task = event.get("task")
    if not isinstance(task, dict):
        mesg = str(event.get("message") or "")
        low = mesg.lower()
        if event.get("error") is True:
            state = "failed"
        elif "queue" in low:
            state = "queued"
        elif "launch" in low:
            state = "preparing"
        elif "cancel" in low or "unknown" in low:
            state = "unknown"
        else:
            state = "unknown"
        return {
            "uuid": None,
            "state": state,
            "status": None,
            "remaining": None,
            "verdict": None,
            "completed": False,
            "message": mesg,
            "tags": [],
            "threats": [],
        }

    status = toInt(task.get("status"))
    state = taskState(status)
    if event.get("completed") is True and state != "failed":
        state = "completed"
    verdict = dget(task, "scores", "verdict") or {}
    return {
        "uuid": taskId(task.get("uuid")),
        "state": state,
        "status": status,
        "remaining": toInt(task.get("remaining")),
        "verdict": verdict.get("text"),
        "completed": state == "completed",
        "message": event.get("message") or "",
        "tags": tagStrs(task.get("tags")) + tagStrs(task.get("usersTags")),
        "threats": [t for t in dlist(task, "threats") if isinstance(t, str)],
    }


# ---- Reports ----


class _Procs:
    """Resolve a report's process references (a process UUID or a PID) to process UUIDs."""

    def __init__(self, procs: list[dict]):
        self.uuids = set()
        self.pids = {}
        for proc in procs:
            uuid = proc.get("uuid")
            if not uuid:
                continue
            self.uuids.add(uuid)
            pid = toInt(proc.get("pid"))
            if pid is not None:
                self.pids.setdefault(pid, uuid)

    def get(self, ref: Any) -> str | None:
        if ref is None or ref == "":
            return None
        if isinstance(ref, str) and ref in self.uuids:
            return ref
        pid = toInt(ref)
        if pid is not None:
            return self.pids.get(pid)
        return None


def normMainObject(main: dict) -> tuple[str | None, str | None, dict | None]:
    """A report's main object as (kind, url, file)."""

    kind = main.get("type")
    url = None
    if kind in ("url", "download"):
        url = main.get("url") or main.get("basename") or main.get("filename")
        if not isinstance(url, str) or not URLRE.match(url):
            url = None

    file = None
    if kind in ("file", "download"):
        file = hashes(main.get("hashes"))
        if file.get("sha256"):
            name = main.get("filename") or main.get("basename")
            if kind == "download" or (isinstance(name, str) and URLRE.match(name)):
                name = None
            file["name"] = basename(name)
            file["mime"] = dget(main, "info", "mime")
        else:
            file = None
    return kind, url, file


def normConfig(item: dict) -> dict:
    """A malware config (``malconf[]``)."""

    config = item.get("config") if isinstance(item.get("config"), dict) else {}
    servers = c2Urls(config.get("C2"))
    return {
        "family": item.get("family") or None,
        "servers": servers,
        "hosts": uniq(urlHost(u) for u in servers),
        "pid": toInt(item.get("processPID")),
        "raw": item,
    }


def normProc(proc: dict, procs: _Procs) -> dict:
    """A process (``processes[]``)."""

    times = proc.get("times") if isinstance(proc.get("times"), dict) else {}
    verdict = dget(proc, "scores", "verdict") or {}
    return {
        "uuid": proc.get("uuid"),
        "pid": toInt(proc.get("pid")),
        "parent": procs.get(proc.get("parentUUID")) or procs.get(proc.get("ppid")),
        "path": proc.get("image") or None,
        "cmd": proc.get("commandLine") or None,
        "time": toMsecs(times.get("start")),
        "exited": toMsecs(times.get("terminate")),
        "exitcode": toInt(proc.get("exitCode")),
        "main": proc.get("mainProcess") is True,
        "threat": proc.get("threatName") or None,
        "verdict": verdictText(verdict.get("threatLevelText")),
        "user": dget(proc, "context", "userName") or None,
    }


def normDns(req: dict, procs: _Procs) -> dict:
    """A DNS request (``network.dnsRequests[]``) with its answers."""

    domain = req.get("domain")
    ips = [ip for ip in dlist(req, "ips") if ipVersion(ip)]
    return {
        "name": domain.strip().lower().rstrip(".") if isinstance(domain, str) else None,
        "time": toMsecs(req.get("time")),
        "ips": [{"ip": ip, "ipver": ipVersion(ip)} for ip in ips],
        "reputation": req.get("reputation") or None,
    }


def normHttp(req: dict, procs: _Procs) -> dict:
    """An HTTP request (``network.httpRequests[]``)."""

    ip = req.get("ip")
    ipver = ipVersion(ip)
    ua = req.get("user-agent")
    return {
        "method": req.get("method") or None,
        "url": req.get("url")
        if isinstance(req.get("url"), str) and URLRE.match(req["url"])
        else None,
        "host": req.get("host") or None,
        "ip": ip if ipver else None,
        "ipver": ipver,
        "port": port(req.get("port")),
        "server": hostPortUrl("tcp", ip, req.get("port")) if ipver else None,
        "code": toInt(req.get("httpCode")),
        "headers": [["user-agent", ua]] if isinstance(ua, str) and ua else [],
        "proc": procs.get(req.get("process")),
        "time": toMsecs(req.get("time")),
        "reputation": req.get("reputation") or None,
    }


def normConn(conn: dict, procs: _Procs) -> dict:
    """A network connection (``network.connections[]``)."""

    ip = conn.get("ip")
    ipver = ipVersion(ip)
    tls = conn.get("tlsFingerprint") if isinstance(conn.get("tlsFingerprint"), dict) else {}
    cc = conn.get("country")
    return {
        "ip": ip if ipver else None,
        "ipver": ipver,
        "port": port(conn.get("port")),
        "proto": proto(conn.get("protocol")),
        "server": hostPortUrl(proto(conn.get("protocol")), ip, conn.get("port")) if ipver else None,
        "cc": cc.lower() if isinstance(cc, str) and re.fullmatch(r"[A-Za-z]{2}", cc) else None,
        "asn": toInt(str(conn.get("asn") or "").upper().removeprefix("AS").split(" ")[0] or None),
        "proc": procs.get(conn.get("process")),
        "time": toMsecs(conn.get("time")),
        "ja3": tls.get("ja3") or None,
        "ja3s": tls.get("ja3S") or None,
        "jarm": tls.get("jarm") or None,
        "reputation": conn.get("reputation") or None,
    }


def normAlert(threat: dict, procs: _Procs) -> dict | None:
    """A Suricata alert (``network.threats[]``), or None without a SID."""

    sid = toInt(threat.get("sid"))
    if sid is None:
        return None
    src, dst = threat.get("srcip"), threat.get("dstip")
    srcver, dstver = ipVersion(src), ipVersion(dst)
    return {
        "sid": sid,
        "msg": threat.get("msg") or None,
        "class": threat.get("class") or None,
        "priority": toInt(threat.get("priority")),
        "src": hostPortUrl("tcp", src, threat.get("srcport")) if srcver else None,
        "srcip": src if srcver else None,
        "srcver": srcver,
        "srcport": port(threat.get("srcport")),
        "dst": hostPortUrl("tcp", dst, threat.get("dstport")) if dstver else None,
        "dstip": dst if dstver else None,
        "dstver": dstver,
        "dstport": port(threat.get("dstport")),
        "proc": procs.get(threat.get("process")),
        "time": toMsecs(threat.get("time")),
    }


def threatLevel(valu: Any) -> str | None:
    """A file's ANY.RUN threat level (``UNKNOWN``, ``LOW``, ``MID``, ``HIGH``) as a tag part."""

    return tagPart(valu) if isinstance(valu, str) else None


def normFile(item: dict, procs: _Procs) -> dict | None:
    """A file the task created (``modified.files[]``), or None without a path or SHA256.

    Files without a SHA256 have no ``file:bytes`` to model, but their creation is still modeled
    by path (with any other hashes ANY.RUN reported).
    """

    file = hashes(item.get("hashes"))
    path = item.get("filename") if isinstance(item.get("filename"), str) else None
    if not file.get("sha256") and not path:
        return None
    file.setdefault("sha256", None)
    file.update(
        {
            "path": path or None,
            "name": basename(path),
            "size": toInt(item.get("size")),
            "mime": dget(item, "info", "mime") or None,
            "threat": threatLevel(item.get("threatLevel")),
            "proc": procs.get(item.get("process")),
            "time": toMsecs(item.get("time")),
            "url": item.get("permanentUrl") or None,
        }
    )
    return file


def _pathKey(path: Any) -> str | None:
    """A case-insensitive key for a Windows (or POSIX) path."""

    return path.replace("/", "\\").lower() if isinstance(path, str) and path else None


def incidentEvents(report: dict) -> list[tuple[dict, dict]]:
    """Every (incident, event) pair of a report's incidents."""

    ret = []
    for incident in dlist(report, "incidents"):
        if not isinstance(incident, dict):
            continue
        for event in dlist(incident, "events"):
            if isinstance(event, dict):
                ret.append((incident, event))
    return ret


def normFileOps(report: dict, procs: _Procs, files: list[dict], reads: bool = False) -> list[dict]:
    """The file operations of a report's incident events (``File`` and ``FileDrop`` events).

    Each is ``{op, path, name, file, proc, time, threat}``, where ``op`` is ``add``, ``write``,
    ``del``, or ``read`` (only with ``reads``) and ``file`` is the file's hashes (from a
    ``FileDrop`` event) or None. A rename is a ``del`` of the old path and an ``add`` of the new
    one. Creations of files already in ``modified.files`` are left to ``files``, and every
    operation gets the threat level ANY.RUN gave the file at the same path.
    """

    threats = {_pathKey(f["path"]): f["threat"] for f in files if f["path"] and f["threat"]}
    created = {_pathKey(f["path"]) for f in files if f["path"]}
    seen = set()
    ret = []

    def add(op, path, incident, event, file=None):
        if not isinstance(path, str) or not path.strip():
            return
        path = path.strip()
        pkey = _pathKey(path)
        if op == "add" and pkey in created:
            return
        if op in READ_OPS and not reads:
            return
        proc = procs.get(incident.get("process"))
        sha256 = (file or {}).get("sha256")
        key = (op, pkey, proc, sha256)
        if key in seen:
            return
        seen.add(key)
        ret.append(
            {
                "op": op,
                "path": path,
                "name": basename(path),
                "file": file or None,
                "proc": proc,
                "time": toMsecs(event.get("time")),
                "threat": threats.get(pkey),
            }
        )

    for incident, event in incidentEvents(report):
        if "sha256" in event and "filename" in event:
            # A FileDrop event.
            file = hashes(event)
            if file.get("sha256"):
                file.update(
                    {"size": toInt(event.get("size")), "mime": event.get("contentType") or None}
                )
                file["name"] = basename(event.get("filename"))
            add(
                "add",
                event.get("filename"),
                incident,
                event,
                file=file if file.get("sha256") else None,
            )
            continue
        oper = event.get("operation")
        if not isinstance(oper, str) or "name" not in event or "key" in event:
            continue
        newname = event.get("newname")
        if isinstance(newname, str) and newname.strip() and newname.strip() != event.get("name"):
            add("del", event.get("name"), incident, event)
            add("add", newname, incident, event)
            continue
        op = FILE_OPS.get(oper.upper())
        if op:
            add(op, event.get("name"), incident, event)
    return ret


def regKey(key: Any) -> str | None:
    """A registry key with its hive's full name (ex. ``HKCU\\Software`` is
    ``HKEY_CURRENT_USER\\Software``), or None."""

    if not isinstance(key, str) or not key.strip():
        return None
    key = key.strip().rstrip("\\")
    upper = key.upper()
    for hive in sorted(HIVES, key=len, reverse=True):
        if upper == hive or upper.startswith(hive + "\\"):
            return HIVES[hive] + key[len(hive) :]
    return key


def regOp(oper: Any) -> str | None:
    """An operation from ``modified.registry`` as ``set``, ``del``, or ``get`` (or None).

    ANY.RUN doesn't document these values, so they're matched by keyword.
    """

    if not isinstance(oper, str):
        return None
    low = oper.strip().lower()
    if low in REG_OPS:
        return REG_OPS[low]
    if "delete" in low or "remove" in low:
        return "del"
    if any(w in low for w in ("write", "set", "create", "modify")):
        return "set"
    if any(w in low for w in ("read", "query", "open", "get")):
        return "get"
    return None


def regValue(value: Any, vtype: Any = None) -> tuple[int | None, str | None]:
    """A registry value as (int, str): an int for DWORD/QWORD values (or untyped integers)."""

    if value is None or value == "":
        return None, None
    value = str(value)
    vtype = str(vtype or "").upper()
    if vtype in ("REG_DWORD", "REG_QWORD") or (not vtype and re.fullmatch(r"-?\d+", value.strip())):
        try:
            return int(value.strip(), 0), None
        except ValueError:
            pass
    return None, value


def normRegOps(report: dict, procs: _Procs, reads: bool = False) -> list[dict]:
    """The registry operations of a report (``modified.registry`` and incident events).

    Each is ``{op, path, key, name, int, str, type, proc, time}``, where ``op`` is ``set``,
    ``del``, or ``get`` (only with ``reads``). ``path`` is the key with the value's name
    appended (``it:dev:regval`` has no prop for the name), or just the key for a key's default
    value and for deleted keys.
    """

    events = [
        (incident, event)
        for incident, event in incidentEvents(report)
        if "key" in event and isinstance(event.get("operation"), str)
    ]
    # Only incident events have the value's type.
    types = {
        ((regKey(e.get("key")) or "").lower(), str(e.get("name") or "").lower()): e.get("typeValue")
        for _, e in events
        if e.get("typeValue")
    }

    seen = set()
    ret = []

    def add(op, key, name, value, vtype, proc, time, delkey=False):
        key = regKey(key)
        if not op or not key or (op == "get" and not reads):
            return
        name = name if isinstance(name, str) else ""
        path = key
        if not delkey and name.strip().lower() not in DEFAULT_VALUES:
            path = f"{key}\\{name}"
        if vtype is None:
            vtype = types.get((key.lower(), name.lower()))
        if op == "del":
            ival, sval = None, None
        else:
            ival, sval = regValue(value, vtype)
        dkey = (op, path.lower(), ival, sval, proc)
        if dkey in seen:
            return
        seen.add(dkey)
        ret.append(
            {
                "op": op,
                "path": path,
                "key": key,
                "name": name or None,
                "int": ival,
                "str": sval,
                "type": vtype or None,
                "proc": proc,
                "time": toMsecs(time),
            }
        )

    for item in dlist(report, "modified", "registry"):
        if isinstance(item, dict):
            oper = str(item.get("operation") or "").lower()
            add(
                regOp(item.get("operation")),
                item.get("key"),
                item.get("name"),
                item.get("value"),
                None,
                procs.get(item.get("process")),
                item.get("time"),
                delkey="key" in oper and "delete" in oper,
            )
    for incident, event in events:
        oper = event["operation"].strip().lower()
        add(
            REG_OPS.get(oper),
            event.get("key"),
            event.get("name"),
            event.get("value"),
            event.get("typeValue"),
            procs.get(incident.get("process")),
            event.get("time"),
            delkey=oper == "delete key",
        )
    return ret


def normScreens(analysis: dict, start: int | None) -> list[dict]:
    """A task's screenshots: ``{uuid, time}`` (the time is the task's start plus the offset)."""

    ret = []
    for item in dlist(analysis, "content", "screenshots"):
        uuid = taskId(item.get("uuid")) if isinstance(item, dict) else None
        if not uuid:
            continue
        offs = item.get("time")
        time = toMsecs(offs)
        if time is None and start is not None and isinstance(offs, (int, float)) and offs >= 0:
            # Screenshot times are int32, too small for epoch millis, so they're offsets.
            # ANY.RUN doesn't document their unit, seconds is the only one that fits a task.
            time = start + int(offs * 1000)
        ret.append({"uuid": uuid, "time": time, "offset": toInt(offs)})
    return ret


def normMutexes(procs: list[dict]) -> list[str]:
    """The mutexes the task's important processes created or opened."""

    ret = []
    for proc in procs:
        if not proc.get("important"):
            continue
        for sync in dlist(proc, "synchronization"):
            if not isinstance(sync, dict) or str(sync.get("type", "")).lower() != "mutex":
                continue
            if isinstance(sync.get("name"), str) and sync["name"].strip():
                ret.append(sync["name"].strip())
    return uniq(ret)


def normReport(report: dict, reads: bool = False) -> dict:
    """Normalize a task report (the ``data`` of GET /v1/analysis/{uuid}).

    Returns the task's ID and link, its main object (``kind``, ``url``, ``file``), times,
    verdict, tags, families, ATT&CK techniques, malware configs, processes, network activity
    (DNS, HTTP, connections, Suricata alerts), created files, file and registry operations
    (reads only with ``reads``), mutexes, screenshots, and whether there's a video.
    """

    analysis = report.get("analysis") if isinstance(report.get("analysis"), dict) else {}
    uuid = taskId(analysis.get("uuid")) or taskId(analysis.get("permanentUrl"))
    main = dget(analysis, "content", "mainObject") or {}
    kind, url, file = normMainObject(main)

    start = toMsecs(analysis.get("creationText")) or toMsecs(analysis.get("creation"))
    end = toMsecs(analysis.get("stopExecText")) or toMsecs(analysis.get("stopExec"))

    verdict = dget(analysis, "scores", "verdict") or {}
    rawprocs = [p for p in dlist(report, "processes") if isinstance(p, dict)]
    procs = _Procs(rawprocs)

    configs = [normConfig(c) for c in dlist(report, "malconf") if isinstance(c, dict)]
    threats = uniqNoCase(p.get("threatName") for p in rawprocs)
    families = uniqNoCase([c["family"] for c in configs] + threats)
    tags = tagStrs(analysis.get("tags"))

    network = report.get("network") if isinstance(report.get("network"), dict) else {}
    files = [f for f in (normFile(i, procs) for i in dlist(report, "modified", "files")) if f]
    errors = []
    if report.get("status") not in (None, "done"):
        errors.append(f"Task {uuid} is {report.get('status')}, its report may be incomplete.")

    return {
        "uuid": uuid,
        "link": f"https://app.any.run/tasks/{uuid}" if uuid else None,
        "status": report.get("status"),
        "kind": kind,
        "url": url,
        "file": file,
        "time": start,
        "ival": ival(start, end),
        "verdict": verdictText(verdict.get("threatLevelText"))
        or verdictLevel(verdict.get("threatLevel")),
        "threat": verdict.get("threatLevelText"),
        "score": toInt(verdict.get("score")),
        "tags": tags,
        "tagnames": uniq(tagPart(t) for t in tags + families),
        "families": families,
        "ttps": uniq(ttp(m.get("id")) for m in dlist(report, "mitre") if isinstance(m, dict)),
        "configs": configs,
        "procs": [normProc(p, procs) for p in rawprocs if p.get("uuid")],
        "dns": [d for d in (normDns(r, procs) for r in dlist(network, "dnsRequests")) if d["name"]],
        "http": [
            h for h in (normHttp(r, procs) for r in dlist(network, "httpRequests")) if h["url"]
        ],
        "flows": [
            c for c in (normConn(r, procs) for r in dlist(network, "connections")) if c["ip"]
        ],
        "alerts": uniqAlerts(normAlert(t, procs) for t in dlist(network, "threats")),
        "files": files,
        "fileops": normFileOps(report, procs, files, reads=reads),
        "regops": normRegOps(report, procs, reads=reads),
        "mutexes": normMutexes(rawprocs),
        "screens": normScreens(analysis, start),
        "video": dget(analysis, "content", "video", "present") is True,
        "env": dget(report, "environments", "os", "title"),
        "errors": errors,
    }


def uniqAlerts(alerts) -> list[dict]:
    """Drop empty and repeated (same SID, endpoints, and time) Suricata alerts."""

    seen = set()
    ret = []
    for alert in alerts:
        if alert is None:
            continue
        key = (alert["sid"], alert["src"], alert["dst"], alert["time"])
        if key in seen:
            continue
        seen.add(key)
        ret.append(alert)
    return ret


# ---- TI Lookup ----


def lookupField(valu: str) -> str | None:
    """The TI Lookup field for an indicator (destinationIP, domainName, url, or a hash)."""

    valu = valu.strip()
    if ipVersion(valu):
        return "destinationIP"
    htype = hashType(valu)
    if htype in ("md5", "sha1", "sha256"):
        return htype
    if URLRE.match(valu):
        return "url"
    if re.fullmatch(r"[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+\.?", valu):
        return "domainName"
    return None


def lookupQuery(field: str, valu: str) -> str:
    """A TI Lookup ``field:"value"`` query (quotes and backslashes escaped)."""

    valu = str(valu).replace("\\", "\\\\").replace('"', '\\"')
    return f'{field}:"{valu}"'


def _threats(item: dict) -> list[str]:
    return uniqNoCase(t for t in item.get("threatName") or [] if isinstance(t, str))


def normLookup(resp: dict) -> dict:
    """Normalize a TI Lookup response (POST /v1/intelligence/api/search).

    Returns the summary (verdict, last seen, tags), the threat names, and the related IPs,
    domains, URLs, files, tasks, mutexes, ATT&CK techniques, and Suricata alerts.
    """

    summary = resp.get("summary") if isinstance(resp.get("summary"), dict) else {}
    lastseen = toMsecs(summary.get("lastSeen"))

    ips = []
    for item in dlist(resp, "destinationIP"):
        ip = item.get("destinationIP") if isinstance(item, dict) else None
        if ipVersion(ip):
            ips.append(
                {
                    "ip": ip,
                    "ipver": ipVersion(ip),
                    "verdict": verdictLevel(item.get("threatLevel")),
                    "threats": _threats(item),
                    "malconf": item.get("isMalconf") is True,
                    "time": toMsecs(item.get("date")),
                }
            )

    fqdns = []
    for item in dlist(resp, "relatedDNS"):
        name = item.get("domainName") if isinstance(item, dict) else None
        if isinstance(name, str) and name.strip():
            fqdns.append(
                {
                    "fqdn": name.strip().lower().rstrip("."),
                    "verdict": verdictLevel(item.get("threatLevel")),
                    "threats": _threats(item),
                    "malconf": item.get("isMalconf") is True,
                    "time": toMsecs(item.get("date")),
                }
            )

    urls = []
    for item in dlist(resp, "relatedURLs"):
        url = item.get("url") if isinstance(item, dict) else None
        if isinstance(url, str) and URLRE.match(url):
            urls.append(
                {
                    "url": url,
                    "verdict": verdictLevel(item.get("threatLevel")),
                    "threats": _threats(item),
                    "malconf": item.get("isMalconf") is True,
                    "time": toMsecs(item.get("date")),
                }
            )

    files = []
    for item in dlist(resp, "relatedFiles"):
        file = hashes(item.get("hashes")) if isinstance(item, dict) else {}
        if file.get("sha256"):
            file.update(
                {
                    "name": basename(item.get("fileName")),
                    "path": item.get("fileName") or None,
                    "task": taskId(item.get("task")),
                    "time": toMsecs(item.get("time")),
                }
            )
            files.append(file)

    tasks = []
    for item in dlist(resp, "sourceTasks"):
        if not isinstance(item, dict):
            continue
        uuid = taskId(item.get("uuid")) or taskId(item.get("related"))
        if not uuid:
            continue
        main = item.get("mainObject") if isinstance(item.get("mainObject"), dict) else {}
        tasks.append(
            {
                "uuid": uuid,
                "link": f"https://app.any.run/tasks/{uuid}",
                "time": toMsecs(item.get("date")),
                "verdict": verdictLevel(item.get("threatLevel")),
                "tags": tagStrs(item.get("tags")),
                "kind": main.get("type"),
                "name": main.get("name"),
                "hashes": hashes(main.get("hashes")),
            }
        )
    tasks.sort(key=lambda t: t["time"] or 0, reverse=True)

    mutexes = uniq(
        item.get("syncObjectName").strip()
        for item in dlist(resp, "relatedSynchronizationObjects")
        if isinstance(item, dict)
        and isinstance(item.get("syncObjectName"), str)
        and str(item.get("syncObjectType", "")).lower() == "mutex"
    )

    ttps = []
    for item in dlist(resp, "relatedIncidents") + dlist(resp, "relatedNetworkThreats"):
        if isinstance(item, dict):
            ttps.extend(ttp(t) for t in item.get("MITRE") or [])

    alerts = []
    for item in dlist(resp, "relatedNetworkThreats"):
        sid = toInt(item.get("suricataID")) if isinstance(item, dict) else None
        if sid is not None:
            alerts.append(
                {
                    "sid": sid,
                    "msg": item.get("suricataMessage") or None,
                    "class": item.get("suricataClass") or None,
                    "level": item.get("suricataThreatLevel") or None,
                }
            )

    threats = uniqNoCase(
        t.get("threatName") for t in dlist(resp, "threatName") if isinstance(t, dict)
    )
    tags = uniqNoCase(t for t in summary.get("tags") or [] if isinstance(t, str))
    level = toInt(summary.get("threatLevel"))
    empty = not any((ips, fqdns, urls, files, tasks, mutexes, alerts, threats))

    return {
        "verdict": verdictLevel(level),
        "level": level,
        "lastseen": lastseen,
        "ival": ival(lastseen),
        "tags": tags,
        "threats": threats,
        "tagnames": uniq(tagPart(t) for t in tags + threats),
        "ips": ips,
        "fqdns": fqdns,
        "urls": urls,
        "files": files,
        "tasks": tasks,
        "mutexes": mutexes,
        "ttps": uniq(ttps),
        "alerts": alerts,
        "countries": uniq(
            c.lower()
            for c in dlist(resp, "destinationIPgeo")
            if isinstance(c, str) and re.fullmatch(r"[A-Za-z]{2}", c)
        ),
        "ports": uniq(port(p) for p in dlist(resp, "destinationPort")),
        "totals": {k: v for k, v in resp.items() if k.startswith("total") and isinstance(v, int)},
        "empty": empty,
    }


# ---- YARA Search ----


def normYaraMatch(match: dict) -> dict | None:
    """A YARA Search match (``matches[]``), or None without a SHA256."""

    file = hashes(match.get("hashes"))
    if not file.get("sha256"):
        return None
    proc = match.get("process") if isinstance(match.get("process"), dict) else {}
    file.update(
        {
            "name": match.get("filePartName") or basename(match.get("fileFullName")),
            "path": match.get("fileFullName") or None,
            "size": toInt(match.get("fileSize")),
            "tags": tagStrs(match.get("relatedTags")),
            "task": taskId(match.get("taskUUID")) or taskId(match.get("tasks")),
            "first": toMsecs(match.get("firstSeen")),
            "last": toMsecs(match.get("lastSeen")),
            "threat": proc.get("threatName") or None,
        }
    )
    return file


# ---- TAXII feeds ----


def _unescape(valu: str) -> str:
    return valu.replace("\\'", "'").replace("\\\\", "\\")


def stixObservables(obj: dict) -> list[tuple[str, str]]:
    """The (kind, value) observables of a STIX object: an indicator's pattern, or an SCO."""

    otype = obj.get("type")
    if otype in STIX_KINDS and isinstance(obj.get("value"), str):
        return [(STIX_KINDS[otype], obj["value"])]
    if otype == "file":
        return [
            (hashType(v), v.lower())
            for v in (obj.get("hashes") or {}).values()
            if isinstance(v, str) and hashType(v) in ("md5", "sha1", "sha256")
        ]
    if otype != "indicator" or not isinstance(obj.get("pattern"), str):
        return []

    ret = []
    for stype, prop, valu in STIX_COMPARE.findall(obj["pattern"]):
        valu = _unescape(valu).strip()
        stype = stype.lower()
        if not valu:
            continue
        if stype == "file":
            if prop.lower() == "value" or not hashType(valu):
                continue
            ret.append((hashType(valu), valu.lower()))
        elif prop.lower() == "value":
            kind = STIX_KINDS[stype]
            if kind in ("ipv4", "ipv6") and ipVersion(valu) != kind:
                # TAXII ipv4-addr values may be CIDRs, only single IPs are modeled.
                continue
            if kind == "fqdn":
                valu = valu.lower().rstrip(".")
            ret.append((kind, valu))
    return uniq(ret)


def normStix(obj: dict) -> dict | None:
    """A TAXII feed object (an indicator or an observable), or None if it has no observable."""

    if not isinstance(obj, dict):
        return None
    observables = stixObservables(obj)
    if not observables:
        return None
    created = toMsecs(obj.get("created"))
    modified = toMsecs(obj.get("modified"))
    valid = toMsecs(obj.get("valid_from")) or created
    until = toMsecs(obj.get("valid_until"))
    labels = [x for x in obj.get("labels") or [] if isinstance(x, str)]
    labels += [x for x in obj.get("indicator_types") or [] if isinstance(x, str)]
    return {
        "id": obj.get("id"),
        "type": obj.get("type"),
        "observables": [{"kind": k, "value": v} for k, v in observables],
        "name": obj.get("name") or None,
        "desc": obj.get("description") or None,
        "created": created,
        "modified": modified,
        "ival": ival(valid, until or modified),
        "labels": uniqNoCase(labels),
        "tagnames": uniq(tagPart(x) for x in labels),
        "confidence": toInt(obj.get("confidence")),
        "revoked": obj.get("revoked") is True,
        "verdict": 40 if obj.get("type") == "indicator" else None,
    }
