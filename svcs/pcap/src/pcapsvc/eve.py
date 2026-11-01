"""Add what Suricata (EVE JSON events) and the rule engines (alerts) found to a flow.

``pcapsvc.flows`` matches each event to its flow (by frame number, or by Community ID and time,
see ``pcapsvc.svc``), then ``pcapsvc.enrich.Enricher`` calls ``applyEve`` and ``hits`` with the
flow's events when it builds the flow's dict.

EVE events are attributed to a side by what they describe (ex. a TLS ``chain`` is the
server's, an HTTP ``User-Agent`` the client's), not by the packet that triggered them. Files
(``fileinfo``) are attributed to the side that sent them.
"""

import base64
import datetime
import ipaddress
import logging
import os
import re
from typing import Any

_SHA256 = re.compile("[0-9a-f]{64}")
"""A SHA-256, in hex."""

logger = logging.getLogger(__name__)


MAX_LIST = 1000
"""The max number of DNS, SMB, Kerberos, FTP, and anomaly records kept per flow."""


def eveTime(valu: str | None) -> int | None:
    """An EVE timestamp (``2026-10-31T15:46:26.112439+0000``) as epoch millis."""

    if not valu:
        return None
    try:
        tick = datetime.datetime.strptime(valu, "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        return None
    return int(tick.timestamp() * 1000)


def _header(headers: list | None, name: str) -> str | None:
    for item in headers or ():
        if str(item.get("name", "")).lower() == name and item.get("value"):
            return str(item["value"])
    return None


def _append(lst: list, valu: Any) -> None:
    if len(lst) < MAX_LIST:
        lst.append(valu)


def normIp(valu: Any) -> str | None:
    """An IP address in its canonical form, Suricata writes IPv6 addresses fully expanded."""

    try:
        return str(ipaddress.ip_address(str(valu)))
    except ValueError:
        return None


def fromClient(flow: dict, ev: dict) -> bool:
    """Whether an EVE event's source (``src_ip``/``src_port``) is the flow's client."""

    return (normIp(ev.get("src_ip")), ev.get("src_port")) == (
        flow["src"]["ip"],
        flow["src"]["port"],
    )


def keyboardLayout(valu: str | None) -> str | None:
    """Suricata's RDP keyboard layout (ex. ``en-US``) like tshark's (``en_us``)."""

    if not valu or valu == "unknown":
        return None
    return str(valu).replace("-", "_").lower()


def applyEve(enr: Any, flow: dict, events: list[dict], filestore: str | None) -> None:
    """Add a flow's EVE events to an Enricher (``pcapsvc.enrich.Enricher``)."""

    client, server = enr.sides[True], enr.sides[False]
    txs: dict[int, dict] = {}
    files: list[dict] = []
    for ev in events:
        etype = ev.get("event_type")
        body = ev.get(etype) if isinstance(ev.get(etype), dict) else {}

        if etype == "tls":
            for key in ("sni",):
                if body.get(key):
                    enr._uniq(enr.tls["sni"], str(body[key]).lower())
            for key, name in (("ja3", "ja3"), ("ja3s", "ja3s")):
                if isinstance(body.get(key), dict) and body[key].get("hash"):
                    enr._uniq(enr.tls[name], body[key]["hash"])
            if body.get("ja4"):
                enr._uniq(enr.tls["ja4"], body["ja4"])
            if body.get("version"):
                enr._uniq(enr.tls.setdefault("versions", []), body["version"])
            # Suricata 8 puts the client's chain in client.chain (older, client_chain).
            cinfo = body.get("client") if isinstance(body.get("client"), dict) else {}
            for side, chain in (
                (server, body.get("chain")),
                (client, cinfo.get("chain") or body.get("client_chain")),
            ):
                if chain and not side["ssl:certs"]:
                    for b64 in chain:
                        try:
                            der = base64.b64decode(b64)
                        except ValueError:
                            continue
                        enr._cert(side, der)

        elif etype == "http":
            txs[ev.get("tx_id", 0)] = {
                "method": body.get("http_method"),
                "url": body.get("url"),
                "status": body.get("status"),
                "reqtype": _header(body.get("request_headers"), "content-type"),
                "resptype": _header(body.get("response_headers"), "content-type")
                or body.get("http_content_type"),
            }
            if body.get("hostname"):
                enr._uniq(enr.http["hosts"], str(body["hostname"]).lower())
            req = {"method": body.get("http_method"), "uri": body.get("url")}
            if body.get("status") is not None:
                req["status"] = body["status"]
            enr.http["requests"].append(req)
            enr._soft(client, body.get("http_user_agent"))
            enr._soft(server, _header(body.get("response_headers"), "server"))

        elif etype == "fileinfo":
            files.append(ev)

        elif etype == "ssh":
            enr._soft(client, (body.get("client") or {}).get("software_version"))
            enr._soft(server, (body.get("server") or {}).get("software_version"))

        elif etype == "rdp":
            info = body.get("client") or {}
            if body.get("event_type") == "connect_request" and info:
                if info.get("client_name") and not client["rdp:hostname"]:
                    client["rdp:hostname"] = str(info["client_name"]).strip().lower() or None
                layout = keyboardLayout(info.get("keyboard_layout"))
                if layout and not client["rdp:keyboard:layout"]:
                    client["rdp:keyboard:layout"] = layout

        elif etype == "smtp":
            email = ev.get("email") or {}
            for key in ("x_mailer", "user_agent"):
                enr._soft(client, email.get(key))
            enr.extra.setdefault("smtp", [])
            _append(
                enr.extra["smtp"],
                {
                    "helo": body.get("helo"),
                    "from": body.get("mail_from"),
                    "to": body.get("rcpt_to"),
                    "subject": email.get("subject"),
                },
            )

        elif etype == "quic":
            if body.get("sni"):
                enr._uniq(enr.tls["sni"], str(body["sni"]).lower())
            if body.get("ja4"):
                enr._uniq(enr.tls["ja4"], body["ja4"])
            for key in ("ja3", "ja3s"):
                if isinstance(body.get(key), dict) and body[key].get("hash"):
                    enr._uniq(enr.tls[key], body[key]["hash"])
            for ext in body.get("extensions") or ():
                if isinstance(ext, dict) and ext.get("name") == "alpn":
                    for alpn in ext.get("values") or ():
                        enr._uniq(enr.tls.setdefault("alpn", []), str(alpn))
            enr._soft(client, body.get("ua"))
            enr.extra.setdefault("quic", [])
            _append(
                enr.extra["quic"],
                {
                    k: body.get(k)
                    for k in ("version", "sni", "ua", "cyu")
                    if body.get(k) is not None
                },
            )

        elif etype == "dns":
            enr.extra.setdefault("dns", [])
            _append(enr.extra["dns"], {**body, "time": eveTime(ev.get("timestamp"))})

        elif etype == "smb":
            enr.extra.setdefault("smb", [])
            keep = {
                k: body.get(k)
                for k in (
                    "command",
                    "status",
                    "dialect",
                    "share",
                    "share_type",
                    "filename",
                    "disposition",
                    "client_dialects",
                    "server_guid",
                )
                if body.get(k) not in (None, "", [])
            }
            if body.get("ntlmssp"):
                keep["ntlmssp"] = body["ntlmssp"]
            if body.get("request") or body.get("response"):
                keep["native"] = {"request": body.get("request"), "response": body.get("response")}
            _append(enr.extra["smb"], keep)
            for key in ("request", "response"):
                info = body.get(key) or {}
                side = client if key == "request" else server
                for nkey in ("native_os", "native_lm"):
                    enr._soft(side, info.get(nkey))

        elif etype == "krb5":
            enr.extra.setdefault("krb5", [])
            _append(
                enr.extra["krb5"],
                {
                    k: body.get(k)
                    for k in (
                        "msg_type",
                        "cname",
                        "realm",
                        "sname",
                        "encryption",
                        "weak_encryption",
                        "error_code",
                        "failed_request",
                        "ticket_encryption",
                        "ticket_weak_encryption",
                    )
                    # Suricata fills missing names with placeholders.
                    if body.get(k) not in (None, "", "<empty>", "<none>")
                },
            )

        elif etype == "sip":
            enr.extra.setdefault("sip", [])
            _append(
                enr.extra["sip"],
                {
                    k: body.get(k)
                    for k in ("method", "uri", "version", "code", "reason")
                    if body.get(k) is not None
                },
            )

        elif etype == "ftp":
            if body.get("command"):
                enr.extra.setdefault("ftp", [])
                _append(
                    enr.extra["ftp"],
                    {
                        "command": body.get("command"),
                        "data": body.get("command_data"),
                        "codes": body.get("completion_code"),
                    },
                )

        elif etype == "anomaly":
            enr.extra.setdefault("anomalies", [])
            _append(
                enr.extra["anomalies"],
                {k: body.get(k) for k in ("type", "event", "layer") if body.get(k) is not None},
            )

        elif etype == "flow":
            if ev.get("app_proto") and ev["app_proto"] != "failed":
                enr._uniq(enr.extra.setdefault("app_proto", []), ev["app_proto"])

    for ev in files:
        _fileinfo(enr, flow, ev, txs, filestore)


def _fileinfo(enr: Any, flow: dict, ev: dict, txs: dict[int, dict], filestore: str | None) -> None:
    """Add a file Suricata extracted (a ``fileinfo`` event) to the side that sent it."""

    from .enrich import mimeType, uriName

    info = ev.get("fileinfo") or {}
    sha256 = info.get("sha256")
    if info.get("state") == "TRUNCATED" and not info.get("stored"):
        # Cut off before Suricata could store it (ex. over its limits). Files cut off at
        # pcap:files:maxsize are stored, and skipped by their size (see FileStore.addPath).
        if sha256 and enr.files is None:
            enr.unsaved += 1
        return
    if not sha256 or not info.get("stored") or enr.files is None or filestore is None:
        if sha256 and enr.files is None:
            enr.unsaved += 1
        return

    # The engine wrote this (see FileStore.addPath), the name has to be a SHA-256.
    sha256 = str(sha256).lower()
    if not _SHA256.fullmatch(sha256):
        return
    path = os.path.join(filestore, sha256[:2], sha256)

    client = fromClient(flow, ev)
    side = enr.sides[client]
    proto = ev.get("app_proto") or "unknown"
    name = info.get("filename")
    mime = None
    if proto in ("http", "http2"):
        tx = txs.get(info.get("tx_id"), {})
        if client:
            name = uriName(tx.get("url") or name)
            mime = mimeType(tx.get("reqtype"))
        else:
            name = uriName(tx.get("url") or name) if tx.get("method") in (None, "GET") else None
            mime = mimeType(tx.get("resptype"))
        proto = "http"
    elif name:
        name = os.path.basename(str(name).replace("\\", "/")) or None
    if proto == "ftp-data":
        proto = "ftp"

    enr._storedFile(
        side,
        path,
        sha256,
        info.get("size"),
        proto,
        name=name,
        mime=mime,
        complete=not info.get("gaps") and info.get("state") != "TRUNCATED",
    )


def dnsQueries(events: list[dict] | None) -> list[dict] | None:
    """A flow's DNS queries, each with its answers, from Suricata's DNS events.

    Requests and responses are matched by DNS ID and query. Returns a list of ``id``,
    ``rrname``, ``rrtype``, ``rcode`` (the response's code, as a number), ``time``, and
    ``answers`` (``rrname``, ``rrtype``, ``ttl``, ``rdata``), or None without events.
    """

    if not events:
        return None
    rcodes = {"NOERROR": 0, "FORMERR": 1, "SERVFAIL": 2, "NXDOMAIN": 3, "NOTIMP": 4, "REFUSED": 5}
    queries: dict[tuple, dict] = {}
    for ev in events:
        qlist = ev.get("queries") or []
        if not qlist and ev.get("rrname"):
            qlist = [{"rrname": ev.get("rrname"), "rrtype": ev.get("rrtype")}]
        for q in qlist:
            key = (ev.get("id"), str(q.get("rrname") or "").lower(), q.get("rrtype"))
            item = queries.setdefault(
                key,
                {
                    "id": ev.get("id"),
                    "rrname": key[1] or None,
                    "rrtype": q.get("rrtype"),
                    "rcode": None,
                    "time": ev.get("time"),
                    "answers": [],
                },
            )
            if ev.get("time") is not None and (item["time"] is None or ev["time"] < item["time"]):
                item["time"] = ev["time"]
            # Requests have an rcode too (NOERROR), only a response's counts.
            if ev.get("type") in ("response", "answer"):
                if ev.get("rcode") is not None:
                    item["rcode"] = rcodes.get(str(ev["rcode"]).upper(), item["rcode"])
                for ans in ev.get("answers") or []:
                    rec = {
                        "rrname": str(ans.get("rrname") or "").lower() or None,
                        "rrtype": ans.get("rrtype"),
                        "ttl": ans.get("ttl"),
                        "rdata": ans.get("rdata"),
                    }
                    if rec not in item["answers"]:
                        item["answers"].append(rec)
    return list(queries.values())


def alertTime(engine: str, alert: dict) -> int | None:
    """When an alert's packet was captured, in epoch millis."""

    if engine == "suricata":
        return eveTime(alert.get("timestamp"))
    secs = alert.get("seconds")
    if secs is None:
        return None
    usecs = 0
    stamp = str(alert.get("timestamp") or "")
    if "." in stamp:
        frac = stamp.rsplit(".", 1)[1]
        if frac.isdigit():
            usecs = int(frac[:6].ljust(6, "0"))
    return int(secs) * 1000 + usecs // 1000


def alertKey(engine: str, alert: dict) -> tuple[int, int, int, str | None, str | None]:
    """An alert's (gid, sid, rev, message, action)."""

    if engine == "suricata":
        info = alert.get("alert") or {}
        return (
            int(info.get("gid", 1)),
            int(info.get("signature_id", 0)),
            int(info.get("rev", 0)),
            info.get("signature"),
            info.get("action"),
        )
    return (
        int(alert.get("gid", 1)),
        int(alert.get("sid", 0)),
        int(alert.get("rev", 0)),
        alert.get("msg"),
        alert.get("action"),
    )


def hits(
    alerts: list[tuple[str, dict]],
    index: dict[str, dict[str, dict]],
    counts: dict[str, dict[str, int]],
) -> list[dict]:
    """Group a flow's alerts into hits, one per engine and rule.

    Parameters
    ----------
    alerts : list
        The flow's (engine, alert) pairs, the engine is ``snort`` or ``suricata``.
    index : dict
        The loaded rules of each engine, ``gid:sid`` -> ``{"guid": ..., "rev": ...}``.
    counts : dict
        Updated with alerts that aren't for a loaded rule: ``builtin`` (the engine's own
        decoder/inspector alerts, gid != 1) and ``unknown``, by engine and ``gid:sid``.
    """

    grouped: dict[tuple[str, str], dict] = {}
    for engine, alert in alerts:
        gid, sid, rev, msg, action = alertKey(engine, alert)
        key = f"{gid}:{sid}"
        rinfo = index.get(engine, {}).get(key)
        if rinfo is None:
            kind = "builtin" if gid != 1 else "unknown"
            bucket = counts.setdefault(kind, {})
            bkey = f"{engine}:{key}"
            bucket[bkey] = bucket.get(bkey, 0) + 1
            continue

        tick = alertTime(engine, alert)
        hit = grouped.get((engine, key))
        if hit is None:
            grouped[(engine, key)] = {
                "engine": engine,
                "rule": rinfo["guid"],
                "key": key,
                "rev": rev or rinfo["rev"],
                "msg": msg,
                "action": action,
                "count": 1,
                "time": tick,
                "last": tick,
            }
            continue
        hit["count"] += 1
        if tick is not None:
            hit["time"] = tick if hit["time"] is None else min(hit["time"], tick)
            hit["last"] = tick if hit["last"] is None else max(hit["last"], tick)
    return sorted(grouped.values(), key=lambda h: (h["time"] or 0, h["engine"], h["key"]))
