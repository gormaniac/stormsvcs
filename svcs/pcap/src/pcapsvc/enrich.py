"""Turn the tshark fields found in a flow's frames into the flow's application layer details.

``pcapsvc.flows`` matches each tshark frame (see ``pcapsvc.tshark``) to its flow and the side
that sent it, then ``enrichFlow`` adds what was found to the flow's dict, per side:

- ``ssl:cert`` / ``ssl:certs``: The TLS certificate (and its chain) the side sent.
- ``ssh:key``: The SSH host key the side sent.
- ``rdp:hostname`` / ``rdp:keyboard:layout``: From an RDP client's Client Core Data.
- ``softnames`` / ``cpes``: Software the side identified itself as (HTTP User-Agent/Server,
  SSH banners, SIP, email clients), and CPEs for the well known ones.
- ``txfiles``: Files the side sent: HTTP bodies (and multipart uploads), FTP transfers, and
  emails (and their attachments). The bytes are written to a ``FileStore``.

And for the flow as a whole: ``tls`` (SNIs, JA3, JA3S, JA4) and ``http`` (hosts, requests).
"""


import email
import email.policy
import hashlib
import locale
import os
import posixpath
import re
import shutil
import struct
import urllib.parse
from typing import Any

from . import eve as p_eve
from . import x509 as p_x509

FTP_FILE_CMDS = ("RETR", "STOR", "STOU", "APPE")
"""FTP commands whose data connection transfers a file (not a directory listing)."""

CPES = (
    (re.compile(r"^openssh[_-](\d+\.\d+)(p\d+)?"),
     lambda m: f"cpe:2.3:a:openbsd:openssh:{m[1]}:{m[2] or '*'}:*:*:*:*:*:*"),
    (re.compile(r"^dropbear[_-](\d{4}\.\d+)"),
     lambda m: f"cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:{m[1]}:*:*:*:*:*:*:*"),
    (re.compile(r"^nginx/(\d+\.\d+\.\d+)"),
     lambda m: f"cpe:2.3:a:f5:nginx:{m[1]}:*:*:*:*:*:*:*"),
    (re.compile(r"^apache/(\d+\.\d+\.\d+)"),
     lambda m: f"cpe:2.3:a:apache:http_server:{m[1]}:*:*:*:*:*:*:*"),
    (re.compile(r"^microsoft-iis/(\d+\.\d+)"),
     lambda m: f"cpe:2.3:a:microsoft:internet_information_services:{m[1]}:*:*:*:*:*:*:*"),
    (re.compile(r"^lighttpd/(\d+\.\d+\.\d+)"),
     lambda m: f"cpe:2.3:a:lighttpd:lighttpd:{m[1]}:*:*:*:*:*:*:*"),
    (re.compile(r"^curl/(\d+\.\d+\.\d+)"),
     lambda m: f"cpe:2.3:a:haxx:curl:{m[1]}:*:*:*:*:*:*:*"),
    (re.compile(r"^wget/(\d+\.\d+(?:\.\d+)?)"),
     lambda m: f"cpe:2.3:a:gnu:wget:{m[1]}:*:*:*:*:*:*:*"),
    (re.compile(r"^thunderbird/(\d+\.\d+(?:\.\d+)?)"),
     lambda m: f"cpe:2.3:a:mozilla:thunderbird:{m[1]}:*:*:*:*:*:*:*"),
)
"""(pattern, CPE builder) pairs for well known software names (matched lowercased)."""


def softname(valu: str) -> str | None:
    """Normalize a software name like Synapse's it:prod:softname (lowercase, single spaced)."""

    valu = " ".join(str(valu).split()).lower()
    return valu or None


def softCpes(name: str) -> list[str]:
    """CPE 2.3 strings for a software name, if it's a well known one with a version."""

    return [build(m) for regx, build in CPES if (m := regx.match(name))]


def sshSoftware(banner: str) -> str | None:
    """The software in an SSH identification string (``SSH-2.0-<software> <comments>``)."""

    parts = banner.strip().split("-", 2)
    if len(parts) == 3 and parts[0] == "SSH":
        return parts[2]
    return None


def keyboardLayout(valu: int) -> str:
    """An RDP keyboard layout as its locale (ex. 0x409 is en_us), or the KLID hex if unknown."""

    if not valu >> 16:
        name = locale.windows_locale.get(valu & 0xFFFF)
        if name:
            return name.lower()
    return f"{valu:08x}"


def _sshString(valu: bytes) -> bytes:
    return struct.pack(">I", len(valu)) + valu


def sshKeyBlob(rec: dict) -> bytes | None:
    """Rebuild an SSH host key's wire format blob (RFC 4253, 5656, 8709) from tshark's fields."""

    def one(field: str) -> bytes | None:
        valu = rec.get(field)
        return bytes.fromhex(valu[0].replace(":", "")) if valu else None

    ktype = rec.get("ssh.host_key.type", [None])[0]
    if not ktype:
        return None
    parts = None
    if ktype == "ssh-rsa":
        parts = (one("ssh.host_key.rsa.e"), one("ssh.host_key.rsa.n"))
    elif ktype == "ssh-dss":
        parts = tuple(one(f"ssh.host_key.dsa.{n}") for n in "pqgy")
    elif ktype.startswith("ecdsa-sha2-"):
        ident = rec.get("ssh.host_key.ecdsa.id", [None])[0]
        parts = (ident.encode() if ident else None, one("ssh.host_key.ecdsa.q"))
    elif ktype in ("ssh-ed25519", "ssh-ed448"):
        parts = (one("ssh.host_key.eddsa.key"),)

    if parts is not None and all(p is not None for p in parts):
        blob = _sshString(ktype.encode()) + b"".join(_sshString(p) for p in parts)
    elif (data := one("ssh.host_key.data")) is not None:
        blob = _sshString(ktype.encode()) + data
    else:
        return None

    size = rec.get("ssh.host_key.length")
    if size and int(size[0]) != len(blob):
        return None
    return blob


def sshKey(blob: bytes, ktype: str) -> dict:
    """An SSH public key's details, with the hashes used as its fingerprints."""

    return {
        "algo": ktype,
        "blob": blob.hex(),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "sha1": hashlib.sha1(blob).hexdigest(),
        "md5": hashlib.md5(blob, usedforsecurity=False).hexdigest(),
    }


def uriName(uri: str | None) -> str | None:
    """The file name at the end of a URI's path, if it has one."""

    if not uri:
        return None
    path = urllib.parse.urlsplit(uri).path
    name = posixpath.basename(urllib.parse.unquote(path))
    return name or None


def mimeType(valu: str | None) -> str | None:
    """A Content-Type without its parameters."""

    if not valu:
        return None
    return valu.split(";", 1)[0].strip().lower() or None


class FileStore:
    """Writes the files found in flows to a directory, named by SHA-256, up to the limits.

    Parameters
    ----------
    dirn : str
        The directory to write files to.
    maxsize : int
        The largest file to keep, in bytes, 0 for no limit.
    limit : int
        The max number of files to keep, 0 for no limit.
    """

    def __init__(self, dirn: str, maxsize: int = 0, limit: int = 0) -> None:
        self.dirn = dirn
        self.maxsize = maxsize
        self.limit = limit
        self.files: dict[str, int] = {}
        self.skipped = 0

    def add(self, data: bytes) -> str | None:
        """Store a file and return its SHA-256, or None if it's over the limits."""

        if self.maxsize and len(data) > self.maxsize:
            self.skipped += 1
            return None
        sha256 = hashlib.sha256(data).hexdigest()
        if sha256 not in self.files:
            if self.limit and len(self.files) >= self.limit:
                self.skipped += 1
                return None
            with open(os.path.join(self.dirn, sha256), "wb") as fd:
                fd.write(data)
            self.files[sha256] = len(data)
        return sha256

    def addPath(self, path: str, sha256: str, size: int) -> str | None:
        """Store a file that's already on disk (ex. Suricata extracted it) by moving it.

        Returns its SHA-256, or None if it's over the limits.
        """

        if self.maxsize and size > self.maxsize:
            self.skipped += 1
            return None
        if sha256 not in self.files:
            if self.limit and len(self.files) >= self.limit:
                self.skipped += 1
                return None
            shutil.move(path, os.path.join(self.dirn, sha256))
            self.files[sha256] = size
        return sha256

    def path(self, sha256: str) -> str:
        """The path a stored file was written to."""

        return os.path.join(self.dirn, sha256)


def _addUniq(items: list, valu: Any) -> None:
    if valu is not None and valu not in items:
        items.append(valu)


class Enricher:
    """Collects the details tshark, Suricata, and the rule engines found in one flow.

    Parameters
    ----------
    files : FileStore | None
        Where to write the files found in the flow, None to not extract them.
    unsaved : bool
        Count the files that would have been extracted when ``files`` is None (they couldn't be
        saved, ex. the service has no Axon), see ``Enricher.unsaved``.
    rules : dict | None
        The loaded rules of each engine (``snort``, ``suricata``), ``gid:sid`` -> rule info,
        to turn alerts into hits (see ``pcapsvc.eve.hits``).
    counts : dict | None
        Updated with the alerts that aren't for a loaded rule (see ``pcapsvc.eve.hits``).
    filestore : str | None
        The directory of the files Suricata extracted.
    """

    def __init__(self, files: FileStore | None, unsaved: bool = False,
                 rules: dict | None = None, counts: dict | None = None,
                 filestore: str | None = None) -> None:
        self.files = files
        self.countunsaved = unsaved
        self.unsaved = 0
        self.rules = rules or {}
        self.counts = counts if counts is not None else {}
        self.filestore = filestore
        self.eve: list[dict] = []
        self.alerts: list[tuple[str, dict]] = []
        self.extra: dict[str, Any] = {}
        self.sides = {True: self._side(), False: self._side()}
        self.tls = {"sni": [], "ja3": [], "ja3s": [], "ja4": []}
        self.http = {"hosts": [], "requests": []}
        self.ftp: dict[bool, dict] = {}
        self.responses = 0
        # HTTP/2 streams, by (sent by the client, stream ID), and their requests by stream ID.
        self.h2: dict[tuple[bool, str], dict] = {}
        self.h2reqs: dict[str, dict] = {}

    @staticmethod
    def _side() -> dict:
        return {"ssl:cert": None, "ssl:certs": [], "ssh:key": None, "rdp:hostname": None,
                "rdp:keyboard:layout": None, "softnames": [], "cpes": [], "txfiles": []}

    @staticmethod
    def _uniq(items: list, valu: Any) -> None:
        _addUniq(items, valu)

    def _soft(self, side: dict, valu: str | None) -> None:
        name = softname(valu) if valu else None
        if not name:
            return
        names = side["softnames"]
        # Engines report the same software differently, ex. Suricata's "openssh_9.6p1" and
        # tshark's "openssh_9.6p1 ubuntu-3ubuntu13.20", keep the most complete name.
        if any(other.startswith(name) for other in names):
            return
        names[:] = [other for other in names if not name.startswith(other)]
        names.append(name)
        for cpe in softCpes(name):
            _addUniq(side["cpes"], cpe)

    def _cert(self, side: dict, der: bytes) -> None:
        """Add a certificate the side sent, the first one is its leaf."""

        cert = p_x509.parseCert(der)
        if any(c["sha256"] == cert["sha256"] for c in side["ssl:certs"]):
            return
        if self.files is not None:
            self.files.add(der)
        side["ssl:certs"].append(cert)
        if side["ssl:cert"] is None:
            side["ssl:cert"] = cert

    def _addEntry(self, side: dict, entry: dict) -> None:
        for other in side["txfiles"]:
            if (other["sha256"], other["name"]) == (entry["sha256"], entry["name"]):
                return
        side["txfiles"].append(entry)

    def _file(self, side: dict, data: bytes, proto: str, name: str | None = None,
              mime: str | None = None, text: str | None = None, complete: bool = True) -> None:
        if not data:
            return
        if self.files is None:
            if self.countunsaved:
                self.unsaved += 1
            return
        sha256 = self.files.add(data)
        if sha256 is None:
            return
        self._addEntry(side, {"sha256": sha256, "size": len(data), "name": name, "mime": mime,
                              "text": text, "proto": proto, "complete": complete})

    def _storedFile(self, side: dict, path: str, sha256: str, size: int, proto: str,
                    name: str | None = None, mime: str | None = None,
                    complete: bool = True) -> None:
        """Add a file that's already on disk (Suricata extracted it)."""

        if self.files.addPath(path, sha256, size) is None:
            return
        self._addEntry(side, {"sha256": sha256, "size": size, "name": name, "mime": mime,
                              "text": None, "proto": proto, "complete": complete})

    def add(self, client: bool, rec: dict) -> None:
        """Add the fields of a frame, sent by the client if ``client`` (else the server)."""

        side = self.sides[client]
        self.eve.extend(rec.get("_eve", ()))
        self.alerts.extend(rec.get("_alerts", ()))

        certs = rec.get("tls.handshake.certificate")
        if certs and not side["ssl:certs"]:
            for hexder in certs:
                self._cert(side, bytes.fromhex(hexder.replace(":", "")))

        for field, key in (("tls.handshake.extensions_server_name", "sni"),
                           ("tls.handshake.ja3", "ja3"), ("tls.handshake.ja3s", "ja3s"),
                           ("tls.handshake.ja4", "ja4")):
            for valu in rec.get(field, ()):
                _addUniq(self.tls[key], valu.lower() if key == "sni" else valu)

        for banner in rec.get("ssh.protocol", ()):
            self._soft(side, sshSoftware(banner))
        if side["ssh:key"] is None and (blob := sshKeyBlob(rec)) is not None:
            side["ssh:key"] = sshKey(blob, rec["ssh.host_key.type"][0])

        if name := rec.get("rdp.client.name"):
            side["rdp:hostname"] = name[0].strip().lower() or None
        if layout := rec.get("rdp.keyboardLayout"):
            side["rdp:keyboard:layout"] = keyboardLayout(int(layout[0]))

        for field in ("http.user_agent", "http.server", "http2.headers.user_agent",
                      "http2.headers.server", "sip.User-Agent", "sip.Server", "imf.user_agent",
                      "imf.ext.mailer", "gquic.tag.uaid"):
            for valu in rec.get(field, ()):
                self._soft(side, valu)

        self._addHttp(side, rec)
        self._addHttp2(client, rec)
        self._addFtp(client, rec)
        if raw := rec.get("imf.raw"):
            self._addEmail(side, bytes.fromhex(raw[0]))

    def _addHttp(self, side: dict, rec: dict) -> None:
        for host in rec.get("http.host", ()):
            _addUniq(self.http["hosts"], host.lower())
        methods, uris = rec.get("http.request.method", ()), rec.get("http.request.uri", ())
        for method, uri in zip(methods, uris):
            self.http["requests"].append({"method": method, "uri": uri})

        body = rec.get("http.file_data")
        if not body:
            if "http.response_for.uri" in rec:
                self.responses += 1
            return
        data = bytes.fromhex(body[0].replace(":", ""))
        if methods:
            name = uriName(uris[0] if uris else None)
        else:
            # Responses come in the order of their requests. Only a GET's response body is
            # the file the URI names, ex. a POST's response isn't the file that was posted.
            reqs = self.http["requests"]
            method = reqs[self.responses]["method"] if self.responses < len(reqs) else None
            self.responses += 1
            name = None
            if method in (None, "GET"):
                name = uriName((rec.get("http.response_for.uri") or [None])[0])

        self._httpBody(side, data, (rec.get("http.content_type") or [None])[0], name, "http")

    def _httpBody(self, side: dict, data: bytes, ctype: str | None, name: str | None,
                  proto: str) -> None:
        """Extract an HTTP body, or the files in it if it's a multipart upload."""

        mime = mimeType(ctype)
        if mime and mime.startswith("multipart/"):
            parts = self._mimeFiles(b"Content-Type: " + ctype.encode() + b"\r\n\r\n" + data)
            if parts:
                for part, pname, pmime in parts:
                    self._file(side, part, proto, name=pname, mime=pmime)
                return
        self._file(side, data, proto, name=name, mime=mime)

    def _addHttp2(self, client: bool, rec: dict) -> None:
        """Collect HTTP/2 requests and the DATA frames of each stream.

        A packet can hold several HTTP/2 frames. ``http2.type`` and ``http2.streamid`` have
        one value per frame, the header and data fields only one per frame that has them, so
        they're matched to streams through the frame types (1 is HEADERS, 0 is DATA).
        """

        for host in rec.get("http2.headers.authority", ()):
            _addUniq(self.http["hosts"], host.lower())

        types, sids = rec.get("http2.type", ()), rec.get("http2.streamid", ())
        if not types or len(types) != len(sids):
            return
        headers = [sid for ftype, sid in zip(types, sids) if ftype == "1"]
        datas = [sid for ftype, sid in zip(types, sids) if ftype == "0"]

        methods = rec.get("http2.headers.method", ())
        paths = rec.get("http2.headers.path", ())
        if methods and len(methods) == len(paths) == len(headers):
            for sid, method, path in zip(headers, methods, paths):
                self.h2reqs[sid] = {"method": method, "uri": path}
                self.http["requests"].append({"method": method, "uri": path})

        ctypes = rec.get("http2.headers.content_type", ())
        if ctypes and len(ctypes) == len(headers):
            for sid, ctype in zip(headers, ctypes):
                self._h2stream(client, sid)["ctype"] = ctype

        payloads = rec.get("http2.data.data", ())
        if len(payloads) == len(datas):
            for sid, data in zip(datas, payloads):
                self._h2stream(client, sid)["data"] += bytes.fromhex(data.replace(":", ""))
        if (body := rec.get("http2.body.reassembled.data")) and datas:
            # The complete body of the stream whose DATA frame ended it.
            self._h2stream(client, datas[-1])["body"] = bytes.fromhex(body[0].replace(":", ""))

    def _h2stream(self, client: bool, sid: str) -> dict:
        return self.h2.setdefault((client, sid), {"data": bytearray(), "body": None,
                                                  "ctype": None})

    def _finishHttp2(self) -> None:
        for (client, sid), stream in self.h2.items():
            data = stream["body"] if stream["body"] is not None else bytes(stream["data"])
            if not data:
                continue
            req = self.h2reqs.get(sid, {})
            name = None
            # Only a GET's response body is the file its path names (see _addHttp).
            if client or req.get("method") in (None, "GET"):
                name = uriName(req.get("uri"))
            self._httpBody(self.sides[client], data, stream["ctype"], name, "http2")

    def _addFtp(self, client: bool, rec: dict) -> None:
        cmd = rec.get("ftp-data.command")
        payload = rec.get("tcp.payload")
        if not cmd or not payload:
            return
        verb, _, arg = cmd[0].partition(" ")
        if verb.upper() not in FTP_FILE_CMDS:
            return
        xfer = self.ftp.setdefault(client, {"name": posixpath.basename(arg.strip()) or None,
                                            "segs": {}})
        seq = int(rec.get("tcp.seq", ["0"])[0])
        xfer["segs"].setdefault(seq, bytes.fromhex(payload[0].replace(":", "")))

    def _addEmail(self, side: dict, raw: bytes) -> None:
        msg = email.message_from_bytes(raw, policy=email.policy.compat32)
        subject = msg.get("Subject")
        self._file(side, raw, "imf", mime="message/rfc822",
                   text=str(subject) if subject else None)
        for part, name, mime in self._mimeFiles(raw):
            self._file(side, part, "imf", name=name, mime=mime)

    @staticmethod
    def _mimeFiles(raw: bytes) -> list[tuple[bytes, str, str]]:
        """The (bytes, file name, mime type) of each named part (attachment) of a MIME message."""

        msg = email.message_from_bytes(raw, policy=email.policy.compat32)
        files = []
        for part in msg.walk():
            if part.is_multipart():
                continue
            name = part.get_filename()
            data = part.get_payload(decode=True)
            if name and data:
                files.append((data, posixpath.basename(name), part.get_content_type()))
        return files

    def _finishFtp(self) -> None:
        for client, xfer in self.ftp.items():
            segs = xfer["segs"]
            base = min(segs)
            data = bytearray()
            complete = True
            for seq in sorted(segs):
                offs, seg = seq - base, segs[seq]
                if offs < len(data):
                    seg = seg[len(data) - offs:]  # Retransmitted (overlapping) bytes.
                elif offs > len(data):
                    complete = False  # Bytes the capture missed.
                data += seg
            self._file(self.sides[client], bytes(data), "ftp", name=xfer["name"],
                       complete=complete)

    def apply(self, flow: dict) -> dict:
        """Add the collected details to a flow dict (see ``pcapsvc.flows.Flow.asdict``)."""

        self._finishFtp()
        self._finishHttp2()
        if self.eve:
            p_eve.applyEve(self, flow, self.eve, self.filestore)
        for client, key in ((True, "src"), (False, "dst")):
            flow[key].update(self.sides[client])
        flow["tls"] = self.tls if any(self.tls.values()) else None
        flow["http"] = self.http if any(self.http.values()) else None
        for key in ("quic", "smb", "krb5", "sip", "smtp", "ftp", "anomalies", "app_proto"):
            flow[key] = self.extra.get(key) or None
        flow["dns"] = p_eve.dnsQueries(self.extra.get("dns"))
        flow["hits"] = p_eve.hits(self.alerts, self.rules, self.counts)
        return flow


def emptySide() -> dict:
    """The details of a flow side tshark found nothing for."""

    return Enricher._side()
