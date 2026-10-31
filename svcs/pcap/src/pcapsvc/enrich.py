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
import struct
import urllib.parse
from typing import Any

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

    def path(self, sha256: str) -> str:
        """The path a stored file was written to."""

        return os.path.join(self.dirn, sha256)


def _addUniq(items: list, valu: Any) -> None:
    if valu is not None and valu not in items:
        items.append(valu)


class Enricher:
    """Collects the details tshark found in one flow's frames."""

    def __init__(self, files: FileStore | None) -> None:
        self.files = files
        self.sides = {True: self._side(), False: self._side()}
        self.tls = {"sni": [], "ja3": [], "ja3s": [], "ja4": []}
        self.http = {"hosts": [], "requests": []}
        self.ftp: dict[bool, dict] = {}
        self.responses = 0

    @staticmethod
    def _side() -> dict:
        return {"ssl:cert": None, "ssl:certs": [], "ssh:key": None, "rdp:hostname": None,
                "rdp:keyboard:layout": None, "softnames": [], "cpes": [], "txfiles": []}

    def _soft(self, side: dict, valu: str | None) -> None:
        name = softname(valu) if valu else None
        if name:
            _addUniq(side["softnames"], name)
            for cpe in softCpes(name):
                _addUniq(side["cpes"], cpe)

    def _file(self, side: dict, data: bytes, proto: str, name: str | None = None,
              mime: str | None = None, text: str | None = None, complete: bool = True) -> None:
        if self.files is None or not data:
            return
        sha256 = self.files.add(data)
        if sha256 is None:
            return
        entry = {"sha256": sha256, "size": len(data), "name": name, "mime": mime, "text": text,
                 "proto": proto, "complete": complete}
        if entry not in side["txfiles"]:
            side["txfiles"].append(entry)

    def add(self, client: bool, rec: dict) -> None:
        """Add the fields of a frame, sent by the client if ``client`` (else the server)."""

        side = self.sides[client]

        certs = rec.get("tls.handshake.certificate")
        if certs and not side["ssl:certs"]:
            for hexder in certs:
                der = bytes.fromhex(hexder.replace(":", ""))
                cert = p_x509.parseCert(der)
                if self.files is not None:
                    self.files.add(der)
                side["ssl:certs"].append(cert)
            side["ssl:cert"] = side["ssl:certs"][0]

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

        for field in ("http.user_agent", "http.server", "sip.User-Agent", "sip.Server",
                      "imf.user_agent", "imf.ext.mailer", "gquic.tag.uaid"):
            for valu in rec.get(field, ()):
                self._soft(side, valu)

        self._addHttp(side, rec)
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
        mime = mimeType((rec.get("http.content_type") or [None])[0])
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

        if mime and mime.startswith("multipart/"):
            ctype = rec["http.content_type"][0]
            parts = self._mimeFiles(b"Content-Type: " + ctype.encode() + b"\r\n\r\n" + data)
            if parts:
                for part, pname, pmime in parts:
                    self._file(side, part, "http", name=pname, mime=pmime)
                return
        self._file(side, data, "http", name=name, mime=mime)

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
        for client, key in ((True, "src"), (False, "dst")):
            flow[key].update(self.sides[client])
        flow["tls"] = self.tls if any(self.tls.values()) else None
        flow["http"] = self.http if any(self.http.values()) else None
        return flow


def emptySide() -> dict:
    """The details of a flow side tshark found nothing for."""

    return Enricher._side()
