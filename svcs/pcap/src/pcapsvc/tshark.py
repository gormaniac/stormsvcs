"""Run tshark over a capture file to pull out application layer details for its flows.

tshark is optional. ``Tshark.frames`` runs it once (twice if the capture has email) and
returns the fields it found, keyed by frame number. Frame numbers are the order packets appear
in the capture file, the same numbers ``pcapsvc.flows`` gives packets, which is how the details
are matched to flows (see ``pcapsvc.enrich``).

Only the fields the installed tshark supports are requested, so older versions still work, just
with fewer details (ex. ``tls.handshake.ja4`` needs Wireshark 4.2).
"""


import asyncio
import json
import os
import re
import shutil
from collections.abc import Iterable


FIELDS = (
    # TLS (certificates are only in cleartext before TLS 1.3).
    "tls.handshake.certificate",
    "tls.handshake.extensions_server_name",
    "tls.handshake.ja3",
    "tls.handshake.ja3s",
    "tls.handshake.ja4",
    # SSH.
    "ssh.protocol",
    "ssh.host_key.length",
    "ssh.host_key.type",
    "ssh.host_key.data",
    "ssh.host_key.rsa.e",
    "ssh.host_key.rsa.n",
    "ssh.host_key.dsa.p",
    "ssh.host_key.dsa.q",
    "ssh.host_key.dsa.g",
    "ssh.host_key.dsa.y",
    "ssh.host_key.ecdsa.id",
    "ssh.host_key.ecdsa.q",
    "ssh.host_key.eddsa.key",
    # RDP (only in cleartext with standard RDP security, not TLS/CredSSP).
    "rdp.client.name",
    "rdp.keyboardLayout",
    # HTTP.
    "http.request.method",
    "http.request.uri",
    "http.response_for.uri",
    "http.host",
    "http.user_agent",
    "http.server",
    "http.content_type",
    "http.file_data",
    # HTTP/2 (only readable with TLS keys, see Tshark.frames).
    "http2.streamid",
    "http2.type",
    "http2.headers.method",
    "http2.headers.path",
    "http2.headers.authority",
    "http2.headers.status",
    "http2.headers.user_agent",
    "http2.headers.server",
    "http2.headers.content_type",
    "http2.data.data",
    "http2.body.reassembled.data",
    # FTP data connections.
    "ftp-data.command",
    "tcp.seq",
    "tcp.payload",
    # Software names from other protocols.
    "sip.User-Agent",
    "sip.Server",
    "imf",
    "imf.user_agent",
    "imf.ext.mailer",
    "imf.subject",
    "gquic.tag.uaid",
)
"""The tshark fields extracted from every capture (the ones the installed tshark supports)."""

FILTER = (
    "tls.handshake.certificate", "tls.handshake.extensions_server_name", "tls.handshake.ja3",
    "tls.handshake.ja3s", "tls.handshake.ja4", "ssh.protocol", "ssh.host_key.type",
    "rdp.client.name", "rdp.keyboardLayout", "http.request.method", "http.response_for.uri",
    "http2.headers.method", "http2.headers.status", "http2.data.data",
    "ftp-data.command", "sip.User-Agent", "sip.Server", "imf", "gquic.tag.uaid",
)
"""Fields (or protocols) that make a frame worth returning, the display filter ORs them."""


DECODE_AS = re.compile(
    r"^[a-z][a-z0-9_.-]{0,63}==[0-9]{1,10}(-[0-9]{1,10})?,[a-z][a-z0-9_.-]{0,63}$"
)
"""A valid "Decode As" rule (tshark's -d).

Ex. ``tcp.port==8443,tls`` or ``udp.port==5000-5010,rtp``.

Rules are the only tshark option Storm users can set per run, so they're strictly validated.
"""


def checkDecodeAs(rules) -> list[str]:
    """Validate "Decode As" rules (see ``DECODE_AS``), returning them without duplicates.

    Raises
    ------
    TsharkError
        If a rule isn't valid.
    """

    if rules is None:
        return []
    if isinstance(rules, str) or not isinstance(rules, (list, tuple)):
        raise TsharkError(f"Decode As rules must be a list, not {rules!r}")
    valid = []
    for rule in rules:
        rule = str(rule).strip().lower()
        if not DECODE_AS.match(rule):
            raise TsharkError(
                f"Invalid Decode As rule {rule!r}, expected <selector>==<value>[-<value>],"
                "<protocol>, ex. tcp.port==8443,tls"
            )
        if rule not in valid:
            valid.append(rule)
    return valid


class TsharkError(Exception):
    """Raised when tshark can't be run or fails."""

    def __init__(self, mesg: str) -> None:
        super().__init__(mesg)
        self.mesg = mesg


def ekName(field: str) -> str:
    """The name tshark's EK output uses for a field."""

    return field.replace(".", "_")


class Tshark:
    """A tshark binary and the fields it supports.

    Parameters
    ----------
    path : str
        The tshark binary, a path or a name on the PATH.
    args : Iterable[str]
        Extra tshark arguments, ex. ``("-d", "tcp.port==2222,ssh")`` to decode SSH on port 2222.
    timeout : float
        Seconds a tshark run may take before it's killed, 0 for no limit.
    """

    def __init__(self, path: str = "tshark", args: Iterable[str] = (), timeout: float = 0) -> None:
        self.path = shutil.which(path) or (path if os.path.isfile(path) else None)
        self.args = list(args)
        self.timeout = timeout or None
        self.supported: set[str] | None = None
        self.version: str | None = None

    @property
    def available(self) -> bool:
        """True if the tshark binary exists."""

        return self.path is not None

    async def _run(self, *args: str) -> tuple[int, bytes, bytes]:
        """Run tshark to completion and return (exit code, stdout, stderr)."""

        if self.path is None:
            raise TsharkError("tshark is not installed")
        proc = await asyncio.create_subprocess_exec(
            self.path, *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise TsharkError(f"tshark took longer than {self.timeout} seconds") from None
        return proc.returncode, out, err

    async def load(self) -> None:
        """Find out the tshark version and which of ``FIELDS`` it supports (once)."""

        if self.supported is not None:
            return
        code, out, err = await self._run("-v")
        if code != 0:
            raise TsharkError(f"tshark -v failed: {err.decode(errors='replace').strip()}")
        self.version = out.decode(errors="replace").splitlines()[0].strip()

        code, out, err = await self._run("-G", "fields")
        if code != 0:
            raise TsharkError(f"tshark -G fields failed: {err.decode(errors='replace').strip()}")
        known = set()
        for line in out.decode(errors="replace").splitlines():
            parts = line.split("\t")
            if len(parts) > 2 and parts[0] in ("F", "P"):
                known.add(parts[2])
        self.supported = known

    def _fields(self) -> list[str]:
        return [f for f in FIELDS if f in self.supported]

    def _filter(self) -> str:
        return " or ".join(f for f in FILTER if f in self.supported)

    def _args(self, keylog: str | None, decode: list[str]) -> list[str]:
        """The tshark arguments for one run: the configured ones, the key log, and decode rules."""

        args = list(self.args)
        if keylog:
            args.extend(("-o", f"tls.keylog_file:{keylog}"))
        for rule in decode:
            args.extend(("-d", rule))
        return args

    async def frames(self, path: str, keylog: str | None = None,
                     decode: list[str] = ()) -> tuple[dict[int, dict], dict]:
        """Run tshark over a capture and return ({frame number: fields}, info).

        Fields are keyed by their tshark name (ex. ``http.user_agent``) and are always lists
        of strings (bytes fields are hex). Frames whose email (IMF) was found also have an
        ``imf.raw`` field with the message's bytes as hex.

        ``info`` has the tshark ``version`` and, when tshark exits with an error after reading
        part of the capture (ex. it's truncated), its ``error``.

        Parameters
        ----------
        path : str
            The capture file.
        keylog : str | None
            An NSS key log file (SSLKEYLOGFILE) with the TLS secrets to decrypt TLS 1.2 and 1.3
            with, which also makes HTTP and HTTP/2 inside TLS readable. Secrets embedded in a
            pcapng file (Decryption Secrets Blocks) are always used.
        decode : list[str]
            "Decode As" rules (see ``checkDecodeAs``), ex. ``["tcp.port==8443,tls"]``.
        """

        await self.load()
        fields = self._fields()
        extra = self._args(keylog, checkDecodeAs(list(decode)))
        args = ["-n", "-r", path, *extra, "-Y", self._filter(), "-T", "ek",
                "-e", "frame.number"]
        for field in fields:
            args.extend(("-e", field))

        code, out, err = await self._run(*args)
        records = {}
        names = {ekName(f): f for f in fields}
        for line in out.splitlines():
            if not line.startswith(b'{"timestamp"'):
                continue
            layers = json.loads(line).get("layers", {})
            num = layers.pop("frame_number", None)
            if not num:
                continue
            records[int(num[0])] = {names.get(k, k): v for k, v in layers.items()}

        info = {"version": self.version, "error": None}
        if code != 0:
            info["error"] = err.decode(errors="replace").strip() or f"tshark exited {code}"
            if not records:
                raise TsharkError(f"tshark failed: {info['error']}")

        if any("imf" in rec for rec in records.values()):
            for num, raw in (await self._emails(path, extra)).items():
                records.setdefault(num, {})["imf.raw"] = [raw]

        return records, info

    async def _emails(self, path: str, extra: list[str]) -> dict[int, str]:
        """The raw bytes (hex) of every email (IMF) in a capture, keyed by frame number."""

        code, out, err = await self._run("-n", "-r", path, *extra, "-Y", "imf",
                                         "-T", "json", "-x", "-J", "frame imf")
        try:
            packets = json.loads(out or b"[]")
        except ValueError:
            return {}
        emails = {}
        for pkt in packets:
            layers = pkt.get("_source", {}).get("layers", {})
            raw = layers.get("imf_raw")
            num = layers.get("frame", {}).get("frame.number")
            if raw and num:
                emails[int(num)] = raw[0] if isinstance(raw[0], str) else raw[0][0]
        return emails
