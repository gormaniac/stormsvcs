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
    "ftp-data.command", "sip.User-Agent", "sip.Server", "imf", "gquic.tag.uaid",
)
"""Fields (or protocols) that make a frame worth returning, the display filter ORs them."""


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

    async def frames(self, path: str) -> tuple[dict[int, dict], dict]:
        """Run tshark over a capture and return ({frame number: fields}, info).

        Fields are keyed by their tshark name (ex. ``http.user_agent``) and are always lists
        of strings (bytes fields are hex). Frames whose email (IMF) was found also have an
        ``imf.raw`` field with the message's bytes as hex.

        ``info`` has the tshark ``version`` and, when tshark exits with an error after reading
        part of the capture (ex. it's truncated), its ``error``.
        """

        await self.load()
        fields = self._fields()
        args = ["-n", "-r", path, *self.args, "-Y", self._filter(), "-T", "ek",
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
            for num, raw in (await self._emails(path)).items():
                records.setdefault(num, {})["imf.raw"] = [raw]

        return records, info

    async def _emails(self, path: str) -> dict[int, str]:
        """The raw bytes (hex) of every email (IMF) in a capture, keyed by frame number."""

        code, out, err = await self._run("-n", "-r", path, *self.args, "-Y", "imf",
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
