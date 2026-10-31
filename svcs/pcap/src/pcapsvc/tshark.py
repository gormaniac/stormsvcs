"""Run tshark over a capture file to pull out application layer details for its flows.

tshark is optional. ``Tshark.frames`` runs it once (twice if the capture has email) and
returns the fields it found, keyed by frame number. Frame numbers are the order packets appear
in the capture file, the same numbers ``pcapsvc.flows`` gives packets, which is how the details
are matched to flows (see ``pcapsvc.enrich``).

Only the fields the installed tshark supports are requested, so older versions still work, just
with fewer details (ex. ``tls.handshake.ja4`` needs Wireshark 4.2).
"""


import contextlib
import json
import os
import re
import shutil
import tempfile
from collections.abc import Iterable, Iterator

from . import sandbox as p_sandbox

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
    # The URI a response is for: tshark < 4.6 has http.response_for.uri, newer only has the
    # request's frame number (see _responseUris).
    "http.response_for.uri",
    "http.response",
    "http.request_in",
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
    "rdp.client.name", "rdp.keyboardLayout", "http.request.method", "http.response",
    "http2.headers.method", "http2.headers.status", "http2.data.data",
    "ftp-data.command", "sip.User-Agent", "sip.Server", "imf", "gquic.tag.uaid",
)
"""Fields (or protocols) that make a frame worth returning, the display filter ORs them."""

GAP_PREFIXES = ("ssh.", "sip.", "imf")
"""The fields tshark is still needed for when Suricata ran (``Tshark.frames(gaps=True)``):
SSH host keys and full banners, SIP User-Agent/Server, and whole emails."""


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


PROTOCOLS = (
    "frame", "eth", "ethertype", "vlan", "sll", "ppp", "pppoes", "null", "loop", "gre",
    "ip", "ipv6", "ipv6.hopopts", "ipv6.routing", "ipv6.fraghdr", "ipv6.dstopts", "icmp",
    "icmpv6", "tcp", "udp", "data", "tls", "x509af", "x509ce", "x509if", "x509sat", "pkcs-1",
    "pkix1explicit", "pkix1implicit", "ber", "ssh", "tpkt", "cotp", "t124", "t125", "rdp",
    "http", "http2", "data-text-lines", "media", "mime_multipart", "urlencoded-form", "ftp",
    "ftp-data", "smtp", "imf", "sip", "sdp", "gquic", "quic",
)
"""The only dissectors tshark runs (``--only-protocols``), what ``FIELDS`` needs and the link
layers and tunnels under them. Every other dissector is off, less code parsing untrusted input.
Protocols named by Decode As rules are enabled too."""


class Tshark:
    """A tshark binary and the fields it supports. tshark always runs in a ``Sandbox``.

    Parameters
    ----------
    path : str
        The tshark binary, a path or a name on the PATH.
    args : Iterable[str]
        Extra tshark arguments, ex. ``("-d", "tcp.port==2222,ssh")`` to decode SSH on port 2222.
    timeout : float
        Seconds a tshark run may take before it's killed, 0 for no limit.
    sandbox : Sandbox | None
        The sandbox tshark runs in, by default a best-effort one.
    protocols : Iterable[str] | None
        The dissectors to run (see ``PROTOCOLS``), None to run every dissector.
    tmpdir : str | None
        Where each run's scratch directory (tshark's config dir and output) is made.
    """

    def __init__(self, path: str = "tshark", args: Iterable[str] = (), timeout: float = 0,
                 sandbox: p_sandbox.Sandbox | None = None,
                 protocols: Iterable[str] | None = PROTOCOLS, tmpdir: str | None = None) -> None:
        self.path = shutil.which(path) or (path if os.path.isfile(path) else None)
        self.args = list(args)
        self.timeout = timeout or None
        self.sandbox = sandbox or p_sandbox.Sandbox()
        self.protocols = list(protocols) if protocols is not None else None
        self.tmpdir = tmpdir
        self.supported: set[str] | None = None
        self.known: set[str] = set()
        self.onlyprotos = False
        self.version: str | None = None

    @property
    def available(self) -> bool:
        """True if the tshark binary exists."""

        return self.path is not None

    @contextlib.contextmanager
    def _workdir(self) -> Iterator[str]:
        """A scratch directory for one run, owned by the sandbox's user."""

        if self.tmpdir:
            os.makedirs(self.tmpdir, exist_ok=True)
        path = tempfile.mkdtemp(prefix="tshark-", dir=self.tmpdir)
        try:
            os.makedirs(os.path.join(path, "config"))
            self.sandbox.prepare(path)
            yield path
        finally:
            shutil.rmtree(path, ignore_errors=True)

    async def _run(self, args: list[str], workdir: str, read: list[str] = (),
                   stdout: str | None = None) -> tuple[int, bytes, bytes]:
        """Run tshark in the sandbox, returning (exit code, stdout, stderr)."""

        if self.path is None:
            raise TsharkError("tshark is not installed")
        prefix = os.path.dirname(os.path.dirname(os.path.realpath(self.path)))
        env = {
            "PATH": os.path.dirname(os.path.realpath(self.path)) + ":/usr/bin:/bin",
            "HOME": workdir,
            "TMPDIR": workdir,
            "WIRESHARK_CONFIG_DIR": os.path.join(workdir, "config"),
            "XDG_CONFIG_HOME": os.path.join(workdir, "config"),
            "LANG": "C.UTF-8",
        }
        try:
            res = await self.sandbox.run(
                [self.path, *args], read=[*read], write=[workdir], execs=[prefix], env=env,
                cwd=workdir, timeout=self.timeout, maxoutput=64 * 1024 * 1024, stdout=stdout,
            )
        except p_sandbox.SandboxError as err:
            raise TsharkError(err.mesg) from None
        return res.code, res.stdout, res.stderr

    async def load(self) -> None:
        """Find out the tshark version and which of ``FIELDS`` it supports (once)."""

        if self.supported is not None:
            return
        with self._workdir() as work:
            code, out, err = await self._run(["-v"], work)
            if code != 0:
                raise TsharkError(f"tshark -v failed: {err.decode(errors='replace').strip()}")
            self.version = out.decode(errors="replace").splitlines()[0].strip()

            code, out, err = await self._run(["-h"], work)
            self.onlyprotos = b"--only-protocols" in out

            fpath = os.path.join(work, "fields.txt")
            code, _, err = await self._run(["-G", "fields"], work, stdout=fpath)
            if code != 0:
                raise TsharkError(f"tshark -G fields failed: {err.decode(errors='replace').strip()}")
            known, protos = set(), set()
            with open(fpath, encoding="utf-8", errors="replace") as fd:
                for line in fd:
                    parts = line.rstrip("\r\n").split("\t")
                    if len(parts) > 2 and parts[0] in ("F", "P"):
                        known.add(parts[2])
                        if parts[0] == "P":
                            protos.add(parts[2])
        self.supported = known
        self.known = protos

    def _fields(self, gaps: bool = False) -> list[str]:
        return [f for f in FIELDS if f in self.supported
                and (not gaps or f.startswith(GAP_PREFIXES))]

    def _filter(self, gaps: bool = False) -> str:
        return " or ".join(f for f in FILTER if f in self.supported
                           and (not gaps or f.startswith(GAP_PREFIXES)))

    def _args(self, keylog: str | None, decode: list[str]) -> list[str]:
        """The tshark arguments for one run: the configured ones, the dissectors to run, the
        key log, and decode rules."""

        args = list(self.args)
        if self.protocols is not None and self.onlyprotos:
            protos = list(self.protocols)
            for rule in decode:
                proto = rule.rsplit(",", 1)[1]
                if proto not in protos:
                    protos.append(proto)
            args.extend(("--only-protocols", ",".join(p for p in protos if p in self.known)))
        if keylog:
            args.extend(("-o", f"tls.keylog_file:{keylog}"))
        for rule in decode:
            args.extend(("-d", rule))
        return args

    async def frames(self, path: str, keylog: str | None = None,
                     decode: list[str] = (), gaps: bool = False) -> tuple[dict[int, dict], dict]:
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
        gaps : bool
            Only extract what Suricata can't (see ``GAP_PREFIXES``), when Suricata ran too.
            Ignored with a key log, only tshark can see inside the TLS it decrypts.
        """

        await self.load()
        gaps = gaps and not keylog
        path = os.path.abspath(path)
        keylog = os.path.abspath(keylog) if keylog else None
        fields = self._fields(gaps)
        extra = self._args(keylog, checkDecodeAs(list(decode)))
        args = ["-n", "-r", path, *extra, "-Y", self._filter(gaps), "-T", "ek",
                "-e", "frame.number"]
        for field in fields:
            args.extend(("-e", field))

        read = [path] + ([keylog] if keylog else [])
        records = {}
        names = {ekName(f): f for f in fields}
        with self._workdir() as work:
            opath = os.path.join(work, "frames.json")
            code, _, err = await self._run(args, work, read=read, stdout=opath)
            with open(opath, "rb") as fd:
                for line in fd:
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

            _responseUris(records)
            if any("imf" in rec for rec in records.values()):
                for num, raw in (await self._emails(path, extra, work, read)).items():
                    records.setdefault(num, {})["imf.raw"] = [raw]

        return records, info

    async def _emails(self, path: str, extra: list[str], work: str,
                      read: list[str]) -> dict[int, str]:
        """The raw bytes (hex) of every email (IMF) in a capture, keyed by frame number."""

        opath = os.path.join(work, "emails.json")
        await self._run(["-n", "-r", path, *extra, "-Y", "imf", "-T", "json", "-x",
                         "-J", "frame imf"], work, read=read, stdout=opath)
        try:
            with open(opath, "rb") as fd:
                packets = json.load(fd)
        except (OSError, ValueError):
            return {}
        emails = {}
        for pkt in packets:
            layers = pkt.get("_source", {}).get("layers", {})
            raw = layers.get("imf_raw")
            num = layers.get("frame", {}).get("frame.number")
            if raw and num:
                emails[int(num)] = raw[0] if isinstance(raw[0], str) else raw[0][0]
        return emails


def _responseUris(records: dict[int, dict]) -> None:
    """Give HTTP responses the URI of their request (``http.response_for.uri``), from the
    request's frame (``http.request_in``), for tshark versions that don't add it."""

    for rec in records.values():
        if "http.response_for.uri" in rec or not rec.get("http.request_in"):
            continue
        uris = []
        for num in rec["http.request_in"]:
            with contextlib.suppress(ValueError):
                uris.extend((records.get(int(num)) or {}).get("http.request.uri", ()))
        rec["http.response_for.uri"] = uris[:1]
