"""The slib.pcap service.

``PcapSvc`` analyzes capture files (pcap, pcapng, or either gzip compressed) and returns their
flows to Storm, which models them as ``inet:flow`` nodes:

1. **Flows (dpkt, always).** ``pcapsvc.flows`` reads every packet and builds the flows. Flows
   are always built the same way, the engines only add to them.
2. **Engines (optional, sandboxed, run concurrently).**

   - Suricata analyzes the protocols (TLS, HTTP, SSH, RDP, SMTP, FTP, DNS, QUIC, SMB, Kerberos,
     SIP), extracts the files sent, and matches the Suricata rules.
   - Snort 3 matches the Snort rules.
   - tshark fills the gaps Suricata has (SSH host keys, SIP headers, whole emails), decrypts
     TLS with key logs, and does everything when Suricata isn't available.

   Their output is matched to flows by frame number (``pcap_cnt``/``pkt_num``), or by Community
   ID and time, see ``pcapsvc.enrich`` and ``pcapsvc.eve``.
3. **Rules.** The Cortex is the source of truth for the rules, see ``pcapsvc.rulesvc``.

Captures are read from the Axon (``axon:url``) or streamed to the service by Storm. Files found
in the flows are uploaded to the Axon, when the service has one.
"""

import asyncio
import binascii
import contextlib
import gzip
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import tempfile
from collections.abc import AsyncIterator
from typing import Any

import aiohttp
import synapse.common as s_common
import synapse.exc as s_exc
import synapse.lib.cell as s_cell
import synapse.lib.coro as s_coro
import synapse.telepath as s_telepath
from stormlibpp.telepath import TelepathRetn

from . import communityid as p_communityid
from . import enrich as p_enrich
from . import eve as p_eve
from . import feeds as p_feeds
from . import flows as p_flows
from . import rules as p_rules
from . import rulesvc as p_rulesvc
from . import sandbox as p_sandbox
from . import snort as p_snort
from . import suricata as p_suricata
from . import tshark as p_tshark
from .api import PcapCellApi

logger = logging.getLogger(__name__)


SHA256RE = re.compile(r"^[0-9a-f]{64}$")

CHUNK = 1024 * 1024
"""The size of the chunks files are uploaded to the Axon in."""

UPLOAD_IDLE = 60 * 60 * 1000
"""Uploads (streamed by Storm) untouched for this long (ms) are removed."""

UPLOAD_KINDS = ("capture", "keylog")
"""The kinds of files Storm can stream to the service."""

PROTO_NUMS = {"tcp": 6, "udp": 17, "icmp": 1, "ipv6-icmp": 58, "sctp": 132, "gre": 47}
"""IP protocol numbers by the protocol names Snort and Suricata use in alerts."""


def normSha256(valu) -> str:
    """Normalize a SHA-256 (or a file:bytes ``sha256:<sha256>`` value) to lowercase hex.

    Raises
    ------
    PcapSvcError
        If it isn't a SHA-256.
    """

    sha256 = str(valu).strip().lower().removeprefix("sha256:")
    if not SHA256RE.match(sha256):
        raise PcapSvcError(f"Invalid SHA-256: {sha256}")
    return sha256


class PcapSvcError(Exception):
    """An error that is returned to Storm as a failed ``TelepathRetn``."""

    def __init__(self, mesg: str) -> None:
        super().__init__(mesg)
        self.mesg = mesg


def _gunzip(src: str, dst: str) -> None:
    """Decompress a gzip compressed capture (Snort and Suricata only read plain captures)."""

    with gzip.open(src, "rb") as ifd, open(dst, "wb") as ofd:
        shutil.copyfileobj(ifd, ofd, CHUNK)


def _isGzip(path: str) -> bool:
    with open(path, "rb") as fd:
        return fd.read(2) == b"\x1f\x8b"


def _remapNum(rec: dict, key: str, nums: list[int] | None) -> None:
    """Map a packet number in a part of a split capture to the capture's frame number."""

    if nums is None or not rec.get(key):
        return
    try:
        idx = int(rec[key]) - 1
    except (TypeError, ValueError):
        rec[key] = None
        return
    rec[key] = nums[idx] if 0 <= idx < len(nums) else None


def _mergeSuricata(runs: list[tuple[dict, list[int] | None]], outdir: str) -> dict[str, Any]:
    """Merge the Suricata runs over the parts of a split capture into one EVE file (with the
    capture's frame numbers) and one file store."""

    eve = os.path.join(outdir, "eve.json")
    store = os.path.join(outdir, "filestore")
    os.makedirs(store, exist_ok=True)
    warnings: list[str] = []
    with open(eve, "w", encoding="utf-8") as fd:
        for res, nums in runs:
            warnings.extend(res["warnings"])
            for ev in p_suricata.iterEve(res["eve"]):
                _remapNum(ev, "pcap_cnt", nums)
                fd.write(json.dumps(ev) + "\n")
            # Files are checked again when they're stored (see FileStore.addPath).
            src = res.get("filestore")
            if not src or not os.path.isdir(src):
                continue
            for sub in os.listdir(src):
                subdir = os.path.join(src, sub)
                if len(sub) != 2 or os.path.islink(subdir) or not os.path.isdir(subdir):
                    continue
                os.makedirs(os.path.join(store, sub), exist_ok=True)
                for name in os.listdir(subdir):
                    dst = os.path.join(store, sub, name)
                    if not os.path.lexists(dst):
                        os.rename(os.path.join(subdir, name), dst)
    return {"eve": eve, "filestore": store, "warnings": warnings}


def alertCommunityId(proto: str, src: str, sport: Any, dst: str, dport: Any) -> str | None:
    """The Community ID of an alert's packet, from its protocol, addresses, and ports."""

    ipproto = PROTO_NUMS.get(str(proto).lower())
    try:
        srcb, dstb = ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed
    except ValueError:
        return None
    if ipproto is None:
        return None
    if ipproto in (6, 17, 132):
        try:
            return p_communityid.communityId(ipproto, srcb, dstb, int(sport), int(dport))
        except (TypeError, ValueError):
            return None
    return p_communityid.communityId(ipproto, srcb, dstb)


class PcapSvc(p_rulesvc.RuleMixin, s_cell.Cell):
    """The Cell implementation for the slib.pcap service."""

    cellapi = PcapCellApi

    confdefs = {
        "axon:url": {
            "type": ["string", "null"],
            "default": None,
            "description": (
                "The Telepath URL of the Cortex's Axon. With it the service reads captures from "
                "the Axon itself and uploads every file it extracts from flows there. Without "
                "it Storm streams captures to the service, and extracted files aren't saved."
            ),
        },
        "pcap:timeout": {
            "type": "integer",
            "default": p_flows.DEFAULT_TIMEOUT,
            "minimum": 0,
            "description": (
                "The default seconds a flow can be idle before the next packet between the "
                "same endpoints starts a new flow, 0 to never time out flows."
            ),
        },
        "pcap:limit": {
            "type": "integer",
            "default": 100000,
            "minimum": 1,
            "description": "The max number of flows returned for one capture file.",
        },
        "pcap:handshake": {
            "type": "integer",
            "default": p_flows.DEFAULT_HANDSHAKE,
            "minimum": 0,
            "description": (
                "The default max number of characters kept from each side of a flow's first "
                "text payload (its :src:handshake/:dst:handshake), 0 to keep none."
            ),
        },
        "pcap:maxsize": {
            "type": "integer",
            "default": 1024 * 1024 * 1024,
            "minimum": 0,
            "description": "The max size, in bytes, of a capture file to read, 0 for no limit.",
        },
        "pcap:workers": {
            "type": "integer",
            "default": 2,
            "minimum": 1,
            "description": "The max number of captures analyzed at once.",
        },
        "pcap:uploads": {
            "type": "integer",
            "default": 16,
            "minimum": 1,
            "description": (
                "The max number of captures and key logs being streamed to the service at once "
                "(without an Axon), each up to its max size."
            ),
        },
        "pcap:files": {
            "type": "boolean",
            "default": True,
            "description": "Extract the files sent in flows (HTTP, FTP, SMB, email) by default.",
        },
        "pcap:files:maxsize": {
            "type": "integer",
            "default": 64 * 1024 * 1024,
            "minimum": 0,
            "description": "The largest file, in bytes, extracted from a flow, 0 for no limit.",
        },
        "pcap:files:limit": {
            "type": "integer",
            "default": 10000,
            "minimum": 0,
            "description": "The max number of files extracted from one capture, 0 for no limit.",
        },
        "pcap:feeds": {
            "type": "array",
            "items": {"type": "object"},
            "default": [dict(f) for f in p_feeds.DEFAULT_FEEDS],
            "description": (
                "The rule feeds the service starts with, each a {name, url, engine, enabled, "
                "exclude, desc}. Only read the first time the service starts, after that feeds "
                "are managed with slib.pcap.admin.feed."
            ),
        },
        "pcap:feeds:secrets": {
            "type": "object",
            "additionalProperties": {
                "type": "object",
                "properties": {
                    "value": {"type": "string"},
                    "hosts": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["value", "hosts"],
                "additionalProperties": False,
            },
            "default": {},
            "description": (
                "Secrets feed URLs reference as ${name}, each only sent to its hosts, ex. "
                '{"talos:oinkcode": {"value": "...", "hosts": ["www.snort.org"]}}. Only the '
                "service's operator can see them."
            ),
        },
        "pcap:feeds:interval": {
            "type": "number",
            "default": 24,
            "description": "Hours between feed downloads (a sync downloads a feed when it's due).",
        },
        "pcap:feeds:timeout": {
            "type": "number",
            "default": 300,
            "description": "Seconds before a feed download times out.",
        },
        "pcap:feeds:maxsize": {
            "type": "integer",
            "default": 268435456,
            "description": "The max size, in bytes, of a feed (and of the rules it unpacks to).",
        },
        "suricata:enabled": {
            "type": "boolean",
            "default": True,
            "description": "Use Suricata (when it's installed) for protocols and rules by default.",
        },
        "suricata:bin": {
            "type": "string",
            "default": "suricata",
            "description": "The Suricata binary, a path or a name on the PATH.",
        },
        "suricata:conf": {
            "type": ["string", "null"],
            "default": None,
            "description": (
                "The base suricata.yaml, the service's outputs and settings are applied over it. "
                "Defaults to the one installed with Suricata."
            ),
        },
        "suricata:vars": {
            "type": "object",
            "default": p_suricata.DEFAULT_VARS,
            "description": "Suricata address variables, ex. HOME_NET and EXTERNAL_NET.",
        },
        "suricata:set": {
            "type": "object",
            "default": {},
            "description": (
                "Overrides of Suricata's config, dotted keys like suricata --set, ex. "
                '{"stream.memcap": "2gb"} (operator only). They win over the service\'s '
                "settings, so they can break what the service needs (ex. the EVE outputs)."
            ),
        },
        "suricata:timeout": {
            "type": "number",
            "default": 900,
            "description": "Seconds before a Suricata run is killed.",
        },
        "snort:enabled": {
            "type": "boolean",
            "default": True,
            "description": "Use Snort (when it's installed) for Snort rules by default.",
        },
        "snort:bin": {
            "type": "string",
            "default": "snort",
            "description": "The Snort 3 binary, a path or a name on the PATH.",
        },
        "snort:snort2lua": {
            "type": "string",
            "default": "snort2lua",
            "description": "The snort2lua binary, converts Snort 2.x rules to Snort 3.",
        },
        "snort:conf": {
            "type": ["string", "null"],
            "default": None,
            "description": (
                "The base Snort config (snort.lua). Defaults to the snort.lua installed with "
                "Snort. Relative includes are found in the config's directory."
            ),
        },
        "snort:vars": {
            "type": "object",
            "default": p_snort.DEFAULT_VARS,
            "description": (
                "Snort variables to set in the base config, ex. HOME_NET and EXTERNAL_NET. Only "
                "variables the base config assigns can be set."
            ),
        },
        "snort:args": {
            "type": "array",
            "items": {"type": "string"},
            "default": [],
            "description": "Extra arguments for every Snort run (operator only).",
        },
        "snort:timeout": {
            "type": "number",
            "default": 900,
            "description": "Seconds before a Snort run (a rule build or a scan) is killed.",
        },
        "tshark:enabled": {
            "type": "boolean",
            "default": True,
            "description": "Use tshark (when it's installed) by default.",
        },
        "tshark:path": {
            "type": "string",
            "default": "tshark",
            "description": "The tshark binary, a path or a name on the PATH.",
        },
        "tshark:args": {
            "type": "array",
            "items": {"type": "string"},
            "default": [],
            "description": (
                'Extra tshark arguments for every run (operator only), ex. ["-d", '
                '"tcp.port==2222,ssh"]. Users set Decode As rules with --decode-as.'
            ),
        },
        "tshark:protocols": {
            "type": ["array", "null"],
            "items": {"type": "string"},
            "default": list(p_tshark.PROTOCOLS),
            "description": (
                "The only dissectors tshark runs (--only-protocols), null to run every "
                "dissector. Protocols named by Decode As rules are added to it."
            ),
        },
        "tshark:keylog:maxsize": {
            "type": "integer",
            "default": 16 * 1024 * 1024,
            "minimum": 0,
            "description": "The largest TLS key log, in bytes, read for a run, 0 for no limit.",
        },
        "tshark:timeout": {
            "type": "number",
            "default": 600,
            "minimum": 0,
            "description": "Seconds a tshark run may take before it's killed, 0 for no limit.",
        },
        "sandbox:mode": {
            "type": "string",
            "enum": list(p_sandbox.MODES),
            "default": "best-effort",
            "description": (
                "How engines (tshark, Suricata, Snort) are sandboxed: best-effort applies every "
                "layer the host supports, strict refuses to run an engine without all of them, "
                "off runs them directly."
            ),
        },
        "sandbox:user": {
            "type": ["string", "null"],
            "default": p_sandbox.DEFAULT_USER,
            "description": "The unprivileged user engines run as when the service runs as root.",
        },
        "sandbox:rlimits": {
            "type": "object",
            "default": p_sandbox.DEFAULT_RLIMITS,
            "description": (
                "Resource limits of an engine run: as (address space bytes), cpu (seconds), "
                "fsize (bytes per file), nofile, core. 0 is unlimited."
            ),
        },
        "sandbox:seccomp": {
            "type": "boolean",
            "default": True,
            "description": "Refuse engines IPv4, IPv6, and packet sockets with a seccomp filter.",
        },
    }

    async def __anit__(self, dirn, *args, **kwargs):
        await s_cell.Cell.__anit__(self, dirn, *args, **kwargs)
        self.axonurl = self.conf.get("axon:url")
        self.tmpdir = os.path.join(self.dirn, "tmp")
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        os.makedirs(self.tmpdir, exist_ok=True)

        self.sandbox = p_sandbox.Sandbox(
            mode=self.conf.get("sandbox:mode"),
            user=self.conf.get("sandbox:user"),
            rlimits=self.conf.get("sandbox:rlimits"),
            seccomp=self.conf.get("sandbox:seccomp"),
        )
        self.tshark = p_tshark.Tshark(
            path=self.conf.get("tshark:path"),
            args=self.conf.get("tshark:args"),
            timeout=self.conf.get("tshark:timeout"),
            sandbox=self.sandbox,
            protocols=self.conf.get("tshark:protocols"),
            tmpdir=self.tmpdir,
        )
        self.snort = p_snort.Snort(
            os.path.join(self.dirn, "snort"),
            binpath=self.conf.get("snort:bin"),
            s2lpath=self.conf.get("snort:snort2lua"),
            conf=self.conf.get("snort:conf"),
            snortvars=self.conf.get("snort:vars"),
            args=self.conf.get("snort:args"),
            timeout=self.conf.get("snort:timeout"),
            sandbox=self.sandbox,
        )
        self.suricata = p_suricata.Suricata(
            os.path.join(self.dirn, "suricata"),
            binpath=self.conf.get("suricata:bin"),
            conf=self.conf.get("suricata:conf"),
            addrvars=self.conf.get("suricata:vars"),
            timeout=self.conf.get("suricata:timeout"),
            sandbox=self.sandbox,
            overrides=self.conf.get("suricata:set"),
        )
        self.versions: dict[str, str | None] = {}
        self.uploads: dict[str, dict[str, Any]] = {}
        self.runsema = asyncio.Semaphore(self.conf.get("pcap:workers"))

        await self._initRules()
        # The engines run as the sandbox's user, which has to get to their files.
        self.sandbox.reach(self.tmpdir, self.rulesdir, self.snort.workdir, self.suricata.workdir)

        self.session = aiohttp.ClientSession(trust_env=True)
        self.onfini(self.session.close)
        self.schedCoro(self._pruneLoop())

    # ---- Status ----

    async def _version(self, name: str) -> str | None:
        if name in self.versions:
            return self.versions[name]
        vers = None
        try:
            if name == "tshark" and self.tshark.available:
                await self.tshark.load()
                vers = self.tshark.version
            elif name == "snort" and self.snort.available():
                vers = await self.snort.version()
            elif name == "suricata" and self.suricata.available():
                vers = await self.suricata.version()
        except (p_tshark.TsharkError, p_snort.SnortError, p_suricata.SuricataError) as err:
            logger.warning("Unable to get the %s version: %s", name, err.mesg)
            return None
        self.versions[name] = vers
        return vers

    async def status(self) -> dict[str, Any]:
        """The service's engines, sandbox, Axon, and rules."""

        engines = {}
        for name, avail, enabled in (
            ("suricata", self.suricata.available(), self.conf.get("suricata:enabled")),
            ("snort", self.snort.available(), self.conf.get("snort:enabled")),
            ("tshark", self.tshark.available, self.conf.get("tshark:enabled")),
        ):
            engines[name] = {
                "available": avail,
                "enabled": enabled,
                "version": await self._version(name) if avail else None,
            }
        return {
            "engines": engines,
            "sandbox": self.sandbox.probe(),
            "axon": bool(self.axonurl),
            "rules": await self.ruleStatus(),
        }

    async def hasAxon(self) -> bool:
        """Whether the service has an Axon (``axon:url``): it reads captures from it and saves
        extracted files to it."""

        return bool(self.axonurl)

    # ---- Uploads (when Storm streams files to the service) ----

    def _pruneUploads(self, idle: int = UPLOAD_IDLE) -> list[str]:
        cutoff = s_common.now() - idle
        stale = [iden for iden, up in self.uploads.items() if up["touched"] < cutoff]
        for iden in stale:
            self._dropUpload(iden)
        return stale

    async def _pruneLoop(self) -> None:
        while not await self.waitfini(timeout=600):
            self._pruneUploads()
            self._prunePushes()

    async def uploadStart(self, kind: str = "capture") -> str:
        """Start streaming a file (a ``capture`` or a ``keylog``) to the service. Returns its ID.

        Send the file with ``uploadChunk``, then pass the ID to ``flows``.
        """

        if kind not in UPLOAD_KINDS:
            raise PcapSvcError(
                f"Invalid upload kind {kind!r}, use one of: {', '.join(UPLOAD_KINDS)}"
            )
        self._pruneUploads()
        if len(self.uploads) >= self.conf.get("pcap:uploads"):
            raise PcapSvcError(
                f"The service already has {len(self.uploads)} uploads (pcap:uploads), "
                "try again once they're analyzed."
            )
        iden = s_common.guid()
        path = os.path.join(self.tmpdir, f"upload-{iden}")
        open(path, "wb").close()  # noqa: ASYNC230 - creates an empty file
        maxsize = self.conf.get("pcap:maxsize" if kind == "capture" else "tshark:keylog:maxsize")
        self.uploads[iden] = {
            "path": path,
            "kind": kind,
            "size": 0,
            "maxsize": maxsize,
            "sha256": hashlib.sha256(),
            "touched": s_common.now(),
        }
        return iden

    def _reqUpload(self, iden: str, kind: str | None = None) -> dict[str, Any]:
        upload = self.uploads.get(iden)
        if upload is None or (kind is not None and upload["kind"] != kind):
            raise PcapSvcError(f"Unknown upload: {iden}")
        upload["touched"] = s_common.now()
        return upload

    def _dropUpload(self, iden: str) -> None:
        upload = self.uploads.pop(iden, None)
        if upload is not None:
            with contextlib.suppress(OSError):
                os.remove(upload["path"])

    async def uploadChunk(self, iden: str, byts: bytes) -> int:
        """Append a chunk to an upload. Returns its size so far."""

        upload = self._reqUpload(iden)
        upload["size"] += len(byts)
        if upload["maxsize"] and upload["size"] > upload["maxsize"]:
            self._dropUpload(iden)
            raise PcapSvcError(
                f"The {upload['kind']} is larger than the service's max size of "
                f"{upload['maxsize']} bytes."
            )
        upload["sha256"].update(byts)
        with open(upload["path"], "ab") as fd:  # noqa: ASYNC230 - a small append per chunk
            fd.write(byts)
        return upload["size"]

    async def uploadCancel(self, iden: str) -> bool:
        """Remove an upload."""

        found = iden in self.uploads
        self._dropUpload(iden)
        return found

    def _takeUpload(self, iden: str, kind: str, dst: str, sha256: str | None = None) -> int:
        """Move an upload to ``dst`` (it's then gone). Returns its size."""

        upload = self._reqUpload(iden, kind)
        digest = upload["sha256"].hexdigest()
        if sha256 is not None and digest != sha256:
            self._dropUpload(iden)
            raise PcapSvcError(f"The uploaded {kind} has the SHA-256 {digest}, not {sha256}.")
        self.uploads.pop(iden)
        shutil.move(upload["path"], dst)
        return upload["size"]

    # ---- The Axon ----

    def _opts(
        self, timeout: int | None, limit: int | None, handshake: int | None
    ) -> tuple[int, int, int]:
        """The analysis options to use, filling in (and capping) them from the config."""

        maxlimit = self.conf.get("pcap:limit")
        timeout = self.conf.get("pcap:timeout") if timeout is None else timeout
        handshake = self.conf.get("pcap:handshake") if handshake is None else handshake
        limit = maxlimit if not limit else limit

        for name, valu in (("timeout", timeout), ("limit", limit), ("handshake", handshake)):
            if not isinstance(valu, int) or isinstance(valu, bool) or valu < 0:
                raise PcapSvcError(f"Invalid {name} {valu!r}, expected an integer >= 0.")

        return timeout, min(limit, maxlimit), handshake

    async def _download(
        self, axon, sha256: str, path: str, maxsize: int, what: str = "capture"
    ) -> int:
        """Append a file from the Axon to ``path``, returning its size."""

        shabyts = binascii.unhexlify(sha256)
        size = await axon.size(shabyts)
        if size is None:
            raise PcapSvcError(f"The {what} file:bytes:sha256={sha256} is not in the Axon.")
        if maxsize and size > maxsize:
            raise PcapSvcError(
                f"The {what} file:bytes:sha256={sha256} is {size} bytes, larger "
                f"than the max size of {maxsize} bytes."
            )
        try:
            with open(path, "ab") as fd:  # noqa: ASYNC230 - a write per Axon chunk
                async for byts in axon.get(shabyts):
                    fd.write(byts)
        except s_exc.NoSuchFile:
            raise PcapSvcError(
                f"The {what} file:bytes:sha256={sha256} is not in the Axon."
            ) from None
        return size

    async def _upload(self, axon, files: p_enrich.FileStore) -> int:
        """Upload the extracted files the Axon doesn't have yet, returning how many."""

        count = 0
        for sha256 in files.files:
            if await axon.has(binascii.unhexlify(sha256)):
                continue
            async with await axon.upload() as upfd:
                with open(files.path(sha256), "rb") as fd:  # noqa: ASYNC230 - chunked reads
                    while byts := fd.read(CHUNK):
                        await upfd.write(byts)
                await upfd.save()
            count += 1
        return count

    @contextlib.asynccontextmanager
    async def _axon(self):
        if not self.axonurl:
            yield None
            return
        async with s_telepath.withTeleEnv(), await s_telepath.openurl(self.axonurl) as axon:
            yield axon

    # ---- Engines ----

    async def _runTshark(
        self, path: str, keylog: str | None, decode: list[str], gaps: bool
    ) -> tuple[dict, dict]:
        info = {"enabled": True, "version": None, "error": None, "gaps": gaps and not keylog}
        try:
            frames, tsinfo = await self.tshark.frames(path, keylog=keylog, decode=decode, gaps=gaps)
        except p_tshark.TsharkError as err:
            info["error"] = err.mesg
            return {}, info
        info.update(tsinfo)
        return frames, info

    async def _runSuricata(
        self,
        parts: list[tuple[str, list[int] | None]],
        outdir: str,
        decode: list[str],
        files: bool,
        rules: bool,
        netvars: dict[str, str],
    ) -> tuple[dict | None, dict]:
        """Run Suricata over a capture, or each part of one split by link type (see
        ``pcapsvc.flows.splitLinktypes``), whose packet counts are mapped back to the
        capture's frame numbers."""

        info: dict[str, Any] = {"enabled": True, "error": None, "rules": 0, "warnings": []}
        active = self._acquire("suricata") if rules else None
        try:
            if active is not None:
                info["rules"] = len(active[1])
            runs = []
            for idx, (path, nums) in enumerate(parts):
                odir = outdir if len(parts) == 1 else os.path.join(outdir, f"part{idx}")
                os.makedirs(odir, exist_ok=True)
                res = await self.suricata.run(
                    path,
                    odir,
                    rulespath=active[0] if active else None,
                    decode=decode,
                    filestore=files,
                    maxbody=self.conf.get("pcap:files:maxsize"),
                    netvars=netvars,
                )
                info["warnings"].extend(res["warnings"])
                runs.append((res, nums))
            if len(runs) == 1:
                res = runs[0][0]
            else:
                res = await s_coro.executor(_mergeSuricata, runs, outdir)
            return {**res, "index": active[1] if active else {}}, info
        except p_suricata.SuricataError as err:
            info["error"] = err.mesg
            return None, info
        finally:
            if active is not None:
                self._release(active[0])

    async def _runSnort(
        self, parts: list[tuple[str, list[int] | None]], netvars: dict[str, str]
    ) -> tuple[dict | None, dict]:
        info: dict[str, Any] = {"enabled": True, "error": None, "rules": 0, "warnings": []}
        active = self._acquire("snort")
        if active is None:
            info["enabled"] = False
            return None, info
        alerts: list[dict] = []
        try:
            info["rules"] = len(active[1])
            info["alerts"] = 0
            for path, nums in parts:
                found: list[dict] = []
                count, warnings = await self.snort.scan(
                    active[0], path, found.append, netvars=netvars
                )
                for alert in found:
                    _remapNum(alert, "pkt_num", nums)
                alerts.extend(found)
                info["warnings"].extend(warnings)
                info["alerts"] += count
            return {"alerts": alerts, "index": active[1]}, info
        except p_snort.SnortError as err:
            info["error"] = err.mesg
            return None, info
        finally:
            self._release(active[0])

    @staticmethod
    def _correlate(frames: dict, suri: dict | None, snort: dict | None) -> tuple[list, dict]:
        """Add the engines' events and alerts to ``frames`` (by frame number). Returns the
        records without a frame number (see ``pcapsvc.flows.matchLoose``) and the rule index
        of each engine."""

        loose: list = []
        index: dict[str, dict] = {}
        if suri is not None:
            index["suricata"] = suri["index"]
            for ev in p_suricata.iterEve(suri["eve"]):
                etype = ev.get("event_type")
                if etype == "stats":
                    continue
                kind = "suricata" if etype == "alert" else "eve"
                num = ev.get("pcap_cnt")
                if num:
                    rec = frames.setdefault(int(num), {})
                    if kind == "eve":
                        rec.setdefault("_eve", []).append(ev)
                    else:
                        rec.setdefault("_alerts", []).append(("suricata", ev))
                elif ev.get("community_id"):
                    tick = p_eve.eveTime(ev.get("timestamp"))
                    if etype == "flow":
                        tick = p_eve.eveTime((ev.get("flow") or {}).get("start")) or tick
                    loose.append((ev["community_id"], tick, kind, ev))

        if snort is not None:
            index["snort"] = snort["index"]
            for alert in snort["alerts"]:
                num = alert.get("pkt_num")
                if num:
                    frames.setdefault(int(num), {}).setdefault("_alerts", []).append(
                        ("snort", alert)
                    )
                    continue
                cid = alertCommunityId(
                    alert.get("proto"),
                    alert.get("src_addr"),
                    alert.get("src_port"),
                    alert.get("dst_addr"),
                    alert.get("dst_port"),
                )
                if cid:
                    loose.append((cid, p_eve.alertTime("snort", alert), "snort", alert))
        return loose, index

    # ---- Analysis ----

    async def analyze(
        self,
        sha256: str,
        timeout: int | None = None,
        limit: int | None = None,
        handshake: int | None = None,
        tshark: bool | None = None,
        files: bool | None = None,
        keylogs: list[str] | None = None,
        decode: list[str] | None = None,
        suricata: bool | None = None,
        snort: bool | None = None,
        rules: bool = True,
        upload: str | None = None,
        keyloguploads: list[str] | None = None,
        netvars: dict[str, str] | None = None,
    ) -> tuple[list[dict], dict]:
        """Analyze a capture and return its flows and a summary of it.

        See ``pcapsvc.flows.analyze`` for what the flows and summary contain. The summary also
        has the file's ``sha256`` and ``size``, how each engine went (``engines``), and the
        extracted files (``files``).

        Parameters
        ----------
        sha256 : str
            The capture's SHA-256.
        upload : str | None
            The ID of the capture's upload (see ``uploadStart``), otherwise it's read from
            the Axon.
        keylogs, keyloguploads : list | None
            TLS key logs to decrypt with, by SHA-256 in the Axon or by upload ID.
        decode : list | None
            Decode As rules, for tshark (``-d``) and Suricata (detection ports).
        tshark, suricata, snort, files : bool | None
            Use each engine, and extract files, None for the service's config.
        rules : bool
            Match the capture against the rules (Snort and Suricata).

        Raises
        ------
        PcapSvcError
            If the capture (or a key log) can't be read, is too big, or isn't a capture.
        """

        sha256 = normSha256(sha256)
        keylogs = [normSha256(k) for k in (keylogs or ())]
        keyloguploads = list(keyloguploads or ())
        try:
            decode = p_tshark.checkDecodeAs(decode)
            netvars = p_rules.checkNetVars(netvars)
        except (p_tshark.TsharkError, p_rules.RuleError, TypeError) as err:
            raise PcapSvcError(getattr(err, "mesg", str(err))) from None

        timeout, limit, handshake = self._opts(timeout, limit, handshake)
        opts = {
            "tshark": self.conf.get("tshark:enabled") if tshark is None else bool(tshark),
            "suricata": self.conf.get("suricata:enabled") if suricata is None else bool(suricata),
            "snort": self.conf.get("snort:enabled") if snort is None else bool(snort),
            "files": self.conf.get("pcap:files") if files is None else bool(files),
            "rules": bool(rules),
            "netvars": netvars,
        }

        if upload is None and not self.axonurl:
            raise PcapSvcError("The service has no axon:url, the capture must be uploaded.")
        if keylogs and not self.axonurl:
            raise PcapSvcError("The service has no axon:url, key logs must be uploaded.")

        async with self.runsema:
            with tempfile.TemporaryDirectory(dir=self.tmpdir) as tmp:
                return await self._analyze(
                    tmp,
                    sha256,
                    upload,
                    keylogs,
                    keyloguploads,
                    decode,
                    timeout,
                    limit,
                    handshake,
                    opts,
                )

    async def _fetch(
        self,
        axon,
        tmp: str,
        sha256: str,
        upload: str | None,
        keylogs: list[str],
        keyloguploads: list[str],
    ) -> tuple[str, int, str | None]:
        """Get the capture (and the key logs, joined into one) into the run's directory.

        Returns (the capture's path, its size, the key log's path or None).
        """

        path = os.path.join(tmp, "capture")
        if upload is not None:
            size = self._takeUpload(upload, "capture", path, sha256)
        else:
            size = await self._download(axon, sha256, path, self.conf.get("pcap:maxsize"))

        keylog = None
        if keylogs or keyloguploads:
            keylog = os.path.join(tmp, "keylog")
            for kiden in keyloguploads:
                part = os.path.join(tmp, f"keylog-{kiden}")
                self._takeUpload(kiden, "keylog", part)
                with open(part, "rb") as ifd, open(keylog, "ab") as ofd:  # noqa: ASYNC230
                    shutil.copyfileobj(ifd, ofd)
                    ofd.write(b"\n")
            for ksha in keylogs:
                await self._download(
                    axon, ksha, keylog, self.conf.get("tshark:keylog:maxsize"), what="TLS key log"
                )
                with open(keylog, "ab") as fd:  # noqa: ASYNC230 - one byte
                    fd.write(b"\n")
        return path, size, keylog

    async def _engines(
        self,
        tmp: str,
        path: str,
        plain: str,
        keylog: str | None,
        decode: list[str],
        opts: dict,
        saving: bool,
    ) -> dict[str, Any]:
        """Run the engines (concurrently). Returns their results and how each went."""

        suridir = os.path.join(tmp, "suricata")
        os.makedirs(suridir)
        # libpcap (Suricata and Snort read captures with it) can't read a pcapng with
        # interfaces of different link types, so those are split.
        parts: list[tuple[str, list[int] | None]] = [(plain, None)]
        if (opts["suricata"] and self.suricata.available()) or (
            opts["snort"] and opts["rules"] and self.snort.available()
        ):
            splitdir = os.path.join(tmp, "split")
            os.makedirs(splitdir)
            parts = await s_coro.executor(p_flows.splitLinktypes, plain, splitdir) or parts
        self.sandbox.prepare(tmp)

        info: dict[str, dict] = {
            name: {"enabled": False, "error": None} for name in ("suricata", "snort", "tshark")
        }
        tasks: dict[str, Any] = {}
        if opts["suricata"] and self.suricata.available():
            tasks["suricata"] = self._runSuricata(
                parts, suridir, decode, saving, opts["rules"], opts["netvars"]
            )
        elif opts["suricata"]:
            info["suricata"]["error"] = "Suricata is not installed"
        if opts["snort"] and opts["rules"] and self.snort.available():
            tasks["snort"] = self._runSnort(parts, opts["netvars"])
        if opts["tshark"] and self.tshark.available:
            tasks["tshark"] = self._runTshark(path, keylog, decode, gaps="suricata" in tasks)
        elif opts["tshark"]:
            info["tshark"]["error"] = "tshark is not installed"
        if keylog and "tshark" not in tasks:
            info["tshark"]["error"] = info["tshark"]["error"] or "TLS key logs need tshark"

        results = dict(zip(tasks, await asyncio.gather(*tasks.values())))
        out: dict[str, Any] = {"frames": {}, "suricata": None, "snort": None}
        for name, (res, einfo) in results.items():
            info[name] = einfo
            out["frames" if name == "tshark" else name] = res

        if out["suricata"] is None and info["tshark"].get("gaps"):
            # Suricata failed, so tshark has to do everything.
            out["frames"], info["tshark"] = await self._runTshark(path, keylog, decode, gaps=False)
        out["info"] = info
        return out

    async def _analyze(
        self,
        tmp: str,
        sha256: str,
        upload: str | None,
        keylogs: list[str],
        keyloguploads: list[str],
        decode: list[str],
        timeout: int,
        limit: int,
        handshake: int,
        opts: dict,
    ) -> tuple[list[dict], dict]:
        filesdir = os.path.join(tmp, "files")
        os.makedirs(filesdir)

        async with self._axon() as axon:
            path, size, keylog = await self._fetch(
                axon, tmp, sha256, upload, keylogs, keyloguploads
            )

            # Snort and Suricata only read plain captures, dpkt and tshark read either.
            plain = path
            if await s_coro.executor(_isGzip, path):
                plain = os.path.join(tmp, "capture.pcap")
                try:
                    await s_coro.executor(_gunzip, path, plain)
                except (OSError, EOFError, gzip.BadGzipFile) as err:
                    raise PcapSvcError(
                        f"file:bytes:sha256={sha256}: Unable to decompress the capture: {err}"
                    ) from None

            # Files are saved to the Axon, without one they're only counted.
            saving = opts["files"] and axon is not None
            res = await self._engines(tmp, path, plain, keylog, decode, opts, saving)
            # Reading the engines' output (EVE can be hundreds of MB) is done in a thread.
            loose, index = await s_coro.executor(
                self._correlate, res["frames"], res["suricata"], res["snort"]
            )

            store = None
            if saving:
                store = p_enrich.FileStore(
                    filesdir,
                    maxsize=self.conf.get("pcap:files:maxsize"),
                    limit=self.conf.get("pcap:files:limit"),
                )
            suri = res["suricata"]
            with open(path, "rb") as fd:  # noqa: ASYNC230 - read in the executor
                try:
                    flows, summary = await s_coro.executor(
                        p_flows.analyze,
                        fd,
                        timeout=timeout,
                        limit=limit,
                        handshake=handshake,
                        seed=sha256,
                        frames=res["frames"],
                        files=store,
                        unsaved=opts["files"] and not saving,
                        rules=index,
                        loose=loose,
                        filestore=suri["filestore"] if suri else None,
                    )
                except p_flows.PcapError as err:
                    raise PcapSvcError(f"file:bytes:sha256={sha256}: {err.mesg}") from None

            if store is not None:
                summary["files"]["uploaded"] = await self._upload(axon, store)

        summary["sha256"] = sha256
        summary["size"] = size
        summary["keylogs"] = len(keylogs) + len(keyloguploads)
        summary["decode"] = decode
        summary["netvars"] = opts["netvars"]
        summary["engines"] = res["info"]
        summary.setdefault("files", None)
        return flows, summary

    def checkNetVars(self, netvars: dict[str, str]) -> TelepathRetn:
        """Validate network variables (ex. HOME_NET), see ``pcapsvc.rules.checkNetVars``.

        The ``TelepathRetn``'s data is the normalized variables.
        """

        try:
            return TelepathRetn(status=True, mesg="", data=p_rules.checkNetVars(netvars))
        except p_rules.RuleError as err:
            return TelepathRetn(status=False, mesg=err.mesg, data=None)

    def checkDecodeAs(self, rules: list[str]) -> TelepathRetn:
        """Validate tshark "Decode As" rules, see ``pcapsvc.tshark.checkDecodeAs``.

        The ``TelepathRetn``'s data is the normalized rules.
        """

        try:
            return TelepathRetn(status=True, mesg="", data=p_tshark.checkDecodeAs(rules))
        except p_tshark.TsharkError as err:
            return TelepathRetn(status=False, mesg=err.mesg, data=None)

    async def flows(self, sha256: str, **opts: Any) -> AsyncIterator[TelepathRetn]:
        """Yield the flows in a capture, each wrapped in a ``TelepathRetn``.

        The first item's data is ``{"summary": <summary>}``, every item after it is
        ``{"flow": <flow>}``. An error yields a single ``status=False`` item. See ``analyze``
        for the options.
        """

        try:
            flows, summary = await self.analyze(sha256, **opts)
        except PcapSvcError as err:
            yield TelepathRetn(status=False, mesg=err.mesg, data=None)
            return
        except (s_exc.SynErr, OSError) as err:
            yield TelepathRetn(status=False, mesg=f"Unable to read {sha256}: {err}", data=None)
            return

        yield TelepathRetn(status=True, mesg="", data={"summary": summary})
        for flow in flows:
            yield TelepathRetn(status=True, mesg="", data={"flow": flow})
