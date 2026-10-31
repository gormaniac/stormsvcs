"""The slib.pcap service.

``PcapSvc`` downloads capture files (pcap, pcapng, or either gzip compressed) from an
Axon, aggregates their packets into flows (see ``pcapsvc.flows``), and returns them to
Storm, which models them as ``inet:flow`` nodes.

When tshark is installed, it also runs tshark over the capture to find application layer
details (certificates, SSH keys, software, transferred files, etc., see ``pcapsvc.tshark``
and ``pcapsvc.enrich``). Files found in the flows are uploaded to the Axon.
"""


import binascii
import os
import re
import tempfile
from collections.abc import AsyncIterator

from stormlibpp.telepath import TelepathRetn
import synapse.exc as s_exc
import synapse.lib.cell as s_cell
import synapse.lib.coro as s_coro
import synapse.telepath as s_telepath

from . import enrich as p_enrich
from . import flows as p_flows
from . import tshark as p_tshark
from .api import PcapCellApi


SHA256RE = re.compile(r"^[0-9a-f]{64}$")

CHUNK = 1024 * 1024
"""The size of the chunks files are uploaded to the Axon in."""


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


class PcapSvc(s_cell.Cell):
    """The Cell implementation for the slib.pcap service."""

    cellapi = PcapCellApi

    confdefs = {
        "axon:url": {
            "type": "string",
            "description": "The Telepath URL of the Axon that capture files are read from.",
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
        "pcap:files": {
            "type": "boolean",
            "default": True,
            "description": (
                "Extract the files sent in flows (HTTP, FTP, email) into the Axon by default. "
                "Needs tshark."
            ),
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
        "tshark:enabled": {
            "type": "boolean",
            "default": True,
            "description": (
                "Use tshark (when it's installed) for application layer details by default."
            ),
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
                "Extra tshark arguments, ex. [\"-d\", \"tcp.port==2222,ssh\"] to decode SSH "
                "on a non-standard port."
            ),
        },
        "tshark:keylog:maxsize": {
            "type": "integer",
            "default": 16 * 1024 * 1024,
            "minimum": 0,
            "description": "The largest TLS key log, in bytes, read from the Axon, 0 for no limit.",
        },
        "tshark:timeout": {
            "type": "number",
            "default": 600,
            "minimum": 0,
            "description": "Seconds a tshark run may take before it's killed, 0 for no limit.",
        },
        "pcap:maxsize": {
            "type": "integer",
            "default": 1024 * 1024 * 1024,
            "minimum": 0,
            "description": "The max size, in bytes, of a capture file to read, 0 for no limit.",
        },
    }

    async def __anit__(self, dirn, *args, **kwargs):
        await s_cell.Cell.__anit__(self, dirn, *args, **kwargs)
        self.axonurl = self.conf.get("axon:url")
        self.tmpdir = os.path.join(self.dirn, "tmp")
        os.makedirs(self.tmpdir, exist_ok=True)
        self.tshark = p_tshark.Tshark(
            path=self.conf.get("tshark:path"),
            args=self.conf.get("tshark:args"),
            timeout=self.conf.get("tshark:timeout"),
        )

    def _opts(self, timeout: int | None, limit: int | None,
              handshake: int | None) -> tuple[int, int, int]:
        """The analysis options to use, filling in (and capping) them from the config."""

        maxlimit = self.conf.get("pcap:limit")
        timeout = self.conf.get("pcap:timeout") if timeout is None else timeout
        handshake = self.conf.get("pcap:handshake") if handshake is None else handshake
        limit = maxlimit if not limit else limit

        for name, valu in (("timeout", timeout), ("limit", limit), ("handshake", handshake)):
            if not isinstance(valu, int) or isinstance(valu, bool) or valu < 0:
                raise PcapSvcError(f"Invalid {name} {valu!r}, expected an integer >= 0.")

        return timeout, min(limit, maxlimit), handshake

    async def _download(self, axon, sha256: str, fd) -> int:
        """Write a file from the Axon into fd, returning its size."""

        maxsize = self.conf.get("pcap:maxsize")
        shabyts = binascii.unhexlify(sha256)

        size = await axon.size(shabyts)
        if size is None:
            raise PcapSvcError(f"file:bytes:sha256={sha256} is not in the Axon.")
        if maxsize and size > maxsize:
            raise PcapSvcError(
                f"file:bytes:sha256={sha256} is {size} bytes, larger than the "
                f"pcap:maxsize of {maxsize} bytes."
            )
        try:
            async for byts in axon.get(shabyts):
                fd.write(byts)
        except s_exc.NoSuchFile:
            raise PcapSvcError(f"file:bytes:sha256={sha256} is not in the Axon.") from None

        return size

    async def _upload(self, axon, files: p_enrich.FileStore) -> int:
        """Upload the extracted files the Axon doesn't have yet, returning how many."""

        count = 0
        for sha256 in files.files:
            if await axon.has(binascii.unhexlify(sha256)):
                continue
            async with await axon.upload() as upfd:
                with open(files.path(sha256), "rb") as fd:
                    while byts := fd.read(CHUNK):
                        await upfd.write(byts)
                await upfd.save()
            count += 1
        return count

    async def _keylog(self, axon, keylogs: list[str], path: str) -> int:
        """Download TLS key logs from the Axon into one file, returning how many there were."""

        maxsize = self.conf.get("tshark:keylog:maxsize")
        with open(path, "wb") as fd:
            for sha256 in keylogs:
                shabyts = binascii.unhexlify(sha256)
                size = await axon.size(shabyts)
                if size is None:
                    raise PcapSvcError(
                        f"The TLS key log file:bytes:sha256={sha256} is not in the Axon."
                    )
                if maxsize and size > maxsize:
                    raise PcapSvcError(
                        f"The TLS key log file:bytes:sha256={sha256} is {size} bytes, larger than "
                        f"the tshark:keylog:maxsize of {maxsize} bytes."
                    )
                async for byts in axon.get(shabyts):
                    fd.write(byts)
                fd.write(b"\n")
        return len(keylogs)

    async def _tshark(self, path: str, keylog: str | None,
                      decode: list[str]) -> tuple[dict, dict]:
        """Run tshark over a capture, returning (frames, info). Failures are in the info."""

        info = {"enabled": True, "version": None, "error": None}
        try:
            frames, tsinfo = await self.tshark.frames(path, keylog=keylog, decode=decode)
        except p_tshark.TsharkError as err:
            info["error"] = err.mesg
            return {}, info
        info.update(tsinfo)
        return frames, info

    async def analyze(self, sha256: str, timeout: int | None = None, limit: int | None = None,
                      handshake: int | None = None, tshark: bool | None = None,
                      files: bool | None = None, keylogs: list[str] | None = None,
                      decode: list[str] | None = None) -> tuple[list[dict], dict]:
        """Read a capture file from the Axon and return its flows and a summary of it.

        See ``pcapsvc.flows.analyze`` for what the flows and summary contain. The summary
        also has the file's ``sha256`` and ``size``, how tshark went (``tshark``), and how many
        files were extracted (``files``).

        Raises
        ------
        PcapSvcError
            If the file (or a key log) isn't in the Axon or is too big, the file isn't a
            capture file, or a Decode As rule is invalid.
        """

        sha256 = normSha256(sha256)
        keylogs = [normSha256(k) for k in (keylogs or ())]
        try:
            decode = p_tshark.checkDecodeAs(decode)
        except (p_tshark.TsharkError, TypeError) as err:
            raise PcapSvcError(getattr(err, "mesg", str(err))) from None

        timeout, limit, handshake = self._opts(timeout, limit, handshake)
        tshark = self.conf.get("tshark:enabled") if tshark is None else bool(tshark)
        files = self.conf.get("pcap:files") if files is None else bool(files)

        if not self.axonurl:
            raise PcapSvcError("The slib.pcap service has no axon:url configured.")

        with tempfile.TemporaryDirectory(dir=self.tmpdir) as tmp:
            path = os.path.join(tmp, "capture")
            filesdir = os.path.join(tmp, "files")
            os.makedirs(filesdir)

            async with s_telepath.withTeleEnv(), await s_telepath.openurl(self.axonurl) as axon:
                with open(path, "wb") as fd:
                    size = await self._download(axon, sha256, fd)

                frames: dict = {}
                tsinfo = {"enabled": False, "version": None, "error": None}
                if tshark and not self.tshark.available:
                    tsinfo["error"] = "tshark is not installed"
                elif tshark:
                    keylog = None
                    if keylogs:
                        keylog = os.path.join(tmp, "keylog")
                        await self._keylog(axon, keylogs, keylog)
                    frames, tsinfo = await self._tshark(path, keylog, decode)
                tsinfo["keylogs"] = len(keylogs)
                tsinfo["decode"] = decode

                store = None
                if files and tsinfo["enabled"] and not tsinfo["error"]:
                    store = p_enrich.FileStore(
                        filesdir, maxsize=self.conf.get("pcap:files:maxsize"),
                        limit=self.conf.get("pcap:files:limit"),
                    )

                with open(path, "rb") as fd:
                    try:
                        flows, summary = await s_coro.executor(
                            p_flows.analyze, fd, timeout=timeout, limit=limit,
                            handshake=handshake, seed=sha256, frames=frames, files=store,
                        )
                    except p_flows.PcapError as err:
                        raise PcapSvcError(f"file:bytes:sha256={sha256}: {err.mesg}") from None

                if store is not None:
                    summary["files"]["uploaded"] = await self._upload(axon, store)

        summary["sha256"] = sha256
        summary["size"] = size
        summary["tshark"].update(tsinfo)
        summary.setdefault("files", None)
        return flows, summary

    def checkDecodeAs(self, rules: list[str]) -> TelepathRetn:
        """Validate tshark "Decode As" rules, see ``pcapsvc.tshark.checkDecodeAs``.

        The ``TelepathRetn``'s data is the normalized rules.
        """

        try:
            return TelepathRetn(status=True, mesg="", data=p_tshark.checkDecodeAs(rules))
        except p_tshark.TsharkError as err:
            return TelepathRetn(status=False, mesg=err.mesg, data=None)

    async def flows(self, sha256: str, timeout: int | None = None, limit: int | None = None,
                    handshake: int | None = None, tshark: bool | None = None,
                    files: bool | None = None, keylogs: list[str] | None = None,
                    decode: list[str] | None = None) -> AsyncIterator[TelepathRetn]:
        """Yield the flows in a capture file in the Axon, each wrapped in a ``TelepathRetn``.

        The first item's data is ``{"summary": <summary>}``, every item after it is
        ``{"flow": <flow>}``. An error yields a single ``status=False`` item.

        Parameters
        ----------
        sha256 : str
            The SHA-256 of the capture file in the Axon.
        timeout : int | None
            Seconds a flow can be idle before a new flow starts, 0 to never time out flows.
            Defaults to the ``pcap:timeout`` config.
        limit : int | None
            The max number of flows, capped by (and defaulting to) the ``pcap:limit`` config.
        handshake : int | None
            The max number of characters kept from each side's first text payload, 0 for none.
            Defaults to the ``pcap:handshake`` config.
        tshark : bool | None
            Use tshark for application layer details, if it's installed. Defaults to the
            ``tshark:enabled`` config.
        files : bool | None
            Extract the files sent in flows into the Axon (needs tshark). Defaults to the
            ``pcap:files`` config.
        keylogs : list[str] | None
            SHA-256s of NSS key logs (SSLKEYLOGFILE) in the Axon, to decrypt TLS 1.2 and 1.3
            with (needs tshark).
        decode : list[str] | None
            tshark "Decode As" rules, ex. ``["tcp.port==8443,tls"]``, see
            ``pcapsvc.tshark.checkDecodeAs``.
        """

        try:
            flows, summary = await self.analyze(sha256, timeout=timeout, limit=limit,
                                                handshake=handshake, tshark=tshark, files=files,
                                                keylogs=keylogs, decode=decode)
        except PcapSvcError as err:
            yield TelepathRetn(status=False, mesg=err.mesg, data=None)
            return
        except (s_exc.SynErr, OSError) as err:
            yield TelepathRetn(status=False, mesg=f"Unable to read {sha256}: {err}", data=None)
            return

        yield TelepathRetn(status=True, mesg="", data={"summary": summary})
        for flow in flows:
            yield TelepathRetn(status=True, mesg="", data={"flow": flow})
