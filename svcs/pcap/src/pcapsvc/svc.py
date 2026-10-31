"""The slib.pcap service.

``PcapSvc`` downloads capture files (pcap, pcapng, or either gzip compressed) from an
Axon, aggregates their packets into flows (see ``pcapsvc.flows``), and returns them to
Storm, which models them as ``inet:flow`` nodes.
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

from . import flows as p_flows
from .api import PcapCellApi


SHA256RE = re.compile(r"^[0-9a-f]{64}$")


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

    async def _download(self, sha256: str, fd) -> int:
        """Write a file from the Axon into fd, returning its size."""

        if not self.axonurl:
            raise PcapSvcError("The slib.pcap service has no axon:url configured.")

        maxsize = self.conf.get("pcap:maxsize")
        shabyts = binascii.unhexlify(sha256)

        async with s_telepath.withTeleEnv(), await s_telepath.openurl(self.axonurl) as axon:
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

    async def analyze(self, sha256: str, timeout: int | None = None, limit: int | None = None,
                      handshake: int | None = None) -> tuple[list[dict], dict]:
        """Read a capture file from the Axon and return its flows and a summary of it.

        See ``pcapsvc.flows.analyze`` for what the flows and summary contain. The summary
        also has the file's ``sha256`` and ``size``.

        Raises
        ------
        PcapSvcError
            If the file isn't in the Axon, is too big, or isn't a capture file.
        """

        sha256 = str(sha256).strip().lower().removeprefix("sha256:")
        if not SHA256RE.match(sha256):
            raise PcapSvcError(f"Invalid SHA-256: {sha256}")

        timeout, limit, handshake = self._opts(timeout, limit, handshake)

        with tempfile.TemporaryFile(dir=self.tmpdir) as fd:
            size = await self._download(sha256, fd)
            fd.seek(0)
            try:
                flows, summary = await s_coro.executor(
                    p_flows.analyze, fd, timeout=timeout, limit=limit, handshake=handshake,
                    seed=sha256,
                )
            except p_flows.PcapError as err:
                raise PcapSvcError(f"file:bytes:sha256={sha256}: {err.mesg}") from None

        summary["sha256"] = sha256
        summary["size"] = size
        return flows, summary

    async def flows(self, sha256: str, timeout: int | None = None, limit: int | None = None,
                    handshake: int | None = None) -> AsyncIterator[TelepathRetn]:
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
        """

        try:
            flows, summary = await self.analyze(sha256, timeout=timeout, limit=limit,
                                                handshake=handshake)
        except PcapSvcError as err:
            yield TelepathRetn(status=False, mesg=err.mesg, data=None)
            return
        except (s_exc.SynErr, OSError) as err:
            yield TelepathRetn(status=False, mesg=f"Unable to read {sha256}: {err}", data=None)
            return

        yield TelepathRetn(status=True, mesg="", data={"summary": summary})
        for flow in flows:
            yield TelepathRetn(status=True, mesg="", data={"flow": flow})
