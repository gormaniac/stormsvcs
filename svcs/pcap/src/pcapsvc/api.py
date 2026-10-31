"""The CellApi implementation for slib.pcap."""


from collections.abc import AsyncIterator

from stormlibpp.telepath import TelepathRetn
from stormlibpp.utils import normver
import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc

from .defs import SVC_EVTS, PKGDEFS, SVC_NAME, SVC_VER


class PcapCellApi(s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the slib.pcap service."""

    _storm_svc_name = SVC_NAME
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS
    _storm_svc_pkgs = PKGDEFS

    async def flows(self, sha256: str, timeout: int | None = None, limit: int | None = None,
                    handshake: int | None = None, tshark: bool | None = None,
                    files: bool | None = None) -> AsyncIterator[TelepathRetn]:
        """Yield the flows in a capture file in the Axon, see ``PcapSvc.flows``."""

        async for retn in self.cell.flows(sha256, timeout=timeout, limit=limit,
                                          handshake=handshake, tshark=tshark, files=files):
            yield retn
