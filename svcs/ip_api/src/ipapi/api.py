"""The CellApi implementation for ipapi."""


from stormlibpp.telepath import BoolRetn
from stormlibpp.utils import normver
import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc

from .defs import SVC_EVTS, PKGDEFS, SVC_NAME, SVC_VER


class IpApiCellApi(s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the slib.ipapi service."""

    _storm_svc_name = SVC_NAME
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS
    _storm_svc_pkgs = PKGDEFS

    async def queryIp(self, ipaddr: str) -> BoolRetn:
        """Query information about the given IP address."""

        return await self.cell.queryIp(ipaddr)
