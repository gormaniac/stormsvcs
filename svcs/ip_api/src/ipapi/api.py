"""The CellApi implementation for ipapi."""

from typing import TYPE_CHECKING

import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc
from stormlibpp.utils import normver

from .defs import PKGDEFS, SVC_EVTS, SVC_NAME, SVC_VER

if TYPE_CHECKING:
    from .svc import IpRetn


class IpApiCellApi(s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the slib.ipapi service."""

    _storm_svc_name = SVC_NAME
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS
    _storm_svc_pkgs = PKGDEFS

    async def queryIp(self, ipaddr: str) -> "IpRetn":
        """Query information about the given IP address."""

        return await self.cell.queryIp(ipaddr)
