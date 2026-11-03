"""The CellApi implementation for slib.vt."""

from collections.abc import Awaitable

import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc
from stormlibpp.telepath import BoolRetn, TelepathRetn
from stormlibpp.utils import normver

from .client import VtApiError
from .defs import PKGDEFS, SVC_EVTS, SVC_NAME, SVC_VER
from .quota import VtQuotaError

# The errors a call can fail with, which are returned to Storm instead of raised.
ERRORS = (VtApiError, VtQuotaError)

# VtSvc methods that are exposed over Telepath as-is, wrapped in a TelepathRetn.
# See VtSvc for each method's arguments and the VirusTotal endpoint it calls.
RETN_METHS = (
    "rawRequest",
    "quota",
    "getObject",
    "lookup",
    "rels",
    "getRelated",
    "related",
    "comments",
    "addComment",
    "addVote",
    "rescan",
    "submitUrl",
    "submitFile",
    "analysis",
    "waitAnalysis",
    "behaviour",
    "search",
    "threatCategories",
    "attackTechnique",
)


async def _retn(coro: Awaitable) -> TelepathRetn:
    """Await a VtSvc call and wrap the result (or error) in a TelepathRetn."""

    try:
        data = await coro
    except ERRORS as err:
        return TelepathRetn(status=False, mesg=err.mesg, data=None)
    return TelepathRetn(status=True, mesg="", data=data)


def _retnMeth(name: str):
    async def meth(self, *args, **kwargs) -> TelepathRetn:
        return await _retn(getattr(self.cell, name)(*args, **kwargs))

    meth.__name__ = name
    meth.__qualname__ = f"VtCellApi.{name}"
    meth.__doc__ = f"Call VtSvc.{name}() and return a TelepathRetn."
    return meth


class VtCellApi(s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the slib.vt service.

    Every method returns a ``TelepathRetn``.
    """

    _storm_svc_name = SVC_NAME
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS
    _storm_svc_pkgs = PKGDEFS

    async def setApiKey(self, apikey: str | None) -> BoolRetn:
        """Set (or clear) the service-wide VirusTotal API key."""

        await self.cell.setApiKey(apikey)
        mesg = "Set the slib.vt API key." if apikey else "Cleared the slib.vt API key."
        return BoolRetn(status=True, mesg=mesg, data=True)

    async def hasApiKey(self) -> BoolRetn:
        """Whether the service has a stored or configured API key."""

        return BoolRetn(status=True, mesg="", data=await self.cell.hasApiKey())

    async def community(self) -> BoolRetn:
        """Whether the service enforces the Public API's limits (vt:community)."""

        return BoolRetn(status=True, mesg="", data=self.cell.community)


for _name in RETN_METHS:
    setattr(VtCellApi, _name, _retnMeth(_name))
