"""The CellApi implementation for slib.vt."""

import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc
from stormlibpp.svc import RetnApi
from stormlibpp.telepath import BoolRetn
from stormlibpp.utils import normver

from .client import VtApiError
from .defs import PKGDEFS, SVC_EVTS, SVC_NAME, SVC_VER
from .quota import VtQuotaError


class VtCellApi(RetnApi, s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the slib.vt service.

    Every method returns a ``TelepathRetn``. Errors are returned as ``status=False``, never
    raised, so Storm can always report them (see ``stormlibpp.svc.RetnApi``).
    """

    # VtSvc methods exposed over Telepath as-is, wrapped in a TelepathRetn.
    # See VtSvc for each method's arguments and the VirusTotal endpoint it calls.
    RETN_METHS = (
        "apiKeySource",
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
    # Errors returned to Storm with their own message. Anything else is logged and returned
    # as an "Unexpected error".
    RETN_ERRORS = (VtApiError, VtQuotaError)

    _storm_svc_name = SVC_NAME
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS
    _storm_svc_pkgs = PKGDEFS

    def _retnRedact(self, mesg: str) -> str:
        """Scrub the service's stored and configured API keys from error messages.

        ``quota(remote=True)`` puts the key in the URL path, so an error can contain it.
        """

        return self.cell.redact(mesg)

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
