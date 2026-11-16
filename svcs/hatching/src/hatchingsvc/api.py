"""The CellApi implementation for slib.hatching."""

import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc
from stormlibpp.svc import RetnApi
from stormlibpp.telepath import BoolRetn
from stormlibpp.utils import normver

from .defs import PKGDEFS, SVC_EVTS, SVC_NAME, SVC_VER
from .errors import HatchingApiError


class HatchingCellApi(RetnApi, s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the slib.hatching service.

    Every method returns a ``TelepathRetn`` (or yields them, for generators). Errors are
    returned as ``status=False``, never raised, so Storm can always report them (see
    ``stormlibpp.svc.RetnApi``).
    """

    # HatchingSvc methods exposed over Telepath as-is, wrapped in a TelepathRetn.
    # See HatchingSvc for each method's arguments and the Hatching Triage endpoint it calls.
    RETN_METHS = (
        "rawRequest",
        "maxSize",
        "resolve",
        # Samples
        "search",
        "samples",
        "sample",
        "summary",
        "deleteSample",
        "setProfile",
        "magicLink",
        "submitUrl",
        "submitFileInit",
        "submitFileChunk",
        "submitFile",
        "importSample",
        "wait",
        # Reports and modeling
        "overview",
        "staticReport",
        "taskReport",
        "urlscanReport",
        "normSample",
        "dumpedFiles",
        # Profiles
        "profiles",
        "profile",
        "addProfile",
        "editProfile",
        "delProfile",
        # Yara
        "rules",
        "rule",
        "addRule",
        "editRule",
        "renameRule",
        "delRule",
        # Users and API keys
        "users",
        "user",
        "addUser",
        "delUser",
        "userKeys",
        "addUserKey",
        "delUserKey",
        # Resources, geolocations, stats, and organization settings
        "resources",
        "geolocations",
        "stats",
        "orgSettings",
        "setMagicLinks",
    )

    # HatchingSvc async generators exposed over Telepath, each item wrapped in a TelepathRetn.
    GENR_METHS = (
        "sampleEvents",
        "kernelReport",
        "downloadSample",
        "downloadTaskFile",
        "downloadArchive",
    )

    # Errors returned to Storm with their own message. Bad input (ValueError, TypeError) is
    # "Invalid input", anything else (a bug, or a report shape the service doesn't expect) is
    # logged and returned as an "Unexpected error".
    RETN_ERRORS = (HatchingApiError,)

    _storm_svc_name = SVC_NAME
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS
    _storm_svc_pkgs = PKGDEFS

    async def setApiKey(self, apikey: str | None) -> BoolRetn:
        """Set (or clear) the service-wide Hatching Triage API key."""

        await self.cell.setApiKey(apikey)
        mesg = "Set the slib.hatching API key." if apikey else "Cleared the slib.hatching API key."
        return BoolRetn(status=True, mesg=mesg, data=True)

    async def hasApiKey(self) -> BoolRetn:
        """Whether the service has a stored or configured API key."""

        return BoolRetn(status=True, mesg="", data=await self.cell.hasApiKey())
