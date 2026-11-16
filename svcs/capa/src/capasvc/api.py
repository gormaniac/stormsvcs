"""The CellApi implementation for slib.capa."""

import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc
from stormlibpp.svc import RetnApi
from stormlibpp.utils import normver

from .defs import PKGDEFS, SVC_EVTS, SVC_NAME, SVC_VER
from .rules import CapaRulesError


class CapaSvcError(Exception):
    """Raised by CapaSvc when a call fails, ``mesg`` is returned to Storm."""

    def __init__(self, mesg: str) -> None:
        super().__init__(mesg)
        self.mesg = mesg


class CapaCellApi(RetnApi, s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the slib.capa service.

    Every method returns a ``TelepathRetn`` (or yields them, for generators). Errors are
    returned as ``status=False``, never raised, so Storm can always report them (see
    ``stormlibpp.svc.RetnApi``).
    """

    # CapaSvc methods exposed over Telepath as-is, wrapped in a TelepathRetn.
    # See CapaSvc for each method's arguments.
    RETN_METHS = ("scan", "rulesInfo", "tags", "reload", "custom")
    # CapaSvc generators exposed over Telepath, each item wrapped in a TelepathRetn.
    GENR_METHS = ("rules",)
    # Errors returned to Storm with their own message. Anything else is logged and returned
    # as an "Unexpected error".
    RETN_ERRORS = (CapaSvcError, CapaRulesError)

    _storm_svc_name = SVC_NAME
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS
    _storm_svc_pkgs = PKGDEFS
