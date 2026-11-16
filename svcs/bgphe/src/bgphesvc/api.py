"""The CellApi implementation for slib.bgphe."""

import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc
from stormlibpp.svc import RetnApi
from stormlibpp.utils import normver

from .defs import PKGDEFS, SVC_EVTS, SVC_NAME, SVC_VER


class BgpHeCellApi(RetnApi, s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the slib.bgphe service.

    Every method returns a ``TelepathRetn`` (or yields them, for generators). Errors are
    returned as ``status=False``, never raised, so Storm can always report them (see
    ``stormlibpp.svc.RetnApi``).
    """

    # BgpHeSvc methods exposed over Telepath as-is, wrapped in a TelepathRetn.
    # See BgpHeSvc for each method's arguments.
    RETN_METHS = ("subdomains", "hosts", "whoisDomain", "whoisAsn", "prefixes")
    # BgpHeSvc generators exposed over Telepath, each item wrapped in a TelepathRetn.
    GENR_METHS = ("certs",)
    # BgpHeApiError and BgpHeSvcError are SvcErrors, so the default RETN_ERRORS returns them
    # with their own message. Anything else is logged and returned as an "Unexpected error".

    _storm_svc_name = SVC_NAME
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS
    _storm_svc_pkgs = PKGDEFS
