"""The CellApi implementation for slib.malpedia."""

import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc
from stormlibpp.svc import RetnApi
from stormlibpp.utils import normver

from .defs import PKGDEFS, SVC_EVTS, SVC_NAME, SVC_VER


class MalpediaCellApi(RetnApi, s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the slib.malpedia service.

    Every method returns a ``TelepathRetn`` (or yields them, for generators). Errors are
    returned as ``status=False``, never raised, so Storm can always report them (see
    ``stormlibpp.svc.RetnApi``).
    """

    # MalpediaSvc methods exposed over Telepath as-is, wrapped in a TelepathRetn.
    # See MalpediaSvc for each method's arguments.
    RETN_METHS = (
        "pull",
        "synced",
        "viewSynced",
        "viewInfo",
        "resetView",
        "status",
        "record",
        "find",
        "refresh",
        "schedInfo",
    )
    # MalpediaSvc generators exposed over Telepath, each item wrapped in a TelepathRetn.
    # changes(view, kind, full=False, size=BATCH_SIZE) yields batches of the records that
    # changed since a view's last sync.
    GENR_METHS = ("changes",)
    # MalpediaApiError and MalpediaSvcError are SvcErrors, so the default RETN_ERRORS returns
    # them with their own message. Anything else is logged and returned as an "Unexpected error".

    _storm_svc_name = SVC_NAME
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS
    _storm_svc_pkgs = PKGDEFS
