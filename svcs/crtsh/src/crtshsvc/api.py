"""The CellApi implementation for slib.crtsh."""

import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc
from stormlibpp.svc import RetnApi
from stormlibpp.telepath import TelepathRetn
from stormlibpp.utils import normver

from .db import CrtshDbError, dsnSecrets
from .defs import PKGDEFS, SVC_EVTS, SVC_NAME, SVC_VER


class CrtshCellApi(RetnApi, s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the slib.crtsh service.

    Every method returns a ``TelepathRetn`` (or yields them, for generators). Errors are
    returned as ``status=False``, never raised, so Storm can always report them (see
    ``stormlibpp.svc.RetnApi``).
    """

    # CrtshSvc methods exposed over Telepath as-is, wrapped in a TelepathRetn.
    # See CrtshSvc for each method's arguments.
    RETN_METHS = ("lookup", "get", "chain", "cas")
    # CrtshSvc generators exposed over Telepath, each item wrapped in a TelepathRetn.
    GENR_METHS = ("searchGenr", "issuedGenr", "pivotGenr")
    # Errors returned to Storm with their own message. Anything else is logged and returned
    # as an "Unexpected error".
    RETN_ERRORS = (CrtshDbError,)

    _storm_svc_name = SVC_NAME
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS
    _storm_svc_pkgs = PKGDEFS

    def _retnRedact(self, mesg: str) -> str:
        """Replace the password of ``crtsh:dsn`` in an error message.

        The default DSN has none, but a mirror's may, and a connection error can include it.
        """

        for secret in dsnSecrets(self.cell.conf.get("crtsh:dsn")):
            mesg = mesg.replace(secret, "<redacted>")
        return mesg

    async def rawQuery(
        self, sql: str, args: list | None = None, limit: int | None = None
    ) -> TelepathRetn:
        """Run ``CrtshSvc.rawQuery``. ``mesg`` counts the rows, and says when they're the limit
        (``limit`` capped by ``crtsh:sql:limit``), so there may be more."""

        limit = self.cell._limit(limit, conf="crtsh:sql:limit")
        rows = await self.cell.rawQuery(sql, args=args, limit=limit)
        mesg = f"{len(rows)} rows"
        if len(rows) >= limit:
            mesg += f" (the limit of {limit}, there may be more)"
        return TelepathRetn(status=True, mesg=mesg, data=rows)
