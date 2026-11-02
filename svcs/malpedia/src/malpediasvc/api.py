"""The CellApi implementation for slib.malpedia."""

from collections.abc import AsyncIterator, Awaitable

import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc
from stormlibpp.telepath import TelepathRetn
from stormlibpp.utils import normver

from .client import MalpediaApiError
from .defs import PKGDEFS, SVC_EVTS, SVC_NAME, SVC_VER

# The errors a call can fail with, which are returned to Storm instead of raised.
ERRORS = (MalpediaApiError,)

# MalpediaSvc methods that are exposed over Telepath as-is, wrapped in a TelepathRetn.
# See MalpediaSvc for each method's arguments.
RETN_METHS = (
    "pull",
    "synced",
    "viewSynced",
    "resetView",
    "status",
    "record",
    "find",
    "refresh",
    "schedInfo",
)


def _errMesg(err: Exception) -> str | None:
    """The message of an error the API returns instead of raising, or None."""

    from .svc import MalpediaSvcError

    if isinstance(err, (MalpediaApiError, MalpediaSvcError)):
        return err.mesg
    return None


async def _retn(coro: Awaitable) -> TelepathRetn:
    """Await a MalpediaSvc call and wrap the result (or error) in a TelepathRetn."""

    try:
        data = await coro
    except Exception as err:
        mesg = _errMesg(err)
        if mesg is None:
            raise
        return TelepathRetn(status=False, mesg=mesg, data=None)
    return TelepathRetn(status=True, mesg="", data=data)


def _retnMeth(name: str):
    async def meth(self, *args, **kwargs) -> TelepathRetn:
        return await _retn(getattr(self.cell, name)(*args, **kwargs))

    meth.__name__ = name
    meth.__qualname__ = f"MalpediaCellApi.{name}"
    meth.__doc__ = f"Call MalpediaSvc.{name}() and return a TelepathRetn."
    return meth


class MalpediaCellApi(s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the slib.malpedia service.

    Every method returns a ``TelepathRetn`` (or yields them, for generators).
    """

    _storm_svc_name = SVC_NAME
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS
    _storm_svc_pkgs = PKGDEFS

    async def changes(
        self, view: str, kind: str, full: bool = False, size: int = 250
    ) -> AsyncIterator[TelepathRetn]:
        """Yield batches of the records that changed since a view's last sync.

        An error ends the generator after yielding a single ``status=False`` item.
        """

        try:
            async for batch in self.cell.changes(view, kind, full=full, size=size):
                yield TelepathRetn(status=True, mesg="", data=batch)
        except Exception as err:
            mesg = _errMesg(err)
            if mesg is None:
                raise
            yield TelepathRetn(status=False, mesg=mesg, data=None)


for _name in RETN_METHS:
    setattr(MalpediaCellApi, _name, _retnMeth(_name))
