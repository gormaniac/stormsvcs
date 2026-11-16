"""The CellApi implementation for slib.crtsh."""

import logging
from collections.abc import AsyncIterator, Awaitable

import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc
from stormlibpp.telepath import TelepathRetn
from stormlibpp.utils import normver

from .db import CrtshDbError
from .defs import PKGDEFS, SVC_EVTS, SVC_NAME, SVC_VER

logger = logging.getLogger(__name__)

# CrtshSvc methods that are exposed over Telepath as-is, wrapped in a TelepathRetn.
# See CrtshSvc for each method's arguments.
RETN_METHS = ("lookup", "get", "chain", "cas", "rawQuery")

# CrtshSvc generators that are exposed over Telepath, each item wrapped in a TelepathRetn.
GENR_METHS = ("searchGenr", "issuedGenr", "pivotGenr")


def _errRetn(err: Exception) -> TelepathRetn:
    """A failed TelepathRetn for an error. Unexpected errors are logged with their traceback."""

    if isinstance(err, CrtshDbError):
        return TelepathRetn(status=False, mesg=err.mesg, data=None)
    logger.exception("Unexpected slib.crtsh error.", exc_info=err)
    return TelepathRetn(
        status=False, mesg=f"Unexpected error: {type(err).__name__}: {err}", data=None
    )


async def _retn(coro: Awaitable) -> TelepathRetn:
    """Await a CrtshSvc call and wrap the result (or error) in a TelepathRetn.

    Every error is returned as ``status=False``, so Storm can always report it with a warning.
    """

    try:
        data = await coro
    except Exception as err:
        return _errRetn(err)
    return TelepathRetn(status=True, mesg="", data=data)


async def _retnGenr(genr: AsyncIterator) -> AsyncIterator[TelepathRetn]:
    """Wrap each item from a CrtshSvc generator in a TelepathRetn.

    An error ends the generator after yielding a single ``status=False`` item.
    """

    try:
        async for item in genr:
            yield TelepathRetn(status=True, mesg="", data=item)
    except Exception as err:
        yield _errRetn(err)


def _retnMeth(name: str):
    async def meth(self, *args, **kwargs) -> TelepathRetn:
        return await _retn(getattr(self.cell, name)(*args, **kwargs))

    meth.__name__ = name
    meth.__qualname__ = f"CrtshCellApi.{name}"
    meth.__doc__ = f"Call CrtshSvc.{name}() and return a TelepathRetn."
    return meth


def _genrMeth(name: str):
    async def meth(self, *args, **kwargs) -> AsyncIterator[TelepathRetn]:
        async for item in _retnGenr(getattr(self.cell, name)(*args, **kwargs)):
            yield item

    meth.__name__ = name
    meth.__qualname__ = f"CrtshCellApi.{name}"
    meth.__doc__ = f"Yield from CrtshSvc.{name}(), each item wrapped in a TelepathRetn."
    return meth


class CrtshCellApi(s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the slib.crtsh service.

    Every method returns a ``TelepathRetn`` (or yields them, for generators).
    """

    _storm_svc_name = SVC_NAME
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS
    _storm_svc_pkgs = PKGDEFS


for _name in RETN_METHS:
    setattr(CrtshCellApi, _name, _retnMeth(_name))
for _name in GENR_METHS:
    setattr(CrtshCellApi, _name, _genrMeth(_name))
