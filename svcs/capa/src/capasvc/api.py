"""The CellApi implementation for slib.capa."""

from collections.abc import AsyncIterator, Awaitable

import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc
from stormlibpp.telepath import TelepathRetn
from stormlibpp.utils import normver

from .defs import PKGDEFS, SVC_EVTS, SVC_NAME, SVC_VER
from .rules import CapaRulesError


class CapaSvcError(Exception):
    """Raised by CapaSvc when a call fails, ``mesg`` is returned to Storm."""

    def __init__(self, mesg: str) -> None:
        super().__init__(mesg)
        self.mesg = mesg


ERRORS = (CapaSvcError, CapaRulesError)

# CapaSvc methods that are exposed over Telepath as-is, wrapped in a TelepathRetn.
# See CapaSvc for each method's arguments.
RETN_METHS = ("scan", "rulesInfo", "tags", "reload", "custom")

# CapaSvc generators that are exposed over Telepath, each item wrapped in a TelepathRetn.
GENR_METHS = ("rules",)


async def _retn(coro: Awaitable) -> TelepathRetn:
    """Await a CapaSvc call and wrap the result (or error) in a TelepathRetn."""

    try:
        data = await coro
    except ERRORS as err:
        return TelepathRetn(status=False, mesg=err.mesg, data=None)
    return TelepathRetn(status=True, mesg="", data=data)


async def _retnGenr(genr: AsyncIterator) -> AsyncIterator[TelepathRetn]:
    """Wrap each item from a CapaSvc generator in a TelepathRetn.

    An error ends the generator after yielding a single ``status=False`` item.
    """

    try:
        async for item in genr:
            yield TelepathRetn(status=True, mesg="", data=item)
    except ERRORS as err:
        yield TelepathRetn(status=False, mesg=err.mesg, data=None)


def _retnMeth(name: str):
    async def meth(self, *args, **kwargs) -> TelepathRetn:
        return await _retn(getattr(self.cell, name)(*args, **kwargs))

    meth.__name__ = name
    meth.__qualname__ = f"CapaCellApi.{name}"
    meth.__doc__ = f"Call CapaSvc.{name}() and return a TelepathRetn."
    return meth


def _genrMeth(name: str):
    async def meth(self, *args, **kwargs) -> AsyncIterator[TelepathRetn]:
        async for item in _retnGenr(getattr(self.cell, name)(*args, **kwargs)):
            yield item

    meth.__name__ = name
    meth.__qualname__ = f"CapaCellApi.{name}"
    meth.__doc__ = f"Yield from CapaSvc.{name}(), each item wrapped in a TelepathRetn."
    return meth


class CapaCellApi(s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the slib.capa service.

    Every method returns a ``TelepathRetn`` (or yields them, for generators).
    """

    _storm_svc_name = SVC_NAME
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS
    _storm_svc_pkgs = PKGDEFS


for _name in RETN_METHS:
    setattr(CapaCellApi, _name, _retnMeth(_name))
for _name in GENR_METHS:
    setattr(CapaCellApi, _name, _genrMeth(_name))
