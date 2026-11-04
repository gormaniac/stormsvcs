"""The CellApi implementation for slib.bgphe."""

from collections.abc import AsyncIterator, Awaitable

import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc
from stormlibpp.telepath import TelepathRetn
from stormlibpp.utils import normver

from .client import BgpHeApiError
from .defs import PKGDEFS, SVC_EVTS, SVC_NAME, SVC_VER

# BgpHeSvc methods that are exposed over Telepath as-is, wrapped in a TelepathRetn.
# See BgpHeSvc for each method's arguments.
RETN_METHS = ("subdomains", "hosts", "whoisDomain", "whoisAsn", "prefixes")

# BgpHeSvc generators that are exposed over Telepath, each item wrapped in a TelepathRetn.
GENR_METHS = ("certs",)


def _errMesg(err: Exception) -> str | None:
    """The message of an error the API returns instead of raising, or None."""

    from .svc import BgpHeSvcError

    if isinstance(err, (BgpHeApiError, BgpHeSvcError)):
        return err.mesg
    return None


async def _retn(coro: Awaitable) -> TelepathRetn:
    """Await a BgpHeSvc call and wrap the result (or error) in a TelepathRetn."""

    try:
        data = await coro
    except Exception as err:
        mesg = _errMesg(err)
        if mesg is None:
            raise
        return TelepathRetn(status=False, mesg=mesg, data=None)
    return TelepathRetn(status=True, mesg="", data=data)


async def _retnGenr(genr: AsyncIterator) -> AsyncIterator[TelepathRetn]:
    """Wrap each item from a BgpHeSvc generator in a TelepathRetn.

    An error ends the generator after yielding a single ``status=False`` item.
    """

    try:
        async for item in genr:
            yield TelepathRetn(status=True, mesg="", data=item)
    except Exception as err:
        mesg = _errMesg(err)
        if mesg is None:
            raise
        yield TelepathRetn(status=False, mesg=mesg, data=None)


def _retnMeth(name: str):
    async def meth(self, *args, **kwargs) -> TelepathRetn:
        return await _retn(getattr(self.cell, name)(*args, **kwargs))

    meth.__name__ = name
    meth.__qualname__ = f"BgpHeCellApi.{name}"
    meth.__doc__ = f"Call BgpHeSvc.{name}() and return a TelepathRetn."
    return meth


def _genrMeth(name: str):
    async def meth(self, *args, **kwargs) -> AsyncIterator[TelepathRetn]:
        async for item in _retnGenr(getattr(self.cell, name)(*args, **kwargs)):
            yield item

    meth.__name__ = name
    meth.__qualname__ = f"BgpHeCellApi.{name}"
    meth.__doc__ = f"Yield from BgpHeSvc.{name}(), each item wrapped in a TelepathRetn."
    return meth


class BgpHeCellApi(s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the slib.bgphe service.

    Every method returns a ``TelepathRetn`` (or yields them, for generators).
    """

    _storm_svc_name = SVC_NAME
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS
    _storm_svc_pkgs = PKGDEFS


for _name in RETN_METHS:
    setattr(BgpHeCellApi, _name, _retnMeth(_name))
for _name in GENR_METHS:
    setattr(BgpHeCellApi, _name, _genrMeth(_name))
