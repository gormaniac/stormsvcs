"""The CellApi implementation for slib.snort."""

from collections.abc import AsyncIterator, Awaitable

import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc
from stormlibpp.telepath import TelepathRetn
from stormlibpp.utils import normver

from .defs import PKGDEFS, SVC_EVTS, SVC_NAME, SVC_VER

# SnortSvc methods that are exposed over Telepath as-is, wrapped in a TelepathRetn.
# See SnortSvc for each method's arguments.
RETN_METHS = (
    "status",
    "hasAxon",
    # Rules
    "pushStart",
    "pushRules",
    "pushDone",
    "pushCancel",
    "ruleUpdate",
    "rebuild",
    "ruleErrors",
    "ruleInfo",
    "ruleParse",
    "ruleCheck",
    # Feeds
    "feeds",
    "feedAdd",
    "feedDel",
    "feedEnable",
    "feedPull",
    "feedSynced",
    # Scanning
    "scanStart",
    "scanChunk",
    "scanRun",
    "scanAxon",
)

# SnortSvc async generators that are exposed over Telepath, each item wrapped in a TelepathRetn.
GENR_METHS = ("feedChanges",)


def _errMesg(err: Exception) -> str | None:
    """The message of the service's own errors, or None for anything else."""

    # Imported here, the svc module imports this one.
    from .engine import SnortError
    from .feeds import FeedError
    from .svc import SnortSvcError

    if isinstance(err, (SnortSvcError, SnortError, FeedError)):
        return err.mesg
    if isinstance(err, (ValueError, TypeError)):
        # Bad input from Storm, ex. a non-numeric engine.
        return f"Invalid input: {err}"
    return None


async def _retn(coro: Awaitable) -> TelepathRetn:
    """Await a SnortSvc call and wrap the result (or error) in a TelepathRetn."""

    try:
        data = await coro
    except Exception as err:
        if (mesg := _errMesg(err)) is None:
            raise
        return TelepathRetn(status=False, mesg=mesg, data=None)
    return TelepathRetn(status=True, mesg="", data=data)


async def _retnGenr(genr: AsyncIterator) -> AsyncIterator[TelepathRetn]:
    """Wrap each item from a SnortSvc generator in a TelepathRetn.

    An error ends the generator after yielding a single ``status=False`` item.
    """

    try:
        async for item in genr:
            yield TelepathRetn(status=True, mesg="", data=item)
    except Exception as err:
        if (mesg := _errMesg(err)) is None:
            raise
        yield TelepathRetn(status=False, mesg=mesg, data=None)


def _retnMeth(name: str):
    async def meth(self, *args, **kwargs) -> TelepathRetn:
        return await _retn(getattr(self.cell, name)(*args, **kwargs))

    meth.__name__ = name
    meth.__qualname__ = f"SnortCellApi.{name}"
    meth.__doc__ = f"Call SnortSvc.{name}() and return a TelepathRetn."
    return meth


def _genrMeth(name: str):
    async def meth(self, *args, **kwargs) -> AsyncIterator[TelepathRetn]:
        async for item in _retnGenr(getattr(self.cell, name)(*args, **kwargs)):
            yield item

    meth.__name__ = name
    meth.__qualname__ = f"SnortCellApi.{name}"
    meth.__doc__ = f"Yield the items of SnortSvc.{name}(), each wrapped in a TelepathRetn."
    return meth


class SnortCellApi(s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the slib.snort service.

    Every method returns a ``TelepathRetn`` (or yields them, for generators).
    """

    _storm_svc_name = SVC_NAME
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS
    _storm_svc_pkgs = PKGDEFS


for _name in RETN_METHS:
    setattr(SnortCellApi, _name, _retnMeth(_name))

for _name in GENR_METHS:
    setattr(SnortCellApi, _name, _genrMeth(_name))
