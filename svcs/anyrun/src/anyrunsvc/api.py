"""The CellApi implementation for slib.anyrun."""

from collections.abc import AsyncIterator, Awaitable

import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc
from stormlibpp.telepath import BoolRetn, TelepathRetn
from stormlibpp.utils import normver

from .client import AnyRunApiError
from .defs import PKGDEFS, SVC_EVTS, SVC_NAME, SVC_VER

# AnyRunSvc methods that are exposed over Telepath as-is, wrapped in a TelepathRetn.
# See AnyRunSvc for each method's arguments and the ANY.RUN endpoint it calls.
RETN_METHS = (
    "rawRequest",
    "maxSize",
    # Account
    "limits",
    "environments",
    "presets",
    # Tasks
    "history",
    "report",
    "normReport",
    "iocs",
    "aiSummary",
    "summary",
    "status",
    "wait",
    "droppedFiles",
    # Submissions and task control
    "submitFile",
    "submitUrl",
    "submitDownload",
    "rerun",
    "addTime",
    "stopTask",
    "deleteTask",
    # TI Lookup
    "lookup",
    "lookupIndicator",
    "normLookup",
    # YARA Search
    "yaraSearch",
    "yaraStatus",
    "yaraResults",
    "yaraStop",
    "yaraRun",
    "yaraGet",
    # TI Feeds
    "feeds",
)

# AnyRunSvc async generators that are exposed over Telepath, each item wrapped in a TelepathRetn.
GENR_METHS = (
    "monitor",
    "downloadSample",
    "downloadPcap",
    "downloadDropped",
    "feedObjects",
)


async def _retn(coro: Awaitable) -> TelepathRetn:
    """Await an AnyRunSvc call and wrap the result (or error) in a TelepathRetn."""

    try:
        data = await coro
    except AnyRunApiError as err:
        return TelepathRetn(status=False, mesg=err.mesg, data=None)
    except (ValueError, TypeError) as err:
        # Bad input from Storm, ex. a non-numeric limit.
        return TelepathRetn(status=False, mesg=f"Invalid input: {err}", data=None)
    return TelepathRetn(status=True, mesg="", data=data)


async def _retnGenr(genr: AsyncIterator) -> AsyncIterator[TelepathRetn]:
    """Wrap each item from an AnyRunSvc generator in a TelepathRetn.

    An error ends the generator after yielding a single ``status=False`` item.
    """

    try:
        async for item in genr:
            yield TelepathRetn(status=True, mesg="", data=item)
    except AnyRunApiError as err:
        yield TelepathRetn(status=False, mesg=err.mesg, data=None)
    except (ValueError, TypeError) as err:
        yield TelepathRetn(status=False, mesg=f"Invalid input: {err}", data=None)


def _retnMeth(name: str):
    async def meth(self, *args, **kwargs) -> TelepathRetn:
        return await _retn(getattr(self.cell, name)(*args, **kwargs))

    meth.__name__ = name
    meth.__qualname__ = f"AnyRunCellApi.{name}"
    meth.__doc__ = f"Call AnyRunSvc.{name}() and return a TelepathRetn."
    return meth


def _genrMeth(name: str):
    async def meth(self, *args, **kwargs) -> AsyncIterator[TelepathRetn]:
        async for item in _retnGenr(getattr(self.cell, name)(*args, **kwargs)):
            yield item

    meth.__name__ = name
    meth.__qualname__ = f"AnyRunCellApi.{name}"
    meth.__doc__ = f"Yield each item of AnyRunSvc.{name}() as a TelepathRetn."
    return meth


class AnyRunCellApi(s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the slib.anyrun service.

    Every method returns a ``TelepathRetn`` (or yields them, for generators).
    """

    _storm_svc_name = SVC_NAME
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS
    _storm_svc_pkgs = PKGDEFS

    async def setApiKey(self, apikey: str | None) -> BoolRetn:
        """Set (or clear) the service-wide ANY.RUN API key."""

        await self.cell.setApiKey(apikey)
        mesg = "Set the slib.anyrun API key." if apikey else "Cleared the slib.anyrun API key."
        return BoolRetn(status=True, mesg=mesg, data=True)

    async def hasApiKey(self) -> BoolRetn:
        """Whether the service has a stored or configured API key."""

        return BoolRetn(status=True, mesg="", data=await self.cell.hasApiKey())


for _name in RETN_METHS:
    setattr(AnyRunCellApi, _name, _retnMeth(_name))

for _name in GENR_METHS:
    setattr(AnyRunCellApi, _name, _genrMeth(_name))
