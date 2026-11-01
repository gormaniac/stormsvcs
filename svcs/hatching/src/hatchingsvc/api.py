"""The CellApi implementation for slib.hatching."""

from collections.abc import AsyncIterator, Awaitable

import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc
from stormlibpp.telepath import BoolRetn, TelepathRetn
from stormlibpp.utils import normver

from .defs import PKGDEFS, SVC_EVTS, SVC_NAME, SVC_VER
from .errors import HatchingApiError

# HatchingSvc methods that are exposed over Telepath as-is, wrapped in a TelepathRetn.
# See HatchingSvc for each method's arguments and the Hatching Triage endpoint it calls.
RETN_METHS = (
    "rawRequest",
    "maxSize",
    "resolve",
    # Samples
    "search",
    "samples",
    "sample",
    "summary",
    "deleteSample",
    "setProfile",
    "magicLink",
    "submitUrl",
    "submitFile",
    "importSample",
    "wait",
    # Reports and modeling
    "overview",
    "staticReport",
    "taskReport",
    "urlscanReport",
    "normSample",
    "dumpedFiles",
    # Profiles
    "profiles",
    "profile",
    "addProfile",
    "editProfile",
    "delProfile",
    # Yara
    "rules",
    "rule",
    "addRule",
    "editRule",
    "renameRule",
    "delRule",
    # Users and API keys
    "users",
    "user",
    "addUser",
    "delUser",
    "userKeys",
    "addUserKey",
    "delUserKey",
    # Resources, geolocations, stats, and organization settings
    "resources",
    "geolocations",
    "stats",
    "orgSettings",
    "setMagicLinks",
)

# HatchingSvc async generators that are exposed over Telepath, each item wrapped in a TelepathRetn.
GENR_METHS = (
    "sampleEvents",
    "kernelReport",
    "downloadSample",
    "downloadTaskFile",
    "downloadArchive",
)


async def _retn(coro: Awaitable) -> TelepathRetn:
    """Await a HatchingSvc call and wrap the result (or error) in a TelepathRetn."""

    try:
        data = await coro
    except HatchingApiError as err:
        return TelepathRetn(status=False, mesg=err.mesg, data=None)
    except (ValueError, TypeError) as err:
        # Bad input from Storm, ex. a non-numeric limit.
        return TelepathRetn(status=False, mesg=f"Invalid input: {err}", data=None)
    return TelepathRetn(status=True, mesg="", data=data)


async def _retnGenr(genr: AsyncIterator) -> AsyncIterator[TelepathRetn]:
    """Wrap each item from a HatchingSvc generator in a TelepathRetn.

    An error ends the generator after yielding a single ``status=False`` item.
    """

    try:
        async for item in genr:
            yield TelepathRetn(status=True, mesg="", data=item)
    except HatchingApiError as err:
        yield TelepathRetn(status=False, mesg=err.mesg, data=None)
    except (ValueError, TypeError) as err:
        yield TelepathRetn(status=False, mesg=f"Invalid input: {err}", data=None)


def _retnMeth(name: str):
    async def meth(self, *args, **kwargs) -> TelepathRetn:
        return await _retn(getattr(self.cell, name)(*args, **kwargs))

    meth.__name__ = name
    meth.__qualname__ = f"HatchingCellApi.{name}"
    meth.__doc__ = f"Call HatchingSvc.{name}() and return a TelepathRetn."
    return meth


def _genrMeth(name: str):
    async def meth(self, *args, **kwargs) -> AsyncIterator[TelepathRetn]:
        async for item in _retnGenr(getattr(self.cell, name)(*args, **kwargs)):
            yield item

    meth.__name__ = name
    meth.__qualname__ = f"HatchingCellApi.{name}"
    meth.__doc__ = f"Yield each item of HatchingSvc.{name}() as a TelepathRetn."
    return meth


class HatchingCellApi(s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the slib.hatching service.

    Every method returns a ``TelepathRetn`` (or yields them, for generators).
    """

    _storm_svc_name = SVC_NAME
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS
    _storm_svc_pkgs = PKGDEFS

    async def setApiKey(self, apikey: str | None) -> BoolRetn:
        """Set (or clear) the service-wide Hatching Triage API key."""

        await self.cell.setApiKey(apikey)
        mesg = "Set the slib.hatching API key." if apikey else "Cleared the slib.hatching API key."
        return BoolRetn(status=True, mesg=mesg, data=True)

    async def hasApiKey(self) -> BoolRetn:
        """Whether the service has a stored or configured API key."""

        return BoolRetn(status=True, mesg="", data=await self.cell.hasApiKey())


for _name in RETN_METHS:
    setattr(HatchingCellApi, _name, _retnMeth(_name))

for _name in GENR_METHS:
    setattr(HatchingCellApi, _name, _genrMeth(_name))
