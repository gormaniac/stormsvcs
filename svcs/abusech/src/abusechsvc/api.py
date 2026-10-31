"""The CellApi implementation for slib.abusech."""


from collections.abc import AsyncIterator, Awaitable

from stormlibpp.telepath import BoolRetn, TelepathRetn
from stormlibpp.utils import normver
import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc

from .client import AbuseChApiError
from .defs import SVC_EVTS, PKGDEFS, SVC_NAME, SVC_VER


# AbuseChSvc methods that are exposed over Telepath as-is, wrapped in a TelepathRetn.
# See AbuseChSvc for each method's arguments and the abuse.ch endpoint it calls.
RETN_METHS = (
    "rawRequest", "maxSize",
    # Bulk imports
    "bulkExports", "bulkStart", "bulkStage", "bulkDone",
    # MalwareBazaar
    "bazaarQuery", "bazaarInfo", "normBazaarInfo", "bazaarSearch", "normBazaarSearch",
    "bazaarRecent", "normBazaarRecent", "bazaarDetections", "normBazaarDetections", "bazaarCscb", "normBazaarCscb", "bazaarFile",
    "bazaarUpload", "bazaarUpdate", "bazaarComment",
    # URLhaus
    "urlhausUrl", "urlhausUrlId", "normUrlhausUrl", "urlhausHost", "normUrlhausHost",
    "urlhausPayload", "normUrlhausPayload", "urlhausTag", "urlhausSignature", "normUrlhausSearch",
    "urlhausRecentUrls", "urlhausRecentPayloads", "normUrlhausRecent", "urlhausDownload", "urlhausSubmit",
    # ThreatFox
    "threatfoxQuery", "threatfoxRecent", "threatfoxIoc", "threatfoxSearch", "threatfoxHash",
    "threatfoxTag", "threatfoxMalware", "normThreatfox", "threatfoxTypes", "threatfoxTagList",
    "threatfoxMalwareList", "threatfoxLabel", "threatfoxSubmit",
    # YARAify
    "yaraifyQuery", "yaraifyHash", "normYaraifyHash", "yaraifySearch", "normYaraifySearch",
    "yaraifyRecentRules", "normYaraifyRecentRules", "yaraifyResults", "normYaraifyResults",
    "yaraifyTasks", "normYaraifyTasks", "yaraifyIdentifier", "yaraifyRescan", "yaraifyScan",
    "yaraifyDeploy", "yaraifyRule", "yaraifyFile", "yaraifyDeployedRules", "normYaraifyDeployedRules",
    "yaraifyDeleteRule", "yaraifyUnpacked",
    # Hunting
    "fplist", "normFplist",
)

# AbuseChSvc async generators that are exposed over Telepath, each item wrapped in a TelepathRetn.
GENR_METHS = (
    "bulkPull", "bulkBuild", "bulkNodes",
    "bazaarExport", "urlhausExport", "threatfoxExport", "yaraifyRulesExport",
    "feodoBlocklist", "sslblBlocklist",
)


async def _retn(coro: Awaitable) -> TelepathRetn:
    """Await an AbuseChSvc call and wrap the result (or error) in a TelepathRetn."""

    try:
        data = await coro
    except AbuseChApiError as err:
        return TelepathRetn(status=False, mesg=err.mesg, data=None)
    except (ValueError, TypeError) as err:
        # Bad input from Storm, ex. a non-numeric ID.
        return TelepathRetn(status=False, mesg=f"Invalid input: {err}", data=None)
    return TelepathRetn(status=True, mesg="", data=data)


async def _retnGenr(genr: AsyncIterator) -> AsyncIterator[TelepathRetn]:
    """Wrap each item from an AbuseChSvc generator in a TelepathRetn.

    An error ends the generator after yielding a single ``status=False`` item.
    """

    try:
        async for item in genr:
            yield TelepathRetn(status=True, mesg="", data=item)
    except AbuseChApiError as err:
        yield TelepathRetn(status=False, mesg=err.mesg, data=None)
    except (ValueError, TypeError) as err:
        yield TelepathRetn(status=False, mesg=f"Invalid input: {err}", data=None)


def _retnMeth(name: str):
    async def meth(self, *args, **kwargs) -> TelepathRetn:
        return await _retn(getattr(self.cell, name)(*args, **kwargs))

    meth.__name__ = name
    meth.__qualname__ = f"AbuseChCellApi.{name}"
    meth.__doc__ = f"Call AbuseChSvc.{name}() and return a TelepathRetn."
    return meth


def _genrMeth(name: str):
    async def meth(self, *args, **kwargs) -> AsyncIterator[TelepathRetn]:
        async for item in _retnGenr(getattr(self.cell, name)(*args, **kwargs)):
            yield item

    meth.__name__ = name
    meth.__qualname__ = f"AbuseChCellApi.{name}"
    meth.__doc__ = f"Yield the items of AbuseChSvc.{name}(), each wrapped in a TelepathRetn."
    return meth


class AbuseChCellApi(s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the slib.abusech service.

    Every method returns a ``TelepathRetn`` (or yields them, for generators).
    """

    _storm_svc_name = SVC_NAME
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS
    _storm_svc_pkgs = PKGDEFS

    async def setApiKey(self, apikey: str | None) -> BoolRetn:
        """Set (or clear) the service-wide abuse.ch Auth-Key."""

        await self.cell.setApiKey(apikey)
        mesg = "Set the slib.abusech Auth-Key." if apikey else "Cleared the slib.abusech Auth-Key."
        return BoolRetn(status=True, mesg=mesg, data=True)

    async def hasApiKey(self) -> BoolRetn:
        """Whether the service has a stored or configured Auth-Key."""

        return BoolRetn(status=True, mesg="", data=await self.cell.hasApiKey())


for _name in RETN_METHS:
    setattr(AbuseChCellApi, _name, _retnMeth(_name))

for _name in GENR_METHS:
    setattr(AbuseChCellApi, _name, _genrMeth(_name))
