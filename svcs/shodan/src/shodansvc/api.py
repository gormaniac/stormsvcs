"""The CellApi implementation for slib.shodan."""


from collections.abc import AsyncIterator, Awaitable

from stormlibpp.telepath import BoolRetn, TelepathRetn
from stormlibpp.utils import normver
import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc

from .client import ShodanApiError
from .defs import SVC_EVTS, PKGDEFS, SVC_NAME, SVC_VER


# ShodanSvc methods that are exposed over Telepath as-is, wrapped in a TelepathRetn.
# See ShodanSvc for each method's arguments and the Shodan endpoint it calls.
RETN_METHS = (
    "rawRequest",
    # Search
    "host", "normHost", "count", "search", "searchFacets", "searchFilters", "searchTokens",
    # On-demand scanning
    "ports", "protocols", "services", "scan", "scanInternet", "scans", "scanStatus",
    # Network alerts
    "alertCreate", "alertEdit", "alertInfo", "alertDelete", "alertTriggers",
    "alertTriggerEnable", "alertTriggerDisable", "alertTriggerIgnore", "alertTriggerUnignore",
    "alertNotifierAdd", "alertNotifierDel",
    # Notifiers
    "notifiers", "notifierProviders", "notifierCreate", "notifierGet", "notifierEdit", "notifierDelete",
    # Directory
    "queries", "queriesSearch", "queriesTags",
    # Bulk data
    "datasets", "datasetFiles",
    # Organization
    "org", "orgMemberAdd", "orgMemberDel",
    # Account, API status, and utility
    "profile", "apiInfo", "myip", "httpHeaders", "honeyscore",
    # DNS
    "dnsDomain", "dnsDomainAll", "dnsResolve", "dnsReverse",
    # Exploits
    "exploitsSearch", "exploitsCount",
    # Trends
    "trendsSearch", "trendsFacets", "trendsFilters",
    # InternetDB
    "internetdb", "normInternetDb",
    # CVEDB
    "cve", "normCve", "cves", "cpes",
)


async def _retn(coro: Awaitable) -> TelepathRetn:
    """Await a ShodanSvc call and wrap the result (or error) in a TelepathRetn."""

    try:
        data = await coro
    except ShodanApiError as err:
        return TelepathRetn(status=False, mesg=err.mesg, data=None)
    return TelepathRetn(status=True, mesg="", data=data)


async def _retnGenr(genr: AsyncIterator) -> AsyncIterator[TelepathRetn]:
    """Wrap each item from a ShodanSvc generator in a TelepathRetn.

    An error ends the generator after yielding a single ``status=False`` item.
    """

    try:
        async for item in genr:
            yield TelepathRetn(status=True, mesg="", data=item)
    except ShodanApiError as err:
        yield TelepathRetn(status=False, mesg=err.mesg, data=None)


def _retnMeth(name: str):
    async def meth(self, *args, **kwargs) -> TelepathRetn:
        return await _retn(getattr(self.cell, name)(*args, **kwargs))

    meth.__name__ = name
    meth.__qualname__ = f"ShodanCellApi.{name}"
    meth.__doc__ = f"Call ShodanSvc.{name}() and return a TelepathRetn."
    return meth


class ShodanCellApi(s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the slib.shodan service.

    Every method returns a ``TelepathRetn`` (or yields them, for generators).
    """

    _storm_svc_name = SVC_NAME
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS
    _storm_svc_pkgs = PKGDEFS

    async def setApiKey(self, apikey: str | None) -> BoolRetn:
        """Set (or clear) the service-wide Shodan API key."""

        await self.cell.setApiKey(apikey)
        mesg = "Set the slib.shodan API key." if apikey else "Cleared the slib.shodan API key."
        return BoolRetn(status=True, mesg=mesg, data=True)

    async def hasApiKey(self) -> BoolRetn:
        """Whether the service has a stored or configured API key."""

        return BoolRetn(status=True, mesg="", data=await self.cell.hasApiKey())

    async def searchGenr(self, query: str, limit: int = 100, minify: bool = True,
                         page: int = 1, apikey=None) -> AsyncIterator[TelepathRetn]:
        """Yield normalized banners from a paged Shodan search."""

        async for item in _retnGenr(self.cell.searchGenr(query, limit=limit, minify=minify,
                                                          page=page, apikey=apikey)):
            yield item

    async def stream(self, kind: str = "banners", values=None, query: str | None = None,
                     aid: str | None = None, limit: int = 100, timeout: float = 60,
                     apikey=None) -> AsyncIterator[TelepathRetn]:
        """Yield normalized banners from the Shodan Streaming API."""

        async for item in _retnGenr(self.cell.stream(kind=kind, values=values, query=query, aid=aid,
                                                      limit=limit, timeout=timeout, apikey=apikey)):
            yield item


for _name in RETN_METHS:
    setattr(ShodanCellApi, _name, _retnMeth(_name))
