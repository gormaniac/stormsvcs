"""The CellApi implementation for slib.shodan."""

import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc
from stormlibpp.svc import RetnApi
from stormlibpp.telepath import BoolRetn
from stormlibpp.utils import normver

from .client import ShodanApiError
from .defs import PKGDEFS, SVC_EVTS, SVC_NAME, SVC_VER


class ShodanCellApi(RetnApi, s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the slib.shodan service.

    Every method returns a ``TelepathRetn`` (or yields them, for generators). Errors are
    returned as ``status=False``, never raised, so Storm can always report them (see
    ``stormlibpp.svc.RetnApi``).
    """

    # ShodanSvc methods exposed over Telepath as-is, wrapped in a TelepathRetn.
    # See ShodanSvc for each method's arguments and the Shodan endpoint it calls.
    RETN_METHS = (
        "rawRequest",
        # Search
        "host",
        "normHost",
        "count",
        "countIps",
        "search",
        "searchFacets",
        "searchFilters",
        "searchTokens",
        "bannerHash",
        "fileHash",
        # On-demand scanning
        "ports",
        "protocols",
        "services",
        "scan",
        "scanInternet",
        "scans",
        "scanStatus",
        # Network alerts
        "alertCreate",
        "alertEdit",
        "alertInfo",
        "alertDelete",
        "alertTriggers",
        "alertTriggerEnable",
        "alertTriggerDisable",
        "alertTriggerIgnore",
        "alertTriggerUnignore",
        "alertNotifierAdd",
        "alertNotifierDel",
        # Notifiers
        "notifiers",
        "notifierProviders",
        "notifierCreate",
        "notifierGet",
        "notifierEdit",
        "notifierDelete",
        # Directory
        "queries",
        "queriesSearch",
        "queriesTags",
        # Bulk data
        "datasets",
        "datasetFiles",
        # Organization
        "org",
        "orgMemberAdd",
        "orgMemberDel",
        # Account, API status, and utility
        "profile",
        "apiInfo",
        "myip",
        "httpHeaders",
        # DNS
        "dnsDomain",
        "dnsDomainAll",
        "dnsResolve",
        "dnsReverse",
        # Trends
        "trendsSearch",
        "trendsFacets",
        "trendsFilters",
        # InternetDB
        "internetdb",
        "normInternetDb",
        # CVEDB
        "cve",
        "normCve",
        "ghsa",
        "euvd",
        "normVuln",
        "cves",
        "cpes",
        # Query provenance
        "apiUrl",
        "streamUrl",
    )
    # ShodanSvc generators exposed over Telepath, each item (a normalized banner) wrapped in
    # a TelepathRetn: searchGenr() pages through a search, stream() reads the Streaming API.
    GENR_METHS = ("searchGenr", "stream")
    # Errors returned to Storm with their own message. Anything else is logged and returned
    # as an "Unexpected error".
    RETN_ERRORS = (ShodanApiError,)

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
