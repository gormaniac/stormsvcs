"""The CellApi implementation for slib.abusech."""

from urllib.parse import quote

import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc
from stormlibpp.svc import RetnApi
from stormlibpp.telepath import BoolRetn
from stormlibpp.utils import normver

from .client import AbuseChApiError
from .defs import PKGDEFS, SVC_EVTS, SVC_NAME, SVC_VER


class AbuseChCellApi(RetnApi, s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the slib.abusech service.

    Every method returns a ``TelepathRetn`` (or yields them, for generators). Errors are
    returned as ``status=False``, never raised, so Storm can always report them (see
    ``stormlibpp.svc.RetnApi``).
    """

    # AbuseChSvc methods exposed over Telepath as-is, wrapped in a TelepathRetn.
    # See AbuseChSvc for each method's arguments and the abuse.ch endpoint it calls.
    RETN_METHS = (
        "rawRequest",
        "maxSize",
        # Bulk imports
        "bulkExports",
        "bulkStart",
        "bulkStage",
        "bulkDone",
        # MalwareBazaar
        "bazaarQuery",
        "bazaarInfo",
        "normBazaarInfo",
        "bazaarSearch",
        "normBazaarSearch",
        "bazaarRecent",
        "normBazaarRecent",
        "bazaarDetections",
        "normBazaarDetections",
        "bazaarCscb",
        "normBazaarCscb",
        "bazaarFile",
        "bazaarUpload",
        "bazaarUpdate",
        "bazaarComment",
        # URLhaus
        "urlhausUrl",
        "urlhausUrlId",
        "normUrlhausUrl",
        "urlhausHost",
        "normUrlhausHost",
        "urlhausPayload",
        "normUrlhausPayload",
        "urlhausTag",
        "urlhausSignature",
        "normUrlhausSearch",
        "urlhausRecentUrls",
        "urlhausRecentPayloads",
        "normUrlhausRecent",
        "urlhausDownload",
        "urlhausSubmit",
        # ThreatFox
        "threatfoxQuery",
        "threatfoxRecent",
        "threatfoxIoc",
        "threatfoxSearch",
        "threatfoxHash",
        "threatfoxTag",
        "threatfoxMalware",
        "normThreatfox",
        "threatfoxTypes",
        "threatfoxTagList",
        "threatfoxMalwareList",
        "threatfoxLabel",
        "threatfoxSubmit",
        # YARAify
        "yaraifyQuery",
        "yaraifyHash",
        "normYaraifyHash",
        "yaraifySearch",
        "normYaraifySearch",
        "yaraifyRecentRules",
        "normYaraifyRecentRules",
        "yaraifyResults",
        "normYaraifyResults",
        "yaraifyTasks",
        "normYaraifyTasks",
        "yaraifyIdentifier",
        "yaraifyRescan",
        "yaraifyScan",
        "yaraifyDeploy",
        "yaraifyRule",
        "yaraifyFile",
        "yaraifyDeployedRules",
        "normYaraifyDeployedRules",
        "yaraifyDeleteRule",
        "yaraifyUnpacked",
        # Hunting
        "fplist",
        "normFplist",
    )

    # AbuseChSvc async generators exposed over Telepath, each item wrapped in a TelepathRetn.
    GENR_METHS = (
        "bulkPull",
        "bulkBuild",
        "bulkNodes",
        "bazaarExport",
        "urlhausExport",
        "threatfoxExport",
        "yaraifyRulesExport",
        "feodoBlocklist",
        "sslblBlocklist",
    )

    # Errors returned to Storm with their own message. Bad input (ValueError, TypeError) is
    # "Invalid input", anything else is logged and returned as an "Unexpected error".
    RETN_ERRORS = (AbuseChApiError,)

    _storm_svc_name = SVC_NAME
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS
    _storm_svc_pkgs = PKGDEFS

    def _retnRedact(self, mesg: str) -> str:
        """Replace the service's Auth-Keys (stored and configured) in an error message.

        The exports take the Auth-Key in the URL path, and an error from an HTTP library can
        include the URL, so every message returned to Storm is scrubbed (ABUSE-PY-02).
        """

        keys = {self.cell.abuseinfo.get("apikey"), self.cell.conf.get("abusech:apikey")}
        for key in sorted(filter(None, keys), key=len, reverse=True):
            for valu in (key, quote(key, safe="")):
                mesg = mesg.replace(valu, "<redacted>")
        return mesg

    async def setApiKey(self, apikey: str | None) -> BoolRetn:
        """Set (or clear) the service-wide abuse.ch Auth-Key."""

        await self.cell.setApiKey(apikey)
        mesg = "Set the slib.abusech Auth-Key." if apikey else "Cleared the slib.abusech Auth-Key."
        return BoolRetn(status=True, mesg=mesg, data=True)

    async def hasApiKey(self) -> BoolRetn:
        """Whether the service has a stored or configured Auth-Key."""

        return BoolRetn(status=True, mesg="", data=await self.cell.hasApiKey())
