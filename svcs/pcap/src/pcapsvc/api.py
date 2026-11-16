"""The CellApi implementation for slib.pcap."""

from collections.abc import AsyncIterator
from typing import Any

import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc
from stormlibpp.svc import RetnApi
from stormlibpp.telepath import TelepathRetn
from stormlibpp.utils import normver

from .defs import PKGDEFS, SVC_EVTS, SVC_NAME, SVC_VER

FLOW_OPTS = (
    "timeout",
    "limit",
    "handshake",
    "tshark",
    "files",
    "keylogs",
    "decode",
    "suricata",
    "snort",
    "rules",
    "upload",
    "keyloguploads",
    "netvars",
)
"""The options ``flows`` takes (see ``PcapSvc.analyze``)."""


class PcapCellApi(RetnApi, s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the slib.pcap service.

    Every method returns a ``TelepathRetn`` (or yields them, for generators). Errors are
    returned as ``status=False``, never raised, so Storm can always report them (see
    ``stormlibpp.svc.RetnApi``). The service's own errors (``PcapSvcError``, ``RuleSvcError``,
    ``SnortError``, ``SuricataError`` and ``FeedError``) are ``stormlibpp.svc.SvcError``s and
    keep their message, anything else is logged and returned as an "Unexpected error".
    """

    # PcapSvc methods exposed over Telepath as-is, wrapped in a TelepathRetn. See PcapSvc for
    # each method's arguments.
    RETN_METHS = (
        "status",
        "hasAxon",
        # Uploads
        "uploadStart",
        "uploadChunk",
        "uploadCancel",
        # Rules
        "ruleStatus",
        "pushStart",
        "pushRules",
        "pushDone",
        "pushCancel",
        "ruleUpdate",
        "ruleErrors",
        "ruleWarnings",
        "ruleParse",
        "ruleCheck",
        # Feeds
        "feeds",
        "feedAdd",
        "feedDel",
        "feedEnable",
        "feedPull",
        "feedSynced",
    )

    # PcapSvc async generators exposed over Telepath, each item wrapped in a TelepathRetn.
    GENR_METHS = ("feedChanges",)

    _storm_svc_name = SVC_NAME
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS
    _storm_svc_pkgs = PKGDEFS

    async def flows(self, sha256: str, **opts: Any) -> AsyncIterator[TelepathRetn]:
        """Yield the flows in a capture, see ``PcapSvc.flows`` (and ``FLOW_OPTS``)."""

        bad = sorted(set(opts) - set(FLOW_OPTS))
        if bad:
            yield TelepathRetn(status=False, mesg=f"Unknown options: {', '.join(bad)}", data=None)
            return
        async for retn in self.cell.flows(sha256, **opts):
            yield retn

    async def checkNetVars(self, netvars: dict[str, str]) -> TelepathRetn:
        """Validate network variables, returning them normalized (see ``PcapSvc``)."""

        return self.cell.checkNetVars(netvars)

    async def checkDecodeAs(self, rules: list[str]) -> TelepathRetn:
        """Validate tshark "Decode As" rules, returning them normalized (see ``PcapSvc``)."""

        return self.cell.checkDecodeAs(rules)
