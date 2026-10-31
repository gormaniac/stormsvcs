"""The CellApi implementation for slib.pcap."""

from collections.abc import AsyncIterator, Awaitable
from typing import Any

import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc
from stormlibpp.telepath import TelepathRetn
from stormlibpp.utils import normver

from .defs import PKGDEFS, SVC_EVTS, SVC_NAME, SVC_VER

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
)
"""PcapSvc methods exposed over Telepath as-is, wrapped in a TelepathRetn. See PcapSvc for each
method's arguments."""

GENR_METHS = ("feedChanges",)
"""PcapSvc async generators exposed over Telepath, each item wrapped in a TelepathRetn."""

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
)
"""The options ``flows`` takes (see ``PcapSvc.analyze``)."""


def _errMesg(err: Exception) -> str | None:
    """The message of the service's own errors, or None for anything else."""

    # Imported here, the svc module imports this one.
    from .feeds import FeedError
    from .rulesvc import RuleSvcError
    from .snort import SnortError
    from .suricata import SuricataError
    from .svc import PcapSvcError

    if isinstance(err, (PcapSvcError, RuleSvcError, SnortError, SuricataError, FeedError)):
        return err.mesg
    if isinstance(err, (ValueError, TypeError)):
        # Bad input from Storm, ex. a non-numeric value.
        return f"Invalid input: {err}"
    return None


async def _retn(coro: Awaitable) -> TelepathRetn:
    """Await a PcapSvc call and wrap the result (or error) in a TelepathRetn."""

    try:
        data = await coro
    except Exception as err:
        if (mesg := _errMesg(err)) is None:
            raise
        return TelepathRetn(status=False, mesg=mesg, data=None)
    return TelepathRetn(status=True, mesg="", data=data)


async def _retnGenr(genr: AsyncIterator) -> AsyncIterator[TelepathRetn]:
    """Wrap each item from a PcapSvc generator in a TelepathRetn.

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
    meth.__qualname__ = f"PcapCellApi.{name}"
    meth.__doc__ = f"Call PcapSvc.{name}() and return a TelepathRetn."
    return meth


def _genrMeth(name: str):
    async def meth(self, *args, **kwargs) -> AsyncIterator[TelepathRetn]:
        async for item in _retnGenr(getattr(self.cell, name)(*args, **kwargs)):
            yield item

    meth.__name__ = name
    meth.__qualname__ = f"PcapCellApi.{name}"
    meth.__doc__ = f"Yield the items of PcapSvc.{name}(), each wrapped in a TelepathRetn."
    return meth


class PcapCellApi(s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the slib.pcap service.

    Every method returns a ``TelepathRetn`` (or yields them, for generators).
    """

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

    async def checkDecodeAs(self, rules: list[str]) -> TelepathRetn:
        """Validate tshark "Decode As" rules, returning them normalized (see ``PcapSvc``)."""

        return self.cell.checkDecodeAs(rules)


for _name in RETN_METHS:
    setattr(PcapCellApi, _name, _retnMeth(_name))

for _name in GENR_METHS:
    setattr(PcapCellApi, _name, _genrMeth(_name))
