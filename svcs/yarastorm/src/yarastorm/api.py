"""The CellApi implementation for yarastorm."""

import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc
from stormlibpp.telepath import BoolRetn, ListRetn, TelepathRetn
from stormlibpp.utils import normver

from .defs import ADMIN_PERM, PKGDEFS, SVC_EVTS, SVC_NAME, SVC_VER


class YaraApi(s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the yarastorm service.

    Methods that change the service's rules require the service user that the Cortex
    connects with to have the ``slib.yara.admin`` permission on the service (the service's
    root user, the default, has it).
    """

    _storm_svc_name = SVC_NAME
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS
    _storm_svc_pkgs = PKGDEFS

    def _denied(self) -> BoolRetn | None:
        """A failed BoolRetn if this API's user can't change the service's rules."""

        if self.user.allowed(ADMIN_PERM):
            return None
        perm = ".".join(ADMIN_PERM)
        return BoolRetn(
            status=False,
            mesg=f"The service user {self.user.name} needs the {perm} permission.",
            data=False,
        )

    async def matchFile(self, file_sha256: str):
        """Test if the service's Yara rules match a given file in the Axon."""

        async for retn in self.cell.matchFile(file_sha256):
            yield retn

    async def compileRule(self, yara_rule, check: bool = False) -> BoolRetn:
        """Compile the given Yara rule and save it to this Cell's storage.

        Only checking a rule (``check=True``) doesn't need the admin permission.
        """

        if not check and (denied := self._denied()) is not None:
            return denied
        return await self.cell.compileRule(yara_rule, check)

    async def removeRule(self, rule_id: str) -> BoolRetn:
        """Remove a compiled Yara rule from this Cell's storage."""

        if (denied := self._denied()) is not None:
            return denied
        return await self.cell.removeRule(rule_id)

    async def listRules(self) -> ListRetn:
        """List the IDs of the compiled Yara rules this service scans with."""

        return await self.cell.listRules()

    async def getRuleCount(self) -> TelepathRetn:
        """Get the number of compiled Yara rules this service scans with."""

        return await self.cell.getRuleCount()
