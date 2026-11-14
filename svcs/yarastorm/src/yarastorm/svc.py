"""The yarastorm service."""

import asyncio
import logging
import os
import tempfile
from collections.abc import AsyncGenerator
from typing import TypedDict

import synapse.common as s_common
import synapse.exc as s_exc
import synapse.lib.cell as s_cell
import synapse.telepath as s_telepath
import yara_x
from stormlibpp import utils
from stormlibpp.node import NodeTuple, StormNode
from stormlibpp.telepath import BoolRetn, ListRetn, TelepathRetn

from .api import YaraApi

logger = logging.getLogger(__name__)

RULE_FORM = "it:app:yara:rule"
"""The Synapse form of the nodes that this service compiles Yara rules from."""

AXON_TIMEOUT = 10
"""The number of seconds to wait for the Axon connection before a scan fails."""


def isRuleId(rule_id: str) -> bool:
    """Whether ``rule_id`` is a valid ``it:app:yara:rule`` guid.

    Rule IDs are used as file names in the rule directory, so anything else (``..``,
    path separators, etc.) is rejected.
    """

    return isinstance(rule_id, str) and s_common.isguid(rule_id)


class YaraMatch(TypedDict):
    """The results of a single Yara match attempt, either successful or unsuccessful."""

    rule: str
    sha256: str
    matched: bool


class MatchRetn(TelepathRetn):
    """A TelepathRetn that describes a Yara match on a file.

    ``data`` is a ``YaraMatch`` when the result is about a specific rule (including a rule
    that couldn't be loaded, which has ``status=False``), or ``None`` when the file itself
    couldn't be scanned.
    """

    data: YaraMatch | None


class YaraRules:
    """Manage the Yara rules that a YaraSvc uses.

    Compiled rules are saved as flat files in ``ruledir``, named by the rule's
    ``it:app:yara:rule`` guid. Only top-level files with a guid name are rules.

    Parameters
    ----------
    ruledir : str
        The directory that compiled Yara rules are saved in.
    """

    def __init__(self, ruledir: str) -> None:
        self.ruledir = ruledir
        self.rules: dict[str, yara_x.Rules] = {}
        os.makedirs(self.ruledir, exist_ok=True)
        self.load()

    def _path(self, rule_id: str) -> str:
        """The on-disk path of a rule, raises ``BadArg`` if the ID is not a guid."""

        if not isRuleId(rule_id):
            raise s_exc.BadArg(mesg=f"Invalid Yara rule ID: {rule_id!r}")
        return os.path.join(self.ruledir, rule_id)

    def load(self) -> None:
        """Load all compiled Yara rules from the ruledir into this object.

        Only top-level files named with a guid are loaded, anything else in
        ``ruledir`` (sub directories, temp files, etc.) is skipped.
        """

        for fname in os.listdir(self.ruledir):
            if not isRuleId(fname):
                continue
            rpath = os.path.join(self.ruledir, fname)
            if os.path.isfile(rpath):
                self.load_rule(rpath)

    def load_rule(self, rpath: str) -> None:
        """Load a Yara rule into this object.

        A loaded rule is stored in ``rules`` with a key of the file's basename.
        This should equate to the Yara rule's Synapse guid.

        The value is a compiled ``yara_x.Rules`` object. Files that are missing or that
        can't be deserialized (ex. a corrupt or partially written file) are logged and
        skipped, so one bad file can't stop the service from starting or a scan from
        finishing.

        Returns
        -------
        None
        """

        try:
            with open(rpath, "rb") as fd:
                self.rules[os.path.basename(rpath)] = yara_x.Rules.deserialize_from(fd)
        except FileNotFoundError:
            return
        except Exception as err:
            logger.warning("Skipping unreadable compiled Yara rule %s: %s", rpath, err)

    def get(self, rule_id: str) -> yara_x.Rules | None:
        """Get a Yara rule from this object, loading from disk if needed.

        Will return None if the Yara rule is not known to this object and can't be
        loaded from disk, or if ``rule_id`` is not a valid rule ID. Never raises.

        Parameters
        ----------
        rule_id : str
            The ID of the rule, which should equate to the rule's file basename
            on disk. This should be the same as the GUID of the rule according
            to Synapse.

        Returns
        -------
        yara_x.Rules | None
            The compiled ``yara_x.Rules`` object from this object's memory. Or
            ``None`` if the rule is not stored in this object's memory and
            cannot be loaded from disk by the given ``rule_id``.
        """

        if not isRuleId(rule_id):
            return None

        if rule_id not in self.rules:
            self.load_rule(os.path.join(self.ruledir, rule_id))

        return self.rules.get(rule_id, None)

    def add(self, rule_id: str, compiled_rule: yara_x.Rules) -> None:
        """Write a compiled Yara rule to disk and store it in this object.

        Will overwrite any existing rule on disk or in the object with the same ``rule_id``.
        The rule is written to a temp file first and moved into place, so a crash can't
        leave a partially written rule behind.

        Parameters
        ----------
        rule_id : str
            The ID of the rule, which should equate to the rule's file basename
            on disk. This should be the same as the GUID of the rule according
            to Synapse.
        compiled_rule : yara_x.Rules
            The compiled Yara rule.

        Raises
        ------
        synapse.exc.BadArg
            If ``rule_id`` is not a guid.

        Returns
        -------
        None
        """

        rule_path = self._path(rule_id)

        fd, tmp_path = tempfile.mkstemp(dir=self.ruledir, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as fobj:
                compiled_rule.serialize_into(fobj)
            os.replace(tmp_path, rule_path)
        except BaseException:
            try:
                os.remove(tmp_path)
            except FileNotFoundError:
                pass
            raise

        self.rules[rule_id] = compiled_rule

    def remove(self, rule_id: str) -> bool:
        """Remove a Yara rule from this object and from disk.

        Parameters
        ----------
        rule_id : str
            The ID of the rule, which should equate to the rule's file basename
            on disk. This should be the same as the rule's node GUID.

        Raises
        ------
        synapse.exc.BadArg
            If ``rule_id`` is not a guid.

        Returns
        -------
        bool
            Whether the rule existed (in memory or on disk) before it was removed.
        """

        rule_path = self._path(rule_id)
        existed = self.rules.pop(rule_id, None) is not None

        try:
            os.remove(rule_path)
        except FileNotFoundError:
            return existed

        return True


class YaraSvc(s_cell.Cell):
    """The Cell implementation for the yarastorm service."""

    cellapi = YaraApi

    # The config keys keep their original underscore names so existing deployments
    # (SYN_YARASVC_AXON_URL, cell.yaml files, etc.) keep working.
    confdefs = {
        "axon_url": {
            "type": "string",
            "description": "The Telepath URL for an Axon service. "
            "This Axon is used to pull files for Yara matching.",
        },
        "rule_dir": {
            "type": "string",
            "description": "The directory that compiled Yara rules are saved in. "
            "A relative path is relative to the Cell's 'dirn' path, an absolute path is "
            "used as is.",
            "default": "rules/",
        },
        "max_size": {
            "type": "integer",
            "minimum": 1,
            "description": "The largest file, in bytes, that the service will pull from the "
            "Axon to scan. Larger files are not scanned. No limit if unset.",
        },
    }

    async def __anit__(self, dirn, *args, **kwargs):
        await s_cell.Cell.__anit__(self, dirn, *args, **kwargs)
        self.axonurl = self.conf.get("axon_url")
        self.maxsize = self.conf.get("max_size")
        self.rules = YaraRules(utils.absjoin(self.dirn, self.conf.get("rule_dir")))

        # One Telepath client for every scan, it reconnects on its own if the Axon goes away.
        self.axon: s_telepath.Client | None = None
        if self.axonurl:
            self.axon = await s_telepath.Client.anit(self.axonurl)
            self.onfini(self.axon)
        else:
            logger.warning(
                "The yarastorm service has no axon_url configured, slib.yara.scan will not "
                "be able to scan files."
            )

    async def _getBytes(self, sha256: str) -> bytes | None:
        """Get a file's bytes from the Axon.

        Returns ``None`` if the file is not in the Axon or is empty.

        Raises
        ------
        synapse.exc.BadArg
            If the service has no ``axon_url``, ``sha256`` is not a sha256 hex string,
            or the file is larger than ``max_size``.
        TimeoutError
            If the Axon can't be reached.
        """

        if self.axon is None:
            raise s_exc.BadArg(mesg="The yarastorm service has no axon_url configured.")

        if not isinstance(sha256, str) or len(sha256) != 64:
            raise s_exc.BadArg(mesg=f"Invalid sha256: {sha256!r}")
        try:
            shabyts = bytes.fromhex(sha256)
        except ValueError:
            raise s_exc.BadArg(mesg=f"Invalid sha256: {sha256!r}") from None

        axon = await self.axon.proxy(timeout=AXON_TIMEOUT)

        if self.maxsize is not None:
            size = await axon.size(shabyts)
            if size is None:
                return None
            if size > self.maxsize:
                raise s_exc.BadArg(
                    mesg=f"The file is {size} bytes, more than the {self.maxsize} byte "
                    "max (max_size)."
                )

        parts = []
        try:
            async for part in axon.get(shabyts):
                parts.append(part)
        except s_exc.NoSuchFile:
            return None

        if not parts:
            return None

        return b"".join(parts)

    async def matchFile(self, file_sha256: str) -> AsyncGenerator[MatchRetn, None]:
        """Test if the loaded Yara rules match the given file in the Axon.

        Never raises, errors are yielded as a ``MatchRetn`` with ``status=False``.
        """

        try:
            file_bytes = await self._getBytes(file_sha256)
        except asyncio.CancelledError:  # pragma: no cover
            raise
        except TimeoutError:
            yield MatchRetn(
                status=False,
                mesg=f"Unable to connect to the Axon within {AXON_TIMEOUT} seconds.",
                data=None,
            )
            return
        except s_exc.SynErr as err:
            yield MatchRetn(status=False, mesg=err.get("mesg") or str(err), data=None)
            return
        except Exception as err:
            yield MatchRetn(
                status=False, mesg=f"Unable to read the file from the Axon: {err}", data=None
            )
            return

        if file_bytes is None:
            yield MatchRetn(
                status=False,
                mesg=f"Bytes for file:bytes:sha256={file_sha256} are not in the Axon.",
                data=None,
            )
            return

        for rule_id in list(self.rules.rules):
            rule_obj = self.rules.get(rule_id)
            if rule_obj is None:
                yield MatchRetn(
                    status=False,
                    mesg=f"Couldn't load {RULE_FORM}={rule_id} from the service's storage.",
                    data=YaraMatch(rule=rule_id, sha256=file_sha256, matched=False),
                )
                continue

            try:
                matched = bool(rule_obj.scan(file_bytes).matching_rules)
            except Exception as err:
                yield MatchRetn(
                    status=False,
                    mesg=f"Error scanning with {RULE_FORM}={rule_id}: {err}",
                    data=YaraMatch(rule=rule_id, sha256=file_sha256, matched=False),
                )
                continue

            yield MatchRetn(
                status=True,
                mesg="",
                data=YaraMatch(rule=rule_id, sha256=file_sha256, matched=matched),
            )

    async def compileRule(self, yara_rule: NodeTuple, check: bool = False) -> BoolRetn:
        """Compile the given Yara rule and save it to this Cell's storage.

        With ``check=True`` the rule is only compiled, not saved.
        """

        try:
            rulenode = StormNode.unpack(yara_rule)
        except Exception:
            return BoolRetn(status=False, mesg="Invalid packed node.", data=False)

        if rulenode.form != RULE_FORM:
            return BoolRetn(
                status=False,
                mesg=f"Expected an {RULE_FORM} node, got {rulenode.form}.",
                data=False,
            )

        if not isRuleId(rulenode.value):
            return BoolRetn(
                status=False, mesg=f"Invalid {RULE_FORM} guid: {rulenode.value!r}", data=False
            )

        if not rulenode.props["text"]:
            return BoolRetn(
                status=False,
                mesg=f"{RULE_FORM}={rulenode.value} has no :text to compile.",
                data=False,
            )

        try:
            rule = yara_x.compile(rulenode.props["text"])
        except yara_x.CompileError as err:
            return BoolRetn(status=False, mesg=f"Yara Compile Error - {err}", data=False)

        if check:
            return BoolRetn(status=True, mesg="Successfully compiled rule!", data=True)

        try:
            self.rules.add(rulenode.value, rule)
        except Exception as err:
            return BoolRetn(status=False, mesg=f"Unable to save the rule: {err}", data=False)

        return BoolRetn(status=True, mesg="", data=True)

    async def removeRule(self, rule_id: str) -> BoolRetn:
        """Remove a compiled Yara rule from this Cell's storage.

        ``data`` is whether the service had the rule. Removing a rule the service doesn't
        have is not an error.
        """

        if not isRuleId(rule_id):
            return BoolRetn(status=False, mesg=f"Invalid {RULE_FORM} guid: {rule_id!r}", data=False)

        try:
            existed = self.rules.remove(rule_id)
        except Exception as err:
            return BoolRetn(status=False, mesg=f"Unable to remove the rule: {err}", data=False)

        return BoolRetn(status=True, mesg="", data=existed)

    async def listRules(self) -> ListRetn:
        """List the IDs of the compiled Yara rules this service scans with."""

        return ListRetn(status=True, mesg="", data=sorted(self.rules.rules))

    async def getRuleCount(self) -> TelepathRetn:
        """Get the number of compiled Yara rules this service scans with."""

        return TelepathRetn(status=True, mesg="", data=len(self.rules.rules))
