"""The yarastorm service."""

import asyncio
import logging
import os
import stat
import tempfile
from collections.abc import AsyncGenerator
from typing import TypedDict

import synapse.common as s_common
import synapse.exc as s_exc
import synapse.lib.cell as s_cell
import synapse.lib.coro as s_coro
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

SCAN_TIMEOUT = 60
"""The default number of seconds a single rule may spend scanning a file (``scan_timeout``)."""


def scanBytes(rules: yara_x.Rules, byts: bytes, timeout: int) -> bool:
    """Scan ``byts`` with ``rules`` and return whether any of the rules matched.

    Runs the scan with a new ``yara_x.Scanner`` (so it's safe to call from a worker thread)
    that gives up after ``timeout`` seconds with a ``yara_x.TimeoutError``.
    """

    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(timeout)
    return bool(scanner.scan(byts).matching_rules)


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

    ``data`` is a ``YaraMatch`` when the result is about a specific rule (including a scan
    with that rule that failed or timed out, which has ``status=False``), or ``None`` when the
    file itself couldn't be scanned.
    """

    data: YaraMatch | None


class YaraRules:
    """Manage the Yara rules that a YaraSvc uses.

    Compiled rules are saved as flat files in ``ruledir``, named by the rule's
    ``it:app:yara:rule`` guid. Only top-level files with a guid name are rules.

    The rule files on disk are the source of truth: ``load()`` brings ``rules`` in line with
    them, so a rule file added, replaced, or removed by something other than this object
    (ex. another process or a restored backup) is picked up the next time it's called.

    Parameters
    ----------
    ruledir : str
        The directory that compiled Yara rules are saved in.
    """

    def __init__(self, ruledir: str) -> None:
        self.ruledir = ruledir
        self.rules: dict[str, yara_x.Rules] = {}
        # The (mtime_ns, size) of each rule file when it was last read, loaded or not. Used to
        # only re-read files that changed, and to only log an unreadable file once.
        self._stats: dict[str, tuple[int, int]] = {}
        # The rule files that couldn't be loaded, and why.
        self.bad: dict[str, str] = {}
        os.makedirs(self.ruledir, exist_ok=True)
        self.load()

    def _path(self, rule_id: str) -> str:
        """The on-disk path of a rule, raises ``BadArg`` if the ID is not a guid."""

        if not isRuleId(rule_id):
            raise s_exc.BadArg(mesg=f"Invalid Yara rule ID: {rule_id!r}")
        return os.path.join(self.ruledir, rule_id)

    @staticmethod
    def _stat(rpath: str) -> tuple[int, int] | None:
        """The (mtime_ns, size) of a regular file, or ``None`` if it isn't one."""

        try:
            info = os.stat(rpath)
        except OSError:
            return None
        if not stat.S_ISREG(info.st_mode):
            return None
        return (info.st_mtime_ns, info.st_size)

    def load(self) -> None:
        """Bring the in-memory rules in line with the rule files in ``ruledir``.

        New and changed rule files are (re)loaded, and rules whose file is gone are dropped.
        Only top-level files named with a guid are rules, anything else in ``ruledir`` (sub
        directories, temp files, etc.) is skipped. A file that can't be read is logged once
        and skipped until it changes.
        """

        try:
            fnames = os.listdir(self.ruledir)
        except FileNotFoundError:
            fnames = []

        ondisk = {}
        for fname in fnames:
            if not isRuleId(fname):
                continue
            fstat = self._stat(os.path.join(self.ruledir, fname))
            if fstat is not None:
                ondisk[fname] = fstat

        for rule_id in (self._stats.keys() | self.rules.keys()) - ondisk.keys():
            self._forget(rule_id)

        for rule_id, fstat in ondisk.items():
            if self._stats.get(rule_id) != fstat:
                self.load_rule(os.path.join(self.ruledir, rule_id))

    def _forget(self, rule_id: str) -> None:
        """Drop everything this object knows about a rule."""

        self._stats.pop(rule_id, None)
        self.rules.pop(rule_id, None)
        self.bad.pop(rule_id, None)

    def load_rule(self, rpath: str) -> None:
        """Load a Yara rule into this object.

        A loaded rule is stored in ``rules`` with a key of the file's basename.
        This should equate to the Yara rule's Synapse guid.

        The value is a compiled ``yara_x.Rules`` object. A missing file is forgotten. A file
        that can't be deserialized (ex. a corrupt file, or one from an incompatible yara-x)
        is logged, recorded in ``bad``, and any previously loaded copy of the rule is
        dropped, so one bad file can't stop the service from starting or a scan from
        finishing.

        Returns
        -------
        None
        """

        rule_id = os.path.basename(rpath)
        fstat = self._stat(rpath)
        try:
            with open(rpath, "rb") as fd:
                rule = yara_x.Rules.deserialize_from(fd)
        except FileNotFoundError:
            self._forget(rule_id)
            return
        except Exception as err:
            logger.warning("Skipping unreadable compiled Yara rule %s: %s", rpath, err)
            self.rules.pop(rule_id, None)
            self.bad[rule_id] = str(err)
            if fstat is not None:
                self._stats[rule_id] = fstat
            return

        self.rules[rule_id] = rule
        self.bad.pop(rule_id, None)
        if fstat is not None:
            self._stats[rule_id] = fstat

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
            rpath = os.path.join(self.ruledir, rule_id)
            if self._stats.get(rule_id) != self._stat(rpath):
                self.load_rule(rpath)

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
            fstat = self._stat(rule_path)
        except BaseException:
            try:
                os.remove(tmp_path)
            except FileNotFoundError:
                pass
            raise

        self.rules[rule_id] = compiled_rule
        self.bad.pop(rule_id, None)
        if fstat is not None:
            self._stats[rule_id] = fstat

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
        existed = rule_id in self.rules or rule_id in self.bad
        self._forget(rule_id)

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
            "Axon to scan. Larger files are not scanned. No limit if unset. The whole file "
            "is held in memory while it's scanned, so set this to bound the service's memory "
            "use.",
        },
        "scan_timeout": {
            "type": "integer",
            "minimum": 1,
            "default": SCAN_TIMEOUT,
            "description": "The number of seconds one rule may spend scanning one file before "
            "the scan of that file with that rule is abandoned and reported as an error.",
        },
    }

    async def __anit__(self, dirn, *args, **kwargs):
        await s_cell.Cell.__anit__(self, dirn, *args, **kwargs)
        self.axonurl = self.conf.get("axon_url")
        self.maxsize = self.conf.get("max_size")
        self.scantimeout = self.conf.get("scan_timeout")
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
        """Test if the service's Yara rules match the given file in the Axon.

        Yields one ``MatchRetn`` per rule file in ``rule_dir`` (rule files added, changed, or
        removed since the last call are picked up first), or a single file-level error. A
        rule file that can't be loaded yields a ``status=False`` result for that rule. Each rule is scanned in a worker thread, with a ``scan_timeout``.

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

        # Pick up rule files added, replaced, or removed on disk since the last scan.
        self.rules.load()

        for rule_id, err in list(self.rules.bad.items()):
            yield MatchRetn(
                status=False,
                mesg=f"Couldn't load {RULE_FORM}={rule_id} from the service's storage: {err}",
                data=YaraMatch(rule=rule_id, sha256=file_sha256, matched=False),
            )

        for rule_id, rule_obj in list(self.rules.rules.items()):
            try:
                # Scans are CPU bound, so run them off the event loop.
                matched = await s_coro.executor(
                    scanBytes, rule_obj, file_bytes, self.scantimeout
                )
            except asyncio.CancelledError:  # pragma: no cover
                raise
            except yara_x.TimeoutError:
                yield MatchRetn(
                    status=False,
                    mesg=f"Scanning with {RULE_FORM}={rule_id} timed out after "
                    f"{self.scantimeout} seconds (scan_timeout).",
                    data=YaraMatch(rule=rule_id, sha256=file_sha256, matched=False),
                )
                continue
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
        """List the IDs of the rule files in this service's ``rule_dir``.

        Reflects the rule files on disk (see ``YaraRules.load``), including ones that couldn't
        be loaded, so ``slib.yara.sync`` can recompile or remove them.
        """

        self.rules.load()
        return ListRetn(status=True, mesg="", data=sorted(self.rules.rules.keys() | self.rules.bad))

    async def getRuleCount(self) -> TelepathRetn:
        """Get the number of compiled Yara rules this service scans with (loaded rules only).

        Reflects the rule files on disk (see ``YaraRules.load``).
        """

        self.rules.load()
        return TelepathRetn(status=True, mesg="", data=len(self.rules.rules))
