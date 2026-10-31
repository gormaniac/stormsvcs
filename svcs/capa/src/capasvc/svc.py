"""The slib.capa service.

``CapaSvc`` runs Mandiant's capa (https://github.com/mandiant/capa) against files it
pulls from an Axon, and serves the capa rules it uses (see ``capasvc.rules``) so the
Storm package can model them. Methods raise ``CapaSvcError`` (or ``CapaRulesError``)
on failure, ``CapaCellApi`` wraps them in the standard ``TelepathRetn`` convention.
"""

import asyncio
import collections
import json
import logging
import os
import re
import shutil
import sys
import time
from collections.abc import AsyncIterator
from typing import Any

import capa.rules
import synapse.common as s_common
import synapse.exc as s_exc
import synapse.lib.cell as s_cell
import synapse.lib.coro as s_coro
import synapse.telepath as s_telepath

from .api import CapaCellApi, CapaSvcError
from .custom import CustomRules
from .defs import RULES_URL, RULES_VERSION
from .rules import CapaRules, CapaRulesError, ruleRecord, rulesSha256, rulesStat


logger = logging.getLogger(__name__)

FORMATS = ("auto", "pe", "dotnet", "elf", "sc32", "sc64")
"""The capa input formats the service supports, ``auto`` lets capa detect it.

Formats that describe another file are left out: sandbox reports (cape, drakvuf, vmray) and
frozen features (freeze). Their results are about the sample they came from, not the file
that was scanned.
"""

OSES = ("auto", "windows", "linux", "macos")
"""The OS values capa accepts, ``auto`` lets capa detect it."""

AXON_TIMEOUT = 30
"""Seconds to wait for the Axon connection before a scan fails."""

MAX_CUSTOM_SETS = 16
"""The max number of custom rule sets the service keeps (the least recently used go first)."""

CUSTOM_RETRY = 60
"""Seconds before capa tries a custom rule set it couldn't load again (ex. it ran out of memory)."""

MAX_ADDRS = 100
"""The max number of match addresses kept per rule."""

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

EXIT_CODES = {
    10: "capa could not find its rules",
    11: "capa could not find the file",
    12: "capa found an invalid rule",
    13: "The file is corrupt",
    14: "capa can't analyze the file (ex. it's packed or an installer)",
    15: "capa found an invalid FLIRT signature",
    16: "The file is not a format capa supports",
    17: "The file is for an architecture capa doesn't support",
    18: "The file is for an OS capa doesn't support",
    25: "The input format is invalid",
    26: "capa couldn't load a feature extractor for the file",
}
"""Messages for capa's exit codes (``capa.main.E_*``)."""

LOG_PREFIX_RE = re.compile(r"^(ERROR|WARNING|CRITICAL)\s+capa:\s*")
LOG_SUFFIX_RE = re.compile(r"\s+\S+\.py:\d+\s*$")


def stderrMesg(text: str) -> str:
    """Condense capa's (rich formatted) log output into a single line message."""

    parts = []
    for line in text.splitlines():
        line = LOG_PREFIX_RE.sub("", LOG_SUFFIX_RE.sub("", line.strip())).strip()
        if not line or set(line) <= set("-─"):
            continue
        parts.append(line)
    return " ".join(parts)


def fmtAddr(addr: Any) -> str | None:
    """Format a capa result document address, or None for file scope (``no address``) matches."""

    if not isinstance(addr, dict):
        return str(addr)

    kind = addr.get("type")
    valu = addr.get("value")
    if kind in (None, "no address"):
        return None
    if kind == "absolute" and isinstance(valu, int):
        return hex(valu)
    if isinstance(valu, int):
        return f"{kind}:{hex(valu)}"
    return f"{kind}:{json.dumps(valu, sort_keys=True)}"


class CapaSvc(s_cell.Cell):
    """The Cell implementation for the slib.capa service."""

    cellapi = CapaCellApi

    confdefs = {
        "axon:url": {
            "type": "string",
            "description": "The Telepath URL of the Axon the service pulls files to scan from.",
        },
        "capa:rules": {
            "type": "string",
            "description": (
                "The capa rules directory. The service's container image bundles the capa-rules "
                "release that matches its version of capa."
            ),
        },
        "capa:rules:version": {
            "type": "string",
            "default": RULES_VERSION,
            "description": "The version of the rules in capa:rules, used for rule URLs and names.",
        },
        "capa:rules:url": {
            "type": "string",
            "default": RULES_URL,
            "description": (
                "A template for a rule's URL, given {version} and {path} (the rule's path in "
                "capa:rules). Set to an empty string for no URLs."
            ),
        },
        "capa:sigs": {
            "type": "string",
            "description": (
                "A directory of FLIRT signatures capa uses to recognize library code in PE "
                "files. Library code is analyzed like any other code without them."
            ),
        },
        "capa:timeout": {
            "type": "integer",
            "default": 900,
            "minimum": 1,
            "description": "Seconds before a capa run is killed.",
        },
        "capa:workers": {
            "type": "integer",
            "default": 2,
            "minimum": 1,
            "description": "The max number of files capa analyzes at once.",
        },
        "capa:maxsize": {
            "type": "integer",
            "default": 104857600,
            "minimum": 1,
            "description": "The max size (in bytes) of a file the service will scan.",
        },
    }

    async def __anit__(self, dirn, *args, **kwargs):
        await s_cell.Cell.__anit__(self, dirn, *args, **kwargs)

        self.workdir = s_common.gendir(self.dirn, "capa", "work")
        self.cachedir = s_common.gendir(self.dirn, "capa", "cache")
        self.nosigsdir = s_common.gendir(self.dirn, "capa", "nosigs")
        # Custom rule sets are sent again by Storm before it scans, so they don't outlive a run.
        shutil.rmtree(s_common.genpath(self.dirn, "capa", "custom"), ignore_errors=True)
        self.customdir = s_common.gendir(self.dirn, "capa", "custom")
        # Custom rule sets by key (least recently used first), the error (or None) and time of
        # building capa's cache for each, and how many scans are using each.
        self.customSets: collections.OrderedDict[str, CustomRules] = collections.OrderedDict()
        self.customBuilt: dict[str, tuple[str | None, float]] = {}
        self.customUse: collections.Counter[str] = collections.Counter()

        # Leftovers from a run that was killed with the service.
        for name in os.listdir(self.workdir):
            os.unlink(os.path.join(self.workdir, name))

        # One Telepath client for every scan, it reconnects on its own if the Axon goes away.
        self.axon: s_telepath.Client | None = None
        if url := self.conf.get("axon:url"):
            self.axon = await s_telepath.Client.anit(url)
            self.onfini(self.axon)

        self.sema = asyncio.Semaphore(self.conf.get("capa:workers"))
        self.procs: set[asyncio.subprocess.Process] = set()
        self.onfini(self._killProcs)

        self.capaRules: CapaRules | None = None
        self.rulesErr: str | None = None
        # Set once capa's rules cache is built, see _warmCache.
        self.cacheReady = asyncio.Event()
        self.cacheReady.set()
        # Only one cache build runs at a time, capa skips a build if the cache file exists,
        # even if another build is still writing it.
        self.cacheLock = asyncio.Lock()
        try:
            await self.reload()
        except (CapaSvcError, CapaRulesError):
            # The service still starts so the error can be reported to Storm (see rulesErr).
            pass

    async def _killProcs(self) -> None:
        for proc in list(self.procs):
            self._endProc(proc)

    def _endProc(self, proc: asyncio.subprocess.Process) -> None:
        """Stop tracking a subprocess, killing it if it's still running."""

        self.procs.discard(proc)
        if proc.returncode is None:
            proc.kill()

    # ---- Rules ----

    async def reload(self) -> dict[str, Any]:
        """(Re)load the capa rules from ``capa:rules``. Returns ``rulesInfo()``."""

        path = self.conf.get("capa:rules")
        if not path:
            self.capaRules = None
            self.rulesErr = "The slib.capa service has no capa:rules directory configured."
            logger.warning(self.rulesErr)
            raise CapaSvcError(self.rulesErr)

        try:
            self.capaRules = await s_coro.executor(
                CapaRules,
                path,
                self.conf.get("capa:rules:version"),
                self.conf.get("capa:rules:url"),
            )
        except CapaRulesError as err:
            self.capaRules = None
            self.rulesErr = err.mesg
            logger.warning(f"Unable to load the capa rules: {err.mesg}")
            raise

        self.rulesErr = None
        # Custom rule sets were checked against the old rules, Storm sends them again.
        self.customSets.clear()
        self.customBuilt.clear()
        info = self.capaRules.info()
        logger.info(
            f"Loaded {info['rules']} capa rules ({info['version']}, sha256={info['sha256']})"
        )
        self.cacheReady = asyncio.Event()
        self.schedCoro(self._warmCache(self.capaRules, self.cacheReady))
        return info

    async def _warmCache(self, rules: CapaRules, ready: asyncio.Event) -> None:
        """Have capa build its cache of the rules, so the first scan doesn't have to.

        capa takes several seconds to parse its rules without a cache, it caches them in
        ``capa/cache`` in the service's storage. Scans wait for ``ready``, capa doesn't write
        the cache atomically so a scan could read a partial cache while it's built.
        """

        try:
            async with self.cacheLock:
                # A reload since this was scheduled has its own build.
                if self.capaRules is rules:
                    await self._buildCache(rules)
        finally:
            ready.set()

    async def _buildCache(self, rules: CapaRules) -> None:

        if (mesg := await self._runCacheBuild([rules.path])) is not None:
            logger.warning(f"Unable to build the capa rules cache: {mesg}")
            return

        self._cleanCache(rules)

    async def _runCacheBuild(self, paths: list[str]) -> str | None:
        """Have capa load (and cache) the rules in these directories.

        Returns
        -------
        str | None
            capa's error if it couldn't load the rules (ex. a rule needs a missing rule).
        """

        try:
            proc = await asyncio.create_subprocess_exec(
                *self._cacheCmd(paths),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            self.procs.add(proc)
            timeout = self.conf.get("capa:timeout")
            try:
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except TimeoutError:
                return f"capa took longer than {timeout} seconds (capa:timeout) to load the rules"
            finally:
                # Kills it if it timed out.
                self._endProc(proc)
        except Exception as err:  # pragma: no cover - the cache is only an optimization
            return str(err)

        if proc.returncode != 0:
            return stderrMesg(stderr.decode("utf-8", "replace")) or f"exit code {proc.returncode}"
        return None

    def _cacheCmd(self, paths: list[str]) -> list[str]:
        """The command line that has capa load (and cache) the rules in these directories."""

        code = (
            "import pathlib, sys, capa.rules; "
            "capa.rules.get_rules([pathlib.Path(p) for p in sys.argv[2:]], "
            "cache_dir=pathlib.Path(sys.argv[1]))"
        )
        return [sys.executable, "-c", code, self.cachedir, *paths]

    def _cleanCache(self, rules: CapaRules) -> None:
        """Delete capa's caches of rules other than these (ex. an older version of the rules).

        The caches of the custom rule sets in use with these rules are kept. Nothing is deleted
        if these aren't the loaded rules anymore (they were reloaded), the reload cleans up.
        """

        if self.capaRules is not rules:
            return

        keep = {rules.cacheName(self.cachedir)}
        keep.update(
            cs.cacheName(self.cachedir) for cs in self.customSets.values() if cs.official is rules
        )
        for name in os.listdir(self.cachedir):
            if name in keep or not (name.startswith("capa-") and name.endswith(".cache")):
                continue
            try:
                os.unlink(os.path.join(self.cachedir, name))
            except OSError as err:  # pragma: no cover - the cache is only an optimization
                logger.warning(f"Unable to delete the old capa rules cache {name}: {err}")
                continue
            logger.info(f"Deleted the old capa rules cache {name}")

    def _getRules(self) -> CapaRules:
        if self.capaRules is None:
            raise CapaSvcError(self.rulesErr or "The capa rules are not loaded.")
        return self.capaRules

    async def rulesInfo(self) -> dict[str, Any]:
        """A summary of the loaded capa rules (path, version, sha256, counts) and capa itself."""

        import capa.version

        info = self._getRules().info()
        info["capa"] = capa.version.__version__
        return info

    async def rules(self, names: list[str] | None = None) -> AsyncIterator[dict[str, Any]]:
        """Yield the record of every capa rule (or the named ones), sorted by name."""

        rules = self._getRules().rules
        if names:
            missing = [n for n in names if n not in rules]
            if missing:
                raise CapaSvcError(f"Unknown capa rules: {', '.join(missing)}")
            keys = sorted(set(names))
        else:
            keys = sorted(rules)

        for name in keys:
            yield rules[name]
            await asyncio.sleep(0)

    async def custom(self, rules: list[dict[str, Any]]) -> dict[str, Any]:
        """Check a set of custom capa rules and save them for scans.

        Parameters
        ----------
        rules : list[dict]
            The custom rules, each a dict of the ``guid`` of its ``meta:rule`` and its ``text``.

        Returns
        -------
        dict
            The set's ``key`` (pass it to ``scan``, None if no rule can be used), its ``rules``,
            and the rules that were skipped: ``errors`` (invalid rules) and ``shadowed`` (an
            official rule has the same name).
        """

        official = self._getRules()
        if not isinstance(rules, (list, tuple)):
            raise CapaSvcError("Custom rules must be a list of {guid, text} dicts.")
        rules = [dict(r) if isinstance(r, dict) else {} for r in rules]

        cset = await s_coro.executor(CustomRules, official, rules, self.customdir)
        if cset.key is not None and self.capaRules is official:
            known = self.customSets.get(cset.key)
            if known is None or known.official is not official:
                self.customSets[cset.key] = cset
            self.customSets.move_to_end(cset.key)
            self._pruneCustom()
        return cset.info()

    def _pruneCustom(self) -> None:
        """Delete the least recently used custom rule sets, past ``MAX_CUSTOM_SETS``.

        Sets in use by a scan are kept. A deleted set is sent again by the next scan with it.
        """

        for key in list(self.customSets):
            if len(self.customSets) <= MAX_CUSTOM_SETS:
                return
            if self.customUse[key]:
                continue

            cset = self.customSets.pop(key)
            self.customBuilt.pop(key, None)
            shutil.rmtree(cset.path, ignore_errors=True)
            cache = os.path.join(self.cachedir, cset.cacheName(self.cachedir))
            if os.path.exists(cache):
                os.unlink(cache)
            logger.info(f"Deleted the least recently used custom capa rules {key}")

    async def _prepCustom(self, rules: CapaRules, key: str) -> CustomRules:
        """The custom rule set for a scan, with capa's cache of it built (once).

        Raises
        ------
        CapaSvcError
            If the set is unknown, or capa can't load it with the official rules.
        """

        def current() -> CustomRules:
            cset = self.customSets.get(key)
            if cset is None or cset.official is not rules or self.capaRules is not rules:
                raise CapaSvcError(
                    "Unknown custom capa rules (the service restarted, reloaded its rules, or "
                    "deleted the set), send them again with custom()."
                )
            return cset

        def needsBuild() -> bool:
            built = self.customBuilt.get(key)
            # Failures are tried again after a while, they may not happen again.
            return built is None or (
                built[0] is not None and time.monotonic() - built[1] > CUSTOM_RETRY
            )

        cset = current()
        self.customSets.move_to_end(key)

        if needsBuild():
            async with self.cacheLock:
                # A reload (or prune) while this waited makes the set unknown.
                cset = current()
                if needsBuild():
                    mesg = await self._runCacheBuild([rules.path, cset.path])
                    self.customBuilt[key] = (mesg, time.monotonic())
                    if mesg is None:
                        self._cleanCache(rules)

        if (mesg := self.customBuilt[key][0]) is not None:
            raise CapaSvcError(f"capa can't use the custom rules: {mesg}")
        return cset

    async def tags(self) -> list[dict[str, Any]]:
        """The record of every tag (without a prefix) the rules' namespaces become."""

        return self._getRules().tagRecords()

    # ---- Scanning ----

    async def scan(
        self,
        sha256: str,
        fmt: str = "auto",
        osname: str = "auto",
        custom: str | None = None,
    ) -> dict[str, Any]:
        """Pull a file from the Axon, run capa against it, and return a summary of the results.

        Parameters
        ----------
        sha256 : str
            The SHA256 of the file in the Axon.
        fmt : str
            The capa input format, one of ``FORMATS``.
        osname : str
            The OS of the file, one of ``OSES``.
        custom : str | None
            The key of a custom rule set (see ``custom``) to scan with, with the official rules.

        Returns
        -------
        dict
            The file's hashes, the analysis details (format, arch, os, flavor), the versions of
            capa and its rules, and ``matches``: the reported rules that matched, with each
            rule's record (see ``CapaRules.ruleRecord``) and match addresses.
        """

        sha256 = str(sha256).strip().lower()
        if not SHA256_RE.match(sha256):
            raise CapaSvcError(f"Invalid SHA256: {sha256}")
        if fmt not in FORMATS:
            raise CapaSvcError(f"Invalid format {fmt}, expected one of: {', '.join(FORMATS)}")
        if osname not in OSES:
            raise CapaSvcError(f"Invalid OS {osname}, expected one of: {', '.join(OSES)}")

        rules = self._getRules()
        await self.cacheReady.wait()

        if not custom:
            return await self._scan(rules, sha256, fmt, osname)

        # A set in use isn't pruned.
        self.customUse[custom] += 1
        try:
            cset = await self._prepCustom(rules, custom)
            return await self._scan(rules, sha256, fmt, osname, cset)
        finally:
            self.customUse[custom] -= 1
            if not self.customUse[custom]:
                del self.customUse[custom]

    async def _scan(
        self,
        rules: CapaRules,
        sha256: str,
        fmt: str,
        osname: str,
        cset: CustomRules | None = None,
    ) -> dict[str, Any]:
        """Fetch a file and run capa against it, see ``scan``."""

        async with self.sema:
            path = s_common.genpath(self.workdir, f"{sha256}.{s_common.guid()}")
            try:
                await self._fetch(sha256, path)
                # Checked right before capa runs, after any wait for a worker or the download.
                await self._checkRules(rules)
                doc = await self._runCapa(rules, path, fmt, osname, cset)
            finally:
                if os.path.exists(path):
                    os.unlink(path)

        res = self._summarize(rules, sha256, doc, cset)
        # What the scan asked for, capa's detected format and OS are "format" and "os".
        res["options"] = {"format": fmt, "os": osname}
        return res

    async def _checkRules(self, rules: CapaRules) -> None:
        """Make sure the rules on disk (that capa reads) are still the loaded rules.

        Raises
        ------
        CapaSvcError
            If the rules on disk changed or can't be read.
        """

        try:
            # Only stat the files, unless something about them changed.
            stat = await s_coro.executor(rulesStat, rules.path)
            if stat == rules.stat:
                return
            if await s_coro.executor(rulesSha256, rules.path) == rules.sha256:
                # Touched but unchanged, so the next scans only stat them again.
                rules.stat = stat
                return
        except CapaRulesError as err:
            raise CapaSvcError(f"The capa rules on disk can't be read: {err.mesg}") from None

        raise CapaSvcError(
            "The capa rules on disk changed since the service loaded them, reload them "
            "with: slib.capa.admin.sync --reload"
        )

    async def _fetch(self, sha256: str, path: str) -> None:
        """Save a file from the Axon to ``path``."""

        if self.axon is None:
            raise CapaSvcError("The slib.capa service has no axon:url configured.")

        maxsize = self.conf.get("capa:maxsize")
        byts = s_common.uhex(sha256)

        try:
            axon = await self.axon.proxy(timeout=AXON_TIMEOUT)
            size = await axon.size(byts)
            if size is None:
                raise CapaSvcError(f"The file {sha256} is not in the Axon.")
            if size > maxsize:
                raise CapaSvcError(
                    f"The file {sha256} is {size} bytes, more than the {maxsize} byte "
                    "max (capa:maxsize)."
                )
            # Disk writes run in a thread, so a large file doesn't block the service.
            fd = await s_coro.executor(open, path, "wb")
            try:
                async for chunk in axon.get(byts):
                    await s_coro.executor(fd.write, chunk)
            finally:
                await s_coro.executor(fd.close)
        except CapaSvcError:
            raise
        except TimeoutError:
            raise CapaSvcError(
                f"Unable to connect to the Axon within {AXON_TIMEOUT} seconds."
            ) from None
        except s_exc.NoSuchFile:
            raise CapaSvcError(f"The file {sha256} is not in the Axon.") from None
        except Exception as err:
            raise CapaSvcError(f"Unable to read {sha256} from the Axon: {err}") from None

    def _capaCmd(
        self,
        rules: CapaRules,
        path: str,
        fmt: str,
        osname: str,
        cset: CustomRules | None = None,
    ) -> list[str]:
        """The command line that runs capa against a file and prints its JSON results."""

        sigs = self.conf.get("capa:sigs") or self.nosigsdir
        custom = ["--rules", cset.path] if cset is not None else []
        return [
            sys.executable,
            "-m",
            "capa.main",
            "--json",
            "--quiet",
            "--rules",
            rules.path,
            *custom,
            "--signatures",
            sigs,
            "--format",
            fmt,
            "--os",
            osname,
            path,
        ]

    async def _runCapa(
        self,
        rules: CapaRules,
        path: str,
        fmt: str,
        osname: str,
        cset: CustomRules | None = None,
    ) -> dict[str, Any]:
        """Run capa against a file in a subprocess and return its result document."""

        timeout = self.conf.get("capa:timeout")
        env = dict(os.environ)
        # capa caches its parsed rules here (it uses $XDG_CACHE_HOME as-is).
        env["XDG_CACHE_HOME"] = self.cachedir
        env["COLUMNS"] = "1000"

        proc = await asyncio.create_subprocess_exec(
            *self._capaCmd(rules, path, fmt, osname, cset),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        self.procs.add(proc)
        try:
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except TimeoutError:
                proc.kill()
                await proc.wait()
                raise CapaSvcError(f"capa took longer than {timeout} seconds (capa:timeout).")
        finally:
            # Also covers a cancelled scan (ex. the Storm query was cancelled).
            self._endProc(proc)

        errmesg = stderrMesg(stderr.decode("utf-8", "replace"))
        if proc.returncode != 0:
            mesg = EXIT_CODES.get(proc.returncode, f"capa failed (exit code {proc.returncode})")
            if errmesg:
                mesg = f"{mesg}: {errmesg}"
            raise CapaSvcError(mesg)

        try:
            return await s_coro.executor(json.loads, stdout)
        except ValueError:
            raise CapaSvcError(f"capa returned invalid JSON: {errmesg}") from None

    def _unknownRecord(self, name: str, result: dict[str, Any]) -> dict[str, Any]:
        """The record of a rule capa reported that isn't a loaded rule, see ``ruleRecord``."""

        source = result.get("source")
        try:
            meta = capa.rules.Rule.from_yaml(source).meta
        except Exception:
            rmeta = result.get("meta", {})
            meta = {k: rmeta.get(k) for k in ("namespace", "description", "authors")}
        meta = dict(meta, name=name)
        return ruleRecord(meta, source)

    def _summarize(
        self,
        rules: CapaRules,
        sha256: str,
        doc: dict[str, Any],
        cset: CustomRules | None = None,
    ) -> dict[str, Any]:
        """Condense a capa result document into the results slib.capa models."""

        meta = doc.get("meta", {})
        sample = meta.get("sample", {})
        analysis = meta.get("analysis", {})

        matches = []
        for name, result in doc.get("rules", {}).items():
            rmeta = result.get("meta", {})
            # capa doesn't report library or subscope rules, they're parts of other rules.
            if rmeta.get("lib") or rmeta.get("is_subscope_rule"):
                continue

            record = rules.rules.get(name)
            if record is None and cset is not None:
                record = cset.records.get(name)
            if record is None:
                # Not a loaded rule (a safety net, scans check the rules on disk first), model
                # it from the source capa reported.
                record = self._unknownRecord(name, result)

            addrs = []
            for match in result.get("matches", ()):
                addr = fmtAddr(match[0] if isinstance(match, (list, tuple)) else match)
                if addr is not None:
                    addrs.append(addr)

            matches.append(
                {
                    "rule": record,
                    "count": len(result.get("matches", ())),
                    "addrs": addrs[:MAX_ADDRS],
                }
            )

        matches.sort(key=lambda m: m["rule"]["name"])

        return {
            "sha256": sample.get("sha256") or sha256,
            "md5": sample.get("md5"),
            "sha1": sample.get("sha1"),
            "time": s_common.now(),
            "capa": meta.get("version"),
            "rules": {
                "version": rules.version,
                "sha256": rules.sha256,
                "custom": cset.key if cset is not None else None,
            },
            "flavor": meta.get("flavor"),
            "format": analysis.get("format"),
            "arch": analysis.get("arch"),
            "os": analysis.get("os"),
            "extractor": analysis.get("extractor"),
            "matches": matches,
        }
