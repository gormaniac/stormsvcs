"""The slib.capa service.

``CapaSvc`` runs Mandiant's capa (https://github.com/mandiant/capa) against files it
pulls from an Axon, and serves the capa rules it uses (see ``capasvc.rules``) so the
Storm package can model them. Methods raise ``CapaSvcError`` (or ``CapaRulesError``)
on failure, ``CapaCellApi`` wraps them in the standard ``TelepathRetn`` convention.
"""


import asyncio
import json
import logging
import os
import re
import sys
from collections.abc import AsyncIterator
from typing import Any

import synapse.common as s_common
import synapse.exc as s_exc
import synapse.lib.cell as s_cell
import synapse.lib.coro as s_coro
import synapse.telepath as s_telepath

from .api import CapaCellApi, CapaSvcError
from .defs import RULES_URL, RULES_VERSION
from .rules import CapaRules, CapaRulesError, nsTag, ruleGuid


logger = logging.getLogger(__name__)

FORMATS = ("auto", "pe", "dotnet", "elf", "sc32", "sc64", "freeze")
"""The capa input formats the service supports, ``auto`` lets capa detect it.

Sandbox report formats (cape, drakvuf, vmray) are left out, their results describe
the sample the report is about, not the report file itself.
"""

OSES = ("auto", "windows", "linux", "macos")
"""The OS values capa accepts, ``auto`` lets capa detect it."""

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

        # Leftovers from a run that was killed with the service.
        for name in os.listdir(self.workdir):
            os.unlink(os.path.join(self.workdir, name))

        self.sema = asyncio.Semaphore(self.conf.get("capa:workers"))
        self.procs: set[asyncio.subprocess.Process] = set()
        self.onfini(self._killProcs)

        self.capaRules: CapaRules | None = None
        self.rulesErr: str | None = None
        # Set once capa's rules cache is built, see _warmCache.
        self.cacheReady = asyncio.Event()
        self.cacheReady.set()
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
                CapaRules, path, self.conf.get("capa:rules:version"),
                self.conf.get("capa:rules:url"),
            )
        except CapaRulesError as err:
            self.capaRules = None
            self.rulesErr = err.mesg
            logger.warning(f"Unable to load the capa rules: {err.mesg}")
            raise

        self.rulesErr = None
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
            await self._buildCache(rules)
        finally:
            ready.set()

    async def _buildCache(self, rules: CapaRules) -> None:

        code = (
            "import pathlib, sys, capa.rules; "
            "capa.rules.get_rules([pathlib.Path(sys.argv[1])], cache_dir=pathlib.Path(sys.argv[2]))"
        )
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-c", code, rules.path, self.cachedir,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
            )
            self.procs.add(proc)
            try:
                _, stderr = await proc.communicate()
            finally:
                self._endProc(proc)
        except Exception as err:  # pragma: no cover - the cache is only an optimization
            logger.warning(f"Unable to build the capa rules cache: {err}")
            return

        if proc.returncode != 0:
            mesg = stderrMesg(stderr.decode("utf-8", "replace"))
            logger.warning(f"Unable to build the capa rules cache: {mesg}")

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

    async def tags(self) -> list[dict[str, Any]]:
        """The record of every tag (without a prefix) the rules' namespaces become."""

        return self._getRules().tagRecords()

    # ---- Scanning ----

    async def scan(self, sha256: str, fmt: str = "auto", osname: str = "auto") -> dict[str, Any]:
        """Pull a file from the Axon, run capa against it, and return a summary of the results.

        Parameters
        ----------
        sha256 : str
            The SHA256 of the file in the Axon.
        fmt : str
            The capa input format, one of ``FORMATS``.
        osname : str
            The OS of the file, one of ``OSES``.

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

        async with self.sema:
            path = s_common.genpath(self.workdir, f"{sha256}.{s_common.guid()}")
            try:
                await self._fetch(sha256, path)
                doc = await self._runCapa(rules, path, fmt, osname)
            finally:
                if os.path.exists(path):
                    os.unlink(path)

        return self._summarize(rules, sha256, doc)

    async def _fetch(self, sha256: str, path: str) -> None:
        """Save a file from the Axon to ``path``."""

        url = self.conf.get("axon:url")
        if not url:
            raise CapaSvcError("The slib.capa service has no axon:url configured.")

        maxsize = self.conf.get("capa:maxsize")
        byts = s_common.uhex(sha256)

        try:
            async with s_telepath.withTeleEnv():
                async with await s_telepath.openurl(url) as axon:
                    size = await axon.size(byts)
                    if size is None:
                        raise CapaSvcError(f"The file {sha256} is not in the Axon.")
                    if size > maxsize:
                        raise CapaSvcError(
                            f"The file {sha256} is {size} bytes, more than the {maxsize} byte "
                            "max (capa:maxsize)."
                        )
                    with open(path, "wb") as fd:
                        async for chunk in axon.get(byts):
                            fd.write(chunk)
        except CapaSvcError:
            raise
        except s_exc.NoSuchFile:
            raise CapaSvcError(f"The file {sha256} is not in the Axon.") from None
        except Exception as err:
            raise CapaSvcError(f"Unable to read {sha256} from the Axon: {err}") from None

    def _capaCmd(self, rules: CapaRules, path: str, fmt: str, osname: str) -> list[str]:
        """The command line that runs capa against a file and prints its JSON results."""

        sigs = self.conf.get("capa:sigs") or self.nosigsdir
        return [
            sys.executable, "-m", "capa.main", "--json", "--quiet",
            "--rules", rules.path, "--signatures", sigs,
            "--format", fmt, "--os", osname,
            path,
        ]

    async def _runCapa(self, rules: CapaRules, path: str, fmt: str, osname: str) -> dict[str, Any]:
        """Run capa against a file in a subprocess and return its result document."""

        timeout = self.conf.get("capa:timeout")
        env = dict(os.environ)
        # capa caches its parsed rules here (it uses $XDG_CACHE_HOME as-is).
        env["XDG_CACHE_HOME"] = self.cachedir
        env["COLUMNS"] = "1000"

        proc = await asyncio.create_subprocess_exec(
            *self._capaCmd(rules, path, fmt, osname),
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

    def _summarize(self, rules: CapaRules, sha256: str, doc: dict[str, Any]) -> dict[str, Any]:
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
            if record is None:
                # The rules on disk changed since they were loaded, model what capa reported.
                namespace = rmeta.get("namespace") or None
                record = {
                    "guid": ruleGuid(name),
                    "name": name,
                    "namespace": namespace,
                    "tag": nsTag(namespace),
                    "lib": False,
                    "type": "capa",
                    "desc": rmeta.get("description") or None,
                    "text": result.get("source"),
                    "path": None,
                    "url": None,
                    "authors": [],
                    "techniques": [],
                    "meta": rmeta,
                }

            addrs = []
            for match in result.get("matches", ()):
                addr = fmtAddr(match[0] if isinstance(match, (list, tuple)) else match)
                if addr is not None:
                    addrs.append(addr)

            matches.append({
                "rule": record,
                "count": len(result.get("matches", ())),
                "addrs": addrs[:MAX_ADDRS],
            })

        matches.sort(key=lambda m: m["rule"]["name"])

        return {
            "sha256": sample.get("sha256") or sha256,
            "md5": sample.get("md5"),
            "sha1": sample.get("sha1"),
            "time": s_common.now(),
            "capa": meta.get("version"),
            "rules": {"version": rules.version, "sha256": rules.sha256},
            "flavor": meta.get("flavor"),
            "format": analysis.get("format"),
            "arch": analysis.get("arch"),
            "os": analysis.get("os"),
            "extractor": analysis.get("extractor"),
            "matches": matches,
        }

