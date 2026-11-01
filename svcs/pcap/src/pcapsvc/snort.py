"""Run Snort 3 (and snort2lua), in the sandbox (see ``pcapsvc.sandbox``).

``Snort`` builds a rules file from a set of rule texts (converting Snort 2.x rules with
snort2lua and dropping every rule Snort refuses to load) and matches PCAPs against it.

Snort refuses to start if any rule is invalid, so ``Snort.validate`` loads the rules in test mode
(``-T``), removes the rules on the lines Snort reports errors for, and tries again until Snort
loads cleanly. A rule with an unbalanced quote makes Snort read the following lines as part of
it (blaming the wrong rules), so rules are checked for that first (see ``precheck``).
"""

import json
import logging
import os
import re
import shutil
import tempfile
from collections.abc import Callable, Iterable
from typing import Any

import synapse.lib.coro as s_coro

from . import rules as s_rules
from . import sandbox as p_sandbox

logger = logging.getLogger(__name__)


DEFAULT_VARS = {
    "HOME_NET": "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]",
    "EXTERNAL_NET": "any",
}
"""The Snort variables set in the generated config. PCAPs are often from anywhere (ex. a sandbox),
so the home network is every RFC 1918 network and the external network is anything."""

ALERT_FIELDS = (
    "seconds",
    "timestamp",
    "proto",
    "src_addr",
    "src_port",
    "dst_addr",
    "dst_port",
    "gid",
    "sid",
    "rev",
    "msg",
    "action",
    "dir",
    "pkt_num",
    "vlan",
)
"""The alert_json fields the service reads."""

MAX_VALIDATE_PASSES = 25
"""The max times ``validate`` reloads the rules, each pass removes every reported error."""

_ERROR_LINE = re.compile(r"^ERROR: (?P<path>.+?):(?P<line>\d+) (?P<mesg>.*)$")
_CONVERT_FAIL = re.compile(
    r"Failed to convert rule:(?P<rule>.*?)\^\^\^\^ (?P<why>[^\n]*)", re.DOTALL
)
_DAQ_FATAL = re.compile(r"Couldn't start DAQ instance|Failed to start DAQ instance")
_DAQ_WARN = re.compile(r"Error receiving message from the DAQ")
_SID = re.compile(r"\bsid\s*:\s*(\d+)")
_GID = re.compile(r"\bgid\s*:\s*(\d+)")

PCAP_MAGICS = (
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",  # pcap (usec)
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",  # pcap (nsec)
    b"\x0a\x0d\x0d\x0a",  # pcapng
)
"""The magic bytes a PCAP (or PCAPNG) file starts with."""


def _luaString(valu: str) -> str:
    """A Lua string literal."""

    return "'" + str(valu).replace("\\", "\\\\").replace("'", "\\'") + "'"


class SnortError(Exception):
    """Raised when Snort can't be run, or fails for a reason other than a bad rule."""

    def __init__(self, mesg: str) -> None:
        super().__init__(mesg)
        self.mesg = mesg


def isPcap(head: bytes) -> bool:
    """Whether the first bytes of a file are a PCAP or PCAPNG magic number."""

    return head[:4] in PCAP_MAGICS


def precheck(text: str) -> str | None:
    """Check that Snort 3 rule text is a single rule Snort can be pointed at, line by line.

    Returns an error message, or None if the text looks loadable. This only catches problems that
    would make Snort blame other rules (unbalanced quotes, text after the rule), Snort itself
    decides if the rule is valid.
    """

    if "\n" in text or "\r" in text:
        return "The rule must be a single line."

    quoted = False
    escaped = False
    depth = 0
    opened = False
    for idx, char in enumerate(text):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif quoted:
            continue
        elif char == "(":
            depth += 1
            opened = True
        elif char == ")":
            depth -= 1
            if depth == 0 and opened:
                rest = text[idx + 1 :].strip()
                if rest and not rest.startswith("#"):
                    return "The rule has text after its closing parenthesis (one rule only)."
                break

    if quoted:
        return "The rule has an unterminated quoted string."
    if not opened or depth != 0:
        return "The rule's option parentheses aren't balanced."
    return None


def _errTail(text: str, lines: int = 10) -> str:
    return "\n".join(text.strip().splitlines()[-lines:])


# Blocking helpers, run in an executor so big rule sets don't block the ioloop.


def _writeLines(path: str, lines: Iterable[str]) -> None:
    with open(path, "w", encoding="utf-8") as fd:
        fd.writelines(line + "\n" for line in lines)


def _prepConvert(rules: dict[str, str], path: str) -> tuple[dict[str, str], dict[str, str]]:
    """Write Snort 2 rules to a file for snort2lua. Returns (gid:sid -> key, key -> parse error)."""

    bykey: dict[str, str] = {}
    errors: dict[str, str] = {}
    texts = []
    for key, text in rules.items():
        try:
            rule = s_rules.parseRule(text, enabled=True)
        except s_rules.RuleError as err:
            errors[key] = err.mesg
            continue
        bykey[s_rules.ruleKey(rule["gid"], rule["sid"])] = key
        texts.append(rule["text"])
    _writeLines(path, texts)
    return bykey, errors


def _readConverted(
    path: str, errpath: str, bykey: dict[str, str]
) -> tuple[dict[str, str], dict[str, str]]:
    """Read snort2lua's output.

    Returns (key -> Snort 3 text, gid:sid -> why it failed to convert).
    """

    converted: dict[str, str] = {}
    with open(path, encoding="utf-8", errors="replace") as fd:
        for rule, _, _ in s_rules.parseRules(fd.read()):
            if rule is None or not rule["enabled"]:
                continue
            key = bykey.get(s_rules.ruleKey(rule["gid"], rule["sid"]))
            if key is not None:
                converted[key] = rule["text"]

    reasons = {}
    if os.path.exists(errpath):
        with open(errpath, encoding="utf-8", errors="replace") as fd:
            for match in _CONVERT_FAIL.finditer(fd.read()):
                rtext = match.group("rule")
                if sid := _SID.search(rtext):
                    gid = _GID.search(rtext)
                    skey = s_rules.ruleKey(int(gid.group(1)) if gid else 1, int(sid.group(1)))
                    reasons[skey] = match.group("why").strip()
    return converted, reasons


def _prechecks(rules: dict[str, str]) -> tuple[list[str], dict[str, str]]:
    """Run ``precheck`` on every rule. Returns (the keys that passed, key -> error)."""

    keys = []
    errors = {}
    for key, text in rules.items():
        if (mesg := precheck(text)) is not None:
            errors[key] = mesg
        else:
            keys.append(key)
    return keys, errors


def _readAlerts(path: str, onalert: Callable[[dict[str, Any]], None]) -> int:
    """Call ``onalert`` with each alert in an alert_json file. Returns the number of alerts."""

    count = 0
    if not os.path.exists(path):
        return count
    with open(path, encoding="utf-8", errors="replace") as fd:
        for line in fd:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except ValueError:
                logger.warning("Skipping an unparsable Snort alert: %s", line[:200])
                continue
            onalert(alert)
            count += 1
    return count


class Snort:
    """Run Snort 3 and snort2lua.

    Parameters
    ----------
    workdir : str
        A directory the service owns, the generated Snort config is saved here.
    binpath : str
        The ``snort`` binary (a path, or a name on the PATH).
    s2lpath : str
        The ``snort2lua`` binary.
    conf : str | None
        The base Snort config (``snort.lua``), by default the one installed with Snort.
    snortvars : dict | None
        Snort variables to set in the config (see ``DEFAULT_VARS``). Only variables that the base
        config itself assigns (ex. ``HOME_NET``) can be set.
    args : list | None
        Extra arguments for every Snort run.
    timeout : float
        Seconds before a Snort run is killed.
    sandbox : Sandbox | None
        The sandbox Snort and snort2lua run in, by default a best-effort one.
    """

    def __init__(
        self,
        workdir: str,
        binpath: str = "snort",
        s2lpath: str = "snort2lua",
        conf: str | None = None,
        snortvars: dict[str, str] | None = None,
        args: list[str] | None = None,
        timeout: float = 600,
        sandbox: p_sandbox.Sandbox | None = None,
    ) -> None:
        self.workdir = workdir
        self.binpath = binpath
        self.s2lpath = s2lpath
        self.baseconf = conf
        self.snortvars = dict(DEFAULT_VARS if snortvars is None else snortvars)
        self.args = list(args or [])
        self.timeout = timeout
        self.sandbox = sandbox or p_sandbox.Sandbox()
        self.conf: str | None = None
        self.incpath: str | None = None
        os.makedirs(self.workdir, exist_ok=True)

    def available(self) -> bool:
        """Whether the snort binary can be found."""

        return shutil.which(self.binpath) is not None

    def _baseConf(self) -> str:
        if self.baseconf:
            return self.baseconf
        binpath = shutil.which(self.binpath)
        if binpath is None:
            raise SnortError(f"Unable to find the snort binary ({self.binpath}).")
        prefix = os.path.dirname(os.path.dirname(os.path.realpath(binpath)))
        return os.path.join(prefix, "etc", "snort", "snort.lua")

    def writeConf(self) -> str:
        """Generate the Snort config the service runs with (the base config, its variables set).

        Relative includes in the base config are found with ``--include-path``.

        Raises
        ------
        SnortError
            If the base config can't be read, or a variable isn't assigned in it.
        """

        base = self._baseConf()
        text, unset = self._confText(self.snortvars)
        if unset:
            raise SnortError(
                f"The base Snort config ({base}) doesn't set {unset[0]}, so it can't be "
                "overridden. Use a custom snort:conf instead."
            )
        path = os.path.join(self.workdir, "snort.lua")
        with open(path, "w", encoding="utf-8") as fd:
            fd.write("-- Generated by the slib.pcap service, changes are overwritten.\n")
            fd.write(text)
        self.conf = path
        self.incpath = os.path.dirname(os.path.realpath(base))
        return path

    def _confText(self, snortvars: dict[str, str]) -> tuple[str, list[str]]:
        """The base config with its assignments of ``snortvars`` replaced. Returns the text and
        the names the base config doesn't assign."""

        base = self._baseConf()
        try:
            with open(base, encoding="utf-8") as fd:
                text = fd.read()
        except OSError as err:
            raise SnortError(f"Unable to read the base Snort config {base}: {err}") from err

        unset = []
        for name, valu in snortvars.items():
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
                raise SnortError(f"Invalid Snort variable name: {name}")
            pattern = re.compile(rf"(?m)^{name}\s*=.*$")
            if not pattern.search(text):
                unset.append(name)
                continue
            line = f"{name} = {_luaString(valu)}"
            text = pattern.sub(lambda _m, line=line: line, text, count=1)
        return text, unset

    def _confArgs(self) -> list[str]:
        if self.conf is None:
            self.writeConf()
        return ["-c", self.conf, "--include-path", self.incpath]

    async def _exec(
        self,
        argv: list[str],
        cwd: str,
        timeout: float | None = None,
        read: Iterable[str] = (),
        write: Iterable[str] = (),
    ) -> tuple[int, str, str]:
        """Run snort (or snort2lua) in the sandbox. It can read its configs, the paths in
        ``read``, and write to ``cwd`` and the paths in ``write``."""

        binpath = shutil.which(argv[0])
        if binpath is None:
            raise SnortError(f"Unable to find {argv[0]}.")
        prefix = os.path.dirname(os.path.dirname(os.path.realpath(binpath)))
        readable = [*read, self.workdir]
        if self.incpath:
            readable.append(self.incpath)
        env = {
            "PATH": os.path.dirname(os.path.realpath(binpath)) + ":/usr/bin:/bin",
            "LD_LIBRARY_PATH": os.path.join(prefix, "lib"),
            "HOME": cwd,
            "LANG": "C.UTF-8",
        }
        try:
            res = await self.sandbox.run(
                [binpath, *argv[1:]],
                read=readable,
                write=[cwd, *write],
                execs=[prefix],
                env=env,
                cwd=cwd,
                timeout=timeout or self.timeout,
                maxoutput=64 * 1024 * 1024,
            )
        except p_sandbox.SandboxError as err:
            raise SnortError(err.mesg) from None
        return res.code, res.stdout.decode(errors="replace"), res.stderr.decode(errors="replace")

    async def version(self) -> str:
        """The Snort version, ex. ``3.12.4.0``."""

        with tempfile.TemporaryDirectory(dir=self.workdir) as tmpd:
            self.sandbox.prepare(tmpd)
            rc, stdout, stderr = await self._exec([self.binpath, "-V"], cwd=tmpd, timeout=60)
        if match := re.search(r"Version (\S+)", stdout + stderr):
            return match.group(1)
        raise SnortError(f"Unable to get the Snort version (rc={rc}): {_errTail(stdout + stderr)}")

    async def convert(self, rules: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
        """Convert Snort 2.x rules to Snort 3 with snort2lua.

        Parameters
        ----------
        rules : dict
            Rule key -> Snort 2.x rule text. Every rule must have a unique gid:sid.

        Returns
        -------
        tuple
            (key -> Snort 3 rule text, key -> the error for rules that couldn't be converted).
        """

        if not rules:
            return {}, {}

        with tempfile.TemporaryDirectory(dir=self.workdir) as tmpd:
            self.sandbox.prepare(tmpd)
            src = os.path.join(tmpd, "snort2.rules")
            dst = os.path.join(tmpd, "snort3.rules")
            err = os.path.join(tmpd, "errors.txt")
            bykey, errors = await s_coro.executor(_prepConvert, rules, src)
            self.sandbox.prepare(tmpd)

            rc, stdout, stderr = await self._exec(
                [
                    self.s2lpath,
                    "-c",
                    src,
                    "-r",
                    dst,
                    "-o",
                    os.path.join(tmpd, "snort3.lua"),
                    "-e",
                    err,
                    # Not -q, it leaves the error file empty.
                ],
                cwd=tmpd,
            )
            if not os.path.exists(dst):
                raise SnortError(f"snort2lua failed (rc={rc}): {_errTail(stdout + stderr)}")

            converted, reasons = await s_coro.executor(_readConverted, dst, err, bykey)

        for skey, key in bykey.items():
            if key not in converted:
                why = reasons.get(skey, "snort2lua didn't output the rule")
                errors[key] = f"Unable to convert the Snort 2 rule to Snort 3: {why}"

        return converted, errors

    async def validate(self, rules: dict[str, str], path: str) -> tuple[list[str], dict[str, str]]:
        """Write every rule Snort can load to a rules file.

        Parameters
        ----------
        rules : dict
            Rule key -> Snort 3 rule text (single line).
        path : str
            The rules file to write, only valid rules are written to it.

        Returns
        -------
        tuple
            (the keys of the valid rules, in file order, key -> the error for invalid rules).

        Raises
        ------
        SnortError
            If Snort fails to load for a reason that isn't a rule (ex. a bad config).
        """

        keys, errors = await s_coro.executor(_prechecks, rules)

        for _ in range(MAX_VALIDATE_PASSES):
            await s_coro.executor(_writeLines, path, [rules[key] for key in keys])

            if not keys:
                return keys, errors

            rc, stdout, stderr = await self._exec(
                [self.binpath, *self._confArgs(), "-R", path, "-T", "-q", *self.args],
                cwd=os.path.dirname(path),
                read=[path],
            )
            if rc == 0:
                return keys, errors

            bad: dict[int, str] = {}
            base = os.path.basename(path)
            for line in (stdout + "\n" + stderr).splitlines():
                match = _ERROR_LINE.match(line.strip())
                if match and os.path.basename(match.group("path")) == base:
                    lineno = int(match.group("line"))
                    if 1 <= lineno <= len(keys):
                        bad.setdefault(lineno, match.group("mesg").strip())

            if not bad:
                raise SnortError(
                    f"Snort failed to load the rules (rc={rc}): {_errTail(stdout + stderr)}"
                )

            for lineno, mesg in bad.items():
                errors[keys[lineno - 1]] = mesg
            keys = [key for idx, key in enumerate(keys, start=1) if idx not in bad]

        raise SnortError(f"Snort still reported rule errors after {MAX_VALIDATE_PASSES} passes.")

    async def check(self, text: str, engine: str = s_rules.ENGINE_SNORT3) -> str | None:
        """Check a single rule. Returns the error, or None if Snort can load it."""

        try:
            rule = s_rules.parseRule(text, enabled=True)
        except s_rules.RuleError as err:
            return err.mesg

        text = rule["text"]
        if engine == s_rules.ENGINE_SNORT2:
            converted, errors = await self.convert({"rule": text})
            if "rule" in errors:
                return errors["rule"]
            text = converted["rule"]

        with tempfile.TemporaryDirectory(dir=self.workdir) as tmpd:
            self.sandbox.prepare(tmpd)
            _, errors = await self.validate({"rule": text}, os.path.join(tmpd, "check.rules"))
        return errors.get("rule")

    async def scan(
        self,
        rulespath: str,
        pcappath: str,
        onalert: Callable[[dict[str, Any]], None],
        netvars: dict[str, str] | None = None,
    ) -> tuple[int, list[str]]:
        """Match a PCAP against a rules file, calling ``onalert`` with each alert (alert_json).

        ``netvars`` (see ``pcapsvc.rules.checkNetVars``) override the config's network
        variables for this scan. Ones the base config assigns (ex. HOME_NET) are replaced
        there, so the variables the stock snort_defaults.lua derives from them follow. The
        rest are set in the ``default_variables.nets`` table the stock snort.lua gives
        ``ips.variables`` (ignored when the config has no such table).

        Returns the number of alerts, and Snort's warnings about the PCAP (ex. it's truncated,
        the alerts are for the packets Snort could read).

        Raises
        ------
        SnortError
            If Snort fails, ex. the PCAP is corrupt.
        """

        fields = " ".join(ALERT_FIELDS)
        confargs = self._confArgs()
        extra = []
        with tempfile.TemporaryDirectory(dir=self.workdir) as logdir:
            if netvars:
                # Variables the base config assigns are replaced there, so the ones the stock
                # snort_defaults.lua derives from them (ex. HTTP_SERVERS = HOME_NET) follow.
                # The rest (ex. DNS_SERVERS) are set in default_variables, if it's there.
                text, unset = self._confText({**self.snortvars, **netvars})
                conf = os.path.join(logdir, "snort.lua")
                with open(conf, "w", encoding="utf-8") as fd:  # noqa: ASYNC230 - small
                    fd.write(text)
                confargs = ["-c", conf, "--include-path", self.incpath]
                for name in unset:
                    extra.extend(
                        (
                            "--lua",
                            (
                                "if default_variables and default_variables.nets then "
                                f"default_variables.nets.{name} = {_luaString(netvars[name])} end"
                            ),
                        )
                    )
            self.sandbox.prepare(logdir)
            rc, stdout, stderr = await self._exec(
                [
                    self.binpath,
                    *confargs,
                    "-R",
                    rulespath,
                    "-r",
                    pcappath,
                    "-k",
                    "none",
                    "-q",
                    "-y",
                    "-U",
                    "-l",
                    logdir,
                    "-A",
                    "alert_json",
                    "--lua",
                    f"alert_json = {{ file = true, fields = '{fields}' }}",
                    *extra,
                    *self.args,
                ],
                cwd=logdir,
                read=[rulespath, pcappath],
            )
            output = stdout + "\n" + stderr
            # Snort exits 0 when the DAQ can't open the PCAP.
            if rc != 0 or _DAQ_FATAL.search(output):
                raise SnortError(f"Snort failed to read the PCAP (rc={rc}): {_errTail(output)}")
            warnings = [line.strip() for line in output.splitlines() if _DAQ_WARN.search(line)]

            count = await s_coro.executor(
                _readAlerts, os.path.join(logdir, "alert_json.txt"), onalert
            )
        return count, warnings
