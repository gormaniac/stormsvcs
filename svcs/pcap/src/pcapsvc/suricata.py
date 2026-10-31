"""Run Suricata 8 on captures, in the sandbox (see ``pcapsvc.sandbox``).

Suricata is the service's main protocol analyzer and its engine for Suricata rules. Each run
reads one capture offline (``-r``) with a config generated from the installed ``suricata.yaml``
(see ``Suricata.config``), and writes EVE JSON (protocol events, alerts, anomalies, flows) and
the files it extracted (file-store v2, named by SHA-256) to the run's directory.

Rules are validated like Snort's (see ``pcapsvc.snort``): Suricata's test mode (``-T``) reports
every rule it can't parse by its line number, those rules are dropped and the rest are loaded
again until Suricata loads cleanly.
"""


import copy
import json
import logging
import os
import re
import shutil
import tempfile
from collections.abc import Iterable, Iterator
from typing import Any

import synapse.lib.coro as s_coro
import yaml

from . import rules as p_rules
from . import sandbox as p_sandbox

logger = logging.getLogger(__name__)


DEFAULT_VARS = {
    "HOME_NET": "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]",
    "EXTERNAL_NET": "any",
}
"""Suricata address variables set in the generated config. Captures come from anywhere, so the
home network is every RFC 1918 network and the external network is anything (like Snort's)."""

TLS_FIELDS = [
    "subject", "issuer", "session_resumed", "serial", "fingerprint", "sni", "version",
    "not_before", "not_after", "chain", "ja3", "ja3s", "ja4", "subjectaltname", "client",
    "client_chain", "client_alpns", "server_alpns",
]
"""The EVE TLS fields logged (``chain`` has the leaf certificate first)."""

SMTP_FIELDS = ["received", "x-mailer", "x-originating-ip", "relays", "reply-to", "bcc",
               "user-agent"]
"""The extra email headers EVE SMTP events log."""

APP_PROTOCOLS = ("dns", "ftp", "http", "http2", "krb5", "quic", "rdp", "sip", "smb", "smtp",
                 "ssh", "tls")
"""The app-layer parsers turned on (some are off by default, ex. RDP and SIP)."""

DECODE_PROTOCOLS = {
    "tls": "tls", "ssl": "tls", "http": "http", "http2": "http2", "ssh": "ssh", "ftp": "ftp",
    "smtp": "smtp", "dns": "dns", "smb": "smb", "rdp": "rdp", "sip": "sip", "kerberos": "krb5",
    "quic": "quic", "imap": "imap", "pop": "pop3", "ldap": "ldap", "mqtt": "mqtt", "rfb": "rfb",
    "telnet": "telnet", "tftp": "tftp", "snmp": "snmp", "modbus": "modbus", "dnp3": "dnp3",
    "nfs": "nfs", "pgsql": "pgsql", "dcerpc": "dcerpc", "ike": "ike", "ntp": "ntp",
}
"""tshark protocol names (in Decode As rules) and the Suricata app-layer parser they map to."""

MAX_VALIDATE_PASSES = 25
"""The max times ``validate`` reloads the rules, each pass removes every reported error."""

_RULE_ERROR = re.compile(r'error parsing signature "(?P<rule>.*)" from file (?P<path>\S+) at line '
                         r"(?P<line>\d+)")
_ERROR_MESG = re.compile(r"^E: (?P<mod>[\w-]+): (?P<mesg>.*)$")


class SuricataError(Exception):
    """Raised when Suricata can't be run, or fails for a reason other than a bad rule."""

    def __init__(self, mesg: str) -> None:
        super().__init__(mesg)
        self.mesg = mesg


def _errTail(text: str, lines: int = 10) -> str:
    return "\n".join(text.strip().splitlines()[-lines:])


def _writeLines(path: str, lines: Iterable[str]) -> None:
    with open(path, "w", encoding="utf-8") as fd:
        fd.writelines(line + "\n" for line in lines)


def portSpec(valu: str) -> str:
    """A Decode As value (``8443`` or ``8000-8010``) as a Suricata port (``8443``, ``8000:8010``)."""

    return valu.replace("-", ":")


def decodePorts(decode: Iterable[str]) -> dict[str, dict[str, list[str]]]:
    """The extra detection ports, by Suricata parser and transport, of Decode As rules.

    Only ``tcp.port`` and ``udp.port`` rules for protocols Suricata parses are used, ex.
    ``tcp.port==8443,tls`` -> ``{"tls": {"tcp": ["8443"]}}``.
    """

    ports: dict[str, dict[str, list[str]]] = {}
    for rule in decode:
        sel, _, rest = rule.partition("==")
        valu, _, proto = rest.partition(",")
        parser = DECODE_PROTOCOLS.get(proto)
        if parser is None or sel not in ("tcp.port", "udp.port"):
            continue
        ports.setdefault(parser, {}).setdefault(sel.split(".")[0], []).append(portSpec(valu))
    return ports


def iterEve(path: str) -> Iterator[dict[str, Any]]:
    """Yield every event in an EVE JSON file, skipping lines that aren't JSON."""

    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8", errors="replace") as fd:
        for line in fd:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except ValueError:
                logger.warning("Skipping an unparsable EVE event: %s", line[:200])


class Suricata:
    """Run Suricata.

    Parameters
    ----------
    workdir : str
        A directory the service owns, rule validation runs here.
    binpath : str
        The ``suricata`` binary (a path, or a name on the PATH).
    conf : str | None
        The base ``suricata.yaml``, by default the one installed with Suricata.
    addrvars : dict | None
        Address variables to set (see ``DEFAULT_VARS``).
    timeout : float
        Seconds before a Suricata run is killed.
    sandbox : Sandbox | None
        The sandbox Suricata runs in, by default a best-effort one.
    """

    def __init__(self, workdir: str, binpath: str = "suricata", conf: str | None = None,
                 addrvars: dict[str, str] | None = None, timeout: float = 900,
                 sandbox: p_sandbox.Sandbox | None = None) -> None:
        self.workdir = workdir
        self.binpath = binpath
        self.baseconf = conf
        self.addrvars = dict(DEFAULT_VARS if addrvars is None else addrvars)
        self.timeout = timeout
        self.sandbox = sandbox or p_sandbox.Sandbox()
        self._base: dict[str, Any] | None = None
        os.makedirs(self.workdir, exist_ok=True)

    def available(self) -> bool:
        """Whether the suricata binary can be found."""

        return shutil.which(self.binpath) is not None

    def _prefix(self) -> str:
        binpath = shutil.which(self.binpath)
        if binpath is None:
            raise SuricataError(f"Unable to find the suricata binary ({self.binpath}).")
        return os.path.dirname(os.path.dirname(os.path.realpath(binpath)))

    def _etcdir(self) -> str:
        if self.baseconf:
            return os.path.dirname(os.path.realpath(self.baseconf))
        return os.path.join(self._prefix(), "etc", "suricata")

    def baseConfig(self) -> dict[str, Any]:
        """The base ``suricata.yaml``, parsed (once)."""

        if self._base is None:
            path = self.baseconf or os.path.join(self._etcdir(), "suricata.yaml")
            try:
                with open(path, encoding="utf-8") as fd:
                    self._base = yaml.safe_load(fd)
            except (OSError, yaml.YAMLError) as err:
                raise SuricataError(f"Unable to read the base Suricata config {path}: {err}") \
                    from err
        return self._base

    def config(self, outdir: str, decode: Iterable[str] = (), filestore: bool = True,
               maxbody: int = 0) -> dict[str, Any]:
        """The config of a run, the base config with the service's outputs and settings.

        Parameters
        ----------
        outdir : str
            The run's directory, EVE and the file store are written here.
        decode : Iterable[str]
            Decode As rules (see ``pcapsvc.tshark.checkDecodeAs``), they add detection ports.
        filestore : bool
            Extract the files sent in flows.
        maxbody : int
            The max bytes of an HTTP body (and of each stream) inspected and extracted, 0 for
            no limit.
        """

        conf = copy.deepcopy(self.baseConfig())
        etc = self._etcdir()

        addrs = conf.setdefault("vars", {}).setdefault("address-groups", {})
        for name, valu in self.addrvars.items():
            addrs[name] = valu

        types: list[Any] = [
            {"alert": {"payload": False, "packet": False, "metadata": True,
                       "tagged-packets": False}},
            {"anomaly": {"enabled": True,
                         "types": {"decode": True, "stream": True, "applayer": True}}},
            {"http": {"extended": True, "dump-all-headers": "both"}},
            {"dns": {"enabled": True}},
            {"tls": {"extended": True, "custom": TLS_FIELDS}},
            {"files": {"force-magic": False, "force-hash": ["sha256"]}},
            {"smtp": {"extended": True, "custom": SMTP_FIELDS}},
            "ftp", "rdp", "smb", "krb5", "sip", "quic", "ssh", "http2", "flow",
        ]
        conf["outputs"] = [
            {"eve-log": {"enabled": True, "filetype": "regular", "filename": "eve.json",
                         "community-id": True, "community-id-seed": 0, "types": types}},
            {"file-store": {"version": 2, "enabled": bool(filestore), "dir": "filestore",
                            "force-filestore": True, "write-fileinfo": False}},
        ]
        conf["logging"] = {"default-log-level": "notice",
                           "outputs": [{"console": {"enabled": True}}]}
        conf["stats"] = {"enabled": False}
        conf["default-log-dir"] = outdir

        protos = conf.setdefault("app-layer", {}).setdefault("protocols", {})
        for name in APP_PROTOCOLS:
            if not isinstance(protos.get(name), dict):
                protos[name] = {}
            protos[name]["enabled"] = True
        protos["tls"]["ja3-fingerprints"] = True
        protos["tls"]["ja4-fingerprints"] = True
        htp = protos["http"].setdefault("libhtp", {}).setdefault("default-config", {})
        # Suricata logs a body cut off at the limit as a whole (CLOSED) file, so the limit is
        # one byte over: a file over maxbody is one that was cut off (see FileStore.addPath).
        htp["request-body-limit"] = maxbody + 1 if maxbody else 0
        htp["response-body-limit"] = maxbody + 1 if maxbody else 0
        smtp = protos["smtp"]
        if not isinstance(smtp.get("mime"), dict):
            smtp["mime"] = {}
        smtp["mime"]["decode-mime"] = True

        for parser, bytrans in decodePorts(decode).items():
            pconf = protos.setdefault(parser, {})
            if not isinstance(pconf, dict):
                pconf = protos[parser] = {}
            pconf.setdefault("enabled", True)
            if any(isinstance(pconf.get(t), dict) for t in ("tcp", "udp")):
                # Parsers with per transport settings (ex. DNS).
                for trans, ports in bytrans.items():
                    sub = pconf.setdefault(trans, {})
                    dports = sub.setdefault("detection-ports", {})
                    dports["dp"] = ", ".join(filter(None, [str(dports.get("dp") or ""), *ports]))
            else:
                ports = [p for trans in bytrans.values() for p in trans]
                dports = pconf.setdefault("detection-ports", {})
                dports["dp"] = ", ".join(filter(None, [str(dports.get("dp") or ""), *ports]))

        stream = conf.setdefault("stream", {})
        stream["checksum-validation"] = False
        stream["midstream"] = True
        reasm = stream.setdefault("reassembly", {})
        # Reassemble whole streams (bounded by Suricata's memcaps), a smaller depth would
        # starve the parsers. Files over the body limits are logged as TRUNCATED.
        reasm["depth"] = 0
        reasm["randomize-chunk-size"] = False

        conf["pcap-file"] = {"checksum-checks": "no"}
        conf["unix-command"] = {"enabled": False}
        conf["runmode"] = "single"
        conf["rule-files"] = []
        conf["classification-file"] = os.path.join(etc, "classification.config")
        conf["reference-config-file"] = os.path.join(etc, "reference.config")
        conf["threshold-file"] = os.path.join(etc, "threshold.config")
        # The service's own sandbox applies Landlock (and more) to the whole process.
        security = conf.setdefault("security", {})
        security["landlock"] = {"enabled": False}
        conf.pop("plugins", None)
        return conf

    def writeConfig(self, path: str, conf: dict[str, Any]) -> str:
        """Write a config to a file (Suricata needs the YAML 1.1 header)."""

        with open(path, "w", encoding="utf-8") as fd:
            fd.write("%YAML 1.1\n---\n")
            yaml.safe_dump(conf, fd, sort_keys=False)
        return path

    async def _exec(self, args: list[str], outdir: str, read: Iterable[str] = (),
                    timeout: float | None = None) -> tuple[int, str]:
        """Run suricata in the sandbox, returning (exit code, its output)."""

        prefix = self._prefix()
        binpath = os.path.join(prefix, "bin", "suricata")
        if not os.path.exists(binpath):
            binpath = os.path.realpath(shutil.which(self.binpath))
        env = {
            "PATH": os.path.dirname(binpath) + ":/usr/bin:/bin",
            "HOME": outdir,
            "LANG": "C.UTF-8",
        }
        try:
            res = await self.sandbox.run(
                [binpath, *args], read=[*read, self._etcdir()], write=[outdir],
                execs=[prefix], env=env, cwd=outdir, timeout=timeout or self.timeout,
                maxoutput=64 * 1024 * 1024,
            )
        except p_sandbox.SandboxError as err:
            raise SuricataError(err.mesg) from None
        return res.code, res.text

    async def version(self) -> str:
        """The Suricata version, ex. ``8.0.8``."""

        with tempfile.TemporaryDirectory(dir=self.workdir) as tmpd:
            self.sandbox.prepare(tmpd)
            rc, out = await self._exec(["-V"], tmpd, timeout=60)
        if match := re.search(r"Suricata version (\S+)", out):
            return match.group(1)
        raise SuricataError(f"Unable to get the Suricata version (rc={rc}): {_errTail(out)}")

    async def validate(self, rules: dict[str, str], path: str) -> tuple[list[str], dict[str, str]]:
        """Write every rule Suricata can load to a rules file.

        Parameters
        ----------
        rules : dict
            Rule key -> Suricata rule text.
        path : str
            The rules file to write, only valid rules are written to it.

        Returns
        -------
        tuple
            (the keys of the valid rules, in file order, key -> the error for invalid rules).

        Raises
        ------
        SuricataError
            If Suricata fails to load for a reason that isn't a rule (ex. a bad config).
        """

        keys, errors = [], {}
        for key, text in rules.items():
            if "\n" in text.strip() or "\r" in text:
                errors[key] = "The rule must be a single line."
            else:
                keys.append(key)

        with tempfile.TemporaryDirectory(dir=self.workdir) as tmpd:
            conf = self.writeConfig(os.path.join(tmpd, "suricata.yaml"),
                                    self.config(tmpd, filestore=False))
            self.sandbox.prepare(tmpd)
            for _ in range(MAX_VALIDATE_PASSES):
                await s_coro.executor(_writeLines, path, [rules[key].strip() for key in keys])
                if not keys:
                    return keys, errors

                rc, out = await self._exec(["-T", "-c", conf, "-S", path, "-l", tmpd], tmpd,
                                           read=[path, conf])
                if rc == 0:
                    return keys, errors

                bad: dict[int, str] = {}
                last = None
                for line in out.splitlines():
                    line = line.strip()
                    if match := _RULE_ERROR.search(line):
                        lineno = int(match.group("line"))
                        if 1 <= lineno <= len(keys):
                            bad.setdefault(lineno, last or "Suricata couldn't parse the rule.")
                        last = None
                    elif match := _ERROR_MESG.match(line):
                        last = match.group("mesg").strip()

                if not bad:
                    raise SuricataError(
                        f"Suricata failed to load the rules (rc={rc}): {_errTail(out)}")
                for lineno, mesg in bad.items():
                    errors[keys[lineno - 1]] = mesg
                keys = [key for idx, key in enumerate(keys, start=1) if idx not in bad]

        raise SuricataError(
            f"Suricata still reported rule errors after {MAX_VALIDATE_PASSES} passes.")

    async def check(self, text: str) -> str | None:
        """Check a single rule. Returns the error, or None if Suricata can load it."""

        try:
            rule = p_rules.parseRule(text, enabled=True)
        except p_rules.RuleError as err:
            return err.mesg
        with tempfile.TemporaryDirectory(dir=self.workdir) as tmpd:
            self.sandbox.prepare(tmpd)
            _, errors = await self.validate({"rule": rule["text"]},
                                            os.path.join(tmpd, "check.rules"))
        return errors.get("rule")

    async def run(self, capture: str, outdir: str, rulespath: str | None = None,
                  decode: Iterable[str] = (), filestore: bool = True,
                  maxbody: int = 0) -> dict[str, Any]:
        """Analyze a capture (and match it against a rules file, if given).

        Returns
        -------
        dict
            ``eve`` (the EVE JSON file), ``filestore`` (the directory of extracted files,
            ``<sha256[:2]>/<sha256>``), and ``warnings`` (Suricata's warnings about the
            capture).

        Raises
        ------
        SuricataError
            If Suricata fails, ex. the capture is corrupt.
        """

        conf = self.writeConfig(os.path.join(outdir, "suricata.yaml"),
                                self.config(outdir, decode=decode, filestore=filestore,
                                            maxbody=maxbody))
        self.sandbox.prepare(outdir)
        args = ["-c", conf, "-r", capture, "-l", outdir, "-k", "none", "--runmode", "single"]
        read = [capture, conf]
        if rulespath:
            args.extend(("-S", rulespath))
            read.append(rulespath)
        else:
            args.append("--disable-detection")

        rc, out = await self._exec(args, outdir, read=read)
        if rc != 0:
            raise SuricataError(f"Suricata failed to read the capture (rc={rc}): {_errTail(out)}")
        warnings = [line[3:].strip() for line in out.splitlines()
                    if line.startswith("W: ") and "output-json-tls" not in line]
        return {
            "eve": os.path.join(outdir, "eve.json"),
            "filestore": os.path.join(outdir, "filestore"),
            "warnings": warnings,
        }
