"""Run the engines (tshark, Suricata, Snort) that parse untrusted captures in a sandbox.

Every engine run goes through ``Sandbox.run``, which starts ``_sbxexec.py`` (a small standard
library script) to apply the sandbox to itself and then exec the engine. See ``_sbxexec`` for
the layers. ``Sandbox`` also bounds the run from the outside: a wall clock timeout that kills
the engine's whole process group, and a cap on the output it can return.

Modes (the ``sandbox:mode`` config):

- ``best-effort`` (the default): every layer the host supports is applied, the rest are skipped
  (see ``Sandbox.probe``, shown by ``slib.pcap.status``).
- ``strict``: an engine only runs if every layer can be applied.
- ``off``: engines run directly, with only the timeout and output cap.

Every layer works in a default Docker container (no extra capabilities or seccomp/AppArmor
changes), Landlock needs a host kernel with it enabled (5.13+, 6.7+ to block TCP).
"""

import asyncio
import collections
import contextlib
import contextvars
import ctypes
import json
import logging
import os
import pwd
import shutil
import signal
import stat
import sys
import time
from dataclasses import dataclass, field
from typing import Any

from . import _sbxexec

logger = logging.getLogger(__name__)

MODES = ("best-effort", "strict", "off")
"""The sandbox modes."""

DEFAULT_USER = "slib-pcap-engine"
"""The unprivileged user engines run as (created in the service's image), when the service runs
as root."""

DEFAULT_RLIMITS = {
    "as": 8 * 1024**3,
    "cpu": 3600,
    "fsize": 4 * 1024**3,
    "nofile": 4096,
    "core": 0,
}
"""The default resource limits of an engine run, bytes or seconds (0 is unlimited)."""

SYSTEM_READ = (
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/nsswitch.conf",
    "/etc/localtime",
    "/etc/timezone",
    "/etc/passwd",
    "/etc/group",
    "/etc/host.conf",
    "/etc/hosts",
    "/etc/gai.conf",
    "/etc/services",
    "/etc/protocols",
    "/etc/magic",
    "/etc/magic.mime",
    "/proc/self",
    "/sys/devices/system/cpu",
    "/dev/urandom",
    "/dev/null",
)
"""Paths every engine may read: libc and loader config (ld.so.cache, nsswitch, localtime, the
user and service databases), libmagic's local config, its own /proc entry, the CPU topology
(thread counts), and /dev/urandom. Not the rest of /etc (ex. /etc/shadow)."""

SYSTEM_EXEC = ("/usr", "/lib", "/lib64", "/bin", "/sbin")
"""Paths every engine may read and execute from (libraries, the dynamic linker)."""

SYSTEM_WRITE = ("/dev/null",)
"""Paths every engine may write."""


class SandboxError(Exception):
    """Raised when an engine can't be run in the sandbox, or its run fails the sandbox's bounds."""

    def __init__(self, mesg: str) -> None:
        super().__init__(mesg)
        self.mesg = mesg


@dataclass
class Result:
    """The result of an engine run."""

    code: int
    stdout: bytes
    stderr: bytes
    warnings: list[str] = field(default_factory=list)
    """Sandbox layers that were skipped (best-effort mode)."""
    alerts: list[dict] = field(default_factory=list)
    """What the run did that it shouldn't have (see ``Sandbox.alert``)."""
    applied: list[str] | None = None
    """The sandbox layers the wrapper applied, None if it didn't report (ex. mode off)."""
    verified: bool | None = None
    """Whether the engine's /proc status matched the layers applied, None if the engine
    exited before it could be checked."""

    @property
    def text(self) -> str:
        """stdout and stderr, decoded, for error messages."""

        return (self.stdout + b"\n" + self.stderr).decode(errors="replace")


_APPLIED = (_sbxexec.PREFIX + " applied ").encode()


def _readLimited(maxsize: int):
    async def read(
        stream: asyncio.StreamReader,
        buf: bytearray,
        over: asyncio.Event,
        result: Result | None = None,
    ) -> None:
        while chunk := await stream.read(65536):
            if result is not None and result.applied is None:
                # The wrapper's report of the layers it applied, before it execs the engine.
                head = bytes(buf[:65536]) + chunk
                if (idx := head.find(_APPLIED)) != -1 and (end := head.find(b"\n", idx)) != -1:
                    with contextlib.suppress(ValueError):
                        result.applied = json.loads(head[idx + len(_APPLIED) : end])
            if over.is_set():
                # Keep draining (and dropping) the output until the engine is killed, so the
                # pipe closes and waiting for the engine finishes.
                continue
            if maxsize and len(buf) + len(chunk) > maxsize:
                buf.extend(chunk[: maxsize - len(buf)])
                over.set()
                continue
            buf.extend(chunk)

    return read


RUN_ALERTS: contextvars.ContextVar[list | None] = contextvars.ContextVar(
    "slib_pcap_run_alerts", default=None
)
"""The alerts of the current analysis: ``PcapSvc.analyze`` sets a list, every engine run in
its context (including concurrent ones) adds its alerts to it."""

CRASH_SIGNALS = {
    signal.SIGSEGV: "a segmentation fault",
    signal.SIGBUS: "a bus error",
    signal.SIGILL: "an illegal instruction",
    signal.SIGFPE: "a floating point exception",
    signal.SIGABRT: "an abort (ex. a failed assertion or heap corruption check)",
    signal.SIGTRAP: "a trap",
}
"""Signals an engine dies of when it crashes, often what an exploit attempt looks like."""

ALERT_KINDS = ("seccomp", "crash", "unconfined", "leftover", "escaped", "file")
"""The kinds of sandbox alerts:

- ``seccomp``: the engine tried to open a network socket and was killed (SIGSYS).
- ``crash``: the engine crashed on its input (see ``CRASH_SIGNALS``).
- ``unconfined``: the engine's /proc status didn't match the sandbox layers applied.
- ``leftover``: processes of the run's group were still running after it ended.
- ``escaped``: an engine process left the run's process group (or was orphaned to the
  service), it was killed.
- ``file``: a file the engine's user owns outside the engines' directories.
"""

PR_SET_CHILD_SUBREAPER = 36


def _procStatus(pid: int) -> dict[str, str] | None:
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8", errors="replace") as fd:
            lines = fd.read().splitlines()
    except OSError:
        return None
    out = {}
    for line in lines:
        key, _, valu = line.partition(":")
        out[key] = valu.strip()
    return out


def _procPgrp(pid: int) -> int | None:
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8", errors="replace") as fd:
            stat = fd.read()
    except OSError:
        return None
    # The command is in parentheses and may contain spaces, the fields after it are fixed.
    rest = stat.rsplit(")", 1)[-1].split()
    try:
        return int(rest[2])
    except (IndexError, ValueError):
        return None


def sandboxed(status: dict[str, str], own: dict[str, str] | None) -> bool:
    """Whether a process was started in the sandbox (or by something that was): it has more
    seccomp filters than the service, or no_new_privs when the service doesn't. Both are
    inherited and can't be undone, so they mark every process an engine starts."""

    own = own or {}
    try:
        if int(status.get("Seccomp_filters", 0)) > int(own.get("Seccomp_filters", 0)):
            return True
    except ValueError:
        pass
    return status.get("NoNewPrivs") == "1" and own.get("NoNewPrivs") != "1"


def checkStatus(
    status: dict[str, str], applied: list[str], ids: tuple[int, int] | None, seccomp: bool
) -> list[str]:
    """What's wrong with an engine's /proc status, given the layers its wrapper applied."""

    problems = []
    if ids is not None and "user" in applied:
        uids = status.get("Uid", "").split()
        gids = status.get("Gid", "").split()
        if not uids or any(int(u) != ids[0] for u in uids):
            problems.append(f"it runs with uids {' '.join(uids) or '?'}, not {ids[0]}")
        if not gids or any(int(g) != ids[1] for g in gids):
            problems.append(f"it runs with gids {' '.join(gids) or '?'}, not {ids[1]}")
        if status.get("Groups", "").strip():
            problems.append(f"it has supplementary groups {status['Groups']}")
    if "no_new_privs" in applied and status.get("NoNewPrivs") != "1":
        problems.append("no_new_privs isn't set")
    if seccomp and "seccomp" in applied and status.get("Seccomp") != "2":
        problems.append(f"its seccomp mode is {status.get('Seccomp', '?')}, not 2 (filter)")
    if status.get("CapEff", "0").strip("0") and ids is not None and "user" in applied:
        problems.append(f"it has capabilities {status['CapEff']}")
    return problems


class Sandbox:
    """The sandbox engine runs go through.

    Parameters
    ----------
    mode : str
        ``best-effort``, ``strict``, or ``off`` (see the module docs).
    user : str | None
        The user engines run as when the service runs as root, None to keep the service's user.
    rlimits : dict | None
        Resource limits (see ``DEFAULT_RLIMITS``), merged over the defaults.
    seccomp : bool
        Apply the seccomp filter that refuses IP and packet sockets.
    """

    def __init__(
        self,
        mode: str = "best-effort",
        user: str | None = DEFAULT_USER,
        rlimits: dict[str, int] | None = None,
        seccomp: bool = True,
    ) -> None:
        if mode not in MODES:
            raise SandboxError(f"Invalid sandbox mode {mode!r}, use one of: {', '.join(MODES)}")
        self.mode = mode
        self.user = user
        self.rlimits = {**DEFAULT_RLIMITS, **(rlimits or {})}
        self.seccomp = seccomp
        self.script = os.path.abspath(_sbxexec.__file__)
        self._probe: dict[str, Any] | None = None
        self._reached: set[str] = set()
        self._live: set[int] = set()
        self.alerts: collections.deque[dict] = collections.deque(maxlen=100)
        self.alertcount = 0
        self.subreaper = False
        if self.mode != "off":
            # Engine processes that are orphaned (ex. a daemonized child) become the service's
            # children instead of init's, so the sweep finds them.
            with contextlib.suppress(OSError, AttributeError):
                libc = ctypes.CDLL(None, use_errno=True)
                self.subreaper = libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0

    def alert(self, kind: str, engine: str, detail: str, result: Result | None = None) -> dict:
        """Record that an engine did something it shouldn't have. Alerts are logged, kept for
        the service's status, added to the current analysis (``RUN_ALERTS``), and to
        ``result``."""

        rec = {"kind": kind, "engine": engine, "detail": detail, "time": int(time.time() * 1000)}
        logger.warning("Sandbox alert (%s) for %s: %s", kind, engine, detail)
        self.alerts.append(rec)
        self.alertcount += 1
        if (run := RUN_ALERTS.get()) is not None:
            run.append(rec)
        if result is not None:
            result.alerts.append(rec)
        return rec

    def sweep(self, engine: str = "engine", result: Result | None = None) -> list[int]:
        """Kill engine processes that got out of their run: orphans the service inherited
        (as a subreaper) and, with a sandbox user, the user's processes outside every running
        engine's process group. Returns the killed pids."""

        ids = self.ids()
        me = os.getpid()
        own = _procStatus(me)
        killed = []
        try:
            pids = [int(name) for name in os.listdir("/proc") if name.isdigit()]
        except OSError:
            return killed
        for pid in pids:
            if pid == me or pid in self._live:
                continue
            status = _procStatus(pid)
            if status is None:
                continue
            uids = status.get("Uid", "").split()
            # The service has children of its own (ex. Synapse's IO workers), only the ones
            # marked as started in the sandbox are engine orphans.
            orphan = self.subreaper and status.get("PPid") == str(me) and sandboxed(status, own)
            if status.get("State", "").startswith("Z"):
                # Already dead (ex. a run's leftover that was killed), only reap it.
                if orphan:
                    with contextlib.suppress(ChildProcessError, OSError):
                        os.waitpid(pid, os.WNOHANG)
                continue
            ours = ids is not None and bool(uids) and int(uids[0]) == ids[0]
            if ours and _procPgrp(pid) in self._live:
                continue
            if not (orphan or ours):
                continue
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(pid, signal.SIGKILL)
            if orphan:
                with contextlib.suppress(ChildProcessError, OSError):
                    os.waitpid(pid, 0)
            killed.append(pid)
            name = status.get("Name", "?")
            how = "was orphaned to the service" if orphan else "left its run's process group"
            self.alert("escaped", engine, f"process {pid} ({name}) {how}, it was killed", result)
        return killed

    def sweepFiles(
        self,
        roots: list[str],
        exclude: list[str] = (),
        maxfiles: int = 100000,
        engine: str = "engine",
    ) -> list[str]:
        """Find files the engine's user owns under ``roots`` (outside ``exclude``, the
        directories engines are given), which it shouldn't have been able to write. Returns
        their paths (each is an alert)."""

        ids = self.ids()
        if ids is None:
            return []
        skip = [os.path.abspath(path) for path in exclude]
        found, seen = [], 0
        for root in roots:
            for dirpath, dirnames, filenames in os.walk(root, onerror=lambda _err: None):
                if any(dirpath == d or dirpath.startswith(d + os.sep) for d in skip):
                    dirnames[:] = []
                    continue
                for name in [*filenames, *dirnames]:
                    seen += 1
                    if seen > maxfiles:
                        return found
                    path = os.path.join(dirpath, name)
                    try:
                        info = os.lstat(path)
                    except OSError:
                        continue
                    if info.st_uid == ids[0]:
                        found.append(path)
                        self.alert(
                            "file", engine, f"{path} is owned by the sandbox user {self.user}"
                        )
        return found

    async def _verify(self, proc: asyncio.subprocess.Process, result: Result, engine: str) -> None:
        """Check the engine's /proc status against the layers its wrapper reports applying.

        The wrapper reports them after applying them all, and they're kept across its exec of
        the engine, so the kernel's view of the process is checked as soon as the report is
        in (the status is readable whoever the engine runs as, its exe isn't).
        """

        ids = self.ids()
        for _ in range(2000):
            if proc.returncode is not None:
                return
            if result.applied is not None:
                status = _procStatus(proc.pid)
                if status is None:
                    return
                problems = checkStatus(status, result.applied, ids, self.seccomp)
                result.verified = not problems
                for problem in problems:
                    self.alert("unconfined", engine, problem, result)
                return
            await asyncio.sleep(0.005)

    def ids(self) -> tuple[int, int] | None:
        """The (uid, gid) engines run as, or None if they run as the service's user."""

        if self.mode == "off" or self.user is None or os.geteuid() != 0:
            return None
        try:
            ent = pwd.getpwnam(self.user)
        except KeyError:
            return None
        return ent.pw_uid, ent.pw_gid

    def probe(self) -> dict[str, Any]:
        """Which sandbox layers this host supports (cached), for the service's status."""

        if self._probe is None:
            ids = self.ids()
            userok = self.user is None or os.geteuid() != 0 or ids is not None
            abi = _sbxexec.landlockAbi()
            self._probe = {
                "mode": self.mode,
                "user": self.user if ids else None,
                "uid": ids[0] if ids else os.geteuid(),
                "root": os.geteuid() == 0,
                "landlock": abi,
                "landlock:tcp": abi >= 4,
                "seccomp": self.seccomp
                and _sbxexec.AUDIT_ARCHES.get(os.uname().machine) is not None,
                "missing": [],
            }
            missing = self._probe["missing"]
            if not abi:
                missing.append("landlock")
            elif abi < 4:
                missing.append("landlock:tcp")
            if not userok:
                missing.append(f"user {self.user}")
        return self._probe

    def spec(
        self,
        read: list[str],
        write: list[str],
        execs: list[str],
        env: dict[str, str],
        cwd: str | None,
    ) -> dict[str, Any]:
        """The ``_sbxexec`` spec of a run."""

        ids = self.ids()
        return {
            "strict": self.mode == "strict",
            "rlimits": self.rlimits,
            "uid": ids[0] if ids else None,
            "gid": ids[1] if ids else None,
            "landlock": True,
            "seccomp": self.seccomp,
            "read": sorted({*SYSTEM_READ, *read}),
            "write": sorted({*SYSTEM_WRITE, *write}),
            "exec": sorted({*SYSTEM_EXEC, *execs}),
            "env": env,
            "cwd": cwd,
        }

    def prepare(self, *paths: str) -> None:
        """Make directories (and the files in them) usable by the engine's user.

        The service creates a run's directories as its own user, the engine runs as
        ``user``, so they're handed to it.
        """

        ids = self.ids()
        if ids is None:
            return
        uid, gid = ids
        for path in paths:
            if not os.path.exists(path):
                continue
            self.reach(path)
            os.chown(path, uid, gid)
            if os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for name in dirs + files:
                        with contextlib.suppress(OSError):
                            os.chown(os.path.join(root, name), uid, gid, follow_symlinks=False)

    def reach(self, *paths: str) -> None:
        """Let the engine's user get to ``paths``: give it search (only) permission on the
        directories (and the directories above them) that it can't search, ex. a 0700 cell
        directory.

        Only the search bit is added, so the engine's user can't list those directories.
        """

        ids = self.ids()
        if ids is None:
            return
        uid, gid = ids
        # Search permission lets the engine's user open any file it can name in a directory, so
        # it's only given where Landlock limits what engines can read anyway. Without Landlock a
        # directory like the cell's (cell.yaml has secrets) stays closed to it.
        confined = bool(self.probe()["landlock"])
        for path in paths:
            path = os.path.abspath(path)
            parent = path if os.path.isdir(path) else os.path.dirname(path)
            while parent not in self._reached:
                try:
                    info = os.stat(parent)
                except OSError:
                    break
                if info.st_uid == uid:
                    need = stat.S_IXUSR
                elif info.st_gid == gid:
                    need = stat.S_IXGRP
                else:
                    need = stat.S_IXOTH
                if not info.st_mode & need:
                    if info.st_uid != os.geteuid() or not confined:
                        why = "the service doesn't own it"
                        if info.st_uid == os.geteuid():
                            why = "the host doesn't support Landlock"
                        logger.warning(
                            "The sandbox user %s can't get to %s, and it isn't opened up "
                            "because %s. Make it (and the directories above it) searchable "
                            "by the user.",
                            self.user,
                            parent,
                            why,
                        )
                        break
                    os.chmod(parent, stat.S_IMODE(info.st_mode) | need)
                self._reached.add(parent)
                if parent == os.path.dirname(parent):
                    break
                parent = os.path.dirname(parent)

    async def run(
        self,
        argv: list[str],
        read: list[str] = (),
        write: list[str] = (),
        execs: list[str] = (),
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        timeout: float | None = None,
        maxoutput: int = 0,
        stdout: str | None = None,
        engine: str | None = None,
    ) -> Result:
        """Run an engine in the sandbox and wait for it.

        While it runs, its /proc status is checked against the layers applied, and after it
        exits its process group and the service's orphans are swept. What it shouldn't have
        done is reported as alerts (see ``ALERT_KINDS``), in the result and ``RUN_ALERTS``.

        Parameters
        ----------
        argv : list[str]
            The engine and its arguments. The engine is found on ``env["PATH"]``.
        read, write, execs : list[str]
            Paths the engine may read, write (and create files in), and execute from, on top of
            the system paths (see ``SYSTEM_READ``, ``SYSTEM_EXEC``, ``SYSTEM_WRITE``).
        env : dict | None
            The engine's whole environment (nothing is inherited from the service). Defaults to
            a PATH with the engine's directory.
        cwd : str | None
            The engine's working directory.
        timeout : float | None
            Seconds before the engine (and anything it started) is killed.
        maxoutput : int
            The max bytes of stdout (and of stderr) kept in memory, 0 for no limit. An engine
            that writes more is killed.
        stdout : str | None
            A file to write the engine's stdout to instead of returning it (bounded by the
            ``fsize`` rlimit instead of ``maxoutput``).

        Raises
        ------
        SandboxError
            If the engine can't be found or started, the sandbox can't be applied in strict
            mode, the engine timed out, or wrote more than ``maxoutput``.
        """

        binpath = shutil.which(argv[0], path=(env or {}).get("PATH")) or shutil.which(argv[0])
        if binpath is None:
            raise SandboxError(f"Unable to find {argv[0]}.")
        binpath = os.path.realpath(binpath)
        engine = engine or os.path.basename(binpath)
        if env is None:
            env = {"PATH": os.path.dirname(binpath) + ":/usr/bin:/bin", "LANG": "C.UTF-8"}
        execs = [os.path.dirname(binpath), *execs]
        # The engine's user has to get to what it runs, reads, and writes, ex. a capture in a
        # 0700 directory.
        self.reach(*read, *write, *execs)

        if self.mode == "off":
            cmd = [binpath, *argv[1:]]
        else:
            spec = self.spec(list(read), list(write), list(execs), env, cwd)
            cmd = [
                sys.executable,
                "-I",
                "-S",
                self.script,
                json.dumps(spec),
                "--",
                binpath,
                *argv[1:],
            ]

        outfd = None
        if stdout is not None:
            # Opening the file is cheap, the engine does the writing.
            outfd = open(stdout, "wb")  # noqa: SIM115, ASYNC230 - closed below
        try:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=outfd if outfd is not None else asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    start_new_session=True,
                    cwd=cwd if self.mode == "off" else None,
                    env=env if self.mode == "off" else {"LANG": "C.UTF-8"},
                )
            except OSError as err:
                raise SandboxError(f"Unable to run {argv[0]}: {err}") from err
            self._live.add(proc.pid)

            out, errb = bytearray(), bytearray()
            leftovers: list[bool] = []
            over = asyncio.Event()
            read_ = _readLimited(maxoutput)
            result = Result(0, b"", b"")
            tasks = [asyncio.create_task(read_(proc.stderr, errb, over, result))]
            if proc.stdout is not None:
                tasks.append(asyncio.create_task(read_(proc.stdout, out, over)))
            verify = None
            if self.mode != "off":
                verify = asyncio.create_task(self._verify(proc, result, engine))

            async def exited() -> None:
                # The return code is set when the engine exits, proc.wait() also waits for
                # its output pipes to close, which something it left running keeps open.
                while proc.returncode is None:
                    await asyncio.sleep(0.02)

            async def waitAll() -> None:
                done = asyncio.gather(*tasks)
                overt = asyncio.create_task(over.wait())
                exit_ = asyncio.create_task(exited())
                try:
                    finished, _ = await asyncio.wait(
                        {done, overt, exit_}, return_when=asyncio.FIRST_COMPLETED
                    )
                    if overt in finished:
                        raise SandboxError(f"{argv[0]} wrote more than {maxoutput} bytes.")
                    if done not in finished:
                        try:
                            await asyncio.wait_for(asyncio.shield(done), 1)
                        except TimeoutError:
                            # Its pipes are held open by processes it left behind: kill its
                            # group (reported below), and any that left it (the sweep).
                            with contextlib.suppress(ProcessLookupError, PermissionError):
                                os.killpg(proc.pid, 0)
                                leftovers.append(True)
                                os.killpg(proc.pid, signal.SIGKILL)
                            self.sweep(engine, result)
                            try:
                                await asyncio.wait_for(asyncio.shield(done), 5)
                            except TimeoutError:
                                pass
                    await proc.wait()
                finally:
                    overt.cancel()
                    exit_.cancel()

            try:
                await asyncio.wait_for(waitAll(), timeout=timeout or None)
            except TimeoutError:
                self._kill(proc)
                await proc.wait()
                raise SandboxError(f"{argv[0]} took longer than {timeout} seconds.") from None
            except BaseException:
                self._kill(proc)
                await proc.wait()
                raise
            finally:
                for task in tasks:
                    task.cancel()
                if verify is not None:
                    verify.cancel()
                # Anything still in the run's process group outlived the engine.
                leftover = bool(leftovers)
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.killpg(proc.pid, 0)
                    leftover = True
                if leftover:
                    with contextlib.suppress(ProcessLookupError, PermissionError):
                        os.killpg(proc.pid, signal.SIGKILL)
                    if proc.returncode == 0:
                        self.alert(
                            "leftover",
                            engine,
                            "processes of its run were still "
                            "running after it exited, they were killed",
                            result,
                        )
                self._live.discard(proc.pid)
        finally:
            if outfd is not None:
                outfd.close()
        self.sweep(engine, result)

        warnings = []
        stderr = bytes(errb)
        lines = []
        prefix = _sbxexec.PREFIX.encode()
        for line in stderr.splitlines(keepends=True):
            if line.startswith(prefix):
                warnings.append(line[len(prefix) :].decode(errors="replace").strip())
            else:
                lines.append(line)
        stderr = b"".join(lines)
        if proc.returncode == _sbxexec.EXIT_SANDBOX and warnings:
            raise SandboxError(f"The sandbox couldn't run {argv[0]}: {'; '.join(warnings)}")
        result.code, result.stdout, result.stderr = proc.returncode, bytes(out), stderr
        result.warnings = [w for w in warnings if not w.startswith("applied ")]
        code = proc.returncode
        if code is not None and code < 0 and self.mode != "off":
            sig = -code
            if sig == signal.SIGSYS and self.seccomp and "seccomp" in (result.applied or ()):
                self.alert(
                    "seccomp", engine, "it tried to open a network socket, and was killed", result
                )
            elif sig in CRASH_SIGNALS:
                self.alert(
                    "crash",
                    engine,
                    f"it crashed with {CRASH_SIGNALS[sig]} ({signal.Signals(sig).name})",
                    result,
                )
        return result

    @staticmethod
    def _kill(proc: asyncio.subprocess.Process) -> None:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGKILL)
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
