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
import contextlib
import json
import logging
import os
import pwd
import shutil
import signal
import stat
import sys
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

SYSTEM_READ = ("/etc", "/proc/self", "/sys/devices/system/cpu", "/dev/urandom", "/dev/null")
"""Paths every engine may read: libc config (ld.so.cache, nsswitch, localtime), its own /proc
entry, the CPU topology (thread counts), and /dev/urandom."""

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

    @property
    def text(self) -> str:
        """stdout and stderr, decoded, for error messages."""

        return (self.stdout + b"\n" + self.stderr).decode(errors="replace")


def _readLimited(maxsize: int):
    async def read(stream: asyncio.StreamReader, buf: bytearray, over: asyncio.Event) -> None:
        while chunk := await stream.read(65536):
            if maxsize and len(buf) + len(chunk) > maxsize:
                buf.extend(chunk[: maxsize - len(buf)])
                over.set()
                return
            buf.extend(chunk)

    return read


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
    ) -> Result:
        """Run an engine in the sandbox and wait for it.

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

            out, errb = bytearray(), bytearray()
            over = asyncio.Event()
            read_ = _readLimited(maxoutput)
            tasks = [asyncio.create_task(read_(proc.stderr, errb, over))]
            if proc.stdout is not None:
                tasks.append(asyncio.create_task(read_(proc.stdout, out, over)))

            async def waitAll() -> None:
                done = asyncio.gather(*tasks)
                overt = asyncio.create_task(over.wait())
                try:
                    finished, _ = await asyncio.wait(
                        {done, overt}, return_when=asyncio.FIRST_COMPLETED
                    )
                    if overt in finished:
                        raise SandboxError(f"{argv[0]} wrote more than {maxoutput} bytes.")
                    await proc.wait()
                finally:
                    overt.cancel()

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
        finally:
            if outfd is not None:
                outfd.close()

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
        return Result(proc.returncode, bytes(out), stderr, warnings)

    @staticmethod
    def _kill(proc: asyncio.subprocess.Process) -> None:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGKILL)
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
