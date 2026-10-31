"""Exec an engine (tshark, Suricata, Snort) inside the slib.pcap sandbox.

This runs as ``python -I _sbxexec.py <spec json> -- <argv...>``, see ``pcapsvc.sandbox``. It only
uses the standard library (it runs before the engine, with nothing else imported), applies every
sandbox layer the spec asks for to itself, then replaces itself with the engine:

1. Resource limits (address space, CPU, file size, open files, no core dumps).
2. A clean environment (only what the spec gives).
3. Dropping to an unprivileged user and group, when started as root.
4. ``no_new_privs``, so nothing the engine runs can gain privileges.
5. Landlock: the engine can only read the paths in ``read`` (and execute from ``exec``), only
   write to the paths in ``write``, and can't bind or connect TCP sockets.
6. A seccomp filter that refuses IPv4, IPv6, and packet sockets (Landlock doesn't cover UDP).

A layer the kernel doesn't support is skipped, unless the spec is ``strict``, then the engine
isn't run. Problems are reported on stderr as ``slib-pcap-sandbox: ...`` lines and exit code 125.
"""


import ctypes
import ctypes.util
import errno
import json
import os
import platform
import resource
import sys

EXIT_SANDBOX = 125
"""The exit code when the sandbox can't be set up (the engine wasn't run)."""

PREFIX = "slib-pcap-sandbox:"

# Landlock (include/uapi/linux/landlock.h), the syscall numbers are the same on every arch.
SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE = 445
SYS_LANDLOCK_RESTRICT_SELF = 446
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1

FS_EXECUTE = 1 << 0
FS_WRITE_FILE = 1 << 1
FS_READ_FILE = 1 << 2
FS_READ_DIR = 1 << 3
FS_REMOVE_DIR = 1 << 4
FS_REMOVE_FILE = 1 << 5
FS_MAKE_CHAR = 1 << 6
FS_MAKE_DIR = 1 << 7
FS_MAKE_REG = 1 << 8
FS_MAKE_SOCK = 1 << 9
FS_MAKE_FIFO = 1 << 10
FS_MAKE_BLOCK = 1 << 11
FS_MAKE_SYM = 1 << 12
FS_REFER = 1 << 13  # ABI 2
FS_TRUNCATE = 1 << 14  # ABI 3
FS_IOCTL_DEV = 1 << 15  # ABI 5

NET_BIND_TCP = 1 << 0  # ABI 4
NET_CONNECT_TCP = 1 << 1

SCOPE_ABSTRACT_UNIX_SOCKET = 1 << 0  # ABI 6
SCOPE_SIGNAL = 1 << 1

READ = FS_READ_FILE | FS_READ_DIR
READ_EXEC = READ | FS_EXECUTE
FILE_RIGHTS = FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE | FS_IOCTL_DEV
"""The rights that apply to a file (a rule on a file can only have these)."""

# seccomp
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000

AUDIT_ARCHES = {"x86_64": (0xC000003E, 41), "aarch64": (0xC00000B7, 198)}
"""(AUDIT_ARCH value, the socket syscall number) of the arches the seccomp filter supports."""

AF_INET, AF_INET6, AF_PACKET = 2, 10, 17

RLIMITS = {
    "as": resource.RLIMIT_AS,
    "cpu": resource.RLIMIT_CPU,
    "fsize": resource.RLIMIT_FSIZE,
    "nofile": resource.RLIMIT_NOFILE,
    "core": resource.RLIMIT_CORE,
}


class SandboxError(Exception):
    """A sandbox layer couldn't be applied."""


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("fs", ctypes.c_uint64), ("net", ctypes.c_uint64), ("scoped", ctypes.c_uint64)]


class _PathBeneath(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed", ctypes.c_uint64), ("fd", ctypes.c_int32)]


class _SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8), ("jf", ctypes.c_uint8),
                ("k", ctypes.c_uint32)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint16), ("filter", ctypes.POINTER(_SockFilter))]


def _libc() -> ctypes.CDLL:
    return ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)


def landlockAbi(libc: ctypes.CDLL | None = None) -> int:
    """The kernel's Landlock ABI version, 0 if Landlock isn't available (or is blocked)."""

    libc = libc or _libc()
    libc.syscall.restype = ctypes.c_long
    abi = libc.syscall(SYS_LANDLOCK_CREATE_RULESET, None, ctypes.c_size_t(0),
                       ctypes.c_uint32(LANDLOCK_CREATE_RULESET_VERSION))
    return max(0, abi)


def applyLandlock(read: list[str], write: list[str], execs: list[str],
                  libc: ctypes.CDLL | None = None) -> int:
    """Restrict this process (and what it execs) to the given paths. Returns the ABI used.

    Raises
    ------
    SandboxError
        If Landlock isn't available, or a rule can't be added.
    """

    libc = libc or _libc()
    abi = landlockAbi(libc)
    if abi < 1:
        raise SandboxError("Landlock isn't available (kernel 5.13+ with Landlock enabled).")

    fsall = (1 << 13) - 1
    if abi >= 2:
        fsall |= FS_REFER
    if abi >= 3:
        fsall |= FS_TRUNCATE
    if abi >= 5:
        fsall |= FS_IOCTL_DEV

    net = NET_BIND_TCP | NET_CONNECT_TCP if abi >= 4 else 0
    scoped = SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL if abi >= 6 else 0
    attr = _RulesetAttr(fsall, net, scoped)
    size = 24 if abi >= 6 else (16 if abi >= 4 else 8)
    fd = libc.syscall(SYS_LANDLOCK_CREATE_RULESET, ctypes.byref(attr), ctypes.c_size_t(size),
                      ctypes.c_uint32(0))
    if fd < 0:
        raise SandboxError(f"Unable to create a Landlock ruleset: {os.strerror(ctypes.get_errno())}")

    def allow(path: str, rights: int) -> None:
        if not os.path.exists(path):
            return
        if not os.path.isdir(path):
            rights &= FILE_RIGHTS
        pfd = os.open(path, os.O_PATH | os.O_CLOEXEC)
        try:
            rule = _PathBeneath(rights & fsall, pfd)
            if libc.syscall(SYS_LANDLOCK_ADD_RULE, fd, LANDLOCK_RULE_PATH_BENEATH,
                            ctypes.byref(rule), ctypes.c_uint32(0)) != 0:
                raise SandboxError(f"Unable to allow {path} in Landlock: "
                                   f"{os.strerror(ctypes.get_errno())}")
        finally:
            os.close(pfd)

    try:
        for path in read:
            allow(path, READ)
        for path in execs:
            allow(path, READ_EXEC)
        for path in write:
            allow(path, fsall)
        if libc.syscall(SYS_LANDLOCK_RESTRICT_SELF, fd, ctypes.c_uint32(0)) != 0:
            raise SandboxError(f"Unable to apply Landlock: {os.strerror(ctypes.get_errno())}")
    finally:
        os.close(fd)
    return abi


def _bpf(code: int, k: int, jt: int = 0, jf: int = 0) -> _SockFilter:
    return _SockFilter(code, jt, jf, k)


def applySeccomp(libc: ctypes.CDLL | None = None) -> None:
    """Refuse (EPERM) socket() for IPv4, IPv6, and packet sockets, allow everything else.

    Raises
    ------
    SandboxError
        If the arch isn't supported, or the filter can't be loaded.
    """

    libc = libc or _libc()
    arch = AUDIT_ARCHES.get(platform.machine())
    if arch is None:
        raise SandboxError(f"The seccomp filter doesn't support {platform.machine()}.")
    audit, nrsocket = arch

    ld, jeq, ret = 0x20, 0x15, 0x06  # BPF_LD|BPF_W|BPF_ABS, BPF_JMP|BPF_JEQ|BPF_K, BPF_RET|BPF_K
    deny = SECCOMP_RET_ERRNO | errno.EPERM
    prog = [
        _bpf(ld, 4),                       # 0: arch
        _bpf(jeq, audit, 1, 0),            # 1: our arch? -> 3, else -> 2
        _bpf(ret, SECCOMP_RET_ALLOW),      # 2
        _bpf(ld, 0),                       # 3: syscall nr
        _bpf(jeq, nrsocket, 1, 0),         # 4: socket? -> 6, else -> 5
        _bpf(ret, SECCOMP_RET_ALLOW),      # 5
        _bpf(ld, 16),                      # 6: args[0], the address family (low 32 bits)
        _bpf(jeq, AF_INET, 3, 0),          # 7 -> 11
        _bpf(jeq, AF_INET6, 2, 0),         # 8 -> 11
        _bpf(jeq, AF_PACKET, 1, 0),        # 9 -> 11
        _bpf(ret, SECCOMP_RET_ALLOW),      # 10
        _bpf(ret, deny),                   # 11
    ]
    arr = (_SockFilter * len(prog))(*prog)
    fprog = _SockFprog(len(prog), arr)
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(fprog), 0, 0) != 0:
        raise SandboxError(f"Unable to load the seccomp filter: {os.strerror(ctypes.get_errno())}")


def setRlimits(limits: dict[str, int]) -> None:
    """Set resource limits (soft and hard), by name (see ``RLIMITS``). 0 means unlimited."""

    for name, valu in limits.items():
        res = RLIMITS[name]
        if valu is None:
            continue
        valu = int(valu)
        if valu <= 0 and name != "core":
            valu = resource.RLIM_INFINITY
        _, hard = resource.getrlimit(res)
        if hard != resource.RLIM_INFINITY and (valu == resource.RLIM_INFINITY or valu > hard):
            valu = hard
        resource.setrlimit(res, (valu, valu))


def dropUser(uid: int, gid: int) -> None:
    """Switch to an unprivileged user and group (when running as root)."""

    if os.geteuid() != 0:
        return
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    if os.geteuid() != uid or os.getegid() != gid:  # pragma: no cover - the kernel refused
        raise SandboxError("Unable to drop to the sandbox user.")


def _fail(mesg: str) -> None:
    sys.stderr.write(f"{PREFIX} {mesg}\n")
    sys.stderr.flush()
    os._exit(EXIT_SANDBOX)


def _warn(mesg: str) -> None:
    sys.stderr.write(f"{PREFIX} warning: {mesg}\n")


def main(argv: list[str]) -> None:
    """Apply the sandbox spec in ``argv[0]`` and exec ``argv[2:]`` (``argv[1]`` is ``--``)."""

    if len(argv) < 3 or argv[1] != "--":
        _fail("usage: _sbxexec.py <spec json> -- <argv...>")
    try:
        spec = json.loads(argv[0])
    except ValueError as err:
        _fail(f"invalid spec: {err}")
    cmd = argv[2:]
    strict = bool(spec.get("strict"))

    def layer(name: str, func, *args) -> None:
        try:
            func(*args)
        except (SandboxError, OSError, ValueError) as err:
            if strict:
                _fail(f"{name}: {err}")
            _warn(f"{name} skipped: {err}")

    layer("rlimits", setRlimits, spec.get("rlimits") or {})
    if spec.get("uid") is not None:
        layer("user", dropUser, int(spec["uid"]), int(spec["gid"]))

    libc = _libc()

    def noNewPrivs() -> None:
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise SandboxError(os.strerror(ctypes.get_errno()))

    layer("no_new_privs", noNewPrivs)

    if spec.get("landlock"):
        layer("landlock", applyLandlock, spec.get("read") or [], spec.get("write") or [],
              spec.get("exec") or [], libc)
    if spec.get("seccomp"):
        layer("seccomp", applySeccomp, libc)

    os.umask(0o077)
    env = {str(k): str(v) for k, v in (spec.get("env") or {}).items()}
    if spec.get("cwd"):
        os.chdir(spec["cwd"])
    try:
        os.execvpe(cmd[0], cmd, env)
    except OSError as err:
        _fail(f"unable to run {cmd[0]}: {err}")


if __name__ == "__main__":
    main(sys.argv[1:])
