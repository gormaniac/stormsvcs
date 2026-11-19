# Sandbox

tshark, Suricata and Snort parse untrusted captures with a lot of C (and some Rust), so every
engine run (analyses, rule builds and checks, version lookups, `snort2lua`) goes through
`Sandbox.run` in {src}`svcs/pcap/src/pcapsvc/sandbox.py`. It starts
{src}`svcs/pcap/src/pcapsvc/_sbxexec.py`, a standard-library-only script that applies the
sandbox to itself and then `exec`s the engine, and it bounds and watches the run from the
outside.

## Modes

| `sandbox:mode` | Behaviour |
| --- | --- |
| `best-effort` (default) | Every layer the host supports is applied, the rest are skipped with a warning. |
| `strict` | Any layer that can't be applied fails the run: `The sandbox couldn't run <engine>: <layer>: <error>`. |
| `off` | The engine runs directly, only the timeout and output cap apply. No `seccomp`, `crash`, `unconfined` or `escaped` alerts. |

Dropping to the sandbox user is never optional: if it fails, the engine isn't run, even in
`best-effort`.

## Layers

`_sbxexec.py` is run as `python -I -S _sbxexec.py <spec json> -- <engine argv>` with a minimal
environment (`LANG=C.UTF-8`). In order:

1. **Resource limits** (`setRlimits`): `sandbox:rlimits` as soft and hard limits, each clamped
   to the current hard limit. Defaults: `RLIMIT_AS` 4 GiB, `RLIMIT_CPU` 3600 s, `RLIMIT_FSIZE`
   4 GiB, `RLIMIT_NOFILE` 4096, `RLIMIT_CORE` 0, `RLIMIT_NPROC` 256. `0` is unlimited (for
   `core` it means no core dumps). `nproc` is left out unless engines run as the sandbox user,
   since it counts every process of the user, which would include the service's threads.
2. **Unprivileged user** (`dropUser`): when the service runs as root and `sandbox:user` exists,
   `setgroups([])`, `setgid`, `setuid` to it (`slib-pcap-engine`, uid 2000 in the image).
3. **`no_new_privs`** (`prctl(PR_SET_NO_NEW_PRIVS)`): nothing the engine runs can gain
   privileges.
4. **Landlock** (`applyLandlock`): a ruleset handling every filesystem right the kernel's ABI
   knows (incl. `REFER` from ABI 2, `TRUNCATE` from 3, `IOCTL_DEV` from 5), TCP bind and connect
   from ABI 4, and abstract Unix socket and signal scoping from ABI 6. The engine may read the
   `read` paths, read and execute the `exec` paths, and do anything under the `write` paths.
   From ABI 7 it sets `LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON`, so denials of the exec'd engine
   go to the kernel audit log.
5. **seccomp** (`applySeccomp`): a BPF filter on `socket()`. `AF_UNIX` is allowed, `AF_INET`,
   `AF_INET6` and `AF_PACKET` kill the process (`SECCOMP_RET_KILL_PROCESS`, SIGSYS), every other
   family (ex. netlink, which libraries probe) fails with `EPERM`. Syscalls of a foreign arch
   (ex. 32-bit `socketcall` on x86_64) and x32 syscalls kill the process. Supported on `x86_64`
   and `aarch64`. Off with `sandbox:seccomp: false`.

Then it reports `slib-pcap-sandbox: applied [<layers>]` on stderr, sets `umask 077`, changes to
the spec's `cwd`, and `execvpe`s the engine with the spec's environment only. Problems are
`slib-pcap-sandbox:` lines on stderr and exit code 125, which `Sandbox.run` turns into a
`SandboxError`. Skipped layers become the result's `warnings`.

### What engines can reach

| | Paths |
| --- | --- |
| Read (`SYSTEM_READ`) | `/etc/ld.so.cache`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d`, `/etc/nsswitch.conf`, `/etc/localtime`, `/etc/timezone`, `/etc/passwd`, `/etc/group`, `/etc/host.conf`, `/etc/hosts`, `/etc/gai.conf`, `/etc/services`, `/etc/protocols`, `/etc/magic`, `/etc/magic.mime`, `/proc/self`, `/sys/devices/system/cpu`, `/dev/urandom`, `/dev/null`, plus the run's inputs (capture, key log, rules file, generated config, the engine's config directory, the Snort include path). Not the rest of `/etc` (ex. `/etc/shadow`). |
| Read and execute (`SYSTEM_EXEC`) | `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, and the engine's install prefix (ex. `/opt/suricata`). |
| Write | `/dev/null` and the run's directory. |
| Environment | Only what the wrapper sets per engine, ex. `PATH`, `HOME` (the run directory), `LANG`, `LD_LIBRARY_PATH` for Snort, `TMPDIR`/`WIRESHARK_CONFIG_DIR`/`XDG_CONFIG_HOME` for tshark. |
| Network | None: TCP connect/bind refused by Landlock (ABI 4+), IP and packet sockets kill the engine (seccomp). |

### Directory access

The service creates each run's directories as itself, and `Sandbox.prepare` chowns them (and
their contents) to the engine user. `Sandbox.reach` gives the engine user search (`x`) permission,
and only that, on directories above an engine's files it can't search (ex. a `0700`
`/vertex/storage`), and only on directories the service owns and only when the host has
Landlock: search permission lets the user open any file it can name, so without Landlock a
directory like the cell's (`cell.yaml` holds secrets) stays closed. In that case a warning is
logged, and you have to make the directories searchable yourself if engines can't reach their
files. `Sandbox.restore` puts the original modes back when the service stops.

## Bounds from outside

`Sandbox.run` also:

- starts the engine in a new session and process group (`start_new_session=True`),
- kills the whole process group (SIGKILL) when the wall clock timeout passes
  (`<engine> took longer than <n> seconds.`) or the run is cancelled (ex. the Storm query was
  killed), and gives up waiting after 5 seconds even if something it left behind holds its
  output pipes open,
- caps stdout and stderr at `maxoutput` (64 MiB for every engine) and kills an engine that writes
  more (`<engine> wrote more than <n> bytes.`). tshark's stdout goes straight to a file, bounded
  by `RLIMIT_FSIZE` instead,
- waits for the engine's exit code, not its pipes: if its pipes are still open a second after it
  exits, the leftover processes are killed.

| Engine timeout | Config |
| --- | --- |
| Suricata | `suricata:timeout` (900) |
| Snort, `snort2lua` | `snort:timeout` (900) |
| tshark | `tshark:timeout` (600, `0` for none) |
| Snort and Suricata version lookups | 60 |

## Alerts

The sandbox watches what engines try, so a capture that exploits one is noticed, not just
contained. Every alert (`{kind, engine, detail, time}`) is logged as a warning, counted, kept
(the last 100, `slib.pcap.status` shows the count and last 10), added to the current analysis's
summary (`summary.sandbox.alerts`, warned about by `slib.pcap.flows`: "The capture may be trying
to exploit it"), and to the run's result.

| Kind | When |
| --- | --- |
| `seccomp` | The engine died of SIGSYS with the seccomp layer applied: it tried to open an IP or packet socket. |
| `crash` | The engine died of SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT or SIGTRAP. |
| `unconfined` | `/proc/<pid>/status` of the running engine doesn't match the layers the wrapper reported: uids or gids not the sandbox user's, supplementary groups, `NoNewPrivs` not 1, `Seccomp` not 2, or effective capabilities. Checked as soon as the wrapper's report arrives (the layers survive the exec). |
| `leftover` | Processes of the run's process group were still running after the engine exited successfully. They're killed. |
| `escaped` | A process that left its run's process group (ex. `setsid`), or was orphaned to the service, is still running. It's killed. |
| `file` | A file or directory owned by the sandbox user outside the engines' directories, found by the sweep. |

### Sweeps

- The service sets itself as a child subreaper (`PR_SET_CHILD_SUBREAPER`) unless the mode is
  `off`, so orphaned engine processes become its children instead of init's.
- After every run, and every 10 minutes, `Sandbox.sweep` walks `/proc`: a child of the service
  marked as started in the sandbox (more seccomp filters than the service, or `no_new_privs` when
  the service has none, both inherited and permanent), or any process of the sandbox user, that
  isn't in a running engine's process group, is killed and reported `escaped`. Zombies are
  reaped (other zombies of the service after 60 seconds).
- Every 10 minutes `sweepFiles` looks under `/tmp`, `/var/tmp`, `/dev/shm` and the cell
  directory (excluding `tmp/`, `snort/` and `suricata/`, at most 100000 entries) for anything the
  sandbox user owns, each a `file` alert.

## Monitoring from the host

These checks run in the service's container, so an exploit that gets root there (ex. through a
kernel bug) can hide from them. Monitor uid 2000 from the host too. With
[Falco](https://falco.org/):

```yaml
- rule: slib.pcap engine outside its sandbox
  desc: An slib.pcap engine (uid 2000) ran something other than an engine, or used the network.
  condition: >
    user.uid = 2000 and
    ((spawned_process and not proc.exepath in (/opt/wireshark/bin/tshark,
                                               /opt/suricata/bin/suricata,
                                               /opt/snort/bin/snort, /opt/snort/bin/snort2lua))
     or (evt.type in (connect, bind, sendto) and fd.l4proto in (tcp, udp))
     or (evt.type in (setuid, setresuid, setgid, setresgid) and evt.dir = <))
  output: "slib.pcap engine %proc.cmdline did %evt.type (container=%container.name)"
  priority: CRITICAL
```

or `auditd` (`/etc/audit/rules.d/slib-pcap.rules`):

```text
-a always,exit -F arch=b64 -S execve -F uid=2000 -F exe!=/opt/wireshark/bin/tshark -F exe!=/opt/suricata/bin/suricata -F exe!=/opt/snort/bin/snort -F exe!=/opt/snort/bin/snort2lua -k slib-pcap-exec
-a always,exit -F arch=b64 -S connect,bind -F uid=2000 -k slib-pcap-net
-a always,exit -F arch=b64 -S setuid,setreuid,setresuid,setgid,setresgid -F uid=2000 -k slib-pcap-priv
```

Landlock denials (ABI 7, Linux 6.15+) are audit records of type `LANDLOCK_ACCESS` (with
`LANDLOCK_DOMAIN`). Reading the audit log needs `CAP_AUDIT_READ`, which containers don't have.

## Host support

`Sandbox.probe()` (in `slib.pcap.status`) reports the mode, the engine uid, whether the service
runs as root, the Landlock ABI (`0` without Landlock), whether TCP is covered (`landlock:tcp`,
ABI 4+), whether seccomp is on and supported, and `missing` (`landlock`, `landlock:tcp`,
`user <name>` when the user doesn't exist). Every layer works in a default Docker container,
Landlock needs a host kernel with it enabled (5.13+). Suricata's own Landlock support is turned
off in its config, the service applies Landlock to the whole process instead.
