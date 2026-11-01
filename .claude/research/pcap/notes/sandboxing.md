# Sandboxing tshark (and Suricata) parsing untrusted PCAPs inside a Docker container

Scope: a Python asyncio service (stormsvcs `pcap`) that runs `tshark -n -r <file> -T ek -Y <filter> -e <fields>` (+ `-o tls.keylog_file:<path>`, `-d` Decode As) inside Docker. Mix of web sources and **local experiments** run on 2026-10-31 on the research host (Linux 6.18, tshark 4.2.2 from Ubuntu `4.2.2-1.1build3`, Landlock ABI 7 reported by the kernel). The research host is a VM, *not* a Docker container with the default seccomp profile, so namespace results here do not carry over to Docker (see Q1).

Repo facts (read from the repo, not the web):
- `svcs/pcap/docker/prod/Dockerfile` is `FROM ghcr.io/gormaniac/stormsvcs/base:latest` and runs `apt-get install -y --no-install-recommends tshark`. `docker/Dockerfile` (the base) is `FROM vertexproject/vtx-base-image:py311`. No `USER` directive, so everything runs as root.
- `svcs/pcap/src/pcapsvc/tshark.py` `_run()` calls `asyncio.create_subprocess_exec(self.path, *args, stdout=PIPE, stderr=PIPE)` with no `env=`, `user=` or rlimits, then `asyncio.wait_for(proc.communicate(), timeout=self.timeout)`. The default `timeout=0` means no limit (per the docstring). stdout is buffered fully in memory, so there's no output cap.

## Q1. Which sandboxing mechanisms work in an unprivileged Docker container (default seccomp, no extra caps)?

### Takeaway
With Docker's default seccomp and AppArmor profiles and no extra capabilities, **namespace-based tools (bwrap, nsjail, firejail, minijail, `unshare`) generally fail**. What does work with no runtime changes: **Landlock** (the default seccomp profile allows its syscalls; the host kernel must have Landlock enabled), **seccomp-bpf applied by the process itself** after `no_new_privs`, **running tshark as a separate unprivileged UID** (the container starts as root, so it can drop privileges), and **rlimits**. A good layered default is: dedicated UID + clean env + rlimits + Landlock (filesystem, plus TCP when ABI≥4) + optional seccomp filter + a wall-clock timeout. Stronger options need operator changes: gVisor (`--runtime=runsc`), `--network none` (for a dedicated parser container), a read-only rootfs, a custom seccomp profile that allows `unshare`/`clone` for nsjail or bwrap, or `--cap-add SYS_ADMIN` with AppArmor unconfined (not recommended).

### Cited Findings
**Docker default seccomp profile**
- The default profile is an allowlist. Blocked calls fail with `EPERM` through the default `SCMP_ACT_ERRNO` action. Rows from its table:
  - `clone`: "Deny cloning new namespaces. Also gated by CAP_SYS_ADMIN … except CLONE_NEWUSER."
  - `unshare`: "Deny cloning new namespaces for processes. Also gated by CAP_SYS_ADMIN, with the exception of `unshare --user`."
  - `setns` and `mount` are gated by CAP_SYS_ADMIN.
  - `pivot_root` is denied.
  - `bpf` is gated by CAP_SYS_ADMIN.
  - `keyctl`, `add_key`, `request_key` and `userfaultfd` are denied.
  - `--security-opt seccomp=unconfined` removes the profile.
  — [Docker seccomp docs](https://docs.docker.com/engine/security/seccomp/)
- **Conflicting evidence on `unshare --user`.** The Docker docs table implies user-namespace creation is allowed. A Bitbucket Pipelines issue says the default Docker seccomp policy denies unsharing the user namespace, even though that needs no capability and the sysctl and AppArmor would allow it — [Bitbucket issue 13655](https://bitbucket.org/site/master/issues/13655/pipelines-relax-seccomp-policy-to-allow). bwrap users also report failures under default Docker (below). Treat "userns works in default Docker" as **unreliable**.
- The default seccomp profile **allows `landlock_create_ruleset`, `landlock_add_rule` and `landlock_restrict_self`**. They were added in a January 2022 moby commit "so containerized applications can voluntarily restrict their own file access" — [moby default.json mirror](https://codeclimate.com/github/dotcloud/docker/profiles/seccomp/default.json/source), [moby commit mirror](https://git.causa-arcana.com/kotovalexarian-likes-github/moby--moby/commit/af819bf623a8d414289b24f9817c6317cf3f96d5). These are mirrors, not github.com/moby/moby directly.

**bubblewrap (bwrap)**
- In an unprivileged container, bwrap fails with "No permissions to create new namespace". Adding capabilities alone still gives "Failed to make / slave: Permission denied".
- Docker's default seccomp blocks the `clone`/`unshare` that bwrap needs.
- Reported working combination: `--cap-add SYS_ADMIN --security-opt apparmor=unconfined --security-opt seccomp=unconfined`.
- `--unshare-pid --proc` additionally fails ("Can't mount proc") unless `--security-opt systempaths=unconfined` is set.
- `seccomp=unconfined` alone was not enough in a Kubernetes pod.
- The maintainer (smcv) says bwrap "cannot work if it's run inside a container that doesn't allow the necessary syscalls, mount operations, etc." and considers this out of scope.
- One commenter suggests Sandlock (Landlock + seccomp, no namespaces) for unprivileged containers.
- Source for all of the above: [bubblewrap issue #505](https://github.com/containers/bubblewrap/issues/505)

**nsjail**
- Features: namespaces (UTS/MOUNT/PID/IPC/NET/USER/CGROUPS/TIME), cgroups v1/v2 (memory/pids/cpu/net_cls), rlimits, and seccomp through Kafel policies (`-P/--seccomp_policy`, `--seccomp_string`).
- Modes: `-Mo` (once), `-Ml`, `-Me`, `-Mr`.
- Flags: `--chroot`, `--bindmount_ro/-R`, `--rlimit_as` (MB), `--time_limit/-t` (default 600 s), and `--disable_clone_new{net,user,pid,cgroup}`. Disabling the user namespace requires root.
- The README's Docker example uses `docker run --privileged`.
- Source: [google/nsjail README](https://github.com/google/nsjail)

**Ubuntu AppArmor userns restriction**
- On Ubuntu 23.10+, AppArmor restricts unprivileged user namespaces: `unshare -U` may work while `unshare -Ur` (map to root) fails. Disabling it through sysctl is discouraged — [creationline blog](https://www.creationline.com/tech-blog/?p=83183)
- Mounting `/proc` inside a user namespace fails without real privilege — [containerd book ch. 7](https://thecontainerdbook.pages.dev/chapters/part-2/07-security)

**Landlock**
- Landlock first shipped in Linux 5.13. Unprivileged processes must set `no_new_privs`.
- ABI list:
  - 1: base fs rights
  - 2: REFER
  - 3: TRUNCATE
  - 4: TCP bind/connect by port
  - 5: IOCTL_DEV
  - 6: scoping of abstract UNIX sockets and signals
  - 7: audit-log flags
  - 8: TSYNC (all threads)
  - 9: RESOLVE_UNIX
  - 10: UDP
  - 11: RESTRICT_SELF_NO_NEW_PRIVS
- Landlock cannot restrict chdir, stat, flock, chmod, chown, setxattr, utime, fcntl or access. Pipes and sockets passed via /proc can't be restricted. There's a 16-layer limit.
- Source: [kernel Landlock docs](https://docs.kernel.org/userspace-api/landlock.html). The page doesn't map ABIs to kernel versions. ABIs 8–11 appear only in the newest docs; the 6.18 host kernel here reports ABI 7.
- Some distros don't enable Landlock by default and need `lsm=landlock,...` on the kernel command line. Verify with dmesg/journalctl — [Suricata Landlock docs](https://docs.suricata.io/en/latest/configuration/landlock.html)

**Landlock helpers**
- `landrun` (Go CLI): `--ro`, `--rox`, `--rw`, `--rwx` paths, `--bind-tcp` / `--connect-tcp` ports, `--unrestricted-network`. It denies everything when no rules are given. Filesystem rules need kernel ≥5.13; TCP rules need ≥6.7. Packaged in Debian/Ubuntu (`landrun 0.1.15`) — [landrun GitHub](https://github.com/Zouuup/landrun), [Ubuntu manpage](https://manpages-ps7.admin.canonical.com/manpages/questing/man1/landrun.1.html)
- Python packages:
  - `landlockpy`: `Ruleset.allow_path`, `.allow_port`, `.restrict()`; Python ≥3.10 — [PyPI landlockpy](https://pypi.org/project/landlockpy/)
  - `py-landlock`: `Landlock().allow_read`, `.allow_write`, `.apply()`, plus low-level `create_ruleset`/`add_rule`/`restrict_self` — [PyPI py-landlock](https://pypi.org/project/py-landlock/)
  - `landlock` (Edward-Knight): `Ruleset().allow(path)`, `.apply()`; pre-release `1.0.0.dev4` — [GitHub Edward-Knight/landlock](https://github.com/Edward-Knight/landlock)

**gVisor**
- Requires x86_64/ARM64 and Linux ≥5.6. Install with `apt-get install runsc`, which auto-configures Docker, or with `sudo runsc install && sudo systemctl reload docker`. Run with `docker run --runtime=runsc`.
- Legacy auto-download installs are dropped at the end of September 2026.
- This is a host or operator change, not something the image can do — [gVisor install](https://gvisor.dev/docs/user_guide/install/)

**Python `subprocess` privilege options**
- `user=`, `group=`, `extra_groups=` and `umask=` were added in 3.9. `process_group=` was added in 3.11.
- "Specifying user will not drop existing supplementary group memberships! The caller must also pass `extra_groups=()`."
- `preexec_fn` "is NOT SAFE to use in the presence of threads … The child process could deadlock before exec is called."
- Source: [Python subprocess docs](https://docs.python.org/3/library/subprocess.html)

**Local experiments** (research host: root, kernel 6.18, *not* default-Docker seccomp)
- A roughly 40-line ctypes Landlock wrapper (`.claude/research/pcap/prototypes/landlock_exec.py`: create ruleset → allow read of `/usr`, `/lib`, `/etc`, `/proc/self`, the pcap, and r/w `/dev/null` → `prctl(PR_SET_NO_NEW_PRIVS)` → `landlock_restrict_self` → `execvp`) ran `tshark -n -r rdp.pcapng -T ek` successfully. Under the same wrapper:
  - `cat /root/.bashrc` → "Permission denied"
  - `echo x > /tmp/pwn` → "Permission denied"
  - a TCP connect to 1.1.1.1:80 → `PermissionError [Errno 13]` (ABI≥4 net rule)
- `setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs --inh-caps=-all tshark …` failed with "You don't have permission to read the file /root/.config/wireshark/hosts", because `HOME` still pointed at /root. A dedicated UID also needs `HOME` / `WIRESHARK_CONFIG_DIR` set to a directory that UID can access or that doesn't exist.
- `unshare -Urn` gave "Network is unreachable" on this host. That depends on user namespaces being allowed, which default Docker may block (see the conflict above).

### Inferences
- **Recommended default (no runtime-flag changes).** A small exec wrapper (`python3 -I sandbox_exec.py … -- tshark …`, or `landrun`, or `setpriv` + `prlimit`) launched by `create_subprocess_exec`. In order, it should:
  1. Set rlimits.
  2. Drop to a dedicated `tshark` UID/GID with `extra_groups=()`.
  3. Use a clean `env` (`PATH`, `HOME=/nonexistent`, `WIRESHARK_CONFIG_DIR=/nonexistent` or an empty read-only directory, `TMPDIR=<per-run tmp>`, `LANG=C`).
  4. Set no_new_privs.
  5. Apply Landlock (fs read: `/usr`, `/lib*`, `/etc` (or a narrower list), the capture, the key log; fs write: nothing or the per-run tmp; net: deny all TCP if ABI≥4).
  6. Optionally install a seccomp filter.
  7. `exec` tshark.

  Doing this in the wrapper instead of `preexec_fn` avoids the thread-safety warning (Synapse services use thread executors).
- **Degrade gracefully.** If `landlock_create_ruleset` returns ENOSYS/EOPNOTSUPP (Landlock disabled, or an old Docker whose seccomp profile predates 2022), log a warning and keep the other layers. Make this a config option (`sandbox: strict|best-effort|off`), with strict refusing to run.
- **Container root caveat.** Without user namespaces, root inside the container is host root (minus capabilities), so a tshark RCE as root is worse than one as UID 65534 + no_new_privs + Landlock. Dropping the UID is the cheapest big win.
- **Stronger options when the operator controls the runtime**, ranked:
  1. gVisor `--runtime=runsc` for the whole service.
  2. A separate parser container with `--network none --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges --pids-limit --memory`.
  3. nsjail/bwrap with a custom seccomp profile that permits `unshare` and `clone(CLONE_NEW*)`, such as Podman's.
  4. `--cap-add SYS_ADMIN --security-opt seccomp=unconfined,apparmor=unconfined`. This is **discouraged**: it weakens the outer container more than the inner jail helps.
- firejail and minijail weren't researched in depth. Both are namespace-based (firejail is also setuid), so they should hit the same Docker seccomp/AppArmor wall as bwrap. That's an inference, not verified.

### Gaps
- No primary moby source pinned for whether current default seccomp allows `unshare(CLONE_NEWUSER)`; the docs and the Bitbucket report conflict. Test empirically in the target Docker version: `docker run --rm image unshare -Urn true`.
- Whether Docker Desktop's LinuxKit kernel and common cloud kernels have Landlock in the active LSM list wasn't verified. Test with the syscall `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`, which returns the ABI number.
- vtx-base-image's exact distro: its README says the images are "built on Debian docker images" ([vtx-base-image](https://github.com/vertexproject/vtx-base-image)), but I couldn't read the Dockerfile (GitHub API access was denied). Check with `docker run --rm vertexproject/vtx-base-image:py311 cat /etc/os-release`. The Debian release decides the tshark version (Debian 12 ships 4.0.x; Debian 13 ships 4.4.x). That's an inference; I didn't verify it against packages.debian.org.

## Q2. Filesystem isolation and reducing tshark's attack surface (config, plugins, Lua, dissector allowlists)

### Takeaway
Point `WIRESHARK_CONFIG_DIR` (and `HOME`) at an empty or nonexistent directory so no personal preferences, Decode As entries, hosts files or personal Lua plugins load. Pass all settings with `-o` and `-d` instead of profiles. Use `--only-protocols <list>` or `--disable-all-protocols` + `--enable-protocol` (present in 4.2 and documented in the current 4.6 man page) to shrink the dissector surface. Landlock/UID then enforces that only the capture, the key log and system data directories are readable. Lua can't be turned off by flag. Global Lua plugins come from the plugin dirs, and `enable_lua` lives in `init.lua`. The Ubuntu 4.2.2 package ships no `init.lua`, so the controls are "don't install Lua plugins" plus filesystem confinement.

### Cited Findings
- Verified tshark options (the man page currently online is "TShark 4.6.9"):
  - `--only-protocols`: "Only enable dissection of these protocols, comma separated." All others are disabled.
  - `--disable-all-protocols`: "Disable dissection of all protocols."
  - `--disable-protocol` / `--enable-protocol <proto>`: `ALL` is accepted.
  - `--disable-heuristic` / `--enable-heuristic <short_name>`.
  - `-o` "overriding … any value read from a preference file".
  - `-C <profile>` and `--global-profile`.
  - `--temp-dir` (otherwise `$TMPDIR`, then /tmp).
  - `-2` (two-pass; requires seekable input).
  - `-M <n>` session auto-reset (incompatible with `-2`).
  - `-c` (max packets).
  - `-X lua_script:` / `read_format:`.
  - `-n` disables name resolution, but `-N` can override it.
  - Source: [tshark(1)](https://www.wireshark.org/docs/man-pages/tshark.html)
- **Locally verified in tshark 4.2.2** (`tshark -h`): `--only-protocols`, `--disable-all-protocols`, `--enable/--disable-protocol`, `--enable/--disable-heuristic`, `--temp-dir`, `-M`, `-2` and `-X` all exist. The question's suggested `--max-packets` is **not** a tshark flag; use `-c`.
- Environment variables (tshark man page):
  - `WIRESHARK_CONFIG_DIR` "overrides the location of personal configuration files" (default `$XDG_CONFIG_HOME/wireshark`; since 3.0).
  - `WIRESHARK_PLUGIN_DIR`, `WIRESHARK_DATA_DIR` and `WIRESHARK_EXTCAP_DIR` override plugin, data and extcap locations.
  - `WIRESHARK_RUN_FROM_BUILD_DIRECTORY` loads plugins and data from the build dir and "has no effect when running as root or setuid".
  - Personal plugins live in `$HOME/.local/lib/wireshark/plugins`. Lua plugins may also live in `$XDG_CONFIG_HOME/wireshark/plugins`.
  - Startup files: preferences, disabled_protos, enabled_protos, heuristic_protos, hosts, services, ethers.
  - Source: [tshark(1)](https://www.wireshark.org/docs/man-pages/tshark.html)
- Lua control: set `enable_lua = false` in global or personal `init.lua`. `disable_lua` is the 2.6-and-earlier name and is ignored when `enable_lua` is present. `run_user_scripts_when_superuser` was changed to default `true`, reasoning that root "can already execute arbitrary code via C plugins" — [Wireshark Lua support chapter](https://www.wireshark.org/docs/wsdg%5Fhtml%5Fchunked/wsluarm.html), [Debian source wsdg_lua_support.adoc](https://sources.debian.org/src/wireshark/4.6.1-2/doc/wsdg_src/wsdg_lua_support.adoc), [osmocom commit "Load init.lua from plugins directory"](https://gitea.osmocom.org/osmocom/wireshark/commit/9fb85a847d0ae94d6b4a94baa67f16bcfbd965fe)
- **Local:** `tshark -G folders` (4.2.2 as root) reports these directories:

  | Folder | Path |
  |---|---|
  | Personal configuration | `/root/.config/wireshark` |
  | Global configuration | `/usr/share/wireshark` |
  | Personal Plugins | `/root/.local/lib/wireshark/plugins/4.2` |
  | Global Plugins | `/usr/lib/x86_64-linux-gnu/wireshark/plugins/4.2` |
  | Personal Lua Plugins | `/root/.local/lib/wireshark/plugins` |
  | Global Lua Plugins | `/usr/lib/x86_64-linux-gnu/wireshark/plugins` |
  | MaxMind database path | `/usr/share/GeoIP`, `/var/lib/GeoIP` |

  tshark is linked against `liblua5.2.so.0` ("Lua 5.2.4"). No `init.lua` was found in `/usr/share/wireshark` or `/etc/wireshark`.
- **Local `strace` of an offline read**: successful opens were limited to `/lib/x86_64-linux-gnu`, `/etc` (17 opens), `/etc/gnutls`, `/usr/share/wireshark` (and `dtds`), the global plugin dirs (`plugins/4.2/epan`, `wiretap`), `gconv`, `/proc`, `/dev` and the capture file. There were 49 ENOENT probes, mostly `/root/.config/wireshark/{services,enterprises,hosts,subnets,ss7pcs,decode_as_entries,preferences,disabled_protos,…}`. With `env -i … WIRESHARK_CONFIG_DIR=/nonexistent HOME=/nonexistent`, those probes moved to `/nonexistent/...`.

### Inferences
- **Recommended tshark invocation hardening:**
  - `env={"PATH":"/usr/bin:/bin","HOME":"/nonexistent","WIRESHARK_CONFIG_DIR":"/nonexistent","TMPDIR":<run tmp>,"LANG":"C.UTF-8"}`
  - `--temp-dir <run tmp>`
  - `-n` and never `-N`
  - `-o` for TLS keylog
  - **`--only-protocols`** with an explicit list derived from the fields the service extracts (frame, eth, sll, vlan, ip, ipv6, tcp, udp, tls, http, http2?, dns, ssh, smtp, imf, rdp, x509*…). Validate it against fixture captures, since a missing lower-layer protocol silently drops fields (inference).
  - Optionally `--disable-heuristic` for heuristics not needed.
  - The allowlist should be a config option so operators can widen it, and `-d` Decode As targets must be within the allowlist or be added automatically.
- Global plugins can't be disabled by env var alone. `WIRESHARK_PLUGIN_DIR=/nonexistent` might redirect them, but that's untested. Landlock can deny reading `/usr/lib/.../wireshark/plugins` if no plugin is needed; test it, because some Debian builds ship codec and epan plugins that dissectors rely on (inference).
- Mount the capture read-only and pass it by path, or better, pass it as an open fd (`-r /proc/self/fd/N` or `-r -`). Note that `-2` needs seekable input, and so does `-r -`; the man page says `-2` doesn't work with pipes. Then Landlock only needs to grant that one file.

### Gaps
- Didn't verify whether `WIRESHARK_PLUGIN_DIR` *replaces* or *adds to* the global plugin path, or whether a Lua kill switch exists in 4.4/4.6 beyond `init.lua`.
- `tls.keylog_file` read behaviour (opened once vs re-read) wasn't checked. It matters for Landlock rules only if the path changes.

## Q3. Network isolation

### Takeaway
tshark `-r` needs no network. `-n` disables name resolution, but `-N` overrides it. With `-n`, tshark still makes **AF_UNIX connects to `/var/run/nscd/socket`** (glibc NSS user/group lookups), so the sandbox must tolerate those failing. Landlock ABI≥4 blocks TCP connect/bind. ABI 10 covers UDP; before that, UDP and raw sockets need seccomp (deny `socket(AF_INET/AF_INET6/AF_NETLINK/AF_PACKET)`) or a network namespace. A netns needs Docker `--network none` or unshare permission.

### Cited Findings
- `-n` "Disable network object name resolution"; `-N` turns resolution on for chosen types — [tshark(1)](https://www.wireshark.org/docs/man-pages/tshark.html)
- Landlock ABI 4 adds TCP bind/connect restrictions, ABI 10 adds UDP, and ABI 6 adds abstract-UNIX-socket scoping — [kernel Landlock docs](https://docs.kernel.org/userspace-api/landlock.html). landrun's TCP rules need kernel ≥6.7 — [landrun](https://github.com/Zouuup/landrun)
- **Local:** `strace -e socket,connect` during `tshark -n -r` shows repeated `socket(AF_UNIX…)` + `connect("/var/run/nscd/socket") = -1 ENOENT`. The Landlock wrapper with TCP rules blocked `socket.create_connection(("1.1.1.1",80))` with EACCES. `unshare -Urn` gave ENETUNREACH (host, not Docker).

### Inferences
- In-container default:
  - Landlock net deny (ABI≥4).
  - A seccomp filter returning EPERM for `socket()` with any domain except AF_UNIX. Or allow AF_UNIX only: NSS needs it to fail gracefully, and EPERM vs ENOENT should both be tolerated by glibc (inference; test).
  - Keep `-n` and reject any user-supplied `-N`.
- If the operator can, run tshark in a dedicated sidecar container with `--network none`. That's the simplest complete network block.

### Gaps
- Didn't test glibc behaviour when `socket(AF_UNIX)` is denied by seccomp; it should fall back to files but that's unverified.

## Q4. Resource limits (rlimits, cgroups, timeouts, output caps, tshark memory)

### Takeaway
Apply `RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_FSIZE`, `RLIMIT_NOFILE` and `RLIMIT_NPROC`/`RLIMIT_CORE` in the exec wrapper (or with the `prlimit` binary), not in `preexec_fn`. Keep the existing `asyncio.wait_for` timeout, but make it non-zero by default and kill the whole process group. Stream stdout with a byte cap instead of `communicate()`. tshark's main memory driver is per-session state: conversations, reassembly, and `-2` (which keeps the whole first pass in memory). `-M <n>` bounds it by resetting session state but loses cross-reset context and is incompatible with `-2`. Disabling TCP reassembly or decompression through `-o` prefs trades fidelity for memory.

### Cited Findings
- `-M` "Automatically reset internal session when reached to specified number of packets", not with `-2`. `-2` requires seekable input. `-c` caps packets read. `-a` autostop conditions (duration/filesize/packets) apply to *writing* captures — [tshark(1)](https://www.wireshark.org/docs/man-pages/tshark.html)
- `process_group=` (3.11) and `start_new_session=` replace `setpgid`/`setsid` in preexec_fn. `preexec_fn` isn't thread-safe — [Python subprocess docs](https://docs.python.org/3/library/subprocess.html)
- nsjail offers `--rlimit_as` (MB), `--time_limit`, and cgroup v2 memory/pids/cpu — [nsjail README](https://github.com/google/nsjail)
- **Local:** `prlimit --as=$((512*1024*1024)) --cpu=30 --fsize=0 --nofile=64 tshark -n -r rdp.pcapng -T ek` worked on a small capture. `RLIMIT_FSIZE=0` is safe because tshark writes only to its stdout pipe (pipes aren't subject to FSIZE; that's an inference from POSIX semantics, and the test produced output).
- Wireshark advisories regularly include **infinite loops and memory leaks**, not just crashes. Examples: wnpa-sec-2026-107 (TIFF infinite loop), wnpa-sec-2026-103 (USB HID infinite loop and memory leak), wnpa-sec-2025-04 (MONGO infinite loop), wnpa-sec-2025-08 (MEGACO infinite loop) — [Wireshark security](https://www.wireshark.org/security/)

### Inferences
- Suggested limits (configurable):
  - `RLIMIT_AS` 2–4 GiB. glib/wmem reserve virtual memory; measure peak RSS on the largest expected capture, because AS limits can break mmap-heavy allocators.
  - `RLIMIT_CPU` ≈ timeout.
  - `RLIMIT_FSIZE` 0, or the tmp size if `--temp-dir` is used.
  - `RLIMIT_NOFILE` 64–256.
  - `RLIMIT_CORE` 0.
  - `RLIMIT_NPROC` doesn't work per-UID inside a container's shared UID, so prefer cgroup pids.
  - Wall-clock timeout of 300–600 s. The default `0` means no limit, which with infinite-loop CVEs is a DoS risk.
  - A stdout cap such as 512 MiB, read incrementally from `proc.stdout`; on overflow, kill the process and return partial results with a warning.
- cgroups v2 inside Docker: the container normally sees its own cgroup read-only, so per-tshark cgroups need a delegated writable cgroup (`--cgroupns=private` + rw mount or systemd delegation). Treat this as an operator-side option and use `docker run --memory/--pids-limit` on the whole service instead. That's an inference; I found no source in this pass.
- Memory bounding for large captures:
  - Prefer one pass (drop `-2` unless a field needs it).
  - Use `-M 100000`-style resets only if the fields extracted are per-packet.
  - Consider `-o tcp.desegment_tcp_streams:FALSE` for huge captures. Pref names exist in 4.x but weren't verified in this pass.
  - Use `-c` as a hard packet cap.
- asyncio caveat: `asyncio.create_subprocess_exec` forwards `preexec_fn`, `user`, `process_group` etc. to `Popen`. Using an exec wrapper keeps everything in the child after fork/exec, so no Python code runs between fork and exec in the service's process.

### Gaps
- No measured tshark memory profile for large (GB-scale) captures; no source on reassembly memory limits or prefs that bound them.
- No verified source on cgroup v2 delegation inside default Docker.

## Q5. seccomp syscall allowlist feasibility for tshark, and Suricata's own hardening

### Takeaway
An allowlist for offline `tshark -r` is small and feasible. Local strace showed **43 distinct syscalls** for an EK run. A deny-list (block `socket` for non-UNIX domains, `execve` after start, `ptrace`, `mount`, `bpf`, `keyctl`, `personality`, `io_uring_*` and the like) is lower-risk to ship than a strict allowlist, because syscall usage varies with glibc and Wireshark versions. Suricata has **built-in Landlock** (added in 7.0, off by default, `landlock:` YAML section) and privilege drop via `run-as` / `--user` / `--group`. I found no built-in seccomp in Suricata.

### Cited Findings
- **Local strace -c** (tshark 4.2.2, `-n -r rdp.pcapng -T ek`, glibc on Ubuntu): `access arch_prctl brk clone3 close connect execve fstat futex getdents64 getegid geteuid getgid getrandom getresuid getuid ioctl lseek madvise mmap mprotect mremap munmap newfstatat openat prctl pread64 prlimit64 read readlink rseq rt_sigaction rt_sigprocmask set_robust_list set_tid_address setresgid setresuid socket sysinfo uname write`. `clone3` means tshark spawns threads; the `setres*id` calls are tshark's privilege-dropping logic.
- tshark prints "Running as user "root" and group "root". This could be dangerous." (local observation).
- Suricata Landlock:
  - `landlock: enabled: yes`, plus `directories: write: [...]` and `read: [...]`.
  - Off by default and "in blocking mode by default so careful testing is needed".
  - Needs Linux ≥5.13, possibly the `lsm=landlock` boot param.
  - Source: [Suricata Landlock docs](https://docs.suricata.io/en/latest/configuration/landlock.html)
  - Added in 7.0 per the commit "landlock: basic implementation" by Eric Leblond; built by default if the header is present — [mirror of Suricata git](https://git.morozoff.pro/aiden/suricata/commits/tag/suricata-7.0.1/configure.ac), [Ubunlog 7.0 coverage](https://en.ubunlog.com/suricata-7-0-llega-con-soporte-de-landlock-mejoras-y-mas/) (secondary sources)
- Suricata privilege drop:
  - YAML `run-as: user: / group:` or `--user suricata --group suricata`; Linux only.
  - Containers: `--cap-add=net_admin --cap-add=net_raw --cap-add=sys_nice` for live capture.
  - Rootless Podman isn't supported.
  - Source: [Suricata security docs](https://docs.suricata.io/en/latest/security.html)

### Inferences
- For offline `suricata -r file.pcap`, no NET_ADMIN/NET_RAW is needed. Run it as the dedicated UID with Landlock enabled in its YAML (read: rules dir, config, the pcap; write: the per-run log dir), and still wrap it with rlimits and a timeout.
- Build seccomp with libseccomp's Python bindings (`seccomp` module from the `python3-seccomp` / libseccomp package), applied in the wrapper after Landlock and before exec. Docker's default profile still allows the `seccomp()`/`prctl(PR_SET_SECCOMP)` calls (inference: they're absent from Docker's blocked list).
- Generate the allowlist per image build by running tshark under strace over the fixture captures in CI, and fail the CI if new syscalls appear.
- Wireshark's own privilege separation (dumpcap does capture with caps; tshark and wireshark parse unprivileged) is the documented model: parsers shouldn't be privileged. I didn't fetch a source in this pass.

### Gaps
- No existing published seccomp profile for tshark was found in this pass. Didn't check Arkime/Zeek sandboxing.
- Suricata 8 changes to Landlock or any seccomp support weren't verified. The docs fetched are `latest`, so they're current, but the docs don't list version history.

## Q6. Prior art and Wireshark security posture

### Takeaway
Wireshark ships many dissector and file-parser advisories every year: 110 IDs in 2026 so far, versus 8 in all of 2025. That makes parser sandboxing and prompt upgrades both necessary. I found no public, documented sandbox design from CloudShark, PacketTotal, CAPE or Arkime in this pass.

### Cited Findings
- 2026 advisories go up to wnpa-sec-2026-110, all fixed in 4.6.9 / 4.4.19. They cover dissector crashes (802.11, X11, MBIM, Catapult DCT2000, RF4CE, the Frame metadissector), infinite loops (TIFF, USB HID), the Toshiba file parser, and "Profile import crash and possible code execution" (2026-106).
- 2025 had 8, including the SSH dissector crash (2025-03, fixed 4.4.9), an HTTP3 crash, and a "Dissection engine crash" (2025-02).
- The security page offers no hardening guidance beyond upgrading and SECURITY.md.
- Source: [Wireshark security](https://www.wireshark.org/security/)
- The local image's tshark is **4.2.2** (Ubuntu package). The 4.2 branch's last listed fix in the advisories is 4.2.14 (wnpa-sec-2025-04), and 2026 fixes target only 4.4/4.6. So a 4.2.x distro build may be unpatched for 2026 advisories unless the distro backports — [Wireshark security](https://www.wireshark.org/security/) (inference from the fixed-version columns).

### Inferences
- Pin or upgrade tshark: use the Wireshark stable PPA on Ubuntu or Debian backports, and record `tshark -v` in run info (the service already stores `version`). Consider warning when the version is below the latest fixed release.
- Profile import (2026-106) is irrelevant if the service never uses `-C`, which is one more reason to use `-o` and a nonexistent config dir.

### Gaps
- No sourced details found for how CloudShark, PacketTotal, CAPE/Cuckoo or Arkime sandbox tshark. CAPE runs tshark/Suricata on the host side; that's unverified.

## Q7. Testing the sandbox

### Takeaway
Write integration tests that run arbitrary commands through the same wrapper, and assert:
- reads outside the allowlist fail (EACCES)
- writes fail
- TCP/UDP connects fail
- rlimit and timeout kills happen
- tshark still produces the expected fields on the fixture captures

Also probe Landlock ABI and userns availability at service start and report them.

### Cited Findings (local, using the prototype wrapper)
- `cat /root/.bashrc` → "Permission denied"; `sh -c 'echo x > /tmp/pwn'` → "Permission denied"; Python TCP connect → `PermissionError [Errno 13]`; tshark EK output still correct.
- The Landlock ABI probe is `syscall(444 /*landlock_create_ruleset*/, NULL, 0, 1 /*LANDLOCK_CREATE_RULESET_VERSION*/)`, which returned 7 on this host. ABI semantics: [kernel Landlock docs](https://docs.kernel.org/userspace-api/landlock.html)
- landrun suggests `--log-level debug` to debug denials — [landrun](https://github.com/Zouuup/landrun). Landlock ABI 7 adds audit logging of denials — [kernel Landlock docs](https://docs.kernel.org/userspace-api/landlock.html)

### Inferences
- Test matrix:
  1. Read `/etc/shadow`, the service storage dir (`/vertex/storage`), another run's capture, and `/proc/1/environ` → EACCES. `/proc/1/environ` needs the UID drop, since Landlock only allowed `/proc/self`.
  2. Write to `/tmp`, the capture, cwd → EACCES/EROFS.
  3. `socket(AF_INET)` connect and UDP sendto → EPERM/EACCES/ENETUNREACH.
  4. A fork bomb or busy loop → killed by RLIMIT_CPU/timeout.
  5. `head -c` an infinite stdout → output cap triggers.
  6. Run the existing `tests/test_tshark.py` fixtures under the sandbox to confirm there's no field loss with `--only-protocols`.
- Run the same tests in CI inside `docker run` with default flags, to catch environments where Landlock is missing, and make "strict" mode fail loudly there.

### Gaps
- No upstream test suite for tshark sandboxes found; the matrix above is a proposal.
