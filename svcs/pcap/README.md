# pcap

A Synapse Advanced Power-Up (Storm Service) that analyzes packet captures: it models every
network flow in them as an `inet:flow` node with everything the capture says about it, and
matches them against Snort and Suricata rules from feeds or from the graph.

A capture goes through up to four engines:

1. **Flows (dpkt, always).** Pure Python readers for pcap and pcapng decode every packet's IP and
   transport headers and aggregate them into bidirectional flows: endpoints, VLANs, packet and
   byte counts per direction, TCP flags and state, duration, the first text payload each side
   sent, and the flow's [Community ID](https://github.com/corelight/community-id-spec).
2. **Protocols and rules (Suricata 8).** Suricata parses the application layer (TLS, HTTP and
   HTTP/2, DNS, QUIC, SMB, Kerberos, SSH, RDP, FTP, SMTP, SIP), extracts the files sent in flows,
   reports protocol anomalies, and matches the Suricata rules (`it:app:suricata:rule`).
3. **Snort rules (Snort 3).** Snort matches the Snort 3 and Snort 2.x rules (`it:app:snort:rule`).
4. **The gaps (tshark).** tshark fills in what Suricata doesn't parse (SSH host keys, full SIP
   software names, whole emails), and with a TLS key log decrypts TLS 1.2 and 1.3. Without
   Suricata it does all of the application layer.

Engine output is matched to flows by frame number (Suricata's `pcap_cnt`, Snort's `pkt_num`,
tshark's frame numbers), and by Community ID and time for the few events without one, so flows
are built the same way whatever engines ran: they only add details. Every engine is optional and
the service works with any of them missing. All of them run [sandboxed](#sandbox).

The service registers the `slib.pcap` Storm package.

Supported captures:

- **Formats:** libpcap (micro- and nanosecond, either byte order), pcapng (every interface keeps
  its own link type, timestamp resolution, and offset; multiple sections), and gzip compressed
  versions of either. Truncated captures are read up to where they're cut off.
- **Link types:** Ethernet (including VLAN/QinQ and PPPoE), raw IP, BSD loopback (`NULL`/`LOOP`),
  Linux cooked capture (`SLL` and `SLL2`), and PPP.
- **Protocols:** IPv4 and IPv6. TCP and UDP flows are keyed by address, port, and VLANs, every
  other IP protocol (ICMP, ICMPv6, GRE, ESP, etc.) by address and VLANs.

## Deploying

```bash
docker run -d --name slib-pcap \
    -v /srv/slib-pcap:/vertex/storage \
    -e SYN_PCAPSVC_AXON_URL="aha://axon..." \
    -p 27492:27492 \
    ghcr.io/gormaniac/stormsvcs/pcap:latest
```

```
service.add slib.pcap tcp://<user>:<passwd>@<host>:27492/*
```

The image builds tshark 4.6, Suricata 8, and Snort 3 (with libdaq) from source on the shared
Debian 12 base image. Build it without Snort with `--build-arg SNORT=no`.

### The Axon (recommended)

Set `axon:url` to the Axon the Cortex stores files in (the one `$lib.axon` uses). It's optional,
but without it the service is much less useful:

| | With `axon:url` | Without it |
|---|---|---|
| Captures and key logs | The service reads them from the Axon itself. | Storm streams each one to the service. |
| Files extracted from flows (HTTP, HTTP/2, FTP, SMB, email, TLS certificates) | Uploaded to the Axon, modeled as `file:bytes` and `file:attachment` nodes. | Counted, but not saved. |

The URL's user needs to read and write the Axon. `slib.pcap.status` and the `slib.pcap.admin.*`
commands warn admins when the service has no Axon, and `slib.pcap.flows` warns users when a
capture had files that couldn't be saved.

Captures, extracted files, and engine output are spooled to a temp directory under the service's
storage directory (not held in memory) and deleted once a capture is analyzed. `pcap:workers`
captures are analyzed at once, the rest wait.

### Sandbox

tshark, Suricata, and Snort parse untrusted input with a lot of C (and some Rust), so every run
of one is sandboxed:

- **An unprivileged user.** When the service runs as root (it does in the image) engines run as
  `sandbox:user` (`slib-pcap-engine`, uid 2000), which owns only the run's directory.
- **Landlock.** Engines can only read the run's inputs and the system files they need (the
  loader and libc config in `/etc`, not the rest of it), write the run's directory, and run
  their own binary. TCP connects and binds are refused too on kernels
  with Landlock ABI 4 or later.
- **seccomp.** IPv4, IPv6, and packet sockets are refused (the engine is killed and the try
  reported, see below).
- **no_new_privs, resource limits** (`sandbox:rlimits`: memory, CPU time, file size, open files,
  no core dumps), **a clean environment, a new process group** that is killed on timeout, and
  **capped output**.

Landlock and seccomp are features of the host's kernel (Landlock needs Linux 5.13 or later), not
the image. With Landlock the service gives the engine's user search permission on the
directories above an engine's files (ex. a 0700 storage directory) when it needs it. Without
Landlock it doesn't, since that would let a compromised engine open any file it can name in
them, like `cell.yaml`: keep the storage directory's files that hold secrets `0600`, and make
the directories searchable yourself if the engines can't get to their files. `sandbox:mode` `best-effort` (the default) applies every layer the host supports,
`strict` refuses to run engines without all of them, and `off` runs them directly.
`slib.pcap.status` shows what the host supports.

### Detecting sandbox escapes

The sandbox also watches what engines try, so a capture that exploits one is noticed, not just
contained. Every alert is logged, shown as a warning on the `slib.pcap.flows` run that caused
it (the capture may be malicious), and counted (with the latest ones) in `slib.pcap.status`:

| Alert | When |
|---|---|
| `seccomp` | An engine tried to open an IPv4, IPv6, or packet socket. The filter kills it (SIGSYS) instead of failing the call, the engines never open those offline. |
| `crash` | An engine died of a crash signal (SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT, SIGTRAP), often what an exploit attempt looks like. |
| `unconfined` | The kernel's view of the running engine (`/proc/<pid>/status`: its uids and gids, supplementary groups, capabilities, `NoNewPrivs`, `Seccomp`) doesn't match the layers its wrapper reported applying. |
| `leftover` | Processes of the run's process group were still running after the engine exited. They're killed. |
| `escaped` | A process that left its run's process group (ex. `setsid`), or that was orphaned to the service, is still running. The service is a child subreaper, so orphans become its children, and engine descendants are told apart from its other children by the seccomp filter and `no_new_privs` they inherit (and can't drop). They're killed. |
| `file` | A file the sandbox user owns outside the engines' directories (`/tmp`, `/var/tmp`, `/dev/shm`, and the storage directory are swept every 10 minutes). |

On kernels with Landlock ABI 7 (Linux 6.15+) the service also asks the kernel to log every
Landlock denial of the engines (`LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON`) to the audit log,
where host tooling can collect them (reading the audit log needs `CAP_AUDIT_READ`, which
containers don't have).

These checks run in the service's container, so an exploit that gets root there (ex. through a
kernel bug) can hide from them. Monitor the engine user (uid 2000) from the host too, ex. with
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

```
-a always,exit -F arch=b64 -S execve -F uid=2000 -F exe!=/opt/wireshark/bin/tshark -F exe!=/opt/suricata/bin/suricata -F exe!=/opt/snort/bin/snort -F exe!=/opt/snort/bin/snort2lua -k slib-pcap-exec
-a always,exit -F arch=b64 -S connect,bind -F uid=2000 -k slib-pcap-net
-a always,exit -F arch=b64 -S setuid,setreuid,setresuid,setgid,setresgid -F uid=2000 -k slib-pcap-priv
```

Landlock denials are audit records of type `LANDLOCK_ACCESS` (with `LANDLOCK_DOMAIN`) for the
engine user's processes.

### Configuration

| Option | Default | Description |
|---|---|---|
| `axon:url` | | The Telepath URL of the Cortex's Axon, see [The Axon](#the-axon-recommended). |
| `pcap:timeout` | `300` | The default seconds a flow can be idle before the next packet between the same endpoints starts a new flow, `0` to never time out. |
| `pcap:limit` | `100000` | The max number of flows for one capture. Packets for any more flows are dropped (and counted). |
| `pcap:handshake` | `1024` | The default max characters kept from each side's first text payload, `0` for none. |
| `pcap:maxsize` | `1073741824` | The max capture size in bytes (1 GiB), `0` for no limit. |
| `pcap:workers` | `2` | The max number of captures analyzed at once. |
| `pcap:uploads` | `16` | The max number of captures and key logs streamed to the service at once (without an Axon). |
| `pcap:files` | `true` | Extract the files sent in flows by default. |
| `pcap:files:maxsize` | `67108864` | The largest file extracted from a flow (64 MiB), `0` for no limit. |
| `pcap:files:limit` | `10000` | The max number of files extracted from one capture, `0` for no limit. |
| `pcap:feeds` | see [Rule feeds](#rule-feeds) | The feeds the service starts with. Only read the first time it starts, after that use `slib.pcap.admin.feed`. |
| `pcap:feeds:secrets` | `{}` | Secrets feed URLs use as `${name}`, each only sent to its hosts, ex. `{"talos:oinkcode": {"value": "...", "hosts": ["www.snort.org"]}}`. |
| `pcap:feeds:interval` | `24` | Hours between feed downloads. |
| `pcap:feeds:timeout` | `300` | Seconds before a feed download times out. |
| `pcap:feeds:maxsize` | `268435456` | The max size of a feed (and of the rules it unpacks to), 256 MiB. |
| `suricata:enabled` | `true` | Use Suricata, when it's installed, by default. |
| `suricata:bin` | `suricata` | The Suricata binary. |
| `suricata:conf` | | The base `suricata.yaml`, the service's outputs and settings are applied over it. Defaults to the installed one. |
| `suricata:vars` | `HOME_NET` RFC 1918, `EXTERNAL_NET` any | Suricata address variables (admins can override them, see `slib.pcap.admin.vars`). |
| `suricata:set` | `{}` | Overrides of Suricata's config as dotted keys, like `suricata --set`, ex. `{"stream.memcap": "2gb"}`. They win over the service's own settings. |
| `suricata:timeout` | `900` | Seconds before a Suricata run is killed. |
| `snort:enabled` | `true` | Use Snort, when it's installed, by default. |
| `snort:bin` | `snort` | The Snort 3 binary. |
| `snort:snort2lua` | `snort2lua` | The binary that converts Snort 2.x rules to Snort 3. |
| `snort:conf` | | The base `snort.lua`. Defaults to the installed one. |
| `snort:vars` | `HOME_NET` RFC 1918, `EXTERNAL_NET` any | Snort variables the base config assigns. |
| `snort:args` | `[]` | Extra arguments for every Snort run (operator only). |
| `snort:timeout` | `900` | Seconds before a Snort run (a rule build or a scan) is killed. |
| `tshark:enabled` | `true` | Use tshark, when it's installed, by default. |
| `tshark:path` | `tshark` | The tshark binary. |
| `tshark:args` | `[]` | Extra tshark arguments for every run (operator only, see [Engine settings](#engine-settings)). |
| `tshark:protocols` | the dissectors the service reads | The only dissectors tshark runs (`--only-protocols`), `null` for all of them. Fewer dissectors is less attack surface. |
| `tshark:keylog:maxsize` | `16777216` | The largest TLS key log read for a run (16 MiB), `0` for no limit. |
| `tshark:timeout` | `600` | Seconds a tshark run may take, `0` for no limit. |
| `sandbox:mode` | `best-effort` | `best-effort`, `strict`, or `off`, see [Sandbox](#sandbox). |
| `sandbox:user` | `slib-pcap-engine` | The user engines run as when the service runs as root. |
| `sandbox:rlimits` | 8 GiB memory, 1 hour CPU, 4 GiB files, 4096 files, no cores | Resource limits of an engine run (`as`, `cpu`, `fsize`, `nofile`, `core`), `0` is unlimited. |
| `sandbox:seccomp` | `true` | Refuse engines network sockets with seccomp. |

## Usage

```
// Analyze PCAPs that are already file:bytes nodes.
file:bytes:mime=application/vnd.tcpdump.pcap | slib.pcap.flows

// Yield the flows, tag them, and set the sensor that captured them.
file:bytes=sha256:<sha256> | slib.pcap.flows --yield --tag cno.case.123 --host <it:host guid>

// Yield the rule matches instead.
file:bytes=sha256:<sha256> | slib.pcap.flows --hits --yield | -> *

// Analyze by SHA-256 (the file:bytes node is created if needed).
slib.pcap.flows <sha256> --yield | +inet:flow:dst:port=443

// Every flow from a PCAP, and its rule matches.
file:bytes=sha256:<sha256> -(refs)> inet:flow
file:bytes=sha256:<sha256> -(refs)> (it:app:snort:hit, it:app:suricata:matched)
```

> Quote SHA-256s that start with `sha256:` on the command line. Storm's parser splits unquoted
> values like `sha256:6010E3...` at what looks like an exponent.

| Option | Default | Description |
|---|---|---|
| `sha256s` | | SHA-256s of captures to analyze instead of the inbound `file:bytes` nodes. |
| `--timeout` | `pcap:timeout` | Seconds a flow can be idle before a new flow starts, `0` to never time out. |
| `--limit` | `pcap:limit` | The max number of flows to model per capture (capped by `pcap:limit`). |
| `--handshake` | `pcap:handshake` | The max characters kept from each side's first text payload. |
| `--tag` | | A tag to add to every flow. |
| `--host` | | The `it:host` that captured the traffic: each flow's `:capture:host` and each hit's `:sensor`. |
| `--sandbox-file` | | The `file:bytes` a sandbox ran to make the capture, set as `:sandbox:file`. |
| `--keylog` | | The SHA-256 of a TLS key log (SSLKEYLOGFILE) to decrypt TLS with. May be used multiple times. |
| `--decode-as` | | A Decode As rule for this run, ex. `"tcp.port==8443,tls"` (quoted). May be used multiple times. |
| `--no-suricata`, `--no-snort`, `--no-tshark` | | Skip an engine. |
| `--no-rules` | | Don't match the capture against the rules (Suricata still parses protocols). |
| `--no-files` | | Don't extract the files sent in flows. |
| `--hits` | | With `--yield`, yield the rule matches instead of the flows. |
| `--yield` | | Yield the `inet:flow` nodes (or the matches) instead of the inbound nodes. |

The command prints how many flows and rule matches were modeled, and warns if the capture was
truncated, had more flows than `--limit`, had files over the extraction limits or that couldn't
be saved, or an engine failed. With `$lib.debug` set it also prints the capture's full summary
(format, link types, packet counts, why any packets were skipped, each engine's version and
warnings, engine events that matched no flow, and file counts).

For automations, `slib.pcap.lib` has `flows()`, which emits the `inet:flow` nodes and raises
`slib.pcap.Error` instead of warning:

```
$pcap = $lib.import(slib.pcap.lib)
for $flow in $pcap.flows($sha256, opts=({"tag": "my.tag", "timeout": (60)})) { yield $flow }
```

### TLS decryption

Give the command one or more NSS key logs (the `SSLKEYLOGFILE` format browsers, curl, and most
TLS libraries write) from the Axon:

```
slib.pcap.flows <pcap sha256> --keylog <keylog sha256> --yield
```

tshark then decrypts the TLS 1.2 and 1.3 sessions the key log has secrets for. Their
certificates (TLS 1.3 encrypts them), and the HTTP/1.1 and HTTP/2 inside them (software names,
requests, and files), are modeled like plaintext traffic. Secrets embedded in a pcapng file
(Decryption Secrets Blocks, ex. from `editcap --inject-secrets`) are always used. Key logs are
read with the same `slib.pcap.user` permission as captures, so treat a key log in the Axon as
readable by anyone with that permission.

### Engine settings

| Setting | Who | How |
|---|---|---|
| `tshark:args`, `snort:args`, `suricata:conf`, `suricata:set` | The service's operator | The service's config (`cell.yaml` or `SYN_PCAPSVC_*`). Not reachable from Storm. |
| Network variables (ex. `HOME_NET`) for every run | Cortex admins with `slib.pcap.admin` | `slib.pcap.admin.vars --set "HOME_NET=[10.0.0.0/8]"`, saved in a Cortex global, over `suricata:vars` and `snort:vars`. |
| Decode As rules for every run | Cortex admins with `slib.pcap.admin` | `slib.pcap.admin.decode --add "tcp.port==8443,tls"`, saved in a Cortex global. |
| Decode As rules for one run | Users with `slib.pcap.user` | `slib.pcap.flows ... --decode-as "tcp.port==8443,tls"`, used with the admin's rules. |
| TLS key logs for one run | Users with `slib.pcap.user` | `slib.pcap.flows ... --keylog <sha256>`. |

Network variables become Suricata `address-groups` for the run. For Snort, the ones the base
`snort.lua` assigns (ex. `HOME_NET`) are replaced in a per-run copy of it, so the variables the
stock `snort_defaults.lua` derives from them (ex. `HTTP_SERVERS`) follow, and the rest (ex.
`DNS_SERVERS`) are set in its `default_variables.nets` table. Values are validated as address
groups (IPs, CIDRs, `any`, `$VARIABLES`, and `[...]` lists of them) before they're saved.

`suricata:set` keys work like `suricata --set`, numbers index lists (ex.
`outputs.0.eve-log.enabled`), and a key that can't apply stops the service at startup.

Decode As rules go to tshark (`-d`) and, for the protocols Suricata parses, become extra
Suricata detection ports (`tcp.port`/`udp.port` rules only). Engines only parse protocols on
their usual ports (Suricata also probes for some), use Decode As rules for anything else.

Storm users can't pass arbitrary engine arguments: tshark options like `-X lua_script:` run code
and `-w` writes files. Decode As rules are validated against
`<selector>==<value>[-<value>],<protocol>` (ex. `udp.port==5000-5010,rtp`) before an engine sees
them, and engines run without a shell. Quote rules on the Storm command line, the Storm parser
can't read them unquoted.

## Rules

Rules are nodes in the graph: `it:app:snort:rule` for Snort rules and `it:app:suricata:rule` for
Suricata rules. The service runs every rule that's `:enabled=true` and has `:text`:

| Rule | Engine |
|---|---|
| `it:app:snort:rule` with `:engine=3` (or unset) | Snort 3. |
| `it:app:snort:rule` with `:engine=2` | Snort 2.x, converted to Snort 3 with `snort2lua` by the service. The node keeps the original text. |
| `it:app:suricata:rule` | Suricata. |

Engines refuse to start if any rule is invalid, so the service loads each engine's rules in test
mode, drops every rule the engine reports an error for, and tries again until it loads cleanly.
`slib.pcap.rule.errors` lists the rules that couldn't be loaded, and why. An engine runs one rule
per gid:sid (Snort 2 and 3 rules share Snort's, Suricata has its own), if several enabled rules
share one the highest `rev` wins (ties go to the lowest guid) and the others are reported as
duplicates. Rules for an engine the service doesn't have are reported too.

`slib.pcap.rule.errors` also lists warnings for rules that loaded but might not do what they
look like they do: rules with no content match (checked against all the traffic their header
matches) or a pcre without one (no fast pattern), `pass` rules (no other rule alerts on what
they match), `noalert` rules, and `drop`/`reject` rules (offline they only alert).

### Custom rules

Add rules from Storm, they're pushed to the service right away:

```
slib.pcap.rule.add 'alert http any any -> any any ( msg:"My rule"; http_uri; content:"/evil"; sid:1000001; rev:1; )'
slib.pcap.rule.add --engine suricata 'alert tls any any -> any any (msg:"Bad SNI"; tls.sni; content:"evil.example"; sid:1000002; rev:1;)'
slib.pcap.rule.check --engine snort2 --text 'alert tcp any any -> any 80 (content:"a"; http_uri; sid:1;)'
```

A custom rule's guid comes from its engine family and gid:sid, so adding it again (ex. a new
`rev`) updates the same node. Any `it:app:snort:rule` or `it:app:suricata:rule` made another way
works too: `slib.pcap.rule.enable` and `slib.pcap.rule.disable` push the change, and rules
changed any other way (ex. editing `:enabled` or `:text` directly) are picked up by the next sync.

### Rule feeds

| Feed | Engine | Enabled | |
|---|---|---|---|
| `snort3-community` | `snort3` | yes | The Snort 3 Community Ruleset from Cisco Talos (GPLv2). |
| `et-open` | `suricata` | yes | Proofpoint Emerging Threats Open, Suricata 8 syntax (MIT). |
| `abusech-sslbl`, `abusech-feodo`, `abusech-urlhaus` | `suricata` | no | abuse.ch's SSL Blacklist (certificates), Feodo Tracker, and URLhaus rules (CC0). |

Manage feeds with `slib.pcap.admin.feed`. Default feeds that are retired (`abusech-sslbl-c2`,
discontinued by abuse.ch) are removed from services that had them, unless an admin changed
their URL. A feed is a URL to a `.rules` file, or a `.tar.gz`,
`.tgz`, `.gz`, or `.zip` of them, and the engine its rules are for. Feeds that need a key (ex.
Talos' registered and subscriber rules, an ET Pro code) use `${name}` placeholders, filled in
from the service's `pcap:feeds:secrets` so the key isn't stored in the Cortex. Each secret lists
the hosts it may be sent to (exact, or `*.example.com`), since Cortex admins choose feed URLs:

```yaml
pcap:feeds:secrets:
  talos:oinkcode: {value: "<oinkcode>", hosts: ["www.snort.org", "snort.org"]}
```

```
slib.pcap.admin.feed add talos 'https://www.snort.org/rules/snortrules-snapshot-31200.tar.gz?oinkcode=${talos:oinkcode}' --engine snort3
```

The service doesn't ship a Talos feed. Whether you can use a ruleset (and how) is up to its
license and your subscription, check its terms before adding it.

### Syncing

`slib.pcap.sync` keeps the Cortex and the service in sync. It runs as a cron job created when
the service is added (hourly, at 17 past), as the admin that added the service, in their default
view. Change it with `slib.pcap.admin.schedule`. Each run:

1. **Syncs every enabled feed** (unless `--no-feeds`). A feed is downloaded when it's due (every
   `pcap:feeds:interval` hours, with `If-None-Match`/`If-Modified-Since`), its rules are parsed
   by the service, and modeled in the Cortex:
   - Each rule is an `it:app:snort:rule` or `it:app:suricata:rule` with a guid unique to the
     feed and the rule's gid:sid, in the feed's `meta:ruleset` (`-(has)>`). `:id` is the sid (or
     `gid:sid` if the gid isn't 1), `:name` the `msg`, `:version` the `rev`, and `:created` and
     `:updated` come from ET style metadata. Snort rules also get `:engine` and `:family`.
   - References become edges: `-(detects)> it:sec:cve`, `-(refs)> inet:url`, and
     `-(refs)> hash:md5`/`hash:sha256`.
   - A rule that joins the feed's ruleset gets the feed's enabled state (rules that are commented
     out in the feed are disabled). After that `:enabled` is up to the Cortex, a sync never
     re-enables a rule you disabled.
   - The feed's `:text` wins, a sync of a changed rule (or a `--force` sync) overwrites edits to
     a feed rule's text. To change a feed rule, add a custom copy with a higher `rev` (or a new
     sid) and disable the original.
   - Rules that leave the feed are disabled and removed from its ruleset.
   - Only the feed's changes since its last sync into the view are synced, so a daily update
     takes seconds. The first sync into a view, or one with `--force`, syncs every rule.
2. **Pushes every enabled rule** in the view to the service (unless `--no-push`), which replaces
   its rules with them and rebuilds each engine's rules if they changed.

Syncing edits nodes as root (in the job's view), so `slib.pcap.sync` holders don't need
permissions for the rulesets, references, and edges it makes. They do need permission to add
`it:app:snort:rule` and `it:app:suricata:rule` nodes to the view's layer, since a sync edits that
view and replaces the service's rules with the view's (the last push wins).

### Matches

Rule matches are grouped into one node per rule and flow:

- `it:app:snort:hit`: `:rule`, `:flow`, `:src`/`:dst` (the flow's client and server, and their
  IPs and ports), `:time` and `.seen` (the first and last alert), `:version` (the rule's rev),
  and `:sensor` (`--host`).
- `it:app:suricata:matched`: `:rule`, `:target` (the flow), `:time` and `.seen`, `:version`, and
  `:sensor`.
- The capture `-(refs)>` its matches, and the service's `meta:source` `-(seen)>` them. Each
  flow's `:raw` also lists its matches with their messages, actions, and counts.

Alerts from rules with a gid other than 1 (the engines' built in decoder and inspector rules)
aren't modeled as matches, they're counted by gid:sid in the capture's summary (see `$lib.debug`
above), with alerts for rules the service no longer has. Suricata's anomaly events (ex. invalid
TLS records, stream gaps) are listed in each flow's `:raw`.

## Permissions

| Permission | Grants |
|---|---|
| `slib.pcap.user` | Analyzing captures, checking rules, and viewing the status, rule errors, and feeds. |
| `slib.pcap.rules` | Adding, enabling, and disabling rules (pushing them to the service). Users also need the node permissions for the rule nodes. |
| `slib.pcap.sync` | Syncing the feeds into the Cortex (as root) and pushing the rules to the service. |
| `slib.pcap.admin` | Managing the feeds, the sync schedule, and the network variables and Decode As rules for every run. |

Users don't need `service.get` or Axon permissions, the `slib.pcap.priv.*` modules talk to the
service (and the Axon) and elevate privileges only for users that hold the matching permission.
Node edits run as the calling user, so they also need permission to create the nodes
(`inet:flow`, `file:bytes`, `inet:client`/`inet:server`, `inet:dns:request`, the match forms,
etc.).

## Commands

| Command | Description |
|---|---|
| `slib.pcap.flows` | Analyze captures and model their flows and rule matches. |
| `slib.pcap.status` | The engines and their versions, the sandbox, the Axon, the loaded rules, and the sync schedule. |
| `slib.pcap.sync` | Sync the feeds and push the rules (`--force`, `--feed`, `--no-feeds`, `--no-push`). |
| `slib.pcap.rule.add` | Add (or update) custom rules (`--engine snort3/snort2/suricata`, `--disabled`). |
| `slib.pcap.rule.enable` | Enable rules and push them. |
| `slib.pcap.rule.disable` | Disable rules and remove them from the service. |
| `slib.pcap.rule.check` | Check if the engines can load rules (nodes or `--text`), without changing the service. |
| `slib.pcap.rule.errors` | The rules the engines couldn't load, and why (`--yield` them). |
| `slib.pcap.feed.list` | The feeds and the state of their last download and sync. |
| `slib.pcap.admin.feed` | Add, remove, enable, or disable a feed. |
| `slib.pcap.admin.schedule` | Show or change the sync cron job. |
| `slib.pcap.admin.vars` | Manage the network variables (ex. `HOME_NET`) both engines use for every run. |
| `slib.pcap.admin.decode` | Manage the Decode As rules used for every run. |

Run any command with `--help` for its options and examples.

```
// Every capture with a match for a CVE.
it:sec:cve=cve-2021-44228 <(detects)- it:app:snort:rule <- it:app:snort:hit <(refs)- file:bytes

// Turn off a noisy rule.
it:app:suricata:rule:id=2013502 | slib.pcap.rule.disable

// Turn on every disabled ET Open rule for a malware family.
meta:ruleset:name=et-open -(has)> it:app:suricata:rule +:name~="cobalt strike" | slib.pcap.rule.enable
```

## Modeling

Each flow is an `inet:flow`. Every property the form has that a capture can tell you is set:

| Property | Value | Needs |
|---|---|---|
| `:time` | When the flow's first packet was captured. | |
| `.seen` | The first and last packet times. | |
| `:duration` | Seconds between the first and last packets (rounded). | |
| `:src` / `:dst` | The client and server as `inet:client`/`inet:server` (TCP, UDP, ICMP, and GRE only). | |
| `:src:ipv4` / `:src:ipv6`, `:src:port`, `:src:proto` | The client's address, port, and protocol (`:dst:*` for the server). | |
| `:src:txcount` / `:src:txbytes` | Packets and bytes the client sent (`:dst:*` for the server). | |
| `:tot:txcount` / `:tot:txbytes` | Packets and bytes sent both ways. | |
| `:src:handshake` / `:dst:handshake` | The first payload each side sent, if it's text (binary payloads like TLS are skipped). | |
| `:ip:proto` | The IP protocol number. | |
| `:ip:tcp:flags` | Every TCP flag seen in the flow, OR'd together. | |
| `:src:ssl:cert` / `:dst:ssl:cert` | The leaf `crypto:x509:cert` each side sent in its TLS handshake. | Suricata or tshark, TLS <= 1.2 or a key log |
| `:dst:ssh:key` | The server's SSH host key, a `crypto:key`. | tshark |
| `:src:rdp:hostname` / `:src:rdp:keyboard:layout` | The RDP client's computer name and keyboard layout. | Suricata or tshark, standard RDP security |
| `:src:softnames` / `:dst:softnames` | Software each side identified itself as: HTTP and HTTP/2 `User-Agent`/`Server`, SSH banners, SIP, SMB native OS/LAN manager, email clients (`User-Agent`/`X-Mailer`), QUIC and gQUIC user agents. | Suricata or tshark |
| `:src:cpes` / `:dst:cpes` | CPEs for well known software in the softnames (OpenSSH, Dropbear, nginx, Apache, IIS, lighttpd, curl, Wget, Thunderbird) with a version. | Suricata or tshark |
| `:src:txfiles` / `:dst:txfiles` | `file:attachment`s for the files each side sent. | Suricata or tshark, an Axon |
| `:capture:host` | The `it:host` given with `--host`. | |
| `:sandbox:file` | The `file:bytes` given with `--sandbox-file`. | |
| `:from` | A guid shared by every flow from the same capture. | |
| `:raw` | Everything else the service found, see below. | |

`:raw` has the flow's Community ID, VLANs, TCP state (`closed`, `reset`, or `open`), flag names,
ICMP types, per-direction payload bytes, the application protocols Suricata detected, TLS SNIs,
versions, ALPNs, and JA3/JA3S/JA4 fingerprints, HTTP hosts and requests, QUIC, SMB (commands,
dialects, shares, and files), Kerberos (message types, client and service names, realms,
encryption types, and errors), SIP, SMTP, and FTP details, the rule matches, and the anomalies.

Every flow is linked to its capture with `file:bytes -(refs)> inet:flow`, and to the service's
`meta:source` with `meta:source -(seen)> inet:flow`. A flow's guid is made from the capture's
SHA-256, the flow's endpoints and VLANs, and its start time, so analyzing the same capture again
updates the same nodes instead of creating duplicates.

### Application layer details

- **DNS** queries are `inet:dns:request` nodes (`:query`, `:query:name`, `:query:type`,
  `:server`, `:time`, and the response's `:reply:code`), linked with
  `inet:flow -(refs)> inet:dns:request`, and their answers `inet:dns:answer` nodes (`:a`,
  `:aaaa`, `:cname`, `:ns`, `:mx`, `:txt`, and `:ttl`). Needs Suricata.
- **TLS certificates** are modeled like `slib.crtsh` models them: `crypto:x509:cert` nodes
  deconflicted by SHA-256 with their subject, issuer, serial, validity, signature, SANs, and
  identities, and `:file` pointing at the DER (uploaded to the Axon). The rest of the chain a
  side sent is linked with `inet:flow -(refs)> crypto:x509:cert`. TLS 1.3 encrypts certificates,
  so TLS 1.3 handshakes only have them with a key log.
- **TLS and QUIC server names** (SNI) clients asked for are linked with
  `inet:flow -(refs)> inet:fqdn`.
- **SSH host keys** are `crypto:key` nodes deconflicted by the SHA-256 of the key's wire format
  blob (the hash OpenSSH fingerprints), with the blob as `:public`, its SHA-1 and MD5, and the
  key type as `:algorithm`. The service rebuilds the blob from tshark's fields for RSA, DSA,
  ECDSA, Ed25519, and Ed448 keys and checks it against the length on the wire.
- **RDP** client details are only in cleartext with standard RDP security. With TLS or
  CredSSP (NLA), the default on modern Windows, they're encrypted. The keyboard layout is its
  locale (ex. `en_us`), or its 8 digit KLID (ex. `00010409`, US Dvorak) when it isn't one.
- **Software names** are the whole value each side sent, lowercased and single spaced, ex.
  `openssh_9.6p1 ubuntu-3ubuntu13.20` and `nginx/1.24.0`.
- **Files** are uploaded to the Axon and modeled as `file:bytes` (with `:size`, and `:mime` from
  the Content-Type when the node doesn't have one) and a `file:attachment` per flow side:
  - HTTP request and response bodies (de-chunked and decompressed). Multipart uploads are split
    into their files. `:name` is the file name at the end of a GET's URI, or a multipart part's
    file name.
  - HTTP/2 request and response bodies, named like HTTP/1.1's.
  - FTP transfers (`RETR`, `STOR`, `STOU`, `APPE`, not directory listings), named by the
    command's path.
  - Files read and written over SMB, named by their path.
  - Emails sent over SMTP, as the whole message (`message/rfc822`, with its subject as
    `:text`), plus each attachment with its file name.

  Files with bytes missing from the capture are still extracted, and marked `complete: false`
  in `:raw`. Files over `pcap:files:maxsize` are skipped (and counted).
- **Not from a capture:** `:src:host`/`:dst:host`, `:src:proc`/`:dst:proc`, and
  `:src:exe`/`:dst:exe` describe the hosts and processes behind the traffic, which packets don't
  carry, and `:src:ssh:key` (a client's key is only sent after encryption starts). Set
  `:capture:host` and `:sandbox:file` with `--host` and `--sandbox-file`.

### How packets become flows

- Bytes are counted at the IP layer, from the IP header's length fields, so they're the bytes on
  the wire even when the capture's snaplen truncated the packet.
- The client (`:src`) is the side that sent the TCP SYN (or received the SYN-ACK), or the ICMP
  echo/timestamp/info/mask request. Otherwise it's the first sender, unless the capture joined a
  TCP connection mid-stream or the first UDP packet came from a privileged port (< 1024) to an
  unprivileged one; then the side using the privileged (or lower, for TCP) port is the server.
- A flow ends when it's idle for `--timeout` seconds, or when a TCP SYN reuses the ports of a
  connection that was reset or closed by both sides. The next packet starts a new flow. Suricata
  and Snort keep their own flow tables, so with unusual timeouts an engine's events can land on
  the flow that the packet they were logged on belongs to rather than the one the engine saw.
- Packets on different VLANs are different flows, even with the same addresses and ports.
  Community IDs don't include VLANs, so engine records without a frame number are matched by
  their VLANs too.
- libpcap (which Suricata and Snort read captures with) can't read a pcapng with interfaces of
  different link types, so the service splits those into a pcap per link type for them and
  maps their packet numbers back to the capture's frames.
- Non-IP packets (ex. ARP), unsupported link types, malformed packets, packets cut off before the
  end of their transport header, and IP fragments after the first (they have no ports) are
  skipped and counted in the summary.

## Testing

```bash
cd svcs/pcap
uv sync
uv run pytest tests
```

The flow tests build every capture they use (pcap, pcapng, gzip, each link type) in
`tests/pcapgen.py`, and the rule tests in `tests/pcaps.py`. The engine tests use real traffic
recorded on loopback in `tests/data/` (HTTP, TLS 1.2 with a client certificate, TLS 1.3 HTTP/1.1
and HTTP/2 with its key log, SSH, SSH with the sntrup761 post-quantum key exchange, passive and
active FTP, SMTP with an attachment, RDP, DNS, QUIC, SMB, Kerberos, and SIP over UDP), plus
corner cases (a connection joined midstream, a reused 5-tuple, ICMP unreachable, the same
5-tuple on two VLANs, and a gzipped pcapng with two link types), see `tests/data/capture.py` to
re-record them. `tests/test_fixtures.py` checks that Suricata finds what tshark does (parity),
and that the engines agree on frame numbers and Community IDs. The sandbox tests probe what a
compromised engine would try (reading `/etc/shadow` or another run's capture, writing outside
its directory, opening sockets, spinning, or flooding its output). No test calls out to external
services, the feed tests use a local feed server (`tests/fakefeeds.py`).

The tests that need an engine skip when it isn't installed (ex. on a dev machine or the CI host
job). CI also runs every test in the service's test image (`docker/test/Dockerfile`, built on
the new production image), which has all of them and fails instead of skipping
(`SLIB_PCAP_REQUIRE=1`). To run them locally:

```bash
docker build -f docker/prod/Dockerfile -t ghcr.io/gormaniac/stormsvcs/pcap:latest .
docker build -f docker/test/Dockerfile -t stormsvcs-pcap-test .
docker run --rm stormsvcs-pcap-test
```

CI caches every image build stage (the engine builds take a while from scratch) in the GitHub
Actions cache.
