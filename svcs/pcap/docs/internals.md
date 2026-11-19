# Internals

This page walks through `pcapsvc` ({src}`svcs/pcap/src/pcapsvc`) for maintainers. The rules
subsystem and the sandbox have their own pages: [Rules and feeds](rules.md) and
[Sandbox](sandbox.md). For the shape every service shares, see {doc}`/dev/architecture`.

## Modules

| Module | Role |
| --- | --- |
| `__init__.py`, `__main__.py` | `__version__`, and `PcapSvc.execmain(argv)` as the entry point. |
| `defs.py` | `SVC_NAME` (`slib.pcap`), `SVC_GUID` (the `meta:source`), the add/del event Storm, the cron and rules-view global names, `SlibPcapPkg` (a `stormlibpp.StormPkg` loading `pkgproto/slib.pcap.yaml`), `PKGDEFS`. |
| `api.py` | `PcapCellApi`, see [Telepath API](api.md). `FLOW_OPTS` lists the options `flows` accepts. |
| `svc.py` | `PcapSvc`: config, uploads, the Axon, running the engines, correlation, analysis. |
| `rulesvc.py` | `RuleMixin` (mixed into `PcapSvc`): pushes, builds, rule errors, feeds. |
| `rules.py` | Rule text parsing, references, network variable validation, rule warnings. |
| `feeds.py` | Feed definitions, secrets, download, unpacking, rule records. |
| `snort.py` | `Snort`: config generation, `snort2lua`, rule validation, scans. |
| `suricata.py` | `Suricata`: config generation, rule validation, runs. |
| `tshark.py` | `Tshark`: field discovery, runs, Decode As validation. |
| `sandbox.py`, `_sbxexec.py` | The engine sandbox, see [Sandbox](sandbox.md). |
| `flows.py` | Pure Python capture readers, the flow table, loose matching, `analyze()`. No Synapse dependencies besides `s_common.guid`. |
| `enrich.py` | `Enricher` (per-flow details from tshark frames and engine events), `FileStore`, software/CPE rules. |
| `eve.py` | Suricata EVE events and engine alerts to flow details, DNS queries, hits. |
| `x509.py` | Certificate parsing with `cryptography`. |
| `communityid.py` | Community ID v1, matching Suricata's ICMP handling. |

## Startup

`PcapSvc.__anit__`:

1. `Cell.__anit__`, then removes and recreates `<dirn>/tmp`.
2. Builds `Sandbox`, `Tshark`, `Snort` (workdir `<dirn>/snort`) and `Suricata` (workdir
   `<dirn>/suricata`) from the config.
3. With `suricata:set`, generates a Suricata config once, so a bad key raises `BadConfValu`
   now instead of failing every run.
4. `self.runsema = asyncio.Semaphore(pcap:workers)`, `self.uploads = {}`.
5. `_initRules()` (see [Rules and feeds](rules.md#service-state)): opens the slab keyvals, seeds
   feeds from `pcap:feeds` on first start, removes retired default feeds, loads the active rules
   files, and schedules a rebuild if they're missing.
6. `sandbox.reach()` on `tmp`, `rules/active`, and the engine workdirs, so the engine user can
   get to them.
7. Opens the `aiohttp.ClientSession(trust_env=True)` used for feeds, registers `fini`s to close
   it and to `sandbox.restore()` directory modes.
8. Starts `_pruneLoop()`: every 600 seconds it prunes idle uploads and pushes (1 hour) and runs
   `sweepSandbox()`.

## Analysis pipeline

`PcapSvc.flows()` calls `analyze()` and yields the summary, then each flow.

### 1. Validation and claims (`analyze`)

- `normSha256` the capture and key logs, `checkDecodeAs`, `checkNetVars`, `_opts` (fill and cap
  `timeout`, `limit`, `handshake`). A failure here drops the run's unclaimed uploads, since no
  run would ever consume them.
- Fails without `axon:url` when there's no upload, or when key logs are given by SHA-256.
- Marks its uploads `busy` (so the idle prune can't remove them while it waits for a worker),
  then waits on `runsema`.
- Sets the `RUN_ALERTS` context variable to a fresh list (every engine run of this analysis
  appends its sandbox alerts) and creates a `threading.Event` that executor work polls, since a
  thread can't be cancelled. When the Storm query is killed, the task is cancelled, the event
  is set, and the engines are killed (see [Sandbox](sandbox.md#bounds-from-outside)).
- Runs `_analyze` in a `tempfile.TemporaryDirectory(dir=<dirn>/tmp)`.

### 2. Fetch (`_fetch`)

The capture goes to `<run>/capture`, moved from its upload (`_takeUpload`, which checks the
upload's SHA-256 matches) or downloaded from the Axon (`axon.size` checked against
`pcap:maxsize` first, then `axon.get`). Key logs (uploads first, then Axon ones) are appended
into one `<run>/keylog`, each followed by a newline, with their total capped at
`tshark:keylog:maxsize`.

### 3. Decompress

If the file starts with `1f 8b`, it's gunzipped in an executor to `<run>/capture.pcap` (Snort and
Suricata need a plain capture, dpkt and tshark read either), capped at
`pcap:maxsize:decompressed`.

### 4. Engines (`_engines`)

- If Suricata or Snort will run, `flows.splitLinktypes` checks the capture: libpcap can't read a
  pcapng with interfaces of different link types, so those are split into one nanosecond pcap per
  link type (`linktype-<n>.pcap`, snaplen 262144, timestamps clamped to what pcap can hold), each
  with the list of original frame numbers of its packets.
- `sandbox.prepare(<run>)` hands the run's directory to the engine user.
- Runs concurrently with `asyncio.gather`:
  - `_runSuricata`: for each part, `Suricata.run` with the active Suricata rules (if `rules`
    and any are loaded), Decode As ports, file store on when files are being saved, the body
    limit, and the network variables. Multiple parts are merged (`_mergeSuricata`): EVE records
    get their `pcap_cnt` mapped back to the capture's frame numbers and file stores are merged.
  - `_runSnort` (only with `rules` and loaded Snort rules): `Snort.scan` per part, `pkt_num`
    mapped back the same way.
  - `_runTshark` on the original capture (gzip is fine), with `gaps=True` when Suricata runs too.
- Each acquired rules file is reference counted (`_acquire`/`_release`), so a rebuild during a
  run doesn't delete the file the run is using.
- If Suricata failed and tshark ran in gap mode, tshark is run again for everything.

### 5. Correlate (`_correlate`)

In an executor (EVE output can be hundreds of MB), every Suricata event and Snort alert is put
on its frame in the tshark `frames` dict: `_eve` for Suricata events (except `stats`),
`_alerts` for `(engine, alert)` pairs. Records without a frame number become "loose"
`(community_id, time, kind, record)` tuples. Snort alerts without `pkt_num` get a Community ID
computed from their `proto`, addresses and ports (`alertCommunityId`; for ICMP Snort puts the
type and code in the port fields).

### 6. Flows (`flows.analyze`)

In an executor, reading the capture file:

- `readPackets` streams `Packet(ts_ns, linktype, data, num)` from pcap (both byte orders, micro
  and nanosecond magics), pcapng (per-interface link type, `if_tsresol`, `if_tsoffset`, multiple
  sections, EPB/PB/SPB), or gzip of either (decompressed once, nested gzip refused). Read errors
  after the header mark the summary `truncated` with the `error`, everything before is kept.
  Records over 256 MiB are treated as corruption.
- `decodePacket` handles Ethernet (VLAN/QinQ, PPPoE via dpkt), raw IP (101, 12, 14, 228, 229),
  NULL/LOOP (by IP version, since the family varies by OS), Linux SLL and SLL2, and PPP.
- `FlowTable.add` keys and builds flows (see [Data model](model.md#how-packets-become-flows)) and
  appends each frame's engine record to its flow with whether the client sent it.
- `Flow.asdict` builds each flow's dict and guid.
- `_ownEvents`: Suricata logs some events on a later packet that can be another flow's (ex. a
  flow timeout). Events and alerts whose Community ID isn't the flow's are moved to the loose
  list.
- `matchLoose` assigns loose records to flows with the same Community ID: when several match,
  those with the record's VLANs first, then the flow active at the record's time, then within a
  second of it (closest end first), then the closest. Unmatched records are counted.
- For each flow an `Enricher` collects tshark fields (`add`), the flow's EVE events and alerts,
  and `apply()` builds the final dict: finishing FTP transfers (reassembling data segments by
  TCP sequence, marking gaps incomplete) and HTTP/2 streams, applying EVE (`eve.applyEve`),
  copying the per-side details, collecting `tls`, `http`, the per-protocol lists, `dns`
  (`eve.dnsQueries`) and `hits` (`eve.hits`).
- The cancel event is checked every 1000 packets and every flow.

### 7. Upload and summarize

Files in the run's `FileStore` that the Axon doesn't have are uploaded in 1 MiB chunks. The
summary gets the SHA-256, size, key log count, Decode As rules, network variables, the engines'
info, and the run's sandbox alerts. The run directory is deleted when `_analyze` returns.

## Engine output handling

Engine output is untrusted, since the engines parse attacker-controlled input:

- EVE and alert_json lines that aren't JSON are skipped and logged.
- A malformed tshark frame or EVE event (wrong types, bad hex or base64) is skipped from that
  point and counted under `summary.events.malformed` (ex. `tshark:frame`, `suricata:tls`,
  `suricata:fileinfo`, `snort:alert`).
- Files from Suricata's file store are copied by `FileStore.addPath`, which opens them one path
  component at a time with `O_NOFOLLOW` under the file store root (so a directory the engine
  replaced with a symlink can't point elsewhere), requires a regular file, and re-hashes and
  sizes the bytes while copying. The EVE `sha256` must be 64 hex characters to be used as a
  path.
- `_mergeSuricata` only moves two-character, non-symlink subdirectories of the file store.

### Side attribution

EVE events are attributed by what they describe, not by the packet they were logged on: a TLS
`chain` is the server's and `client.chain` (Suricata 8, `client_chain` before) the client's, an
HTTP `User-Agent` the client's and `Server` header the server's, SSH `client`/`server`
software, SMB `request`/`response` native OS/LM, RDP `connect_request` the client's. `fileinfo`
events go to the side that sent the file (`src_ip`/`src_port` compared with the flow's client).
tshark fields go to the side that sent the frame.

### HTTP file names

For HTTP request bodies the name is the request URI's basename. A response body only gets the
URI's basename when its request was a `GET` (a POST's response isn't the posted file).
tshark responses are paired with requests in order. On tshark 4.6, which no longer has
`http.response_for.uri`, `_responseUris` fills it from `http.request_in`.

## tshark

`Tshark.load()` (once) runs `tshark -v` (version), `tshark -h` (whether `--only-protocols`
exists), and `tshark -G fields` (into a file) to learn which of `FIELDS` the installed tshark
supports. A run (`frames`):

```text
tshark -n -r <capture> [tshark:args] [--only-protocols <protocols>] [-o tls.keylog_file:<keylog>]
       [-d <rule> ...] -Y "<filter>" -T ek -e frame.number -e <field> ...
```

- `FIELDS`: TLS certificate, SNI, JA3/JA3S/JA4; SSH protocol and host key fields; RDP client
  name and keyboard layout; HTTP method, URI, response URI, request frame, host, user agent,
  server, content type, file data; HTTP/2 stream, type, headers and data; FTP data command, TCP
  seq and payload; SIP `User-Agent`/`Server`; IMF and its user agent, mailer, subject; gQUIC
  `uaid`.
- The display filter ORs the `FILTER` fields, so only frames worth reading are returned.
- With `gaps=True` (Suricata ran, no key log) only fields starting with `ssh.`, `sip.` and `imf`
  are requested.
- `--only-protocols` is `tshark:protocols` (default `PROTOCOLS`: link layers and tunnels, IP,
  ICMP, TCP, UDP, TLS and X.509, SSH, RDP and its TPKT/COTP/T.124/T.125 stack, HTTP, HTTP/2,
  MIME multipart, FTP, SMTP, IMF, SIP, SDP, gQUIC, QUIC), plus each Decode As rule's protocol,
  filtered to protocols this tshark knows.
- When any frame has IMF, a second run (`-Y imf -T json -x -J "frame imf"`) gets each email's raw
  bytes as `imf.raw`.
- stdout is written straight to a file (bounded by the `fsize` rlimit), stderr is capped at
  64 MiB. A non-zero exit with some records keeps them and reports the `error`, with none it
  fails.
- The environment points `HOME`, `TMPDIR`, `WIRESHARK_CONFIG_DIR` and `XDG_CONFIG_HOME` at the
  run's scratch directory, so no user profile is read.

## Suricata

`Suricata.config()` deep-copies the base `suricata.yaml` and sets:

- `vars.address-groups` from `suricata:vars` and the run's network variables.
- One `eve-log` output (`eve.json`, Community ID with seed 0) with `alert` (metadata, no
  payload), `anomaly` (decode, stream, applayer), `http` (extended, all headers), `dns`, `tls`
  (extended, custom fields incl. `chain`, `client_chain`, JA3/JA3S/JA4, ALPNs), `files`
  (SHA-256), `smtp` (extended with extra headers), `ftp`, `rdp`, `smb`, `krb5`, `sip`, `quic`,
  `ssh`, `http2`, `flow`. A `file-store` v2 output (`filestore`, `force-filestore`), enabled
  only when files are saved.
- Console logging at `notice`, stats off, `default-log-dir` the run directory.
- Enables the `dns`, `ftp`, `http`, `http2`, `krb5`, `quic`, `rdp`, `sip`, `smb`, `smtp`, `ssh`,
  `tls` parsers, JA3 and JA4 fingerprints, HTTP request/response body limits of
  `pcap:files:maxsize + 1` (a body over the limit is one that was cut off), SMTP `decode-mime`,
  and Decode As detection ports.
- `stream`: no checksum validation, `midstream: true`, reassembly `depth: 0` (whole streams,
  bounded by memcaps), no random chunk sizes. `pcap-file.checksum-checks: no`.
- `unix-command` off, `runmode: single`, `rule-files: []` (rules are given with `-S`), the
  classification, reference and threshold files from the config directory, Suricata's own
  Landlock off (the service's sandbox applies it), `plugins` removed.
- Finally `suricata:set` overrides.

A run: `suricata -c <conf> -r <capture> -l <run> -k none --runmode single` plus `-S <rules>` or
`--disable-detection`. A non-zero exit fails the run. `W:` lines (except `output-json-tls`)
become the run's warnings.

## Snort

`Snort.writeConf()` copies the base `snort.lua` with each `snort:vars` assignment line
(`^NAME\s*=`) replaced by `NAME = '<value>'`, and fails if a variable isn't assigned there. A
scan:

```text
snort -c <conf> --include-path <base conf dir> -R <rules> -r <capture> -k none -q -y -U
      -l <logdir> -A alert_json --lua "alert_json = { file = true, fields = '<ALERT_FIELDS>' }"
      [--lua "if default_variables and default_variables.nets then ... end" ...] [snort:args]
```

`ALERT_FIELDS`: `seconds timestamp proto src_addr src_port dst_addr dst_port gid sid rev msg
action dir pkt_num vlan`. With network variables, a per-run config is written with them
replaced, and the ones the base config doesn't assign are set in `default_variables.nets`.
Snort exits 0 when the DAQ can't open the capture, so `Couldn't start DAQ instance` /
`Failed to start DAQ instance` in its output also fails the scan. `Error receiving message
from the DAQ` lines become warnings (ex. a truncated capture).

## Community ID

`communityid.communityId` implements Community ID v1 (seed 0, SHA-1, base64, `1:` prefix). For
ICMP and ICMPv6 it hashes the type and its counterpart type (ex. 8 and 0), or 0 for a type
without one (ex. 3, unreachable), and orders the endpoints like any other flow, which is what
Suricata does (and differs from the spec for one-way types), so the IDs match Suricata's. A
flow's ICMP Community ID is computed from its first ICMP packet.

## State and background work

| State | Where | Lifetime |
| --- | --- | --- |
| Uploads | `self.uploads` (memory) and `tmp/upload-<iden>` | Until consumed by a run, cancelled, or idle for 1 hour. Lost on restart (`tmp/` is cleared). |
| Pushes | `self.pushes` (memory) | Until `pushDone`/`pushCancel`, or idle for 1 hour. |
| Rules, feeds | Slab keyvals and `rules/` | Persistent, see [Rules and feeds](rules.md#service-state). |
| Engine versions | `self.versions` (memory) | Process lifetime. |
| Sandbox alerts | `self.sandbox.alerts` (last 100) and `alertcount` | Process lifetime. |

Background: `_pruneLoop` (every 10 minutes: uploads, pushes, sandbox sweep) and, at startup,
`_initBuild` when the active rules files are missing.

## Logging

The service logs with `logging.getLogger(__name__)` per module: sandbox alerts and skipped
engine records (warning), rule builds (info), feeds with unparsable rules (warning), and
directories the engine user can't reach (warning). Unexpected API errors are logged with
tracebacks by `RetnApi`.

## The Storm package

{src}`svcs/pcap/src/pcapsvc/pkgproto/slib.pcap.yaml` declares the four permissions, seven modules
and 13 commands. There are no `configvars` and no `onload`. Design points:

- **Privilege split.** Only the `slib.pcap.priv.*` modules call `$lib.service.get("slib.pcap")`
  (and `$lib.axon`). They're declared with `asroot:perms`, so they run as root for callers with
  the matching permission. Everything that edits nodes on a user's behalf (`slib.pcap.model`,
  `slib.pcap.lib`) runs as the caller, so node permissions still apply. `slib.pcap.priv.sync`
  calls `slib.pcap.model` from its root context, which is how syncing edits rules as root.
- **Streaming without an Axon.** `slib.pcap.priv.user.flows` checks `hasAxon()`. Without one it
  reads the capture and key logs with `$lib.axon.read(..., size=1048576)` and streams them with
  `uploadStart`/`uploadChunk`, passing `{"upload": <ID>, "sha256": <SHA-256>}` for key logs so
  the service checks their hashes. Uploads of a failed run are cancelled.
- **Globals.** `slib:pcap:vars`, `slib:pcap:decode`, `slib:pcap:cron`, `slib:pcap:rules:view` are
  read and written with `$lib.globals.get()/set()` (lint rule R005 is ignored: the package
  requires Synapse `<3.0.0`).
- **Pipeline rules in functions.** A `for` loop that runs while a node is in a function's
  pipeline sends the node downstream after the first iteration, so model and sync functions
  that loop never hold a node, and helpers like `setProp`/`addValu`/`refs` yield and edit the
  node in their own runtime.
- **Commands that yield once.** `slib.pcap.rule.add`, `.rule.errors` and `.feed.list` collect
  nodes in `init` and yield them in `fini` with `--yield`, the inbound nodes pass through
  otherwise (`-$cmdopts.yield`).
- **Lint.** CI runs Synapse's Storm linter with `storm_lint: block`. The `noqa` comments mark
  2.x-only APIs (`$node.form()`, `.seen`, `it:app:snort:hit`, `$lib.cron.enable()`).

The package README is `pkgproto/README.md`, a copy of the service README.

## Tests

```bash
cd svcs/pcap
uv sync
uv run pytest
```

`conftest.py` loads the `stormlibpp.testing` plugin, which fails tests that use deprecated
Synapse APIs. `pyproject.toml` turns `DeprecationWarning`s from `pcapsvc` into errors.

| File | Covers |
| --- | --- |
| `test_flows.py` | Readers, link types, flow building, Community IDs, splitting, loose matching (captures built by `pcapgen.py`). |
| `test_enrich.py` | `pcapsvc.enrich` and `pcapsvc.x509` with hand built tshark records (no tshark). |
| `test_eve.py` | `pcapsvc.eve` with recorded style EVE lines (no Suricata). |
| `test_tshark.py` | `pcapsvc.tshark` and tshark enrichment of the captures in `tests/data`. |
| `test_suricata.py`, `test_snort_engine.py` | The Suricata and Snort wrappers (config tests run everywhere, the rest run the engines). |
| `test_rules.py`, `test_feeds.py` | `pcapsvc.rules` and `pcapsvc.feeds` (no engines). |
| `test_rulesvc.py` | Feeds synced into a Cortex (from the local feed server in `fakefeeds.py`), pushes, custom rules, and hits in captures (`pcaps.py`). |
| `test_sandbox.py` | `pcapsvc.sandbox` and `_sbxexec`: what a compromised engine would try (reading `/etc/shadow` or another run's capture, writing outside its directory, opening sockets, spinning, flooding its output, leaving its process group). |
| `test_fixtures.py` | The recorded corner case captures through each engine, Suricata/tshark parity, and that the engines agree on frame numbers and Community IDs. |
| `test_svc.py` | `PcapSvc` and its Telepath API, the version checks, and that `pkgproto/README.md` matches the README. |
| `test_pcap_storm.py`, `test_model_storm.py` | The Storm package in a test Cortex with an Axon (`getTestCoreProxSvc`): commands, modeling (crafted flows for `test_model_storm.py`), permissions. |

`tests/data/` holds real traffic recorded on loopback (HTTP, TLS 1.2 with a client certificate,
TLS 1.3 HTTP/1.1 and HTTP/2 with `tls13.keylog`, SSH, SSH with sntrup761, passive and active FTP,
SMTP with an attachment, RDP, DNS, QUIC, SMB, Kerberos, SIP, VLANs) plus corner cases
(`corner.pcapng`, `multi.pcapng.gz` with two link types). `tests/data/capture.py` re-records
them. `pcaps.py` builds the rule test captures.

Tests that need an engine use `tests/engines.py`'s `needs(...)`: they skip when the binary isn't
on `PATH`, unless `SLIB_PCAP_REQUIRE=1`, then they fail. CI runs the host test job (engines
missing, they skip) and the test image (`docker_tests: true`), which has every engine and sets
`SLIB_PCAP_REQUIRE=1`. No test calls an external service. To run the full suite locally:

```bash
docker build -f docker/prod/Dockerfile -t ghcr.io/gormaniac/stormsvcs/pcap:latest .
docker build -f docker/test/Dockerfile -t stormsvcs-pcap-test .
docker run --rm stormsvcs-pcap-test
```

See {doc}`/dev/testing` and {doc}`/dev/ci`.
