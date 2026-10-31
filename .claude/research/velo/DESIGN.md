# slib.velo — Velociraptor IR/EDR Advanced Power-Up: Design Document

**Status:** DESIGN — no code yet. This document is the implementation plan.
**Date:** 2026-10-31
**Targets:** Velociraptor 0.77.x (0.73+ compatible where noted) · Synapse ≥ 2.256.0 · stormsvcs conventions
**Research appendices (same directory):** `velociraptor-research.md` (API/object model, verified against
Velocidex/velociraptor master + protos) and `synapse-model-research.md` (verified against a live
`getModelDict()` dump of synapse 2.256.0). Every form/property/edge named below exists in that dump unless
explicitly marked as a workaround.

---

## 1. Overview

### 1.1 Goal

A Storm Service ("Advanced Power-Up") that connects a Synapse Cortex to one or more
[Velociraptor](https://docs.velociraptor.app) deployments and models **everything Velociraptor documents
during an incident response**:

- **Managed/investigated devices** — every enrolled client, its OS/identity/agent metadata, and its labels.
- **Collections** — every hunt and flow, what was asked (artifacts + parameters), who asked, when, and the
  outcome (state, stats, errors, logs).
- **Findings** — every result row of every artifact, mapped to first-class forensic forms (processes, network
  connections, files, registry, event logs, services, tasks, users, YARA/Sigma hits, browser history, …), with
  a lossless generic fallback for artifacts the service doesn't know.
- **Alerts** — `Server.Internal.Alerts` rows, monitoring/detection-artifact hits, and analyst annotations, as
  `risk:alert` nodes wired to their evidence.
- **Collected files** — uploaded file content pushed into the Axon with full hash/path/host linkage.
- **Timelines** — Velociraptor notebook super-timelines ingested as curated `meta:timeline`/`meta:event`
  structures, **plus** service-built timelines: one *full-incident* timeline and one *per-device* timeline per
  investigated host.
- **The incident itself** — a `risk:compromise` hub node (with per-incident tag) that every ingested node is
  reachable from, so an analyst can lift the entire incident subgraph with one query.

After a full IR engagement in Velociraptor, `slib.velo.incident.sync` should reproduce the investigation
inside Synapse as a connected graph: incident → hunts → flows → hosts → forensic evidence → alerts →
timelines, with provenance on every node.

### 1.2 Non-goals (v1)

- **Not a Velociraptor GUI replacement.** No artifact authoring, no client-monitoring table management, no
  user administration (an `--admin` raw-VQL escape hatch covers rare needs).
- **No endpoint response actions by default.** Starting collections/hunts *is* in scope (it's how analysts
  drive an IR from Storm) but is gated behind its own permission; quarantine/kill/remediation VQL is out of
  scope for v1.
- **No direct filestore/datastore reads.** The 0.75 filestore compression and the explicit "internal/unstable"
  warnings make the gRPC `Query()` API the only integration surface (plus `VFSGetBuffer` for bytes). Offline
  collector/export-zip import is a v2 candidate (§14).
- **No plaso-style raw-disk super-timelining.** We ingest what Velociraptor has; we don't re-parse disk images.

### 1.3 Why this is a big service

Velociraptor has **no first-class "finding" object and no fixed schemas** — artifacts are open-ended named VQL
packages whose output columns vary by artifact, artifact version, OS, and custom overrides. The service
therefore needs: a per-artifact **mapper registry** with a lossless fallback; defensive **timestamp
normalization** (µs/s/ns/RFC3339 are all in play); **watermark-based incremental sync** (no server-side
cursors on `Query()`); **org iteration** (multi-tenancy); and a **two-sided timeline model** (Velociraptor's
curated notebook timelines + machine timelines derived from `:time` props). Each is designed below.

---

## 2. Background (condensed; see research appendices for field-level detail)

### 2.1 Velociraptor object model in one paragraph

Clients (`C.xxx`) hold persistent connections to the server. Analysts schedule **flows** (`F.xxx`) — a
collection of **artifacts** (named VQL packages, types `CLIENT`, `CLIENT_EVENT`, `SERVER`, `SERVER_EVENT`,
`NOTEBOOK`) — on one client, or fan them out to many clients as a **hunt** (`H.xxx`). Results are JSONL result
sets per `(client, artifact, flow)`; collected file bytes are **uploads** in the filestore. `CLIENT_EVENT`
artifacts stream rows continuously into per-day monitoring result sets. Analysts work in **notebooks**
(`N.xxx`, VQL/markdown cells) and build **super-timelines** (named sets of component timelines; rows =
`Timestamp, Message, Description, <original columns>, _Source`; analyst-curated rows live in the reserved
`Annotation` component). The `alert()` VQL function routes `{client_id, name, timestamp, event_data, artifact,
artifact_type, flow_id}` rows into the `Server.Internal.Alerts` server-event queue. **Orgs** partition
everything; the root org has an empty id. The one stable API: streaming gRPC
`Query(VQLCollectorArgs) → stream VQLResponse` over mTLS (api_client yaml with CA/cert/key; certs expire after
1 year), plus `VFSGetBuffer` for filestore bytes. All enumeration is server-side VQL: `clients()`, `flows()`,
`hunts()`, `hunt_flows()`, `hunt_results()`, `source()`, `uploads()`, `monitoring()`, `watch_monitoring()`,
`timelines()`, `timeline()`, `notebook_get()`, `artifact_definitions()`, `orgs()`.

### 2.2 Synapse model anchors (all verified in 2.256.0)

- **Provenance:** `meta:source` + `meta:source -(seen)> *` edges (the `meta:seen` *form* is deprecated).
  `meta:source` carries `:ingest:cursor/:latest/:offset`; `meta:feed` (`:source`, `:cursor`, `:latest`,
  `:offset`, `:period`, `:query`, `:opts`) + `meta:feed -(found)> *` is the per-stream ingest tracker.
- **Queries/hunts:** `it:exec:query` (`:text`, `:language`, `:time`, `:host`, `:api:url`, `:opts`,
  `:service:account`, `:offset`) + `it:exec:query -(found)> *` ("node was returned as a result of running the
  query").
- **Incident:** there is **no `incident` form.** The decomposition is `risk:compromise` (the incident; has
  `:tag`, `:vector`, `:time/:lasttime/:detected`, `:severity`, `:ext:id`, `:url`) + `risk:attack` per discrete
  attacker action (`:compromise` prop; `-(uses)>`/`-(targets)>` edges — the `:used:*`/`:target:*` props are
  deprecated) + `risk:alert` per detection (`:ext:id`, `:type` taxonomy, `:severity`, `:priority`, `:engine`,
  `:detected`, `:host`, `:url`, `:status`, `:verdict`, `:benign`, `:attack`; `risk:alert -(about)> *`).
- **Timelines:** `meta:timeline` (`:title`, `:summary`, `:type` taxonomy) + `meta:event` (`:timeline` **property**
  — not an edge, `:title`, `:summary`, `:time`, `:duration`, `:index`, `:type`). Events link evidence via
  `meta:event -(refs)> *`. `ou:campaign:timeline` exists for campaign-level rollups.
- **Forensics:** `it:host`, `it:exec:proc/thread/loadlib/mmap/mutex/pipe/bind/url/file:add|read|write|del/reg:get|set|del`
  (all implement `it:host:activity`: `:host`, `:proc`, `:thread`, `:exe`, `:time`), `it:fs:file`, `it:log:event`
  (`:type` taxonomy, `:data` raw JSON, `:ext:id`, `:severity`; `it:log:event -(about)> *`), `it:logon`,
  `it:account`, `it:group`, `it:domain`, `inet:flow`, `inet:dns:request`, `it:os:windows:service`,
  `it:os:windows:task`, `it:os:posix:cron`, `it:dev:regkey`/`it:dev:regval`, `it:app:yara:rule/match/procmatch`,
  `it:app:sigma:rule/matched`, `it:av:scan:result`, `file:bytes`/`file:filepath`/`it:cmd`/`it:cmd:session`/
  `it:cmd:history`, `it:storage:volume`/`it:storage:mount`, `it:screenshot`.
- **Known model gaps + workarounds** (no dedicated form exists): prefetch/amcache/shimcache (→ `it:exec:proc`
  with `.seen` + `it:fs:file` + evidentiary tag), browser history (→ `it:exec:url` with `:browser`), EVTX
  (→ `it:log:event` with `:type` taxonomy + `:data`), USB (→ `it:prod:hardware` + `it:storage:volume/mount`),
  drivers (→ `it:os:windows:service` `:type` 1/2 + `it:exec:loadlib`), EDR-alert form (→ `risk:alert`).
- **Deprecations to avoid:** `meta:seen`, `it:av:sig/filehit/prochit`, `risk:hasvuln` (→ `risk:vulnerable`),
  `it:exec:proc:user` (→ `:account`), `:src:exe` (→ `:src:proc`+`:path`), `risk:attack:used:*`/`:target:*`
  (→ edges), `:techniques` arrays (→ `-(uses)> ou:technique`).
- **Tag conventions:** `rep.<reporter>.<assertion>` for third-party reporting (→ `rep.velo.*`, prefix
  configurable), `cno.*` for analyst assessments (`cno.inc.<name>` pairs with `risk:compromise:tag`).
- **Precedent:** `synapse-microsoft-defender` is the closest EDR power-up: alerts → `risk:alert`, incidents →
  `risk:attack`, evidence processes → `it:exec:proc` via `-(refs)>`, provenance via `meta:source -(seen)>`.
  **No Velociraptor power-up exists** — no naming collisions to worry about.

---

## 3. Naming & repo integration

| Item | Value | Rationale |
|---|---|---|
| Service folder | `svcs/velociraptor/` | matches README "uniquely named folder under svcs/" |
| Python package | `velosvc` | matches `shodansvc`/`crtshsvc`/`abusechsvc` pattern |
| Storm package / service name | `slib.velo` | "velo" is the community shorthand; keeps 20+ command names typeable (`slib.velo.incident.sync` vs `slib.velociraptor.incident.sync`) |
| Command namespace | `slib.velo.*` | |
| Tag prefix (default, admin-configurable) | `rep.velo` | mirrors `rep.shodan` convention |
| services.toml entry | `[stormsvcs.velociraptor]` → `name = "Velociraptor"`, `src = "svcs/velociraptor/"`, `workflow = ".github/workflows/velociraptor.yml"` | |
| CI workflow | copy `.github/workflows/shodan.yml`, change the service name; register in `_main.yml` | |
| Versioning | starts `0.1.0`; synchronized across `pyproject.toml`, `src/velosvc/__init__.py`, `pkgproto/slib.velo.yaml`, `uv.lock` per CLAUDE.md; include a `test_versions_match` test like shodan's | |
| License | `ln -s ../../LICENSE LICENSE` | |
| synapse_minversion | `[2, 207, 0]` or later (needs `meta:feed`, `it:os:windows:task/service`, `risk:alert:host`; pin precisely during implementation by checking the model-updates changelog for the newest prop we touch) | |

New top-level dependencies (service `pyproject.toml`): `stormlibpp` (as always), `grpcio`, and
`pyvelociraptor` (brings the generated `api_pb2`/`api_pb2_grpc` stubs). If pyvelociraptor's pinned
`grpcio`/`protobuf` conflict with Synapse's, vendor the two generated `*_pb2*.py` modules into
`velosvc/_proto/` instead (they are stable; regenerate per Velociraptor minor release) — decide at
implementation time, prefer the dependency.

---

## 4. Service architecture

### 4.1 Component layout

```
svcs/velociraptor/
├── README.md                     # user-facing docs (quickstart, perms, command reference)
│                                 # (design + research stay in .claude/research/velo/ — not shipped)
├── pyproject.toml / uv.lock / LICENSE
├── docker/{prod,test}/           # per repo conventions; prod image FROM ghcr.io/gormaniac/stormsvcs/base
├── src/velosvc/
│   ├── __init__.py               # __version__
│   ├── __main__.py               # python -m velosvc → run the Cell
│   ├── defs.py                   # SVC_NAME/VER/GUID, SVC_EVTS, PKGDEFS (StormPkg subclass)
│   ├── svc.py                    # VeloSvc(s_cell.Cell) — config, server registry, task mgmt
│   ├── api.py                    # VeloCellApi(CellApi, StormSvc) — TelepathRetn wrappers
│   ├── client.py                 # VeloClient — one gRPC channel/stub per (server, org); query/stream/fetch
│   ├── vql.py                    # VQL statement builders (env-parameterized, NEVER interpolated)
│   ├── norm.py                   # row normalizers: timestamps, flows, hunts, clients, alerts, timelines
│   ├── mappers.py                # artifact-name → normalized "node proposal" transforms (§5.5)
│   └── pkgproto/
│       ├── slib.velo.yaml        # package def: perms, commands, modules
│       └── storm/
│           ├── commands/slib.velo.*.storm
│           └── modules/
│               ├── slib.velo.priv.{user,collect,hunt,files,admin}.storm   # asroot svc wrappers
│               ├── slib.velo.model.storm          # core node builders (host, source, seen, feed, query)
│               ├── slib.velo.model.exec.storm     # proc/netstat/bind/loadlib/cmd builders
│               ├── slib.velo.model.file.storm     # fs:file/file:bytes/filepath/uploads
│               ├── slib.velo.model.log.storm      # it:log:event + evtx derivations (logon, proc, task…)
│               ├── slib.velo.model.alert.storm    # risk:alert/attack/compromise
│               ├── slib.velo.model.timeline.storm # meta:timeline/meta:event
│               ├── slib.velo.ingest.storm         # mapper dispatch + sync loops + watermarks
│               └── slib.velo.util.storm           # arg parsing, printing, time helpers
└── tests/
    ├── fakevelo.py               # in-process fake gRPC Velociraptor server (§9)
    ├── fixtures/                 # canned VQLResponse rows per artifact (from research report schemas)
    ├── conftest.py
    ├── test_velosvc.py           # Python unit tests (client, norm, mappers)
    ├── test_velo_storm.py        # StormPkgTest suites (pkg load, modeling, perms, versions-match)
    ├── test_velo_timeline.py     # timeline construction/retrieval tests
    └── test_live.py              # gated live tests against a real deployment (env-flag, like shodan)
```

Division of labor (repo convention): **Python owns all compute** — gRPC, paging, retries, timestamp/row
normalization, mapper transforms to neutral dicts. **Storm owns the entrypoints and node creation** — commands
parse args, call priv modules, and feed normalized dicts to `slib.velo.model.*` builders that create nodes as
the calling user.

### 4.2 The gRPC client (`client.py`)

- One `VeloClient` per configured **server profile** (§4.3), lazily building one `grpc.aio.secure_channel`
  from the profile's api_client YAML (`ca_certificate`, `client_cert`, `client_private_key`,
  `api_connection_string`) with `grpc.ssl_target_name_override="VelociraptorServer"` (required — the server
  cert CN), generous `grpc.max_receive_message_length`, and keepalive options (`watch_*` streams are
  long-lived).
- **`query(vql, env=…, org_id=…, max_row=1000, max_wait=1, timeout=…) → AsyncIterator[dict]`** — sends
  `VQLCollectorArgs(Query=[VQLRequest(Name, VQL)], env=[VQLEnv…], org_id, max_row, max_wait)`, yields parsed
  rows from each `VQLResponse.Response` JSON array; routes `response.log` lines to the service logger (and
  surfaces them to Storm when `$lib.debug`). **All dynamic values go through `env`** (VQL-injection defense,
  gotcha #6); `vql.py` holds only static, reviewed statements that reference `env.X`.
- **`watch(artifact, org_id=…) → AsyncIterator[dict]`** — a never-ending `watch_monitoring()` query with
  automatic reconnect + backfill: on stream break, reconnect and re-read missed rows via
  `monitoring(start_time=<last _ts watermark>)` before resuming the live stream (gotcha #4).
- **`fetch(components, offset=0, length=…) → AsyncIterator[bytes]`** — chunked `VFSGetBuffer` reads for
  uploaded-file bytes (1 MiB chunks default).
- Paged helpers that wrap windowed VQL: `source_rows(client_id/flow_id/hunt_id, artifact, source, start_row,
  count)`, `hunt_flows(hunt_id, start_row, limit)`, `monitoring_rows(client_id, artifact, start_time,
  end_time, start_row)`, `timeline_rows(notebook_id, supertimeline, components, start)`.
- Retry policy: idempotent reads retry 4× with exponential backoff on transient gRPC errors; `watch()` streams
  reconnect forever with jitter; non-idempotent ops (`collect_client`, `hunt`) never auto-retry.
- Health: `Check` RPC + a lightweight `SELECT version() FROM scope()` probe; parse server version once per
  connection and cache it (drives version-dependent behavior, §4.5).

### 4.3 Server profiles, orgs, and credentials

Unlike shodan's single API key, a Velociraptor integration has (a) **mTLS api_client YAML blobs**, not
per-user keys, and (b) potentially **several deployments** (common for IR consultancies: one server per
engagement). Design:

- The Cell keeps a named **server profile registry** in its slab (`slab.getSafeKeyVal("slib:velo:servers")`):
  `name → {config_yaml, default_org, orgs_mode, verify, added_by, added_at}`. One profile is marked default.
- `confdefs` allow a bootstrap profile via Cell config/env (`velo:config:yaml` or `velo:config:path`,
  `velo:profile:name`, plus `velo:timeout`, `velo:ratelimit`, `velo:maxrow`, `velo:fetch:chunksize`) so a
  docker-compose deployment works with zero Storm-side setup.
- `slib.velo.admin.server.add <name> --config <yaml|path> [--default] [--org <id>]…` manages profiles at
  runtime (admin perm; the YAML contains a private key, so it is stored only cell-side and is **never**
  readable from Storm — same posture as shodan's stored API key behind asroot priv modules).
- Per-user credentials are deliberately **not** supported in v1: Velociraptor API identity is a server-side
  principal with its own ACLs; Synapse-side authorization is enforced by our package permissions instead.
  (Future option: per-user vault-stored api configs, noted in §14.)
- **Orgs:** every API call carries `org_id`. Profile `orgs_mode` is `root` (default; single-tenant), `list`
  (explicit org ids), or `all` (enumerate via `orgs()` at sync time). All sync commands take `--org` overrides.
  Every guid seed and every `meta:source` includes the org (§5.1) so two orgs never collide.
- **Credential hygiene & expiry:** the api cert expires after 1 year (gotcha #2). The Cell parses the cert's
  notAfter at profile-add time and exposes it; `slib.velo.info` prints days-remaining and warns under 30 days;
  the nightly sync (if scheduled) logs a warning too. Recommended Velociraptor-side roles for the service
  principal: **`api,reader`** baseline; `analyst` if notebook/timeline writes are wanted
  (`timeline_add`); `investigator` only when Storm-driven collection (`slib.velo.collect`/`hunt.start`) is used.
  Document that `acl grant` *replaces* roles and CLI grants need a server restart (gotcha #3).

### 4.4 Telepath API surface (`api.py`)

All methods return/yield `TelepathRetn` via the shodan-style `_retnMeth`/`_retnGenr` wrappers. Planned
surface (names camelCase per conventions):

| Group | Methods (all take `server=`, `org=` kwargs) |
|---|---|
| Profiles/health | `addServer`, `delServer`, `listServers`, `setDefaultServer`, `serverInfo` (version, cert expiry, org list), `check` |
| Clients | `clients(search)` (genr), `clientInfo(clientId)`, `clientLabels`, `setLabels(clientIds, labels, op)` (write-gated), `clientMetadata(clientId)` |
| Flows | `flows(clientId, flowId=None)` (genr), `flowResults(clientId, flowId, artifact, source, startRow, count)` (genr), `flowLogs`, `uploadsList(clientId=, flowId=, huntId=)` (genr) |
| Hunts | `hunts(huntId=None)` (genr), `huntFlows(huntId, startRow, limit)` (genr), `huntResults(huntId, artifact, source)` (genr) |
| Results (universal) | `sourceRows(...)` (genr; the `source()` wrapper), `monitoringRows(clientId, artifact, startTime, endTime, startRow)` (genr) |
| Live | `watch(artifact)` (genr; never ends — used by the tail command under a dmon) |
| Timelines/notebooks | `notebooks()` (genr), `notebookGet(notebookId)`, `timelinesList(notebookId)`, `timelineRows(notebookId, name, components, start)` (genr) |
| Artifacts | `artifactDefs(names)` (genr; drives mapper fallback + `--describe`) |
| Files | `fetchUpload(components, size)` (genr of byte chunks; Storm side streams into the Axon via `$lib.axon`), `vfsStatDownload(clientId, components)` (hashes when present) |
| Actions (write-gated) | `collect(clientId, artifacts, specs, urgent, timeout, cpuLimit)`, `startHunt(args)`, `huntAdd`, `cancelFlow`, `labelClients` |
| Escape hatch | `rawQuery(vql, env, orgId, maxRow)` (genr; admin perm — mirrors `slib.shodan.admin.request`) |
| Mappers | `normRows(artifact, rows, context)` → normalized node-proposals (lets Storm batch-call the Python mapper layer, §5.5) |

### 4.5 Version compatibility strategy

The Cell probes server version per profile and adapts (research gotcha #1):

- **≥0.77:** `System.Hunt.Participation` is gone → always use `hunt_flows()`. Flow `request` may be summarized.
- **≥0.75:** artifact exodus — treat `Windows.KapeFiles.Targets` and `Windows.Triage.Targets` as aliases in
  the mapper registry (same shape); never assume an artifact exists, discover via `artifact_definitions()`.
- **≤0.74:** `Windows.KapeFiles.Targets` is the built-in triage name.
- Timestamp normalization is version-independent and defensive per field (µs for proto epochs like
  `create_time`/`ping`, seconds for `uploads.json Timestamp`/`_ts`, ns for `execution_duration`, RFC3339
  strings in JSON rows). `norm.py` owns a single `normTime(valu, hint)` used everywhere; heuristics
  (magnitude-based) only when no hint exists, with unit tests over all observed shapes.

---

## 5. Data model mapping (the heart of the service)

### 5.1 Identity, provenance, and guid discipline

**Deployment identity.** Every node guid seed and every provenance anchor is scoped by
`(<profile deployment id>, <org id>)` where the deployment id is the stable `api_connection_string` host (or
an admin-supplied override) — Velociraptor client/flow/hunt ids are only unique within a deployment+org.
Below, `$dep` = `"<deployment>/<org>"`.

**`meta:source` per deployment+org** (the provenance anchor, like shodan's single source but multiplied):

```
[ meta:source=$lib.guid(slib.velo, source, $dep)
    :name=`velociraptor {$dep}` :type=slib.velo :url=$serverUrl ]
```

Every node the service creates or updates gets `<(seen)+ { meta:source=$src }` and `.seen` fused with the
best event time — exactly the shodan `seen()` helper pattern. The package `SVC_EVTS` add-event creates
nothing source-wise (sources are per-profile, created on first sync) but seeds the config globals
(`slib:velo:tag:prefix` = `rep.velo`, `slib:velo:tag:enabled` = true, plus sync defaults from §6).

**Guid seeds** (all via `$lib.guid()` with namespaced tuples; idempotent re-ingest is the invariant — the
same Velociraptor datum always maps to the same node):

| Node | Seed |
|---|---|
| `it:host` (client) | `(slib.velo, host, $dep, $clientId)` |
| `it:exec:query` (flow) | `(slib.velo, flow, $dep, $flowId)` |
| `it:exec:query` (hunt) | `(slib.velo, hunt, $dep, $huntId)` |
| `meta:feed` (per sync stream) | `(slib.velo, feed, $dep, $stream)` — e.g. stream = `flows`, `monitoring/<artifact>`, `alerts` |
| `risk:alert` | `(slib.velo, alert, $dep, $name, $clientId, $tsMicros)` (the alert queue has no id; name+client+ts is the dedup identity Velociraptor itself uses) |
| `it:exec:proc` (pslist) | `(slib.velo, proc, $dep, $clientId, $pid, $createTimeMicros)` (pid alone is unstable) |
| `it:exec:proc` (prefetch-evidence) | `(slib.velo, prefetchproc, $dep, $clientId, $exePathNorm)` |
| `it:log:event` (evtx) | `(slib.velo, winevt, $dep, $clientId, $channel, $recordId)` |
| `it:log:event` (generic row) | `(slib.velo, row, $dep, $flowId, $artifact, $source, $rowIdx)` |
| `inet:flow` (netstat) | `(slib.velo, netflow, $dep, $clientId, $proto, $laddr, $lport, $raddr, $rport, $tsMicros)` |
| `it:fs:file` | `(slib.velo, fsfile, $dep, $clientId, $pathNorm)` |
| `it:account` | `(slib.velo, account, $dep, $clientId|$domain, $sid|$uid|$nameNorm)` (SID preferred; host-scoped vs domain-scoped per §5.4) |
| `it:logon` | `(slib.velo, logon, $dep, $clientId, $recordId)` (derived from the 4624 event identity) |
| `it:os:windows:service` / `:task` / `it:os:posix:cron` | `(slib.velo, winsvc|wintask|cron, $dep, $clientId, $nameNorm|$taskUri|$cmdNorm)` |
| `meta:timeline` / `meta:event` | §5.10 |
| `risk:compromise` | `(slib.velo, incident, $dep, $incidentName)` |
| `it:exec:url` (browser) | `(slib.velo, url, $dep, $clientId, $browser, $urlNorm, $visitTimeMicros)` |
| `it:app:yara:procmatch`, `it:app:sigma:matched`, etc. | `(slib.velo, yarahit|sigmahit, $dep, $clientId, $rule, $target..., $ts)` |

The **row-identity trick**: because mappers compute guid seeds deterministically from row content, a
Velociraptor *timeline* row (which carries the original result columns) re-derives the **same** guid as the
flow-results ingest did — so `meta:event -(refs)> <evidence node>` links resolve exactly, even when the
timeline is ingested before/without the underlying flow (§5.10).

**The Velociraptor product nodes** (once, at package init): `$lib.gen.softByName(velociraptor)` →
`it:prod:soft` (`:url=https://docs.velociraptor.app`), per-observed-version `it:prod:softver`
(`:name=velociraptor`, `:vers=<agent version>`), used for `it:hostsoft`, `risk:alert:engine`, and
`it:log:event:product`.

### 5.2 Clients → devices

Source: `clients()` / `client_info()` rows (ClientInfo schema) + `Generic.Client.Info` interrogation results.

| Velociraptor field | Synapse |
|---|---|
| `client_id` | `it:host=$guid :ext:id=$clientId`; **also** `it:prod:softid=(…)` `:id=$clientId :host=$host :soft=<velo agent softver> :soft:name=velociraptor` (the "ID issued to a host by a software application" form — exactly a Velociraptor client id) |
| `hostname` / `fqdn` | `:name=$hostname`; `inet:fqdn=$fqdn` + `it:hosturl`? no — just `inet:fqdn` node + `inet:dns:a` when `ip_address` present; `:desc` gets a one-line summary |
| `system`/`release`/`architecture` (+ interrogation `Platform`, `PlatformVersion`, `KernelVersion`) | `:os=<it:prod:softver for the OS>` (`$lib.gen.softByName` per platform, `:vers=$platformVersion`), `:os:name=$system` |
| `ip_address` (last seen) | `:ipv4`/(v6) prop + `inet:ipv4` node |
| `mac_addresses[]` | `inet:mac` nodes + `-(refs)>` from host (no `it:host:macs` prop exists; edge keeps it lossless) |
| `first_seen_at`/`last_seen_at` (`ping`) | `.seen` interval on the host (fused, ival auto-expands) |
| `client_version`, `build_time` | agent `it:prod:softver` + `it:hostsoft=($host, $agentver)` |
| `labels[]` | tags: `rep.velo.label.<normalized label>` on the `it:host` (normalize: lower, [^a-z0-9]+ → `_`); labels are *the* Velociraptor triage mechanism (e.g. `Compromised`), so also: a label matching the configured incident-label pattern can drive `incident.sync --label` targeting (§5.9) |
| `metadata{}` | small k/v → node data (`$node.data.set(velo:metadata, $dict)`) — queryable, lossless, no prop explosion |
| `last_interrogate_flow_id` | `-(refs)>` edge host → that flow's `it:exec:query` |
| Windows domain (interrogation `WindowsInfo.Domain`) | `it:domain=$lib.guid(slib.velo, domain, $dep, $domainNorm) :name=$domain`; host `:domain=$it:domain` |
| `Users` source (interrogation) / `Windows.Sys.Users` / `Linux.Sys.Users` | `it:account` nodes (§5.4) |

The deployment's platform itself: `inet:service:platform` is optional-v2; `meta:source:url` + the
`it:prod:soft` suffice for v1.

### 5.3 Hunts & flows → queries, feeds, and the collection fabric

**Flow → `it:exec:query`:**

| Velociraptor | Synapse `it:exec:query` |
|---|---|
| `session_id` (`F.xxx`) | guid seed; also stored in `:opts` JSON (`{"flow_id": …}`) and node data `velo:flow` (full normalized context) |
| requested artifacts + specs | `:text` = canonical compact text (`collect: Artifact.A(param=x), Artifact.B`) — human-lift-able; full `ArtifactCollectorArgs` into node data; `:language=vql` |
| `create_time`/`start_time` | `:time` (µs → epoch ms) |
| `creator` | `:service:account`? — creator is a Velociraptor GUI user, not an inet service account in v1: store in `:opts`/node data + `rep.velo.creator.<user>` optional tag; (`inet:service:account` wiring is v2, §14) |
| client | `:host=$hostGuid` |
| `state`/`status` | tags `rep.velo.flow.state.<running|finished|error>` + error text in node data |
| stats (`total_collected_rows`, uploads, duration) | node data `velo:flow:stats` |
| API endpoint | `:api:url=<grpc endpoint>` |

Every node produced from that flow's results gets `<(found)+ { it:exec:query=$flowQuery }` — the declared
`it:exec:query -(found)> *` edge ("returned as a result of running the query"). This single convention makes
*"show me everything this collection found"* a one-pivot query and is the natural-graph glue between
collections and evidence.

**Hunt → `it:exec:query`** (same shape; `:text` = `hunt: <artifacts> where <condition>`; `:host` unset) plus:

- `hunt -(refs)> flow` edges for each participating flow (from `hunt_flows()`), so hunt → flows → evidence
  chains walk naturally.
- Hunt targeting (`condition.labels`, os) and stats → node data; `tags[]` (0.75+) → `rep.velo.hunt.tag.<t>`.
- `expires`, `create_time` → `.seen` interval.

**`meta:feed` per sync stream** records ingest state (§6): `:source=<meta:source>`, `:name` (e.g.
`"flows C.xxx"`, `"monitoring Windows.Detection.ProcessCreation"`), `:query` = the VQL used, `:latest`/
`:offset`/`:cursor` watermarks, `:period` fused. Feeds also get `-(found)>` edges to nodes when the ingest ran
through that feed — giving both "what did this *collection* find" (`it:exec:query`) and "what did this *sync
stream* bring in" (`meta:feed`) views.

### 5.4 Accounts, groups, logons

- `Windows.Sys.Users` (`Name, UUID (SID), Directory, Mtime, Data.ProfileLoadTime…`) / interrogation `Users` /
  `Linux.Sys.Users` (`User, Uid, Gid, Homedir, Shell`) → `it:account` with `:user`, `:host` (local accounts)
  **or** `:domain` (domain SIDs — SID S-1-5-21-domain-… with RID ≥ 1000 heuristic + domain from
  interrogation), `:windows:sid`, `:posix:uid/:gid/:home/:shell`. Profile load/unload times fuse `.seen`.
- Group membership (when collected, e.g. `Windows.System.LocalAdmins`) → `it:group` (`:windows:sid`, `:host`)
  + account `:groups` array.
- Logon events (EVTX 4624/4625/4634, `Windows.EventLogs.RDPAuth`, `Linux.Sys.LastUserLogin`) → `it:logon`
  (`:host`, `:account`, `:time`, `:success`, `:client:ipv4`, `:logoff:time` when a matching 4634 is seen)
  **and** the underlying `it:log:event` with `it:log:event -(about)> it:logon` (§5.7). Logons are prime
  timeline material (§5.10).

### 5.5 The artifact mapper registry (results → forms)

**Problem:** artifact output is schemaless and open-ended (gotcha #7); the Elastic uploader breaks on exactly
this. **Design:** a Python-side registry in `mappers.py`:

```python
@mapper("Windows.System.Pslist", "Linux.Sys.Pslist", "MacOS.Sys.Pslist")
def map_pslist(row: dict, ctx: MapCtx) -> list[Proposal]: ...
```

- Each mapper turns one result row (+ context: client/flow/hunt/org/artifact/source) into a list of
  **node proposals** — plain dicts `{form, guidseed | valu, props, tags, edges, nodedata, time}` — that the
  Storm `slib.velo.ingest` module materializes generically (one generic builder walks proposals; per-form
  helpers in `model.*.storm` handle the fiddly ones like comp forms and `risk:vulnerable`-style ndefs).
  This keeps "Python owns compute, Storm owns node edits" while making mapper logic unit-testable in pure
  Python against fixture rows.
- **Matching** is by artifact name with alias sets (KapeFiles/Triage), then by **artifact name prefix**
  (`Windows.EventLogs.*` → the generic EVTX mapper reads the common `System`/`EventData` shape), then the
  **generic fallback** (below). `Custom.<Name>` artifacts map to their base name's mapper (Velociraptor
  override convention), with a config switch to disable.
- Mappers must tolerate missing columns (every field optional; `?=` semantics end-to-end) and normalize
  timestamps via `normTime`.

**v1 mapper table** (columns are the verbatim artifact outputs from the research report):

| Artifact(s) | Forms created | Key mappings & edges |
|---|---|---|
| `Generic.Client.Info` (all sources) | `it:host` props, `it:account`, `it:domain`, agent `it:hostsoft` | §5.2 |
| `Windows.System.Pslist` / `Linux.Sys.Pslist` / `MacOS.Sys.Pslist` | `it:exec:proc`, `file:bytes`, `file:filepath`, `it:cmd`, `it:account` | `Pid→:pid`, `CreateTime→:time`, `CommandLine→:cmd` (+`it:cmd` node), `Exe→:path`(+`:path:base`), `Hash.SHA256→:exe=file:bytes` (+`:md5/:sha1` props, `file:filepath=($exe,$path)`), `Username→:account`, `Ppid→:src:proc` (second pass links parents by `(clientId,ppid)` when the parent row exists; else leave unset — pid-reuse safe), `TokenIsElevated/Authenticode` → node data + `rep.velo.untrusted` tag when Authenticode untrusted |
| `Windows.Network.Netstat(+Enriched)` | `inet:flow` (ESTAB w/ raddr), `it:exec:bind` (LISTEN), `it:exec:proc` (Enriched) | `Laddr/Lport/Raddr/Rport/Type→` flow `:src:*`/`:dst:*` (+`:src:host=$host`, `:src:proc`, `:ip:proto`), `Timestamp→:time`; LISTEN rows → `it:exec:bind :server=<proto://ip:port>` `:proc`; `:raw` keeps the row |
| `Windows.System.DNSCache`, DNS event artifacts | `inet:dns:request` | `:host`, `:query:name`, `:time`; answers → `inet:dns:a` where present |
| `Windows.Forensics.Prefetch` / `Windows.Timeline.Prefetch` | `it:exec:proc` (evidence-of-execution), `it:fs:file` (the .pf) | one proc per executable: `ExecutablePath→:path`, `LastRunTimes[-1]→:time`, `.seen` fused over all run times (+ optional per-run procs behind `--per-run`); `RunCount` → node data; tag `rep.velo.prefetch`; `Windows.Timeline.Prefetch` `event_time` rows fuse the same guids |
| `Windows.Forensics.Amcache` | `it:fs:file` + `file:bytes`(sha1) + optional `it:exec:proc` | tag `rep.velo.amcache` |
| `Windows.Registry.AppCompatCache` (shimcache) | `it:fs:file` only | tag `rep.velo.shimcache` (presence ≠ execution) |
| `Windows.NTFS.MFT` | `it:fs:file` | `OSPath→:path`, `Created0x10→:ctime`, `LastModified0x10→:mtime`, `LastAccess0x10→:atime`, `FileSize`, `IsDir` filter; 0x30/ADS/anomaly flags (`SI_Lt_FN`, `USecZeros`) → node data + `rep.velo.mft.anomaly` tag |
| `Windows.Forensics.Usn` | `it:exec:file:add/:write/:del` per `Reason` | `Timestamp→:time`, `OSPath→:path`, `:host`; Reason list → pick strongest (FILE_CREATE→add, FILE_DELETE→del, DATA_EXTEND/OVERWRITE→write); full reasons → node data |
| `Windows.EventLogs.Evtx` / `Windows.EventLogs.EvtxHunter` / `Windows.EventLogs.*` | `it:log:event` + derivations | §5.7 |
| `Windows.Detection.Yara.Process` | `it:app:yara:rule`, `it:app:yara:procmatch`, `it:exec:proc` | `Rule→` rule node (`:name`; text when included), procmatch `:proc/:rule/:time`; `HitContext` upload → `file:bytes` + `-(refs)>` |
| `Windows.Detection.Yara.NTFS` / `Generic.Detection.Yara.Glob` | `it:app:yara:rule`, `it:app:yara:match`, `file:bytes`, `it:fs:file` | match comp = (rule, file-hash when uploaded; else `it:fs:file` + `-(refs)>` from rule) |
| Sigma hit artifacts (Velociraptor Sigma project / Hayabusa) | `it:app:sigma:rule`, `it:app:sigma:matched`, `it:log:event` | rule title/level from row; `:target=<log event>`, `:sensor=$host`; level → also a `risk:alert` when ≥ configured threshold (§5.8) |
| `Windows.System.TaskScheduler` | `it:os:windows:task`, `it:cmd`, `it:account`, `file:bytes` (task XML upload) | `TaskName→:uri`, `Command+Arguments→:cmds=[it:cmd]`, `UserId→:account`, `Mtime→.seen`, `_XML→` node data |
| `Windows.System.Services` / `Linux.Sys.Services` | `it:os:windows:service` / `it:os:posix:cron`-adjacent | `Name/DisplayName/PathName→:name/:displayname/:imagepath`, `ServiceType→:type` (int; kernel/fs drivers = driver coverage), `StartMode→:start`, `ServiceDll`/hashes → `file:bytes` + node data; `Created→.seen` |
| `Windows.Sysinternals.Autoruns` | dispatch by `Category`: services→`it:os:windows:service`, tasks→`it:os:windows:task`, logon/run-keys→`it:dev:regval`+`it:exec:reg:set`, drivers→service-form, everything else→`it:fs:file`+`file:bytes`(hashes) | `Entry Location`→regkey; `Image Path`→file; `Time→:time/.seen`; always tag `rep.velo.autorun.<category>` |
| `Windows.Registry.NTUser`/`UserAssist`/`RecentDocs`/Registry Hunter rows | `it:dev:regkey`, `it:dev:regval` (+`it:exec:reg:set` when event-shaped; UserAssist→ prefetch-style `it:exec:proc` evidence w/ `rep.velo.userassist`) | `OSPath→key`, `Data/Mtime` → regval props/`.seen` |
| `Windows.Applications.Chrome.History` (+Edge/Firefox/SQLiteHunter) | `it:exec:url` | `url→:url`, `visit_time→:time`, `title→:page:title`, `:browser=<it:prod:softver chrome/edge/firefox>`, `:host`; `User` → `it:account` + `-(refs)>`; downloads tables → `it:exec:file:add` + `inet:urlfile` |
| `Windows.Sys.Users` / `Linux.Sys.Users` / `LocalAdmins` | `it:account`, `it:group` | §5.4 |
| `Linux.Sys.BashHistory` | `it:cmd:session` (`:host`, `:file`), `it:cmd:history` (`:cmd`, `:index`, `:time` when timestamps on) | |
| `Windows.Triage.Targets` / `Windows.KapeFiles.Targets` | `it:fs:file` per `All File Metadata` row; `Uploads` source → §5.6 pipeline (incl. `SourceFileSha256`) | |
| `System.VFS.ListDirectory` / `System.VFS.DownloadFile` | `it:fs:file`; download rows → `file:bytes` with `Sha256/Md5` | VFS coverage falls out of normal artifact ingest (research §7) |
| `Generic.Client.Stats`, `Server.Monitor.*` telemetry | **skipped by default** (pure telemetry; configurable allowlist) | |
| anything else | **generic fallback** ↓ | |

**Generic fallback mapper** (the "everything lives on the model" guarantee): any row of any unmapped artifact
becomes `it:log:event` with `:type=velo.artifact.<artifact name lowered/dotted>` (a `it:log:event:type:taxonomy`
subtree under `velo.artifact`), `:data=<full raw row JSON>`, `:host`, `:time` (best-effort column sniff:
`Timestamp|EventTime|_ts|mtime|…` via `normTime`), `:product=<velo softver>`, `:ext:id=<flowId>/<artifact>/<rowIdx>`
— plus the standard `-(found)>`/`-(seen)>` edges and incident tag. Lossless, connected, and lift-able
(`it:log:event:type^=velo.artifact.custom`). Admins can later promote an artifact to a real mapper without
re-collection (re-ingest is idempotent; the fallback nodes remain as the raw record). A Storm-side
**`slib.velo.admin.mapmeta`** command stores per-artifact hints (timestamp column, message column, host
column) in `$lib.globals` for fallback tuning — the same hints Velociraptor's own timeline UI asks an analyst
for.

### 5.6 Uploads → Axon + file graph

Pipeline for `uploads()` rows (schema: `vfs_path`, `_Components`, `file_size`, `uploaded_size`, `_accessor`,
`_client_components`, `Timestamp` secs):

1. `uploadsList` genr yields upload metadata; Storm filters by size policy (`--max-size`, default 256 MiB;
   sparse `Type="idx"` rows skipped).
2. **Hashes:** metadata has none (gotcha #9). Preference order: (a) artifact-level hash columns already
   ingested (`SourceFileSha256`, Pslist `Hash`), (b) `VFSStatDownload`'s `VFSDownloadInfo.MD5/SHA256` for
   VFS-downloaded files, (c) hash-while-streaming: `fetchUpload` chunks → `$lib.axon.upload()` genr — the Axon
   returns size+sha256; the service computes md5/sha1/sha256 server-side in the same pass and returns them
   with the final chunk so one download populates everything.
3. Nodes: `file:bytes=<sha256>` (`:size`, `:md5`, `:sha1`, `:name`), `file:filepath=($bytes, $clientPath)`,
   `it:fs:file` (`:host`, `:path=$clientPath`, `:file=$bytes`) — fused with timestamps when the artifact
   provided them (KapeFiles `Uploads` rows carry `Created/Modified/LastAccessed`).
4. Edges: `<(found)+` from the flow query; `<(seen)+` source; incident tag.
5. `--no-bytes` mode models metadata only (hash-less `it:fs:file`), for low-bandwidth or confidentiality
   constraints.

### 5.7 Event logs & monitoring streams

**EVTX rows** (generic `Windows.EventLogs.Evtx` shape: nested `System` dict + `EventData`, flattened
`TimeCreated, Channel, EventID, EventRecordID, Computer, OSPath`):

- Base node: `it:log:event` seeded `(…, $channel, $recordId)` — `:type=velo.evtx.<channel-lower>.<eventid>`
  (taxonomy: e.g. `velo.evtx.security.4624`), `:time=TimeCreated`, `:ext:id=EventRecordID`,
  `:mesg=<Message when present>`, `:data=<EventData/UserData raw>`, `:host`, `:severity` (mapped from Level
  when present), `:product=<velo softver>`.
- **Derivation registry** (second-stage mappers keyed by channel+event id) creates first-class nodes and links
  them `it:log:event -(about)> <node>`:
  - Security 4624/4625/4634/4648 → `it:logon` (§5.4); 4688 → `it:exec:proc` (`:cmd`, `:src:proc` from
    CreatorProcessId); 4698/4702 → `it:os:windows:task`; 7045/4697 (System) → `it:os:windows:service`;
    1102 → tag `rep.velo.log.cleared` on host + `risk:alert` (log clearing is finding-grade);
    Sysmon Operational 1→`it:exec:proc`, 3→`inet:flow`, 11→`it:exec:file:add`, 13→`it:exec:reg:set`,
    22→`inet:dns:request`, 7→`it:exec:loadlib`, 17/18→`it:exec:pipe`.
  - The registry is data-driven (dict in `mappers.py`) so coverage grows cheaply; unknown event ids stay as
    plain `it:log:event` — still timeline-able and lift-able by taxonomy.
- **Monitoring (CLIENT_EVENT) rows** reuse the same mappers (a `Windows.Detection.ProcessCreation` row is
  proc-shaped regardless of arriving via flow or monitoring); context marks them `monitored` and the feed
  watermark uses `_ts`. Detection-flavored event artifacts (name matches `*.Detection.*`, Sigma hits, or an
  admin-configured list) **also** raise `risk:alert` per §5.8.

### 5.8 Alerts & findings → `risk:alert`

Sources, in order of signal strength:

1. **`Server.Internal.Alerts` queue rows** `{client_id, name, timestamp, event_data{…}, artifact,
   artifact_type, flow_id}` → `risk:alert`:
   `:name=$name`, `:type=velo.alert.<artifact_type lower>` (taxonomy), `:detected=$timestamp`,
   `:host=$hostGuid`, `:engine=<velo softver>`, `:ext:id=<dedup identity>`, `:desc` = rendered event_data
   summary, raw event_data → node data; `:severity` parsed from `event_data.Severity|level` when the emitting
   artifact set one (severity is convention-only in Velociraptor); `:url` = GUI deep link
   (`https://<gui>/app/index.html?#/collected/<client>/<flow>` — admin-configurable GUI base URL).
   Edges: `-(about)>` the host, the flow query, and **every evidence node resolvable from event_data** (the
   row-identity trick: if event_data carries Pid+CreateTime or a path, re-derive the proc/file guid and link).
2. **Detection-artifact hits** (§5.7): one `risk:alert` per hit row, `:type=velo.detection.<artifact>`,
   `-(about)>` the derived evidence node (`it:app:yara:procmatch`, sigma match, proc…).
3. **Timeline annotations** (§5.10): rows in the reserved `Annotation` component are analyst assertions —
   `meta:note` (`:text=$Notes`, `:author`↔`_AnnotatedBy`, `:created=_AnnotatedAt`) `-(about)>` the evidence +
   the `meta:event`, **not** a risk:alert (they're notes, not detections).
4. **Labels** like `Compromised` (configurable regex) → tag `rep.velo.label.compromised` on the host; the
   incident command treats label-matched hosts as in-scope (§5.9); no alert node (a label is state, not an
   event).

Status workflow props (`:status`, `:assignee`, `:verdict`, `:benign`) are left to analysts — the service only
sets `:status=0 (new)` on creation and **never overwrites analyst-set values on re-ingest** (`?=` everywhere;
the one deliberate exception: `.seen`/stats fusing).

**Promotion to `risk:attack`/`risk:compromise` is analyst-driven, service-assisted:**
`slib.velo.incident.attack --incident <name> [--technique T1055] <inbound alerts/evidence>` mints a
`risk:attack` (`:compromise=<incident>`, `:time` from evidence, `-(uses)>` each inbound evidence node,
`-(targets)>` its host; `risk:alert:attack` set on inbound alerts; `-(uses)> it:mitre:attack:technique` when
given). The service never invents attacks from raw telemetry — that judgment is the analyst's (mirrors the
Defender power-up split: alerts are machine-made, attacks are confirmations).

### 5.9 The incident: `risk:compromise` as the hub

`slib.velo.incident.init --name <name> [--desc …] [--type <taxo>] [--tag cno.inc.<name>] [--ext-id …]`:

```
[ risk:compromise=$lib.guid(slib.velo, incident, $dep, $name)
    :name=$name :desc?=$desc :type?=$type :reporter:name?=<org> :ext:id?=$extid
    :url?=<velo GUI link> :tag=cno.inc.<name> ]
```

plus the two framing timelines (§5.10). Scope binding — any combination of:
`--hunt H.x` (repeatable), `--flow F.x`, `--client C.x`, `--label <velo label>`, `--search <clients() query>`,
`--since/--until <time>`. The scope is stored on the compromise node's node data (`velo:incident:scope`) so
`incident.sync` re-runs are reproducible.

`slib.velo.incident.sync --name <name> [--full|--delta]` then orchestrates, per scoped client/hunt:
client sync → hunt/flow sync → results ingest (all mappers) → uploads ingest → alert sync (time-window
filtered) → notebook/timeline ingest for notebooks referencing the scoped flows/hunts → timeline build
(§5.10). **Every node created in incident scope** gets the incident tag (`+#cno.inc.<name>`) and is therefore
one lift away (`#cno.inc.<name>`); the compromise node additionally gets direct edges to the top-level
objects: `-(uses)>`?? — no: semantic edges only where the model declares them. The hub wiring is:

```
risk:compromise  (tag cno.inc.<name> on all member nodes)
  :vector → risk:attack (set by analyst later)
  <- :compromise - risk:attack -(uses)>/-(targets)> evidence/hosts
  <- :attack - risk:alert -(about)> evidence/hosts
  -(refs)> it:exec:query (each scoped hunt + flow)     # generic refs edge: declared * refs *
  -(refs)> it:host (each scoped device)
  -(refs)> meta:timeline (incident + per-device timelines)
risk:compromise:time/:lasttime  ← min/max evidence :time seen during sync (fused, ismin/ismax semantics via ?= + manual min/max logic)
```

So connectivity holds even for nodes whose natural edges are sparse: *at minimum* everything shares the
incident tag and hangs off the compromise via query/host/timeline refs — satisfying the "at least through an
overarching incident-related node, if not naturally" requirement, while the natural edges (`:host`, `:proc`,
`-(found)>`, `-(about)>`) do the real graph work.

### 5.10 Timelines (the two-sided design)

**Side 1 — machine timeline (implicit, free).** Every forensic node carries `:time` (or `.seen`) + `:host` +
the incident tag. A per-device machine timeline is a *query*, not a structure:

```
#cno.inc.acme2026 .seen@=(2026/01/01, now) +:host=$host | sort :time   // conceptually
// packaged as: slib.velo.timeline.show --incident acme2026 --host C.abc [--forms it:exec:proc,it:logon…]
```

`slib.velo.timeline.show` renders a merged, time-sorted table across all `it:host:activity` forms +
`it:logon` + `inet:flow` + `it:fs:file`(mtime) + `risk:alert` for one host or the whole incident — the
"supertimeline" view without minting nodes. This is deliberately NOT meta:event material: the Synapse docs
define `meta:event` as *curated* ("analytically relevant event in a curated timeline"); minting one per
telemetry row would bury the curated signal and bloat the graph.

**Side 2 — curated timelines (`meta:timeline`/`meta:event` structures).** Created by `incident.init`:

- **Incident master timeline:** `meta:timeline=$lib.guid(slib.velo, timeline, $dep, $incident)`
  `:title="<name> — incident timeline" :type=velo.incident` (+incident tag).
- **Per-device timelines:** `meta:timeline=$lib.guid(slib.velo, timeline, $dep, $incident, $clientId)`
  `:title="<name> — <hostname>" :type=velo.host`; linked `incident-timeline -(refs)> device-timeline` and
  `device-timeline -(refs)> it:host`.

**Constraint that shapes the design:** `meta:event:timeline` is a single-valued property — an event belongs to
exactly one timeline. Duplicating every event onto both the device and incident timelines would double nodes
and desync edits. **Decision:** host-specific events live on their *device* timeline; cross-host/analyst-level
events (initial access assessed, attacker pivoted, containment started) live on the *incident* timeline; the
incident timeline **aggregates by reference** (`-(refs)>` to device timelines). Retrieval:

```
// full incident timeline (own events + all device events), time-ordered:
meta:timeline=$itl { meta:event:timeline=$node } | union {
  meta:timeline=$itl -(refs)> meta:timeline { meta:event:timeline=$node } }
| sort :time
// packaged as: slib.velo.timeline.show --incident acme2026 --curated
// per-device: meta:event:timeline=$devicetl | sort :time   (plus :index for undated events)
```

(All events also carry the incident tag, so `meta:event#cno.inc.acme2026 | sort :time` is the one-lift
equivalent; the structure exists for Optic browsing, `:index` ordering, and campaign rollup via
`ou:campaign:timeline`.)

**What mints curated `meta:event` nodes:**

1. **Velociraptor super-timeline ingest** (`slib.velo.timeline.sync --notebook N.x [--supertimeline <name>]
   [--annotations-only]`): enumerate notebooks → `timelines(notebook_id)` → `timeline()` rows
   (`Timestamp, Message, Description, <orig cols>, _Source`). Every row was *deliberately added by an analyst*
   (via "Add to Timeline" or `timeline_add`) — that **is** curation, so by default each row becomes:
   `meta:event=$lib.guid(slib.velo, event, $dep, $notebookId, $super, $_Source, $Timestamp, <row digest>)`
   `:timeline=<device tl if the row resolves to one scoped host, else incident tl>` `:time=$Timestamp`
   `:title=$Message` `:summary=$Description` `:type=velo.timeline.<_Source normalized>`, node data = original
   columns, `-(refs)>` evidence nodes re-derived via the row-identity trick (§5.1) when the source columns
   suffice (else just the host). Rows from the reserved `Annotation` component additionally mint the
   `meta:note` (§5.8 #3) and carry `:type=velo.timeline.annotation`. `--annotations-only` restricts to that
   component for analysts who use big machine timelines inside Velociraptor.
2. **Service-promoted events** (`timeline.build --auto`): deterministic promotion of *finding-grade* nodes
   only — each `risk:alert` (`:type` prefix filterable), each `risk:attack`, log-cleared events, first/last
   evidence per host (bookend events) → `meta:event` on the right device timeline with `-(refs)>` the node.
   Threshold/config via globals; always idempotent (seeded guids).
3. **Analyst events** (`slib.velo.timeline.event --incident <n> [--host C.x] --time … --title … [--index N]
   <inbound nodes…>`): manual curation; inbound nodes become `-(refs)>` targets. `:duration` supported for
   span events (e.g. "exfil window").

### 5.11 Notebooks (analyst work product)

v1 ingests notebooks *as pointers + timelines*, not as full documents: a `meta:note` per notebook
(`:text` = name + description + cell count + GUI URL, `:type=velo.notebook`, `:author`←creator,
`:created/:updated`) `-(about)>` the flow/hunt/incident nodes it references, + super-timeline ingest (§5.10).
Full cell-level ingest (cells → `meta:note` replies, cell tables → generic rows) is deferred (§14) — cells are
versioned (gotcha #15) and mostly narrative; the timelines carry the analytic conclusions.

### 5.12 Tags & taxonomies (summary)

| Tag / taxonomy | Meaning |
|---|---|
| `rep.velo.label.<label>` | Velociraptor client label (host state) |
| `rep.velo.prefetch` / `.amcache` / `.shimcache` / `.userassist` / `.autorun.<cat>` / `.mft.anomaly` | evidentiary basis for inferred nodes |
| `rep.velo.flow.state.<state>` / `rep.velo.hunt.tag.<t>` / `rep.velo.creator.<user>` | collection metadata |
| `rep.velo.log.cleared`, `rep.velo.untrusted` | notable conditions |
| `cno.inc.<name>` | incident membership (= `risk:compromise:tag`) |
| `it:log:event:type` → `velo.evtx.<channel>.<id>`, `velo.artifact.<name>` | log taxonomy |
| `risk:alert:type` → `velo.alert.<artifact_type>`, `velo.detection.<artifact>` | alert taxonomy |
| `meta:timeline:type` → `velo.incident`, `velo.host`; `meta:event:type` → `velo.timeline.<component>`, `velo.timeline.annotation`, `velo.promoted.<kind>` | timeline taxonomy |

Prefix `rep.velo` is admin-configurable (`slib.velo.admin.tags`, same UX as shodan's); taxonomy roots get
`syn:tag` doc text set at package init. Taxonomy *form* nodes (`it:log:event:type:taxonomy` etc.) get `:title`
docs for the fixed roots.

---

## 6. Sync & orchestration

### 6.1 Modes

| Mode | Mechanism | Commands |
|---|---|---|
| **Backfill / pull** | windowed VQL (`source(start_row=,count=)`, `hunt_flows(start_row=,limit=)`, `monitoring(start_time=)`) with per-stream `meta:feed` watermarks (`:offset` = rows, `:latest` = time, `:cursor` = opaque e.g. last flow id) | `slib.velo.sync`, `slib.velo.client.sync`, `slib.velo.hunt.sync`, `slib.velo.flow.sync`, `slib.velo.incident.sync` |
| **Live tail / push-equivalent** | `watch_monitoring()` on `System.Flow.Completion` (→ auto-ingest finished flows), `System.Upload.Completion` (→ per-file ingest), `Server.Internal.Alerts` (→ alerts), + configured detection artifacts; reconnect-with-backfill per §4.2 | `slib.velo.sync.tail` — designed to run under a **Storm dmon** (`$lib.dmon.add`), one dmon per watched queue; `slib.velo.admin.dmon --enable` installs/removes them |
| **Scheduled delta** | cron (`$lib.cron`) calling `slib.velo.sync --delta` nightly as a safety net under the tail | documented in README, optionally installed by `admin.dmon` |

The idiomatic-integration research finding (Elastic/Splunk/Timesketch forwarders all key on
`System.Flow.Completion`) maps directly onto the tail design; the pull path covers history from before the
service existed.

### 6.2 Incremental correctness

- **Idempotency** is guaranteed by guid seeding (§5.1) — every sync is safely re-runnable; `?=` prop sets
  never clobber analyst edits; `.seen`/stat fusing is additive.
- **Watermarks** live on `meta:feed` nodes (queryable, survives service restarts, visible to analysts) *and*
  are mirrored in the Cell slab for cheap reads. `--full` ignores them; `--delta` (default) resumes.
- **Ordering:** flows are ingested newest-watermark-forward; within a flow, artifacts in
  `artifacts_with_results` order; monitoring by `_ts`. Parent-proc linking and logon/logoff pairing run as
  second-pass fixups at the end of each flow ingest (they need the full row set).
- **Deletions** (gotcha #13): Velociraptor flows/clients/hunts can be deleted server-side. The service never
  deletes Cortex nodes; a `--verify` sync flags nodes whose backing object 404s with `rep.velo.gone`.
- **Retention** (gotcha #14): monitoring day-files get pruned server-side; the tail + nightly delta keep
  Synapse as the longer-term store — a selling point worth documenting.

### 6.3 Scale controls

MFT/USN collections reach millions of rows. Controls, all admin-configurable with sane defaults:

- Per-command `--limit` (rows) and global `slib:velo:sync:maxrows` (default 500k/flow artifact; exceeding
  logs + tags the flow query `rep.velo.truncated` with resume offset stored, so analysts can continue
  deliberately).
- Per-artifact ingest policy: `allow` (default), `deny` (telemetry artifacts like `Generic.Client.Stats`),
  `meta-only` (flow/query node but no row ingest) — stored in globals, managed by `slib.velo.admin.artifacts`.
- `max_row=1000` batches on the wire; Storm-side node edits batched per response part to keep nexus pressure
  sane; `$lib.time.sleep(0)` yields inside long loops (standard long-runtime hygiene).
- Uploads: size cap + bytes-optional (§5.6).

---

## 7. Storm package surface

### 7.1 Permissions (package `perms`, gate `cortex`)

| Perm | Grants |
|---|---|
| `slib.velo.user` | read-side everything: list/sync clients, hunts, flows, results, alerts, timelines, incidents; model nodes |
| `slib.velo.files` | pull upload bytes into the Axon (bandwidth/storage heavy — separate opt-in) |
| `slib.velo.collect` | start client collections, cancel flows, set labels (touches endpoints) |
| `slib.velo.hunt` | create/modify hunts (fleet-wide blast radius > single collection) |
| `slib.velo.admin` | server profiles, org modes, tag prefix, mapper/artifact policy, dmons, raw VQL |

Priv (asroot) modules mirror these 1:1 (`slib.velo.priv.user` etc., `asroot:perms` per module) so the service
credentials never leak to Storm and users don't need `service.get` — exactly the shodan pattern. Node-creating
modules (`slib.velo.model.*`, `slib.velo.ingest`) run **unprivileged** as the calling user.

### 7.2 Commands (v1)

Discovery/read:

- `slib.velo.info` — server profiles, versions, org list, cert expiry, watermark summary.
- `slib.velo.client.list [--search label:X|host:Y] [--org O] [--sync] [--yield]` — list/ingest clients;
  cmdinputs: `it:host` (re-sync inbound hosts by `:ext:id`).
- `slib.velo.hunt.list [--id H.x] [--sync]`, `slib.velo.flow.list --client C.x [--sync]`.
- `slib.velo.flow.sync --client C.x --flow F.x [--artifact A [--source S]] [--limit N] [--no-files] [--yield]`
  — the workhorse: ingest one collection completely.
- `slib.velo.hunt.sync --id H.x [--results-only] [--limit-per-client N]`.
- `slib.velo.monitoring.sync --artifact A [--client C.x] [--since T] [--until T]`.
- `slib.velo.alerts.sync [--since T]`.
- `slib.velo.uploads.sync (--flow F.x|--hunt H.x) [--max-size N] [--no-bytes]` (perm: files).
- `slib.velo.notebook.list`, `slib.velo.timeline.sync --notebook N.x [--supertimeline S] [--annotations-only]
  [--incident <name>]`.
- `slib.velo.sync [--full|--delta] [--clients] [--hunts] [--alerts] [--monitoring]` — umbrella delta sync.
- `slib.velo.sync.tail [--queue flowcomp|uploads|alerts|<event artifact>]` — dmon body.

Incident:

- `slib.velo.incident.init --name N [--desc|--type|--ext-id|--tag]` / `slib.velo.incident.scope --name N
  (--hunt|--flow|--client|--label|--search|--since|--until)…` / `slib.velo.incident.sync --name N
  [--full|--delta]` / `slib.velo.incident.status --name N` (counts per form, timeline summary, gaps).
- `slib.velo.incident.attack --incident N [--technique Tnnnn] [--time T] [--desc …]` (inbound nodes → attack).
- `slib.velo.timeline.show (--incident N [--host C.x]) [--curated] [--forms …] [--since/--until]`.
- `slib.velo.timeline.build --incident N [--auto] [--notebook N.x]`.
- `slib.velo.timeline.event --incident N [--host C.x] --time T --title … [--summary …] [--index N]`.

Actions (gated):

- `slib.velo.collect --client C.x --artifact A… [--param k=v]… [--urgent] [--wait [--sync]]` (cmdinputs:
  `it:host` with `:ext:id`); `slib.velo.flow.cancel`.
- `slib.velo.hunt.start --artifact A… [--label L|--os windows] [--expires T] [--pause]`.
- `slib.velo.label --add/--del L` (cmdinputs `it:host`).

Admin:

- `slib.velo.admin.server.{add,del,list,default}`, `slib.velo.admin.tags [--prefix|--enable|--disable]`,
  `slib.velo.admin.artifacts [--deny A|--allow A|--meta-only A|--list]`, `slib.velo.admin.mapmeta --artifact A
  --time-col T --msg-col M`, `slib.velo.admin.dmon [--enable|--disable|--status]`,
  `slib.velo.admin.query "<VQL>" [--env k=v]… [--org O]` (raw escape hatch, prints JSON).

Every command: `--yield` where it makes sense, cmdinputs declared for pipeline use, errors via
`$lib.warn`/`$lib.exit` conventions, extra verbosity under `$lib.debug` — all per repo conventions. Command
count ≈ 30, on par with shodan's 29.

### 7.3 User-facing docs

README structure (packaged via `docs:` like shodan): quickstart (mint api config → add server → sync),
permission/role matrix (both sides: Synapse perms ↔ Velociraptor roles), command reference, the incident
walkthrough (§13), modeling reference (the §5 tables, condensed), scale/tuning, troubleshooting (cert expiry,
org access, version quirks).

---

## 8. Python implementation notes

- `svc.py` `confdefs`: `velo:config:yaml|path`, `velo:profile:name`, `velo:timeout` (default 600 — VQL can be
  slow), `velo:ratelimit` (queries/sec, default 5), `velo:maxrow` (default 1000), `velo:fetch:chunksize`,
  `velo:gui:url` (for deep links). Session/channel lifecycle on `__anit__`/`onfini` like shodan's aiohttp
  session.
- `vql.py`: every statement a named constant with `env.` placeholders only, e.g.
  `LIST_FLOWS = "SELECT * FROM flows(client_id=ClientId) LIMIT 1000"` with windowing variants; a tiny builder
  assembles `SELECT * FROM source(...)` arg permutations from allow-listed kwargs. No f-strings into VQL,
  ever; unit test asserts no `{` interpolation in any constant.
- `norm.py`: `normTime` (hint-driven, §4.5), `normClient`, `normFlow` (incl. request summarization),
  `normHunt`, `normAlert`, `normUpload`, `normTimelineRow`, path normalizers (NT path → file:path-safe,
  device-path stripping, case policy: preserve case, let Synapse types normalize).
- `mappers.py`: `@mapper` registry, `Proposal` dataclass, `MapCtx` (dep/org/client/flow/hunt/artifact/source/
  rowidx/host guid), the EVTX derivation table, column-sniffing helpers for the fallback. Pure functions —
  the test surface.
- Concurrency: per-profile `asyncio.Semaphore` honoring `velo:ratelimit`; watch streams as cell `schedCoro`
  tasks only while a tail genr is being consumed (the dmon holds the genr open; no server-side buffering of
  unconsumed events beyond a bounded queue with drop-oldest + warning).

---

## 9. Testing strategy

Per repo conventions: no default external calls; full coverage of Python and Storm paths.

1. **`fakevelo.py`** — an in-process **grpc.aio server** implementing `Query`, `VFSGetBuffer`, `Check` from
   the real generated stubs. `Query` pattern-matches the incoming VQL constant + env and returns canned
   `VQLResponse` streams from `tests/fixtures/*.json`. Fixtures encode the **verbatim schemas** from the
   research report (Pslist, Netstat, Prefetch, MFT, Usn, Evtx 4624/4688/1102/Sysmon, TaskScheduler, Services,
   Autoruns CSV shape, Chrome.History, Triage Uploads, uploads.json rows, ClientInfo, flow/hunt protos,
   `Server.Internal.Alerts` rows, timeline rows incl. Annotation, notebook metadata) — including the nasty
   bits: mixed timestamp units, missing columns, nested EventData, a `Custom.Windows.System.Pslist` override,
   and an unmapped artifact for the fallback path. Records all requests for assertions (fakeshodan pattern).
2. **Python unit tests**: `normTime` across all unit shapes; every mapper against fixtures (golden node
   proposals); guid-seed stability (same row → same seed; different dep/org → different); VQL constants
   injection-free; client paging/retry (fake flaky server); watch reconnect+backfill.
3. **Storm tests** (`StormPkgTest` style, `s_tests.SynTest` + fake service like shodan's `shodanSvc`
   contextmanager): package load + `test_versions_match` (4 locations per CLAUDE.md); per-command modeling
   assertions (e.g. flow.sync creates N `it:exec:proc` with `-(found)>`/`-(seen)>` edges, correct props);
   incident lifecycle end-to-end (init→scope→sync→attack→timeline.show output); timeline ingest incl.
   row-identity `-(refs)>` resolution and the incident/device aggregation query; idempotency (run sync twice,
   node counts identical, analyst-edited prop survives); perms (each command denied without its perm —
   shodan's `TestShodanStormPerms` pattern); scale guards (maxrows truncation tagging); generic fallback
   (unmapped artifact → `it:log:event` with taxonomy + data).
4. **`test_live.py`** — env-gated (`VELO_LIVE_CONFIG=...`) smoke tests against a real deployment, mirroring
   shodan's gated live tests. Document a `velociraptor --config ... gui` dev-box recipe in the README.
5. CI: the standard `_service.yml` pipeline; the test docker image adds `grpcio` build deps if wheels are
   unavailable for the pinned Python (3.11).

---

## 10. Docker & deployment

- `docker/prod/Dockerfile` — copy of shodan's with name swapped; entrypoint runs the Cell
  (`python -m velosvc`); healthcheck identical. Mount or env-inject the api_client YAML
  (`velo:config:path=/vertex/velo/api.config.yaml` as a secret volume) — never bake certs into the image.
- `docker/test/` for the CI test environment.
- Network note for README: the container must reach `API.bind_address:8001` (mTLS gRPC); Velociraptor's API
  defaults to localhost — operators must set `API.hostname` + bind before minting the api config (connection
  string is baked in).

---

## 11. Performance & scale budget (design targets)

| Dimension | Target | Mechanism |
|---|---|---|
| Fleet size | 10k clients | client sync is one `clients()` stream; ~10k nodes/min is fine for Storm batch edits |
| One flow, big artifact (MFT) | 1M rows | 500k default cap + resume offsets; ~1k rows/VQLResponse part; proposal batching; expect ~20–40 min for a deliberate full-MFT ingest — document, don't hide |
| Typical IR incident (20 hosts, triage + pslist + evtx + prefetch + netstat) | < 30 min full sync | measured target for the walkthrough dataset |
| Live tail latency | < 15 s flow-completion → nodes | `max_wait=1` on watch streams |
| Uploads | 256 MiB/file cap default; stream-hash single pass | §5.6 |

Nexus/layer pressure and Optic usability (tag cardinality: per-incident tags are bounded; `rep.velo.label.*`
bounded by label hygiene) get a README "operational guidance" section.

---

## 12. Security considerations

- The api_client YAML embeds a private key ⇒ cell-slab only, asroot priv modules only, never in Storm vars,
  never logged; `admin.server.add --config` accepts a path or inline YAML but echoes only the cert subject +
  expiry back.
- Velociraptor-side least privilege: document `api,reader` vs `analyst` vs `investigator` per enabled feature
  set (§4.3); explicitly warn that an over-privileged principal can `execve` on the server via VQL.
- VQL injection: env-only parameterization (§4.2, enforced by tests). Row *content* is hostile-adversary data
  (attacker-controlled strings on compromised hosts): everything lands in typed props/`:data`/node data —
  never interpolated into Storm text or tag names without normalization (tag normalizer strips to
  `[a-z0-9_]`); `:mesg`/`:title` length-capped.
- Collected file bytes are malware: Axon-only handling, no local tempfile execution surface; hashes computed
  stream-side.
- `slib.velo.collect`/`hunt.start` touch endpoints — separate perms + `--urgent` requires explicit flag;
  README states the blast-radius difference between the two perms.
- Export/`admin.query` output can include other orgs' data if the principal is over-scoped — org iteration is
  explicit, never implicit `orgs=['*']`.

---

## 13. Worked example (acceptance narrative)

The README walkthrough — also the integration-test storyline:

```
// 1. Admin: register the deployment
slib.velo.admin.server.add engagement-acme --config /vertex/velo/api.config.yaml --default

// 2. Analyst ran the IR in Velociraptor: hunted triage + pslist + evtx across labeled hosts,
//    got alerts, built a notebook super-timeline. Now pull it all:
slib.velo.incident.init --name acme2026 --desc "ACME ransomware response" --type ransomware
slib.velo.incident.scope --name acme2026 --hunt H.CQ6PT1AV9S91S --label Compromised --since 2026/09/01
slib.velo.incident.sync --name acme2026

// 3. Everything is one lift away:
#cno.inc.acme2026                                      // the whole incident subgraph
risk:compromise:name=acme2026 -(refs)> it:host         // investigated devices
risk:compromise:name=acme2026 -(refs)> it:exec:query -(found)> *   // per-collection evidence
risk:alert#cno.inc.acme2026 -(about)> *                // findings and their evidence
slib.velo.timeline.show --incident acme2026                        // full-incident machine timeline
slib.velo.timeline.show --incident acme2026 --host WIN-DC01 --curated  // per-device curated timeline

// 4. Analyst confirms the initial access and promotes it:
risk:alert:name="Suspicious psexec" | slib.velo.incident.attack --incident acme2026 --technique T1569.002
risk:compromise:name=acme2026 [ :vector={risk:attack#cno.inc.acme2026 +:type=initial-access} ]

// 5. Keep it live for the rest of the engagement:
slib.velo.admin.dmon --enable      // tails flow completions, uploads, alerts into the same incident scope
```

Acceptance criteria for v1 = this walkthrough succeeds against the fake server in tests and against a live
0.77 dev deployment manually, with: every Velociraptor object class represented (client, hunt, flow, results
across ≥12 mapped artifacts, generic fallback, uploads w/ bytes, alerts, labels, notebook timeline), zero
orphan nodes (everything reachable from the compromise node via tag or ≤2 edge hops), and idempotent re-sync.

---

## 14. Deferred / v2+ candidates

- **Offline collector & export-zip import** — ingest flow/hunt export zips and offline-collector output
  without server access (formats verified in research §2.6); valuable for cold cases.
- **Notebook cell-level ingest** (cells → threaded `meta:note`s; cell tables via `source(notebook_id=…)`).
- **`inet:service:*` modeling** of the Velociraptor GUI users/platform (creator accounts as
  `inet:service:account`, deployment as `inet:service:platform`).
- **Per-user API credentials** via typed vaults (requires per-analyst Velociraptor principals; ACL story
  first).
- **Write-back**: push Synapse annotations into Velociraptor (timeline_add of Synapse-curated events,
  `AnnotateTimeline`, label sync Synapse→Velo) — needs `analyst` role and careful loop prevention.
- **MITRE auto-mapping** from Sigma rule tags / artifact metadata → `-(uses)> it:mitre:attack:technique` on
  alerts (pairs with the synapse-mitre-attack power-up).
- **it:sec:c2:config extraction** hand-off: uploads that are malware → trigger other services (yarastorm,
  future capa/hatching) — the `enrich`-style cross-service story.
- **Optic workflows/layouts** for the incident views, if/when this repo grows Optic packaging.
- **Quarantine/response actions** (`Windows.Remediation.Quarantine`) behind a new high-friction perm.

## 15. Open questions (to resolve during implementation)

1. **pyvelociraptor dependency vs vendored protos** (§3) — decide on grpcio/protobuf compat with the pinned
   Synapse base image; vendoring is the fallback. Spike first.
2. **Exact `synapse_minversion`** — audit the newest prop/form we touch against the model-updates changelog
   (candidates: `meta:feed` intro, `risk:alert:host`, `it:os:windows:task`) and pin.
3. **Proposal-batch API shape** — one Telepath call per response part (`normRows`) vs mapper execution inline
   in the result genr (fewer round trips). Benchmark against the 1M-row target; the design allows either
   behind `slib.velo.ingest`.
4. **`risk:compromise:time` min/max fusing** — `:time`/`:lasttime` lack ismin/ismax typeopts; implement
   compare-and-set in Storm (read-modify-write under a single node edit) and verify under concurrent syncs.
5. **Host entity resolution across deployments** — same physical machine enrolled in two deployments yields
   two `it:host` guids by design (per-deployment identity is correct for IR provenance); document the manual
   merge pattern (`:name`/`:serial` pivots + `-(linked)>`), revisit if users demand auto-merge.
6. **Timeline event volume** — if analysts' Velociraptor super-timelines contain tens of thousands of rows,
   default-ingesting all of them as meta:event may still be too chatty; ship with a soft cap (e.g. 5k/timeline,
   warn + `--force`) and gather feedback.
7. **`it:prod:softid` vs `:ext:id` for client ids** — design says both; confirm no Optic UX confusion, drop
   `it:prod:softid` if redundant in practice.

---

## 16. Phased roadmap

| Phase | Scope | Exit criteria |
|---|---|---|
| **0 — scaffold** (0.1.0) | repo plumbing (folder, services.toml, CI, docker, LICENSE), Cell+CellApi skeleton, profile registry, fake server + `Check`/version probe, `slib.velo.info`, `admin.server.*`, `admin.query` | CI green; info/raw query work against fake + live dev server |
| **1 — inventory** (0.2.0) | clients/hunts/flows listing + sync; `it:host`/`it:exec:query`/`meta:source`/`meta:feed` modeling; watermarks; `client.list/sync`, `hunt.*`, `flow.list` | inventory walkthrough; idempotency tests |
| **2 — results engine** (0.3.0) | mapper registry + proposal builder + generic fallback; first 6 mappers (ClientInfo, Pslist, Netstat, Evtx(+4624/4688/1102), Services, TaskScheduler); `flow.sync`/`hunt.sync`/`monitoring.sync` | mapped + fallback ingest with full edge wiring |
| **3 — findings & files** (0.4.0) | alerts sync, detection→alert, uploads→Axon pipeline, labels, remaining v1 mappers (Prefetch, Amcache, MFT, USN, Yara, Sigma, Registry, Browser, Triage/Kape, BashHistory, VFS) | alert evidence-linking (row-identity) tests pass |
| **4 — incident & timelines** (0.5.0) | incident.init/scope/sync/attack/status; meta:timeline/meta:event; velo timeline ingest; timeline.show/build/event; incident tagging everywhere | §13 walkthrough green end-to-end |
| **5 — live & polish** (0.6.0) | sync.tail dmons, reconnect/backfill, scheduled delta, scale guards, admin.artifacts/mapmeta, README docs, operational guidance | soak test against live dev server; docs complete |
| **1.0.0** | after real-engagement shakeout + open-questions resolved | maintainer call (major per CLAUDE.md) |

Each phase = its own PR(s) with the per-service version bump (patch/minor rules per CLAUDE.md) across all four
version locations, `uv.lock` edited directly + `uv lock --check`.
