# Synapse Data Model Research for a Velociraptor IR Ingest Storm Service

**Date:** 2026-10-31
**Model version verified against:** `synapse==2.256.0` (current PyPI release and GitHub `master`; version tuple `(2, 256, 0)` from `synapse/lib/version.py`).
**Verification method:** This report was NOT written from memory or secondhand sources. The complete runtime data model was dumped from a live temporary Cortex (`synapse.cortex.getTempCortex()` -> `getModelDict()`) of synapse 2.256.0 installed from PyPI into `/home/user/vraptor-research/.venv`. The dump (595 forms, 698 types, 90 declared light-edge definitions, 2 universal props, 21 interfaces) is at `/home/user/vraptor-research/model.json`; the model source clone is at `/home/user/vraptor-research/synapse-src/synapse/models/`. Every property table in Section B below is machine-generated from that dump — it is the same content that renders at the official autodocs page:

- https://synapse.docs.vertex.link/en/latest/synapse/autodocs/datamodel_forms.html
- https://synapse.docs.vertex.link/en/latest/synapse/autodocs/datamodel_types.html
- Model source: https://github.com/vertexproject/synapse/tree/master/synapse/models (`infotech.py`, `risk.py`, `inet.py`, `files.py`, `base.py` — note: there is **no `meta.py`**; all `meta:*` forms live in `base.py`; plus `orgs.py`, `dns.py`, `auth.py`, `person.py`, `proj.py`)

---

## A. Design-level findings and conventions

### A.1 Executive mapping: Velociraptor concept -> Synapse form

| Velociraptor concept | Synapse form(s) | Notes |
|---|---|---|
| Client / endpoint | `it:host` | guid form; seed guid from client_id; set `:ext:id`=client_id, `:name`, `:os`, `:os:name`, `:ipv4`, `:domain`, `:serial` |
| Velociraptor server / deployment | `meta:source` (provenance) + optionally `inet:service:platform` + `it:prod:soft`/`it:prod:softver` | one `meta:source` per deployment |
| Agent version on host | `it:prod:softver` + `it:hostsoft` comp node `(host, softver)` | |
| Hunt / flow (collection) | `it:exec:query` (`:text`=VQL, `:language`=`vql`, `:time`, `:host`) + `-(found)>` edges to result nodes | canonical "query found these nodes" pattern |
| Ingest state / feed | `meta:feed` (`:source`, `:cursor`, `:latest`, `:offset`) + `-(found)>` edges, or `meta:source:ingest:*` props | both exist in 2.256 |
| Process listing (Pslist) | `it:exec:proc` | `:host`, `:pid`, `:time`, `:exited`, `:cmd`, `:path`, `:exe`, `:account`, `:src:proc` |
| Command lines | `it:cmd` (str) via `it:exec:proc:cmd`; shell histories via `it:cmd:session` + `it:cmd:history` | |
| Netstat / sockets | `it:exec:bind` (listening) and `inet:flow` (connections; has `:src:proc`, `:src:host`, `:raw`) | |
| DNS cache / queries | `inet:dns:request` (`:host`, `:query:name`, `:time`) | |
| File / MFT / NTFS metadata | `it:fs:file` (`:host`, `:path`, `:file`, `:ctime`, `:mtime`, `:atime`, `:user`) | the filesystem-entry form |
| File content (uploads) | `file:bytes` (+ Axon for bytes) | sha256-keyed |
| File create/read/write/delete telemetry | `it:exec:file:add` / `:read` / `:write` / `:del` | all implement `it:host:activity` |
| Registry key/value | `it:dev:regkey` (str), `it:dev:regval` (guid: `:key`,`:str`,`:int`,`:bytes`) | **not** `it:os:windows:registry` (does not exist) |
| Registry telemetry | `it:exec:reg:get` / `:set` / `:del` (`:reg` -> `it:dev:regval`) | |
| Windows event log record | `it:log:event` (`:type` taxonomy, `:mesg`, `:data` raw JSON, `:ext:id`, `:host`, `:time`, `:severity`) | **no `it:sec:evtx` form exists** — flagged in A.8 |
| Logon events (4624 etc.) | `it:logon` (`:host`, `:account`, `:time`, `:success`, `:client:ipv4`, `:logoff:time`, `:duration`) | optionally also keep the raw `it:log:event` |
| Users & groups | `it:account` (`:windows:sid`, `:posix:uid`, `:groups`), `it:group`, `auth:creds`, `ps:contact` via `it:account:contact` | |
| AD domain | `it:domain` (`:name`, `:org`) via `it:host:domain` / `it:account:domain` | |
| Scheduled tasks | `it:os:windows:task` (`:host`, `:cmds`, `:account`, `:uri`, `:path`, `:file`, `:period`) | exists |
| Windows services | `it:os:windows:service` (`:host`, `:name`, `:displayname`, `:imagepath`, `:type`, `:start`) | exists |
| cron | `it:os:posix:cron` | |
| Browser history | `it:exec:url` (`:url`, `:time`, `:host`, `:browser`->`it:prod:softver`, `:page:title`) | **no dedicated browser-history form** |
| Prefetch / Amcache / Shimcache | **no dedicated forms** — model as `it:exec:proc` (+`.seen` interval) and/or `it:fs:file` of the artifact file; see A.8 | flagged |
| USB / drives / volumes | `it:storage:volume` + `it:storage:mount` (and `it:prod:hardware` for the device model) | **no `it:dev:drive` form** |
| Drivers | **no `it:os:windows:driver` form** — use `it:os:windows:service` (`:type` 1/2 = kernel/fs driver) and/or `it:exec:loadlib` / `it:hostsoft` | flagged |
| Mutexes / pipes | `it:dev:mutex`, `it:dev:pipe` (strings) + `it:exec:mutex`, `it:exec:pipe` (instances) | |
| YARA hunt results | `it:app:yara:rule` + `it:app:yara:match` (file) / `it:app:yara:procmatch` (process) | |
| Velociraptor monitoring/alerts | `risk:alert` (`:ext:id`, `:type` taxonomy, `:severity`, `:priority`, `:detected`, `:engine`, `:host`, `:url`, `:benign`, `:verdict`, `:status`) + `-(about)>` edges | |
| The incident itself | `risk:compromise` (+ `risk:attack` per discrete attacker action, `:compromise` prop links them) | **there is no `incident` form**; see A.3 |
| Incident / per-device timeline | `meta:timeline` + `meta:event` (`meta:event:timeline` **property**, not an edge) | verified to exist; see A.4 |
| Analyst notes | `meta:note` + `-(about)>` edges | |
| Sigma matches | `it:app:sigma:rule` + `it:app:sigma:matched` (`:rule`, `:target`->`it:log:event`, `:sensor`->`it:host`) | good fit for Velociraptor sigma support |
| AV scan results | `it:av:scan:result` (`it:av:sig`/`it:av:filehit`/`it:av:prochit` are **deprecated**) | |
| MITRE technique refs | `it:mitre:attack:technique`; link with `-(uses)>` from risk nodes or `-(refs)>` | |

### A.2 GUID generation conventions

- `$lib.guid()` -> random guid. `$lib.guid(arg1, arg2, ...)` or `$lib.guid(valu=$item)` -> **deterministic** guid from hashed arguments (verified signature in `synapse/lib/stormtypes.py` 2.256.0: `guid(*args, valu=$lib.undef)`).
- Convention used by Vertex power-ups and Synapse ingest examples: seed stable guids with a namespace-qualified tuple so re-ingest is idempotent and cannot collide with other services:
  - `it:host`: `$lib.guid(velociraptor, host, $client_id)`
  - `it:exec:proc`: `$lib.guid(velociraptor, proc, $client_id, $pid, $start_time)` (pid alone is not stable — include create time)
  - `it:log:event`: `$lib.guid(velociraptor, winevt, $client_id, $channel, $record_id)`
  - `risk:alert`: `$lib.guid(velociraptor, alert, $alert_id)`
  - `inet:flow`: `$lib.guid(velociraptor, flow, $client_id, $src, $sport, $dst, $dport, $time)`
- Docs: https://synapse.docs.vertex.link/en/latest/synapse/userguides/storm_ref_type_specific.html (guid section) and `$lib.guid` in https://synapse.docs.vertex.link/en/latest/synapse/autodocs/stormtypes_libs.html
- `$lib.gen.*` dedup helpers (verified in `synapse/lib/stormlib/gen.py`): `orgByName`, `softByName`, `vulnByCve`, `riskThreat`, `riskToolSoftware`, `campaign`, `psContactByEmail`, `itAvScanResultByTarget`, `langByName`, `langByCode`, `polCountryByIso2`, `newsByUrl`, `industryByName`, `orgHqByName`, `orgByFqdn`. Use `$lib.gen.softByName(velociraptor)` for the tool node.
- Storm syntax reminders: node create/edit `[ <form>=<valu> :prop=... ]`; light edges create `[ +(verb)> { <query> } ]`, reverse create `[ <(verb)+ { ... } ]`; traverse `-(verb)>` / `<(verb)-`; `.seen` set with `[ .seen=($t1, $t2) ]` (intervals auto-expand).

### A.3 How Vertex models an "incident" (no `incident` form exists)

Verified against the 2.256.0 model: there is **no form named `incident`** in any namespace. The Vertex-intended decomposition:

1. **`risk:compromise`** — the incident as a whole: "A compromise and its aggregate impact. The compromise is the result of a successful attack." Carries `:name`, `:desc`, `:type` (taxonomy `risk:compromisetype`), `:time` (earliest evidence), `:lasttime`, `:duration`, `:detected`, `:severity`, `:attacker`/`:target` (`ps:contact`), `:campaign`, `:vector` (-> the initial-access `risk:attack`), `:goal(s)`, loss/ransom econ props, `:ext:id`, `:url`, and **`:tag`** (`syn:tag`) — the designated tag to annotate every node that is part of the compromise (e.g. `cno.inc.acme2026`).
   - Edges: `risk:compromise -(uses)> ou:technique`, `risk:compromise -(stole)> *`, `risk:compromise -(targets)> ou:industry`.
2. **`risk:attack`** — each discrete attacker action within the incident; `:compromise` points at the `risk:compromise`; use `-(uses)> *` for every indicator/tool/vuln used and `-(targets)> *` for each targeted host/account (the old `:target:host`, `:used:*` props are **deprecated** in favor of these edges).
3. **`risk:alert`** — each detection (Velociraptor monitoring hit, server event, analyst flag): `:attack` links an alert to a confirmed attack; `-(about)>` edges link it to the nodes it alerts on (`risk:alert -(about)> *` is a declared model edge).
4. **`ou:campaign`** — only when correlating multiple incidents to one actor effort; it has a `:timeline` (->`meta:timeline`) property.
5. **`proj:ticket`/`proj:project`** — optional IR case/ticket workflow (status enum new->in progress->done, `:assignee`, `:due`).
6. Tagging: apply the per-incident tag named in `risk:compromise:tag` to all involved nodes so a single lift (`#cno.inc.<name>`) returns the incident subgraph.

### A.4 Timelines — verified current mechanics

**`meta:timeline` EXISTS** (in `base.py`) — "A curated timeline of analytically relevant events." Props: `:title`, `:summary`, `:type` (-> `meta:timeline:taxonomy`).

**`meta:event`** — "An analytically relevant event in a curated timeline." Props: **`:timeline`** (->`meta:timeline`), `:title`, `:summary`, `:time`, `:duration`, `:index` (ordering when exact times are unknown), `:type` (->`meta:event:taxonomy`).

- The link between event and timeline is the **`meta:event:timeline` property — there is NO `-(has)>` edge** declared between them (verified in the model edge list; the only declared `has` edges from meta forms are `meta:ruleset -(has)> meta:rule`/rule forms).
- To tie a `meta:event` to the underlying forensic evidence use the generic declared edge **`* -(refs)> *`** ("The source node contains a reference to the target node"), i.e. `meta:event -(refs)> it:exec:proc`. The one specifically declared meta:event edge is `meta:event -(caused)> risk:outage`.
- Recommended Velociraptor pattern:
  - One `meta:timeline` for the incident: `:title="Incident <X> master timeline"`, `:type=velociraptor.incident` (your taxonomy); link from `ou:campaign:timeline` when a campaign exists; tag it with the compromise tag.
  - One `meta:timeline` per device: `:title="<hostname> timeline"`, `:type=velociraptor.host`; its events `-(refs)>` the forensic nodes and may also `-(refs)>` the `it:host`.
  - `meta:event` is for *curated/analytic* events (docs wording: "analytically relevant ... curated"). Do **not** mint a `meta:event` per raw telemetry row — raw rows already carry `:time` props and form the machine timeline (lift by `:host` and sort by `:time`/`.seen`). Mint `meta:event`s for significant, human-selected moments.
- "Process event at T during incident X on host H" canonical shape:

      [ it:exec:proc=$pguid :host=$hguid :time=$t ... ]    // the fact
      [ <(refs)- { meta:event=$eguid } ]                    // curated timeline entry refs it
      meta:event=$eguid [ :timeline=$incident_tl :time=$t :title='...' ]
      it:exec:proc=$pguid [ +#cno.inc.acmehack ]            // compromise tag
      risk:attack=$aguid [ :compromise=$cguid +(uses)> { it:exec:proc=$pguid } ]

- `.seen` (universal, type `ival`): "time interval for first/last observation of the node" — use for *observation* windows (e.g., amcache first/last execution evidence), never as a substitute for event-time props like `:time`/`:ctime`.
- No dedicated Vertex blog post on `meta:timeline` could be located via web search; the form autodocs and model-update changelogs (https://synapse.docs.vertex.link/en/latest/synapse/userguides/model_updates.html) are the authoritative sources.

### A.5 Provenance: `meta:source` + `-(seen)>` (the `meta:seen` form is DEPRECATED)

- `meta:source` — guid form, props `:name`, `:type`, `:url`, plus built-in ingest-state props `:ingest:cursor`, `:ingest:latest`, `:ingest:offset`.
- **The `meta:seen` comp form is marked deprecated in 2.256.0.** The current convention — used by every Vertex Rapid Power-Up (verified in the CrowdStrike, Microsoft Defender, and MITRE ATT&CK power-up user guides) — is the **`meta:source -(seen)> <node>` light edge**: declared in the model as `meta:source -(seen)> *` = "The meta:source observed the target node."
- Service pattern: create one deterministic `meta:source` (e.g. `$lib.guid(velociraptor, source, $deployment_url)`, `:name='velociraptor'`, `:type='velociraptor'`) and add `[ <(seen)+ { meta:source=$src } ]` on every ingested node. Power-ups name sources like `crowdstrike api`, `microsoft defender for endpoint api`, with `:type` like `synapse.microsoft.defender`.
- `meta:feed` ("A data feed provided by a specific source": `:source`->`meta:source`, `:cursor`/`:latest`/`:offset`/`:period`, `:opts`, `:query`) + declared edge `meta:feed -(found)> *` is the newer per-feed ingest-tracking construct — a good fit for one feed per Velociraptor hunt or artifact-collection stream.

### A.6 Lightweight edge verbs — standard semantics (declared in the 2.256.0 model)

The full machine-generated table is in Section B. Verbs the Velociraptor service should use:

| Edge | Semantics |
|---|---|
| `meta:source -(seen)> *` | source observed the node (provenance; replaces deprecated `meta:seen` form) |
| `meta:feed -(found)> *` | feed produced the node |
| `it:exec:query -(found)> *` | node was returned as a result of running the query (hunts/VQL) |
| `risk:alert -(about)> *` | alert is about the node |
| `it:log:event -(about)> *` | log event is about the node (e.g. 4688 event -> the `it:exec:proc`) |
| `meta:note -(about)> *` | analyst note about nodes |
| `* -(refs)> *` | generic "source contains a reference to target" (meta:event->evidence, media:news->IOCs) |
| `meta:rule -(matches)> *`, `-(detects)> *`, `-(generated)> risk:alert / it:log:event` | detection rule lineage |
| `risk:attack` / `risk:compromise` / `risk:threat` / `risk:tool:software` `-(uses)> *` | used the target node (replaces deprecated `:used:*` props) |
| `risk:attack` / `risk:threat` / `ou:campaign` `-(targets)> *` | targeted the node (replaces `:target:*` props) |
| `risk:compromise -(stole)> *` | data/asset stolen in the compromise |
| `it:app:{yara,sigma,snort,suricata}:rule -(detects)> *` | rule designed to detect target |
| `* -(linked)> *` | weakest generic association |

Custom verbs are allowed (CrowdStrike power-up uses `-(_crowdstrike:related)>`; convention: leading underscore + vendor namespace, e.g. `_velociraptor:collected`), but prefer declared verbs.

### A.7 Tag conventions & power-up precedent

- Synapse ships **no built-in tags**; the Vertex convention (userguide "Analytical Model": https://synapse.docs.vertex.link/en/stable/synapse/userguides/analytical_model.html) is:
  - **`rep.<reporter>.<assertion>`** — third-party reporting. Power-up examples (verified from the CrowdStrike user guide): `rep.crowdstrike.confidence.high`, `rep.crowdstrike.threat_type.ransomware`, `rep.crowdstrike.wickedspider`; Defender TI: `rep.microsoft.malvertising`, `rep.microsoft.t1047_windows_management_instrumentation`. A Velociraptor service should tag with **`rep.velociraptor.<...>`** (e.g. `rep.velociraptor.quarantined`, `rep.velociraptor.artifact.windows_system_pslist`) and make the prefix configurable (power-ups migrated "tag prefix configurations" into their config managers).
  - **`cno.*`** — the analyst's *own* assessments (`cno.mal`, `cno.infra.*`, `cno.threat.<cluster>`, and commonly `cno.inc.<incident>` for incident membership — pair with `risk:compromise:tag`).
- **Rapid Power-Up EDR precedent** (catalog: https://synapse.docs.vertex.link/projects/rapid-powerups/en/latest/):
  - **`synapse-microsoft-defender`** (closest EDR analog; verified user guide): endpoint alerts -> **`risk:alert`** (`:ext:id`, `:name`, `:desc`, `:severity`, `:detected`, `:type` taxonomy, `:verdict`, `:benign`, `:url`); M365 incidents -> **`risk:attack`** (`:ext:id`, `:detected`, `:severity`, `:type`, `:url`, `:reporter:name`) with incident->alert via `risk:alert:attack`; alert-evidence processes -> **`it:exec:proc`** (`:account`, `:cmd`, `:exe` (sha256), `:path`, `:path:base`, `:pid`, `:time`) linked **`risk:alert -(refs)> it:exec:proc`** and `-(refs)> it:mitre:attack:technique`; provenance `meta:source` + `-(seen)>`.
  - **`synapse-crowdstrike`** (intel modules only; verified user guide): indicators -> `hash:md5/sha1/sha256` + `rep.crowdstrike.*` tags; actors -> `risk:threat`; reports -> `media:news`; `meta:source :name='crowdstrike api'` + `-(seen)>`; custom edge `-(_crowdstrike:related)>`. Public docs do **not** cover Falcon device/detection ingest.
  - **`synapse-sentinelone` and `synapse-carbonblack` DO NOT EXIST** in the current Rapid Power-Up catalog (verified against the full package index; the only EDR-named packages are `synapse-crowdstrike` and `synapse-microsoft-defender`; `synapse-splunk` covers SIEM alert ingest).
  - **No Velociraptor power-up exists** — no official precedent to collide with.
  - **`synapse-mitre-attack`**: creates `it:mitre:attack:*` nodes via `mitre.attack.sync`, provenance `meta:source` ("mitre att&ck api") + `-(seen)>`, links text-scraped references with `-(refs)>` edges.

### A.8 Artifacts with NO dedicated form (verified absent in 2.256.0) and workarounds

| Missing concept | Verified absent | Recommended modeling |
|---|---|---|
| Prefetch | no type/form matching "prefetch" | `it:exec:proc` per executable (`:host`, `:path`, `:exe`; last-run -> `:time`, first/last-run evidence -> `.seen`) + `it:fs:file` for the `.pf` file; tag `rep.velociraptor.prefetch`. Mint per-run proc nodes only if per-run fidelity is required. |
| Shimcache / Amcache | nothing matches | `it:fs:file` (path, mtime, sha1 from amcache) and/or `it:exec:proc` where execution is implied (amcache); tag `rep.velociraptor.amcache` / `.shimcache` to preserve the evidentiary caveat; `file:filepath`/`file:bytes` for hash linkage. |
| Browser history | no "browser" type | `it:exec:url` with `:browser` (->`it:prod:softver`), `:time`, `:host`, `:url`, `:page:title`. `inet:web:*` is for *service-side* account activity, not host history. Downloads: `it:exec:file:add` + `inet:urlfile`. |
| EVTX-specific form | no `it:sec:evtx` | `it:log:event` with `:type` taxonomy (e.g. `windows.security.4624`), `:ext:id`=EventRecordID, `:data`=raw JSON, `:mesg`, `:host`, `:time`, `:severity`, `:product`; `-(about)>` derived nodes (`it:logon`, `it:exec:proc`, ...). |
| USB device history | no "usb" type | `it:prod:hardware` (`:manufacturer:name`, `:model`, `:type` taxonomy) for the device; storage: `it:storage:volume` (`:id`=volume serial/GUID, `:name`, `:size`, `:type` taxonomy) + `it:storage:mount` (`:host`, `:volume`, `:path`, `:period`). |
| Drivers | no "driver" type | `it:os:windows:service` (`:type`=1 kernel / 2 fs driver; `:imagepath`), `it:exec:loadlib` for load events, `file:bytes` `:mime:pe:*` for the binary. |
| EDR alert form (`it:av:alert`) | does not exist | `risk:alert` (preferred; `:engine` -> `it:prod:softver`) or `it:av:scan:result` for scanner verdicts. `it:av:sig`, `it:av:filehit`, `it:av:prochit` are **deprecated** -> `it:av:scan:result`. |
| `it:dev:drive` | does not exist | `it:storage:volume` / `it:storage:mount`. |
| `it:os:windows:registry` | does not exist | correct forms are `it:dev:regkey` / `it:dev:regval`. |
| `incident` form | does not exist | `risk:compromise` (+`risk:attack`, `risk:alert`, `meta:timeline`) — see A.3. |

### A.9 Deprecations to avoid (all verified from the 2.256 dump)

- `meta:seen` form -> `meta:source -(seen)>` edge.
- `it:av:sig` / `it:av:filehit` / `it:av:prochit` -> `it:av:scan:result`.
- `risk:hasvuln` -> `risk:vulnerable` (`:node`=ndef, `:vuln`, `:period`, `:mitigated`).
- `it:exec:proc:user` (inet:user) -> `it:exec:proc:account` (->`it:account`).
- `it:exec:proc:src:exe` -> create `:src:proc` and set its `:path`.
- `risk:attack:target:*`, `risk:attack:used:*`, `risk:attack:via:*` -> `-(targets)>` / `-(uses)>` edges.
- `:techniques` arrays on `risk:*`/`ou:campaign` -> `-(uses)> ou:technique` edges.
- `it:host:manu`/`it:host:model` -> `:hardware` (`it:prod:hardware`).
- `auth:creds:web:acct` -> `:service:account` (`inet:service:account`).
- `risk:alert:service:instance` / `it:log:event:service:instance` -> `:service:platform`.
- `it:sec:cve:desc/:url/:references` -> `risk:vuln:cve:*` props.
- `ou:campaign:type` -> `:camptype` taxonomy.

### A.10 Local resources

- `/home/user/stormlibpp` — the user's StormLib++ (Python helpers for Storm service dev: `StormPkg`, telepath/HTTP cortex helpers, node utilities, plus own Rapid Power-Ups). No Velociraptor code present. Implementation harness, not a model source.
- `/home/user/stormsvcs/svcs/*` — existing services (abusech, crtsh, ip_api, shodan, yarastorm) follow the pyproject + `src/<pkg>/pkgproto/<pkg>.yaml` layout with per-service version sync (see repo CLAUDE.md).
- Full model dump: `/home/user/vraptor-research/model.json`; synapse source clone: `/home/user/vraptor-research/synapse-src/`.

### A.11 Sources

- https://synapse.docs.vertex.link/en/latest/synapse/autodocs/datamodel_forms.html (canonical form docs)
- https://github.com/vertexproject/synapse/tree/master/synapse/models (model source; v2.256.0)
- https://synapse.docs.vertex.link/en/latest/synapse/userguides/model_updates.html (model changelogs; e.g. v2.154.0 added `risk:alert:host`, v2.232.0 added `meta:rule -(generated)>`)
- https://synapse.docs.vertex.link/projects/rapid-powerups/en/latest/storm-packages/synapse-microsoft-defender/userguide.html (EDR alert/incident precedent)
- https://synapse.docs.vertex.link/projects/rapid-powerups/en/latest/storm-packages/synapse-crowdstrike/userguide.html (tags/provenance precedent)
- https://synapse.docs.vertex.link/projects/rapid-powerups/en/latest/storm-packages/synapse-mitre-attack/userguide.html
- https://synapse.docs.vertex.link/projects/rapid-powerups/en/latest/ (full power-up catalog — confirms no sentinelone/carbonblack/velociraptor packages)
- https://synapse.docs.vertex.link/en/stable/synapse/userguides/analytical_model.html (tag conventions: `rep.*`, `cno.*`)
- https://synapse.docs.vertex.link/en/latest/synapse/autodocs/stormtypes_libs.html (`$lib.guid`, `$lib.gen.*`)
- Local ground truth: `/home/user/vraptor-research/model.json` (runtime `getModelDict()` dump of synapse 2.256.0)

---

## Generated form reference (synapse v2.256.0 runtime model dump)

Every table below was generated from a live `getModelDict()` of synapse==2.256.0 (same content as https://synapse.docs.vertex.link/en/latest/synapse/autodocs/datamodel_forms.html). Properties marked **[deprecated]** are scheduled for removal — do not use them in new code.


### Hosts, Devices, Identity & Accounts


#### `it:host`

- **Type:** base/guid — **implements interface(s):** `inet:service:object`, `phys:object`
- **Doc:** A GUID that represents a host or system.

| property | type | doc |
|---|---|---|
| `:name` | `it:hostname` | The name of the host or system.  |
| `:desc` | `str` | A free-form description of the host.  |
| `:domain` | `it:domain` | The authentication domain that the host is a member of.  |
| `:ipv4` | `inet:ipv4` | The last known ipv4 address for the host.  |
| `:latlong` | `geo:latlong` | The last known location for the host.  |
| `:place` | `geo:place` | The place where the host resides.  |
| `:loc` | `loc` | The geo-political location string for the node.  |
| `:os` | `it:prod:softver` | The operating system of the host.  |
| `:os:name` | `it:prod:softname` | A software product name for the host operating system. Used for entity resolution.  |
| `:hardware` | `it:prod:hardware` | The hardware specification for this host.  |
| `:manu` | `str` | Please use :hardware::manufacturer:name. **[deprecated]** |
| `:model` | `str` | Please use :hardware::model. **[deprecated]** |
| `:serial` | `str` | The serial number of the host.  |
| `:operator` | `ps:contact` | The operator of the host.  |
| `:org` | `ou:org` | The org that operates the given host.  |
| `:ext:id` | `str` | An external identifier for the host.  |
| `:keyboard:layout` | `str` {"lower": true, "onespace": true} | The primary keyboard layout configured on the host.  |
| `:keyboard:language` | `lang:language` | The primary keyboard input language configured on the host.  |
| `:image` | `it:software:image` | The container image or OS image running on the host.  |
| `:url` | `inet:url` | The primary URL associated with the host.  |
| `:status` | `inet:service:object:status` | The status of the host.  |
| `:period` | `ival` | The period when the host existed.  |
| `:creator` | `inet:service:account` | The service account which created the host.  |
| `:remover` | `inet:service:account` | The service account which removed or decommissioned the host.  |
| `:app` | `inet:service:app` | Deprecated. Objects are no longer scoped to an application or agent. **[deprecated]** |
| `:id` | `str` {"strip": true} | A platform specific ID which identifies the host.  |
| `:platform` | `inet:service:platform` | The platform which defines the host.  |
| `:instance` | `inet:service:instance` | Deprecated. Please use :platform. **[deprecated]** |
| `:phys:mass` | `mass` | The mass of the physical host.  |
| `:phys:volume` | `geo:dist` | The cubed volume of the physical host.  |
| `:phys:length` | `geo:dist` | The length of the physical host.  |
| `:phys:width` | `geo:dist` | The width of the physical host.  |
| `:phys:height` | `geo:dist` | The height of the physical host.  |


#### `it:hostname`

- **Type:** base/str
- **Doc:** The name of a host or system.

| property | type | doc |
|---|---|---|


#### `it:host:tenancy`

- **Type:** base/guid — **implements interface(s):** `inet:service:object`
- **Doc:** A time window where a host was a tenant run by another host.

| property | type | doc |
|---|---|---|
| `:lessor` | `it:host` | The host which provides runtime resources to the tenant host.  |
| `:tenant` | `it:host` | The host which is run within the resources provided by the lessor.  |
| `:url` | `inet:url` | The primary URL associated with the host tenancy.  |
| `:status` | `inet:service:object:status` | The status of the host tenancy.  |
| `:period` | `ival` | The period when the host tenancy existed.  |
| `:creator` | `inet:service:account` | The service account which created the host tenancy.  |
| `:remover` | `inet:service:account` | The service account which removed or decommissioned the host tenancy.  |
| `:app` | `inet:service:app` | Deprecated. Objects are no longer scoped to an application or agent. **[deprecated]** |
| `:id` | `str` {"strip": true} | A platform specific ID which identifies the host tenancy.  |
| `:platform` | `inet:service:platform` | The platform which defines the host tenancy.  |
| `:instance` | `inet:service:instance` | Deprecated. Please use :platform. **[deprecated]** |


#### `it:hostsoft`

- **Type:** base/comp
- **Doc:** A version of a software product which is present on a given host.
- **Comp fields (primary value):** `host`=`it:host`, `softver`=`it:prod:softver`

| property | type | doc |
|---|---|---|
| `:host` | `it:host` | Host with the software. _(read-only)_ |
| `:softver` | `it:prod:softver` | Software on the host. _(read-only)_ |


#### `it:hosturl`

- **Type:** base/comp
- **Doc:** A url hosted on or served by a host or system.
- **Comp fields (primary value):** `host`=`it:host`, `url`=`inet:url`

| property | type | doc |
|---|---|---|
| `:host` | `it:host` | Host serving a url. _(read-only)_ |
| `:url` | `inet:url` | URL available on the host. _(read-only)_ |


#### `it:adid`

- **Type:** base/str
- **Doc:** An advertising identification string.

| property | type | doc |
|---|---|---|


#### `it:network`

- **Type:** base/guid
- **Doc:** A GUID that represents a logical network.

| property | type | doc |
|---|---|---|
| `:name` | `str` {"lower": true, "onespace": true} | The name of the network.  |
| `:desc` | `str` | A brief description of the network.  |
| `:type` | `it:network:type:taxonomy` | The type of network.  |
| `:org` | `ou:org` | The org that owns/operates the network.  |
| `:net4` | `inet:net4` | The optional contiguous IPv4 address range of this network.  |
| `:net6` | `inet:net6` | The optional contiguous IPv6 address range of this network.  |
| `:dns:resolvers` | `array` {"type": "inet:server", "typeopts": {"defport": 53, "defproto": "udp"}, "sorted": true, "uniq": true} | An array of DNS servers configured to resolve requests for hosts on the network.  |


#### `it:domain`

- **Type:** base/guid
- **Doc:** A logical boundary of authentication and configuration such as a windows domain.

| property | type | doc |
|---|---|---|
| `:name` | `str` {"lower": true, "onespace": true} | The name of the domain.  |
| `:desc` | `str` | A brief description of the domain.  |
| `:org` | `ou:org` | The org that operates the given domain.  |


#### `it:account`

- **Type:** base/guid
- **Doc:** A GUID that represents an account on a host or network.

| property | type | doc |
|---|---|---|
| `:user` | `inet:user` | The username associated with the account.  |
| `:contact` | `ps:contact` | Additional contact information associated with this account.  |
| `:host` | `it:host` | The host where the account is registered.  |
| `:domain` | `it:domain` | The authentication domain where the account is registered.  |
| `:posix:uid` | `int` | The user ID of the account.  |
| `:posix:gid` | `int` | The primary group ID of the account.  |
| `:posix:gecos` | `int` | The GECOS field for the POSIX account.  |
| `:posix:home` | `file:path` | The path to the POSIX account's home directory.  |
| `:posix:shell` | `file:path` | The path to the POSIX account's default shell.  |
| `:windows:sid` | `it:os:windows:sid` | The Microsoft Windows Security Identifier of the account.  |
| `:groups` | `array` {"type": "it:group", "uniq": true, "sorted": true} | An array of groups that the account is a member of.  |


#### `it:group`

- **Type:** base/guid
- **Doc:** A GUID that represents a group on a host or network.

| property | type | doc |
|---|---|---|
| `:name` | `str` {"lower": true, "onespace": true} | The name of the group.  |
| `:desc` | `str` | A brief description of the group.  |
| `:host` | `it:host` | The host where the group is registered.  |
| `:domain` | `it:domain` | The authentication domain where the group is registered.  |
| `:groups` | `array` {"type": "it:group", "uniq": true, "sorted": true} | Groups that are a member of this group.  |
| `:posix:gid` | `int` | The primary group ID of the account.  |
| `:windows:sid` | `it:os:windows:sid` | The Microsoft Windows Security Identifier of the group.  |


#### `it:logon`

- **Type:** base/guid
- **Doc:** A GUID that represents an individual logon/logoff event.

| property | type | doc |
|---|---|---|
| `:time` | `time` | The time the logon occurred.  |
| `:success` | `bool` | Set to false to indicate an unsuccessful logon attempt.  |
| `:logoff:time` | `time` | The time the logon session ended.  |
| `:host` | `it:host` | The host that the account logged in to.  |
| `:account` | `it:account` | The account that logged in.  |
| `:creds` | `auth:creds` | The credentials that were used for the logon.  |
| `:duration` | `duration` | The duration of the logon session.  |
| `:client:host` | `it:host` | The host where the logon originated.  |
| `:client:ipv4` | `inet:ipv4` | The IPv4 where the logon originated.  |
| `:client:ipv6` | `inet:ipv6` | The IPv6 where the logon originated.  |


#### `auth:creds`

- **Type:** base/guid
- **Doc:** A unique set of credentials used to access a resource.

| property | type | doc |
|---|---|---|
| `:email` | `inet:email` | The email address used to identify the user.  |
| `:user` | `inet:user` | The user name used to identify the user.  |
| `:phone` | `tel:phone` | The phone number used to identify the user.  |
| `:passwd` | `inet:passwd` | The password used to authenticate.  |
| `:passwdhash` | `it:auth:passwdhash` | The password hash used to authenticate.  |
| `:account` | `it:account` | The account that the creds allow access to.  |
| `:website` | `inet:url` | The base URL of the website that the credentials allow access to.  |
| `:host` | `it:host` | The host that the credentials allow access to.  |
| `:wifi:ssid` | `inet:wifi:ssid` | The WiFi SSID that the credentials allow access to.  |
| `:web:acct` | `inet:web:acct` | Deprecated. Use :service:account. **[deprecated]** |
| `:service:account` | `inet:service:account` | The service account that the credentials allow access to.  |


#### `auth:access`

- **Type:** base/guid
- **Doc:** An instance of using creds to access a resource.

| property | type | doc |
|---|---|---|
| `:creds` | `auth:creds` | The credentials used to attempt access.  |
| `:time` | `time` | The time of the access attempt.  |
| `:success` | `bool` | Set to true if the access was successful.  |
| `:person` | `ps:person` | The person who attempted access.  |


#### `ps:contact`

- **Type:** base/guid
- **Doc:** A GUID for a contact info record.

| property | type | doc |
|---|---|---|
| `:org` | `ou:org` | The org which this contact represents.  |
| `:type` | `ps:contact:type:taxonomy` | The type of contact which may be used for entity resolution.  |
| `:asof` | `time` |   |
| `:person` | `ps:person` | The ps:person GUID which owns this contact.  |
| `:vitals` | `ps:vitals` | The most recent known vitals for the contact.  |
| `:name` | `ps:name` | The person name listed for the contact.  |
| `:bio` | `str` | A brief bio provided for the contact.  |
| `:desc` | `str` | A description of this contact.  |
| `:title` | `ou:jobtitle` | The job/org title listed for this contact.  |
| `:titles` | `array` {"type": "ou:jobtitle", "sorted": true, "uniq": true} | An array of alternate titles for the contact.  |
| `:photo` | `file:bytes` | The photo listed for this contact.  |
| `:orgname` | `ou:name` | The listed org/company name for this contact.  |
| `:orgfqdn` | `inet:fqdn` | The listed org/company FQDN for this contact.  |
| `:user` | `inet:user` | The username or handle for this contact.  |
| `:service:accounts` | `array` {"type": "inet:service:account", "sorted": true, "uniq": true} | The service accounts associated with this contact.  |
| `:web:acct` | `inet:web:acct` | Deprecated. Use :service:accounts. **[deprecated]** |
| `:web:group` | `inet:web:group` | Deprecated. Use inet:service:group:profile to link to a group. **[deprecated]** |
| `:birth:place` | `geo:place` | A fully resolved place of birth for this contact.  |
| `:birth:place:loc` | `loc` | The loc of the place of birth of this contact.  |
| `:birth:place:name` | `geo:name` | The name of the place of birth of this contact.  |
| `:death:place` | `geo:place` | A fully resolved place of death for this contact.  |
| `:death:place:loc` | `loc` | The loc of the place of death of this contact.  |
| `:death:place:name` | `geo:name` | The name of the place of death of this contact.  |
| `:dob` | `time` | The date of birth for this contact.  |
| `:dod` | `time` | The date of death for this contact.  |
| `:url` | `inet:url` | The home or main site for this contact.  |
| `:email` | `inet:email` | The main email address for this contact.  |
| `:email:work` | `inet:email` | The work email address for this contact.  |
| `:loc` | `loc` | Best known contact geopolitical location.  |
| `:address` | `geo:address` | The street address listed for the contact.  |
| `:place` | `geo:place` | The place associated with this contact.  |
| `:place:name` | `geo:name` | The reported name of the place associated with this contact.  |
| `:phone` | `tel:phone` | The main phone number for this contact.  |
| `:phone:fax` | `tel:phone` | The fax number for this contact.  |
| `:phone:work` | `tel:phone` | The work phone number for this contact.  |
| `:phones` | `array` {"type": "tel:phone", "uniq": true, "sorted": true} | An array of secondary/associated phone numbers.  |
| `:id` | `str` {"strip": true} | A type or source specific unique ID for the contact.  |
| `:id:number` | `ou:id:number` | An ID number issued by an org and associated with this contact.  |
| `:adid` | `it:adid` | A Advertising ID associated with this contact.  |
| `:imid` | `tel:mob:imid` | An IMID associated with the contact.  |
| `:imid:imei` | `tel:mob:imei` | An IMEI associated with the contact.  |
| `:imid:imsi` | `tel:mob:imsi` | An IMSI associated with the contact.  |
| `:names` | `array` {"type": "ps:name", "uniq": true, "sorted": true} | An array of associated names/aliases for the person.  |
| `:orgnames` | `array` {"type": "ou:name", "uniq": true, "sorted": true} | An array of associated names/aliases for the organization.  |
| `:emails` | `array` {"type": "inet:email", "uniq": true, "sorted": true} | An array of secondary/associated email addresses.  |
| `:web:accts` | `array` {"type": "inet:web:acct", "uniq": true, "sorted": true} | Deprecated. Use :service:accounts. **[deprecated]** |
| `:id:numbers` | `array` {"type": "ou:id:number", "uniq": true, "sorted": true} | An array of secondary/associated IDs.  |
| `:users` | `array` {"type": "inet:user", "uniq": true, "sorted": true} | An array of secondary/associated user names.  |
| `:crypto:address` | `crypto:currency:address` | A crypto currency address associated with the contact.  |
| `:lang` | `lang:language` | The language specified for the contact.  |
| `:langs` | `array` {"type": "lang:language"} | An array of alternative languages specified for the contact.  |
| `:banner` | `file:bytes` | The file representing the banner for the contact.  |
| `:passwd` | `inet:passwd` | The current password for the contact.  |
| `:website` | `inet:url` | A related URL specified by the contact (e.g., a personal or company web page, blog, etc.).  |
| `:websites` | `array` {"type": "inet:url", "uniq": true, "sorted": true} | Alternative related URLs specified by the contact.  |


#### `inet:ipv4`

- **Type:** base
- **Doc:** An IPv4 address.

| property | type | doc |
|---|---|---|
| `:asn` | `inet:asn` | The ASN to which the IPv4 address is currently assigned.  |
| `:latlong` | `geo:latlong` | The best known latitude/longitude for the node.  |
| `:loc` | `loc` | The geo-political location string for the IPv4.  |
| `:place` | `geo:place` | The geo:place associated with the latlong property.  |
| `:type` | `str` | The type of IP address (e.g., private, multicast, etc.).  |
| `:dns:rev` | `inet:fqdn` | The most current DNS reverse lookup for the IPv4.  |


#### `inet:ipv6`

- **Type:** base
- **Doc:** An IPv6 address.

| property | type | doc |
|---|---|---|
| `:asn` | `inet:asn` | The ASN to which the IPv6 address is currently assigned.  |
| `:ipv4` | `inet:ipv4` | The mapped ipv4.  |
| `:latlong` | `geo:latlong` | The last known latitude/longitude for the node.  |
| `:place` | `geo:place` | The geo:place associated with the latlong property.  |
| `:dns:rev` | `inet:fqdn` | The most current DNS reverse lookup for the IPv6.  |
| `:loc` | `loc` | The geo-political location string for the IPv6.  |
| `:type` | `str` | The type of IP address (e.g., private, multicast, etc.).  |
| `:scope` | `str` {"enums": "reserved,interface-local,link-local,realm-local,admin-local,site-local,organization-local,global,unassigned"} | The IPv6 scope of the address (e.g., global, link-local, etc.).  |


#### `inet:mac`

- **Type:** base/str
- **Doc:** A 48-bit Media Access Control (MAC) address.

| property | type | doc |
|---|---|---|
| `:vendor` | `str` | The vendor associated with the 24-bit prefix of a MAC address.  |


#### `inet:fqdn`

- **Type:** base
- **Doc:** A Fully Qualified Domain Name (FQDN).

| property | type | doc |
|---|---|---|
| `:domain` | `inet:fqdn` | The parent domain for the FQDN. _(read-only)_ |
| `:host` | `str` {"lower": true} | The host part of the FQDN. _(read-only)_ |
| `:issuffix` | `bool` | True if the FQDN is considered a suffix.  |
| `:iszone` | `bool` | True if the FQDN is considered a zone.  |
| `:zone` | `inet:fqdn` | The zone level parent for this FQDN.  |


#### `it:prod:hardware`

- **Type:** base/guid
- **Doc:** A specification for a piece of IT hardware.

| property | type | doc |
|---|---|---|
| `:name` | `str` {"lower": true, "onespace": true} | The display name for this hardware specification.  |
| `:type` | `it:prod:hardwaretype` | The type of hardware.  |
| `:desc` | `str` | A brief description of the hardware.  |
| `:cpe` | `it:sec:cpe` | The NIST CPE 2.3 string specifying this hardware.  |
| `:manufacturer` | `ou:org` | The organization that manufactures this hardware.  |
| `:manufacturer:name` | `ou:name` | The name of the organization that manufactures this hardware.  |
| `:make` | `ou:name` | Deprecated. Please use :manufacturer:name. **[deprecated]** |
| `:model` | `str` {"lower": true, "onespace": true} | The model name or number for this hardware specification.  |
| `:version` | `str` {"lower": true, "onespace": true} | Version string associated with this hardware specification.  |
| `:released` | `time` | The initial release date for this hardware.  |
| `:parts` | `array` {"type": "it:prod:hardware", "uniq": true, "sorted": true} | An array of it:prod:hardware parts included in this hardware specification.  |


#### `it:storage:volume`

- **Type:** base/guid
- **Doc:** A physical or logical storage volume that can be attached to a physical/virtual machine or container.

| property | type | doc |
|---|---|---|
| `:id` | `str` {"strip": true} | The unique volume ID.  |
| `:name` | `str` {"lower": true, "onespace": true} | The name of the volume.  |
| `:type` | `it:storage:volume:type:taxonomy` | The type of storage volume.  |
| `:size` | `int` {"min": 0} | The size of the volume in bytes.  |


#### `it:storage:mount`

- **Type:** base/guid
- **Doc:** A storage volume that has been attached to an image.

| property | type | doc |
|---|---|---|
| `:host` | `it:host` | The host that has mounted the volume.  |
| `:volume` | `it:storage:volume` | The volume that the host has mounted.  |
| `:path` | `file:path` | The path where the volume is mounted in the host filesystem.  |


### Software / Product (tool + agent modeling)


#### `it:prod:soft`

- **Type:** base/guid
- **Doc:** A software product.

| property | type | doc |
|---|---|---|
| `:id` | `str` {"strip": true} | An ID for the software.  |
| `:tag` | `syn:tag` | The tag used to annotate nodes that are associated with the software.  |
| `:name` | `it:prod:softname` | Name of the software.  |
| `:type` | `it:prod:soft:taxonomy` | The software type.  |
| `:names` | `array` {"type": "it:prod:softname", "uniq": true, "sorted": true} | Observed/variant names for this software.  |
| `:desc` | `str` | A description of the software.  |
| `:desc:short` | `str` {"lower": true} | A short description of the software.  |
| `:cpe` | `it:sec:cpe` | The NIST CPE 2.3 string specifying this software.  |
| `:author` | `ps:contact` | The contact information of the org or person who authored the software.  |
| `:author:org` | `ou:org` | Deprecated. Please use :author to link to a ps:contact. **[deprecated]** |
| `:author:acct` | `inet:web:acct` | Deprecated. Please use :author to link to a ps:contact. **[deprecated]** |
| `:author:email` | `inet:email` | Deprecated. Please use :author to link to a ps:contact. **[deprecated]** |
| `:author:person` | `ps:person` | Deprecated. Please use :author to link to a ps:contact. **[deprecated]** |
| `:url` | `inet:url` | URL relevant for the software.  |
| `:isos` | `bool` | Set to True if the software is an operating system.  |
| `:islib` | `bool` | Set to True if the software is a library.  |
| `:techniques` | `array` {"type": "ou:technique", "sorted": true, "uniq": true} | Deprecated for scalability. Please use -(uses)> ou:technique. **[deprecated]** |


#### `it:prod:softname`

- **Type:** base/str
- **Doc:** A software product name.

| property | type | doc |
|---|---|---|


#### `it:prod:softver`

- **Type:** base/guid
- **Doc:** A specific version of a software product.

| property | type | doc |
|---|---|---|
| `:software` | `it:prod:soft` | Software associated with this version instance.  |
| `:software:name` | `str` {"lower": true, "strip": true} | Deprecated. Please use it:prod:softver:name. **[deprecated]** |
| `:name` | `it:prod:softname` | Name of the software version.  |
| `:names` | `array` {"type": "it:prod:softname", "uniq": true, "sorted": true} | Observed/variant names for this software version.  |
| `:desc` | `str` | A description of the software.  |
| `:cpe` | `it:sec:cpe` | The NIST CPE 2.3 string specifying this software version.  |
| `:cves` | `array` {"type": "it:sec:cve", "uniq": true, "sorted": true} | A list of CVEs that apply to this software version.  |
| `:vers` | `it:dev:str` | Version string associated with this version instance.  |
| `:vers:norm` | `str` {"lower": true} | Normalized version of the version string.  |
| `:arch` | `it:dev:str` | Software architecture.  |
| `:released` | `time` | Timestamp for when this version of the software was released.  |
| `:semver` | `it:semver` | System normalized semantic version number.  |
| `:semver:major` | `int` | Deprecated. Please use semver range queries. **[deprecated]** |
| `:semver:minor` | `int` | Deprecated. Please use semver range queries. **[deprecated]** |
| `:semver:patch` | `int` | Deprecated. Please use semver range queries. **[deprecated]** |
| `:semver:pre` | `str` | Deprecated. **[deprecated]** |
| `:semver:build` | `str` | Deprecated. **[deprecated]** |
| `:url` | `inet:url` | URL where a specific version of the software is available from.  |


#### `it:prod:softid`

- **Type:** base/guid
- **Doc:** An identifier issued to a given host by a specific software application.

| property | type | doc |
|---|---|---|
| `:id` | `str` | The ID issued by the software to the host.  |
| `:host` | `it:host` | The host which was issued the ID by the software.  |
| `:soft` | `it:prod:softver` | The software which issued the ID to the host.  |
| `:soft:name` | `it:prod:softname` | The name of the software which issued the ID to the host.  |


#### `it:prod:softfile`

- **Type:** base/comp
- **Doc:** A file is distributed by a specific software version.
- **Comp fields (primary value):** `soft`=`it:prod:softver`, `file`=`file:bytes`

| property | type | doc |
|---|---|---|
| `:soft` | `it:prod:softver` | The software which distributes the file. _(read-only)_ |
| `:file` | `file:bytes` | The file distributed by the software. _(read-only)_ |
| `:path` | `file:path` | The default installation path of the file.  |


#### `it:prod:softos`

- **Type:** base/comp
- **Doc:** The software version is known to be compatible with the given os software version.
- **Comp fields (primary value):** `soft`=`it:prod:softver`, `os`=`it:prod:softver`

| property | type | doc |
|---|---|---|
| `:soft` | `it:prod:softver` | The software which can run on the operating system. _(read-only)_ |
| `:os` | `it:prod:softver` | The operating system which the software can run on. _(read-only)_ |


#### `it:prod:softreg`

- **Type:** base/comp
- **Doc:** A registry entry is created by a specific software version.
- **Comp fields (primary value):** `softver`=`it:prod:softver`, `regval`=`it:dev:regval`

| property | type | doc |
|---|---|---|
| `:softver` | `it:prod:softver` | The software which creates the registry entry. _(read-only)_ |
| `:regval` | `it:dev:regval` | The registry entry created by the software. _(read-only)_ |


#### `it:software:image`

- **Type:** base/guid — **implements interface(s):** `inet:service:object`
- **Doc:** The base image used to create a container or OS.

| property | type | doc |
|---|---|---|
| `:name` | `str` {"lower": true, "onespace": true} | The name of the image.  |
| `:type` | `it:software:image:type:taxonomy` | The type of software image.  |
| `:published` | `time` | The time the image was published.  |
| `:publisher` | `ps:contact` | The contact information of the org or person who published the image.  |
| `:parents` | `array` {"type": "it:software:image"} | An array of parent images in precedence order.  |
| `:url` | `inet:url` | The primary URL associated with the software image.  |
| `:status` | `inet:service:object:status` | The status of the software image.  |
| `:period` | `ival` | The period when the software image existed.  |
| `:creator` | `inet:service:account` | The service account which created the software image.  |
| `:remover` | `inet:service:account` | The service account which removed or decommissioned the software image.  |
| `:app` | `inet:service:app` | Deprecated. Objects are no longer scoped to an application or agent. **[deprecated]** |
| `:id` | `str` {"strip": true} | A platform specific ID which identifies the software image.  |
| `:platform` | `inet:service:platform` | The platform which defines the software image.  |
| `:instance` | `inet:service:instance` | Deprecated. Please use :platform. **[deprecated]** |


### Process Execution & Host Activity


#### `it:exec:proc`

- **Type:** base/guid — **implements interface(s):** `it:host:activity`
- **Doc:** A process executing on a host. May be an actual (e.g., endpoint) or virtual (e.g., malware sandbox) host.

| property | type | doc |
|---|---|---|
| `:host` | `it:host` | The host that executed the process. May be an actual or a virtual / notional host.  |
| `:exe` | `file:bytes` | The file considered the "main" executable for the process. For example, rundll32.exe may be considered the "main" executable for DLLs loaded by that program.  |
| `:cmd` | `it:cmd` | The command string used to launch the process, including any command line parameters.  |
| `:cmd:history` | `it:cmd:history` | The command history entry which caused this process to be run.  |
| `:pid` | `int` | The process ID.  |
| `:time` | `time` | The start time for the process.  |
| `:name` | `str` | The display name specified by the process.  |
| `:exited` | `time` | The time the process exited.  |
| `:exitcode` | `int` | The exit code for the process.  |
| `:user` | `inet:user` | The user name of the process owner. **[deprecated]** |
| `:account` | `it:account` | The account of the process owner.  |
| `:path` | `file:path` | The path to the executable of the process.  |
| `:path:base` | `file:base` | The file basename of the executable of the process.  |
| `:src:exe` | `file:path` | Deprecated. Create :src:proc and set :path. **[deprecated]** |
| `:src:proc` | `it:exec:proc` | The process which created the process.  |
| `:killedby` | `it:exec:proc` | The process which killed this process.  |
| `:sandbox:file` | `file:bytes` | The initial sample given to a sandbox environment to analyze.  |
| `:windows:service` | `it:os:windows:service` | The Microsoft Windows service responsible for starting the process.  |
| `:proc` | `it:exec:proc` | The host process which caused the activity.  |
| `:thread` | `it:exec:thread` | The host thread which caused the activity.  |


#### `it:exec:thread`

- **Type:** base/guid — **implements interface(s):** `it:host:activity`
- **Doc:** A thread executing in a process.

| property | type | doc |
|---|---|---|
| `:proc` | `it:exec:proc` | The process which contains the thread.  |
| `:created` | `time` | The time the thread was created.  |
| `:exited` | `time` | The time the thread exited.  |
| `:exitcode` | `int` | The exit code or return value for the thread.  |
| `:src:proc` | `it:exec:proc` | An external process which created the thread.  |
| `:src:thread` | `it:exec:thread` | The thread which created this thread.  |
| `:sandbox:file` | `file:bytes` | The initial sample given to a sandbox environment to analyze.  |
| `:exe` | `file:bytes` | The executable file which caused the activity.  |
| `:thread` | `it:exec:thread` | The host thread which caused the activity.  |
| `:host` | `it:host` | The host on which the activity occurred.  |
| `:time` | `time` | The time that the activity started.  |


#### `it:exec:loadlib`

- **Type:** base/guid — **implements interface(s):** `it:host:activity`
- **Doc:** A library load event in a process.

| property | type | doc |
|---|---|---|
| `:proc` | `it:exec:proc` | The process where the library was loaded.  |
| `:va` | `int` | The base memory address where the library was loaded in the process.  |
| `:loaded` | `time` | The time the library was loaded.  |
| `:unloaded` | `time` | The time the library was unloaded.  |
| `:path` | `file:path` | The path that the library was loaded from.  |
| `:file` | `file:bytes` | The library file that was loaded.  |
| `:sandbox:file` | `file:bytes` | The initial sample given to a sandbox environment to analyze.  |
| `:exe` | `file:bytes` | The executable file which caused the activity.  |
| `:thread` | `it:exec:thread` | The host thread which caused the activity.  |
| `:host` | `it:host` | The host on which the activity occurred.  |
| `:time` | `time` | The time that the activity started.  |


#### `it:exec:mmap`

- **Type:** base/guid — **implements interface(s):** `it:host:activity`
- **Doc:** A memory mapped segment located in a process.

| property | type | doc |
|---|---|---|
| `:proc` | `it:exec:proc` | The process where the memory was mapped.  |
| `:va` | `int` | The base memory address where the map was created in the process.  |
| `:size` | `int` | The size of the memory map in bytes.  |
| `:perms:read` | `bool` | True if the mmap is mapped with read permissions.  |
| `:perms:write` | `bool` | True if the mmap is mapped with write permissions.  |
| `:perms:execute` | `bool` | True if the mmap is mapped with execute permissions.  |
| `:created` | `time` | The time the memory map was created.  |
| `:deleted` | `time` | The time the memory map was deleted.  |
| `:path` | `file:path` | The file path if the mmap is a mapped view of a file.  |
| `:hash:sha256` | `hash:sha256` | A SHA256 hash of the memory map. Bytes may optionally be present in the axon.  |
| `:sandbox:file` | `file:bytes` | The initial sample given to a sandbox environment to analyze.  |
| `:exe` | `file:bytes` | The executable file which caused the activity.  |
| `:thread` | `it:exec:thread` | The host thread which caused the activity.  |
| `:host` | `it:host` | The host on which the activity occurred.  |
| `:time` | `time` | The time that the activity started.  |


#### `it:exec:mutex`

- **Type:** base/guid — **implements interface(s):** `it:host:activity`
- **Doc:** A mutex created by a process at runtime.

| property | type | doc |
|---|---|---|
| `:proc` | `it:exec:proc` | The main process executing code that created the mutex.  |
| `:host` | `it:host` | The host running the process that created the mutex. Typically the same host referenced in :proc, if present.  |
| `:exe` | `file:bytes` | The specific file containing code that created the mutex. May or may not be the same :exe specified in :proc, if present.  |
| `:time` | `time` | The time the mutex was created.  |
| `:name` | `it:dev:mutex` | The mutex string.  |
| `:sandbox:file` | `file:bytes` | The initial sample given to a sandbox environment to analyze.  |
| `:thread` | `it:exec:thread` | The host thread which caused the activity.  |


#### `it:exec:pipe`

- **Type:** base/guid — **implements interface(s):** `it:host:activity`
- **Doc:** A named pipe created by a process at runtime.

| property | type | doc |
|---|---|---|
| `:proc` | `it:exec:proc` | The main process executing code that created the named pipe.  |
| `:host` | `it:host` | The host running the process that created the named pipe. Typically the same host referenced in :proc, if present.  |
| `:exe` | `file:bytes` | The specific file containing code that created the named pipe. May or may not be the same :exe specified in :proc, if present.  |
| `:time` | `time` | The time the named pipe was created.  |
| `:name` | `it:dev:pipe` | The named pipe string.  |
| `:sandbox:file` | `file:bytes` | The initial sample given to a sandbox environment to analyze.  |
| `:thread` | `it:exec:thread` | The host thread which caused the activity.  |


#### `it:exec:bind`

- **Type:** base/guid — **implements interface(s):** `it:host:activity`
- **Doc:** An instance of a host binding a listening port.

| property | type | doc |
|---|---|---|
| `:proc` | `it:exec:proc` | The main process executing code that bound the listening port.  |
| `:host` | `it:host` | The host running the process that bound the listening port. Typically the same host referenced in :proc, if present.  |
| `:exe` | `file:bytes` | The specific file containing code that bound the listening port. May or may not be the same :exe specified in :proc, if present.  |
| `:time` | `time` | The time the port was bound.  |
| `:server` | `inet:server` | The inet:addr of the server when binding the port.  |
| `:server:ipv4` | `inet:ipv4` | The IPv4 address specified to bind().  |
| `:server:ipv6` | `inet:ipv6` | The IPv6 address specified to bind().  |
| `:server:port` | `inet:port` | The bound (listening) TCP port.  |
| `:sandbox:file` | `file:bytes` | The initial sample given to a sandbox environment to analyze.  |
| `:thread` | `it:exec:thread` | The host thread which caused the activity.  |


#### `it:exec:url`

- **Type:** base/guid — **implements interface(s):** `it:host:activity`
- **Doc:** An instance of a host requesting a URL using any protocol scheme.

| property | type | doc |
|---|---|---|
| `:proc` | `it:exec:proc` | The main process executing code that requested the URL.  |
| `:browser` | `it:prod:softver` | The software version of the browser.  |
| `:host` | `it:host` | The host running the process that requested the URL. Typically the same host referenced in :proc, if present.  |
| `:exe` | `file:bytes` | The specific file containing code that requested the URL. May or may not be the same :exe specified in :proc, if present.  |
| `:time` | `time` | The time the URL was requested.  |
| `:url` | `inet:url` | The URL that was requested.  |
| `:page:pdf` | `file:bytes` | The rendered DOM saved as a PDF file.  |
| `:page:html` | `file:bytes` | The rendered DOM saved as an HTML file.  |
| `:page:image` | `file:bytes` | The rendered DOM saved as an image.  |
| `:page:title` | `it:dev:str` | The title of the rendered page.  |
| `:page:favicon` | `file:bytes` | The favicon of the rendered page.  |
| `:page:components` | `array` {"type": "it:prod:softname", "uniq": true, "sorted": true} | The software components included in the rendered page.  |
| `:http:request` | `inet:http:request` | The HTTP request made to retrieve the initial URL contents.  |
| `:client` | `inet:client` | The address of the client during the URL retrieval.  |
| `:client:ipv4` | `inet:ipv4` | The IPv4 of the client during the URL retrieval.  |
| `:client:ipv6` | `inet:ipv6` | The IPv6 of the client during the URL retrieval.  |
| `:client:port` | `inet:port` | The client port during the URL retrieval.  |
| `:sandbox:file` | `file:bytes` | The initial sample given to a sandbox environment to analyze.  |
| `:thread` | `it:exec:thread` | The host thread which caused the activity.  |


#### `it:exec:query`

- **Type:** base/guid — **implements interface(s):** `it:host:activity`
- **Doc:** An instance of an executed query.

| property | type | doc |
|---|---|---|
| `:text` | `it:query` | The query string that was executed.  |
| `:opts` | `data` | An opaque JSON object containing query parameters and options.  |
| `:api:url` | `inet:url` | The URL of the API endpoint the query was sent to.  |
| `:language` | `str` {"lower": true, "onespace": true} | The name of the language that the query is expressed in.  |
| `:offset` | `int` | The offset of the last record consumed from the query.  |
| `:synuser` | `syn:user` | The synapse user who executed the query.  |
| `:service:platform` | `inet:service:platform` | The service platform which was queried.  |
| `:service:instance` | `inet:service:instance` | Deprecated. Please use :service:platform. **[deprecated]** |
| `:service:account` | `inet:service:account` | The service account which ran the query.  |
| `:exe` | `file:bytes` | The executable file which caused the activity.  |
| `:proc` | `it:exec:proc` | The host process which caused the activity.  |
| `:thread` | `it:exec:thread` | The host thread which caused the activity.  |
| `:host` | `it:host` | The host on which the activity occurred.  |
| `:time` | `time` | The time that the activity started.  |
| `:sandbox:file` | `file:bytes` | The initial sample given to a sandbox environment to analyze.  |


#### `it:query`

- **Type:** base/str
- **Doc:** A unique query string.

| property | type | doc |
|---|---|---|


#### `it:cmd`

- **Type:** base/str
- **Doc:** A unique command-line string.

| property | type | doc |
|---|---|---|


#### `it:cmd:session`

- **Type:** base/guid
- **Doc:** A command line session with multiple commands run over time.

| property | type | doc |
|---|---|---|
| `:host` | `it:host` | The host where the command line session was executed.  |
| `:proc` | `it:exec:proc` | The process which was interpreting this command line session.  |
| `:period` | `ival` | The period over which the command line session was running.  |
| `:file` | `file:bytes` | The file containing the command history such as a .bash_history file.  |


#### `it:cmd:history`

- **Type:** base/guid
- **Doc:** A single command executed within a session.

| property | type | doc |
|---|---|---|
| `:cmd` | `it:cmd` | The command that was executed.  |
| `:session` | `it:cmd:session` | The session that contains this history entry.  |
| `:time` | `time` | The time that the command was executed.  |
| `:index` | `int` | Used to order the commands when times are not available.  |
| `:output` | `str` | The output of the command.  |


### File System & File Activity


#### `file:bytes`

- **Type:** base
- **Doc:** The file bytes type with SHA256 based primary property.

| property | type | doc |
|---|---|---|
| `:size` | `int` | The file size in bytes.  |
| `:md5` | `hash:md5` | The md5 hash of the file.  |
| `:sha1` | `hash:sha1` | The sha1 hash of the file.  |
| `:sha256` | `hash:sha256` | The sha256 hash of the file.  |
| `:sha512` | `hash:sha512` | The sha512 hash of the file.  |
| `:ssdeeps` | `array` {"type": "hash:ssdeep", "uniq": true, "sorted": true} | The ssdeep fuzzy hashes of the file.  |
| `:name` | `file:base` | The best known base name for the file.  |
| `:mime` | `file:mime` | The "best" mime type name for the file.  |
| `:mime:x509:cn` | `str` | The Common Name (CN) attribute of the x509 Subject.  |
| `:mime:pe:size` | `int` | The size of the executable file according to the PE file header.  |
| `:mime:pe:imphash` | `hash:md5` | The PE import hash of the file as calculated by pefile; https://github.com/erocarrera/pefile .  |
| `:mime:pe:compiled` | `time` | The compile time of the file according to the PE header.  |
| `:mime:pe:pdbpath` | `file:path` | The PDB string according to the PE.  |
| `:mime:pe:exports:time` | `time` | The export time of the file according to the PE.  |
| `:mime:pe:exports:libname` | `str` | The export library name according to the PE.  |
| `:mime:pe:richhdr` | `hash:sha256` | The sha256 hash of the rich header bytes.  |
| `:exe:compiler` | `it:prod:softver` | The software used to compile the file.  |
| `:exe:packer` | `it:prod:softver` | The packer software used to encode the file.  |


#### `file:path`

- **Type:** base
- **Doc:** A normalized file path.

| property | type | doc |
|---|---|---|
| `:dir` | `file:path` | The parent directory. _(read-only)_ |
| `:base` | `file:base` | The file base name. _(read-only)_ |
| `:base:ext` | `str` | The file extension. _(read-only)_ |


#### `file:base`

- **Type:** base
- **Doc:** A file name with no path.

| property | type | doc |
|---|---|---|
| `:ext` | `str` | The file extension (if any). _(read-only)_ |


#### `file:filepath`

- **Type:** base/comp
- **Doc:** The fused knowledge of the association of a file:bytes node and a file:path.
- **Comp fields (primary value):** `file`=`file:bytes`, `path`=`file:path`

| property | type | doc |
|---|---|---|
| `:file` | `file:bytes` | The file seen at a path. _(read-only)_ |
| `:path` | `file:path` | The path a file was seen at. _(read-only)_ |
| `:path:dir` | `file:path` | The parent directory. _(read-only)_ |
| `:path:base` | `file:base` | The name of the file. _(read-only)_ |
| `:path:base:ext` | `str` | The extension of the file name. _(read-only)_ |


#### `file:subfile`

- **Type:** base/comp
- **Doc:** A parent file that fully contains the specified child file.
- **Comp fields (primary value):** `parent`=`file:bytes`, `child`=`file:bytes`

| property | type | doc |
|---|---|---|
| `:parent` | `file:bytes` | The parent file containing the child file. _(read-only)_ |
| `:child` | `file:bytes` | The child file contained in the parent file. _(read-only)_ |
| `:name` | `file:base` | Deprecated, please use the :path property. **[deprecated]** |
| `:path` | `file:path` | The path that the parent uses to refer to the child file.  |


#### `file:attachment`

- **Type:** base/guid
- **Doc:** A file attachment.

| property | type | doc |
|---|---|---|
| `:name` | `file:path` | The name of the attached file.  |
| `:text` | `str` | Any text associated with the file such as alt-text for images.  |
| `:file` | `file:bytes` | The file which was attached.  |


#### `file:mime`

- **Type:** base/str
- **Doc:** A file mime name string.

| property | type | doc |
|---|---|---|


#### `file:ismime`

- **Type:** base/comp
- **Doc:** Records one, of potentially multiple, mime types for a given file.
- **Comp fields (primary value):** `file`=`file:bytes`, `mime`=`file:mime`

| property | type | doc |
|---|---|---|
| `:file` | `file:bytes` | The file node that is an instance of the named mime type. _(read-only)_ |
| `:mime` | `file:mime` | The mime type of the file. _(read-only)_ |


#### `file:mime:lnk`

- **Type:** base/guid
- **Doc:** The GUID of the metadata pulled from a Windows shortcut or LNK file.

| property | type | doc |
|---|---|---|
| `:flags` | `int` | The flags specified by the LNK header that control the structure of the LNK file.  |
| `:entry:primary` | `file:path` | The primary file path contained within the FileEntry structure of the LNK file.  |
| `:entry:secondary` | `file:path` | The secondary file path contained within the FileEntry structure of the LNK file.  |
| `:entry:extended` | `file:path` | The extended file path contained within the extended FileEntry structure of the LNK file.  |
| `:entry:localized` | `file:path` | The localized file path reconstructed from references within the extended FileEntry structure of the LNK file.  |
| `:entry:icon` | `file:path` | The icon file path contained within the StringData structure of the LNK file.  |
| `:environment:path` | `file:path` | The target file path contained within the EnvironmentVariableDataBlock structure of the LNK file.  |
| `:environment:icon` | `file:path` | The icon file path contained within the IconEnvironmentDataBlock structure of the LNK file.  |
| `:iconindex` | `int` | A resource index for an icon within an icon location.  |
| `:working` | `file:path` | The working directory used when activating the link target.  |
| `:relative` | `str` {"strip": true} | The relative target path string contained within the StringData structure of the LNK file.  |
| `:arguments` | `it:cmd` | The command line arguments passed to the target file when the LNK file is activated.  |
| `:desc` | `str` | The description of the LNK file contained within the StringData section of the LNK file.  |
| `:target:attrs` | `int` | The attributes of the target file according to the LNK header.  |
| `:target:size` | `int` | The size of the target file according to the LNK header. The LNK format specifies that this is only the lower 32 bits of the target file size.  |
| `:target:created` | `time` | The creation time of the target file according to the LNK header.  |
| `:target:accessed` | `time` | The access time of the target file according to the LNK header.  |
| `:target:written` | `time` | The write time of the target file according to the LNK header.  |
| `:driveserial` | `int` | The drive serial number of the volume the link target is stored on.  |
| `:machineid` | `it:hostname` | The NetBIOS name of the machine where the link target was last located.  |


#### `file:mime:pe:section`

- **Type:** base/comp
- **Doc:** The fused knowledge a file:bytes node containing a pe section.
- **Comp fields (primary value):** `file`=`file:bytes`, `name`=`str`, `sha256`=`hash:sha256`

| property | type | doc |
|---|---|---|
| `:file` | `file:bytes` | The file containing the section. _(read-only)_ |
| `:name` | `str` | The textual name of the section. _(read-only)_ |
| `:sha256` | `hash:sha256` | The sha256 hash of the section. Relocations must be zeroed before hashing. _(read-only)_ |


#### `file:mime:pe:export`

- **Type:** base/comp
- **Doc:** The fused knowledge of a file:bytes node containing a pe named export.
- **Comp fields (primary value):** `file`=`file:bytes`, `name`=`str`

| property | type | doc |
|---|---|---|
| `:file` | `file:bytes` | The file containing the export. _(read-only)_ |
| `:name` | `str` | The name of the export in the file. _(read-only)_ |


#### `file:archive:entry`

- **Type:** base/guid
- **Doc:** An archive entry representing a file and metadata within a parent archive file.

| property | type | doc |
|---|---|---|
| `:parent` | `file:bytes` | The parent archive file.  |
| `:file` | `file:bytes` | The file contained within the archive.  |
| `:path` | `file:path` | The file path of the archived file.  |
| `:user` | `inet:user` | The name of the user who owns the archived file.  |
| `:added` | `time` | The time that the file was added to the archive.  |
| `:created` | `time` | The created time of the archived file.  |
| `:modified` | `time` | The modified time of the archived file.  |
| `:comment` | `str` | The comment field for the file entry within the archive.  |
| `:posix:uid` | `int` | The POSIX UID of the user who owns the archived file.  |
| `:posix:gid` | `int` | The POSIX GID of the group who owns the archived file.  |
| `:posix:perms` | `int` | The POSIX permissions mask of the archived file.  |
| `:archived:size` | `int` | The encoded or compressed size of the archived file within the parent.  |


#### `it:fs:file`

- **Type:** base/guid
- **Doc:** A file on a host.

| property | type | doc |
|---|---|---|
| `:host` | `it:host` | The host containing the file.  |
| `:path` | `file:path` | The path for the file.  |
| `:path:dir` | `file:path` | The parent directory of the file path (parsed from :path).  |
| `:path:ext` | `str` {"lower": true, "strip": true} | The file extension of the file name (parsed from :path).  |
| `:path:base` | `file:base` | The final component of the file path (parsed from :path).  |
| `:file` | `file:bytes` | The file on the host.  |
| `:ctime` | `time` | The file creation time.  |
| `:mtime` | `time` | The file modification time.  |
| `:atime` | `time` | The file access time.  |
| `:user` | `inet:user` | The owner of the file.  |
| `:group` | `inet:user` | The group owner of the file.  |


#### `it:exec:file:add`

- **Type:** base/guid — **implements interface(s):** `it:host:activity`
- **Doc:** An instance of a host adding a file to a filesystem.

| property | type | doc |
|---|---|---|
| `:proc` | `it:exec:proc` | The main process executing code that created the new file.  |
| `:host` | `it:host` | The host running the process that created the new file. Typically the same host referenced in :proc, if present.  |
| `:exe` | `file:bytes` | The specific file containing code that created the new file. May or may not be the same :exe specified in :proc, if present.  |
| `:time` | `time` | The time the file was created.  |
| `:path` | `file:path` | The path where the file was created.  |
| `:path:dir` | `file:path` | The parent directory of the file path (parsed from :path).  |
| `:path:ext` | `str` {"lower": true, "strip": true} | The file extension of the file name (parsed from :path).  |
| `:path:base` | `file:base` | The final component of the file path (parsed from :path).  |
| `:file` | `file:bytes` | The file that was created.  |
| `:sandbox:file` | `file:bytes` | The initial sample given to a sandbox environment to analyze.  |
| `:thread` | `it:exec:thread` | The host thread which caused the activity.  |


#### `it:exec:file:read`

- **Type:** base/guid — **implements interface(s):** `it:host:activity`
- **Doc:** An instance of a host reading a file from a filesystem.

| property | type | doc |
|---|---|---|
| `:proc` | `it:exec:proc` | The main process executing code that read the file.  |
| `:host` | `it:host` | The host running the process that read the file. Typically the same host referenced in :proc, if present.  |
| `:exe` | `file:bytes` | The specific file containing code that read the file. May or may not be the same :exe specified in :proc, if present.  |
| `:time` | `time` | The time the file was read.  |
| `:path` | `file:path` | The path where the file was read.  |
| `:path:dir` | `file:path` | The parent directory of the file path (parsed from :path).  |
| `:path:ext` | `str` {"lower": true, "strip": true} | The file extension of the file name (parsed from :path).  |
| `:path:base` | `file:base` | The final component of the file path (parsed from :path).  |
| `:file` | `file:bytes` | The file that was read.  |
| `:sandbox:file` | `file:bytes` | The initial sample given to a sandbox environment to analyze.  |
| `:thread` | `it:exec:thread` | The host thread which caused the activity.  |


#### `it:exec:file:write`

- **Type:** base/guid — **implements interface(s):** `it:host:activity`
- **Doc:** An instance of a host writing a file to a filesystem.

| property | type | doc |
|---|---|---|
| `:proc` | `it:exec:proc` | The main process executing code that wrote to / modified the existing file.  |
| `:host` | `it:host` | The host running the process that wrote to the file. Typically the same host referenced in :proc, if present.  |
| `:exe` | `file:bytes` | The specific file containing code that wrote to the file. May or may not be the same :exe specified in :proc, if present.  |
| `:time` | `time` | The time the file was written to/modified.  |
| `:path` | `file:path` | The path where the file was written to/modified.  |
| `:path:dir` | `file:path` | The parent directory of the file path (parsed from :path).  |
| `:path:ext` | `str` {"lower": true, "strip": true} | The file extension of the file name (parsed from :path).  |
| `:path:base` | `file:base` | The final component of the file path (parsed from :path).  |
| `:file` | `file:bytes` | The file that was modified.  |
| `:sandbox:file` | `file:bytes` | The initial sample given to a sandbox environment to analyze.  |
| `:thread` | `it:exec:thread` | The host thread which caused the activity.  |


#### `it:exec:file:del`

- **Type:** base/guid — **implements interface(s):** `it:host:activity`
- **Doc:** An instance of a host deleting a file from a filesystem.

| property | type | doc |
|---|---|---|
| `:proc` | `it:exec:proc` | The main process executing code that deleted the file.  |
| `:host` | `it:host` | The host running the process that deleted the file. Typically the same host referenced in :proc, if present.  |
| `:exe` | `file:bytes` | The specific file containing code that deleted the file. May or may not be the same :exe specified in :proc, if present.  |
| `:time` | `time` | The time the file was deleted.  |
| `:path` | `file:path` | The path where the file was deleted.  |
| `:path:dir` | `file:path` | The parent directory of the file path (parsed from :path).  |
| `:path:ext` | `str` {"lower": true, "strip": true} | The file extension of the file name (parsed from :path).  |
| `:path:base` | `file:base` | The final component of the file path (parsed from :path).  |
| `:file` | `file:bytes` | The file that was deleted.  |
| `:sandbox:file` | `file:bytes` | The initial sample given to a sandbox environment to analyze.  |
| `:thread` | `it:exec:thread` | The host thread which caused the activity.  |


### Registry


#### `it:dev:regkey`

- **Type:** base/str
- **Doc:** A Windows registry key.

| property | type | doc |
|---|---|---|


#### `it:dev:regval`

- **Type:** base/guid
- **Doc:** A Windows registry key/value pair.

| property | type | doc |
|---|---|---|
| `:key` | `it:dev:regkey` | The Windows registry key.  |
| `:str` | `it:dev:str` | The value of the registry key, if the value is a string.  |
| `:int` | `it:dev:int` | The value of the registry key, if the value is an integer.  |
| `:bytes` | `file:bytes` | The file representing the value of the registry key, if the value is binary data.  |


#### `it:exec:reg:get`

- **Type:** base/guid — **implements interface(s):** `it:host:activity`
- **Doc:** An instance of a host getting a registry key.

| property | type | doc |
|---|---|---|
| `:proc` | `it:exec:proc` | The main process executing code that read the registry.  |
| `:host` | `it:host` | The host running the process that read the registry. Typically the same host referenced in :proc, if present.  |
| `:exe` | `file:bytes` | The specific file containing code that read the registry. May or may not be the same :exe referenced in :proc, if present.  |
| `:time` | `time` | The time the registry was read.  |
| `:reg` | `it:dev:regval` | The registry key or value that was read.  |
| `:sandbox:file` | `file:bytes` | The initial sample given to a sandbox environment to analyze.  |
| `:thread` | `it:exec:thread` | The host thread which caused the activity.  |


#### `it:exec:reg:set`

- **Type:** base/guid — **implements interface(s):** `it:host:activity`
- **Doc:** An instance of a host creating or setting a registry key.

| property | type | doc |
|---|---|---|
| `:proc` | `it:exec:proc` | The main process executing code that wrote to the registry.  |
| `:host` | `it:host` | The host running the process that wrote to the registry. Typically the same host referenced in :proc, if present.  |
| `:exe` | `file:bytes` | The specific file containing code that wrote to the registry. May or may not be the same :exe referenced in :proc, if present.  |
| `:time` | `time` | The time the registry was written to.  |
| `:reg` | `it:dev:regval` | The registry key or value that was written to.  |
| `:sandbox:file` | `file:bytes` | The initial sample given to a sandbox environment to analyze.  |
| `:thread` | `it:exec:thread` | The host thread which caused the activity.  |


#### `it:exec:reg:del`

- **Type:** base/guid — **implements interface(s):** `it:host:activity`
- **Doc:** An instance of a host deleting a registry key.

| property | type | doc |
|---|---|---|
| `:proc` | `it:exec:proc` | The main process executing code that deleted data from the registry.  |
| `:host` | `it:host` | The host running the process that deleted data from the registry. Typically the same host referenced in :proc, if present.  |
| `:exe` | `file:bytes` | The specific file containing code that deleted data from the registry. May or may not be the same :exe referenced in :proc, if present.  |
| `:time` | `time` | The time the data from the registry was deleted.  |
| `:reg` | `it:dev:regval` | The registry key or value that was deleted.  |
| `:sandbox:file` | `file:bytes` | The initial sample given to a sandbox environment to analyze.  |
| `:thread` | `it:exec:thread` | The host thread which caused the activity.  |


### Windows / OS Specifics (services, tasks, cron)


#### `it:os:windows:service`

- **Type:** base/guid
- **Doc:** A Microsoft Windows service configuration on a host.

| property | type | doc |
|---|---|---|
| `:host` | `it:host` | The host that the service was configured on.  |
| `:name` | `str` {"lower": true, "onespace": true} | The name of the service from the registry key within Services.  |
| `:type` | `int` {"min": 0} | The type of service from the Type registry key.  |
| `:start` | `int` {"min": 0} | The start configuration of the service from the Start registry key.  |
| `:errorcontrol` | `int` {"min": 0} | The service error handling behavior from the ErrorControl registry key.  |
| `:displayname` | `str` {"lower": true, "onespace": true} | The friendly name of the service from the DisplayName registry key.  |
| `:description` | `str` | The description of the service from the Description registry key.  |
| `:imagepath` | `file:path` | The path to the service binary from the ImagePath registry key.  |


#### `it:os:windows:task`

- **Type:** base/guid
- **Doc:** A Windows Scheduled Task entry.

| property | type | doc |
|---|---|---|
| `:host` | `it:host` | The host on which the task was configured.  |
| `:cmds` | `array` {"type": "it:cmd", "sorted": false, "uniq": false} | A set of ordered commands executed by the task.  |
| `:account` | `it:account` | The account which the task runs as.  |
| `:period` | `ival` | The period when the task entry existed.  |
| `:desc` | `str` | The description of the task.  |
| `:uri` | `file:path` | The location of the task within the Windows Task Scheduler.  |
| `:path` | `file:path` | The path of the task metadata file.  |
| `:file` | `file:bytes` | The file containing the task metadata.  |


#### `it:os:posix:cron`

- **Type:** base/guid
- **Doc:** A cron job entry configured on a host.

| property | type | doc |
|---|---|---|
| `:host` | `it:host` | The host on which the cron job was configured.  |
| `:cmd` | `it:cmd` | The command which the cron job runs.  |
| `:schedule` | `it:dev:str` | The cron schedule string.  |
| `:account` | `it:account` | The account which the cron job runs as.  |
| `:period` | `ival` | The period when the cron job entry existed.  |
| `:desc` | `str` | A description of the cron job entry.  |
| `:path` | `file:path` | The path to the cron file which contained the job.  |
| `:file` | `file:bytes` | The cron file which contains the job definition.  |


### Event Logs & Generic Log Events


#### `it:log:event`

- **Type:** base/guid — **implements interface(s):** `it:host:activity`
- **Doc:** A GUID representing an individual log event.

| property | type | doc |
|---|---|---|
| `:mesg` | `str` | The log message text.  |
| `:type` | `it:log:event:type:taxonomy` | A taxonometric type for the log event.  |
| `:severity` | `int` {"enums": [[10, "debug"], [20, "info"], [30, "notice"], [40, "warning"], [50, "err"], [60, "crit"], [70, "alert"], [8... | A log level integer that increases with severity.  |
| `:data` | `data` | A raw JSON record of the log event.  |
| `:ext:id` | `str` | An external id that uniquely identifies this log entry.  |
| `:product` | `it:prod:softver` | The software which produced the log entry.  |
| `:service:platform` | `inet:service:platform` | The service platform which generated the log event.  |
| `:service:instance` | `inet:service:instance` | Deprecated. Please use :service:platform. **[deprecated]** |
| `:service:account` | `inet:service:account` | The service account which generated the log event.  |
| `:exe` | `file:bytes` | The executable file which caused the activity.  |
| `:proc` | `it:exec:proc` | The host process which caused the activity.  |
| `:thread` | `it:exec:thread` | The host thread which caused the activity.  |
| `:host` | `it:host` | The host on which the activity occurred.  |
| `:time` | `time` | The time that the activity started.  |
| `:sandbox:file` | `file:bytes` | The initial sample given to a sandbox environment to analyze.  |


#### `it:log:event:type:taxonomy`

- **Type:** base/taxonomy — **implements interface(s):** `meta:taxonomy`
- **Doc:** A taxonomy of log event types.

| property | type | doc |
|---|---|---|
| `:title` | `str` | A brief title of the definition.  |
| `:summary` | `str` | Deprecated. Please use title/desc. **[deprecated]** |
| `:desc` | `str` | A definition of the taxonomy entry.  |
| `:sort` | `int` | A display sort order for siblings.  |
| `:base` | `taxon` | The base taxon. _(read-only)_ |
| `:depth` | `int` | The depth indexed from 0. _(read-only)_ |
| `:parent` | `it:log:event:type:taxonomy` | The taxonomy parent. _(read-only)_ |


### Network Activity


#### `inet:flow`

- **Type:** base/guid
- **Doc:** An individual network connection between a given source and destination.

| property | type | doc |
|---|---|---|
| `:time` | `time` | The time the network connection was initiated.  |
| `:duration` | `int` | The duration of the flow in seconds.  |
| `:from` | `guid` | The ingest source file/iden. Used for reparsing.  |
| `:dst` | `inet:server` | The destination address / port for a connection.  |
| `:dst:ipv4` | `inet:ipv4` | The destination IPv4 address.  |
| `:dst:ipv6` | `inet:ipv6` | The destination IPv6 address.  |
| `:dst:port` | `inet:port` | The destination port.  |
| `:dst:proto` | `str` {"lower": true} | The destination protocol.  |
| `:dst:host` | `it:host` | The guid of the destination host.  |
| `:dst:proc` | `it:exec:proc` | The guid of the destination process.  |
| `:dst:exe` | `file:bytes` | The file (executable) that received the connection.  |
| `:dst:txfiles` | `array` {"type": "file:attachment", "sorted": true, "uniq": true} | An array of files sent by the destination host.  |
| `:dst:txcount` | `int` | The number of packets sent by the destination host.  |
| `:dst:txbytes` | `int` | The number of bytes sent by the destination host.  |
| `:dst:handshake` | `str` | A text representation of the initial handshake sent by the server.  |
| `:src` | `inet:client` | The source address / port for a connection.  |
| `:src:ipv4` | `inet:ipv4` | The source IPv4 address.  |
| `:src:ipv6` | `inet:ipv6` | The source IPv6 address.  |
| `:src:port` | `inet:port` | The source port.  |
| `:src:proto` | `str` {"lower": true} | The source protocol.  |
| `:src:host` | `it:host` | The guid of the source host.  |
| `:src:proc` | `it:exec:proc` | The guid of the source process.  |
| `:src:exe` | `file:bytes` | The file (executable) that created the connection.  |
| `:src:txfiles` | `array` {"type": "file:attachment", "sorted": true, "uniq": true} | An array of files sent by the source host.  |
| `:src:txcount` | `int` | The number of packets sent by the source host.  |
| `:src:txbytes` | `int` | The number of bytes sent by the source host.  |
| `:tot:txcount` | `int` | The number of packets sent in both directions.  |
| `:tot:txbytes` | `int` | The number of bytes sent in both directions.  |
| `:src:handshake` | `str` | A text representation of the initial handshake sent by the client.  |
| `:dst:cpes` | `array` {"type": "it:sec:cpe", "uniq": true, "sorted": true} | An array of NIST CPEs identified on the destination host.  |
| `:dst:softnames` | `array` {"type": "it:prod:softname", "uniq": true, "sorted": true} | An array of software names identified on the destination host.  |
| `:src:cpes` | `array` {"type": "it:sec:cpe", "uniq": true, "sorted": true} | An array of NIST CPEs identified on the source host.  |
| `:src:softnames` | `array` {"type": "it:prod:softname", "uniq": true, "sorted": true} | An array of software names identified on the source host.  |
| `:ip:proto` | `int` {"min": 0, "max": 255} | The IP protocol number of the flow.  |
| `:ip:tcp:flags` | `int` {"min": 0, "max": 255} | An aggregation of observed TCP flags commonly provided by flow APIs.  |
| `:sandbox:file` | `file:bytes` | The initial sample given to a sandbox environment to analyze.  |
| `:src:ssl:cert` | `crypto:x509:cert` | The x509 certificate sent by the client as part of an SSL/TLS negotiation.  |
| `:dst:ssl:cert` | `crypto:x509:cert` | The x509 certificate sent by the server as part of an SSL/TLS negotiation.  |
| `:src:rdp:hostname` | `it:hostname` | The hostname sent by the client as part of an RDP session setup.  |
| `:src:rdp:keyboard:layout` | `str` {"lower": true, "onespace": true} | The keyboard layout sent by the client as part of an RDP session setup.  |
| `:src:ssh:key` | `crypto:key` | The key sent by the client as part of an SSH session setup.  |
| `:dst:ssh:key` | `crypto:key` | The key sent by the server as part of an SSH session setup.  |
| `:capture:host` | `it:host` | The host which captured the flow.  |
| `:raw` | `data` | A raw record used to create the flow which may contain additional protocol details.  |


#### `inet:dns:request`

- **Type:** base/guid
- **Doc:** A single instance of a DNS resolver request and optional reply info.

| property | type | doc |
|---|---|---|
| `:time` | `time` |   |
| `:query` | `inet:dns:query` |   |
| `:query:name` | `inet:dns:name` |   |
| `:query:name:ipv4` | `inet:ipv4` |   |
| `:query:name:ipv6` | `inet:ipv6` |   |
| `:query:name:fqdn` | `inet:fqdn` |   |
| `:query:type` | `int` {"enums": [[1, "A"], [2, "NS"], [3, "MD"], [4, "MF"], [5, "CNAME"], [6, "SOA"], [7, "MB"], [8, "MG"], [9, "MR"], [10,... |   |
| `:server` | `inet:server` |   |
| `:reply:code` | `int` {"enums": [[0, "NOERROR"], [1, "FORMERR"], [2, "SERVFAIL"], [3, "NXDOMAIN"], [4, "NOTIMP"], [5, "REFUSED"], [6, "YXDO... | The DNS server response code.  |
| `:exe` | `file:bytes` | The file containing the code that attempted the DNS lookup.  |
| `:proc` | `it:exec:proc` | The process that attempted the DNS lookup.  |
| `:host` | `it:host` | The host that attempted the DNS lookup.  |
| `:sandbox:file` | `file:bytes` | The initial sample given to a sandbox environment to analyze.  |


#### `inet:dns:answer`

- **Type:** base/guid
- **Doc:** A single answer from within a DNS reply.

| property | type | doc |
|---|---|---|
| `:ttl` | `int` |   |
| `:request` | `inet:dns:request` |   |
| `:a` | `inet:dns:a` | The DNS A record returned by the lookup.  |
| `:ns` | `inet:dns:ns` | The DNS NS record returned by the lookup.  |
| `:rev` | `inet:dns:rev` | The DNS PTR record returned by the lookup.  |
| `:aaaa` | `inet:dns:aaaa` | The DNS AAAA record returned by the lookup.  |
| `:rev6` | `inet:dns:rev6` | The DNS PTR record returned by the lookup of an IPv6 address.  |
| `:cname` | `inet:dns:cname` | The DNS CNAME record returned by the lookup.  |
| `:mx` | `inet:dns:mx` | The DNS MX record returned by the lookup.  |
| `:mx:priority` | `int` | The DNS MX record priority.  |
| `:soa` | `inet:dns:soa` | The domain queried for its SOA record.  |
| `:txt` | `inet:dns:txt` | The DNS TXT record returned by the lookup.  |
| `:time` | `time` | The time that the DNS response was transmitted.  |


#### `inet:dns:query`

- **Type:** base/comp
- **Doc:** A DNS query unique to a given client.
- **Comp fields (primary value):** `client`=`inet:client`, `name`=`inet:dns:name`, `type`=`int`

| property | type | doc |
|---|---|---|
| `:client` | `inet:client` |  _(read-only)_ |
| `:name` | `inet:dns:name` |  _(read-only)_ |
| `:name:ipv4` | `inet:ipv4` |   |
| `:name:ipv6` | `inet:ipv6` |   |
| `:name:fqdn` | `inet:fqdn` |   |
| `:type` | `int` {"enums": [[1, "A"], [2, "NS"], [3, "MD"], [4, "MF"], [5, "CNAME"], [6, "SOA"], [7, "MB"], [8, "MG"], [9, "MR"], [10,... |  _(read-only)_ |


#### `inet:url`

- **Type:** base
- **Doc:** A Universal Resource Locator (URL).

| property | type | doc |
|---|---|---|
| `:fqdn` | `inet:fqdn` | The fqdn used in the URL (e.g., http://www.woot.com/page.html). _(read-only)_ |
| `:ipv4` | `inet:ipv4` | The IPv4 address used in the URL (e.g., http://1.2.3.4/page.html). _(read-only)_ |
| `:ipv6` | `inet:ipv6` | The IPv6 address used in the URL. _(read-only)_ |
| `:passwd` | `inet:passwd` | The optional password used to access the URL. _(read-only)_ |
| `:base` | `str` | The base scheme, user/pass, fqdn, port and path w/o parameters. _(read-only)_ |
| `:path` | `str` | The path in the URL w/o parameters. _(read-only)_ |
| `:params` | `str` | The URL parameter string. _(read-only)_ |
| `:port` | `inet:port` | The port of the URL. URLs prefixed with http will be set to port 80 and URLs prefixed with https will be set to port 443 unless otherwise specified. _(read-only)_ |
| `:proto` | `str` {"lower": true} | The protocol in the URL. _(read-only)_ |
| `:user` | `inet:user` | The optional username used to access the URL. _(read-only)_ |


#### `inet:http:request`

- **Type:** base/guid — **implements interface(s):** `inet:proto:request`
- **Doc:** A single HTTP request.

| property | type | doc |
|---|---|---|
| `:method` | `str` | The HTTP request method string.  |
| `:path` | `str` | The requested HTTP path (without query parameters).  |
| `:url` | `inet:url` | The reconstructed URL for the request if known.  |
| `:query` | `str` | The HTTP query string which optionally follows the path.  |
| `:headers` | `array` {"type": "inet:http:request:header"} | An array of HTTP headers from the request.  |
| `:header:host` | `inet:fqdn` | The FQDN parsed from the "Host:" header in the request.  |
| `:header:referer` | `inet:url` | The referer URL parsed from the "Referer:" header in the request.  |
| `:body` | `file:bytes` | The body of the HTTP request.  |
| `:referer` | `inet:url` | Deprecated. Please use :header:referer. **[deprecated]** |
| `:cookies` | `array` {"type": "inet:http:cookie", "sorted": true, "uniq": true} | An array of HTTP cookie values parsed from the "Cookies:" header in the request.  |
| `:response:time` | `time` |   |
| `:response:code` | `int` |   |
| `:response:reason` | `str` |   |
| `:response:headers` | `array` {"type": "inet:http:response:header"} | An array of HTTP headers from the response.  |
| `:response:body` | `file:bytes` |   |
| `:response:cookies` | `array` {"type": "inet:http:cookie", "sorted": true, "uniq": true} | An array of HTTP cookie values parsed from the "Set-Cookie:" headers in the response.  |
| `:session` | `inet:http:session` | The HTTP session this request was part of.  |
| `:fetch` | `it:exec:url` | The fetch or page load event which caused the HTTP request.  |
| `:flow` | `inet:flow` | The raw inet:flow containing the request.  |
| `:client` | `inet:client` | The inet:addr of the client.  |
| `:client:ipv4` | `inet:ipv4` | The server IPv4 address that the request was sent from.  |
| `:client:ipv6` | `inet:ipv6` | The server IPv6 address that the request was sent from.  |
| `:client:host` | `it:host` | The host that the request was sent from.  |
| `:server` | `inet:server` | The inet:addr of the server.  |
| `:server:ipv4` | `inet:ipv4` | The server IPv4 address that the request was sent to.  |
| `:server:ipv6` | `inet:ipv6` | The server IPv6 address that the request was sent to.  |
| `:server:port` | `inet:port` | The server port that the request was sent to.  |
| `:server:host` | `it:host` | The host that the request was sent to.  |
| `:exe` | `file:bytes` | The executable file which caused the activity.  |
| `:proc` | `it:exec:proc` | The host process which caused the activity.  |
| `:thread` | `it:exec:thread` | The host thread which caused the activity.  |
| `:host` | `it:host` | The host on which the activity occurred.  |
| `:time` | `time` | The time that the activity started.  |
| `:sandbox:file` | `file:bytes` | The initial sample given to a sandbox environment to analyze.  |


#### `inet:server`

- **Type:** base/inet:addr
- **Doc:** A network server address.

| property | type | doc |
|---|---|---|
| `:proto` | `str` {"lower": true} | The network protocol of the server. _(read-only)_ |
| `:ipv4` | `inet:ipv4` | The IPv4 of the server. _(read-only)_ |
| `:ipv6` | `inet:ipv6` | The IPv6 of the server. _(read-only)_ |
| `:host` | `it:host` | The it:host node for the server. _(read-only)_ |
| `:port` | `inet:port` | The server tcp/udp port. _(read-only)_ |


#### `inet:client`

- **Type:** base/inet:addr
- **Doc:** A network client address.

| property | type | doc |
|---|---|---|
| `:proto` | `str` {"lower": true} | The network protocol of the client. _(read-only)_ |
| `:ipv4` | `inet:ipv4` | The IPv4 of the client. _(read-only)_ |
| `:ipv6` | `inet:ipv6` | The IPv6 of the client. _(read-only)_ |
| `:host` | `it:host` | The it:host node for the client. _(read-only)_ |
| `:port` | `inet:port` | The client tcp/udp port. _(read-only)_ |


### Detections: YARA / Sigma / Snort / AV


#### `it:app:yara:rule`

- **Type:** base/guid
- **Doc:** A YARA rule unique identifier.

| property | type | doc |
|---|---|---|
| `:text` | `str` | The YARA rule text.  |
| `:ext:id` | `str` | The YARA rule ID from an external system.  |
| `:url` | `inet:url` | A URL which documents the YARA rule.  |
| `:name` | `str` | The name of the YARA rule.  |
| `:author` | `ps:contact` | Contact info for the author of the YARA rule.  |
| `:version` | `it:semver` | The current version of the rule.  |
| `:created` | `time` | The time the YARA rule was initially created.  |
| `:updated` | `time` | The time the YARA rule was most recently modified.  |
| `:enabled` | `bool` | The rule enabled status to be used for YARA evaluation engines.  |
| `:family` | `it:prod:softname` | The name of the software family the rule is designed to detect.  |


#### `it:app:yara:match`

- **Type:** base/comp
- **Doc:** A YARA rule match to a file.
- **Comp fields (primary value):** `rule`=`it:app:yara:rule`, `file`=`file:bytes`

| property | type | doc |
|---|---|---|
| `:rule` | `it:app:yara:rule` | The YARA rule that matched the file. _(read-only)_ |
| `:file` | `file:bytes` | The file that matched the YARA rule. _(read-only)_ |
| `:version` | `it:semver` | The most recent version of the rule evaluated as a match.  |


#### `it:app:yara:procmatch`

- **Type:** base/guid
- **Doc:** An instance of a YARA rule match to a process.

| property | type | doc |
|---|---|---|
| `:rule` | `it:app:yara:rule` | The YARA rule that matched the process.  |
| `:proc` | `it:exec:proc` | The process that matched the YARA rule.  |
| `:time` | `time` | The time that the YARA engine matched the process to the rule.  |
| `:version` | `it:semver` | The most recent version of the rule evaluated as a match.  |


#### `it:app:sigma:rule`

- **Type:** base/guid
- **Doc:** A Sigma rule.

| property | type | doc |
|---|---|---|
| `:id` | `str` | The Sigma rule id.  |
| `:text` | `str` | The Sigma rule text.  |
| `:name` | `str` | The name of the Sigma rule.  |
| `:desc` | `str` | A brief description of the Sigma rule.  |
| `:url` | `inet:url` | A URL which documents the Sigma rule.  |
| `:version` | `it:semver` | The current version of the rule.  |
| `:author` | `ps:contact` | Contact info for the author of the rule.  |
| `:created` | `time` | The time the rule was created.  |
| `:updated` | `time` | The time the rule was most recently modified.  |
| `:enabled` | `bool` | The rule enabled status to be used for Sigma evaluation engines.  |


#### `it:app:sigma:matched`

- **Type:** base/guid
- **Doc:** An instance of a Sigma rule hit.

| property | type | doc |
|---|---|---|
| `:rule` | `it:app:sigma:rule` | The Sigma rule that matched the log event.  |
| `:target` | `it:log:event` | The it:log:event that matched the Sigma rule.  |
| `:sensor` | `it:host` | The sensor host node that produced the hit.  |
| `:time` | `time` | The time that the match occurred.  |
| `:version` | `it:semver` | The version of the rule at the time of match.  |


#### `it:app:snort:rule`

- **Type:** base/guid
- **Doc:** A snort rule.

| property | type | doc |
|---|---|---|
| `:id` | `str` | The snort rule id.  |
| `:text` | `str` | The snort rule text.  |
| `:name` | `str` | The name of the snort rule.  |
| `:desc` | `str` | A brief description of the snort rule.  |
| `:engine` | `int` | The snort engine ID which can parse and evaluate the rule text.  |
| `:version` | `it:semver` | The current version of the rule.  |
| `:author` | `ps:contact` | Contact info for the author of the rule.  |
| `:created` | `time` | The time the rule was initially created.  |
| `:updated` | `time` | The time the rule was most recently modified.  |
| `:enabled` | `bool` | The rule enabled status to be used for snort evaluation engines.  |
| `:family` | `it:prod:softname` | The name of the software family the rule is designed to detect.  |


#### `it:app:snort:hit`

- **Type:** base/guid
- **Doc:** An instance of a snort rule hit.

| property | type | doc |
|---|---|---|
| `:rule` | `it:app:snort:rule` | The snort rule that matched the file.  |
| `:flow` | `inet:flow` | The inet:flow that matched the snort rule.  |
| `:src` | `inet:addr` | The source address of flow that caused the hit.  |
| `:src:ipv4` | `inet:ipv4` | The source IPv4 address of the flow that caused the hit.  |
| `:src:ipv6` | `inet:ipv6` | The source IPv6 address of the flow that caused the hit.  |
| `:src:port` | `inet:port` | The source port of the flow that caused the hit.  |
| `:dst` | `inet:addr` | The destination address of the trigger.  |
| `:dst:ipv4` | `inet:ipv4` | The destination IPv4 address of the flow that caused the hit.  |
| `:dst:ipv6` | `inet:ipv6` | The destination IPv4 address of the flow that caused the hit.  |
| `:dst:port` | `inet:port` | The destination port of the flow that caused the hit.  |
| `:time` | `time` | The time of the network flow that caused the hit.  |
| `:sensor` | `it:host` | The sensor host node that produced the hit.  |
| `:version` | `it:semver` | The version of the rule at the time of match.  |
| `:dropped` | `bool` | Set to true if the network traffic was dropped due to the match.  |


#### `it:av:sig` **[DEPRECATED FORM]**

- **Type:** base/comp
- **Doc:** Deprecated. Please use it:av:scan:result.
- **Comp fields (primary value):** `soft`=`it:prod:soft`, `name`=`it:av:signame`

| property | type | doc |
|---|---|---|
| `:soft` | `it:prod:soft` | The anti-virus product which contains the signature. _(read-only)_ |
| `:name` | `it:av:signame` | The signature name. _(read-only)_ |
| `:desc` | `str` | A free-form description of the signature.  |
| `:url` | `inet:url` | A reference URL for information about the signature.  |


#### `it:av:signame`

- **Type:** base/str
- **Doc:** An antivirus signature name.

| property | type | doc |
|---|---|---|


#### `it:av:scan:result`

- **Type:** base/guid
- **Doc:** The result of running an antivirus scanner.

| property | type | doc |
|---|---|---|
| `:time` | `time` | The time the scan was run.  |
| `:verdict` | `int` {"enums": [[10, "benign"], [20, "unknown"], [30, "suspicious"], [40, "malicious"]]} | The scanner provided verdict for the scan.  |
| `:scanner` | `it:prod:softver` | The scanner software used to produce the result.  |
| `:scanner:name` | `it:prod:softname` | The name of the scanner software.  |
| `:signame` | `it:av:signame` | The name of the signature returned by the scanner.  |
| `:categories` | `array` {"sorted": true, "uniq": true, "type": "str", "typeopts": {"lower": true, "onespace": true}} | A list of categories for the result returned by the scanner.  |
| `:target:file` | `file:bytes` | The file that was scanned to produce the result.  |
| `:target:proc` | `it:exec:proc` | The process that was scanned to produce the result.  |
| `:target:host` | `it:host` | The host that was scanned to produce the result.  |
| `:target:fqdn` | `inet:fqdn` | The FQDN that was scanned to produce the result.  |
| `:target:url` | `inet:url` | The URL that was scanned to produce the result.  |
| `:target:ipv4` | `inet:ipv4` | The IPv4 address that was scanned to produce the result.  |
| `:target:ipv6` | `inet:ipv6` | The IPv6 address that was scanned to produce the result.  |
| `:multi:scan` | `it:av:scan:result` | Set if this result was part of running multiple scanners.  |
| `:multi:count` | `int` {"min": 0} | The total number of scanners which were run by a multi-scanner.  |
| `:multi:count:benign` | `int` {"min": 0} | The number of scanners which returned a benign verdict.  |
| `:multi:count:unknown` | `int` {"min": 0} | The number of scanners which returned a unknown/unsupported verdict.  |
| `:multi:count:suspicious` | `int` {"min": 0} | The number of scanners which returned a suspicious verdict.  |
| `:multi:count:malicious` | `int` {"min": 0} | The number of scanners which returned a malicious verdict.  |


#### `it:av:filehit` **[DEPRECATED FORM]**

- **Type:** base/comp
- **Doc:** Deprecated. Please use it:av:scan:result.
- **Comp fields (primary value):** `file`=`file:bytes`, `sig`=`it:av:sig`

| property | type | doc |
|---|---|---|
| `:file` | `file:bytes` | The file that triggered the signature hit. _(read-only)_ |
| `:sig` | `it:av:sig` | The signature that the file triggered on. _(read-only)_ |
| `:sig:name` | `it:av:signame` | The signature name. _(read-only)_ |
| `:sig:soft` | `it:prod:soft` | The anti-virus product which contains the signature. _(read-only)_ |


#### `it:av:prochit` **[DEPRECATED FORM]**

- **Type:** base/guid
- **Doc:** Deprecated. Please use it:av:scan:result.

| property | type | doc |
|---|---|---|
| `:proc` | `it:exec:proc` | The file that triggered the signature hit.  |
| `:sig` | `it:av:sig` | The signature that the file triggered on.  |
| `:time` | `time` | The time that the AV engine detected the signature.  |


### Misc host artifacts


#### `it:dev:str`

- **Type:** base/str
- **Doc:** A developer selected string.

| property | type | doc |
|---|---|---|
| `:norm` | `str` {"lower": true} | Lower case normalized version of the it:dev:str.  |


#### `it:dev:int`

- **Type:** base/int
- **Doc:** A developer selected integer constant.

| property | type | doc |
|---|---|---|


#### `it:dev:pipe`

- **Type:** base/str
- **Doc:** A string representing a named pipe.

| property | type | doc |
|---|---|---|


#### `it:dev:mutex`

- **Type:** base/str
- **Doc:** A string representing a mutex.

| property | type | doc |
|---|---|---|


#### `it:screenshot`

- **Type:** base/guid — **implements interface(s):** `it:host:activity`
- **Doc:** A screenshot of a host.

| property | type | doc |
|---|---|---|
| `:image` | `file:bytes` | The image file.  |
| `:desc` | `str` | A brief description of the screenshot.  |
| `:exe` | `file:bytes` | The executable file which caused the activity.  |
| `:proc` | `it:exec:proc` | The host process which caused the activity.  |
| `:thread` | `it:exec:thread` | The host thread which caused the activity.  |
| `:host` | `it:host` | The host on which the activity occurred.  |
| `:time` | `time` | The time that the activity started.  |
| `:sandbox:file` | `file:bytes` | The initial sample given to a sandbox environment to analyze.  |


#### `it:sec:c2:config`

- **Type:** base/guid
- **Doc:** An extracted C2 config from an executable.

| property | type | doc |
|---|---|---|
| `:family` | `it:prod:softname` | The name of the software family which uses the config.  |
| `:file` | `file:bytes` | The file that the C2 config was extracted from.  |
| `:decoys` | `array` {"type": "inet:url"} | An array of URLs used as decoy connections to obfuscate the C2 servers.  |
| `:servers` | `array` {"type": "inet:url"} | An array of connection URLs built from host/port/passwd combinations.  |
| `:proxies` | `array` {"type": "inet:url"} | An array of proxy URLs used to communicate with the C2 server.  |
| `:listens` | `array` {"type": "inet:url"} | An array of listen URLs that the software should bind.  |
| `:dns:resolvers` | `array` {"type": "inet:server"} | An array of inet:servers to use when resolving DNS names.  |
| `:mutex` | `it:dev:mutex` | The mutex that the software uses to prevent multiple-installations.  |
| `:campaigncode` | `it:dev:str` | The operator selected string used to identify the campaign or group of targets.  |
| `:crypto:key` | `crypto:key` | Static key material used to encrypt C2 communications.  |
| `:connect:delay` | `duration` | The time delay from first execution to connecting to the C2 server.  |
| `:connect:interval` | `duration` | The configured duration to sleep between connections to the C2 server.  |
| `:raw` | `data` | A JSON blob containing the raw config extracted from the binary.  |
| `:http:headers` | `array` {"type": "inet:http:header"} | An array of HTTP headers that the sample should transmit to the C2 server.  |


### Risk: Alerts, Attacks, Compromises, Threats, Tools, Vulns


#### `risk:alert`

- **Type:** base/guid
- **Doc:** An instance of an alert which indicates the presence of a risk.

| property | type | doc |
|---|---|---|
| `:type` | `risk:alert:taxonomy` | A type for the alert, as a taxonomy entry.  |
| `:name` | `str` | A brief name for the alert.  |
| `:desc` | `str` | A free-form description / overview of the alert.  |
| `:status` | `int` {"enums": [[0, "new"], [10, "enrichment"], [20, "todo"], [30, "analysis"], [40, "remediation"], [50, "done"]]} | The status of the alert.  |
| `:benign` | `bool` | Set to true if the alert has been confirmed benign. Set to false if malicious.  |
| `:priority` | `meta:priority` | A priority rank for the alert.  |
| `:severity` | `meta:severity` | A severity rank for the alert.  |
| `:verdict` | `risk:alert:verdict:taxonomy` | A verdict about why the alert is malicious or benign, as a taxonomy entry.  |
| `:assignee` | `syn:user` | The Synapse user who is assigned to investigate the alert.  |
| `:ext:assignee` | `ps:contact` | The alert assignee contact information from an external system.  |
| `:engine` | `it:prod:softver` | The software that generated the alert.  |
| `:detected` | `time` | The time the alerted condition was detected.  |
| `:updated` | `time` | The time the alert was most recently modified.  |
| `:vuln` | `risk:vuln` | The optional vulnerability that the alert indicates.  |
| `:attack` | `risk:attack` | A confirmed attack that this alert indicates.  |
| `:url` | `inet:url` | A URL which documents the alert.  |
| `:ext:id` | `str` | An external identifier for the alert.  |
| `:host` | `it:host` | The host which generated the alert.  |
| `:service:platform` | `inet:service:platform` | The service platform which generated the alert.  |
| `:service:instance` | `inet:service:instance` | Deprecated. Please use :service:platform. **[deprecated]** |
| `:service:account` | `inet:service:account` | The service account which generated the alert.  |


#### `risk:alert:taxonomy`

- **Type:** base/taxonomy — **implements interface(s):** `meta:taxonomy`
- **Doc:** A taxonomy of alert types.

| property | type | doc |
|---|---|---|
| `:title` | `str` | A brief title of the definition.  |
| `:summary` | `str` | Deprecated. Please use title/desc. **[deprecated]** |
| `:desc` | `str` | A definition of the taxonomy entry.  |
| `:sort` | `int` | A display sort order for siblings.  |
| `:base` | `taxon` | The base taxon. _(read-only)_ |
| `:depth` | `int` | The depth indexed from 0. _(read-only)_ |
| `:parent` | `risk:alert:taxonomy` | The taxonomy parent. _(read-only)_ |


#### `risk:alert:verdict:taxonomy`

- **Type:** base/taxonomy — **implements interface(s):** `meta:taxonomy`
- **Doc:** A taxonomy of verdicts for the origin and validity of the alert.

| property | type | doc |
|---|---|---|
| `:title` | `str` | A brief title of the definition.  |
| `:summary` | `str` | Deprecated. Please use title/desc. **[deprecated]** |
| `:desc` | `str` | A definition of the taxonomy entry.  |
| `:sort` | `int` | A display sort order for siblings.  |
| `:base` | `taxon` | The base taxon. _(read-only)_ |
| `:depth` | `int` | The depth indexed from 0. _(read-only)_ |
| `:parent` | `risk:alert:verdict:taxonomy` | The taxonomy parent. _(read-only)_ |


#### `risk:attack`

- **Type:** base/guid
- **Doc:** An instance of an actor attacking a target.

| property | type | doc |
|---|---|---|
| `:desc` | `str` | A description of the attack.  |
| `:type` | `risk:attacktype` | A type for the attack, as a taxonomy entry.  |
| `:reporter` | `ou:org` | The organization reporting on the attack.  |
| `:reporter:name` | `ou:name` | The name of the organization reporting on the attack.  |
| `:time` | `time` | Set if the time of the attack is known.  |
| `:detected` | `time` | The first confirmed detection time of the attack.  |
| `:success` | `bool` | Set if the attack was known to have succeeded or not.  |
| `:targeted` | `bool` | Set if the attack was assessed to be targeted or not.  |
| `:goal` | `ou:goal` | The tactical goal of this specific attack.  |
| `:campaign` | `ou:campaign` | Set if the attack was part of a larger campaign.  |
| `:compromise` | `risk:compromise` | A compromise that this attack contributed to.  |
| `:severity` | `meta:severity` | A severity rank for the attack.  |
| `:sophistication` | `meta:sophistication` | The assessed sophistication of the attack.  |
| `:prev` | `risk:attack` | The previous/parent attack in a list or hierarchy.  |
| `:actor` | `entity:actor` | The actor which conducted the attack.  |
| `:actor:org` | `ou:org` | Deprecated. Please use :attacker to allow entity resolution. **[deprecated]** |
| `:actor:person` | `ps:person` | Deprecated. Please use :attacker to allow entity resolution. **[deprecated]** |
| `:attacker` | `ps:contact` | Contact information representing the attacker.  |
| `:target` | `ps:contact` | Deprecated. Please use -(targets)> light weight edges. **[deprecated]** |
| `:target:org` | `ou:org` | Deprecated. Please use -(targets)> light weight edges. **[deprecated]** |
| `:target:host` | `it:host` | Deprecated. Please use -(targets)> light weight edges. **[deprecated]** |
| `:target:person` | `ps:person` | Deprecated. Please use -(targets)> light weight edges. **[deprecated]** |
| `:target:place` | `geo:place` | Deprecated. Please use -(targets)> light weight edges. **[deprecated]** |
| `:via:ipv4` | `inet:ipv4` | Deprecated. Please use -(uses)> light weight edges. **[deprecated]** |
| `:via:ipv6` | `inet:ipv6` | Deprecated. Please use -(uses)> light weight edges. **[deprecated]** |
| `:via:email` | `inet:email` | Deprecated. Please use -(uses)> light weight edges. **[deprecated]** |
| `:via:phone` | `tel:phone` | Deprecated. Please use -(uses)> light weight edges. **[deprecated]** |
| `:used:vuln` | `risk:vuln` | Deprecated. Please use -(uses)> light weight edges. **[deprecated]** |
| `:used:url` | `inet:url` | Deprecated. Please use -(uses)> light weight edges. **[deprecated]** |
| `:used:host` | `it:host` | Deprecated. Please use -(uses)> light weight edges. **[deprecated]** |
| `:used:email` | `inet:email` | Deprecated. Please use -(uses)> light weight edges. **[deprecated]** |
| `:used:file` | `file:bytes` | Deprecated. Please use -(uses)> light weight edges. **[deprecated]** |
| `:used:server` | `inet:server` | Deprecated. Please use -(uses)> light weight edges. **[deprecated]** |
| `:used:software` | `it:prod:softver` | Deprecated. Please use -(uses)> light weight edges. **[deprecated]** |
| `:techniques` | `array` {"type": "ou:technique", "sorted": true, "uniq": true} | Deprecated for scalability. Please use -(uses)> ou:technique. **[deprecated]** |
| `:url` | `inet:url` | A URL which documents the attack.  |
| `:ext:id` | `str` | An external unique ID for the attack.  |


#### `risk:attacktype`

- **Type:** base/taxonomy — **implements interface(s):** `meta:taxonomy`
- **Doc:** A taxonomy of attack types.

| property | type | doc |
|---|---|---|
| `:title` | `str` | A brief title of the definition.  |
| `:summary` | `str` | Deprecated. Please use title/desc. **[deprecated]** |
| `:desc` | `str` | A definition of the taxonomy entry.  |
| `:sort` | `int` | A display sort order for siblings.  |
| `:base` | `taxon` | The base taxon. _(read-only)_ |
| `:depth` | `int` | The depth indexed from 0. _(read-only)_ |
| `:parent` | `risk:attacktype` | The taxonomy parent. _(read-only)_ |


#### `risk:compromise`

- **Type:** base/guid
- **Doc:** A compromise and its aggregate impact. The compromise is the result of a successful attack.

| property | type | doc |
|---|---|---|
| `:name` | `str` {"lower": true, "onespace": true} | A brief name for the compromise event.  |
| `:desc` | `str` | A prose description of the compromise event.  |
| `:reporter` | `ou:org` | The organization reporting on the compromise.  |
| `:reporter:name` | `ou:name` | The name of the organization reporting on the compromise.  |
| `:ext:id` | `str` | An external unique ID for the compromise.  |
| `:url` | `inet:url` | A URL which documents the compromise.  |
| `:type` | `risk:compromisetype` | A type for the compromise, as a taxonomy entry.  |
| `:vector` | `risk:attack` | The attack assessed to be the initial compromise vector.  |
| `:target` | `ps:contact` | Contact information representing the target.  |
| `:attacker` | `ps:contact` | Contact information representing the attacker.  |
| `:campaign` | `ou:campaign` | The campaign that this compromise is part of.  |
| `:time` | `time` | Earliest known evidence of compromise.  |
| `:lasttime` | `time` | Last known evidence of compromise.  |
| `:duration` | `duration` | The duration of the compromise.  |
| `:detected` | `time` | The first confirmed detection time of the compromise.  |
| `:loss:pii` | `int` | The number of records compromised which contain PII.  |
| `:loss:econ` | `econ:price` | The total economic cost of the compromise.  |
| `:loss:life` | `int` | The total loss of life due to the compromise.  |
| `:loss:bytes` | `int` | An estimate of the volume of data compromised.  |
| `:ransom:paid` | `econ:price` | The value of the ransom paid by the target.  |
| `:ransom:price` | `econ:price` | The value of the ransom demanded by the attacker.  |
| `:response:cost` | `econ:price` | The economic cost of the response and mitigation efforts.  |
| `:theft:price` | `econ:price` | The total value of the theft of assets.  |
| `:econ:currency` | `econ:currency` | The currency type for the econ:price fields.  |
| `:severity` | `meta:severity` | A severity rank for the compromise.  |
| `:goal` | `ou:goal` | The assessed primary goal of the attacker for the compromise.  |
| `:goals` | `array` {"type": "ou:goal", "sorted": true, "uniq": true} | An array of assessed attacker goals for the compromise.  |
| `:tag` | `syn:tag` | A tag used to associate nodes with the compromise.  |
| `:techniques` | `array` {"type": "ou:technique", "sorted": true, "uniq": true} | Deprecated for scalability. Please use -(uses)> ou:technique. **[deprecated]** |


#### `risk:compromisetype`

- **Type:** base/taxonomy — **implements interface(s):** `meta:taxonomy`
- **Doc:** A taxonomy of compromise types.

| property | type | doc |
|---|---|---|
| `:title` | `str` | A brief title of the definition.  |
| `:summary` | `str` | Deprecated. Please use title/desc. **[deprecated]** |
| `:desc` | `str` | A definition of the taxonomy entry.  |
| `:sort` | `int` | A display sort order for siblings.  |
| `:base` | `taxon` | The base taxon. _(read-only)_ |
| `:depth` | `int` | The depth indexed from 0. _(read-only)_ |
| `:parent` | `risk:compromisetype` | The taxonomy parent. _(read-only)_ |


#### `risk:threat`

- **Type:** base/guid
- **Doc:** A threat cluster or subgraph of threat activity, as reported by a specific organization.

| property | type | doc |
|---|---|---|
| `:name` | `str` {"lower": true, "onespace": true} | A brief descriptive name for the threat cluster.  |
| `:type` | `risk:threat:type:taxonomy` | A type for the threat, as a taxonomy entry.  |
| `:desc` | `str` | A description of the threat cluster.  |
| `:tag` | `syn:tag` | The tag used to annotate nodes that are associated with the threat cluster.  |
| `:active` | `ival` | An interval for when the threat cluster is assessed to have been active.  |
| `:activity` | `meta:activity` | The most recently assessed activity level of the threat cluster.  |
| `:reporter` | `ou:org` | The organization reporting on the threat cluster.  |
| `:reporter:name` | `ou:name` | The name of the organization reporting on the threat cluster.  |
| `:reporter:discovered` | `time` | The time that the reporting organization first discovered the threat cluster.  |
| `:reporter:published` | `time` | The time that the reporting organization first publicly disclosed the threat cluster.  |
| `:org` | `ou:org` | The authoritative organization for the threat cluster.  |
| `:org:loc` | `loc` | The reporting organization's assessed location of the threat cluster.  |
| `:org:name` | `ou:name` | The reporting organization's name for the threat cluster.  |
| `:org:names` | `array` {"type": "ou:name", "sorted": true, "uniq": true} | An array of alternate names for the threat cluster, according to the reporting organization.  |
| `:country` | `pol:country` | The reporting organization's assessed country of origin of the threat cluster.  |
| `:country:code` | `pol:iso2` | The 2 digit ISO 3166 country code for the threat cluster's assessed country of origin.  |
| `:goals` | `array` {"type": "ou:goal", "sorted": true, "uniq": true} | The reporting organization's assessed goals of the threat cluster.  |
| `:sophistication` | `meta:sophistication` | The reporting organization's assessed sophistication of the threat cluster.  |
| `:techniques` | `array` {"type": "ou:technique", "sorted": true, "uniq": true} | Deprecated for scalability. Please use -(uses)> ou:technique. **[deprecated]** |
| `:merged:time` | `time` | The time that the reporting organization merged this threat cluster into another.  |
| `:merged:isnow` | `risk:threat` | The threat cluster that the reporting organization merged this cluster into.  |
| `:mitre:attack:group` | `it:mitre:attack:group` | A mapping to a MITRE ATT&CK group if applicable.  |
| `:ext:id` | `str` {"strip": true} | An external identifier for the threat.  |
| `:ext:ids` | `array` {"type": "str", "uniq": true, "sorted": true, "typeopts": {"strip": true}} | An array of alternate external identifiers for the threat.  |


#### `risk:tool:software`

- **Type:** base/guid
- **Doc:** A software tool used in threat activity, as reported by a specific organization.

| property | type | doc |
|---|---|---|
| `:tag` | `syn:tag` | The tag used to annotate nodes that are associated with the tool.  |
| `:desc` | `str` | A description of the tool.  |
| `:type` | `risk:tool:software:taxonomy` | A type for the tool, as a taxonomy entry.  |
| `:used` | `ival` | An interval for when the tool is assessed to have been deployed.  |
| `:availability` | `risk:availability` | The reporting organization's assessed availability of the tool.  |
| `:sophistication` | `meta:sophistication` | The reporting organization's assessed sophistication of the tool.  |
| `:reporter` | `ou:org` | The organization reporting on the tool.  |
| `:reporter:name` | `ou:name` | The name of the organization reporting on the tool.  |
| `:reporter:discovered` | `time` | The time that the reporting organization first discovered the tool.  |
| `:reporter:published` | `time` | The time that the reporting organization first publicly disclosed the tool.  |
| `:soft` | `it:prod:soft` | The authoritative software family for the tool.  |
| `:soft:name` | `it:prod:softname` | The reporting organization's name for the tool.  |
| `:soft:names` | `array` {"type": "it:prod:softname", "uniq": true, "sorted": true} | An array of alternate names for the tool, according to the reporting organization.  |
| `:techniques` | `array` {"type": "ou:technique", "uniq": true, "sorted": true} | Deprecated for scalability. Please use -(uses)> ou:technique. **[deprecated]** |
| `:mitre:attack:software` | `it:mitre:attack:software` | A mapping to a MITRE ATT&CK software if applicable.  |
| `:id` | `str` {"strip": true} | An ID for the tool.  |


#### `risk:mitigation`

- **Type:** base/guid
- **Doc:** A mitigation for a specific risk:vuln.

| property | type | doc |
|---|---|---|
| `:vuln` | `risk:vuln` | The vulnerability that this mitigation addresses.  |
| `:name` | `str` {"lower": true, "onespace": true} | A brief name for this risk mitigation.  |
| `:names` | `array` {"type": "str", "sorted": true, "uniq": true, "typeopts": {"lower": true, "onespace": true}} | An array of alternate names for the mitigation.  |
| `:type` | `risk:mitigation:type:taxonomy` | A taxonomy type entry for the mitigation.  |
| `:id` | `str` {"strip": true} | An identifier for the mitigation.  |
| `:desc` | `str` | A description of the mitigation approach for the vulnerability.  |
| `:software` | `it:prod:softver` | Deprecated. Please use risk:mitigation -(uses)> it:prod:softver. **[deprecated]** |
| `:hardware` | `it:prod:hardware` | Deprecated. Please use risk:mitigation -(uses)> it:prod:hardware. **[deprecated]** |
| `:reporter` | `ou:org` | The organization reporting on the mitigation.  |
| `:reporter:name` | `ou:name` | The name of the organization reporting on the mitigation.  |
| `:mitre:attack:mitigation` | `it:mitre:attack:mitigation` | A mapping to a MITRE ATT&CK mitigation if applicable.  |
| `:tag` | `syn:tag` | The tag used to annotate nodes which have the mitigation in place.  |


#### `risk:vuln`

- **Type:** base/guid
- **Doc:** A unique vulnerability.

| property | type | doc |
|---|---|---|
| `:name` | `risk:vulnname` | A user specified name for the vulnerability.  |
| `:names` | `array` {"type": "risk:vulnname", "sorted": true, "uniq": true} | An array of alternate names for the vulnerability.  |
| `:type` | `risk:vuln:type:taxonomy` | A taxonomy type entry for the vulnerability.  |
| `:desc` | `str` | A description of the vulnerability.  |
| `:severity` | `meta:severity` | The severity of the vulnerability.  |
| `:priority` | `meta:priority` | The priority of the vulnerability.  |
| `:reporter` | `ou:org` | The organization reporting on the vulnerability.  |
| `:reporter:name` | `ou:name` | The name of the organization reporting on the vulnerability.  |
| `:reporter:url` | `inet:url` | The URL for the vulnerability provided by the reporter.  |
| `:mitigated` | `bool` | Set to true if a mitigation/fix is available for the vulnerability.  |
| `:exploited` | `bool` | Set to true if the vulnerability has been exploited in the wild.  |
| `:timeline:discovered` | `time` {"ismin": true} | The earliest known discovery time for the vulnerability.  |
| `:timeline:published` | `time` {"ismin": true} | The earliest known time the vulnerability was published.  |
| `:timeline:vendor:notified` | `time` {"ismin": true} | The earliest known vendor notification time for the vulnerability.  |
| `:timeline:vendor:fixed` | `time` {"ismin": true} | The earliest known time the vendor issued a fix for the vulnerability.  |
| `:timeline:exploited` | `time` {"ismin": true} | The earliest known time when the vulnerability was exploited in the wild.  |
| `:id` | `str` {"strip": true} | An identifier for the vulnerability.  |
| `:tag` | `syn:tag` | A tag used to annotate the presence or use of the vulnerability.  |
| `:cve` | `it:sec:cve` | The CVE ID of the vulnerability.  |
| `:cve:desc` | `str` | The description of the vulnerability according to the CVE database.  |
| `:cve:url` | `inet:url` | A URL linking this vulnerability to the CVE description.  |
| `:cve:references` | `array` {"type": "inet:url", "uniq": true, "sorted": true} | An array of documentation URLs provided by the CVE database.  |
| `:nist:nvd:source` | `ou:name` | Deprecated. Please use it:sec:cve:nist:nvd:source. **[deprecated]** |
| `:nist:nvd:published` | `time` | Deprecated. Please use it:sec:cve:nist:nvd:published. **[deprecated]** |
| `:nist:nvd:modified` | `time` {"ismax": true} | Deprecated. Please use it:sec:cve:nist:nvd:modified. **[deprecated]** |
| `:cisa:kev:name` | `str` | Deprecated. Please use it:sec:cve:cisa:kev:name. **[deprecated]** |
| `:cisa:kev:desc` | `str` | Deprecated. Please use it:sec:cve:cisa:kev:desc. **[deprecated]** |
| `:cisa:kev:action` | `str` | Deprecated. Please use it:sec:cve:cisa:kev:action. **[deprecated]** |
| `:cisa:kev:vendor` | `ou:name` | Deprecated. Please use it:sec:cve:cisa:kev:vendor. **[deprecated]** |
| `:cisa:kev:product` | `it:prod:softname` | Deprecated. Please use it:sec:cve:cisa:kev:product. **[deprecated]** |
| `:cisa:kev:added` | `time` | Deprecated. Please use it:sec:cve:cisa:kev:added. **[deprecated]** |
| `:cisa:kev:duedate` | `time` | Deprecated. Please use it:sec:cve:cisa:kev:duedate. **[deprecated]** |
| `:cvss:v2` | `cvss:v2` | The CVSS v2 vector for the vulnerability.  |
| `:cvss:v2_0:score` | `float` | The CVSS v2.0 overall score for the vulnerability.  |
| `:cvss:v2_0:score:base` | `float` | The CVSS v2.0 base score for the vulnerability.  |
| `:cvss:v2_0:score:temporal` | `float` | The CVSS v2.0 temporal score for the vulnerability.  |
| `:cvss:v2_0:score:environmental` | `float` | The CVSS v2.0 environmental score for the vulnerability.  |
| `:cvss:v3` | `cvss:v3` | The CVSS v3 vector for the vulnerability.  |
| `:cvss:v3_0:score` | `float` | The CVSS v3.0 overall score for the vulnerability.  |
| `:cvss:v3_0:score:base` | `float` | The CVSS v3.0 base score for the vulnerability.  |
| `:cvss:v3_0:score:temporal` | `float` | The CVSS v3.0 temporal score for the vulnerability.  |
| `:cvss:v3_0:score:environmental` | `float` | The CVSS v3.0 environmental score for the vulnerability.  |
| `:cvss:v3_1:score` | `float` | The CVSS v3.1 overall score for the vulnerability.  |
| `:cvss:v3_1:score:base` | `float` | The CVSS v3.1 base score for the vulnerability.  |
| `:cvss:v3_1:score:temporal` | `float` | The CVSS v3.1 temporal score for the vulnerability.  |
| `:cvss:v3_1:score:environmental` | `float` | The CVSS v3.1 environmental score for the vulnerability.  |
| `:cvss:av` | `str` {"enums": "N,A,P,L"} | Deprecated. Please use :cvss:v3. **[deprecated]** |
| `:cvss:ac` | `str` {"enums": "L,H"} | Deprecated. Please use :cvss:v3. **[deprecated]** |
| `:cvss:pr` | `str` {"enums": "N,L,H"} | Deprecated. Please use :cvss:v3. **[deprecated]** |
| `:cvss:ui` | `str` {"enums": "N,R"} | Deprecated. Please use :cvss:v3. **[deprecated]** |
| `:cvss:s` | `str` {"enums": "U,C"} | Deprecated. Please use :cvss:v3. **[deprecated]** |
| `:cvss:c` | `str` {"enums": "N,L,H"} | Deprecated. Please use :cvss:v3. **[deprecated]** |
| `:cvss:i` | `str` {"enums": "N,L,H"} | Deprecated. Please use :cvss:v3. **[deprecated]** |
| `:cvss:a` | `str` {"enums": "N,L,H"} | Deprecated. Please use :cvss:v3. **[deprecated]** |
| `:cvss:e` | `str` {"enums": "X,U,P,F,H"} | Deprecated. Please use :cvss:v3. **[deprecated]** |
| `:cvss:rl` | `str` {"enums": "X,O,T,W,U"} | Deprecated. Please use :cvss:v3. **[deprecated]** |
| `:cvss:rc` | `str` {"enums": "X,U,R,C"} | Deprecated. Please use :cvss:v3. **[deprecated]** |
| `:cvss:mav` | `str` {"enums": "X,N,A,L,P"} | Deprecated. Please use :cvss:v3. **[deprecated]** |
| `:cvss:mac` | `str` {"enums": "X,L,H"} | Deprecated. Please use :cvss:v3. **[deprecated]** |
| `:cvss:mpr` | `str` {"enums": "X,N,L,H"} | Deprecated. Please use :cvss:v3. **[deprecated]** |
| `:cvss:mui` | `str` {"enums": "X,N,R"} | Deprecated. Please use :cvss:v3. **[deprecated]** |
| `:cvss:ms` | `str` {"enums": "X,U,C"} | Deprecated. Please use :cvss:v3. **[deprecated]** |
| `:cvss:mc` | `str` {"enums": "X,N,L,H"} | Deprecated. Please use :cvss:v3. **[deprecated]** |
| `:cvss:mi` | `str` {"enums": "X,N,L,H"} | Deprecated. Please use :cvss:v3. **[deprecated]** |
| `:cvss:ma` | `str` {"enums": "X,N,L,H"} | Deprecated. Please use :cvss:v3. **[deprecated]** |
| `:cvss:cr` | `str` {"enums": "X,L,M,H"} | Deprecated. Please use :cvss:v3. **[deprecated]** |
| `:cvss:ir` | `str` {"enums": "X,L,M,H"} | Deprecated. Please use :cvss:v3. **[deprecated]** |
| `:cvss:ar` | `str` {"enums": "X,L,M,H"} | Deprecated. Please use :cvss:v3. **[deprecated]** |
| `:cvss:score` | `float` | Deprecated. Please use version specific score properties. **[deprecated]** |
| `:cvss:score:base` | `float` | Deprecated. Please use version specific score properties. **[deprecated]** |
| `:cvss:score:temporal` | `float` | Deprecated. Please use version specific score properties. **[deprecated]** |
| `:cvss:score:environmental` | `float` | Deprecated. Please use version specific score properties. **[deprecated]** |
| `:cwes` | `array` {"type": "it:sec:cwe", "uniq": true, "sorted": true} | An array of MITRE CWE values that apply to the vulnerability.  |


#### `risk:vulnerable`

- **Type:** base/guid
- **Doc:** Indicates that a node is susceptible to a vulnerability.

| property | type | doc |
|---|---|---|
| `:vuln` | `risk:vuln` | The vulnerability that the node is susceptible to.  |
| `:technique` | `ou:technique` | The technique that the node is susceptible to.  |
| `:period` | `ival` | The time window where the node was vulnerable.  |
| `:node` | `ndef` | The node which is vulnerable.  |
| `:mitigated` | `bool` | Set to true if the vulnerable node has been mitigated.  |
| `:mitigations` | `array` {"type": "risk:mitigation", "sorted": true, "uniq": true} | The mitigations which were used to address the vulnerable node.  |


#### `risk:hasvuln` **[DEPRECATED FORM]**

- **Type:** base/guid
- **Doc:** Deprecated. Please use risk:vulnerable.

| property | type | doc |
|---|---|---|
| `:vuln` | `risk:vuln` | The vulnerability present in the target.  |
| `:person` | `ps:person` | The vulnerable person.  |
| `:org` | `ou:org` | The vulnerable org.  |
| `:place` | `geo:place` | The vulnerable place.  |
| `:software` | `it:prod:softver` | The vulnerable software.  |
| `:hardware` | `it:prod:hardware` | The vulnerable hardware.  |
| `:spec` | `mat:spec` | The vulnerable material specification.  |
| `:item` | `mat:item` | The vulnerable material item.  |
| `:host` | `it:host` | The vulnerable host.  |


#### `it:sec:cve`

- **Type:** base/str
- **Doc:** A vulnerability as designated by a Common Vulnerabilities and Exposures (CVE) number.

| property | type | doc |
|---|---|---|
| `:desc` | `str` | Deprecated. Please use risk:vuln:cve:desc. **[deprecated]** |
| `:url` | `inet:url` | Deprecated. Please use risk:vuln:cve:url. **[deprecated]** |
| `:references` | `array` {"type": "inet:url", "uniq": true, "sorted": true} | Deprecated. Please use risk:vuln:cve:references. **[deprecated]** |
| `:nist:nvd:source` | `ou:name` | The name of the organization which reported the vulnerability to NIST.  |
| `:nist:nvd:published` | `time` | The date the vulnerability was first published in the NVD.  |
| `:nist:nvd:modified` | `time` {"ismax": true} | The date the vulnerability was last modified in the NVD.  |
| `:cisa:kev:name` | `str` | The name of the vulnerability according to the CISA KEV database.  |
| `:cisa:kev:desc` | `str` | The description of the vulnerability according to the CISA KEV database.  |
| `:cisa:kev:action` | `str` | The action to mitigate the vulnerability according to the CISA KEV database.  |
| `:cisa:kev:vendor` | `ou:name` | The vendor name listed in the CISA KEV database.  |
| `:cisa:kev:product` | `it:prod:softname` | The product name listed in the CISA KEV database.  |
| `:cisa:kev:added` | `time` | The date the vulnerability was added to the CISA KEV database.  |
| `:cisa:kev:duedate` | `time` | The date the action is due according to the CISA KEV database.  |


#### `ou:campaign`

- **Type:** base/guid
- **Doc:** Represents an org's activity in pursuit of a goal.

| property | type | doc |
|---|---|---|
| `:org` | `ou:org` | The org carrying out the campaign.  |
| `:org:name` | `ou:name` | The name of the org responsible for the campaign. Used for entity resolution.  |
| `:org:fqdn` | `inet:fqdn` | The FQDN of the org responsible for the campaign. Used for entity resolution.  |
| `:goal` | `ou:goal` | The assessed primary goal of the campaign.  |
| `:slogan` | `lang:phrase` | The slogan used by the campaign.  |
| `:actors` | `array` {"type": "ps:contact", "split": ",", "uniq": true, "sorted": true} | Actors who participated in the campaign.  |
| `:goals` | `array` {"type": "ou:goal", "split": ",", "uniq": true, "sorted": true} | Additional assessed goals of the campaign.  |
| `:success` | `bool` | Records the success/failure status of the campaign if known.  |
| `:name` | `ou:campname` | A terse name of the campaign.  |
| `:names` | `array` {"type": "ou:campname", "sorted": true, "uniq": true} | An array of alternate names for the campaign.  |
| `:reporter` | `ou:org` | The organization reporting on the campaign.  |
| `:reporter:name` | `ou:name` | The name of the organization reporting on the campaign.  |
| `:type` | `str` | Deprecated. Use the :camptype taxonomy. **[deprecated]** |
| `:sophistication` | `meta:sophistication` | The assessed sophistication of the campaign.  |
| `:timeline` | `meta:timeline` | A timeline of significant events related to the campaign.  |
| `:camptype` | `ou:camptype` | The campaign type taxonomy.  |
| `:desc` | `str` | A description of the campaign.  |
| `:period` | `ival` | The time interval when the organization was running the campaign.  |
| `:cost` | `econ:price` | The actual cost to the organization.  |
| `:budget` | `econ:price` | The budget allocated by the organization to execute the campaign.  |
| `:currency` | `econ:currency` | The currency used to record econ:price properties.  |
| `:goal:revenue` | `econ:price` | A goal for revenue resulting from the campaign.  |
| `:result:revenue` | `econ:price` | The revenue resulting from the campaign.  |
| `:goal:pop` | `int` | A goal for the number of people affected by the campaign.  |
| `:result:pop` | `int` | The count of people affected by the campaign.  |
| `:team` | `ou:team` | The org team responsible for carrying out the campaign.  |
| `:conflict` | `ou:conflict` | The conflict in which this campaign is a primary participant.  |
| `:techniques` | `array` {"type": "ou:technique", "sorted": true, "uniq": true} | Deprecated for scalability. Please use -(uses)> ou:technique. **[deprecated]** |
| `:tag` | `syn:tag` | The tag used to annotate nodes that are associated with the campaign.  |
| `:mitre:attack:campaign` | `it:mitre:attack:campaign` | A mapping to a MITRE ATT&CK campaign if applicable.  |
| `:ext:id` | `str` {"strip": true} | An external identifier for the campaign.  |


#### `it:mitre:attack:technique`

- **Type:** base/str
- **Doc:** A MITRE ATT&CK Technique ID.

| property | type | doc |
|---|---|---|
| `:name` | `str` {"lower": true, "onespace": true} | The primary name for the ATT&CK technique.  |
| `:matrix` | `it:mitre:attack:matrix` | The ATT&CK matrix which defines the technique.  |
| `:status` | `it:mitre:attack:status` | The status of this ATT&CK technique.  |
| `:isnow` | `it:mitre:attack:technique` | If deprecated, this field may contain the current value for the technique.  |
| `:desc` | `str` {"strip": true} | A description of the ATT&CK technique.  |
| `:url` | `inet:url` | The URL that documents the ATT&CK technique.  |
| `:tag` | `syn:tag` | Deprecated. Please use ou:technique:tag. **[deprecated]** |
| `:references` | `array` {"type": "inet:url", "uniq": true} | An array of URLs that document the ATT&CK technique.  |
| `:parent` | `it:mitre:attack:technique` | The parent ATT&CK technique on this sub-technique.  |
| `:tactics` | `array` {"type": "it:mitre:attack:tactic", "uniq": true, "sorted": true, "split": ","} | An array of ATT&CK tactics that include this technique.  |
| `:data:components` | `array` {"type": "it:mitre:attack:data:component", "uniq": true, "sorted": true} | An array of MITRE ATT&CK data components that detect the ATT&CK technique.  |


### Meta: Provenance, Notes, Rules, Events, Timelines


#### `meta:source`

- **Type:** base/guid
- **Doc:** A data source unique identifier.

| property | type | doc |
|---|---|---|
| `:name` | `str` {"lower": true} | A human friendly name for the source.  |
| `:type` | `str` {"lower": true} | An optional type field used to group sources.  |
| `:url` | `inet:url` | A URL which documents the meta source.  |
| `:ingest:cursor` | `str` | Used by ingest logic to capture the current ingest cursor within a feed.  |
| `:ingest:latest` | `time` | Used by ingest logic to capture the last time a feed ingest ran.  |
| `:ingest:offset` | `int` | Used by ingest logic to capture the current ingest offset within a feed.  |


#### `meta:seen` **[DEPRECATED FORM]**

- **Type:** base/comp
- **Doc:** Annotates that the data in a node was obtained from or observed by a given source.
- **Comp fields (primary value):** `source`=`meta:source`, `node`=`ndef`

| property | type | doc |
|---|---|---|
| `:source` | `meta:source` | The source which observed or provided the node. _(read-only)_ |
| `:node` | `ndef` | The node which was observed by or received from the source. _(read-only)_ |


#### `meta:note`

- **Type:** base/guid
- **Doc:** An analyst note about nodes linked with -(about)> edges.

| property | type | doc |
|---|---|---|
| `:type` | `meta:note:type:taxonomy` | The note type.  |
| `:text` | `str` | The analyst authored note text.  |
| `:author` | `ps:contact` | The contact information of the author.  |
| `:creator` | `syn:user` | The synapse user who authored the note.  |
| `:created` | `time` | The time the note was created.  |
| `:updated` | `time` | The time the note was updated.  |
| `:replyto` | `meta:note` | The note is a reply to the specified note.  |


#### `meta:rule`

- **Type:** base/guid
- **Doc:** A generic rule linked to matches with -(matches)> edges.

| property | type | doc |
|---|---|---|
| `:name` | `str` {"lower": true, "onespace": true} | A name for the rule.  |
| `:type` | `meta:rule:type:taxonomy` | The rule type.  |
| `:status` | `meta:rule:status:taxonomy` | The status of the rule.  |
| `:desc` | `str` | A description of the rule.  |
| `:text` | `str` | The text of the rule logic.  |
| `:author` | `ps:contact` | The contact information of the rule author.  |
| `:created` | `time` | The time the rule was initially created.  |
| `:updated` | `time` | The time the rule was most recently modified.  |
| `:url` | `inet:url` | A URL which documents the rule.  |
| `:ext:id` | `str` | An external identifier for the rule.  |


#### `meta:ruleset`

- **Type:** base/guid
- **Doc:** A set of rules linked with -(has)> edges.

| property | type | doc |
|---|---|---|
| `:name` | `str` {"lower": true, "onespace": true} | A name for the ruleset.  |
| `:type` | `meta:ruleset:type:taxonomy` | The ruleset type.  |
| `:desc` | `str` | A description of the ruleset.  |
| `:author` | `ps:contact` | The contact information of the ruleset author.  |
| `:created` | `time` | The time the ruleset was initially created.  |
| `:updated` | `time` | The time the ruleset was most recently modified.  |


#### `meta:event`

- **Type:** base/guid
- **Doc:** An analytically relevant event in a curated timeline.

| property | type | doc |
|---|---|---|
| `:timeline` | `meta:timeline` | The timeline containing the event.  |
| `:title` | `str` | A title for the event.  |
| `:summary` | `str` | A prose summary of the event.  |
| `:time` | `time` | The time that the event occurred.  |
| `:index` | `int` | The index of this event in a timeline without exact times.  |
| `:duration` | `duration` | The duration of the event.  |
| `:type` | `meta:event:taxonomy` | Type of event.  |


#### `meta:event:taxonomy`

- **Type:** base/taxonomy — **implements interface(s):** `meta:taxonomy`
- **Doc:** A taxonomy of event types for meta:event nodes.

| property | type | doc |
|---|---|---|
| `:title` | `str` | A brief title of the definition.  |
| `:summary` | `str` | Deprecated. Please use title/desc. **[deprecated]** |
| `:desc` | `str` | A definition of the taxonomy entry.  |
| `:sort` | `int` | A display sort order for siblings.  |
| `:base` | `taxon` | The base taxon. _(read-only)_ |
| `:depth` | `int` | The depth indexed from 0. _(read-only)_ |
| `:parent` | `meta:event:taxonomy` | The taxonomy parent. _(read-only)_ |


#### `meta:timeline`

- **Type:** base/guid
- **Doc:** A curated timeline of analytically relevant events.

| property | type | doc |
|---|---|---|
| `:title` | `str` | A title for the timeline.  |
| `:summary` | `str` | A prose summary of the timeline.  |
| `:type` | `meta:timeline:taxonomy` | The type of timeline.  |


#### `meta:timeline:taxonomy`

- **Type:** base/taxonomy — **implements interface(s):** `meta:taxonomy`
- **Doc:** A taxonomy of timeline types for meta:timeline nodes.

| property | type | doc |
|---|---|---|
| `:title` | `str` | A brief title of the definition.  |
| `:summary` | `str` | Deprecated. Please use title/desc. **[deprecated]** |
| `:desc` | `str` | A definition of the taxonomy entry.  |
| `:sort` | `int` | A display sort order for siblings.  |
| `:base` | `taxon` | The base taxon. _(read-only)_ |
| `:depth` | `int` | The depth indexed from 0. _(read-only)_ |
| `:parent` | `meta:timeline:taxonomy` | The taxonomy parent. _(read-only)_ |


#### `meta:feed`

- **Type:** base/guid
- **Doc:** A data feed provided by a specific source.

| property | type | doc |
|---|---|---|
| `:id` | `str` {"strip": true} | An identifier for the feed.  |
| `:name` | `str` {"lower": true, "onespace": true} | A name for the feed.  |
| `:type` | `meta:feed:type:taxonomy` | The type of data feed.  |
| `:source` | `meta:source` | The meta:source which provides the feed.  |
| `:url` | `inet:url` | The URL of the feed API endpoint.  |
| `:query` | `str` | The query logic associated with generating the feed output.  |
| `:opts` | `data` | An opaque JSON object containing feed parameters and options.  |
| `:period` | `ival` | The time window over which results have been ingested.  |
| `:latest` | `time` | The time of the last record consumed from the feed.  |
| `:offset` | `int` | The offset of the last record consumed from the feed.  |
| `:cursor` | `str` {"strip": true} | A cursor used to track ingest offset within the feed.  |


#### `meta:cluster`

- **Type:** base/guid
- **Doc:** A cluster of analytically relevant nodes generated by a specific source.

| property | type | doc |
|---|---|---|
| `:id` | `str` {"strip": true} | An identifier for the cluster.  |
| `:ids` | `array` {"type": "str", "uniq": true, "sorted": true, "typeopts": {"strip": true}} | An array of alternate identifiers for the cluster.  |
| `:name` | `str` {"lower": true, "onespace": true} | The name of the cluster.  |
| `:names` | `array` {"type": "str", "uniq": true, "sorted": true, "typeopts": {"lower": true, "onespace": true}} | An array of alternate names for the cluster.  |
| `:type` | `meta:cluster:type:taxonomy` | The type of cluster.  |
| `:desc` | `str` | A description of the cluster.  |
| `:tag` | `syn:tag` | The tag used to annotate nodes that are associated with the cluster.  |
| `:reporter` | `ou:org` | The organization reporting on the cluster.  |
| `:reporter:name` | `ou:name` | The name of the organization reporting on the cluster.  |


#### `meta:aggregate`

- **Type:** base/guid
- **Doc:** A node which represents an aggregate count of a specific type.

| property | type | doc |
|---|---|---|
| `:type` | `meta:aggregate:type:taxonomy` | The type of items being counted in aggregate.  |
| `:time` | `time` | The time that the count was computed.  |
| `:count` | `int` | The number of items counted in aggregate.  |


### Project / ticketing (optional incident tracking)


#### `proj:project`

- **Type:** base/guid
- **Doc:** A project in a ticketing system.

| property | type | doc |
|---|---|---|
| `:name` | `str` {"lower": true, "onespace": true} | The project name.  |
| `:type` | `proj:project:type:taxonomy` | The project type.  |
| `:desc` | `str` | The project description.  |
| `:creator` | `syn:user` | The synapse user who created the project.  |
| `:created` | `time` | The time the project was created.  |
| `:platform` | `inet:service:platform` | The platform where the project is hosted.  |


#### `proj:ticket`

- **Type:** base/guid — **implements interface(s):** `proj:task`
- **Doc:** A ticket in a ticketing system.

| property | type | doc |
|---|---|---|
| `:ext:id` | `str` {"strip": true} | Deprecated. Please use :id. **[deprecated]** |
| `:ext:url` | `inet:url` | A URL to the ticket in an external system.  |
| `:epic` | `proj:epic` | The epic that includes the ticket.  |
| `:name` | `str` {"onespace": true} | The name of the ticket.  |
| `:desc` | `str` | A description of the ticket.  |
| `:points` | `int` | Optional SCRUM style story points value.  |
| `:status` | `int` {"enums": [[0, "new"], [10, "in validation"], [20, "in backlog"], [30, "in sprint"], [40, "in progress"], [50, "in re... | The ticket completion status.  |
| `:sprint` | `proj:sprint` | The sprint that contains the ticket.  |
| `:type` | `str` {"lower": true, "strip": true} | The type of ticket.  |
| `:id` | `str` {"strip": true} | The ID of the ticket.  |
| `:project` | `proj:project` | The project containing the ticket.  |
| `:priority` | `meta:priority` | The priority of the ticket.  |
| `:created` | `time` | The time the ticket was created.  |
| `:updated` | `time` | The time the ticket was last updated.  |
| `:due` | `time` | The time the ticket must be complete.  |
| `:completed` | `time` | The time the ticket was completed.  |
| `:creator` | `syn:user` | The user which created the ticket.  |
| `:assignee` | `syn:user` | The user assigned to complete the ticket.  |
| `:ext:creator` | `ps:contact` | The contact information of the creator from an external system.  |
| `:ext:assignee` | `ps:contact` | The contact information of the assignee from an external system.  |


### Declared lightweight edges (global `edges` section of the model)

| n1 form | verb | n2 form | doc |
|---|---|---|---|
| `ou:campaign` | **uses** | `ou:technique` | The campaign used the technique. |
| `ou:org` | **uses** | `ou:technique` | The org uses the technique. |
| `risk:vuln` | **uses** | `ou:technique` | The vulnerability uses the technique. |
| `ou:org` | **uses** | `*` | The ou:org makes use of the target node. |
| `ou:org` | **targets** | `*` | The organization targets the target node. |
| `ou:campaign` | **targets** | `*` | The campaign targeted the target nodes. |
| `ou:campaign` | **uses** | `*` | The campaign made use of the target node. |
| `ou:contribution` | **includes** | `*` | The contribution includes the specific node. |
| `*` | **meets** | `ou:requirement` | The requirement is met by the source node. |
| `ou:org` | **has** | `*` | The organization is or was in possession of the target node. |
| `ou:org` | **owns** | `*` | The organization owns or owned the target node. |
| `*` | **refs** | `*` | The source node contains a reference to the target node. |
| `*` | **linked** | `*` | The source node is linked to the target node. |
| `meta:source` | **seen** | `*` | The meta:source observed the target node. |
| `meta:feed` | **found** | `*` | The meta:feed produced the target node. |
| `meta:note` | **about** | `*` | The meta:note is about the target node. |
| `meta:ruleset` | **has** | `meta:rule` | The meta:ruleset includes the meta:rule. |
| `meta:ruleset` | **has** | `inet:service:rule` | The meta:ruleset includes the inet:service:rule. |
| `meta:ruleset` | **has** | `it:app:snort:rule` | The meta:ruleset includes the it:app:snort:rule. |
| `meta:ruleset` | **has** | `it:app:yara:rule` | The meta:ruleset includes the it:app:yara:rule. |
| `meta:rule` | **matches** | `*` | The meta:rule has matched on target node. |
| `meta:rule` | **detects** | `*` | The meta:rule is designed to detect instances of the target node. |
| `meta:rule` | **generated** | `risk:alert` | The meta:rule generated the risk:alert node. |
| `meta:rule` | **generated** | `it:log:event` | The meta:rule generated the it:log:event node. |
| `risk:tool:software` | **uses** | `math:algorithm` | The tool uses the algorithm. |
| `it:prod:softver` | **uses** | `math:algorithm` | The software uses the algorithm. |
| `file:bytes` | **uses** | `math:algorithm` | The file uses the algorithm. |
| `math:algorithm` | **generates** | `*` | The target node was generated by the algorithm. |
| `risk:attack` | **uses** | `ou:technique` | The attacker used the technique in the attack. |
| `risk:threat` | **uses** | `ou:technique` | The threat cluster uses the technique. |
| `risk:tool:software` | **uses** | `ou:technique` | The tool uses the technique. |
| `risk:compromise` | **uses** | `ou:technique` | The attacker used the technique in the compromise. |
| `risk:extortion` | **uses** | `ou:technique` | The attacker used the technique to extort the victim. |
| `risk:attack` | **uses** | `risk:vuln` | The attack used the vulnerability. |
| `risk:threat` | **uses** | `risk:vuln` | The threat cluster uses the vulnerability. |
| `risk:tool:software` | **uses** | `risk:vuln` | The tool uses the vulnerability. |
| `ou:technique` | **uses** | `risk:vuln` | The technique uses the vulnerability. |
| `risk:attack` | **targets** | `ou:industry` | The attack targeted the industry. |
| `risk:compromise` | **targets** | `ou:industry` | The compromise was assessed to be based on the victim's role in the industry. |
| `risk:threat` | **targets** | `ou:industry` | The threat cluster targets the industry. |
| `risk:threat` | **targets** | `*` | The threat cluster targeted the target node. |
| `risk:threat` | **uses** | `*` | The threat cluster uses the target node. |
| `risk:threat` | **uses** | `inet:service:platform` | The threat cluster uses the service platform. |
| `risk:threat` | **uses** | `inet:service:app` | Deprecated. Please use the inet:service:platform form instead. |
| `risk:attack` | **targets** | `*` | The attack targeted the target node. |
| `risk:attack` | **uses** | `*` | The attack used the target node to facilitate the attack. |
| `risk:tool:software` | **uses** | `*` | The tool uses the target node. |
| `risk:compromise` | **stole** | `*` | The target node was stolen or copied as a result of the compromise. |
| `risk:mitigation` | **addresses** | `ou:technique` | The mitigation addresses the technique. |
| `risk:mitigation` | **uses** | `meta:rule` | The mitigation uses the rule. |
| `risk:mitigation` | **uses** | `it:app:yara:rule` | The mitigation uses the YARA rule. |
| `risk:mitigation` | **uses** | `it:app:snort:rule` | The mitigation uses the Snort rule. |
| `risk:mitigation` | **uses** | `inet:service:rule` | The mitigation uses the service rule. |
| `risk:mitigation` | **uses** | `it:prod:softver` | The mitigation uses the software version. |
| `risk:mitigation` | **uses** | `it:prod:hardware` | The mitigation uses the hardware. |
| `risk:leak` | **leaked** | `*` | The leak included the disclosure of the target node. |
| `risk:leak` | **enabled** | `risk:leak` | The source leak enabled the target leak to occur. |
| `risk:extortion` | **leveraged** | `*` | The extortion event was based on attacker access to the target node. |
| `meta:event` | **caused** | `risk:outage` | The event caused the outage. |
| `risk:attack` | **caused** | `risk:outage` | The attack caused the outage. |
| `risk:outage` | **impacted** | `*` | The outage event impacted the availability of the target node. |
| `risk:alert` | **about** | `*` | The alert is about the target node. |
| `ps:contact` | **has** | `*` | The contact is or was in possession of the target node. |
| `ps:person` | **has** | `*` | The person is or was in possession of the target node. |
| `ps:contact` | **owns** | `*` | The contact owns or owned the target node. |
| `ps:person` | **owns** | `*` | The person owns or owned the target node. |
| `file:bytes` | **refs** | `it:dev:str` | The source file contains the target string. |
| `it:prod:soft` | **uses** | `ou:technique` | The software uses the technique. |
| `it:prod:soft` | **uses** | `risk:vuln` | The software uses the vulnerability. |
| `it:exec:query` | **found** | `*` | The target node was returned as a result of running the query. |
| `it:app:sigma:rule` | **detects** | `*` | The Sigma rule is intended for use in detecting the target node. |
| `it:app:snort:rule` | **detects** | `*` | The snort rule is intended for use in detecting the target node. |
| `it:app:suricata:rule` | **detects** | `*` | The suricata rule is intended for use in detecting the target node. |
| `it:app:yara:rule` | **detects** | `*` | The YARA rule is intended for use in detecting the target node. |
| `it:dev:repo` | **has** | `inet:url` | The repo has content hosted at the URL. |
| `it:dev:repo:commit` | **has** | `it:dev:repo:entry` | The file entry is present in the commit version of the repository. |
| `it:log:event` | **about** | `*` | The it:log:event is about the target node. |
| `*` | **seenat** | `geo:telem` | Deprecated. Please use geo:telem:node. |
| `geo:place` | **contains** | `geo:place` | The source place completely contains the target place. |
| `inet:whois:iprec` | **ipwhois** | `inet:ipv4` | The source IP whois record describes the target IPv4 address. |
| `inet:whois:iprec` | **ipwhois** | `inet:ipv6` | The source IP whois record describes the target IPv6 address. |
| `crypto:key` | **decrypts** | `file:bytes` | The key is used to decrypt the file. |
| `econ:purchase` | **acquired** | `*` | The purchase was used to acquire the target node. |
| `econ:bank:statement` | **has** | `econ:acct:payment` | The bank statement includes the payment. |
| `belief:system` | **has** | `belief:tenet` | The belief system includes the tenet. |
| `belief:subscriber` | **follows** | `belief:tenet` | The subscriber is assessed to generally adhere to the specific tenet. |
| `sci:experiment` | **uses** | `*` | The experiment used the target nodes when it was run. |
| `sci:observation` | **has** | `*` | The observations are summarized from the target nodes. |
| `sci:evidence` | **has** | `*` | The evidence includes observations from the target nodes. |
| `plan:procedure:step` | **uses** | `*` | The step in the procedure makes use of the target node. |

### Universal properties

- `.seen` (ival): The time interval for first/last observation of the node.
- `.created` (time): The time the node was created in the cortex.

### Interface: it:host:activity (inherited by all it:exec:* forms)

Properties common to instances of activity on a host.

| property | type | doc |
|---|---|---|
| `:exe` | `file:bytes` | The executable file which caused the activity. |
| `:proc` | `it:exec:proc` | The host process which caused the activity. |
| `:thread` | `it:exec:thread` | The host thread which caused the activity. |
| `:host` | `it:host` | The host on which the activity occurred. |
| `:time` | `time` | The time that the activity started. |
| `:sandbox:file` | `file:bytes` | The initial sample given to a sandbox environment to analyze. |