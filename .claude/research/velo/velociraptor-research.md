# Velociraptor Technical Reference for a Synapse Storm Service

**Purpose:** source-of-truth research for designing a Storm service that pulls *all* incident-response data out of a Velociraptor server and models it in a Synapse Cortex.

**Research date:** 2026-10-31.
**Primary sources:** docs.velociraptor.app, the Velocidex/velociraptor GitHub repository (master @ commit `61daa5f66b8b`, 2026-10-31, i.e. the 0.77-era code base), the shipped `.proto` files, the shipped artifact YAML definitions, and the pyvelociraptor client. Where a fact comes from source code rather than docs, the file path in the repo is cited (`repo:`).

**Current stable version:** **0.77** line (0.77.1 released ~May 2026; docs banner says *"update to release 0.77.3"* because of CVEs fixed after the v0.77.2 advisory). Recent history: 0.74 (Feb 2025, Sigma editor rework, live event sources), 0.75 (Aug 2025, **big breaking changes**: filestore compression, artifact exodus — see Gotchas), 0.76 (late 2025), 0.77 (May 2026). Since 0.72 the version scheme is `0.MAJOR.PATCH` (e.g. 0.77.3). Sources: https://github.com/Velocidex/velociraptor/releases , https://docs.velociraptor.app/blog/2025/2025-08-30-release-notes-0.75/ , https://docs.velociraptor.app/blog/2026/2026-05-31-release-notes-0.77/

---

## 1. Architecture & Object Model

Velociraptor is a single Go binary acting as server + GUI + API + client (agent). Clients hold a persistent TLS connection to the frontend; the server schedules **flows** (collections of **artifacts**, which are named VQL packages) on clients, or runs artifacts server-side. **Hunts** fan a collection out to many clients. All state is files: a **datastore** (small JSON "*.db" objects) and a **filestore** (bulk data: result sets, uploads), normally both under the same directory tree.

### 1.1 ID conventions

| Object | ID format | Notes |
|---|---|---|
| Client | `C.<random>` | e.g. `C.d828d0c753eb0ccd`; `server` is a pseudo client id for server artifact collections |
| Flow / collection | `F.<random>` (`FLOW_PREFIX = "F."`, repo: `constants/constants.go`) | a.k.a. `session_id` in protobufs; `F.Monitoring` is the well-known monitoring flow |
| Hunt | `H.<random>` (`HUNT_PREFIX = "H."`) | |
| Notebook | `N.<random>` (global); `N.<flow_id>-<client_id>` i.e. `N.F.xxx-C.yyy` (flow notebooks, repo: `paths/flow_metadata.go:164`); `N.H.<xxx>` (hunt notebooks); `N.E.<ArtifactName>-<client_id>` (event notebooks, repo fixture `services/notebook/fixtures/TestInitialNotebook.golden`) | |
| Notebook cell | `NC.<random>` | cells are versioned (see §1.7) |
| Org | root org has empty/`root` id; sub-orgs get `O<random>` (`ORG_PREFIX = "O"`, repo: `constants/constants.go`) | |

### 1.2 Clients

Two overlapping records exist:

**`ApiClient`** (GUI/gRPC `GetClient`/`ListClients`, repo: `api/proto/clients.proto`) — the proto comment says it is superseded by `ClientInfo`:

| Field | Type | Notes |
|---|---|---|
| `client_id` | string | |
| `agent_information` | `{version, name, build_time, build_url}` | Velociraptor agent build info |
| `os_info` | `Uname {system, hostname, release, machine, fqdn, mac_addresses[]}` | |
| `first_seen_at`, `last_seen_at` | uint64 | epoch (last_seen in **microseconds**) |
| `last_ip` | string | last seen remote IP |
| `last_interrogate_flow_id`, `last_interrogate_artifact_name` | string | points at the enrollment/interrogation flow (default artifact `Generic.Client.Info`) |
| `labels` | repeated string | |
| `last_hunt_timestamp`, `last_event_table_version`, `last_label_timestamp` | uint64 | |
| `in_flight_flows` | map<string,int64> | flow_id → last update time |

**`ClientInfo`** (repo: `actions/proto/vql.proto`, what `client_info()` and `clients()` effectively return): `client_id, hostname, fqdn, system, release, architecture, ip_address, ping (µs epoch), ping_time, client_version, client_name, first_seen_at, build_time, build_url, install_time, labels[], mac_addresses[], has_tasks, last_interrogate_flow_id, last_interrogate_artifact_name, last_hunt_timestamp, last_event_table_version, labels_timestamp, in_flight_flows{}, metadata{}` (indexed metadata key/values).

* **Enrollment/interrogation:** on enrollment the server runs `Generic.Client.Info`; its `BasicInformation` source (`Name, BuildTime, Version, build_url, install_time, Labels, Hostname, OS, Architecture, Platform, PlatformVersion, KernelVersion, Fqdn, MACAddresses`) populates the client index (repo: `artifacts/definitions/Generic/Client/Info.yaml`). Re-interrogation creates a new flow and updates `last_interrogate_flow_id`.
* **Labels:** free-form strings on clients; set via GUI, `LabelClients` gRPC (`client_ids[], labels[], operation` = set/remove), or VQL `label(client_id=, labels=[], op="set|remove|check")`. Labels drive hunt targeting and client-monitoring targeting. `ClientLabels {timestamp, label[]}`.
* **Client metadata:** arbitrary key/value per client (`ClientMetadata {items: [{key,value}], client_id}`); VQL `client_metadata(client_id)` / `client_set_metadata(client_id, metadata=dict(...))`.
* **Search:** `clients(search="label:Foo")` / `host:` prefixes; gRPC `ListClients(SearchClientsRequest {offset, limit, query, sort, filter=ONLINE})`.

### 1.3 Flows (collections)

Canonical object: **`ArtifactCollectorContext`** (repo: `flows/proto/artifact_collector.proto`); this is exactly what the `flows()` VQL plugin emits (proto→dict, repo: `vql/server/flows/flows.go` uses `ConvertProtoToOrderedDict`, plus an `AvailableDownloads` key):

| Field (JSON name) | Type | Notes |
|---|---|---|
| `client_id` | string | |
| `session_id` | string | the flow id (`F.xxx`) |
| `request` | `ArtifactCollectorArgs` | creator, artifacts[], specs[], limits (in 0.77 large requests are stored separately and may be summarized) |
| `create_time`, `start_time`, `active_time`, `inflight_time` | uint64 | epoch **microseconds** |
| `total_uploaded_files`, `total_expected_uploaded_bytes`, `total_uploaded_bytes` | uint64 | |
| `total_collected_rows`, `total_logs`, `total_requests`, `outstanding_requests` | uint64/int64 | |
| `execution_duration` | int64 | nanoseconds of client query time |
| `state` | enum | `UNSET, RUNNING, FINISHED, ERROR, IN_PROGRESS, UNRESPONSIVE, WAITING` |
| `status` | string | error text when state=ERROR |
| `artifacts_with_results` | repeated string | names incl. `Artifact/Source` forms — use these to read results |
| `query_stats` | repeated VeloStatus | per-query status |
| `uploaded_files` | repeated `ArtifactUploadedFileInfo {name, vfs_path, size, stored_size, components[], type}` | may be truncated for large flows; prefer `uploads()` |
| `logs` | repeated LogMessage | truncated; prefer `flow_logs()` |

`ArtifactCollectorArgs` (what you pass to `collect_client()` / `CollectArtifact`): `creator, client_id, flow_id, urgent, artifacts[], specs[] (ArtifactSpec {artifact, parameters{env:[{key,value}]}, cpu_limit, timeout, max_batch_rows...}), cpu_limit, iops_limit, progress_timeout, timeout, max_rows, max_logs, max_upload_bytes, ops_per_second, allow_custom_overrides, org_id (via VQL arg)`.

**VQL:** `collect_client(client_id=, artifacts=[...], env=dict()|spec=dict(), timeout=, cpu_limit=, max_rows=, max_bytes=, urgent=, org_id=)` → returns the request incl. `flow_id`; `get_flow(client_id=, flow_id=)`; `cancel_flow()`; `enumerate_flow(client_id=, flow_id=)` lists all datastore/filestore files belonging to a flow (useful for deletion/export); `flow_logs(client_id=, flow_id=)` reads the flow log result set (`client_time, level, message` columns); `flows(client_id=, flow_id=, summary=)` iterates flows (newest first, backed by `clients/<id>/flow_index`).

**Flow completion event:** server event artifact `System.Flow.Completion` — each row: `Flow` (full ArtifactCollectorContext), `FlowId`, `ClientId` (+ `_ts`). Watch with `watch_monitoring(artifact='System.Flow.Completion')` — this is **the** push mechanism for ingesting finished collections (repo: `flows/client_flow_runner.go:718`).

### 1.4 Hunts

**`Hunt`** proto (repo: `api/proto/hunts.proto`); `hunts(hunt_id=, summary=)` emits exactly this as a dict:

| Field | Type | Notes |
|---|---|---|
| `hunt_id` | string | `H.xxx` |
| `create_time`, `start_time`, `expires` | uint64 | epoch µs |
| `creator` | string | user who created it |
| `hunt_description` | string | |
| `tags` | repeated string | 0.75+ |
| `start_request` | ArtifactCollectorArgs | the collection fanned out |
| `condition` | `HuntCondition {labels{label[]}, excluded_labels, os{os: ALL/WINDOWS/LINUX/OSX}}` | targeting |
| `client_limit` | uint64 | |
| `artifacts`, `artifact_sources` | repeated string | |
| `state` | enum | `UNSET, PAUSED, RUNNING, STOPPED, ARCHIVED, DELETED` |
| `stats` | HuntStats | `total_clients_scheduled, total_clients_with_results, total_clients_without_results, total_clients_with_errors, total_uploaded_bytes, total_collected_rows, total_finished_clients, stopped, available_downloads` |
| `org_ids` | repeated string | multi-org hunts |

**VQL:** `hunt(description=, artifacts=[...], expires=, spec=, include_labels=/exclude_labels=/os=, pause=, org_id=[])` creates a hunt; `hunt_add(client_id=, hunt_id=, flow_id=, relaunch=)` manually adds a client/flow to a hunt; `hunt_update()`, `hunt_info()`, `hunt_delete()`. Which clients participated: `hunt_flows(hunt_id=, start_row=, limit=, basic_info=)` → rows `ClientId, FlowId, Fqdn, _OrgId, Flow {full context}` (repo: `vql/server/hunts/hunts.go:293`). Results across clients: `hunt_results(hunt_id=, artifact=, source=, orgs=[])` (adds `ClientId`, `FlowId`, `Fqdn` columns to each result row). gRPC: `CreateHunt, GetHunt, ListHunts (deprecated), GetHuntFlows, GetHuntResults, ModifyHunt, GetHuntTags, EstimateHunt`.

Note: `System.Hunt.Participation` (per-client hunt participation event) was **removed in 0.77** during the event-queue refactor; use `hunt_flows()`.

### 1.5 Artifacts

Artifact = YAML definition (repo: `artifacts/definitions/**`, proto: `artifacts/proto/artifact.proto`): `name, aliases, description, author, reference[], required_permissions[], implied_permissions[], precondition, parameters[] ({name, default, type (string/int/bool/regex/choices/timestamp/csv/json/json_array/hidden/artifactset/upload…), description}), type, sources[] ({name, description, precondition, query, notebook[] templates}), export, imports[], reports[], column_types[], tools[]`.

`type` is one of **`CLIENT`, `CLIENT_EVENT`, `SERVER`, `SERVER_EVENT`, `INTERNAL`** (proto comment) plus **`NOTEBOOK`** (notebook templates, e.g. `Notebooks.Default`, `Notebooks.Timelines`). Event types (`*_EVENT`, `INTERNAL`) create named server-side **event queues** (queue name = artifact name) — https://docs.velociraptor.app/docs/artifacts/event_queues/ .

Enumerate with VQL `artifact_definitions(names=[], deps=, sanitize=)` (full definitions incl. source code), gRPC `GetArtifacts/GetArtifactFile/SetArtifactFile`; set tags/metadata with `artifact_set_metadata()` (0.75+). Custom artifacts live in the datastore under `artifact_definitions/` as YAML.

### 1.6 Client monitoring & server monitoring

* **Client monitoring:** server maintains a versioned **`ClientEventTable {version, artifacts: ArtifactCollectorArgs, label_events: [{label, artifacts}], ...}`** (repo: `flows/proto/artifact_collector.proto`); clients compare `last_event_table_version` and fetch updates. Targeting by **label**. Default event artifact: `Generic.Client.Stats` (CPU/mem telemetry). Configure via GUI, gRPC `GetClientMonitoringState/SetClientMonitoringState`, or VQL `get_client_monitoring()`, `set_client_monitoring(value=)`, `add_client_monitoring(artifact=, label=, parameters=)`, `rm_client_monitoring(artifact=, label=)`. Config seed: `Frontend.default_client_monitoring_artifacts`.
* Client event results stream to the server into per-client, per-artifact, **per-day** timed result sets (see §1.9) and are read with `monitoring(client_id=, artifact=, source=, start_time=, end_time=, start_row=)` (repo: `vql/server/flows/monitoring.go`) or `source(..., start_time=, end_time=)`; live-tail with `watch_monitoring(artifact=)` (streams new rows from **all** clients for that artifact, rows get `ClientId` and `_ts`).
* **Server monitoring:** SERVER_EVENT artifacts run persistently in the server; managed via `GetServerMonitoringState/SetServerMonitoringState` (an `ArtifactCollectorArgs`), VQL `get_server_monitoring()`, `set_server_monitoring()`, `add_server_monitoring(artifact=, parameters=)`, `rm_server_monitoring(artifact=)`. Results in `server_artifacts/<Artifact>/<YYYY-MM-DD>.json`; logs in `server_artifact_logs/`. Docs: https://docs.velociraptor.app/docs/server_automation/server_monitoring/ . `ListAvailableEventResults` gRPC lists which event artifacts have stored data and for which days. `monitoring_logs()` reads event-artifact logs.

### 1.7 Notebooks

**`NotebookMetadata`** (repo: `api/proto/notebooks.proto`): `notebook_id, name, description, creator, collaborators[], public, hidden, created_time, modified_time, version, cells[] (cell ids), cell_metadata[] (NotebookCell), latest_cell_id, env[{key,value}], artifacts[]/specs[]/parameters[]/requests[] (from NOTEBOOK template), available_downloads (exports), available_uploads (attachments: {name/Date/Size/Type/components}), timelines[] (super-timeline names), column_types[], suggestions[]`.

**`NotebookCell`**: `notebook_id, cell_id, input (markdown/VQL source), output (rendered HTML), summary, data, messages[] (query logs), timestamp, duration, type ("markdown"|"vql"), calculating, env, error, current_version, available_versions[]` — cells keep multiple versions.

* Notebook types: **global** (template-created, persistent), **flow**, **hunt**, **event** notebooks (auto-created from the notebook tab; seeded from the artifact's `notebook:` section or a default `SELECT * FROM source()` cell). In flow/hunt/event notebooks the env pre-sets `ClientId`, `FlowId`, `HuntId`, `ArtifactName`, `StartTime/EndTime` so `source()` needs no args. Docs: https://docs.velociraptor.app/docs/notebooks/
* VQL: `notebook_create(name=, description=, collaborators=, public=, artifacts=[NOTEBOOK templates], env=)`, `notebook_get(notebook_id=, verbose=)`, `notebook_update(notebook_id=, description=, collaborators=, public=, attachment=, attachment_filename=)`, `notebook_update_cell(notebook_id=, cell_id=, input=, type=, output=, delete=)`, `notebook_delete()`, `notebook_export(notebook_id=, type="html"|"zip", filename=)`, `create_notebook_download()`, and the `timelines(notebook_id=)` plugin lists its super-timelines. gRPC: `GetNotebooks, NewNotebook, UpdateNotebook, NewNotebookCell, GetNotebookCell, UpdateNotebookCell, RevertNotebookCell, CancelNotebookCell, CreateNotebookDownloadFile, UploadNotebookAttachment, RemoveNotebookAttachment`.
* Cell result tables are stored as result sets and read with `source(notebook_id=, notebook_cell_id=, notebook_cell_version=, notebook_cell_table=N)`.
* Sharing controls GUI visibility only — **not a security boundary** (any READ_RESULTS user can read via VQL if they know the IDs).

### 1.8 Orgs (multi-tenancy)

Docs: https://docs.velociraptor.app/docs/deployment/orgs/ . Orgs share frontend/CA but have separate nonces, datastores (`orgs/<OrgId>/` subtree), per-org ACLs and audit logs. Root org = default; users need ≥Reader in an org to see it. VQL: `orgs()` plugin → rows `Name, OrgId, _client_config`; `org()` → current org `{name, nonce, id, _client_config}`; `org_create(name=, org_id=)`, `org_delete(org=, really_do_it=)`; `whoami()`, `user_grant()`. API calls carry `org_id` in `VQLCollectorArgs` (empty = root). Many server plugins accept `orgs=[...]` (`source`, `hunt_results`) or `org_id=` (`collect_client`, `hunt`) for cross-org work; the API user needs ACLs **in each org**.

### 1.9 Datastore / filestore layout (where everything lives on disk)

Authoritative map (repo: `paths/schema.go`; extensions repo: `file_store/api/extensions.go`). Datastore objects are JSON serialized protos in `*.db` / `*.json.db`; result sets are JSONL `*.json` with a `*.json.index` row index; timed (event) result sets are date-named files; bulk data (uploads) keeps original bytes (but see compression gotcha).

```
<filestore_directory>/
  config/                                  server config, acls/<user>.db, users
  clients/<ClientId>.db                    client record (datastore)
  clients/<ClientId>/
      key.db                               client public key
      labels.db, metadata.db               (per-version; labels/metadata)
      flow_index.json                      index of flows for this client
      tasks/<id>.db                        queued client tasks
      collections/<FlowId>.db              flow context (ArtifactCollectorContext)
      collections/<FlowId>/
          logs.json(+.index)               flow log result set
          requests.db, task.db, stats.db   flow request / compiled task / stats
          uploads.json(+.index)            upload METADATA result set (§6)
          upload_transactions.json         resumable-upload transactions (0.75+)
          uploads/<accessor>/<path...>     the uploaded file bytes (BULK_DATA)
          notebook/N.<FlowId>-<ClientId>.db, …/<cell>/…, …/attach/…  flow notebook
      artifacts/<ArtifactName>/<FlowId>.json           collection RESULTS (one per artifact)
      artifacts/<ArtifactName>/<FlowId>/<Source>.json  results for named sources
      monitoring/<ArtifactName>[/<Source>]/<YYYY-MM-DD>.json       client event results
      monitoring_logs/<ArtifactName>[/<Source>]/<YYYY-MM-DD>.json  client event logs
      vfs/<accessor>/<components...>.db    VFS directory listing cache (datastore)
      vfs_files/<accessor>/<...>           VFS downloaded-file records
  hunts/<HuntId>.db                        hunt object; <HuntId>.json = participation result set
  hunts/<HuntId>/enriched.json             enriched client details
  hunts/<HuntId>/notebook/N.H.*…           hunt notebook tree
  notebooks/<NotebookId>.db                global notebook metadata
  notebooks/<NotebookId>/<CellId>/…        cell result tables (BULK)
  notebooks/<NotebookId>/attach/…, uploads/…   attachments
  notebooks/<NotebookId>/<SuperTimelineName>.db          super-timeline metadata
  notebooks/<NotebookId>/<SuperTimelineName>/<Component>  timeline data (+ .tidx time index)
  server_artifacts/<ArtifactName>/<YYYY-MM-DD>.json      server-event results
  server_artifact_logs/<ArtifactName>/<YYYY-MM-DD>.json
  downloads/<ClientId>/<FlowId>/*.zip      flow export containers
  downloads/hunts/<HuntId>/*.zip           hunt exports
  downloads/notebooks/<NotebookId>/*.zip|*.html
  artifact_definitions/**.yaml             custom artifacts
  client_info/snapshot.json                client index snapshot
  orgs/<OrgId>/ ... (same tree per org)
  acl/<principal>.db                       ACL objects
```

Day naming for timed result sets: `YYYY-MM-DD` UTC (repo: `paths/artifacts/paths.go getDayName`). **Since 0.75 filestore files are chunk-compressed on disk** — read them with `velociraptor fs zcat`, or in VQL `copy()` to a temp file; naive JSON reads of the raw files no longer work (release notes 0.75). The `velociraptor fs ls/cp/zcat` and `inspect` CLI work offline against the datastore. Direct filestore reading is a legitimate integration path but the gRPC/VQL API is version-stable and preferred.

---

## 2. The API

Docs: https://docs.velociraptor.app/docs/server_automation/server_api/ ; proto: https://github.com/Velocidex/velociraptor/blob/master/api/proto/api.proto

### 2.1 Transport & auth

* Streaming **gRPC** on `API.bind_address`/`bind_port` (default 127.0.0.1:8001 — set `0.0.0.0` + `API.hostname` for remote use). Mutual TLS; client certs are minted by the Velociraptor CA:
  `velociraptor --config server.config.yaml config api_client --name <User> --role api,reader api.config.yaml`
  The YAML contains `ca_certificate`, `client_cert`, `client_private_key`, `api_connection_string`, `name`. **Certificates expire after 1 year** (`Defaults.CertificateValidityDays`).
* `--name` is a server principal subject to **ACLs**. Roles (repo: `acls/roles.go`): `administrator` (everything), `org_admin`, `reader` (READ_RESULTS), **`api` (ANY_QUERY + READ_RESULTS — minimum to call Query())**, `analyst` (+NOTEBOOK_EDITOR, LABEL_CLIENTS, PREPARE_RESULTS), `investigator` (analyst + COLLECT_CLIENT + START_HUNT), `artifact_writer`. Plugin-level permissions: nearly all read plugins need `READ_RESULTS`; `collect_client` needs `COLLECT_CLIENT`; `hunt` needs `START_HUNT`; `timeline_add`/notebook mutation need `NOTEBOOK_EDITOR`; exports need `PREPARE_RESULTS`; deletion needs `DELETE_RESULTS`. **A read-only Synapse puller should use roles `api,reader` (add `analyst` if it must build timelines/notebooks).** `acl grant` *replaces* roles; CLI grants need a server restart.
* GUI's REST/JSON API is explicitly **internal and unstable** — do not build on it.

### 2.2 The `Query` method (the main integration surface)

```proto
rpc Query(VQLCollectorArgs) returns (stream VQLResponse)
```

`VQLCollectorArgs` (repo: `actions/proto/vql.proto`): `Query: [VQLRequest{Name, VQL}]`, `env: [{key,value}]` (**always pass data via env, never string-interpolate — VQL injection**), `max_row` (rows per response part, default 1000), `max_row_buffer_size` (default 5MB), `max_wait` (secs before partial batch flush, default 10), `cpu_limit`, `iops_limit`, `timeout`, `heartbeat` (default 30s), `org_id` (API-only), `principal`.

`VQLResponse` stream items: `Response` (JSON array of row dicts — what pyvelociraptor consumes), `JSONLResponse` (JSONL; `uncompressed_size>0` ⇒ compressed), `Columns[]`, `types[] {column,type}`, `query_id`, `part`, `Query`, `timestamp` (µs), `total_rows` (rows in this part), `query_start_row`, `log` (query log lines arrive as separate items with only `log` set).

**Pagination/streaming model:** `Query()` has **no server-side cursor** — it streams all rows of the query in batches of `max_row`. For very large result sets, do windowing in VQL (`source(start_row=, count=)`, `hunt_flows(start_row=, limit=)`, `monitoring(start_row=)`, `timeline(start=<ts>)`, or `LIMIT`). Event queries (`watch_monitoring`) stream forever — use them for live tailing; the connection must be kept open.

Other API-only RPCs: `VFSGetBuffer(VFSFileBuffer{client_id, components[], offset, length, org_id})` → chunked reads of **any filestore file** (this is how you download collected files, exports, etc. — pyvelociraptor `fetch.py`); `WatchEvent(queue)` / `PushEvents` / `WriteEvent`; `GetSubject/SetSubject/DeleteSubject/ListChildren` (raw datastore access, admin-level); `Check` (health); plus all the GUI-oriented RPCs listed in §2.4.

### 2.3 pyvelociraptor

https://github.com/Velocidex/pyvelociraptor — `pip install pyvelociraptor`. Pattern (repo: `pyvelociraptor/client_example.py`):

```python
config = pyvelociraptor.LoadConfigFile("api.config.yaml")
creds = grpc.ssl_channel_credentials(
    root_certificates=config["ca_certificate"].encode(),
    private_key=config["client_private_key"].encode(),
    certificate_chain=config["client_cert"].encode())
options = (('grpc.ssl_target_name_override', "VelociraptorServer",),)  # required: cert CN
with grpc.secure_channel(config["api_connection_string"], creds, options) as channel:
    stub = api_pb2_grpc.APIStub(channel)
    request = api_pb2.VQLCollectorArgs(
        org_id=org_id, max_wait=1, max_row=100,
        Query=[api_pb2.VQLRequest(Name="X", VQL=query)],
        env=[api_pb2.VQLEnv(key=k, value=v) for k, v in env.items()])
    for response in stub.Query(request):
        if response.Response:      # JSON array of rows
            rows = json.loads(response.Response)
        elif response.log:         # query log line
            ...
```

Helper scripts: `client_example.py`, `fetch.py` (VFSGetBuffer), `fetch_flow_uploads.py` (create flow export + download the zip). Also usable: the binary itself as a client — `velociraptor --api_config api.config.yaml query "SELECT ..." --format jsonl`, and 0.77's `velociraptor artifacts collect --api_config ...` / `artifacts fetch` over the API.

### 2.4 Full gRPC service surface (api.proto, for completeness)

Hunts: `CreateHunt, EstimateHunt, GetHuntTable, ListHunts(deprecated), GetHunt, GetHuntTags, ModifyHunt, GetHuntFlows, GetHuntResults`. Clients: `NotifyClients, LabelClients, ListClients, GetClient, GetClientMetadata, SetClientMetadata, GetClientFlows`. Users: `GetUsers, GetGlobalUsers, GetUserRoles, SetUserRoles, GetUser, CreateUser, GetUserFavorites, SetPassword, GetUserUITraits, SetGUIOptions`. VFS: `VFSListDirectory, VFSListDirectoryFiles, VFSRefreshDirectory, VFSStatDirectory, VFSStatDownload, VFSDownloadFile, GetTable, SearchFile`. Flows: `CollectArtifact, CancelFlow, ResumeFlow, GetFlowDetails, GetFlowRequests`. Artifacts/tools: `GetArtifacts, GetArtifactFile, SetArtifactFile, LoadArtifactPack, GetToolInfo, SetToolInfo, GetReport, SearchDocs`. Monitoring: `GetServerMonitoringState, SetServerMonitoringState, GetClientMonitoringState, SetClientMonitoringState, ListAvailableEventResults`. Downloads/notebooks/timeline/secrets: `CreateDownloadFile, GetNotebooks, NewNotebook, UpdateNotebook, DeleteNotebook, NewNotebookCell, GetNotebookCell, UpdateNotebookCell, RevertNotebookCell, CancelNotebookCell, CreateNotebookDownloadFile, UploadNotebookAttachment, RemoveNotebookAttachment, AnnotateTimeline, GetSecretDefinitions, AddSecret, ModifySecret, GetSecret`. API-only: `VFSGetBuffer, Query, WatchEvent, PushEvents, WriteEvent, Scheduler, GetSubject, SetSubject, DeleteSubject, ListChildren, Check, LSP, GetKeywordCompletions, ReformatVQL`.

**`GetTableRequest`** (shared paging request for flow/hunt/notebook/timeline tables, repo: `api/proto/csv.proto`): `rows, start_row, start_time, end_time, client_id, flow_id, artifact, type, hunt_id, notebook_id, cell_id, cell_version, table_id, timeline, include_components[], skip_components[], columns[], sort_column, sort_direction, filter_column, filter_regex, stack_path[], org_id, timezone, version` → `GetTableResponse {columns, rows[{json}], total_rows, column_types, start_time, end_time, timelines[]}`. Practical pagination for a puller, though the same is achievable in pure VQL.

### 2.5 Server-side VQL catalog for enumeration (args verified from docs/source)

Reference index: https://docs.velociraptor.app/vql_reference/server/

| Plugin/function | Args | Returns |
|---|---|---|
| `clients()` | `search` ("label:x", "host:y"), `client_id` | ClientInfo rows (§1.2) |
| `client_info(client_id)` | | single ClientInfo |
| `client_metadata(client_id)` / `client_set_metadata(client_id, metadata=…)` | | dict |
| `flows(client_id, flow_id=, summary=)` | | ArtifactCollectorContext rows + `AvailableDownloads` |
| `flow_results(flow_id, client_id, artifact=, source=)` | | raw result rows |
| `flow_logs(client_id, flow_id)` | | log rows |
| `enumerate_flow(client_id, flow_id)` | | all files of a flow |
| `source(client_id=, flow_id=, hunt_id=, artifact=, source=, start_time=, end_time=, notebook_id=, notebook_cell_id=, notebook_cell_version=, notebook_cell_table=, start_row=, count=, orgs=[])` | | universal result reader (repo: `vql/server/flows/results.go`) |
| `hunts(hunt_id=, summary=)` / `hunt_info` / `hunt_update` | | Hunt rows |
| `hunt_flows(hunt_id, start_row=, limit=, basic_info=)` | | ClientId, FlowId, Fqdn, _OrgId, Flow |
| `hunt_results(hunt_id, artifact=, source=, orgs=[])` | | result rows + ClientId/FlowId/Fqdn |
| `uploads(client_id=, flow_id=, hunt_id=, notebook_id=)` | | upload rows (§6) |
| `monitoring(client_id, artifact, source=, start_time=, end_time=, start_row=)` | | event rows |
| `monitoring_logs(...)` | | event artifact logs |
| `watch_monitoring(artifact)` | | live stream (event query) |
| `send_event(artifact, row, client_id=)` | | inject into a queue |
| `timeline(timeline, components=[], skip=[], start=, notebook_id=)` / `timelines(notebook_id)` / `timeline_add(...)` / `timeline_delete(...)` | §3 | |
| `notebook_get/create/update/update_cell/delete/export` | §1.7 | |
| `label(client_id, labels=[], op=)` | | |
| `collect_client(...)`, `hunt(...)`, `hunt_add(...)`, `cancel_flow()` | §1.3/1.4 | write ops |
| `create_flow_download(client_id, flow_id, wait=, password=, format=, expand_sparse=, name=)` / `create_hunt_download(hunt_id, only_combined=, wait=, format=, base=, password=, expand_sparse=)` / `create_notebook_download(notebook_id, filename=)` | | export zips (repo: `vql/server/downloads/downloads.go`) |
| `artifact_definitions(...)`, `artifact_set/_delete/_set_metadata` | | |
| `orgs()`, `org()`, `org_create`, `org_delete` | §1.8 | |
| `server_metadata()` / `server_set_metadata()` | | server-level key/value store (used for webhook tokens etc.) |
| `gui_users(all_orgs=)`, `favorites_save/delete`, `whoami()`, `query(query=, env=, org_id=)` (run sub-query, incl. cross-org), `file_store(path=)`, `vfs_ls()`, `import_collection(filename=, client_id=)`, `backup/backup_restore`, `parallelize()` | | |

### 2.6 Alternative access paths

1. **Direct filestore/datastore reads** (§1.9) — offline-capable (`velociraptor fs`, `inspect`), but 0.75+ compression and internal layout churn make this brittle.
2. **Flow export zip** (`CreateDownloadFile` / `create_flow_download` / GUI "Prepare Download"), verified member list (repo fixture `vql/server/downloads/fixtures/`):
   `client_info.json`, `collection_context.json` (flow context), `requests.json`, `log.json`/`log.csv`, `results/<ArtifactName>.json` + `.csv` per artifact, `uploads.json` (+ `uploads.json.index`, `uploads.csv`), `uploads/<accessor>/<path>` (file bytes; sparse files get `uploads/sparse/...` + `.idx`).
3. **Hunt export zip**: `hunt_info.json`, `results/All <ArtifactName>.json|.csv` (combined), plus per-client subtrees `<Fqdn>-<ClientId>/` each shaped like a flow export. `only_combined=true` skips per-client trees.
4. **Notebook exports**: HTML report or zip (`notebook_export`) — the "create report" mechanism.
5. **Offline collector zips**: standalone collector output (results JSON + uploads); import server-side with `import_collection()` → becomes a normal flow on a (possibly auto-created) client.

---

## 3. Timelines & Super-timelines

Feature (current form) landed in **0.73**; main doc: https://docs.velociraptor.app/blog/2024/2024-09-12-timelines/ (concepts: *event* = Timestamp + Message + key/value data; *timeline* = named event series; *super-timeline* = set of timelines overlaid in the GUI; *Annotation* = special timeline holding analyst-curated events).

* **Storage:** per-notebook. Super-timeline metadata: datastore `notebooks/<nid>/<SuperTimelineName>.db` = `SuperTimeline {name, timelines: [Timeline]}`; `Timeline {id, start_time, end_time, size, rows, last_modified, timestamp_column, message_column, timestamp_description_column, active, version}` (repo: `timelines/proto/timelines.proto`). Each component timeline's data is a time-sorted filestore file `notebooks/<nid>/<SuperTimeline>/<Component>` with a binary time index (`.tidx`) enabling `SeekToTime` (repo: `timelines/`, `paths/timelines.go`).
* **Creating:** GUI "Add to Timeline" button on any notebook table (choose super-timeline, name, Timestamp column, Message column), or VQL:
  **`timeline_add(timeline=<supertimeline>, name=<component>, query={ SELECT ... }, key=<timestamp column>, message_column=, ts_desc_column=, notebook_id=)`** — creates the super-timeline if missing (requires NOTEBOOK_EDITOR in practice; docs page says READ_RESULTS). https://docs.velociraptor.app/vql_reference/server/timeline_add/
* **Reading:** **`timeline(timeline=<name>, components=[...], skip=[...], start=<time>, notebook_id=)`**. Row shape (verified, repo: `services/notebook/timelines.go:188` + `timelines/transformer.go`):
  `Timestamp` (the key, RFC3339 in JSON), `Message` (from message_column, else auto-built "k: v k: v …" truncated at 80 chars), `Description` (from ts_desc_column), **then all remaining original row columns**, and `_Source` = component timeline name. Rows stream merged across components in time order.
* `timelines(notebook_id=)` lists super-timelines; `timeline_delete(timeline=, notebook_id=, component=)` removes one.
* **Annotations:** gRPC `AnnotateTimeline(AnnotationRequest {timestamp, super_timeline, notebook_id, note, event_json})` copies an event into the reserved component **`Annotation`** (constant, repo: `constants/constants.go`), adding fields `Notes`, `_AnnotatedBy` (username), `_AnnotatedAt`, `_AnnotationID` (guid; re-annotating same ID updates/deletes). Verified sample row: `{Timestamp, Message, Description, <orig fields>, Notes, _AnnotatedBy, _AnnotationID, _Source:"Annotation"}` (repo fixture `services/notebook/fixtures/TestNotebookManagerTimelineAnnotations.golden`). The `Notebooks.Timelines` NOTEBOOK template creates a super-timeline notebook and includes a cell exporting the Annotation series for reporting.
* **For the Synapse service:** per-incident timelines live in notebooks → enumerate global notebooks (`notebook_get`/`GetNotebooks`), then `timelines(notebook_id)` → `timeline(...)` per super-timeline; `Timeline.timestamp_column/message_column` tell you the semantic mapping. To rebuild per-device timelines from raw data, use the same sources analysts use (`source()` over `Windows.Forensics.Usn`, `Windows.Timeline.Prefetch` (`event_time`), `Windows.Sys.Users` (`HomedirMtime`), event logs, etc.) keyed by their timestamp columns.
* **Timesketch:** built-in `Server.Utils.TimesketchUpload` (manual: notebook_id + supertimeline → sketch) and `Server.Monitoring.TimesketchUpload` (SERVER_EVENT, auto-uploads new timelines whose names match a regex) using the timesketch CLI clients (repo: `artifacts/definitions/Server/Monitoring/TimesketchUpload.yaml`).

---

## 4. Alerts / Findings

Velociraptor has **no first-class "finding" object**. The alerting building blocks in 0.7x:

1. **`alert()` VQL function** (any context: client artifact, server artifact, notebook, API). Signature (repo: `vql/functions/alerts.go`): `alert(name=<required>, dedup=<secs, default 7200, -1 disables>, condition=<expr>, **anything_else)`; extra kwargs become `event_data`. Dedup is keyed on alert name. Emits an `AlertMessage` routed to the **`Server.Internal.Alerts`** SERVER_EVENT queue. JSON schema (repo: `services/alerts.go`):
   `{"client_id", "name", "timestamp", "event_data": {...}, "artifact", "artifact_type", "flow_id", "assigned_user", "actioned"}` — `ClientId`/`Artifact`/`ArtifactType` passed inside event_data override scope values for source attribution. KB: https://docs.velociraptor.app/knowledge_base/tips/vql_alerts/ ; blog: https://docs.velociraptor.app/blog/2026/2026-04-19-alerts-and-email/
2. **Consumers** (all `watch_monitoring(artifact='Server.Internal.Alerts')` SERVER_EVENT artifacts):
   * `Server.Monitor.Alerts` (import via `Server.Import.Extras`; params `Secret` (SMTP), `Recipients`, `SeverityTransforms`, `SeverityThreshold`, `ContextInclude/Exclude`, `FlattenContext` (dotted keys, default on)) → email per alert. *Severity is just a convention carried in event_data, not a core field.*
   * `Server.Monitor.Alerts.UserMessage` (Exchange) → in-GUI user messages (0.77 added `user_message()`/`user_messages()` VQL and a GUI message center).
   * `Server.Alerts.Notification` / `Server.Alerts.ProcessCreation` / `Server.Alerts.PsExec` / `...TheHive` → webhook (Slack/Teams/Discord/TheHive) forwarders (repo: `artifacts/definitions/Server/Alerts/`). Message format example: `Alert: %name | Details: %event_data | Artifact: %artifact | ClientId: %client_id | Timestamp: %timestamp`.
   * `Server.Monitor.Errors.Alert` / `Server.Monitor.Client.Errors.Alert` turn monitoring-artifact errors into alerts.
3. **Detection-shaped data besides alert():**
   * **Event monitoring results** — any CLIENT_EVENT detection artifact (e.g. `Windows.Detection.ProcessCreation`, ETW/Sigma live sources added in 0.74) writes rows into `clients/<id>/monitoring/<Artifact>/<day>.json`; read with `monitoring()`/`source(start_time=)`, tail with `watch_monitoring()`.
   * **Sigma**: since 0.74 a reworked Sigma editor + curated Sigma artifact packs (external "Velociraptor Sigma Project", imported via `Server.Import.Extras`/`Server.Import.ArtifactBundle`); Sigma hit rows carry the rule metadata (title, level, etc.) as columns.
   * **Hunt results flagged by analysts** — no flag field exists; analysts express triage via **notebook cells**, **timeline annotations** (§3), and **client labels** (e.g. label `Compromised`). Labels are the de-facto tagging mechanism; `LabelClients`/`label()` + `last_label_timestamp`.
   * **Client metadata** key/values can also carry case fields.
4. **Suggested Synapse mapping:** ingest `Server.Internal.Alerts` rows (name → risk/alert node, event_data → props, client_id/flow_id/artifact → edges), monitoring detection artifacts (per-artifact schemas), timeline Annotation rows (analyst assertions), and labels (tags on host nodes).

---

## 5. Key Artifact Output Schemas

All column lists below were extracted **verbatim from the artifact YAML `SELECT` clauses** in the repo (`artifacts/definitions/...`) at the current master (0.77-era) unless noted. Browse definitions: https://github.com/Velocidex/velociraptor/tree/master/artifacts/definitions and rendered reference pages at https://docs.velociraptor.app/artifact_references/ . Column *types* are dynamic (VQL is schemaless); `column_types` hints exist on some artifacts; dicts/arrays serialize as nested JSON.

**⚠️ 0.75 artifact exodus:** `Windows.KapeFiles.Targets` → **`Windows.Triage.Targets`** (Velociraptor Triage project, https://github.com/Velocidex/velociraptor-triage-collector), `Generic.Forensic.SQLiteHunter` (browser/sqlite artifacts) → SQLiteHunter project, Registry analysis → **Registry Hunter** project (`Windows.Registry.Hunter`), Sigma artifacts → Sigma project, community artifacts → Artifact Exchange. All installable via `Server.Import.Extras` / `Server.Import.ArtifactBundle`; after import they behave like built-ins. A puller must therefore treat the artifact namespace as open-ended and read schemas from `artifact_definitions()` + observed columns.

### Generic.Client.Info (interrogation)
* Source `BasicInformation`: `Name, BuildTime, Version, build_url, install_time, Labels, Hostname, OS, Architecture, Platform, PlatformVersion, KernelVersion, Fqdn, MACAddresses`.
* `DetailedInfo`: `Param, Value` (flattened `info()`); `WindowsInfo`: `Computer Info {DNSHostName, Name, Domain, TotalPhysicalMemory, DomainRole}`, `Network Info {Caption, IPAddresses, IPSubnet, MACAddress, DefaultIPGateway, DNSHostName, DNSServerSearchOrder}`; `LinuxInfo` similar; `Users` (Windows): `Name, Description, LastLogin`.

### Windows.System.Pslist (processes)
`CreateTime, Pid, Ppid, TokenIsElevated, Name, CommandLine, Exe, TokenInfo (dict), Hash {MD5, SHA1, SHA256}, Authenticode {Filename, ProgramName, PublisherLink, IssuerName, SubjectName, Timestamp, Trusted, …}, Username, WorkingSetSize`. Params incl. regex filters, `UseTracker`, `UntrustedAuthenticode`.

### Linux.Sys.Pslist (aliased MacOS.Sys.Pslist)
`Pid, Ppid, Name, CommandLine, Exe, Hash {MD5,SHA1,SHA256}, Username, CreateTime, RSS, Deleted (bool)`.

### Windows.Network.Netstat
`Pid, Name, Family (IPv4/IPv6), Type (TCP/UDP), Status (ESTAB/LISTEN/…), Laddr.IP, Laddr.Port, Raddr.IP, Raddr.Port, Timestamp` (socket creation). **Windows.Network.NetstatEnriched** source `Netstat`: `Pid, Ppid, Name, Path, CommandLine, Hash, Username, Authenticode, Family, Type, Status, Laddr (IP), Lport, Raddr, Rport, Timestamp` (+ optional `KillProcess`, `DumpFile`).

### Windows.Sys.Users (profiled local users)
`Uid (RID), Gid, Name (SID lookup), Description (ProfileList key path), Directory (profile dir), UUID (SID), Mtime (key mtime), HomedirMtime, Data {ProfileLoadTime, ProfileUnloadTime}`. (`Windows.Sys.AllUsers` for NetUserEnum-based list; Linux equivalent `Linux.Sys.Users`: `User, Description, Uid, Gid, Homedir, Shell`.)

### Windows.Forensics.Prefetch
`Executable, FileSize, Hash (prefetch path hash, hex), Version (WinXP/Vista/Win8.1/Win10/Win11), LastRunTimes (array of timestamps, up to 8), RunCount, ExecutablePath, ExecutableDosPath, OSPath (.pf path), PrefetchFileName, CreationTime, ModificationTime, Binary, FilesAccessed (opt), VolumeInfo (opt)`. (`Windows.Timeline.Prefetch` flattens to one row per `event_time` for timelining.)

### Windows.Forensics.Usn ($UsnJrnl)
`Timestamp, Filename, OSPath (drive+path), _Links, Reason (list), MFTId, Sequence, ParentMFTId, ParentSequence, FileAttributes, SourceInfo, Usn`. (Live-monitor variant: `Windows.Detection.Usn`.)

### Windows.NTFS.MFT ($MFT)
`EntryNumber, InUse, ParentEntryNumber, OSPath, _Links, FileName, FileSize, ReferenceCount, IsDir, Created0x10, Created0x30, LastModified0x10, LastModified0x30, LastRecordChange0x10, LastRecordChange0x30, LastAccess0x10, LastAccess0x30, HasADS, SI_Lt_FN, USecZeros, Copied, FileNames, FileNameTypes` (0x10 = $STANDARD_INFORMATION, 0x30 = $FILE_NAME).

### Windows.EventLogs.Evtx (generic EVTX parse)
All `parse_evtx()` columns — notably the nested `System` dict (`Provider`, `EventID.Value`, `TimeCreated.SystemTime`, `Channel`, `Computer`, `Security.UserID`, `EventRecordID`, …) and `EventData`/`UserData` dicts — plus flattened `TimeCreated, Channel, EventRecordID, EventID, OSPath`. **Windows.EventLogs.EvtxHunter** (IOC regex hunt across EVTX): `EventTime, Computer, Channel, Provider, EventID, EventRecordID, UserSID, Username, EventData (dict), UserData (dict), Message, OSPath`. Many purpose-built `Windows.EventLogs.*` (AlternateLogon, RDPAuth, PowershellScriptblock, ScheduledTasks, Cleared, …) each project their own columns from the same `System`/`EventData` base.

### Windows.Detection.Yara.* (Yara scanning)
* `Windows.Detection.Yara.Process`: `ProcessName, ExePath, CommandLine, Pid, Rule, Tags, Meta (dict), YaraString, HitOffset, HitContext (upload of matched bytes)` (+ `ProcessDump` upload if enabled).
* `Windows.Detection.Yara.NTFS`: `FileName, OSPath, Size, ModTime, Rule, Tags, Meta, YaraString, HitOffset, HitContext` (+ `Upload` when UploadHits). 0.77 note: `Generic.Detection.Yara.Glob` takes `YaraUrl` instead of inline rules.

### Windows.KapeFiles.Targets (≤0.74 built-in; now Windows.Triage.Targets — same shape)
Wraps `Generic.Collectors.File`. Source **`All File Metadata`**: `Created, Changed, LastAccessed, Modified, Size, SourceFile`. Source **`Uploads`**: `CopiedOnTimestamp, SourceFile, DestinationFile, FileSize, SourceFileSha256, Created, Changed, Modified, LastAccessed`. Parameters are the KAPE target checkboxes (`_SANS_Triage`, `EventLogs`, …) + `Device`, `VSSAnalysisAge`.

### Scheduled tasks — Windows.System.TaskScheduler
Source `Analysis`: `TaskName (URI), Mtime, Command (expanded), Arguments, UserId, RunLevel, LogonType, StateChange, ComHandler, RegistrationTime, StartBoundary, _XML, OSPath, Authenticode, Upload (opt)`. (Also `Windows.EventLogs.ScheduledTasks` for historical task events.)

### Services — Windows.System.Services
`State, Name, DisplayName, Status, Pid, ExitCode, StartMode, PathName, ServiceType, UserAccount, Created (reg key mtime), ServiceDll, FailureCommand, FailureActions, AbsoluteExePath` + optional `HashServiceExe, CertinfoServiceExe, HashServiceDll, CertinfoServiceDll`. Linux: `Linux.Sys.Services`.

### Autoruns — Windows.Sysinternals.Autoruns
Executes `autorunsc.exe -nobanner -accepteula -t -a <flags> -c -h -s '*'` and parses its CSV, so columns are the Sysinternals CSV set: `Time, Entry Location, Entry, Enabled, Category, Profile, Description, Company, Image Path, Version, Launch String, MD5, SHA-1, PESHA-1, PESHA-256, SHA-256, IMP` (representative — from autorunsc, not hardcoded in YAML). Pure-VQL alternatives: `Windows.Persistence.*`, Registry Hunter.

### Browser history
Built-in `Windows.Applications.Chrome.History` (also `Edge`, `Firefox` dirs): per-user SQLite parse → `User, url_id, visit_time, title, visit_count, typed_count, last_visit_time, hidden, Source (Synced/Local/Extension/Import…), from_url_id, visit_duration, transition, OSPath`. The more complete cross-browser set (`Generic.Forensic.SQLiteHunter`, covering Chrome/Firefox/Safari/Edge history+cookies+downloads) moved to the **SQLiteHunter** project in 0.75 (https://github.com/Velocidex/SQLiteHunter).

### Windows.Registry.*
Built-ins remaining: `Windows.Registry.NTUser` (globs NTUSER.DAT via raw reg accessor → `OSPath, Data, Mtime` style glob columns), `UserAssist` (`Name, User, Path, LastExecution, LastExecutionTS, NumberOfExecutions, RunCounter`—representative), `AppCompatCache` (`Position, Name, Time, …`), `RecentDocs`, `RDP`, `PortProxy`, `MountPoints2`, `TaskCache`, `WDigest`. The deep registry forensic coverage is now **Windows.Registry.Hunter** (external). Treat registry artifact columns as artifact-specific; read from `artifact_definitions()`.

### Other notable IR artifacts (built-in, 0.77)
`Windows.Forensics.Amcache`, `.Bam` (`SID, UserName, Binary, Bam_time`—representative), `.JumpLists`, `.Lnk`, `.RecycleBin`, `.SAM`, `.SRUM` (network/app usage), `.Shellbags`, `.UserAccessLogs` (UAL), `.RDPCache`; `Windows.Memory.Acquisition` (winpmem); `Windows.System.DNSCache`, `.Handles`, `.Shares`, `.LocalAdmins`; `Windows.Sysinternals.SysmonInstall`/ETW live sources; `Exchange`/community: via Artifact Exchange (https://docs.velociraptor.app/exchange/) — e.g. `Windows.EventLogs.Hayabusa`, `Windows.Detection.PsExec`, MISP/TheHive forwarders. MacOS: `MacOS.Sys.*`. Linux triage: `Linux.Triage.UAC` (external, 0.75+), `Linux.Sys.BashHistory/Crontab/LastUserLogin/LogHunter`, `Linux.Network.Netstat*`.

### System.VFS.* (GUI plumbing, useful to know)
`System.VFS.ListDirectory` → `_OSPath, _Components, _Accessor, _Data, Name, Size, Mode, mtime, atime, ctime, btime, _Idx`; `System.VFS.DownloadFile` → `Path, Accessor, Size, Upload, Sha256, Md5, …`.

---

## 6. Uploaded Files (collected file content)

* **Where bytes live:** `clients/<ClientId>/collections/<FlowId>/uploads/<accessor>/<sanitized path components>` (filestore BULK_DATA; chunk-compressed on disk since 0.75). Sparse uploads add a sibling `.idx`.
* **Upload metadata result set** `collections/<FlowId>/uploads.json` — row schema (verified, repo: `flows/client_flow_runner.go:474`):

| Column | Meaning |
|---|---|
| `Timestamp` | epoch secs (server receipt) |
| `started` | string time |
| `vfs_path` | visible VFS path of the stored file |
| `Type` | `""` normal, `"idx"` for sparse index rows |
| `_Components` | filestore path components of the stored file (**use these with `VFSGetBuffer`**) |
| `file_size` | original file size |
| `uploaded_size` | bytes actually stored |
| `_accessor` | client accessor used (file/ntfs/auto/…) |
| `_client_components` | original path components on the client |

* **`uploads()` plugin output** (repo: `vql/server/flows/uploads.go`): passes through the metadata rows, replacing `vfs_path` with a pathspec object, adding `client_path` (original client path) and an `Upload` object `{Path, Size, StoredSize, Components, Accessor}`; in hunt mode each row additionally gets `ClientId` and `FlowId`. Notebook mode rows: `notebook_id, name, started, file_size, uploaded_size, vfs_path, client_path, Upload`.
* **Hashes:** the upload metadata has **no hashes**. Hashes exist when (a) the artifact computed them as columns (e.g. `SourceFileSha256` in Triage/KapeFiles Targets, `Hash` in Pslist), or (b) the file came via the **VFS download** path — `VFSDownloadInfo {vfs_path, name, size, mtime, sparse, MD5, SHA256, components[], flow_id, in_flight, error}` (repo: `flows/proto/vfs.proto`, gRPC `VFSStatDownload`). Also `upload()`'s returned `Upload` object includes `sha256`/`md5` in many artifacts' columns. Otherwise hash server-side: `SELECT hash(path=file_store(path=vfs_path)) ...` (post-0.75: `copy()` first).
* **Retrieval via API:** `VFSGetBuffer(client_id, components=<_Components>, offset, length)` chunked reads (pyvelociraptor `fetch.py`); or create a flow export and download the zip (`fetch_flow_uploads.py`); or `file_store(path=…)` server-side VQL (returns server filesystem path; broken by 0.75 compression — use `copy()`).
* **Upload completion event:** `System.Upload.Completion` rows: `Timestamp, ClientId, VFSPath, UploadName, Accessor, Size, UploadedSize` — push trigger for per-file ingestion (repo: `flows/client_flow_runner.go:455`).
* 0.75+ **resumable uploads**: `UPLOAD_IS_RESUMABLE=TRUE` makes `upload()` async via upload transactions (`upload_transactions.json`); flows may be WAITING while uploads complete.

## 7. VFS (client filesystem browsing data)

Docs: https://docs.velociraptor.app/docs/gui/vfs/ (see also /docs/clients/vfs/, /docs/file_collection/vfs/). The VFS is a **server-side cache** of directory listings/downloads produced by `System.VFS.ListDirectory` / `System.VFS.DownloadFile` flows; top-level trees per accessor (`auto`, `file`, `ntfs`, `registry`). Datastore: `clients/<id>/vfs/<accessor>/<components>.db` (listing metadata referencing the backing flow result set), `clients/<id>/vfs_files/...` (`VFSDownloadInfo` records incl. MD5/SHA256). gRPC: `VFSListDirectory`/`VFSStatDirectory` (→ `VFSListResponse {Response (JSON rows), Columns, total_rows, client_id, flow_id, artifact, start_idx, end_idx, download_version}`), `VFSListDirectoryFiles`/`GetTable` (paged rows incl. `Name, Size, Mode, mtime/atime/ctime/btime, Download info`), `VFSRefreshDirectory` (schedules new listing flow), `VFSDownloadFile`, `VFSStatDownload`, `VFSGetBuffer`. For a Synapse puller the VFS is secondary — the same data arrives as ordinary `System.VFS.*` flow results; ingest those like any artifact and you get VFS coverage for free.

## 8. Existing Integrations (inspiration for the Synapse model)

| Integration | Mechanism | Notes |
|---|---|---|
| **velociraptor-to-timesketch** (ReconInfoSec) https://github.com/ReconInfoSec/velociraptor-to-timesketch | Server artifact uploads KapeFiles.Targets triage zip → S3 → watcher scripts → log2timeline/plaso → timesketch_importer | Batch, file-level; inotify watchers |
| **Built-in Timesketch artifacts** | `Server.Utils.TimesketchUpload` (manual) / `Server.Monitoring.TimesketchUpload` (auto on new timelines) | Maps super-timeline rows → sketch; closest analogue to the Synapse timeline mapping |
| **Elastic.Flows.Upload** (built-in SERVER_EVENT) | watches `System.Flow.Completion`, `elastic_upload()`s all rows of matching artifacts, index per artifact name | Warning in artifact: schemaless artifacts (EventData!) break ES mappings — relevant lesson for Synapse form design |
| **Splunk.Flows.Upload**, **ADX.Flows.Upload** (0.77), **LogScale.Events.Clients** | same flow-completion pattern → `splunk_upload()`, `adx_upload()`, HEC | The canonical "pull everything on completion" reference implementations |
| **Hayabusa→Timesketch super-timeline** blog https://freedurok.github.io/posts/01_velociraptor-to-timesketch | hunt → `Windows.EventLogs.Hayabusa` → Timesketch | |
| **LimaCharlie Velociraptor extension** https://docs.limacharlie.io/docs/velociraptor | runs Velociraptor collections through LC sensors | |
| **OpenCTI / MISP** | **No first-party connector exists** (searched 2026-10). Community options: Artifact Exchange forwarders (e.g. `Server.Alerts.TheHive.Alert`), MISP-related exchange artifacts, custom scripts via pyvelociraptor | The Synapse service would be the first real graph/intel mapping |

**Pattern to copy:** a SERVER_EVENT "forwarder" artifact (`watch_monitoring(artifact='System.Flow.Completion')` → enumerate `Flow.artifacts_with_results` → `source()` each → push) is the idiomatic push integration; a pure external puller via gRPC `Query()` (clients/flows/hunts/source/uploads/timeline plugins) is the idiomatic pull integration. A robust Synapse service should do both: full backfill via pull, live sync via `watch_monitoring` on `System.Flow.Completion`, `System.Upload.Completion`, `Server.Internal.Alerts`, and per-detection event artifacts.

---

## 9. Gotchas

1. **Version churn is real.** 0.75 compressed the filestore (breaks `file_store()` reads → use `copy()`; raw JSON files unreadable → `fs zcat`), and evicted KapeFiles/SQLiteHunter/Registry/Sigma artifacts to external packs (names changed: `Windows.KapeFiles.Targets` → `Windows.Triage.Targets`). 0.77 split flow requests out of the flow object, enforces size limits on hunt/flow/task objects, removed `Server.Internal.Enrollment/Label/Ping/Pong/Notifications/TimelineAdd/FrontendMetrics` and `System.Hunt.Participation`, renamed `Server.Import.ArtifactExchange` → `Server.Import.ArtifactBundle`, and changed `cache()`/`memoize()` semantics. Pin behavior per server version; discover schemas at runtime via `artifact_definitions()`.
2. **API cert expires in 1 year**; regenerate proactively. `grpc.ssl_target_name_override` must be `VelociraptorServer` when connecting by IP. `API.hostname`/bind address must be set before minting configs (connection string is baked in).
3. **`acl grant` replaces roles** (doesn't append) and CLI grants need a server restart; GUI/VQL (`user_grant()`) grants don't. Minimum for Query() is the `api` role; add `reader`/`analyst`/`investigator` per need. Don't give integrations `administrator` — an API key is as powerful as its roles (VQL can `execve` on the server with the right perms).
4. **No cursors on Query()** — results stream in `max_row` batches; long streams can be interrupted, so for large tables page explicitly (`source(start_row=, count=)`) and checkpoint. `watch_monitoring` queries never end — run them on dedicated channels with gRPC keepalives; on reconnect you may miss events (re-read via `monitoring(start_time=)` to backfill — queues are backed by the day-partitioned files).
5. **Timestamps come in mixed units**: proto `uint64` epochs are mostly **microseconds** (flow create/start/active_time, hunt create_time, ping), some are seconds (uploads.json `Timestamp`, `_ts` on event rows), `execution_duration` is nanoseconds; JSON rows often carry RFC3339 strings. Normalize defensively per-field.
6. **VQL injection**: never interpolate user data into VQL text — pass `env` and reference by name.
7. **Schemaless rows**: artifact columns can change between artifact versions, OS versions, and custom overrides (`Custom.<Name>` artifacts shadow built-ins); `EventData` style dict columns have unstable inner shape (this is exactly what breaks the Elastic uploader). Model nested dicts as JSON props, not fixed fields.
8. **Docs vs code drift**: the VQL reference pages omit output columns and have minor arg errors (`flow_results.flow_id` described as "hunt id"; `source()` prose uses `notebook_cell` but the arg is `notebook_cell_id`). The proto files + plugin Go sources (cited above) are authoritative.
9. **uploads have no hashes** in metadata (§6) — plan a hashing step (server-side VQL hash of stored file, or rely on artifact-level hash columns / VFSDownloadInfo).
10. **Flow objects truncate** `uploaded_files` and `logs` for big flows — always use `uploads()` / `flow_logs()` result sets, not the context fields.
11. **Hunt result naming**: multi-source artifacts need `artifact='Name/Source'` or `source=` in `source()`/`flow_results()`/`hunt_results()`; `artifacts_with_results` gives the exact strings. Hunt stats may lag (0.77 removed the housekeeping thread; recalculation is on demand — `hunt_update(recalculate=)`/GUI).
12. **Orgs**: every API call is org-scoped (`org_id` in VQLCollectorArgs, `O...` ids, root = empty); enumerate orgs first (`orgs()`), ensure the API principal has roles in each org, and iterate — or use `orgs=[...]` args on `source()`/`hunt_results()` and `query(org_id=)`.
13. **Deleted/archived things**: hunts have `ARCHIVED/DELETED` states; flows can be deleted (`delete_flow`) leaving dangling references; clients can be deleted (`client_delete`). Handle missing-subject errors gracefully.
14. **Monitoring data retention**: event files are per-day JSON; old days may be pruned by ops scripts — ingest incrementally with `start_time` watermarks.
15. **Notebook cell data** is versioned (`current_version`, `available_versions`) — when scraping notebook tables pass `notebook_cell_version` or you may read stale tables.
16. **gRPC message sizes**: responses are chunked by `max_row`/`max_row_buffer_size` (5MB default) which stays under the default 4MiB gRPC cap in most cases, but set generous `grpc.max_receive_message_length` client-side for safety with wide rows.
17. The GUI's REST API and the datastore layout are **explicitly unstable**; the stable contracts are: the gRPC `Query()` + VQL plugins, the proto schemas, and the export zip formats.
