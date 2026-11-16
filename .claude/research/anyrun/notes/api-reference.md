# ANY.RUN API: implementer's reference (Sandbox + Threat Intelligence)

Compiled 2026-11-02 from primary sources only. Nothing here comes from memory or third-party clients.

## 0. Sources and confidence markers

| Tag | Source |
|---|---|
| **[SPEC]** | Official OpenAPI 3.1 specs that render https://any.run/api-documentation/ (a Scalar viewer). The page's inline script sets `API_VERSIONS = {Sandbox: {v1: SandboxV1.json}, "Threat Intelligence": {v1: TIV1.json}}`. The specs are at `https://files.any.run/schema/SandboxV1.json` (sha256 `dee91bf8…c293f0`) and `https://files.any.run/schema/TIV1.json` (sha256 `dfa3ebf8…fdc24`). **v1 is the only published version** for both products: `SandboxV2.json` and `TIV2.json` return 404. |
| **[SDK]** | Official `anyrun-sdk` 1.16.0 sdist from PyPI (2026-10-22), read as source and not executed. Some notes also come from 1.14.19 and 1.10.10 for history. |
| **UNVERIFIED** | Not stated by either source, or stated in a way that is inconsistent. Treat it as a guess and code defensively. |

The specs are at https://files.any.run/schema/SandboxV1.json and https://files.any.run/schema/TIV1.json, and the SDK is the `anyrun-sdk` sdist on PyPI. Neither is copied here.

No live call was made (api.any.run is blocked from here and there is no key).

---

## 1. Hosts, base URLs, versions

| Purpose | Base | Source |
|---|---|---|
| Sandbox API | `https://api.any.run/v1` (spec `servers: https://api.any.run`, paths start `/v1/...`) | SPEC + SDK `ANY_RUN_API_URL='https://api.{root_url}/v1'` |
| Sandbox reports (IOC / summary / AI / tier1) | `https://api.any.run/report` (paths `/report/{taskUuid}/...`; **no `/v1`**) | SPEC + SDK `ANY_RUN_REPORT_URL` |
| Content downloads (pcap, sample files, video, screenshots, dumps, sslkeys) | `https://content.any.run/tasks/{taskUuid}/download/...` | SPEC (URL patterns inside report schemas) + SDK `ANY_RUN_CONTENT_URL` |
| Web UI links | `https://app.any.run/tasks/{taskUuid}` | SPEC (pattern of `related` / `permanentUrl`) |
| Threat Intelligence (Lookup, YARA, TAXII feeds) | `https://api.any.run/v1` (spec `servers: https://api.any.run/v1`; paths `/intelligence/...`, `/feeds/...`) | SPEC + SDK |
| TI web UI lookup link | `https://intelligence.any.run/analysis/lookup#{%22query%22:%22<value>%22,%22dateRange%22:180}` | SDK `LookupSummary.intelligence_url` |

The SDK `root_url` (default `any.run`) is substituted into all four hosts, which is presumably for on-prem or white-label deployments. Every URL above is `https://<sub>.<root_url>/...`.

**Paths with and without a trailing slash.** The spec writes `/v1/analysis/`, `/v1/environment/` and `/v1/user/` with a trailing slash. The SDK calls `/v1/analysis`, `/v1/environment` and `/v1/user` without one. Both forms are evidently accepted, though only the SDK form is proven by working code.

**History of v1 and "v2".** There is no v2 API in either source. The deprecations that do exist are listed here.
- **Legacy TI Feeds endpoints** `GET /v1/feeds/stix.json`, `/v1/feeds/misp.json` and `/v1/feeds/network_iocs.json` existed in SDK ≤1.10.10. The SDK already marked `stix.json` "DEPRECATED: please, use get_taxii_stix_async instead". All three are **gone from SDK 1.14.19 and 1.16.0** and are **absent from the current spec**. The current feeds API is TAXII 2.1 only (§5). See §5.6 for the legacy parameters, in case they are still needed.
- **Legacy auth.** Up to SDK 1.10.x, feeds used `Authorization: Basic <base64>`. In 1.16.0 that is "supported only for backward compatibility and will be removed in future releases" (§2).
- **Deprecated environment types.** `env_type` values `clean` and `office` are "deprecated starting June 2, 2025" [SPEC]. `obj_ext_elevateprompt` is deprecated in favour of `obj_force_elevation` [SPEC].

---

## 2. Authentication (all endpoints)

### Header format

```
Authorization: API-Key <token>
```

- [SPEC TI] "The value must include the literal prefix `API-Key ` (note the trailing space) followed by your token. Example: `Authorization: API-Key abcdef1234567890abcdef1234567890`."
- [SPEC Sandbox] securitySchemes: `API-Key` is an apiKey in the `Authorization` header, described as "Prefix the API key value with "API-Key"". `Basic` is HTTP Basic. Global `security: [{API-Key: []}, {Basic: []}]`, so either scheme is accepted. Basic means username and password, which is not useful for a service and is UNVERIFIED in detail.
- [SDK] `_api_key_validator`: if the key does not start with `api-key` or `basic` (case-insensitive), it sends `'API-KEY ' + api_key`. Note the upper-case `API-KEY`, so **the prefix match is case-insensitive server-side**. Keys that already carry an `API-Key …` or `Basic …` prefix are passed through verbatim with a deprecation warning: "API keys with a prefix and access to TI Feeds via Basic Authentication are supported only for backward compatibility and will be removed in future releases."
- The same API key works for Sandbox, TI Lookup, YARA and TAXII feeds [SDK: every connector uses the same header]. Whether a key is *licensed* for each product is a separate check (see the errors below).

### Extra headers the SDK sends (optional, informational)

```
x-anyrun-connector: <integration name>   # SDK default "Public:<python version>", e.g. "Public:3.11.6"
x-anyrun-sdk: anyrun_sdk:1.16.0
```

These are not in the spec. Using `x-anyrun-connector: <YourIntegrationName>` is harmless, but UNVERIFIED as to whether the server needs it.

### Teamspace scope (SDK 1.16.0 only, not in spec, UNVERIFIED server-side semantics)

The connector can carry `teamId`, `customerId` and (sandbox only) `caseId`.

- On **POST** these go **in the body**: as JSON keys, or as extra multipart form fields for file uploads.
- On **GET** they are **appended as query params**.
- They are not added to PATCH or DELETE.
- They are explicitly *not* applied (`scoped=False`) to `GET /v1/analysis` (history) and `GET /v1/user` (limits).

### Key-check endpoint (SDK only)

- `GET https://api.any.run/v1/intelligence/keycheck` is used by the Lookup and YARA connectors' `check_authorization`. The SDK docstring says it "does not consume the license". It only checks for HTTP 200/201/202. **Not in spec; response body UNVERIFIED.**
- The Sandbox connector checks a key with `GET /v1/analysis` (history). The Feeds connector checks with a TAXII objects call.

---

## 3. Error handling (all APIs)

### 3.1 Sandbox error envelope [SPEC `ErrorDocumentDto`]

```json
{"error": true, "message": "Task not found"}
```

Required fields: `error` (const `true`) and `message` (string). Spec responses are declared as `4XX` with this schema. The HTTP status is in the example name:

| HTTP | message (exact strings from spec examples) | When |
|---|---|---|
| 403 | `Authorization required` | no auth |
| 403 | `Wrong authorization data` | bad key |
| 403 | `WOW! We can't recognize you! Please contact us support@any.run` | unrecognised user |
| 403 | `API is not available on the free plan` | free plan |
| 403 | `API is disabled in your account` | |
| 403 | `You can't access to this task` | task owned by someone else / private |
| 403 | `Requires an active subscription to a Hunter or Enterprise plan` | plan gating (submit, IOC, AI, tier1) |
| 400 | `This feature is not available for your plan` | plan gating |
| 400 | `Users with the branded reports feature enabled cannot create public tasks.` | submit with `opt_privacy_type=public` |
| 403 | `Private content` | IOC endpoint on private task |
| 403 | `You must use your personal login data or API key for this type of request` | (example `ErrorExample_403_IntelError`, not wired to a path) |
| 404 | `Task not found` | |
| 404 | `User not found` | (example present, not wired to a path) |
| 400 | `Invalid task uuid in request` | |
| 400 | `Task {taskUUID} has already been completed` | addtime / stop |
| 400 | `Task is still running` | delete / AI / tier1 on a running task |
| 429 | `AI Summary limit exceeded` | `/report/{uuid}/ai` |

Success documents use `{"error": false, "data": {...}}` or `{"error": false, "message": "..."}`.

**Note.** The spec's queued-submit example literally contains `"error": "false,"`, which is a string and a docs typo. Do not test `error is False` strictly. Branch on HTTP status, then on the presence of `data.taskid` versus `data.queueTaskId`.

### 3.2 TI error envelope [SPEC `ErrorDto`]

```json
{"message": "The query syntax is incorrect.", "code": "WRONG_QUERY_ERROR"}
```

Required fields: `message` and `code`. There is **no `error` boolean.** Some responses add fields: `validationErrors: [{field, error}]` on 400 and `nextAvailableRequestDate` (ISO date-time) on 429.

Shared 401 responses (`components/responses/Unauthorized`, content `application/json` ErrorDto):

| code | message |
|---|---|
| `AUTH_REQUIRED_ERROR` | `Authorization is required to access this resource.` (no Authorization header) |
| `WRONG_AUTH_DATA_ERROR` | `The provided authorization data is incorrect.` (malformed / missing `API-Key` prefix) |
| `API_KEY_ERROR` | `Invalid API key. Please use your correct API key for this request.` |
| `UNRECOGNIZED_USER_ERROR` | `Unrecognized user. Please verify your credentials or contact support.` |

Shared 402 responses (`PaymentRequired`):

| code | message |
|---|---|
| `EXPIRED_LICENSE_ERROR` | `Your license has expired. Please renew it from support@any.run.` |
| `LIMIT_EXCEEDED_ERROR` | `You have exceeded the request limit for your license. Please acquire more limit from support@any.run.` ("per-window request limit… retry after the window resets") |
| `QUOTA_EXCEEDED_ERROR` | `You have exceeded your request quota. Please acquire quota from support@any.run.` (total plan quota exhausted) |
| `LICENSE_REQUIRED_ERROR` | `Your license is not active. Please acquire a valid license from support@any.run.` |

There are endpoint-specific codes too; see §4 and §6. TAXII has its own two error shapes (§5.5). YARA query-param validation uses the NestJS shape `{"statusCode":400,"message":["offset must be a number"],"error":"Bad Request"}`.

### 3.3 SDK behaviour (what to mirror)

- `_check_response_status` accepts HTTP 200/201/202 only. Anything else raises `RunTimeException(response.get('message') or response.get('description'), status)`. It **does not inspect the `error` flag**.
- On parse errors or exceptions it wraps everything in `RunTimeException('Unknown error: …')`. Connection errors become `'Connection error: …'`.
- **No retries, no backoff, no rate-limit handling** in the SDK. The default total timeout is 300 s (`DEFAULT_REQUEST_TIMEOUT_IN_SECONDS`).
- Recommended for a client: treat non-2xx as error. Pull `message` (Sandbox/TI), `code` (TI), `description` (TAXII business errors) or `message` (TAXII auth errors). Remember that error bodies can be either `application/json` or `application/taxii+json;version=2.1`, so parse JSON regardless of content type.

### 3.4 Rate limits

- **Sandbox:** `GET /v1/user` returns per-minute, hour, day and month limits for `api` and `web`, plus parallel-task slots (§4.9). The spec does not document a sandbox 429 except for the AI summary. What happens when a limit is exceeded is **UNVERIFIED**; there are no rate-limit response headers in the spec. A submit while slots are full is **queued** (202 + `queueTaskId`) rather than rejected [SPEC].
- **TI Lookup:** 429 `{"message":"Too many requests. Try later.","code":"TOO_MANY_REQUESTS","nextAvailableRequestDate":"2026-06-04T12:00:00.000Z"}`. Sleep until `nextAvailableRequestDate`. 402 `LIMIT_EXCEEDED_ERROR` / `QUOTA_EXCEEDED_ERROR` are license-window and quota exhaustion, which are not retriable soon.
- **YARA:** 403 `YARA_DISABLED_ERROR` is "trial request quota used up". No 429 is documented.
- **TAXII:** none documented.

---

## 4. Sandbox API

### 4.1 Endpoint summary

| # | Method | URL | operationId | Success |
|---|---|---|---|---|
| 1 | GET | `https://api.any.run/v1/analysis/` | GetAnalysesHistory | 200 |
| 2 | POST | `https://api.any.run/v1/analysis/` | RunNewAnalysis | 201 (started) / 202 (queued) |
| 3 | GET | `https://api.any.run/v1/analysis/{taskUuid}` | GetAnalysisReport | 200 |
| 4 | PATCH | `https://api.any.run/v1/analysis/addtime/{taskUuid}` | ProlongAnalysis | 202 |
| 5 | PATCH | `https://api.any.run/v1/analysis/stop/{taskUuid}` | StopAnalysis | 202 |
| 6 | DELETE | `https://api.any.run/v1/analysis/delete/{taskUuid}` | DeleteAnalysis | 202 |
| 7 | GET | `https://api.any.run/v1/analysis/monitor/{taskUuid}` | GetAnalysisStatusStream (SSE) | 200 `text/event-stream` |
| 8 | GET | `https://api.any.run/v1/environment/` | GetEnvironment | 200 |
| 9 | GET | `https://api.any.run/v1/user/` | GetUserLimits | 200 |
| 10 | GET | `https://api.any.run/v1/user/presets` | GetUserPresets | 200 |
| 11 | GET | `https://api.any.run/report/{taskUuid}/ioc/json` | GetIOCJson | 200 |
| 12 | GET | `https://api.any.run/report/{taskUuid}/ai` | GetAiSummary | 200 |
| 13 | GET | `https://api.any.run/report/{taskUuid}/summary/tier1` | GetTier1Report | 200 |
| 14 | GET | `https://api.any.run/report/{taskUuid}/summary/tier1-html` | GetTier1HtmlReport | 200 `application/octet-stream` |
| 15 | GET | `https://api.any.run/report/{taskUuid}/summary/{html\|stix\|misp\|json\|brief}` | (not a spec path) | see 4.12 |
| 16 | GET | `https://content.any.run/tasks/{taskUuid}/download/...` | (not a spec path) | binary, see 4.13 |

`taskUuid` is `UuidDto`: a string in lowercase UUID format, pattern `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`. Monitor (#7) also accepts a `queueTaskId`.

### 4.2 GET /v1/analysis/: task history

Description: "Returns max of 100 last tasks from the user's history and their basic information."

Query parameters:

| name | type | default | constraints | meaning |
|---|---|---|---|---|
| `team` | boolean | `false` | | `true` returns team history |
| `skip` | number | `0` | ≥0 | offset |
| `limit` | number | `25` | 0–100 | page size |

The SDK sends `team` as the lowercase string `"true"`/`"false"`. Pagination is by skip/limit only, with no total count returned.

Response 200 `{"error": false, "data": {"tasks": [TaskHistoryDto, ...]}}`. The spec example is copied verbatim:

```json
{"error": false, "data": {"tasks": [{"uuid": "123e4567-e89b-12d3-a456-426614174000", "verdict": "No threats detected", "name": "example.exe", "related": "https://app.any.run/tasks/123e4567-e89b-12d3-a456-426614174000", "pcap": "https://content.any.run/tasks/123e4567-e89b-12d3-a456-426614174000/download/pcap", "file": "https://content.any.run/tasks/123e4567-e89b-12d3-a456-426614174000/download/files/abcdef12-3456-7890-abcd-ef1234567890", "json": "https://api.any.run/report/123e4567-e89b-12d3-a456-426614174000/summary/json", "misp": "https://api.any.run/report/123e4567-e89b-12d3-a456-426614174000/summary/misp", "tags": [], "date": "2026-03-05T10:28:55.238Z", "hashes": {"md5": "d41d8cd98f00b204e9800998ecf8427e", "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "ssdeep": "3:abcdefghijklmno:pqrstuvwxyz"}}]}}
```

`TaskHistoryDto` (required: `uuid, verdict, related, json, misp, date, tags, hashes`):

| field | type |
|---|---|
| `uuid` | UUID |
| `verdict` | `ThreatLevelTextDto`: one of `"No threats detected"`, `"Suspicious activity"`, `"Malicious activity"` |
| `name` | string (main object name), optional |
| `related` | URI `https://app.any.run/tasks/{uuid}` |
| `pcap` | URI `https://content.any.run/tasks/{uuid}/download/pcap`, optional |
| `file` | URI `https://content.any.run/tasks/{uuid}/download/files/{uuid}`, optional (absent for URL tasks presumably) |
| `json` | URI `https://api.any.run/report/{uuid}/summary/json` |
| `misp` | URI `https://api.any.run/report/{uuid}/summary/misp` |
| `date` | ISO date-time |
| `tags` | `TagsDto` (see below) |
| `hashes` | `HashesApiDto` `{md5 (required), sha1, sha256, ssdeep}`, all lowercase hex |

`TagsDto`: an array whose items are **either** a string **or** `{"users": bool, "tag": string}`. Handle both.

### 4.3 POST /v1/analysis/: submit (file / url / download / rerun)

**Content type.** The spec declares the body as `multipart/form-data` (`CreateTaskBody`, `additionalProperties: false`, required: `obj_type`).

[SDK] What the SDK actually sends:
- **file:** `multipart/form-data` with a `file` part (`Content-Disposition: form-data; name="file"; filename="<name>"`). Every other option is a text part whose value is `str(value)`. That means booleans are sent as **`"True"`/`"False"`** (Python repr) and ints as `"64"`, `"240"`, etc.
- **url / download:** an **`application/json`** body with native JSON types (booleans and numbers).
- Both forms are evidently accepted. Safest options: multipart for files; JSON for url/download. If you use multipart for url/download, lowercase `"true"`/`"false"` is expected to work, but whether the server's bool parsing accepts that is UNVERIFIED (the SDK proves `True`/`False` works).
- SDK filtering: a param is omitted when its value is `None` or `''`. `False` and `0` are sent.
- The SDK sets `obj_type='rerun'` automatically when `task_rerun_uuid` is given.

Body fields (all from SPEC; defaults are SPEC defaults, and SDK defaults are noted where they differ):

| field | type | allowed / constraints | default | notes |
|---|---|---|---|---|
| `obj_type` | string | `file`, `url`, `download`, `rerun` | `file` | **required**. `rerun` only with `task_rerun_uuid` |
| `file` | binary | | | for `obj_type=file` |
| `obj_url` | string | | | for `url`/`download`. SDK docstring: "Size range 5-512", `(http/https)://…` |
| `task_rerun_uuid` | string (UUID) | | | for `rerun`; "You can re-run task with new parameters" [SDK] |
| `env_os` | string | `windows`, `linux`, `android`, `macos` | `windows` | |
| `env_bitness` | number | `32`, `64` | `64` | windows: 32/64; linux/android/macos: 64 only. Windows Server 2025: 64 only [SDK] |
| `env_version` | string | `7`, `10`, `11`, `server 2025` (windows); `12.2` (debian), `22.04.2` (ubuntu); `14` (android); `15` (macos) | windows `10`; linux `22.04.2`; android `14`; macos `15` | Linux distro is selected purely by `env_version` |
| `env_type` | string | `complete`, `development` | `complete` | `development` only Windows 10 x64. `clean`/`office` deprecated (June 2 2025) |
| `env_locale` | string | 62 locale codes, e.g. `en-US`, `de-DE`, `ru-RU`, `zh-CN`, `pt-BR`, `ja-JP` (full list in spec) | `en-US` | SDK docstring: "Use locale identifier or country name (Ex: "en-US" or "Brazil"). Case insensitive." |
| `opt_network_connect` | boolean | | `true` | |
| `opt_network_fakenet` | boolean | | `false` | |
| `opt_network_tor` | boolean | | `false` | |
| `opt_network_geo` | string | `fastest`, `AU`, `BR`, `CH`, `DE`, `FR`, `GB`, `IT`, `KR`, `RU`, `US` | `fastest` | TOR exit geo |
| `opt_network_mitm` | boolean | | `false` | HTTPS MITM |
| `opt_network_residential_proxy` | boolean | | `false` | |
| `opt_network_residential_proxy_geo` | string | `fastest` + ~200 ISO-3166 alpha-2 codes | `fastest` | |
| `opt_kernel_heavyevasion` | boolean | | (no spec default) | **Not in the spec body schema**, which is `additionalProperties:false`, yet the SDK sends it for windows/linux/macos-download. UNVERIFIED that the server honours it. SDK default `false` |
| `opt_privacy_type` | string | `public`, `bylink`, `owner`, `byteam` | `bylink` | |
| `opt_timeout` | number | 10–1200 seconds | `60` | "Maximum allowed value depends on the subscription plan". SDK docstrings say "10-660". SDK defaults: 240 for file/download, 120 for url |
| `opt_automated_interactivity` | boolean | | `true` | ML auto-clicker |
| `opt_auto_delete_after` | string | `day`, `week`, `2 weeks`, `month` | (none) | |
| `obj_ext_startfolder` | string | windows: `desktop`, `home`, `downloads`, `appdata`, `temp`, `windows`, `root`; linux/macos: `desktop`, `home`, `downloads`, `temp`; android: `downloads` | `temp` (android `downloads`) | file/download |
| `obj_ext_cmd` | string | | | file/download only |
| `obj_ext_browser` | string | windows: `Internet Explorer`, `Microsoft Edge` (default), `Google Chrome`, `Mozilla Firefox`; linux: `Google Chrome` (default), `Mozilla Firefox`; android: none; macos: `Safari` (default), `Google Chrome`, `Mozilla Firefox` | | url only. Windows Server 2025: Microsoft Edge only [SDK] |
| `obj_ext_useragent` | string | | | download only |
| `obj_ext_elevateprompt` | boolean | | `false` | **Deprecated**, use `obj_force_elevation` |
| `obj_force_elevation` | boolean | | `false` | Windows PE only |
| `auto_confirm_uac` | boolean | | `true` | Windows only |
| `run_as_root` | boolean | | `false` | Linux only |
| `obj_ext_extension` | boolean | | (none; SDK `true`) | "change the file extension to a valid one" |
| `opt_privacy_hidesource` | boolean | | `false` | download only |
| `user_tags` | string | chars `a-z A-Z 0-9 - ,`; max tag length 16; max 8 unique tags | | comma-separated |

Per-OS parameter sets the SDK sends (1.16.0). Use these to decide which options to expose per OS:

- **windows** file: `env_os=windows, env_version, env_bitness, env_type, env_locale, opt_network_{connect,fakenet,tor,geo,mitm,residential_proxy,residential_proxy_geo}, opt_kernel_heavyevasion, opt_privacy_type, opt_timeout, opt_automated_interactivity, opt_auto_delete_after, obj_ext_startfolder, obj_ext_cmd, obj_force_elevation, auto_confirm_uac, obj_ext_extension, task_rerun_uuid, user_tags`.
- **windows** url: the same base without startfolder, cmd, elevation or uac, plus `obj_ext_browser`. Download: base plus `obj_ext_startfolder, obj_ext_cmd, obj_ext_useragent, obj_ext_extension, opt_privacy_hidesource`.
- **linux**: `env_os=linux`, `env_version='22.04.2'` (ubuntu) or `'12.2'` (debian), `env_bitness='64'`, `env_type='complete'`, plus `run_as_root` (file), startfolder limited to desktop/home/downloads/temp, browser Chrome/Firefox.
- **android**: `env_os=android, env_version='14', env_bitness='64', env_type='complete'`, `obj_ext_startfolder='downloads'`. There is no heavyevasion, browser or extension option.
- **macos**: `env_os=macos, env_version='15', env_bitness='64', env_type='complete'`. Browser is Safari/Chrome/Firefox. File and URL analyses have no heavyevasion option, but download does.

Spec example request:

```json
{"obj_type": "url", "obj_url": "https://sample.com", "opt_timeout": 60, "opt_automated_interactivity": true}
```

Responses:
- **201 Created** `TaskSubmitDto`:
  ```json
  {"error": false, "data": {"taskid": "0cf223f2-530e-4a50-b68f-563045268648"}}
  ```
  Note the key is lowercase **`taskid`**.
- **202 Accepted (queued)** `TaskSubmitQueuedDto`, copied verbatim including the docs typo:
  ```json
  {"error": "false,", "message": "Task is queued and awaits execution. To track its status, call GET /v1/analysis/monitor/{queueTaskId}.", "data": {"queueTaskId": "7261f5d1-0939-4abe-8761-b598d46cfc8d"}}
  ```
  Spec: "If the task is queued, it returns queueTaskId (temporary). Once a queued task starts, use the taskUuid (via GET /v1/analysis/monitor/{taskUuid}) to track it." The monitor endpoint accepts the queueTaskId; once started, the monitor response includes the real taskUuid (§4.6).
  [SDK] `check_if_analysis_initialized` **raises** `"Analysis is not started. Queue ID: …"` when `queueTaskId` is present. The SDK does not handle queuing; your client should.
- **4XX**: 403 auth/plan errors, `400 This feature is not available for your plan`, `400 Users with the branded reports feature enabled cannot create public tasks.`

### 4.4 GET /v1/analysis/{taskUuid}: full JSON report

Response 200 `SuccessDocumentDto` = `{"error": false, "data": TaskReportDto}`. The spec has no example for this one.

Errors: 403 (auth / `You can't access to this task`), 404 `Task not found`, 400 `Invalid task uuid in request`.

[SDK] The verdict lives at **`data.analysis.scores.verdict.threatLevelText`**. The SDK's `get_analysis_verdict` reads exactly that path and returns `None` if the report is not ready. There is an optional single retry after 3 s.

`TaskReportDto` (required: `status`). Schema field names are exact; `additionalProperties:false` is used widely in the spec, so these are the full sets:

```
data
├─ status: string                      "Task completion status." (values UNVERIFIED, e.g. "done")
├─ analysis
│  ├─ uuid, permanentUrl (app.any.run/tasks/{uuid})
│  ├─ duration:int, creation:int64 (epoch, unit UNVERIFIED), creationText:date-time,
│  │  stopExec:int64, stopExecText:date-time
│  ├─ reports: { HTML, IOC, STIX, MISP, graph, "TIER1-html" }   (URIs; see 4.12)
│  ├─ tags: TagsDto
│  ├─ sandbox: { name:string, plan:{ name: UserPlanNameDto } }
│  ├─ options: ReportOptionsDto
│  │    timeout:int, additionalTime:int, fakeNet:bool, heavyEvasion:bool, mitm:bool,
│  │    presentation:bool, video:bool, hideSource:bool, network:bool,
│  │    privacy: "public"|"bylink"|"owner"|"byteam", privateSample:bool,
│  │    tor:{used:bool, geo:string}, automatization:{interactivity:bool, uac:bool}
│  ├─ scores
│  │  ├─ verdict: { score:number, threatLevel:number, threatLevelText: ThreatLevelText }  (all required)
│  │  └─ specs: ReportSpecsDto  (booleans) autoStart, cpuOverrun, crashedApps, crashedTask,
│  │       debugOutput, executableDropped, exploitable, injects, knownThreat, lowAccess,
│  │       malwareConfig, memOverrun, multiprocessing, networkLoader, networkThreats,
│  │       notStarted, privEscalation, rebooted, serviceLauncher, spam, staticDetections,
│  │       stealing, suspStruct, torUsed
│  └─ content
│     ├─ mainObject: ReportMainObjectDto (required type, hashes)
│     │    type: "file"|"url"|"download"
│     │    permanentUrl: https://content.any.run/tasks/{uuid}/download/files/{uuid}/{hex}
│     │    filename, basename (submitted name/url), url (full URL for url tasks)
│     │    hashes: {md5, sha1, sha256, ssdeep}
│     │    info: { ext, file (libmagic-style desc), mime, exif: {<group>: {<k>: str|int|num}},
│     │            trid: [{procent:float, extension, filetype}] }
│     ├─ video:   {present:bool, permanentUrl: content…/download/mp4}
│     ├─ pcap:    {present:bool, permanentUrl: content…/download/pcap}
│     ├─ sslkeys: {present:bool, permanentUrl: content…/download/sslkeys}
│     ├─ screenshots: [{uuid, time:int, permanentUrl: …/download/screens/{uuid}/image.jpeg,
│     │                 thumbnailUrl: …/download/thumbnails/{uuid}/image.jpeg}]
│     └─ dumps: [{taskUUID, fileNumber:int, permanentUrl: …/download/dumps/{24hex},
│                 timestamp:int64, processName, pid, address, size}]
├─ environments: ReportEnvironmentDto  (NOTE plural key, singular object)
│    os: { title, build:int, product:"Windows"|"Linux"|"Android"|"Macos" (case-insens.),
│          variant, productType:"Client"|"Server", bitness:32|64,
│          major: "7"|"10"|"11"|"12.2"|"22.04.2"|"14"|"15"|"server 2025",
│          servicePack, softSet:"clean"|"office"|"complete"|"development"|"safebrowsing" }
│    internetExplorer: {version, kbnum}
│    software: [{title, version}],  hotfixes: [{title}]
├─ counters
│    processes:{total, monitored, suspicious, malicious}
│    network:{http, connections, dns, threats}
│    files:{unknown, text, suspicious, malicious}
│    registry:{total, read, write, delete}
│    synchronization:{total, operation:{open, create}, type:{mutex, event}}
├─ processes: [ReportProcessDto]   (required pid, important, status)
│    pid, ppid, uuid, parentUUID, important:bool, image, commandLine, fileName, fileType,
│    mainProcess:bool, times:{start, terminate, monitoringSince} (int64),
│    versionInfo:{company, description, version},
│    cert:{SN, status:int, contentHash, thumbprint},
│    resolvedCOM:{title, module:{fullPath, fileName}},
│    context:{rebootNumber, integrityLevel, userName},
│    scores:{ monitoringReason, dropped:bool, injected:bool, loadsSusp:bool,
│             verdict: {score, threatLevel, threatLevelText},
│             specs: {autoStart, crashedApps, debugOutput, executableDropped, exploitable,
│                     injects, knownThreat, lowAccess, network, networkLoader, stealing,
│                     privEscalation, malwareConfig} },
│    threatName:string, status:string, exitCode:int64, hasMalwareConfig:bool,
│    modules:[{time:int64, image}],
│    synchronization:[{time:int64, name, type, operation}]
├─ network
│  ├─ dnsRequests: [{time:int64, domain, ips:[ipv4|ipv6], reputation:string, reputationNumber:int}]
│  │      (required time, domain, ips)
│  ├─ httpRequests: [{time:int64, method:"GET"|"HEAD"|"OPTIONS"|"TRACE"|"PUT"|"DELETE"|"POST"|"PATCH"|"CONNECT",
│  │      host, url, ip, port:int, proxyDetected:bool, "user-agent":string (hyphenated key!),
│  │      status:string, httpCode:int, process:string (process id/uuid), reputation, country,
│  │      body:{request:{size, type, threatLevel, permanentURL, hashes},
│  │            response:{size, type, threatLevel, permanentURL, hashes}} }]
│  │      (required time, method, host, url, ip, port, status)
│  ├─ connections: [{ip, port:int, protocol, country, asn, time: date-time STRING,
│  │      process, reputation,
│  │      tlsFingerprint:{ja3, ja3Fullstring, ja3S, ja3SFullstring, jarm}}]
│  │      (required ip, port, protocol, time)
│  └─ threats: [{time:string, dstip, srcip, dstport:int, srcport:int, sid:int, class, msg,
│         pro:int (ETPRO), priority:int, process}]          (Suricata alerts)
├─ modified
│  ├─ files: [{time:int64, filename, size:int64, type, threatLevel:"UNKNOWN"|"LOW"|"MID"|"HIGH",
│  │          process, permanentUrl, info:{file, mime}, hashes:{md5,sha1,sha256,ssdeep}}]
│  └─ registry: [{key, name, value, operation, process, time:int64}]
├─ incidents: [{threatLevel:int, title, desc, source, firstSeen:int64, count:int, process,
│               mitre:[{tid:int, sid:int, v:int}],   (numeric technique ids, NOT "T1059" strings)
│               events:[ one of 12 event shapes, see below ]}]
├─ mitre: [{id:string, name:string, phases:[string]}]       (required id; e.g. id "T1059" — format UNVERIFIED)
├─ malconf: [{config:{C2:string (required), Keys:object, Options:object, Strings:[string]},
│             family:string, processPID:int, processTime:int64}]   (all four required)
└─ debugStrings: [{time:int64, message, process}]
```

Incident event shapes (`ReportIncidentEventDto` is a oneOf). Every shape has `_id` and `time`; `time` is a date-time string except where noted:
- Process: `{image, cmdline}`
- ProcessReload: `{image, cmdChild, cmdParent}`
- ProcessYara: `{size, address}`
- Module: `{image, protect: EXECUTABLE|NON_EXECUTABLE, status: LOAD|UNLOAD|SNAP}`
- File: `{operation: READ|WRITE|CREATE|DELETE|CLOSE, device, object, name, status:int64, created, newname, access}`
- FileDrop: `{filename, contentType, size, md5, sha1, sha256}`
- Registry: `{operation: unknown|read|write|delete key|delete value, key, name, value, typeValue: UNKNOWN|REG_NONE|REG_SZ|REG_MULTI_SZ|REG_BINARY|REG_DWORD|REG_QWORD}`
- Ip (`time` is int64): `{process, ipDst, portDst:int, portSrc:int, protocol}`
- Request (`time` is int64): `{filename, process, host, url, ip, port, request, method, proxy:bool}`
- SyncObject: `{type: UNKNOWN|MUTEX|EVENT, operation: UNKNOWN|CREATE|OPEN, name, status:int, isWhiteListed:bool}`
- Suricata (ports are strings): `{process, ipDst, ipSrc, portDst, portSrc, transport, SID, ipDstPacket, ipSrcPacket, totalBytes}`
- Wscript: `{eventId, Operation, Return}` (capitalised keys)

**Threat-level numerics.** `ReportVerdictDto.threatLevel` is a number with no enum in the spec. From SDK and related evidence: `0` = No threats detected, `1` = Suspicious activity, `2` = Malicious activity. The `threatLevelText` strings are authoritative [SPEC], but the **numeric mapping for the report is UNVERIFIED**; it is consistent with the TI `LookupSummary.verdict` mapping `{0:"No info",1:"Suspicious",2:"Malicious"}` and IOC `reputation` 0/1/2 [SDK]. Range and scale of `score` are UNVERIFIED (likely 0–100).

### 4.5 PATCH addtime / stop, DELETE delete

| call | success (HTTP 202) | extra errors |
|---|---|---|
| `PATCH /v1/analysis/addtime/{taskUuid}` | `{"error": false, "message": "Add time in task successful"}` (adds 60 s) | 400 `Task {taskUUID} has already been completed` |
| `PATCH /v1/analysis/stop/{taskUuid}` | `{"error": false, "message": "Stop task successful"}` | 400 already completed |
| `DELETE /v1/analysis/delete/{taskUuid}` | `{"error": false, "message": "Delete task successful"}` | 400 `Task is still running` |

All three can also return the common 403s, `403 You can't access to this task`, `404 Task not found` and `400 Invalid task uuid in request`. No body is sent with any of them. Delete requires the user to have rights to the task; the SDK docstring says "The task must belong to the current user".

The monitor response has `public.maxAddedTimeReached: bool`, which tells you whether addtime is exhausted.

### 4.6 GET /v1/analysis/monitor/{taskUuid}: status stream (SSE)

- Response `200 text/event-stream`. `{taskUuid}` may be a real task UUID or a `queueTaskId`.
- Each event is a line `data: <json>\n`, possibly with other SSE fields.
- [SDK] parsing: read line by line with `readuntil(b'\n')`. Skip blank lines and lines starting with `id`, `event` or `entry`. For other lines, strip the first 6 bytes (`data: `) and `json.loads` the rest. The stream ends when the server closes it; the SDK iterates until EOF.
- [SDK] validation: if the response `Content-Type` does not start with `text/event-stream` (or `application/octet-stream`), it is treated as an error. A JSON body yields `message`.
- If you cannot or will not consume SSE, the alternative is to poll `GET /v1/analysis/{uuid}` or history. Whether there is a non-streaming status endpoint is UNVERIFIED; none is in the spec.

Event payload shapes (from spec examples, verbatim, each prefixed by `data: `):

```
data: {"error": false, "message": "Task is queued and awaits execution."}
data: {"error": false, "message": "Task will be launched soon."}
data: {"error": true, "message": "Pre-launch error occurred."}
data: {"error": false, "message": "Task status is unknown or the task was canceled"}
data: {"task": {...TaskStatusDto...}, "completed": true, "error": false}
```

**Warning.** The SDK's `simplify` path does `status_data.get('task').get('status')`. It crashes on the message-only events. Handle both shapes in your client.

Full running/completed example from the spec, copied:

```json
{"task": {"_id": "64b000000000000000000001", "actions": {"manualclosed": false},
  "scores": {"verdict": {"text": "No threats detected", "threat_level": 0}, "specs": {"multiprocessing": true}},
  "public": {"environment": {"OS": {"elPrompt": false, "full": "Windows 10 Professional (build: 19044, 64 bit)", "build": 19044, "product": "Windows", "variant": "Professional", "bitness": "64", "major": "10", "sp": null, "type": "complete", "product_type": "Client"}},
    "options": {"scriptTracer": {"wscript": true, "powershell": true, "browserPatcher": true, "longSessionMode": false}, "locale": null, "autoclicker": true, "enableSignaturesTracing": false, "openVPN": null, "fakenet": false, "video": true, "onlyimportant": false, "reboots": true, "teamwork": true, "mitm": false, "presentation": false, "logger": "heavy", "network": "unlimited", "netviator": false, "torGeo": null, "residentialProxy": false, "residentialProxyGeo": null, "netConnected": true, "private": "bylink", "resolution": {"width": 1280, "height": 720}, "autoclickerDebugMode": false, "chatGPT": false, "forceElevatePrivileges": false, "heavy_evasion": false, "isPublicDisabled": false, "privateSample": false, "whitelist": []},
    "objects": {"runType": "file", "mainObject": {"names": {"location": "temp", "basename": "example.html", "real": "example.exe", "need_rename": true}, "hashes": {"md5": "d41d8cd98f00b204e9800998ecf8427e", "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "ssdeep": "3:abcdefghijklmno:pqrstuvwxyz"}}},
    "maxAddedTimeReached": false},
  "times": {"startExec": "2025-12-09T14:31:30.308Z", "timeout": 60},
  "tags": ["example"], "usersTags": [], "remaining": 0, "status": 100,
  "uuid": "123e4567-e89b-12d3-a456-426614174000", "threats": []},
 "completed": true, "error": false}
```

`TaskStatusDto` (required: `uuid, status, remaining, times, public, tags, usersTags, scores`):

- **`status`** is an int from -1 to 100, documented as "Task completion rate (%)".
  - [SPEC] mapping: `-1` FAILED; `0–20` PREPARING; `21–99` RUNNING; `100` COMPLETED.
  - [SDK] mapping **differs**: `-1` FAILED; `50–99` RUNNING; `100` COMPLETED; anything else PREPARING. Use the SPEC mapping.
- `remaining`: seconds left. `times: {timeout, startExec}`.
- `scores.verdict: {threat_level:number, text: ThreatLevelText}`. Note the **snake_case** names here; they are camelCase in the report.
- `scores.specs`: snake_case booleans: `autostart, bad_module_certificate, bad_process_certificate, cpu_overrun, crashed_apps, crashed_task, debug_output, executable_dropped, exploitable, has_trace, injects, known_threat, low_access, malware_config, mem_overrun, multiprocessing, network_loader, network_threats, not_started, process_dump, reboot, service_luncher (sic), spam, static_detections, stealing, susp_struct, tor, uac_request`.
- `public.objects.runType`: `file`, `url` or `download`.
- `public.objects.mainObject.names`: either `{need_rename, real, basename, location}` (file) or `{url, basename}` (url).
- `public.environment.OS.bitness` is a **string** `"32"`/`"64"` here.
- `actions.manualclosed`: bool.
- `threats`: [string] of known threat names.
- `completed` (event top level, bool): the event-level done flag.
- Completion: `status == 100` or `completed: true`. The SDK does not stop early; it reads until the server closes the stream.

### 4.7 GET /v1/environment/

Response 200 `{"error": false, "data": {"environments": [TaskEnvironmentDto, ...]}}`.

`TaskEnvironmentDto` (required: `os, version, bitness, type, software`):
- `os`: `windows`, `linux`, `android` or `macos` (case-insensitive pattern)
- `version`: OsVersion string
- `bitness`: int 32 or 64
- `build`: int
- `variant`: string, e.g. `professional`, `debian`, `ubuntu`
- `type`: `clean`, `office`, `complete`, `development` or `safebrowsing`
- `software`: `{ie:{version}, apps:[{name, version}], upps:[string hotfixes]}`

Spec example, truncated at the `…`:

```json
{"error": false, "data": {"environments": [{"build": 22000, "variant": "professional", "version": "11", "type": "complete", "os": "windows", "software": {"ie": {}, "apps": [{"name": "Mozilla Firefox (x64 en-US)", "version": "111.0.1"}, {"name": "PowerShell 7-x64", "version": "7.3.5.0"}, …], "upps": []}, "bitness": 64}, {"build": 1204, "variant": "debian", "version": "12.2", "type": "complete", "os": "linux", "software": {"ie": {}, "apps": [{"name": "chromium", "version": "132.0.6834.110-1~deb12u1"}, …], "upps": []}, "bitness": 64}, {"build": 22042, "variant": "ubuntu", "version": "22.04.2", "type": "complete", "os": "linux", "software": {…}, "bitness": 64}, …]}}
```

### 4.8 GET /v1/user/presets

The response 200 is a **bare JSON array** with no `{error,data}` envelope:

```json
[{"_id": "QiRRnjH9JNnbmevtH", "name": "Default", "userId": "5f4a2c35dfe15b1ff4cd4c1e", "autoclicker": false, "bitness": 64, "browser": "Internet Explorer", "chatGPT": false, "createTime": "2024-01-01T10:00:00.000Z", "el": true, "expirationTime": "2weeks", "expirationTimeSelected": false, "extension": true, "fakenet": false, "hide_source": false, "is64Bit": true, "locale": "en-US", "location": "temp", "mitm": false, "netConnected": true, "netviator": false, "network": "unlimited", "noControls": true, "openVPN": "", "os": "Windows", "privacy": "byteam", "residentialProxy": false, "residentialProxyGeo": "", "timeout": 60, "torGeo": "fastest", "type": "complete", "userPlanName": "Enterprise", "version": "10", "vpn": false}]
```

`userPlanName` is one of: `Free`, `Tester`, `Searcher`, `Trial Hunter`, `Hunter`, `Ally`, `Trial Enterprise`, `Enterprise`, `Enterprise Suite`.

### 4.9 GET /v1/user/: limits

Response 200, from the spec example:

```json
{"error": false, "data": {"limits": {"web": {"minute": -1, "hour": -1, "day": -1, "month": -1}, "api": {"minute": -1, "hour": -1, "day": -1, "month": 250}, "parallels": {"total": 1, "available": 1}}}}
```

`-1` means unlimited. The SDK `get_user_limits` returns `data.limits`. The spec documents only `limits` under `data`. Any other user-info fields are UNVERIFIED.

### 4.10 GET /report/{taskUuid}/ioc/json: task IOCs

Response 200 is a **bare JSON array** of `IocDto` (no envelope):

```json
[{"category": "Main object", "type": "sha256", "name": "sample.exe", "ioc": "31eb1de7e840a342fd468e558e5ab627bcb4c542a8fe01aec4d5ba01d539a0fc", "reputation": 0, "discoveringEntryId": "675e624c22acb500c6d4cafb"}]
```

`IocDto` fields (required: `category, type, ioc, reputation`):

| field | values |
|---|---|
| `category` | `Main object`, `Dropped file`, `DNS requests`, `Connections` |
| `type` | `md5`, `sha1`, `sha256`, `domain`, `ip`, `url` |
| `name` | optional |
| `ioc` | the value |
| `reputation` | int 0–2. [SDK] filter semantics: `0`=unknown, `1`=suspicious, `2`=malicious. The SDK defaults to `suspicious`, i.e. keeps reputation in {1,2}; `all` keeps {0,1,2} |
| `discoveringEntryId` | optional |

Errors: plan gating (403/400), `403 Private content`, 404, 400 invalid UUID.

### 4.11 AI summary and Tier-1 report

- `GET /report/{taskUuid}/ai` returns `{aiSummary?: AiTree, aiRecommendations?: AiTree}`. An AiTree is a map from section title to either a string or a nested AiTree. Text before the first subsection goes under the key `overview`. Keys are omitted when no AI output exists, so `{}` is possible.
  - Errors: `429 {"error":true,"message":"AI Summary limit exceeded"}`, `400 Task is still running`, and plan gating.
  - Spec example:
    ```json
    {"aiSummary": {"Verdict": "Malicious. The sample is a loader that drops and runs a second-stage payload.", "Key findings": {"overview": "The process chain shows persistence and C2 communication.", "Persistence": "Adds a Run registry key to start the dropped executable on logon.", "Network": "Connects to a known C2 server over HTTPS."}}, "aiRecommendations": {"Phase 1 - Containment": {"1.1": "Isolate the affected host from the network.", "1.2": "Block the C2 domain and IP on the perimeter."}, "Phase 2 - Eradication": {"2.1": "Remove the Run registry key and the dropped executable."}}}
    ```
- `GET /report/{taskUuid}/summary/tier1` returns JSON `Tier1ReportDto` with `additionalProperties: true`. Only `aiSummary` and `aiRecommendations` are documented; **the rest of the shape is UNVERIFIED**. It is "a condensed analysis report for first-line SOC analysts".
- `GET /report/{taskUuid}/summary/tier1-html` returns `application/octet-stream` with `Content-Disposition: attachment; filename="{uuid}.tier1.html"`.

### 4.12 Other report formats (SDK-proven URLs, not spec paths)

From SDK `get_analysis_report_async` and the URL patterns in the spec's `analysis.reports` / history:

| format | URL | SDK handling |
|---|---|---|
| json (full) | `GET /v1/analysis/{uuid}` | JSON |
| ioc | `GET /report/{uuid}/ioc/json` | JSON list |
| html | `GET /report/{uuid}/summary/html` | streamed; content-type must start `text/event-stream` or `application/octet-stream` (sic); decoded as text |
| brief | `GET /report/{uuid}/summary/brief` | JSON (**shape UNVERIFIED**; not in spec) |
| stix | `GET /report/{uuid}/summary/stix` | JSON (STIX bundle; **shape UNVERIFIED**) |
| misp | `GET /report/{uuid}/summary/misp` | JSON (MISP event; **shape UNVERIFIED**) |
| tier1 | `GET /report/{uuid}/summary/tier1` | JSON |
| tier1-html | `GET /report/{uuid}/summary/tier1-html` | octet-stream |
| (json alt) | `GET /report/{uuid}/summary/json` | appears as `json` link in history; shape vs `/v1/analysis/{uuid}` **UNVERIFIED** |
| graph | `https://app.any.run/tasks/{uuid}/graph` | web page |

### 4.13 Downloads (content.any.run)

All of these are SDK-proven or appear as spec URL patterns. The SDK sends the same `Authorization` header (session-wide). Whether auth is required for public tasks is UNVERIFIED.

| artifact | URL | notes |
|---|---|---|
| PCAP | `GET https://content.any.run/tasks/{uuid}/download/pcap` | SDK `download_pcap`. Saves as `{uuid}_network_traffic_dump.zip`, suggesting the PCAP may be zipped; **UNVERIFIED** |
| Sample (main object) | `GET <data.analysis.content.mainObject.permanentUrl>`, i.e. `…/download/files/{uuid}/{hex}` | SDK: zip archive, **password `infected`**. Only when `mainObject.type == 'file'` |
| Dropped/modified file | `modified.files[].permanentUrl` | pattern not in spec |
| HTTP bodies | `network.httpRequests[].body.{request,response}.permanentURL` (capital URL) | |
| Video | `…/download/mp4` | `content.video.present` |
| SSL keys | `…/download/sslkeys` | |
| Screenshots | `…/download/screens/{uuid}/image.jpeg`, thumbnails `…/download/thumbnails/{uuid}/image.jpeg` | |
| Process dumps | `…/download/dumps/{24hex}` | |

SDK sample check: `if report['analysis']['options']['privateSample'] == 'false': raise "private content"`. That compares against the **string** `'false'`, whereas the spec type is boolean, so this is an SDK bug. Implement it as `if options.get('privateSample') is True: refuse/expect 403`. The exact semantics are UNVERIFIED.

---

## 5. TI Feeds: TAXII 2.1 (current)

All paths are under `https://api.any.run/v1`. Auth is `Authorization: API-Key <key>`. Responses use `Content-Type: application/taxii+json;version=2.1`. The `Accept` header the server requires is UNVERIFIED; the SDK sends none.

### 5.1 Endpoints

| Method | Path | Returns |
|---|---|---|
| GET | `/feeds/taxii2/` | `TaxiiDiscoveryDto` `{title, description, contact, api_roots:[uri], default:uri}`, e.g. `api_roots: ["https://api.any.run/v1/feeds/taxii2/api1/"]` |
| GET | `/feeds/taxii2/api1/` | `TaxiiApiRootDto` `{title, description, versions:["application/taxii+json;version=2.1"], max_content_length: 9765625}` |
| GET | `/feeds/taxii2/api1/collections/` | `{collections: [TaxiiCollectionDto]}` |
| GET | `/feeds/taxii2/api1/collections/{collectionId}/` | `TaxiiCollectionDto` `{id, title, description, can_read, can_write, media_types:["application/stix+json;version=2.1"]}` |
| GET | `/feeds/taxii2/api1/collections/{collectionId}/objects/` | `TaxiiEnvelopeDto` (paginated) |
| GET | `/feeds/taxii2/api1/collections/{collectionId}/objects/{objectId}` | `TaxiiEnvelopeDto` |
| GET | `/feeds/taxii2/api1/collections/{collectionId}/manifest` | `TaxiiManifestDto` (paginated) |

### 5.2 Collection IDs (stable UUIDv5, identical across environments) [SPEC + SDK Config]

| name (SDK) | id | contents |
|---|---|---|
| `full` | `3dce855a-c044-5d49-9334-533c24678c5a` | All indicators (IP + Domain + URL) |
| `ip` | `55cda200-e261-5908-b910-f0e18909ef3d` | `ipv4-addr` |
| `domain` | `2e0aa90a-5526-5a43-84ad-3db6f4549a09` | `domain-name` |
| `url` | `05bfa343-e79f-57ec-8677-3122ca33d352` | `url` |

### 5.3 GET …/objects/: query parameters

| param | type | default | notes |
|---|---|---|---|
| `added_after` | date-time string | | spec says date-time. SDK docstring example `2025-04-15` (date only) |
| `modified_after` | date-time string | | |
| `limit` | int | **10** (spec) | 1–10000. "Without a limit, the response can contain tens of thousands of objects…" SDK default 10000 |
| `next` | string | | opaque base64 cursor from the previous response |
| `match[type]` | string | | `indicator`, `identity`, `ipv4-addr`, `domain-name`, `url`, `relationship`, `marking-definition`. Comma-separated for multiple [SDK]. SDK default `indicator` |
| `match[id]` | string | | STIX id |
| `match[version]` | string | | SDK default `all` |
| `match[spec_version]` | string | | SDK always sends `2.1` |
| `match[revoked]` | bool (`true`/`false`) | | **SDK-only, not in spec.** SDK default `false`. UNVERIFIED |

The manifest endpoint takes `added_after, modified_after, limit, next, match[id], match[version]`.

[SDK] builds the query string by hand: `'&'.join(f'{k}={v}')`, with **no URL-encoding** and booleans lowercased. So literal `match[type]=indicator` with raw brackets is proven to work. Whether percent-encoded `match%5Btype%5D` works is UNVERIFIED. If you use aiohttp `params=`, check what yarl emits, or pass a pre-built URL with `encoded=True`. Note that `next` cursors are base64 and may contain `+ / =`; the SDK passes them unencoded, so be careful: `+` could be decoded as a space (UNVERIFIED).

### 5.4 Response envelope and pagination

`TaxiiEnvelopeDto` (required: `type, id, spec_version, objects, more`):

```json
{"type": "bundle", "id": "bundle--c3e8a1f2-9d4b-5c6e-8a7f-1b2d3e4f5a6c", "spec_version": "2.1", "objects": [ {…STIX 2.1 object…} ], "more": false, "next": "dGhpcyBpcyBhIGN1cnNvcg=="}
```

The values above are from the spec's per-field examples. Note this is a STIX *bundle* shape, not the plain TAXII envelope. Objects are untyped in the spec ("STIX 2.1 domain object (indicator, malware, etc.)").

**Individual STIX indicator fields are UNVERIFIED.** Expect standard STIX 2.1 `indicator` objects (`type, id, created, modified, pattern, pattern_type, valid_from, labels/indicator_types, confidence, revoked, external_references, …`), but the spec gives no example. Parse the IOC value from `pattern` (e.g. `[ipv4-addr:value = '1.2.3.4']`) and keep the raw object.

Pagination:
- [SPEC] `more: bool` and `next: cursor`.
- [SDK] keeps requesting with `next=<cursor>` while the response contains a `next` key. It stops when `next` is absent and does not check `more`. Recommendation: stop when `more` is false or `next` is missing.

Response headers on objects and manifest: `X-TAXII-Date-Added-First`, `X-TAXII-Date-Added-Last`, `X-TAXII-Date-Modified-First`, `X-TAXII-Date-Modified-Last` (ISO 8601).

[SDK] Delta sync: it stores `X-TAXII-Date-Modified-Last`, parsed with format `%Y-%m-%dT%H:%M:%S.%fZ`. With `get_delta=True` it sends that as `modified_after` on the next call.

Manifest entries: `{id, date_added, version, media_type}`, inside the same bundle-style envelope with `more` and `next`.

### 5.5 TAXII errors

There are two shapes:
- Auth layer `TaxiiAuthErrorDto`: `{"status": "error", "message": "…"}`.
  - 401 `Authorization is required to access this resource.`
  - 402 `Your license has expired. Please renew your subscription to access the service.`
  - 403 `Requires an active subscription`
  - 404 `Feed not found`
- Business `TaxiiErrorDto`: `{"title": "…", "description": "…"}`.
  - 400 `{"title":"Bad Request","description":"Invalid query parameter"}`
  - 404 `{"title":"Not Found","description":"Collection with ID 'invalid-id' could not be found."}`
  - 500 `{"title":"Internal Server Error","description":"An unexpected error occurred"}`

The SDK error extractor uses `message or description`, which covers both.

### 5.6 Legacy feeds (removed; SDK ≤1.10.10 only; not in current spec)

These are for reference only. Whether they are still live is **UNVERIFIED**. The SDK of that era authenticated them with `Authorization: Basic <base64>`.

- `GET https://api.any.run/v1/feeds/stix.json?…` returns `data.objects`
- `GET https://api.any.run/v1/feeds/misp.json?…` returns `data`
- `GET https://api.any.run/v1/feeds/network_iocs.json?…` returns `data`

Query params:
- `IP`, `URL`, `Domain` (bool; plus `File` and `Port` for stix)
- `showRevoked` (bool), `GetNewIoc` (bool)
- `period` = `day`, `week` or `month`
- `from`, `to` (unix timestamps)
- `limit` (default 100), `page` (default 1)

The SDK docstring says: "The last page marker is a response with a single **identity** object". The legacy SDK dropped any param whose value was falsy, so `False` booleans were never sent.

---

## 6. TI Lookup

### 6.1 POST https://api.any.run/v1/intelligence/api/search

Headers: `Authorization: API-Key <key>`, `Content-Type: application/json`.

Request body `RequestDto`:

```json
{"query": "8.8.8.8", "startDate": "2026-05-01", "endDate": "2026-05-31"}
```

| field | type | notes |
|---|---|---|
| `query` | string | a bare indicator (auto-detected) **or** a structured query `field:"value"` with `AND`/`OR`/`NOT` and parentheses |
| `startDate` | `YYYY-MM-DD` | optional |
| `endDate` | `YYYY-MM-DD` | optional. `endDate < startDate` gives 400 `DATE_RANGE_ERROR` |

The full text of the spec's query description follows.

- **Auto-detect order for a bare value:**
  1. IPv4/IPv6 → `destinationIP`
  2. MD5 (32 hex), SHA1 (40) or SHA256 (64) → the matching hash field
  3. domain → `domainName`
  4. URL with a scheme → `url`
- Composite queries must use `field:"value"`. Operators are case-insensitive. Parentheses nest arbitrarily.
- **Supported fields:**
  - Network: `destinationIP`, `destinationIpAsn`, `destinationIPgeo`, `domainName`, `url`, `ja3`, `ja3s`, `jarm`
  - HTTP: `httpRequestContentType`, `httpResponseContentType`, `httpRequestFileType`, `httpResponseFileType`
  - Hashes: `md5`, `sha1`, `sha256`
  - File: `fileName`, `filePath`, `fileExtension`, `fileEventPath`
  - Process: `commandLine`, `imagePath`, `moduleImagePath`, `injectedFlag`
  - Registry: `registryKey`, `registryName`, `registryValue`
  - Sync: `syncObjectName`, `syncObjectType`, `syncObjectOperation`
  - Suricata: `suricataID`, `suricataClass`, `suricataMessage`, `suricataThreatLevel`
  - Threats: `threatName`, `threatLevel`, `MITRE`, `ruleName`, `ruleThreatLevel`
  - Environment: `os`, `osBitVersion`, `osSoftwareSet`, `taskType`, `industry`, `submissionCountry`
- **Aliases:** `filePath`=`fileName`, `host`=`domainName`, `fileEventName`=`fileEventPath`.
- **Wildcards:**
  - `*` matches zero or more characters
  - `?` matches exactly one character
  - `^` anchors the start (`MITRE:"^T108"`)
  - `$` anchors the end (`filePath:".exe$"`)
  - `\` escapes a wildcard (`filePath:"temp\\SK_*.zip$"`)
- **Value vocabularies** [SDK docstrings]:
  - `threatLevel` / `ruleThreatLevel` / `suricataThreatLevel`: `suspicious`, `malicious`, `info`
  - `taskType`: `File`, `URL`
  - `os`: `Windows 7`, `Windows 10`, `Windows 11`
  - `osSoftwareSet`: `clean`, `office`, `complete`
  - `osBitVersion`: `32`, `64`
  - `injectedFlag`: `"true"` or `"false"`
  - `destinationIPgeo` / `submissionCountry`: 2-letter lowercase, e.g. `"ae"`, `"es"`
  - `MITRE`: e.g. `"T1071"`
  - Registry backslashes must be doubled
- **`lookupDepth` is not an API field.** The SDK's `lookup_depth=N` is converted client-side to `startDate = today - N days`. The SDK default is `startDate = today-180d` and `endDate = today`.
- [SDK] keyword mode builds `' AND '.join(f'{field}:"{value}"')` from non-empty kwargs. Fields are emitted in this order: threatName, submissionCountry, taskType, threatLevel, registryKey, registryName, registryValue, os, osSoftwareSet, osBitVersion, ruleName, ruleThreatLevel, MITRE, moduleImagePath, domainName, destinationPort, destinationIP, destinationIpAsn, destinationIPgeo, ja3, ja3s, jarm, imagePath, commandLine, injectedFlag, suricataMessage, suricataClass, suricataThreatLevel, suricataID, filePath, fileEventPath, fileExtension, sha256, sha1, md5, syncObjectName, syncObjectType, syncObjectOperation, url, httpRequestContentType, httpResponseContentType, httpRequestFileType, httpResponseFileType.
  - The SDK also sends **`destinationPort`**, which is not in the spec's field table (UNVERIFIED but used by the SDK).
  - Quoting: the SDK does not escape `"` inside values, so escape them yourself (escape semantics UNVERIFIED).

### 6.2 Response 200: `ResponseApiDto` (bare object, no `{error,data}` envelope)

Required top-level keys: `relatedIncidents, destinationIP, relatedFiles, relatedDNS, relatedURLs, sourceTasks, relatedSynchronizationObjects, relatedNetworkThreats, summary`.

| key | type | item fields (examples from spec) |
|---|---|---|
| `summary` | object | `threatLevel:number` (0 = no info/clean, 1 = suspicious, 2 = malicious per SDK `LookupSummary.verdict`; may be null [SDK Optional]), `lastSeen:date-time`, `detectedType:string` (e.g. `"custom"`), `isTrial:bool`, `tags:[string]`, `details:[{type:"domain", threatLevel, lastSeen, count}]` |
| `destinationPort` | [number] | `[4444, 1194, 443]` |
| `destinationIPgeo` | [string] | `["gb","de"]` |
| `destinationIpAsn` | [{asn, date}] | `{"asn":"akamai international b.v.","date":"2026-05-15T10:30:00.000Z"}` |
| `relatedTasks` | [string] | app.any.run task URLs |
| `threatName` | [{threatName, count}] | `[{"threatName":"agenttesla","count":3}]` |
| `submissionCountries` | [{countryName, count}] | `[{"countryName":"DE","count":10}]` |
| `industries` | [{industryName, confidence}] | `[{"industryName":"Information Technology","confidence":0.7}]`. Spec example is 0–1, but SDK prints `f'{confidence}%'` and types it `int`, so the **scale is UNVERIFIED** |
| `relatedIncidents` | [RelatedIncidentDto] | `{task (url), time, MITRE:["1012","1082"], threatName:[…], event:EventDto, process:ProcessDto}` |
| `destinationIP` | [DestinationIpDto] | `{destinationIP:"198.51.100.42", date, threatLevel:0, threatName:[…], isMalconf:true}` |
| `relatedFiles` | [RelatedFileDto] | `{task, title:"urls", fileLink, time, fileName:"virus.exe", fileExtension:".exe", process, hashes:{md5,sha1,sha256,ssdeep}}`. **Required: task, time, hashes only** |
| `relatedDNS` | [RelatedDnsDto] | `{domainName:"google.com", threatName:[…], threatLevel:0, date, isMalconf}` |
| `relatedURLs` | [RelatedUrlDto] | `{url, date, threatLevel, threatName:[…], isMalconf}` |
| `sourceTasks` | [SourceTaskDto] | `{uuid, related (url), date, threatLevel, tags:[…], mainObject:{type:"url", name:"http://ident.me", hashes}}` |
| `relatedSynchronizationObjects` | [..] | `{syncObjectTime, syncObjectType:"MUTEX", syncObjectOperation:"CREATE", syncObjectName:"Global\\OP_MUTEX46543", task, process}` |
| `relatedNetworkThreats` | [..] | `{suricataClass, imagePath, suricataID:"2022918", suricataMessage, tags, MITRE, suricataThreatLevel:"malicious", task}` |
| `totalTasks`, `totalRelatedFiles`, `totalRelatedURLs`, `totalRelatedDNSs`, `totalDestinationIP`, `totalRelatedIncidents`, `totalRelatedSynchronizationObjects`, `totalNetworkThreats`, `totalDestinationPort`, `totalDestinationIPgeo`, `totalDestinationIpAsn` | number | totals; the arrays may be truncated (page size UNVERIFIED; there is no pagination param) |

Notes:
- `MITRE` values in TI are digit strings **without the `T`** (spec example `["1012","1082"]`). The query field example uses `"T1071"` / `"^T108"`.
- [SDK] `LookupSummary.is_empty()` treats a lookup as "not found" when every non-summary list is empty.
- [SDK] older field-name assumptions in the pydantic model:
  - `relatedFiles[].fileName` is required in the model but optional in the spec.
  - `relatedDNS[].threatName` and `threatLevel` are required in the model but optional in the spec.
  - `summary.tags` is Optional in the model.
  - Code defensively.

Nested sub-objects:
- `ProcessDto` (required `MITRE`, `threatLevel`): `{commandLine, imagePath, threatName, MITRE:[str], pid, scores:{specs:{known_threat, network_loader, network, uac_request, injects, service_luncher, executable_dropped, multiprocessing, crashed_apps, debug_output, stealing, exploitable, static_detections, susp_struct, autostart, low_access, tor, spam, malware_config, process_dump}}, eventsCounters:{raw:{registry, files, modules, objects, rpc}}, threatLevel}`.
- `EventDto`: `{ruleName, commandLine, imagePath, pid, title:[str], destinationPort:[str], destinationIP, destinationIPgeo:[str], destinationIpAsn:[str], url, fileName, registryKey, registryName:[str], registryValue:[str], moduleImagePath, injectedFlag:bool, domainName:[str], httpRequestContentType, httpRequestContentFile, httpResponseContentType, httpResponseContentFile, ruleThreatLevel, sha256}`.

No full 200 example exists in the spec (`components/examples` is just `{"placeholder": {}}`). The field-level examples above are the spec's own.

### 6.3 Errors (search)

- **400** `ErrorDto` + `validationErrors?`:
  - `NOT_EMPTY_BODY_ERROR` "Request body cannot be empty."
  - `WRONG_QUERY_ERROR` "The query syntax is incorrect." (with `validationErrors: [{"field":"query","error":"query should not be empty"}]`)
  - `DATE_RANGE_ERROR` "Incorrect date range."
  - `INVALID_EXPRESSION_ERROR` "Invalid expression: AND operator missing operand(s)."
  - `QUERY_TOO_COMPLEX_ERROR` (too many `*`/`?`)
  - `TOO_MANY_OPERANDS_ERROR`
- **401 / 402**: shared (§3.2).
- **403**:
  - `NO_TI_LICENSE_ERROR` "TI license not found. Please acquire a valid TI license from support@any.run."
  - `API_LOOKUP_DISABLED_ERROR` "TI Lookup API is not available for your license. Please contact support@any.run."
- **429**: `TOO_MANY_REQUESTS` + `nextAvailableRequestDate`.
- **500**: `INTERNAL_SERVER_ERROR` "Something went wrong on our side."

---

## 7. TI YARA Search

Base: `https://api.any.run/v1/intelligence/yara-lookup`. Auth is `API-Key`.

### 7.1 Flow

1. `POST /search` with body `{"query": "<YARA rule text>"}` (`Content-Type: application/json`) returns **200** `JobInfoDto`. Keep `queryId`.
2. Poll `GET /search/{queryId}/count` (or `GET /search/{queryId}`) until `searchInfo.status` is terminal. The SDK polls `/count` every **3 s** and stops only on `done`. Recommendation: stop on `done`, `failed`, `cancelled` or `expired`.
3. `GET /search/{queryId}?offset=&limit=&sort=` returns `{searchInfo, matches[]}`, paginated.
4. Optional: `GET /search/{queryId}/download/stix` returns a STIX bundle of file objects (only after `done`; otherwise 400 `SEARCH_IN_PROGRESS`).
5. Optional: `DELETE /search/{queryId}` stops the search and returns `JobInfoDto`.

### 7.2 Shapes

`JobInfoDto` (required: `query, queryId, ruleName, status, created`):

```json
{"query": "rule grimresources {\n  strings:\n    $s1 = \"loadXML\"\n    $s2 = \"transformNode\"\n  condition:\n    $s2 and $s1\n}", "queryId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "ruleName": "grimresources", "status": "processing", "created": "2026-05-04T10:15:00.000Z", "timesLeft": 120, "progress": 73, "normalizedQueryHash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}
```

This is assembled from the spec's per-field examples.

- `status`: `new`, `processing`, `done`, `cancelled`, `failed` or `expired`.
- [SDK] maps `new`→PREPARING, `processing`→RUNNING, `done`→COMPLETED, anything else→FAILED.
- `timesLeft`: seconds. `progress`: percent.

**Start response.** The POST /search 200 body is `JobInfoDto` at the **top level** [SPEC], and the SDK reads `response['queryId']` at the top level, so the two agree. The count and results endpoints wrap it as `searchInfo`.

`GET /search/{queryId}/count` returns `{"foundMatches": 42, "searchInfo": {JobInfoDto}}`.

`GET /search/{queryId}` query parameters:

| param | type | default | values |
|---|---|---|---|
| `offset` | int | 0 | |
| `limit` | int | 100 | |
| `sort` | string | | `firstNew` or `firstOld` |

It returns `{"searchInfo": JobInfoDto, "matches": [MatchedSampleDto]}`. Bad params give the NestJS 400 shape. The SDK makes one call with defaults and never paginates.

`MatchedSampleDto` (required: `firstSeen, lastSeen, hashes, download, tasks, filePartName, fileFullName, fileSize, fileExt, relatedTags, discoveringEntryId, task, taskUUID`). Spec field examples:

```json
{"firstSeen": "2026-01-15T08:30:00.000Z", "lastSeen": "2026-05-04T14:22:00.000Z",
 "hashes": {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709", "md5": "d41d8cd98f00b204e9800998ecf8427e", "ssdeep": "3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C"},
 "download": "https://content.any.run/tasks/a1b2c3d4-e5f6-7890-abcd-ef1234567890/download/files/fedcba09-8765-4321-0fed-cba987654321/",
 "tasks": ["https://app.any.run/tasks/a1b2c3d4-e5f6-7890-abcd-ef1234567890"],
 "filePartName": "invoice_2026.exe", "fileFullName": "C:\\Users\\admin\\Downloads\\invoice_2026.exe",
 "fileSize": 245760, "fileExt": ".exe", "relatedTags": ["trojan", "AgentTesla"],
 "process": {"processOID": "60f1e2d3c4b5a69788796a5b", "pid": 3412, "cmd": "\"C:\\Users\\admin\\Downloads\\invoice_2026.exe\" --silent", "image": "C:\\Users\\admin\\Downloads\\invoice_2026.exe", "processScoresSpecs": {…}, "threatName": "trojan.agentTesla", "threatScore": 85, "eventsCounters": {"raw": {…}}},
 "discoveringEntryId": "60f1e2d3c4b5a69788796a5b", "task": "60f1e2d3c4b5a69788796a5c", "taskUUID": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}
```

- `hashes`: only `sha256` is required.
- `process`, if present, requires `processOID, pid, cmd, image, threatName`. `threatScore` is 0–100.

`GET /search/{queryId}/download/stix` (format enum is only `stix`) returns:

```json
{"status": "ok", "data": {"type": "bundle", "id": "…", "objects": [{"type": "file", "id": "…", "hashes": {"SHA-256": "…", "SHA-1": "…", "MD5": "…"}, "external_references": [{"source_name": "…", "url": "…"}]}]}}
```

The SDK reads `data.objects`.

**SDK bug.** `get_yara_async(rule, stix=False)` has the flag inverted: `stix=True` returns JSON matches and `stix=False` returns STIX objects. `YaraIterator.json()` therefore actually yields STIX objects. Do not copy this.

### 7.3 YARA errors

- **POST 400**:
  - `YARA_EMPTY_QUERY_ERROR` "YARA search query cannot be empty."
  - `WRONG_QUERY_ERROR` "Invalid YARA rule. Please review: ..."
  - `LONG_SEARCH_ERROR` "YARA rule is too broad to process. Please refine the conditions and try again."
- **POST 403**:
  - `NO_TI_LICENSE_ERROR`
  - `API_YARA_DISABLED_ERROR` "Yara API is not available for your license. Please contact support@any.run."
  - `YARA_DISABLED_ERROR` "Your trial request limit has been reached. Contact us to upgrade your plan."
- **401 / 402**: shared (§3.2). The spec references them for POST; the GET endpoints declare 401 only.
- **404** (GET/DELETE/count/download): `{"message":"Not found.","code":"NOT_FOUND"}`.
- **Download 400**:
  - `WRONG_QUERY_ERROR` "Invalid download format, only "stix" is available"
  - `SEARCH_IN_PROGRESS` "Search process hasn't been finished yet."
- **500**: `YARA_INTERNAL_SERVER_ERROR` "YARA search failed due to a temporary service issue. Please try again later."

---

## 8. Implementation checklist and gotchas (condensed)

1. **One header everywhere:** `Authorization: API-Key <key>`. Accept a key with or without the prefix, as the SDK does.
2. **Base URLs differ by path family:** `api.any.run/v1/...` (sandbox, TI), `api.any.run/report/...` (IOC, AI, summaries), and `content.any.run/tasks/...` (binaries).
3. **Envelopes differ:**
   - Sandbox: `{error, data}` or `{error, message}`
   - presets and IOC: bare arrays
   - TI Lookup: bare object
   - YARA: bare objects
   - TAXII: bundle-style
   - Errors: Sandbox `{error:true,message}`, TI `{message,code}`, TAXII `{status,message}` or `{title,description}`, NestJS `{statusCode,message[],error}`.
4. **Submit:**
   - Success is 201 → `data.taskid`; queued is 202 → `data.queueTaskId`.
   - The monitor endpoint accepts either id. After a queued task starts, take the real UUID from the event's `task.uuid`.
5. **Monitor is SSE.** Parse `data: ` lines and handle the message-only events. Use the SPEC status ranges (0–20 preparing, 21–99 running, 100 done, -1 failed).
6. **Verdicts:**
   - report `data.analysis.scores.verdict.{threatLevel, threatLevelText, score}`
   - monitor `task.scores.verdict.{threat_level, text}`
   - history `verdict` (text)
   - TI `summary.threatLevel` (0/1/2)
   - IOC `reputation` (0/1/2)
7. **MITRE:**
   - sandbox `data.mitre[] {id, name, phases}`
   - sandbox `incidents[].mitre[] {tid:int, sid, v}`
   - TI `MITRE: ["1012"]` (no `T`)
8. **Malware config:**
   - sandbox `data.malconf[] {config:{C2, Keys, Options, Strings}, family, processPID, processTime}`
   - TI `isMalconf` flags on IP, DNS and URL entries
9. **Network:**
   - `data.network.dnsRequests[].{domain, ips[]}`
   - `httpRequests[].{method, host, url, ip, port, "user-agent", httpCode}`
   - `connections[].{ip, port, protocol, asn, country, tlsFingerprint.ja3/jarm}`
   - `threats[]` (Suricata `sid`, `msg`, `class`)
10. **Files and hashes:**
    - `content.mainObject.hashes`
    - `modified.files[].hashes`
    - `incidents[].events[]` FileDrop `{md5, sha1, sha256}`
11. **TAXII paging:** follow `next` until it is absent or `more == false`. The spec limit is 1–10000 (default 10). Save `X-TAXII-Date-Modified-Last` for delta sync. Mind query-string encoding of `match[...]` and `next`.
12. **TI Lookup has no `lookupDepth`.** Compute `startDate`. Back off on 429 using `nextAvailableRequestDate`.
13. **YARA:** POST, then poll `/count` every ~3 s until a terminal status, then page through `GET /search/{id}?offset&limit`.
14. **No v2 exists.** The legacy `/v1/feeds/{stix,misp,network_iocs}.json` endpoints are dropped from SDK ≥1.14 and from the spec.
