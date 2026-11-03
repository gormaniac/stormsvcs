# anyrun

A Synapse Advanced Power-Up (Storm Service) for the [ANY.RUN](https://any.run) Interactive
Sandbox and Threat Intelligence APIs. It's built from ANY.RUN's
[API documentation](https://any.run/api-documentation/) (the `SandboxV1` and `TIV1` OpenAPI
specs), and covers (see [API coverage](#api-coverage)):

- Submitting files (from the Axon), URLs, and URLs to download and run, on Windows, Linux,
  Android, and macOS, with ANY.RUN's environment, network (TOR, residential proxies, FakeNet,
  MITM), privacy, and run options. Rerunning tasks, and adding time to, stopping, and deleting them.
- Following tasks' status (including queued submissions) and waiting for them to finish.
- Modeling task reports: the verdict, tags, malware families and configs, ATT&CK techniques,
  processes, DNS and HTTP requests, connections, Suricata alerts, file operations, and registry
  operations.
- Reading reports, IOCs, AI summaries, and the STIX, MISP, brief, and tier 1 reports.
- Downloading samples (unzipped and checked against their SHA256), PCAPs, dropped files,
  screenshots, and videos into the Axon, linked to their task.
- **TI Lookup** of IPs, domains, URLs, and hashes (or any TI Lookup query).
- **YARA Search** of ANY.RUN's samples.
- **TI Feeds** (TAXII 2.1) of malicious IPs, domains, and URLs.

The service registers the `slib.anyrun` Storm package. Everything is namespaced under
`slib.anyrun` (not `slib.any.run`, so the package doesn't get an `any` level).

## Deploying

The service is published as `ghcr.io/gormaniac/stormsvcs/anyrun`.

```bash
docker run -d --name slib-anyrun \
    -v /srv/slib-anyrun:/vertex/storage \
    -e SYN_ANYRUNSVC_ANYRUN_APIKEY=<optional service-wide key> \
    -p 27492:27492 \
    ghcr.io/gormaniac/stormsvcs/anyrun:latest
```

Then add it to a Cortex:

```
service.add slib.anyrun tcp://<user>:<passwd>@<host>:27492/*
```

### Configuration

| Option | Env var | Default | Description |
|---|---|---|---|
| `anyrun:apikey` | `SYN_ANYRUNSVC_ANYRUN_APIKEY` | none | Fallback API key, see [API keys](#api-keys). |
| `anyrun:url` | `SYN_ANYRUNSVC_ANYRUN_URL` | `https://api.any.run` | The API host (Sandbox, report, and TI endpoints). |
| `anyrun:content_url` | `SYN_ANYRUNSVC_ANYRUN_CONTENT_URL` | `https://content.any.run` | The host samples, PCAPs, and dropped files are downloaded from. |
| `anyrun:timeout` | `SYN_ANYRUNSVC_ANYRUN_TIMEOUT` | `60` | Seconds before a single request times out (downloads and status streams only use it to connect). |
| `anyrun:maxsize` | `SYN_ANYRUNSVC_ANYRUN_MAXSIZE` | `104857600` | The largest file, in bytes, that's submitted or downloaded. |
| `anyrun:poll` | `SYN_ANYRUNSVC_ANYRUN_POLL` | `3` | Seconds between polls of a YARA search (and reconnects of a task's status stream). |

The service honors the standard `HTTP(S)_PROXY` environment variables. The API key is only ever
sent to the `anyrun:url` and `anyrun:content_url` hosts.

## API keys

Keys are resolved in this order, per request:

1. **The calling user's own key** - set with `slib.anyrun.apikey <key>`. It's stored in a
   user scoped Synapse vault (type `anyrun`), so it's only ever used for that user's requests.
2. **The service-wide key** - set with `slib.anyrun.admin.apikey <key>`. It's stored by the
   service, not the Cortex, so it can't be read back from Storm.
3. **The `anyrun:apikey` config option.**

Every endpoint takes the same key (sent as `Authorization: API-Key <key>`), but what it can do
depends on the plan: the Sandbox API needs a Hunter or Enterprise plan, and TI Lookup, YARA
Search, and the TI Feeds need a TI license. The API's errors (ex. `NO_TI_LICENSE_ERROR`) are
shown as warnings.

## Permissions

| Permission | Grants |
|---|---|
| `slib.anyrun.user` | Model tasks, read reports and statuses, download task files, use TI Lookup, YARA Search, and the TI Feeds, and set your own key. |
| `slib.anyrun.submit` | Submit files and URLs, rerun tasks, and add time to, stop, and delete tasks. |
| `slib.anyrun.admin` | The service-wide key, tag settings, and raw API requests. |

Users don't need the `service.get` permission. The `slib.anyrun.priv.*` modules talk to the
service and elevate privileges only for users that hold the matching permission. Users still
need the normal node permissions for the nodes the commands create.

## Commands

| Command | Description |
|---|---|
| `slib.anyrun.enrich` | Model the newest task of `file:bytes`, `hash:*`, and `inet:url` nodes (found in your task history, then with TI Lookup unless `--no-lookup`), or `--task` IDs. `--reads` also models file and registry reads. |
| `slib.anyrun.lookup` | TI Lookup IPs, FQDNs, URLs, files, and hashes and model the results on them. `--related` models the related observables, `--tasks N` the newest tasks' reports. `--query` prints any TI Lookup query's results. |
| `slib.anyrun.history` | List your (or `--team`'s) newest tasks, or model them with `--model`/`--yield`. |
| `slib.anyrun.task.status` | Print tasks' (or queued submissions') status, or `--follow` them. |
| `slib.anyrun.task.wait` | Wait for tasks to finish, then optionally model them. |
| `slib.anyrun.report` | Print a summary of a task's report, the full report (`--json`), its `--iocs`, its `--ai` summary, or another `--format` (`stix`, `misp`, `brief`, `tier1`, `json`). |
| `slib.anyrun.download` | Download a task's sample, `--pcap`, `--dropped` files, `--screenshots`, or `--video` into the Axon. |
| `slib.anyrun.yara` | YARA Search with `it:app:yara:rule` nodes or a `--rule`'s text and model the matches, or get an earlier `--search`'s results. |
| `slib.anyrun.feed` | Read a TI Feed (`full`, `ip`, `domain`, or `url`) and model (or `--print`) its indicators. `--list` lists the feeds. |
| `slib.anyrun.limits` / `.envs` / `.presets` | Print your API limits, the analysis environments, and your saved presets. |
| `slib.anyrun.apikey` | Set or clear your own API key. |
| `slib.anyrun.submit` | Submit `file:bytes` (from the Axon) and `inet:url` nodes, `--url`s, `--download` URLs, or `--rerun` tasks. `--wait` models the results. |
| `slib.anyrun.task.addtime` / `.stop` / `.delete` | Give tasks 60 more seconds, stop them, or delete them. |
| `slib.anyrun.admin.apikey` | Set or clear the service-wide API key. |
| `slib.anyrun.admin.tags` | Change the tag prefix or turn tagging off. |
| `slib.anyrun.admin.request` | Send a raw request to any ANY.RUN endpoint. |

`slib.anyrun.submit` takes these options (unset ones use ANY.RUN's defaults): `--os`
(`windows`, `linux`, `android`, `macos`), `--version`, `--bitness`, `--envtype`, `--locale`,
`--timeout` (10-1200 seconds, the max depends on the plan), `--privacy`, `--autodelete`,
`--tag` (up to 8), `--offline`, `--fakenet`, `--tor`/`--tor-geo`, `--proxy`/`--proxy-geo`,
`--mitm`, `--no-interactive`, and for files `--startfolder`, `--cmd`, `--elevate`, `--root`,
for URLs `--browser`, and for downloads `--useragent` and `--hide-source`. Options that don't
apply to a kind of submission are rejected before anything is sent.

Submissions that ANY.RUN queues (when no parallel task slots are free) are followed by their
queue ID until they start, so `--wait` and `slib.anyrun.task.wait` work for them too.

## Modeling

A task's sample is modeled as a `file:bytes` (or `inet:url`, for URL tasks) with:

- ANY.RUN's tags and the task's threat names as tags under the prefix (`#rep.anyrun.<tag>`, ex.
  `#rep.anyrun.agenttesla`), with the task's run time as the interval.
- An `it:av:scan:result` for ANY.RUN's verdict, one for every task: `Malicious activity` is
  malicious, `Suspicious activity` suspicious, `No threats detected` benign, and a task without
  a verdict yet (ex. one that's still running) is unknown. Its `:signame` is the first family,
  and its `:categories` are the tags. Modeling the task again updates the same node.
- A `risk:tool:software` per malware family (with `:tag` set to its tag).
- `-(uses)> it:mitre:attack:technique` for the task's ATT&CK techniques, and `-(refs)> it:dev:mutex`
  for the mutexes its important processes used.
- An `it:sec:c2:config` per extracted malware config, with its C2 servers (and their hosts)
  tagged `#rep.anyrun.c2` and the family, and the whole config as `:raw`.
- For download tasks, `-(refs)>` the URL the file was downloaded from.

And, linked to the sample with `:sandbox:file` (for file and download tasks):

- `it:exec:proc` nodes for the processes (with `:src:proc` for the parent, and the main
  process's `:exe` set to the sample).
- `inet:dns:request` nodes and their answers (`inet:dns:a`/`aaaa`).
- `inet:http:request` nodes with the method, URL, server, User-Agent, response code, and process.
- `inet:flow` nodes for the connections (with the process), and ANY.RUN's ASN and country
  (`:asn`, `:loc`) for their IPs when the graph doesn't have them yet.
- `it:app:suricata:matched` nodes for the Suricata alerts, matching an `it:app:suricata:rule`
  (`:id` is the SID, `:name` the message) to an `inet:flow` for the alert's endpoints.
- `it:exec:file:add` nodes for the files the task created (with their path, hashes, and
  process), and `-(refs)>` from the sample to each file. Files ANY.RUN reports without a SHA256
  are modeled by path, with `-(refs)>` their `hash:md5` when there is one.
- `it:exec:file:add`, `write`, and `del` nodes for the file operations in ANY.RUN's incidents
  (a rename is a `del` of the old path and an `add` of the new one, and dropped files carry
  their hashes). Every `it:exec:file:*` is tagged `#<prefix>.threat_lvl.<level>` with ANY.RUN's
  threat level for the file at that path (`unknown`, `low`, `mid`, or `high`), when it gave one.
- `it:exec:reg:set` and `it:exec:reg:del` nodes for the registry changes (`modified.registry`
  and the incidents' registry events), each with its process and an `it:dev:regval`:
  - `it:dev:regval` has no prop for a value's name, so `:key` is the key with the name
    appended (ex. `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater`).
    The default value and deleted keys use the bare key.
  - Hive abbreviations are expanded (`HKCU` is `HKEY_CURRENT_USER`, `\REGISTRY\MACHINE` is
    `HKEY_LOCAL_MACHINE`), so keys match registry data from other sources.
  - DWORD and QWORD values (and untyped integers) are `:int`, everything else is `:str`.
  - The value's guid doesn't include the task, so the same value set by different tasks or
    samples is one node to pivot on.

With `--reads`, `it:exec:file:read` and `it:exec:reg:get` nodes are modeled too. They're off by
default because a task can have thousands of them.

`slib.anyrun.download` links what it downloads to the task: the PCAP, video, and screenshots get
a `-(refs)>` edge from the task's verdict (`it:av:scan:result`, the only node unique to a task,
so two runs of the same sample stay apart).
Each screenshot is an `it:screenshot` (with `:image`, `:sandbox:file`, `:time`, and `:desc`),
and a URL task's last screenshot is the `:page:image` of an `it:exec:url` for the browser's visit.

TI Lookup (`slib.anyrun.lookup`) tags the looked up node with ANY.RUN's tags and threat names
(for the last time it was seen), models the threat names as `risk:tool:software`, and records
the verdict as an `it:av:scan:result` that's updated by each lookup. `hash:*` nodes are modeled
on their `file:bytes` node when ANY.RUN knows its SHA256. With `--related`, the related IPs,
domains, and URLs are tagged with their own threat names (and `#rep.anyrun.c2` when they came
from a malware config), and the related files and mutexes are created.

YARA Search matches are modeled as `file:bytes` nodes (tagged with ANY.RUN's tags for them) and
an `it:app:yara:match` for the rule. TI Feed indicators are modeled as their IP, FQDN, URL, or
file and tagged `#rep.anyrun.feed` (and their labels) for the time they're valid.

Every node is linked to the service's `meta:source` (`any.run`) with a `-(seen)>` edge. Modeling
a task again updates the same nodes.

### Tasks that are still running

A task that's still running (its report's status isn't `done`, `failed`, `error`, or
`canceled`) is modeled as far as it got, with an unknown verdict, and the user is warned. A one
time cron job then runs `slib.anyrun.enrich --task <task> --attempt <n>` in 10 minutes, up to 3
tries in all, after which the user is warned that it gave up.

The cron jobs are created by the privileged `slib.anyrun.priv.user` module, so users don't need
the `cron.add` permission. They're still owned by, and run as, the user who ingested the task,
so they use that user's API key and node permissions, in the view the task was ingested in.
Ingesting a running task again doesn't schedule a second retry. The jobs are named
`slib.anyrun retry of task <task> (try <n> of 3)`, and stay in `cron.list` after they run, like
any one time job.

### Not modeled

- TLS fingerprints (JA3, JA3S, JARM) of connections: `inet:tls:ja3:sample` needs the sandbox's
  client address, which ANY.RUN doesn't report.
- Incidents (ANY.RUN's per process behavior signatures) beyond their file and registry events,
  ATT&CK mappings for registry persistence locations, debug strings, screenshot thumbnails, SSL
  keys, and memory dumps.
- File `CLOSE` events, and the incidents' numeric threat levels (they rate the incident, not a file).
- Config `Keys`, `Options`, and `Strings` beyond the config's `:raw`.
- Process users (`it:exec:proc:user` is deprecated), and the relationships between a TI Lookup's
  indicator and its related observables (ANY.RUN only says they were seen in the same tasks; use
  `--tasks` to model those tasks).
- URL tasks' behavioral nodes can't set `:sandbox:file`, which needs a `file:bytes`.

## API coverage

| ANY.RUN API | Commands |
|---|---|
| `POST /v1/analysis` (`file`, `url`, `download`, `rerun`) | `submit` |
| `GET /v1/analysis`, `/v1/analysis/{uuid}` | `history`, `enrich`, `report`, `download` |
| `GET /v1/analysis/monitor/{uuid}` (server-sent events) | `task.status`, `task.wait`, `submit --wait` |
| `PATCH /v1/analysis/addtime/{uuid}`, `/stop/{uuid}`, `DELETE /delete/{uuid}` | `task.addtime`, `task.stop`, `task.delete` |
| `GET /v1/user`, `/v1/user/presets`, `/v1/environment` | `limits`, `presets`, `envs` |
| `GET /report/{uuid}/ioc/json`, `/ai`, `/summary/{stix,misp,brief,tier1,json}` | `report` |
| `content.any.run` sample, PCAP, file, screenshot, and video downloads | `download` |
| `POST /v1/intelligence/api/search` (TI Lookup) | `lookup`, `enrich`, `download` |
| `/v1/intelligence/yara-lookup/search` (YARA Search) | `yara` |
| `/v1/feeds/taxii2/api1/collections/...` (TI Feeds) | `feed` |
| Anything else | `admin.request` |

Out of scope: the HTML reports, SSL keys, and memory dumps (their links are in the full report), the TAXII manifest endpoint, and
the legacy `/v1/feeds/{stix,misp,network_iocs}.json` feeds (ANY.RUN replaced them with TAXII).

### Behavior the docs don't pin down

These were coded defensively from ANY.RUN's specs and official SDK, and are worth checking with
a live key (see [Testing](#testing)):

- The report's integer times (process starts, DNS and HTTP requests) don't document a unit, so
  it's inferred from the size (seconds, millis, or micros). Small values, which would be offsets
  into the task, aren't modeled.
- Sample downloads are zips with the password `infected` (per ANY.RUN's SDK). Every download is
  unzipped when it's a zip and checked against the SHA256 the report expects.
- File submissions' multipart options are sent the way ANY.RUN's SDK sends them (ex. `True`/`False`).
- Screenshot times are small integers, so they're treated as seconds into the task.
- `modified.registry`'s operations aren't documented, so they're matched by keyword (`write`,
  `set`, `delete`, `read`...). Unrecognized ones are skipped. Each `modified.files` entry is
  treated as a creation (the spec calls its time the "file creation timestamp").

## Testing

```bash
uv sync --dev
uv run pytest tests
```

The tests run against `tests/fakeanyrun.py`, a fake ANY.RUN server built from the response
shapes in ANY.RUN's API specs. `tests/test_live.py` makes read-only requests to the real API when
`SLIB_ANYRUN_LIVE=1` and `SLIB_ANYRUN_APIKEY` are set (and `SLIB_ANYRUN_TASK`, a task the key can
read, to check reports and status streams).
