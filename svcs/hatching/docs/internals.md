# Internals

A walkthrough of the service for maintainers. For the conventions every service follows, see
{doc}`/dev/architecture` and {doc}`/dev/contract`.

## Layout

| Path | What |
| --- | --- |
| {src}`svcs/hatching/src/hatchingsvc/__init__.py` | `__version__` and the `HatchingSvc` export. |
| {src}`svcs/hatching/src/hatchingsvc/__main__.py` | `python -m hatchingsvc`: `HatchingSvc.execmain(sys.argv[1:])`. |
| {src}`svcs/hatching/src/hatchingsvc/defs.py` | The service name (`slib.hatching`), version, guid, the `meta:source` guid, the `add` event, and the Storm package (`PKGDEFS`). |
| {src}`svcs/hatching/src/hatchingsvc/api.py` | `HatchingCellApi`, the Telepath API. |
| {src}`svcs/hatching/src/hatchingsvc/svc.py` | `HatchingSvc`, the Cell: config, API keys, the client cache, uploads, and one method per Triage endpoint. |
| {src}`svcs/hatching/src/hatchingsvc/norm.py` | Pure functions that normalize Triage's reports for modeling. |
| {src}`svcs/hatching/src/hatchingsvc/errors.py` | `HatchingApiError`. |
| `src/hatchingsvc/pkgproto/` | The Storm package: `slib.hatching.yaml`, `storm/commands/*.storm`, `storm/modules/*.storm`, and a copy of the README. |
| `tests/` | The tests and the fake Triage server. |
| `docker/prod/`, `docker/test/` | The production and test images. |

## defs.py

- `SVC_NAME = "slib.hatching"`, `SVC_VER = __version__`, `SVC_GUID`.
- `SOURCE_GUID = "76172c35a9074f998791a9d2b69ff6d8"`, the `meta:source` every modeled node is
  linked to. It's hard-coded again as `$source` in `slib.hatching.model`.
- `SVC_EVTS["add"]["storm"]` creates the `meta:source` (`:name="hatching triage"`
  `:type=slib.hatching` `:url=https://tria.ge`) and sets the globals
  `slib:hatching:tag:enabled` (`true`) and `slib:hatching:tag:prefix` (`rep.hatching`) when
  they're unset.
- `SlibHatchingPkg` is a `stormlibpp.StormPkg` with `proto_name = "slib.hatching"`: it loads
  `pkgproto/slib.hatching.yaml` and the Storm files next to it (`genopts.dotstorm: true`, so
  a command's or module's code is `storm/commands/<name>.storm` / `storm/modules/<name>.storm`).
  `PKGDEFS = (SlibHatchingPkg().asdict(),)`.

## api.py

`HatchingCellApi(RetnApi, s_cell.CellApi, s_stormsvc.StormSvc)` lists the Cell methods to expose:
`RETN_METHS` (45 coroutines) and `GENR_METHS` (`sampleEvents`, `kernelReport`,
`downloadSample`, `downloadTaskFile`, `downloadArchive`). `RetnApi.__init_subclass__` generates a
method for each name that calls `self.cell.<name>(*args, **kwargs)` and wraps the result in a
`TelepathRetn`. `RETN_ERRORS = (HatchingApiError,)`. Two methods are hand-written, `setApiKey`
and `hasApiKey`, returning a `BoolRetn`; `RetnApi` guards them too. See
[API](api.md#telepath-api) for every method and the error mapping.

The `StormSvc` attributes are `_storm_svc_name = SVC_NAME`,
`_storm_svc_vers = normver(SVC_VER)[1]`, `_storm_svc_evts = SVC_EVTS`, and
`_storm_svc_pkgs = PKGDEFS`.

## svc.py

### Constants

| Name | Value | Meaning |
| --- | --- | --- |
| `TERMINAL` | `("reported", "failed")` | Statuses that end an analysis. |
| `UNAVAILABLE` | `("NOT_FOUND", "REPORT_NOT_AVAILABLE", "NOT_AVAILABLE")` | API error names that mean a report doesn't exist (yet). |
| `MAX_TIMEOUT` | `3600` | The longest analysis timeout accepted. |
| `MAX_CLIENTS` | `32` | Per-key pyhatching clients kept open. |
| `MAX_RESULTS` | `1000` | The cap on `search`/`samples` results. |
| `MAX_UPLOADS` | `16` | Open file uploads kept; the oldest is dropped. |
| `UPLOAD_TTL` | `3600` | Seconds an idle upload is kept. |
| `WAIT_RETRY` | `2` | Seconds `wait` pauses before re-opening an events stream that closed early. |

### Startup and shutdown

`__anit__` opens `self.hatchinginfo = self.slab.getSafeKeyVal("slib:hatching")` (the stored
key), reads `hatching:maxsize`, creates the client cache (`clients`, an `OrderedDict` by key;
`inuse`, a `Counter` per client; `retired`, a set), deletes and recreates
`<dirn>/tmp/uploads`, and registers `onfini` handlers that close every client and delete every
upload. There are no background loops; the only scheduled task is the per-call event pump in
`sampleEvents`.

### API keys and clients

`getApiKey(apikey)` returns `apikey or hatchinginfo["apikey"] or conf["hatching:apikey"]`.

`getClient(apikey)` returns a started `pyhatching.PyHatchingClient` for the resolved key, created
with `url=hatching:url`, `timeout=hatching:timeout`, `api_path=hatching:api_path`, and
`raise_on_api_err=True`. Clients are cached per key, least recently used first; past 32, the
oldest is closed, or if it's still in use, moved to `retired` and closed when its last call ends.
`useClient(apikey)` is the context manager every call goes through: it counts the client as in
use, and converts pyhatching's errors:

| pyhatching error | Raised as |
| --- | --- |
| `PyHatchingApiError` | `HatchingApiError("Hatching Triage: <error or 'error'> - <message> (HTTP <status>)", error=..., status=...)` |
| any other `PyHatchingError` (request, JSON, validation, value, file) | `HatchingApiError("Hatching Triage: <err>")` |

`_call(apikey, meth, ...)` calls a client method and `dump()`s the result (pydantic models to
`model_dump(mode="json", by_alias=True, exclude_none=True)`); `_genr` does the same per item of
a client generator; `_bytes` counts a download's chunks against `hatching:maxsize`.

### The upstream client

pyhatching (1.1.0 is locked) sends every request to `<url><api_path><path>` with
`Authorization: Bearer <key>` and a `pyhatching/<version>` User-Agent, through an
`aiohttp.ClientSession` with `trust_env=True` (proxy environment variables). The total timeout is
`hatching:timeout`; streaming requests (downloads, events, kernel logs) have no total timeout and
use it only to connect. Lists are paged 200 at a time (`MAX_PAGE_SIZE`) following the API's
`next` offset, until the limit. Downloads are read in 1 MiB chunks. Neither pyhatching nor the
service retries failed requests, rate limits them, or caches responses; a `429` comes back as a
`TOO_MANY_REQUESTS` error.

The service also calls pyhatching's private `_request()` directly in two places: `rawRequest`,
and `renameRule` (pyhatching's `update_rule` always sends the rule's own name).

### Sample resolution

`resolve(sample)` passes a non-hash through. For a hash (pyhatching's `is_hash`: hex MD5, SHA1,
SHA256, SHA512, or ssdeep), it calls `search_page("<type>:<hash>", limit=20)` and returns the
first `reported` result, else the first result. Every sample-taking method resolves first, so a
hash argument costs one extra search.

### Submissions

`_submitReq()` builds a `pyhatching.base.SubmissionRequest` after `_checkNetwork()` and the
interactive/profiles check: `target=name`, `interactive`, `password`, `profiles` (from
`profileList()`, which turns `"profile:pick"` strings and dicts into `{profile, pick}`),
`user_tags`, and `defaults={timeout, network, geolocation}` (only the set ones). Empty values are
sent as `None` and dropped from the JSON.

#### File uploads

Telepath calls carry their arguments in one message, so a file isn't sent in one call:

1. `slib.hatching.priv.submit.submitFile` checks `$lib.axon.has($sha256)`, then calls
   `submitFileInit()`, which prunes idle uploads, creates an empty file
   `<dirn>/tmp/uploads/<guid>`, and returns the guid. Past 16 uploads, the oldest is dropped.
2. It reads the Axon 1 MiB at a time (`$lib.axon.read($sha256, offs=..., size=1048576)`) and
   sends each chunk with `submitFileChunk(upload, byts)`, which appends it to the file. A chunk
   that would pass `hatching:maxsize` drops the upload and fails.
3. `submitFile(upload, name, ...)` removes the upload from the open set (so it can't be evicted
   mid-send), submits the file (pyhatching reads it into memory and posts it as multipart
   `_json` + `file`), and deletes the file whether it worked or not.

The file writes are done in place (not in an executor) on purpose: with no `await` between the
checks and the write, a cancelled call can't leave an untracked file, and a `submitFile` can't
run before a chunk is on disk.

### Waiting and events

`wait(sample, timeout)` returns immediately if the sample is already `reported` or `failed`.
Otherwise it follows `GET /v0/samples/{id}/events` until an event has a terminal status; if the
stream closes early it re-checks the sample and re-opens the stream after 2 seconds. The whole
follow is bounded by `asyncio.wait_for(timeout)`, and the sample is fetched again at the end.

`sampleEvents` runs the events stream in a task (`schedCoro`) that pushes items onto a queue,
and the generator reads the queue until `limit` events, the `timeout` deadline, or the end of the
stream. An error in the stream is re-raised to the caller (so it becomes a failed item); the task
is cancelled when the generator ends.

### Reports and normalization

`normSample(sample, tasks)` checks the status, gets the overview, the static report (tolerating
`UNAVAILABLE` errors), and with `tasks` the reports of `behavioralTasks(sid, overview)` (the
overview's tasks of kind `behavioral` or named `behavioral*`, with the status `reported`),
fetched concurrently with `asyncio.gather` by `_taskReports`. A task report that fails with a
`HatchingApiError` becomes a message in `errors`; any other exception is raised. It then calls
`norm.normSample()` and appends the Triage-reported failures to `errors`.

`dumpedFiles` uses the same task list and reports, and returns each `dumped` entry that has a
SHA256 and a name and isn't a `region`.

## norm.py

Pure, synchronous functions, unit tested on their own (`TestNorm`). The main ones:

| Function | Does |
| --- | --- |
| `normSample(info, overview, static, tasks)` | Builds the dict described in [API](api.md#normsample). |
| `normTask(name, report)` | Processes, flows, IP geolocation, DNS, HTTP (with request/response pairing), and dropped files of one task report. |
| `normConfig(config, detailed)` / `mergeConfig` / `configKey` | Malware config normalization and merging; a config's identity is `(family, servers)`. |
| `normExtracts`, `normCreds`, `normSigs` | The `extracted` section, credentials, and signatures (unique by lowercased label/name, highest score). |
| `tagPart`, `tagName`, `families` | Tag normalization. |
| `verdict(score)` | Triage score to `10`/`30`/`40`. |
| `toMsecs` | ISO 8601 to epoch millis (`0001-01-01T00:00:00Z`, Go's unset time, is `None`). |
| `c2Url`, `hostPortUrl`, `decoyUrl`, `splitHostPort`, `urlHost`, `ipVersion`, `isPublicIp` | Network value normalization. |
| `cmdLine`, `basename`, `rrType`, `headers`, `ttps`, `strs`, `uniq`, `lower` | Small helpers. |

Values are checked for type before use (ex. `strs()` drops non-strings), so an unexpected report
shape degrades to missing values rather than an exception.

## The Storm package

{src}`svcs/hatching/src/hatchingsvc/pkgproto/slib.hatching.yaml` declares the package
(`synapse_version: ">=2.137.0,<3.0.0"`), its four permissions (`slib.hatching.user`, `submit`,
`manage`, `admin`, all `gate: cortex`), the modules, and the commands. There are no `onload`
hooks or `configvars`; the only package state is the two tag globals and the users' vaults.

Modules:

- `slib.hatching.priv.user`, `.priv.submit`, `.priv.manage`, `.priv.admin` each declare
  `asroot:perms` with their one permission. Their `init` does
  `$svc = $lib.service.get("slib.hatching")`, and every function passes
  `apikey=$userKey()`.
- `slib.hatching.lib` and `slib.hatching.model` require `slib.hatching.user` and run as the
  caller, so node edits are checked against the caller's permissions.
- `slib.hatching.util` has no permission.

Every command is an `init` block that imports what it needs. Commands that work on inbound nodes
do the per-node work in the main block, and use `divert $cmdopts.yield <genr>` to either yield the
results or pass the node through. Work that runs once per query (the `--sample`/`--url`/`--name`
options, and the positional-argument commands) collects its nodes in `$made` in `init`, and
yields them in `fini` when `--yield` is set (the main block `spin`s the inbound nodes away then).

`slib.hatching.model`'s functions return single nodes and keep loops out of node-yielding
functions: a `for` loop running while a node is in a function's pipeline would send the node
downstream after the first iteration and end the function early, so loops call helpers that
yield or edit the node in their own runtime.

Downloads use `slib.hatching.priv.user._upload()`: it passes the service's download generator
through `_bytes()` (which raises `HatchingError` on a failed item) into `$lib.axon.upload()`, and
returns `{status, mesg, data: {sha256, size}}`.

## Error handling

- Python raises `HatchingApiError` for everything the user should see, and `RetnApi` turns every
  exception into a `status=False` `TelepathRetn` (see [API](api.md#telepathretn)).
- Storm checks every return with `slib.hatching.util.failed()`, which warns
  `slib.hatching: <what> failed: <mesg>` and lets the command continue with the next item.
- Only invalid option combinations raise (`BadArg`): `download --file` without `--task`,
  `yara.add --rename` without `--name`, `admin.tags --enable --disable`, and an invalid
  `admin.tags --prefix`.
- Secrets: the service-wide key is only in the service's slab and never returned (only
  `hasApiKey`); users' keys are only read from their own user scoped vault; `admin.user.keys`
  and `admin.user.key.add` print only the first 4 characters of a key unless `--show`. The
  service doesn't redact error messages (`_retnRedact()` isn't overridden).

## Tests

```bash
cd svcs/hatching
uv sync
uv run pytest
```

`tests/conftest.py` loads the `stormlibpp.testing` pytest plugin, which fails any test that uses a
deprecated Synapse API and lets the fake server on localhost bypass proxies (see
{doc}`/dev/testing`). `pyproject.toml` also turns `DeprecationWarning`s from `hatchingsvc` into
errors.

The tests run against `pyhatching.testing.FakeTriage`, an aiohttp server that serves every
endpoint pyhatching uses from in-memory state seeded with one fully reported sample
(`261031-a1b2c3d4e5`, with an overview, static and `behavioral1` task reports, a malware config,
dumped files, a pcap, and kernel events), and records every request. `tests/helpers.py` extends it
where it differs from the real API (a `PUT /v0/yara/{name}` with a new `name` renames the rule),
and provides `hatchingSvc(test, apikey=..., conf=...)`, which yields `(core, svc, fake)`: a test
Cortex with the service added, pointed at the fake.

| File | Covers |
| --- | --- |
| `tests/test_hatching.py` | Versions and README checks (`assertVersionsMatch`, `assertMainHelp`, the two READMEs match and name every command); `norm.py` (`TestNorm`); the Cell and Telepath API: keys, the client cache, every endpoint, submissions and uploads (spooling, races, leftovers, max size), wait and events, downloads, profiles, rules, users; error paths. |
| `tests/test_hatching_storm.py` | The Storm package: every command, the full model (`enrich` with and without `--tasks`, archives, configs merging, IPv6), tags, once-per-query behaviour, permissions (including that `service.get` isn't needed and the stored key can't be read). |
| `tests/test_live.py` | Read-only tests against the real API, skipped unless `HATCHING_LIVE_APIKEY` is set (`HATCHING_LIVE_URL` for a non-public instance). |

```bash
# Live tests (read only).
HATCHING_LIVE_APIKEY=<key> uv run pytest tests/test_live.py
HATCHING_LIVE_APIKEY=<key> HATCHING_LIVE_URL=https://private.tria.ge uv run pytest tests/test_live.py
```

Lint the Storm code with `uv run python -m synapse.tools.storm.lint src/` (see {doc}`/dev/ci`).
