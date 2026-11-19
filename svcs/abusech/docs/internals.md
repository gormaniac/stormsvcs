# Internals

A walkthrough of the code for developers maintaining the service. See the stormsvcs
{doc}`/dev/architecture` and {doc}`/dev/contract` for the conventions every service follows.

## Layout

| File | Contents |
|---|---|
| {src}`svcs/abusech/src/abusechsvc/__init__.py` | `__version__` (`<version>`) and the `AbuseChSvc` export. |
| {src}`svcs/abusech/src/abusechsvc/__main__.py` | `python -m abusechsvc <cell dir>` runs `AbuseChSvc.execmain()`. |
| {src}`svcs/abusech/src/abusechsvc/defs.py` | The Storm service definition: `SVC_NAME`, `SVC_GUID`, `SOURCES`, `EXT_PROPS`, the `add` event Storm (`SVC_EVTS`), and `PKGDEFS` (the package, built by StormLib++'s `StormPkg` from `pkgproto/`). |
| {src}`svcs/abusech/src/abusechsvc/api.py` | `AbuseChCellApi`, the Telepath API. |
| {src}`svcs/abusech/src/abusechsvc/svc.py` | `AbuseChSvc`, the cell: config, Auth-Keys, one method per endpoint and dataset, and bulk jobs. |
| {src}`svcs/abusech/src/abusechsvc/client.py` | `AbuseChClient`, the HTTP transport, and `unzip()`. |
| {src}`svcs/abusech/src/abusechsvc/norm.py` | Normalizes abuse.ch responses into shared shapes. |
| {src}`svcs/abusech/src/abusechsvc/bulk.py` | `NodeBuilder`, which builds bulk import nodes. |
| {src}`svcs/abusech/src/abusechsvc/pkgproto/` | The `slib.abusech` Storm package: `slib.abusech.yaml`, `storm/commands/`, `storm/modules/`, and `README.md` (a copy of the service README, checked by a test). |

## The cell (`svc.py`)

`AbuseChSvc.__anit__()`:

- Opens `self.abuseinfo = self.slab.getSafeKeyVal("slib:abusech")` for the stored Auth-Key.
- Creates one `aiohttp.ClientSession(trust_env=True)` (closed on fini) and an
  `AbuseChClient` with `abusech:urls`, `abusech:ratelimit`, `abusech:timeout` and
  `abusech:maxsize`.
- Deletes and recreates `<dirn>/tmp/bulk`, and schedules `_bulkPruneLoop()`.

### Method conventions

- Methods named after an endpoint return abuse.ch's `data` as-is (`_data()` returns the
  response's `data`, or a default when it's empty; a non-object response is an error). The
  `norm*` variants return normalized shapes; generators always yield normalized items.
- Every method takes `apikey=None`; `_query()`/`_fetch()` resolve it with `getApiKey()`.
- Hashes are checked with `hashType()` (by length: 32 MD5, 40 SHA1, 64 SHA256, 96 SHA3-384,
  hex only) and each endpoint refuses the types it doesn't support.
- Limits: `clampLimit()` keeps a limit sent to abuse.ch in 1-1000 (0/None means 1000),
  `sliceLimit()`/`limitReached()` treat 0/None/negative as "everything".
- `BAZAAR_SEARCHES`, `YARAIFY_SEARCHES`, the export and blocklist file maps, and
  `BAZAAR_UPDATE_KEYS` are the tables the commands' choices mirror.
- `READ_QUERIES` lists the read-only `query` values per API (MalwareBazaar, ThreatFox,
  YARAify). `bazaarQuery`, `threatfoxQuery` and `yaraifyQuery` pass
  `idempotent=query in READ_QUERIES[...]`, so only those are retried after a 5xx or timeout.
  Writes also pass `notfound=False`, so a "not found" status is an error, not a silent no-op.

### Downloads and datasets

| Helper | Used for | Behavior |
|---|---|---|
| `_download()` | Sample downloads | `client.fetch()` the zip (empty for "not found" → `None`), refuse non-zips and anything over `abusech:maxsize`, `unzip()` with password `infected`, and require exactly one file (`_sample()` returns `{name, size, sha256, bytes}`). |
| `_fetchText()` | Feodo/SSLBL blocklists, MalwareBazaar `yara_rules.json` | `client.fetch()` into memory, unzip if needed, decode, and raise if the first 2 KiB has a `# ... has been deprecated` line. |
| `_downloadBytes()` | ThreatFox JSON exports | `client.download()` into memory (capped at `abusech:maxsize`), unzip if needed. Parsed with `parseThreatfox()` in a thread. |
| `_csvRows()` | MalwareBazaar and URLhaus CSV exports | `client.download()` into a `tempfile.TemporaryFile` (capped at `abusech:bulk:maxsize`), then `_fileLines()` streams the lines (from inside the zip when zipped, checking the first 20 lines for a deprecation notice) into `norm.parseCsvLines()`. Yields to the loop every 1000 rows. |
| `_join()` | Uploads | Joins the chunks read from the Axon, refusing more than `abusech:maxsize`. |

The YARAhub export (`yaraifyRulesExport`) downloads `yarahub/yaraify-rules.zip` into memory,
unzips it and splits every file with `norm.parseYara()`. `_ruleText()` fills in missing rule
text for `normYaraifyRecentRules`/`normYaraifyDeployedRules` with one `get_yara_rule` per rule,
ignoring failures.

Quirks handled per endpoint: ThreatFox `ioc` returns the IOC without the `data` wrapper; the
Hunting false positive list is the response itself (keyed by ID); YARAify `get_results`
reports an unknown task as `{"query_status": "error", "data": "unknown_task_id"}` (returned as
`None`); `list_tasks` returns `"no results"` as `data`; URLhaus host lookups refuse anything
with `:`; `urlhausSubmit` returns the plain-text response.

### Background tasks

`_bulkPruneLoop()` runs `_bulkPrune()` every 600 seconds (via `waitfini(timeout=600)`),
removing jobs whose `touched` time is older than `BULK_IDLE` (6 hours). Every job access
updates `touched`. There are no other loops and no caching: every call goes to abuse.ch.

## The transport (`client.py`)

`AbuseChClient` is shared by every platform.

### Requests

- `url(base, path)` joins a base URL (`BASE_URLS` plus `abusech:urls` overrides) and a path.
- `headers(base, apikey)` sends `Auth-Key: <key>` when there's a key, and raises
  `NoApiKeyError` for the `KEYED_APIS` without one. For the `EXPORT_APIS`
  (`bazaar:export`, `urlhaus:export`, `threatfox:export`) the URL-quoted key is also the first
  path segment.
- `send()` builds the body: `files` as multipart (form fields alongside, a `json_data` field
  sent as `application/json`, files as `application/octet-stream`), else `form` (form
  encoded), else `json_data` (JSON). `normForm()` drops `None` values, sends bools as
  `1`/`0` and joins lists with commas; `params` are normalized the same way. Bodies are read
  in 1 MiB chunks and capped at `maxsize` (also checked against `Content-Length` first).
- `query()` parses the JSON and applies `checkStatus()`, returning `None` for "not found"
  (unless `notfound=False`).
- `fetch()` returns `(bytes, content type)`, checking a JSON body's `query_status` too; a
  "not found" returns empty bytes.
- `stream()` GETs a large file with `ClientTimeout(total=None, sock_connect=timeout,
  sock_read=timeout)` and yields 1 MiB chunks. An HTTP error, or a JSON response that ends
  within `STATUS_MAX` (1 MiB), is read and checked like any other response; a larger JSON body
  is treated as data (ex. ThreatFox `recent.json`). `download()` writes a stream to a file
  object, refusing more than its `maxsize`.

### `query_status`

`checkStatus()` turns abuse.ch's status convention into errors:

| Condition | Result |
|---|---|
| HTTP 401/403, or `query_status` in `unknown_auth_key`, `invalid_auth_key`, `auth_key_required`, `unauthorized` | `AbuseChApiError("abuse.ch <base>: <message> (check your Auth-Key)")` |
| A "not found" status (`isNotFound()`: starts with `no_result` or `unknown_`, or ends with `not_found`, except `unknown_query`, `unknown_selector`, `unknown_operation`, `unknown_key` and the auth statuses) | `None` / empty, or an error with `notfound=False` |
| Any other HTTP status of 400 or more | `AbuseChApiError(<best message>)` (`errMesg()`: the status with abuse.ch's string `data`, or `error`/`detail`/`message`, or the start of a non-HTML body, or `HTTP <code>`) |
| A `query_status` not in `OK_STATUSES` (`ok`, `queued`, `inserted`, `updated`, `success`, `processing`, `exists`, `file_already_known`) | `AbuseChApiError("abuse.ch <base>: <status>[: <data>]")` |

`AbuseChApiError` carries `mesg`, `code` (HTTP status) and `status` (`query_status`).

### Rate limiting and retries

- `RateLimiter(rate)` spaces every request (including retries and streams) at least
  `1/abusech:ratelimit` seconds apart, across all platforms, behind an `asyncio.Lock`.
- Up to `MAX_RETRIES` (3) retries, waiting `backoff * 2**attempt` (1, 2, 4 seconds), or the
  `Retry-After` header (seconds or an HTTP date) capped at `MAX_RETRY_WAIT` (60 seconds).
- Always retried: HTTP 429 and 503 (`RETRY_CODES`), and `aiohttp.ClientConnectorError`
  (nothing was sent).
- Retried only for idempotent requests: HTTP 500, 502, 504, timeouts, and dropped
  connections. A request is idempotent unless the caller says otherwise or it has `files`;
  writes, uploads, `rescan_file`, `delete_yara_rule`, `generate_identifier` (not in
  `READ_QUERIES`), URLhaus submissions and raw requests aren't.
- `stream()` retries only before the first byte arrives; a partial download can't resume.

### Zips

`unzip()` uses `pyzipper.AESZipFile` (MalwareBazaar's sample zips are AES encrypted, which the
standard library can't read; it also reads ZipCrypto and plain zips), with the password
`infected` for samples and none for datasets. `maxsize` caps each file and the running total
of all files, using the sizes in the zip's directory, so a small zip can't expand into more
memory (a zip bomb). Bad zips and bad passwords become `AbuseChApiError`.

### Secret redaction

- `scrubKey()`/`scrubError()` replace the request's key (raw and URL-quoted) with
  `<auth-key>` in every `AbuseChApiError` the transport raises, including aiohttp errors that
  echo the URL.
- `AbuseChCellApi._retnRedact()` replaces the stored and configured keys with `<redacted>` in
  every error message returned to Storm.
- `checkRawPath()` stops `rawRequest` from sending the key to a path outside the API.

## Normalization (`norm.py`)

The module flattens each platform's fields into the shapes listed in
[the API reference](api.md#normalized-shapes), so the Storm model and `NodeBuilder` only deal
with one shape per kind of record.

- Values: `ts()` makes times Synapse-parseable (drops ` UTC`/`Z`/`+00:00`, converts epoch
  seconds or milliseconds to UTC, since Synapse would read `1700000000` as `YYYYMMDDhh`);
  `timePair()` orders a first/last pair as times; `normTag()`/`normTags()` make tag segments;
  `toInt()`, `toFloat()`, `toBool()`, `lst()`, `splitList()`, `lower()`, `isHex()`.
- CSV: `csvRecordLines()` drops `#` comments and blank lines between records but keeps them
  inside quoted fields that span lines; `parseCsvLines()` streams rows with one
  `csv.reader`, skips an un-commented header row, and maps `""`, `n/a`, `None` to `None`.
- Observables: `normObservable(kind, valu)` types a value by its abuse.ch type (or guesses it)
  into `file:bytes` (by hash length), `inet:url`, `inet:ipv4`/`inet:ipv6`, `inet:server`
  (`ip:port`, bracketed IPv6), `inet:fqdn`, `inet:email`, or `hash:md5` (JA3). `normHost()`
  drops a port from URLhaus/Feodo hosts.
- Files: `normSample()` handles every platform's sample fields, `normVendors()` reads each
  `vendor_intel` vendor with its own function (`VENDORS`) or `_vendorGeneric()`,
  `normFileInfo()` splits `file_information` into links, related hashes, families and notes,
  `normOle()` and `normCert()` / `normVirusTotal()` / `normC2Config()` the rest.
- `parseYara()` splits rule text on `rule <name>` and reads each rule's `meta:` section.

## Bulk builder (`bulk.py`)

`buildModel()` builds a standalone `synapse.datamodel.Model` from Synapse's core model
modules plus the `EXT_PROPS`, cached on the cell (`_bulkmodel`) after the first build.
`NodeBuilder` keeps nodes as `{ndef: {"props", "tags", "edges"}}`:

- `node()` normalizes a primary value; `guid()` normalizes props and uses
  `s_common.guid(sorted((name, norm), ...))`, the same as `$lib.guid()` on a dict.
- `prop()` merges `.seen` intervals, `addArray()` accumulates array values, `tag()` normalizes
  the tag and its interval (skipping invalid ones, like `+?#`) and merges intervals.
- `flush()` returns the batch and resets it; held nodes (families) stay until `finish()`.

See [Bulk imports](bulk.md) for how it's driven. Bump `BUILDER_VERSION` when the built nodes
change.

## The Storm package

{src}`svcs/abusech/src/abusechsvc/pkgproto/slib.abusech.yaml` declares the package (`version` the
service version, `synapse_version: ">=2.256.0,<3.0.0"`, `genopts.dotstorm: true`, the README as a doc),
the five permissions, the modules and the commands. There are no `configvars` and no
`onload`; settings are Cortex globals, initialized by the service's `add` event.

### Modules

| Module | Privilege | Role |
|---|---|---|
| `slib.abusech.priv.user` | `asroot:perms` `slib.abusech.user` | Wrappers for every read method; passes the user's key. Returns the service's `{status, mesg, data}` or emits them. |
| `slib.abusech.priv.download` | `asroot:perms` `slib.abusech.download` | `bazaar()`, `urlhaus()`, `yaraify()`, `yaraifyUnpacked()`: download and `$lib.axon.put()` the bytes, returning `{sha256, size, name}`. |
| `slib.abusech.priv.submit` | `asroot:perms` `slib.abusech.submit` | Upload, update, comment, submit, scan, rescan, deploy and delete wrappers; `tooLarge()` checks a file's size against `maxSize()` before `chunks()` reads it from the Axon in 1 MiB pieces. |
| `slib.abusech.priv.admin` | `asroot:perms` `slib.abusech.admin` | `setApiKey`, `hasApiKey`, `tagSettings`, `setTagPrefix` (validated), `setTagsEnabled`, `rawRequest`. |
| `slib.abusech.priv.bulk` | `asroot:perms` `slib.abusech.bulk` | `run()`, `datasets()`, `isRecent()`, see [Bulk imports](bulk.md). |
| `slib.abusech.priv.tags` | `asroot:perms` `slib.abusech.user`, `bulk`, or `admin` | `tagPrefix()` (null when disabled) and `tagSettings()`; reading globals needs a permission those users don't otherwise have. |
| `slib.abusech.lib` | unprivileged | The user API, see [the Storm module](api.md#the-slib-abusech-lib-storm-module). |
| `slib.abusech.model` | unprivileged | Models normalized records; every node edit runs as the caller. |
| `slib.abusech.download` | unprivileged | `download(plat, sha256, unpacked)`: downloads via the priv module and models the file. |
| `slib.abusech.util` | unprivileged | `userKey()`, `isIpv6()`, `failed()`, `hashType()`, `nodeHash()`, `table()`, `printJson()`, `printSubmission()`, `first()`. |
| `slib.abusech.families` | unprivileged, checks `slib.abusech.admin` on import | The 0.4.0 family merge used by `slib.abusech.admin.families.merge`. |

Only the priv modules call `$lib.service.get("slib.abusech")` or the Axon, which is why users
need neither `service.get` nor Axon permissions, and the service-wide key is never readable
from Storm. Synapse doesn't check permissions on importing a module (only `asroot:perms`), so
`slib.abusech.lib` is gated by the priv modules it imports (importing it without
`slib.abusech.user` raises `AuthDeny`), and `slib.abusech.families` raises `AuthDeny` in its
`init` unless the caller has `slib.abusech.admin`.

### Patterns in the Storm code

- **Run once.** A command's body runs once per inbound node. Work that ignores the inbound
  nodes is in a function gated on `$util.first($state)` (a `({"done": false})` dict made in
  `init`), yielded with `divert (true) $fn()`, so it runs once without a `spin`.
- **Yield or pass through.** Node-driven commands end with
  `divert $cmdopts.yield $model.nodes($results)`.
- **Batching submissions.** `urlhaus.submit` and `threatfox.submit` collect values per node and
  submit in `fini`.
- **Model functions return one node.** A `for` loop that runs while a node is in a function's
  pipeline would send the node on after its first iteration and end the function early, so
  model functions only `yield` a node when they don't loop, and loops call helpers that edit
  the node in their own runtime.
- **Synapse 3.x lint.** The code passes `python -m synapse.tools.storm.lint src` (CI blocks
  on it) and `--v3-ready`; 3.x-only changes (`inet:ipv4` and `risk:tool:software` renames,
  `.seen`, `$node.form()`, `$lib.globals.get()`, `$lib.vars.type()`) are `// noqa`'d with a
  note, since the package requires Synapse <3.0.0.

## Tests

```bash
cd svcs/abusech
uv sync --dev
uv run pytest
```

| File | Covers |
|---|---|
| `tests/fakeabusech.py` | `FakeAbuseCh`, an aiohttp server on `127.0.0.1` that serves canned responses (trimmed from, and shaped like, real abuse.ch data) for every API under a per-API path prefix, records each request (method, path, query, `Auth-Key`, form, JSON, files), rejects missing keys (401) and `badkey` (403), and takes `overrides` of `(base, query) -> (status, body)`. `abusechSvc(test)` yields `(core, svc, fake)`: a Cortex with the service added, pointed at the fake (`abusech:ratelimit: 0`, `abusech:apikey: testkey`, `client.backoff = 0`). |
| `tests/test_abusech.py` | Normalization (`TestNorm`), the transport (`TestClient`: statuses, retries, size caps, zips, redaction), the cell's methods (`TestSvc`), and regression tests for audit fixes. |
| `tests/test_abusech_storm.py` | Every command against the fake in a real Cortex: the package, each platform, blocklists, enrich, admin commands, permissions, options, and the family and edge migrations. |
| `tests/test_bulk.py` | `NodeBuilder`, bulk jobs, `--bulk` (including `test_parity`, which compares the bulk and Storm nodes), the datasets global, limits and job ownership. |
| `tests/test_live.py` | Live tests against the real APIs, read-only, skipped by default. |

`tests/conftest.py` enables the StormLib++ test plugin (`pytest_plugins =
["stormlibpp.testing"]`), which fails a test that uses a deprecated Synapse API and lets the
fake on localhost bypass any proxy. `pyproject.toml` turns `DeprecationWarning`s from
`abusechsvc` into errors. See {doc}`/dev/testing`.

Live tests:

```bash
# The keyless datasets only (Feodo Tracker and SSL Blacklist).
SLIB_ABUSECH_LIVE=1 uv run pytest tests/test_live.py

# Also the Auth-Key based APIs.
SLIB_ABUSECH_LIVE=1 ABUSECH_AUTH_KEY=<key> uv run pytest tests/test_live.py
```

CI ({src}`.github/workflows/abusech.yml`) runs the shared service pipeline with
`docker_tests: true` (the tests also run in the test image built on the new production image)
and `storm_lint: block`. See {doc}`/dev/ci`.
