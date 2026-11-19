# Internals

## Source layout

| Module | Role |
| --- | --- |
| {src}`svcs/malpedia/src/malpediasvc/__init__.py` | `__version__` (`<version>`) and the `MalpediaSvc` export. |
| {src}`svcs/malpedia/src/malpediasvc/__main__.py` | `python -m malpediasvc <dirn>` runs `MalpediaSvc.execmain()`. |
| {src}`svcs/malpedia/src/malpediasvc/defs.py` | `SVC_NAME`, `SVC_VER`, the `meta:source` guid, the `add`/`del` events, `stormStr()`, and the `StormPkg` that loads `pkgproto/slib.malpedia.yaml`. |
| {src}`svcs/malpedia/src/malpediasvc/api.py` | `MalpediaCellApi`, the `RetnApi` Telepath API. |
| {src}`svcs/malpedia/src/malpediasvc/svc.py` | `MalpediaSvc`: config, slab stores, pull, diffing, lookups, scheduling. |
| {src}`svcs/malpedia/src/malpediasvc/client.py` | `MalpediaClient`: the throttled, retrying HTTP client. |
| {src}`svcs/malpedia/src/malpediasvc/norm.py` | Normalizes API data into records, plus the tag, URL and date helpers. |
| {src}`svcs/malpedia/src/malpediasvc/bib.py` | A tolerant BibTeX parser. |
| `pkgproto/` | The Storm package: commands, modules, and the README copy. |

## The upstream client

`MalpediaClient(session, url, interval, timeout, backoff)` wraps an `aiohttp.ClientSession`.
The cell creates the session with `trust_env=True` and closes it on `fini`.

### Endpoints

Every request is a `GET` under `malpedia:url`. Path segments are quoted with
`quote(str(v), safe="")`.

| Method | Path | Returns |
| --- | --- | --- |
| `version()` | `/get/version` | `{"version": int, "date": str}`. It must have a `version` key. |
| `listActors()` | `/list/actors` | list of actor IDs |
| `listFamilies()` | `/list/families` | list of family IDs (not used by the service) |
| `getActors()` | `/get/actors` | dict keyed by display name |
| `getFamilies()` | `/get/families` | dict keyed by family ID |
| `getActor(id)` | `/get/actor/<id>` | dict, including `families` |
| `getFamily(id)` | `/get/family/<id>` | dict |
| `getReferences()` | `/get/references` | `{"references": {url: [...]}, ...}`. `references` must be a dict. |
| `getBib()` / `getBibActor(id)` / `getBibFamily(id)` | `/get/bib`, `/get/bib/actor/<id>`, `/get/bib/family/<id>` | BibTeX text |
| `findActor(needle)` / `findFamily(needle)` | `/find/actor/<n>`, `/find/family/<n>` | list |
| `listYara()` | `/list/yara` | `{family: [{"path", "tlp"}]}` |
| `getYaraFamily(id)` | `/get/yara/<id>` | `{tlp: {filename: text}}` |
| `getYaraAfter(date)` | `/get/yara/after/<yyyy-mm-dd>` | `{tlp: {filename: text}}` |
| `getYaraTlp(tlp)` | `/get/yara/<tlp>/zip` | `{filename: text}`, from the `.yar` members of the zip. `tlp` must be one of `tlp_white`, `tlp_green`, `tlp_amber`, and the service only uses `tlp_white`. |

A response whose top-level type is wrong (`_reqDict` / `_reqList`) raises `MalpediaApiError`
with the message `Unexpected response from <path>: ...`.

### Transport behavior

| Aspect | Behavior |
| --- | --- |
| Auth | None. No token or `Authorization` header is ever sent. |
| Headers | `User-Agent: slib.malpedia (Synapse Storm Service; https://github.com/gormaniac/stormsvcs)` and `Accept-Encoding: gzip, deflate`. |
| Throttling | `Throttle` serializes every request (an `asyncio.Lock`) and spaces their starts at least `interval` seconds apart. Retries count as requests. |
| Timeout | `aiohttp.ClientTimeout(total=malpedia:timeout)` per attempt. |
| Retries | `MAX_RETRIES = 3`, so 4 attempts in all. Connection errors, timeouts, and HTTP `429`, `500`, `502`, `503` and `504` are retried. |
| Backoff | `backoff * 2**attempt` seconds (5, 10, 20 with the defaults). A `Retry-After` header (seconds or an HTTP date) is honored when it's longer. A `Retry-After` over `MAX_RETRY_AFTER = 600` seconds fails at once. |
| Other errors | Any other status `>= 400` fails at once. The message comes from the JSON `detail`/`error`/`message`, else `not found` for a 404, else up to 300 characters of a non-HTML body. |
| Size limit | `MAX_BODY = 256 MiB`, checked against `Content-Length` and while streaming in 1 MiB chunks. |
| Counting | `count` is the total number of requests. `counter()` is a context manager that counts one task's requests through a `ContextVar`. `pull()` uses it for `summary["requests"]`. |
| Caching | None in the client. The snapshot is the cache. |

All of these errors are `MalpediaApiError(mesg, code)`, which is a `SvcError`, so Storm gets the
message. `code` is the HTTP status when there was one. The pull uses it to treat 404s as "not a
gap".

## Normalization

{src}`svcs/malpedia/src/malpediasvc/norm.py` turns API data into JSON- and msgpack-safe records
with a stable `key`:

| Kind | Key | Builder |
| --- | --- | --- |
| `news` | `sha256(url)` | `parseBib()` gives `{url: bib record}` with duplicate URLs merged. `buildNews()` joins it with the references and the families' `library_entries`. |
| `actor` | actor ID | `resolveActorIds()` matches `/get/actors` names to `/list/actors` IDs, then `normActor()`. |
| `family` | family ID | `normFamily()`, using `ActorIndex` for attribution, then `addActorLinks()` (MISP `related` `uses`) and `withActorTags()`. |
| `yara` | file name | `normYara()`, using `yaraListing()` for family and TLP, and `yaraMeta()` for meta strings. |

Helper behavior:

- `normDate()` accepts `YYYY`, `YYYY-MM`, `YYYY-MM-DD` and `YYYYMMDD`. It returns ISO with the
  same precision, or `None` for an invalid date.
- `tagPart()` matches `syn:tag:part`: lowercase, with the `\w+` runs joined by `_`.
- `tagPath()` applies that to each dot-separated part.
- `recHash()` is the SHA-256 of the record as sorted, compact JSON. It is the change detector.
- `yaraFamily()` parses `<family>_<auto|[a-z]N>.yar`.
- `normYara()` returns `None` (the file is skipped) unless the text declares a `rule`.

Record examples are on the [Data model](model.md) page.

### BibTeX parser

{src}`svcs/malpedia/src/malpediasvc/bib.py` parses `@type{key, field = value, ...}`. It
supports:

- braced, quoted and bare values, and `#` concatenation,
- `%` line comments, and skips `@comment`/`@preamble`/`@string` blocks,
- LaTeX escapes (`\&`, `\%`, `\_`, `\#`, `\$`, `\{`, `\}`), accents (`\'e`, `\"{u}`,
  `\c{c}`, ...) and letters (`\ss`, `\o`, `\ae`, ...),
- a backslash right before the closing braces (`{C:\}`),
- author lists split on top-level ` and `, with braces protecting an inner `and`.

An entry that can't be parsed is skipped with an error message, and parsing resumes at the next
line starting with `@`. Entries without a `url` are skipped too. The pull passes up to 20 of
these messages on as warnings.

## State

The cell's slab holds four `SafeKeyVal` stores:

| Store | Keys | Values |
| --- | --- | --- |
| `slib:malpedia:info` | `version`, `date`, `complete`, `pulled`, `checked`, `failed`, `rejected`, `gaps`, `gaptried`, `yarafull`, `yaradate`, `storing`, `last`, `requests`, `schedtime` | Pull bookkeeping. Times are epoch ms. `gaptried` is `{actor id: ms}`. `schedtime` is `(hour, minute)`. |
| `slib:malpedia:snap` | `<kind>:<key>` | `{"hash", "rec"}` |
| `slib:malpedia:views` | `<view>:<kind>:<key>` | The `{"hash", "rec"}` the view last modeled. |
| `slib:malpedia:viewinfo` | `<view>` | `{"synced", "version", "date", "tags"}` |

Keys too long for the store (or not strings) are treated as absent by `_kvget()` / `_kvpop()`,
not as errors. The actor records are cached in memory (`_actorcache`) until the next store of
actors.

The service doesn't use the Axon or any files outside the slab.

### Locks

| Lock | Held by | Purpose |
| --- | --- | --- |
| `pulllock` | `pull()` for its whole run | One pull at a time. Callers that wait then make their own decision, which is usually `"checked recently"` or `"unchanged"`. |
| `storelock` | the store phase of a pull, each `changes()` key scan and batch, `synced()` | A view never reads a half-written snapshot. |

### Crash safety

`storing=true` is set before the store phase and cleared after it. If the cell starts with
`storing` still set, it logs a warning and pops `version`, `checked`, `yarafull` and `storing`.
The next pull then downloads everything, including the YARA zip, and rewrites the snapshot,
even if Malpedia's version is unchanged.

## Background tasks

The service runs no loops or background tasks of its own. All periodic work is the Cortex's
`slib.malpedia.sync` cron job (see [Syncing](syncing.md)). Pull normalization runs in a worker
thread (`s_coro.executor`), and storing yields to the event loop every 500 records.

## Error handling

- Library code raises `MalpediaApiError` (client) or `MalpediaSvcError` (service). Both
  subclass `stormlibpp.svc.SvcError`, so `RetnApi` returns their message to Storm.
- `pull()` stores every failure in `info["failed"]` and re-raises it. An unexpected exception is
  logged with its traceback and wrapped as `The pull failed unexpectedly: <repr>`.
- There are no secrets to redact.
- In Storm, the commands use `$lib.warn()`. `slib.malpedia.priv.sync` catches per-record
  modeling errors, counts them as `failed`, and doesn't mark those records synced. A
  service-side failure stops the sync with `summary.error`. The next sync continues from what
  was marked.

## The Storm package

{src}`svcs/malpedia/src/malpediasvc/pkgproto/slib.malpedia.yaml` declares:

- `synapse_version: ">=2.234.0,<3.0.0"`
- `genopts.dotstorm: true`, so the Storm sources live in `pkgproto/storm/`
- the README as the package doc
- the three permissions, the five modules and the seven commands

| Module | asroot perms | Role |
| --- | --- | --- |
| `slib.malpedia.priv.user` | `slib.malpedia.user` | Read-only service calls. |
| `slib.malpedia.priv.sync` | `slib.malpedia.sync` | Pull, sync and refresh orchestration. It checks permissions itself, because anyone with the permission can import it. |
| `slib.malpedia.priv.admin` | `slib.malpedia.admin` | Cron, tag settings, reset. |
| `slib.malpedia.model` | | Node modeling. |
| `slib.malpedia.util` | | Formatting. |

There is no `onload` and there are no configvars. Settings live in Storm globals
(`$lib.globals`) because the package targets Synapse 2.x. The modules carry
`// noqa: R005 M001 M002` markers for the Storm linter's 3.x rules on those globals,
`$lib.gen.*` and renamed forms.

A Storm detail that shapes the model code: a `for` loop that runs while a node is in a
function's pipeline sends the node downstream after its first iteration. So the model functions
only yield a node when they don't loop. Loops call helpers that edit the node in their own
runtime instead.

## Tests

```bash
cd svcs/malpedia
uv sync
uv run pytest
```

`tests/conftest.py` enables the `stormlibpp.testing` plugin. It fails tests on Synapse
deprecations, and lets localhost bypass proxies. `pyproject.toml` turns `DeprecationWarning`s
from `malpediasvc` into errors.

| File | Covers |
| --- | --- |
| `tests/fakemalpedia.py` | `FakeMalpedia`, an `aiohttp` server on `127.0.0.1` that serves the real response shapes (as of Malpedia version 26601) from mutable `state`. It records every request path and header, and can inject HTTP errors (with `Retry-After`) per path. It raises if `/api/get/misp` is ever requested. `malpediaSvc()` gives a Cortex with the service added via `getTestCoreProxSvc`, using `svcConf()` (no interval, no backoff, `minage=0`, autosync off). |
| `tests/test_bib.py` | The BibTeX parser. |
| `tests/test_client.py` | Endpoints, retries, `Retry-After`, counters, size limits, throttling, unzip, error messages. |
| `tests/test_norm.py` | Normalization. |
| `tests/test_svc.py` | Pull logic: exact request lists, incremental pulls, YARA gaps and full refetches, missing actor rotation, shrink guard, store lock, interrupted store, `changes()`/`synced()`. |
| `tests/test_malpedia_storm.py` | The package end to end: autosync, sync and modeling, views, tag prefix changes, refresh, search, schedule, permissions, `service.del`. |
| `tests/test_live.py` | A few cheap read-only requests against the real API. Skipped unless `SLIB_MALPEDIA_LIVE=1`. |

```bash
SLIB_MALPEDIA_LIVE=1 uv run pytest tests/test_live.py
```

Please never point a full sync at the real Malpedia from tests. See {doc}`/dev/testing` and
{doc}`/dev/contract` for the repo-wide conventions.
