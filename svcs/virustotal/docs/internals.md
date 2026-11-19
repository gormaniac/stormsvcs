# Internals

A walkthrough of the service's code for maintainers. For the conventions every service in
the monorepo follows, see {doc}`/dev/architecture` and {doc}`/dev/contract`.

## Layout

| Path | What |
| --- | --- |
| {src}`svcs/virustotal/src/vtsvc/__init__.py` | `__version__` and the `VtSvc` export. |
| {src}`svcs/virustotal/src/vtsvc/__main__.py` | `python -m vtsvc <dirn>`: `VtSvc.execmain()`. |
| {src}`svcs/virustotal/src/vtsvc/defs.py` | The service name (`slib.vt`), version, the `meta:source` guid, the service `add` event, and the Storm package definition (`SlibVtPkg`, a StormLib++ `StormPkg`). |
| {src}`svcs/virustotal/src/vtsvc/api.py` | `VtCellApi`, the Telepath API. |
| {src}`svcs/virustotal/src/vtsvc/svc.py` | `VtSvc`, the Cell: config, API key handling, one method per endpoint. |
| {src}`svcs/virustotal/src/vtsvc/client.py` | `VtClient`, the HTTP transport, errors, retries, and `TtlCache`. |
| {src}`svcs/virustotal/src/vtsvc/quota.py` | `QuotaLimiter`, the Public API rate limiter. |
| {src}`svcs/virustotal/src/vtsvc/norm.py` | Normalization of VirusTotal objects for modeling. |
| {src}`svcs/virustotal/src/vtsvc/pkgproto/slib.vt.yaml` | The Storm package: perms, modules, commands. |
| `src/vtsvc/pkgproto/storm/` | The Storm code of each command and module. |
| `tests/` | Tests, the fake VirusTotal server, and captured responses. |

## defs.py

`SVC_GUID = 176fcd24cf1f42bfa5d95a013eec1487` is the guid of the `meta:source` node.
`SVC_EVTS["add"]` is Storm the Cortex runs once as root when the service is added: it makes
the source node and initializes the Cortex globals `slib:vt:tag:enabled` (`true`) and
`slib:vt:tag:prefix` (`rep.vt`) if they're unset. `PKGDEFS` is the package built by
`stormlibpp.StormPkg` from `pkgproto/slib.vt.yaml` and the `storm/` files (the yaml has
`genopts: dotstorm: true`, so each command's and module's code is read from
`storm/commands/<name>.storm` and `storm/modules/<name>.storm`). The package's version comes
from the yaml, and a test checks it matches `__version__` (see {doc}`/dev/versioning`).

## api.py

`VtCellApi(RetnApi, s_cell.CellApi, s_stormsvc.StormSvc)`:

- `RETN_METHS` lists the 20 `VtSvc` methods exposed as-is; `RetnApi` generates a Telepath
  method for each that awaits `self.cell.<name>(...)` and wraps the result or error.
- `RETN_ERRORS = (VtApiError, VtQuotaError)`: their messages go to Storm unchanged.
- `setApiKey`, `hasApiKey`, and `community` are written by hand and return `BoolRetn`s;
  `RetnApi` guards them so they can't raise either.
- `_retnRedact()` scrubs the stored key and the `vt:apikey` key from every error message
  (`VtSvc.redact()`).
- `_storm_svc_name`, `_storm_svc_vers` (from `stormlibpp.utils.normver`), `_storm_svc_evts`,
  and `_storm_svc_pkgs` make it a Storm service that provides its own package.

See [API](api.md) for every method.

## svc.py

`VtSvc(s_cell.Cell)`. `__anit__`:

1. Opens two SafeKeyVals in the cell slab: `slib:vt` (the stored API key, under `apikey`)
   and `slib:vt:quota` (the limiter's state).
2. Caches `vt:community` (`self.community`) and `vt:verdict:malicious` (`self.malicious`).
3. Creates the `QuotaLimiter` (`enforce=vt:community`, the `vt:limit:*` options).
4. Creates one `aiohttp.ClientSession(trust_env=True)`, closed on fini.
5. Creates the `VtClient` with `vt:url`, `vt:timeout`, and a
   `TtlCache(vt:cache:ttl, vt:cache:size)`.

Key resolution is `getApiKey(apikey) = apikey or stored key or vt:apikey`, used by
`_api()`, which every endpoint method calls.

Module level tables:

| Name | Value |
| --- | --- |
| `COLLECTIONS` | `file` -> `files`, `url` -> `urls`, `domain` -> `domains`, `ip_address` -> `ip_addresses` |
| `PUBLIC_RELS` | The relationships allowed per collection with `vt:community`, see [slib.vt.related](commands.md#slib-vt-related) |
| `MAX_PAGE` | `40`, the most objects per relationship or search page |
| `DIRECT_UPLOAD_MAX` | 32MB; larger files use `GET /files/upload_url` |
| `UPLOAD_MAX` | 650MB, the largest file VirusTotal accepts |
| `VERDICTS` | `("harmless", "malicious")` |

Path segments are URL quoted with `quote(str(v), safe="")`, so an identifier can't add path
segments. URLs are identified by their unpadded URL safe base64 (`norm.urlId`) when the
identifier contains `://`.

`related()` pages through `getRelated()`: each page asks for `min(limit - got, 40)` objects
and passes the previous page's `meta.cursor`. It stops at `limit` objects, on a page without
a cursor or without objects, or on a 404. A singular relationship (ex. a domain's `parent`)
returns one object rather than a list, which is wrapped. The result includes
`norm.relEdge()` for the relationship.

`submitFile()` joins the chunks, checks the size, gets an upload URL above 32MB, and posts an
`aiohttp.FormData` with `file` (filename `name` or `sample`) and optional `password`.
`waitAnalysis()` polls with `asyncio.sleep(interval)` until `done`, or until the next poll
would be past `timeout`.

## client.py

`VtClient.request(method, path, *, apikey, params, json_data, form, data, cache)`:

- **Auth**: `x-apikey: <key>` and `accept: application/json` headers. No key raises
  `NoApiKeyError` before anything else.
- **URL**: `vt:url` (trailing `/` stripped) plus `path`. A `path` that starts with `http://`
  or `https://` is used as-is (the one time upload URL). `VtSvc.rawRequest()` only passes a
  full URL on if it's on `vt:url`'s scheme and host.
- **Params**: `normParams()` drops `None` values, sends booleans as `true`/`false` and lists
  as comma separated strings, and rejects non dict params.
- **Body**: at most one of `json_data` (JSON), `form` (URL encoded, normalized like params),
  or `data` (as-is, ex. multipart).
- **Cache**: only for GETs with `cache=True`, keyed by `(keyId(apikey), url, sorted params)`.
  Hits return before the limiter; successful (`< 400`) responses are stored.
- **Quota**: `limiter.acquire(apikey)` before each attempt.
- **Timeout**: `aiohttp.ClientTimeout(total=vt:timeout)` per attempt.
- **Retries**: up to `MAX_RETRIES = 2` for `TRANSIENT = {TransientError,
  DeadlineExceededError}` or HTTP 502/503/504, sleeping `backoff * 2**attempt` (`backoff`
  defaults to 5 seconds).
- **No pagination** at this level; see `related()`.

Errors:

| Condition | Raises |
| --- | --- |
| `aiohttp.ClientError` or `TimeoutError` | `VtApiError("Unable to connect to VirusTotal: <err>")` (not retried) |
| A `< 400` response that isn't JSON | `VtApiError("Unable to parse the JSON response from <METHOD> <path>")` |
| HTTP 429 | cooldown, then `VtQuotaError` |
| HTTP 404 or error code `NotFoundError` | `NotFoundError` |
| HTTP 401 | `VtApiError("VirusTotal rejected the API key: ...")` |
| HTTP 403 | `VtApiError("VirusTotal denied access, this may need a premium (VT Enterprise) API key: ...")` |
| Any other error | `VtApiError(<message>)` |

`VtApiError` carries `mesg`, `code` (HTTP status), and `error` (VirusTotal's error code).
`errInfo()` formats VirusTotal's `{"error": {"code", "message"}}` as `<message> (<code>,
HTTP <status>)`.

`TtlCache(ttl, size, clock=time.monotonic)` is an `OrderedDict` LRU whose entries expire
`ttl` seconds after they're set. `ttl` or `size` of 0 disables it. Expired entries are
removed when they're looked up, or evicted by size.

## quota.py

`QuotaLimiter` is described in full on [Rate limits and quotas](quota.md). Its `clock` and
`sleep` can be replaced, which the tests use to run hours of limits instantly.

## Normalization

`norm.py` turns each VirusTotal object (`{"id", "type", "attributes"}`) into a flat dict the
Storm model reads, so the Storm side does no parsing. Every `norm*` result has `type` and
`id`. Common to files, domains, IPs, and URLs (`_common()`, values illustrative):

```json
{
  "type": "domain", "id": "example.com",
  "scan": {"time": 1793698573000, "verdict": 10,
           "counts": {"total": 92, "malicious": 0, "suspicious": 0, "benign": 66, "unknown": 26},
           "engines": [{"name": "...", "version": null, "update": null,
                        "category": "harmless", "verdict": 10, "signame": null}],
           "detections": 0},
  "tags": [], "reputation": 0, "votes": {"harmless": 0, "malicious": 0},
  "modified": 1793600000000,
  "vtags": ["verdict.benign"]
}
```

Then per type:

| Function | Adds |
| --- | --- |
| `normFile` | `sha256`, `sha1`, `md5`, `size`, `ssdeep`, `tlsh`, `vhash`, `authentihash`, `imphash`, `compiled`, `name`, `names`, `magic`, `filetype`, `type_tag`, `first_seen`, `last_seen`, `first_seen_itw`, `times_submitted`, `threat` (`label`, `names`, `categories`), `sandboxes`, `yara`, `ids`, `sigma`, `signature` |
| `normDomain` | `fqdn`, `whois` (`text`, `asof`, `registrar`, `created`, `expires`, `updated`), `dns` (`type`, `value`, SOA `email`), `dns_time`, `cert`, `jarm`, `categories`, `first_seen` |
| `normIp` | `ip`, `version`, `asn`, `as_owner`, `country`, `network`, `rir`, `whois`, `jarm`, `cert`, `https` (`tcp://<ip>:443`), `first_seen` |
| `normUrl` | `url`, `final`, `redirects`, `title`, `code`, `content_sha256`, `content_size`, `threat_names`, `categories`, `first_seen`, `last_seen`, `times_submitted`, `links` |
| `normResolution` | `fqdn`, `ip`, `version`, `time`, `resolver` |
| `normComment` | `text`, `time`, `tags`, `votes` |
| `normAnalysis` | `status`, `time`, `done`, `scan`, `sha256`, `md5`, `sha1`, `size`, `url` |
| `normHistWhois` | `text`, `asof`, `registrar`, `created`, `expires`, `updated` |
| `normCert` | `sha256`, `sha1`, `serial`, `subject`, `subject_cn`, `issuer`, `notbefore`, `notafter`, `selfsigned`, `sans`, `crls`, `time` |
| `normBehaviour` | `verdicts`, `tags`, `vtags`, `dns`, `traffic`, `http`, `techniques`, `mutexes`, `dropped` |

Some normalized fields (ex. `reputation`, `votes`, `tlsh`, `title`, `rir`) are returned to
Storm but not modeled; see [Data model](model.md). Other object types become a stub
`{"type", "id"}`, which the Storm side prints rather than models. `verdict()`, `counts()`,
`objTags()`, and `tagPart()` derive the verdicts and tag names described on the
[Data model](model.md#tags) page; `REL_EDGES` / `relEdge()` define the relationship edges.

## Storm package

- **Perms**: `slib.vt.user`, `slib.vt.submit`, `slib.vt.admin`, each `gate: cortex`.
- **Privileged modules**: `slib.vt.priv.user`, `slib.vt.priv.submit`, and
  `slib.vt.priv.admin` declare `asroot:perms`, so importing them needs the permission and
  they then run with root's permissions. They are the only code that calls the service
  (users don't need `service.get`), read the caller's own key from their user scoped
  `virustotal` vault, and only pass it on: the service-wide key never comes back to Storm.
- **Unprivileged modules**: `slib.vt.lib` (command logic), `slib.vt.model` (node edits), and
  `slib.vt.util`. They declare no perms (a module's `perms` key isn't enforced by Synapse);
  `slib.vt.lib` still needs `slib.vt.user`, since its `init` imports `slib.vt.priv.user`. Node edits run as the caller, so they're subject to the caller's node
  permissions.
- **Commands** are thin: each parses its options, calls `slib.vt.lib` or a `priv` module,
  and reports failures with `slib.vt.util.failed()`. Commands with `--yield` collect nodes
  and yield them in `fini` after `spin`ning the inbound nodes.
- **Settings**: the tag settings are the Cortex globals `slib:vt:tag:enabled` and
  `slib:vt:tag:prefix`. `slib.vt.lib`'s `init` calls `slib.vt.model.setPrefix()` with
  `slib.vt.priv.user.tagPrefix()`. There are no other configvars; everything else is the
  service's cell config.
- **onload**: the package has none. Setup happens in the service's `add` event.
- **Model quirk**: functions in `slib.vt.model` that loop never yield their node inside the
  loop; loops call helpers that edit the node in their own runtime (see the note at the top
  of `slib.vt.model.storm`).
- The Storm code lints clean with `synapse.tools.storm.lint`, and CI blocks on it
  (`storm_lint: block`). The `noqa` comments mark 2.x APIs the package needs.

## Background tasks and state

The service runs no background loops; all work happens in Telepath calls. Its state:

| State | Where | Lifetime |
| --- | --- | --- |
| Service-wide API key | slab, SafeKeyVal `slib:vt`, key `apikey` | until cleared |
| Rate limiter counts | slab, SafeKeyVal `slib:vt:quota` | see [Persisted state](quota.md#persisted-state) |
| Response cache | memory | `vt:cache:ttl`, until restart |
| Per key locks | memory | until restart |
| Tag settings | Cortex globals | until changed |
| Per user keys | Cortex vaults | until the user clears them |

The service doesn't use the Axon itself; `slib.vt.priv.submit` reads files from the Cortex's
Axon and sends the chunks over Telepath.

## Tests

```bash
cd svcs/virustotal
uv run pytest
```

| File | Covers |
| --- | --- |
| {src}`svcs/virustotal/tests/fakevt.py` | `FakeVt`, an aiohttp server on `127.0.0.1` that mimics `/api/v3` from captured, trimmed Public API responses in `tests/data/`, keeps mutable state (votes, analysis polls), and records every request, key, and body. It accepts two keys (`"a" * 64`, `"b" * 64`), answers 401 for others and 429 for the key `"429"`, and can force a status for a path (`fake.status`). Relationship pages honor `limit` and an integer `cursor`. `vtSvc()` yields a Cortex with the service added and pointed at the fake, with all limits set to `0` unless a test sets them. |
| {src}`svcs/virustotal/tests/test_quota.py` | The limiter with a fake clock and dict store: the window, spacing (never 5 in 60s), daily reset and pruning, monthly limit, per key counts, `maxwait`, not enforced, persistence across instances, cooldown, and a real LMDB slab. |
| {src}`svcs/virustotal/tests/test_client.py` | Errors (no key, 404, 401, 429, two bodies, 503 retries, connection failure), the cache (per key, per params), `TtlCache`, and param normalization. |
| {src}`svcs/virustotal/tests/test_norm.py` | The normalizers against the captured responses. |
| {src}`svcs/virustotal/tests/test_vt_storm.py` | The package end to end: loading, every command, modeling, tags, guid stability, rate limits through Storm, API keys, admin commands, and permissions. Also `assertVersionsMatch()`, `assertMainHelp()`, and that `README.md` matches `pkgproto/README.md`. |
| {src}`svcs/virustotal/tests/test_live.py` | Against the real API, skipped unless enabled. Read only, about 12 requests, with the default limits (about 3 minutes). |

```bash
SLIB_VT_LIVE=1 VT_API_KEY=<key> uv run pytest tests/test_live.py -s
```

`tests/conftest.py` loads the `stormlibpp.testing` plugin, which fails tests that use
deprecated Synapse APIs; `pyproject.toml` also turns `DeprecationWarning`s from `vtsvc` into
errors. See {doc}`/dev/testing`.
