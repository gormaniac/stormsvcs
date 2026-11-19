# API

The `slib.vt` package's Storm modules and the service's Telepath API.

## TelepathRetn

Every Telepath method returns a `TelepathRetn`
([StormLib++](https://docs.gormo.co/stormlibpp/), `stormlibpp.telepath`), a dict:

```json
{"status": true, "mesg": "", "data": {"...": "..."}}
```

| Key | Meaning |
| --- | --- |
| `status` | `true` if the call worked, `false` if it failed. |
| `mesg` | The error message when `status` is false (empty on success, except `setApiKey`). |
| `data` | The return value when `status` is true, `null` when it failed. |

`VtCellApi` ({src}`svcs/virustotal/src/vtsvc/api.py`) subclasses `stormlibpp.svc.RetnApi`,
so no method raises to Storm. Errors become `status=false` returns:

| Error | `mesg` |
| --- | --- |
| `VtApiError` and its subclasses (`NoApiKeyError`, `NotFoundError`, `VtSvcError`), `VtQuotaError` (the `RETN_ERRORS`), and Synapse `AuthDeny` | The error's own message. |
| `ValueError`, `TypeError`, `s_exc.BadArg` | `Invalid input: <message>` |
| Anything else | `Unexpected error: <type>: <message>`, logged with its traceback. |

`VtCellApi._retnRedact()` replaces the service's stored key and the `vt:apikey` key (and
their URL quoted forms) with `<redacted>` in every error message. The key is sent in the
`x-apikey` header, and only `quota(remote=True)` puts it in a URL path
(`/users/{key}/overall_quotas`), so an error such as `Unable to parse the JSON response from
GET /users/<redacted>/overall_quotas` never shows it. A user's own key (from their vault) is
not redacted; only they can send requests with it.

Some example error messages:

```text
No VirusTotal API key is configured. Run slib.vt.apikey to set your own key, or slib.vt.admin.apikey to set a service-wide key.
VirusTotal rejected the API key: Wrong API key (WrongCredentialsError, HTTP 401)
VirusTotal denied access, this may need a premium (VT Enterprise) API key: <message> (<code>, HTTP 403)
VirusTotal rejected the request for going over a quota: Quota exceeded (QuotaExceededError, HTTP 429)
The VirusTotal daily quota (500 requests) for this API key is used up, it resets at 00:00 UTC (in 3h 12m).
Timed out waiting for room under the VirusTotal rate limit of 4 requests per minute (vt:limit:maxwait is 600s). Try again later, or with fewer nodes.
The urls relationship of domains isn't available to VirusTotal Public API keys. Available: comments, votes, ...
Unknown VirusTotal object type: foo
Unable to connect to VirusTotal: <aiohttp error>
```

VirusTotal's own errors are formatted `<message> (<error code>, HTTP <status>)`; a non JSON
error body is `<first 500 chars> (HTTP <status>)`, and an empty or HTML one is
`HTTP <status>`.

## Telepath methods

`kind` is one of `file`, `url`, `domain`, `ip_address`, or a collection name (`files`,
`urls`, `domains`, `ip_addresses`); anything else fails with `Unknown VirusTotal object
type: <kind>`. `ident` is a hash, URL, domain, or IP; a URL containing `://` is converted to
its unpadded URL safe base64 id. Every method that sends a request takes `apikey` (default
`None`: the stored key, then `vt:apikey`). "Cache" means the request may be answered from,
and saved to, the response cache.

All of these are generator free: `GENR_METHS` is empty, and each method returns one
TelepathRetn.

### Lookups

| Method | Request | Cache | `data` |
| --- | --- | --- | --- |
| `getObject(kind, ident, cache=True, apikey=None)` | `GET /{collection}/{id}` | `cache` | VirusTotal's raw JSON (`{"data": {...}}`). A 404 is a `NotFoundError` (status false). |
| `lookup(kind, ident, cache=True, apikey=None)` | as `getObject` | `cache` | The normalized object (see [Internals](internals.md#normalization)), or `null` if VirusTotal doesn't have it. |
| `getRelated(kind, ident, rel, limit=10, cursor=None, cache=True, apikey=None)` | `GET /{collection}/{id}/{rel}?limit=&cursor=` | `cache` | One raw page. `limit` is clamped to 1..40. With `vt:community`, `rel` must be in the Public relationships list. |
| `related(kind, ident, rel, limit=10, cache=True, apikey=None)` | pages of `getRelated` | `cache` | `{"items": [<normalized>...], "count": <VirusTotal's meta.count or null>, "requests": <pages fetched>, "edge": {"verb": "refs", "dir": "out" \| "in"} or null}` |
| `comments(kind, ident, limit=10, apikey=None)` | `related(..., "comments")` | yes | As `related`. |
| `rels(coll)` | none | | The list of relationships of a collection a Public API key can read (`PUBLIC_RELS`), the ones `getRelated()` allows with `vt:community`. An unknown collection fails with `Unknown VirusTotal object type: <coll>`. |
| `behaviour(sha256, apikey=None)` | `GET /files/{sha256}/behaviour_summary` | yes | The normalized summary, or `null` on a 404 or an empty `data`. |
| `search(query, limit=10, apikey=None)` | `GET /search?query=&limit=` | yes | `{"items": [<normalized>...], "count": <meta.count, or len(items)>}`. `limit` clamped to 1..40. |
| `threatCategories(apikey=None)` | `GET /popular_threat_categories` | yes | VirusTotal's `data` list. |
| `attackTechnique(tid, apikey=None)` | `GET /attack_techniques/{tid}` | yes | VirusTotal's `data` object. |

### Submissions and community

| Method | Request | `data` |
| --- | --- | --- |
| `addComment(kind, ident, text, apikey=None)` | `POST /{collection}/{id}/comments` | The normalized comment (`{"type": "comment", "id", "text", "time", "tags", "votes"}`). Empty text fails. |
| `addVote(kind, ident, verdict, apikey=None)` | `POST /{collection}/{id}/votes` | VirusTotal's vote object. `verdict` must be `harmless` or `malicious`. |
| `rescan(kind, ident, apikey=None)` | `POST /{collection}/{id}/analyse` | `{"type": "analysis", "id": <id>}` |
| `submitUrl(url, apikey=None)` | `POST /urls` (form `url=<url>`) | `{"type": "analysis", "id": <id>}` |
| `submitFile(chunks, name=None, password=None, apikey=None)` | `POST /files` multipart, or `GET /files/upload_url` then a `POST` to that URL when over 32MB | `{"type": "analysis", "id": <id>}`. `chunks` is a list of bytes joined into the file. Empty files and files over 650MB fail. |
| `analysis(ident, apikey=None)` | `GET /analyses/{id}` | The normalized analysis. |
| `waitAnalysis(ident, timeout=600, interval=30, apikey=None)` | `GET /analyses/{id}` per poll | The last normalized analysis; check `done`. `interval` is raised to at least 15 (`vt:community`) or 1. |

A normalized analysis:

```json
{
  "type": "analysis", "id": "u-275a021b-1793698573", "status": "completed",
  "time": 1793698573000, "done": true,
  "scan": {"time": 1793698573000, "verdict": 40,
           "counts": {"total": 97, "malicious": 8, "suspicious": 1, "benign": 70, "unknown": 18},
           "engines": [{"name": "...", "version": null, "update": null, "category": "malicious",
                        "verdict": 40, "signame": "..."}],
           "detections": 9},
  "sha256": null, "md5": null, "sha1": null, "size": null,
  "url": "http://www.eicar.org/download/eicar.com.txt"
}
```

`scan` is `null` until VirusTotal returns `stats`. `sha256`/`md5`/`sha1`/`size` come from
`meta.file_info` (file analyses), `url` from `meta.url_info` (URL analyses).

### Quota and raw requests

| Method | Request | `data` |
| --- | --- | --- |
| `quota(remote=False, apikey=None)` | none, or `GET /users/{key}/overall_quotas` with `remote` | The limiter's status for the resolved key, see below. Fails with `No VirusTotal API key is configured.` without a key. |
| `rawRequest(method, path, params=None, json_data=None, form=None, apikey=None)` | `method path` | VirusTotal's parsed JSON, or `null` for an empty body. Rate limited, not cached. At most one of `json_data` / `form`. `path` is relative to `vt:url`; a full URL (or `//host/...`) on any other scheme and host fails with `Only requests to the VirusTotal API (<scheme>://<host>) are allowed, ...`, so the key is never sent elsewhere. |
| `apiKeySource()` | none | `"stored"` (set with `setApiKey`), `"config"` (`vt:apikey`), or `null`: which service-wide key is in use. |

`quota()` data:

```json
{
  "enforced": true,
  "limits": {"minute": 4, "day": 500, "month": 15500},
  "used": {"minute": 2, "day": 2, "month": 2},
  "wait": 0.0,
  "resets": 1795132800000,
  "resetsMonth": 1796083200000,
  "cached": 2,
  "remote": {
    "api_requests_hourly": {"allowed": 240, "used": 0},
    "api_requests_daily": {"allowed": 500, "used": 0},
    "api_requests_monthly": {"allowed": 15500, "used": 0}
  }
}
```

`remote` is only present with `remote=True`, and keeps only VirusTotal's `api_requests_*`
quotas (their `user` part). The fields are explained in
[Rate limits and quotas](quota.md#inspecting-usage).

### API key and mode

These are written by hand on `VtCellApi` rather than listed in `RETN_METHS`:

| Method | `data` |
| --- | --- |
| `setApiKey(apikey)` | `true`. Stores the service-wide key, or removes it when `apikey` is `null`/empty. `mesg` is `Set the slib.vt API key.` or `Cleared the slib.vt API key.` |
| `hasApiKey()` | Whether a stored key or `vt:apikey` is set. |
| `community()` | The `vt:community` setting. |

Telepath methods are not permission checked; see the warning in
[API keys](deployment.md#api-keys).

## Storm modules

| Module | Runs as | Permission to import | Purpose |
| --- | --- | --- | --- |
| `slib.vt.priv.user` | root (`asroot:perms` `slib.vt.user`) | `slib.vt.user` | Read only service calls, the tag prefix. |
| `slib.vt.priv.submit` | root (`asroot:perms` `slib.vt.submit`) | `slib.vt.submit` | Calls that send data to VirusTotal, Axon reads. |
| `slib.vt.priv.admin` | root (`asroot:perms` `slib.vt.admin`) | `slib.vt.admin` | The service-wide key, tag settings, raw requests. |
| `slib.vt.lib` | the caller | `slib.vt.user` (through its import of `slib.vt.priv.user`) | The command logic: look up and model. |
| `slib.vt.model` | the caller | none | Node creation from normalized dicts. |
| `slib.vt.util` | the caller | none | Printing and node to VirusTotal object helpers. |

The `priv` modules are the only code that calls `$lib.service.get("slib.vt")`. Each one
reads the caller's API key with `userKey()`: the `apikey` secret of
`$lib.vault.bytype(virustotal, scope=user)`, or `null`. Only the user scope is read, and
the service-wide key is never returned to Storm.

### slib.vt.priv.user

Every function returns the service's `{status, mesg, data}` dict, using the caller's key.

| Function | Calls |
| --- | --- |
| `lookup(kind, ident, cache=(true))` | `lookup()` |
| `behaviour(sha256)` | `behaviour()` |
| `related(kind, ident, rel, limit=(10))` | `related()` |
| `rels(kind)` | `rels()` |
| `comments(kind, ident, limit=(10))` | `comments()` |
| `search(query, limit=(10))` | `search()` |
| `analysis(ident)` | `analysis()` |
| `waitAnalysis(ident, timeout=(600), interval=(30))` | `waitAnalysis()` |
| `quota(remote=(false))` | `quota()` |
| `tagPrefix()` | The tag prefix (`slib:vt:tag:prefix`), or `null` when `slib:vt:tag:enabled` is false. Not a service call. |
| `userKey()` | The caller's own key, or `null`. |

### slib.vt.priv.submit

| Function | Calls |
| --- | --- |
| `submitFile(sha256, size, name=(null), password=(null))` | Checks the Axon has the file, `size` is set and at most 681574400, reads it in 1MiB chunks, then `submitFile()`. Its own failures are returned as `{"status": false, "mesg": ..., "data": null}`. |
| `submitUrl(url)` | `submitUrl()` |
| `rescan(kind, ident)` | `rescan()` |
| `addComment(kind, ident, text)` | `addComment()` |
| `addVote(kind, ident, verdict)` | `addVote()` |

### slib.vt.priv.admin

| Function | Does |
| --- | --- |
| `setApiKey(apikey)` | `setApiKey()` |
| `hasApiKey()` | `hasApiKey()` |
| `apiKeySource()` | `apiKeySource()` |
| `tagSettings()` | `{"enabled": <slib:vt:tag:enabled>, "prefix": <slib:vt:tag:prefix>}` |
| `setTagPrefix(prefix)` | Casts to `syn:tag` (raises `BadArg` if invalid), stores and returns it. |
| `setTagsEnabled(enabled)` | Sets `slib:vt:tag:enabled`. |
| `rawRequest(path, method=get, params=(null), json=(null))` | `rawRequest()` with the caller's key. |

### slib.vt.lib

Usable from other Storm code by users with `slib.vt.user`. Each function warns or prints
instead of raising, and makes node edits as the caller.

| Function | Returns |
| --- | --- |
| `enrich(kind, ident, engines=detected, behaviour=(false), cache=(true), name="slib.vt.enrich")` | The modeled node, or `null` (not found, failed, or not modelable). |
| `subject(n)` | The node related objects and comments are linked to (see [slib.vt.related](commands.md#slib-vt-related)). |
| `related(n, kind, ident, rel, limit=(10), name="slib.vt.related")` | The list of related nodes. |
| `comments(n, kind, ident, limit=(10))` | The list of `meta:note` nodes. |
| `analysis(a, engines=detected, name="slib.vt.analysis")` | The analyzed node of a completed normalized analysis `a`, else `null`. |

```text
$vt = $lib.import(slib.vt.lib)
$node = $vt.enrich(domain, example.com)
$nodes = $vt.related($node, domain, example.com, resolutions, limit=(40))
```

### slib.vt.model

Node creation, used by `slib.vt.lib`. Its main entry points take the normalized dicts from
the service: `obj(o, engines=detected, n=(null))` (any object), `file(f, engines)`,
`domain(d, engines)`, `ip(i, engines)`, `url(u, engines)`, `behaviour(n, b)`,
`comment(n, c)`, `analysis(a, engines)`, `scan(n, scan, engines, signame, categories)`, and
`setPrefix(prefix)` (the tag prefix for this runtime, `null` disables tags). Helpers like
`fqdnNode()`, `ipNode()`, `urlNode()`, `sha256Node()`, `dnsNode()`, `edge()`, and `tags()`
make single nodes. It does no permission checks of its own.

### slib.vt.util

| Function | Returns |
| --- | --- |
| `failed(retn, what)` | `true` (after warning `slib.vt: <what> failed: <mesg>`) if `retn.status` is false. |
| `target(n)` | `(kind, ident)` for a node, or `null`, see [Conventions](commands.md#conventions). |
| `when(time)` | An epoch millis time as `%Y-%m-%d %H:%M:%S UTC`, or `never`. |
| `detections(scan)` | `"<m> malicious, <s> suspicious of <n> engines"`, or `"not scanned"`. |
| `table(columns, rows)` | Prints a `$lib.tabular` table. |
| `printJson(valu)` | Prints indented JSON. |
