# API

The service has two APIs: the Storm modules in the `slib.hatching` package, for Storm code
that wants more than the commands, and the service's Telepath API, which only the package's
privileged modules call.

## Storm modules

| Module | Requires | Runs as | Purpose |
| --- | --- | --- | --- |
| `slib.hatching.lib` | `slib.hatching.user` to import | The caller | The user API: find, model, download, and submit. Functions warn on failure and return a node (or list of nodes), or `null`. |
| `slib.hatching.model` | `slib.hatching.user` to import | The caller | Builds nodes from normalized data (see [Model](model.md)). |
| `slib.hatching.util` | Nothing | The caller | Shared helpers: the caller's API key, warnings, hash detection, tables. |
| `slib.hatching.priv.user` | `slib.hatching.user` | root (`asroot:perms`) | Wrappers around the read-only service methods. |
| `slib.hatching.priv.submit` | `slib.hatching.submit` | root | Wrappers around submission, profile picking, import, and delete. |
| `slib.hatching.priv.manage` | `slib.hatching.manage` | root | Wrappers around profile and Yara rule changes. |
| `slib.hatching.priv.admin` | `slib.hatching.admin` | root | Wrappers around the service-wide key, tag settings, users, org settings, and raw requests. |

The `priv` modules are the only code that calls `$lib.service.get("slib.hatching")`. They run as
root for callers that hold the listed permission, so users don't need `service.get`, and a
caller can't reach the service (or its stored key) except through these wrappers. Each wrapper
passes the caller's own key (`slib.hatching.util.userKey()`) as the `apikey` argument. The `priv`
functions return the service's `{status, mesg, data}` dict unchanged (generators `emit` them);
they don't warn.

### slib.hatching.lib

```text
$hatching = $lib.import(slib.hatching.lib)
```

| Function | Returns | Description |
| --- | --- | --- |
| `model(sample, tasks=(false))` | The sample node, or `null` | Model a reported sample by ID or hash (`normSample`), printing a summary and warning about report errors. With `tasks`, also its behavioral tasks. Uses the configured tag prefix. |
| `findSample(query, url=(null))` | A sample ID, or `null` | The newest `reported` sample among the first 50 results of a Triage search. With `url`, only a `url` kind sample whose `url` equals it. |
| `nodeQuery(node)` | A search query, or `null` | `url:"<url>"` for an `inet:url`, `<hashtype>:<hash>` for a `file:bytes` (`:sha256`, then `:sha1`, `:md5`, `:sha512`) or `hash:*` node. |
| `enrich(node, tasks=(false))` | The sample node, or `null` | `findSample($nodeQuery($node))`, then `model()`. |
| `downloadSample(sample)` | A `file:bytes`, or `null` | Download a file sample into the Axon (warns for a URL sample). |
| `downloadTaskFile(sample, task, name)` | A `file:bytes`, or `null` | Download a task file (ex. `dump.pcap`) into the Axon. |
| `downloadArchive(sample, fmt=tar)` | A `file:bytes`, or `null` | Download the `tar` or `zip` archive into the Axon, named `<sample ID>.<fmt>` (a hash is resolved to its sample's ID first). |
| `downloadPcaps(sample, task=(null), pcapng=(false))` | A list of `file:bytes` | `dump.pcap` (or `dump.pcapng`) of `task`, or of every reported behavioral task in the overview report (the service's `sampleTasks`). |
| `downloadDumped(sample)` | A list of `file:bytes` | Every file dropped during the reported behavioral tasks (`dumpedFiles`). |
| `submitNode(node, opts)` | A node, the sample's metadata dict, or `null` | Submit a `file:bytes` (from the Axon) or `inet:url`. `opts` is the `slib.hatching.submit` options dict (see below). Requires `slib.hatching.submit` too. |
| `submitUrl(url, opts)` | A node, the sample's metadata dict, or `null` | Submit a URL. Requires `slib.hatching.submit` too. |

`opts` keys, as built by `slib.hatching.submit`: `fetch`, `interactive`, `password`, `profiles`
(a list of `profile` or `profile:pick` strings), `tags`, `timeout`, `network`, `geolocation`,
`name` (the filename for a file), `wait` (seconds, `0` for no wait), and `tasks`. With a non-zero
`wait`, the submission is waited on and modeled, and the sample's node is returned; otherwise (or
if it isn't reported in time) the sample's metadata dict is returned.

```text
$hatching = $lib.import(slib.hatching.lib)

// Model a sample and work with its node.
$file = $hatching.model("261031-a1b2c3d4e5", tasks=(true))
if $file { yield $file }

// Download the pcaps of every behavioral task.
for $n in $hatching.downloadPcaps("261031-a1b2c3d4e5") { yield $n }
```

### slib.hatching.model

The node builders. The entry point is `sample(data, prefix=(null))`, which takes the `data` of
a `normSample` call and returns the sample's node (or `null`). `prefix=(null)` applies no tags.
The other functions model one piece each and are called by `sample()`: `scan`, `sigResult`,
`member`, `credsNode`, `family`, `c2config`, `c2configNode`, `dropperUrls`, `ransomNote`,
`taskNodes`, `procNode`, `flowNode`, `ipGeo`, `dnsNode`, `answerNode`, `httpNode`, `fileAdd`, and
the observable helpers `ipNode`, `hostNode`, `urlNode`, `emailNode`, `mutexNode`,
`techniqueNode`, `fileNode`, `fileBySha256`, and `axonFile(sha256, size=(null), name=(null))`.
`nodes(items)` yields the non-null nodes of a list.

### slib.hatching.util

| Function | Description |
| --- | --- |
| `userKey()` | The caller's own API key: the `apikey` secret of their user scoped vault of type `hatching`, or `null`. Only the user scope is read. |
| `failed(retn, what)` | Warn `slib.hatching: <what> failed: <mesg>` and return `true` if `retn.status` is false. |
| `hashType(valu)` | `md5`, `sha1`, `sha256`, or `sha512` for a hex string of that length, else `null`. |
| `nodeHash(node)` | The best hash of a `file:bytes` or `hash:*` node, or `null`. |
| `table(columns, rows)`, `printJson(valu)`, `printSamples(samples)` | Output helpers. |
| `basename(path)` | The last part of a Windows or POSIX path. |

## Telepath API

The Cell API is `hatchingsvc.api.HatchingCellApi`
({src}`svcs/hatching/src/hatchingsvc/api.py`), which subclasses StormLib++'s
`stormlibpp.svc.RetnApi`, `synapse.lib.cell.CellApi`, and `synapse.lib.stormsvc.StormSvc` (name
`slib.hatching`, the package in `PKGDEFS`, and the `add` event in `SVC_EVTS`).

### TelepathRetn

Every method returns, and every generator yields, a `TelepathRetn` dict
([StormLib++](https://docs.gormo.co/stormlibpp/)):

```json
{"status": true, "mesg": "", "data": "<the method's return value>"}
```

```json
{"status": false, "mesg": "Hatching Triage: NOT_FOUND - <message> (HTTP 404)", "data": null}
```

The methods never raise to the caller. `RetnApi` builds them from the `HatchingSvc` methods named
in `RETN_METHS` (coroutines) and `GENR_METHS` (async generators), and turns any exception into a
`status=False` return:

| Exception | `mesg` |
| --- | --- |
| `HatchingApiError` (the only `RETN_ERRORS` entry) | Its own message, ex. `Hatching Triage: <error> - <message> (HTTP <status>)` for an API error, `Hatching Triage: <error>` for a connection or validation error, or the service's own validation messages. |
| Synapse `AuthDeny` | Its own message. |
| `ValueError`, `TypeError`, `BadArg` | `Invalid input: <error>` (ex. `limit="nope"`). |
| Anything else | `Unexpected error: <type>: <error>`, logged with its traceback by `stormlibpp.svc`. |

A generator that fails yields one `status=False` item and stops. `_retnRedact()` replaces the
service's own API keys (the stored key and `hatching:apikey`) in every error message with
`<redacted>`, so they can't reach Storm. A caller's own key (its `apikey` argument) isn't
redacted.

### Arguments

Every Triage-backed method takes an optional `apikey` keyword argument: the caller's own key,
which wins over the stored key and `hatching:apikey`. A `sample` argument is a sample ID or a
file hash (MD5, SHA1, SHA256, SHA512, ssdeep), resolved by `resolve`. Values are returned as
plain, msgpack-safe JSON: pyhatching's models are dumped `by_alias` with `None` fields dropped,
so `data` has the Triage API's own field names.

### Keys and settings

| Method | `data` | Description |
| --- | --- | --- |
| `setApiKey(apikey)` | `true` | Store (or with `null`/`""` clear) the service-wide key. `mesg` is `Set the slib.hatching API key.` or `Cleared the slib.hatching API key.` Hand-written in the API class. |
| `hasApiKey()` | bool | Whether a stored key or `hatching:apikey` is set. Hand-written. |
| `maxSize()` | int | `hatching:maxsize`. |
| `resolve(sample, apikey=None)` | str | A sample ID. A hash is searched (`<hashtype>:<hash>`, 20 results); the newest `reported` sample wins, else the newest. Fails with `Hatching Triage has no sample for <hash>.` A non-hash is returned stripped, unchanged. |
| `rawRequest(method, path, params=None, json_data=None, apikey=None)` | Any JSON | Any request (ex. `"get", "/v0/samples"`). A missing leading `/` is added. HTTP 400+ fails. |

### Samples

| Method | `data` | Endpoint |
| --- | --- | --- |
| `search(query, limit=20, apikey=None)` | list of sample dicts | `GET /v0/search`, paged (200 per page) up to `limit`. `limit` 0, negative, or above 1000 means 1000. |
| `samples(subset="owned", limit=20, apikey=None)` | list of sample dicts | `GET /v0/samples?subset=<owned\|org\|public>`, paged like `search`. |
| `sample(sample, apikey=None)` | sample dict | `GET /v0/samples/{id}` |
| `summary(sample, apikey=None)` | dict | `GET /v0/samples/{id}/summary` |
| `deleteSample(sample, apikey=None)` | `true` | `DELETE /v0/samples/{id}` |
| `setProfile(sample, profiles=None, auto=False, pick=None, apikey=None)` | `true` | `POST /v0/samples/{id}/profile`. `profiles` items are a name, `"profile:pick"`, or a `{profile, pick}` dict. `pick` without `profiles` sets `auto`. Fails with `Pick at least one profile, a file to analyze, or auto.` when given none, and with `Profiles can't be combined with auto or pick: ...` when given `profiles` and `auto` or `pick` (the API takes either profiles, or `auto` with the files to `pick`). |
| `magicLink(sample, apikey=None)` | str | `GET /v0/samples/{id}/magic`, returned as `<hatching:url>/<id>/magic/<token>`. |
| `submitUrl(url, fetch=False, interactive=False, profiles=None, tags=None, timeout=None, network=None, geolocation=None, apikey=None)` | sample dict | `POST /v0/samples`, kind `url` (or `fetch`). |
| `importSample(sample, apikey=None)` | sample dict | `POST /v0/samples`, kind `import`, with `url` set to the public sample's ID or URL. |
| `submitFileInit()` | str (upload ID) | Start a file upload. |
| `submitFileChunk(upload, byts)` | int (bytes so far) | Append a chunk to an upload. |
| `submitFile(upload, name, interactive=False, password=None, profiles=None, tags=None, timeout=None, network=None, geolocation=None, apikey=None)` | sample dict | `POST /v0/samples`, kind `file` (multipart), from the upload. The upload is deleted either way. |
| `wait(sample, timeout=600, apikey=None)` | sample dict | Wait up to `timeout` seconds for the status `reported` or `failed`, then return the sample. Check its `status`. |

A sample dict is Triage's sample object, ex.:

```json
{
  "id": "261031-a1b2c3d4e5",
  "status": "reported",
  "kind": "file",
  "filename": "invoice.exe",
  "private": false,
  "tasks": [
    {"id": "static1", "status": "reported"},
    {"id": "behavioral1", "status": "reported", "target": "invoice.exe"}
  ],
  "submitted": "2026-10-31T12:00:00Z",
  "completed": "2026-10-31T12:05:00Z"
}
```

Submission validation (raised as `HatchingApiError` before any request):

- `timeout` must be between 1 and 3600: `The timeout must be between 1 and 3600 seconds.`
- `geolocation` requires `network="vpn"`: `A geolocation requires the vpn network.`
- `profiles` with `interactive`: `Profiles can't be picked for an interactive submission, ...`
- An empty upload: `The file is empty.` An upload that would pass `hatching:maxsize`:
  `The file is larger than the max of <n> bytes.` (the upload is dropped). An unknown or expired
  upload ID: `The file upload doesn't exist, it may have expired.`
- pyhatching's own `SubmissionRequest` validation: `Invalid submission: <error>`.

`timeout`, `network`, and `geolocation` are sent as the request's `defaults` (used when the
sandbox picks the profiles), `tags` as `user_tags`, and `name` as `target`.

### Reports

| Method | `data` | Endpoint |
| --- | --- | --- |
| `overview(sample, apikey=None)` | dict | `GET /v1/samples/{id}/overview.json` |
| `staticReport(sample, apikey=None)` | dict | `GET /v0/samples/{id}/reports/static` |
| `taskReport(sample, task, apikey=None)` | dict | `GET /v0/samples/{id}/{task}/report_triage.json` |
| `urlscanReport(sample, task="urlscan1", apikey=None)` | dict | `GET /v0/samples/{id}/{task}/report_urlscan.json` |
| `normSample(sample, tasks=False, apikey=None)` | dict | The sample's reports normalized for modeling, see [normSample](#normsample). |
| `dumpedFiles(sample, apikey=None)` | `{"files": [...], "errors": [...]}` | The downloadable files dropped in each reported behavioral task. |
| `sampleTasks(sample, apikey=None)` | `{"id": str, "tasks": [str]}` | The sample's ID and the names of its reported behavioral tasks, from its overview report (the tasks `normSample`, `dumpedFiles`, and `download --pcap` use). |

A `task` is a task name like `behavioral1`; a full task ID (`<sample>-behavioral1`) works too.

`dumpedFiles` data:

```json
{
  "files": [
    {
      "task": "behavioral1",
      "name": "files/0x0003000000022c2b-1.dat",
      "path": "C:\\Users\\Admin\\AppData\\Roaming\\upd.exe",
      "sha256": "<lowercased sha256>",
      "size": 18
    }
  ],
  "errors": ["The behavioral2 report of 261031-a1b2c3d4e5 is unavailable: ..."]
}
```

### normSample

`normSample` fails with `Sample <id> isn't reported yet (its status is <status>).` unless the
sample is `reported`. A missing static report (`NOT_FOUND`, `REPORT_NOT_AVAILABLE`, or
`NOT_AVAILABLE`, ex. for a URL sample) is tolerated; any other error fails the call. Task reports
are fetched concurrently, and one that fails is described in `errors` instead.

```text
{
  "id", "kind", "status",
  "score": int | null,            // overview analysis.score
  "verdict": 10 | 30 | 40 | null,
  "time": epoch millis | null,    // completed, else submitted
  "ival": [submitted, max(completed, submitted + 1)] | null,
  "url": str | null,              // URL samples only
  "file": {sha256, md5, sha1, sha512, ssdeep, size, name, mime} | null,  // file samples only
  "members": [{sha256, md5, sha1, sha512, ssdeep, size, path, name, score, tags}],
  "rawtags": [str],               // Triage's tags, as reported
  "tags": [str],                  // normalized tag names (below the prefix)
  "categories": [str],            // non-family tags, lowercased
  "families": [str],              // lowercased, sorted
  "ttps": [str],                  // ATT&CK IDs, sorted
  "iocs": {"urls": [str], "hosts": [str]},
  "signatures": [{key, name, score, verdict, categories, ttps, desc}],  // by score desc, key
  "configs": [{family, servers, hosts, mutexes, decoys, listens, resolvers, wallets, creds,
               campaign, botnet, version, raw, detailed}],
  "creds": [{protocol, host, port, url, username, password, email, emailto}],
  "droppers": [{family, language, urls}],
  "ransom": [{family, emails, urls, wallets}],
  "tasks": [{
    "name", "target",             // target: the SHA256 the task ran
    "procs": [{procid, parent, pid, cmd, path, orig, sample}],
    "flows": [{id, server, client, proto, ip, ipver, port, procid, txbytes, rxbytes, txcount,
               rxcount, protocols, domain, sni, ja3, ja3s}],
    "ips": [{ip, ipver, asn, cc}],
    "dns": [{flow, index, name, type, server}],
    "answers": [{type, name, value}],
    "http": [{flow, index, method, url, headers, server, code, reason, rheaders}],
    "files": [{name, sha256, md5, sha1, sha512, ssdeep, size, path, basename, procid}]
  }],
  "errors": [str]                 // unavailable task reports, then failures Triage reported
}
```

See [Model](model.md) for how each field is normalized and modeled.

### Generators

| Method | Yields (`data` of each item) | Endpoint |
| --- | --- | --- |
| `sampleEvents(sample=None, limit=100, timeout=600, apikey=None)` | sample dicts | `GET /v0/samples/{id}/events`, or `GET /v0/samples/events` with no sample. Stops after `limit` events (`0` for no limit), `timeout` seconds, or when the stream ends. |
| `kernelReport(sample, task, log=None, limit=1000, apikey=None)` | kernel monitor event dicts | `GET /v0/samples/{id}/{task}/logs/{log}.json`. `log` is picked from the task's platform when `None`. Stops after `limit` events (`0` for all). |
| `downloadSample(sample, apikey=None)` | bytes chunks (1 MiB) | `GET /v0/samples/{id}/sample` |
| `downloadTaskFile(sample, task, name, apikey=None)` | bytes chunks | `GET /v0/samples/{id}/{task}/{name}`, ex. `dump.pcap`, `dump.pcapng`, `screenshot.png`, or a dumped file's name. |
| `downloadArchive(sample, fmt="tar", apikey=None)` | bytes chunks | `GET /v0/samples/{id}/archive` (`tar`) or `/archive.zip` (`zip`). |

The download generators fail (one `status=False` item) once the total passes `hatching:maxsize`:
`The download is larger than the max of <n> bytes.` The Storm package feeds them to
`$lib.axon.upload()` and raises a `HatchingError` on the first failed item, which aborts the
upload; the error is returned to the command as a `status=False` dict and no node is made.

### Profiles, Yara rules, users, and more

| Method | `data` | Endpoint |
| --- | --- | --- |
| `profiles(apikey=None)` | list of profile dicts | `GET /v0/profiles`, every page |
| `profile(profile, apikey=None)` | profile dict | `GET /v0/profiles/{id or name}` |
| `addProfile(name, tags=None, timeout=None, network=None, geolocation=None, apikey=None)` | profile dict | `POST /v0/profiles` (validated like a submission) |
| `editProfile(profile, name=None, tags=None, timeout=None, network=None, geolocation=None, apikey=None)` | the updated profile dict | Reads the profile, then `PUT /v0/profiles/{id}` with the current values for the unset arguments. The geolocation is dropped when the network isn't `vpn`. |
| `delProfile(profile, apikey=None)` | `true` | `DELETE /v0/profiles/{id or name}` |
| `rules(apikey=None)` | list of rule dicts | `GET /v0/yara` (its `rules`) |
| `rule(name, apikey=None)` | rule dict (`name`, `rule`, `warnings`) | `GET /v0/yara/{name}` |
| `addRule(name, text, apikey=None)` | `true` | `POST /v0/yara` |
| `editRule(name, text, apikey=None)` | `true` | `PUT /v0/yara/{name}` |
| `renameRule(name, newname, text=None, apikey=None)` | `true` | `PUT /v0/yara/{name}` with `{"name": newname, "rule": text}`; reads the current text when `text` is `None`. |
| `delRule(name, apikey=None)` | `true` | `DELETE /v0/yara/{name}` |
| `users(limit=None, apikey=None)` | list of user dicts | `GET /v0/users`, every page (`None` or `0` for all) |
| `user(user, apikey=None)` | user dict | `GET /v0/users/{id}` |
| `addUser(login, password=None, name=None, role=None, confirmed=False, apikey=None)` | user dict | `POST /v0/users`; a login with `@` is sent as `email` (with `email_confirmed` when `confirmed`), otherwise as `username`. An empty login fails with `A username or email address is required.` |
| `delUser(user, apikey=None)` | `true` | `DELETE /v0/users/{id}` |
| `userKeys(user, apikey=None)` | list of key dicts (`name`, `key`) | `GET /v0/users/{id}/apikeys` |
| `addUserKey(user, name, apikey=None)` | key dict | `POST /v0/users/{id}/apikeys` |
| `delUserKey(user, name, apikey=None)` | `true` | `DELETE /v0/users/{id}/apikeys/{name}` |
| `resources(apikey=None)` | list of resource dicts (`name`, `tags`, ...) | `GET /v0/resources`, flattened out of its groups |
| `geolocations(apikey=None)` | list of geolocation dicts (`name`, `tags`, ...) | `GET /v0/geolocations`, flattened out of its groups |
| `stats(org=False, apikey=None)` | dict | `GET /v0/stats/user`, or `/v0/stats/org` with `org` |
| `orgSettings(apikey=None)` | dict | `GET /v0/org/settings` |
| `setMagicLinks(enabled, apikey=None)` | `true` | `PUT /v0/org/settings/magic` with `{"enabled": enabled}` |

### Calling it directly

```python
import synapse.telepath as s_telepath

async with await s_telepath.openurl("tcp://root:secret@localhost:27492/*") as prox:
    retn = await prox.search("family:emotet", limit=5)
    if retn["status"]:
        for sample in retn["data"]:
            print(sample["id"], sample["status"])

    async for retn in prox.downloadSample("261031-a1b2c3d4e5"):
        if not retn["status"]:
            raise RuntimeError(retn["mesg"])
        ...  # retn["data"] is a bytes chunk
```
