# Telepath API

The service's Telepath API is `PcapCellApi` in {src}`svcs/pcap/src/pcapsvc/api.py`. Storm code
reaches it with `$lib.service.get("slib.pcap")`, but only the `slib.pcap.priv.*` modules do, and
users don't need `service.get` permissions.

## TelepathRetn and errors

`PcapCellApi` subclasses `stormlibpp.svc.RetnApi`
([StormLib++ docs](https://docs.gormo.co/stormlibpp/)), so no method raises over Telepath.
Every method returns a `TelepathRetn`:

```python
{"status": True, "mesg": "", "data": <result>}      # success
{"status": False, "mesg": "<why>", "data": None}    # failure
```

and generators yield one per item, ending after a single `status=False` item on error.

- `RETN_METHS` names `PcapSvc` coroutines that get a generated method calling
  `self.cell.<name>(*args, **kwargs)` and wrapping the result in `data`.
- `GENR_METHS` names `PcapSvc` async generators, each item is wrapped.
- `RETN_ERRORS` isn't overridden, so it's the default `(SvcError,)`. The service's errors
  (`PcapSvcError`, `RuleSvcError`, `FeedError`, `SnortError`, `SuricataError`) subclass
  `stormlibpp.svc.SvcError`, so their message is returned as-is. `AuthDeny` also keeps its
  message. `ValueError`, `TypeError` and `BadArg` return `Invalid input: <error>`. Anything else
  is logged with its traceback and returned as `Unexpected error: <type>: <error>`.
- `_retnRedact()` replaces every `pcap:feeds:secrets` value (and its URL-quoted form) in every
  error message with its `${name}` placeholder (`pcapsvc.feeds.redact`), so an unexpected error
  carrying a feed URL with its secrets filled in (ex. from aiohttp) doesn't reach Storm. Feed
  errors are also redacted by the service itself before they are saved and raised (see
  [Rules and feeds](rules.md#secrets-in-feed-urls)).
- `flows`, `checkNetVars` and `checkDecodeAs` are written by hand and build their own
  `TelepathRetn`s, `RetnApi` still guards them so they never raise.

From Storm:

```text
$svc = $lib.service.get("slib.pcap")
$retn = $svc.ruleStatus()
if (not $retn.status) { $lib.warn($retn.mesg) } else { $lib.print($retn.data.loaded) }
```

## Methods

### Status

| Method | Returns (`data`) |
| --- | --- |
| `status()` | `{engines, sandbox, axon, rules}`, see below. |
| `hasAxon()` | `bool`, whether `axon:url` is set. |
| `ruleStatus()` | The rules summary, see below. |

`status()` data:

```json
{
  "engines": {
    "suricata": {"available": true, "enabled": true, "version": "8.0.8"},
    "snort": {"available": true, "enabled": true, "version": "3.12.4.0"},
    "tshark": {"available": true, "enabled": true, "version": "TShark (Wireshark) 4.6.9 ..."}
  },
  "sandbox": {
    "mode": "best-effort", "user": "slib-pcap-engine", "uid": 2000, "root": true,
    "landlock": 6, "landlock:tcp": true, "seccomp": true, "missing": [],
    "alerts": 0, "recent": []
  },
  "axon": true,
  "rules": {"...": "ruleStatus()"}
}
```

`version` is cached per engine after the first successful lookup. `sandbox` is `Sandbox.probe()`
plus `alerts` (the count since start) and `recent` (the last 10 alerts, `{kind, engine,
detail, time}`). `missing` lists unsupported layers: `landlock`, `landlock:tcp`, `user <name>`.

`ruleStatus()` data:

```json
{
  "rules": 52000, "loaded": 51800, "engines": {"snort": 4100, "suricata": 47700},
  "invalid": 200, "took": 61000, "changed": false,
  "built": 1700000000000, "pushed": 1700000000000, "building": false, "error": null
}
```

`rules` is the number pushed, `loaded` the rules in the active rules files (per engine in
`engines`), `invalid` the number of errors, `took` the last build's ms, `error` the last build's
failure.

### Analysis

| Method | Args | Returns |
| --- | --- | --- |
| `flows(sha256, **opts)` | see below | async generator, see [flows](#flows) |
| `uploadStart(kind="capture")` | `kind`: `capture` or `keylog` | `str`, the upload ID |
| `uploadChunk(iden, byts)` | upload ID, `bytes` | `int`, the upload's size so far |
| `uploadCancel(iden)` | upload ID | `bool`, whether it existed |
| `checkNetVars(netvars)` | `{name: address group}` | the normalized dict (`status=False` with the reason if invalid) |
| `checkDecodeAs(rules)` | `[rule, ...]` | the normalized list, lowercased and deduplicated |

Uploads are how Storm sends captures and key logs when the service has no Axon. `uploadStart`
fails when `pcap:uploads` uploads are already held, `uploadChunk` drops the upload and fails once
it passes `pcap:maxsize` (captures) or `tshark:keylog:maxsize` (key logs). Uploads untouched for an
hour are pruned (every 10 minutes), except those claimed by a waiting run.

### flows

```python
flows(sha256, timeout=None, limit=None, handshake=None, tshark=None, files=None, keylogs=None,
      decode=None, suricata=None, snort=None, rules=True, upload=None, keyloguploads=None,
      netvars=None)
```

Any other keyword returns a single `status=False` item, `Unknown options: <names>`.

| Option | Type | Meaning |
| --- | --- | --- |
| `sha256` | str | The capture's SHA-256 (hex or `sha256:<hex>`, case-insensitive). |
| `timeout`, `handshake` | int or None | None uses `pcap:timeout`/`pcap:handshake`. Must be ints `>= 0`. |
| `limit` | int or None | `0`/None uses `pcap:limit`, otherwise capped at it. |
| `tshark`, `suricata`, `snort`, `files` | bool or None | Run the engine / extract files, None uses the `*:enabled`/`pcap:files` config. |
| `rules` | bool | Match the rules (Snort only runs with rules, Suricata runs with `--disable-detection` without). |
| `keylogs` | list of SHA-256s | Key logs in the Axon (needs `axon:url`). |
| `upload` | str or None | The capture's upload ID. Without it the capture is read from the Axon (needs `axon:url`). |
| `keyloguploads` | list | Key log uploads, each an ID or `{"upload": <ID>, "sha256": <SHA-256>}` (then the upload's hash must match). |
| `decode` | list of str | Decode As rules (validated). |
| `netvars` | dict | Network variables for Snort and Suricata (validated). |

The first item's data is `{"summary": <summary>}`, every following item is
`{"flow": <flow>}` (the flow dict, see [Data model](model.md#raw)). Flows are computed
completely before the first item is yielded. A failure yields one `status=False` item:
`PcapSvcError`s keep their message (ex. `Invalid SHA-256: ...`, `The capture
file:bytes:sha256=<sha256> is not in the Axon.`, `file:bytes:sha256=<sha256>: The file is not a
pcap or pcapng file`, `The service has no axon:url, the capture must be uploaded.`), Synapse,
OS and zlib errors return `Unable to read <sha256>: <error>`.

The summary:

| Key | Meaning |
| --- | --- |
| `sha256`, `size` | The capture's SHA-256 and size (compressed size for gzip). |
| `format`, `compressed` | `pcap` or `pcapng`, and whether it was gzip compressed. |
| `linktypes` | `[{"type": <LINKTYPE_*>, "name": <name or null>}]` |
| `packets`, `decoded` | Packet records read, and IP packets added to flows. |
| `skipped` | Counts by reason: `linktype`, `malformed`, `nonip`, `fragment`, `truncated`, `badiface`. |
| `flows`, `dropped`, `limited` | Flows made, packets dropped past `limit`, whether any were. |
| `first`, `last` | First and last packet time (ms). |
| `truncated`, `error` | Whether reading stopped early, and why. |
| `tshark` | `{"frames": <frames with engine records>, "matched": <frames matched to a flow>}` |
| `events` | `unmatched` (engine records no flow matched), `builtin` and `unknown` (alerts for rules not loaded, by `<engine>:<gid>:<sid>`), `malformed` (skipped engine records by kind, ex. `suricata:tls`, `tshark:frame`, `snort:alert`). |
| `hits` | Total hits. |
| `files` | `{"count", "skipped", "uploaded"}` with an Axon, `{"count": 0, "skipped": 0, "unsaved": n}` without one, `null` when extraction is off. |
| `keylogs`, `decode`, `netvars` | The number of key logs, and the Decode As rules and network variables used. |
| `engines` | Per engine: `suricata` `{enabled, error, rules, warnings}`, `snort` `{enabled, error, rules, warnings, alerts}`, `tshark` `{enabled, error, version, gaps}`. An engine that didn't run has `enabled: false` and, if it was wanted, an `error` like `Suricata is not installed`. |
| `sandbox` | `{"alerts": [...]}`, the sandbox alerts of this run's engines. |

### Rules

| Method | Args | Returns |
| --- | --- | --- |
| `pushStart()` | | `str`, a push ID |
| `pushRules(iden, rules)` | push ID, list of `(guid, form, text, engine)` | `int`, rules in the push so far |
| `pushDone(iden, force=False)` | push ID | build summary |
| `pushCancel(iden)` | push ID | `bool` |
| `ruleUpdate(rules=None, dels=None)` | `(guid, form, text, engine)` list, guid list | build summary with `errors` |
| `ruleErrors(guids=None)` | optional guids | `{guid: error}` |
| `ruleWarnings(guids=None)` | optional guids | `{guid: [warning, ...]}` |
| `ruleParse(text, engine=None)` | rule text, `snort3`/`snort2`/`suricata`/`2`/`3` (None is `snort3`) | parsed rule, see below |
| `ruleCheck(text, engine=None)` | rule text, engine | `str` error, or `None` if the engine loads it |

A pushed rule is `(guid, form, text, engine)`: `guid` a 32 hex guid, `form`
`it:app:snort:rule` or `it:app:suricata:rule`, `text` non-empty, and `engine` the node's
`:engine` (2, 3 or null for Snort rules). Anything else fails the call with `RuleSvcError`. A
push replaces every rule the service has with the pushed ones when `pushDone` is called, and
only rebuilds if they changed (or `force`, or the last build failed or its files are missing).
Pushes untouched for an hour are pruned.

The build summary: `{rules, loaded, engines, invalid, took, changed}` (as in `ruleStatus`,
`changed` false when nothing was rebuilt). `ruleUpdate` adds `errors`, the errors of the rules
it was given.

`ruleParse` data, the fields of `pcapsvc.rules.Rule` plus the node identity:

```json
{
  "text": "alert http any any -> any any ( msg:\"My rule\"; ... sid:1000001; rev:1; )",
  "enabled": true, "action": "alert", "header": "alert http any any -> any any",
  "gid": 1, "sid": 1000001, "rev": 1, "msg": "My rule", "classtype": null, "priority": null,
  "refs": [["cve", "cve-2021-44228"]], "metadata": {}, "family": null,
  "created": null, "updated": null,
  "id": "1000001", "engine": "snort3", "form": "it:app:snort:rule", "guid": "<guid>"
}
```

### Feeds

| Method | Args | Returns |
| --- | --- | --- |
| `feeds(view=None)` | a view iden | list of feeds, see below |
| `feedAdd(fdef)` | `{name, url, engine, enabled, exclude, desc}` | the feed |
| `feedDel(name)` | | the removed feed |
| `feedEnable(name, enabled=True)` | | the feed |
| `feedPull(name, force=False, view=None)` | | the feed's state, with `skipped` |
| `feedChanges(name, view, full=False, size=500)` | | async generator of batches |
| `feedSynced(name, sha256, view)` | the synced download's SHA-256 | the feed's state |

A feed (from `feeds`, `feedAdd`, ...): the definition plus `form` (the engine's rule form) and
`ruleset` (its `meta:ruleset` guid), and from `feeds` an `info`:

```json
{
  "name": "et-open", "url": "https://rules.emergingthreats.net/open/suricata-8.0/emerging.rules.tar.gz",
  "engine": "suricata", "enabled": true, "exclude": ["emerging-deleted.rules"], "desc": "...",
  "form": "it:app:suricata:rule", "ruleset": "<guid>",
  "info": {
    "pulled": 1700000000000, "sha256": "<download sha256>", "etag": "...", "modified": "...",
    "count": 70000, "enabled": 52000, "errors": 3, "files": 60,
    "views": {"<view>": {"sha256": "...", "at": 1700000000000}},
    "synced": "<sha256 last synced into view>", "error": null
  }
}
```

`feedPull` returns the `info` (with `synced` for `view`) and `skipped` (true when the feed wasn't
due). A failed download or parse sets `error` and `failed` in the info and fails the call.

`feedChanges` yields `{"full": bool, "upsert": [<rule record>, ...], "removed": [<guid>, ...]}`
batches of up to `size` records. `removed` is only in the first batch. A rule record:

```json
{
  "guid": "<guid>", "id": "2013502", "gid": 1, "sid": 2013502, "rev": 5,
  "engine": "suricata", "engineid": null, "form": "it:app:suricata:rule",
  "text": "alert ...", "enabled": true, "msg": "...", "classtype": "...",
  "refs": [["url", "http://..."]], "family": null, "created": "2011-08-31",
  "updated": "2024-01-02", "file": "emerging-malware.rules"
}
```

`engineid` is `2`/`3` for Snort feeds. `feedSynced` fails if the feed was downloaded again since
the given SHA-256 (`The <name> feed was downloaded again during the sync.`).

## Storm modules

| Module | Perms | Contents |
| --- | --- | --- |
| `slib.pcap.lib` | `slib.pcap.user` | The user API, below. |
| `slib.pcap.model` | | Node edits (`flow`, `hit`, `cert`, `rule`, `ruleRefs`, `fileNode`, ...), see [Data model](model.md). |
| `slib.pcap.util` | | `failed`, `data`, `table`, `when`, `printBuild`, `warnNoAxon`, `warnAll`. |
| `slib.pcap.priv.user` | `asroot` with `slib.pcap.user` | Service wrappers for users, Axon streaming, the globals. |
| `slib.pcap.priv.rules` | `asroot` with `slib.pcap.rules` | `rulesView()`, `denied()` (why this view can't change the rules, or null), `update(rules, dels)`. |
| `slib.pcap.priv.sync` | `asroot` with `slib.pcap.sync` | `feeds()`, `syncFeed(feed, force)`, `push(force)`. |
| `slib.pcap.priv.admin` | `asroot` with `slib.pcap.admin` | Feed admin, `schedule(period)`, `enable(enabled)`, the vars and decode globals. |

`slib.pcap.lib` functions:

| Function | Returns |
| --- | --- |
| `flows(sha256, opts=(null), file=(null))` | Emits each `inet:flow`. Raises `slib.pcap.Error` (with `sha256`) on failure. `file` is the capture's `file:bytes` node, created from the SHA-256 when null. |
| `ingest(sha256, opts=(null), file=(null), hits=(false))` | Like `flows()` for user-facing code: validates `tag`/`host`/`sandbox`, warns instead of raising, prints the run's report. With `hits`, emits the match nodes instead of the flows. |
| `status()` | The service's `status()` data, or null with a warning. |
| `feeds()` | The feeds (with this view's sync state), or null. |
| `ruleErrors(guids=(null))`, `ruleWarnings(guids=(null))` | The service's errors / warnings, or null. |
| `schedule()` | The sync cron job's `pprint()` with `enabled` as a bool, or null. |
| `normSha256(valu)` | Lowercased hex, `sha256:` removed. |
| `decodeRules(decode)` | The admin's Decode As rules followed by `decode`. |
| `nodes(items)` | Yields the items (for `divert`). |

`opts` keys: `timeout`, `limit`, `handshake`, `tshark`, `suricata`, `snort`, `files`, `rules`
(default true), `keylogs` (SHA-256s), `decode` (added to the admin's rules), `tag`, `host`,
`sandbox`. The admin's network variables (`slib:pcap:vars`) are always sent.

```text
$pcap = $lib.import(slib.pcap.lib)
try {
    for $flow in $pcap.flows($sha256, opts=({"tag": "rep.pcap", "rules": (false)})) { yield $flow }
} catch slib.pcap.Error as err {
    $lib.warn($err.mesg)
}
```
