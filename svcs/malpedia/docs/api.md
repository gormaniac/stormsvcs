# Telepath API

## Storm modules

The package has no public Storm library API. Its modules exist to serve its commands:

| Module | Privilege | Contents |
| --- | --- | --- |
| `slib.malpedia.priv.user` | `asroot`, for holders of `slib.malpedia.user` | `status()` and `find(kind, needle)`, which wrap the service calls. They return the raw `TelepathRetn`. |
| `slib.malpedia.priv.sync` | `asroot`, for `slib.malpedia.sync` | `refreshLimit()`, `reqEdit(name)`, `pull(force=false)`, `sync(force=false, full=false, pull=true, progress=false)`, `refresh(actors, families, nolimit=false)`. |
| `slib.malpedia.priv.admin` | `asroot`, for `slib.malpedia.admin` | `cron()`, `schedule(period)`, `enable(enabled=true)`, `unschedule()`, `autoSchedule()`, `tagSettings()`, `setTagPrefix(name, prefix)`, `resetView()`. |
| `slib.malpedia.model` | none | The modeling functions, see [Data model](model.md). |
| `slib.malpedia.util` | none | Printing helpers (`data`, `when`, `table`, `kindCounts`, `plural`, `nodes`). |

Anyone with `slib.malpedia.sync` can import `slib.malpedia.priv.sync`. So `sync()` and
`refresh()` run the same checks as the commands: `reqEdit()` (the layer's `node.add.<form>`
permissions), `slib.malpedia.admin` for `force`/`nolimit`, and the 25-ID refresh limit, which
raises `BadArg`.

`sync()` returns:

```json
{
  "pull": "<pull summary or null>",
  "pullerror": "<why the pull failed, or null>",
  "error": "<why the sync stopped early, or null>",
  "kinds": {"news": {"total": 0, "added": 0, "updated": 0, "removed": 0, "skipped": 0, "failed": 0}},
  "errors": ["<at most 10 per-record errors>"],
  "retagged": false
}
```

`refresh()` returns
`{"nodes": [<risk:threat / risk:tool:software nodes>], "counts": {kind: n}, "errors": [...],
"warnings": [...]}`.

## The Telepath service

`MalpediaCellApi` ({src}`svcs/malpedia/src/malpediasvc/api.py`) subclasses
`stormlibpp.svc.RetnApi`, `synapse.lib.cell.CellApi` and `synapse.lib.stormsvc.StormSvc`. It
registers as `slib.malpedia`, with the package version as the service version. It provides the
`add`/`del` events and the package definition.

### TelepathRetn

Every method returns, or for generators yields, a `TelepathRetn` dict:

| Key | Type | Meaning |
| --- | --- | --- |
| `status` | bool | `true` on success. |
| `mesg` | str | Empty on success. The error message on failure. |
| `data` | any | The method's return value on success. `null` on failure. |

`RetnApi` builds each method from the cell method of the same name. An exception never reaches
Storm. Instead, `errRetn()` turns it into `status=false`:

- `MalpediaApiError` and `MalpediaSvcError` are both `stormlibpp.svc.SvcError`s (the default
  `RETN_ERRORS`). So are Synapse `AuthDeny` errors. Their message is returned as-is.
- `ValueError`, `TypeError` and `s_exc.BadArg` are returned as `Invalid input: <mesg>`.
- Anything else is logged with its traceback and returned as
  `Unexpected error: <Type>: <mesg>`.

The service holds no secrets, so it doesn't override `_retnRedact()`.

Storm checks `status` before using `data`:

```text
$svc = $lib.service.get(slib.malpedia)
$retn = $svc.status()
if $retn.status { $lib.print($retn.data.version) } else { $lib.warn($retn.mesg) }
```

`view` arguments must be view idens (32 hex characters). Otherwise the call fails with
`Invalid view iden: ...`. `kind` must be one of `news`, `actor`, `family`, `yara`. Otherwise it
fails with `Unknown record kind ...`.

### RETN_METHS

#### pull(force=False)

Pull Malpedia into the snapshot, if it's due. The decision logic is described in
[Syncing](syncing.md#the-pull-decision). Pulls are serialized: concurrent callers wait for the
running pull, then make their own decision. `data` is a summary:

```json
{
  "pulled": true,
  "reason": null,
  "initial": true,
  "version": 26601,
  "date": "2026-10-30T16:25:07Z",
  "requests": 9,
  "added":   {"news": 5, "actor": 4, "family": 3, "yara": 3},
  "updated": {"news": 0, "actor": 0, "family": 0, "yara": 0},
  "removed": {"news": 0, "actor": 0, "family": 0, "yara": 0},
  "warnings": ["2 family attributions don't resolve to exactly one actor (not linked): ..."],
  "yarafull": true,
  "gaps": 0
}
```

When nothing was pulled, `pulled` is `false` and `reason` is either `"checked recently"` (0
requests) or `"unchanged"` (1 request). The per-kind dicts are then empty, and `yarafull` and
`gaps` are absent. `initial` is `true` until the first pull completes.

Errors: any `MalpediaApiError` (HTTP errors after retries, connection failures, unexpected
response shapes). Also these `MalpediaSvcError`s:

- the shrink guard: `Malpedia returned <n> <kind> records, but the snapshot has <m>. Refusing
  to remove that many, ...`
- a rejected version: `Malpedia version <v> was refused because it removes too much ...`
- `The pull failed unexpectedly: ...`

Every failure is stored as `failed` (see `status()`), and the snapshot is left untouched.

#### synced(view, kind, done=None, removed=None)

Record that a view modeled records:

- `done` is a list of `[key, hash]` pairs. A pair is only marked if the snapshot still has
  that hash.
- `removed` is a list of keys of removed records that the view handled.

`data` is the number of records marked. A `done` item that isn't a 2-item list fails with
`Expected [key, hash] pairs, got ...`.

#### viewSynced(view, tags=None)

Record that a view finished a sync. `tags` is `{"prefix": str, "tlp": str}`, the prefixes the
sync applied. Passing `null` keeps the prefixes stored from the previous sync. `data` is the
view's new sync info:

```json
{"synced": 1761900000000, "version": 26601, "date": "2026-10-30T16:25:07Z",
 "tags": {"prefix": "rep.malpedia", "tlp": "rep.malpedia.tlp"}}
```

#### viewInfo(view)

`data` is the view's sync info, as above, or `{}` if the view was never synced.

#### resetView(view)

Mark every record the view synced as unsynced, and forget its sync time and version. `data`
is `true`.

The view's version of each record stays stored, with its hash cleared, so the next
`changes()` sends every record again (as `new: false`, with the usual `drop` diff), and still
sends the ones Malpedia removed since as `removed`. The tag prefixes the view last synced with
(`tags`) are kept, so `viewInfo()` returns `{"tags": ...}` afterwards, or `{}` if there were
none. `status(view)` doesn't count the unsynced records.

#### status(view=None)

`data`:

```json
{
  "version": 26601, "date": "2026-10-30T16:25:07Z", "complete": true,
  "pulled": 1761900000000, "checked": 1761900000000, "requests": 10,
  "failed": null, "gaps": 0, "yarafull": 1761900000000,
  "last": "<the summary of the last successful pull>",
  "counts": {"news": 5, "actor": 4, "family": 3, "yara": 3},
  "minage": 12,
  "view": null
}
```

Times are epoch milliseconds. `requests` is the running total of requests sent by successful
pulls. With a `view`, `view` holds that view's sync info plus a `counts` dict of the records it
has synced (not counting the ones a reset marked unsynced).

#### find(kind, needle)

A live search of `/api/find/actor/<needle>` (`kind="actor"`) or `/api/find/family/<needle>`
(`kind="family"`). `data` is Malpedia's list of matches. Items without a `name` are dropped.
Each item gets a `known` bool (whether the snapshot has the ID), and a known item without a
`common_name` gets the snapshot's name:

```json
[{"name": "apt28", "common_name": "APT28", "synonyms": ["Fancy Bear", "Sofacy"], "known": true}]
```

Errors: `A search needs a non-empty string.`, and
`Can only search actors or families, not ...`.

#### refresh(kind, ident)

Get an actor or family straight from Malpedia and normalize it for modeling, without changing
the snapshot. `ident` is normalized as described in
[`slib.malpedia.refresh`](commands.md#slib-malpedia-refresh). `data`:

```text
{"id": "apt28", "actor": [<item>], "family": [<item>], "yara": [<item>], "news": [<item>],
 "warnings": ["<BibTeX parse warnings>"]}
```

Each item has the same shape as an upsert item from `changes()`, with `"new": false` and
`"drop": {}`.

Errors: `Can only refresh an actor or family, not ...`, `A refresh needs an <kind> ID.`,
`Invalid Malpedia <kind> ID: ...`, and `MalpediaApiError` (for example HTTP 404 for an unknown
ID).

#### schedInfo()

The daily sync schedule. The first call picks a random time (hour 0-23, minute 1-59) with
`random.SystemRandom` and stores it, so the time is fixed for the life of the service's
storage:

```json
{"autosync": true, "hour": 3, "minute": 17, "period": "daily@03:17"}
```

### GENR_METHS

#### changes(view, kind, full=False, size=250)

Yield batches of the records of `kind` that changed since the view's last sync. With
`full=True`, every record is yielded. `size` is clamped to 1-5000. Each yielded `TelepathRetn`
holds one batch:

```json
{
  "kind": "news",
  "total": 5,
  "upsert": [
    {"key": "<record key>", "hash": "<sha256 of the record>", "new": true,
     "rec": {"...": "the record"}, "drop": {"actors": [["apt28", "threat.apt28"]]}}
  ],
  "removed": [{"key": "<record key>", "rec": {"...": "the view's version of the record"}}]
}
```

- `total` is the number of upserts plus removals, fixed when the generator starts.
- Upsert batches come first, then removal batches.
- `new` is `true` if the view never synced the record.
- `drop` is what the record lost since the view's version, limited to the fields the model
  undoes (see [Data model](model.md#updates-and-removals)).

Generator semantics:

- The list of changed keys is computed once, under the store lock. Each batch is read under
  the lock again, so a batch never sees a half-written snapshot.
- If a pull runs between two batches, later batches carry the newer records. A key that
  disappeared is skipped.
- The generator never marks anything synced. The caller reports progress with `synced()`
  after each batch, so a sync that stops early resumes where it left off.
- An error ends the generator after one `status=false` item.
