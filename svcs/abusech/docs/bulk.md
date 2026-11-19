# Bulk imports

Modeling an export row by row in Storm runs at about 50 rows/second, so the large exports
(MalwareBazaar `full`, URLhaus `full` and `payloads`, millions of rows) would take days. The
`--bulk` option of `slib.abusech.bazaar.export`, `slib.abusech.urlhaus.export` and
`slib.abusech.threatfox.export` instead builds every node of a whole export inside the
service, in Python, and has the Cortex ingest them in one feed.

```text
background { slib.abusech.urlhaus.export full --bulk }
```

Requires `slib.abusech.user` (to run the command), `slib.abusech.bulk` (to import
`slib.abusech.priv.bulk`), and the `node` permission on the layer (the ingest). It prints a
warning to run it in the background, since the full exports can take hours.

## Exports

| Platform | `kind` | File | Pull policy |
|---|---|---|---|
| `bazaar` | `recent` | `recent.csv` | once an hour |
| `bazaar` | `full` | `full.csv.zip` | reuse |
| `urlhaus` | `recent` | `recent.csv` | once an hour |
| `urlhaus` | `online` | `online.csv` | once an hour |
| `urlhaus` | `full` | `full.csv.zip` | reuse |
| `urlhaus` | `payloads` | `payload.csv.zip` | reuse |
| `threatfox` | `recent` | `recent.json` | once an hour |
| `threatfox` | `full` | `full.json.zip` | reuse |

The MalwareBazaar `yara` export can't be bulk imported (`BadArg`).

## The steps

`slib.abusech.priv.bulk.run(plat, kind, reuse, repull)` drives the whole import, as root for
`slib.abusech.bulk` users. It takes no file, job or dataset record from the caller: it picks
the file itself.

1. **Pick the file.** With `--reuse`, the last pull from the datasets global (or a warning and
   stop if there's none). Otherwise, if there's a previous pull and no `--repull`:
   - a recent export (`recent`, and URLhaus's `online`) pulled less than an hour ago warns
     `The <kind> export was last pulled <n> minutes ago (...). To avoid overusing abuse.ch,
     rerun with --reuse to import that pull again, or --repull to pull a new one.` and stops;
     one pulled longer ago is pulled again;
   - a full export reuses the last pull, printing `Using the <kind> export pulled at ...`, and
     warns that newer data isn't included when that pull is more than a day old.

   `--reuse` with `--repull` raises `BadArg`. A reused file no longer in the Axon warns to
   rerun with `--repull`.
2. **Pull** (when needed). `$lib.axon.upload()` saves the service's `bulkPull()` stream into
   the Cortex's Axon. The service streams it from abuse.ch as served (zipped or not), so the
   Auth-Key in the export URL never reaches Storm. The download stops with an error once it's
   larger than `abusech:bulk:maxsize`, so an export too big to stage is never saved. The pull
   (`sha256`, `size`, `time`) is recorded in the datasets global right away.
3. **Stage.** `bulkStart()` creates a job, then the file is read from the Axon in 1 MiB chunks
   and appended with `bulkStage()`.
4. **Build.** `bulkBuild()` checks the staged file's SHA256, then builds the nodes in batches
   into the job's `.nodes` file, yielding progress (printed every 50,000 rows).
5. **Save.** The `.nodes` file is streamed back with `bulkNodes()` into the Axon.
6. **Ingest.** `$lib.feed.fromAxon(<sha256>)` ingests it as the calling user. Then each family
   built with a tag gets its `:tag` set, only where unset: `risk:tool:software=<guid> -:tag [
   :tag = <tag> ]`.
7. **Record** the nodes file in the datasets global, and print `Ingested <n> nodes in <s>s.`
8. **Clean up.** `bulkDone()` removes the job, also when a step failed. A failure is a warning,
   `slib.abusech.<plat>.export: The bulk import failed: <message>`.

The tag prefix used is the current setting (`null`, no tags, when tagging is disabled).

### Service-side steps

The service methods behind these steps (see [the Telepath API](api.md#generators)):

| Method | Does |
|---|---|
| `bulkPull(plat, kind)` | Streams the export (`AbuseChClient.stream()`), retried until the first byte. Raises once the download is over `abusech:bulk:maxsize` (`The <plat> <kind> export is larger than the max of <n> bytes (abusech:bulk:maxsize).`). |
| `bulkStart(plat, kind, sha256, owner)` | Checks the export and SHA256, prunes idle jobs if at `abusech:bulk:maxjobs`, refuses a new job past it (`There are already <n> bulk import jobs running ...`), creates `<cell>/tmp/bulk/<job id>/`, returns the job ID. |
| `bulkStage(jobid, byts, owner)` | Appends to `source`, refusing a copy over `abusech:bulk:maxsize`. |
| `bulkBuild(jobid, prefix, batch=1000, owner)` | Hashes `source` in a thread and compares it to the job's SHA256, parses it, and writes `export.nodes`. Yields `{"rows", "nodes"}` every `batch` rows, then `{"done": true, "rows", "skipped", "nodes", "size", "builder", "seconds", "familytags"}`. |
| `bulkNodes(jobid, chunk=1048576, owner)` | Streams `export.nodes`. |
| `bulkDone(jobid, owner)` | Removes the job's directory. Another owner's job is left alone. |

Parsing: the CSV exports are read line by line (from inside the zip when zipped) with one CSV
reader; ThreatFox's JSON export is parsed whole, in a thread, with the unzipped size capped at
`abusech:bulk:maxsize`. Each record is normalized exactly as the Storm path normalizes it
(`norm.normSample`, `norm.normUrl`, `norm.normUrlhausPayloadRow`, `norm.normIoc`) and built
by `abusechsvc.bulk.NodeBuilder`.

### Jobs

- A job belongs to the caller that started it: `<Telepath user iden>:<Storm user iden>`.
  Every later call must come from the same pair; another caller's job is reported as
  `Unknown bulk import job: <id>`, so its ID doesn't confirm it exists.
- At most `abusech:bulk:maxjobs` (default 4) jobs exist at once.
- Jobs untouched for 6 hours are removed by a loop that runs every 10 minutes (ex. after a
  cancelled background query); every job is removed when the service starts.
- The export and `.nodes` files stay in the Axon.

## The datasets global

Every pull and import is recorded in the Cortex global `slib:abusech:datasets`, keyed
`<platform>:<kind>`:

```json
{
  "urlhaus:recent": {
    "sha256": "<export file sha256>",
    "size": 12345678,
    "time": 1763500000000,
    "file": "urlhaus:recent",
    "nodes": {
      "sha256": "<.nodes file sha256>",
      "size": 987654,
      "count": 500000,
      "built": 500000,
      "rows": 122103,
      "skipped": 0,
      "builder": 3,
      "time": 1763500400000
    }
  }
}
```

`count` is the number of nodes `$lib.feed.fromAxon()` ingested, `built` the nodes the service
built, `rows` the export rows read, `skipped` the rows that couldn't be modeled, and `builder`
the `NodeBuilder` version (`bulk.BUILDER_VERSION`, currently 3, bumped when the nodes change).
`nodes` is `null` until an import of that pull finishes. Times are epoch milliseconds.

```text
$lib.print($lib.globals.get("slib:abusech:datasets"))
```

## What's built

`NodeBuilder` ({src}`svcs/abusech/src/abusechsvc/bulk.py`) mirrors `slib.abusech.model`
function by function for what the exports contain: samples (`sample()`, with tags, families,
reporter, ClamAV and VirusTotal scans, links), URLs (`url()`, with tags, status, host and
blacklists, reference, reporter, payloads and `inet:urlfile`), and ThreatFox IOCs (`ioc()`,
with the observable, `it:sec:stix:indicator`, family, reporter and samples). Values are
normalized with a standalone copy of the Synapse data model (`bulk.buildModel()`, Synapse's
core models plus the `file:bytes` extended props), so primary values and props match what
Storm creates and nodes keyed by primary value merge with nodes modeled live. Guid nodes get
the guid `$lib.guid()` gives the same props. Edges are the current ones (builder version 3).

Nodes are written as `syn.nodes` nodedefs (`(ndef, {"props", "tags", "edges"})`) packed with
msgpack, one batch at a time. Families (`risk:tool:software`) are held until the end, so their
`:soft:names` collect every alias in the export instead of being replaced batch by batch;
their edges go out with each batch. A family's `:tag` isn't in the nodes file (it would replace
an existing one) and is set after the ingest, as above.

On the live recent exports, URLhaus `recent` (122,103 rows) built in 64s and ingested in 369s
(about 280 rows/s overall), ThreatFox `recent` (9,027 IOCs) in 32s, and MalwareBazaar
`recent` (881 samples) in 5s, per the README. `tests/test_bulk.py` (`test_parity`) checks the
bulk path builds the same nodes as the Storm path.

## Differences from the Storm model

A bulk import can only add and set, so on nodes that already exist:

- Old `<prefix>.<platform>.status.*` tags aren't removed.
- Array props (`file:bytes:ssdeeps`, `risk:tool:software:soft:names`) are set to the values
  in the import, replacing (not adding to) existing values.
- `file:bytes:name` is set even when the node already has a name.
- Files only known by an MD5/SHA1 (ex. ThreatFox hash IOCs) always get a `guid:` `file:bytes`,
  where Storm would reuse an existing node with that hash.
- Guid nodes made from props (`risk:tool:software`, `inet:service:account`,
  `it:av:scan:result`, etc.) get the guid Storm's `({...})` would generate, but the service
  can't look up an existing node with those props first, so one made some other way isn't
  reused.
