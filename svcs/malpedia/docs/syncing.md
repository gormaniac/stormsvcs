# Syncing

This page covers the lifecycle end to end: what happens on registration, how the daily
schedule is set up, how the service decides whether and how much to pull, and how a view is
then modeled.

## Registration and the initial bulk pull

`service.add slib.malpedia <url>` makes the Cortex load the package and run the service's
`add` event, as root. The event comes from `SVC_EVTS["add"]` in
{src}`svcs/malpedia/src/malpediasvc/defs.py`. Its steps:

1. It creates (or updates) `meta:source=15b7f8ff9cef4e8fa9fedd9f2b10c1a5`, with
   `:name=malpedia :type=slib.malpedia :url=https://malpedia.caad.fkie.fraunhofer.de`.
2. It sets the global `slib:malpedia:tag:prefix` to `rep.malpedia` if unset, and
   `slib:malpedia:tag:tlp` to `rep.malpedia.tlp` if unset.
3. It deletes any cron job named `slib.malpedia (initial setup and sync)` (one an earlier
   `service.del` couldn't delete), then starts a one-time cron job with that name that runs
   immediately: `$lib.cron.at(query=..., now=(true))`. Its query is:

   ```text
   if $lib.import(slib.malpedia.priv.admin).autoSchedule() { slib.malpedia.sync }
   ```

A one-time job is used because the service isn't ready to answer Telepath calls while its own
`add` event runs. The job runs as root in the Cortex's default view, and `service.add`
returns without waiting for it. The job is created, and runs, even when `malpedia:autosync` is
off, because only the service can read its config. The finished job stays in `cron.list` until
`service.del` deletes it.

`autoSchedule()` then does the following:

1. It calls the service's `schedInfo()`. If that fails, it warns
   `slib.malpedia: Unable to read the sync schedule: ...` and returns `false`. No sync runs.
2. If `malpedia:autosync` is `false`, it returns `false`. Nothing is scheduled and no sync
   runs.
3. Otherwise, if there is no sync cron job yet, it looks for a cron job named
   `slib.malpedia.sync` with the query `slib.malpedia.sync` (one left behind by a
   `service.del` that couldn't delete it) and adopts it. If there is none, it calls
   `schedule(<period>)` with the service's random daily period. It returns `true`, and the
   job runs `slib.malpedia.sync`.

That first `slib.malpedia.sync` is the **bulk pull**. The snapshot isn't `complete` yet, so the
pull ignores `malpedia:pull:minage` and the version comparison. It downloads every bulk
endpoint and the full YARA zip. Then the sync models every record into the default view: about
19k articles, 1.1k actors, 3.8k families and 2.3k YARA rules, which takes 10-15 minutes. Its
progress shows in `slib.malpedia.status`.

A Cortex only does this bulk download once. New views, `--full` syncs and tag prefix changes
all re-model the local snapshot instead.

`autoSchedule()` only schedules when there's no job to use, so an existing daily job is never
duplicated. `service.del` deletes the daily job. Adding the service again runs the `add` event
again (the Cortex gives the re-added service a new iden), so it creates a new daily job, at the
same stored time and in the default view (an earlier `--period` or view isn't kept), and starts
another setup job and sync. That sync follows the normal pull decision below, so it's cheap
when the service's snapshot is already complete.

With `malpedia:autosync: false`, the setup job still runs once, but nothing is scheduled or
synced. Run `slib.malpedia.sync` and
`slib.malpedia.admin.schedule --period ...` by hand.

## The daily schedule

The first `schedInfo()` call picks the daily time with `random.SystemRandom`:

- hour: `randrange(0, 24)`, so 0-23,
- minute: `randrange(1, 60)`, so 1-59 (never on the hour).

It stores the pair as `schedtime` in the service's `slib:malpedia:info` store, so the time
stays the same across restarts and re-adds. The random time spreads deployments out, so they
don't all hit Malpedia at the same minute. The period is `daily@HH:MM`, for example
`daily@03:17`.

`schedule(period)` (in `slib.malpedia.priv.admin`) does this:

1. Creates `$lib.cron.add(query="slib.malpedia.sync", period=$period)` in the current view.
   During setup that is the default view.
2. Names it `slib.malpedia.sync` and gives it the doc
   `Pull Malpedia (if it changed) and sync its library, actors, families, and YARA rules into the view.`
3. Stores its iden in the global `slib:malpedia:cron`.
4. Deletes the previous job, if there was one.

Synapse parses `daily@03:17` as a recurring job with the requirement `{"hour": 3, "minute": 17}`,
the increment unit `day` and the increment value `1`. Synapse cron times are UTC.

To move the job, run `slib.malpedia.admin.schedule --period <period>` from the view that should
be synced. To sync several views, add more cron jobs yourself (`cron.add`) running
`slib.malpedia.sync` in each view. Only the first sync after `malpedia:pull:minage` hours
contacts Malpedia. The others model the snapshot for free.

## The pull decision

`MalpediaSvc.pull(force)` holds `pulllock` for its whole run, so concurrent syncs never pull
twice. It decides in this order:

| Step | Condition | Result | Requests |
| --- | --- | --- | --- |
| 1 | not forced, snapshot `complete`, last pull didn't fail, and `now - checked < malpedia:pull:minage` hours | `reason: "checked recently"` | 0 |
| 2 | always (when step 1 didn't return) | `GET /api/get/version` | 1 |
| 3 | not forced, `complete`, no outstanding `gaps`, and version equals the stored version | `checked = now`, `reason: "unchanged"` | 1 |
| 4 | not forced, and version equals the last `rejected` version | fail: `Malpedia version <v> was refused ...` | 1 |
| 5 | otherwise | fetch, build, guard, store | see below |

Notes on the table:

- `checked` is only updated by a successful check (step 3 or a completed pull). A failed pull
  sets `failed`, which turns off step 1, so the next sync retries even within `minage`.
- `gaps` counts entities the last pull couldn't get (see [Gap requests](#gap-requests)). They
  force a pull at the next check even if the version is unchanged.
- Step 4 stops the service from downloading a version it already refused, just to refuse it
  again.

### What a pull requests

**Always**, in this order:

| Request | Used for |
| --- | --- |
| `/api/list/actors` | Every actor ID. |
| `/api/get/actors` | Every actor, keyed by display name. |
| `/api/get/families` | Every family, with aliases, attribution and `library_entries`. |
| `/api/get/references` | Every library URL and the actors and families it's tagged with. |
| `/api/get/bib` | The whole library as BibTeX: title, authors, date, publisher. |
| `/api/list/yara` | Which YARA rules exist, and their family and TLP. |

**YARA**, one of two modes:

- **Full** (`/api/get/yara/tlp_white/zip`, about 4MB). Used when the snapshot isn't `complete`
  (the first pull), when the snapshot has no rules, when the pull is forced, or when
  `malpedia:yara:fullage > 0` and the last full download was at least `fullage` days ago (or
  never happened). The full set replaces the stored rules.
- **Incremental** (`/api/get/yara/after/<date>`). `<date>` is the UTC date of the last
  successful pull minus one day, for overlap, because the endpoint takes a date and Malpedia's
  clock isn't ours. The endpoint only returns rules whose `malpedia_version` date is new. That
  is why full downloads recur every `fullage` days: they catch rules edited without a new date.

A typical result: version + 6 bulk + `yara/after` is 8 requests, about 10 with gap requests,
and about 5MB when Malpedia changed. When it didn't, the pull is 1 tiny request.

Against the test fake, the first pull is 9 requests. The extra one is a gap request for an
actor (`turla`) that isn't in `/api/get/actors`:

```text
/api/get/version
/api/list/actors
/api/get/actors
/api/get/families
/api/get/references
/api/get/bib
/api/list/yara
/api/get/actor/turla
/api/get/yara/tlp_white/zip
```

### Gap requests

The bulk data has two known gaps. They are filled with per-entity requests, at most
`MAX_GAP_REQUESTS = 25` per kind per pull.

**Actors** that are in `/api/list/actors` but not in `/api/get/actors`. Display names are
matched to IDs by `actorSlug()` (lowercase, with ` ` and `/` replaced by `_`), then by a unique
alphanumeric match. Unmatched IDs are requested with `/api/get/actor/<id>`:

- They are ordered new IDs first (not in the snapshot), then by when they were last tried
  (`gaptried`, oldest first), then by ID. So every missing actor eventually gets its turn.
- A 404 isn't a gap. The actor keeps its last known record, if there is one.
- Any other failure, and every actor past the cap, adds to `gaps`. The actor keeps its last
  known record, so it doesn't look removed.

**YARA rules** that `/api/list/yara` lists, but that are neither stored nor returned by
`yara/after`. They are requested per family with `/api/get/yara/<family>`. If more than 25
families need it, the service downloads the zip instead (and records a full download). A
failure other than 404 adds to `gaps`.

When `gaps > 0`, the next check pulls again, even if Malpedia's version is the same.
`slib.malpedia.status` reports the count.

### Build, guard, store

1. **Build.** `_build()` runs in a thread (`s_coro.executor`). It normalizes everything into
   `{kind: {key: {"hash": sha256, "rec": record}}}`. If `/api/list/yara` is empty, no rules
   are removed, and the pull warns.
2. **Shrink guard.** Unless the pull is forced, the service checks every kind that already has
   at least `SHRINK_MIN = 20` records. If the new set has fewer than `SHRINK_RATIO = 0.5` of
   them, the pull is refused, and the version is stored as `rejected`.
3. **Store.** Under `storelock`, with `storing=true` set, each kind's snapshot is replaced:
   keys that are gone are deleted, and only records whose hash changed are rewritten. The
   per-kind added/updated/removed counts go into the summary.
4. **Bookkeeping.** The service sets `yarafull` (on a full download), `gaptried`, `gaps`,
   `version`, `date`, `pulled`, `checked`, `yaradate` (today, UTC) and `complete=true`, and
   clears `rejected`. The summary is stored as `last`, and the request count is added to
   `requests`.

Nothing is written before step 3. So any failure, whether an HTTP error, a parse error or the
guard, leaves the previous snapshot intact.

## Modeling a view

`slib.malpedia.priv.sync.sync()` runs as root after the optional pull:

1. `viewInfo(view)` returns the tag prefixes the view last synced with. `model.conf(old=...)`
   compares them to the current globals. If either changed, the sync becomes a full sync, and
   the model removes tags under the old prefix.
2. `model.conf()` also makes sure the `meta:source`, the `malpedia` reporter `ou:org` and the
   `meta:ruleset` exist in the view.
3. For each kind, in the order `news`, `actor`, `family`, `yara`, it iterates
   `changes(view, kind, full)`. It models each upsert with `model.model()` and each removal
   with `model.removed()`. After each batch it calls `synced()` with the `[key, hash]` pairs
   and removed keys that succeeded.
4. It calls `viewSynced(view, tags)`. After a prefix change with any failed record, `tags` is
   `null`, so the old prefixes are kept and the next sync re-models again.

Articles are modeled first, so the stub `risk:threat` / `risk:tool:software` nodes they link
to get their full props a moment later in the same sync.
