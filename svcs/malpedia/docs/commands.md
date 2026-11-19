# Commands

The `slib.malpedia` package has seven commands:

| Command | Permission | Purpose |
| --- | --- | --- |
| [`slib.malpedia.sync`](#slib-malpedia-sync) | `slib.malpedia.sync` | Pull Malpedia (if due) and model the changes into the current view. |
| [`slib.malpedia.refresh`](#slib-malpedia-refresh) | `slib.malpedia.sync` | Get actors or families straight from Malpedia and model them. |
| [`slib.malpedia.search`](#slib-malpedia-search) | `slib.malpedia.user` | Search Malpedia's actor and family names and synonyms. |
| [`slib.malpedia.status`](#slib-malpedia-status) | `slib.malpedia.user` | The snapshot's state and the current view's sync state. |
| [`slib.malpedia.admin.schedule`](#slib-malpedia-admin-schedule) | `slib.malpedia.admin` | Show or change the sync cron job. |
| [`slib.malpedia.admin.tags`](#slib-malpedia-admin-tags) | `slib.malpedia.admin` | Show or change the tag prefixes. |
| [`slib.malpedia.admin.reset`](#slib-malpedia-admin-reset) | `slib.malpedia.admin` | Forget what the current view has synced. |

Every command reports problems with `$lib.warn()` and doesn't raise. The exceptions are
permission failures (`AuthDeny`), which are raised before any output.

## Syncing

### slib.malpedia.sync

Pull Malpedia into the service's snapshot (if it's due), then model every record that changed
since the current view's last sync.

```text
slib.malpedia.sync [--force] [--full] [--no-pull]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--force` | flag | `false` | Pull now even if Malpedia was checked within `malpedia:pull:minage` hours or its version is unchanged. Also downloads every YARA rule (the zip), and applies the pull even if it would remove more than half of a kind (the shrink guard) or is the version an earlier pull refused for that. Needs `slib.malpedia.admin`. With `--no-pull` it does nothing (and needs nothing). |
| `--full` | flag | `false` | Model every record into this view, not only the ones that changed since its last sync. |
| `--no-pull` | flag | `false` | Don't contact Malpedia, only model the service's snapshot. |

**Permissions:** `slib.malpedia.sync`, plus `node.add.<form>` on the current view's layer for
`media:news`, `risk:threat`, `risk:tool:software` and `it:app:yara:rule`. `--force` also needs
`slib.malpedia.admin`, unless `--no-pull` is used: then there's no pull to force, so the
command only warns `--force does nothing with --no-pull, there's no pull to force.`

**Input:** none, inbound nodes are ignored. **Output:** none, the command only prints.

What it does:

1. Unless `--no-pull` is used, it calls the service's `pull(force=...)`.
   - It prints one of these results: `Pulled Malpedia version <v> (<date>) with <n> requests:
     added ...; updated ...; removed ...`, or `Malpedia is unchanged since the last pull`, or
     `Malpedia was checked recently, not pulling it again yet`. It adds
     `Downloaded every YARA rule.` when the zip was fetched.
   - Each pull warning is printed with `$lib.warn()`, for example unresolved family
     attributions or actors that couldn't be requested.
   - If the pull fails, it warns `Pulling Malpedia failed, syncing the service's last pull
     instead: <mesg>`, and continues with the existing snapshot.
2. It models the changed records in the order `news`, `actor`, `family`, `yara`, in batches
   of 250. It prints `Modeling <n> <kind> records.` for each kind that has changes.
3. It prints a table of `kind`, `changes`, `added`, `updated`, `removed`, `skipped` and
   `failed` counts. Up to 10 per-record errors are printed as `Unable to model <kind> <key>:
   <mesg>`. If the service failed mid-sync, it warns
   `The sync stopped early, the next sync will continue it: <mesg>`.

A record that fails to model isn't marked as synced, so the next sync retries it. Only
articles can be `skipped`: their URL isn't a valid `inet:url`.

If a tag prefix changed since the view's last sync (see
[`slib.malpedia.admin.tags`](#slib-malpedia-admin-tags)), the sync prints
`The tag prefixes changed since this view's last sync, modeling every record to replace the
old tags.` It then behaves like `--full`, and removes the tags added under the old prefix.

```text
// Sync Malpedia into the current view.
slib.malpedia.sync

// Model every record into this view again, without pulling Malpedia.
slib.malpedia.sync --full --no-pull

// Ignore malpedia:pull:minage and download everything (admin).
slib.malpedia.sync --force
```

The service schedules this command to run daily. See [Syncing](syncing.md).

### slib.malpedia.refresh

Get actors or families straight from Malpedia (not the snapshot) and model them, between
daily syncs.

```text
slib.malpedia.refresh [--actor <id>]... [--family <id>]... [--yield] [--no-limit]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--actor` | str, repeatable | `[]` | A Malpedia actor ID (for example `apt28`) to refresh. |
| `--family` | str, repeatable | `[]` | A Malpedia family ID (for example `win.xagent`) to refresh. |
| `--yield` | flag | `false` | Yield the refreshed `risk:threat` / `risk:tool:software` nodes instead of the inbound nodes. |
| `--no-limit` | flag | `false` | Refresh more than 25 actors and families in one run. Needs `slib.malpedia.admin`. |

**Permissions:** `slib.malpedia.sync`, plus the same `node.add.<form>` layer check as
`slib.malpedia.sync`. `--no-limit` also needs `slib.malpedia.admin`.

**Input:**

| Form | Used when |
| --- | --- |
| `risk:threat` | `:reporter:name=malpedia` and `:ext:id` is set. Refreshes actor `:ext:id`. |
| `risk:tool:software` | `:reporter:name=malpedia` and `:id` is set. Refreshes family `:id`. |

Other nodes, and nodes that don't qualify, get a warning and are passed through (with
`--yield`, dropped). If `--actor` or `--family` is given, inbound nodes are ignored. The
command then runs once.

IDs are matched case-insensitively. The Storm side lowercases `--actor`/`--family` values, and
the service maps an ID to the snapshot's spelling. So `APT28` refreshes `apt28`, not a second
node. An ID is rejected if it is empty, longer than 200 characters, or contains whitespace,
`/`, `?` or `#`.

What each refresh requests:

| Kind | Requests | Models |
| --- | --- | --- |
| actor | `/api/get/actor/<id>`, `/api/get/bib/actor/<id>` | The actor, every family on its page (with `-(uses)>` from the actor, even if the family's attribution names don't resolve), and the articles in its BibTeX. |
| family | `/api/get/family/<id>`, `/api/get/yara/<id>`, `/api/get/bib/family/<id>` | The family (actors resolved against the snapshot), its YARA rules, and the articles in its BibTeX. |

The records are modeled in the order actor, family, yara, news. This is the same modeling as a
sync, but the `drop` diff is always empty. A refresh **sets** Malpedia's current values and
never undoes anything: tags and edges Malpedia dropped are removed by the next daily sync.
Refreshing doesn't change the snapshot or the view's sync state.

**Limits:** each ID is refreshed at most once per run. Without `--no-limit`, a run refreshes
at most 25 IDs:

- With `--actor`/`--family`, if more than 25 IDs are given, nothing is refreshed and the
  command warns `Not refreshing <n> actors and families at once, the limit is 25.`
- With inbound nodes, the first 25 distinct IDs are refreshed. After that the command warns
  once, `Refreshed 25 actors and families, skipping the rest.`, and passes the rest through.

Output per refresh: `Modeled news=..., actor=..., family=..., yara=...`, then a warning for
each error (`Unable to refresh <kind> <id>: <mesg>`) and each BibTeX parse warning. If there
was nothing to refresh, it warns `Nothing to refresh. Use --actor or --family, or pipe in
Malpedia's risk:threat or risk:tool:software nodes.`

```text
slib.malpedia.refresh --actor apt28 --family win.xagent

risk:tool:software:id=win.emotet | slib.malpedia.refresh --yield
```

## Lookups

### slib.malpedia.search

Search Malpedia's actor and family names and synonyms. This is a live query against
`/api/find/actor/<needle>` and `/api/find/family/<needle>`.

```text
slib.malpedia.search <needle> [--actors] [--families] [--yield]
```

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `needle` | str | required | The text to search for. Malpedia matches it as a substring. Empty or blank text is an error. |
| `--actors` | flag | `false` | Only search actors. |
| `--families` | flag | `false` | Only search families. |
| `--yield` | flag | `false` | Yield the matching `risk:threat` / `risk:tool:software` nodes that exist in the current view. |

Without `--actors` or `--families`, or with both, both kinds are searched.

**Permissions:** `slib.malpedia.user`. **Input:** none.

For each kind, it prints `<n> actors match <needle>:` (or `families`), then a table:

| Column | Source |
| --- | --- |
| `id` | Malpedia's `name` field (the actor or family ID). |
| `name` | `common_name`. For a known family without one, the snapshot's name. |
| `synced` | `yes` if the snapshot has the ID. |
| `synonyms` | `synonyms` (actors) or `alt_names` (families). |

With `--yield`, it lifts `risk:threat=(malpedia, <id>)` / `risk:tool:software=(malpedia, <id>)`
for each match. A match that isn't in the view yields nothing.

```text
slib.malpedia.search "fancy bear"

// Yield the matching families that are in the current view.
slib.malpedia.search emotet --families --yield
```

### slib.malpedia.status

Show the service's snapshot and the current view's sync state. It makes no requests to
Malpedia.

```text
slib.malpedia.status
```

**Permissions:** `slib.malpedia.user`. **Input:** none.

It prints, from `status(view=<current view>)`:

- `Malpedia version <v> (<date>), pulled <time>, last checked <time>.`, or
  `Malpedia hasn't been pulled yet, run slib.malpedia.sync.`
- `The service has news=..., actor=..., family=..., yara=... (<n> requests to Malpedia so far).`
- `Checks Malpedia at most every <minage> hours.`
- `Last downloaded every YARA rule <time>.` (once a pull has completed)
- `The last pull couldn't get <n> actors or YARA rule families, the next check pulls again.`
  (when there are gaps)
- A warning, `The last pull failed (the next sync retries it): <mesg>` (when the last pull
  failed)
- `This view was synced <time> (Malpedia version <v>) and has <counts>.`, or
  `This view hasn't been synced yet (<counts>).`
- `Last pull warning: <warning>` for each warning of the last successful pull.

Times are printed as `%Y-%m-%d %H:%M:%S UTC`, or `never`.

## Administration

### slib.malpedia.admin.schedule

Show or change the cron job that runs `slib.malpedia.sync`. The job's iden is kept in the
`slib:malpedia:cron` global.

```text
slib.malpedia.admin.schedule [--period <period>] [--enable | --disable] [--delete]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--period` | str | `null` | Replace the sync cron job with a new one on this period, **in the current view**. Uses `cron.add --period` syntax, for example `daily@03:17`. |
| `--enable` | flag | `false` | Enable the sync cron job. |
| `--disable` | flag | `false` | Disable the sync cron job. |
| `--delete` | flag | `false` | Delete the sync cron job and forget its iden. |

**Permissions:** `slib.malpedia.admin`.

How the options combine:

- `--enable` together with `--disable` only warns `Use --enable or --disable, not both.`
- `--delete` wins over everything else. It prints `Deleted the sync cron job.` or
  `There is no sync cron job.`
- `--period` creates the new job (`query=slib.malpedia.sync`, `name=slib.malpedia.sync`, with
  a `doc`), stores its iden, then deletes the old job. It prints
  `slib.malpedia.sync now runs <period> (cron <iden>).` An invalid period warns
  `Unable to schedule slib.malpedia.sync with period <period>: <mesg>`, and the old job is
  kept.
- Then `--enable`/`--disable` apply, if given. If there is no job, the command warns
  `There is no sync cron job, create one with --period.`
- Finally it prints the job: `cron <iden> (enabled|disabled) runs slib.malpedia.sync, in view
  <view>, last run: <time>`.

A job deleted outside this command (for example with `cron.del`) is treated as missing.

`service.del` deletes the job. Adding the service again schedules a new one, at the service's
stored random time in the default view (not the old `--period` or view), and runs a sync
there. See [Syncing](syncing.md#registration-and-the-initial-bulk-pull).

Malpedia is a free community resource, so please don't sync more often than daily. Syncs
within `malpedia:pull:minage` hours of the last check don't contact Malpedia anyway.

```text
slib.malpedia.admin.schedule
slib.malpedia.admin.schedule --period daily@04:41
slib.malpedia.admin.schedule --disable
```

### slib.malpedia.admin.tags

Show or change the tag prefixes.

```text
slib.malpedia.admin.tags [--prefix <tag>] [--tlp-prefix <tag>]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--prefix` | str | `null` | The prefix for actor (`<prefix>.threat.<id>`), family (`<prefix>.mal.<id>`) and removed (`<prefix>.removed`) tags. Stored in `slib:malpedia:tag:prefix`. |
| `--tlp-prefix` | str | `null` | The prefix for YARA TLP tags (`<tlp prefix>.<tlp>`). Stored in `slib:malpedia:tag:tlp`. |

**Permissions:** `slib.malpedia.admin`.

A prefix must already be a valid, normalized tag name. It must cast to `syn:tag`, and the
result must equal the input stripped and lowercased. Otherwise the command warns
`Invalid tag prefix <valu>, it isn't a valid tag name. The <which> prefix wasn't changed.`
It always prints the current `prefix=... tlp=...`.

Changing a prefix doesn't retag anything right away. The next `slib.malpedia.sync` in each
view sees that the prefixes differ from the ones that view last synced with. It then models
every record again with the new tags, and removes the tags (and empty parent tags) it added
under the old prefix. If any record fails during that sync, the new prefixes aren't recorded
for the view, so the next sync does it again. Records Malpedia removed aren't modeled again,
so they keep their old tags.

The TLP prefix is its own setting. Changing `--prefix` doesn't move it, even though its
default (`rep.malpedia.tlp`) lives under `rep.malpedia`: the add event always sets
`slib:malpedia:tag:tlp`, so the model's `<prefix>.tlp` fallback (for an unset global) doesn't
apply. Use `--tlp-prefix` to move it too, for example `--prefix rep.mp --tlp-prefix rep.mp.tlp`.

```text
slib.malpedia.admin.tags
slib.malpedia.admin.tags --prefix rep.mp --tlp-prefix tlp
slib.malpedia.sync --no-pull
```

### slib.malpedia.admin.reset

Forget what the current view has synced, so its next sync models every record again. It
doesn't contact Malpedia or change any nodes.

```text
slib.malpedia.admin.reset --yes
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--yes` | flag | `false` | Confirm the reset. Without it, the command only warns. |

**Permissions:** `slib.malpedia.admin`.

This calls `resetView(<view>)`, which marks every record the view synced as unsynced and
forgets the view's sync time and version (so `slib.malpedia.status` says the view hasn't been
synced yet). The view's last synced version of each record is kept, as are the tag prefixes it
last synced with. So the next sync still tags the records Malpedia removed in the meantime
`removed`, counts the others as `updated`, undoes what they lost since, and removes the tags
under a prefix that changed since.
