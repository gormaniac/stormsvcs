# slib.malpedia

A Storm Service that keeps [Malpedia](https://malpedia.caad.fkie.fraunhofer.de)'s public data in sync with Synapse:

- the **library** (~19k malware analysis and threat intel articles) as `media:news`,
- **threat actors** as `risk:threat`,
- **malware families** as `risk:tool:software`,
- and the families' **YARA rules** as `it:app:yara:rule`,

all linked together and tagged, with one bulk pull when the service is added and small daily updates after that.

Only Malpedia's [public API](https://malpedia.caad.fkie.fraunhofer.de/usage/api) endpoints that need no account ("Access limitation: none") are used, no API token is ever sent, and the site itself is never scraped. MISP data (`/api/get/misp`), samples, and ApiScout are out of scope.

## How it works

The service keeps a normalized **snapshot** of Malpedia in its own storage, and tracks which version of every record it has modeled into each Cortex **view**. Storm models only what changed.

### Pulling Malpedia (the service)

A pull costs very little:

1. `GET /api/get/version` - Malpedia's commit number. If it's the same as the last pull, that's the only request.
2. Otherwise, each bulk endpoint once:

   | Request | What for |
   | --- | --- |
   | `/api/get/bib` | Every library article's title, authors, date, publisher, and language (BibTeX). |
   | `/api/get/references` | Every library URL and the actors and families it's tagged with. |
   | `/api/list/actors`, `/api/get/actors` | Every actor. `get/actors` is keyed by display name, `list/actors` has the IDs. |
   | `/api/get/families` | Every family, with its aliases and the actors it's attributed to. |
   | `/api/list/yara` | Which YARA rules exist (to find removed rules). |
   | `/api/get/yara/after/<date>` | The YARA rules updated since the last pull (with a day of overlap). |

3. Every YARA rule, as one zip (`/api/get/yara/tlp_white/zip`, ~4MB), instead of `yara/after`: on the **first** pull, on forced pulls (`slib.malpedia.sync --force`), and once every `malpedia:yara:fullage` days (7 by default). `yara/after` only returns rules whose `malpedia_version` date is new, so a rule edited without a new date would otherwise keep its old text forever.

A handful of per-entity requests fill gaps in the bulk data, capped at 25 per pull: actors that are in `list/actors` but missing from `get/actors` (`/api/get/actor/<id>`), and new rules `yara/after` didn't return (`/api/get/yara/<family>`, or the zip again if more than 25 families need it). If one of those fails (anything but a 404), or more than 25 actors are missing, the next check pulls again even if Malpedia's version didn't change, so the gap is filled without waiting for a new Malpedia version.

A daily pull is ~8 requests plus any gap requests (usually ~10 in all) and ~5MB when Malpedia changed (plus the ~4MB zip once a week), and 1 tiny request when it didn't. Requests are serialized and spaced `malpedia:interval` seconds apart (2 by default), send a `User-Agent` naming the service, and back off exponentially on errors and HTTP 429s. A Cortex only ever does the bulk pull once. New views, `--full` syncs, and tag prefix changes all re-model the local snapshot, not Malpedia.

A failed pull changes nothing: everything is downloaded and normalized before the snapshot changes, and if Malpedia returns fewer than half of the records of a kind the snapshot already has, the pull is refused (likely an upstream problem) unless it's forced. Syncs never read the snapshot while a pull is writing it. If the service stops while a pull is writing the snapshot, the next pull downloads (and rewrites) everything again, even if Malpedia's version is the same.

### Modeling a view (Storm)

`slib.malpedia.sync` pulls (if due), then asks the service for the records that changed since the view's last sync and models them in this order:

| Malpedia | Synapse | Identity |
| --- | --- | --- |
| Library article | `media:news` | `$lib.gen.newsByUrl(<url>)`, so it merges with the same article from other sources |
| Actor | `risk:threat` | guid `(malpedia, <actor id>)`, `:ext:id=<actor id>` |
| Family | `risk:tool:software` | guid `(malpedia, <family id>)`, `:id=<family id>` |
| YARA rule | `it:app:yara:rule` | guid `(malpedia, <rule file>)`, `:ext:id=<rule file>` |

Every node is linked `meta:source (malpedia) -(seen)> node`, in every view (the sync creates the `meta:source` in a view that doesn't have it).

**`media:news`** (an article): `:url`, `:title`, `:published`, `:publisher` / `:publisher:name` (the BibTeX organization or institution), `:authors` (`ps:contact` by name), and `:ext:id` (the BibTeX key). An article can come from other sources too, so these are only set when they're empty. Articles are tagged with every actor's and family's tag they're about, and linked `media:news -(refs)> risk:threat` / `risk:tool:software`. When several `media:news` nodes have the same URL, the sync always uses the same one: the one `$lib.gen.newsByUrl()` makes, or else the oldest.

**`risk:threat`** (an actor): `:name`, `:org:name`, `:org:names` (synonyms), `:desc`, `:country` / `:country:code`, `:mitre:attack:group` (when exactly one `G####` synonym), `:ext:ids` (Malpedia's MISP galaxy UUID is added, other sources' IDs are kept), `:reporter` / `:reporter:name` (malpedia), `:tag`, and `-(targets)> ou:industry` for its targeted sectors. The node is tagged with its own tag, and the `syn:tag` gets a `:title` and a link to the actor's Malpedia page.

**`risk:tool:software`** (a family): `:id`, `:soft:name`, `:soft` (the `it:prod:soft` with that name, see `$lib.gen.softByName()`), `:soft:names` (alt names), `:desc`, `:reporter` / `:reporter:name`, `:tag`, and `risk:threat -(uses)> risk:tool:software` for the actors it's attributed to. Malpedia attributes families by actor *name*. Names are resolved to actor IDs by display name, then by unique synonym. Ambiguous or unknown names aren't linked, and the pull warns about them. An actor's own `uses` relations to families (in its MISP galaxy `related` list) are linked too.

**`it:app:yara:rule`**: `:name`, `:text`, `:ext:id`, `:url`, `:author`, `:created`, `:updated` (Malpedia's rule version date), `:family`, tagged with its TLP (`rep.malpedia.tlp.white`) and its family's tag, linked `it:app:yara:rule -(detects)> risk:tool:software`, and in the `meta:ruleset` "malpedia yara rules" (`meta:ruleset -(has)> it:app:yara:rule`). `:enabled` is never set, so the rules don't start running in other services (ex. `slib.yara`) until an analyst enables them.

#### Tags

| Tag | On |
| --- | --- |
| `rep.malpedia.threat.<actor id>` | The actor's `risk:threat` (also its `:tag`) and the articles about it. |
| `rep.malpedia.mal.<platform>.<family>` | The family's `risk:tool:software` (also its `:tag`), its YARA rules, and the articles about it. Ex. `rep.malpedia.mal.win.xagent`. |
| `rep.malpedia.tlp.<tlp>` | YARA rules, by the TLP Malpedia published them under. |
| `rep.malpedia.removed` | Actors, families, and YARA rules Malpedia removed (they're never deleted). |

IDs are normalized like Synapse tag parts, ex. `[vault_7_8]` becomes `vault_7_8`. The prefixes are configurable with `slib.malpedia.admin.tags`. The next sync in each view after a prefix change models every record again with the new tags, and removes the tags it added under the old prefix. Removed records (tagged `removed`, not in Malpedia anymore) aren't modeled again, so they keep their old tags.

#### Updates and removals

Each record the view synced is remembered, so when Malpedia changes a record the sync also undoes what the old version added: an article that's no longer tagged with an actor loses that actor's tag (and its parent tags, unless the article has other tags under them) and `-(refs)>` edge, a family that's no longer attributed to an actor loses the `-(uses)>` edge, a YARA rule that moved to another family loses the old tag and `-(detects)>` edge, and dropped aliases, descriptions, countries, and sectors are removed. Records that come back lose the `removed` tag.

A record that fails to model isn't marked synced, so the next sync tries it again, and a sync that stops early picks up where it left off. A removed record whose node isn't in the view (ex. an analyst deleted it) has nothing to undo, so it's done.

#### Upgrading from 0.2.x

- Articles were linked with `-(about)>` edges, which the data model doesn't declare for `media:news`. Syncs now use `-(refs)>`, and replace the `-(about)>` edge of every article they model. Run `slib.malpedia.sync --full --no-pull` once per view to replace them all.
- Views synced in a view without the `malpedia` `meta:source` have no `-(seen)>` edges. `slib.malpedia.sync --full --no-pull` adds them.
- The tag prefixes a view was synced with weren't recorded, so the old tags from a prefix change before the upgrade aren't removed.
- The first pull after the upgrade downloads every YARA rule.

## Installation

Run the image (`ghcr.io/gormaniac/stormsvcs/malpedia`) and add it to the Cortex:

```
service.add slib.malpedia tcp://root:<password>@<host>:27492/
```

When the service is added, it (unless `malpedia:autosync` is off):

1. creates the `malpedia` `meta:source` and the default tag settings,
2. schedules `slib.malpedia.sync` to run **daily** at a random time (so deployments don't all hit Malpedia at once), in the Cortex's default view (move it with `slib.malpedia.admin.schedule --period` from another view),
3. and starts the **initial sync**, also in the default view, in the background (a one time cron job), so `service.add` doesn't wait for it. The first sync models ~19k articles, ~1.1k actors, ~3.8k families, and ~2.3k YARA rules, which takes 10-15 minutes.

`service.del` deletes the daily sync cron job and the setup job. The tag settings, and the nodes, are kept.

### Configuration

| Option | Default | Description |
| --- | --- | --- |
| `malpedia:url` | `https://malpedia.caad.fkie.fraunhofer.de/api` | Malpedia's API. |
| `malpedia:interval` | `2.0` | Minimum seconds between two requests to Malpedia. |
| `malpedia:timeout` | `300` | Timeout, in seconds, for one request. |
| `malpedia:backoff` | `5.0` | Base seconds of the exponential backoff between retries. |
| `malpedia:pull:minage` | `12` | Hours after a version check before a sync checks again (syncs in between model the snapshot without any requests). Failed pulls are retried by the next sync. |
| `malpedia:yara:fullage` | `7` | Days after the last download of every YARA rule (one ~4MB zip) before a pull downloads them all again, to catch rules that changed without a new version date. `0` only does it on the first pull and forced pulls. |
| `malpedia:autosync` | `true` | Schedule the daily sync and start the initial sync when the service is added. |

## Commands

| Command | Permission | Description |
| --- | --- | --- |
| `slib.malpedia.sync [--full] [--no-pull] [--force]` | `slib.malpedia.sync` (`--force`: `slib.malpedia.admin`) | Pull (if due) and model the changes into the current view. |
| `slib.malpedia.refresh [--actor <id>] [--family <id>] [--yield] [--no-limit]` | `slib.malpedia.sync` (`--no-limit`: `slib.malpedia.admin`) | Get actors/families straight from Malpedia (2-3 requests each) and model them, between daily syncs. Also takes Malpedia `risk:threat` / `risk:tool:software` nodes. Refreshes each one once, and at most 25 per run unless `--no-limit` is used. It sets Malpedia's values, but doesn't undo anything (the daily sync does). |
| `slib.malpedia.search <text> [--actors] [--families] [--yield]` | `slib.malpedia.user` | Search actor and family names and synonyms. |
| `slib.malpedia.status` | `slib.malpedia.user` | The snapshot's Malpedia version, counts, and the view's sync state. |
| `slib.malpedia.admin.schedule [--period <period>] [--enable/--disable/--delete]` | `slib.malpedia.admin` | Manage the sync cron job. |
| `slib.malpedia.admin.tags [--prefix <tag>] [--tlp-prefix <tag>]` | `slib.malpedia.admin` | Change the tag prefixes (they must be valid tag names). Each view's next sync applies them, and removes the old tags. |
| `slib.malpedia.admin.reset --yes` | `slib.malpedia.admin` | Forget what the view synced, so the next sync models everything. |

Syncing edits nodes as root (so users don't need permissions on every form, tag, and edge involved), but only for users that can add `media:news`, `risk:threat`, `risk:tool:software`, and `it:app:yara:rule` nodes to the view's layer.

## Things the API doesn't have

The scraping-era plan for this service called for a few things Malpedia's public API doesn't expose, so they're left out rather than scraped:

- **VirusTotal collection links** on family pages.
- **The library's per-page metadata** beyond what `/api/get/bib` and `/api/get/references` have. Those two cover every article and every actor/family tag, so the library pages are never needed.
- **TLP:GREEN/AMBER YARA rules**, which need a registered account.
- **When an actor or family was discovered or first published.** Malpedia only has a family's last `updated` date, so `:reporter:discovered` and `:reporter:published` aren't set.

Some data the service has isn't modeled, because Synapse 2.x has no property for it: a family's UUID, platform, and `updated` date, an article's language, BibTeX entry type, and the date Malpedia added it, and a YARA rule's description and license. `risk:tool:software:type` isn't set either: Malpedia doesn't say whether a family is malware or a tool.

## Development

```
uv sync
uv run pytest
```

Tests run against a fake Malpedia server (`tests/fakemalpedia.py`). `tests/test_live.py` runs a few cheap, read-only requests against the real API, and is skipped unless `SLIB_MALPEDIA_LIVE=1` is set. Please don't point the full sync at the real Malpedia in tests.
