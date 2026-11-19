# Data model

Everything here is written by {src}`svcs/malpedia/src/malpediasvc/pkgproto/storm/modules/slib.malpedia.model.storm`.
It works from the normalized records built by {src}`svcs/malpedia/src/malpediasvc/norm.py`.
Tag names below use the default prefixes `rep.malpedia` and `rep.malpedia.tlp`.

## Identity and deduplication

| Record | Form | Node identity | Extra ID prop |
| --- | --- | --- | --- |
| actor | `risk:threat` | guid `(malpedia, <actor id>)` | `:ext:id=<actor id>` |
| family | `risk:tool:software` | guid `(malpedia, <family id>)` | `:id=<family id>` |
| yara | `it:app:yara:rule` | guid `(malpedia, <rule file name>)` | `:ext:id=<rule file name>` |
| news | `media:news` | by URL, see below | `:ext:id=<first BibTeX key>` (only if unset) |

Because the guids are derived from Malpedia's IDs, syncs are idempotent, and syncs in
different views make the same nodes.

**Articles** merge with `media:news` from other sources. `getNews(url)` normalizes the URL as
`inet:url`, then uses:

1. the node `$lib.gen.newsByUrl()` would make (`media:news=(gen, url, <url>)`), if it exists,
2. otherwise, the oldest (`.created`) `media:news` with that `:url`,
3. otherwise, it creates one with `$lib.gen.newsByUrl(<url>, try=(true))`.

So syncs and removals always edit the same article when several nodes share a URL. If a URL
doesn't normalize, the record is counted as `skipped`.

Before keying, the service strips a trailing empty `?` or `#` from each URL
(`norm.canonUrl`), because `inet:url` drops them. That way `https://a/b?` and `https://a/b` are
one record. The news record key is the SHA-256 of the URL, because URLs can exceed LMDB's key
limit.

**Other shared nodes**, all deconflicted:

| Node | How |
| --- | --- |
| `meta:source` | Fixed guid `15b7f8ff9cef4e8fa9fedd9f2b10c1a5`, `:name=malpedia`, `:type=slib.malpedia`, `:url=https://malpedia.caad.fkie.fraunhofer.de`. Each sync creates it in the view if it's missing. |
| `ou:org` (reporter) | `$lib.gen.orgByName(malpedia)` |
| `meta:ruleset` | guid `(malpedia, yara)`, `:name="malpedia yara rules"`, `:desc="YARA rules from Malpedia (https://malpedia.caad.fkie.fraunhofer.de)."` |
| `ps:contact` (authors) | `ps:contact=({"name": <ps:name>})`, a guid deconflicted by name. |
| `ou:org` (publishers) | `$lib.gen.orgByName(<ou:name>)` |
| `it:prod:soft` | `$lib.gen.softByName(<it:prod:softname>)` |
| `ou:industry` | `$lib.gen.industryByName(<ou:industryname>)` |
| `pol:country` | `$lib.gen.polCountryByIso2(<code>, try=(true))` |

## Every node: the source link

Every modeled actor, family, rule and article gets `meta:source=15b7f8ff... -(seen)> <node>`.
Modeling a record also removes `#rep.malpedia.removed` from it, because the record is back in
Malpedia. After a prefix change, it removes `#<old prefix>.removed` too.

## media:news (library articles)

The service builds article records from three sources:

- `/api/get/bib`: the BibTeX, parsed by {src}`svcs/malpedia/src/malpediasvc/bib.py`.
- `/api/get/references`: `{url: [{"type": "actor"|"family", "id": ...}]}`.
- each family's `library_entries`: BibTeX keys that also tag the article with the family.

Entries with the same URL are merged.

Articles can come from other sources, so every prop is only set **when it's unset**
(`*unset=`). A prop that another source already set is never overwritten.

| Prop | Value | Upstream field |
| --- | --- | --- |
| `:url` | the canonical URL | BibTeX `url` / references key |
| `:title` | title, LaTeX unescaped | BibTeX `title` |
| `:published` | `YYYY`, `YYYY-MM` or `YYYY-MM-DD` | BibTeX `date` |
| `:publisher:name` | `ou:name` | BibTeX `organization`, else `institution` |
| `:publisher` | `$lib.gen.orgByName(<publisher>)`. Only when the article has no `:publisher`, and its `:publisher:name` is unset or equal to this name. | same |
| `:authors` | `ps:contact` guids, in order. Only when the article has no `:authors`. | BibTeX `author`, split on top-level `and` |
| `:ext:id` | the first BibTeX key | BibTeX entry key |

Tags and edges, for each actor and family the article is about:

| Edit | Example |
| --- | --- |
| `+#rep.malpedia.threat.<actor id>` | `#rep.malpedia.threat.apt28` |
| `+#rep.malpedia.mal.<family id>` | `#rep.malpedia.mal.win.xagent` |
| `media:news -(refs)> risk:threat` | |
| `media:news -(refs)> risk:tool:software` | |

If the target `risk:threat` / `risk:tool:software` doesn't exist yet, a stub is created with its
identity, `:reporter`, `:reporter:name` and `:tag`. The full node arrives later in the same
sync. Any `-(about)>` edge to the same target (from 0.2.x) is removed.

Not modeled: the BibTeX entry type, `language`, and `urldate` (when Malpedia added the
article). They are in the record but Synapse 2.x `media:news` has no props for them.

## risk:threat (actors)

Source: `/api/get/actors` (keyed by display name), matched to `/api/list/actors` IDs. Missing
actors are filled in from `/api/get/actor/<id>`.

| Prop | Value | Upstream field |
| --- | --- | --- |
| `:name` | display name | `value` (falls back to the ID) |
| `:org:name` | `ou:name` of the display name (removed if it doesn't normalize) | `value` |
| `:org:names` | `ou:name` synonyms, excluding ones equal (ignoring case) to the display name. Removed when empty. | `meta.synonyms` |
| `:desc` | description. Removed when Malpedia drops it. | `description` |
| `:ext:ids` | Malpedia's MISP galaxy UUID is added (`++=`). The old UUID is removed if it changed. Other sources' IDs are kept. | `uuid` |
| `:country:code` | lowercased ISO2, only if it is exactly two letters (`?=`) | `meta.country` |
| `:country` | `$lib.gen.polCountryByIso2()` | `meta.country` |
| `:mitre:attack:group` | set when exactly one synonym matches `G####` (`?=`) | `meta.synonyms` |
| `:ext:id` | actor ID | `/api/list/actors` |
| `:reporter` | `ou:org` for `malpedia` | |
| `:reporter:name` | `malpedia` | |
| `:tag` | `rep.malpedia.threat.<actor id>` | |

When a dropped value has no replacement, `:country`/`:country:code` and `:mitre:attack:group`
are removed.

Tags and edges:

- `+#rep.malpedia.threat.<actor id>` on the node.
- The `syn:tag` gets `:title?=<display name>`, and `:doc` set to `Malpedia: <actor url>` if it
  has no doc. The actor URL is `https://malpedia.caad.fkie.fraunhofer.de/actor/<id>`.
- `risk:threat -(targets)> ou:industry` for each sector in `meta.targeted-sector` and
  `meta.cfr-target-category`. Dropped sectors lose the edge. Removing an edge never creates an
  `ou:industry`.

Example record, from the test fake:

```json
{
  "key": "apt28", "id": "apt28", "name": "APT28",
  "uuid": "5b4ee3ea-eee3-4c8e-8323-85ae32658754",
  "desc": "The Sofacy Group is a cyber espionage group.",
  "aliases": ["APT 28", "Fancy Bear", "G0007", "Hidden Bear", "Sofacy"],
  "country": "ru", "sectors": ["Government", "Military"], "mitre": "G0007",
  "tag": "threat.apt28", "url": "https://malpedia.caad.fkie.fraunhofer.de/actor/apt28"
}
```

## risk:tool:software (families)

Source: `/api/get/families` (keyed by family ID) or `/api/get/family/<id>`.

| Prop | Value | Upstream field |
| --- | --- | --- |
| `:id` | family ID, for example `win.xagent` | key |
| `:soft:name` | `it:prod:softname` of the common name (removed if it doesn't normalize) | `common_name` (falls back to the ID) |
| `:soft` | `$lib.gen.softByName(<soft:name>)` | `common_name` |
| `:soft:names` | alt names, excluding the common name. Removed when empty. | `alt_names` |
| `:desc` | description. Removed when Malpedia drops it. An empty string counts as none. | `description` |
| `:reporter` / `:reporter:name` | `malpedia` | |
| `:tag` | `rep.malpedia.mal.<family id as tag path>` | |

Tags and edges:

- `+#rep.malpedia.mal.<platform>.<name>` on the node, for example
  `#rep.malpedia.mal.win.xagent`.
- The `syn:tag` gets `:title?=<common name>`, and `:doc` set to `Malpedia: <family url>` if it
  has no doc. The family URL is `https://malpedia.caad.fkie.fraunhofer.de/details/<id>`.
- `risk:threat -(uses)> risk:tool:software` for each attributed actor. When an attribution is
  dropped, the edge is removed.

**Attribution.** Malpedia attributes families by actor *name*, not ID. `norm.ActorIndex`
resolves each `attribution` entry in this order:

1. an exact display name,
2. a unique display name or ID, ignoring case and punctuation,
3. a unique synonym, ignoring case and punctuation.

Ambiguous or unknown names aren't linked, and the pull warns about them (up to 20 are listed).
An actor's own MISP galaxy `related` entries with `type: uses` add links too, when their
`dest-uuid` is a family's `uuid`.

Not modeled: the family's `uuid`, `platform`, `updated` date and `notes`. Neither are
`:reporter:discovered` and `:reporter:published`, which Malpedia doesn't provide.
`risk:tool:software:type` isn't set, because Malpedia doesn't say whether a family is malware
or a tool.

## it:app:yara:rule (YARA rules)

Source: the TLP:WHITE rules from `/api/get/yara/tlp_white/zip`, `/api/get/yara/after/<date>`
or `/api/get/yara/<family>`. `/api/list/yara` maps each file to its family and TLP, and decides
which rules still exist. Files that don't declare a `rule` are skipped, with a warning.

| Prop | Value | Upstream |
| --- | --- | --- |
| `:name` | the first rule name declared in the file | rule text |
| `:text` | the whole file | rule text |
| `:ext:id` | file name, for example `win.xagent_w0.yar` | |
| `:url` (`?=`) | `malpedia_reference` meta, else the family page URL | meta |
| `:author` | `ps:contact` by name. Removed when there is none. | `author` meta |
| `:created` (`?=`) | normalized date | `date` meta |
| `:updated` (`?=`) | normalized date | `malpedia_version` meta |
| `:family` | `it:prod:softname` of the family's common name. Removed when there is none. | listing / file name |

`:enabled` is **never** set. Malpedia's rules don't start running in other services (for
example `slib.yara`) until an analyst enables them.

Tags and edges:

| Edit | Example |
| --- | --- |
| `+#rep.malpedia.tlp.<tlp>` | `#rep.malpedia.tlp.white` |
| `+#rep.malpedia.mal.<family>` | `#rep.malpedia.mal.win.xagent` |
| `it:app:yara:rule -(detects)> risk:tool:software` | |
| `meta:ruleset -(has)> it:app:yara:rule` | the "malpedia yara rules" ruleset |

A rule's TLP comes from its directory (`tlp_white`, `tlp_clear`, `tlp_green`, `tlp_amber`,
`tlp_red`), and falls back to the `malpedia_sharing` meta. It is normalized to `white`,
`clear`, and so on.

When a rule moves to another family or TLP, it loses the old family tag, the old TLP tag and
the old `-(detects)>` edge.

Not modeled: the rule's `description` and `malpedia_license` meta. They are in the record but
`it:app:yara:rule` has no props for them.

## Tags

| Tag | On | Set by |
| --- | --- | --- |
| `<prefix>.threat.<actor id>` | the actor's `risk:threat` (also its `:tag`), and articles about it | `--prefix` |
| `<prefix>.mal.<family id>` | the family's `risk:tool:software` (also its `:tag`), its rules, and articles about it | `--prefix` |
| `<tlp prefix>.<tlp>` | YARA rules | `--tlp-prefix` |
| `<prefix>.removed` | actors, families and rules Malpedia removed | `--prefix` |

The defaults are `prefix=rep.malpedia` and `tlp prefix=rep.malpedia.tlp`. They are stored in
the Storm globals `slib:malpedia:tag:prefix` and `slib:malpedia:tag:tlp`. If the TLP global is
unset, `<prefix>.tlp` is used. See
[`slib.malpedia.admin.tags`](commands.md#slib-malpedia-admin-tags).

IDs are turned into tag parts the way `syn:tag:part` normalizes them: lowercased, with every run
of non-word characters joined with `_`. For example `[Vault 7/8]` (ID `[vault_7_8]`) becomes
`threat.vault_7_8`. Family IDs keep their dots as tag levels (`win.xagent` becomes
`mal.win.xagent`).

When an article or rule loses a tag, its parent tags are removed too, unless the node has
another tag under them. So an article that loses its only actor tag doesn't keep a bare
`#rep.malpedia.threat`.

## Updates and removals

The service remembers the version of each record that each view modeled. A change sends Storm
the new record, plus a `drop` diff of what was lost since the view's version. The diff covers
only the fields the model undoes:

| Kind | `drop` fields | Undo |
| --- | --- | --- |
| news | `actors`, `families` | Remove the tag (and empty parents) and the `-(refs)>` / `-(about)>` edge. |
| actor | `desc`, `uuid`, `country`, `mitre`, `sectors` | Remove the prop, remove the UUID from `:ext:ids`, remove `-(targets)>`. |
| family | `desc`, `actortags` | Remove `:desc`, remove `risk:threat -(uses)>`. |
| yara | `tlp`, `familytag`, `family` | Remove the old TLP and family tags and the old `-(detects)>` edge. |

When Malpedia removes a record:

| Kind | What happens |
| --- | --- |
| news | The article loses every Malpedia actor and family tag and edge it had. It isn't tagged `removed` and isn't deleted. |
| actor, family | `+#<prefix>.removed`. The node isn't deleted. |
| yara | `+#<prefix>.removed`, and it leaves the ruleset (`<(has)-`). |

If the node isn't in the view (for example an analyst deleted it), there's nothing to undo, so
the removal is marked done. A removed record that comes back loses the `removed` tag.
