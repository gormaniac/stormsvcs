# slib.shodan rework: query provenance, count modeling, inbound nodes, and host history timelines

**Status:** DESIGN. No code yet. This document is the implementation plan.
**Date:** 2026-11-02
**Targets:** Shodan REST/Streaming/Trends APIs as documented on 2026-11-02 · Synapse ≥ 2.137.0
(the package's current `synapse_minversion`, see Open question 7) · stormsvcs conventions ·
starting from `slib.shodan` **0.5.0**
**Research appendices (same directory):**
- `shodan-api-research.md`: the Shodan API, with citations and a "Could not verify" list.
- `synapse-model-research.md`: the Synapse model, verified against a live `getModelDict()` dump of
  synapse 2.256.0.

Every form, property and edge named below is in that dump unless it is marked as a workaround.
Every Shodan field appears in the API appendix.

---

## 1. Overview

### 1.1 Goal

This rework adds five capabilities to the existing `slib.shodan` service (`svcs/shodan/`):

1. **Query provenance.** Each Shodan query the service runs (search, stream, count) becomes an
   `it:exec:query` node. It records what was asked, by whom and when, and `-(found)>` edges link it
   to the `inet:server`, `inet:banner` and `inet:ipv4`/`inet:ipv6` nodes the query returned.
2. **A modeling count command (`slib.shodan.count`).** It models the infrastructure a query matches
   without spending query credits, using the free `/shodan/host/count` endpoint. The output is an
   IP-whois-style view (ASN, org, location, …) plus the ports each matching IP serves. It models the
   *data* that count returns, not the counts. `slib.shodan.search --count` remains the way to print
   totals.
3. **More inbound forms** for `slib.shodan.host`, `slib.shodan.trends`, `slib.shodan.stream` and the new
   count command.
4. **Host history timelines.** `slib.shodan.host --history` builds one `meta:timeline` per IP and one
   `meta:event` per historical banner. Each event links to the `inet:server`, `inet:banner` and IP
   node created from that banner. Re-runs are idempotent.
5. **Saved queries in Synapse.** Saved Shodan queries are `meta:rule` nodes, and they come from two
   separate sources that **never sync**:
   - **Community queries** are copied from Shodan's public query directory. Their `:name` starts with
     `[Community] `.
   - **Local queries** are saved in the Cortex by analysts with a new `slib.shodan.query.save`
     command.

   `slib.shodan.queries` lists both by default, and a `--source` flag picks one (§5.9).

**Acceptance:** `inet:ipv4=1.2.3.4 | slib.shodan.host --history` gives a timeline you can lift with
`meta:timeline:title="Shodan history: 1.2.3.4" -> meta:event | sort :time`. Each event pivots
(`-(refs)>`) to the exact server, banner and IP that the crawl observed. Running the command twice
creates no new nodes.

### 1.2 Non-goals for this rework

- **Modeling counts.** Facet counts and totals are not stored anywhere, including props, node data
  and tags. They are relative to a 30-day window and change constantly. `search --count` prints them.
- **Full Shodan history.** The API only returns 90 days, capped at the most recent 1,000 banners,
  with no paging (API appendix §1.3). Longer history accumulates only by running the command again
  over time.
- **Grouping routine crawls into "scans".** Shodan has no grouping ID for routine crawls. Each one
  is a single IP:port probe (API appendix §2, gotcha 4). One event per banner is the most accurate
  unit available.
- **Linking queries and events to every derived node.** `-(found)>` and `-(refs)>` go only to
  `inet:server`, `inet:banner` and `inet:ipv4/6`. Everything else (certs, softvers, vulns, headers,
  DNS) is one hop from those nodes already. This was the maintainer's decision.
- **New Shodan endpoints**, except reading `_shodan.options.scan` (§5.4).

### 1.3 Why this is hard

1. **`model.banner()` returns only the `inet:server`.** Both `-(found)>` and `-(refs)>` need the
   banner and IP nodes that each banner produced. The model functions have to change shape without
   breaking the documented `$lib.import(slib.shodan.lib)` API.
2. **Facets don't nest** (API appendix §5). "Ports per IP" can't come from one count call. It takes a
   two-stage fan-out of N+1 free calls, rate limited to 1 request per second.
3. **Facet value formats are mostly undocumented** (API appendix §4.2, Could not verify 2–3). The
   value formats for `asn`, `ip`, `ssl.cert.serial` and `vuln` are inferred. Normalization has to
   accept every plausible format and validate with `$lib.trycast`.
4. **`_shodan.id` is not guaranteed to exist** (API appendix §1.6). The idempotency key needs a
   deterministic fallback.
5. **The default facet list isn't decided yet** (Open question 1). The design has to make it a single
   constant plus a config override, so filling it in later doesn't change the code.

---

## 2. Background (condensed)

**Shodan.** Shodan's unit of data is the *banner*: one observation of one IP:port at one time. Each
banner has a `timestamp` (ISO 8601, UTC, no timezone) and a `_shodan` block with `id` (per-banner,
usually a UUID), `crawler`, `module`, `ptr` and `options.{hostname, referrer, scan}`. Search, count
and host lookups cover the last 30 days. `?history=true` covers 90 days, up to 1,000 banners. Count
is free and returns `{total, facets: {name: [{count, value}]}}`, with a default facet size of 5 and a
plan-dependent maximum. Search costs 1 query credit per page when the query has a filter or the page
is ≥ 2. The REST API is limited to 1 request per second, with HTTP 429 above that. Details and
citations are in `shodan-api-research.md`.

**Synapse model anchors** (verified, `synapse-model-research.md`):

- `it:exec:query` has `:text (it:query)`, `:language`, `:opts (data)`, `:api:url`, `:offset`,
  `:time`, `:synuser`. `:service:instance` is deprecated, so don't use it.
- `it:exec:query -(found)> *` is declared: "The target node was returned as a result of running the query."
- `* -(refs)> *` is declared generically.
- `meta:timeline` has `:title`, `:summary`, `:type (meta:timeline:taxonomy)`.
  `meta:event` has `:timeline` (**single-valued**), `:time`, `:title`, `:summary`, `:index`,
  `:duration`, `:type (meta:event:taxonomy)`.
- `meta:source -(seen)> *` is the service's existing provenance convention (`slib.shodan.model`
  `seen()`), and it applies to every new node.
- IP-whois forms: `inet:ipv4/6:asn/:loc/:latlong/:place/:dns:rev`, `inet:asn:name/:owner`,
  `inet:asnet4/6`, `inet:whois:iprec` (+ `-(ipwhois)> inet:ipv4/6`), `pol:country` (via
  `$lib.gen.polCountryByIso2`), and `ou:org` (via `$lib.gen.orgByName`).
- `inet:ssh:hassh` does **not** exist.
- `svcs/ip_api` is the precedent for IP-whois modeling. It sets `inet:asn` with an `:owner` org,
  `:loc`, `:latlong`, `:place` and a `geo:telem`.

---

## 3. Naming & repo integration

This is an existing service, so nothing about its layout changes.

| Item | Value |
|---|---|
| Service folder / package | `svcs/shodan/` / `shodansvc` (unchanged) |
| Storm package | `slib.shodan` (unchanged) |
| New commands | `slib.shodan.count`, `slib.shodan.admin.count`, `slib.shodan.query.save` |
| New taxonomies | `meta:timeline:type=svc.shodan.host.history.` and `meta:event:type=svc.shodan.banner.`, under the same `svc.shodan.` root as the existing `meta:rule:type=svc.shodan.query.`. New `meta:rule:type` children: `svc.shodan.query.community.` and `svc.shodan.query.local.` (§5.9). |
| New globals | `slib:shodan:count:facets` (facet list override) and `slib:shodan:count:facetmap` (custom mappings), set by `slib.shodan.admin.count` |
| Versions | Each roadmap phase is one **minor** bump: 0.6.0 → 0.9.0 (§16). The version is set in `pyproject.toml`, `__init__.py`, `slib.shodan.yaml` and `uv.lock` (edit the lock entry directly, then `uv lock --check`), per `CLAUDE.md`. |
| Dependencies | None new |

---

## 4. Service architecture

### 4.1 Files touched

```
svcs/shodan/src/shodansvc/
├── norm.py          # + normFacetValue(), normCountFacets(); normBanner keeps _shodan.options.scan
│                    #   and metadata.truncated
├── svc.py           # + countIps() helper (two-stage fan-out), stays in the 1 rps limiter
├── api.py           # + "countIps" in RETN_METHS (generator, like searchGenr)
├── defs.py          # + COUNT_IP_FACETS / COUNT_QUERY_FACETS placeholders (Open question 1)
└── pkgproto/
    ├── slib.shodan.yaml                       # new commands, cmdinputs, options
    └── storm/
        ├── modules/slib.shodan.model.storm    # banner() result dict, query(), timeline(), event()
        ├── modules/slib.shodan.lib.storm      # host() timeline support, count(), streamValues()
        ├── modules/slib.shodan.priv.user.storm# + countIps() wrapper
        ├── commands/slib.shodan.count.storm   # new
        ├── commands/slib.shodan.admin.count.storm # new
        └── commands/{search,stream,host,trends}.storm  # query nodes, inbound nodes
```

### 4.2 Python changes

- **`ShodanSvc.countIps(query, ipfacets, limit, apikey)`** is an async generator:
  1. `count(query, facets=f"ip:{limit}")` gets the top IPs.
  2. For each IP: `count(f"{query} ip:{ip}", facets=<per-IP facets>)` (Open question 4 covers
     whether IPv6 needs `ip:` or `net:`).
  3. Yield `{"ip": <dotted>, "facets": {name: [value, ...]}}`. The counts are dropped here, so Storm
     never sees them.

  It goes through the existing `RateLimiter` (1 rps) and 429 retry in `client.py`. An error in step 1
  ends the generator. An error for one IP yields a `status=False` item and the loop continues, so a
  single plan-gated or bad IP doesn't throw away the rest of the run.
- **`norm.normFacetValue(facet, value)`** normalizes values from formats we haven't confirmed:
  - `asn`: strip any `AS` prefix and cast to int.
  - `ip`: if the value is an int, convert it to dotted form.
  - `vuln` / `vuln.verified`: upper-case; drop values that start with `!` (gotcha 20).
  - `port`: int.
  - `ssl.cert.serial`: int → hex string, the same as the existing `normCert`.
  - Anything else: `str(value)`.

  Storm then `$lib.trycast`s each value into its target type, so a bad format is skipped with a
  warning and never raises.
- **`normBanner`** also keeps:
  - `scan`: `_shodan.options.scan`.
  - `region`: `_shodan.region` or `_shodan.options.region`, whichever is set (gotcha 3).
  - `truncated`: `metadata.truncated`.
  - `hash`: the banner `hash`, used in the fallback event key.
- No new Telepath surface beyond `countIps`. The API key handling is unchanged: the user vault takes
  precedence over the service key, and the key is never readable from Storm.

---

## 5. Data model mapping

### 5.1 Identity, provenance and guid seeds

| Node | Identity | Why |
|---|---|---|
| `it:exec:query` | `$lib.guid()` (random, **one per execution**) | An execution is a fact with its own time and results. Re-running a search is a new execution. Deterministic seeds would merge distinct runs and blur their `-(found)>` sets. |
| `meta:timeline` (host history) | `$lib.guid(slib.shodan, history, <ip repr>)` | One per IP, stable across runs and users. |
| `meta:event` (one banner) | `$lib.guid(slib.shodan, banner, <_shodan.id>)`. If there's no id: `$lib.guid(slib.shodan, banner, <ip>, <port>, <transport>, <timestamp>, <hash>)` | Idempotent re-runs (API appendix §1.6, gotcha 2). `timestamp` has microsecond resolution, so the fallback is unique per crawl. |
| `meta:timeline:taxonomy` / `meta:event:taxonomy` | taxon values above | Created with `[ ... ?= ]`. |

Every new node gets `<(seen)+ { meta:source=<slib.shodan guid> }` through `model.seen()`. Props set
on existing nodes use `?=`, so analyst edits survive re-runs. The exceptions are `:time` and
`:timeline` on events, which are deterministic for a given guid.

### 5.2 Model refactor: banner results

`model.banner(b, tagPrefix)` currently returns the `inet:server`. It changes to:

- **`model.bannerNodes(b, tagPrefix)`** (new) returns
  `({"server": <inet:server>, "banner": <inet:banner or null>, "ip": <inet:ipv4/6>})`.
- **`model.banner()`** stays as a wrapper that returns `bannerNodes(...).server`. The public
  return value doesn't change.
- **`model.host(h, tagPrefix, timeline=$lib.null)`** passes each banner's result dict to `event()`
  when it's given a timeline.

All the existing derived modeling (certs, softvers, vulns, headers, SSH keys, DNS) stays exactly as
it is.

### 5.3 `it:exec:query`, one per Shodan query execution

| Prop | Value |
|---|---|
| `:text` | The query exactly as sent to Shodan, including the AND'd query built for an inbound node. For streams: `<kind>:<values joined by ','>`, or the custom query. |
| `:language` | `shodan` |
| `:time` | `$lib.time.now()` when the first request is sent |
| `:synuser` | `$lib.user.iden` |
| `:api:url` | Endpoint without the key, ex. `https://api.shodan.io/shodan/host/search`, `https://api.shodan.io/shodan/host/count`, `https://stream.shodan.io/shodan/asn/3303,15169` |
| `:offset` | The number of results consumed: banners for search/stream, IPs for count |
| `:opts` | `{"command": "slib.shodan.search", "limit", "page", "minify"}`, `{"kind", "values", "limit", "timeout"}` for streams, or `{"ipfacets", "limit"}` for count. **Never the key.** |

Edges:

- `it:exec:query -(found)> inet:server`, `inet:banner` and `inet:ipv4`/`inet:ipv6`. Only these
  three classes, as decided.
- `it:exec:query -(refs)> <inbound node>`, when the query was built from an inbound node (cert,
  JARM, `meta:rule`, ASN, …). This makes "searches run for this node" one pivot:
  `crypto:x509:cert=… <(refs)- it:exec:query -(found)> inet:server`.

Which commands create query nodes:

| Command | Creates `it:exec:query`? |
|---|---|
| `search` (ingest mode) | Yes. One per query executed: per inbound node, or once for a bare query. |
| `search --count/--tokens/--filters` | **No.** These are print-only modes and model nothing. |
| `stream` | Yes, one per run. |
| `count` | Yes. One per stage-1 query. Per-IP stage-2 calls attach to the same node, since they are one logical execution. |
| `trends` | No. It prints aggregates and models nothing. |
| `host`, `dns.*`, `cve`, `cpe` | No. These are lookups, not queries (Open question 5). |

Library API: `$shodan.search(query, ...)` returns `({"query": <it:exec:query>, "ips": [...]})`
(new function). The existing functions are unchanged.

### 5.4 Host history timeline

Built by `slib.shodan.host --history`, and also by `slib.shodan.host --timeline` for non-history
lookups, which add the latest banner per port to the same timeline.

**`meta:timeline`**

| Prop | Value |
|---|---|
| `:title` | `?= "Shodan history: <ip>"` |
| `:summary` | `?= "Shodan banners observed for <ip>, one meta:event per banner. Shodan's history covers 90 days and at most the latest 1,000 banners per lookup."` |
| `:type` | `svc.shodan.host.history.` |
| edges | `meta:timeline -(refs)> inet:ipv4/6` (the subject IP) |

**`meta:event`**, one per banner in `data`:

| Prop | Shodan field |
|---|---|
| `:timeline` | the IP's timeline |
| `:time` | `timestamp` (UTC) |
| `:title` | `?= "<transport>/<port> <product> <version>"`, ex. `tcp/22 OpenSSH 8.9p1`. Without a product: `<transport>/<port> <_shodan.module>`. |
| `:summary` | `?=`. If `_shodan.options.scan` is set: `"On-demand scan <scan id>"`; otherwise `"Crawler <_shodan.crawler>"`. If `metadata.truncated` is set, add `" (truncated: <fields>)"`. |
| `:type` | `svc.shodan.banner.` |
| edges | `-(refs)> inet:server`, `-(refs)> inet:banner` (when the banner has `data`), `-(refs)> inet:ipv4/6`. Nothing else. |

Rules:

- Host-level fields (`vulns`, `tags`, `hostnames`, `ports`, `last_update`) probably describe only
  the current 30-day view (API appendix §1.7, unverified). They are modeled as they are today and are
  **not** attached to events.
- `meta:event:timeline` is single-valued. That's fine here: a banner belongs to exactly one IP.
- Historical banners may have large fields removed. If `metadata.truncated` ever lists `data`, skip
  the `inet:banner` and the `refs` edge to it. A truncated text would create a different
  `inet:banner` whose banner hash doesn't match (Open question 6). The event still references the
  server and IP.
- A host with 1,000 historical banners creates 1,000 events. That's acceptable, and the timeline
  makes it browsable. Re-runs are free because the events are idempotent.

### 5.5 Count modeling (`slib.shodan.count`)

What it models: **the infrastructure a query matches, with no counts.**

**Stage 1:** `count(<query>, facets=ip:<limit>)` returns the matching IPs.

- Each IP becomes an `inet:ipv4/6` node, linked with `it:exec:query -(found)>`.

**Stage 2**, for each IP: `count(<query> ip:<ip>, facets=<per-IP facet list>)`. Each facet's values
are mapped onto that IP's nodes:

| Facet | Model | Status |
|---|---|---|
| `port` | `inet:server=tcp://<ip>:<port>` (+ `-(found)>` from the query). Each `port` value is a port that **matched the query** on that IP, not every open port. That's the intended meaning. | built-in |
| `asn` | `inet:ipv4/6:asn ?=`, via the existing `model.setAsn()` | built-in candidate |
| `org` / `isp` | `inet:asn:owner` via `$lib.gen.orgByName` (`ip_api` precedent) | built-in candidate |
| `country` | `inet:ipv4/6:loc ?=` (lower-cased ISO2), and `pol:country` via `$lib.gen.polCountryByIso2` | built-in candidate |
| `city` / `region` | Extend `:loc` (`us.va.ashburn`), using the same loc-building rules as `ip_api.buildLoc` | built-in candidate |
| `domain` / `hostname` | `inet:dns:a/aaaa=(<fqdn>, <ip>)`, the same evidence `model.banner()` already uses for banner hostnames | built-in candidate |
| *others* | through the custom mapping (§5.6) | maintainer list |

**The facet list is deliberately left open** (Open question 1). The maintainer will supply a list
that produces an IP-whois view "à la `ip_api`" with ports per result. The design only fixes:

- `defs.COUNT_IP_FACETS`: the default per-IP list (placeholder: `["port:1000"]` until the maintainer
  supplies the list).
- `slib:shodan:count:facets`: an admin override.
- `--facets`: per-run additions.

Edges and nodes:

- `-(found)>` goes only to the IPs and `inet:server` nodes.
- Whois-style data lives in props on, or one hop from, those nodes. This meets the reachability rule
  without breaking the three-class edge decision.
- Query-level facets that aren't scoped to an IP (ex. top orgs across all results) are **not
  modeled**. They'd have no IP to attach to (Open question 2).

### 5.6 Custom facet → model mappings

Stored in `slib:shodan:count:facetmap` by `slib.shodan.admin.count --map`. The format is
declarative, not Storm, so no admin-supplied code ever runs as other users:

```json
{
  "http.title":  {"kind": "node", "form": "it:dev:str"},
  "ssl.jarm":    {"kind": "node", "form": "inet:ssl:jarmhash"},
  "os":          {"kind": "node", "form": "it:prod:softver", "props": {"name": "$valu"}},
  "hostname":    {"kind": "comp", "form": "inet:dns:a", "valu": ["$valu", "$ip"]}
}
```

- `kind=prop` sets a prop on the IP node.
- `kind=node` creates `<form>=<valu or props>`, linked `inet:ipv4 -(refs)> <node>`.
  (Open question 3: confirm the edge, or use only `prop`/`comp` kinds.)
- `kind=comp` builds a comp form that contains the IP.
- Values go through `normFacetValue`, then `$lib.trycast` to the target type. Invalid values are
  skipped with one warning per facet.
- Built-in mappings take precedence unless the custom map explicitly overrides them.

### 5.7 Tags & taxonomies

| Item | Value |
|---|---|
| `meta:timeline:type` | `svc.shodan.host.history.` |
| `meta:event:type` | `svc.shodan.banner.` |
| `meta:rule:type` | `svc.shodan.query.` (parent, existing), `svc.shodan.query.community.`, `svc.shodan.query.local.` |
| Shodan tags | unchanged: `<prefix>.<shodan tag>` via `applyTags()` when tagging is enabled |

### 5.8 Lossless fallback

The raw `_shodan` block is not stored. Every field that matters is mapped: `id` into the guid,
`options.scan`, `crawler` and `truncated` into the summary, and `module` into the title fallback.
Open question 8 covers whether to also store `_shodan` as node data on the event.

### 5.9 Saved queries: community vs. local

There are two kinds of saved query. Both are `meta:rule` nodes that `slib.shodan.search` can run,
but they come from different places and **never sync with each other or with Shodan**.

| | Community queries | Local queries |
|---|---|---|
| Where they come from | Shodan's public query directory (`GET /shodan/query`, `/shodan/query/search`), copied into the Cortex by `slib.shodan.queries --yield` | Saved by an analyst with `slib.shodan.query.save` (or created by hand) |
| `:type` | `svc.shodan.query.community.` | `svc.shodan.query.local.`. Existing rules with the bare `svc.shodan.query.` type also count as local. |
| `:name` | `"[Community] " + title` (falls back to the query text when there's no title). The prefix is only added once. | Whatever the analyst gives it, no prefix |
| guid | `$lib.guid(slib.shodan, query, community, <query text>)` | `$lib.guid(slib.shodan, query, local, <query text>)` |
| Updates | A snapshot. Later changes in Shodan's directory reach the Cortex only if someone runs `--yield` again. Entries removed from the directory are never deleted locally. | Never sent to Shodan. Shodan's API has no endpoint to save a directory query (only the three read endpoints exist), and sharing to the directory is done on shodan.io. |

**What doesn't sync, stated plainly:**

- Saving a local query does not publish it to Shodan.
- Editing a community query in the Cortex does not change it on Shodan.
- New or changed directory entries don't show up in the Cortex until they're ingested again.
- A local query and a community query with the same text are **two separate nodes**, because their
  guids use different seeds. Saving your own copy of a community query never merges it with the
  community copy.

**Community `meta:rule` props**, from the directory result fields (`title`, `description`, `query`,
`timestamp`, `tags`, `votes`; Open question 10):

| Prop | Value |
|---|---|
| `:name` | `?= "[Community] <title>"` |
| `:text` | `query` (it's in the guid, so it never changes for a given node) |
| `:desc` | `?= description` |
| `:created` | `?= timestamp` |
| `:url` | `?= https://www.shodan.io/search?query=<url-encoded query>` |
| tags | the directory `tags` as `<prefix>.query.<tag>`, only when tagging is enabled |

- `votes` is not stored, since it's a count (§1.2).
- `?=` means re-ingesting never overwrites an analyst's edits to the name or description.

**Local `meta:rule` props:** `:name`, `:text`, `:desc` (optional), `:created=now`, and
`:author` is left unset. `slib.shodan.query.save` warns, without failing, if the same text already
exists as a local query, and returns the existing node.

**Running saved queries.** `searchQuery()` currently requires `:type` to equal `svc.shodan.query.`.
It changes to accept any type at or under `svc.shodan.query.`. Lifting every saved query is then
`meta:rule:type^=svc.shodan.query.`, and lifting one source is
`meta:rule:type=svc.shodan.query.community.`. Each run's `it:exec:query -(refs)> meta:rule` (§5.3)
gives every saved query its run history.

---

## 6. Sync & orchestration

There are no scheduled syncs. Every run is an on-demand command.

- **History:** each `host --history` run adds new events and is a no-op for events already seen.
  Running it on a schedule (cron) extends a timeline beyond the 90-day API window. That's the only
  way to keep longer history.
- **Count fan-out:** N+1 requests at 1 request per second. `--limit` (IPs) defaults to 100, about
  100 seconds. `--limit 0` is capped at the plan's facet maximum and is warned about. Each IP is
  modeled as soon as its call returns, so an interrupted run keeps what it already ingested.

---

## 7. Storm package surface

### 7.1 Permissions

| Perm | Covers |
|---|---|
| `slib.shodan.user` | `count` (new), and the existing user commands |
| `slib.shodan.admin` | `admin.count` (new: facet list and mappings) |

### 7.2 Commands

**`slib.shodan.count`** (new)

- `query` (positional, AND'd with the query built for each inbound node)
- `--limit <n>`: IPs, default 100
- `--facets <csv>`: extra per-IP facets for this run
- `--yield`: yield the `it:exec:query` nodes instead of the inbound nodes; by default it yields the
  IPs, matching `search`
- cmdinputs: every `search` form, through `$shodan.searchQuery()`

**`slib.shodan.admin.count`** (new)

- `--facets <csv>` / `--reset`
- `--map <json>` / `--unmap <facet>`
- `--list`

**`slib.shodan.search`**

- Ingest mode creates `it:exec:query` nodes.
- New `--yield-query` option: yield the query nodes instead of the IPs.

**`slib.shodan.stream`**

- Creates one `it:exec:query` per run.
- New cmdinputs, all collected into one stream like `scan` does (one subscription, not one per node):
  - `inet:asn` → `asn`, no `AS` prefix (gotcha 12)
  - `risk:vuln` (`:cve`) / `it:sec:cve` → `vulns`
  - `pol:country` (`:iso2`) → `countries`
  - `meta:rule` with `:type=svc.shodan.query.` → `custom` (case-sensitive, gotcha 13)
- If the inbound nodes mix kinds, warn and use the first kind.

**`slib.shodan.host`**

- New option: `--timeline`.
- `--history` implies `--timeline`; `--no-timeline` opts out.
- New cmdinputs:
  - `inet:server` → `:ipv4`/`:ipv6`
  - `inet:banner` → `:server:ipv4`/`:server:ipv6`
  - `inet:dns:a` / `inet:dns:aaaa` → `:ipv4`/`:ipv6`
- `inet:fqdn` is deferred (§14).

**`slib.shodan.trends`**

- Accepts inbound nodes through `searchQuery()`.
- It rejects inbound forms whose filter Trends doesn't support. The supported list is in API
  appendix §7; `hash` and `ssl.cert.fingerprint` *are* supported, `hostname` is supported, `scan` is
  not. Check the filter prefix of the built query against a `TRENDS_FILTERS` constant in
  `slib.shodan.lib`.

**`slib.shodan.queries`**

Lists both kinds of saved query (§5.9).

- **`--source all|local|shodan`**, default `all`:
  - `local`: only `meta:rule` nodes stored in the Cortex. That includes local queries and any
    community queries ingested earlier, which show their `[Community]` name.
  - `shodan`: only the live Shodan directory.
  - `all`: both. Local results print first.
- The printed table gets a `source` column (`local`, `community (stored)` or `shodan`). A Shodan
  result whose community guid already exists in the Cortex is marked `stored`.
- `--search <text>`:
  - On Shodan it uses `/shodan/query/search`.
  - Locally it's a case-insensitive substring match on `:name`, `:text` and `:desc`. The match is
    done in Storm, not as a regex, so the search text is never treated as a pattern.
- `--yield`:
  - Shodan results are stored as community `meta:rule` nodes, then yielded.
  - Local results are lifted and yielded.
  - Without `--yield`, the command only prints and creates nothing.
- `--tags`, `--page`, `--sort` and `--order` apply to the Shodan side only. If they're used with
  `--source local`, the command warns.

**`slib.shodan.query.save`** (new)

- `query` (positional), `--name <str>` (required), `--desc <str>`, `--yield`.
- Creates a local `meta:rule` (§5.9). It never contacts Shodan.
- Requires the `slib.shodan.user` perm and node-add permission for `meta:rule`.

### 7.3 Docs

Update `README.md` and each command's `descr` with the new behavior. Add examples of pivoting from a
query to its results and walking a timeline.

---

## 8. Python implementation notes

- Never put the API key in `:opts` or `:api:url`. Build `:api:url` from `client.BASE_URLS` plus the
  path, without params.
- Escape IPs in stage-2 queries with the existing `quote()` logic. An IP comes from Shodan's own
  facet output, which is still untrusted input to a query string.
- `countIps` must not hold the rate-limiter lock across yields. It already uses
  `RateLimiter.wait()` per request.

---

## 9. Testing strategy

**`fakeshodan.py`**

- Host fixtures with `history=true`:
  - repeated banners for the same port with different timestamps
  - one banner with `_shodan.id: null`
  - one with `_shodan.options.scan`
  - one with `metadata.truncated`
- `/shodan/host/count` that inspects the `ip:` filter and returns per-IP facets. The facet values
  should use the awkward formats: `AS`-prefixed and bare ASNs, an integer IP, lower-case CVEs and a
  `!CVE`.

**Python unit tests**

- `normFacetValue` for every case above.
- `countIps`:
  - drops the counts
  - continues after a per-IP error
  - honors the limit

**StormPkgTest**

- **Query provenance:**
  - one `it:exec:query` per inbound node
  - `-(found)>` only to the three forms
  - `-(refs)>` to the inbound node
  - no key anywhere in the node
  - print-only modes create no query nodes
- **History:**
  - one timeline per IP and N events
  - run twice → node count unchanged (idempotency)
  - the fallback key is used when `id` is null
  - events reference only server, banner and IP
- **Count:**
  - IPs, servers and mapped props are created
  - no count values are stored in props, node data or tags
  - custom mapping kinds work
  - an invalid mapping value is skipped with a warning
- **Inbound:** each new cmdinput form on host, trends and stream.
- **Saved queries:**
  - `--source local`, `--source shodan` and `--source all` each list the right rows.
  - Community rules get exactly one `[Community] ` prefix, including after re-ingest.
  - A local and a community rule with the same text are two separate nodes.
  - Re-ingest keeps analyst edits to `:name` and `:desc`.
  - `query.save` makes no Shodan request (the fake server asserts no calls).
  - Local search text containing regex characters is matched literally.
  - `search` runs community, local and legacy `svc.shodan.query.` rules.
- **Model existence:** `it:exec:query -(found)>`, `meta:timeline` and `meta:event` exist on the
  pinned synapse (Open question 7).
- **Versions:** `test_versions_match` is updated each phase.

**Live tests (gated)**

- One keyed `host?history=true` call that records whether host-level fields are current-only and
  whether `_shodan.id` is stable across two calls (Open questions 6 and 9).
- One count call with `ip` and `asn` facets to pin down the value formats.

---

## 10. Docker & deployment

Unchanged.

---

## 11. Performance & scale budget

| Dimension | Target | Mechanism |
|---|---|---|
| History events per host | ≤ 1,000 per lookup | API cap. Idempotent guids keep re-runs a no-op. |
| Count fan-out | 100 IPs ≈ 100 seconds | 1 rps limiter, `--limit`, IPs modeled as they arrive |
| Query nodes | 1 per execution | `-(found)>` only to 3 forms, so edge count ≤ 3 × results |

---

## 12. Security considerations

- The key is never stored on graph nodes. Strip `api_key` from any `/shodan/scans` data (gotcha 6).
- Custom mappings are declarative JSON stored by admins. No Storm text from globals is ever evaluated.
- Facet values and banner fields are attacker-controlled. Everything goes through
  `$lib.trycast`/`?=`, and `:title`/`:summary` are built from typed fields only.

---

## 13. Worked example / acceptance narrative

```
// Query provenance.
crypto:x509:cert:sha1=e652c8bd1cafd04a44239fa8dab0c59deacb79ee | slib.shodan.search --yield-query
-> it:exec:query -(found)> inet:server

// History timeline, run twice: the second run adds nothing.
inet:ipv4=1.2.3.4 | slib.shodan.host --history
inet:ipv4=1.2.3.4 | slib.shodan.host --history
meta:timeline:title="Shodan history: 1.2.3.4" -> meta:event | sort :time
meta:event:type=svc.shodan.banner. +:time@=(-30 days, now) -(refs)> inet:banner

// Model the infrastructure behind a query, with no query credits.
slib.shodan.count "ssl.jarm:2ad2ad0002ad2ad00042d42d00000069d641f34fe76acdc05c40262f8815e5" --limit 50
inet:ipv4 <(found)- it:exec:query:text~="ssl.jarm" | -> inet:server

// Inbound nodes on the commands that gained them.
inet:server:port=22 | slib.shodan.host
inet:asn=15169 | slib.shodan.stream asn --limit 50

// Saved queries: copy matching community queries in, save a local one, then run both.
slib.shodan.queries --source shodan --search "cobalt strike" --yield
slib.shodan.query.save "ssl.jarm:2ad2ad0002ad2ad00042d42d00000069d641f34fe76acdc05c40262f8815e5" --name "CS JARM"
slib.shodan.queries --source local
meta:rule:type^=svc.shodan.query. | slib.shodan.search --limit 200
```

**Acceptance criteria:**

1. The idempotency tests pass: a second history run creates no nodes or edges.
2. `-(found)>` and event `-(refs)>` reach only `inet:server`, `inet:banner` and `inet:ipv4/6`.
3. No count value appears in props, node data or tags.
4. No API key appears in any node.

---

## 14. Deferred / later candidates

- **`inet:fqdn` input on `host` with `--resolve`.** It overlaps `enrich`, which already does DNS
  for fqdns.
- **Using `scan:<id>` with `scan --wait`.** This would ingest exactly the on-demand scan's banners
  and link them to a `meta:event`. The search costs credits, but it's free through count.
- **Search and stream banners landing in the IP's timeline**, behind a global toggle.
- **`it:exec:query:service:platform`** pointing at an `inet:service:platform` for Shodan.
- **`inet:whois:iprec`** from a host lookup's org and netblock, if the maintainer's facet list
  calls for it.

---

## 15. Open questions

1. **Default count facet list.** The maintainer will supply it. It goes in `defs.COUNT_IP_FACETS`,
   and the built-in mapper table in §5.5 gets trimmed or extended to match.
2. **Query-level (non-IP) facets.** Skip them (the current design), or model them linked only from
   the query? Linking them from the query would add `-(found)>` targets beyond the three agreed
   classes.
3. **Custom `kind=node` link.** Is `inet:ipv4 -(refs)> <node>` acceptable, or should custom mappings
   be limited to `prop` and `comp`?
4. **IPv6 in stage-2 queries.** Is it `ip:<v6>` or `net:<v6>/128`? Settle this with a live call.
5. **Query nodes for `host`, `dns`, `cve` and `cpe` lookups.** Currently no.
6. **Can `metadata.truncated` include `data` on historical banners?** Settle with a live call. §5.4
   handles it either way.
7. **`synapse_minversion`.** Confirm that `it:exec:query -(found)>` and `meta:event:type` exist at
   2.137.0, or bump the floor.
8. **Store `_shodan` as event node data?** Not needed now.
9. **Is `_shodan.id` stable across repeated calls?** If it isn't, re-runs would duplicate events.
   Then the fallback key becomes the primary key, since it's built only from stable fields.
10. **Directory result fields.** Confirm the field names in `/shodan/query` results (`title`,
    `description`, `query`, `timestamp`, `tags`, `votes`) with one live call, and confirm there's no
    stable directory ID. If there is one, the community guid should use it instead of the query text.
11. **Legacy `svc.shodan.query.` rules.** Leave them as they are and treat them as local (the current
    design), or retype them to `svc.shodan.query.local.` with a one-time migration in the package's
    `onload`?

---

## 16. Phased roadmap

| Phase | Version | Scope | Exit criteria |
|---|---|---|---|
| 1 | 0.6.0 | `bannerNodes()` refactor. `it:exec:query` on `search` and `stream`. `--yield-query`. | Provenance tests; existing tests still pass. |
| 2 | 0.7.0 | Host history timeline: `--timeline`, `--history`, fallback key, `normBanner` additions. | Idempotency tests; live check of Open questions 6 and 9. |
| 3 | 0.8.0 | Inbound nodes for `host`, `trends` and `stream`. | Per-form tests. |
| 4 | 0.9.0 | Saved queries: `queries --source/--yield`, `query.save`, the community/local `meta:rule` types, and `searchQuery()` accepting the whole `svc.shodan.query.` subtree. | Saved-query tests. |
| 5 | 0.10.0 | `slib.shodan.count`, `admin.count`, `countIps`, `normFacetValue`, custom mappings. | **Blocked on Open question 1** (the facet list); count tests. |
