# Search, count, stream and saved query commands

All of these need the `slib.shodan.user` permission. See [Commands](commands.md) for the
behavior every command shares, including [the queries built from inbound
nodes](commands.md#queries-built-from-nodes).

(shodan-cmd-search)=
## slib.shodan.search

Search Shodan (`GET /shodan/host/search`) and model every matching banner. Yields the matching
`inet:ipv4`/`inet:ipv6` nodes, once each.

```text
slib.shodan.search [<query>] [--limit <n>] [--page <n>] [--minify] [--facets <facets>]
                   [--count] [--tokens] [--filters] [--file-hash favicon|html]
                   [--yield-query] [--stream-inbound]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `query` | str, optional | `""` | The Shodan query. With inbound nodes, it's AND'd with each node's query. |
| `--limit` | int | `100` | The most banners to ingest per query. `0` reads every page, and warns that it uses a query credit per 100 results. |
| `--page` | int | `1` | The page to start at. |
| `--minify` | flag | false | Ask for minified banners (`minify=true`). Shodan leaves out large fields, ex. the HTTP page. |
| `--facets` | str | null | Comma separated facets (ex. `country,port:5`), printed as tables from a free count request. |
| `--count` | flag | false | Only print the total (and any `--facets`), from the free count API. Ingests and records nothing. |
| `--tokens` | flag | false | Print how Shodan parses the query (`GET /shodan/host/search/tokens`) as JSON, and stop. |
| `--filters` | flag | false | Print the search filters and facets (`/filters`, `/facets`), and stop. |
| `--file-hash` | `favicon` or `html` | null | Search inbound `file:bytes` as this kind, instead of going by `:mime`. |
| `--yield-query` | flag | false | Yield each run's `it:exec:query` instead of the IPs. |
| `--stream-inbound` | flag | false | Run each inbound node as it arrives (see [Commands](commands.md#reading-inbound-nodes-first)). |

Takes the 19 forms listed under [queries built from nodes](commands.md#queries-built-from-nodes).
Inbound nodes are consumed: the command yields IPs (or queries), never the inbound nodes.
Without inbound nodes, `query` runs on its own. With neither, and no `--filters`, the command
raises `BadArg: slib.shodan.search requires a query, inbound nodes, or --filters.`

Each query runs like this:

1. With `--tokens`, it prints the parsed query. Otherwise, with `--count` or `--facets`, it
   calls `GET /shodan/host/count` and prints `Total results: <n> (<query>)` and a table per
   facet.
2. Unless `--count`, `--tokens` or `--filters` was given, the service pages through
   `GET /shodan/host/search` (`searchGenr()`, see [internals](internals.md#search-paging)) and
   every banner is modeled (see [model](model.md#hosts-and-banners)). So `--facets` without
   `--count` prints the facets and ingests too.
3. The run is recorded as an `it:exec:query` (see [model](model.md#query-runs)) with `:opts`
   `{"command": "slib.shodan.search", "limit": ..., "page": ..., "minify": ...}`, linked
   `-(found)>` to each banner's `inet:server`, `inet:banner` and IP, and `-(refs)>` to every
   inbound node that built the query.

Shodan charges one query credit per page of 100 results. Shodan answers a page past the
deepest one a plan can read with an HTTP 400, 403 or 404, which ends the results without a
warning once at least one page was read. An error on the first page is a warning. A failure
after some pages keeps what was ingested and records the run.

```text
// Ingest the first 100 results.
slib.shodan.search "product:nginx country:US"

// Free: the total and the top countries and ports.
slib.shodan.search "ssl.cert.subject.cn:vertex.link" --count --facets country,port:5

// How Shodan parses a query, and the available filters.
slib.shodan.search "apache port:8080" --tokens
slib.shodan.search --filters

// The US services presenting the same SSH banner, free.
inet:server=tcp://1.2.3.4:22 -> inet:banner | slib.shodan.search "country:US" --count

// Every server found by the searches run for a certificate.
crypto:x509:cert:sha1=e652c8bd1cafd04a44239fa8dab0c59deacb79ee | slib.shodan.search --yield-query | -(found)> inet:server

// Run every saved query.
meta:rule:type^=svc.shodan.query | slib.shodan.search --limit 200
```

(shodan-cmd-count)=
## slib.shodan.count

List the IPs matching a query with the count API's `ip` facet (`GET /shodan/host/count`),
which uses no query credits, and model them. Yields the `inet:ipv4`/`inet:ipv6` nodes.

```text
slib.shodan.count [<query>] [--size <n>] [--facets <facets>] [--file-hash favicon|html]
                  [--yield-query]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `query` | str, optional | `""` | The Shodan query. With inbound nodes, it's AND'd with each node's query. |
| `--size` | int | null | The number of IPs to ask for. Defaults to the most the key's plan allows. Must be at least 1. |
| `--facets` | str | null | Comma separated extra facets (ex. `country,org:10`), printed as tables, never modeled. An `ip` facet here is ignored. |
| `--file-hash` | `favicon` or `html` | null | Count inbound `file:bytes` as this kind, instead of going by `:mime`. |
| `--yield-query` | flag | false | Yield each run's `it:exec:query` instead of the IPs. |

Takes the same inbound forms as `slib.shodan.search`, run as each node arrives. Without
inbound nodes or a query, it raises `BadArg: slib.shodan.count requires a query or inbound
nodes.`

Only the IPs are modeled (each linked to the `meta:source`), nothing else about the results.
Each query is one request, plus one more the first time a key asks for more IPs than its plan
allows (see [internals](internals.md#countips-and-facet-limits)). The command prints
`slib.shodan.count: <n> IPs (<query>)` and the facets, and warns:

- `Your plan returns at most <n> IPs per count, asked for <size>.` when `--size` was over the
  plan's limit and was lowered.
- `<query> returned <n> IPs, the most your plan allows in one call. It likely matches more,
  narrow the query (ex. add country: or asn:) to get the rest.` when the IPs fill the limit.
  (Or `the size asked for` with `--size`.)

Facet values that aren't IPs are warned about and skipped. Shodan returns the IPs busiest
first, by the number of matching banners.

The run is recorded as an `it:exec:query` with `:api:url` `https://api.shodan.io/shodan/host/count`,
`:offset` the number of IPs, and `:opts` `{"command": "slib.shodan.count", "size": <asked>,
"facets": <facets>, "full": <bool>}`, linked `-(found)>` to every IP and `-(refs)>` to the
inbound node.

```text
slib.shodan.count "http.favicon.hash:-1166125415"
slib.shodan.count "product:nginx country:US" --size 100 --facets org:10
meta:rule:type^=svc.shodan.query | slib.shodan.count
```

(shodan-cmd-hash)=
## slib.shodan.hash

Compute Shodan's hashes in the service, and print the search filter that finds every service
with the same banner, favicon or HTML page. No Shodan API calls.

```text
slib.shodan.hash [--text <text>]... [--file-hash favicon|html]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--text` | str, repeatable | `[]` | Banner text to hash instead of the inbound nodes, which are dropped. Prints `hash:<n>`. |
| `--file-hash` | `favicon` or `html` | null | Hash inbound `file:bytes` as this kind, instead of going by `:mime`. |

| Form | Prints | Hash |
| --- | --- | --- |
| `inet:banner` | `hash:<n> (the banner from <:server>)` | MurmurHash3 of the UTF-8 `:text` |
| `file:bytes` with `:mime` `image/*` | `http.favicon.hash:<n> (file:bytes <repr>)` | MurmurHash3 of the bytes' base64, with a newline every 76 characters and at the end |
| `file:bytes` with `:mime` `text/html` or `application/xhtml+xml` | `http.html_hash:<n> (file:bytes <repr>)` | MurmurHash3 of the raw bytes |

Every hash is a signed 32-bit MurmurHash3 (x86_32, seed 0), the same as Python's
`mmh3.hash()`. A `file:bytes` is read from the Axon by `:sha256`, 1 MiB at a time, and must be
at most 16 MiB, which needs `axon.has` and `axon.get`. Files that aren't in the Axon, are too
large, or have another `:mime` are warned about. Inbound nodes pass through.

```text
inet:server=tcp://1.2.3.4:22 -> inet:banner | slib.shodan.hash
file:bytes:mime=image/x-icon | slib.shodan.hash
slib.shodan.hash --text "SSH-2.0-OpenSSH_8.9\r\n"
```

(shodan-cmd-trends)=
## slib.shodan.trends

Search Shodan's historical Trends database (`GET trends.shodan.io/api/v1/search`) and print a
monthly breakdown. Nothing is modeled.

```text
slib.shodan.trends [<query>] [--facets <facets>] [--filters] [--file-hash favicon|html]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `query` | str, optional | `""` | The query. With inbound nodes, it's AND'd with each node's query. |
| `--facets` | str | null | Comma separated facets to break the results down by, per month. |
| `--filters` | flag | false | Print the Trends filters and facets (`/api/v1/search/filters`, `/facets`). |
| `--file-hash` | `favicon` or `html` | null | Search inbound `file:bytes` as this kind. |

Takes the same inbound forms as `slib.shodan.search`. A node whose query uses a filter Trends
doesn't support (ex. `ssl.cert.serial` is supported, `http.html` isn't) is warned about and
dropped, other inbound nodes pass through. Without inbound nodes, a query or `--filters`, it
raises `BadArg`. Prints `Total results: <n> (<query>)`, a month / count table, and a value /
count table for each facet and month.

```text
slib.shodan.trends "product:openssh" --facets version:5
crypto:x509:cert:sha1=e652c8bd1cafd04a44239fa8dab0c59deacb79ee | slib.shodan.trends --facets country:5
```

(shodan-cmd-stream)=
## slib.shodan.stream

Read banners from the Streaming API and model them. Yields the `inet:ipv4`/`inet:ipv6` nodes.

```text
slib.shodan.stream [<type>] [--value <v>]... [--query <q>] [--alert <id>]
                   [--limit <n>] [--timeout <s>] [--yield-query]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `type` | one of `banners`, `asn`, `countries`, `ports`, `tags`, `vulns`, `custom`, `alert` | null | The stream to read. Without one, the first inbound node's type, or `banners`. |
| `--value` | str, repeatable | `[]` | An ASN, country code, port, tag or CVE to filter by. Added to the inbound nodes' values. |
| `--query` | str | null | The query of a `custom` stream. |
| `--alert` | str | null | A network alert ID, to read one alert's `alert` stream. |
| `--limit` | int | `100` | Stop after this many banners. `0` for no limit. |
| `--timeout` | int | `60` | Stop after this many seconds. `0` for no timeout. |
| `--yield-query` | flag | false | Yield the `it:exec:query` instead of the IPs. |

| `type` | Request (`stream.shodan.io`) | Values |
| --- | --- | --- |
| `banners` | `/shodan/banners` | none |
| `asn` | `/shodan/asn/{values}` | required, comma separated |
| `countries` | `/shodan/countries/{values}` | required |
| `ports` | `/shodan/ports/{values}` | required |
| `tags` | `/shodan/tags/{values}` | required |
| `vulns` | `/shodan/vulns/{values}` | required |
| `custom` | `/shodan/custom?query=<query>` | `--query` required |
| `alert` | `/shodan/alert`, or `/shodan/alert/{id}` with `--alert` | none |

Inbound nodes are collected and read as one stream (one subscription):

| Form | Stream | Value |
| --- | --- | --- |
| `inet:asn` | `asn` | The ASN number |
| `risk:vuln` | `vulns` | `:cve`, upper case |
| `it:sec:cve` | `vulns` | The CVE, upper case |
| `pol:country` | `countries` | `:iso2`, upper case |
| `meta:rule` | `custom` | `:text`, for saved queries (`:type` `svc.shodan.query.local.` or `.community.`) |

The stream type is the `type` given (`banners` too, which skips every inbound node), or, when
none is given, the first inbound node's (`banners` without inbound nodes).
Nodes for another type are skipped with a warning. A custom stream takes one query: `--query`
wins, then the first `meta:rule`, and the rest are warned about. When there were inbound nodes
but none could be streamed, the command warns `None of the inbound nodes could be streamed.`
and stops. Inbound nodes are never yielded.

The stream stops after `--limit` banners or `--timeout` seconds, whichever comes first. With a
timeout, the service also asks Shodan not to send heartbeats (`heartbeat=false`) and stops when
no data arrives for `--timeout` seconds. Both `0` reads until the connection ends. The Streaming
API needs a plan that includes it.

The run is recorded as an `it:exec:query` with `:text` the custom query, `<type>:<values>` (ex.
`ports:443,53`), `<type>:<alert id>`, or the type, `:api:url` the stream's public URL (ex.
`https://stream.shodan.io/shodan/ports/443,53`), and `:opts` `{"command": "slib.shodan.stream",
"kind", "values", "alert", "limit", "timeout"}`.

```text
slib.shodan.stream asn --value AS15169 --value 13335 --limit 50
slib.shodan.stream custom --query "port:22" --timeout 30
slib.shodan.stream alert --alert ABCDEFG
inet:asn=15169 inet:asn=13335 | slib.shodan.stream --limit 50
risk:vuln:cve^=cve-2024 | slib.shodan.stream --timeout 30
```

(shodan-cmd-queries)=
## slib.shodan.queries

List saved Shodan queries: the ones stored in the Cortex (local and community `meta:rule`
nodes), and Shodan's query directory. See [model](model.md#saved-queries).

```text
slib.shodan.queries [--source all|local|shodan] [--search <text>] [--yield] [--tags]
                    [--page <n>] [--pages <n>] [--sort timestamp|votes] [--order asc|desc]
                    [--size <n>]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--source` | `all`, `local`, `shodan` | `all` | List the stored queries (`local`), Shodan's directory (`shodan`), or both. |
| `--search` | str | null | Only queries with this text. See below. |
| `--yield` | flag | false | Yield the `meta:rule` nodes, storing directory queries as community rules. |
| `--tags` | flag | false | List the directory's most popular tags (`GET /shodan/query/tags`) instead. |
| `--page` | int | `1` | The directory page to start at (10 queries a page). |
| `--pages` | int | `1` | The number of directory pages to list, one request each. Below 1 warns and uses 1. |
| `--sort` | `timestamp`, `votes` | `timestamp` | The directory's sort, for `GET /shodan/query`. |
| `--order` | `asc`, `desc` | `desc` | The directory's sort order. |
| `--size` | int | `10` | The number of tags to list with `--tags`. |

Stored queries print first, as a source / name / query table, with a `local` or `community`
source, then `Total saved queries: <n>` and a source / votes / title / query table for the
directory. A directory query already stored prints as `shodan (stored)`. `--page`, `--pages`,
`--sort` and `--order` with `--source local` only warn.

`--search` matches stored queries whose `:name`, `:text` or `:desc` contain the text,
ignoring case (not a regex). For the directory it calls `GET /shodan/query/search`. That
endpoint has returned HTTP 503 ("Query search unavailable at the moment") since at least
2026-11, so on any 5xx the service lists the same pages of `GET /shodan/query` (with the
default sort) and keeps the queries whose title, query, description or tags contain the text.
The command then warns that only the `<scanned>` queries on the pages listed (of the
directory's total) were searched. To search all of the directory (~7,000 queries, ~700 pages),
copy it once and search the copies:

```text
slib.shodan.queries --source shodan --pages 1000 --yield | count
slib.shodan.queries --source local --search webcam
```

With `--yield`, each directory query listed is stored as a community `meta:rule` (re-copying
keeps edits to `:name` and `:desc`), and every stored and copied rule is yielded once. Inbound
nodes are dropped.

```text
slib.shodan.queries
slib.shodan.queries --source shodan --search webcam --pages 20 --yield | slib.shodan.count
slib.shodan.queries --tags
```

(shodan-cmd-query-save)=
## slib.shodan.query.save

Save a query in the Cortex as a local `meta:rule` (`:type svc.shodan.query.local.`). Local
queries are never sent to Shodan: its API can't save queries to the directory.

```text
slib.shodan.query.save <query> --name <name> [--desc <desc>] [--yield]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `query` | str | required | The query, stripped. An empty query raises `BadArg`. |
| `--name` | str | required | A name for the query. |
| `--desc` | str | null | A description. |
| `--yield` | flag | false | Yield the `meta:rule`. |

A query whose text is already a local query (any local `meta:rule` with that `:text`) warns
`<query> is already a local saved query (<name>).` and keeps the existing node. The node is
linked to the `meta:source` like every other. The command prints
`slib.shodan.query.save: Saved <name> (<query>).` Inbound nodes are dropped.

```text
slib.shodan.query.save "ssl.jarm:2ad2ad0002ad2ad00042d42d00000069d641f34fe76acdc05c40262f8815e5" --name "CS JARM"
slib.shodan.query.save "http.favicon.hash:-1166125415" --name "Favicon" --yield | slib.shodan.count
```
