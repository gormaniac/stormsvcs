# Storm commands

Every command in the `slib.vt` package, from
{src}`svcs/virustotal/src/vtsvc/pkgproto/slib.vt.yaml` and
`pkgproto/storm/commands/*.storm`.

## Conventions

- **Errors never stop the pipeline.** Service calls return a `{status, mesg, data}` dict (see
  [API](api.md#telepathretn)). A failed call prints a warning, `slib.vt: <what> failed:
  <mesg>`, and the command moves on to the next node.
- **Inbound nodes.** Commands that take nodes map each one to a VirusTotal object
  (`slib.vt.util.target()`):

  | Form | VirusTotal object | Identifier |
  | --- | --- | --- |
  | `file:bytes` | file | `:sha256`, else `:sha1`, else `:md5` |
  | `hash:md5`, `hash:sha1`, `hash:sha256` | file | the hash |
  | `inet:fqdn` | domain | the FQDN |
  | `inet:ipv4`, `inet:ipv6` | IP address | the address |
  | `inet:url` | URL | the URL (sent as its unpadded URL safe base64) |

  A node of any other form, or a `file:bytes` without a hash, gets a warning like
  `slib.vt.enrich: Can't look up <node>, it has no hash.`
- **`--yield`**: without it, inbound nodes pass through unchanged. With it, the inbound
  nodes are dropped and the nodes the command found are yielded once every inbound node has
  been processed.
- **Requests and quota.** Every request counts against the key's quota and, with
  `vt:community` true, waits for a slot under the per minute limit. A 4 per minute key does
  about 240 requests an hour. Cacheable lookups answered from the response cache don't count.
  See [Rate limits and quotas](quota.md).
- **API key.** Each call uses the caller's own key (`slib.vt.apikey`) if they have one,
  otherwise the service-wide key. See [API keys](deployment.md#api-keys).

| Command | Permission | Requests | Cached |
| --- | --- | --- | --- |
| `slib.vt.enrich` | `slib.vt.user` | 1 per object, +1 per file with `--behaviour` | yes (unless `--no-cache`) |
| `slib.vt.related` | `slib.vt.user` | 1 per page of up to 40 objects | yes |
| `slib.vt.comments` | `slib.vt.user` | 1 per page of up to 40 comments | yes |
| `slib.vt.search` | `slib.vt.user` | 1 | yes |
| `slib.vt.analysis` | `slib.vt.user` | 1 per check | no |
| `slib.vt.quota` | `slib.vt.user` | 0, `--remote`: 1 | no |
| `slib.vt.apikey` | `slib.vt.user` | 0 | |
| `slib.vt.submit` | `slib.vt.submit` | 1 per submission (2 for files over 32MB), +1 per check with `--wait` | no |
| `slib.vt.rescan` | `slib.vt.submit` | 1 per node | no |
| `slib.vt.comment` | `slib.vt.submit` | 1 per node | no |
| `slib.vt.vote` | `slib.vt.submit` | 1 per node | no |
| `slib.vt.admin.apikey` | `slib.vt.admin` | 0 | |
| `slib.vt.admin.tags` | `slib.vt.admin` | 0 | |
| `slib.vt.admin.request` | `slib.vt.admin` | 1 (plus retries) | no |

Transient errors (VirusTotal `TransientError` / `DeadlineExceededError`, or HTTP 502, 503,
504) are retried up to twice, and each retry is another request.

## Lookup commands

### slib.vt.enrich

Look up files, URLs, domains, and IPs and model their reports.

```text
slib.vt.enrich [--hash <hash>]... [--fqdn <fqdn>]... [--ip <ip>]... [--url <url>]...
               [--engines {detected,all,none}] [--behaviour] [--no-cache] [--yield]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--hash` | str, repeatable | `[]` | An MD5, SHA1, or SHA256 to look up. |
| `--fqdn` | str, repeatable | `[]` | A domain to look up. |
| `--ip` | str, repeatable | `[]` | An IPv4 or IPv6 address to look up. |
| `--url` | str, repeatable | `[]` | A URL to look up. |
| `--engines` | `detected` \| `all` \| `none` | `detected` | Which per engine results to model as `it:av:scan:result` nodes. `detected` is engines whose verdict is suspicious or malicious. The overall result is always modeled. |
| `--behaviour` | flag | false | For files, also get and model the sandbox behaviour summary (`GET /files/{sha256}/behaviour_summary`, one more request, always cacheable). |
| `--no-cache` | flag | false | Ask VirusTotal even if the report is in the response cache. The fresh response replaces the cached one. |
| `--yield` | flag | false | Yield the looked up nodes (ex. the `file:bytes` of a `hash:md5`) instead of the inbound nodes. |

Inputs: `file:bytes`, `hash:md5`, `hash:sha1`, `hash:sha256`, `inet:fqdn`, `inet:ipv4`,
`inet:ipv6`, `inet:url`.

The option values are looked up first (in the order `--hash`, `--fqdn`, `--ip`, `--url`),
then each inbound node. Each lookup is `GET /files/{hash}`, `/domains/{fqdn}`,
`/ip_addresses/{ip}`, or `/urls/{base64 url}`, and prints one line:

```text
slib.vt.enrich: inet:fqdn=example.com - 0 malicious, 0 suspicious of 92 engines.
slib.vt.enrich: VirusTotal doesn't have file 0000...0000.
```

A 404 is not an error, it only prints. What gets modeled is on the [Data model](model.md)
page: the object's node and props, the overall and per engine scan results, the verdict and
other tags, and the object type's extras (DNS records, whois, certificates, YARA/IDS/Sigma
matches, sandbox verdicts, redirects, ...).

```text
// Enrich the hashes and IPs tagged #my.tag.
#my.tag | slib.vt.enrich

// A hash that isn't in the Cortex, yielding its file:bytes.
slib.vt.enrich --hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f --yield

// Every engine's result, and the sandbox behaviour.
file:bytes:sha256=24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c
    | slib.vt.enrich --engines all --behaviour
```

### slib.vt.related

Model the objects VirusTotal relates to the inbound nodes.

```text
slib.vt.related --rel <relationship> [--limit <n>] [--yield]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--rel` | str, required | | The relationship name. |
| `--limit` | int | `10` | The most related objects to get per node. Pages of up to 40 are fetched until the limit is reached or VirusTotal has no more. |
| `--yield` | flag | false | Yield the related nodes instead of the inbound nodes. |

Inputs: `file:bytes`, `hash:md5`, `hash:sha1`, `hash:sha256`, `inet:fqdn`, `inet:ipv4`,
`inet:ipv6`, `inet:url`.

With `vt:community` true, only these relationships are allowed; any other fails without a
request (`The <rel> relationship of <collection> isn't available to VirusTotal Public API
keys. Available: ...`). With `vt:community` false, any name is sent to VirusTotal.

| Object | Relationships |
| --- | --- |
| file | `comments`, `votes`, `graphs`, `collections`, `behaviours`, `bundled_files`, `contacted_domains`, `contacted_ips`, `contacted_urls`, `dropped_files`, `execution_parents`, `pe_resource_children`, `pe_resource_parents` |
| URL | `comments`, `votes`, `graphs`, `collections`, `related_comments`, `last_serving_ip_address`, `network_location` |
| domain | `comments`, `votes`, `graphs`, `collections`, `related_comments`, `resolutions`, `subdomains`, `siblings`, `parent`, `immediate_parent`, `communicating_files`, `referrer_files`, `historical_whois`, `historical_ssl_certificates` |
| IP | `comments`, `votes`, `graphs`, `collections`, `related_comments`, `resolutions`, `communicating_files`, `referrer_files`, `historical_whois`, `historical_ssl_certificates` |

Each page is `GET /{collection}/{id}/{rel}?limit=<n>&cursor=<cursor>`. A 404 ends the paging
quietly. It prints `slib.vt.related: <ident> <rel>: <got> of <VirusTotal's count>.`, then one
indented `<type> <id>` line for each object that isn't modeled (votes, graphs, collections,
behaviours, and other types).

The related objects are linked to the node's *subject*: the `file:bytes` of a `hash:sha256`
(created if needed), the one existing `file:bytes` with a `hash:md5`/`hash:sha1` (or the hash
node itself if there are none or several), otherwise the inbound node. How each related
object is modeled, and which edges link it, is in
[Relationships](model.md#relationships).

```text
inet:fqdn=example.com | slib.vt.related --rel resolutions --limit 40
inet:ipv4=1.2.3.4 | slib.vt.related --rel communicating_files --yield
file:bytes:sha256=24d004a1... | slib.vt.related --rel contacted_domains
```

### slib.vt.comments

Model the community's comments on the inbound nodes.

```text
slib.vt.comments [--limit <n>] [--yield]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--limit` | int | `10` | The most comments to get per node. |
| `--yield` | flag | false | Yield the `meta:note` nodes instead of the inbound nodes. |

Inputs: the same eight forms as `slib.vt.enrich`.

This is the `comments` relationship (`GET /{collection}/{id}/comments`, paged like
`slib.vt.related`, and cacheable). Each comment becomes a `meta:note` (`:type
virustotal.comment`) `-(about)>` the node's subject (see `slib.vt.related`). Prints
`slib.vt.comments: <ident>: <n> comments.`

```text
inet:fqdn=example.com | slib.vt.comments --limit 20
```

### slib.vt.search

The basic VirusTotal search (not VT Intelligence search). Takes no inbound nodes.

```text
slib.vt.search <query> [--limit <n>]
```

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `query` | str | | The query: a hash, URL, domain, IP, or comment text. |
| `--limit` | int | `10` | The most results, clamped to 1 to 40. |

Sends `GET /search?query=<query>&limit=<n>` (cacheable), models every file, URL, domain, and
IP result like `slib.vt.enrich` does (with `--engines detected`), prints
`slib.vt.search: <n> results for <query>.`, and yields the modeled nodes.

```text
slib.vt.search 8.8.8.8
```

### slib.vt.analysis

Check an analysis from `slib.vt.submit` or `slib.vt.rescan`, and model its results once it's
completed. Takes no inbound nodes.

```text
slib.vt.analysis <id> [--wait] [--timeout <secs>] [--interval <secs>]
                 [--engines {detected,all,none}] [--yield]
```

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `id` | str | | The analysis id. |
| `--wait` | flag | false | Poll until the analysis completes or `--timeout` passes. |
| `--timeout` | int | `600` | The most seconds to poll with `--wait`. |
| `--interval` | int | `30` | Seconds between polls with `--wait`. The service raises it to at least 15 with `vt:community` true (at least 1 otherwise). |
| `--engines` | `detected` \| `all` \| `none` | `detected` | Which per engine results to model. |
| `--yield` | flag | false | Yield the analyzed `file:bytes` or `inet:url` node. |

Each check is `GET /analyses/{id}`, never cached. With `--wait`, the service polls, sleeping
`interval` seconds between polls, and returns the last result once it's `completed` or the
next poll would be after the deadline. Every poll also waits for a rate limit slot.

If the analysis isn't completed it prints `slib.vt.analysis: Analysis <id> is <status>.`
(VirusTotal's statuses are ex. `queued`, `in-progress`). When it's completed, the analyzed
file (`file:bytes` with `:sha256`, `:md5`, `:sha1`, `:size`) or URL (`inet:url`) is modeled
with the analysis's scan results, and it prints `slib.vt.analysis: Analysis <id> of
<sha256 or url> completed: <m> malicious, <s> suspicious of <n> engines.` No tags are applied
from an analysis.

```text
slib.vt.analysis u-275a021b-1793698573
slib.vt.analysis u-275a021b-1793698573 --wait --timeout 600 --yield
```

### slib.vt.quota

Show the limits and how much of them your key has used.

```text
slib.vt.quota [--remote]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--remote` | flag | false | Also ask VirusTotal for the key's quotas (`GET /users/{key}/overall_quotas`, one request). |

Uses the same key resolution as every other command. Output:

```text
slib.vt: VirusTotal request limits are enforced (vt:community).
 period   | used     | limit
==========|==========|==========
 minute   | 2        | 4
----------|----------|----------
 day      | 2        | 500
----------|----------|----------
 month    | 2        | 15500
Next request can be sent in 0.0s. The daily count resets at 2026-11-20 00:00:00 UTC. 2 responses are cached.
VirusTotal's counts for the key:
 quota                    | used     | allowed
==========================|==========|==========
 api_requests_hourly      | 0        | 240
--------------------------|----------|----------
 api_requests_daily       | 0        | 500
--------------------------|----------|----------
 api_requests_monthly     | 0        | 15500
```

A limit of `0` is shown as `none`. The service's counts are taken before the `--remote`
request is sent. VirusTotal's counts include requests from other clients using the key. The
fields are explained in [Rate limits and quotas](quota.md#inspecting-usage).

### slib.vt.apikey

Set, show, or clear your own VirusTotal API key.

```text
slib.vt.apikey [<apikey>] [--clear]
```

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `apikey` | str, optional | | Your API key. Without it (and without `--clear`), shows whether you have one. |
| `--clear` | flag | false | Delete your key's vault. |

The key lives in a Synapse vault of type `virustotal` with scope `user`:

- Set, no vault yet: creates vault `virustotal:<username>` owned by you, with secrets
  `{"apikey": <key>}`. Prints `slib.vt: Saved your VirusTotal API key in vault
  virustotal:<username>.`
- Set, vault exists: replaces its `apikey` secret. Prints `slib.vt: Updated your VirusTotal
  API key.`
- Show: `slib.vt: Your VirusTotal API key is set in vault <name>.` or `slib.vt: You don't
  have a VirusTotal API key set.`
- `--clear`: deletes the vault. Prints `slib.vt: Deleted your VirusTotal API key.`

The key isn't checked against VirusTotal. Once set, all your `slib.vt` calls use it, with its
own rate limits, instead of the service-wide key.

## Submit commands

These send data to VirusTotal. Submitted files and URLs are shared with the VirusTotal
community, and comments and votes are public.

### slib.vt.submit

Submit files from the Axon and URLs for analysis.

```text
slib.vt.submit [--url <url>]... [--password <pw>] [--wait] [--timeout <secs>]
               [--interval <secs>] [--yield]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--url` | str, repeatable | `[]` | A URL to submit. |
| `--password` | str | | The password of a submitted ZIP file (sent as the `password` form field of file uploads). |
| `--wait` | flag | false | Wait for each analysis (like `slib.vt.analysis --wait`) and model its results. |
| `--timeout` | int | `600` | The most seconds to wait per analysis with `--wait`. |
| `--interval` | int | `30` | Seconds between checks with `--wait` (at least 15 with `vt:community` true). |
| `--yield` | flag | false | Yield the submitted nodes instead of the inbound nodes. |

Inputs: `file:bytes` (read from the Axon by `:sha256`) and `inet:url`. Other forms are
skipped without a warning.

- `--url` values are submitted first, then each inbound node.
- A URL is `POST /urls` with the form field `url`.
- A file needs `:sha256` (`... has no :sha256, so it can't be read from the Axon.`), the
  Axon must have it (`The Axon doesn't have <sha256>.`), and it needs `:size` (`The file's
  size is unknown.`). Files over 681574400 bytes (650MB) are refused. The file is read from
  the Axon in 1MiB chunks and sent to the service whole, as a multipart `POST /files` with
  field `file` (filename `:name`, or `sample`). Over 32MB (33554432 bytes) it first gets a
  one time upload URL (`GET /files/upload_url`) and posts to that instead.
- Prints `slib.vt.submit: Submitted <url or sha256>, analysis <id>.`
- With `--wait`, the analysis is polled and, once completed, modeled like
  `slib.vt.analysis` does with `--engines detected`.
- With `--yield`: for a `--url`, the analyzed node, or the `inet:url` of the URL when there
  was no completed analysis (that node is created even if the submission failed); for an
  inbound node, the node itself.

```text
file:bytes:sha256=... | slib.vt.submit --wait
slib.vt.submit --url https://example.com/login
```

### slib.vt.rescan

Ask VirusTotal to analyze objects it already has again. No options.

Inputs: the same eight forms as `slib.vt.enrich`. Each node is `POST
/{collection}/{id}/analyse`, and prints `slib.vt.rescan: Rescanning <ident>, analysis
<id>.` Check the result with `slib.vt.analysis <id>`.

```text
file:bytes:sha256=... | slib.vt.rescan
```

### slib.vt.comment

Add a comment to the inbound nodes in VirusTotal.

```text
slib.vt.comment <text>
```

| Argument | Type | Meaning |
| --- | --- | --- |
| `text` | str | The comment. Words that start with `#` become VirusTotal tags. Empty or whitespace only text fails (`A comment needs some text.`). |

Inputs: the same eight forms as `slib.vt.enrich`. Each node is `POST
/{collection}/{id}/comments` with `{"data": {"type": "comment", "attributes": {"text":
<text>}}}`, and prints `slib.vt.comment: Added comment <comment id> to <ident>.` Nothing is
modeled; run `slib.vt.comments` to model it.

```text
inet:fqdn=bad.example.com | slib.vt.comment "Phishing kit #phishing"
```

### slib.vt.vote

Vote the inbound nodes harmless or malicious.

```text
slib.vt.vote {harmless,malicious}
```

Inputs: the same eight forms as `slib.vt.enrich`. Each node is `POST
/{collection}/{id}/votes` with `{"data": {"type": "vote", "attributes": {"verdict":
<verdict>}}}`, and prints `slib.vt.vote: Voted <ident> <verdict>.` Voting twice on the same
object returns VirusTotal's error, ex. `Already voted (AlreadyExistsError, HTTP 409)`.

```text
inet:url=https://bad.example.com/ | slib.vt.vote malicious
```

## Admin commands

### slib.vt.admin.apikey

Set, check, or clear the service-wide API key (stored in the service's slab).

```text
slib.vt.admin.apikey [<apikey>] [--clear]
```

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `apikey` | str, optional | | The key to store. |
| `--clear` | flag | false | Remove the stored key. |

Prints `Set the slib.vt API key.` / `Cleared the slib.vt API key.`, or, without arguments,
`slib.vt: A service-wide API key is set.` / `slib.vt: No service-wide API key is set.`

:::{note}
The check reports the stored key *or* the `vt:apikey` config option, and `--clear` only
removes the stored key, so a configured `vt:apikey` is still used (and still reported as
set) after `--clear`.
:::

### slib.vt.admin.tags

Show or change the tags `slib.vt` applies.

```text
slib.vt.admin.tags [--prefix <tag>] [--enable | --disable]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--prefix` | str | | The tag prefix. Normalized with `$lib.cast(syn:tag, ...)`; an invalid tag prints `slib.vt.admin.tags: Invalid tag prefix: <error>` and the prefix is unchanged. |
| `--enable` | flag | false | Enable tagging. |
| `--disable` | flag | false | Disable tagging. Both together is a warning and changes nothing. |

Always ends by printing the settings: `slib.vt.admin.tags: enabled=true prefix=rep.vt`. The
settings are the Cortex globals `slib:vt:tag:enabled` and `slib:vt:tag:prefix`, read when a
command imports `slib.vt.lib` (or by `slib.vt.search`). Existing tags are not renamed or
removed when the prefix changes or tagging is disabled.

```text
slib.vt.admin.tags
slib.vt.admin.tags --prefix rep.virustotal
slib.vt.admin.tags --disable
```

### slib.vt.admin.request

Send a raw request to the API and print the JSON response. An escape hatch for endpoints the
service has no method for.

```text
slib.vt.admin.request <path> [--method <method>] [--param name=value]... [--json <json>]
```

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `path` | str | | The API path, relative to `vt:url`, ex. `/files/<sha256>`. |
| `--method` | str | `get` | The HTTP method. |
| `--param` | str, repeatable | `[]` | A `name=value` query param, split on the first `=`. A value without `=` is a warning, and nothing is sent. |
| `--json` | str | | A JSON request body. Invalid JSON is a warning, and nothing is sent. |

The request is rate limited and counted like every other, never cached, and uses the caller's
own key if they have one. The response is printed with `$lib.json.save(..., indent=(true))`.

```text
slib.vt.admin.request /popular_threat_categories
slib.vt.admin.request /files/<sha256>/votes --param limit=5
slib.vt.admin.request /search --param query=8.8.8.8 --param limit=1
```
