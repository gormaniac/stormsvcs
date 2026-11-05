# slib.vt

A Storm Service for the [VirusTotal](https://www.virustotal.com) **Public (community) API v3**. It enriches files, URLs, domains, and IPs, pivots on their relationships, and submits, rescans, comments, and votes. It always stays within the Public API's rate limits.

It's built for free VirusTotal Community API keys. Premium keys work too, see [Premium keys](#premium-keys).

## Rate limits

The Public API allows **4 requests per minute and 500 per day** (the day resets at 00:00 UTC), plus a monthly quota (15.5K for a community key). VirusTotal rejects requests over them, and its terms forbid working around them. So while `vt:community` is true (the default), every request the service sends first reserves a slot, per API key:

- **Per minute**: requests are queued (first in, first out) and spaced so there are never more than `vt:limit:minute` (4) in any 61 second window. The extra second is slack for clock differences with VirusTotal. A request that would wait longer than `vt:limit:maxwait` seconds (600) fails instead.
- **Per day / month**: once `vt:limit:day` (500) or `vt:limit:month` (15500) requests have been sent, requests fail right away until the next UTC day or month, instead of waiting for hours.
- If VirusTotal still answers HTTP 429 (ex. another client uses the same key), the request isn't retried. The key is paused for a minute.

Every request counts, including errors, retries, and each page of a relationship. The counts are kept in the service's storage, so a restart doesn't reset them. They're keyed by a hash of the API key, so keys aren't stored there. Users with their own key (`slib.vt.apikey`) get their own limits. Everyone else shares the service-wide key's limits.

Successful lookups are cached for `vt:cache:ttl` seconds (an hour), so enriching the same node twice only uses quota once. `--no-cache` skips the cache.

`slib.vt.quota` shows the limits, how much of them the key has used, and when the next request can be sent. `--remote` also shows VirusTotal's own counts, which include other clients using the key.

With a Public API key, enriching 100 nodes takes about 25 minutes. Use small, targeted batches.

## Commands

| Command | Perm | What it does | Requests |
| --- | --- | --- | --- |
| `slib.vt.enrich` | `slib.vt.user` | Look up `file:bytes`, `hash:md5/sha1/sha256`, `inet:fqdn`, `inet:ipv4/6`, and `inet:url` nodes (or `--hash/--fqdn/--ip/--url` values) and model their reports. `--behaviour` adds the sandbox behaviour summary for files. | 1 per node (+1 with `--behaviour`) |
| `slib.vt.related` | `slib.vt.user` | Model a relationship of the inbound nodes (`--rel resolutions`, `communicating_files`, ...). | 1 per 40 objects |
| `slib.vt.comments` | `slib.vt.user` | Model community comments as `meta:note -(about)>` the node. | 1 per 40 comments |
| `slib.vt.search` | `slib.vt.user` | The basic search (hash, URL, domain, IP), yields the matching nodes. | 1 |
| `slib.vt.analysis` | `slib.vt.user` | Check an analysis (`--wait` to poll), and model its results when it's done. | 1 per check |
| `slib.vt.quota` | `slib.vt.user` | Show the limits and the key's usage. | 0 (`--remote`: 1) |
| `slib.vt.apikey` | `slib.vt.user` | Set, show, or clear your own key (a user scoped `virustotal` vault). | 0 |
| `slib.vt.submit` | `slib.vt.submit` | Submit `file:bytes` (from the Axon) and URLs. **Submissions are shared with the VirusTotal community.** | 1 (2 over 32MB) + checks |
| `slib.vt.rescan` | `slib.vt.submit` | Ask VirusTotal to reanalyze files, URLs, domains, or IPs. | 1 per node |
| `slib.vt.comment` | `slib.vt.submit` | Add a comment (`#words` are tags). | 1 per node |
| `slib.vt.vote` | `slib.vt.submit` | Vote `harmless` or `malicious`. | 1 per node |
| `slib.vt.admin.apikey` | `slib.vt.admin` | Set, check, or clear the service-wide key. | 0 |
| `slib.vt.admin.tags` | `slib.vt.admin` | Change the tag prefix (`rep.vt`), or turn tagging off. | 0 |
| `slib.vt.admin.request` | `slib.vt.admin` | Send a raw API request (still rate limited). | 1 |

The commands that talk to the service run their service calls in `asroot` modules gated by these perms. Users don't need `service.get`, and the service-wide key is never readable from Storm. Node edits run as the calling user.

## API coverage

| Endpoint | Used by |
| --- | --- |
| `GET /files/{hash}`, `/urls/{id}`, `/domains/{domain}`, `/ip_addresses/{ip}` | `slib.vt.enrich` (URLs are identified by their unpadded URL safe base64) |
| `GET /{collection}/{id}/{relationship}` | `slib.vt.related`, `slib.vt.comments` |
| `GET /files/{id}/behaviour_summary` | `slib.vt.enrich --behaviour` |
| `GET /search?query=` | `slib.vt.search` |
| `GET /analyses/{id}` | `slib.vt.analysis`, `slib.vt.submit --wait` |
| `POST /files`, `GET /files/upload_url` (over 32MB, up to 650MB), `POST /urls` | `slib.vt.submit` |
| `POST /{collection}/{id}/analyse` | `slib.vt.rescan` |
| `POST /{collection}/{id}/comments`, `POST /{collection}/{id}/votes` | `slib.vt.comment`, `slib.vt.vote` |
| `GET /users/{key}/overall_quotas` | `slib.vt.quota --remote` |
| Anything else | `slib.vt.admin.request` |

These relationships are allowed with a Public API key. They're the ones VirusTotal's docs mark as available to "Everyone". Others (ex. a URL's `downloaded_files`, a domain's `urls`, a file's `itw_urls`) need VT Enterprise, so the service refuses them without sending a request.

| Object | Relationships |
| --- | --- |
| File | `contacted_domains`, `contacted_ips`, `contacted_urls`, `dropped_files`, `bundled_files`, `execution_parents`, `pe_resource_children`, `pe_resource_parents`, `behaviours`, `comments`, `votes`, `graphs`, `collections` |
| Domain | `resolutions`, `subdomains`, `siblings`, `parent`, `immediate_parent`, `communicating_files`, `referrer_files`, `historical_whois`, `historical_ssl_certificates`, `comments`, `related_comments`, `votes`, `graphs`, `collections` |
| IP | `resolutions`, `communicating_files`, `referrer_files`, `historical_whois`, `historical_ssl_certificates`, `comments`, `related_comments`, `votes`, `graphs`, `collections` |
| URL | `last_serving_ip_address`, `network_location`, `comments`, `related_comments`, `votes`, `graphs`, `collections` |

Out of scope: VT Intelligence search, downloads, Livehunt/Retrohunt, Graph, private scanning, feeds, and the other premium-only APIs.

## Data model

Every node the service creates is linked `meta:source (virustotal) -(seen)> node`.

| VirusTotal | Synapse |
| --- | --- |
| File | `file:bytes` (`sha256:<sha256>`): `:sha256`, `:sha1`, `:md5`, `:size`, `:name` (the meaningful name), `:ssdeeps`, `:mime:pe:imphash`, `:mime:pe:compiled`, and `.seen` from the first and last submission dates |
| Latest multi-engine scan | `it:av:scan:result` (`:scanner:name=virustotal`, `:target:*`, `:time`, `:verdict`, `:multi:count*`, and for files `:signame` (the suggested threat label) and `:categories`) |
| Each engine's result | `it:av:scan:result` with `:multi:scan` set to the scan. By default only engines that detected something (`--engines detected`), or `all`, or `none` |
| Sandbox verdicts | `it:av:scan:result` (`:scanner:name=<sandbox>`, `:signame`, `:categories`) |
| Crowdsourced YARA | `it:app:yara:rule` (`:author` as a `ps:contact`) and `it:app:yara:match` |
| Crowdsourced IDS / Sigma | `it:app:snort:rule` / `it:app:sigma:rule -(matches)> file:bytes` |
| Domain | `inet:fqdn`, `inet:dns:a/aaaa/cname/mx/ns/txt/soa` (`.seen` = the records' date), `inet:whois:rec`, `crypto:x509:cert` (the last HTTPS cert, with `:identities:fqdns` from its SANs) |
| IP | `inet:ipv4/6` (`:asn`, `:loc`), `inet:asn:name`, `inet:whois:iprec` (`:net4/6`), `inet:tls:servercert` and `inet:ssl:jarmsample` for `tcp://<ip>:443` |
| URL | `inet:url`, `inet:urlredir` for each redirect, and `inet:urlfile` for the final response's content |
| Behaviour summary | `file:bytes -(refs)>` the `inet:fqdn`s it looked up (with `inet:dns:a/aaaa` for their answers), the `inet:server`s it contacted, the `inet:url`s it requested, its `it:dev:mutex`es, and its dropped `file:bytes`. `-(uses)> it:mitre:attack:technique` for the ATT&CK techniques |
| Related objects | Modeled like the objects above, and linked with `-(refs)>`: `file -(refs)>` its contacted domains, IPs, URLs, dropped and bundled files, and PE resource children. Communicating and referrer files and execution parents `-(refs)>` the node. Resolutions are `inet:dns:a/aaaa`, historical whois are `inet:whois:rec/iprec`, and historical certs are `crypto:x509:cert` (and `inet:tls:servercert` for IPs) |
| Comment | `meta:note` (`:type=virustotal.comment`, `:created`) `-(about)>` the node |

Related objects and comments of a `hash:sha256` are linked to its `file:bytes`, and those of a `hash:md5/sha1` to the one `file:bytes` with that hash (or the hash node if the Cortex doesn't have one).

**Tags** go under the prefix (`rep.vt`, see `slib.vt.admin.tags`):

| Tag | From |
| --- | --- |
| `<prefix>.verdict.malicious/suspicious/benign` | The latest scan: malicious with at least `vt:verdict:malicious` (3) malicious engines, suspicious with any detection, benign when engines ran and none detected it. Replaced on every enrichment. |
| `<prefix>.tag.<tag>` | VirusTotal's tags, ex. `rep.vt.tag.peexe` |
| `<prefix>.family.<name>` | A file's top popular threat name, or a URL's threat names |
| `<prefix>.category.<category>` | A file's popular threat categories |
| `<prefix>.behaviour.<verdict or tag>` | The behaviour summary's verdicts and tags |

Tag parts are lowercased, with runs of other characters replaced by `_` (`Mal/HTMLGen-A` -> `mal_htmlgen_a`).

**Not modeled**: reputation, vote counts, vendor categories, popularity ranks, TLSH, vhash, authentihash, TrID, signature info, PE sections and imports, behaviour command lines, registry keys, and memory patterns. Lists are capped (50 names, 100 rules and detections, 50 of each behaviour), so one object never creates thousands of nodes.

## Configuration

| Option | Default | |
| --- | --- | --- |
| `vt:apikey` | none | A fallback key, after a user's own key and the key set with `slib.vt.admin.apikey`. |
| `vt:community` | `true` | Enforce the Public API's limits and relationships. |
| `vt:limit:minute` / `vt:limit:day` / `vt:limit:month` | `4` / `500` / `15500` | The limits, per key. `0` disables one. |
| `vt:limit:maxwait` | `600` | The most seconds a request waits for room under the per minute limit. `0` waits as long as it takes. |
| `vt:cache:ttl` / `vt:cache:size` | `3600` / `1000` | The response cache. `0` disables it. |
| `vt:verdict:malicious` | `3` | Malicious engine detections needed for a malicious verdict. |
| `vt:timeout` | `120` | Seconds per request. |
| `vt:url` | `https://www.virustotal.com/api/v3` | The API's base URL. |

### Premium keys

Set `vt:community` to `false`. The limits aren't enforced (requests are still counted), every relationship is allowed, and `slib.vt.analysis --wait` can poll faster than every 15 seconds. Premium-only fields VirusTotal returns, but the service doesn't know about, aren't modeled.

## Deploying

The service is published as `ghcr.io/gormaniac/stormsvcs/virustotal`.

```bash
docker run -d --name slib-vt \
    -v /srv/slib-vt:/vertex/storage \
    -e SYN_VTSVC_VT_APIKEY=<optional service-wide API key> \
    -p 27492:27492 \
    ghcr.io/gormaniac/stormsvcs/virustotal:latest
```

Every option above can be set with its env var: `SYN_VTSVC_` and the option's name in upper case, with `:` as `_` (ex. `SYN_VTSVC_VT_COMMUNITY=false`).

Then add it to a Cortex:

```
service.add slib.vt tcp://<user>:<passwd>@<host>:27492/*
slib.vt.admin.apikey <your VirusTotal API key>
slib.vt.enrich --fqdn example.com
```

## Testing

```
uv run pytest
```

The tests use a fake VirusTotal server built from real (trimmed) Public API responses in `tests/data`. `tests/test_live.py` runs against the real API through the service, so it stays within the limits (about 12 requests, 3 minutes):

```
SLIB_VT_LIVE=1 VT_API_KEY=<key> uv run pytest tests/test_live.py -s
```
