# Shodan REST API research (for the shodansvc rework)

Researched 2026-11-02. No API key was used and no keyed calls were made. Every claim has an inline
citation. Labels used throughout:

- **[doc]**: stated by an official Shodan source (developer.shodan.io, help.shodan.io, book.shodan.io, datapedia.shodan.io).
- **[client]**: shown by the official Python client source (`achillean/shodan-python`, pinned commit
  [`87a0688`](https://github.com/achillean/shodan-python/tree/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8), v1.31.0).
- **[inferred]**: my own reasoning from the sources. Not stated by Shodan.
- **[3rd-party]**: from a non-Shodan source. Weak evidence.

Short URL keys used below:

| Key | URL |
|---|---|
| DEV | https://developer.shodan.io/api |
| OAS | https://developer.shodan.io/api/openapi.json |
| STREAM | https://developer.shodan.io/api/stream |
| TRENDSDOC | https://developer.shodan.io/api/trends |
| DP | https://datapedia.shodan.io/property/_shodan.html |
| SCHEMA | https://datapedia.shodan.io/banner.schema.json (v25, per https://datapedia.shodan.io/changelog.html "Version 25 — 2026-10-23") |
| TIMEFRAMES | https://book.shodan.io/behind-the-scenes/data-timeframes/ (same text at https://help.shodan.io/mastery/data_timeline) |
| CRAWLER | https://book.shodan.io/behind-the-scenes/crawler-algorithm/ |
| IPINFO | https://book.shodan.io/websites/www/ip-information/ |
| BOOKAPI | https://book.shodan.io/developer-apis/shodan-api/ |
| SCANHELP | https://help.shodan.io/the-basics/on-demand-scanning |
| CREDITS | https://help.shodan.io/the-basics/credit-types-explained |
| STATSHELP | https://help.shodan.io/command-line-interface/3-stats |
| LOOKUP | https://help.shodan.io/developer-fundamentals/looking-up-ip-info |
| RN2025 | https://book.shodan.io/release-notes/2025/ |
| PY | https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8 |

### What the service already does (for context)

From reading `svcs/shodan/src/shodansvc/{svc.py,norm.py,client.py}`:

- `host(ip, history, minify)` calls `GET /shodan/host/{ip}` with a single IP path segment.
- `normBanner` keeps `_shodan.id`, `_shodan.module` and `_shodan.crawler`. It drops `_shodan.ptr`,
  `_shodan.options.*` (`scan`, `referrer`, `hostname`, `region`), `hash`, `cpe23_hash`, and
  `metadata.truncated`.
- `normHost` merges every entry in `data` into `banners`, and takes `ports`, `tags`, `hostnames`,
  `vulns` and `last_update` from the host level.
- `count()` and `search()` pass `facets` through without changing them. `searchGenr` pages 100 at a
  time. Search does not pass `fields`.
- `stream()` supports `banners`, `asn`, `countries`, `ports`, `tags`, `vulns`, `custom` and `alert`.
- The client rate-limits `api` and `trends` to 1 request per second and retries HTTP 429 up to 3 times.

---

## 1. Host history: `GET /shodan/host/{ip}?history=true`

### 1.1 Parameters (documented)

- `history` (optional, boolean): "True if all historical banners should be returned. Removed large
  fields are listed in metadata.truncated of each banner (default: False)" [doc, DEV].
- `minify` (optional, boolean): "True to only return the list of ports and the general host
  information, no banners. (default: False)" [doc, DEV].
- The OpenAPI spec lists exactly `key`, `history`, `minify` and `ip` [doc, OAS].
- The client only sends `history`/`minify` when they are truthy. It also accepts a list of IPs and
  joins them with commas into the path (`'/shodan/host/{}'.format(','.join(ips))`)
  [client, [PY/shodan/client.py#L423-L441](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/client.py#L423-L441)].
  Bulk lookups take up to 100 IPs per request on the Corporate plan and return a *list* of host
  objects [doc, LOOKUP "Bulk Lookups"].

### 1.2 What comes back

- **Each historical banner is its own entry in `data`.** With `history=True`, "the top-level data
  property now contains a list of all the banners that were ever seen for that IP" [doc, LOOKUP
  "Historic Data"]. That sentence predates the 90-day change (see 1.3). The current docs say the
  historical lookup returns individual banners, capped at 1,000 [doc, TIMEFRAMES]. The official CLI
  prints one row per `data` entry with `banner['timestamp'][:10]` when `--history` is set, so it
  expects one entry per observation [client, [PY/shodan/cli/host.py#L86-L92](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/cli/host.py#L86-L92)].
- The same IP:port appears many times (once per crawl in the window). Without `history`, you get "the
  most recent banner for an IP and port that was collected the past 30 days" [doc, TIMEFRAMES].

### 1.3 How far back, and the cap

- "The historical IP lookups feature of the API provides data going back up to 90 days. Note that it
  returns at most 1,000 banners so if the IP has been frequently rescanned during the 90 days then the
  API will only return the most recent 1,000 banners." [doc, TIMEFRAMES]
- The older "full history back to 2009" behavior was removed: "we had to change the way that feature
  worked and decided to offer a 90 day timeframe instead, combined with Shodan Trends for long-term
  views" [doc, TIMEFRAMES]. Shodan's 2025 release notes add: "Clarified that the history API does not
  include the full IP history" [doc, RN2025 "Help Center"].
- The Book's API page also says history "includes banners that are up to 90 days old" [doc, BOOKAPI "IP Lookup"].
- **No pagination.** The OpenAPI spec has no `page`/`offset` parameter for this endpoint [doc, OAS].
  The cap is a hard 1,000 most-recent banners [doc, TIMEFRAMES].
- Large fields are removed from historical banners. They are listed in `metadata.truncated` [doc, DEV].
  The 2026-11-02 changelog says: "Historical banners from /shodan/host/{ip}?history=true do the same
  when large fields are removed" [doc, https://book.shodan.io/changelog/2026-11-02/]. The example
  given is `"metadata": {"truncated": ["smb.raw"]}`.

### 1.4 Plan and credit requirements

- IP lookups through the main REST API need "at least a Shodan Membership (one-time payment of $49 for
  lifetime account upgrade)" [doc, LOOKUP "Requirements"].
- "IP lookups don't consume query credits." [doc, BOOKAPI "Usage Limits"]. The developer docs give no
  credit cost for this endpoint [doc, DEV].
- No source says `history=true` needs a higher plan than a normal lookup. See Could-not-verify.

### 1.5 `_shodan` fields (from datapedia and the Book)

From [doc, DP] and the `_Shodan` / `_ShodanOptions` definitions in [doc, SCHEMA]: "The _shodan property
contains information about how the banner was generated. It doesn't store any data about the
port/ service itself."

| Field | Type | Required | Description (verbatim) |
|---|---|---|---|
| `_shodan.crawler` | string | yes | "Unique ID of the crawler" |
| `_shodan.id` | string | yes (schema) | "Unique ID of the banner; used in the "_shodan.options.referrer" to indicate when the current banner was generated as a result of another banner" |
| `_shodan.module` | string | yes | "The initial protocol that the crawler used when talking to the service" |
| `_shodan.options` | `_ShodanOptions` | yes | (object) |
| `_shodan.ptr` | boolean | no | "Whether or not the crawler has a PTR entry" |
| `_shodan.options.hostname` | string | no | "Hostname that was used to talk to the service (ex. for HTTP it would set the "Host:" header to this hostname)" |
| `_shodan.options.referrer` | string | no | "Banner ID that triggered the creation of the current banner" |
| `_shodan.options.scan` | string | no | "Unique scan ID that identifies the request that launched the scan" |
| `_shodan.options.region` | (not in schema) | no | Shows up only in datapedia's example: `"options": {"hostname": "testserver.com", "referrer": "2581ab0d-...", "region": "na"}` [doc, DP "Example"] |
| `_shodan.region` | (not in schema) | — | The Book says "The _shodan.region property lets you know the region of the crawler that created the banner" [doc, CRAWLER "Globally Distributed"]. The schema doesn't define it, and the datapedia example puts `region` under `options`. **Read both locations.** |

Other things to know about these fields:

- `crawler` is a 40-hex-character string in every example (e.g. `"ac284849be0745621b3c518f74c14cf43cafbf08"`)
  [doc, DEV]. It identifies the crawler *machine*, not a single run [inferred from the description
  "Unique ID of the crawler"].
- `module` examples include `"dns-udp"` and `"auto"` [doc, DEV], and `"sip"` [doc, STREAM]. You can
  search on it with `shodan.module:smtp` [doc, DP "Search Queries"].
- A 2025 note mentions a new `_shodan.alert` property in Monitor webhooks
  [doc, RN2025: "Updated webhook docs to include the new _shodan.alert property"]. It isn't in the schema.

### 1.6 Is `_shodan.id` a UUID? Is it unique and stable enough to use as an idempotency key?

- **Format:** Every current example is a UUIDv4-looking string, e.g. `"cea5795b-55fd-4595-b9e5-ad5ca847cb4b"`
  [doc, DEV host example], `"534cc127-e734-44bc-be88-2e219a56a099"` [doc, DEV search example],
  `"220ef463-756f-4446-a89f-685053da8865"` [doc, STREAM]. The schema only says `string`. It does not
  promise a UUID format [doc, SCHEMA].
- **Uniqueness:** Documented as "Unique ID of the banner" [doc, DP]. Each crawl produces its own banner
  and its own ID [inferred: the referrer mechanism needs per-banner IDs, CRAWLER].
- **It is not guaranteed to be present.** The Book says: "_shodan.id: A unique ID for the banner.
  This property is guaranteed to exist if a cascading request could get launched from the service,
  though it doesn't necessarily mean that any cascading requests succeeded." [doc, CRAWLER]. That
  wording implies it may be missing on other banners. The datapedia schema marks it required
  [doc, SCHEMA], but an older official example shows `"_shodan": {..., "id": null}` (2018 data)
  [doc, LOOKUP]. **The service needs a fallback key.** One option is
  `(ip, port, transport, timestamp, hash)` [inferred].
- **Stability across repeated API calls:** not documented. The ID describes a stored banner, so the
  same stored banner should come back with the same ID [inferred]. Not verified.

### 1.7 Are host-level fields current-only when `history=true`?

Not documented. The docs only describe `data` changing ("the resulting info object will have the
same structure as before but the top-level data property now contains a list of all the banners")
[doc, LOOKUP]. Two clues suggest the host-level fields are *not* rebuilt from history:

- The CLI pads `host['data']` with placeholder banners when `len(host['ports']) != len(host['data'])`,
  so `ports` and `data` are not always in sync [client,
  [PY/shodan/cli/host.py#L53-L71](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/cli/host.py#L53-L71)].
- `last_update` equals the newest banner `timestamp` in the docs example
  (`"2021-01-22T08:49:35.190817"` in both places) [doc, DEV].

So `ports`, `vulns`, `tags`, `hostnames` and `last_update` *probably* describe the current (30-day)
view [inferred]. **This is unverified. Check it with one live call.** Until then, build
history-derived facts from the banners in `data`, not from the host-level fields.

---

## 2. Is there a "scan" ID that groups banners from one crawl?

### 2.1 On-demand scans: yes, through `_shodan.options.scan` and the `scan:` filter

- The banner schema defines `_shodan.options.scan`: "Unique scan ID that identifies the request that
  launched the scan" [doc, DP / SCHEMA].
- Shodan's guide says to fetch scan results with a search filter: "The easiest way to get the results
  of the scan is by using the scan search filter ... `scan:R2XRT5HH6X67PFAB`". It shows
  `shodan download --limit -1 scan-results.json.gz scan:R2XRT5HH6X67PFAB` and
  `api.search_cursor('scan:{}'.format(scan['id']))` [doc, SCANHELP "Bulk Download"].
  - `scan:` is a filter, so each search page costs query credits (see §6). `GET /shodan/host/count`
    with `query=scan:<id>` and facets is free [inferred from §3 rules].
- **Internet-wide and routine crawls have no scan grouping.** The routine crawler picks a random IPv4
  address and a random port, grabs one banner, and repeats [doc, CRAWLER "Randomized"]. A banner is
  one IP:port probe. No ID groups the ports of a host from one pass. Grouping is possible only through
  `options.scan` (on-demand scans) and `options.referrer` (cascades) [doc, CRAWLER, DP]. Treating
  "same crawler + close timestamps" as one crawl would be a guess [inferred].
- The official CLI does **not** match results by scan ID. `shodan scan submit` creates a temporary
  network alert (`api.create_alert('Scan: ...', netblocks)`), reads `api.stream.alert(aid=...)`,
  removes duplicates by `'{ip}:{port}'`, polls `scan_status` until `DONE`, and then deletes the alert
  [client, [PY/shodan/cli/scan.py#L163-L209](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/cli/scan.py#L163-L209),
  [#L328-L330](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/cli/scan.py#L328-L330)].
  It also notes that a recently crawled host "cant get scanned again so soon".

### 2.2 `POST /shodan/scan`

- Parameters: `ips` ("A comma-separated list of IPs or netblocks (in CIDR notation)") and `service`
  (a list of `[port, protocol]`). You can also pass a JSON form, `{"ips": {"1.1.1.1": [[53,"dns-udp"],[443,"https"]]}}`
  [doc, DEV]. Hostnames are accepted too: `api.scan('google.com')` [doc, SCANHELP].
- `force`: sent by the client ("Only available to enterprise users")
  [client, [PY/shodan/client.py#L463-L495](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/client.py#L463-L495)].
  It is not in the REST docs. Without Enterprise, a recently crawled IP "won't be able to scan it again
  within the next 24 hours" [doc, SCANHELP].
- Response: `{"count": 2, "id": "vwWO7P5N1rWF5jbh", "credits_left": 100000}` [doc, DEV].
  The `id` is a 16-character alphanumeric string, not a UUID [doc, DEV examples].
- Cost: "1 IP consumes 1 scan credit. You must have a paid API plan" [doc, DEV]. The client sends
  this as a form POST [client, client.py#L493].

### 2.3 `GET /shodan/scans`

- "Returns a listing of all the on-demand scans that are currently active on the account." [doc, DEV]
- Response: `{"matches": [{"status", "created", "status_check", "credits_left", "api_key", "id", "size"}], "total": 19}`
  [doc, DEV]. Example: `"status": "PROCESSING", "created": "2021-01-26T08:17:43.794000", "status_check": "2021-01-26T08:17:43.900000", "credits_left": 100000, "api_key": "toH56...", "id": "Mo8W7itcWumiy9Ay", "size": 1`.
  - **`api_key` is the caller's API key.** Never store or log it [inferred].
- `page`: the client says "Page through the list of scans 100 results at a time"
  [client, [PY/shodan/client.py#L497-L505](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/client.py#L497-L505)].
  The OpenAPI spec lists no `page` parameter [doc, OAS].

### 2.4 `GET /shodan/scan/{id}`

- Response: `{"count": 1, "status": "DONE", "id": "Mo8W7itcWumiy9Ay", "created": "2021-01-26T08:17:43.794000"}`.
  Status values: `SUBMITTING`, `QUEUE`, `PROCESSING`, `DONE` [doc, DEV].
- **The path is inconsistent:** the HTML docs and the client use `/shodan/scan/{id}` [doc, DEV; client
  [client.py#L524-L532](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/client.py#L524-L532)],
  but the OpenAPI spec says `/shodan/scans/{id}` [doc, OAS]. The service already uses `/shodan/scan/{id}`, which is right.
- Neither response lists the banners. You get them through `scan:<id>`, a host lookup, or a stream
  [doc, SCANHELP; BOOKAPI "Scanning"].

### 2.5 How the website's host history view groups things

- The IP page has three tabs: Regular view, Raw Data, Timeline. "The Timeline view shows the most
  recent 1,000 banners that have been collected within the past 90 days sorted by timestamp."
  [doc, IPINFO]. It is a flat list sorted by time, not grouped by scan or crawl.
- It was "Restored ... now renamed to 'Timeline' to better reflect that it shows recently collected
  data rather than complete historical records" [doc, RN2025].
- www.shodan.io and beta.shodan.io pages returned a Cloudflare 403 to my fetches, so I couldn't look
  at the page itself.

---

## 3. `GET /shodan/host/count`

- Parameters: `query` (required; same syntax as search) and `facets` (optional) [doc, DEV; OAS lists `key, query, facets`].
- `facets` syntax: "A comma-separated list of properties to get summary information on. Property
  names can also be in the format of "property:count", where "count" is the number of facets that
  will be returned for a property (i.e. "country:100" to get the top 100 countries for a search
  query)." [doc, DEV]. The client builds `name` or `name:N` joined by commas
  [client, [PY/shodan/helpers.py#L13-L24](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/helpers.py#L13-L24)].
- Response:

  ```json
  {"matches": [], "facets": {"org": [{"count": 3012386, "value": "Amazon.com"}, ...],
                             "os":  [{"count": 601923,  "value": "Ubuntu"}, ...]},
   "total": 19590274}
  ```
  [doc, DEV]. `matches` is present and empty [doc, DEV]. The client docstring says the response has
  "1 main property: total. If facets have been provided then another property called "facets""
  [client, [client.py#L406-L421](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/client.py#L406-L421)].
- **Free:** "this method does not return any host results ... As a result this method does not consume
  query credits." [doc, DEV]. This applies even when the query uses filters [inferred from "does not
  consume"; CREDITS ties credits to downloading results]. It still needs an API key.
- **Default facet size:** 5. "this is how we let Shodan know to return 3 instead of the default 5 for
  a facet. If you want to see more than 5, you could do ('country', 1000)"
  [client docs, [PY/docs/examples/query-summary.rst#L35-L38](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/docs/examples/query-summary.rst#L35-L38)].
  The CLI `shodan stats` defaults to `--facets country,org` and `--limit 10`
  [client, [PY/shodan/__main__.py#L542-L560](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/__main__.py#L542-L560)].
  The help page instead says it facets "on a few popular properties such as org and port" by default
  and returns "the top 10 values of a facet" [doc, STATSHELP]. The help page is out of date.
- **Maximum facet size:**
  - "Facet result sizes are now limited based on the user's subscription level" [doc, RN2025 "Shodan API → Changed"].
  - "increased the number of facet values that may be returned from 65,336 to 131,072" and "error
    message now indicates when a limit in the number of facets is reached instead of returning a
    timeout error" [doc, https://book.shodan.io/changelog/2025-11-06/]. It doesn't say whether
    131,072 is per facet or per request, or which plan gets it.
  - Monitor had requested facet sizes "too high" and was patched "to use a limit based on the
    current subscription level" [doc, https://book.shodan.io/changelog/2025-11-07/].
  - The per-plan numbers are not published. See Could-not-verify.
- **Maximum number of facets per request:** not documented.
- **Rate limit:** 1 request per second for the REST API. "only returns 429 status codes for requests
  that are above the 1 request/ second rate limit" (since 2025-11-10; before that, going over the
  limit blocked later requests too) [doc, https://book.shodan.io/changelog/2025-11-10/]. The client
  enforces 1 request per second itself [client,
  [client.py#L316](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/client.py#L316),
  [#L347-L350](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/client.py#L347-L350);
  [CHANGELOG 1.27.0](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/CHANGELOG.md)].
- **Time window:** count, search and host lookup all use a 30-day window [doc, TIMEFRAMES]. A count
  `total` is the number of *banners* (services), not distinct IPs [inferred: the index holds banners,
  per https://help.shodan.io/the-basics/search-query-fundamentals "The Banner ... is the fundamental
  unit of data ... what you'll be searching for"].
- Restricted filters are allowed in facet analysis on the website: "Search filters aren't restricted
  for facet analysis! Everybody can use the vuln and tag filters on the Facet Analysis page."
  [doc, https://book.shodan.io/websites/www/facet-analysis/]. This only covers the *website*. Whether
  the API's `/count` accepts `vuln:`/`tag:` on lower plans is not documented.

---

## 4. Available facets and the format of their values

### 4.1 Where the list comes from

- `GET /shodan/host/search/facets` returns the list, but needs a key. The docs only show a fragment:
  `['asn', 'bitcoin.ip', 'bitcoin.ip_count', ...]` [doc, DEV]. The full list is on the website's
  "Facet Analysis" page, https://www.shodan.io/search/facet [doc, DEV; doc, https://book.shodan.io/websites/www/facet-analysis/],
  which returned Cloudflare 403 to my fetch. **I could not get the full main-search facet list.**
  The service should call `/shodan/host/search/facets` at runtime and not hardcode the list.
- The **Trends** API docs publish a full facet list. It is likely close to the main list but not
  identical [doc, TRENDSDOC `GET /api/v1/search/facets`]:
  `asn, city, country, domain, has_screenshot, hash, http.component, http.component_category,
  http.favicon.hash, http.html_hash, http.robots_hash, http.status, http.title, http.waf, ip, isp,
  mongodb.database.name, org, os, port, product, redis.key, region, rsync.module, screenshot.label,
  ssh.fingerprint, ssl.alpn, ssl.cert.fingerprint, ssl.cert.issuer.cn, ssl.cert.serial,
  ssl.cert.subject.cn, ssl.ja3s, ssl.jarm, ssl.version, state, tag, version, vuln, vuln.verified`.
- Facets confirmed on the **main** search by official sources:
  - `org`, `os` [doc, DEV count example]
  - `country` [doc, DEV search example]
  - `port`, `city` [doc, STATSHELP]
  - `domain`, `asn` [client docs, query-summary.rst#L29-L39]
  - `vuln.verified`, used as `api.count('net:0/0', facets=[('vuln.verified', 100)])` [doc, https://book.shodan.io/enterprise/real-time-firehose/;
    also STATSHELP-style `shodan stats --facets vuln.verified:100 net:0/0` in https://help.shodan.io/mastery/vulnerability-assessment]
  - `http.html_hash` ("search filter and facet") [doc, https://help.shodan.io/mastery/property-hashes]
  - `http.dom_hash`, `http.title_hash`, `http.server_hash`, `open_dir.hash`, `open_dir.extension`,
    and the HTTP identifier facets [doc, RN2025 "New search filters and facets"]
  - `asset` ("New search filter and facet") [doc, https://book.shodan.io/changelog/ entry 2025-10-09]
  - `bitcoin.ip`, `bitcoin.ip_count` [doc, DEV]

### 4.2 Value formats

The only facet values shown in official docs are `country` (`"US"`, `"CN"`) and `org`
(`"Amazon.com"`, `"Google Cloud"`) [doc, DEV]. `os` (`"Ubuntu"`) appears in the count example
[doc, DEV]. Trends uses the same `country` format [doc, TRENDSDOC]. The CLI warns that "some facet
values are numbers" and converts them to strings [client,
[__main__.py#L573](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/__main__.py#L573)].
For the rest, the best guide is the type of the matching banner field [doc, SCHEMA], which the facet
very likely mirrors [inferred]:

| Facet | Banner field type (SCHEMA) and example | Expected facet `value` | Basis |
|---|---|---|---|
| `country` | `location.country_code` string, `"US"` | ISO 3166-1 alpha-2 string, `"US"` | **doc** (DEV, TRENDSDOC) |
| `org` | `org` string, `"Google"` | org name string | **doc** (DEV) |
| `os` | `os` string | string, `"Ubuntu"` | **doc** (DEV) |
| `asn` | `asn` string, `"AS15169"` (DEV) | probably `"AS15169"` with the prefix | inferred |
| `isp` | `isp` string | string | inferred |
| `port` | `port` integer | integer (JSON number) | inferred, consistent with client.__main__#L573 |
| `city`, `region`, `state` | strings | strings | inferred |
| `ip` | `ip` integer (`134744072`) and `ip_str` string | **unknown**: could be integer or dotted string | could not verify |
| `net` | — | **unknown**. `net` is a filter (`net:0/0` [doc, vulnerability-assessment]). Not in the Trends facet list | could not verify |
| `hash` | `hash` integer, signed 32-bit (`-553166942`) | integer | inferred |
| `http.favicon.hash` | `HttpFavicon.hash` integer | signed int32 | inferred |
| `http.html_hash` | integer (`199333125`) | integer | inferred |
| `http.title`, `http.status`, `product`, `version` | string / int / string / string | same | inferred |
| `ssl.cert.serial` | `SslCertificate.serial` **integer** | probably integer. Real serials can exceed 64 bits, so they may come back as big ints or strings. Don't assume hex | inferred, risk |
| `ssl.cert.fingerprint` | object `{sha1, sha256}` | probably a hex string (sha1 or sha256?) | could not verify |
| `ssl.jarm` | string, 62 hex chars (`"2ad2ad00..."` [doc, STREAM]) | string | inferred |
| `ssl.ja3s` | string (MD5 hex) | string | inferred |
| `ssh.fingerprint` | string | string (colon-hex MD5 in practice) | inferred |
| `ssh.hassh` | string | string. **No source lists `ssh.hassh` as a facet** (not in the Trends list) | could not verify |
| `vuln` | `vulns` object keyed by ID, e.g. `"CVE-2014-0160"` [doc, vulnerability-assessment] | CVE ID strings. Case unknown (could be upper or lower) | could not verify |
| `vuln.verified` | `Vulnerability.verified` boolean | probably CVE IDs of verified vulns, since the Book script uses `item['value']` as vuln IDs for `stream.vulns()` | doc (script), format inferred |
| `tag` | `Tag` enum: `"ai","alpr","c2","cdn","cloud","compromised","cryptocurrency","database","devops","doublepulsar","eol-os","eol-product","honeypot","ics","iot","lsp","malware","mcp","medical","onion","open-dir","pqc","proxy","self-signed","scanner","ssh-bad-key","starttls","tor","videogame","vpn"` | one of the enum strings | enum is doc (SCHEMA). Facet format inferred |
| `domain` | `domains` array of strings | domain string | inferred |
| `cpe` | `cpe23`/`cpe` arrays | CPE strings | inferred |

Host-level `vulns` can include IDs with a leading `!`. The CLI skips any `vuln.startswith('!')`
[client, [cli/host.py#L35-L37](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/cli/host.py#L35-L37)].
What `!` means isn't documented. It may mark a negated or not-vulnerable result [inferred].

### 4.3 Plan gating

- **Filters:** `vuln` needs Small Business or higher, and `tag` needs Corporate. This comes from search
  snippets of https://account.shodan.io/billing, which I couldn't fetch myself [3rd-party relay,
  WebSearch summary, possibly stale]. https://www.shodan.io/search/filters lists `tag` and `vuln` under
  "Restricted ... only available to users of higher API plans" (also only seen through a search snippet).
- Academic accounts: "The vuln search filter can only be used via the website. You can't use it on
  the CLI or the API." [doc, https://help.shodan.io/the-basics/academic-upgrade]
- Website facet analysis allows `vuln` and `tag` for everyone [doc, facet-analysis]. For the API, see Could-not-verify.
- No source gates the `vuln` or `ip` *facets* specifically. The facet size cap depends on the plan
  [doc, RN2025]. I found nothing official that says `ip` needs Enterprise or Academic.

### 4.4 The `ip` facet

- `ip` is a facet in Trends [doc, TRENDSDOC]. Community notes use `shodan stats --facets ip,port,...`
  on the main search [3rd-party, https://github.com/00xPh4ntom/Shodan-Notes].
- "Top N IPs" means the N IPs with the most *matching banners* (counts are banners) [inferred]. The
  largest N is whatever the plan's facet cap allows (up to 131,072 values per the 2025-11-06
  changelog) [doc]. Shodan Monitor itself uses facets to "get a breakdown of active IPs within a
  network range" [doc, https://book.shodan.io/changelog/2025-11-07/], so asking for an IP breakdown
  through facets is a supported pattern.

---

## 5. Can facets be nested or pivoted (e.g. ports per IP)?

- **No nesting is documented.** Each facet in a request is computed on its own over the whole query
  result. The response is `facets: {name: [{count, value}]}` with no sub-buckets [doc, DEV]. The help
  page shows several facets side by side (`port:100,org:20`) with separate limits, not nested
  [doc, STATSHELP]. Trends adds a per-month level (`facets.<name>[i] = {key: "2017-06", values: [{count, value}]}`),
  but that is a time split, not a facet-by-facet pivot [doc, TRENDSDOC; client
  [__main__.py#L862-L894](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/__main__.py#L862-L894)].
- **`facets=ip:N,port:M` does not give ports per IP.** It returns two independent top-lists [inferred
  from the response shape].
- What does work (all [inferred] from documented building blocks unless noted):
  1. **Two-stage count fan-out (no query credits):** run `count(query, facets="ip:N")` to get the top
     IPs. Then for each IP run `count(f"{query} ip:{ip}", facets="port:100")`, or
     `net:{ip}/32`. The `ip` and `net` filters exist [doc, TRENDSDOC filter list includes `ip` and
     `net`]. It costs N+1 calls at 1 request per second [doc, changelog 2025-11-10]. It is exact per
     IP within the 30-day window [doc, TIMEFRAMES].
  2. **Host lookups:** `GET /shodan/host/{ip}?minify=true` returns `ports` plus host info (`org`,
     `isp`, `asn`, location, `hostnames`) "no banners" [doc, DEV]. On Corporate, 100 IPs fit in one
     call with comma-joined IPs [doc, LOOKUP "Bulk Lookups"]. No query credits [doc, BOOKAPI]. The
     ports here are the host's ports overall, not just the ones matching the query. Using
     `minify=true` for a whois-style summary with ports is my suggestion, not something Shodan describes.
  3. **InternetDB (keyless, free):** `internetdb.shodan.io/{ip}` gives ports per IP. The service
     already has this. Its freshness differs from the main API.
  4. **Paid search with `fields`:** `GET /shodan/host/search?query=...&minify=false&fields=ip_str,port`
     returns IP:port pairs that match the query [doc, https://book.shodan.io/changelog/2026-03-05/].
     Each 100 results costs a query credit (§6).
- The official client and docs suggest no nesting trick. The only "facet then act" pattern in the
  docs is the Book's firehose script: it takes `vuln.verified` facet values, then subscribes with
  `stream.vulns(...)` [doc, real-time-firehose].

---

## 6. `GET /shodan/host/search`

- Parameters: `query`, `facets`, `page` ("page through results 100 at a time (default: 1)"), `minify`
  ("whether or not to truncate some of the larger fields, such as http.html. Removed fields are listed
  in metadata.truncated of each banner (default: True)"), and `fields` ("Comma-separated list of fields
  to return ... Example: tags,http.title,http.favicon.hash") [doc, DEV].
- `fields` requires `minify=false`: "you need to set minify=false as that parameter is enabled by
  default and is mutually exclusive with the new fields parameter" [doc, https://book.shodan.io/changelog/2026-03-05/].
- As of **2026-11-02**, "Search results no longer include http.html (with the default minify=true) or
  smb.raw". Ask for them through `fields` [doc, https://book.shodan.io/changelog/2026-11-02/].
- The client also sends `limit`/`offset` instead of `page` when `limit` is given. These are not in the
  REST docs [client, [client.py#L534-L571](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/client.py#L534-L571)].
  The CLI caps `shodan search --limit` at 1,000 [client, __main__.py#L472, #L486-L488].
- Response keys: `matches`, `facets`, `total`, `_scroll_id` (in the example, not listed as a parameter)
  [doc, DEV]. The 2025 notes mention "More unique scroll hashes" [doc, RN2025].
- **Credits:** "If any of the following criteria are met, your account will be deducted 1 query
  credit: The search query contains a filter. Accessing results past the 1st page using the "page".
  For every 100 results past the 1st page 1 query credit is deducted." [doc, DEV]. Worked examples:
  `apache` page 1 is free, `product:mongodb` costs 1, and page 3 of `apache` costs 1 [doc, CREDITS].
  Credits reset monthly [doc, CREDITS]. The Book's "1 query credit is deducted per 100 pages of search
  results" [doc, BOOKAPI] looks like a typo for 100 *results*. Treat it as 1 credit per page with a
  filter or page ≥ 2.
- `search_cursor` computes `total_pages = ceil(total/100)` and pages forward. It retries with
  `time.sleep(tries)` up to 5 times. It "can't be used with facets" [client,
  [client.py#L573-L623](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/client.py#L573-L623)].
- **Suggested metadata for a query-execution node** [inferred]: the endpoint (`/shodan/host/search`,
  `/shodan/host/count`, or the Trends URL), `query`, `facets` string as sent, `page` (or page
  range), `minify`/`fields`, `total`, number of `matches` returned, time of execution (UTC),
  `credits` used (credits before and after from `GET /api-info` → `query_credits` [doc, DEV]),
  and `metadata.truncated` presence. Never record the `key` parameter.

---

## 7. Trends API (`trends.shodan.io/api/v1/search`)

- "Get breakdown of historical results aggregate by facet field." Parameters: `query` ("Search
  query used to search the historical database, e.g. product:nginx") and `facets` (optional) [doc, TRENDSDOC].
- Response: `{"total": N, "matches": [{"month": "2017-06", "count": 9038297}, ...], "facets": {"country": [{"key": "2017-06", "values": [{"count", "value"}]}]}}`
  [doc, TRENDSDOC]. The client always sends `facets` (an empty string if there are none)
  [client, [client.py#L263-L278](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/client.py#L263-L278)].
- Data goes back to 2017 [doc, TIMEFRAMES; https://book.shodan.io/websites/trends/].
- **Only a subset of filters works.** The Trends filter list is
  `all, asn, city, country, cpe, has_ipv6, has_screenshot, has_ssl, has_vuln, hash, hostname,
  http.component, http.component_category, http.favicon.hash, http.html_hash, http.robots_hash,
  http.securitytxt, http.status, http.title, http.waf, ip, isp, net, org, os, port, product, region,
  screenshot.label, ssh.fingerprint, ssl, ssl.alpn, ssl.cert.fingerprint, ssl.cert.issuer.cn,
  ssl.cert.serial, ssl.cert.subject.cn, ssl.ja3s, ssl.jarm, ssl.version, state, tag, title, version, vuln`
  [doc, TRENDSDOC]. These are missing compared with main search [inferred by comparing with filters
  documented elsewhere]: `scan`, `asset`, `domain`, `shodan.module`, `http.dom_hash`/`title_hash`/`server_hash`,
  `open_dir.*`, `ssh.hassh`, `vuln.verified` (as a filter), `cloud.*`, and the protocol-specific filters.
  The `facets` list differs from the `filters` list. For example, `domain`, `redis.key`,
  `mongodb.database.name` and `vuln.verified` are facets but not filters.
- Plan: the developer docs label the section "Historical Data Enterprise" [doc, TRENDSDOC]. The Book's
  Trends page has badges for Member, Freelancer, Small Business, Corporate and Enterprise, and says:
  "in Shodan Trends it doesn't require a Corporate API tier to use the tag filter. All search filters
  listed on the Trends Filters page are available to everyone." [doc, https://book.shodan.io/websites/trends/].
  These two official sources conflict. The Book is newer [inferred].
- Trends shares the 1 request per second key limit [inferred; the client uses the same `_request`
  limiter for `service='trends'`, client.py#L341-L350].

---

## 8. Streaming API filters

Base `https://stream.shodan.io`. Output is newline-separated JSON (`t=json`) or SSE (`t=sse`).
`debug=1` adds `{"event": "debug", "discarded": N}` messages [doc, STREAM].

| Endpoint | Value format (verbatim from docs) | Notes |
|---|---|---|
| `/shodan/banners` | — | "This stream provides ALL of the data that Shodan collects" [doc, STREAM]. The client says "only available to API subscription plans and for those it only returns a fraction of the data" [client, [stream.py#L100-L106](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/stream.py#L100-L106)] |
| `/shodan/asn/{asn}` | "Comma-separated list of ASNs; example "3303,32475"" | **No `AS` prefix** in the example (unlike banner `asn`, which is `"AS15169"`) [doc, STREAM]. Whether a prefix is accepted: unknown |
| `/shodan/countries/{countries}` | "Comma-separated list of countries indicated by their 2 letter code; example "DE,US"" | [doc, STREAM] |
| `/shodan/ports/{ports}` | "Comma-separated list of ports; example "22,443"" | [doc, STREAM] |
| `/shodan/vulns/{vulns}` | "Comma-separated list of case-insensitive vulnerabilities; example "CVE-2017-7679,CVE-2018-15919"" | Case-insensitive [doc, STREAM] |
| `/shodan/tags/{tags}` | Comma-joined tags | **Not on the developer site.** Only the client has it [client, [stream.py#L142-L151](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/stream.py#L142-L151); CLI `--tags` __main__.py#L640] |
| `/shodan/custom?query=` | "Space-separated list of case-sensitive key:value filters or data query; example "port:8080,443", "port:22 SSH-2.0-OpenSSH_6.4", "!country:VN"" | "It generally follows the query syntax of the main search engine except that here the query is case-sensitive!" Use "-" or "!" to negate [doc, STREAM]. The header shows `/shodan/custom/query={query}` (a typo). The curl example uses `/shodan/custom?query=` [doc, STREAM]. Same in the client [stream.py#L119-L129] |
| `/shodan/alert`, `/shodan/alert/{id}` | alert ID, e.g. `"OYPRB8IR9Z35AZPR"` | "network alerts are renewed periodically every 1 hour" [doc, STREAM] |

- **Plan:** The data-stream section is labelled "Enterprise" (`Data Streams Enterprise`) [doc, STREAM].
  "Only users with an API subscription are able to access the Streaming API." The real-time stream
  section is badged Enterprise [doc, BOOKAPI]. The network-alert streams are the "Private Firehose"
  for networks you monitor [doc, STREAM].
- **Heartbeats and timeouts:** blank-line heartbeats keep the connection alive. The client sends
  `heartbeat=False` when it has a timeout, and retries on Cloudflare 524 [client,
  [stream.py#L16-L63](https://github.com/achillean/shodan-python/blob/87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8/shodan/stream.py#L16-L63)].
- Throughput is about 1,200–1,500 banners per second on the full firehose [doc, https://book.shodan.io/enterprise/real-time-firehose/].

---

## 9. Gotchas

1. **History is capped at 90 days and 1,000 banners, with no paging.** A host that is rescanned
   often loses its older banners silently [doc, TIMEFRAMES]. Don't assume you have the full history.
   Record the window on the execution node [inferred].
2. **`_shodan.id` may be missing or null.** It is guaranteed only where a cascade could start
   [doc, CRAWLER]. A 2018 official example has `"id": null` [doc, LOOKUP]. Use a fallback idempotency
   key (`ip`, `port`, `transport`, `timestamp`, `hash`) [inferred].
3. **`_shodan.region` location is inconsistent.** The Book says `_shodan.region` [doc, CRAWLER]. The
   datapedia example shows `_shodan.options.region` [doc, DP]. The schema defines neither [doc, SCHEMA].
4. **Scan grouping only exists for on-demand scans** (`_shodan.options.scan`, `scan:<id>` filter)
   [doc, DP; SCANHELP]. Routine crawls are random single IP:port probes [doc, CRAWLER]. The scan `id`
   is 16 alphanumeric characters, not a UUID [doc, DEV].
5. **Scan-status path:** `/shodan/scan/{id}` in the HTML docs and client, `/shodan/scans/{id}` in
   OpenAPI [doc, DEV vs OAS].
6. **`GET /shodan/scans` returns `api_key`.** Remove it before storing anything [doc, DEV].
7. **Re-scan cooldown:** about 24 hours without Enterprise `force` [doc, SCANHELP].
8. **Credits:** count and host lookups are free [doc, DEV; BOOKAPI]. A search costs 1 credit if it has
   any filter *or* is page ≥ 2, per 100 results [doc, DEV; CREDITS]. The `scan:` filter therefore costs
   credits through search, but is free through count [inferred]. On-demand scans cost 1 scan credit
   per IP [doc, DEV]. Credits reset monthly [doc, CREDITS].
9. **Facet size limits depend on the plan, and the numbers aren't published.** Since 2025-11-06 an
   over-limit request returns an explicit error instead of a timeout [doc, changelog 2025-11-06].
   Default size is 5 [client docs]. The CLI default is 10 [client].
10. **Facets don't nest.** "Ports per IP" needs a count call per IP or a host lookup (§5) [inferred].
11. **Facet value types vary.** Some are strings and some are JSON numbers (`port`, hashes) [client
    __main__.py#L573]. Store values as strings or normalize per facet. `ssl.cert.serial` is an
    integer in the schema and may be larger than 64 bits [doc, SCHEMA; inferred].
12. **ASN format differs:** banners use `"AS15169"` [doc, DEV]. The stream ASN path uses `3303` with
    no prefix [doc, STREAM].
13. **Case sensitivity:** stream `custom` queries are case-sensitive [doc, STREAM]. The vulns stream is
    case-insensitive [doc, STREAM]. Main search treats `vuln:`/`tag:` case-insensitively since a website
    fix [3rd-party via search snippet, unverified].
14. **Timestamps** look like `"2021-01-22T08:49:35.190817"`: ISO 8601 with microseconds and **no
    timezone**, and are "in UTC time" [doc, SCHEMA `timestamp` description; DEV]. Scan `created` and
    `status_check` use the same format (`"2021-01-26T08:17:43.794000"`) [doc, DEV]. DNS `last_seen`
    uses it as well [doc, BOOKAPI]. Trends uses `"YYYY-MM"` months [doc, TRENDSDOC].
15. **Duplicate banners:** history returns many banners per IP:port [doc, TIMEFRAMES]. The CLI removes
    duplicates from scan streams by `ip:port` [client, cli/scan.py#L192-L196]. Empty banners have
    `hash` 0, so `-hash:0` filters them out [doc, https://help.shodan.io/mastery/property-hashes]. Some
    empty banners are no longer indexed [doc, RN2025 "Filtered empty banners"].
16. **`ports` and `data` can be out of sync** (e.g. SSL/Telnet data hidden by plan). The CLI pads with
    placeholder banners [client, cli/host.py#L53-L71]. Don't infer closed ports from missing banners.
17. **Truncated fields:** as of 2026-11-02, search drops `http.html` (when `minify=true`) and `smb.raw`.
    History banners drop large fields too. Both list them in `metadata.truncated`
    [doc, changelog 2026-11-02]. `fields` requires `minify=false` [doc, changelog 2026-03-05].
18. **Rate limit:** 1 request per second per key. Over-limit requests get HTTP 429 (since 2025-11-10)
    [doc, changelog 2025-11-10].
19. **Plan gating** (§4.3): host lookups need Membership+ [doc, LOOKUP]. The `vuln` filter needs Small
    Business+ and `tag` needs Corporate (not first-hand) [3rd-party relay of the billing page].
    Academic accounts can't use `vuln` through the API [doc, academic-upgrade]. Streams need a
    subscription or Enterprise [doc, STREAM; BOOKAPI]. Trends plan requirement conflicts between
    sources [doc, TRENDSDOC vs Book Trends].
20. **Vulns starting with `!`** appear in host `vulns`, and the CLI skips them [client, cli/host.py#L35-L37].
    Their meaning isn't documented.
21. **The 30-day window applies to search, count and host** [doc, TIMEFRAMES]. A count `total` is
    banners, not IPs [inferred].
22. **The `/shodan/tags/{tags}` stream** is only in the client, not in the official docs [client vs STREAM].

---

## Could not verify

Each item below is open because I couldn't confirm it without a key, or because Shodan's site
blocked automated access (Cloudflare 403 on www.shodan.io, beta.shodan.io and account.shodan.io;
I also did not use an archive copy).

1. The full main-search facet list (`GET /shodan/host/search/facets` needs a key, and https://www.shodan.io/search/facet returned 403). Fetch it at runtime.
2. The value format of the `ip` facet (integer or dotted string), whether `net` is a facet, and whether `ssh.hassh` is a facet.
3. The value formats of `asn` (`AS` prefix?), `ssl.cert.serial` (int, string or hex?), `ssl.cert.fingerprint` (sha1 or sha256?), and the case of `vuln` and `vuln.verified`.
4. Per-plan facet size limits, whether 131,072 is per facet or per request, and the maximum number of facets per request.
5. Whether `history=true` needs a higher plan than a plain lookup, and its credit cost (the Book only says IP lookups are free).
6. Whether host-level `ports`, `vulns`, `tags`, `hostnames` and `last_update` are current-only when `history=true`.
7. Whether `_shodan.id` is the same across repeated API calls for the same stored banner, and how often it is missing on current data.
8. Where `region` lives: `_shodan.region` or `_shodan.options.region`.
9. Whether `/shodan/host/count` accepts restricted filters (`vuln:`, `tag:`) on lower API plans (the website allows them for facet analysis).
10. Current plan gating for `vuln`/`tag` filters (the billing page is only known from search snippets and may be stale), and the Trends plan requirement (Enterprise per the dev docs, all paid tiers per the Book).
11. Whether the stream ASN path accepts an `AS` prefix, and whether `/shodan/tags/{tags}` is still supported server-side.
12. Whether `GET /shodan/scans` paginates with `page` (client only) and what its page size is.
13. How the website's Timeline tab is actually laid out (the page was blocked). Its behavior is known only from the Book text.
14. What the leading `!` on vuln IDs means.
