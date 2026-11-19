# Internals

## Source layout

| File | Contents |
| --- | --- |
| {src}`svcs/shodan/src/shodansvc/__init__.py` | `__version__` and the `ShodanSvc` export. |
| {src}`svcs/shodan/src/shodansvc/__main__.py` | `python -m shodansvc <dirn>`, runs `ShodanSvc.execmain()`. |
| {src}`svcs/shodan/src/shodansvc/defs.py` | The Storm service name (`slib.shodan`), version, `meta:source` guid, the `add` event, and the Storm package (`SlibShodanPkg`, a `stormlibpp.StormPkg` loaded from `pkgproto/slib.shodan.yaml`). |
| {src}`svcs/shodan/src/shodansvc/api.py` | `ShodanCellApi`, the Telepath API. |
| {src}`svcs/shodan/src/shodansvc/svc.py` | `ShodanSvc`, the Cell, with a method per Shodan endpoint. |
| {src}`svcs/shodan/src/shodansvc/client.py` | `ShodanClient`, the HTTP transport shared by every API. |
| {src}`svcs/shodan/src/shodansvc/norm.py` | Normalization of Shodan's responses, and the hashes. |
| {src}`svcs/shodan/src/shodansvc/pkgproto/` | The `slib.shodan` Storm package: `slib.shodan.yaml`, `storm/commands/*.storm`, `storm/modules/*.storm`, and a copy of the README. |

## client.py

`ShodanClient(session, urls=None, rate=1.0, timeout=60.0)` sends every request. `ShodanSvc`
builds one at startup from `shodan:urls`, `shodan:ratelimit` and `shodan:timeout`, with an
`aiohttp.ClientSession(trust_env=True)` that is closed when the Cell finishes.

| Constant | Value |
| --- | --- |
| `BASE_URLS` | `api`, `stream`, `trends`, `internetdb`, `cvedb` (see [Deployment](deployment.md#cell-configuration)) |
| `KEYED_APIS` | `api`, `stream`, `trends`: these get the `key` query param |
| `RATE_LIMITED_APIS` | `api`, `trends`: these wait on the rate limiter |
| `MAX_RETRIES` | `3` |

### request()

`request(method, path, *, base="api", apikey=None, params=None, json_data=None, form=None)`:

1. Refuses a JSON body and a form body together, and an unknown `base`.
2. Normalizes `params` (and `form`) with `normParams()`: `None` values are dropped, booleans
   become `true`/`false`, lists, tuples and sets become comma separated strings, dicts become
   JSON, and anything else `str()`. A `params` value that isn't a dict is a `ShodanApiError`.
3. For a keyed API, adds `key=<apikey>`, or raises `NoApiKeyError` without one.
4. Waits on the `RateLimiter` for `api` and `trends`. It's one `asyncio.Lock` and timestamp for
   the whole service, spacing calls at least `1/rate` seconds apart across every user.
5. Sends the request with a total timeout of `shodan:timeout`. A connection error or timeout
   is `ShodanApiError("Unable to connect to Shodan (<base>): <error>")`, with the error text
   passed through `scrubMesg()` so it never holds the key (see [error handling](#error-handling)).
6. On an HTTP 429, sleeps `2**attempt` seconds (1, 2, 4) and retries, up to 3 retries. Each
   retry waits on the rate limiter again. The last 429 is returned as an error.
7. Parses the body as JSON (an empty body is `None`). Invalid JSON with a status under 400 is
   `Unable to parse the JSON response from <url>`.
8. A status of 400 or more, or a JSON object with an `error` key (even on a 200), is a
   `ShodanApiError` with the status as `code` and a message from `errMesg()`.

`errMesg()` picks the most useful message: the body's `error`, `detail` (InternetDB and
CVEDB) or `message` (skipping values that are HTML pages, which the Streaming API wraps in
JSON), then a non-HTML, non-JSON body (first 500 characters), then the status. For keyed APIs,
an empty or HTML 401 or 403 gets an explanation, since Shodan returns those both for bad keys
and for keys whose plan lacks the API:

- 401: `Shodan rejected the API key: it is invalid, or its plan doesn't include this API (HTTP 401)`
- 403: `Access denied: the API key's plan doesn't include this API (HTTP 403)`

Keyless APIs just get `HTTP <code>` (a 403 there is an IP or WAF block).

### stream()

`stream(path, *, apikey=None, params=None, limit=100, timeout=60.0)` reads the Streaming API,
which never ends on its own:

- With a timeout, it sends `heartbeat=false`, so an idle stream sends nothing, and sets the
  socket read timeout to `timeout`. A read timeout ends the stream quietly.
- It also stops when `timeout` seconds have passed since the start (checked as lines arrive),
  or after `limit` banners. `0` turns either off.
- Each non-empty line is parsed as JSON, and lines that aren't JSON are skipped.
- A status other than 200 is a `ShodanApiError` from `errMesg()`. Connection errors are
  `Unable to connect to the Shodan Streaming API: <error>`.
- Streams aren't rate limited or retried.

## svc.py

`ShodanSvc(s_cell.Cell)` sets `cellapi = ShodanCellApi` and the `confdefs` on
[Deployment](deployment.md#cell-configuration). Its `__anit__` opens the `slib:shodan` safe
key-value store in the Cell's slab, the HTTP session, the facet limit cache and the client.

### API keys

- `getApiKey(apikey=None)` returns `apikey or <stored key> or conf["shodan:apikey"]`.
- `setApiKey(apikey)` stores the key under `apikey`, or pops it for a null or empty value.
- `hasApiKey()` is `bool(getApiKey())`.
- `_api(method, path, apikey=None, base="api", params=None, json_data=None, form=None)`
  resolves the key and calls `client.request()`. Keyless methods (InternetDB, CVEDB) call
  `client.request()` directly, so no key is ever sent there.

### URL paths

Every value put in a URL path is quoted as one segment with `_seg()`
(`urllib.parse.quote(value, safe="")`), so a value like `../org` can't reach another endpoint
with the key. The ignored service of an alert trigger goes through `_service()`, which only
allows `<ip>:<port>` (an IPv4 or IPv6 address, optionally in brackets, and a port up to 65535)
and quotes it keeping the `:`. CVEDB IDs are upper-cased.

### countIps and facet limits

`countIps(query, size=None, facets=None, apikey=None)` lists the IPs matching a query with the
count API's `ip` facet, which costs no query credits. One request returns at most the plan's
facet limit in values, and Shodan doesn't publish the limit per plan, so the service learns it:

1. `size` below 1 is an error. The key is hashed (SHA-256) to look up a cached limit, trusted
   for `FACET_LIMIT_TTL` (86400 seconds). The key itself is never cached.
2. It asks for `size`, or the cached limit, or `COUNT_IP_SIZE` (131072, the most facet values
   Shodan has published it returns). The facets are `ip:<n>` plus any extra `facets` (an `ip`
   facet among them is dropped).
3. When Shodan answers `Facet size too big for current subscription (limit: <n>)` with `<n>`
   below the size asked for, the limit is cached, the request is retried with `ip:<n>`, and
   `lowered` is true when a `size` was given. A limit at or above the size asked for means
   another facet was too big, and the error is raised.
4. When a size over the cached limit works, the plan changed, so the cached limit is dropped.
5. It returns the IP values (dropping the counts), the size asked for, the limit if known,
   `full` (the IPs fill the size, so there are likely more), `lowered`, and the other facets.

The cache is in memory, so a restart costs each key one extra request.

### Search paging

`searchGenr(query, limit=100, minify=True, page=1, apikey=None)` calls `search()` for page
`page`, `page + 1`, ... and yields each match as a `normBanner` dict. It stops when:

- `limit` banners were yielded (`0` for no limit),
- a page has no matches,
- `page * 100 >= total` (`SEARCH_PAGE_SIZE` is 100), or
- a page after the first fails with HTTP 400, 403 or 404 (`DEEP_PAGE_CODES`), which is how
  Shodan answers a page deeper than the plan can read. It's logged at INFO and ends the
  results. Other errors, and any error on the first page, are raised.

Each page is one query credit.

### Directory paging

`queries()` and `queriesSearch()` share `_directoryPages(path, params, page, pages)`, which
fetches pages `page` to `page + max(pages, 1) - 1` and stops early when a page is empty or
`num * 10 >= total` (`DIRECTORY_PAGE_SIZE` is 10). `queriesSearch()` falls back to `queries()`
on any 5xx from `/shodan/query/search`, and matches the query (lower-cased) against each
query's title, query, description and tags joined (`_directoryText()`).

### DNS paging

`dnsDomainAll(domain, history=False, rtype=None, maxpages=10)` calls `dnsDomain()` for page
1, 2, ... while Shodan returns `more`, up to `maxpages` (`0` for no limit), merging the tags
(the last non-empty), subdomains (sorted, deduplicated) and records (`norm.normDnsRecords()`).
`more` in the result says whether pages remain. `history` is only sent when true.

### Secrets in responses

`scans()` and `scanStatus()` remove the `api_key` field Shodan includes (top level, and each
scan in `matches`), so a key, ex. the service-wide one, is never readable from Storm.
`apiUrl()` and `streamUrl()` build URLs from `BASE_URLS` (never `shodan:urls`) and never add a
key.

## norm.py

The normalizers flatten Shodan's responses for the Storm modeling code (see
[API](api.md#normalized-shapes) for the shapes, and [model](model.md) for how they're used):

| Function | Does |
| --- | --- |
| `normHost()`, `normInternetDb()` | A host lookup or InternetDB result, in one shape. Host vulns are merged with the banners' detailed ones. |
| `normBanner()` | One banner. Drops `data` when Shodan truncated it. Timestamps lose a trailing `+00:00` or `Z` (`_ts()`). |
| `normHttp()`, `normHttpHeaders()`, `normFile()` | HTTP requests, headers (lower case, deduplicated, without `Date`), redirects, files and open directory listings. |
| `normCert()`, `normTls()` | TLS cert fields (ASN.1 times to `YYYY/MM/DD HH:MM:SS`, int serials to hex), JARM (all zeros dropped) and JA3S. |
| `normSshKey()` | The host key file, `<algo> <base64>\n`, and its hashes. |
| `normCpe()`, `normCpes()`, `normSoftvers()` | CPE padding, and pairing CPEs with the product and version. |
| `normVulns()` | Dict or list vulns, keeping `CVE-` IDs. |
| `tcpPorts()` | Bare ports minus `UDP_PORTS`. |
| `normDnsRecords()` | DNS domain records. |
| `normCve()`, `normAdvisory()`, `cvssScores()`, `cvssBaseScore()` | CVEDB CVEs, GHSAs and EUVD entries, and CVSS versions. `cvssBaseScore()` uses Synapse's `s_infosec.CVSS_CALC`. |
| `murmur3()`, `bannerHash()`, `faviconHash()`, `htmlHash()`, `fileHash()` | A pure Python signed 32-bit MurmurHash3 (x86_32, seed 0, the same as `mmh3.hash()`), and Shodan's three hashes built on it. |

## Error handling

`ShodanSvc` methods raise `ShodanApiError` (with `mesg` and the HTTP `code`, if any) and let
`ShodanCellApi` (`stormlibpp.svc.RetnApi`) turn every exception into a `status=False`
`TelepathRetn` (see [API](api.md#telepathretn)). The Storm code checks every retn with
`slib.shodan.util.failed()` and warns.

API keys are sent as the `key` query parameter, kept apart from the URL (`client._prep()`
returns the base URL and path, and the params separately). The messages the service builds
include at most that URL, never the params. `Unable to connect to Shodan (<base>): <error>` and
`Unable to connect to the Shodan Streaming API: <error>` embed `aiohttp`'s own error text, which
can include the full URL, so `client.scrubMesg()` first drops the query string of every URL in it
(`?<redacted>`) and replaces the key that was sent. `ShodanCellApi._retnRedact()` then removes
the stored and configured keys from every message returned to Storm.

## State

| State | Where | Lifetime |
| --- | --- | --- |
| Service-wide API key | The Cell slab, safe key-value store `slib:shodan`, key `apikey` | Until cleared |
| Facet limits | `ShodanSvc.facetlimits`, `{sha256(key): (limit, monotonic time)}` | In memory, 24 hours |
| User API keys | Cortex vaults of type `shodan`, user scope | Until `slib.shodan.apikey --clear` |
| Tag settings | Cortex Storm globals `slib:shodan:tag:enabled`, `slib:shodan:tag:prefix` | Until changed |

The service runs no background tasks or loops, and doesn't use an Axon. It has no caches
besides the facet limits.

## The Storm package

{src}`svcs/shodan/src/shodansvc/pkgproto/slib.shodan.yaml` defines the package: name
`slib.shodan`, the service's version, `synapse_version: ">=2.256.0,<3.0.0"`, `genopts.dotstorm:
true` (each command's and module's Storm is in `storm/commands/<name>.storm` and
`storm/modules/<name>.storm`), the README as its doc, four permissions, seven modules and 33
commands. There are no `configvars` or `onload`: the settings are Storm globals made by the
service's `add` event.

Modules:

- `slib.shodan.priv.user`, `.priv.scan`, `.priv.alert`, `.priv.admin` use `asroot:perms`: a
  user holding the listed permission runs them as root. Each `init` block gets
  `$lib.service.get("slib.shodan")`. They're the only modules that call the service, which
  keeps `service.get` (and with it the service-wide key) away from users.
- `slib.shodan.lib` and `slib.shodan.model` use `perms` (the caller needs `slib.shodan.user`)
  and run as the caller, so node edits use the caller's permissions.
- `slib.shodan.util` has no permissions.

Commands only import what they need, ex. `slib.shodan.scan` imports `slib.shodan.lib` (and so
needs `slib.shodan.user`) only when `--wait` is above 0.

Notes on the Storm code:

- In `slib.shodan.model`, a `for` loop that runs while a node is in a function's pipeline would
  send the node on after its first iteration and end the function early. So functions that
  yield a node don't loop, and loops call helpers that edit the node in their own runtime.
- Commands that read every inbound node first collect them in an `init` list and `spin`, then
  process the list in a later pipeline stage (`| if $pending { ... }`).
- `slib.shodan.scan`, `slib.shodan.alert.add` and `slib.shodan.alert.edit` collect targets and
  make their one request in `fini`.
- The `// noqa:` comments mark findings of Synapse's Storm linter that are intended on Synapse
  2.x. CI runs the linter with `storm_lint: block`, so new findings fail.

## Tests

The tests are in {src}`svcs/shodan/tests/`:

| File | Covers |
| --- | --- |
| `fakeshodan.py` | `FakeShodan`, an `aiohttp` server on `127.0.0.1` serving canned responses for every API under a per-API prefix (`/api`, `/stream`, `/trends`, `/internetdb`, `/cvedb`), and `shodanSvc()`, which yields a Cortex with the service added and pointed at it. |
| `test_shodan.py` | `norm.py` (`TestNorm`), `client.py` (`TestClient`), and `ShodanSvc` methods (`TestShodanSvc`). |
| `test_shodan_storm.py` | The Storm package: commands, modeling, permissions, key privacy, the DNS cleanup, and the package contract (versions match, README names every command, `assertMainHelp()`). |
| `test_live.py` | Live tests against the real APIs, skipped by default. |
| `conftest.py` | Enables the `stormlibpp.testing` pytest plugin. |

The fake is strict like the real API: it records every request (`fake.requests`,
`fake.last()`), rejects `key=badkey` with a 401, ignores query params on the form-body
endpoints (`POST /shodan/scan`, `/shodan/scan/internet`, `/notifier`), enforces a facet limit
(`fake.facetlimit`, 1000) with Shodan's error, and serves real response shapes (ex. trimmed
real banners for scanme.nmap.org, with Shodan's own hashes). `fake.streamhandler` replaces the
Streaming API handler. `shodanSvc()` sets `shodan:urls` to the fake, `shodan:ratelimit` to `0`
and `shodan:apikey` to `testkey`.

Run them with:

```bash
cd svcs/shodan
uv sync
uv run pytest
```

The live tests are gated by environment variables:

```bash
# Keyless APIs only (InternetDB and CVEDB).
SLIB_SHODAN_LIVE=1 uv run pytest tests/test_live.py

# Also the keyed APIs: free endpoints and a few host lookups, never scan credits.
SLIB_SHODAN_LIVE=1 SHODAN_API_KEY=<key> uv run pytest tests/test_live.py
```

The `stormlibpp.testing` plugin fails any test that uses a deprecated Synapse API, and
`pyproject.toml` turns `DeprecationWarning`s from `shodansvc` into errors. CI also runs the
tests inside the test image, `ruff`, and the Storm linter (see {doc}`/dev/testing` and
{doc}`/dev/ci`). Changes need a version bump in every place the version lives (see
{doc}`/dev/versioning`).
