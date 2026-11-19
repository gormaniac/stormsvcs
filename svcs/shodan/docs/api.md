# API

There are two APIs: the Storm modules in the `slib.shodan` package, and the service's Telepath
API, which only the `slib.shodan.priv.*` modules call (and users with `service.get`).

## Storm modules

| Module | Permission to import | Runs as | Purpose |
| --- | --- | --- | --- |
| `slib.shodan.lib` | `slib.shodan.user` | The caller | The user API: query Shodan and model the results. |
| `slib.shodan.model` | `slib.shodan.user` | The caller | Model normalized data as nodes. |
| `slib.shodan.util` | none | The caller | Printing and small helpers. |
| `slib.shodan.priv.user` | `slib.shodan.user` | root (`asroot:perms`) | Service calls for user features. |
| `slib.shodan.priv.scan` | `slib.shodan.scan` | root | Service calls for scans. |
| `slib.shodan.priv.alert` | `slib.shodan.alert` | root | Service calls for alerts and notifiers. |
| `slib.shodan.priv.admin` | `slib.shodan.admin` | root | Service calls and settings for admins. |

The `priv` modules are the only code that calls the service. They run as root so users don't
need `service.get`, and each passes the caller's own key (`userKey()`, from
`$lib.vault.bytype(shodan, scope=user)`) as the `apikey` argument.

### slib.shodan.lib

```text
$shodan = $lib.import(slib.shodan.lib)
$ipnode = $shodan.host(8.8.8.8, history=(true))
$res = $shodan.search("product:nginx country:US", limit=(200))
$vulns = $shodan.cves(product=log4j, kev=(true))
```

These functions query Shodan, model the results, and return nodes. Failed calls are reported
with `$lib.warn()` and return null (or an empty list), they don't raise.

| Function | Returns |
| --- | --- |
| `host(ip, history=(false), minify=(false), internetdb=(false), timeline=(null))` | The IP node, or null. Falls back to InternetDB without a key. `timeline` defaults to `history`. See {ref}`shodan-cmd-host`. |
| `search(query, limit=(100), minify=(false), page=(1), ref=(null))` | `{"query": <it:exec:query>, "ips": [<ip nodes>]}`, or null. `ref` is linked `-(refs)>` from the query. |
| `count(query, size=(null), facets=(null), ref=(null))` | `{"query": <it:exec:query>, "ips": [...], "size": <n>, "full": <bool>, "facets": {...}}`, or null. |
| `ingest(retns, what, text, apiurl, opts, ref=(null))` | Emits `{"query": <it:exec:query>, "ip": <ip or null>}` per banner, then `{"query": ..., "ip": null, "done": true}`. Models a generator of banner retns and records the run. |
| `domain(domain, history=(false), rtype=(null), maxpages=(10))` | A list of the subdomain `inet:fqdn` nodes. |
| `resolve(fqdn)` | The IP node, or null. |
| `reverse(ip)` | A list of the `inet:fqdn` nodes. |
| `cve(vulnid, cpes=(false))` | The `risk:vuln` of a CVE, GHSA or EUVD ID, or null. |
| `cves(cpe23=(null), product=(null), kev=(false), epss=(false), limit=(100), start=(null), end=(null), cpes=(false))` | A list of `risk:vuln` nodes. |
| `countCves(cpe23=(null), product=(null), kev=(false), start=(null), end=(null))` | The number of matching CVEs, or null. |
| `bannerHash(banner)` | Shodan's hash of an `inet:banner` node or of banner text, or null. |
| `fileHash(file, kind=(null))` | `{"kind": "favicon"\|"html", "hash": <n>}` for a `file:bytes` in the Axon, or null. |
| `searchQuery(n, filehash=(null))` | The query for a node (see [Commands](commands.md#queries-built-from-nodes)), or null. |
| `trendsQuery(n, filehash=(null))` | The `searchQuery()`, if Trends supports all of its filters, or null. |
| `streamTarget(n)` | `{"kind": <stream type>, "value": <str>}` for a node, or null. |
| `hostIp(n)` | The IP to look up for a node, as a string, or null. |
| `enrich(node)` | A list of the nodes `slib.shodan.enrich` makes for a node. |
| `enrichKey(node)` | The lookup key `enrich()` makes for a node, ex. `cve:CVE-2021-44228`, or null. |
| `quote(valu)` | A value quoted for a search filter, with `"` and `,` escaped. |
| `storedQueries(match=(null))` | Yields the stored saved query `meta:rule` nodes, optionally matching a text. |
| `saveQuery(query, name, desc=(null))` | The local `meta:rule`. Raises `BadArg` for an empty query. |
| `isQueryRule(rule)`, `isCommunityRule(rule)` | Whether a `meta:rule` is a saved query, or a community one. |
| `isStored(q)` | Whether a directory query is already a community `meta:rule`. |
| `searchUrl()`, `countUrl()` | The public `:api:url` of the search and count endpoints. |
| `maxFileHashSize()` | `16777216`, the largest file hashed. |
| `trendsFilters()` | The filters Trends supports. |

### slib.shodan.model

The modeling functions take the normalized dicts the service returns. The main ones:

| Function | Models | Returns |
| --- | --- | --- |
| `host(h, tagPrefix=(null), timeline=(false))` | A `normHost`/`normInternetDb` dict | The IP node |
| `historyBanners(h, tagPrefix=(null), timeline=(false))` | A history lookup's banners, as historical | The IP node |
| `bannerNodes(b, tagPrefix=(null), historical=(false))` | A `normBanner` dict | `{"server", "banner", "ip"}`, or null |
| `banner(b, tagPrefix=(null))` | A `normBanner` dict | The `inet:server` |
| `cve(c, tagPrefix=(null), cpes=(false))` | A `normCve` dict | The `risk:vuln` |
| `dnsRecordNode(rec)` | A `normDnsRecords` item | The record node |
| `queryNode(text, apiurl, opts, ref=(null))` | A query run | The `it:exec:query` |
| `found(query, nodes)` | `-(found)>` edges | nothing |
| `communityRule(q, tagPrefix=(null))`, `localRule(text, name, desc=(null))` | Saved queries | The `meta:rule` |
| `timelineNode(ipnode)`, `eventNode(timeline, b, res)` | Host history | The node |
| `seen(n, time=(null))` | The `meta:source -(seen)>` edge and `.seen` | The node |

Smaller helpers (`ipNode`, `fqdnNode`, `asnNode`, `orgNode`, `serverNode`, `certNode`,
`softverNode`, `httpNodes`, `fileNode`, ...) each make one kind of node. `nodes(items)` yields
the non-null nodes of a list, for `divert`.

### slib.shodan.util

| Function | Purpose |
| --- | --- |
| `isIpv6(ip)` | True when the value doesn't cast to `inet:ipv4`. |
| `splitArg(arg)` | Split `name=value` into a list, or null without a `=`. |
| `failed(retn, what)` | Warn `slib.shodan: <what> failed: <mesg>` and return true when `retn.status` is false. |
| `table(columns, rows)` | Print a table with `$lib.tabular.printer()`. `columns` is a list of `(name, width)`. |
| `printFacets(facets)` | Print Shodan's `{facet: [{"value", "count"}]}` as tables. |
| `printJson(valu)` | Print a value as indented JSON. |

### The priv modules

Each function returns the service's `{status, mesg, data}` dict as-is, or emits them for
generators. They map onto the Telepath methods below:

| Module | Functions |
| --- | --- |
| `slib.shodan.priv.user` | `userKey()`, `hasKey()`, `tagPrefix()` (the prefix, or null when tagging is off), `host`, `count`, `countIps`, `search`, `searchGenr`, `bannerHash`, `fileHash`, `searchFacets`, `searchFilters`, `searchTokens`, `ports`, `protocols`, `services`, `alertTriggers`, `notifierProviders`, `profile`, `apiInfo`, `myip`, `httpHeaders`, `dnsDomain` (calls `dnsDomainAll`), `dnsResolve`, `dnsReverse`, `queries`, `queriesSearch`, `queriesTags`, `trendsSearch`, `trendsFacets`, `trendsFilters`, `internetdb` (calls `normInternetDb`), `vuln` (calls `normVuln`), `cves`, `cpes`, `apiUrl` (returns the URL, not a retn), `streamUrl`, `stream` |
| `slib.shodan.priv.scan` | `scan`, `scanInternet`, `scans`, `scanStatus` |
| `slib.shodan.priv.alert` | `alertCreate`, `alertEdit`, `alertInfo`, `alertDelete`, `alertTriggerEnable`, `alertTriggerDisable`, `alertTriggerIgnore`, `alertTriggerUnignore`, `alertNotifierAdd`, `alertNotifierDel`, `notifiers`, `notifierCreate`, `notifierGet`, `notifierEdit`, `notifierDelete` |
| `slib.shodan.priv.admin` | `setApiKey`, `hasApiKey`, `tagSettings()`, `setTagPrefix(prefix)`, `setTagsEnabled(enabled)`, `datasets`, `datasetFiles`, `org`, `orgMemberAdd`, `orgMemberDel`, `rawRequest` |

`priv.user.host()` calls the service's `normHost`, and `priv.user.search()` defaults
`minify=(false)` (the service defaults it to true).

## Telepath API

`ShodanCellApi` ({src}`svcs/shodan/src/shodansvc/api.py`) subclasses `stormlibpp.svc.RetnApi`,
`synapse.lib.cell.CellApi` and `synapse.lib.stormsvc.StormSvc`. For each name in `RETN_METHS`,
`RetnApi` generates a method that calls the `ShodanSvc` method with the same name and
arguments and wraps the result. For each name in `GENR_METHS`, it wraps every item the
generator yields.

### TelepathRetn

Every method returns (or yields) a `TelepathRetn` dict
(see the [StormLib++ docs](https://docs.gormo.co/stormlibpp/)):

| Key | Meaning |
| --- | --- |
| `status` | `true` when the call worked. |
| `mesg` | The error message when `status` is false, else `""` (or a message for `setApiKey`). |
| `data` | The result. `null` on errors. |

Errors never raise to Storm. `RetnApi._retnErr()` turns any exception into a `status=false`
retn:

| Exception | `mesg` |
| --- | --- |
| `ShodanApiError` (the only `RETN_ERRORS` type, including its subclass `NoApiKeyError`) | Its own message, ex. `Invalid API key`, `HTTP 503`, `No Shodan API key is configured. ...` |
| Synapse `AuthDeny` | Its own message |
| `ValueError`, `TypeError`, `BadArg` | `Invalid input: <message>` |
| Anything else | `Unexpected error: <Type>: <message>`, logged with its traceback |

`ShodanCellApi` doesn't override `_retnRedact()`, so messages are returned unchanged.

A generator yields one `status=true` retn per item. An error ends it after one final
`status=false` retn.

### Methods

`apikey` is optional on every keyed method. It's the caller's key, and the service falls back
to its stored key and then `shodan:apikey` (`getApiKey()`). Raw methods return Shodan's JSON
as-is. "norm" methods return the dicts described in [normalized shapes](#normalized-shapes).

#### Keys

| Method | Returns `data` |
| --- | --- |
| `setApiKey(apikey)` | `true`. Stores the key, or removes it when `apikey` is null or empty. `mesg` is `Set the slib.shodan API key.` or `Cleared the slib.shodan API key.` |
| `hasApiKey()` | Whether a stored or configured key exists (ignores user keys). |

#### Search

| Method | Endpoint | Returns `data` |
| --- | --- | --- |
| `host(ip, history=False, minify=False, apikey=None)` | `GET /shodan/host/{ip}` | Raw host |
| `normHost(ip, history=False, minify=False, apikey=None)` | same | `normHost` dict |
| `count(query, facets=None, apikey=None)` | `GET /shodan/host/count` | Raw `{"total", "facets"}` |
| `countIps(query, size=None, facets=None, apikey=None)` | same, with the `ip` facet | `{"ips": [str], "size": int, "limit": int\|null, "full": bool, "lowered": bool, "facets": {...}}` |
| `search(query, page=1, facets=None, minify=True, fields=None, apikey=None)` | `GET /shodan/host/search` | Raw page, `{"total", "matches", "facets"}` |
| `searchGenr(query, limit=100, minify=True, page=1, apikey=None)` | same, paged | Generator of `normBanner` dicts |
| `searchFacets(apikey=None)` | `GET /shodan/host/search/facets` | List of names |
| `searchFilters(apikey=None)` | `GET /shodan/host/search/filters` | List of names |
| `searchTokens(query, apikey=None)` | `GET /shodan/host/search/tokens` | Raw |
| `bannerHash(text)` | none | Signed 32-bit MurmurHash3 of the UTF-8 text |
| `fileHash(chunks, kind)` | none | The `favicon` or `html` hash of the joined byte chunks. Another `kind` is a `ShodanApiError`. |

#### Scanning

| Method | Endpoint | Returns `data` |
| --- | --- | --- |
| `ports(apikey=None)` | `GET /shodan/ports` | List of ports |
| `protocols(apikey=None)` | `GET /shodan/protocols` | `{name: description}` |
| `services(apikey=None)` | `GET /shodan/services` | `{port: name}` |
| `scan(ips, force=False, apikey=None)` | `POST /shodan/scan`, form body | `{"id", "count", "credits_left"}`. `ips` is a list of IPs/CIDRs (comma joined) or a dict `{ip: [[port, protocol], ...]}` (sent as JSON). |
| `scanInternet(port, protocol, apikey=None)` | `POST /shodan/scan/internet`, form body | `{"id"}` |
| `scans(page=1, apikey=None)` | `GET /shodan/scans` | `{"total", "matches"}`, without any `api_key` |
| `scanStatus(scanid, apikey=None)` | `GET /shodan/scan/{id}` | `{"id", "status", "count", "created"}`, without `api_key` |

#### Network alerts and notifiers

| Method | Endpoint |
| --- | --- |
| `alertCreate(name, ips, expires=0, apikey=None)` | `POST /shodan/alert`, JSON `{"name", "filters": {"ip": [...]}, "expires"}` |
| `alertEdit(aid, ips, apikey=None)` | `POST /shodan/alert/{id}`, JSON `{"filters": {"ip": [...]}}` |
| `alertInfo(aid=None, include_expired=True, apikey=None)` | `GET /shodan/alert/{id}/info`, or `GET /shodan/alert/info` without `aid` |
| `alertDelete(aid, apikey=None)` | `DELETE /shodan/alert/{id}` |
| `alertTriggers(apikey=None)` | `GET /shodan/alert/triggers` |
| `alertTriggerEnable(aid, trigger, apikey=None)` | `PUT /shodan/alert/{id}/trigger/{trigger}` |
| `alertTriggerDisable(aid, trigger, apikey=None)` | `DELETE /shodan/alert/{id}/trigger/{trigger}` |
| `alertTriggerIgnore(aid, trigger, service, apikey=None)` | `PUT /shodan/alert/{id}/trigger/{trigger}/ignore/{service}`. `service` must be `<ip>:<port>` |
| `alertTriggerUnignore(aid, trigger, service, apikey=None)` | `DELETE` of the same path |
| `alertNotifierAdd(aid, nid, apikey=None)` | `PUT /shodan/alert/{id}/notifier/{nid}` |
| `alertNotifierDel(aid, nid, apikey=None)` | `DELETE /shodan/alert/{id}/notifier/{nid}` |
| `notifiers(apikey=None)` | `GET /notifier` |
| `notifierProviders(apikey=None)` | `GET /notifier/provider` |
| `notifierCreate(provider, args, desc=None, apikey=None)` | `POST /notifier`, form body of `args` plus `provider` and `description` |
| `notifierGet(nid, apikey=None)` | `GET /notifier/{id}` |
| `notifierEdit(nid, args, apikey=None)` | `PUT /notifier/{id}`, `args` as query params |
| `notifierDelete(nid, apikey=None)` | `DELETE /notifier/{id}` |

These return Shodan's JSON as-is.

#### Directory, bulk data, organization, account

| Method | Endpoint | Returns `data` |
| --- | --- | --- |
| `queries(page=1, sort="timestamp", order="desc", pages=1, apikey=None)` | `GET /shodan/query`, `pages` pages from `page` | `{"total", "matches"}`, every page's matches |
| `queriesSearch(query, page=1, pages=1, apikey=None)` | `GET /shodan/query/search` | `{"total", "matches", "fallback": null}`, or on a 5xx `{"total", "matches", "fallback": <Shodan's error>, "scanned": <n>, "directoryTotal": <n>}` |
| `queriesTags(size=10, apikey=None)` | `GET /shodan/query/tags` | Raw |
| `datasets(apikey=None)` | `GET /shodan/data` | Raw list |
| `datasetFiles(dataset, apikey=None)` | `GET /shodan/data/{dataset}` | Raw list |
| `org(apikey=None)` | `GET /org` | Raw |
| `orgMemberAdd(user, notify=True, apikey=None)` | `PUT /org/member/{user}` | Raw |
| `orgMemberDel(user, apikey=None)` | `DELETE /org/member/{user}` | Raw |
| `profile(apikey=None)` | `GET /account/profile` | Raw |
| `apiInfo(apikey=None)` | `GET /api-info` | Raw |
| `myip(apikey=None)` | `GET /tools/myip` | The IP string |
| `httpHeaders(apikey=None)` | `GET /tools/httpheaders` | Raw |
| `rawRequest(method, path, base="api", params=None, json_data=None, apikey=None, form=None)` | Any. `base` is `api`, `stream`, `trends`, `internetdb` or `cvedb` | Raw |

#### DNS and Trends

| Method | Endpoint | Returns `data` |
| --- | --- | --- |
| `dnsDomain(domain, history=False, rtype=None, page=1, apikey=None)` | `GET /dns/domain/{domain}` | One raw page |
| `dnsDomainAll(domain, history=False, rtype=None, maxpages=10, apikey=None)` | same, paged | `{"domain", "tags", "subdomains": [sorted], "records": [normDnsRecords], "more": bool}`. `maxpages=0` reads every page. |
| `dnsResolve(hostnames, apikey=None)` | `GET /dns/resolve` | `{hostname: ip}` |
| `dnsReverse(ips, apikey=None)` | `GET /dns/reverse` | `{ip: [hostnames]}` |
| `trendsSearch(query, facets=None, apikey=None)` | `GET trends:/api/v1/search` | `{"total", "matches": [{"month", "count"}], "facets": {facet: [{"key": <month>, "values": [...]}]}}` |
| `trendsFacets(apikey=None)` | `GET trends:/api/v1/search/facets` | List |
| `trendsFilters(apikey=None)` | `GET trends:/api/v1/search/filters` | List |

#### InternetDB and CVEDB (no key)

| Method | Endpoint | Returns `data` |
| --- | --- | --- |
| `internetdb(ip)` | `GET internetdb:/{ip}` | Raw `{"ip", "ports", "hostnames", "cpes", "vulns", "tags"}` |
| `normInternetDb(ip)` | same | `normHost`-shaped dict |
| `cve(cveid)` | `GET cvedb:/cve/{ID}` (upper case) | Raw |
| `normCve(cveid)` | same | `normCve` dict |
| `ghsa(ghsaid)`, `euvd(euvdid)` | `GET cvedb:/ghsa/{ID}`, `/euvd/{ID}` | Raw |
| `normVuln(vulnid)` | `/ghsa`, `/euvd` or `/cve` by prefix | `normCve`-shaped dict |
| `cves(cpe23=None, product=None, is_kev=False, sort_by_epss=False, skip=0, limit=1000, start_date=None, end_date=None, count=False)` | `GET cvedb:/cves` | `{"cves": [normCve]}`, or `{"total": n}` with `count` |
| `cpes(product, skip=0, limit=1000, count=False)` | `GET cvedb:/cpes` | `{"cpes": [padded CPE 2.3]}`, or `{"total": n}` |

#### Streams and provenance

| Method | Returns `data` |
| --- | --- |
| `stream(kind="banners", values=None, query=None, aid=None, limit=100, timeout=60, apikey=None)` | Generator of `normBanner` dicts from the Streaming API (see {ref}`shodan-cmd-stream`). `values` is a list or a comma separated string. |
| `streamUrl(kind="banners", values=None, query=None, aid=None)` | The stream's public URL, without the key |
| `apiUrl(path, base="api")` | `<public base URL><path>` |

### Normalized shapes

`normBanner` (from `searchGenr()`, `stream()`, and each item of `normHost()["banners"]`):

```json
{
  "ip": "8.8.8.8", "port": 443, "transport": "tcp",
  "timestamp": "2026-10-01T12:00:00.000000",
  "module": "https", "crawler": "xyz", "id": "abc", "scan": null, "region": null,
  "truncated": [], "hash": -1234, "product": "nginx", "version": "1.25.3",
  "info": null, "os": null,
  "cpes": ["cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*", "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"],
  "softvers": [{"cpe": "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*", "product": "nginx", "version": "1.25.3"},
               {"cpe": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", "product": null, "version": null}],
  "data": "HTTP/1.1 200 OK\r\nServer: nginx\r\n...",
  "http_headers": [{"name": "server", "value": "nginx"}, {"name": "content-type", "value": "text/html"}],
  "hostnames": ["dns.google"], "domains": ["dns.google"], "tags": ["cdn"],
  "vulns": [{"cve": "CVE-2021-44228", "cvss": 10.0, "verified": false, "summary": "Log4Shell"}],
  "asn": "AS15169", "org": "Google LLC", "isp": null,
  "location": {"city": "Mountain View", "region": "CA", "country": "United States",
               "country_code": "us", "lat": 37.4056, "lon": -122.0775, "latlong": [37.4056, -122.0775]},
  "cert": {"sha256": "...", "sha1": "...", "subject": "CN=dns.google", "subject_cn": "dns.google",
           "issuer": "CN=GTS CA 1C3, O=Google Trust Services", "issuer_cn": "GTS CA 1C3",
           "serial": "499602d2", "notbefore": "2026/09/01 00:00:00", "notafter": "2026/12/01 00:00:00",
           "selfsigned": false, "sigalg": "sha256WithRSAEncryption", "version": 2, "expired": null,
           "jarm": "...", "ja3s": null, "versions": ["TLSv1.2", "TLSv1.3"]},
  "tls": {"jarm": "29d29d00029d29d00041d41d0000005", "ja3s": null},
  "http": {"url": "https://dns.google/", "host": "dns.google", "path": "/", "status": 200, "...": "..."},
  "ssh": null
}
```

- `http` (from `normHttp()`, or null) has `url`, `host` (null for an IP), `path`, `status`,
  `reason`, `headers`, `title`, `server`, `favicon` (Shodan's favicon hash), `body` (a file),
  `redirects` (each with `url`, `host`, `path`, `status`, `reason`, `headers`, `body`), `files`
  and `listing` (open directory URLs). Each file (`normFile()`) is `{"kind", "url", "local",
  "name", "mime", "b64", "size", "md5", "sha1", "sha256", "sha512"}`, where `b64` is the bytes
  as base64.
- `ssh` is `{"type", "fingerprint", "key", "pubkey"}` or null. `pubkey` is `{"text", "algo",
  "size", "md5", "sha1", "sha256", "sha512"}` or null.

`normHost` (from `normHost()` and `normInternetDb()`):

```json
{
  "ip": "8.8.8.8", "asn": "AS15169", "org": "Google LLC", "isp": "Google LLC", "os": null,
  "last_update": "2026-10-01T12:00:00.000000",
  "hostnames": ["dns.google"], "domains": ["dns.google"], "tags": ["cloud", "honeypot"],
  "ports": [53, 443], "tcp_ports": [443], "cpes": [],
  "vulns": [{"cve": "CVE-2021-44228", "cvss": 10.0, "verified": false, "summary": "Log4Shell"}],
  "location": {"...": "..."},
  "banners": [{"...": "normBanner"}]
}
```

InternetDB results have `asn`, `org`, `isp`, `os`, `last_update` and `location` null, no
`domains` or `banners`, and InternetDB's `cpes`.

`normCve` (from `normCve()`, `normVuln()` and `cves()`), here for `normVuln("GHSA-jfh8-c2jp-5v3q")`,
an advisory CVEDB links to a CVE:

```json
{
  "cve": "CVE-2021-44228", "aliases": ["EUVD-2021-34768", "GHSA-JFH8-C2JP-5V3Q"],
  "summary": "Apache Log4j2 JNDI features ...", "cvss": 10.0, "cvss_version": 3.0,
  "cvss_v2": 9.3, "cvss_v3": 10.0, "cvss_v4": null, "cvss_scores": {"v2_0": 9.3, "v3_1": 10.0},
  "epss": 0.99999, "ranking_epss": 1.0, "kev": true,
  "propose_action": null, "ransomware_campaign": "Known",
  "references": ["https://logging.apache.org/log4j/2.x/security.html",
                 "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
  "published": "2021-12-10T10:15:09",
  "cpes": ["cpe:2.3:a:apache:log4j:2.0:-:*:*:*:*:*:*"],
  "cwes": ["CWE-20", "CWE-502"]
}
```

A plain CVE lookup has the linked GHSA/EUVD IDs (if any) as `aliases` and no `cwes`. An
advisory lookup adds its own ID and linked IDs to `aliases` (sorted), merges the references,
and sets `cwes` from `cwe_ids`. An advisory without a CVE has `cve` set to `""` and the
advisory's own details.

`normDnsRecords` items are `{"fqdn", "type" (upper case), "value", "seen"}`.
