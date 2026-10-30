# shodan

A Synapse Advanced Power-Up (Storm Service) that integrates every Shodan API into Synapse:
host lookups, search, on-demand scanning, network alerts and notifiers, DNS, the Streaming
API, the directory of saved queries, bulk data, organization management, Trends, and the
free InternetDB and CVEDB APIs.

Two Shodan APIs have been retired and aren't supported:

- The Exploits API (`exploits.shodan.io`) now redirects to CVEDB. Use `slib.shodan.cve`.
- The Honeyscore API (`/labs/honeyscore`) was folded into Shodan's crawlers. Likely honeypots
  get Shodan's `honeypot` tag, which `slib.shodan.host` applies as `#rep.shodan.honeypot`.

The service registers the `slib.shodan` Storm package. Everything is namespaced under `slib.shodan`.

## Deploying

The service is published as `ghcr.io/gormaniac/stormsvcs/shodan`.

```bash
docker run -d --name slib-shodan \
    -v /srv/slib-shodan:/vertex/storage \
    -e SYN_SHODANSVC_SHODAN_APIKEY=<optional service-wide key> \
    -p 27492:27492 \
    ghcr.io/gormaniac/stormsvcs/shodan:latest
```

Then add it to a Cortex:

```
service.add slib.shodan tcp://<user>:<passwd>@<host>:27492/*
```

### Configuration

| Option | Env var | Default | Description |
|---|---|---|---|
| `shodan:apikey` | `SYN_SHODANSVC_SHODAN_APIKEY` | none | Fallback API key, see [API keys](#api-keys). |
| `shodan:ratelimit` | `SYN_SHODANSVC_SHODAN_RATELIMIT` | `1.0` | Max requests/second to the API key based APIs (Shodan allows 1/s). |
| `shodan:timeout` | `SYN_SHODANSVC_SHODAN_TIMEOUT` | `60` | Seconds before a single request times out. |
| `shodan:urls` | `SYN_SHODANSVC_SHODAN_URLS` | Shodan's | Override base URLs (`api`, `stream`, `trends`, `internetdb`, `cvedb`). |

The service honors the standard `HTTP(S)_PROXY` environment variables.

## API keys

Keys are resolved in this order, per request:

1. **The calling user's own key** - set with `slib.shodan.apikey <key>`. It's stored in a
   user scoped Synapse vault (type `shodan`), so it is only ever used for that user's requests.
2. **The service-wide key** - set with `slib.shodan.admin.apikey <key>`. It's stored by the
   service, not the Cortex, so it can't be read back from Storm.
3. **The `shodan:apikey` config option.**

When no key is available, `slib.shodan.host` falls back to InternetDB. The InternetDB and
CVEDB APIs never need a key.

## Permissions

| Permission | Grants |
|---|---|
| `slib.shodan.user` | Lookups, search, DNS, CVEs, trends, streams, and setting your own key. |
| `slib.shodan.scan` | On-demand scans (uses scan credits). |
| `slib.shodan.alert` | Network alerts and notifiers. |
| `slib.shodan.admin` | The service-wide key, tag settings, organization, bulk data, and raw API requests. |

Users don't need the `service.get` permission. The `slib.shodan.priv.*` modules talk to the
service and elevate privileges only for users that hold the matching permission. Users still
need the normal node permissions for the nodes the commands create.

## Commands

| Command | Description |
|---|---|
| `slib.shodan.host` | Look up IPs and model everything Shodan knows (ASN, location, hostnames, tags, vulns, every banner). `--history`, `--minify`, `--internetdb`. |
| `slib.shodan.enrich` | Enrich any supported node with the best API: IPs → host, `inet:fqdn` → DNS, `risk:vuln`/`it:sec:cve` → CVEDB, `it:sec:cpe` → CVEs. |
| `slib.shodan.search` | Search Shodan, model each banner, and yield the IPs. `--count` and `--facets` are free, `--tokens` explains a query, `--filters` lists filters/facets. |
| `slib.shodan.stream` | Read banners from the Streaming API (`banners`, `asn`, `countries`, `ports`, `tags`, `vulns`, `custom`, `alert`) for `--limit` banners or `--timeout` seconds. |
| `slib.shodan.dns.domain` | Model every DNS record and subdomain Shodan knows for a domain. |
| `slib.shodan.dns.lookup` | Resolve `inet:fqdn`s and reverse-resolve IPs. |
| `slib.shodan.cve` | Model CVEDB details (CVSS, KEV, references, linked GHSA/EUVD IDs) on `risk:vuln`s. Accepts CVE, GHSA, and EUVD IDs. Search by `--cpe`/`--product` with `--kev`, `--epss`, `--start`, `--end`, `--count`. |
| `slib.shodan.cpe` | Search CVEDB for a product's CPEs. |
| `slib.shodan.trends` | Monthly historical breakdown of a query, with `--facets`. |
| `slib.shodan.queries` | Browse/search the saved query directory and its tags. |
| `slib.shodan.info` | Account, plan, remaining credits, and the service's public IP. |
| `slib.shodan.ref` | Reference data: `ports`, `protocols`, `services`, `filters`, `facets`, `triggers`, `providers`, `httpheaders`. |
| `slib.shodan.apikey` | Set/clear your own API key. |
| `slib.shodan.scan` | Scan inbound IPs/CIDRs as one scan. `--wait` polls until it's done, then ingests the results. |
| `slib.shodan.scan.status` | List your scans, or check one. |
| `slib.shodan.scan.internet` | Request an Internet-wide scan of a port/protocol. |
| `slib.shodan.alert.list` | List alerts, or show one. |
| `slib.shodan.alert.add` | Create an alert for the inbound IPs/CIDRs, enabling `--trigger`s and attaching `--notifier`s in one step. |
| `slib.shodan.alert.edit` | Replace/`--append` IPs, `--enable`/`--disable` triggers, `--ignore`/`--unignore` services, and add/remove notifiers in one step. |
| `slib.shodan.alert.del` | Delete alerts. |
| `slib.shodan.notifier.list` / `.add` / `.edit` / `.del` | Manage notifiers. |
| `slib.shodan.admin.apikey` | Set/clear/check the service-wide key. |
| `slib.shodan.admin.tags` | Set the tag `--prefix` (default `rep.shodan`), `--enable` or `--disable` tagging. |
| `slib.shodan.admin.org` | Show the organization, or `--add`/`--remove` members. |
| `slib.shodan.admin.data` | List bulk datasets and their files. |
| `slib.shodan.admin.request` | Send a raw request to any Shodan API, for anything not covered above. |

Run any command with `--help` for all of its options and examples.

### Examples

```
// Everything Shodan knows about some IPs. Likely honeypots get Shodan's honeypot tag (#rep.shodan.honeypot).
inet:ipv4#my.tag | slib.shodan.host

// Ingest the first 200 nginx servers in the US, then look at their certs.
slib.shodan.search "product:nginx country:US" --limit 200 | -> inet:server -> inet:tls:servercert -> crypto:x509:cert

// Monitor a netblock and get emailed about new services and vulns.
inet:cidr4=1.2.3.0/24 | slib.shodan.alert.add corp --trigger new_service --trigger vulnerable --notifier default

// Enrich vulns with CVSS/KEV data from CVEDB.
risk:vuln:cve | slib.shodan.cve
```

The `slib.shodan.lib` module can also be used directly from Storm:

```
$shodan = $lib.import(slib.shodan.lib)
$ipnode = $shodan.host(8.8.8.8, history=(true))
$vulns = $shodan.cves(product=log4j, kev=(true))
```

## Data model

| Shodan data | Synapse |
|---|---|
| IP, ASN, org, location | `inet:ipv4`/`inet:ipv6` (`:asn`, `:latlong`, `:loc`), `inet:asn:owner` → `ou:org` |
| Hostnames | `inet:dns:a`/`inet:dns:aaaa` |
| Services and banners | `inet:server`, `inet:banner` |
| Products and CPEs | `it:prod:softver` (`:cpe`, `:name`, `:vers`), with `inet:server -(uses)> it:prod:softver` |
| Vulnerabilities | `risk:vuln` (via `$lib.gen.vulnByCve`), `risk:vulnerable` for the IP and the server |
| TLS certificates | `crypto:x509:cert` (deconflicted by `:sha256`), `inet:tls:servercert` |
| DNS records | `inet:dns:a/aaaa/cname/mx/ns/txt/soa` |
| CVEDB | `risk:vuln` `:cve:desc`, `:cve:references`, `:cvss:v3_1:score`, `:cvss:v2_0:score`, `:timeline:published`, GHSA/EUVD IDs in `:names`, GHSA CWEs in `:cwes`; `it:prod:softver:cves` with `--cpes`. Advisories without a CVE are deconflicted by `risk:vuln:id`. |
| Shodan tags, CISA KEV | Tags under the prefix, ex. `#rep.shodan.cloud`, `#rep.shodan.honeypot`, `#rep.shodan.kev` |

Every node is linked to the service's `meta:source` with a `-(seen)>` edge, and has `.seen`
updated from Shodan's timestamps.

## Shodan API coverage

Every Shodan API endpoint is available through a command, and all of them are methods on
the service (`$lib.service.get(slib.shodan)`, for those with `service.get`).

| Endpoint | Storm |
|---|---|
| `GET /shodan/host/{ip}` | `slib.shodan.host`, `slib.shodan.enrich` |
| `GET /shodan/host/count` | `slib.shodan.search --count/--facets` |
| `GET /shodan/host/search` | `slib.shodan.search` |
| `GET /shodan/host/search/facets`, `/filters` | `slib.shodan.search --filters`, `slib.shodan.ref facets/filters` |
| `GET /shodan/host/search/tokens` | `slib.shodan.search --tokens` |
| `GET /shodan/ports`, `/protocols`, `/services` | `slib.shodan.ref ports/protocols/services` |
| `POST /shodan/scan`, `GET /shodan/scan/{id}` | `slib.shodan.scan` (`--wait` polls the status) |
| `POST /shodan/scan/internet` | `slib.shodan.scan.internet` |
| `GET /shodan/scans`, `/shodan/scan/{id}` | `slib.shodan.scan.status` |
| `POST /shodan/alert`, `PUT .../trigger/{t}`, `PUT .../notifier/{id}` | `slib.shodan.alert.add` |
| `GET /shodan/alert/info`, `/shodan/alert/{id}/info` | `slib.shodan.alert.list` |
| `POST /shodan/alert/{id}`, `PUT/DELETE .../trigger/{t}`, `.../ignore/{svc}`, `.../notifier/{id}` | `slib.shodan.alert.edit` |
| `DELETE /shodan/alert/{id}` | `slib.shodan.alert.del` |
| `GET /shodan/alert/triggers` | `slib.shodan.ref triggers` |
| `GET /notifier`, `/notifier/{id}` | `slib.shodan.notifier.list` |
| `GET /notifier/provider` | `slib.shodan.ref providers` |
| `POST /notifier`, `PUT /notifier/{id}`, `DELETE /notifier/{id}` | `slib.shodan.notifier.add/edit/del` |
| `GET /shodan/query`, `/query/search`, `/query/tags` | `slib.shodan.queries` |
| `GET /shodan/data`, `/shodan/data/{dataset}` | `slib.shodan.admin.data` |
| `GET /org`, `PUT/DELETE /org/member/{user}` | `slib.shodan.admin.org` |
| `GET /account/profile`, `/api-info`, `/tools/myip` | `slib.shodan.info` |
| `GET /tools/httpheaders` | `slib.shodan.ref httpheaders` |
| `GET /dns/domain/{domain}` | `slib.shodan.dns.domain`, `slib.shodan.enrich` |
| `GET /dns/resolve`, `/dns/reverse` | `slib.shodan.dns.lookup` |
| Streaming API (all streams) | `slib.shodan.stream` |
| Trends API (`/api/v1/search`, `/facets`, `/filters`) | `slib.shodan.trends` |
| InternetDB (`/{ip}`) | `slib.shodan.host --internetdb` (or no API key) |
| CVEDB (`/cve/{id}`, `/ghsa/{id}`, `/euvd/{id}`, `/cves`, `/cpes`) | `slib.shodan.cve`, `slib.shodan.cpe`, `slib.shodan.enrich` |
| Anything else | `slib.shodan.admin.request` |

## Development

```bash
cd svcs/shodan
uv sync --dev
uv run pytest
```

The tests run a real Cortex with the service added, pointed at a fake Shodan HTTP server
(`tests/fakeshodan.py`), so no API key or network access is needed.

### Live tests

`tests/test_live.py` runs against the real Shodan APIs and is skipped by default:

```bash
# Keyless APIs only (InternetDB and CVEDB), no account needed.
SLIB_SHODAN_LIVE=1 uv run pytest tests/test_live.py

# Also the keyed APIs. Only uses free endpoints and one host lookup, never scan credits.
SLIB_SHODAN_LIVE=1 SHODAN_API_KEY=<key> uv run pytest tests/test_live.py
```

Notes from verifying the service against the live APIs (2026-10):

- **Requests with a malformed key.** `GET /shodan/host/{ip}` and `GET /shodan/ports` returned
  full, real data with a made-up key (ex. `?key=invalidkey000`), while `/api-info` returned a
  401 HTML page. Those two endpoints were used to check real host/banner responses against
  `norm.py` (it matched: short `cpe23` lists, banner `vulns` as a dict, host `vulns` as a list,
  `ssl`/`ssh`/`http` blocks). Don't rely on this; it is undocumented Shodan behavior and the
  live tests use a real key for these endpoints.
- **Network secrets in a Claude Code cloud environment.** A "body parameter" network secret for
  `api.shodan.io` is only injected into POSTs with a form-encoded body. Nearly every Shodan read
  endpoint is a GET that requires `?key=` in the URL, so with that secret configured every GET to
  `api.shodan.io` fails at the proxy (`502 injection failed`), even with an explicit key. Use an
  environment variable (`SHODAN_API_KEY`) for live tests instead.
- **Errors.** Most endpoints return `{"error": ...}` JSON, a bad key returns a 401 HTML page, and
  the Streaming API wraps that HTML page in JSON. `client.errMesg()` handles all three.
- **InternetDB** returns a 404 for IPs it hasn't seen, but some private IPs (ex. `10.0.0.1`) do
  have data.
- **CVEDB** returns shortened CPE 2.3 strings, IDs are case-insensitive, and GHSA references
  are `{"type": ..., "url": ...}` objects instead of strings.

Layout:

- `src/shodansvc/client.py` - The HTTP transport shared by every Shodan API (keys, rate limiting, retries, errors, streams).
- `src/shodansvc/svc.py` - `ShodanSvc`, with a method per Shodan endpoint.
- `src/shodansvc/api.py` - `ShodanCellApi`, the Telepath API. Wraps every method in a `TelepathRetn`.
- `src/shodansvc/norm.py` - Flattens Shodan's responses into dicts that are easy to model in Storm.
- `src/shodansvc/pkgproto/` - The `slib.shodan` Storm package.
