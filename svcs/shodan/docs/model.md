# Data model

The service normalizes Shodan's responses into flat dicts ({src}`svcs/shodan/src/shodansvc/norm.py`),
and the `slib.shodan.model` Storm module ({src}`svcs/shodan/src/shodansvc/pkgproto/storm/modules/slib.shodan.model.storm`)
makes the nodes, as the calling user. Values Synapse rejects are skipped (most props are set
with `?=`/`?+=`), so one bad value never fails a whole host.

## The meta:source

| | |
| --- | --- |
| Node | `meta:source=5c1b0a3d0e7f4b2e9a8c6d4f2b1e0a97` |
| `:name` | `shodan` |
| `:type` | `slib.shodan` (set by the service's `add` event) |
| `:url` | `https://www.shodan.io` (set by the `add` event) |

Nearly every node the package makes or updates is linked from the `meta:source` with a
`-(seen)>` edge (`slib.shodan.model.seen()`), including `inet:asn`, its `ou:org` owner,
`it:prod:softver`, `risk:vuln`, `it:exec:query`, timelines, events and community saved queries.
When Shodan gives a time, the node's `.seen` is updated with it:

| Time | Used for |
| --- | --- |
| A banner's `timestamp` | Every node made from the banner |
| A host's `last_update` | The IP, its ASN, reverse DNS records, vulns, and servers from bare ports |
| A DNS record's `last_seen` | The record |

InternetDB has no times, so its nodes get no `.seen`. CVEDB's publish dates are only
`risk:vuln:timeline:published`, never a `.seen`.

```text
// Everything the service has seen.
meta:source=5c1b0a3d0e7f4b2e9a8c6d4f2b1e0a97 -(seen)> *
```

## Tags

Tags are `<prefix>.<tag>`, where the prefix is the `slib:shodan:tag:prefix` global (default
`rep.shodan`). Each tag is normalized as a `syn:tag:part` with `$lib.tags.prefix()`, and
values that can't be one are skipped. When tagging is disabled (`slib:shodan:tag:enabled` is
false), no tags are applied. See {ref}`shodan-cmd-admin-tags`.

| Tag | Applied to |
| --- | --- |
| `<prefix>.<shodan tag>` | The IP, for a host's tags (Shodan's and InternetDB's, ex. `#rep.shodan.cloud`, `#rep.shodan.honeypot`) |
| `<prefix>.<shodan tag>` | The `inet:server`, for a current banner's tags (ex. `#rep.shodan.cdn`) |
| `<prefix>.<shodan tag>` | The `inet:banner`, for a historical banner's tags (ex. `#rep.shodan.self-signed`) |
| `<prefix>.<shodan tag>` | The domain's `inet:fqdn`, for `slib.shodan.dns.domain`'s tags |
| `<prefix>.kev` | `risk:vuln` nodes CVEDB marks as CISA KEV |
| `<prefix>.banner` | `file:bytes`, `inet:servfile` and `inet:urlfile` nodes extracted from banners |
| `<prefix>.query.<tag>` | Community `meta:rule` nodes, for the directory query's tags |

## Hosts and banners

A host lookup (`slib.shodan.host`, `slib.shodan.enrich`, `slib.shodan.scan --wait`) is
modeled by `slib.shodan.model.host()`. Search, count and stream results are banners, modeled
by `bannerNodes()` alone.

### The host

| Shodan field | Synapse |
| --- | --- |
| `ip_str` | `inet:ipv4` or `inet:ipv6` (IPv4-mapped strings are IPv4) |
| `asn`, `org` | `:asn` of the IP, an `inet:asn` (the number without `AS`) whose `:owner` is the `ou:org` from `$lib.gen.orgByName(org)` |
| `latitude`, `longitude` | `:latlong` |
| `country_code` | `:loc`, lower case |
| `tags` | Tags on the IP |
| `hostnames` | `inet:dns:rev` (IPv4) or `inet:dns:rev6` (IPv6) of `(ip, hostname)`, lower case |
| `vulns` | `risk:vulnerable` of the IP and each CVE's `risk:vuln` (see [vulns](#vulns-from-shodan)) |
| `ports` | Only when there are no banners (minified lookups, InternetDB): a `tcp://` `inet:server` per port, see [below](#ports-without-a-transport) |
| `cpes` (InternetDB only) | `it:prod:softver` (`:cpe`), with `inet:ipv4 -(uses)> it:prod:softver` |
| `data` | Each banner, see [banners](#banners) |

`city`, `region_code`, `isp`, `os` and `domains` aren't modeled.

Shodan's hostnames come from reverse DNS and TLS/HTTP observations, not forward lookups, so
they're modeled as `inet:dns:rev`/`rev6`, never `inet:dns:a`/`aaaa`.

### Banners

| Shodan field | Synapse |
| --- | --- |
| `ip_str`, `port`, `transport` | `inet:server=<transport>://<ip>:<port>` (`tcp` when missing, IPv6 in brackets), and the IP |
| `asn`, `org` | The IP's `:asn` and owner, as for a host (not for historical banners) |
| `data` | `inet:banner=(<server>, <data>)`, the full text. Left out when Shodan truncated `data` (`metadata.truncated`), since a partial text would be a different banner. |
| `data`, HTTP status line and headers | `inet:http:response:header=(<name>, <value>)` for each header (lower case names, deduplicated, without `Date`), with `inet:banner -(refs)> inet:http:response:header` |
| `tags` | Tags on the `inet:server`, or on the `inet:banner` for a historical banner |
| `cpe23` (or `cpe`), `product`, `version` | `it:prod:softver`, with `inet:server -(uses)> it:prod:softver`, see [software](#software-and-cpes) |
| `vulns` | `risk:vulnerable` of the `inet:server` and each CVE's `risk:vuln` (not for historical banners) |
| `ssl.cert` | `crypto:x509:cert` and `inet:tls:servercert`, see [certificates](#tls-certificates-and-fingerprints) |
| `ssl.jarm`, `ssl.ja3s` | `inet:ssl:jarmsample`, `inet:tls:ja3s:sample` |
| `ssh.key` | The host key as a `file:bytes` and `inet:servfile`, see [SSH keys](#ssh-host-keys) |
| `http` | `inet:http:request`, `file:bytes`, `it:dev:str` and more, see [HTTP](#http) |
| `hostnames` | `inet:dns:rev`/`rev6` of `(ip, hostname)` |
| `timestamp` | `.seen` of every node made from the banner |

Each banner's "own" nodes are its `inet:server`, `inet:banner` and IP. Queries and timeline
events link only to these, and everything else is one hop from them.

```text
inet:ipv4=8.8.8.8 -> inet:server -> inet:banner
inet:ipv4=8.8.8.8 -> inet:server -(uses)> it:prod:softver
```

### Ports without a transport

Minified host lookups and InternetDB only list port numbers. Most are TCP, so each port is
modeled as `tcp://<ip>:<port>` (`norm.tcpPorts()`), except the ports Shodan crawls over UDP
(`norm.UDP_PORTS`), whose transport is unknown and which are skipped: 53, 67, 69, 123, 137,
161, 177, 500, 520, 623, 1194, 1434, 1604, 1812, 1900, 2123, 3283, 3478, 3671, 3702, 4500,
5060, 5093, 5351, 5353, 5683, 10001, 11211, 17185, 27015, 30718 and 47808. Banners always have
a transport, so this only applies to bare ports.

### Software and CPEs

Banners list every CPE Shodan detected (ex. `cpe:2.3:a:openbsd:openssh:6.6.1p1` and
`cpe:2.3:o:canonical:ubuntu_linux`), but `product` and `version` describe only one of them.
`norm.normSoftvers()` pairs them:

1. CPEs are padded to all 13 CPE 2.3 components with `*` (`norm.normCpe()`), CPE 2.2 URIs are
   kept as-is. `cpe23` is used, or `cpe` when there's no `cpe23`.
2. The product and version are paired with the application (`a`) CPE whose version equals the
   banner's version, or else one whose version is a prefix of it at a word boundary (ex.
   `6.6.1p1` for `6.6.1p1 Ubuntu 2ubuntu2.13`, but not `1.1` for `1.18.0`).
3. Each CPE becomes an `it:prod:softver` deconflicted by `{"cpe": <cpe>}`, and the paired one
   also gets `:name` and `:vers`.
4. When no CPE matches, the product gets its own `it:prod:softver` deconflicted by
   `{"name": <product>, "vers": <version>}`.

### TLS certificates and fingerprints

| Shodan field (`ssl`) | Synapse |
| --- | --- |
| `cert.fingerprint.sha256` | `crypto:x509:cert`, deconflicted by `{"sha256": ...}`. No SHA-256, no cert. |
| `cert.fingerprint.sha1` | `:sha1` |
| `cert.serial` | `:serial`, as a hex string when Shodan gives an integer |
| `cert.subject`, `cert.issuer` | `:subject`, `:issuer`, as `K=V, K=V` strings |
| `cert.subject.CN` | Added to `:identities:fqdns` |
| `cert.issued`, `cert.expires` | `:validity:notbefore`, `:validity:notafter` |
| `cert.subject == cert.issuer` | `:selfsigned` |
| `cert.version` | `:version` |
| (the server) | `inet:tls:servercert=(<server>, <cert>)` |
| `jarm` | `inet:ssl:jarmsample=(<server>, <jarm>)`, lower case, skipped when it's all zeros (no answer) |
| `ja3s` | `inet:tls:ja3s:sample=(<server>, <ja3s>)`, lower case |

### SSH host keys

`ssh.key` is the base64 key blob. The file is the key as OpenSSH saves it, `<algo> <base64
key>\n`, with the algorithm read from the blob (falling back to `ssh.type`), so its hashes
match `.pub` files and `ssh-keyscan` output. It's modeled as a `file:bytes` (`:mime`
`text/plain`) and an `inet:servfile` of the server and the file, both tagged
`<prefix>.banner`. Invalid keys are skipped.

### HTTP

For a banner with an `http` field, `norm.normHttp()` builds the requests Shodan made and the
files the server returned. The scheme is `https` when the banner has an `ssl` field, else
`http`. The host is `http.host` (the Host header Shodan sent), or the IP.

| Synapse | From |
| --- | --- |
| `inet:http:request` | The final response. `:server`, `:time` (the banner's timestamp), `:url` (`<scheme>://<host>[:<port>]<http.location>`, the port only when it's not 80/443), `:path`, `:header:host` (only when the host isn't an IP), `:response:code` (`http.status`, or the status line), `:response:reason`, `:response:headers` (the parsed headers), and `:response:body` (the page's `file:bytes`) |
| Another `inet:http:request` per redirect | Each `http.redirects` hop Shodan followed, with its own URL, status, headers and body |
| `it:dev:str` | `http.title`, with `inet:http:request -(refs)> it:dev:str` and `inet:banner -(refs)> it:dev:str` |
| `inet:url` | Each file and folder of an open directory (`open_dir.data`), under the page's URL, with `inet:http:request -(refs)> inet:url` |
| `file:bytes` | Every file the server returned, see below |

The files, each a `file:bytes` (`:size`, `:md5`, `:sha1`, `:sha512`, `:mime`, and `:name` from
the URL path when the node has none), an `inet:urlfile` of the URL it came from, and an
`inet:servfile` when this server returned it, all tagged `<prefix>.banner`:

| Kind | Shodan field | URL | `:mime` |
| --- | --- | --- | --- |
| The page | `http.html` | The request's URL | `Content-Type`, or `text/html` |
| robots.txt | `http.robots` | `/robots.txt` | `text/plain` |
| security.txt | `http.securitytxt` | `/.well-known/security.txt` | `text/plain` |
| Sitemap | `http.sitemap` | `/sitemap.xml` | `application/xml` |
| Favicon | `http.favicon.data` (base64) | `http.favicon.location` | From its magic bytes (PNG, ICO, GIF, JPEG, BMP, WebP, SVG), else `image/x-icon` |
| Redirect body | The body in a hop's `data` | The hop's URL | `Content-Type`, or `text/html` |

A favicon on another server (its location's host isn't the IP, the Host header or a hostname,
or its port differs) only gets the `inet:urlfile`. The bytes are saved to the Cortex's Axon
when the user has `axon.upload`, so `slib.shodan.hash` and `slib.shodan.search` can hash them.
An Axon failure is a warning, and the `file:bytes` is made either way.

```text
// The title and page hashes of each web server on an IP.
inet:ipv4=1.2.3.4 -> inet:server -> inet:http:request -(refs)> it:dev:str
inet:ipv4=1.2.3.4 -> inet:server -> inet:http:request :response:body -> file:bytes

// Web servers with an open directory listing linpeas.sh.
inet:url:path=/linpeas.sh <(refs)- inet:http:request :server -> inet:server
```

### Vulns from Shodan

Banners give `vulns` as `{"CVE-X": {"cvss": ..., "verified": ..., "summary": ...}}` and hosts
and InternetDB as `["CVE-X", ...]` (`norm.normVulns()`). Only `CVE-` IDs are kept. A host's
vulns include every banner's, with the banner's details.

Each CVE's `risk:vuln` comes from `$lib.gen.vulnByCve(<cve>)` (the existing `risk:vuln` with
that `:cve`, or a new one). Its `:desc` is set to Shodan's summary when it has none. A
`risk:vulnerable`, deconflicted by `{"node": [<form>, <value>], "vuln": <risk:vuln>}`, links it
to the IP (host vulns) or the `inet:server` (banner vulns). Shodan's `cvss` and `verified`
aren't modeled. Use `slib.shodan.cve` for CVEDB's details.

## Host history timelines

With `slib.shodan.host --history` or `--timeline`, each banner is also an event in the IP's
Shodan history:

| Node | Values |
| --- | --- |
| `meta:timeline` | Guid `(slib.shodan, history, <ip>)`, one per IP. `:type` `svc.shodan.host.history.`, `:title` `Shodan history: <ip>` and `:summary` (both only when unset), and `-(refs)>` the IP |
| `meta:event` | Guid `(slib.shodan, banner, <_shodan.id>)`, or without an ID `(slib.shodan, banner, <ip>, <port>, <transport>, <timestamp>, <hash>)`. `:timeline`, `:time` (the banner's timestamp), `:type` `svc.shodan.banner.`, `:title` and `:summary` (only when unset), and `-(refs)>` the banner's `inet:server`, `inet:banner` and IP |

The event's title is `<transport>/<port>` and the product and version, or the crawler module
without a product, ex. `tcp/22 OpenSSH 8.9p1` or `tcp/80 http`. Its summary is `On-demand scan
<id>` or `Crawler <id>`, plus `(truncated: <fields>)` when Shodan truncated fields. Analysts can
edit titles and summaries, since they're only set when unset.

Since events are keyed by Shodan's banner ID, re-running a lookup only adds new banners.
Shodan's history covers 90 days, at most the latest 1,000 banners, so re-run lookups to keep a
longer one.

```text
meta:event:time +{ :timeline -> meta:timeline +:title="Shodan history: 45.33.32.156" }
meta:event:title^="tcp/22" -(refs)> inet:banner
```

## DNS

| Command | Synapse |
| --- | --- |
| `slib.shodan.dns.domain` | `inet:dns:a`, `inet:dns:aaaa`, `inet:dns:cname`, `inet:dns:mx`, `inet:dns:ns`, `inet:dns:txt` of `(<fqdn>, <value>)`, and `inet:dns:soa` deconflicted by `{"fqdn": <fqdn>, "ns": <value>}`. `<fqdn>` is `<subdomain>.<domain>`, or the domain. `.seen` is the record's `last_seen`. Also the domain's `inet:fqdn` (tagged) and each subdomain's. |
| `slib.shodan.dns.lookup` of a hostname | `inet:dns:a`/`inet:dns:aaaa` of `(<fqdn>, <ip>)`, and the IP |
| `slib.shodan.dns.lookup` of an IP | `inet:dns:rev`/`inet:dns:rev6` and an `inet:fqdn` per hostname, and the IP's `:dns:rev` set to the first hostname |

These are the only `inet:dns:a`/`aaaa` nodes the package makes.

## Query runs

Each `slib.shodan.search`, `slib.shodan.count` and `slib.shodan.stream` run (and the
`slib.shodan.lib` `search()` and `count()` functions) is an `it:exec:query`, a new node each
run (`it:exec:query=*`):

| Prop / edge | Value |
| --- | --- |
| `:text` | The query sent to Shodan, ex. `hash:-145740310 country:US`, or a stream's `ports:443,53` |
| `:language` | `shodan` |
| `:time` | When it ran |
| `:synuser` | The user who ran it |
| `:api:url` | The public endpoint, ex. `https://api.shodan.io/shodan/host/search`, never with the key |
| `:opts` | The command's options (see each command), never with the key |
| `:offset` | The number of banners read (search, stream) or IPs (count) |
| `-(found)>` | Each banner's `inet:server`, `inet:banner` and IP, or each IP for a count |
| `-(refs)>` | The inbound node(s) the query was built from |

A query is only recorded once it has succeeded, so a failed query leaves nothing. A query that
matched nothing is still recorded.

```text
it:exec:query:time +{ -(refs)> inet:asn=15169 }
```

## Saved queries

Saved queries are `meta:rule` nodes whose `:text` is the query, of two kinds that never sync:

| | Community | Local |
| --- | --- | --- |
| Made by | `slib.shodan.queries --yield`, from Shodan's directory | `slib.shodan.query.save` |
| Guid | `(slib.shodan, query, community, <query>)` | `(slib.shodan, query, local, <query>)` |
| `:type` | `svc.shodan.query.community.` | `svc.shodan.query.local.` |
| `:name` | `[Community] <title>` (or the query, without a title). Synapse lower-cases `:name`, so ex. `[community] webcams` | The name given |
| `:desc` | The directory's description | `--desc` |
| `:created` | The directory's timestamp | When it was saved |
| `:url` | `https://www.shodan.io/search?query=<query>` | not set |
| Tags | `<prefix>.query.<tag>` for each directory tag | none |

`:name`, `:desc`, `:created` and `:url` are only set when unset, so re-copying keeps edits.
Only those two `:type` values are saved queries, the bare `svc.shodan.query.` isn't. The same
query text is a separate node for each kind.

## CVEDB vulnerabilities

`slib.shodan.cve`, `slib.shodan.enrich` and the `it:sec:cpe` lookups model CVEDB results with
`slib.shodan.model.cve()`.

| CVEDB | Synapse |
| --- | --- |
| A CVE (`cve_id`) | The `risk:vuln` from `$lib.gen.vulnByCve()`, and an `it:sec:cve` |
| A GHSA or EUVD linked to a CVE | The CVE's `risk:vuln`, with the advisory's IDs in `:names` |
| A GHSA or EUVD without a CVE | `risk:vuln` deconflicted by `{"id": <first alias>}` |
| `summary` (GHSA `summary`, EUVD `description`) | `:cve:desc`, and `:desc` when unset |
| `references` | `:cve:references` (GHSA `{"type", "url"}` objects become their URLs) |
| `published_time` | `:timeline:published` |
| CVSS scores | `:cvss:v2_0:score`, `:cvss:v3_0:score`, `:cvss:v3_1:score`, see below |
| GHSA/EUVD IDs | `:names` (upper case) |
| `cwe_ids` (advisories) | `:cwes` |
| `kev` | The `<prefix>.kev` tag |
| `cpes` (with `--cpes`) | `it:prod:softver` deconflicted by `{"cpe": <cpe>}`, with the CVE added to `:cves` |

`epss`, `ranking_epss`, `propose_action`, `ransomware_campaign` and `cvss_v4` are in the
normalized data but not modeled.

Each score goes in the prop of its CVSS version (`norm.cvssScores()`):

- `cvss_v2` is always v2.0.
- `cvss_v3` goes in the v3 prop of `cvss_version`, and `cvss` in the prop of `cvss_version`
  when `cvss_v2`/`cvss_v3` didn't already set it.
- CVEDB's own `cvss_version` is a number and only ever the major version (3.0 for any v3
  score), so a numeric 3.x is treated as 3.1, the version NVD has scored with since 2019. Its
  v3 scores go in `:cvss:v3_1:score`.
- EUVD's `cvss_version` is a string, and a GHSA's CVSS vector (ex. `CVSS:3.1/AV:N/...`), say the
  exact version.
- A GHSA without a CVE has no `cvss`. When it has exactly one v3 vector, its base score is
  computed with Synapse's CVSS calculator.
- A score without a known version, or a v4.0 score (Synapse 2.x has no prop for it), is left
  unset.

`it:sec:cpe` nodes from `slib.shodan.cpe --yield` are linked to the `meta:source`.

## Deconfliction and idempotency

Running a command again updates the same nodes instead of making new ones, except for
`it:exec:query`, which is new each run.

| Form | Deconflicted by |
| --- | --- |
| `inet:ipv4`/`6`, `inet:fqdn`, `inet:asn`, `inet:server`, `inet:banner`, `inet:dns:*`, `inet:url`, `it:dev:str`, `it:sec:cpe`, `it:sec:cve` | Their values |
| `file:bytes` | The file's SHA-256 |
| `inet:servfile`, `inet:urlfile`, `inet:tls:servercert`, `inet:ssl:jarmsample`, `inet:tls:ja3s:sample`, `inet:http:response:header` | Their comp values |
| `ou:org` | `$lib.gen.orgByName()`: the `ou:org` with that `ou:name`, or guid `(gen, name, <name>)` |
| `risk:vuln` | `$lib.gen.vulnByCve()` for CVEs, `{"id": <advisory id>}` otherwise |
| `risk:vulnerable` | `{"node": [<form>, <value>], "vuln": <risk:vuln>}` |
| `crypto:x509:cert` | `{"sha256": <sha256>}` |
| `it:prod:softver` | `{"cpe": <cpe>}`, or `{"name": <product>, "vers": <version>}` |
| `inet:dns:soa` | `{"fqdn": <fqdn>, "ns": <value>}` |
| `inet:http:request` | `$lib.guid(slib, shodan, http, request, <server>, <time>, <url>)` |
| `meta:timeline` | `(slib.shodan, history, <ip>)` |
| `meta:event` | `(slib.shodan, banner, <banner id>)`, see [timelines](#host-history-timelines) |
| `meta:rule` | `(slib.shodan, query, community\|local, <query>)` |
| `it:exec:query` | A new guid every run |

## Changes in 0.17.0

0.17.0 changed how some data is modeled. Nodes made by older versions aren't changed, except by
{ref}`shodan-cmd-admin-dns-cleanup`:

- Shodan's hostnames are `inet:dns:rev`/`rev6` records, not `inet:dns:a`/`aaaa`.
- Bare ports Shodan crawls over UDP are no longer modeled as `tcp://` servers.
- CVEDB scores go in the prop of their CVSS version, scores without a version are left unset,
  GHSAs without a CVE get their v3 vector's score, and CVEDB publish dates are no longer
  `.seen`.
- `inet:asn`, `ou:org`, `it:prod:softver` and `risk:vuln` nodes are linked to the `meta:source`.
- JARM and JA3S fingerprints are modeled.
