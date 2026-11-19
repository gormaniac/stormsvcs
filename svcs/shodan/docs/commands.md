# Commands

The `slib.shodan` package has 33 commands. This page covers what they share. Each command's
options are on the pages for its group:

- [Hosts, DNS and account](commands-hosts.md): `slib.shodan.host`, `slib.shodan.enrich`,
  `slib.shodan.dns.domain`, `slib.shodan.dns.lookup`, `slib.shodan.info`, `slib.shodan.ref`,
  `slib.shodan.apikey`.
- [Search, count, streams and saved queries](commands-search.md): `slib.shodan.search`,
  `slib.shodan.count`, `slib.shodan.hash`, `slib.shodan.trends`, `slib.shodan.stream`,
  `slib.shodan.queries`, `slib.shodan.query.save`.
- [Vulnerabilities](commands-vulns.md): `slib.shodan.cve`, `slib.shodan.cpe`.
- [Scans, alerts and notifiers](commands-scan-alert.md): `slib.shodan.scan`,
  `slib.shodan.scan.status`, `slib.shodan.scan.internet`, `slib.shodan.alert.*`,
  `slib.shodan.notifier.*`.
- [Administration](commands-admin.md): `slib.shodan.admin.*`.

Every command also has `--help`, which prints its description, options and examples from the
package.

## Command index

| Command | Permission | Inputs | Yields | Shodan API |
| --- | --- | --- | --- | --- |
| {ref}`slib.shodan.host <shodan-cmd-host>` | user | IPs, servers, banners, DNS A/AAAA/rev | inbound, or IPs with `--yield` | `/shodan/host/{ip}`, InternetDB |
| {ref}`slib.shodan.enrich <shodan-cmd-enrich>` | user | IPs, `inet:fqdn`, `risk:vuln`, `it:sec:cve`, `it:sec:cpe` | inbound, or results with `--yield` | host, DNS domain, CVEDB |
| {ref}`slib.shodan.dns.domain <shodan-cmd-dns-domain>` | user | `inet:fqdn` | inbound, or subdomains with `--yield` | `/dns/domain/{domain}` |
| {ref}`slib.shodan.dns.lookup <shodan-cmd-dns-lookup>` | user | `inet:fqdn`, IPs | inbound, or results with `--yield` | `/dns/resolve`, `/dns/reverse` |
| {ref}`slib.shodan.info <shodan-cmd-info>` | user | none | inbound | `/account/profile`, `/api-info`, `/tools/myip` |
| {ref}`slib.shodan.ref <shodan-cmd-ref>` | user | none | inbound | reference endpoints |
| {ref}`slib.shodan.apikey <shodan-cmd-apikey>` | user | none | inbound | none (a Cortex vault) |
| {ref}`slib.shodan.search <shodan-cmd-search>` | user | 19 forms, see [below](#queries-built-from-nodes) | IPs, or `it:exec:query` | `/shodan/host/search`, `/count`, `/tokens` |
| {ref}`slib.shodan.count <shodan-cmd-count>` | user | as search | IPs, or `it:exec:query` | `/shodan/host/count` |
| {ref}`slib.shodan.hash <shodan-cmd-hash>` | user | `inet:banner`, `file:bytes` | inbound (none with `--text`) | none (local) |
| {ref}`slib.shodan.trends <shodan-cmd-trends>` | user | as search | inbound | Trends |
| {ref}`slib.shodan.stream <shodan-cmd-stream>` | user | `inet:asn`, `risk:vuln`, `it:sec:cve`, `pol:country`, `meta:rule` | IPs, or `it:exec:query` | Streaming API |
| {ref}`slib.shodan.queries <shodan-cmd-queries>` | user | none | `meta:rule` with `--yield` | `/shodan/query*` |
| {ref}`slib.shodan.query.save <shodan-cmd-query-save>` | user | none | `meta:rule` with `--yield` | none |
| {ref}`slib.shodan.cve <shodan-cmd-cve>` | user | `risk:vuln`, `it:sec:cve`, `it:sec:cpe` | inbound, or `risk:vuln` with `--yield` | CVEDB |
| {ref}`slib.shodan.cpe <shodan-cmd-cpe>` | user | none | `it:sec:cpe` with `--yield` | CVEDB `/cpes` |
| {ref}`slib.shodan.scan <shodan-cmd-scan>` | scan | IPs, CIDRs | inbound | `/shodan/scan` |
| {ref}`slib.shodan.scan.status <shodan-cmd-scan-status>` | scan | none | inbound | `/shodan/scans`, `/shodan/scan/{id}` |
| {ref}`slib.shodan.scan.internet <shodan-cmd-scan-internet>` | scan | none | inbound | `/shodan/scan/internet` |
| {ref}`slib.shodan.alert.list <shodan-cmd-alert-list>` | alert | none | inbound | `/shodan/alert/info` |
| {ref}`slib.shodan.alert.add <shodan-cmd-alert-add>` | alert | IPs, CIDRs | inbound | `/shodan/alert` |
| {ref}`slib.shodan.alert.edit <shodan-cmd-alert-edit>` | alert | IPs, CIDRs | inbound | `/shodan/alert/{id}/...` |
| {ref}`slib.shodan.alert.del <shodan-cmd-alert-del>` | alert | none | inbound | `DELETE /shodan/alert/{id}` |
| {ref}`slib.shodan.notifier.list <shodan-cmd-notifier-list>` | alert | none | inbound | `/notifier` |
| {ref}`slib.shodan.notifier.add <shodan-cmd-notifier-add>` | alert | none | inbound | `POST /notifier` |
| {ref}`slib.shodan.notifier.edit <shodan-cmd-notifier-edit>` | alert | none | inbound | `PUT /notifier/{id}` |
| {ref}`slib.shodan.notifier.del <shodan-cmd-notifier-del>` | alert | none | inbound | `DELETE /notifier/{id}` |
| {ref}`slib.shodan.admin.apikey <shodan-cmd-admin-apikey>` | admin | none | inbound | none (the service) |
| {ref}`slib.shodan.admin.tags <shodan-cmd-admin-tags>` | admin | none | inbound | none (Storm globals) |
| {ref}`slib.shodan.admin.dns.cleanup <shodan-cmd-admin-dns-cleanup>` | admin | none | inbound | none (the Cortex) |
| {ref}`slib.shodan.admin.org <shodan-cmd-admin-org>` | admin | none | inbound | `/org` |
| {ref}`slib.shodan.admin.data <shodan-cmd-admin-data>` | admin | none | inbound | `/shodan/data` |
| {ref}`slib.shodan.admin.request <shodan-cmd-admin-request>` | admin | none | inbound | any |

"user", "scan", "alert" and "admin" are the `slib.shodan.user`, `slib.shodan.scan`,
`slib.shodan.alert` and `slib.shodan.admin` permissions. "Yields inbound" means the inbound
nodes pass through unchanged (commands that only print don't take inputs, but nodes piped to
them still pass through).

## Common behavior

### Errors are warnings

Every service call returns `{status, mesg, data}`. A failed call is reported with
`$lib.warn("slib.shodan: <what> failed: <mesg>")`, ex. `slib.shodan: Host lookup of 10.0.0.1
failed: No information available for that IP.`, and the command carries on with the next
input. Commands only raise `BadArg` for a bad combination of options, ex. `slib.shodan.search`
with no query, no inbound nodes and no `--filters`.

Unsupported inbound forms, and nodes missing the props a command needs, are warned about (ex.
`slib.shodan: The node form inet:email is not supported.`) and skipped.

### API keys

Commands use the calling user's own key (see {ref}`shodan-cmd-apikey`), then the service-wide
key, then the `shodan:apikey` option. See [Deployment](deployment.md#api-keys).

### Tags

Modeling applies Shodan's tags (ex. `cloud`, `vpn`, `honeypot`, `cdn`, `self-signed`) as
`#<prefix>.<tag>`. The prefix is `rep.shodan` by default, set with
{ref}`shodan-cmd-admin-tags`, and tagging can be turned off there. See
[model](model.md#tags).

### Each lookup runs once

Commands that look something up per inbound node make each distinct lookup once per run:

- `slib.shodan.host` looks up each IP once, ex. for several `inet:server` nodes on one IP.
- `slib.shodan.cve` looks up each CVE ID once (upper-cased).
- `slib.shodan.enrich` makes each lookup once, keyed `host:<ip>`, `domain:<fqdn>`, `cve:<CVE>`
  or `cpe:<cpe>`.
- `slib.shodan.search`, `slib.shodan.count` and `slib.shodan.trends` run each distinct query
  once, and print `<n> inbound nodes had the same query as an earlier one, each query was
  searched once.` (or "counted", "run") at the end. For search and count, the one
  `it:exec:query` gets a `-(refs)>` edge to every inbound node that built the query.
- `slib.shodan.dns.domain --domain` skips repeated values.

### Reading inbound nodes first

A Storm lift is still running while a command processes the nodes it returns. When the command
creates nodes of the lifted form, the lift can return those too, ex. `inet:fqdn |
slib.shodan.dns.domain` would also look up every subdomain it found, using more query credits.

So `slib.shodan.search`, `slib.shodan.enrich`, `slib.shodan.dns.domain` and
`slib.shodan.dns.lookup` read every inbound node into a list before running any. Their
`--stream-inbound` flag runs each node as it arrives instead, for inbound sets too large to
hold in memory, with that risk. `slib.shodan.count`, `slib.shodan.trends`, `slib.shodan.host`
and `slib.shodan.cve` run each node as it arrives. `slib.shodan.scan`, `slib.shodan.alert.add`,
`slib.shodan.alert.edit` and `slib.shodan.stream` collect every inbound node and make one
request at the end.

### Query runs

Each `slib.shodan.search`, `slib.shodan.count` and `slib.shodan.stream` run is recorded as an
`it:exec:query` with `-(found)>` edges to what it returned. Print-only modes and failed runs
record nothing. See [model](model.md#query-runs).

### Queries built from nodes

`slib.shodan.search`, `slib.shodan.count` and `slib.shodan.trends` build a Shodan query for
each inbound node (`slib.shodan.lib.searchQuery()`), then AND it with the command's `query`
argument by joining them with a space (ex. `hash:-145740310 country:US`). `$quote(x)` below
wraps the value in double quotes, escaping `"` as `\"` and `,` as `\,` (a comma is Shodan's OR
inside a filter value).

| Form | Query |
| --- | --- |
| `inet:banner` | `hash:<n>`, Shodan's banner hash of `:text` (see {ref}`shodan-cmd-hash`) |
| `file:bytes` | `http.favicon.hash:<n>` when `:mime` starts with `image/`, `http.html_hash:<n>` when it's `text/html` or `application/xhtml+xml`, or the kind `--file-hash` picks. The bytes are read from the Axon (at most 16 MiB). |
| `crypto:x509:cert` | `ssl.cert.fingerprint:<:sha1>`, or without a `:sha1`, `ssl.cert.serial:0x<:serial>` with leading zeros removed |
| `inet:tls:servercert` | The query for its `:cert` |
| `it:sec:cpe` | `cpe:$quote(cpe:2.3:<:part>:<:vendor>:<:product>)`, plus `version:$quote(<:version>)` unless the version is empty, `*` or `-` |
| `it:prod:softver` | The query for its `:cpe` node, otherwise `product:$quote(<:name or :software:name>)` plus `version:$quote(<:vers>)` when set |
| `it:sec:cve` | `vuln:<CVE>` (upper case) |
| `risk:vuln` | `vuln:<:cve>` (upper case) |
| `inet:ssl:jarmhash` | `ssl.jarm:<hash>` |
| `inet:tls:ja3s:sample` | `ssl.ja3s:<:ja3s>` |
| `inet:asn` | `asn:AS<n>` |
| `inet:cidr4`, `inet:cidr6` | `net:<cidr>` |
| `inet:fqdn` | `hostname:$quote(<fqdn>)` |
| `inet:server` | `ip:$quote(<:ipv4 or :ipv6>) port:<:port>` |
| `ou:org` | `org:$quote(<:name>)` |
| `ou:name` | `org:$quote(<name>)` |
| `it:dev:str` | The string, as-is |
| `meta:rule` | `:text`, only when `:type` is `svc.shodan.query.local.` or `svc.shodan.query.community.` |

Examples of queries built from nodes:

```text
inet:banner        -> hash:-145740310
crypto:x509:cert   -> ssl.cert.fingerprint:e652c8bd1cafd04a44239fa8dab0c59deacb79ee
it:sec:cpe=cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*
                   -> cpe:"cpe:2.3:a:f5:nginx" version:"1.25.3"
ou:org:name="github, inc."
                   -> org:"github\, inc."
inet:server=tcp://1.2.3.4:22
                   -> ip:"1.2.3.4" port:22
```

`slib.shodan.trends` also checks that every filter in the query is one Trends supports (the
list in `slib.shodan.lib.trendsFilters()`), and skips the node with a warning otherwise.
