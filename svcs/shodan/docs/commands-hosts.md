# Hosts, DNS and account commands

All of these need the `slib.shodan.user` permission. See [Commands](commands.md) for the
behavior every command shares.

(shodan-cmd-host)=
## slib.shodan.host

Look up IPs in Shodan and model everything Shodan has for them: the IP's ASN and owner,
location, reverse DNS names, tags, vulns, and every service banner (see
[model](model.md#hosts-and-banners)).

```text
slib.shodan.host [--ip <ip>]... [--history] [--timeline] [--no-timeline]
                 [--minify] [--internetdb] [--yield]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--ip` | str, repeatable | `[]` | An IP to look up instead of the inbound nodes. Inbound nodes are dropped when it's used. |
| `--history` | flag | false | Also look up the IP's history (`history=true`), and add every banner to the IP's timeline unless `--no-timeline`. |
| `--timeline` | flag | false | Add the banners to the IP's timeline without `--history`. |
| `--no-timeline` | flag | false | Don't add the banners of a `--history` lookup to the timeline. |
| `--minify` | flag | false | Ask Shodan for minified results (`minify=true`): ports and host info, no banners. |
| `--internetdb` | flag | false | Use the free InternetDB API instead of the host API. |
| `--yield` | flag | false | Yield the `inet:ipv4`/`inet:ipv6` nodes instead of the inbound nodes. |

Inbound nodes and the IP looked up for each:

| Form | IP |
| --- | --- |
| `inet:ipv4`, `inet:ipv6` | The node |
| `inet:server` | `:ipv4` or `:ipv6` |
| `inet:banner` | `:server:ipv4` or `:server:ipv6` |
| `inet:dns:a`, `inet:dns:rev` | `:ipv4` |
| `inet:dns:aaaa`, `inet:dns:rev6` | `:ipv6` |

Nodes of other forms, or without an IP, are warned about and dropped. Each IP is looked up once
per run. Without `--yield`, the other inbound nodes pass through. With `--ip` and no `--yield`,
nothing is yielded.

How a lookup works (`slib.shodan.lib.host()`):

1. When `--internetdb` isn't given and the user has no API key (their vault key or a
   service-wide key), it warns `No Shodan API key is available, falling back to InternetDB.` and
   uses InternetDB.
2. It calls `GET /shodan/host/{ip}` (with `history=false` and `minify` as given), or InternetDB's
   `GET /{ip}`. A 404 is a warning, ex. `Host lookup of 10.0.0.1 failed: No information
   available for that IP.`
3. The host is modeled (`slib.shodan.model.host()`). A minified or InternetDB result has no
   banners, so its ports are modeled as `tcp://` `inet:server` nodes, except the ports Shodan
   crawls over UDP (see [model](model.md#ports-without-a-transport)).
4. With `--history` (and not InternetDB), it calls `GET /shodan/host/{ip}?history=true` and
   models only that result's banners, as historical banners: their vulns and ASN aren't
   modeled, and Shodan's tags for them go on the `inet:banner`, not the `inet:server`. A
   history lookup's host-level fields combine its whole history, and Shodan's history lags its
   newest data by about a day, which is why there are two lookups.

The timeline is on when `(--timeline or --history) and not --no-timeline`. Each banner then
becomes a `meta:event` in the IP's `meta:timeline` (see [model](model.md#host-history-timelines)).
A minified or InternetDB lookup has no banners, and warns `<what> has no banners to add to a
timeline.`

Both host lookups are free in Shodan (no query credits).

```text
// Look up IPs already in the Cortex.
inet:ipv4#my.tag | slib.shodan.host

// The IPs of servers, banners or DNS records, each looked up once.
inet:fqdn=vertex.link -> inet:dns:a | slib.shodan.host --yield

// Current data, plus the 90 day banner history as a timeline.
inet:ipv4=1.2.3.4 | slib.shodan.host --history
meta:event:time +{ :timeline -> meta:timeline +:title="Shodan history: 1.2.3.4" }

// The free, less detailed InternetDB.
slib.shodan.host --ip 1.1.1.1 --internetdb --yield
```

(shodan-cmd-enrich)=
## slib.shodan.enrich

Enrich each inbound node with the best matching API.

```text
slib.shodan.enrich [--yield] [--stream-inbound]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--yield` | flag | false | Yield the resulting nodes instead of the inbound nodes. |
| `--stream-inbound` | flag | false | Run each inbound node as it arrives, instead of reading all of them first (see [Commands](commands.md#reading-inbound-nodes-first)). |

| Form | Lookup | Same as | Results |
| --- | --- | --- | --- |
| `inet:ipv4`, `inet:ipv6` | Host lookup, or InternetDB without a key | `slib.shodan.host` | The IP node |
| `inet:fqdn` | DNS domain records, up to 10 pages | `slib.shodan.dns.domain` | The subdomain `inet:fqdn` nodes |
| `risk:vuln` | CVEDB, by `:cve` (warns without one) | `slib.shodan.cve` | The `risk:vuln` |
| `it:sec:cve` | CVEDB | `slib.shodan.cve` | The `risk:vuln` |
| `it:sec:cpe` | CVEDB CVEs for the CPE, up to 100 | `slib.shodan.cve` of an `it:sec:cpe` | The `risk:vuln` nodes |

Lookups use the defaults of those commands: no history, no `--cpes`. Other forms are warned
about. Without `--yield`, every inbound node passes through. Each lookup is made once per run.

```text
#my.tag | slib.shodan.enrich
inet:fqdn=vertex.link | slib.shodan.enrich --yield
```

(shodan-cmd-dns-domain)=
## slib.shodan.dns.domain

Model every DNS record and subdomain Shodan has for a domain, from `GET /dns/domain/{domain}`.

```text
slib.shodan.dns.domain [--domain <fqdn>]... [--history] [--type <type>] [--pages <n>]
                       [--yield] [--stream-inbound]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--domain` | str, repeatable | `[]` | A domain to query instead of the inbound nodes, which are dropped. Repeated values are skipped. |
| `--history` | flag | false | Include historical records (sends `history=true`, the param is left out otherwise). |
| `--type` | str | null | Only records of this type, sent as Shodan's `type` param (A, AAAA, CNAME, NS, SOA, MX, TXT). |
| `--pages` | int | `10` | The most result pages to read. `0` reads all of them. |
| `--yield` | flag | false | Yield the subdomain `inet:fqdn` nodes instead of the inbound nodes. |
| `--stream-inbound` | flag | false | Run each inbound node as it arrives (see [Commands](commands.md#reading-inbound-nodes-first)). |

Takes `inet:fqdn` nodes. Others are warned about and pass through (they're dropped with
`--yield`).

The service reads page 1, 2, ... while Shodan says `more`, up to `--pages`, and merges them
(`dnsDomainAll()`). When results remain after the last page, the command warns `<domain> has
more DNS results than were retrieved, increase --pages.` Each page is one request, and Shodan
charges a query credit per lookup.

What it models (see [model](model.md#dns)):

- Each record as `inet:dns:a`, `inet:dns:aaaa`, `inet:dns:cname`, `inet:dns:mx`,
  `inet:dns:ns`, `inet:dns:txt` or `inet:dns:soa` (`:fqdn`, `:ns`), with `.seen` from the
  record's `last_seen`. Other record types are skipped.
- The domain's `inet:fqdn`, tagged with Shodan's tags for the domain.
- An `inet:fqdn` for each subdomain, `<sub>.<domain>`.

```text
inet:fqdn=vertex.link | slib.shodan.dns.domain
slib.shodan.dns.domain --domain vertex.link --type A --history --yield
```

(shodan-cmd-dns-lookup)=
## slib.shodan.dns.lookup

Resolve hostnames to IPs, and IPs to hostnames.

```text
slib.shodan.dns.lookup [--yield] [--stream-inbound]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--yield` | flag | false | Yield the resolved IP or hostname nodes instead of the inbound nodes. |
| `--stream-inbound` | flag | false | Run each inbound node as it arrives (see [Commands](commands.md#reading-inbound-nodes-first)). |

| Form | Request | Models | Yields with `--yield` |
| --- | --- | --- | --- |
| `inet:fqdn` | `GET /dns/resolve?hostnames=<fqdn>` | `inet:dns:a` or `inet:dns:aaaa`, the IP | The IP |
| `inet:ipv4`, `inet:ipv6` | `GET /dns/reverse?ips=<ip>` | `inet:dns:rev`/`inet:dns:rev6` and an `inet:fqdn` per hostname, and the IP's `:dns:rev` set to the first hostname | The `inet:fqdn` nodes |

One request per node. Other forms are warned about and pass through (they're dropped with
`--yield`). A hostname Shodan can't resolve, or an IP without hostnames, models nothing.

```text
inet:fqdn=vertex.link | slib.shodan.dns.lookup --yield
inet:ipv4=8.8.8.8 | slib.shodan.dns.lookup
```

(shodan-cmd-info)=
## slib.shodan.info

Print the account, API plan and credits of the API key in use, and the service's public IP. No
options. Calls `GET /account/profile`, `GET /api-info` and `GET /tools/myip`, and prints each
part that succeeds:

```text
Account:
  Name: visi
  Member: true
  Created: 2020-01-01
  Credits: 0
API plan: dev
credits              remaining    monthly limit
query                99           100
scan                 98           100
monitored IPs        1            16
Unlocked: true (unlocked left: 99)
HTTPS: true  Telnet: false
slib.shodan service IP: 5.6.7.8
```

(shodan-cmd-ref)=
## slib.shodan.ref

Print Shodan reference data.

```text
slib.shodan.ref <name>
```

| `name` | Request | Prints |
| --- | --- | --- |
| `ports` | `GET /shodan/ports` | The ports Shodan crawls, comma separated |
| `protocols` | `GET /shodan/protocols` | A protocol / description table, the protocols on-demand scans can use |
| `services` | `GET /shodan/services` | A port / service table |
| `filters` | `GET /shodan/host/search/filters` | The search filters |
| `facets` | `GET /shodan/host/search/facets` | The search facets |
| `triggers` | `GET /shodan/alert/triggers` | A trigger / rule / description table of network alert triggers |
| `providers` | `GET /notifier/provider` | A provider / required args table |
| `httpheaders` | `GET /tools/httpheaders` | The HTTP headers the service sends to Shodan, `<name>: <value>` |

`name` must be one of those values.

```text
slib.shodan.ref triggers
```

(shodan-cmd-apikey)=
## slib.shodan.apikey

Set, check or delete your own Shodan API key. It's stored in the Cortex, in a user scoped
Synapse vault of type `shodan`, and takes precedence over the service-wide key.

```text
slib.shodan.apikey [<apikey>] [--clear]
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `apikey` | str, optional | null | Your Shodan API key. Prints whether you have one when omitted. |
| `--clear` | flag | false | Delete your vault. |

- With a key and no vault, it creates the vault `shodan:<username>` (type `shodan`, scope
  `user`, owned by you) with the secret `{"apikey": <key>}`.
- With a key and an existing vault, it replaces the vault's `apikey` secret.
- Without a key, it prints `Your Shodan API key is set in vault <name>.` or `You don't have a
  Shodan API key set.`
- `--clear` deletes the vault.

The `slib.shodan.priv.*` modules read this vault with `$lib.vault.bytype(shodan, scope=user)`,
so only your own requests use it.

```text
slib.shodan.apikey ABCDEFG
slib.shodan.apikey --clear
```
