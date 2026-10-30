# slib.shodan

A Storm Service that integrates every Shodan API into Synapse: host lookups, search,
on-demand scanning, network alerts and notifiers, DNS, streaming, saved queries, bulk data,
organization management, Exploits, Trends, and the free InternetDB and CVEDB APIs.

Run any `slib.shodan.*` command with `--help` for its options and examples.

## API keys

Keys are resolved per request, in this order:

1. Your own key, set with `slib.shodan.apikey <key>` (stored in a user scoped vault of type `shodan`).
2. The service-wide key, set by an admin with `slib.shodan.admin.apikey <key>`.
3. The service's `shodan:apikey` config option.

Without a key, `slib.shodan.host` falls back to the free InternetDB API.

## Permissions

- `slib.shodan.user` - Lookups, search, DNS, CVEs, exploits, trends, and streams.
- `slib.shodan.scan` - On-demand scans.
- `slib.shodan.alert` - Network alerts and notifiers.
- `slib.shodan.admin` - The service-wide key, tag settings, organization, bulk data, and raw requests.

## Examples

```
// Everything Shodan knows about some IPs, tagging likely honeypots.
inet:ipv4#my.tag | slib.shodan.host --honeyscore

// Free: count results and summarize by country.
slib.shodan.search "product:nginx" --count --facets country:10

// Ingest the first 200 results.
slib.shodan.search "product:nginx country:US" --limit 200

// Enrich any mix of IPs, domains, CVEs, and CPEs.
#my.tag | slib.shodan.enrich

// Monitor a netblock for new services and vulns.
inet:cidr4=1.2.3.0/24 | slib.shodan.alert.add corp --trigger new_service --trigger vulnerable --notifier default
```

Shodan's own tags (ex. `cloud`, `vpn`, `honeypot`) and CISA KEV vulns are tagged under
`rep.shodan` by default. Change it with `slib.shodan.admin.tags`.
