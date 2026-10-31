# slib.abusech

A Storm Service that integrates every abuse.ch platform into Synapse: MalwareBazaar, URLhaus,
ThreatFox, YARAify, Feodo Tracker, SSL Blacklist, and the abuse.ch false positive list.

Run any `slib.abusech.*` command with `--help` for its options and examples.

## Auth-Keys

Every abuse.ch API needs a free Auth-Key from https://auth.abuse.ch/ (one key works for every
platform). Keys are resolved per request, in this order:

1. Your own key, set with `slib.abusech.apikey <key>` (stored in a user scoped vault of type `abusech`).
2. The service-wide key, set by an admin with `slib.abusech.admin.apikey <key>`.
3. The service's `abusech:apikey` config option.

## Permissions

- `slib.abusech.user` - Lookups, searches, exports, and blocklists.
- `slib.abusech.download` - Download malware samples into the Axon.
- `slib.abusech.submit` - Send samples, URLs, IOCs, comments, scans, and YARA rules to abuse.ch.
- `slib.abusech.admin` - The service-wide key, tag settings, and raw requests.

## Examples

```
// Everything abuse.ch knows about some files, URLs, and hosts.
#my.tag | slib.abusech.enrich

// Recent Emotet samples, and Cobalt Strike C2s.
slib.abusech.bazaar.search signature Emotet --limit 50
slib.abusech.threatfox.search malware win.cobalt_strike

// Botnet C2 blocklists.
slib.abusech.feodo recommended
slib.abusech.sslbl ips
```

abuse.ch's tags, malware families, and statuses are tagged as `rep.abusech.<platform>.<tag>`
by default (ex. `#rep.abusech.bazaar.emotet`). Change it with `slib.abusech.admin.tags`.
