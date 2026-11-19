# Commands

The `slib.abusech` package has 34 Storm commands. This page lists them and explains the
behavior they share; each platform's page has the full reference for its commands. Run any
command with `--help` in Storm for its options and examples.

## Command index

| Command | Permission | Purpose |
|---|---|---|
| [`slib.abusech.enrich`](#slib-abusech-enrich) | `user` | Enrich any supported node from every platform that knows its form. |
| [`slib.abusech.bazaar.lookup`](commands-bazaar.md) | `user` | Look up samples (`get_info`) and model everything MalwareBazaar knows. |
| [`slib.abusech.bazaar.search`](commands-bazaar.md) | `user` | Search samples by tag, signature, hash, certificate, recent, or detections. |
| [`slib.abusech.bazaar.cscb`](commands-bazaar.md) | `user` | Model the Code Signing Certificate Blocklist. |
| [`slib.abusech.bazaar.download`](commands-bazaar.md) | `download` | Download samples into the Axon. |
| [`slib.abusech.bazaar.submit`](commands-bazaar.md) | `submit` | Submit `file:bytes` from the Axon to MalwareBazaar. |
| [`slib.abusech.bazaar.update`](commands-bazaar.md) | `submit` | Comment on samples, or update samples you submitted. |
| [`slib.abusech.bazaar.export`](commands-bazaar.md) | `user` (+`bulk`) | Model the `recent`/`full` CSV export or the `yara` rule statistics. |
| [`slib.abusech.urlhaus.lookup`](commands-urlhaus.md) | `user` | Look up URLs, URL IDs, hosts, and payloads. |
| [`slib.abusech.urlhaus.search`](commands-urlhaus.md) | `user` | URLs by tag or signature, recent URLs or payloads. |
| [`slib.abusech.urlhaus.download`](commands-urlhaus.md) | `download` | Download payloads into the Axon. |
| [`slib.abusech.urlhaus.submit`](commands-urlhaus.md) | `submit` | Report malware URLs. |
| [`slib.abusech.urlhaus.export`](commands-urlhaus.md) | `user` (+`bulk`) | Model the `recent`, `online`, `full`, or `payloads` CSV export. |
| [`slib.abusech.threatfox.lookup`](commands-threatfox.md) | `user` | Look up IOCs by value, ID, IP, or sample hash. |
| [`slib.abusech.threatfox.search`](commands-threatfox.md) | `user` | IOCs by `recent` days, `tag`, or `malware`. |
| [`slib.abusech.threatfox.ref`](commands-threatfox.md) | `user` | Print IOC/threat types, tags, malware families, or find a label. |
| [`slib.abusech.threatfox.submit`](commands-threatfox.md) | `submit` | Share IOCs with ThreatFox. |
| [`slib.abusech.threatfox.export`](commands-threatfox.md) | `user` (+`bulk`) | Model the `recent` or `full` JSON export. |
| [`slib.abusech.yaraify.lookup`](commands-yaraify.md) | `user` | Look up files by hash, or scan task results. |
| [`slib.abusech.yaraify.search`](commands-yaraify.md) | `user` | Files by YARA rule, ClamAV signature, or fuzzy hash. |
| [`slib.abusech.yaraify.scan`](commands-yaraify.md) | `submit` | Scan files from the Axon, or rescan known files by hash. |
| [`slib.abusech.yaraify.tasks`](commands-yaraify.md) | `user` | List your scan tasks, or generate a new identifier. |
| [`slib.abusech.yaraify.rules`](commands-yaraify.md) | `user` | Model YARAhub rules. |
| [`slib.abusech.yaraify.deploy`](commands-yaraify.md) | `submit` | Deploy YARA rules for live hunting, or delete deployed rules. |
| [`slib.abusech.yaraify.download`](commands-yaraify.md) | `download` | Download (shared or unpacked) files into the Axon. |
| [`slib.abusech.feodo`](commands-blocklists.md) | `user` | Model a Feodo Tracker C2 blocklist. |
| [`slib.abusech.sslbl`](commands-blocklists.md) | `user` | Model an SSL Blacklist blocklist. |
| [`slib.abusech.fplist`](commands-blocklists.md) | `user` | Model the abuse.ch false positive list. |
| [`slib.abusech.apikey`](commands-admin.md) | `user` | Set, clear, or check your own Auth-Key. |
| [`slib.abusech.admin.apikey`](commands-admin.md) | `admin` | Set, clear, or check the service-wide Auth-Key. |
| [`slib.abusech.admin.tags`](commands-admin.md) | `admin` | Set the tag prefix, enable or disable tagging. |
| [`slib.abusech.admin.families.merge`](commands-admin.md) | `admin` | Merge malware family nodes made before 0.4.0. |
| [`slib.abusech.admin.edges.migrate`](commands-admin.md) | `admin` | Rewrite the `-(refs)>` edges made before 0.5.0. |
| [`slib.abusech.admin.request`](commands-admin.md) | `admin` | Send a raw request to an abuse.ch API. |

"Permission" is the `slib.abusech.<perm>` permission the command declares (a user needs it
to run the command at all), plus `bulk` for the `--bulk` option. Commands that model nodes
also need the normal node permissions, see [Permissions](deployment.md#permissions).

## Shared behavior

### Inbound nodes and `--yield`

The commands fall into three groups by how they treat the pipeline:

Node driven (`enrich`, `*.lookup`, `*.download`, `bazaar.update`, `yaraify.scan`)
: Each inbound node of a supported form (the command's `cmdinputs`) is looked up. Without
  `--yield` the inbound node passes through; with `--yield` it's replaced by the nodes the
  lookup modeled (ex. the `file:bytes`, or the IOC observables). Nodes of other forms get a
  warning, and nodes with nothing to look up (ex. a `file:bytes` with no hash) are skipped
  with a warning.

Option driven (`--hash`, `--url`, `--id`, `--host`, `--ioc`, `--task`, `--uuid`)
: An option that names what to look up makes the command ignore the inbound nodes: the work
  runs **once per command**, not once per inbound node, and the inbound nodes are dropped.
  With `--yield` the results are yielded. The options are repeatable (`action: append`).

Dataset commands (searches, exports, blocklists, `bazaar.cscb`, `fplist`, `yaraify.rules`)
: These run once and always drop the inbound nodes. The four `*.search` commands always yield
  their results; the others only yield with `--yield`.

Submission commands (`bazaar.submit`, `urlhaus.submit`, `threatfox.submit`,
`yaraify.deploy`) pass the inbound nodes through. `urlhaus.submit` and `threatfox.submit`
collect every inbound node and send them in **one** submission when the pipeline ends.

### Errors and output

- A failed service call is a Storm warning, `slib.abusech: <what> failed: <message>`, and
  the command carries on with the next node. abuse.ch's own error (ex. `abuse.ch bazaar:
  illegal_hash`, or `... (check your Auth-Key)` for an auth failure) is in the message.
- "Not found" is not an error: lookups print or warn that abuse.ch doesn't have the value
  and model nothing.
- Invalid option combinations raise `BadArg` (ex. `--reuse` without `--bulk`, or a search
  without a value).
- Counts and progress are printed, ex. `slib.abusech.bazaar.search: Found 50 samples.`
- Submission responses are printed as `slib.abusech: <what>: <response>` (a string response)
  or as indented JSON.

### Limits

`--limit` is an int on every command that takes one. `0` (or a negative value) means "the
default": the max (1000) for the MalwareBazaar, ThreatFox tag/malware, and YARAify searches,
and every result elsewhere. Positive values above 1000 are clamped to 1000 where abuse.ch caps
the result set.

### Tags

Most nodes get abuse.ch's tags, families and statuses as `<prefix>.<platform>.<tag>`, where
the prefix defaults to `rep.abusech` (set with `slib.abusech.admin.tags`) and the platform is
`bazaar`, `urlhaus`, `threatfox`, `yaraify`, `feodo`, `sslbl` or `hunting`. With tagging
disabled no tags are applied, but everything else is still modeled. See
[the data model](model.md#tags).

## `slib.abusech.enrich`

Enrich nodes from every abuse.ch platform that knows about their form. It's
`slib.abusech.lib.enrich()` for each inbound node.

```text
slib.abusech.enrich [--platform <platform> ...] [--yield]
```

| Option | Type | Default | Meaning |
|---|---|---|---|
| `--platform` | str, repeatable, one of `bazaar`, `urlhaus`, `threatfox`, `yaraify` | `[]` (all four) | Only query these platforms. |
| `--yield` | flag | `false` | Yield the enriched/created nodes instead of the inbound nodes. |

Permission: `slib.abusech.user`.

What each form is looked up with:

| Inbound form | Platforms and queries |
|---|---|
| `file:bytes`, `hash:md5`, `hash:sha1`, `hash:sha256` | MalwareBazaar `get_info`, YARAify `lookup_hash`, URLhaus `/payload/` (MD5 or SHA256 only), ThreatFox by file (see below). A `file:bytes` is looked up by its `:sha256`, else `:sha1`, else `:md5`. |
| `inet:url` | URLhaus `/url/`, ThreatFox `search_ioc` (exact) |
| `inet:fqdn` | URLhaus `/host/`, ThreatFox `search_ioc` (exact) |
| `inet:ipv4` | URLhaus `/host/`, ThreatFox by IP |
| `inet:ipv6` | ThreatFox by IP (URLhaus doesn't support IPv6 hosts) |
| `inet:server` | ThreatFox `search_ioc` (exact) for `<ip>:<port>`, only when the server has a `:port` |

ThreatFox "by file" is an exact `search_ioc` for the hash (the hash's own IOC) plus
`search_hash` (IOCs associated with the sample) for MD5/SHA256, deduplicated by IOC ID.
ThreatFox "by IP" is a non-exact `search_ioc` for the IP, keeping the IOCs whose value is the
IP or whose server IP is it (so `ip:port` C2s match). Both return every match.

```text
// Enrich a mixed set of nodes from every platform.
#my.tag | slib.abusech.enrich

// Only check MalwareBazaar and ThreatFox, and yield the results.
file:bytes#my.tag | slib.abusech.enrich --platform bazaar --platform threatfox --yield
```
