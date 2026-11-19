# ThreatFox commands

The commands for [ThreatFox](https://threatfox.abuse.ch) (base URLs `threatfox` and
`threatfox:export`). Nodes they create are linked to the ThreatFox `meta:source` and tagged
`<prefix>.threatfox.*`. How an IOC is modeled is in [the data model](model.md#iocs-threatfox).

## `slib.abusech.threatfox.lookup`

Look up IOCs in ThreatFox and model them.

```text
slib.abusech.threatfox.lookup [--ioc <value> ...] [--id <id> ...] [--hash <hash> ...]
    [--fuzzy] [--limit <n>] [--yield]
```

| Option | Type | Default | Meaning |
|---|---|---|---|
| `--ioc` | str, repeatable | `[]` | An IOC value to search for (`search_ioc`). |
| `--id` | str, repeatable | `[]` | A ThreatFox IOC ID to look up (`ioc`). Must be an integer. |
| `--hash` | str, repeatable | `[]` | A sample hash to find IOCs for (by file, below). |
| `--fuzzy` | flag | `false` | Let `--ioc` searches match partially (`exact_match=false`, ThreatFox's default) instead of exactly. |
| `--limit` | int | `0` | The max number of IOCs per lookup, `0` for every match. Not applied to `--id`. |
| `--yield` | flag | `false` | Yield the IOC (observable) nodes instead of the inbound nodes. |

Any of `--ioc`, `--id`, `--hash` makes the command ignore the inbound nodes; it then prints
`slib.abusech.threatfox.lookup: Found <n> IOCs.`

| Inbound form | Query |
|---|---|
| `file:bytes`, `hash:md5`, `hash:sha1`, `hash:sha256` | By file: an exact `search_ioc` for the hash (the hash's own IOC), plus `search_hash` (the IOCs associated with the sample) when it's an MD5 or SHA256. IOCs are deduplicated by ID. Uses `--limit`. |
| `inet:ipv4`, `inet:ipv6` | By IP: a non-exact `search_ioc` for the IP, keeping IOCs whose value is the IP or whose server IP is it (ex. its `ip:port` C2s). Every match. |
| `inet:url`, `inet:fqdn` | An exact `search_ioc` for the node's value. |
| `inet:server` | An exact `search_ioc` for `<ip>:<port>`, when the server has a `:port`. |

The inbound URL, FQDN, IP and server lookups are `slib.abusech.lib.enrich()` restricted to
ThreatFox.

- Permission: `slib.abusech.user`
- Each IOC is modeled as its observable, tagged with its threat type, malware family, tags
  (and `compromised`), an `it:sec:stix:indicator` for the IOC record, the family's
  `risk:tool:software`, related samples, the reference, and the reporter.
- An IOC whose value can't be typed as a Synapse observable warns `slib.abusech: Unable to
  model ThreatFox IOC <id> (<type>: <value>).`

```text
inet:fqdn#my.tag | slib.abusech.threatfox.lookup

slib.abusech.threatfox.lookup --ioc 1.2.3.4:443 --id 123456 --yield
```

## `slib.abusech.threatfox.search`

Search ThreatFox for IOCs and model them. Always yields the IOC nodes, and drops the inbound
nodes.

```text
slib.abusech.threatfox.search <by> [<value>] [--limit <n>]
```

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `by` | str, one of `recent`, `tag`, `malware` | | What to search by. |
| `value` | str, optional | `null` | The days, tag, or malware family. Required for `tag` and `malware` (`BadArg`). |
| `--limit` | int | `0` | The max number of IOCs, `0` for every match. |

| `by` | Query | `value` | `--limit` |
|---|---|---|---|
| `recent` | `get_iocs` (`days`) | Days, default `1`, clamped to 1-7. Cast to an int in Storm. | Cuts the result. |
| `tag` | `taginfo` (`tag`, `limit`) | A ThreatFox tag | Sent as `limit`, kept in 1-1000 (`0` sends 1000). |
| `malware` | `malwareinfo` (`malware`, `limit`) | A malware family, ex. `win.cobalt_strike` | As for `tag`. |

- Permission: `slib.abusech.user`
- Prints `slib.abusech.threatfox.search: Found <n> IOCs.`

```text
slib.abusech.threatfox.search recent 3

slib.abusech.threatfox.search malware win.cobalt_strike --limit 500 | <(uses)- file:bytes
```

## `slib.abusech.threatfox.ref`

Print ThreatFox reference data as a table. Models nothing.

```text
slib.abusech.threatfox.ref <name> [--malware <name>] [--platform <platform>]
```

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `name` | str, one of `types`, `tags`, `malware`, `label` | | The reference data to print. |
| `--malware` | str | `null` | The malware name to find a label for. Required for `label` (`BadArg`). |
| `--platform` | str, one of `win`, `osx`, `apk`, `jar`, `elf` | `null` | Narrow the `label` search to a platform. |

| `name` | Query | Columns |
|---|---|---|
| `types` | `types` | `id`, `ioc_type`, `threat_type` (`fk_threat_type`), `description` |
| `tags` | `tag_list` | `tag`, `first_seen`, `last_seen`, `color` |
| `malware` | `malware_list` | `malware`, `printable` (`malware_printable`), `aliases` (`malware_alias`) |
| `label` | `get_label` (`malware`, `platform`) | `malware`, `printable`, `aliases` |

- Permission: `slib.abusech.user`

```text
slib.abusech.threatfox.ref types

slib.abusech.threatfox.ref label --malware "cobalt strike" --platform win
```

## `slib.abusech.threatfox.submit`

Share IOCs with ThreatFox (`submit_ioc`). Every inbound node and every `--ioc` are sent in
**one** submission when the pipeline ends, so they must all be the same IOC type. Inbound
nodes pass through. Make sure you've read ThreatFox's submission policy first.

```text
slib.abusech.threatfox.submit <threat> <malware> [--ioc <value> ... --type <ioc type>]
    [--confidence <0-100>] [--reference <url>] [--comment <text>] [--tag <tag> ...]
    [--compromised] [--anonymous]
```

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `threat` | str, required | | The threat type (`threat_type`), ex. `botnet_cc`, `payload_delivery`, `payload`. |
| `malware` | str, required | | The ThreatFox malware family (`malware`), ex. `win.cobalt_strike`. |
| `--ioc` | str, repeatable | `[]` | An IOC to submit, in addition to the inbound nodes. |
| `--type` | str | `null` | The IOC type (`ioc_type`) of the `--ioc` values, ex. `ip:port`, `domain`, `url`, `sha256_hash`. Required with `--ioc` and no inbound nodes. |
| `--confidence` | int | `50` | Your confidence (`confidence_level`), clamped to 0-100. |
| `--reference` | str | `null` | A reference URL. |
| `--comment` | str | `null` | A comment. |
| `--tag` | str, repeatable | `[]` | A tag for the IOCs. |
| `--compromised` | flag | `false` | The IOCs are compromised legitimate infrastructure (`is_compromised`). |
| `--anonymous` | flag | `false` | Submit anonymously (`anonymous=1`). |

The IOC type of each inbound node:

| Form | Value sent | `ioc_type` |
|---|---|---|
| `inet:url` | the URL | `url` |
| `inet:fqdn` | the FQDN | `domain` |
| `inet:server` | `<ip>:<port>` | `ip:port` |
| `file:bytes` | `:sha256`, else `:sha1`, else `:md5`, else `:_sha3_384` | `sha256_hash`, `sha1_hash`, `md5_hash`, `sha3_384_hash` |

The first node (or `--type`) fixes the type; a later node of a different type is skipped
with a warning (`Skipping <node>, every IOC must be a <type>.`). Nodes that can't be
submitted get a warning.

- Permission: `slib.abusech.submit`
- Use `slib.abusech.threatfox.ref types` and `slib.abusech.threatfox.ref malware` for valid
  values. Never retried after a 5xx or timeout.

```text
inet:server#my.c2 | slib.abusech.threatfox.submit botnet_cc win.cobalt_strike --confidence 75

slib.abusech.threatfox.submit payload_delivery win.cobalt_strike --ioc http://a.example/x.exe --type url
```

## `slib.abusech.threatfox.export`

Model the IOCs in a ThreatFox JSON export. Runs once and drops the inbound nodes.

```text
slib.abusech.threatfox.export [<kind>] [--limit <n>] [--bulk [--reuse | --repull]] [--yield]
```

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `kind` | str, one of `recent`, `full` | `recent` | `recent` (`recent.json`, the last 48 hours) or `full` (`full.json.zip`, every IOC). |
| `--limit` | int | `0` | The max number of IOCs to model, `0` for all. Ignored with `--bulk`. |
| `--bulk` | flag | `false` | Bulk import the whole export, see [Bulk imports](bulk.md). |
| `--reuse` | flag | `false` | With `--bulk`, import the last pull again. |
| `--repull` | flag | `false` | With `--bulk`, pull a new copy even if one was pulled recently. |
| `--yield` | flag | `false` | Yield the IOC nodes. Not used with `--bulk`. |

Without `--bulk` the export is downloaded and parsed in memory, capped at `abusech:maxsize`
(the download and the unzipped JSON). The `full` export unzips to more than the default, which
fails with a message suggesting `--bulk` (capped at `abusech:bulk:maxsize` instead) or raising
`abusech:maxsize`.

- Permission: `slib.abusech.user`, plus `slib.abusech.bulk` for `--bulk`
- `--reuse`/`--repull` without `--bulk`, or both together, raise `BadArg`.

```text
slib.abusech.threatfox.export
slib.abusech.threatfox.export recent --bulk
background { slib.abusech.threatfox.export full --bulk }
```
