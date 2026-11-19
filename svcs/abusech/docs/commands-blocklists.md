# Blocklist commands

The commands for the datasets of [Feodo Tracker](https://feodotracker.abuse.ch),
[SSL Blacklist](https://sslbl.abuse.ch) and abuse.ch Hunting's false positive list. All three
run once and drop the inbound nodes. The Feodo Tracker and SSLBL files don't need an
Auth-Key (one is sent when available); the false positive list does.

## `slib.abusech.feodo`

Model a Feodo Tracker botnet C2 blocklist (Dridex, Emotet, TrickBot, QakBot, BazarLoader, ...).

```text
slib.abusech.feodo [<list>] [--limit <n>] [--yield]
```

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `list` | str, one of `all`, `recommended`, `aggressive` | `all` | The blocklist. |
| `--limit` | int | `0` | The max number of C2s to model, `0` for all. |
| `--yield` | flag | `false` | Yield the `inet:server` nodes (or the IP, for an entry without a port). |

| `list` | File | Contents |
|---|---|---|
| `all` | `ipblocklist.json` | Every C2 seen in the last 30 days, with its status, family, hostname, ASN and country |
| `recommended` | `ipblocklist_recommended.json` | The C2s Feodo Tracker recommends blocking |
| `aggressive` | `ipblocklist_aggressive.csv` | Every C2 ever seen. CSV columns `first_seen_utc`, `dst_ip`, `dst_port`, `c2_status`, `last_online`, `malware` |

Each C2 is modeled as:

- The `inet:ipv4`/`inet:ipv6`, with `:asn` (an `inet:asn` with `:name`) and `:loc` (the
  country) when given.
- The `inet:server` `tcp://<ip>:<port>`.
- Both tagged `<prefix>.feodo.c2`, the family (ex. `#rep.abusech.feodo.qakbot`), and
  `<prefix>.feodo.status.<status>` (replacing an older `status.*` tag), with the C2's first
  seen to last online interval.
- A hostname as an `inet:fqdn` and an `inet:dns:a` (or `inet:dns:aaaa`).
- The family as a `risk:tool:software`.

- Permission: `slib.abusech.user`
- The file is downloaded into memory (capped at `abusech:maxsize`).

```text
slib.abusech.feodo recommended --yield
```

## `slib.abusech.sslbl`

Model an SSL Blacklist blocklist.

```text
slib.abusech.sslbl [<list>] [--limit <n>] [--yield]
```

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `list` | str, one of `certs`, `ja3` | `certs` | The blocklist. |
| `--limit` | int | `0` | The max number of entries to model, `0` for all. |
| `--yield` | flag | `false` | Yield the modeled nodes. |

| `list` | File | Modeled as |
|---|---|---|
| `certs` | `sslblacklist.csv` (`listingdate`, `sha1`, `listingreason`) | A `crypto:x509:cert` keyed by `:sha1`, tagged `<prefix>.sslbl.c2` and the family (with the listing date), and the listing reason as a `meta:note` (`:type=slib.abusech.sslbl.reason`) |
| `ja3` | `ja3_fingerprints.csv` (`ja3_md5`, `firstseen`, `lastseen`, `listingreason`) | A `hash:md5` tagged `<prefix>.sslbl.ja3` and the family (first to last seen), the listing reason as a `meta:note`, and a `meta:note` (`:type=slib.abusech.sslbl.ja3`) saying it's a JA3. SSLBL stopped updating this list in 2021. |

The family is taken from the listing reason by dropping everything from `C&C`, `C2`,
`malware distribution` or `botnet` on (ex. `Dridex C&C` is `Dridex`).

SSLBL's botnet C2 IP lists were deprecated on 2025-01-03; use `slib.abusech.feodo` or
`slib.abusech.threatfox.search` for C2 IPs. A dataset replaced by a "has been deprecated"
notice is reported as an error with that notice.

- Permission: `slib.abusech.user`

```text
slib.abusech.sslbl certs

slib.abusech.sslbl ja3 --yield
```

## `slib.abusech.fplist`

Model the abuse.ch false positive list (Hunting `get_fplist`): the hashes, domains, URLs and
IPs abuse.ch removed from its platforms as false positives.

```text
slib.abusech.fplist [--platform <platform>] [--yield]
```

| Option | Type | Default | Meaning |
|---|---|---|---|
| `--platform` | str | `null` | Only model the entries for this platform, ex. `malwarebazaar`, `urlhaus`, `threatfox` (normalized like a tag segment before comparing). |
| `--yield` | flag | `false` | Yield the false positive nodes. |

Each entry's observable (typed by its `entry_type`) is tagged `<prefix>.hunting.fp` and
`<prefix>.hunting.fp.<platform>` (with the entry's time), with the removal notes and who
removed it as a `meta:note` (`:type=slib.abusech.hunting.fp`). A sample is listed once per hash
type on consecutive rows; those rows are merged into one `file:bytes` with every hash.

- Permission: `slib.abusech.user`
- Prints `slib.abusech.fplist: <n> false positive entries.`

```text
slib.abusech.fplist --platform malwarebazaar --yield
```
