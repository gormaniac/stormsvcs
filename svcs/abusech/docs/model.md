# Data model

Everything abuse.ch returns is normalized by the service
({src}`svcs/abusech/src/abusechsvc/norm.py`) into a few shared shapes and modeled in Storm by
`slib.abusech.model` ({src}`svcs/abusech/src/abusechsvc/pkgproto/storm/modules/slib.abusech.model.storm`),
as the calling user. Bulk imports build the same nodes in Python (see [Bulk imports](bulk.md)).
This page lists every form, prop, tag, edge and source the package writes.

## Conventions

### Meta sources

The service's `add` event creates one `meta:source` per platform, with fixed guids
(`SOURCES` in {src}`svcs/abusech/src/abusechsvc/defs.py`):

| Platform | `meta:source` guid | `:name` | `:type` | `:url` |
|---|---|---|---|---|
| `bazaar` | `0880c1df548847f591cc4d25071e8ec7` | `malwarebazaar` | `slib.abusech.bazaar` | `https://bazaar.abuse.ch` |
| `urlhaus` | `30f3e2d0445842dc998e5d84667730d5` | `urlhaus` | `slib.abusech.urlhaus` | `https://urlhaus.abuse.ch` |
| `threatfox` | `72093b870fba45978e5a725ccf5d4af7` | `threatfox` | `slib.abusech.threatfox` | `https://threatfox.abuse.ch` |
| `yaraify` | `dfe12ed859bf4bbea106c0f9cec44fa8` | `yaraify` | `slib.abusech.yaraify` | `https://yaraify.abuse.ch` |
| `feodo` | `a4449303c07f41f782aa730f8d449033` | `feodo tracker` | `slib.abusech.feodo` | `https://feodotracker.abuse.ch` |
| `sslbl` | `af7571ed96af44cba0ceab4b6bf44c5b` | `ssl blacklist` | `slib.abusech.sslbl` | `https://sslbl.abuse.ch` |
| `hunting` | `2f9357321acd42188845ba7c95bf6471` | `abuse.ch hunting` | `slib.abusech.hunting` | `https://hunting.abuse.ch` |

Every observable and record the model creates (files, URLs, hosts, servers, IOC records,
rules, matches, scans, certificates, families, C2 configs, subfiles, URL files, DNS records)
gets a `meta:source -(seen)>` edge from the platform it came from (`seen()`), and its `.seen`
widened with abuse.ch's first/last seen times when it has them. Supporting nodes do not get a
`-(seen)>` edge: `meta:note`, `ps:contact`, `inet:passwd`, `inet:asn`, `inet:service:platform`,
`inet:service:account`, `crypto:x509:signedfile` (which gets one only when made for a file).

```text
// Everything ThreatFox has told you about.
meta:source=72093b870fba45978e5a725ccf5d4af7 -(seen)> *
```

### Tags

abuse.ch's tags, malware families, threat types and statuses become tags named
`<prefix>.<platform>.<tag>`:

- The prefix is the `slib:abusech:tag:prefix` global (default `rep.abusech`). When
  `slib:abusech:tag:enabled` is false no tags are applied, and families get no `:tag`.
  Both are set with `slib.abusech.admin.tags`.
- `<platform>` is `bazaar`, `urlhaus`, `threatfox`, `yaraify`, `feodo`, `sslbl` or `hunting`:
  the platform that reported it, not the form.
- Each abuse.ch value is normalized into one tag segment (`normTag()`): lower cased, every run
  of characters other than `a-z0-9_` replaced with `_`, and leading/trailing `_` stripped.
  `Cobalt Strike` is `cobalt_strike`, `Loki Password Stealer (PWS)` is
  `loki_password_stealer_pws`.
- Tags are added with `+?#`, so a value that isn't a valid tag is skipped silently.
- A tag carries the interval abuse.ch saw the node, when known (ex. a URL's added to last
  online, or an IOC's first to last seen). Intervals are ordered first, so a last seen before
  the first seen doesn't drop the tag.

Tag segments by record:

| Record | Tags under `<prefix>.<platform>.` |
|---|---|
| Sample (`file:bytes`) | each abuse.ch tag; each family (the signature, and `*_malware` file information such as `dropped_by_malware`); `type.<file type>`; `delivery.<method>`; `origin.<country>`; `magika.<type>`, `format.<format>`, `arch.<arch>`; `ole.<flag>` for each true `oleid` flag (ex. `ole.vba_macros`) |
| Vendor-unpacked child file | the families the vendor detected in it |
| ThreatFox IOC observable | the threat type (ex. `botnet_cc`), the family, each tag, `compromised` |
| ThreatFox payload sample | the IOC's family (with the sample's time) |
| URLhaus URL | the threat (ex. `malware_download`), each tag, `status.<url_status>`, `larted` |
| URLhaus host | each blacklist listing, `<list>.<status>` (ex. `spamhaus_dbl.abused_legit_malware`, `surbl.listed`); `not_listed`/`unlisted`/`none` are skipped |
| Extracted C2 (host/server) | `c2`, the family |
| Feodo Tracker IP and server | `c2`, the family, `status.<status>` |
| SSLBL certificate | `c2`, the family |
| SSLBL JA3 (`hash:md5`) | `ja3`, the family |
| YARA rule | `tlp.<matching TLP>`, `sharing.<sharing TLP>` |
| CSCB certificate | `cscb` |
| False positive | `fp`, `fp.<platform>` |

`status.*` tags are replaced: every existing `<prefix>.<platform>.status.*` tag is removed
before the current one is added (`setStatus()`). Bulk imports can't remove tags, see
[Bulk imports](bulk.md#differences-from-the-storm-model).

### Notes

Free text is modeled as a `meta:note` (`:type`, `:text`, `:author` a `ps:contact`,
`:created`) with a `meta:note -(about)> <node>` edge. Notes are guid nodes keyed on
`({"type", "text"[, "author"]})`, so the same text isn't added twice.

| `meta:note:type` | Text |
|---|---|
| `slib.abusech.<plat>.info` | MalwareBazaar file information values that aren't links, hashes or families (`<context>: <value>`), TrID results (`trid: ...`), the OLE summary (`ole: format: ..., container: ..., application: ..., author: ..., external relationships: ..., maldoc score: ...`), and olevba findings (`olevba <type>: <keyword> - <description>`) |
| `slib.abusech.<plat>.comment` | MalwareBazaar comments, by the commenter's `ps:contact`, with the comment date; the submitter's comment is first, dated at the first seen |
| `slib.abusech.<plat>.rule.desc` | A YARA rule's description, non-URL reference (`Reference: ...`) and license (`License: ...`) |
| `slib.abusech.<plat>.cscb` | The CSCB listing reason |
| `slib.abusech.sslbl.reason` | The SSLBL listing reason |
| `slib.abusech.sslbl.ja3` | `A JA3 TLS client fingerprint, listed by the abuse.ch SSL Blacklist.` (always, even with tagging off) |
| `slib.abusech.hunting.fp` | The false positive's removal notes, with `(removed by <who>)`, dated at the entry's time |

### Extended props

The `add` event adds these `file:bytes` props, for the fuzzy hashes abuse.ch provides that
Synapse doesn't model (`EXT_PROPS` in {src}`svcs/abusech/src/abusechsvc/defs.py`):

| Prop | Type | Meaning |
|---|---|---|
| `file:bytes:_sha3_384` | `hex` (size 96) | The SHA3-384 hash. |
| `file:bytes:_tlsh` | `str` (stripped, lower) | The TLSH fuzzy hash, always in its versioned form (`t1` + 70 hex characters). |
| `file:bytes:_telfhash` | `str` (stripped, lower) | The telfhash (ELF symbol fuzzy hash). |
| `file:bytes:_gimphash` | `str` (stripped, lower) | The gimphash (Go import hash). |
| `file:bytes:_dhash_icon` | `str` (stripped, lower) | The dhash (perceptual hash) of the file's icon. |

The model only sets them when they exist (`setProp()` checks `$lib.model.prop()`).

## Samples

A sample from any platform (`norm.normSample`: MalwareBazaar `get_info`, searches and CSV
exports, YARAify `metadata`, URLhaus payloads, ThreatFox `malware_samples`) is modeled by
`model.sample()`.

### Files

A file is keyed by its SHA256: `file:bytes=<sha256>`. A file known only by an MD5, SHA1 or
SHA3-384 reuses an existing `file:bytes` with that `:sha1`, `:md5`, or `:_sha3_384` (in that
order), else becomes `file:bytes=guid:<$lib.guid(<type>, <hash>)>` (ex.
`guid:` of `(sha1, <sha1>)`).

| abuse.ch field | Prop |
|---|---|
| `sha256_hash`, `sha1_hash`, `md5_hash` | `:sha256`, `:sha1`, `:md5` |
| `sha3_384_hash` | `:_sha3_384` |
| `file_size` (`response_size`) | `:size` |
| `file_name` (`filename`) | `:name`, only when the node has none (`n/a`, `unknown`, `none` are ignored) |
| `file_type_mime` (`mime_type`) | `:mime` |
| `imphash` (32 hex characters only) | `:mime:pe:imphash` |
| `ssdeep` | added to `:ssdeeps` |
| `tlsh`, `telfhash`, `gimphash`, `dhash_icon` | `:_tlsh`, `:_telfhash`, `:_gimphash`, `:_dhash_icon` |
| `first_seen`, `last_seen` | `.seen`, and the interval of the sample's tags |
| `file_type`, `tags`, `signature`, `delivery_method`, `origin_country`, `magika`, `file_format`, `file_arch` | tags, see [Tags](#tags) |

### Related records

| abuse.ch data | Synapse |
|---|---|
| `signature` | A malware family, see [Malware families](#malware-families). |
| `reporter` (unless `anonymous`) | An `inet:service:account -(refs)> file:bytes`, see [Reporters](#reporters). |
| `intelligence.clamav` (or `clamav`) | One `it:av:scan:result` per signature: `:scanner:name=clamav`, `:signame`, `:verdict=40`. |
| `vendor_intel` | An `it:av:scan:result` per vendor entry, see [Vendor scans](#vendor-scans). |
| `virustotal` (URLhaus: `{"result": "10 / 60", "percent", "link"}`) | An `it:av:scan:result` with `:scanner:name=virustotal`, `:multi:count` (total), `:multi:count:malicious` (hits), `:verdict` 40 with any hits else 10, and the link as `inet:url -(about)> file:bytes`. |
| `vtpercent` (MalwareBazaar CSV) | A `virustotal` `it:av:scan:result` with `:verdict` 40 when above 0, else 10. |
| `yara_rules` | An `it:app:yara:rule` per rule and an `it:app:yara:match` of it with the file, see [YARA rules and matches](#yara-rules-and-matches). |
| `code_sign` | A `crypto:x509:cert` per certificate and a `crypto:x509:signedfile`, see [Certificates](#certificates). |
| `file_information` links | `inet:url -(about)> file:bytes`. |
| `file_information` hashes (ex. `dropped_by_sha256`) | The related `file:bytes`, with `<dropper> -(linked)> <dropped>`: a `dropped_by` file `-(linked)>` this one, any other relation this one `-(linked)>` it. |
| `file_information` `*malware` values | Family tags on the file. |
| Other `file_information`, `trid`, `ole_information` | `meta:note` `slib.abusech.<plat>.info`, and `ole.*` tags. |
| `comment`, `comments` | `meta:note` `slib.abusech.<plat>.comment`. |
| `archive_pw` | `inet:passwd` and `file:bytes -(uses)> inet:passwd`. |
| YARAify unpacked files | `file:subfile` (`:parent` the sample, `:child` the unpacked file, `:path` its file name), and the child's own YARA matches. |
| URLhaus payload `urls` | The `inet:url` (modeled in full) and an `inet:urlfile` of it with the file, `.seen` the URL's first/last seen for that payload. |

### Vendor scans

Each `vendor_intel` entry is an `it:av:scan:result` (`model.scan()`), keyed on
`({"target:file", "scanner:name"[, "signame"]})`:

| Prop | Value |
|---|---|
| `:target:file` | the file |
| `:scanner:name` | the vendor, lower case: `any.run`, `cape`, `cert-pl_mwdb`, `yoroi_yomi`, `intezer`, `triage`, `reversinglabs`, `spamhaus_hbl`, `unpacme`, `filescan-io`, `kaspersky`, `docguard`, or another vendor's own name |
| `:signame` | the family or detection name the vendor reported |
| `:verdict` | `10` benign, `20` unknown, `30` suspicious, `40` malicious |
| `:time` | the vendor's analysis or first seen date |
| `:categories` | the vendor's tags/signatures, lower case |
| `:multi:count`, `:multi:count:malicious` | scanner counts (ReversingLabs `scanner_count`/`scanner_match`) |

Verdicts come from the vendor's verdict string (ex. `malicious`, `suspicious`, `clean`,
`no threats detected`), or a 0-100 score (70 and up is 40, 30 and up is 30, above 0 is 20, else
10). Triage's 1-10 score is 40 from 8, 30 from 6, else 10. A vendor that names a family without
a verdict is treated as malicious. Vendors not listed above are read with common key names
(`verdict`/`status`/..., `malware_family`/`family_name`/..., `analysis_url`/`report_link`/...).

Each scan also models:

- The report link as `inet:url -(about)> file:bytes`.
- Files the vendor unpacked (UnpacMe, and other vendors' `unpacked`/`children`) as
  `file:subfile`, tagged with their detected families. The sample itself is never its own
  child.
- Triage's extracted malware config C2s, see [C2 configs](#c2-configs).
- URLs the vendor found in the file (DocGuard `urls`) as `file:bytes -(refs)> inet:url`.

### C2 configs

Each C2 in a sandbox's extracted malware config (Triage `malware_config`, ex.
`{"extraction": "c2", "c2": "host:port"}`) is modeled by `model.c2config()`:

- The C2 as an observable: `inet:url`, `inet:fqdn`, `inet:ipv4`/`inet:ipv6`, or
  `inet:server` (with its IP), tagged `c2` and the family.
- An `it:sec:c2:config` keyed on `({"file"[, "family"]})`, with `:file` and `:family`, and the
  C2 added to `:servers` as an `inet:url`: the C2's URL itself, `tcp://<host>:<port>`, or
  `tcp://<host>` for a bare host (`tcp://[<ipv6>]` for IPv6).
- The family as a `risk:tool:software`.

There's no edge from the file to the C2; the config records it.

## YARA rules and matches

A rule (`norm.normRule`, from MalwareBazaar results and the `yara` export, YARAify results,
YARAhub rule lists, downloads and the rule export) is an `it:app:yara:rule` (`model.rule()`):

| Field | Prop / edge |
|---|---|
| guid | `({"ext:id": <yarahub uuid>, "name": <name>})`, or `({"name": <name>})` without a UUID |
| `rule_name` (`name`, `yara_rule_name`) | `:name` |
| `yarahub_uuid` (`uuid`) | `:ext:id` |
| `author` | `:author`, a `ps:contact` `({"name": <author>})` |
| `reference` (a URL) | `:url` |
| `date` | `:created` |
| `malpedia_family` | `:family` |
| the rule text | `:text`, replaced on every sighting (authors update rules in place) |
| `time_stamp` / `last_hit_utc` | `.seen` |
| `tlp` / `yarahub_rule_matching_tlp`, `yarahub_rule_sharing_tlp` | tags `tlp.<tlp>`, `sharing.<tlp>` (the `TLP:` prefix dropped) |
| `description`, non-URL `reference`, `yarahub_license` | `meta:note` `slib.abusech.<plat>.rule.desc` |
| `yarahub_reference_md5` | an `it:app:yara:match` of the rule with the reference sample (a `file:bytes` by MD5) |

Rules named `xxx` (YARAify's mask for non-public rules) are dropped, and a UUID of `xxx` is
ignored. A match is `it:app:yara:match=(<rule>, <file>)` with `.seen` the sample's first seen.

## Certificates

A code signing certificate (MalwareBazaar `code_sign`, or a CSCB entry) is a
`crypto:x509:cert` (`model.cert()`), keyed on `({"sha256"})`, else `({"sha1"})`, else
`({"md5"})` (the `thumbprint`, by `thumbprint_algorithm` or its length), else
`({"serial"[, "issuer"]})`:

| Field | Prop |
|---|---|
| `thumbprint` | `:sha256`, `:sha1` or `:md5` |
| `serial_number` (`serial`, `:` removed, hex only) | `:serial` |
| `subject_cn` | `:subject` |
| `issuer_cn` | `:issuer` |
| `valid_from`, `valid_to` | `:validity:notbefore`, `:validity:notafter` |
| `time_stamp` | `.seen` |
| `cscb_listed` (or from `get_cscb`) | tag `cscb`, and the `cscb_reason` as a `meta:note` |

A certificate from a sample also gets `crypto:x509:signedfile=(<cert>, <file>)`. The
signature algorithm isn't modeled.

## URLs

A URLhaus URL (`norm.normUrl`: `/url/`, `/urlid/`, recent URLs, host/tag/signature results,
the CSV exports) is an `inet:url` (`model.url()`):

| Field | Synapse |
|---|---|
| `url` | `inet:url` |
| `date_added` (`dateadded`), `last_online` | `.seen`, and the interval of every tag below |
| `threat`, `tags` | tags |
| `url_status` | tag `status.<status>`, replacing the old one |
| `larted` | tag `larted` |
| `host` | the host (`inet:fqdn`/`inet:ipv4`/`inet:ipv6`; a `host:port` is modeled as the host), tagged with the `blacklists` listings |
| `urlhaus_reference` (`urlhaus_link`) | `inet:url -(about)> <url>` |
| `reporter` (unless `anonymous`) | `inet:service:account -(refs)> <url>` |
| `payloads`, or the payload a signature result / payload export row carries | the sample, and `inet:urlfile=(<url>, <file>)` with `.seen` the payload's first/last seen on the URL |

A URLhaus host lookup (`model.urlhausHost()`) models the host with its listings (dated at its
`firstseen`), the host's URLhaus reference as `inet:url -(about)> <host>`, and every URL on it.

## ThreatFox IOCs

A ThreatFox IOC (`norm.normIoc`, from any IOC query or the JSON export) is modeled by
`model.ioc()` as its observable plus a record of the IOC.

The observable, typed by `ioc_type`:

| `ioc_type` | Form |
|---|---|
| `ip:port` | `inet:server` `tcp://<ip>:<port>` (and the `inet:ipv4`/`inet:ipv6`) |
| `domain` | `inet:fqdn` |
| `url` | `inet:url` |
| `md5_hash`, `sha1_hash`, `sha256_hash`, `sha3_384_hash` | `file:bytes` (a SHA3-384-only file is found by, or keyed on, `:_sha3_384`) |
| `envelope_from`, `body_from` | `inet:email` |

The observable gets `.seen` (first to last seen) and the IOC's tags. The record:

| Field | `it:sec:stix:indicator` prop / edge |
|---|---|
| guid | `({"id": "threatfox--<id>"})` |
| | `:name` `threatfox IOC <id>: <value>` |
| `confidence_level` | `:confidence` |
| `threat_type_desc` and `comment` | `:description` (joined by a blank line) |
| | `:pattern` (STIX 2.1, ex. `[domain-name:value = 'evil.com']`, or `[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '1.2.3.4' AND network-traffic:dst_port = 443]` for `ip:port`), `:pattern_type=stix` |
| `first_seen`, `last_seen` | `:created`, `:valid_from`, `:updated`, `.seen` |
| threat type, family, tags | `:labels` |
| | `-(detects)> <observable>` |
| `reference` (a URL) | `inet:url -(about)> <indicator>` |

Also modeled: the family (`malware_printable`, with `malware_alias` aliases, `malware` as
`:id`, and `malware_malpedia` as `inet:url -(about)> <family>`; ThreatFox's `Unknown ...`
placeholders aren't families), the reporter (`-(refs)> <observable>`), and each
`malware_samples` entry as a sample with `file:bytes -(uses)> <observable>` (its
`malware_bazaar` link as `inet:url -(about)> file:bytes`).

## Malware families

A malware family is a `risk:tool:software` keyed on its name and reporter:

```text
$lib.guid((reporter:name, abuse.ch), (soft:name, <the name normalized as it:prod:softname>))
```

which is the same guid `({"soft:name": <name>, "reporter:name": "abuse.ch"})` gives. So a
family is one node whatever the tag settings, the prefix, or the platform it was seen on, and
bulk imports key it the same way.

| Prop | Value |
|---|---|
| `:soft:name` | abuse.ch's name for the family (ex. `Loki Password Stealer (PWS)`, lower cased by Synapse) |
| `:soft:names` | the name and its aliases |
| `:reporter:name` | `abuse.ch` |
| `:type` | `malware` |
| `:id` | ThreatFox's Malpedia-style ID (ex. `win.cobalt_strike`) |
| `:tag` | `<prefix>.<platform>.<family tag>` from the first platform it was tagged on (never changed afterwards) |

Families come from MalwareBazaar signatures, ThreatFox IOCs, Feodo Tracker and SSLBL
entries, and extracted C2 configs. `:soft:name` and the tag segment don't always look alike
(`loki password stealer (pws)` vs `loki_password_stealer_pws`).

Before 0.4.0 families seen with tagging on were keyed on `({"tag": <tag>})`; see
[`slib.abusech.admin.families.merge`](commands-admin.md).

## Reporters

The abuse.ch user who reported something is an `inet:service:account` keyed on
`({"platform": <platform>, "user": <name>})`, on an `inet:service:platform`
`({"name": <platform name>})` with `:url` (`malwarebazaar`, `urlhaus`, `threatfox`,
`yaraify`, `feodo tracker`, `ssl blacklist`, `abuse.ch hunting`), with
`inet:service:account -(refs)> <node>`. Anonymous reports have no reporter.

## Blocklists

| Dataset | Synapse |
|---|---|
| Feodo Tracker C2 | `inet:ipv4`/`inet:ipv6` (`:asn` an `inet:asn` with `:name`, `:loc` the country) and `inet:server` `tcp://<ip>:<port>`, both tagged `c2`, the family and `status.<status>` with the first seen to last online interval; a hostname as `inet:fqdn` and `inet:dns:a`/`inet:dns:aaaa`; the family. |
| SSLBL certificate | `crypto:x509:cert` `({"sha1": <sha1>})`, tagged `c2` and the family (dated at the listing date), with the reason as a `meta:note`. |
| SSLBL JA3 | `hash:md5` (Synapse 2.x has no form for a bare JA3; `inet:tls:ja3:sample` needs the client), tagged `ja3` and the family, with the reason and a "this is a JA3" `meta:note`. |
| False positive | The entry's observable (typed by `entry_type`), tagged `fp` and `fp.<platform>`, with the removal notes as a `meta:note`. A sample's per-hash rows become one `file:bytes`. |

## Light edges

| Edge | Meaning |
|---|---|
| `meta:source -(seen)> <node>` | The node came from that platform. |
| `inet:url -(about)> <node>` | A reference or report link about a sample, URL, host, family, scan's file, or IOC record. |
| `meta:note -(about)> <node>` | A note about the node. |
| `inet:service:account -(refs)> <node>` | The abuse.ch user who reported it. |
| `it:sec:stix:indicator -(detects)> <observable>` | The ThreatFox IOC record. |
| `file:bytes -(refs)> inet:url` | A URL a vendor found in the file. |
| `file:bytes -(linked)> file:bytes` | A related sample (a dropper `-(linked)>` the file it dropped). |
| `file:bytes -(uses)> inet:passwd` | The sample archive's password. |
| `file:bytes -(uses)> <observable>` | A ThreatFox payload listed with the IOC. |

Synapse 2.256 declares `-(refs)>` and `-(linked)>` between any forms and `meta:note -(about)>`,
but not `-(about)>` from `inet:url`, `-(detects)>` from `it:sec:stix:indicator`, or
`-(uses)>` from `file:bytes` to these forms. Synapse 2.x allows light edges it doesn't declare.

Before 0.5.0 all of these (except `-(seen)>` and the notes' `-(about)>`) were `-(refs)>`, and
a file had a `-(refs)>` edge to each extracted C2; see
[`slib.abusech.admin.edges.migrate`](commands-admin.md).

## Deduplication

Nodes keyed by a primary value (`file:bytes` by SHA256, `inet:url`, `inet:fqdn`, IPs,
`inet:server`, `hash:md5`, `inet:passwd`, `inet:email`, `inet:asn`) merge with nodes from
anywhere else. Guid nodes are made with Storm's `({...})` syntax, which first looks for a node
with those props and otherwise uses the guid of them:

| Form | Keyed on |
|---|---|
| `file:bytes` (no SHA256) | an existing node with the hash, else `guid:<$lib.guid(<hash type>, <hash>)>` |
| `risk:tool:software` | `soft:name`, `reporter:name` |
| `it:sec:stix:indicator` | `id` (`<platform>--<ioc id>`) |
| `it:app:yara:rule` | `ext:id` and `name`, or `name` |
| `it:av:scan:result` | `target:file`, `scanner:name`, and `signame` when there is one |
| `it:sec:c2:config` | `file`, and `family` when there is one |
| `crypto:x509:cert` | `sha256`, `sha1`, `md5`, or `serial` (and `issuer`) |
| `inet:service:platform` | `name` |
| `inet:service:account` | `platform`, `user` |
| `meta:note` | `type`, `text`, and `author` when there is one |
| `ps:contact` | `name` |

So rerunning a lookup or import updates the same nodes. Most props are set with `?=`, so a
later sighting overwrites them (ex. `:text` of a rule, `:verdict` of a scan); `:name` of a
file is only set when unset, and family `:tag` only once.

## Not modeled

Popularity counters (MalwareBazaar download/upload/mail counts, ThreatFox credits and
sightings, YARAify sightings, MalwareBazaar YARA rule sample counts, URLhaus payload counts),
URLhaus URL IDs and takedown durations, ThreatFox IOC type descriptions, a sample's other file
names (only the first is `:name`), YARAify scan task lists, scan scores, links to abuse.ch's own
download endpoints, and certificate signature algorithms. They're still returned by the
service's `norm*` methods (see [the Telepath API](api.md)) and `slib.abusech.admin.request`.
