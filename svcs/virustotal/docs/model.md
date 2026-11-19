# Data model

How VirusTotal objects become Synapse nodes. The Python service normalizes each VirusTotal
object into a flat dict ({src}`svcs/virustotal/src/vtsvc/norm.py`), and the Storm module
`slib.vt.model` ({src}`svcs/virustotal/src/vtsvc/pkgproto/storm/modules/slib.vt.model.storm`)
makes the nodes, as the calling user.

The package targets the Synapse 2.x model (`synapse_version` `>=2.234.0,<3.0.0`).

## Conventions

- **Source.** Every node the package creates or updates gets an edge from the service's
  source node: `meta:source=176fcd24cf1f42bfa5d95a013eec1487 -(seen)> <node>`. The source
  node (`:name virustotal`, `:type slib.vt`, `:url https://www.virustotal.com`) is made by
  the service's `add` event.
- **Times.** VirusTotal's epoch seconds are converted to epoch milliseconds.
- **Optional props** are set with `?=`, so a value that doesn't norm is skipped rather than
  failing the command. Later enrichments overwrite props with the new values.
- **Caps.** Lists are capped before modeling: 50 file names, 100 items of other lists
  (VirusTotal tags, YARA / IDS / Sigma results, DNS records, SANs, CRLs, redirects, threat
  names), and 50 of each behaviour list. One object never creates thousands of nodes.
- **Guid nodes** are deconflicted by list seeds that start with `slib.vt` (below), so
  enriching an object again updates the same nodes. These are the same guids the 0.2.0
  package generated.

## Scan results

The latest multi-engine scan of every file, domain, IP, and URL (`last_analysis_stats` and
`last_analysis_results`) is an `it:av:scan:result`. Each engine's result is another
`it:av:scan:result` with `:multi:scan` pointing at the overall one. `--engines` chooses which
engines are modeled: `detected` (verdict suspicious or malicious, the default), `all`, or
`none`.

| | Overall result | Per engine result |
| --- | --- | --- |
| Guid seed | `(slib.vt, scan, <form>, <repr>, <time>)` | `(slib.vt, scan, <form>, <repr>, <time>, <engine name>)` |
| `:scanner:name` | `virustotal` | `engine_name` (or the results key) |
| `:target:file` / `:target:fqdn` / `:target:ipv4` / `:target:ipv6` / `:target:url` | the node | the node |
| `:time` | `last_analysis_date` | the overall result's `:time` |
| `:verdict` | see below | from the engine's `category` |
| `:signame` | files: `popular_threat_classification.suggested_threat_label` | `result`, only for `malicious`/`suspicious` |
| `:categories` | files: the popular threat categories | |
| `:multi:count` | the sum of every count in `last_analysis_stats` | |
| `:multi:count:malicious` / `:suspicious` | `malicious` / `suspicious` | |
| `:multi:count:benign` | `harmless + undetected` | |
| `:multi:count:unknown` | the rest (`type-unsupported`, `timeout`, `failure`, ...) | |
| `:multi:scan` | | the overall result |

`<time>` is `:time` (epoch millis), or the string `latest` if VirusTotal gave no
`last_analysis_date`. Because the guid includes the scan time, a newer scan creates new
result nodes, and an unchanged one updates the existing nodes. An analysis
(`slib.vt.analysis`, `slib.vt.submit --wait`) of the same object at the same time maps to
the same nodes.

Verdicts use Synapse's `it:av:scan:result:verdict` values:

| Verdict | Value | Overall (from `last_analysis_stats`) | Per engine (`category`) |
| --- | --- | --- | --- |
| malicious | 40 | `malicious >= vt:verdict:malicious` (default 3) | `malicious` |
| suspicious | 30 | any `malicious` or `suspicious` below that | `suspicious` |
| benign | 10 | `harmless + undetected > 0` and no detections | `harmless`, `undetected` |
| unknown | 20 | no engine ran | anything else |

## Files

`file:bytes=sha256:<sha256>` (from a file report, a related file, or a search result):

| VirusTotal attribute | Synapse |
| --- | --- |
| `sha256` (or the object id, if 64 characters), lowercased | `:sha256` |
| `md5`, `sha1`, `size` | `:md5`, `:sha1`, `:size` |
| `meaningful_name`, else the first of `names` | `:name` |
| `ssdeep` | `:ssdeeps` (added to the array) |
| `pe_info.imphash` | `:mime:pe:imphash` |
| `pe_info.timestamp` | `:mime:pe:compiled` |
| `first_submission_date`, `last_submission_date` | `.seen` |

The file is linked to:

| VirusTotal | Synapse |
| --- | --- |
| `sandbox_verdicts.<key>` | `it:av:scan:result`, guid `(slib.vt, sandbox, <sha256>, <sandbox name>)`: `:scanner:name` (`sandbox_name` or the key), `:target:file`, `:verdict` (`category`, as for engines), `:signame` (the first of `malware_names`), `:categories` (`malware_classification`, lowercased). No `:time`, so it's updated in place. |
| `crowdsourced_yara_results[]` | `it:app:yara:rule`, guid `(slib.vt, yara, <ruleset_id>, <rule_name>)`: `:name`, `:ext:id` (`ruleset_id`), `:url` (`source`), `:author` (a `ps:contact`, guid `(slib.vt, contact, <author>)`, `:name`). Then `it:app:yara:match=(<rule>, <file>)` with `.seen` from `match_date`. |
| `crowdsourced_ids_results[]` | `it:app:snort:rule`, guid `(slib.vt, ids, <rule_id or rule_msg>)`: `:id` (`rule_id`), `:name` (`rule_msg`), `:desc` (`rule_category`), `:text` (`rule_raw`). `it:app:snort:rule -(matches)> file:bytes`. |
| `sigma_analysis_results[]` | `it:app:sigma:rule`, guid `(slib.vt, sigma, <rule_id>)`: `:id`, `:name` (`rule_title`), `:desc` (`rule_description`), `:author` (a `ps:contact`). `it:app:sigma:rule -(matches)> file:bytes`. |

### Behaviour summary

With `slib.vt.enrich --behaviour`, `GET /files/{sha256}/behaviour_summary` is modeled on the
file:

| `behaviour_summary` field | Synapse | Cap |
| --- | --- | --- |
| `dns_lookups[].hostname` | `file:bytes -(refs)> inet:fqdn` (hostnames with a `.`) | 50 lookups |
| `dns_lookups[].resolved_ips` | `inet:dns:a` / `inet:dns:aaaa` `(<hostname>, <ip>)` | 20 per lookup |
| `ip_traffic[]` (`destination_ip`, `destination_port`, `transport_layer_protocol` tcp/udp) | `file:bytes -(refs)> inet:server` (ex. `tcp://1.2.3.4:443`, `udp://[::1]:53`) | 50 unique |
| `http_conversations[].url` | `file:bytes -(refs)> inet:url` | 50 |
| `mitre_attack_techniques[].id` (upper cased, starting with `T`) | `file:bytes -(uses)> it:mitre:attack:technique` | 100 |
| `mutexes_created[]` | `file:bytes -(refs)> it:dev:mutex` | 50 unique |
| `files_dropped[].sha256` | `file:bytes -(refs)> file:bytes` | 50 unique |
| `verdicts[]`, `tags[]` | `<prefix>.behaviour.<part>` tags | 50 each |

Command lines, registry keys, memory patterns, and the rest of the summary aren't modeled.

## Domains

`inet:fqdn` from the object id (lowercased), with `.seen` from `first_seen_date`.

| VirusTotal attribute | Synapse |
| --- | --- |
| `last_dns_records[]` of type `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT` | `inet:dns:a` / `aaaa` / `cname` / `mx` / `ns` / `txt` `=(<fqdn>, <value>)`, the value without a trailing `.` (except TXT), `.seen` from `last_dns_records_date` |
| `last_dns_records[]` of type `SOA` | `inet:dns:soa`, guid `(slib.vt, soa, <fqdn>, <value>, <rname>)`: `:fqdn`, `:ns` (`value`), `:email` (`rname`) |
| `whois` (with `whois_date`) | `inet:whois:rec=(<fqdn>, <whois_date>)`: `:text` (`whois`), `:registrar` (`registrar`), `:created` (`creation_date`), `:expires` (`expiration_date`), `:updated` (`last_update_date`) |
| `last_https_certificate` | `crypto:x509:cert`, see [Certificates](#certificates) |

Not modeled: `categories`, `jarm`, popularity ranks, `reputation`, `total_votes`.

## IP addresses

`inet:ipv4` (if the address casts as one) or `inet:ipv6`.

| VirusTotal attribute | Synapse |
| --- | --- |
| `asn`, `as_owner` | `inet:asn=<asn>` with `:name` (`as_owner`), and the IP's `:asn` |
| `country` (lowercased) | `:loc` |
| `whois` | `inet:whois:iprec`, guid `(slib.vt, iprec, <ip>, <whois_date>, <whois>)`: `:text`, `:asof` (`whois_date`), `:asn`, `:country`, and `:net4` / `:net6` from `network` |
| `last_https_certificate` | `crypto:x509:cert` (see [Certificates](#certificates)), and `inet:tls:servercert=(tcp://<ip>:443, <cert>)` |
| `jarm` | `inet:ssl:jarmsample=(tcp://<ip>:443, <jarm>)` |

IPv6 servers are written `tcp://[<ip>]:443`. Not modeled: `regional_internet_registry`,
`first_seen_date`, `reputation`, `total_votes`.

## URLs

`inet:url` from `url`, with `.seen` from `first_submission_date` and `last_submission_date`.

| VirusTotal attribute | Synapse |
| --- | --- |
| `redirection_chain[]` | `inet:urlredir=(<prev>, <hop>)` for each hop, starting from the URL |
| `last_final_url` (if it differs from the URL and the last hop) | `inet:urlredir=(<last hop>, <final>)` |
| `last_http_response_content_sha256`, `last_http_response_content_length` | `file:bytes=sha256:<sha256>` with `:size`, and `inet:urlfile=(<final URL, or the URL>, <file>)` |

Not modeled: `title`, `last_http_response_code`, `categories`, `outgoing_links`,
`times_submitted`.

## Certificates

`last_https_certificate` (domains and IPs) and `historical_ssl_certificates` objects, when
they have a `thumbprint_sha256`. The node is deconflicted by `:sha256`:
`crypto:x509:cert=({"sha256": <thumbprint_sha256>})`.

| Certificate field | Synapse |
| --- | --- |
| `thumbprint_sha256` (lowercased) | `:sha256` |
| `thumbprint` | `:sha1` |
| `serial_number` (lowercased) | `:serial` |
| `subject`, `issuer` | `:subject`, `:issuer`, written `K=V, K=V` in VirusTotal's key order |
| `validity.not_before`, `validity.not_after` | `:validity:notbefore`, `:validity:notafter` |
| `subject == issuer` | `:selfsigned` |
| `extensions.subject_alternative_name` (lowercased, wildcard names dropped) | `:identities:fqdns` |
| `extensions.crl_distribution_points` | `:crl:urls` |
| `last_https_certificate_date` | `.seen` |

## Relationships

`slib.vt.related` models each related object by its type, linked to the inbound node's
subject (see [slib.vt.related](commands.md#slib-vt-related)):

| Related object type | Modeled as |
| --- | --- |
| `file`, `domain`, `ip_address`, `url` | Like `slib.vt.enrich` (with `--engines detected`), from the data in the relationship, with no extra requests. Tags are applied. |
| `resolution` | `inet:fqdn`, and `inet:dns:a` / `inet:dns:aaaa` `=(<host_name>, <ip_address>)` with `.seen` from `date` |
| `comment` | `meta:note -(about)>` the subject, see [Comments](#comments) |
| `whois` (`historical_whois`) | On an `inet:fqdn`: `inet:whois:rec=(<fqdn>, <asof>)`. On an IP: `inet:whois:iprec`, guid `(slib.vt, iprec, <ip>, <asof>, <text>)`. `:text` is rebuilt from `whois_map` as `Key: value` lines; `asof` is `last_updated` (or `first_seen_date`); `:registrar`, `:created` (`Creation Date`), `:expires` (`Registry Expiry Date` or `Expiry Date`), and `:updated` (`Updated Date`) come from `whois_map`. |
| `ssl_cert` (`historical_ssl_certificates`) | `crypto:x509:cert`, and on an IP also `inet:tls:servercert=(tcp://<ip>:443, <cert>)` |
| anything else (ex. `vote`, `graph`, `collection`) | Not modeled, printed as `<type> <id>` |

These relationships also get an edge between the subject and each related node; the others
(ex. `resolutions`, `subdomains`, `siblings`, `parent`) are linked only through the nodes'
props, or not at all:

| Collection | Relationship | Edge |
| --- | --- | --- |
| files | `contacted_domains`, `contacted_ips`, `contacted_urls`, `dropped_files`, `bundled_files`, `pe_resource_children` | `file:bytes -(refs)> <related>` |
| files | `pe_resource_parents`, `execution_parents` | `<related file> -(refs)> file:bytes` |
| domains | `communicating_files`, `referrer_files` | `<related file> -(refs)> inet:fqdn` |
| ip_addresses | `communicating_files`, `referrer_files` | `<related file> -(refs)> inet:ipv4/6` |
| urls | `last_serving_ip_address` | `inet:url -(refs)> inet:ipv4/6` |

## Comments

`slib.vt.comments` (and `comment` objects in `slib.vt.related`):

| Comment field | Synapse |
| --- | --- |
| `id` | the guid seed `(slib.vt, comment, <id>)` |
| `text` | `:text` |
| `date` | `:created` |
| | `:type` = `virustotal.comment.` (a `meta:note:type:taxonomy`) |

`meta:note -(about)> <subject>`. The comment's own tags and votes aren't modeled. Comments
with no text are skipped.

## Tags

Tags go under the prefix in the Cortex global `slib:vt:tag:prefix` (default `rep.vt`), and
only while `slib:vt:tag:enabled` is true (the default). Change both with
[`slib.vt.admin.tags`](commands.md#slib-vt-admin-tags).

| Tag | Applied to | From |
| --- | --- | --- |
| `<prefix>.verdict.malicious` / `.suspicious` / `.benign` | files, domains, IPs, URLs | The overall scan verdict. An unknown verdict adds no verdict tag. |
| `<prefix>.tag.<tag>` | files, domains, IPs, URLs | VirusTotal's `tags` |
| `<prefix>.family.<name>` | files | The first `popular_threat_classification.popular_threat_name` |
| `<prefix>.family.<name>` | URLs | Each of `threat_names` |
| `<prefix>.category.<category>` | files | Each `popular_threat_classification.popular_threat_category` |
| `<prefix>.behaviour.<part>` | files, with `--behaviour` | The behaviour summary's `verdicts` and `tags` |

Each tag part is lowercased, with every run of characters other than `a-z0-9_` replaced by
`_` and leading/trailing `_` stripped, ex. `Mal/HTMLGen-A` becomes `mal_htmlgen_a` and
`CVE-2017-0144` becomes `cve_2017_0144`.

Before an object's tags are applied, `<prefix>.verdict` (and every tag under it) is removed
from the node, so the verdict tag always reflects the latest scan. Every other tag is only
added, never removed. Tags are added with `+?#`, so a tag that doesn't norm is skipped.
Tags are applied by `slib.vt.enrich`, `slib.vt.related`, and `slib.vt.search`; analyses
apply none.

## Edges

| Edge | From | To |
| --- | --- | --- |
| `-(seen)>` | `meta:source` (slib.vt) | every node the package makes |
| `-(refs)>` | `file:bytes` | behaviour `inet:fqdn`, `inet:server`, `inet:url`, `it:dev:mutex`, dropped `file:bytes`; and the relationships above |
| `-(refs)>` | related `file:bytes`, `inet:url` | the relationships above |
| `-(uses)>` | `file:bytes` | `it:mitre:attack:technique` |
| `-(matches)>` | `it:app:snort:rule`, `it:app:sigma:rule` | `file:bytes` |
| `-(about)>` | `meta:note` (comments) | the subject node |

## Example pivots

```text
// The per engine results of a file (the overall one has no :multi:scan).
file:bytes:sha256=24d004a1... -> it:av:scan:result +:multi:scan

// Every domain the service has modeled.
meta:source=176fcd24cf1f42bfa5d95a013eec1487 -(seen)> inet:fqdn

// Files the service tagged malicious.
file:bytes#rep.vt.verdict.malicious

// The domains a file contacted in a sandbox.
file:bytes:sha256=24d004a1... -(refs)> inet:fqdn
```
