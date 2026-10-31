# abusech

A Synapse Advanced Power-Up (Storm Service) that integrates every abuse.ch platform into Synapse:

- **MalwareBazaar** - malware samples, their metadata, YARA/ClamAV/vendor intel, and code signing certificates.
- **URLhaus** - malware distribution URLs, hosts, and payloads.
- **ThreatFox** - IOCs (C2s, payload delivery, payloads) shared by the community.
- **YARAify** - YARA scanning, YARAhub rules, and file lookups.
- **Feodo Tracker** - botnet C2 blocklists (Dridex, Emotet, TrickBot, QakBot, BazarLoader, ...).
- **SSL Blacklist (SSLBL)** - malicious TLS certificates, botnet C2 IPs, and JA3 fingerprints.
- **Hunting** - the abuse.ch false positive list.

Every API endpoint and dataset is a method on the service, and is exposed through a Storm
command (related endpoints are combined into one command). Everything abuse.ch returns is
modeled, see [Data model](#data-model).

The service registers the `slib.abusech` Storm package. Everything is namespaced under `slib.abusech`.

## Deploying

The service is published as `ghcr.io/gormaniac/stormsvcs/abusech`.

```bash
docker run -d --name slib-abusech \
    -v /srv/slib-abusech:/vertex/storage \
    -e SYN_ABUSECHSVC_ABUSECH_APIKEY=<optional service-wide Auth-Key> \
    -p 27492:27492 \
    ghcr.io/gormaniac/stormsvcs/abusech:latest
```

Then add it to a Cortex (as an admin, adding the service creates extended model properties):

```
service.add slib.abusech tcp://<user>:<passwd>@<host>:27492/*
```

### Configuration

| Option | Env var | Default | Description |
|---|---|---|---|
| `abusech:apikey` | `SYN_ABUSECHSVC_ABUSECH_APIKEY` | none | Fallback Auth-Key, see [Auth-Keys](#auth-keys). |
| `abusech:ratelimit` | `SYN_ABUSECHSVC_ABUSECH_RATELIMIT` | `5.0` | Max requests/second sent to abuse.ch (0 disables it). |
| `abusech:timeout` | `SYN_ABUSECHSVC_ABUSECH_TIMEOUT` | `120` | Seconds before a single request times out. |
| `abusech:maxsize` | `SYN_ABUSECHSVC_ABUSECH_MAXSIZE` | `67108864` | Max bytes of a file downloaded from or submitted to abuse.ch. |
| `abusech:urls` | `SYN_ABUSECHSVC_ABUSECH_URLS` | abuse.ch's | Override base URLs (`bazaar`, `bazaar:export`, `urlhaus`, `urlhaus:submit`, `urlhaus:export`, `threatfox`, `threatfox:export`, `yaraify`, `yaraify:export`, `hunting`, `feodo`, `sslbl`). |

The service honors the standard `HTTP(S)_PROXY` environment variables.

## Auth-Keys

Every abuse.ch API requires a free Auth-Key from https://auth.abuse.ch/. One key works for
every platform. Keys are resolved in this order, per request:

1. **The calling user's own key** - set with `slib.abusech.apikey <key>`. It's stored in a
   user scoped Synapse vault (type `abusech`), so it is only ever used for that user's requests.
2. **The service-wide key** - set with `slib.abusech.admin.apikey <key>`. It's stored by the
   service, not the Cortex, so it can't be read back from Storm.
3. **The `abusech:apikey` config option.**

The Feodo Tracker and SSL Blacklist blocklists and the YARAhub rule export don't need a key (one is
sent when available). The MalwareBazaar, URLhaus, and ThreatFox exports take the key in their URL
(`https://<api>/v2/files/exports/<Auth-Key>/<file>`), which the service never includes in errors.

## Permissions

| Permission | Grants |
|---|---|
| `slib.abusech.user` | Lookups, searches, exports, blocklists, and setting your own key. |
| `slib.abusech.download` | Downloading malware samples into the Axon. |
| `slib.abusech.submit` | Sending data to abuse.ch: samples, URLs, IOCs, comments, YARAify scans, and YARA rules. |
| `slib.abusech.admin` | The service-wide key, tag settings, and raw API requests. |

Users don't need the `service.get` or Axon permissions. The `slib.abusech.priv.*` modules talk
to the service (and the Axon) and elevate privileges only for users that hold the matching
permission. Users still need the normal node permissions for the nodes the commands create.

## Commands

| Command | Description |
|---|---|
| `slib.abusech.enrich` | Enrich any supported node from every platform that knows its form (files/hashes, URLs, FQDNs, IPs, servers). `--platform` limits it. |
| `slib.abusech.bazaar.lookup` | Look up samples by MD5/SHA1/SHA256/SHA3-384 and model everything MalwareBazaar knows. |
| `slib.abusech.bazaar.search` | Search samples by `tag`, `signature`, `filetype`, `clamav`, `imphash`, `tlsh`, `telfhash`, `gimphash`, `dhash`, `yara`, `issuer`, `subject`, or `recent`. |
| `slib.abusech.bazaar.cscb` | Model the Code Signing Certificate Blocklist. |
| `slib.abusech.bazaar.download` | Download samples into the Axon (unzipped). |
| `slib.abusech.bazaar.submit` | Submit `file:bytes` from the Axon, with tags, delivery method, links, and context. |
| `slib.abusech.bazaar.update` | Comment on samples, or add information (`--add key=value`) to samples you submitted. |
| `slib.abusech.bazaar.export` | Model the `recent` or `full` CSV export. |
| `slib.abusech.urlhaus.lookup` | Look up URLs (or URL IDs), hosts, and payloads. |
| `slib.abusech.urlhaus.search` | URLs by `tag` or `signature`, and `recent-urls`/`recent-payloads`. |
| `slib.abusech.urlhaus.download` | Download payloads into the Axon (unzipped). |
| `slib.abusech.urlhaus.submit` | Report malware URLs. |
| `slib.abusech.urlhaus.export` | Model the `recent`, `online`, or `full` CSV export. |
| `slib.abusech.threatfox.lookup` | Look up IOCs by value, ID, or associated sample hash. |
| `slib.abusech.threatfox.search` | IOCs by `recent` (days), `tag`, or `malware`. |
| `slib.abusech.threatfox.ref` | Print the IOC/threat `types`, every `tags` and `malware` family, or find a malware `label`. |
| `slib.abusech.threatfox.submit` | Share IOCs (`inet:url`, `inet:fqdn`, `inet:server`, `file:bytes`, or `--ioc`). |
| `slib.abusech.threatfox.export` | Model the `recent` or `full` JSON export. |
| `slib.abusech.yaraify.lookup` | Look up files by hash, or scan task results by `--task`. |
| `slib.abusech.yaraify.search` | Files by `yara`, `clamav`, `imphash`, `gimphash`, `dhash`, `tlsh`, or `telfhash`. |
| `slib.abusech.yaraify.scan` | Scan files from the Axon (or rescan known files by hash), `--wait` models the results. |
| `slib.abusech.yaraify.tasks` | List the tasks for your identifier, or generate a new one with `--new`. |
| `slib.abusech.yaraify.rules` | Model YARAhub rules, with their text, by `--uuid`, `--recent` rules, your `--deployed` rules, or `--all` shared rules. |
| `slib.abusech.yaraify.deploy` | Deploy `it:app:yara:rule` nodes (or `--text`) for live hunting, or `--delete` your deployed rules. |
| `slib.abusech.yaraify.download` | Download (shared) files into the Axon (unzipped), or files YARAify unpacked with `--unpacked`. |
| `slib.abusech.feodo` | Model the `all`, `recommended`, or `aggressive` C2 blocklist. |
| `slib.abusech.sslbl` | Model the `certs`, `ips`, `ips-aggressive`, or `ja3` blocklist. |
| `slib.abusech.fplist` | Model the false positive list (optionally one `--platform`). |
| `slib.abusech.apikey` | Set/clear your own Auth-Key. |
| `slib.abusech.admin.apikey` | Set/clear/check the service-wide Auth-Key. |
| `slib.abusech.admin.tags` | Set the tag `--prefix` (default `rep.abusech`), `--enable` or `--disable` tagging. |
| `slib.abusech.admin.request` | Send a raw request to any abuse.ch API, for anything not covered above. |

Run any command with `--help` for all of its options and examples.

### Examples

```
// Everything abuse.ch knows about some files, URLs, and hosts.
#my.tag | slib.abusech.enrich

// The latest AgentTesla samples, and the URLs that served them.
slib.abusech.bazaar.search signature AgentTesla --limit 50 | slib.abusech.urlhaus.lookup

// Cobalt Strike C2s from ThreatFox, and the samples that use them.
slib.abusech.threatfox.search malware win.cobalt_strike | <(refs)- file:bytes

// Block the recommended Feodo Tracker C2s and SSLBL's C2 IPs.
slib.abusech.feodo recommended
slib.abusech.sslbl ips

// Scan a file with YARAify and model the YARA matches.
file:bytes=<sha256> | slib.abusech.yaraify.scan --unpack --wait 120 --yield | -> it:app:yara:match -> it:app:yara:rule
```

The `slib.abusech.lib` module can also be used directly from Storm:

```
$abusech = $lib.import(slib.abusech.lib)
$file = $abusech.bazaarLookup(<sha256>)
$urls = $abusech.urlhausSearch(tag, Mozi)
$iocs = $abusech.threatfox(malware, win.cobalt_strike, limit=(500))
```

## Data model

abuse.ch's tags, malware families, threat types, and statuses are applied as tags under the
prefix (default `rep.abusech`), per platform: `#rep.abusech.<platform>.<tag>` where platform is
`bazaar`, `urlhaus`, `threatfox`, `yaraify`, `feodo`, `sslbl`, or `hunting`. Tags carry the time
interval abuse.ch saw the node (ex. a URL's first seen to last online). Every node is linked to
the platform's `meta:source` with a `-(seen)>` edge, and has `.seen` updated from abuse.ch's timestamps.

| abuse.ch data | Synapse |
|---|---|
| Sample hashes, size, name, MIME type, imphash, ssdeep | `file:bytes` `:sha256`, `:sha1`, `:md5`, `:size`, `:name`, `:mime`, `:mime:pe:imphash`, `:ssdeeps` |
| SHA3-384, TLSH, telfhash, gimphash, icon dhash | Extended props `file:bytes:_sha3_384`, `:_tlsh`, `:_telfhash`, `:_gimphash`, `:_dhash_icon` (added when the service is added) |
| File type, tags, signature, delivery method, origin country | Tags, ex. `#rep.abusech.bazaar.type.exe`, `.agenttesla`, `.delivery.email_attachment`, `.origin.de` |
| Malware families | `risk:tool:software` (`:soft:name`, `:soft:names` aliases, `:id` Malpedia ID, `:tag` the family's tag), Malpedia link `inet:url -(refs)>` |
| Reporters | `inet:service:account` (on an `inet:service:platform` per abuse.ch platform) `-(seen)>` the node |
| ClamAV, vendor intel (ANY.RUN, Triage, ReversingLabs, ...), VirusTotal | `it:av:scan:result` (`:scanner:name`, `:signame`, `:verdict`, `:time`, `:categories`, `:multi:count`, `:multi:count:malicious`), report links as `inet:url -(refs)> file:bytes` |
| YARA rules and matches | `it:app:yara:rule` (`:name`, `:ext:id` YARAhub UUID, `:author`, `:url`, `:text`, `:created`, `:family`), TLP tag, description/license as a `meta:note`; `it:app:yara:match`. `:text` is only available for rules the author shares (TLP:WHITE), and is replaced when the author updates the rule. |
| Code signing certificates | `crypto:x509:cert` (`:sha256`/`:sha1` thumbprint, `:serial`, `:subject`, `:issuer`, `:validity:*`), `crypto:x509:signedfile`; CSCB listings tagged `#rep.abusech.bazaar.cscb` with the reason as a `meta:note` |
| Unpacked/related files | `file:subfile` (YARAify/UnpacMe unpacked files), droppers as `file:bytes -(refs)> file:bytes` |
| Comments, file information, OLE info | `meta:note -(about)>` the node |
| Archive passwords | `inet:passwd`, `file:bytes -(refs)> inet:passwd` |
| URLhaus URLs | `inet:url` tagged with the threat, tags, `status.<online/offline>`, `larted`; reference `inet:url -(refs)>`; payloads as `inet:urlfile` |
| URLhaus hosts | `inet:fqdn`/`inet:ipv4`/`inet:ipv6` tagged with Spamhaus DBL/SURBL listings (ex. `#rep.abusech.urlhaus.spamhaus_dbl.abused_legit_malware`) |
| ThreatFox IOCs | The observable (`inet:url`, `inet:fqdn`, `inet:server`, `inet:ipv4/6`, `file:bytes`) tagged with the threat type, family, tags, and `compromised`; the IOC record as an `it:sec:stix:indicator` (`:id`, `:confidence`, STIX `:pattern`, `:description` with the comment, `:labels`, `:created`, `:updated`) `-(refs)>` the observable; the reference as `inet:url -(refs)>`; samples as `file:bytes -(refs)>` the observable |
| Feodo Tracker/SSLBL C2s | `inet:server` and `inet:ipv4` tagged `c2`, the family, and `status.<status>`; `inet:ipv4:asn` (with `inet:asn:name`), `:loc`; hostnames as `inet:dns:a` |
| SSLBL certificates | `crypto:x509:cert:sha1` tagged `c2` and the family, with the listing reason as a `meta:note` |
| SSLBL JA3 fingerprints | `hash:md5` tagged `ja3` and the family, with the listing reason as a `meta:note` |
| False positive list | The entry's node tagged `#rep.abusech.hunting.fp` and `.fp.<platform>`, with the removal notes as a `meta:note` |

Not modeled: popularity counters (MalwareBazaar download/upload/mail counts, ThreatFox
credits), URLhaus takedown durations, and links to abuse.ch's own download endpoints. They
don't describe the indicators themselves, and are still available from the service's methods
and `slib.abusech.admin.request`.

## abuse.ch API coverage

| Platform | Endpoint | Storm |
|---|---|---|
| MalwareBazaar | `get_info` | `slib.abusech.bazaar.lookup`, `slib.abusech.enrich` |
| | `get_taginfo`, `get_siginfo`, `get_file_type`, `get_clamavinfo`, `get_imphash`, `get_tlsh`, `get_telfhash`, `get_gimphash`, `get_dhash_icon`, `get_yarainfo`, `get_issuerinfo`, `get_subjectinfo`, `get_recent` | `slib.abusech.bazaar.search` |
| | `get_cscb` | `slib.abusech.bazaar.cscb` |
| | `get_file` | `slib.abusech.bazaar.download` |
| | Sample upload | `slib.abusech.bazaar.submit` |
| | `update`, `add_comment` | `slib.abusech.bazaar.update` |
| | CSV exports (`recent.csv`, `full.csv.zip`) | `slib.abusech.bazaar.export` |
| URLhaus | `/url/`, `/urlid/`, `/host/`, `/payload/` | `slib.abusech.urlhaus.lookup`, `slib.abusech.enrich` |
| | `/tag/`, `/signature/`, `/urls/recent/`, `/payloads/recent/` | `slib.abusech.urlhaus.search` |
| | `/download/{sha256}/` | `slib.abusech.urlhaus.download` |
| | URL submission | `slib.abusech.urlhaus.submit` |
| | CSV exports (`recent.csv`, `online.csv`, `full.csv.zip`) | `slib.abusech.urlhaus.export` |
| ThreatFox | `search_ioc`, `search_hash`, `ioc` | `slib.abusech.threatfox.lookup`, `slib.abusech.enrich` |
| | `get_iocs`, `taginfo`, `malwareinfo` | `slib.abusech.threatfox.search` |
| | `types`, `tag_list`, `malware_list`, `get_label` | `slib.abusech.threatfox.ref` |
| | `submit_ioc` | `slib.abusech.threatfox.submit` |
| | JSON exports (`recent.json`, `full.json.zip`) | `slib.abusech.threatfox.export` |
| YARAify | `lookup_hash`, `get_results` | `slib.abusech.yaraify.lookup`, `slib.abusech.enrich` |
| | `get_yara`, `get_clamav`, `get_imphash`, `get_gimphash`, `get_dhash_icon`, `get_tlsh`, `get_telfhash` | `slib.abusech.yaraify.search` |
| | File scan, `rescan_file` | `slib.abusech.yaraify.scan` |
| | `list_tasks`, `generate_identifier` | `slib.abusech.yaraify.tasks` |
| | `get_yara_rule`, `recent_yararules`, `show_deployed_yara_rules`, the YARAhub rule export | `slib.abusech.yaraify.rules` |
| | YARA rule upload, `delete_yara_rule` | `slib.abusech.yaraify.deploy` |
| | `get_file`, `get_unpacked` | `slib.abusech.yaraify.download` |
| Feodo Tracker | `ipblocklist.json`, `ipblocklist_recommended.txt`, `ipblocklist_aggressive.csv` | `slib.abusech.feodo` |
| SSL Blacklist | `sslblacklist.csv`, `sslipblacklist.csv`, `sslipblacklist_aggressive.csv`, `ja3_fingerprints.csv` | `slib.abusech.sslbl` |
| Hunting | `get_fplist` | `slib.abusech.fplist` |
| Any | Anything else | `slib.abusech.admin.request` |

## Development

```bash
cd svcs/abusech
uv sync --dev
uv run pytest
```

The tests run a real Cortex with the service added, pointed at a fake abuse.ch HTTP server
(`tests/fakeabusech.py`), so no Auth-Key or network access is needed.

### Live tests

`tests/test_live.py` runs against the real abuse.ch APIs and is skipped by default. It only reads,
nothing is submitted:

```bash
# The keyless datasets only (Feodo Tracker and SSL Blacklist).
SLIB_ABUSECH_LIVE=1 uv run pytest tests/test_live.py

# Also the Auth-Key based APIs.
SLIB_ABUSECH_LIVE=1 ABUSECH_AUTH_KEY=<key> uv run pytest tests/test_live.py
```

Layout:

- `src/abusechsvc/client.py` - The HTTP transport shared by every abuse.ch API (Auth-Keys, rate limiting, retries, `query_status` errors, zips).
- `src/abusechsvc/svc.py` - `AbuseChSvc`, with a method per abuse.ch endpoint and dataset.
- `src/abusechsvc/api.py` - `AbuseChCellApi`, the Telepath API. Wraps every method in a `TelepathRetn`.
- `src/abusechsvc/norm.py` - Flattens abuse.ch's responses into a few shared shapes that are easy to model in Storm.
- `src/abusechsvc/pkgproto/` - The `slib.abusech` Storm package.
