# abusech

A Synapse Advanced Power-Up (Storm Service) that integrates every abuse.ch platform into Synapse:

- **MalwareBazaar** - malware samples, their metadata, YARA/ClamAV/vendor intel, and code signing certificates.
- **URLhaus** - malware distribution URLs, hosts, and payloads.
- **ThreatFox** - IOCs (C2s, payload delivery, payloads) shared by the community.
- **YARAify** - YARA scanning, YARAhub rules, and file lookups.
- **Feodo Tracker** - botnet C2 blocklists (Dridex, Emotet, TrickBot, QakBot, BazarLoader, ...).
- **SSL Blacklist (SSLBL)** - malicious TLS certificates and JA3 fingerprints. (SSLBL's botnet C2 IP lists
  were deprecated on 2025-01-03, use Feodo Tracker or ThreatFox for C2 IPs.)
- **Hunting** - the abuse.ch false positive list.

Every API endpoint and dataset is a method on the service, and is exposed through a Storm
command (related endpoints are combined into one command). Everything abuse.ch returns is
modeled, see [Data model](#data-model).

The service registers the `slib.abusech` Storm package. Everything is namespaced under `slib.abusech`.
The package requires Synapse 2.256.0 or later (and before 3.0.0), the version it's tested with.

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
| `abusech:maxsize` | `SYN_ABUSECHSVC_ABUSECH_MAXSIZE` | `67108864` | Max bytes of a file downloaded from or submitted to abuse.ch, of any response or dataset read into memory, and of anything unzipped (each file, and all of a zip's files together). |
| `abusech:bulk:maxsize` | `SYN_ABUSECHSVC_ABUSECH_BULK_MAXSIZE` | `17179869184` | Max bytes of an export streamed to disk: a bulk import's staged copy, and the CSV exports the export commands read without `--bulk`. |
| `abusech:bulk:maxjobs` | `SYN_ABUSECHSVC_ABUSECH_BULK_MAXJOBS` | `4` | Max bulk import jobs at once. |
| `abusech:urls` | `SYN_ABUSECHSVC_ABUSECH_URLS` | abuse.ch's | Override base URLs (`bazaar`, `bazaar:export`, `urlhaus`, `urlhaus:submit`, `urlhaus:export`, `threatfox`, `threatfox:export`, `yaraify`, `yaraify:export`, `hunting`, `feodo`, `sslbl`). |

The service honors the standard `HTTP(S)_PROXY` environment variables.

Requests that fail in a way that may be temporary are retried up to 3 times, waiting 1, 2,
then 4 seconds, or as long as abuse.ch's `Retry-After` header says (at most 60 seconds): HTTP
429 and 503, and failing to connect, always; HTTP 500, 502, and 504, timeouts, and dropped
connections only for requests that are safe to repeat (not submissions, uploads, updates,
deletes, or `slib.abusech.admin.request`). Downloads of the exports and blocklists are retried
until their first byte arrives.

The ThreatFox JSON exports are parsed in memory. Without `--bulk` they're capped at
`abusech:maxsize`, which the `full` export unzips to more than by default, so import it with
`--bulk`, which caps it at `abusech:bulk:maxsize` instead.

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
| `slib.abusech.bulk` | Bulk importing exports (`--bulk`). Ingesting also needs the `node` permission on the layer. |
| `slib.abusech.submit` | Sending data to abuse.ch: samples, URLs, IOCs, comments, YARAify scans, and YARA rules. |
| `slib.abusech.admin` | The service-wide key, tag settings, raw API requests, and merging old malware family nodes. |

Users don't need the `service.get` or Axon permissions. The `slib.abusech.priv.*` modules talk
to the service (and the Axon) and elevate privileges only for users that hold the matching
permission. Users still need the normal node permissions for the nodes the commands create.

## Commands

| Command | Description |
|---|---|
| `slib.abusech.enrich` | Enrich any supported node from every platform that knows its form (files/hashes, URLs, FQDNs, IPs, servers). `--platform` limits it. |
| `slib.abusech.bazaar.lookup` | Look up samples by MD5/SHA1/SHA256 and model everything MalwareBazaar knows. |
| `slib.abusech.bazaar.search` | Search samples by `tag`, `signature`, `filetype`, `clamav`, `imphash`, `tlsh`, `telfhash`, `gimphash`, `dhash`, `yara`, `issuer`, `subject`, certificate `serial`, `recent`, or recent `detections`. |
| `slib.abusech.bazaar.cscb` | Model the Code Signing Certificate Blocklist. |
| `slib.abusech.bazaar.download` | Download samples into the Axon (unzipped). |
| `slib.abusech.bazaar.submit` | Submit `file:bytes` from the Axon, with tags, delivery method, links, typed references (`--ref any_run=<url>`), and context. |
| `slib.abusech.bazaar.update` | Comment on samples, or update samples you submitted (`--add add_tag=x`, `--add urlhaus=<url>`, ...). |
| `slib.abusech.bazaar.export` | Model the `recent` or `full` CSV export, or the `yara` rule statistics. `--bulk` imports the whole export at once (see [Bulk imports](#bulk-imports)). |
| `slib.abusech.urlhaus.lookup` | Look up URLs (or URL IDs), hosts (FQDNs and IPv4, URLhaus doesn't support IPv6), and payloads. |
| `slib.abusech.urlhaus.search` | URLs by `tag` or `signature`, and `recent-urls`/`recent-payloads`. |
| `slib.abusech.urlhaus.download` | Download payloads into the Axon (unzipped). |
| `slib.abusech.urlhaus.submit` | Report malware URLs. |
| `slib.abusech.urlhaus.export` | Model the `recent`, `online`, or `full` CSV export, or every collected `payloads` URL. `--bulk` imports the whole export at once. |
| `slib.abusech.threatfox.lookup` | Look up IOCs by value, ID, IP (its `ip:port` C2s), or sample hash (the hash's own IOC and the IOCs associated with the sample). |
| `slib.abusech.threatfox.search` | IOCs by `recent` (days), `tag`, or `malware`. Returns every match by default. |
| `slib.abusech.threatfox.ref` | Print the IOC/threat `types`, every `tags` and `malware` family, or find a malware `label`. |
| `slib.abusech.threatfox.submit` | Share IOCs (`inet:url`, `inet:fqdn`, `inet:server`, `file:bytes`, or `--ioc`). |
| `slib.abusech.threatfox.export` | Model the `recent` or `full` JSON export. `--bulk` imports the whole export at once. |
| `slib.abusech.yaraify.lookup` | Look up files by hash, or scan task results by `--task`. |
| `slib.abusech.yaraify.search` | Files by `yara`, `clamav`, `imphash`, `gimphash`, `dhash`, `tlsh`, or `telfhash`. |
| `slib.abusech.yaraify.scan` | Scan files from the Axon (or rescan known files by hash), `--wait` models the results. |
| `slib.abusech.yaraify.tasks` | List the `queued`, `processed`, or `all` tasks for your identifier, or generate a new one with `--new`. |
| `slib.abusech.yaraify.rules` | Model YARAhub rules, with their text, by `--uuid`, `--recent` rules, your `--deployed` rules, or `--all` shared rules. |
| `slib.abusech.yaraify.deploy` | Deploy `it:app:yara:rule` nodes (or `--text`) for live hunting, or `--delete` your deployed rules. |
| `slib.abusech.yaraify.download` | Download (shared) files into the Axon (unzipped), or files YARAify unpacked with `--unpacked`. |
| `slib.abusech.feodo` | Model the `all`, `recommended`, or `aggressive` C2 blocklist. |
| `slib.abusech.sslbl` | Model the `certs` or `ja3` blocklist. |
| `slib.abusech.fplist` | Model the false positive list (optionally one `--platform`). |
| `slib.abusech.apikey` | Set/clear your own Auth-Key. |
| `slib.abusech.admin.apikey` | Set/clear/check the service-wide Auth-Key. |
| `slib.abusech.admin.tags` | Set the tag `--prefix` (default `rep.abusech`, it must be a valid tag name), `--enable` or `--disable` tagging. |
| `slib.abusech.admin.families.merge` | Merge the malware family nodes made before 0.4.0 into the current ones, see [Malware families](#malware-families). A dry run unless `--apply`. |
| `slib.abusech.admin.edges.migrate` | Rewrite the `-(refs)>` edges made before 0.5.0 into the current edges, see [Light edges](#light-edges). A dry run unless `--apply`. |
| `slib.abusech.admin.request` | Send a raw request to any abuse.ch API, for anything not covered above. |

Run any command with `--help` for all of its options and examples.

Options that name what to look up (ex. `--hash`, or a blocklist or export) ignore the inbound
nodes: they run once per command, not once per inbound node, and the inbound nodes are dropped.

### Examples

```
// Everything abuse.ch knows about some files, URLs, and hosts.
#my.tag | slib.abusech.enrich

// The latest AgentTesla samples, and the URLs that served them.
slib.abusech.bazaar.search signature AgentTesla --limit 50 | slib.abusech.urlhaus.lookup

// Cobalt Strike C2s from ThreatFox, and the samples that use them.
slib.abusech.threatfox.search malware win.cobalt_strike | <(uses)- file:bytes

// Model the recommended Feodo Tracker C2s and SSLBL's JA3 fingerprints.
slib.abusech.feodo recommended
slib.abusech.sslbl ja3

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

## Bulk imports

Modeling an export row by row in Storm runs at about 50 rows/second, so the large exports
(MalwareBazaar `full`, URLhaus `full` and `payloads`, millions of rows) would take days. The
export commands' `--bulk` option imports a whole export at once instead:

1. The export is pulled from abuse.ch into the Cortex's Axon (the service streams it, so the
   Auth-Key never reaches Storm).
2. The file is copied from the Axon into a job directory in the service's storage
   (`<cell dir>/tmp/bulk/`), and its SHA256 is checked.
3. The service builds every node in Python (`abusechsvc.bulk`), the same nodes the Storm model
   creates, normalized with a copy of the Synapse data model so values match. Nodes are
   written in batches to a `syn.nodes` msgpack `.nodes` file.
4. The `.nodes` file is saved into the Axon and ingested with `$lib.feed.fromAxon()`, as the
   calling user.

Bulk imports can take hours for the full exports, so run them in the background:

```
background { slib.abusech.urlhaus.export full --bulk }
```

Every pull is recorded in the `slib:abusech:datasets` global, keyed `<platform>:<export>`
(ex. `urlhaus:full`): the export file's `sha256`, `size`, and pull `time`, and its `nodes` file
(`sha256`, `size`, `count` the nodes ingested, `built` the nodes built, `rows`, `skipped`,
`builder` version, and `time`).

- **Full exports** (`full`, `payloads`) reuse their last pull by default, so a service update can
  rebuild the same data without pulling it again. `--repull` pulls a new one. When the reused pull
  is more than a day old, the command warns that newer data isn't included.
- **Recent exports** (`recent`, `online`) can only be pulled once an hour, as abuse.ch asks.
  Within the hour, the command warns and stops: `--reuse` imports the last pull again, and
  `--repull` pulls a new one anyway.

Measured on the live recent exports: URLhaus `recent` (122,103 rows) built in 64s and ingested in
369s (~280 rows/s overall, vs ~51 rows/s modeling in Storm), ThreatFox `recent` (9,027 IOCs) in
32s, and MalwareBazaar `recent` (881 samples) in 5s. The bulk path's nodes were compared with the
Storm path's on that same live data and matched exactly (`tests/test_bulk.py` keeps checking it).

Since a bulk import can only add and set, it differs from the Storm model on nodes that already
exist: old `status.*` tags aren't removed, `file:bytes:ssdeeps` and
`risk:tool:software:soft:names` are replaced instead of added to, `file:bytes:name` is replaced,
and files only known by an MD5/SHA1 get their own `guid:` node instead of reusing an existing one.
Guid nodes made from props (`risk:tool:software`, `inet:service:account`, `it:av:scan:result`,
etc.) get the same guid Storm's `{...}` syntax would generate, but the service can't look up an
existing node with those props first, so one made some other way (ex. by hand) isn't reused.

A job belongs to the user that started it: only they can stage, build, read, or remove it (the
service checks both the Telepath user and the Storm user). At most `abusech:bulk:maxjobs` jobs
run at once, and a job's staged copy can be at most `abusech:bulk:maxsize` bytes.

A job's files are removed from the service's storage when the import finishes or fails. Jobs
left behind by a cancelled import are removed after 6 hours idle, and every job is removed when
the service restarts. The export and `.nodes` files stay in the Axon.

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
| Malware families | `risk:tool:software` keyed on its name and reporter, see [Malware families](#malware-families) (`:soft:name`, `:soft:names` aliases, `:id` Malpedia ID, `:tag` the family's tag on the first platform it was tagged on), Malpedia link `inet:url -(about)>` |
| Reporters | `inet:service:account` (on an `inet:service:platform` per abuse.ch platform) `-(refs)>` the node |
| ClamAV, vendor intel, VirusTotal | `it:av:scan:result` (`:scanner:name`, `:signame`, `:verdict`, `:time`, `:categories`, `:multi:count`, `:multi:count:malicious`), report links as `inet:url -(about)> file:bytes`. Each vendor (ANY.RUN, CAPE, CERT-PL MWDB, DocGuard, FileScan.IO, Intezer, Kaspersky, ReversingLabs, Spamhaus HBL, Triage, UnpacMe, YOROI) is read according to its own fields and scales |
| Extracted malware configs (Triage) | `it:sec:c2:config` (`:file`, `:family`, `:servers` with every C2: a URL C2 as itself, `host:port` as `tcp://host:port`, a bare host as `tcp://host`), the C2 host/server tagged `c2` and the family. The config records the file's C2s, there's no edge from the file to them |
| File format, architecture, Magika type, OLE flags | Tags, ex. `#rep.abusech.bazaar.format.pe`, `.arch.amd64`, `.magika.pebin`, `.ole.vba_macros`; TrID, OLE details, and olevba findings as `meta:note`s. URLs DocGuard found in a file as `file:bytes -(refs)> inet:url` |
| YARA rules and matches | `it:app:yara:rule` (`:name`, `:ext:id` YARAhub UUID, `:author`, `:url`, `:text`, `:created`, `:family`), matching and sharing TLP tags, description/license/reference as a `meta:note`; `it:app:yara:match`, including the sample the author wrote the rule for. Matches of non-public rules (masked as "xxx") aren't modeled. `:text` is only available for rules the author shares (TLP:WHITE), and is replaced when the author updates the rule. |
| Code signing certificates | `crypto:x509:cert` (`:sha256`/`:sha1` thumbprint, `:serial`, `:subject`, `:issuer`, `:validity:*`), `crypto:x509:signedfile`; CSCB listings tagged `#rep.abusech.bazaar.cscb` with the reason as a `meta:note` |
| Unpacked/related files | `file:subfile` (YARAify/UnpacMe unpacked files), related samples as `file:bytes -(linked)> file:bytes` (a dropper `-(linked)>` the file it dropped) |
| Comments, file information, OLE info | `meta:note -(about)>` the node |
| Archive passwords | `inet:passwd`, `file:bytes -(uses)> inet:passwd` |
| URLhaus URLs | `inet:url` tagged with the threat, tags, `status.<online/offline>`, `larted` (all with the URL's first seen to last online); reference `inet:url -(about)>`; payloads as `inet:urlfile` |
| URLhaus hosts | `inet:fqdn`/`inet:ipv4`/`inet:ipv6` tagged with Spamhaus DBL/SURBL listings (ex. `#rep.abusech.urlhaus.spamhaus_dbl.abused_legit_malware`), with the same time as the URL's tags. A `host:port` is modeled as the host |
| ThreatFox IOCs | The observable (`inet:url`, `inet:fqdn`, `inet:server`, `inet:ipv4/6`, `file:bytes`) tagged with the threat type, family, tags, and `compromised`; the IOC record as an `it:sec:stix:indicator` (`:id`, `:confidence`, STIX `:pattern`, `:description` with the comment, `:labels`, `:created`, `:updated`) `-(detects)>` the observable; the reference as `inet:url -(about)>`; samples as `file:bytes -(uses)>` the observable |
| Feodo Tracker/SSLBL C2s | `inet:server` and `inet:ipv4` tagged `c2`, the family, and `status.<status>`; `inet:ipv4:asn` (with `inet:asn:name`), `:loc`; hostnames as `inet:dns:a` |
| SSLBL certificates | `crypto:x509:cert:sha1` tagged `c2` and the family, with the listing reason as a `meta:note` |
| SSLBL JA3 fingerprints | `hash:md5` tagged `ja3` and the family, with the listing reason as a `meta:note`, and a `meta:note` (`:type=slib.abusech.sslbl.ja3`) saying it's a JA3, since Synapse 2.x has no form for a bare JA3 (`inet:tls:ja3:sample` needs the client) |
| False positive list | The entry's node tagged `#rep.abusech.hunting.fp` and `.fp.<platform>`, with the removal notes as a `meta:note`. A sample's per-hash rows are merged into one `file:bytes` |
| SHA3-384-only files (ThreatFox IOCs, the false positive list) | `file:bytes` keyed by `:_sha3_384` |

Not modeled: popularity counters (MalwareBazaar download/upload/mail counts, ThreatFox credits
and sightings, YARAify sightings, MalwareBazaar YARA rule sample counts, URLhaus payload counts),
URLhaus URL IDs and takedown durations, ThreatFox IOC type descriptions (the type is a tag), a
sample's other file names (only the first is `:name`, Synapse has one), YARAify scan task lists,
links to abuse.ch's own download endpoints, and certificate signature algorithms (Synapse wants
an OID). They don't describe the indicators themselves, and are still available from the
service's `norm*` methods and `slib.abusech.admin.request`.

`:soft:name` is abuse.ch's name for a family (ex. `Loki Password Stealer (PWS)`, lower cased by
Synapse), while its tag is normalized into a tag segment (`loki_password_stealer_pws`), so the
two don't always look alike.

### Malware families

A malware family is a `risk:tool:software` keyed on its name (as `:soft:name` normalizes it) and
`:reporter:name=abuse.ch`, the guid `({"soft:name": <name>, "reporter:name": "abuse.ch"})` gives.
So the same family is one node whatever the tag settings, the tag prefix, or the platform it was
seen on. Bulk imports key it the same way.

Before 0.4.0, families seen with tagging on were keyed on their tag instead
(`({"tag": "rep.abusech.<platform>.<family>"})`), so a family could have one node per platform
and tag prefix, plus one for tagging off (ABUSE-ST-01). New sightings no longer touch those
nodes. `slib.abusech.admin.families.merge` merges them into the current node for their name:

- Props the current node doesn't have are copied, array props (ex. `:soft:names`) are combined,
  and `.seen` is merged.
- Tags (with their times) and light edges (both directions) are moved.
- Props of other nodes that reference the old node (by guid, ndef, or in an array) are
  re-pointed at the current node.
- The old node is deleted. Tag props aren't moved.

Only nodes whose guid is the old tag-keyed guid of their `:tag` are merged, so nodes made some
other way are left alone. Without `--apply` it's a dry run that prints what it would merge, and a
second `--apply` finds nothing to do:

```
slib.abusech.admin.families.merge
slib.abusech.admin.families.merge --apply
```

### Light edges

| Edge | Meaning |
|---|---|
| `inet:url -(about)>` node | A reference/report link about a sample, URL, host, malware family, or IOC record |
| `inet:service:account -(refs)>` node | The abuse.ch user who reported it |
| `it:sec:stix:indicator -(detects)>` observable | The ThreatFox IOC record |
| `file:bytes -(refs)> inet:url` | A URL a vendor's scan found in the file |
| `file:bytes -(linked)> file:bytes` | A related sample (a dropper `-(linked)>` the file it dropped) |
| `file:bytes -(uses)> inet:passwd` | The archive's password |
| `file:bytes -(uses)>` observable | A ThreatFox payload listed with the IOC |

A file's C2s from a vendor's extracted malware config are in its `it:sec:c2:config:servers`
instead of an edge. Synapse 2.256 declares `-(refs)>` and `-(linked)>` between any forms, but not
`-(about)>` from `inet:url`, `-(detects)>` from `it:sec:stix:indicator`, or `-(uses)>` from
`file:bytes` to these forms (it declares `meta:note -(about)>`, `-(detects)>` from rule forms,
and `file:bytes -(uses)> math:algorithm`). Synapse 2.x allows light edges it doesn't declare.

Before 0.5.0 all of these were `-(refs)>`. `slib.abusech.admin.edges.migrate` rewrites the old
edges into the current ones:

- `inet:url -(refs)>` becomes `-(about)>`, `it:sec:stix:indicator -(refs)>` becomes
  `-(detects)>`, `file:bytes -(refs)> file:bytes` becomes `-(linked)>` (same direction), and
  `file:bytes -(refs)> inet:passwd` becomes `-(uses)>`.
- A file's edge to an observable becomes `-(uses)>` when the file is from ThreatFox and a
  ThreatFox `it:sec:stix:indicator` detects the observable (a payload listed with an IOC).
- Otherwise, a file's edge to a C2 is removed when one of its `it:sec:c2:config` nodes has the C2
  in `:servers`. Before 0.5.0 a C2 given as a bare host (no port) or as a URL wasn't put in
  `:servers`: a bare host is added as `tcp://host` (when the file has one config, with more the
  edge is kept with a warning), then the edge is removed. A URL C2 can't be told from a URL the
  vendor found in the file, so its edge is kept until the next lookup of the file puts it in
  `:servers`.
- Reporters' and vendor-found URLs' `-(refs)>` edges are kept.

Only edges between nodes linked to an abuse.ch `meta:source` (`-(seen)>`) are changed (an
`inet:passwd` isn't linked to one, so only its file has to be), so `-(refs)>` edges anything else
made are left alone. Without `--apply` it's a dry run that prints how many edges of each kind it
would change, and a second `--apply` changes nothing. It needs the `node.edge.add` and
`node.edge.del` permissions:

```
slib.abusech.admin.edges.migrate
slib.abusech.admin.edges.migrate --apply
```

Bulk imports make the current edges (builder version 3). Imports made before 0.5.0 have the old
ones, which the command also rewrites.

### Changes in 0.5.0

- The `-(refs)>` edges are replaced by `-(about)>`, `-(detects)>`, `-(linked)>`, and `-(uses)>`,
  and a file's extracted C2s are only in its `it:sec:c2:config`, see [Light edges](#light-edges).
  Run `slib.abusech.admin.edges.migrate` to rewrite the old edges.
- Every extracted C2 is in `it:sec:c2:config:servers`, including those given as a URL or a bare
  host.

### Changes in 0.4.0

- Malware families are keyed on their name, see above. Run `slib.abusech.admin.families.merge`
  to merge the old nodes.
- Reporters are linked with `-(refs)>` instead of `-(seen)>`, which is meant for `meta:source`.
  Existing `-(seen)>` edges from `inet:service:account` nodes are left as they are.
- The URLhaus `larted` and host blacklist tags carry the same time as the URL's other tags.
- JA3 fingerprints get a `meta:note` saying they're a JA3.
- Epoch timestamps are converted to dates (Synapse read `1700000000` as `YYYYMMDDhh`), and
  first/last seen pairs in mixed formats are ordered as times, not strings.
- Quoted CSV fields that span lines keep their `#` and blank lines, and the rows after them parse.
- `host:port` URLhaus/Feodo hosts are modeled as the host, instead of being dropped.
- Limits of 0 or less mean "the default" everywhere: the max (1000) for searches, and every
  result elsewhere. Negative limits are no longer sent to abuse.ch.
- Every response, download, and unzip read into memory is capped at `abusech:maxsize`, and
  exports streamed to disk at `abusech:bulk:maxsize`.
- A sample zip with no files or several files is an error, not "not available".
- `slib.abusech.admin.request` refuses paths that leave the API's base URL (ex. `../`).
- Retries, bulk job limits and owners, and running `--hash`-style options once, see above.


## abuse.ch API coverage

| Platform | Endpoint | Storm |
|---|---|---|
| MalwareBazaar | `get_info` | `slib.abusech.bazaar.lookup`, `slib.abusech.enrich` |
| | `get_taginfo`, `get_siginfo`, `get_file_type`, `get_clamavinfo`, `get_imphash`, `get_tlsh`, `get_telfhash`, `get_gimphash`, `get_dhash_icon`, `get_yarainfo`, `get_issuerinfo`, `get_subjectinfo`, `get_certificate`, `get_recent`, `recent_detections` | `slib.abusech.bazaar.search` |
| | `get_cscb` | `slib.abusech.bazaar.cscb` |
| | `get_file` | `slib.abusech.bazaar.download` |
| | Sample upload | `slib.abusech.bazaar.submit` |
| | `update`, `add_comment` | `slib.abusech.bazaar.update` |
| | Exports (`recent.csv`, `full.csv.zip`, `yara_rules.json`) | `slib.abusech.bazaar.export` |
| URLhaus | `/url/`, `/urlid/`, `/host/`, `/payload/` | `slib.abusech.urlhaus.lookup`, `slib.abusech.enrich` |
| | `/tag/`, `/signature/`, `/urls/recent/`, `/payloads/recent/` | `slib.abusech.urlhaus.search` |
| | `/download/{sha256}/` | `slib.abusech.urlhaus.download` |
| | URL submission | `slib.abusech.urlhaus.submit` |
| | Exports (`recent.csv`, `online.csv`, `full.csv.zip`, `payload.csv.zip`) | `slib.abusech.urlhaus.export` |
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
| Feodo Tracker | `ipblocklist.json`, `ipblocklist_recommended.json`, `ipblocklist_aggressive.csv` | `slib.abusech.feodo` |
| SSL Blacklist | `sslblacklist.csv`, `ja3_fingerprints.csv` | `slib.abusech.sslbl` |
| Hunting | `get_fplist` | `slib.abusech.fplist` |
| Any | Anything else | `slib.abusech.admin.request` |

Datasets that are left out on purpose, because another dataset above has the same (or more) data,
or they aren't data to model: the plain-text hash/URL/IP lists and hostfile/RPZ/MISP/Suricata/Snort/
ClamAV/vendor-firewall formats of every platform, the other URLhaus/ThreatFox CSV/JSON variants, the
MalwareBazaar code signing blocklist CSV (`get_cscb` has the same data), and the hourly/daily malware
sample batches (bulk zips of live malware).

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
- `src/abusechsvc/bulk.py` - `NodeBuilder`, which builds the bulk import nodes.
- `src/abusechsvc/pkgproto/` - The `slib.abusech` Storm package. Its `README.md` is a copy of this
  file (a test checks they match), copy it there after editing this one.

### Storm lint

The Storm code passes `python -m synapse.tools.storm.lint src`, and CI blocks on it. It also
passes `--v3-ready`: the 3.x-only changes that don't work on Synapse 2.x (the 3.x model renames,
`.seen`, `$node.form()` as a gtor, `$lib.globals.<name>`, and `$lib.utils.type()`) are
`// noqa`'d with a note, since the package requires Synapse <3.0.0.
