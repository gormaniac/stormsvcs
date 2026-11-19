# Telepath and Storm API

The service has two programmatic surfaces: the `slib.abusech.lib` Storm module, which queries,
models and returns nodes, and the service's Telepath API, which returns abuse.ch's data (raw
or normalized) without modeling it. Storm code should use the module; the Telepath API is
only reachable from Storm through the `slib.abusech.priv.*` modules.

## The `slib.abusech.lib` Storm module

Import it with `$lib.import(slib.abusech.lib)`. Importing it requires `slib.abusech.user`
(it imports `slib.abusech.priv.user`, an `asroot:perms` module). Node edits run as the
caller. Every function reports service errors as a warning (`slib.abusech: <what> failed:
<message>`) and returns `null`, an empty list, or emits nothing, instead of raising. The tag
settings are read once, when the module is imported.

| Function | Returns | Service call |
|---|---|---|
| `bazaarLookup(sha)` | `file:bytes` node or `null` | `normBazaarInfo` |
| `bazaarSearch(by, valu, limit=(100))` | list of `file:bytes` | `normBazaarSearch` |
| `bazaarRecent(selector=time)` | list of `file:bytes` | `normBazaarRecent` |
| `bazaarDetections(hours=(48))` | list of `file:bytes` | `normBazaarDetections` |
| `bazaarCscb()` | list of `crypto:x509:cert` | `normBazaarCscb` |
| `bazaarExport(kind=recent, limit=(0))` | emits `file:bytes` (or `it:app:yara:rule` for `yara`) | `bazaarExport` |
| `urlhausUrl(url=(null), urlid=(null))` | `inet:url` or `null` | `normUrlhausUrl` |
| `urlhausHost(host)` | the host node or `null` | `normUrlhausHost` |
| `urlhausPayload(sha)` | `file:bytes` or `null` | `normUrlhausPayload` |
| `urlhausSearch(by, valu, limit=(0))` | list of `inet:url` (`by` is `tag` or `signature`) | `normUrlhausSearch` |
| `urlhausRecent(kind=urls, limit=(null))` | list of `inet:url` (`urls`) or `file:bytes` (`payloads`) | `normUrlhausRecent` |
| `urlhausExport(kind=recent, limit=(0))` | emits `inet:url` | `urlhausExport` |
| `threatfox(by, valu=(null), limit=(100), exact=(false))` | list of IOC observable nodes | `normThreatfox` |
| `threatfoxExport(kind=recent, limit=(0))` | emits IOC observable nodes | `threatfoxExport` |
| `yaraifyLookup(sha, malpedia=(null))` | `file:bytes` or `null` | `normYaraifyHash` |
| `yaraifySearch(by, valu, limit=(25))` | list of `file:bytes` | `normYaraifySearch` |
| `yaraifyTask(taskid, malpedia=(null))` | `($status, $file)`: `("done", <file:bytes>)`, `(<status>, null)` while running, `("unknown", null)` for an unknown task, `(null, null)` on error | `normYaraifyResults` |
| `yaraifyRecentRules()` | list of `it:app:yara:rule` | `normYaraifyRecentRules` |
| `yaraifyDeployedRules()` | list of `it:app:yara:rule` | `normYaraifyDeployedRules` |
| `yaraifyRule(uuid)` | list of `it:app:yara:rule` | `yaraifyRule` |
| `yaraifyRulesExport(limit=(0))` | emits `it:app:yara:rule` | `yaraifyRulesExport` |
| `feodoBlocklist(kind=all, limit=(0))` | emits `inet:server` (or the IP) | `feodoBlocklist` |
| `sslblBlocklist(kind=certs, limit=(0))` | emits `crypto:x509:cert` (`certs`) or `hash:md5` (`ja3`) | `sslblBlocklist` |
| `fplist(platform=(null))` | list of observable nodes | `normFplist` |
| `enrich(node, platforms=(null))` | list of nodes (may contain `null`s), see [`slib.abusech.enrich`](commands.md) | several |

`threatfox()`'s `by` is `recent` (`valu` is days), `id`, `search` (with `exact`), `hash`,
`tag`, `malware`, `ip`, or `file` (see `normThreatfox` below).

```text
$abusech = $lib.import(slib.abusech.lib)
$file = $abusech.bazaarLookup(094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d)
$urls = $abusech.urlhausSearch(tag, Mozi)
$iocs = $abusech.threatfox(malware, win.cobalt_strike, limit=(500))
for $c2 in $abusech.feodoBlocklist(recommended) { $lib.print($c2.repr()) }
```

The lower level modules, `slib.abusech.model` (modeling a normalized record, ex.
`model.sample($s, bazaar)`), `slib.abusech.priv.*` and `slib.abusech.util`, are internal;
see [Internals](internals.md#the-storm-package).

## TelepathRetn

Every Telepath method returns (or, for generators, yields) a StormLib++
[`TelepathRetn`](https://docs.gormo.co/stormlibpp/), a dict:

| Key | Type | Meaning |
|---|---|---|
| `status` | bool | `true` if the call worked. |
| `mesg` | str | The error message when `status` is `false` (empty otherwise, except `setApiKey`). |
| `data` | any | The result when `status` is `true`, `null` on error. |

The API class `AbuseChCellApi` ({src}`svcs/abusech/src/abusechsvc/api.py`) subclasses
`stormlibpp.svc.RetnApi`, which generates a method for each name in `RETN_METHS` (calls the
cell's coroutine and wraps the result) and `GENR_METHS` (wraps each yielded item), and guards
every hand-written public method, so **no method raises to Storm**. Errors become
`status=false`:

| Error | `mesg` |
|---|---|
| `AbuseChApiError` (the only `RETN_ERRORS` entry; includes `NoApiKeyError`) and Synapse `AuthDeny` | The error's own message, ex. `abuse.ch bazaar: illegal_hash`, `abuse.ch threatfox: unknown_auth_key (check your Auth-Key)` |
| `ValueError`, `TypeError`, `BadArg` | `Invalid input: <message>` (ex. a non-integer ThreatFox IOC ID) |
| Anything else | `Unexpected error: <type>: <message>`, and the traceback is logged |

Every message goes through `_retnRedact()`, which replaces the stored and configured Auth-Keys
(raw and URL-quoted) with `<redacted>`.

A generator yields `status=true` items, and on an error yields one `status=false` item and
stops. In Storm:

```text
for $retn in $svc.feodoBlocklist(kind=all) {
    if (not $retn.status) { $lib.warn($retn.mesg) break }
    $lib.print($retn.data.ip)
}
```

The API carries the `slib.abusech` Storm service definition (`_storm_svc_name`,
`_storm_svc_vers` from the package version, the `add` event, and the package), which is what
`service.add` loads.

The methods do no permission checks of their own: the Storm package gates them. Every
method that talks to abuse.ch takes an optional `apikey` keyword, used before the stored and
configured keys (see [Auth-Keys](deployment.md#auth-keys)).

## Telepath methods

The `data` of each method; the shapes are in [Normalized shapes](#normalized-shapes).

### Keys and settings

| Method | Args | `data` |
|---|---|---|
| `setApiKey` | `apikey` (a string, or `null`/empty to clear) | `true`, with `mesg` `Set the slib.abusech Auth-Key.` or `Cleared the slib.abusech Auth-Key.` |
| `hasApiKey` | | bool: whether a stored or configured key exists |
| `maxSize` | | int: `abusech:maxsize` |
| `rawRequest` | `base`, `path=""`, `method="post"`, `form=None`, `json_data=None`, `params=None`, `apikey=None` | the parsed JSON response, or `null` for a "not found". `base` must be `bazaar`, `urlhaus`, `urlhaus:submit`, `threatfox`, `yaraify` or `hunting`; see [`slib.abusech.admin.request`](commands-admin.md) for the path rules. |

### MalwareBazaar

| Method | Args | `data` |
|---|---|---|
| `bazaarQuery` | `query`, `fields=None` (more form fields), `apikey` | the raw response (`null` when not found) |
| `bazaarInfo` | `sha` (MD5, SHA1 or SHA256) | the raw `get_info` record, or `null` |
| `normBazaarInfo` | `sha` | a sample, or `null` |
| `bazaarSearch` | `by` (see [`bazaar.search`](commands-bazaar.md)), `valu`, `limit=100` | raw list |
| `normBazaarSearch` | `by`, `valu`, `limit=100` | list of samples, cut to `limit` (`0` keeps all) |
| `bazaarRecent` | `selector="time"` (`time` or `100`) | raw list |
| `normBazaarRecent` | `selector="time"` | list of samples |
| `bazaarDetections` | `hours=48` (1-168) | raw list |
| `normBazaarDetections` | `hours=48` | list of samples |
| `bazaarCscb` | | raw list |
| `normBazaarCscb` | | list of certs (`blocklisted: true`) |
| `bazaarFile` | `sha256` | a downloaded file, or `null` when not available |
| `bazaarUpload` | `chunks` (list of bytes), `name`, `anonymous=False`, `tags=None`, `delivery_method=None`, `references=None` (dict of lists), `context=None` (dict), `apikey` | the raw response |
| `bazaarUpdate` | `sha256`, `key` (one of the `--add` keys), `valu` | the raw response |
| `bazaarComment` | `sha256`, `comment` | the raw response |

### URLhaus

| Method | Args | `data` |
|---|---|---|
| `urlhausUrl` | `url` | raw `/url/` response, or `null` |
| `urlhausUrlId` | `urlid` | raw `/urlid/` response, or `null` |
| `normUrlhausUrl` | `url=None`, `urlid=None` (`urlid` wins) | a URL, or `null` |
| `urlhausHost` | `host` (FQDN or IPv4) | raw `/host/` response, or `null` |
| `normUrlhausHost` | `host` | a host, or `null` |
| `urlhausPayload` | `sha` (MD5 or SHA256) | raw `/payload/` response, or `null` |
| `normUrlhausPayload` | `sha` | a sample with `urls` (each URL with `seen` and `last_seen`), or `null` |
| `urlhausTag` / `urlhausSignature` | `tag` / `signature` | raw response, or `null` |
| `normUrlhausSearch` | `by` (`tag` or `signature`), `valu`, `limit=0` | `{"first_seen", "last_seen", "url_count", "payload_count", "urls": [<URL>, ...]}` |
| `urlhausRecentUrls` / `urlhausRecentPayloads` | `limit=None` | raw response |
| `normUrlhausRecent` | `kind="urls"` (`urls` or `payloads`), `limit=None` | list of URLs or samples |
| `urlhausDownload` | `sha256` | a downloaded file, or `null` |
| `urlhausSubmit` | `urls` (list), `threat="malware_download"`, `tags=None`, `anonymous=False` | str: URLhaus' response text |

### ThreatFox

| Method | Args | `data` |
|---|---|---|
| `threatfoxQuery` | `query`, `body=None` (more JSON fields) | raw response |
| `threatfoxRecent` | `days=1` (1-7) | raw list |
| `threatfoxIoc` | `iocid` (int) | the raw IOC, or `null` |
| `threatfoxSearch` | `term`, `exact=False` | raw list |
| `threatfoxHash` | `sha` (MD5 or SHA256) | raw list |
| `threatfoxTag` / `threatfoxMalware` | `tag` / `malware`, `limit=100` (1-1000) | raw list |
| `normThreatfox` | `by`, `valu=None`, `limit=100`, `exact=False` | list of IOCs |
| `threatfoxTypes` | | raw dict, `{<id>: {"ioc_type", "fk_threat_type", "description"}}` |
| `threatfoxTagList` | | raw dict, `{<tag>: {"first_seen", "last_seen", "color"}}` |
| `threatfoxMalwareList` | | raw dict, `{<malware>: {"malware_printable", "malware_alias"}}` |
| `threatfoxLabel` | `malware`, `platform=None` | raw list |
| `threatfoxSubmit` | `threat_type`, `ioc_type`, `malware`, `iocs` (list), `confidence=50`, `reference=None`, `comment=None`, `tags=None`, `anonymous=False`, `compromised=False` | the raw response |

`normThreatfox`'s `by`: `recent` (`valu` is days, default 1), `id`, `search` (uses
`exact`), `hash`, `tag`, `malware` (both send `limit`), `ip` (non-exact search filtered to
the IP and its `ip:port` IOCs), or `file` (an exact search for the hash, plus `search_hash`
for MD5/SHA256, deduplicated by ID). The result is cut to `limit` (`0` keeps all), except
for `id`.

### YARAify

| Method | Args | `data` |
|---|---|---|
| `yaraifyQuery` | `query`, `body=None` | raw response |
| `yaraifyHash` | `sha` (MD5, SHA1, SHA256 or SHA3-384), `malpedia=None` | raw `lookup_hash` data, or `null` |
| `normYaraifyHash` | `sha`, `malpedia=None` | a sample with `unpacked` and `tasks`, or `null` |
| `yaraifySearch` | `by`, `valu`, `limit=25` | raw list |
| `normYaraifySearch` | `by`, `valu`, `limit=25` | list of samples |
| `yaraifyRecentRules` / `yaraifyDeployedRules` | | raw lists |
| `normYaraifyRecentRules` / `normYaraifyDeployedRules` | `text=True` | list of rules, with `text` downloaded when `text` is true |
| `yaraifyRule` | `uuid` | list of rules parsed from the downloaded text (`[]` when not found) |
| `yaraifyResults` | `task_id`, `malpedia=None` | raw results, a status string (ex. `queued`), or `null` for an unknown task |
| `normYaraifyResults` | `task_id`, `malpedia=None` | `{"status": "done", "task_id", "file": <sample>}`, `{"status": "<status>", "task_id", "file": null}`, or `null` |
| `yaraifyTasks` | `identifier`, `status="processed"` (`queued`, `processed`, or `None` for all) | raw list (`[]` for "no results") |
| `normYaraifyTasks` | `identifier`, `status="processed"` | list of tasks |
| `yaraifyIdentifier` | | the new identifier (as YARAify returns it, a string or `{"identifier": ...}`) |
| `yaraifyRescan` | `sha` | `{"task_id": ...}` |
| `yaraifyScan` | `chunks`, `name`, `identifier=None`, `clamav_scan=True`, `unpack=False`, `share_file=False`, `skip_known=False`, `skip_noisy=False` | `{"task_id": ...}` |
| `yaraifyDeploy` | `text`, `name="rule.yar"` | the response `data`, or its `query_status` |
| `yaraifyDeleteRule` | `uuid` | the response `data`, or its `query_status` |
| `yaraifyFile` / `yaraifyUnpacked` | `sha256` | a downloaded file, or `null` |

### Hunting and bulk imports

| Method | Args | `data` |
|---|---|---|
| `fplist` | | raw dict keyed by entry ID |
| `normFplist` | `platform=None` | list of false positives |
| `bulkExports` | | `[["bazaar", "recent"], ["bazaar", "full"], ["urlhaus", "recent"], ["urlhaus", "online"], ["urlhaus", "full"], ["urlhaus", "payloads"], ["threatfox", "recent"], ["threatfox", "full"]]` |
| `bulkStart` | `plat`, `kind`, `sha256`, `user=None` | str: the job ID |
| `bulkStage` | `jobid`, `byts`, `user=None` | int: the staged size so far |
| `bulkDone` | `jobid`, `user=None` | `true` |

### Generators

| Method | Args | Yields (`data` of each item) |
|---|---|---|
| `bazaarExport` | `kind="recent"` (`recent`, `full`, `yara`), `limit=0` | samples (rules for `yara`) |
| `urlhausExport` | `kind="recent"` (`recent`, `online`, `full`, `payloads`), `limit=0` | URLs (a `payloads` row is a URL with its payload) |
| `threatfoxExport` | `kind="recent"` (`recent`, `full`), `limit=0` | IOCs |
| `yaraifyRulesExport` | `limit=0` | rules |
| `feodoBlocklist` | `kind="all"` (`all`, `recommended`, `aggressive`), `limit=0` | C2s |
| `sslblBlocklist` | `kind="certs"` (`certs`, `ja3`), `limit=0` | SSLBL certs or JA3s |
| `bulkPull` | `plat`, `kind`, `apikey=None` | raw bytes chunks of the export, as served (zipped or not); an error once it's over `abusech:bulk:maxsize` |
| `bulkBuild` | `jobid`, `prefix=None`, `batch=None` (default 1000), `user=None` | progress dicts, see [Bulk imports](bulk.md#service-side-steps) |
| `bulkNodes` | `jobid`, `chunk=None` (default 1 MiB), `user=None` | raw bytes chunks of the job's `.nodes` file |

`limit=0` (or negative) yields everything. `bulkStart`, `bulkStage`, `bulkBuild`,
`bulkNodes` and `bulkDone` are hand-written: they turn `user` (the Storm user iden the
`slib.abusech.priv.bulk` module passes) into a job owner `<Telepath user iden>:<user>`, and
a job used by another owner is reported as unknown.

## Normalized shapes

The dict shapes `norm.py` returns. Times are strings Synapse's time type parses
(`YYYY-MM-DD[ HH:MM[:SS[.fff]]]`, epoch values converted to UTC). Missing values are `null`
(or `[]` for lists).

### Sample

```json
{
  "sha256": "094f...", "md5": "f1f1...", "sha1": "1a2b...", "sha3_384": null,
  "size": 1234567, "name": "invoice.exe", "names": ["invoice.exe"],
  "mime": "application/x-dosexec", "type": "exe",
  "first_seen": "2026-10-01 12:00:00", "last_seen": "2026-10-02 08:30:00",
  "signature": "AgentTesla", "families": ["agenttesla", "guloader"], "tags": ["agenttesla", "exe"],
  "reporter": "abuse_ch", "origin_country": "de", "delivery_method": "email_attachment",
  "imphash": "f34d...", "tlsh": "t1a2b3c4d5e6f7", "telfhash": null, "gimphash": null,
  "ssdeep": "24576:abcdefg:hijklmn", "dhash_icon": "e8e8b2b2b2b2e8e8", "magika": null,
  "archive_pw": null,
  "clamav": ["Win.Trojan.AgentTesla-1234"],
  "rules": ["<rule>"], "certs": ["<cert>"], "scans": ["<scan>"],
  "links": [{"context": "twitter", "url": "https://twitter.com/abuse_ch/status/1"}],
  "related": [{"rel": "dropped_by", "sha256": "dddd..."}],
  "notes": ["comment: Seen in a phishing campaign"],
  "comments": [{"id": null, "time": "2026-10-01 12:00:00", "author": "abuse_ch", "text": "..."}],
  "attrs": ["format.pe", "arch.amd64", "ole.vba_macros"]
}
```

Extra keys by source: `seen` and `last` (a payload on a URL, or a ThreatFox sample's `seen`),
`urls` (URLhaus payload lookups), `unpacked` (`[{"sha256", "md5", "name", "rules"}]`) and
`tasks` (task IDs) for YARAify files.

### Rule, cert and scan

```json
{"name": "...", "uuid": null, "author": null, "desc": null, "url": null, "date": null,
 "time": null, "tlp": "clear", "sharing_tlp": null, "refmd5": null, "license": null,
 "family": null, "text": null}
```

```json
{"md5": null, "sha1": null, "sha256": "bbbb...", "serial": "00c8f5d1e1a2b3c4d5",
 "subject": "Evil Corp LLC", "issuer": "Sectigo RSA Code Signing CA",
 "notbefore": "2026-01-01 00:00:00", "notafter": "2027-01-01 00:00:00",
 "algo": "sha256WithRSAEncryption", "blocklisted": true,
 "reason": "Used to sign AgentTesla", "time": null}
```

```json
{"vendor": "triage", "verdict": 40, "signame": "AgentTesla", "score": 100.0,
 "link": "https://...", "time": null, "categories": [], "count": null, "malicious": null,
 "children": [{"sha256": "...", "md5": null, "sha1": null, "families": []}],
 "c2s": [{"c2": "1.2.3.4:443", "obs": {"form": "inet:server", "...": "..."}, "host": "1.2.3.4",
          "port": 443, "url": "tcp://1.2.3.4:443", "family": "AgentTesla",
          "family_tag": "agenttesla"}],
 "urls": []}
```

### URL and host

```json
{"id": "123", "url": "http://evil.example/x.exe", "status": "online",
 "host": {"form": "inet:fqdn", "valu": "evil.example"},
 "added": "2026-10-01 12:00:00", "last_online": "2026-10-02 12:00:00",
 "threat": "malware_download", "tags": ["elf", "mozi"], "reporter": "abuse_ch",
 "larted": true, "takedown": null, "reference": "https://urlhaus.abuse.ch/url/123/",
 "blacklists": ["spamhaus_dbl.abused_legit_malware"], "payloads": ["<sample>"]}
```

A host (`normUrlhausHost`) is `{"host": <obs>, "first_seen", "url_count", "reference",
"blacklists", "urls": [<URL>, ...]}`.

### IOC

```json
{"id": "41", "ioc": "1.2.3.4:443", "ioc_type": "ip:port", "ioc_type_desc": "...",
 "threat_type": "botnet_cc", "threat_type_desc": "...", "malware": "win.cobalt_strike",
 "family": "Cobalt Strike", "family_tag": "cobalt_strike", "aliases": [],
 "malpedia": null,
 "confidence": 75, "first_seen": "...", "last_seen": null, "reference": null,
 "reporter": "abuse_ch", "tags": ["cobaltstrike"], "comment": null, "compromised": false,
 "sightings": null, "credits": [],
 "obs": {"form": "inet:server", "valu": "1.2.3.4:443", "ip": "1.2.3.4", "ipform": "inet:ipv4", "port": 443},
 "pattern": "[network-traffic:dst_ref.type = 'ipv4-addr' AND ...]", "samples": ["<sample>"]}
```

An observable (`obs`) is `{"form", "valu"}`, plus `ip`, `ipform`, `port` for `inet:server`
and `hashes` (ex. `{"sha256": ...}`) for `file:bytes`.

### Blocklist entries, tasks, false positives, downloads

| Shape | Keys |
|---|---|
| C2 (Feodo) | `ip`, `ipform`, `port`, `family`, `family_tag`, `status`, `first_seen`, `last_online`, `hostname`, `asn`, `as_name`, `country`, `source` |
| SSLBL cert | `sha1`, `time`, `reason`, `family`, `family_tag` |
| SSLBL JA3 | `ja3`, `first_seen`, `last_seen`, `reason`, `family`, `family_tag` |
| YARAify task | `task_id`, `time`, `status`, `name`, `sha256`, `md5`, `clamav_scan`, `unpack`, `share_file`, `rules`, `clamav`, `unpacked`, `sample` |
| False positive | `obs`, `time`, `platform`, `removed_by`, `notes` |
| Downloaded file | `name` (the name in the zip), `size`, `sha256`, `bytes` (the unzipped file) |
