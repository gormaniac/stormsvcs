# Model

Modeling is split in two. The service's `normSample` (see {src}`svcs/hatching/src/hatchingsvc/norm.py`)
fetches a reported sample's metadata, overview report, static report, and (with `--tasks`) every
reported behavioral task report, and flattens them into one normalized dict. The Storm module
`slib.hatching.model` ({src}`svcs/hatching/src/hatchingsvc/pkgproto/storm/modules/slib.hatching.model.storm`)
turns that dict into nodes, running as the calling user. The normalized shape is documented in
[API](api.md#normsample).

Everything below is written by `slib.hatching.enrich`, and by `search`, `sample.wait`, and
`submit --wait` when they model. `download` and `yara.get --yield` write the few nodes listed
under [Other commands](#other-commands).

## Conventions

- **The source.** Every node modeled from an analysis is linked from the service's source,
  `meta:source=76172c35a9074f998791a9d2b69ff6d8` (`:name="hatching triage"`,
  `:type=slib.hatching`, `:url=https://tria.ge`), with a `-(seen)>` edge. The source is created
  by the service's `add` event (see [Deployment](deployment.md#persistent-state)).
- **Tags.** Tags are `<prefix>.<name>`, where the prefix is the global
  `slib:hatching:tag:prefix` (default `rep.hatching`). When `slib:hatching:tag:enabled` is false,
  no tags are applied and `risk:tool:software:tag` is left unset. See
  [`slib.hatching.admin.tags`](commands.md#slibhatchingadmintags).
- **Tag intervals.** Tags get the analysis interval `[submitted, max(completed, submitted + 1ms)]`
  (the overview's `sample.submitted`/`completed`, falling back to the sample metadata's). With no
  submitted time, tags are applied without an interval.
- **Idempotency.** Every guid is derived from the Triage sample ID (and the task name and Triage's
  own IDs), so modeling a sample again updates the same nodes instead of creating new ones.
- **Optional props.** Props are set with `?=`, so a value that doesn't normalize (ex. a malformed
  URL) is skipped instead of failing the whole sample.
- **Existing values.** A `file:bytes` keeps the `:name` and `:mime` it already has, and an IP keeps
  its `:asn` and `:loc`. A malware config is merged with what an earlier run modeled (see
  [Malware configs](#malware-configs)).

## Tag names

Each Triage tag becomes one tag below the prefix (`tagName()` in `norm.py`):

| Triage tag | Tag |
| --- | --- |
| `family:cobaltstrike` | `<prefix>.cobaltstrike` |
| `backdoor` | `<prefix>.backdoor` |
| `botnet:1234` | `<prefix>.botnet.1234` |
| `Some Tag!` | `<prefix>.some_tag` |

A tag part is lowercased, every run of characters other than `a-z`, `0-9`, and `_` is replaced
with `_`, and leading and trailing `_` are stripped. A Triage tag with an empty part after that is
dropped. The sample's malware families (below) are added as tags too.

The sample's tags are the overview's `analysis.tags`, plus (with `--tasks`) each task report's
`analysis.tags`, plus its families. Its **families** are the overview's `analysis.family`, the
`family:` tags, each malware config's and ransom note's family, all lowercased, unique, and
sorted.

Fixed tags:

| Tag | Applied to |
| --- | --- |
| `<prefix>.c2` | Malware config C2 servers: the `inet:url` and its host (`inet:fqdn`, `inet:ipv4`, or `inet:ipv6`). |
| `<prefix>.dropper` | URLs a dropper downloads from. |
| `<prefix>.ransom` | Email addresses and URLs in a ransom note. |

These nodes also get `<prefix>.<family>` for the config's, dropper's, or ransom note's family.

## The sample

| Sample kind | Node |
| --- | --- |
| File (`kind` other than `url`) | `file:bytes=sha256:<sha256>`, from the overview's `sample.sha256`. |
| URL (`kind=url`) | `inet:url=<url>`, the sample metadata's `url` (or the overview's `sample.target`). |

A file sample without a SHA256 isn't modeled (`Sample <id> has no file hash or URL to model it
by.`).

| `file:bytes` prop | From |
| --- | --- |
| `:sha256`, `:md5`, `:sha1`, `:sha512` | The overview's `sample.sha256`, `md5`, `sha1`, `sha512` |
| `:size` | `sample.size` |
| `:name` | The base name of `sample.target` (or the metadata's `filename`), only if the node has no `:name` |
| `:mime` | The static report's `files[].mime` for the file with the sample's SHA256, only if the node has no `:mime` |
| `:ssdeeps` | `sample.ssdeep`, added to the array |

The sample node gets the tags above, and these edges:

| Edge | To |
| --- | --- |
| `-(uses)>` | `it:mitre:attack:technique` for each ATT&CK technique ID (matching `T1234` or `T1234.001`, uppercased) in the overview's, its targets', and task reports' signatures, the overview's task summaries, and the task reports' `analysis.ttp`. |
| `-(refs)>` | `inet:url` for each IOC URL, and `inet:fqdn`/`inet:ipv4`/`inet:ipv6` for each IOC domain and IP, from the overview's `sample.iocs` and `targets[].iocs` (hosts lowercased, trailing `.` stripped). |
| `-(refs)>` | `it:dev:mutex` for each mutex in a malware config. |
| `-(refs)>` | Dropper URLs and ransom note email addresses and URLs. |
| `-(refs)>` | `auth:creds` for every credential (see [Credentials](#credentials)). |
| `-(refs)>` | The `file:bytes` of each file dropped in a behavioral task (with `--tasks`). |

A host is an `inet:ipv4` if it casts to one, an `inet:ipv6` if it contains `:`, and an
`inet:fqdn` otherwise.

## Verdict and signatures

Triage's score becomes an `it:av:scan:result` verdict, mapped from
[Triage's scoring](https://tria.ge/docs/scoring/) (`verdict()` in `norm.py`):

| Triage score | `:verdict` |
| --- | --- |
| 8-10 | `40` (malicious) |
| 5-7 | `30` (suspicious) |
| 1-4 | `10` (benign) |
| missing or `0` | unset |

The **verdict** is `it:av:scan:result=(slib.hatching, <sample id>, scan)`, only when the overview
has an `analysis.score`:

| Prop | Value |
| --- | --- |
| `:scanner:name` | `hatching triage` |
| `:target:file` or `:target:url` | The sample node |
| `:time` | The analysis' completed time (or submitted, without one) |
| `:verdict` | From `analysis.score` |
| `:signame` | The first of the sample's families (sorted), if any |
| `:categories` | The sample's Triage tags that aren't `family:` tags, lowercased |

Each matched **signature** is `it:av:scan:result=(slib.hatching, <sample id>, signature, <key>)`,
where `<key>` is the signature's `label` (or its `name`), lowercased. Signatures come from the
overview, its `targets`, and (with `--tasks`) the task reports; the same key is one result, with
the highest score seen:

| Prop | Value |
| --- | --- |
| `:scanner:name`, `:target:file`/`:target:url`, `:time` | As the verdict |
| `:verdict` | From the signature's `score` |
| `:signame` | The signature's `name` (or `label`) |
| `:categories` | The signature's `tags` that aren't `family:` tags, lowercased |
| `:multi:scan` | The verdict |

Each signature result also gets `-(uses)> it:mitre:attack:technique` for its `ttp`. Signatures
are only modeled when the sample has a verdict.

## Families

Each family is a `risk:tool:software=(slib.hatching, family, <family>)` with
`:soft:name=<family>`, `:reporter:name="hatching triage"`, and `:tag=<prefix>.<family tag part>`
(unset when tags are disabled). Families aren't linked to the sample by an edge; pivot on the
tag, ex. `risk:tool:software:tag=rep.hatching.cobaltstrike` and `#rep.hatching.cobaltstrike`.

## Malware configs

Each config in an `extracted[].config` (overview and, with `--tasks`, task reports) is normalized
by `normConfig()`:

| Config field | Normalized |
| --- | --- |
| `family` | Lowercased |
| `c2` | Each entry as a URL: a value with a scheme is kept, `host:port` becomes `tcp://host:port`, IPv6 hosts are bracketed. Unique. |
| (from `c2`) | The URLs' hosts |
| `mutex` | Unique strings |
| `decoy` | URLs; a bare `host/path` becomes `http://host/path` |
| `listen_addr`, `listen_port` | `tcp://<listen_addr or 0.0.0.0>:<listen_port>` |
| `dns` | Each IP entry as `udp://<ip>:<port or 53>` (non-IP entries are dropped) |
| `credentials` | See [Credentials](#credentials) |
| `campaign` | As is |
| the whole config | Kept as `raw` |

Copies of a config with the same family and C2 servers (the overview's and each task report's)
are merged into one, field by field (`mergeConfig()`): an empty value never replaces a non-empty
one, lists are unioned, and when both copies set a scalar differently, the task report's copy
wins (it's extracted from that task's own memory dumps). The `raw` config is merged the same way.

Each config is `it:sec:c2:config=(slib.hatching, <sample id>, config, <family>, <servers>)`:

| Prop | Value | On a node an earlier run modeled |
| --- | --- | --- |
| `:family` | The family | Set |
| `:file` | The sample's `file:bytes` (unset for URL samples) | Set |
| `:servers` | The C2 URLs | Set |
| `:decoys` | Decoy URLs | Unioned with the node's |
| `:listens` | Listener URLs | Unioned with the node's |
| `:dns:resolvers` | Resolver `inet:server`s | Unioned with the node's |
| `:mutex` | The first mutex (the rest are only `-(refs)>` from the sample) | Replaced by a config from a task report, only filled in by an overview-only one |
| `:campaigncode` | `campaign` | Same as `:mutex` |
| `:raw` | The merged raw config | Same as `:mutex` |

So modeling a sample again without `--tasks` doesn't undo what its task reports added.

Around the config node:

- Each C2 URL (`inet:url`) and C2 host is tagged `<prefix>.c2` and `<prefix>.<family>`.
- Each listener URL is created as an `inet:url`.
- `it:sec:c2:config -(refs)> auth:creds` for the config's credentials.

Not modeled from configs: wallets, `keys`, `webinject`, `command_lines`, `attr`, `botnet`, and
`version` (they stay in `:raw`).

## Droppers and ransom notes

From `extracted[].dropper`: each URL in `urls[].url` is an `inet:url` tagged `<prefix>.dropper`
and `<prefix>.<family>`, with `-(refs)>` from the sample. The dropper's language and source
aren't modeled.

From `extracted[].ransom_note`: each email address (lowercased) is an `inet:email` and each URL
an `inet:url`, tagged `<prefix>.ransom` and `<prefix>.<family>`, with `-(refs)>` from the sample.
Wallets aren't modeled (Triage doesn't say which currency they're for), nor is the note's text.

## Credentials

Credentials come from `extracted[].credentials` and each config's `credentials`. Entries without
a username and a password are skipped.

`auth:creds=(slib.hatching, creds, <url>, <username>, <password>)`:

| Prop | Value |
| --- | --- |
| `:user` | `username` |
| `:passwd` | `password` |
| `:email` | The username, lowercased, when it looks like an email address |
| `:website` | `<protocol>://<host>:<port>` (protocol and host lowercased), when the protocol and host are set |

The `:email`, the `:website` URL, and the `email_to` address are also created as `inet:email`
and `inet:url` nodes, and the credential gets `-(refs)> inet:email` for `email_to`. The sample
`-(refs)>` every credential, including its configs'.

## Archive members

For a file sample, each of the overview's `targets` with a SHA256 other than the sample's (a file
in an archive, or another container, that Triage analyzed) is a `file:bytes=sha256:<sha256>` with
its hashes, `:size`, and `:name` (the base name of its `target` path), tagged with its own
Triage tags and families, and a `file:subfile=(<sample>, <member>)` with `:path` set to the
`target` path.

## Behavioral tasks

With `--tasks`, each reported behavioral task (an overview task of kind `behavioral`, or named
`behavioral*`, with the status `reported`) is fetched and modeled. A task report that can't be
fetched is skipped with a warning; the rest are still modeled.

Task node guids are `$lib.guid(slib.hatching, <sample id>, <task name>, <kind>, <Triage id>)`,
where the Triage ID is the process's `procid` or the flow's `id`, both unique within a task.

`:sandbox:file` is set to the sample on every task node when the sample is a `file:bytes`. URL
samples have no `file:bytes`, so their task nodes have no `:sandbox:file`.

### Processes

`it:exec:proc` per `processes[]` entry with a `procid`:

| Prop | From |
| --- | --- |
| `:sandbox:file` | The sample |
| `:pid` | `pid` |
| `:cmd` | `cmd` (a list of args is joined with spaces) |
| `:path` | `image` |
| `:src:proc` | The parent's `it:exec:proc`, by `procid_parent`, when that process is in the report |
| `:exe` | The file the task ran, for processes whose image's base name matches the task target's base name (case-insensitive): the sample, or the archive member the task picked (by the task's `sha256`) |

### Network flows

`inet:flow` per `network.flows[]` entry with an `id` and a `dst`:

| Prop | From |
| --- | --- |
| `:dst` | `<proto>://<ip>:<port>`, only when `dst`'s host is an IP |
| `:dst:ipv4` or `:dst:ipv6` | `dst`'s IP |
| `:dst:port` | `dst`'s port |
| `:dst:proto` | `proto`, lowercased (default `tcp`) |
| `:src` | `<proto>://<ip>:<port>` from `src`, only when it's a globally routable IP |
| `:src:proc` | The `it:exec:proc` by `procid` |
| `:src:txbytes`, `:dst:txbytes` | `tx_bytes`, `rx_bytes` |
| `:src:txcount`, `:dst:txcount` | `tx_packets`, `rx_packets` |

The sandbox VM's private client address isn't modeled, so unrelated analyses aren't linked
through it. Each flow also gets `-(refs)>` the host of its `domain` and its TLS server name
(`tls_sni`), and:

- `inet:tls:ja3:sample=(<client>, <tls_ja3>)`, only when the flow has a (public) client.
- `inet:tls:ja3s:sample=(<server>, <tls_ja3s>)`, when the flow has a server.

### IP geolocation

For each IP in `network.ips`, Triage's `asn` (with any `AS` prefix stripped) and `cc` are set as
`:asn` and `:loc` on the `inet:ipv4`/`inet:ipv6`, only when the node doesn't have them yet.

### DNS

`inet:dns:request=(slib.hatching, <sample id>, <task>, dns, <flow>, <index>, <name>)` per DNS
question in `network.requests[].dns_request` (its `questions`, or its `domains` when it has none):

| Prop | From |
| --- | --- |
| `:query:name` | The question's name, lowercased, trailing `.` stripped |
| `:query:type` | The record type without its class (ex. `IN A` is `A`), normalized by Synapse to its number |
| `:server` | The request flow's `:dst` |

Each `dns_response.answers[]` record of type `A`, `AAAA`, or `CNAME` becomes an `inet:dns:a`,
`inet:dns:aaaa`, or `inet:dns:cname` of `(name, value)`.

### HTTP

`inet:http:request=(slib.hatching, <sample id>, <task>, http, <flow>, <index>, <url>)` per
`network.requests[].http_request`:

| Prop | From |
| --- | --- |
| `:flow` | The request's `inet:flow` |
| `:server` | The flow's `:dst` |
| `:method`, `:url` | `method`, `url` (the URL is also created as an `inet:url`) |
| `:headers` | `Name: value` lines as `(name, value)` pairs, names lowercased |
| `:response:code` | The response's `status` |
| `:response:reason` | The reason from the response's status line (ex. `OK` from `HTTP/1.1 200 OK`) |
| `:response:headers` | The response's headers, like `:headers` |

A response is paired with a request when it's on the same flow, after the request, and before
the flow's next request.

### Dropped files

For each `dumped[]` entry with a SHA256 that isn't a memory `region`:

- A `file:bytes=sha256:<sha256>` with its hashes, `:size`, `:name` (the base name of the file's
  original `path`), and `:ssdeeps`.
- `it:exec:file:add=(slib.hatching, <sample id>, <task>, file, <name>, <sha256>)` with
  `:sandbox:file`, `:file`, `:path` (the original path), and `:proc` (by `procid`).
- The sample `-(refs)>` the dropped `file:bytes`.

The dropped files themselves aren't downloaded; use
[`slib.hatching.download --dumped`](commands.md#slibhatchingdownload).

## Other commands

| Command | Writes |
| --- | --- |
| `slib.hatching.download` | A `file:bytes=sha256:<sha256>` per downloaded file with `:sha256`, `:size`, `:name` (if unset), and `-(seen)>` from the source. |
| `slib.hatching.yara.get --yield` | `it:app:yara:rule=({"name": <name>, "text": <rule>})` with `:name` and `:text`. No source edge. |

## Not modeled

- Cryptocurrency wallets from configs and ransom notes, and config `keys`, `webinject`,
  `command_lines`, and `attr` (they stay in the config's `:raw`).
- Dropper source code, ransom note text, and signature indicators and descriptions.
- Relative timestamps (process start, flow first/last seen, request times). They're offsets into
  the task, and the reports don't say when the task started.
- Flow `protocols`.
- The static report beyond the sample's MIME type, kernel monitor events (print them with
  `slib.hatching.kernel`), and UrlScan reports (their shape is documented as subject to change,
  print them with `slib.hatching.report --urlscan`).
- Failures Triage reports in an analysis (ex. a task that couldn't run) are printed as warnings,
  not modeled.
