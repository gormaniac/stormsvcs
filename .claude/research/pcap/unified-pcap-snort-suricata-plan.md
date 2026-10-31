# Anchor two IDS engines on one flow table

Fold PR #16 (`svcs/pcap`, `slib.pcap`) and PR #17 (`svcs/snort`, `slib.snort`) into one service: **`slib.pcap`**. In it, the dpkt flow table owns flow identity and three external engines feed into it. Suricata 8 does protocol analysis and runs Suricata-native rules. A real Snort 3 engine runs Snort rules. tshark covers the few items Suricata can't produce. **Suricata can't replace Snort as the Snort rule engine.** Talos publishes only Snort 2.9 and Snort 3 rulesets. OISF has said it has "no plans" for a Snort 3 converter or support. Even Snort 2.9 rules that load in Suricata can match differently, because of `fast_pattern` case sensitivity, `isdataat` off-by-one and `urilen` range differences ([rule compatibility](https://docs.suricata.io/en/latest/rules/differences-from-snort.html), [OISF forum](https://forum.suricata.io/t/fr-snort3-rules/1333), [snort.org downloads](https://www.snort.org/downloads)). Keep Snort 3 as an engine you can switch off, and keep Suricata as the default workhorse. Suricata's EVE output should replace most of today's tshark enrichment: TLS leaf/chain DER, JA3/JA4, HTTP/1 and HTTP/2 headers, RDP client data, SMTP, FTP and SHA256-named file extraction. tshark stays only for TLS key-log decryption, SSH host keys, SIP User-Agent/Server, RDP certificates, raw .eml, and exact per-frame attribution. **Skip the Rust helper.** The two gaps it would close can be closed in pure Python with dpkt and `cryptography`, or by tshark, which already runs. One exec wrapper sandboxes tshark, Suricata and Snort alike. It drops to a dedicated UID, cleans the environment, sets rlimits, sets no_new_privs and applies Landlock. Every one of those layers works in a default Docker container, while bwrap and nsjail do not. Settle the flow identity scheme before PR #16 merges, so that merging PR #17 into it is purely additive (minor bumps) and never has to rewrite the flow identity (which would be a breaking change).

## Suricata cannot be the Snort engine, so ship both and make Snort optional

The rule-engine question is about fidelity, not parsing. Suricata accepts the Snort 2.9 grammar, but the behaviour behind it differs in ways that silently change detection. Snort's fast-pattern matcher is always case-insensitive and Suricata's is not. `fast_pattern:only` is accepted and "silently ignored". Relative `isdataat` is off by one. `urilen` ranges are exclusive in Suricata and inclusive in Snort. `http_header` buffers exclude cookies and normalise whitespace. `byte_extract` variables used across buffers evaluate to 0 ([Suricata: Differences From Snort](https://docs.suricata.io/en/latest/rules/differences-from-snort.html)). Snort 3 rules are worse still. Snort 3 moved to sticky buffers that come *before* `content`, a standalone `service:` option, and first-class `soid`. A Snort 3 `http_uri; content:...` sequence is therefore read by Suricata as a modifier on the previous content, or rejected as an error ([Snort blog, 2020-08](https://blog.snort.org/2020/08/how-rules-are-improving-in-snort-3.html)). The only maintained official converter goes Snort 2 to Snort 3 (`snort2lua`). The one community Suricata/Snort converter goes the other way and calls itself a "first foray" ([Snort3Converter](https://github.com/Cisconate/Snort3Converter)). Shared-object and preprocessor rules can't run in Suricata at all, as far as the notes could determine.

| Option | What it is | Snort fidelity | Cost | Verdict |
|---|---|---|---|---|
| A. Suricata only | Load Snort 2 rules natively and report failures | Low: Snort 3 rules mostly fail and Snort 2 rules drift | One engine | Acceptable only as a fallback |
| B. Suricata plus a converter | Build and maintain a Snort 3 to Suricata translator | Unprovable without a PCAP regression corpus | High, with no upstream support | Reject |
| C. Snort 3 plus Suricata | Each engine runs its own native rules | Exact, including Talos SO rules with a user oinkcode | Two binaries, two configs, two output parsers | **Recommend** |
| D2. Snort 3 only | PR #17 as-is | Exact | Loses Suricata app-layer data and Suricata-native feeds | Too narrow |

Option C is the plan, with one refinement. Feeds are routed by native syntax, never by "whichever engine is installed". Talos Community, Registered and Subscriber rules go to Snort 3. Snort 2.9 custom rules go to Snort 3 through `snort2lua`, which PR #17 already does. ET Open and ET Pro go to Suricata using ET's `suricata-7.0.3` build, along with abuse.ch and every other source in the suricata-update index ([ET Open directories](https://rules.emergingthreats.net/open/), [OISF index.yaml](https://www.openinfosecfoundation.org/rules/index.yaml)). One consequence is a change to PR #17's default `et-open` feed, which today points at the `snort-2.9.0` build and is converted for Snort ([PR17 feeds.py](https://github.com/gormaniac/stormsvcs/blob/83354b1f3260ff15c0f7e7e95dcdb32721b1f706/svcs/snort/src/snortsvc/feeds.py)). In the merged service it should move to Suricata's native build. Loading ET into both engines would produce two hits for every ET detection, because both builds carry the same sids. Snort is optional at three levels: in the image (a build argument that skips the Snort stage), at service start (`snort:enabled`), and per run (`--no-snort`). Operators who don't use Talos then pay nothing for it.

## One dpkt flow table anchors every engine's output

### The pipeline runs three engines in parallel against one canonical capture

The combined data flow keeps PR #16's central guarantee: "flows are always built the same way whether or not tshark ran" ([PR16 README](https://github.com/gormaniac/stormsvcs/blob/claude/pcap-flow-analyzer/svcs/pcap/README.md)). The guarantee extends to Suricata and Snort. A run has five stages.

**Acquisition.** The service fetches the capture into a per-run temp directory, either directly from the Axon or as chunks streamed by Storm. It hashes the capture. If the capture is gzipped, it decompresses it to one canonical file. Every engine then reads the same bytes, so frame numbers agree across engines.

**Analysis.** Four passes run concurrently under the existing worker semaphore:

- The dpkt flow pass, in an executor. It is extended to keep a frame-number-to-flow index and a Community ID per flow.
- Suricata, as one subprocess per capture. It produces EVE for flows and protocols, a file store, and alerts when rules are loaded.
- Snort 3, if enabled and rules exist. It produces `alert_json`.
- tshark, with its `-Y` filter narrowed to the gap protocols and with key logs and Decode As rules applied.

**Correlation.** Every engine record is mapped onto a dpkt flow.

**Merge.** Per-field precedence rules decide which source wins when two disagree.

**Output.** Extracted files are uploaded to the Axon, de-duplicated by SHA256. The run then yields the summary, the flow dicts and the hit dicts to Storm, which owns all modelling, as the repo conventions require ([copilot-instructions](https://github.com/gormaniac/stormsvcs/blob/main/.github/copilot-instructions.md)).

Keep dpkt as the flow builder instead of adopting Suricata's `flow` records, even though Suricata emits bidirectional flows with counts, TCP flags and `app_proto`. Suricata's flow records carry no `pcap_cnt`. Its flow timeouts differ from dpkt's: TCP established is 600 s and UDP is 300 s, against PR #16's `pcap:timeout` of 300. It splits flows on `tcp_reuse` and keys on VLAN. And it can swap direction after protocol detection on midstream TCP and UDP ([output-json-flow.c](https://github.com/OISF/suricata/blob/main-8.0.x/src/output-json-flow.c), [app-layer.c](https://github.com/OISF/suricata/blob/main-8.0.x/src/app-layer.c), [suricata.yaml.in](https://github.com/OISF/suricata/blob/main-8.0.x/suricata.yaml.in)). A deterministic Python flow table that works with no engines installed is the right anchor. Suricata's flow records become a join aid and a cross-check, not the source of truth.

### Lean on Suricata for nine of the fourteen enrichment items

Read the table as a source-of-truth assignment. "Primary" is what populates the flow dict by default. "Fallback or override" applies only when the primary can't see the data.

| Data item | Primary source | Fallback or override | Notes |
|---|---|---|---|
| Flow tuple, counts, bytes, handshake bytes, TCP flags and state | dpkt | none | Unchanged from PR #16 |
| TLS SNI, version, ALPN, JA3/JA3S, JA4 | Suricata `tls` with `custom` fields | tshark when a key log is supplied | `custom` disables `extended`, so list every field ([suricata.yaml.in](https://github.com/OISF/suricata/blob/main-8.0.x/suricata.yaml.in)) |
| TLS leaf and chain certificates | Suricata `certificate` and `chain` (base64 DER) | tshark with a key log (the TLS 1.3 Certificate message is encrypted) | Decode with `base64` and parse with `cryptography` ([output-json-tls.c](https://github.com/OISF/suricata/blob/main-8.0.x/src/output-json-tls.c)) |
| SSH banners, HASSH | Suricata `ssh` with `hassh: yes` | none | |
| SSH server host key | tshark | Later, a pure-Python KEX-reply parser | Absent from the EVE SSH logger ([logger.rs](https://github.com/OISF/suricata/blob/main-8.0.x/rust/src/ssh/logger.rs)) |
| RDP client name, keyboard layout, build | Suricata `rdp` (enable the parser) | tshark | Off by default in suricata.yaml |
| RDP TLS certificates | tshark | none | EVE gives only `x509_serials` |
| HTTP/1 and HTTP/2 UA, Host, URI, Server, all headers | Suricata `http` with `dump-all-headers: both` | tshark for HTTP inside decrypted TLS | |
| Files (HTTP, HTTP/2, SMTP, FTP, SMB, NFS) | Suricata file-store v2 with `force-filestore` | tshark for files in decrypted TLS | Raise the libhtp body limits and reassembly depth ([file-extraction.rst](https://github.com/OISF/suricata/blob/main-8.0.x/doc/userguide/file-extraction/file-extraction.rst)) |
| FTP commands, ftp-data filenames | Suricata `ftp` and `ftp_data` | none | `runmode single` sidesteps the ftp-data ordering issue |
| SMTP envelope, headers, attachments | Suricata `smtp` and `email` | none | |
| Raw .eml | tshark IMF pass (as today) | A second Suricata run with `raw-extraction` | `raw-extraction` is disabled when `decode-mime` is on ([suricata-yaml.rst](https://github.com/OISF/suricata/blob/main-8.0.x/doc/userguide/configuration/suricata-yaml.rst)) |
| SIP User-Agent and Server | tshark | Python over dpkt payloads of `app_proto: sip` flows | Not in EVE, only in detection buffers ([sip/log.rs](https://github.com/OISF/suricata/blob/main-8.0.x/rust/src/sip/log.rs)) |
| Softnames and CPEs | Python, derived from whichever UA, Server or banner strings were collected | n/a | Source-independent |

Suricata becomes primary for everything EVE supports. tshark becomes a narrow, sandboxed specialist that runs only when one of its five triggers applies: a key log was supplied, the capture has SSH, SIP or RDP-over-TLS, or the operator wants raw email. tshark detects no TLS decryption on its own; Suricata's open Redmine #7796 confirms Suricata has none in pcap mode ([Redmine #7796](https://redmine.openinfosecfoundation.org/issues/7796)). When both sources report the same field, the record keeps a per-field `source` marker in `:raw`. The precedence is tshark-with-decryption over Suricata over tshark-without-decryption. Two behaviour changes need care. First, Suricata 8 no longer logs app-layer metadata with alerts by default, so protocol fields must come from protocol events, not alerts ([upgrade.rst](https://github.com/OISF/suricata/blob/main-8.0.x/doc/userguide/upgrade.rst)). Second, Suricata 7 is end of life at 7.0.17, so target 8.0.x only ([oss-security 2026-09-19](https://www.openwall.com/lists/oss-security/2026/09/19/1)).

To make Suricata see what tshark sees, the generated `suricata.yaml` should set several options. Use `-k none`. Set `stream.midstream: true`. Set `stream.reassembly.depth: 0`, which means unlimited. Raise the libhtp body limits and the memcaps. Set `randomize-chunk-size: no` and `--runmode single` for deterministic EVE order. Turn on `community-id: true` with seed 0. Feed it exactly one file per invocation with no BPF filter ([options.rst](https://github.com/OISF/suricata/blob/main-8.0.x/doc/userguide/partials/options.rst)). The plan is one Suricata subprocess per capture. Unix-socket mode keeps rules loaded, but it processes pcaps strictly one at a time. Revisit it only if measured rule-load time dominates small captures ([unix-socket.rst](https://github.com/OISF/suricata/blob/main-8.0.x/doc/userguide/unix-socket.rst)). When a run needs flows but no IDS, run Suricata with detection disabled, which still emits every protocol event.

### Frame numbers are the primary join; Community ID plus time is the fallback

Correlation works in tiers, each a fallback for the one above.

**Tier 1: frame number.** A frame number maps straight to a dpkt flow through the frame index, which PR #16 already builds to match tshark output. In Suricata, `pcap_cnt` is a 1-based counter incremented for every packet libpcap delivers. The docs say it identifies "the packet number in the pcap … to look up a packet in Wireshark", so on a single unfiltered file it equals tshark's `frame.number` ([source-pcap-file-helper.c](https://github.com/OISF/suricata/blob/main-8.0.x/src/source-pcap-file-helper.c), [EVE format](https://github.com/OISF/suricata/blob/main-8.0.x/doc/userguide/output/eve/eve-json-format.rst)). It appears on alert, anomaly, app-layer and fileinfo events. It identifies the packet that *triggered* logging, which is usually the last packet of a transaction, not the first. That is enough for flow attribution, and it is why exact per-frame mapping stays a tshark job. Snort 3's `alert_json` can emit `pkt_num` ([Snort alert logging](https://docs.snort.org/start/alert_logging)). PR #17's `ALERT_FIELDS` doesn't request it today ([PR17 engine.py](https://github.com/gormaniac/stormsvcs/blob/83354b1f3260ff15c0f7e7e95dcdb32721b1f706/svcs/snort/src/snortsvc/engine.py)). The port should add `pkt_num`, `flowstart_time`, `service`, `class` and `priority`. Whether `pkt_num` equals the frame number is unverified, so a parity test must prove it before tier 1 is trusted for Snort.

**Tier 2: `flow_id` within a run.** Suricata events with no `pcap_cnt` include `flow` records, events emitted on flow-timeout or shutdown pseudo-packets, and transactions logged at flow end. They join by `flow_id` to that run's `flow` record. That record maps to a dpkt flow by Community ID, plus overlap of `[start, end]` with the dpkt flow's `[time, last]`, plus VLAN when the capture has tagged duplicates ([output-json.c](https://github.com/OISF/suricata/blob/main-8.0.x/src/output-json.c)). `flow_id` is valid only inside one eve.json and must never be stored. Community ID has no time component, which is exactly why the time overlap is required for reused 5-tuples. For ICMP, compute the ID the way Suricata does (type plus counterpart type, else 0), not through pycommunityid's spec mapping, because the two differ for unpaired types such as destination unreachable ([community-id-spec](https://github.com/corelight/community-id-spec), [pycommunityid](https://github.com/corelight/pycommunityid)). Community ID is about 40 lines of SHA1. It can be implemented in the service or taken from the `communityid` package.

**Tier 3: tuple plus time.** Snort alerts with no usable `pkt_num` match on a direction-normalised 5-tuple and alert time falling inside a flow's interval. PR #17 already normalises client to server by swapping endpoints when `dir == "S2C"`.

**Tier 4: unmatched.** An alert that maps to no flow is still modelled as a hit, but without `:flow`, and is counted in `summary.ids.unmatched`. Two common causes are flows dropped by `pcap:limit` and packets dpkt skipped. An unmatched alert never mints its own flow, because that would recreate the duplicate-flow problem this design removes.

### One flow identity scheme replaces two conflicting ones

Today the same TCP session scanned by both services becomes two different `inet:flow` nodes. PR #16 keys a flow as md5 of `repr((sha256, (ipproto, client ip, client port, server ip, server port, start_ns)))` ([PR16 flows.py](https://github.com/gormaniac/stormsvcs/blob/claude/pcap-flow-analyzer/svcs/pcap/src/pcapsvc/flows.py)). PR #17 keys it as `guid(("slib.snort.flow", sha256, proto, src, sport, dst, dport))`, with no start time, so reused 5-tuples collapse into one flow ([PR17 svc.py](https://github.com/gormaniac/stormsvcs/blob/83354b1f3260ff15c0f7e7e95dcdb32721b1f706/svcs/snort/src/snortsvc/svc.py)). The merged scheme is PR #16's semantics, written in PR #17's style and versioned. The flow guid is `guid(("slib.pcap.flow", 1, capture sha256, ipproto, client ip, client port, server ip, server port, start_ns, vlan ids))`. The literal `1` is a scheme version, so a future change can coexist with old nodes instead of silently forking them. Only the dpkt flow table mints flow guids. Hit guids change from PR #17's per-tuple key to `guid(("slib.pcap.hit", engine, flow guid, rule guid))`, giving one hit per (rule, flow) as PR #17 intends. A hit with no flow falls back to the capture sha256 plus the alert tuple. Adding VLAN IDs to the key is a deliberate change. Suricata keys flows by VLAN and dpkt currently doesn't, so a capture with the same tuple on two VLANs would otherwise merge flows that Suricata keeps apart. Because PR #16 isn't merged, this change can be made inside PR #16 at version 0.1.0 at no compatibility cost. Made after release, it would orphan every existing `inet:flow` and count as a breaking change under CLAUDE.md's rules.

## Model everything in one version-isolated Storm module

Synapse 2.256 and Synapse 3 (3.7.0 is the current release, and it requires Python 3.14) name many of the forms and properties this service touches differently, so all form and property names should live in one `slib.pcap.model` module that the rest of the package calls by function. In 2.x, Snort uses `it:app:snort:rule`, which has `:engine`, `:enabled` and `:family`. Snort matches are `it:app:snort:hit`, with `:rule`, `:flow`, src/dst props, `:time`, `:sensor`, `:version` and `:dropped`. Suricata has a separate `it:app:suricata:rule`, which has no `:engine` or `:family`. Suricata matches are `it:app:suricata:matched`, which link to the flow through `:target`, not `:flow`, and carry no src/dst props ([Synapse 2.x infotech.py](https://github.com/vertexproject/synapse/blob/master/synapse/models/infotech.py)). In Synapse 3.7.0 the following changes, as read from the released wheel ([synapse 3.7.0 on PyPI](https://pypi.org/project/synapse/3.7.0/): `synapse/models/infotech.py` L2846-2887, `synapse/models/base.py` L425-457 and L834-855, `synapse/models/doc.py`):

- Snort and Suricata stay parallel, first-class forms. `it:app:snort:rule` and `it:app:suricata:rule` are both `meta:rule` subtypes, and only the Snort form adds a prop (`:engine`). Rule props come from `meta:rule` (`:name`, `:type` taxonomy, `:status`, `:severity`, `:priority`, `:url`, `:enabled`, `:text`) and from the `doc:authorable` interface (`:id`, `:desc`, `:created`, `:updated`, `:version`).
- Matches are `it:app:snort:matched` and `it:app:suricata:matched`. Both implement the shared `base:matched` interface: `:rule`, `:target` (an `inet:flow`), `:rule:version`, `:severity`, and `:time` (through `base:event`). Both add `:sensor` and `:dropped`. Match nodes no longer carry src/dst props.
- No rename metadata links `it:app:snort:hit` to `it:app:snort:matched` in 3.7.0, so existing 2.x hits would need an explicit migration.
- `meta:ruleset -(has)> meta:rule` is declared on the generic parent, so it covers Snort and Suricata rules alike.
- `-(detects)>` edges are typed for both rule forms: `risk:vuln`, `it:software`, `meta:technique` and `it:softwarename`.
- `inet:flow` uses `:client*`/`:server*` instead of `:src*`/`:dst*`, including `client:software:names`/`client:software:cpes`, and IPs are `inet:ip`.

| Concept | Synapse 2.256 (target now) | Synapse 3.7.0 (plan for) |
|---|---|---|
| Flow | `inet:flow` with `:src*`/`:dst*`, `:tot:*`, `:ip:proto`, `:raw` | `inet:flow` with `:client*`/`:server*`, `inet:ip` |
| Snort rule | `it:app:snort:rule` (`:engine` 2 or 3) | `it:app:snort:rule`, a `meta:rule` subtype (keeps `:engine`) |
| Snort match | `it:app:snort:hit` (`:flow`, `:time`, src/dst) | `it:app:snort:matched` (`base:matched`: `:target`, `:time`, `:rule:version`) |
| Suricata rule | `it:app:suricata:rule` | `it:app:suricata:rule`, a `meta:rule` subtype |
| Suricata match | `it:app:suricata:matched` (`:target`) | `it:app:suricata:matched` (`base:matched`, same shape as Snort's) |
| Ruleset | `meta:ruleset -(has)> it:app:snort:rule` declared; the Suricata edge is not | `meta:ruleset -(has)> meta:rule`, covering both engines |
| Detects edge | `-(detects)> *` | Typed targets: `risk:vuln`, `it:software`, `meta:technique`, `it:softwarename` |

The 2.x plan works as follows. Both engines' rules live in feed `meta:ruleset`s. For Suricata this uses an undeclared `-(has)>` light edge, so a test should confirm that the Cortex accepts it ([Synapse 2.x base.py](https://github.com/vertexproject/synapse/blob/master/synapse/models/base.py)). Hits set the props each form actually has: `:flow`, endpoints and `:time` for Snort, and `:target`, `:time` and `:version` for Suricata. Both get `<(seen)+ meta:source` and `<(refs)+ file:bytes`, as PR #17 does. `:time` is the first alert, and `count`, `msg`, `action` and the last-seen time go into the returned dict. `:dropped` stays unset, because offline "would_drop" isn't a drop. Snort rules keep `:engine` 2 or 3. The service's internal push protocol widens from PR #17's integer engine to a named engine (`snort2`, `snort3`, `suricata`), because Suricata rules have no `:engine` prop to carry the distinction. The merged package takes the higher `synapse_minversion`, 2.234.0 from PR #17 instead of PR #16's 2.137.0 ([PR17 slib.snort.yaml](https://github.com/gormaniac/stormsvcs/blob/83354b1f3260ff15c0f7e7e95dcdb32721b1f706/svcs/snort/src/snortsvc/pkgproto/slib.snort.yaml)). The 3.x port should be its own later milestone and a major version. It's mostly renames, because 3.7.0 keeps both engines' forms and gives their matches the same shape. It also needs a Python 3.14 base image, since the services pin Python 3.11 today.

## Commands, rules and settings each get one clear owner

### The Storm surface merges under `slib.pcap.*` with four permissions

Neither package has shipped from `main`, so the merged package can take its final names now with no deprecation aliases. That holds unless the maintainer has deployed either branch, which is an open question. PR #16's `slib.pcap.flows` stays the primary analysis command and now runs the whole pipeline. PR #17's commands move under the `slib.pcap.` prefix, and the engine is selected by name.

| Merged command | Origin | Permission | Notes |
|---|---|---|---|
| `slib.pcap.flows` | PR #16 | `slib.pcap.user` | Yields `inet:flow`. New `--no-suricata`, `--no-snort` and `--no-rules` options; keeps `--keylog`, `--decode-as`, `--no-tshark`, `--no-files` |
| `slib.pcap.scan` | `slib.snort.scan` | `slib.pcap.user` | Same pipeline; yields Snort and Suricata hits |
| `slib.pcap.status` | `slib.snort.status` | `slib.pcap.user` | Engine versions, rule counts, sandbox probe results |
| `slib.pcap.rule.add`, `.enable`, `.disable` | `slib.snort.rule.*` | `slib.pcap.rules` | `--engine snort3\|snort2\|suricata` replaces `--engine 2` |
| `slib.pcap.rule.check`, `slib.pcap.rule.errors` | `slib.snort.rule.*` | `slib.pcap.user` | Per-engine validation and an error listing with an engine column |
| `slib.pcap.sync` | `slib.snort.sync` | `slib.pcap.sync` | Runs as root through a privileged module; cron iden in `slib:pcap:cron` |
| `slib.pcap.feed.list` | `slib.snort.feed.list` | `slib.pcap.user` | Shows engine, license class and last sync |
| `slib.pcap.admin.feed`, `slib.pcap.admin.schedule` | `slib.snort.admin.*` | `slib.pcap.admin` | |
| `slib.pcap.admin.decode` | PR #16 | `slib.pcap.admin` | Unchanged; manages the `slib:pcap:decode` global |

The modules follow PR #17's split, which is the stricter of the two designs. Only the privileged `asroot:perms` modules call the service or the Axon: `slib.pcap.priv` (user), `slib.pcap.priv.rules`, `slib.pcap.priv.sync` and `slib.pcap.priv.admin`. The `slib.pcap.lib` module keeps PR #16's automation-friendly `flows()`, which raises `slib.pcap.Error`, and adds `scan()` and `hits()` ([PR16 slib.pcap.yaml](https://github.com/gormaniac/stormsvcs/blob/claude/pcap-flow-analyzer/svcs/pcap/src/pcapsvc/pkgproto/slib.pcap.yaml)). The Telepath API combines PR #16's `flows()` generator and `checkDecodeAs()` with PR #17's push, feed, rule and scan methods. Everything still returns `TelepathRetn`.

The two PRs fetch captures differently. PR #16 requires `axon:url` because it also writes extracted files back. PR #17 defaults to Storm streaming 1 MiB chunks, with an optional direct Axon ([PR17 svc.py](https://github.com/gormaniac/stormsvcs/blob/83354b1f3260ff15c0f7e7e95dcdb32721b1f706/svcs/snort/src/snortsvc/svc.py)). The merged service should support both. `axon:url` becomes optional. When it is unset, captures are streamed, and extracted files are hashed and modelled as `file:bytes` but not uploaded.

### Rule management routes feeds by license and engine, and reports load errors per rule

| Feed | Engine | License (as published) | Default | Handling |
|---|---|---|---|---|
| Talos Snort 3 Community | Snort 3 | GPLv2 | On | Fetched as in PR #17 |
| Talos Registered / Subscriber (incl. LightSPD SO rules) | Snort 3 | Non-Commercial Use License, "personal use only", no embedding in a sold product | Off | Operator-supplied oinkcode only; never bundled |
| ET Open (`suricata-7.0.3` build) | Suricata | MIT in the suricata-update index; BSD/GPLv2 files in the ET listing | On | Replaces PR #17's Snort ET feed |
| ET Pro | Suricata | Commercial, secret code | Off | Operator secret |
| abuse.ch sslbl-ja3, feodotracker, urlhaus | Suricata | CC0-1.0 | Opt-in | sslbl-c2 is deprecated |
| Other suricata-update sources | Suricata | Varies (GPL-3.0, CC-BY-SA, commercial) | Off | Admin adds them |

The license facts come from [snort.org/license](https://www.snort.org/license), the [OISF index](https://www.openinfosecfoundation.org/rules/index.yaml) and the [ET listing](https://rules.emergingthreats.net/open/snort-edge/). They are not legal advice. One concern goes beyond downloading. The model writes full rule `:text` into the Cortex, so a Cortex shared outside the licensee's organisation may itself count as distribution of Talos Registered rules. That is a question for the maintainer. Secrets such as oinkcodes and ET Pro codes belong in operator service config or environment variables, referenced by name from feed URL templates. They should never be Cortex globals that Storm admins can read back.

Rule identity keeps PR #17's feed-scoped guid, `guid(("slib.pcap.rule", engine, feed, gid, sid))`. Sids are unique only within a vendor's ranges, and Snort inspector gids (116, 119, 120 and others) mean nothing to Suricata, so the alert lookup key is (engine, gid, sid) resolved to a guid through a per-engine index ([EVE format](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html)). Collisions are resolved per engine with PR #17's existing policy: the highest rev wins, ties go to the lowest guid, and the losers are reported as "Duplicate gid:sid" errors. The same sid in different engines is not a collision. Validation runs at push or sync time, never at scan time. For Snort, PR #17's existing approach stays: `-T` passes, parsing `ERROR: path:line`, removing the bad rule and retrying up to 25 passes. For Suricata, the service writes one rule per line, keeps a line-to-guid index, and runs `suricata -T -S <file>` with load errors non-fatal. It parses the signature errors from Suricata's log and maps them back to rule guids. Detect-engine stats (`rules_loaded`/`rules_failed`) serve as a cross-check ([command-line options](https://docs.suricata.io/en/latest/command-line-options.html)). Suricata 8 adds new reasons a rule won't load. Unknown `requires` values now count as unmet, and `ja3.hash` rejects non-hex content ([upgrade guide](https://docs.suricata.io/en/latest/upgrade.html)). These belong in the same `rule.errors` listing. The listing should also flag rules that load but are known to be semantically risky.

### Settings split into operator config, admin globals and validated per-run options

| Layer | Who sets it | Keys (examples) | Rule |
|---|---|---|---|
| Operator service config (`SYN_PCAPSVC_*`) | Whoever deploys the container | `axon:url`, `{tshark,suricata,snort}:enabled`, `:path`, `:timeout`; `tshark:args`, `snort:args`, `suricata:set`; `sandbox:mode`, `sandbox:rlimits`, `tshark:protocols`; feed secrets; `pcap:maxsize`, `pcap:limit`; workers | Anything that can change argv, the filesystem or the trust boundary |
| Admin Cortex globals and service-stored admin state | `slib.pcap.admin` | `slib:pcap:decode` (Decode As defaults), `slib:pcap:cron`, feed definitions and schedule, optional `slib:pcap:vars` override of HOME_NET/EXTERNAL_NET | Detection tuning that Cortex admins legitimately own |
| Per-run options | `slib.pcap.user` | `--timeout`, `--limit`, `--handshake`, `--tag`, `--host`, `--sandbox-file`, `--keylog`, `--decode-as` (regex-validated), `--no-tshark`, `--no-files`, `--no-suricata`, `--no-snort`, `--no-rules` | Never raw engine arguments |

PR #16 already enforces this boundary for tshark. Raw `tshark:args` is operator-only. Per-run options are limited to Decode As rules that pass validation and to key logs. Admin defaults live in the `slib:pcap:decode` global managed by `slib.pcap.admin.decode` ([PR16 README](https://github.com/gormaniac/stormsvcs/blob/claude/pcap-flow-analyzer/svcs/pcap/README.md)). The plan applies the same rule to the two new engines. `suricata:set` overrides and `snort:args` are operator-only. Snort's `snort:vars` keeps its operator default, and an admin global can override it so that both engines share one HOME_NET. Decode As maps cleanly onto tshark. It could be translated into Suricata's per-protocol `detection-ports` through `--set`. That is a later, optional milestone: `--set` can't append to lists, so this needs config-file generation, and Snort has no simple per-run equivalent ([options.rst](https://github.com/OISF/suricata/blob/main-8.0.x/doc/userguide/partials/options.rst)).

## One exec wrapper sandboxes tshark, Suricata and Snort

The sandbox exists because the parsers are the attack surface. The research notes count Wireshark advisories numbered up to wnpa-sec-2026-110 this year, against 8 in all of 2025. They include infinite loops and memory leaks as well as crashes, and Wireshark's security page lists the 2026 fixes only in 4.6.9 and 4.4.19 ([Wireshark security](https://www.wireshark.org/security/)). Suricata 8.0.7 was a security release with what oss-security called an unusually high number of vulnerability reports ([oss-security](https://www.openwall.com/lists/oss-security/2026/09/19/1)). Every engine reads attacker-controlled bytes, so **the same wrapper should launch all of them**: tshark, Suricata, Snort, `snort2lua`, and the `-T` validation runs. Each gets a per-engine profile.

The design has to fit what an unprivileged Docker container allows. The default seccomp profile denies namespace creation (`clone`/`unshare` with `CLONE_NEW*`, `mount`, `pivot_root`). Reports conflict on whether even user namespaces work. bwrap fails with "No permissions to create new namespace", and its maintainer considers containers out of scope ([Docker seccomp](https://docs.docker.com/engine/security/seccomp/), [bubblewrap #505](https://github.com/containers/bubblewrap/issues/505)). nsjail's Docker example uses `--privileged` ([nsjail](https://github.com/google/nsjail)). The default profile does allow the three Landlock syscalls, which were added so containers can "voluntarily restrict their own file access" ([moby commit mirror](https://git.causa-arcana.com/kotovalexarian-likes-github/moby--moby/commit/af819bf623a8d414289b24f9817c6317cf3f96d5)). The service container also runs as root, because neither image sets `USER`, so dropping to a separate UID is cheap and the biggest single gain.

The wrapper is a small module executed as `python3 -I -m pcapsvc.sandbox --profile tshark --run-dir <tmp> -- tshark ...`. The service launches it through `create_subprocess_exec` with `start_new_session=True`. All restriction happens inside the wrapper process before `exec`, so no Python runs between fork and exec in the service, which uses threads. That sidesteps the documented `preexec_fn` thread-safety hazard ([Python subprocess](https://docs.python.org/3/library/subprocess.html)). The wrapper applies these steps in order:

1. **rlimits.** Configurable: `RLIMIT_AS` of 2 to 4 GiB, `RLIMIT_CPU` near the wall-clock timeout, `RLIMIT_FSIZE` of 0 for tshark and the run-dir budget for Suricata and Snort, `RLIMIT_NOFILE` of 64 to 256, and `RLIMIT_CORE` of 0.
2. **Drop to a dedicated UID/GID.** Created in the Dockerfile, for example `pcapsbx`, with supplementary groups cleared.
3. **Clean environment.** `PATH`, `LANG=C.UTF-8`, `TMPDIR=<run dir>`, `HOME=/nonexistent` and `WIRESHARK_CONFIG_DIR=/nonexistent`. Without these, tshark reads `/root/.config/wireshark/*`. The local experiments showed a bare UID drop failing on exactly that.
4. **Set `no_new_privs`.**
5. **Landlock.** Read access to the system library and data paths, the canonical capture, and that run's key log or rules. Write access only to the run's output directory. All TCP denied when ABI ≥ 4.
6. **Optional seccomp deny-list.** Non-UNIX `socket()`, `ptrace`, `mount`, `bpf`, `keyctl` and `io_uring_*`.
7. **`exec` the engine.**

On the service side, the existing timeouts remain. PR #16 already passes `tshark:timeout`, which defaults to 600 s, to the Tshark class. The Tshark class's own constructor default of 0 should become non-zero, so that no caller gets an unbounded run. On timeout the service kills the whole process group. stdout, which PR #16 currently buffers in memory with no cap through `communicate()`, should be read incrementally against a byte cap such as 512 MiB. On overflow the service kills the process and returns partial results with a warning.

Each profile also narrows the parser. tshark runs with `-n` (and `-N` is never accepted), `--temp-dir <run dir>`, and `--only-protocols` with an operator-widenable list derived from the extracted fields. Any Decode As target is added to that list automatically. All 4.2.2 flags were verified locally, but the allowlist must be checked against fixtures, because a missing lower layer silently drops fields ([tshark(1)](https://www.wireshark.org/docs/man-pages/tshark.html)). Suricata runs with no capabilities, because offline `-r` needs none. Its own `landlock:` YAML section can be enabled as a second layer ([Suricata Landlock](https://docs.suricata.io/en/latest/configuration/landlock.html)). Snort reads `/opt/snort`, the generated config, the rules file and the capture, and writes only its `-l` directory.

The modes are `sandbox:mode = strict | best-effort | off`. Strict refuses to run when Landlock or the UID drop is unavailable. Best-effort, the default, logs which layers applied. At startup the service probes the Landlock ABI with `landlock_create_ruleset(NULL, 0, VERSION)`, which returned 7 on the research host. It also probes user-namespace availability and records both, plus the layers applied, in `slib.pcap.status` and in every run summary. Some kernels don't enable Landlock in the LSM list, and older Docker seccomp profiles predate the allowance, so degradation must be visible, not silent ([kernel Landlock docs](https://docs.kernel.org/userspace-api/landlock.html)). Stronger isolation needs operator changes to the runtime, and the README should document it. In ranked order: run the whole service under gVisor (`--runtime=runsc`), or run a read-only rootfs with `--cap-drop ALL`, `--pids-limit` and `--memory` ([gVisor](https://gvisor.dev/docs/user_guide/install/)). `--network none` doesn't fit this service as a whole, because it needs the Axon, the Cortex and rule feeds. That is exactly why the in-process Landlock network deny matters.

## Packaging needs two from-source engine builds on a bookworm base

`vertexproject/vtx-base-image:py311` is built `FROM python:3.11.14-slim-bookworm` ([vtx-base-image Dockerfile](https://github.com/vertexproject/vtx-base-image/blob/master/python311/Dockerfile)). On Debian 12, Suricata is available only as 7.0.10 from bookworm-backports. Suricata 8 is packaged in trixie-backports (8.0.7), Debian unstable (8.0.8) and the OISF Ubuntu PPA ([Debian madison](https://api.ftp-master.debian.org/madison?package=suricata&text=on)). Snort 3 isn't packaged for Debian at all, which is why PR #17 builds libdaq 3.0.28 and Snort 3.12.4.0 from source and ships 12 MB of stripped binaries ([PR17 Dockerfile](https://github.com/gormaniac/stormsvcs/blob/83354b1f3260ff15c0f7e7e95dcdb32721b1f706/svcs/snort/docker/prod/Dockerfile)).

| Approach | Suricata 8 | tshark | Convention fit | Risk |
|---|---|---|---|---|
| **Bookworm base, multi-stage source builds** | Builder stage from the repo base with rustup Rust ≥ 1.75 and cbindgen ≥ 0.20 | apt (Debian 12 package line) | Keeps the repo rule that all services use `docker/` | Longer CI builds; build deps partly from memory |
| Trixie service base | apt from trixie-backports (8.0.7) | apt 4.4.x line (per notes, unverified) | Breaks the shared-base rule | Diverges from vtx-base-image |
| Copy from `jasonish/suricata:8.0.8` | COPY binaries | apt | Keeps the base | glibc and library mismatch |
| Mix trixie packages into bookworm | apt pinning | apt | Keeps the base | "FrankenDebian" libc conflicts |

The recommendation is the first row. Add a `suricata-build` stage alongside PR #17's `snort-build` stage, each `FROM ghcr.io/gormaniac/stormsvcs/base:latest` so glibc matches. Each strips its outputs and copies only binaries, default configs and runtime `.so` packages into the final stage. `ARG ENABLE_SNORT` lets operators build a Snort-free image. Suricata 8 builds need Rust 1.75 and cbindgen 0.20 ([configure.ac](https://github.com/OISF/suricata/blob/main-8.0.x/configure.ac)). The research notes infer, without verifying, that bookworm's packaged rustc is too old, so the builder installs Rust with rustup. Both engines rebuild slowly, so consider publishing an `engines` image to GHCR from its own workflow and `COPY --from` it into the service image. Engine upgrades and Python changes then stop invalidating each other's caches.

tshark is the weakest link in the image. The 2026 Wireshark advisories list fixes only in 4.4.19 and 4.6.9. The 4.2 branch's last listed fix is 4.2.14 ([Wireshark security](https://www.wireshark.org/security/)). The research host's tshark was Ubuntu's 4.2.2, and the notes infer, without confirming, that Debian 12's package is on the older 4.0 line. Either way, the stock package isn't on a branch Wireshark itself patches for 2026, and Debian security backports, if any, have to be checked per CVE. The plan treats this as a reason for, not against, keeping tshark narrow and sandboxed. It records `tshark -v` in every summary, as PR #16 already does, and warns when the version is below a configured minimum. Whether to build tshark from source, or to move the image to trixie, is an open question for the maintainer. The test image should copy PR #17's `ARG BASE_IMAGE` pattern. PR #16's test Dockerfile hardcodes `pcap:latest`, which breaks the `_service.yml` `docker_tests` flow PR #17 introduces.

## Skip the Rust helper; the gaps close cheaper elsewhere

A Rust helper was considered for the two items Suricata can't produce: SSH host keys and per-frame certificates. It doesn't earn its place.

**The crates are a poor fit.** The published `ssh-parser` 0.5.0 is LGPL and from 2021, and doesn't parse the KEX reply. Its unreleased master does, but it returns `UnknownProtocol` for OpenSSH's actual defaults, `sntrup761x25519-sha512` and `mlkem768x25519-sha256` ([ssh-parser kex.rs](https://github.com/rusticata/ssh-parser/blob/master/src/kex.rs), [OpenSSH release notes](https://www.openssh.com/releasenotes.html)). `tls-parser` leaves TCP and record reassembly to the caller. No general Rust TCP reassembly crate has meaningful adoption ([tls-parser](https://github.com/rusticata/tls-parser), [crates.io search](https://crates.io/search?q=tcp%20reassembly)).

**The cost is real.** The notes estimate 1,200 to 2,000 lines and 2 to 4 engineer-weeks. A local native dependency would also complicate the repo's hand-edited `uv.lock` rule.

**The cheaper paths already exist.** tshark already runs for the SSH host key. If tshark is ever dropped, the server's host key K_S is simply the first length-prefixed string of the message-31 reply for every DH, ECDH and post-quantum hybrid method, and of message 33 for group exchange ([ML-KEM hybrid draft](https://www.ietf.org/archive/id/draft-ietf-sshm-mlkem-hybrid-kex-10.txt)). That is roughly 80 to 150 lines of Python over a capped dpkt reassembly. `cryptography` already provides `load_ssh_public_key` and `ssh_key_fingerprint` ([cryptography ssh.py](https://github.com/pyca/cryptography/blob/main/src/cryptography/hazmat/primitives/serialization/ssh.py)).

| Option | Closes SSH host key | Per-frame cert attribution | Isolation | Effort |
|---|---|---|---|---|
| tshark (already running) | Yes | Yes | Sandbox wrapper | None |
| Pure Python (dpkt + `cryptography`) | Yes | Yes, with an offset-to-frame map | Subprocess or process pool with rlimits | Small |
| Rust CLI (musl static binary) | Partly: needs custom code for PQ hybrids | Yes | Subprocess | 2 to 4 weeks |
| PyO3 module | Same as the CLI | Yes | None: a panic is a `BaseException` that can exit the interpreter | 2 to 4 weeks plus a wheel pipeline |

Revisit Rust only if profiling shows dpkt flow building dominates on multi-GB captures. If that happens, the right shape is a sandboxed static CLI behind the same wrapper, never an in-process PyO3 module ([PyO3 panic.rs](https://github.com/PyO3/pyo3/blob/main/src/panic.rs)).

## Migration lands in six versioned steps

PR #16 merges first, because it owns the flow table that everything else attaches to. The svcs/snort part of PR #17 should not merge as a standalone service. Its code moves into `svcs/pcap`, and PR #17 closes with a pointer to the port. PR #17's repo-level changes should land on their own: the ruff `target-version` and line length, the `_service.yml` `docker_tests` input, and the CI wiring ([PR #17](https://github.com/gormaniac/stormsvcs/pull/17)). The alternative is to merge PR #17 as-is and deprecate `slib.snort` later. That would leave users with two `inet:flow` schemes in the Cortex and a deprecation cycle for a service nobody has adopted. Every step below bumps `svcs/pcap` in all four places: `pyproject.toml`, `__version__`, `slib.pcap.yaml` and the `uv.lock` package entry, which is edited directly and checked with `uv lock --check` ([CLAUDE.md](https://github.com/gormaniac/stormsvcs/blob/main/CLAUDE.md)). Step 0 is the exception, because 0.1.0 has not been released. Step 0 should also port PR #17's `test_versions_match` into the pcap tests.

| Step | Version | Milestone | Done when |
|---|---|---|---|
| 0. Amend PR #16 before merge | 0.1.0 (unreleased) | Versioned flow guid with VLAN; frame-to-flow index exposed; Community ID per flow; `test_versions_match`; test Dockerfile takes `BASE_IMAGE` | PR #16 merged; reruns of the same capture produce identical guids |
| 1. Repo infra from PR #17 | n/a (repo-level), plus a pcap patch bump if its test Dockerfile changes | Ruff settings, `docker_tests` input, workflow opt-in | pcap docker tests run in CI |
| 2. Sandbox wrapper for tshark | 0.2.0 | Wrapper, profiles, `sandbox:mode`, probes in status, stdout cap, process-group kill, non-zero class default timeout, `--only-protocols` | The sandbox test matrix passes in default `docker run`; tshark fixtures show no field loss |
| 3. Snort port | 0.3.0 | Engine, rules, feeds and push code move into `pcapsvc`; commands renamed to `slib.pcap.*`; hits joined to dpkt flows by `pkt_num`; Snort engine runs under the wrapper | PR #17's 39 tests ported and passing; `pkt_num` parity proven; one `inet:flow` per session whichever engines ran |
| 4. Suricata protocol pass | 0.4.0 | Suricata 8 builder stage; generated YAML; EVE parser; file-store replaces tshark file export; tshark narrowed to gap triggers | A parity suite shows Suricata matches or beats the PR #16 tshark output on every fixture except the documented gaps |
| 5. Suricata rules | 0.5.0 | `it:app:suricata:rule`/`matched`; ET Open moved to the Suricata build; abuse.ch opt-in; per-rule load errors | ET Open loads with failures listed per guid; no duplicate ET hits across engines |
| 6. Hardening and 3.x | 0.6.x, then 1.0.0 | Seccomp allowlist generated in CI by strace; optional unix-socket pool if load time warrants it; Synapse 3.x model module on a Python 3.14 base image, with a hit-to-`matched` migration (major) | 3.x Cortex test suite green |

Testing follows PR #16's strongest habit: real recordings, not synthetic packets, for anything an engine parses. PR #16 already keeps loopback recordings for FTP, HTTP, RDP, SMTP, SSH, TLS and TLS 1.3 with a key log, plus a `capture.py` to re-record them ([PR16 README](https://github.com/gormaniac/stormsvcs/blob/claude/pcap-flow-analyzer/svcs/pcap/README.md)). The fixture set should grow to cover the corner cases this design depends on:

- TLS 1.2 with a full chain, and TLS 1.3 with and without a key log
- SSH using `mlkem768x25519` and `sntrup761x25519`
- SIP over UDP
- HTTP/2
- active and passive FTP
- SMTP with an attachment
- non-NLA RDP
- a capture with the same 5-tuple on two VLANs
- 5-tuple reuse inside one capture
- midstream TCP
- ICMP destination-unreachable
- a multi-interface gzipped pcapng

For IDS coverage, pair small local rules for both engines with HTTP and TLS fixtures known to trigger them. Tests never fetch real feeds; they reuse PR #17's fake aiohttp feed server.

Engine-dependent tests use `needtshark`, `needsuricata` and `needsnort` markers that skip when the binary is missing. A single `SLIB_PCAP_REQUIRE=1` in the test image turns those skips into failures, generalising PR #17's `SLIB_SNORT_REQUIRE`. Cross-engine invariants get explicit tests:

- Suricata `pcap_cnt` equals tshark `frame.number`.
- Snort `pkt_num` equals frame number.
- Python Community ID equals Suricata's, ICMP included.
- Two runs over the same capture give byte-identical flow and hit dicts.

The sandbox gets its own suite, which runs probe commands through the same wrapper. Reads of `/etc/shadow`, `/vertex/storage`, another run's capture and `/proc/1/environ` must fail. So must writes to `/tmp` and to the capture, and TCP and UDP connects. A busy loop and an endless stdout must be killed by the CPU limit, the timeout and the output cap. CI should run this suite inside a default `docker run` so environments without Landlock are caught.

## Risks and open questions the maintainer must settle

| Risk | Likelihood and impact | Mitigation |
|---|---|---|
| Synapse 3.x renames match and flow props (`it:app:snort:hit` to `it:app:snort:matched`, `:src*`/`:dst*` to `:client*`/`:server*`) and needs Python 3.14 | Certain for 3.7.0; moderate rework | All names in one model module; a 3.x port as a separate major, with the base image move |
| Talos Registered rules redistributed through the Cortex | Medium; licensing exposure | Off by default, operator oinkcode only, documented warning |
| Snort `pkt_num` ≠ frame number | Unknown; breaks tier-1 joins | Parity test before relying on it; tuple-plus-time fallback |
| Flow mismatches from VLAN, timeouts, `tcp_reuse`, or UDP direction swaps | Medium; orphan hits | VLAN in the flow key, raised Suricata timeouts, endpoint-normalised joins, `unmatched` counter |
| Landlock missing on host kernels or old Docker | Medium; weaker sandbox | best-effort mode, visible probes, strict mode for hardened deployments |
| Unpatched tshark from apt | High given the reported 2026 advisory volume | Narrow tshark use, sandbox, version warning, option to source a newer build |
| Image size and CI time from two source builds | High; slower iteration | A separate engines image with caching, and a Snort-optional build arg |
| Rule-load time dominates small captures | Medium; latency | Measure; unix-socket pool as a later option |
| Semantic drift if users push Snort 2 rules with `--engine suricata` | Medium; false negatives | Route by syntax and flag such rules in `rule.errors` |

| Open question | Recommended default |
|---|---|
| Has either branch been deployed anywhere, which would require deprecation aliases for `slib.snort.*`? | Assume not and skip the aliases |
| Should VLAN IDs join the flow key, and should flow guids move to `s_common.guid`? | Yes, inside PR #16 before merge |
| Is a trixie-based service image acceptable, giving Suricata 8 and a newer tshark from apt? | No; keep bookworm and build from source |
| Is Snort mandatory in the published image, or a build-time option? | Built by default, switchable off at build, start and run time |
| Should `axon:url` become optional, with Storm streaming as the PR #17 default? | Yes; file upload only when it is set |
| Should Decode As also drive Suricata `detection-ports`? | Later, optional |
| When should the services move to Synapse 3, which needs a Python 3.14 base image? | After step 5, as the 1.0.0 major |
| Should Snort decoder and inspector alerts (gid ≠ 1) and Suricata anomaly events be modelled? | Count them now and model them later |
| Should Suricata's DNS, QUIC, SMB and Kerberos events feed new enrichment? | After step 5, as minor bumps |

## Conclusion

The three services stop conflicting once each becomes a contributor to one dpkt flow table instead of an owner of flows. Their real disagreements were about identity, and all of it moves to dpkt: flow guids, frame numbering and direction. Then Snort and Suricata are just rule engines, and tshark is just a decryption-capable specialist. The engine question resolves the same way. Suricata is the better analyser and the wrong Snort engine. Snort 3 stays because Talos only speaks Snort, not because it adds analysis.

Two choices are time-sensitive. The flow identity has to be fixed inside PR #16 while 0.1.0 is unreleased; after release the same change counts as breaking and orphans every existing flow. Any Synapse 3.x exposure has to stay behind one model module, because 3.7.0 renames the match forms and flow props this plan uses, even though it keeps separate Snort and Suricata forms. Everything else, including Suricata rules, the unix-socket pool, Decode As for Suricata and the seccomp allowlist, can land as ordinary minor bumps. The tshark sandbox is the first new feature, at 0.2.0. It works in a stock container with no changes to how the container is run, and the same wrapper then covers the two new engines.
