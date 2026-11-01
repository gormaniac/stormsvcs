# Rule compatibility: Snort 2.9 / Snort 3 / Suricata 7.x-8.x, and running Snort rules on one PCAP service

Research date: 2026-10-31. Versions seen: Suricata 8.0.x is current; the OISF rule index recommends 8.0.8 ([index.yaml](https://www.openinfosecfoundation.org/rules/index.yaml)). The latest Snort 3 on snort.org is 3.12.4.0, and the latest Snort 2 is 2.9.20 ([snort.org/downloads](https://www.snort.org/downloads)).

## 1. How compatible is Suricata with Snort 2.9 rule syntax?

### Takeaway
Suricata parses the Snort 2.9 rule grammar (header, `content` plus `http_*` modifiers, PCRE buffer flags, `flowbits`, `byte_*`, `uricontent`). Many keywords behave differently, though, so a rule that loads can still match differently. Snort compatibility has not been an OISF priority for years. Rules that use preprocessor or shared-object features, or that rely on Snort-specific semantics, fail or misbehave.

### Cited Findings
- Suricata maintains an official "Differences From Snort" page. It covers buffers and keyword behavior. It does not give a list of unsupported keywords, and it does not cover threshold/detection_filter, gid, metadata, service, or SO rules — [Suricata docs: Differences From Snort](https://docs.suricata.io/en/latest/rules/differences-from-snort.html)
- **Ports and protocol detection:** Suricata detects app-layer protocols on any port. Its `http_*` buffers fill whenever HTTP is detected, whatever ports the rule lists. The docs recommend `alert http ... any` or `app-layer-protocol:` — [same](https://docs.suricata.io/en/latest/rules/differences-from-snort.html)
- **`http_*` modifiers:** Suricata still accepts the Snort 2 content modifiers (`http_uri`, `http_header`, `http_cookie`, etc.), but buffer contents differ:
  - `http_header` excludes the trailing CRLFCRLF and Cookie headers.
  - Duplicate headers are joined with ", ".
  - Whitespace after the colon is normalized.
  - `http_cookie` has no header name or CRLF.
  - There is no `http_raw_cookie`; use `http_raw_header`.
  - `http_uri` decodes `+` to space only with libhtp `query-plusspace-decode: yes`.
  - Source: [same](https://docs.suricata.io/en/latest/rules/differences-from-snort.html)
- **`urilen`:** Suricata ranges are exclusive (`2<>10` means greater than 2 and less than 10), and Snort's are inclusive. Suricata defaults to the normalized buffer, and Snort to raw — [same](https://docs.suricata.io/en/latest/rules/differences-from-snort.html)
- **PCRE buffer flags:** Suricata maps `U I H D C P M S Y` to buffers. `K` (raw cookie) is Snort-only. Suricata adds `Q W Z V`. A relative PCRE combined with `U` and similar flags works in Suricata, while Snort raises a syntax error — [same](https://docs.suricata.io/en/latest/rules/differences-from-snort.html)
- **`uricontent`:** Deprecated in both engines; use `http_uri` — [same](https://docs.suricata.io/en/latest/rules/differences-from-snort.html)
- **Sticky buffers:** `file_data`, `dns_query`, and `tls_*` are sticky in Suricata, and `pkt_data` resets to the payload. A relative `isdataat` applies to the buffer of the previous content match, and the docs note "Snort does not behave like this!" — [same](https://docs.suricata.io/en/latest/rules/differences-from-snort.html)
- **`byte_extract`/`byte_jump`/`byte_test`/`byte_math`:**
  - In Suricata, extracted variables must be used in the same buffer, otherwise they evaluate to 0. Snort allows cross-buffer use.
  - The `byte_math` `rvalue` accepts 0 (Snort rejects it), and dividing by zero never matches.
  - "Suricata's rule parser rejects rules that repeat keywords" in one rule.
  - Source: [same](https://docs.suricata.io/en/latest/rules/differences-from-snort.html)
- **`isdataat`:** `rawbytes` is accepted but does nothing. Relative checks are off by one: Snort's `isdataat:!0,relative` corresponds to Suricata's `isdataat:!1,relative` — [same](https://docs.suricata.io/en/latest/rules/differences-from-snort.html)
- **`flowbits`:**
  - Suricata can set and check the same flowbit within one packet.
  - Suricata checks `isset` after the fast pattern match but before other content. Snort evaluates left to right.
  - Dependent chains can depend on rule order or sid (Redmine bug 1399).
  - `noalert;` is equivalent to `flowbits:noalert;`.
  - The flowbits `toggle` command is deprecated in 8.0.6 and will be removed in 9.0 ([upgrade notes](https://docs.suricata.io/en/latest/upgrade.html)).
  - Source: [Differences page](https://docs.suricata.io/en/latest/rules/differences-from-snort.html)
- **`fast_pattern`:** Snort's matcher is always case-insensitive, and Suricata's is case-sensitive unless `nocase` is set. Snort truncates by `max-pattern-len` and drops leading NULs; Suricata does neither. `fast_pattern:only` is accepted but "silently ignored" — [same](https://docs.suricata.io/en/latest/rules/differences-from-snort.html)
- **Packet and stream keywords:** Packet keywords (`dsize`, `flags`, `ttl`) generally do not mix with `http_*` in Suricata, and Snort allows the mix. `dsize` with an app-layer protocol won't match the first app-layer packet — [same](https://docs.suricata.io/en/latest/rules/differences-from-snort.html)
- **Preprocessor-generated alerts:** Snort's reputation preprocessor generates GID 136 alerts. Suricata uses `iprep` instead, and its file matching uses `filename`/`fileext`/`filemagic`/`filemd5` etc. — [same](https://docs.suricata.io/en/latest/rules/differences-from-snort.html)
- **Alert limits:** Suricata has a hard, non-configurable limit of 15 alerts per packet or stream. It can emit duplicate alerts for one TCP packet, once for the packet and once for the stream. Snort uses `event_queue` — [same](https://docs.suricata.io/en/latest/rules/differences-from-snort.html)
- **Unknown keywords:** Loading Snort rules into Suricata commonly produces `SC_ERR_INVALID_SIGNATURE` errors (user report, 2020) — [forum thread](https://forum.suricata.io/t/convert-snort-rules-to-suricata-rules-and-vice-versa/343)
- **OISF priority:** Victor Julien (OISF lead, 2021-05-05) said Snort compatibility has not been a priority for several years, but he was open to "low hanging fruits" — [forum: FR Snort3 rules](https://forum.suricata.io/t/fr-snort3-rules/1333)
- **Missing references/classtypes:** By default Suricata only warns about a missing `reference` or `classtype` value. `--strict-rule-keywords` turns these warnings into errors — [command-line options](https://docs.suricata.io/en/latest/command-line-options.html)

### Inferences
- Snort 2.9 `metadata:service http` is ignored for detection by Suricata, so service-scoped Snort 2 rules fall back to their port headers. Suricata's protocol detection partly compensates, because its `http_*` buffers ignore ports. This is my inference from the protocol detection notes; I did not verify how Suricata handles `metadata:service`.
- Shared-object (SO) rules are compiled Snort plugins (stub rules with `metadata:engine shared, soid`). Suricata cannot execute them. They need a real Snort engine, or must be dropped. This is inference; I found no Suricata doc that addresses SO rules.
- Snort 2 preprocessor/decoder rules (gid != 1, e.g. `preprocessor.rules`, `decoder.rules`) have no Suricata equivalent. They should be treated as unsupported. This is inference: Suricata has its own `decoder-events.rules`/`stream-events.rules` with different sids.
- My training knowledge (unverified this session) is that Suricata supports `threshold`, `detection_filter`, `gid`, `rev`, `classtype`, `reference`, `priority` and free-form `metadata`. Confirm `threshold` semantics (type limit/threshold/both, track by_src/by_dst) against https://docs.suricata.io/en/latest/rules/thresholding.html.
- Even Snort 2 rules that load can produce false negatives or positives because of the `fast_pattern` case sensitivity, `isdataat` off-by-one, `urilen` range, and header buffer differences. "Loads without error" does not mean equivalent detection.

### Gaps
- I found no maintained, authoritative list of Snort 2.9 keywords that Suricata 7/8 rejects outright. The Differences page covers semantics, not rejection.
- I did not measure the load-failure rate of the current Talos Snort 2.9 snapshot on Suricata 8. A spot test with `suricata -T -S snort.rules` would quantify it.

## 2. Snort 3 rule syntax and divergence from Suricata; Suricata loading Snort 3 rules; conversion tools

### Takeaway
Snort 3 moved to sticky buffers and a standalone `service:` option. It removed `uricontent`, the PCRE buffer flags, and active/dynamic rules. It made `soid` a real option and replaced `urilen` with `bufferlen`. Some rules therefore look superficially more like Suricata's, but Suricata does not officially support Snort 3 rules and OISF has no plans for a converter. No reliable Snort-to-Suricata rule converter exists. The only robust official converter goes Snort 2 to Snort 3 (snort2lua).

### Cited Findings
- **Snort 3 rule changes (official Snort blog, 2020-08-12):**
  - "Added sticky buffers": buffer selectors precede content and stay in effect until changed.
  - `uricontent` deleted.
  - `urilen` raw/norm deleted; `urilen` replaced by generic `bufferlen` on the current sticky buffer.
  - PCRE options B, U, P, H, M, C, I, D, K, S, Y deleted in favor of sticky buffers.
  - `http_header` gains an option selector; new `http_param` buffer.
  - `metadata:service` becomes `service:`.
  - `alert file` and `alert service` rule types added; service rules no longer block port rules.
  - `http_encode` deleted; `metadata: rule-flushing` removed.
  - Active/dynamic rules deleted; `metadata engine shared` deleted; `soid` is now a non-metadata option.
  - Byte test `=<` is a syntax error (use `<=`).
  - All rules need a SID, and SID 0 is not allowed.
  - Metadata is ignored by detection and usable for selection via `--metadata-filter`.
  - Nets and/or ports may be omitted from headers.
  - `#begin`/`#end` block comments added.
  - Fast-pattern-only rules are determined automatically.
  - `sd_pattern` added.
  - Snort 3 parses all rules and reports all errors before quitting.
  - Source: [blog.snort.org: How rules are improving in Snort 3](https://blog.snort.org/2020/08/how-rules-are-improving-in-snort-3.html)
- **Divergence from Suricata syntax:**
  - Snort 3 uses `http_uri;` and related buffers as sticky buffers.
  - Suricata 5+ uses dotted sticky buffers (`http.uri;`, `http.header;`, `file.data` etc.) but still accepts the legacy `http_uri` *content modifiers*. A Snort 3 rule in which `http_uri;` precedes `content:` would be parsed by Suricata as a modifier applying to the previous content, or as an error.
  - This is inference from the two syntaxes; the Suricata sticky buffer behavior is per the [Differences page](https://docs.suricata.io/en/latest/rules/differences-from-snort.html).
- **Suricata position on Snort 3 rules:** Jason Ish (OISF, 2021-05-04): "no plans for a (official) conversion tool" or support for Snort 3 rules. Victor Julien (2021-05-05) was open to "low hanging fruits" and asked for details — [forum.suricata.io/t/fr-snort3-rules/1333](https://forum.suricata.io/t/fr-snort3-rules/1333)
- **snort2lua (official, ships with Snort 3):** `snort2lua -c old.rules -r updated.rules` converts Snort 2 rules to Snort 3. Unsupported options become comments in the output, and some rules need manual work — [blog.snort.org 2020-09](https://blog.snort.org/2020/09/converting-custom-snort-2-rules-for.html)
- **Community converters:**
  - [Cisconate/Snort3Converter](https://github.com/Cisconate/Snort3Converter) (MIT, 11 stars, 33 commits, no releases) converts Suricata to Snort 3 only, the opposite direction. It is tested on URL, SSH, PCRE and User-Agent features only, and calls itself a "first foray".
  - Google [gonids](https://github.com/google/gonids) was suggested on the Suricata forum. It is a Go IDS rule parser, and the forum thread does not confirm that it converts rules.
  - Source for both: [forum thread](https://forum.suricata.io/t/convert-snort-rules-to-suricata-rules-and-vice-versa/343)
- A Suricata forum responder said that compatibility "has not been a focus for some time" and that they knew of no conversion tool covering all options. This is a search-result summary of a forum thread; I did not fetch the exact post — [forum.suricata.io](https://forum.suricata.io/t/convert-snort-rules-to-suricata-rules-and-vice-versa/343)
- An unofficial "Snort 2 Rule Input" converter web page also exists. It is unvetted and I did not evaluate it — [maxias13.github.io/snort-rule-converter-site](https://maxias13.github.io/snort-rule-converter-site/)

### Inferences
- A Snort 3 to Suricata converter would need to:
  - map sticky buffer names (`http_uri` to `http.uri`, `file_data` to `file.data`, `http_header:field x` to `http.header` or a dedicated buffer);
  - map `service:` to an app-layer protocol in the header;
  - drop `soid` and SO rules;
  - handle `bufferlen`, `alert file`/`alert service` headers, and omitted nets/ports.

  This is feasible for simple content/PCRE rules, but semantic gaps remain (the Differences page items) and Snort 3-only buffers like `http_param` and `sd_pattern` would be lost. Converted rules would need per-rule validation against test PCAPs to be trustworthy.
- The `suricata-update` source index includes no Talos or Snort sources (see Q3). suricata-update has no Snort-to-Suricata conversion feature that I could find.

### Gaps
- I did not find the current docs.snort.org rule-option reference page (docs.snort.org/upgrade/differences returned 404). The Snort 3 changes above come from the 2020 blog, and later 3.x options (e.g. SnortML-related ones) are not enumerated.
- I found no study measuring how many Talos Snort 3 rules load or work on Suricata.

## 3. Ruleset publishing: Talos, ET Open/Pro, abuse.ch, suricata-update sources

### Takeaway
- **Talos** publishes Snort 2.9 and Snort 3 rulesets only, with no Suricata version. The free Community rules are GPLv2. Registered and Subscriber rules are under a Non-Commercial Use License that forbids embedding them in a sold product.
- **Proofpoint ET** publishes separate Suricata (`suricata-5.0`, `suricata-7.0.3`) and Snort (`snort-2.9.0`, `snort-edge`) builds of ET Open.
- **suricata-update's index** lists 30 Suricata-native sources (ET, abuse.ch, Stamus, Secureworks, PT, etc.) and no Talos.

### Cited Findings
- **Talos downloads:**
  - Snort 3 community: `snort3-community-rules.tar.gz`.
  - Snort 2.9 community: `community-rules.tar.gz`.
  - Registered snapshots: Snort 3 has `Talos_LightSPD.tar.gz` and `snortrules-snapshot-31470/31440/...`; Snort 2.9 has `snortrules-snapshot-29171/29181/29200`.
  - Subscriber extra: `Snort3_rules_timetag.txt`.
  - Engines: 3.12.4.0 and 2.9.20.
  - Source: [snort.org/downloads](https://www.snort.org/downloads)
- **Snort licensing:**
  - The engine and Community rules are GPLv2.
  - Proprietary Talos rules (Registered/Subscriber) are under a Non-Commercial Use License: "licensed to you for your personal use only". Distribution "cannot be done for the purpose of reaping a commercial profit or gain", and embedding them in a product sold to a third party violates the license.
  - Source: [snort.org/license](https://www.snort.org/license)
- **Snort 2 EOL status:**
  - On 2026-01-20 Talos stopped publishing rules for Snort 2.9.11.1, 2.9.13.0, 2.9.14.1, 2.9.15.1, 2.9.16.0, 2.9.16.1, 2.9.17.0 and 2.9.19.0, and for Snort 3 3.0.3.1 through 3.1.9.0.
  - "Snort 2.9.20 is the version of Snort that we will continue to support for the longest period of time." No end date is given, and Snort 2 as a whole was not declared EOL.
  - Source: [blog.snort.org 2026-01](https://blog.snort.org/2026/01/)
  - An earlier notice (2024-03-07) ended rules for 2.9.8.3 — [blog.snort.org](https://blog.snort.org/2024/03/snort-2983-and-snort-29130-end-of-life.html)
  - SO rules for 2.9.8.3 had a separate EOL notice in 2021 — [blog.snort.org 2021-07](https://blog.snort.org/2021/07/snort-2983-end-of-life-for-shared.html)
  - The 2.9.13.0 dates conflict across posts (July 2024 vs 2025/2026).
- **ET Open directories:**
  - Open directories: `snort-2.9.0/`, `snort-edge/`, `suricata-5.0/`, `suricata-7.0.3/`, plus `old/`. All were updated 2026-10-30 — [rules.emergingthreats.net/open/](https://rules.emergingthreats.net/open/)
  - `snort-edge/` contains `emerging.rules.tar.gz`, `emerging-all.rules` (47 MB), `SID-Descriptions-ETOpen.json.gz`, `classification.config`, `version.txt`, and BSD/GPLv2 license files. The listing does not say whether "edge" means Snort 3 — [snort-edge/](https://rules.emergingthreats.net/open/snort-edge/)
- **suricata-update `et/open` and `et/pro`:**
  - `et/open` URL: `https://rules.emergingthreats.net/open/suricata-%(__version__)s/emerging.rules.tar.gz`. The index lists its license as MIT.
  - `et/pro` (commercial, access code) URL: `https://rules.emergingthreatspro.com/%(secret-code)s/suricata-%(__version__)s/etpro.rules.tar.gz`.
  - Source: [OISF index.yaml](https://www.openinfosecfoundation.org/rules/index.yaml)
- **Other suricata-update sources (index.yaml):**
  - oisf/trafficid (MIT).
  - abuse.ch/sslbl-blacklist, abuse.ch/sslbl-ja3, abuse.ch/feodotracker, abuse.ch/urlhaus (all CC0-1.0). abuse.ch/sslbl-c2 was deprecated 2025-01-03.
  - Secureworks scwx/enhanced, malware and security (commercial).
  - Stamus: stamus/lateral (GPL-3.0) and the stamus/nrd-* feeds (commercial).
  - etnetera/aggressive (MIT); tgreen/hunting (GPLv3, min 7.0.3); pawpatrules (CC-BY-SA-4.0); ptrules/open (custom).
  - aleksibovellan/nmap (MIT); ipfire/dbl (CC-BY-SA-4.0, min 8.0.0); julioliraup/antiphishing (GPL-3.0).
  - the-hunters-ledger/open and echap/stalkerware (CC-BY-4.0, min 8.0.0).
  - Obsolete: ptresearch/attackdetection, malsilo/win-malware.
  - No Talos or Snort sources are listed.
  - Source: [OISF index.yaml](https://www.openinfosecfoundation.org/rules/index.yaml)

### Inferences
- Talos does not publish Suricata rules. Its downloads page lists only Snort 2.9 and Snort 3 artifacts, and the suricata-update index has no Talos source. I found no official Talos Suricata ruleset.
- **ET Open:** Running the Snort ET build on Suricata, or the reverse, is pointless. The service should fetch the `suricata-7.0.3` build for Suricata 7/8, and `snort-2.9.0` (or `snort-edge`) only for a Snort engine. The files differ mainly in syntax: Suricata dotted sticky buffers, app-layer protocol headers, and Suricata-only keywords like `tls.sni`, `ja3.hash` and `dns.query` in the Suricata build. This is inference; I did not diff the files.
- **Talos licensing for a hosted service:** Distributing Talos Registered/Subscriber rules inside a commercial product or service appears to conflict with the Non-Commercial license. Users should supply their own oinkcode and rules, or the service should bundle only Community (GPLv2) rules. This is not legal advice.
- abuse.ch feeds (CC0) and ET Open are the safest feeds to redistribute or bundle.

### Gaps
- I did not confirm whether ET `snort-edge` targets Snort 3 (no README).
- I did not fetch Proofpoint's documentation on ET Pro Snort vs Suricata differences.
- I did not verify whether Talos ever offered an official Suricata conversion. No evidence was found.

## 4. Uniform metadata representation; sid collisions

### Takeaway
All three engines share the same core tuple: gid, sid, rev, msg, classtype, priority, reference, metadata. Both engines' alert outputs expose gid, sid and rev, so `(engine, ruleset, gid, sid, rev)` is a workable uniform key. Sids are only unique within a vendor's allocated ranges, so the ruleset or source must be part of the identity.

### Cited Findings
- The Suricata EVE alert carries:
  - `alert.gid`, `alert.signature_id` (sid), `alert.rev`, `alert.signature` (msg), `alert.category` (classtype description), `alert.severity` (priority), and `alert.metadata` as string arrays.
  - `alert.action` ("allowed"/"blocked"); top-level `verdict`, `flow_id`, and `pcap_cnt` (packet number in pcap mode).
  - Example: `"gid": 1, "signature_id": 2018358, "rev": 10, "category": "Potentially Bad Traffic", "severity": 2`.
  - Source: [Suricata EVE JSON format](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html)
- Snort 3 `alert_json` can output `gid`, `sid`, `rev`, `msg`, `class`, `priority`, `service`, and `rule` (formatted "gid:sid:rev", e.g. `"1:1000000:0"`) — [docs.snort.org alert_logging](https://docs.snort.org/start/alert_logging)
- In Snort 3, metadata is ignored by detection and usable for selection via `--metadata-filter`. `service` and `soid` are first-class options — [blog.snort.org](https://blog.snort.org/2020/08/how-rules-are-improving-in-snort-3.html)
- `alert.metadata` logging is configurable in the Suricata alert output — [EVE format](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html)
- ET publishes `SID-Descriptions-ETOpen.json.gz`, a per-sid description file — [snort-edge listing](https://rules.emergingthreats.net/open/snort-edge/)

### Inferences
- **Common sid ranges:** These are from training knowledge and should be verified.
  - Talos/Snort: sid < 1,000,000, with local rules at 1,000,000+.
  - ET Open: 2,000,000-2,103,999 (e.g. 2018358 above).
  - ET Pro: 2,800,000+.
  - Suricata's own decoder/stream/app-layer events: 2,200,000-2,299,999.
  - abuse.ch and other community feeds pick their own ranges, and collisions with local rules are possible.
  - Recommendation: key alerts by `(source/ruleset, gid, sid, rev)`, not by sid alone.
- **Preprocessor gids:** Snort 3 inspector alerts use gid != 1 (e.g. 119/120 for http_inspect, 116 for decoder). Suricata uses gid 1 for nearly everything. A unified model should keep gid, but should not assume equal gid/sid pairs mean the same detection across engines.
- **Metadata:** `metadata` key/value pairs (`affected_product`, `attack_target`, `created_at`, `signature_severity`, `policy balanced-ips` etc.) are free-form in both engines. Parsing them into a list of (key, value) pairs gives a uniform representation.
- **Classtype:** classtype maps through each ruleset's `classification.config`. Suricata EVE emits the description (category), not the short name, so the service should ship or parse classification.config to normalize both.

### Gaps
- I did not verify official sid range allocation documents for Talos and ET.

## 5. Bottom-line options and detecting/reporting rules that fail to load

### Takeaway
- **(A) Suricata only:** Run Snort 2 rules natively and report the rules that fail. This is the simplest option, but load success does not mean equal detection, and Snort 3 rules mostly won't load.
- **(B) Suricata plus a converter:** No reliable converter exists, so you would have to build and maintain one.
- **(C) Real Snort 3 alongside Suricata:** Rules run with exact fidelity, including Talos SO rules, at the cost of two engines, two configs and two output formats.
- For a service whose purpose is "scan with Snort rulesets", (C) is the only option that gives correct Snort semantics. (A) is acceptable as a low-cost fallback.

### Cited Findings
- **Suricata load-failure detection:**
  - `-T` tests the configuration.
  - `--engine-analysis` prints reports on engine sections and exits.
  - `-S file` loads only the given signatures, and `-s` adds them to the YAML rules.
  - `--init-errors-fatal` exits with failure on signature load errors (the default is to warn and continue).
  - `--strict-rule-keywords` makes missing reference/classtype warnings into errors.
  - The page does not document exit codes.
  - Source: [Suricata command-line options](https://docs.suricata.io/en/latest/command-line-options.html)
- **Suricata detect-engine stats:** These include the last reload time, the number of rules loaded and the number of rules failed, and are reported per tenant under multi-tenancy. They come from a mirror of a Suricata commit, so verify the field names against the official docs — [git mirror commit graph](https://git.morozoff.pro/aiden/suricata/commits/commit/720cfcfcca6b2355b3d977a2d018f9e3bc068e6e)
  - The unix-socket commands `ruleset-stats` (rules_loaded/rules_failed), `ruleset-failed-rules`, and `ruleset-reload-time` exist — [simplified.guide (third-party)](https://www.simplified.guide/suricata/rule-reload)
  - A forum report shows 19,927 failed against 22,166 loaded, and the responder points to `suricata -T` log output for the reasons — [forum.suricata.io](https://forum.suricata.io/t/error-errcode-sc-err-no-rules-loaded-43-loading-signatures-failed/678)
- **Suricata 8 rule-load behavior changes:**
  - Unknown `requires` values are treated as unmet, so the rule is not loaded.
  - `ja3.hash`/`ja3s.hash` reject non-hex content.
  - Multiple `tls.cert_subject` print a warning.
  - Checksum keywords no longer depend on `stream.checksum-validation`.
  - Source: [Suricata upgrade guide](https://docs.suricata.io/en/latest/upgrade.html)
- **Snort 3 error reporting:** Snort 3 "parses all rules and reports all errors before quitting", whereas Snort 2 stopped at the first error. Rules load via `-R`, `--rule-path` or `--stdin-rules` — [blog.snort.org](https://blog.snort.org/2020/08/how-rules-are-improving-in-snort-3.html)
- **snort2lua conversion:** snort2lua turns unsupported Snort 2 options into comments in its output, which gives the service a way to flag Snort 2 to Snort 3 conversion problems — [blog.snort.org](https://blog.snort.org/2020/09/converting-custom-snort-2-rules-for.html)

### Inferences
- **Option A: Suricata only.**
  - Pros: one engine, EVE output, and app-layer metadata (http/tls/dns/fileinfo/flow events) for free.
  - Cons:
    - Talos Snort 3 rules (the current Talos focus) will largely fail to parse.
    - Snort 2.9 rules load with semantic drift (see Q1).
    - SO rules and preprocessor rules are impossible.
    - Talos Snort 2.9 rules are only published for 2.9.20, which is approaching EOL.
  - To report failures, run `suricata -T -S <ruleset> -l <dir>` per ruleset and parse the signature-error lines from suricata.log / the JSON log. Alternatively, read `rules_failed` from stats, or `ruleset-failed-rules` via the unix socket. Mark each failed sid as "unsupported" in the service output.
- **Option B: Suricata plus conversion.**
  - Snort 2 rules to Suricata needs only small fixups: `isdataat` off-by-one, `fast_pattern:only` removal, and `urilen` ranges.
  - Snort 3 rules to Suricata means a custom converter: sticky-buffer renaming, `service:` to app-layer header, and dropping `soid` and `sd_pattern`.
  - Expect a nontrivial percentage of rules to be unconvertible. Without a PCAP regression corpus there is no way to prove the converted rules are equivalent. This is high maintenance with no upstream support (OISF: no plans).
- **Option C: Snort 3 plus Suricata in one service.**
  - Use Snort 3 (3.12.x) with Talos Snort 3 rules (and LightSPD SO rules where the user supplies an oinkcode), and with Snort 2 rules converted via snort2lua. Use Suricata 8 for ET Open/Pro Suricata builds, abuse.ch, and other Suricata-native feeds.
  - Normalize both outputs to a common alert record keyed by `(engine, ruleset, gid, sid, rev)` plus packet number (Suricata `pcap_cnt`, Snort `pkt_num`).
  - Costs:
    - two binaries in the image (Snort 3 needs libdaq and LibDAQ modules, plus hyperscan optionally);
    - two rule update paths (suricata-update and PulledPork3 for Snort; PulledPork3 was not researched here);
    - Snort alerts lack Suricata's rich app-layer records.
  - This is the most faithful option.
- **Option D: other ideas.**
  - (D1) Suricata only, with Snort 2 rules accepted only from ET's Suricata build. Treat "Snort rules" as an import format with an explicit per-rule compatibility report, and don't claim Talos coverage.
  - (D2) Snort 3 only, for users who only want Talos.
  - (D3) Validate rules per ruleset at upload or update time, not at scan time, and cache the loaded/failed lists so scan output can link alerts and failures to ruleset versions.
- **Suricata pcap-scanning operations:**
  - `suricata -r file.pcap -S rules -l outdir -k none --runmode single` (or autofp/workers) works for offline scans.
  - `-k none` avoids drops caused by checksum-offloaded captures.
  - `--pcap-file-recursive` handles directories.
  - Source: [command-line options](https://docs.suricata.io/en/latest/command-line-options.html)
  - Large rulesets make detect-engine build time dominant for small PCAPs. A persistent Suricata in unix-socket pcap mode (`pcap-file` command) amortizes rule loading. This is inference and training knowledge; verify it in the unix-socket docs.
- **Snort 3 pcap-scanning operations:**
  - `snort -q -R rules -r file.pcap -A alert_json` per the docs; the `--lua "alert_json = {fields = '...'}"` override adds fields.
  - `file = true` writes `alert_json.txt`.
  - Source: [docs.snort.org alert_logging](https://docs.snort.org/start/alert_logging)
  - For reading a pcap, the DAQ is `pcap` by default with `-r`; `--daq dump` writes the packets out. I did not verify these defaults.
- **Alert field mapping between engines:**

  | Concept | Suricata EVE | Snort 3 alert_json |
  |---|---|---|
  | packet index | `pcap_cnt` | `pkt_num` |
  | flow correlation | `flow_id` | no flow_id; use `src_ap`/`dst_ap`/`proto` plus `flowstart_time` |
  | payload | `payload` / `packet` (optional) | `b64_data` (optional) |
  | rule identity | `alert.gid`/`signature_id`/`rev` | `gid`/`sid`/`rev` or `rule` |
  | message | `alert.signature` | `msg` |
  | class | `alert.category` | `class` |
  | priority | `alert.severity` | `priority` |
  | service | — | `service` |
  | action | `alert.action` / `verdict` | `action` (e.g. "would_drop") |

  Sources: [EVE](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html), [Snort alert_logging](https://docs.snort.org/start/alert_logging)
- **Snort 3 alert_json fields:**
  - Defaults: timestamp, pkt_num, proto, pkt_gen, pkt_len, dir, src_ap, dst_ap, rule, action.
  - Other available fields include b64_data, seconds, flowstart_time, client_bytes, client_pkts, server_bytes, server_pkts, service, msg, class, gid, sid, rev, priority, eth_*, tcp_*, vlan, mpls, geneve_vni and iface.
  - Source: [docs.snort.org alert_logging](https://docs.snort.org/start/alert_logging)

### Gaps
- I did not benchmark either engine for offline pcap throughput or rule-load time, so there are no measured performance numbers.
- I did not verify the exact Suricata log message format and event_type for signature load errors (e.g. `"event_type":"engine"` in suricata.json), or whether `stats.detect.engines[].rules_failed` appears in EVE stats in 8.0.
- I did not verify the Snort 3 exit code or error output format for a rule parse failure, or a machine-readable way to get failed rules.
- I did not research PulledPork3 (Snort 3 rule management, which handles LightSPD/SO rule selection).
