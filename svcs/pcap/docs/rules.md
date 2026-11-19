# Rules and feeds

The Cortex is the source of truth for rules. Rules are `it:app:snort:rule` and
`it:app:suricata:rule` nodes. The service downloads feeds and parses them, Storm models the
feeds' rules as nodes, and every enabled rule node with `:text` is pushed to the service, which
builds a rules file per engine from the rules the engine can load.

Code: {src}`svcs/pcap/src/pcapsvc/rulesvc.py` (`RuleMixin`), {src}`svcs/pcap/src/pcapsvc/rules.py`,
{src}`svcs/pcap/src/pcapsvc/feeds.py`, {src}`svcs/pcap/src/pcapsvc/snort.py`,
{src}`svcs/pcap/src/pcapsvc/suricata.py`, and the Storm in `slib.pcap.priv.sync`,
`slib.pcap.priv.rules` and `slib.pcap.model`.

```text
 feed URL --download/parse--> service: rules/feeds/<name>.mpk
                                  | feedChanges (batches of 500)
                                  v
 Cortex view: meta:ruleset -(has)> it:app:snort:rule / it:app:suricata:rule  <-- slib.pcap.rule.add
                                  | push (enabled, with :text, batches of 1000)
                                  v
 service: slib:pcap:rules (slab) --build--> rules/active/{snort,suricata}-<build>.rules
                                  | every analysis
                                  v
                         snort -R / suricata -S
```

## Which rules run

| Node | Engine |
| --- | --- |
| `it:app:snort:rule` with `:engine=3`, or no `:engine` | Snort 3. |
| `it:app:snort:rule` with `:engine=2` | Snort 2.x, converted to Snort 3 with `snort2lua` at build time. The node keeps the original text. |
| `it:app:suricata:rule` | Suricata. |

A push sends every rule node in the view with `:enabled=true` and `:text` (Snort rules also need
an `:engine` of 2, 3, or none). Any other `:engine` is refused by the service
(`... rules (with :engine N) can't be run by the service.`).

## Rule parsing

`rules.parseRule` reads only what's needed to identify and model a rule. Whether a rule is valid
is up to the engine.

- A rule starts with an action: `alert`, `block`, `drop`, `log`, `pass`, `react`, `reject`,
  `rejectboth`, `rejectdst`, `rejectsrc`, `rewrite`, `sdrop` (case-insensitive). A leading `#`
  marks a disabled (commented out) rule, the marker is removed from `text`.
- Trailing-backslash continuation lines are joined, and multi-line rules become one line.
- The options in parentheses are split on `;` (a `\` escapes, quoted `;` don't split). If no
  `sid` is found that way, they're split again ignoring quotes (Snort 2.x lets a pcre hold an
  unescaped `"`).
- Read options: `sid` (required), `gid` (default 1), `rev` (default 1), `msg`, `classtype`,
  `priority`, `reference` (`scheme,value`), `metadata` (`key value, ...`), from which
  `created_at`, `updated_at` (`YYYY_MM_DD` or `YYYY-MM-DD`) and `malware_family` are used.

`rules.iterRuleText` finds rules in a file: comments and blank lines are skipped, a rule ends at
a line ending with `)` (Snort 3 multi-line style) or a blank line not continued by a backslash,
and a line that starts a new rule always ends the previous one. A commented-out multi-line rule
has every line uncommented.

## Building

Every push or update that changes the rules, and a push with `force`, calls `_build()` under a
lock:

1. **Prepare** (`_prepare`, in an executor): parse every pushed rule. Parse errors are recorded.
   Pick one rule per engine family and `gid:sid` (Snort 2 and Snort 3 share Snort's namespace,
   Suricata has its own): the highest `rev` wins, ties go to the lowest guid. The losers get
   `Duplicate <space> gid:sid <gid>:<sid>, rule <guid> (rev <n>) is used instead.`
2. **Snort** (`_buildSnort`): without Snort installed, every Snort rule gets `The service doesn't
   have Snort, so Snort rules can't be run.` Otherwise Snort 2 rules are converted with
   `snort2lua` (`-c <in> -r <out> -o <lua> -e <errors>`), rules that didn't come out get
   `Unable to convert the Snort 2 rule to Snort 3: <why>`, and then the Snort 3 rules and the
   converted ones are validated.
3. **Suricata** (`_buildSuricata`): the same without Suricata, otherwise validated.
4. **Write**: each engine's valid rules are in `rules/active/<engine>-<build guid>.rules`, with
   `<file>.index.json` mapping `gid:sid` to `{guid, rev}` (how alerts become hits).
5. **Record**: the errors replace `slib:pcap:ruleerrs`, the warnings of the loaded rules replace
   `slib:pcap:rulewarns`, and `rules:active`, `rules:count`, `rules:invalid`, `rules:built`,
   `rules:took` are saved in `slib:pcap:ruleinfo`. The previous rules files are deleted once no
   running analysis uses them.

A build that fails for a reason other than a bad rule (ex. a broken `snort:conf`) saves
`rules:error`, deletes its half-written files, keeps the previous rules active, and fails the
call. The next push rebuilds even if nothing changed.

### Validation

Engines refuse to start if any rule is invalid, so each engine's rules are loaded in test mode,
every rule the engine reports is dropped, and the rest are loaded again, up to 25 passes:

- **Snort** (`Snort.validate`): first `precheck` each rule (single line, balanced quotes and
  parentheses, nothing after the closing parenthesis except a comment), since an unbalanced quote
  makes Snort blame the following rules. Then
  `snort -c <conf> --include-path <dir> -R <file> -T -q [snort:args]`, reading
  `ERROR: <file>:<line> <mesg>` lines. A failure with no rule error fails the build.
- **Suricata** (`Suricata.validate`): rules must be a single line. Then
  `suricata -T -c <generated conf> -S <file> -l <tmp>`, reading `error parsing signature "..."
  from file <file> at line <n>` and the preceding `E: <module>: <mesg>` line as the reason.

`slib.pcap.rule.check` runs the same validation on one rule in a scratch directory without
touching the service's rules.

### Warnings

Rules that load but might not do what they look like they do get warnings
(`rules.ruleWarnings`), listed by `slib.pcap.rule.errors`:

| Warning | When |
| --- | --- |
| No content match | No `content`, `uricontent`, `pcre`, `byte_test`, `byte_jump`, `byte_math`, `dsize`, `isdataat`, `base64_data` or `regex`, and the protocol isn't `ip`, `ipv4`, `ipv6` or `pkthdr`. It's checked against all the traffic its header matches. |
| pcre without content | A `pcre` but no `content`/`uricontent`: no fast pattern. |
| `pass` rule | No other rule alerts on what it matches. |
| `noalert` | A `noalert` option, or `noalert` in `flowbits`/`xbits`: it only sets state. |
| `drop`, `sdrop`, `reject*` | Offline nothing is blocked, it only alerts. |

## Pushes

Two ways rules get to the service:

- **Full push** (`slib.pcap.sync`, `slib.pcap.priv.sync.push`): `pushStart()`, then every
  enabled rule in batches of 1000 with `pushRules(iden, batch)`, then `pushDone(iden, force)`.
  The service replaces its whole rule set with the pushed rules. A failed batch cancels the push,
  leaving the service's rules as they were.
- **Incremental** (`slib.pcap.rule.add`, `.enable`, `.disable`): `ruleUpdate(rules, dels)` adds
  or updates some rules and removes others by guid.

Either rebuilds only when the stored rules changed, or a rebuild is needed anyway (the last
build failed, or rules files are missing). Rules edited any other way (ex. setting `:enabled` or
`:text` directly) reach the service on the next full push.

### The rules view

The service has one set of rules, so they come from one view: the view the add event ran in
(saved in `slib:pcap:rules:view`), or the view of the last `slib.pcap.admin.schedule --period`.
Installs from before the global existed use the sync cron job's view. `push()` and `update()`
return `The service's rules come from view <view>, they can't be changed from this view. An
admin can move them with slib.pcap.admin.schedule --period in another view.` in any other view,
so a fork can't replace or disable the rules every analysis uses. `slib.pcap.rule.enable` and
`.disable` call `slib.pcap.priv.rules.denied()` first and, in another view, warn without editing
`:enabled`. Feeds can still be synced into another view with `slib.pcap.sync --no-push`.

## Feeds

| Feed | Engine | Enabled | URL |
| --- | --- | --- | --- |
| `snort3-community` | `snort3` | yes | `https://www.snort.org/downloads/community/snort3-community-rules.tar.gz` (Snort 3 Community Ruleset, GPLv2) |
| `et-open` | `suricata` | yes | `https://rules.emergingthreats.net/open/suricata-8.0/emerging.rules.tar.gz` (Proofpoint ET Open, MIT), excludes `emerging-deleted.rules` |
| `abusech-sslbl` | `suricata` | no | `https://sslbl.abuse.ch/blacklist/sslblacklist_tls_cert.tar.gz` (SSL Blacklist, CC0) |
| `abusech-feodo` | `suricata` | no | `https://feodotracker.abuse.ch/downloads/feodotracker.tar.gz` (Feodo Tracker, CC0) |
| `abusech-urlhaus` | `suricata` | no | `https://urlhaus.abuse.ch/downloads/urlhaus_suricata.tar.gz` (URLhaus, CC0) |

`RETIRED_FEEDS` lists default feeds that were removed upstream (`abusech-sslbl-c2`,
`https://sslbl.abuse.ch/blacklist/sslipblacklist.tar.gz`). A service that has one with that
exact URL removes it at startup.

The service doesn't ship a Talos registered or subscriber feed. Whether you can use a ruleset,
and how, is up to its license and your subscription.

### Feed definitions

`{name, url, engine, enabled, exclude, desc}`, normalized by `feeds.normFeed`: `name`
lowercased and matching `^[a-z0-9][a-z0-9_.-]*$` (it's used as a file name), `url` an `http://`
or `https://` URL, `engine` one of `snort3`, `snort2`, `suricata` (default `snort3`), `enabled`
(default true), `exclude` a list of `fnmatch` patterns (a single string is accepted), `desc` a
string. Definitions are stored in the `slib:pcap:feeds` slab keyval.

### Download

`feedPull(name, force, view)`:

1. Skips (`skipped: true`) when not forced, the feed was downloaded before, its records file
   exists, and the last download is younger than `pcap:feeds:interval` hours.
2. Fills `${name}` secrets into the URL (see below).
3. `GET` with `If-None-Match`/`If-Modified-Since` from the last download (not when forced or the
   records file is missing), a total timeout of `pcap:feeds:timeout`, reading 1 MiB chunks and
   failing past `pcap:feeds:maxsize`. Any status other than 200 or 304 fails.
4. On 304 only `pulled` is updated.
5. Otherwise the feed is unpacked and parsed in an executor, and the records are written to
   `rules/feeds/<name>.mpk`. `sha256`, `etag`, `modified`, `count`, `enabled`, `errors`, `files`
   are saved in `slib:pcap:feedinfo`. Unparsable rules are logged (the first three).

A failed download or parse saves `error` and `failed` and fails the call (the sync warns).

### Unpacking

`feeds.unpack` works in memory and nothing is written to disk:

| Download | Read as |
| --- | --- |
| gzip that is a tar (`.tar.gz`, `.tgz`) | Every regular `*.rules` member. |
| gzip of anything else (`.gz`) | Decompressed (at most `maxsize`), then checked again. |
| `PK\x03\x04` (`.zip`) | Every `*.rules` member. |
| An uncompressed tar (over 512 bytes) | Every regular `*.rules` member. |
| Anything else | One file, `feed.rules`. |

Members matching an `exclude` pattern (by base name or path) are skipped. Each member's declared
size is checked against what's left of `pcap:feeds:maxsize`, and at most that (plus a byte) is
read, so a member that lies about its size can't be decompressed into memory. A feed with no
`.rules` files fails.

### Rule records

`feeds.parseFeed` parses every rule (enabled or commented out). A `gid:sid` in a feed more than
once keeps the highest `rev`. Each becomes a record (see [Telepath API](api.md#feeds)) with
guid `guid(("slib.pcap.rule", <feed>, gid, sid))`, the feed's engine and form, and the rule's
text, enabled state (commented out rules are disabled), message, references, family and dates.

### Secrets in feed URLs

A URL like
`https://www.snort.org/rules/snortrules-snapshot-31200.tar.gz?oinkcode=${talos:oinkcode}`
references a secret (`${[a-zA-Z0-9_.:-]+}`). Secrets are only in the service's
`pcap:feeds:secrets` config, so Cortex admins (who choose feed URLs) never see them:

```yaml
pcap:feeds:secrets:
  talos:oinkcode: {value: "<oinkcode>", hosts: ["www.snort.org", "snort.org"]}
```

- The URL's host is computed with the placeholders replaced, and each secret is only filled in
  when that host matches one of its `hosts` (exact, or a `*.example.com` suffix match). Otherwise
  the download fails: `The secret ${name} isn't allowed to be sent to <host>.`
- A missing secret fails: `The feed's URL needs the secret ${name}, set it in the service's
  pcap:feeds:secrets config ...`
- Values are URL-quoted (`safe=""`).
- Download errors have every secret's value (raw and quoted) replaced with `${name}` before
  they're saved in the feed's info or returned. The Telepath API's `_retnRedact()` does the same
  to every error message it returns, including unexpected ones (see
  [Telepath API](api.md)).
- `feeds()` and the other feed methods return the URL with its placeholders.

## Syncing

`slib.pcap.sync` runs `slib.pcap.priv.sync.syncFeed` for each enabled feed (or each `--feed`),
then `push()`. A sync of one feed into the current view:

1. `feedPull(name, force, view)`. If not forced and the download's SHA-256 is the one last
   synced into this view, stop.
2. Create or update the feed's `meta:ruleset` (`:name`, `:type=slib.pcap.feed`, `:desc`,
   `:updated`).
3. `feedChanges(name, view, full=force)` yields batches of 500. The changes are computed against
   the snapshot of the records last synced into this view
   (`rules/feeds/synced/<name>/<view>.mpk`): records that differ are upserted, guids that are gone
   are `removed`. Without a snapshot, or with `force`, every record is upserted and the batch says
   `full`.
4. Per upserted record:
   - **New rule** (no node with the guid): created with the record's enabled state and its
     references, then all of a batch's new rules join the ruleset in one edit.
   - **Existing rule**: skipped if it's in the ruleset and `:text` and `:engine` are unchanged.
     Otherwise `:id`, `:text`, `:version`, `:name`, `:created`, `:updated` (and `:engine`,
     `:family`) are set from the feed, its references are linked, and if it wasn't in the ruleset
     it joins with the feed's enabled state. `:enabled` isn't touched for a rule already in the
     ruleset, so a sync never re-enables a rule you disabled. The feed's `:text` wins over edits.
   - A rule added but not joined (ex. the sync failed in between) joins on the next sync.
5. Per removed guid in the ruleset: `:enabled=false` and removed from the ruleset. A full sync
   also retires every ruleset member that no upserted record named.
6. `feedSynced(name, sha256, view)` copies the records to the view's snapshot and records the
   SHA-256 and time in the feed's `views`. If the feed was downloaded again in the meantime it
   fails, and the next sync starts over.

To change a feed rule, add a custom copy with a higher `rev` (or a new sid) and disable the
original. Every rule is modeled in Storm, so a first sync of a large feed takes a while (the
README measured about 10 ms a rule, roughly 10 minutes for ET Open), later syncs only touch the
changes.

The sync's edits run as root (in `slib.pcap.priv.sync`), so `slib.pcap.sync` holders don't need
permissions for the rulesets, references and edges, but the command checks they may add both
rule forms to the current layer.

## Matches

During an analysis each engine runs with its active rules file, and the engine's index turns
alerts into hits (see [Data model](model.md#rule-matches)). Alerts for a `gid:sid` that isn't in
the index are counted, not modeled. An engine with no loaded rules: Snort doesn't run, Suricata
runs with `--disable-detection`.

## Service state

| Keyval (cell slab) | Holds |
| --- | --- |
| `slib:pcap:rules` | Pushed rules, guid -> `(text, engine)`. |
| `slib:pcap:ruleinfo` | `feeds:seeded`, `rules:active` (engine -> file name), `rules:count`, `rules:invalid`, `rules:built`, `rules:took`, `rules:pushed`, `rules:error`. |
| `slib:pcap:ruleerrs` | guid -> error, from the last build. |
| `slib:pcap:rulewarns` | guid -> warnings, from the last build. |
| `slib:pcap:feeds` | name -> feed definition. |
| `slib:pcap:feedinfo` | name -> download state and `views` (view -> `{sha256, at}`). |

At startup the active rules are loaded from `rules:active` and their index files. If rules were
pushed but a rules file is missing, a rebuild is scheduled.
