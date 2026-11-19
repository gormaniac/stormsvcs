# Commands

Every command is defined in {src}`svcs/pcap/src/pcapsvc/pkgproto/slib.pcap.yaml`, with its
Storm in `pkgproto/storm/commands/`. Run any command with `--help` for its options and
examples.

| Command | Permission | Purpose |
| --- | --- | --- |
| [`slib.pcap.flows`](#slibpcapflows) | `slib.pcap.user` | Analyze captures, model their flows and rule matches. |
| [`slib.pcap.status`](#slibpcapstatus) | `slib.pcap.user` | Engines, sandbox, Axon, rules, sync schedule. |
| [`slib.pcap.rule.check`](#slibpcaprulecheck) | `slib.pcap.user` | Check if an engine can load rules, without changing the service. |
| [`slib.pcap.rule.errors`](#slibpcapruleerrors) | `slib.pcap.user` | The rules the engines couldn't load, and warnings. |
| [`slib.pcap.feed.list`](#slibpcapfeedlist) | `slib.pcap.user` | The feeds and their download and sync state. |
| [`slib.pcap.rule.add`](#slibpcapruleadd) | `slib.pcap.rules` | Add or update custom rules, and push them. |
| [`slib.pcap.rule.enable`](#slibpcapruleenable) | `slib.pcap.rules` | Enable rule nodes and push them. |
| [`slib.pcap.rule.disable`](#slibpcapruledisable) | `slib.pcap.rules` | Disable rule nodes and remove them from the service. |
| [`slib.pcap.sync`](#slibpcapsync) | `slib.pcap.sync` | Sync the feeds into the view and push every enabled rule. |
| [`slib.pcap.admin.feed`](#slibpcapadminfeed) | `slib.pcap.admin` | Add, remove, enable, or disable a feed. |
| [`slib.pcap.admin.schedule`](#slibpcapadminschedule) | `slib.pcap.admin` | Show or change the sync cron job. |
| [`slib.pcap.admin.vars`](#slibpcapadminvars) | `slib.pcap.admin` | Network variables for every run. |
| [`slib.pcap.admin.decode`](#slibpcapadmindecode) | `slib.pcap.admin` | Decode As rules for every run. |

Service errors are reported as warnings (`slib.pcap: <what> failed: <mesg>`) rather than raised,
so a failed call doesn't kill the pipeline. The exceptions are `slib.pcap.sync` (raises
`AuthDeny` without the layer permissions) and `slib.pcap.lib.flows()` (raises `slib.pcap.Error`).

## Analysis

### slib.pcap.flows

Analyze captures (pcap, pcapng, or either gzip compressed, as `file:bytes` in the Axon) and model
every flow in them as an `inet:flow`, with what the engines found and the rule matches.

```text
slib.pcap.flows [sha256s ...] [--timeout <int>] [--limit <int>] [--handshake <int>]
                [--tag <tag>] [--host <it:host>] [--sandbox-file <file:bytes>]
                [--keylog <sha256> ...] [--decode-as <rule> ...]
                [--no-suricata] [--no-snort] [--no-tshark] [--no-rules] [--no-files]
                [--yield] [--hits]
```

**Input:** `file:bytes` nodes with a `:sha256`. Any other node is warned about and dropped.

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `sha256s` | str, `nargs: *` | | SHA-256s (or `sha256:<hex>`) of captures in the Axon to analyze instead of the inbound nodes. Each is analyzed once, in the `fini` block, and the inbound nodes are dropped. The `file:bytes` node is created only once the service has read the capture. |
| `--timeout` | int | `null` (`pcap:timeout`, 300) | Seconds a flow can be idle before a new flow starts, `0` to never time out. |
| `--limit` | int | `0` (`pcap:limit`) | Max flows per capture, capped at `pcap:limit`. `0` means the service's max. |
| `--handshake` | int | `null` (`pcap:handshake`, 1024) | Max characters kept of each side's first text payload, `0` for none. |
| `--tag` | str | `null` | A tag added to every flow. |
| `--host` | str | `null` | The `it:host` (guid) that captured the traffic: each flow's `:capture:host` and each match's `:sensor`. |
| `--sandbox-file` | str | `null` | The `file:bytes` a sandbox ran to make the capture: each flow's `:sandbox:file` and each DNS request's `:sandbox:file`. |
| `--keylog` | str, `append` | `[]` | SHA-256 of a TLS key log (`SSLKEYLOGFILE` format) in the Axon. Repeatable. Needs tshark. |
| `--decode-as` | str, `append` | `[]` | A Decode As rule `<selector>==<value>[-<value>],<protocol>` (ex. `"tcp.port==8443,tls"`, quoted). Repeatable. Added after the admin's rules (`slib.pcap.admin.decode`). |
| `--no-suricata` | flag | | Don't run Suricata. |
| `--no-snort` | flag | | Don't run Snort. |
| `--no-tshark` | flag | | Don't run tshark. |
| `--no-rules` | flag | | Don't match rules (Snort doesn't run, Suricata runs with `--disable-detection`). |
| `--no-files` | flag | | Don't extract files. |
| `--yield` | flag | | Yield the `inet:flow` nodes instead of the inbound nodes. |
| `--hits` | flag | | With `--yield`, yield the `it:app:snort:hit` and `it:app:suricata:matched` nodes instead of the flows. Without `--yield` it has no effect. |

`--tag`, `--host` and `--sandbox-file` are normalized (`syn:tag`, `it:host`, `file:bytes`)
before the run, an invalid value warns and stops the command for that capture. When an engine
flag isn't given, the engine's `*:enabled` config decides, and only installed engines run.

What it creates: `inet:flow`, `file:bytes` (the capture, and every extracted file),
`file:attachment`, `crypto:x509:cert`, `crypto:key`, `inet:fqdn`, `inet:dns:request`,
`inet:dns:answer`, `inet:dns:soa`, `it:app:snort:hit`, `it:app:suricata:matched`, and their edges.
See [Data model](model.md).

Output: `slib.pcap: Modeled <n> flows (<m> rule matches) from <p> packets in file:bytes=<repr>`,
and warnings when:

- the capture is truncated (read up to the error),
- it had more flows than the limit (`<dropped> packets for the rest were dropped`),
- engine records were malformed and skipped (per kind, ex. `suricata:tls`),
- the sandbox caught an engine doing something it shouldn't (see [Sandbox](sandbox.md#alerts)),
- an enabled engine had an error,
- `--hits` was used and neither engine had rules loaded,
- key logs were given but tshark didn't run,
- files couldn't be saved (no `axon:url`), or were over the extraction limits.

With `$lib.debug` it also prints the engines that didn't run and why, and the whole summary
(`slib.pcap: <sha256> summary: {...}`, see [Telepath API](api.md#flows)).

```text
// Analyze PCAPs that are already file:bytes nodes.
file:bytes:mime=application/vnd.tcpdump.pcap | slib.pcap.flows

// Yield the flows, tag them, and set the sensor.
file:bytes=sha256:<sha256> | slib.pcap.flows --yield --tag cno.case.123 --host <it:host guid>

// Yield the rule matches, then pivot to the rules.
file:bytes=sha256:<sha256> | slib.pcap.flows --hits --yield | :rule -> *

// By SHA-256 (the file:bytes node is created if needed).
slib.pcap.flows <sha256> --yield | +inet:flow:dst:port=443

// Decrypt TLS with a key log in the Axon, and parse TLS on port 8443.
file:bytes=sha256:<sha256> | slib.pcap.flows --keylog <keylog sha256> --decode-as "tcp.port==8443,tls" --yield
```

The flows and matches of a capture can be lifted again later:

```text
file:bytes=sha256:<sha256> -(refs)> inet:flow
file:bytes=sha256:<sha256> -(refs)> (it:app:snort:hit, it:app:suricata:matched)
```

#### TLS decryption

`--keylog` takes NSS key logs, the format browsers, curl and most TLS libraries write with
`SSLKEYLOGFILE`. All of a run's key logs are joined into one file (at most
`tshark:keylog:maxsize` together) and given to tshark (`-o tls.keylog_file:...`). tshark then
decrypts the TLS 1.2 and 1.3 sessions it has secrets for. With a key log tshark extracts every
field (not only the gaps), so certificates of TLS 1.3 handshakes, and HTTP/1.1 and HTTP/2 inside
TLS (software names, requests, files), are modeled like cleartext. Secrets embedded in a pcapng
(Decryption Secrets Blocks, ex. from `editcap --inject-secrets`) are always used.

#### Decode As

Engines only parse protocols on their usual ports (Suricata also probes for some). A Decode As
rule goes to tshark as `-d <rule>` (its protocol is also added to `--only-protocols`), and a
`tcp.port` or `udp.port` rule for a protocol Suricata parses adds Suricata detection ports (ex.
`tcp.port==8443,tls` adds `8443` to `app-layer.protocols.tls.detection-ports.dp`). Rules are
validated against `^[a-z][a-z0-9_.-]{0,63}==[0-9]{1,10}(-[0-9]{1,10})?,[a-z][a-z0-9_.-]{0,63}$`
after being lowercased, and duplicates are dropped. Quote them, Storm can't parse them unquoted.

### slib.pcap.status

```text
slib.pcap.status
```

No arguments. Prints, from the service's `status()` and the sync cron job:

- each engine: `not installed`, `<version> (disabled by default)`, or `<version>`,
- `Sandbox: <mode>, engines run as <uid>, Landlock ABI <n>, seccomp <bool>`, the number of
  sandbox alerts since the service started and the latest 10 (as warnings), and a warning listing
  the layers the host doesn't support,
- whether the service has an Axon (a warning if not),
- `Rules: <loaded> loaded of <pushed> pushed (<engine> <count>, ...), <invalid> invalid`, the last
  push and build times, whether a build is running, and the last build error,
- `Sync schedule: cron <iden> (<enabled|disabled>), last run: <time>`, or none.

## Rules

See [Rules and feeds](rules.md) for how rules get from the Cortex to the engines.

### slib.pcap.rule.add

Add (or update) custom rules as nodes, and push them to the service.

```text
slib.pcap.rule.add <text> [<text> ...] [--engine snort3|snort2|suricata] [--disabled] [--yield]
```

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `text` | str, `nargs: +` | | The rules, one per argument. |
| `--engine` | `snort3`, `snort2`, `suricata` | `snort3` | The rules' syntax. `snort3` and `snort2` make `it:app:snort:rule` (`:engine` 3 or 2), `suricata` makes `it:app:suricata:rule`. |
| `--disabled` | flag | | Add the rules with `:enabled=false`, and remove them from the service if it had them. |
| `--yield` | flag | | Yield the rule nodes (once, in `fini`) instead of the inbound nodes. |

Each rule is parsed by the service (`ruleParse`), which gives its guid:
`guid(("slib.pcap.custom", <"snort"|"suricata">, gid, sid))`. Adding a rule with the same
engine family and gid:sid again (ex. a new `rev`) updates the same node. The node gets `:id`,
`:text`, `:version` (the rev), `:name` (`msg`), `:created`/`:updated` (ET style
`created_at`/`updated_at` metadata), `:enabled`, and for Snort rules `:engine` and `:family`
(`malware_family` metadata). References become edges (see [Data model](model.md#rules)).

Then the enabled rules are pushed (`ruleUpdate`), which rebuilds the engines' rules if anything
changed. The command prints a line per rule and the build summary, and warns for each rule the
engine couldn't load. The push is refused from a view other than the rules view (see
[Rules and feeds](rules.md#the-rules-view)), the nodes are still edited.

```text
slib.pcap.rule.add 'alert http any any -> any any ( msg:"My rule"; http_uri; content:"/evil"; sid:1000001; rev:1; )'
slib.pcap.rule.add --engine suricata 'alert dns any any -> any any (msg:"Evil DNS"; dns.query; content:"evil.example"; sid:1000002; rev:1;)'
```

### slib.pcap.rule.enable

```text
<it:app:snort:rule | it:app:suricata:rule> | slib.pcap.rule.enable
```

**Input:** `it:app:snort:rule`, `it:app:suricata:rule`. Sets `:enabled=true` on each, then pushes
the ones that have `:text` (and, for Snort rules, an `:engine` of 2, 3, or none) in one
`ruleUpdate` in `fini`. Rules without `:text` or with another `:engine` are warned about and not
pushed. Other forms pass through untouched.

```text
meta:ruleset:name=et-open -(has)> it:app:suricata:rule +:name~="cobalt strike" | slib.pcap.rule.enable
```

### slib.pcap.rule.disable

```text
<it:app:snort:rule | it:app:suricata:rule> | slib.pcap.rule.disable
```

**Input:** the rule forms. Sets `:enabled=false`, and removes the rules from the service (by
guid) in one `ruleUpdate` in `fini`.

```text
it:app:suricata:rule:id=2013502 | slib.pcap.rule.disable
```

`slib.pcap.rule.enable` and `.disable` check the view first: in a view that isn't the
[rules view](rules.md#the-rules-view) they warn once (`The service's rules come from view
<view>, ... The rules weren't changed.`), don't edit `:enabled`, and pass their nodes through.

### slib.pcap.rule.check

Check if the engines can load rules, without changing the service.

```text
<rule nodes> | slib.pcap.rule.check
slib.pcap.rule.check --text <rule> [--engine snort3|snort2|suricata]
```

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--text` | str | `null` | Check this rule text instead of the inbound nodes. |
| `--engine` | `snort3`, `snort2`, `suricata` | `snort3` | The syntax of `--text`. |

**Input:** `it:app:snort:rule` (`snort2` when `:engine=2`, else `snort3`) and
`it:app:suricata:rule`. Rules without `:text` are warned about. The service parses the rule,
converts Snort 2 rules with `snort2lua`, and loads it in the engine's test mode in a scratch
directory. Prints `... is valid.` or warns `... is invalid: <the engine's error>`. Fails when the
service doesn't have the engine.

```text
it:app:snort:rule:id=1000001 | slib.pcap.rule.check
slib.pcap.rule.check --engine snort2 --text 'alert tcp any any -> any 80 (content:"a"; http_uri; sid:1;)'
```

### slib.pcap.rule.errors

```text
slib.pcap.rule.errors [--no-warnings] [--yield]
```

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--no-warnings` | flag | | Don't list the warnings of rules that loaded. |
| `--yield` | flag | | Yield the nodes of the rules that couldn't be loaded (not the ones with warnings). |

Prints each rule the last build couldn't load, as `<form>=<guid> (sid <id>): <error>`, then each
warning of a loaded rule as `<form>=<guid> (sid <id>) warning: <mesg>`. Errors include parse
errors, engine load errors, duplicates (`Duplicate snort gid:sid 1:1000001, rule <guid> (rev 3)
is used instead.`), failed Snort 2 conversions, and rules for an engine the service doesn't have.
The warnings are listed in [Rules and feeds](rules.md#warnings).

## Feeds and syncing

### slib.pcap.feed.list

```text
slib.pcap.feed.list [--yield]
```

Prints a table (`name`, `enabled`, `engine`, `rules`, `downloaded`, `synced`) and each feed's URL
(with `${secret}` placeholders, never the values). `synced` is `yes` when the feed's last
download was synced into the current view. Warns for feeds whose last download failed.
`--yield` yields the feeds' `meta:ruleset` nodes that exist in the view.

### slib.pcap.sync

Sync the feeds into the current view and push every enabled rule to the service. This is what
the cron job runs.

```text
slib.pcap.sync [--feed <name> ...] [--force] [--no-feeds] [--no-push]
```

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--feed` | str, `append` | `[]` | Only sync these feeds, even if disabled. Unknown names are warned about. |
| `--force` | flag | | Download every synced feed now (no conditional request), sync all of its rules (a full sync), and rebuild the service's rules even if they're unchanged. |
| `--no-feeds` | flag | | Don't sync feeds, only push. |
| `--no-push` | flag | | Don't push the rules. |

The command raises `AuthDeny` unless the caller may add both `it:app:snort:rule` and
`it:app:suricata:rule` nodes to the current layer. The rest runs as root in the current view
(`slib.pcap.priv.sync`). Per feed it prints one of: `synced <n> rules (<a> added, <u> updated,
<r> removed)` (full sync), `synced the feed's changes (...)`, `downloaded, the feed is
unchanged`, `up to date (the feed isn't due to be downloaded yet)`, or a warning with the error.
Then the build summary of the push. Pushing is refused outside the rules view, use `--no-push`
there. See [Rules and feeds](rules.md#syncing) for the full algorithm.

```text
slib.pcap.sync
slib.pcap.sync --force
slib.pcap.sync --feed et-open --no-push
```

## Admin

Every admin command warns when the service has no `axon:url`.

### slib.pcap.admin.feed

```text
slib.pcap.admin.feed add <name> <url> [--engine snort3|snort2|suricata] [--exclude <pattern> ...] [--desc <text>] [--disabled]
slib.pcap.admin.feed del|enable|disable <name>
```

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `action` | `add`, `del`, `enable`, `disable` | | What to do. |
| `name` | str | | The feed's name, lowercased. Must match `^[a-z0-9][a-z0-9_.-]*$`. |
| `url` | str, `nargs: ?` | `null` | The feed's `http(s)://` URL (`add`). `${name}` placeholders are filled from `pcap:feeds:secrets` at download time. |
| `--engine` | `snort3`, `snort2`, `suricata` | `snort3` | The syntax of the feed's rules (`add`). |
| `--exclude` | str, `append` | `[]` | A rules file name pattern (`fnmatch`, against the base name or the archive path) to skip (`add`). |
| `--desc` | str | `""` | The feed's description (`add`), set as the ruleset's `:desc`. |
| `--disabled` | flag | | Add the feed disabled (`add`). |

- `add` creates or replaces the feed. If the URL, engine, or excludes changed, its download state
  and every view's sync snapshot are dropped, so the next sync downloads it and does a full sync.
  The feed syncs on the next `slib.pcap.sync`.
- `del` removes the feed and its downloaded rules from the service. Its `meta:ruleset` and rule
  nodes stay in the Cortex.
- `enable` / `disable` set the feed's `enabled`. Disabled feeds aren't downloaded or synced by
  `slib.pcap.sync` (unless named with `--feed`). Their rule nodes are left as they are.

```text
slib.pcap.admin.feed enable abusech-sslbl
slib.pcap.admin.feed add talos 'https://www.snort.org/rules/snortrules-snapshot-31200.tar.gz?oinkcode=${talos:oinkcode}' --engine snort3
slib.pcap.admin.feed add my-feed https://example.com/my.rules --engine suricata
```

### slib.pcap.admin.schedule

```text
slib.pcap.admin.schedule [--period <period>] [--enable | --disable]
```

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--period` | str | `null` | A `cron.add --period` value, ex. `hourly@:17` or `daily@03:00`. |
| `--enable` | flag | | Enable the cron job. |
| `--disable` | flag | | Disable the cron job. |

`--period` creates a new cron job running `slib.pcap.sync` in the current view, with the caller
as its creator, saves it in `slib:pcap:cron`, makes the current view the rules view
(`slib:pcap:rules:view`), and deletes the old job. `--enable` and `--disable` can't be combined.
Always prints the job: `cron <iden> (<state>) runs slib.pcap.sync, in view <view>, last run:
<time>`.

### slib.pcap.admin.vars

```text
slib.pcap.admin.vars [--clear] [--set NAME=VALUE ...] [--del NAME ...]
```

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--set` | str, `append` | `[]` | A `NAME=VALUE` variable (quoted). Names are uppercased. |
| `--del` | str, `append` | `[]` | A variable to remove. |
| `--clear` | flag | | Remove every variable before any `--set`. |

The variables are validated by the service (`checkNetVars`): names match
`[A-Z][A-Z0-9_]{0,63}`, values are address groups (`any`, an IP or CIDR, a `$VARIABLE`, a
`[...]` list of those nested up to 8 deep, each optionally negated with `!`) of at most 4096
characters from `[0-9A-Za-z[].:/,!$_ -]`. Valid variables are saved in the `slib:pcap:vars`
global and sent with every run, over `suricata:vars` and `snort:vars`. A malformed `--set`
saves nothing. Prints the variables.

For Suricata they become `vars.address-groups` of the run's config. For Snort, a variable the
base `snort.lua` assigns (ex. `HOME_NET`) is replaced in a per-run copy of it, so the variables
the stock `snort_defaults.lua` derives from it (ex. `HTTP_SERVERS`) follow, and the rest (ex.
`DNS_SERVERS`) are set in its `default_variables.nets` table (with `--lua`), which a custom
`snort:conf` has to use too.

```text
slib.pcap.admin.vars --set "HOME_NET=[10.0.0.0/8,172.16.0.0/12]"
slib.pcap.admin.vars --set "DNS_SERVERS=[10.0.0.53]" --del HTTP_SERVERS
```

### slib.pcap.admin.decode

```text
slib.pcap.admin.decode [--clear] [--add <rule> ...] [--del <rule> ...]
```

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--add` | str, `append` | `[]` | A Decode As rule to add (lowercased). |
| `--del` | str, `append` | `[]` | A rule to remove. |
| `--clear` | flag | | Remove every rule before any `--add`. |

Rules are validated by the service (`checkDecodeAs`, see
[Decode As](#decode-as)) and saved in the `slib:pcap:decode` global. Every run uses them,
followed by the run's own `--decode-as` rules. Prints the rules.

```text
slib.pcap.admin.decode --add "tcp.port==8443,tls" --add "tcp.port==2222,ssh"
slib.pcap.admin.decode --del "tcp.port==2222,ssh"
```

## Storm library: slib.pcap.lib

For automations, `slib.pcap.lib` (requires `slib.pcap.user`) exposes the same analysis. See
[Telepath API](api.md#storm-modules) for every function.

```text
$pcap = $lib.import(slib.pcap.lib)
for $flow in $pcap.flows($sha256, opts=({"tag": "my.tag", "timeout": (60)})) { yield $flow }
```

`flows()` raises `slib.pcap.Error` (with `sha256`) instead of warning, and doesn't validate
`tag`/`host`/`sandbox` first, use `ingest()` for the command's behaviour.
