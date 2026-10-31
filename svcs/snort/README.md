# snort

A Synapse Advanced Power-Up (Storm Service) that matches PCAPs in the Axon against a Snort 3 rule
corpus, and models the matches as `it:app:snort:hit` nodes.

- **The Cortex is the source of truth for the rules.** The service runs every enabled
  `it:app:snort:rule` (with `:text`) in the Cortex, and nothing else.
- **Open source rule feeds are synced into the Cortex.** The service regularly downloads the
  [Snort 3 Community ruleset](https://www.snort.org/downloads#rules) and
  [Emerging Threats Open](https://rules.emergingthreats.net/open/) (Snort 2.9 syntax, converted
  with `snort2lua`) and models their rules as `it:app:snort:rule` nodes, so they can be queried,
  enabled, and disabled like any other node. Admins can add their own feeds.
- **Custom rules come from the Cortex too.** Add them with `slib.snort.rule.add`, or create
  `it:app:snort:rule` nodes any other way.

The service registers the `slib.snort` Storm package. Everything is namespaced under `slib.snort`.

## Deploying

The service is published as `ghcr.io/gormaniac/stormsvcs/snort`. The image includes Snort 3
(built from source) and `snort2lua`.

```bash
docker run -d --name slib-snort \
    -v /srv/slib-snort:/vertex/storage \
    -p 27492:27492 \
    ghcr.io/gormaniac/stormsvcs/snort:latest
```

Then add it to a Cortex as an admin (the admin that adds the service owns the scheduled sync, see
[Syncing](#syncing)):

```
service.add slib.snort tcp://<user>:<passwd>@<host>:27492/*
```

The first sync runs within the hour. To sync right away, run `slib.snort.sync` (the first sync
models every feed's rules, about 75,000 nodes, so it takes a few minutes).

### Configuration

| Option | Env var | Default | Description |
|---|---|---|---|
| `snort:axon` | `SYN_SNORTSVC_SNORT_AXON` | none | A Telepath URL for the Cortex's Axon. When set, the service reads PCAPs from the Axon itself, otherwise Storm streams them to the service. |
| `snort:vars` | `SYN_SNORTSVC_SNORT_VARS` | `{"HOME_NET": "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]", "EXTERNAL_NET": "any"}` | Snort variables set in the config. PCAPs come from anywhere, so the home network is every RFC 1918 network and the external network is anything. Only variables the base config assigns can be set. |
| `snort:conf` | `SYN_SNORTSVC_SNORT_CONF` | the installed `snort.lua` | The base Snort config. Relative includes are found in its directory. |
| `snort:args` | `SYN_SNORTSVC_SNORT_ARGS` | `[]` | Extra arguments for every Snort run. |
| `snort:workers` | `SYN_SNORTSVC_SNORT_WORKERS` | `2` | The max number of PCAPs scanned at once. |
| `snort:maxsize` | `SYN_SNORTSVC_SNORT_MAXSIZE` | `1073741824` | The max size, in bytes, of a PCAP. |
| `snort:timeout` | `SYN_SNORTSVC_SNORT_TIMEOUT` | `900` | Seconds before a Snort run (a rule build or a scan) is killed. |
| `snort:bin` | `SYN_SNORTSVC_SNORT_BIN` | `snort` | The Snort 3 binary. |
| `snort:snort2lua` | `SYN_SNORTSVC_SNORT_SNORT2LUA` | `snort2lua` | The snort2lua binary. |
| `snort:feeds` | `SYN_SNORTSVC_SNORT_FEEDS` | Snort 3 Community and ET Open | The feeds a new service starts with. Only read the first time the service starts, after that use `slib.snort.admin.feed`. |
| `snort:feeds:interval` | `SYN_SNORTSVC_SNORT_FEEDS_INTERVAL` | `24` | Hours between feed downloads. |
| `snort:feeds:timeout` | `SYN_SNORTSVC_SNORT_FEEDS_TIMEOUT` | `300` | Seconds before a feed download times out. |
| `snort:feeds:maxsize` | `SYN_SNORTSVC_SNORT_FEEDS_MAXSIZE` | `268435456` | The max size, in bytes, of a feed (and of the rules it unpacks to). |

The service honors the standard `HTTP(S)_PROXY` environment variables for feed downloads.

## How it works

```
 rule feeds ──download──> service ──parsed rules──> Storm ──> it:app:snort:rule nodes (+ meta:ruleset)
                                                                        │
            ┌──────────────── every enabled rule with :text ────────────┘
            v
         service: snort2lua (engine 2) -> snort -T (drop rules Snort rejects) -> rules file
            │
 PCAP (Axon) ──> snort -r <pcap> ──> alerts grouped by rule and flow ──> Storm ──> it:app:snort:hit, inet:flow
```

### Rules

An `it:app:snort:rule` is run by the service if it's `:enabled=true`, has `:text`, and its `:engine`
is one the service supports:

| `:engine` | Syntax |
|---|---|
| `3` (or unset) | Snort 3. |
| `2` | Snort 2.x, converted to Snort 3 with `snort2lua` by the service. The node keeps the original text. |

Snort refuses to start if any rule is invalid, so the service loads the rules in test mode, drops
every rule Snort reports an error for, and tries again until Snort loads cleanly. Rules that
couldn't be loaded (and why) are listed by `slib.snort.rule.errors`. Snort runs one rule per
gid:sid, if several enabled rules share one the highest `rev` wins (ties go to the lowest guid) and
the others are reported as duplicates.

`slib.snort.rule.enable`, `slib.snort.rule.disable`, and `slib.snort.rule.add` push their rules to
the service right away. Rules changed any other way (ex. editing `:enabled` or `:text` directly)
are picked up by the next sync. A push only rebuilds the service's rules file when the rules changed.

### Syncing

`slib.snort.sync` keeps the Cortex and the service in sync. It runs as a cron job created when
the service is added (hourly, at 17 past), as the admin that added the service, in their default
view. Change it with `slib.snort.admin.schedule`. Each run:

1. **Syncs every enabled feed** (unless `--no-feeds`). A feed is downloaded when it's due (every
   24 hours, with `If-None-Match`/`If-Modified-Since`), its rules are parsed by the service, and
   modeled in the Cortex:
   - Each rule is an `it:app:snort:rule` with a guid unique to the feed and the rule's gid:sid,
     in the feed's `meta:ruleset` (`-(has)>`). `:id` is the sid (or `gid:sid` if the gid isn't 1),
     `:name` the `msg`, `:version` the `rev`, `:engine` the feed's engine, and `:family`, `:created`,
     and `:updated` come from ET style metadata.
   - References become edges: `-(detects)> it:sec:cve`, `-(refs)> inet:url`, and
     `-(refs)> hash:md5`/`hash:sha256`.
   - A rule that joins the feed's ruleset gets the feed's enabled state (rules that are commented
     out in the feed are disabled). After that `:enabled` is up to the Cortex, a sync never re-enables
     a rule you disabled.
   - The feed's `:text` wins, a sync of a changed rule (or a `--force` sync) overwrites edits to a
     feed rule's text. To change a feed rule, add a custom copy with a higher `rev` (or a new sid)
     and disable the original.
   - Rules that leave the feed are disabled and removed from its ruleset.
   - Only the feed's changes since its last sync into the view are synced (the service keeps what
     it last synced into each view), so a daily update takes seconds. The first sync into a view,
     or one with `--force`, syncs every rule (new rules are added in bulk) and restores any edits
     to the feed's rules.
2. **Pushes every enabled rule** in the view to the service (unless `--no-push`), which replaces
   its rules with them and rebuilds its rules file if anything changed.

Syncing edits nodes as root (in the job's view), so `slib.snort.sync` holders don't need node
permissions.

### Scans

`slib.snort.scan` reads each PCAP (a `file:bytes` with a `:sha256`, in the Axon) and runs Snort on
it with checksum checks off (`-k none`, captures often have offloaded checksums). Snort's alerts
are grouped into one hit per rule and flow:

- `it:app:snort:hit` - `:rule`, `:flow`, `:src`/`:dst` (and their IPs and ports) of the packet
  that alerted, `:time` and `.seen` (the first and last alert), and `:version` (the rule's rev).
- `inet:flow` - from the client to the server (a response that alerts is the same flow),
  with `:src`, `:dst`, `:ip:proto`, `:time`, and `.seen`.
- The PCAP `-(refs)>` its hits and flows, and the `slib.snort` `meta:source` `-(seen)>` the hits.

Hit and flow guids are unique to the PCAP, so scanning a PCAP again updates the same nodes.
Truncated PCAPs are scanned up to where they're cut off, with a warning.

## Permissions

| Permission | Grants |
|---|---|
| `slib.snort.user` | Scanning PCAPs, checking rules, and viewing the status, rule errors, and feeds. |
| `slib.snort.rules` | Adding, enabling, and disabling rules (pushing them to the service). Users also need the node permissions for the rule nodes. |
| `slib.snort.sync` | Syncing the feeds into the Cortex (as root) and pushing the rules to the service. |
| `slib.snort.admin` | Managing the feeds and the sync schedule. |

Users don't need the `service.get` or Axon permissions, the `slib.snort.priv.*` modules talk to
the service (and the Axon) and elevate privileges only for users that hold the matching permission.
Users still need the normal node permissions for the hits, flows, and rules the commands create.

## Commands

| Command | Description |
|---|---|
| `slib.snort.scan` | Scan `file:bytes` PCAPs and model the hits (`--yield` the hits). |
| `slib.snort.sync` | Sync the feeds and push the rules (`--force`, `--feed`, `--no-feeds`, `--no-push`). |
| `slib.snort.status` | The Snort version, loaded rules, and sync schedule. |
| `slib.snort.rule.add` | Add (or update) custom rules (`--engine 2` for Snort 2.x, `--disabled`). |
| `slib.snort.rule.enable` | Enable rules and push them. |
| `slib.snort.rule.disable` | Disable rules and remove them from the service. |
| `slib.snort.rule.check` | Check if Snort can load rules (nodes or `--text`), without changing the service. |
| `slib.snort.rule.errors` | The rules the service couldn't load, and why (`--yield` them). |
| `slib.snort.feed.list` | The feeds and the state of their last download and sync. |
| `slib.snort.admin.feed` | Add, remove, enable, or disable a feed. |
| `slib.snort.admin.schedule` | Show or change the sync cron job. |

Run any command with `--help` for its options and examples.

## Examples

```
// Scan PCAPs, and see the rules that matched.
file:bytes#my.pcaps | slib.snort.scan --yield | -> it:app:snort:rule

// Every PCAP with a hit for a CVE.
it:sec:cve=cve-2021-44228 <(detects)- it:app:snort:rule <- it:app:snort:hit <(refs)- file:bytes

// Add a custom rule.
slib.snort.rule.add 'alert http any any -> any any ( msg:"My rule"; http_uri; content:"/evil"; sid:1000001; rev:1; )'

// Turn off a noisy rule.
it:app:snort:rule:id=2013502 | slib.snort.rule.disable

// Turn on every ET Open rule for a malware family.
meta:ruleset:name=et-open -(has)> it:app:snort:rule +:family="cobalt strike" | slib.snort.rule.enable

// Add a feed.
slib.snort.admin.feed add my-feed https://example.com/my.rules.tar.gz --engine 3
```

## Testing

```bash
uv run pytest tests
```

The tests that run Snort skip without it (ex. on a dev machine or the CI host job). CI also runs
every test in the service's test image (`docker/test/Dockerfile`), which has Snort, via the
`docker_tests` input of `.github/workflows/_service.yml`. To run them locally:

```bash
docker build -f docker/prod/Dockerfile -t ghcr.io/gormaniac/stormsvcs/snort:latest .
docker build -f docker/test/Dockerfile -t stormsvcs-snort-test .
docker run --rm stormsvcs-snort-test
```

## TODO

- Run Suricata too, for Suricata syntax rules (Synapse models them as `it:app:suricata:rule`).
- Model Snort's builtin (decoder/inspector) alerts, they're ignored for now.
