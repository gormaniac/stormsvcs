# Commands

Every command of the `slib.hatching` package, grouped by the permission it requires. The
command definitions are in {src}`svcs/hatching/src/hatchingsvc/pkgproto/slib.hatching.yaml`, and
each command's Storm is in `pkgproto/storm/commands/<name>.storm`.

## Conventions

- **Sample arguments.** Wherever a command takes a sample, it can be a Triage sample ID (ex.
  `261031-a1b2c3d4e5`) or a hash of a submitted file (MD5, SHA1, SHA256, SHA512, or ssdeep). The
  service resolves a hash with a Triage search (`<hashtype>:<hash>`, the newest 20 results) and
  uses the newest *reported* sample, falling back to the newest sample when none is reported. A
  hash with no sample fails with `Hatching Triage has no sample for <hash>.`
- **Errors.** Failed service calls are reported as warnings, ex.
  `slib.hatching: Getting sample x failed: Hatching Triage: NOT_FOUND - ... (HTTP 404)`, and the
  command carries on with the next item. Only bad option combinations raise a `BadArg` error.
- **Runs once per query.** Options that name their own inputs (`--sample` on `enrich` and
  `download`, `--url` on `submit`, `--name` on `yara.add`) and the commands that take samples as
  positional arguments do their work once, in the command's `init` block, not once per inbound
  node. Inbound nodes pass through unchanged, unless `--yield` replaces them with the resulting
  nodes (yielded once, at the end of the query).
- **Inbound nodes.** A command that models or downloads inbound nodes (`enrich`, `download`,
  `submit`, `yara.add`) drops, with a warning, any node of a form it doesn't support. With
  `--yield` it yields the resulting nodes in their place (`divert`), otherwise the inbound node
  passes through.
- **Tags.** Modeling commands apply Triage's tags under the prefix set with
  [`slib.hatching.admin.tags`](#slibhatchingadmintags) (`rep.hatching` by default). See
  [Model](model.md).
- Command names below drop the `slib.hatching.` prefix in prose (ex. `enrich` is
  `slib.hatching.enrich`).

## User commands

All of these require `slib.hatching.user`.

### slib.hatching.enrich

Model the newest reported Triage analysis of files, hashes, and URLs.

```text
slib.hatching.enrich [--sample <sample>]... [--tasks] [--yield]
```

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--sample` | str, repeatable | `[]` | A sample ID (or hash) to model, once, instead of the inbound nodes. |
| `--tasks` | flag | `false` | Also model the behavioral tasks: processes, network flows, DNS and HTTP requests, and dropped files. |
| `--yield` | flag | `false` | Yield the sample nodes instead of the inbound nodes. |

Inputs: `file:bytes` (looked up by `:sha256`, else `:sha1`, `:md5`, or `:sha512`), `hash:md5`,
`hash:sha1`, `hash:sha256`, `hash:sha512`, and `inet:url`. A node is looked up with a Triage
search (`sha256:<hash>`, or `url:"<url>"` for an `inet:url`), up to 50 results. The newest
result with the status `reported` is modeled. For an `inet:url`, only a `url` kind sample whose
URL is exactly the node's value counts, since Triage's `url:` search also matches samples whose
malware configs contain the URL. A node without a hash, or with no reported sample, is warned
about and passes through (or yields nothing).

For each modeled sample it prints
`slib.hatching: Modeled sample <id> (score=<score> families=<families> tasks=<count>).` and warns
about any task report that couldn't be retrieved and any failure Triage reported in the analysis.
A sample that isn't reported yet fails with `Sample <id> isn't reported yet (its status is
<status>).`

Creates the sample's `file:bytes` (or `inet:url`), its tags, `it:av:scan:result` verdict and
signature results, `risk:tool:software` families, `it:mitre:attack:technique` edges, IOC,
credential, and config nodes, and archive members. With `--tasks`, also the behavioral task
nodes. See [Model](model.md).

```text
// Model the analyses of some files.
file:bytes#my.tag | slib.hatching.enrich

// Model a sample by ID, including its behavioral tasks, and yield its node.
slib.hatching.enrich --sample 261031-a1b2c3d4e5 --tasks --yield

// Model a URL's newest URL analysis.
inet:url="https://example.com/login" | slib.hatching.enrich --yield
```

### slib.hatching.search

Search Triage ([search syntax](https://tria.ge/docs/cloud-api/search/)). Prints the matching
samples, or models them.

```text
slib.hatching.search <query> [--limit <n>] [--model] [--tasks] [--yield]
```

| Argument | Type | Default | Description |
| --- | --- | --- | --- |
| `query` | str | required | The search query. |
| `--limit` | int | `20` | The most samples to return, at most 1000. `0` (or anything above 1000) means 1000. |
| `--model` | flag | `false` | Model each reported sample. |
| `--tasks` | flag | `false` | With `--model`/`--yield`, also model the behavioral tasks. |
| `--yield` | flag | `false` | Model each reported sample and yield its node. |

Without `--model`/`--yield`, prints `<n> samples matched <query>.` and a table of `id`, `status`,
`kind`, `target` (the URL, or the filename), and `submitted`. With them, each sample whose status
is `reported` is modeled like `enrich --sample`, and the rest are skipped with
`Skipping sample <id>, it's <status>.`

```text
slib.hatching.search "family:emotet" --limit 50

// Model the 10 newest Cobalt Strike samples.
slib.hatching.search "family:cobaltstrike" --limit 10 --yield
```

### slib.hatching.samples

List the newest samples submitted by you, your organization, or the public.

```text
slib.hatching.samples [--subset owned|org|public] [--limit <n>]
```

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--subset` | str, one of `owned`, `org`, `public` | `owned` | Whose samples to list. |
| `--limit` | int | `20` | The most samples to list, at most 1000. `0` means 1000. |

Prints the same table as `search`.

### slib.hatching.sample.info

Print a sample's metadata (status and tasks) as JSON, its summary, or a shareable magic link.

```text
slib.hatching.sample.info <sample> [<sample> ...] [--summary] [--link]
```

| Argument | Type | Default | Description |
| --- | --- | --- | --- |
| `sample` | str, one or more | required | The sample IDs (or hashes). |
| `--summary` | flag | `false` | Print the sample's summary (scores, tags, and tasks) instead (`GET /v0/samples/{id}/summary`). |
| `--link` | flag | `false` | Print a magic link instead, `<hatching:url>/<id>/magic/<token>`. Takes precedence over `--summary`. Magic links must be enabled for the organization (see [`admin.org --magic`](#slibhatchingadminorg)). |

```text
slib.hatching.sample.info 261031-a1b2c3d4e5 --summary
slib.hatching.sample.info 261031-a1b2c3d4e5 --link
```

### slib.hatching.sample.wait

Wait for samples to finish their analysis, then optionally model them.

```text
slib.hatching.sample.wait <sample> [<sample> ...] [--timeout <secs>] [--model] [--tasks] [--yield]
```

| Argument | Type | Default | Description |
| --- | --- | --- | --- |
| `sample` | str, one or more | required | The sample IDs (hashes are resolved too). |
| `--timeout` | int | `600` | The most seconds to wait for each sample. |
| `--model` | flag | `false` | Model each sample once it's `reported`. |
| `--tasks` | flag | `false` | With `--model`/`--yield`, also model the behavioral tasks. |
| `--yield` | flag | `false` | Model each reported sample and yield its node. |

The samples are waited on one after another. For each it prints
`Sample <id> is <status>.` A sample is done when its status is `reported` or `failed`; a sample
that's still running after `--timeout` is printed with its current status and not modeled.

```text
slib.hatching.sample.wait 261031-a1b2c3d4e5 --timeout 900 --yield
```

### slib.hatching.events

Print the status changes of a running sample, or of all your running samples.

```text
slib.hatching.events [--sample <sample>] [--limit <n>] [--timeout <secs>]
```

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--sample` | str | `null` | The sample to follow (`GET /v0/samples/{id}/events`). All of your running samples by default (`GET /v0/samples/events`). |
| `--limit` | int | `100` | The most events to print, `0` for no limit. |
| `--timeout` | int | `600` | The most seconds to wait for events. |

Prints `slib.hatching.events: <id> <status>` per event. It stops at `--limit` events, after
`--timeout` seconds, when Triage closes the stream, or at the first error.

```text
slib.hatching.events --sample 261031-a1b2c3d4e5
slib.hatching.events --limit 50 --timeout 300
```

### slib.hatching.report

Print a report as JSON.

```text
slib.hatching.report <sample> [--static] [--task <task>] [--urlscan]
```

| Argument | Type | Default | Description |
| --- | --- | --- | --- |
| `sample` | str | required | The sample ID (or hash). |
| `--static` | flag | `false` | Print the static report (`GET /v0/samples/{id}/reports/static`). |
| `--task` | str | `null` | Print this task's report, ex. `behavioral1` (`GET /v0/samples/{id}/{task}/report_triage.json`). |
| `--urlscan` | flag | `false` | Print a URL sample's UrlScan report, of `--task` or `urlscan1` (`GET /v0/samples/{id}/{task}/report_urlscan.json`). |

With none of them, it prints the overview report (`GET /v1/samples/{id}/overview.json`). The
precedence is `--urlscan`, then `--task`, then `--static`.

```text
slib.hatching.report 261031-a1b2c3d4e5
slib.hatching.report 261031-a1b2c3d4e5 --task behavioral1
slib.hatching.report 261031-a1b2c3d4e5 --urlscan
```

### slib.hatching.kernel

Print a task's kernel monitor events, one JSON object per line.

```text
slib.hatching.kernel <sample> <task> [--log <name>] [--limit <n>]
```

| Argument | Type | Default | Description |
| --- | --- | --- | --- |
| `sample` | str | required | The sample ID (or hash). |
| `task` | str | required | The task name, ex. `behavioral1`. |
| `--log` | str | `null` | The log name: `onemon` (Windows), `stahp` (Linux), `bigmac` (macOS), or `droidy` (Android). By default it's picked from the task's OS/platform in the overview report. |
| `--limit` | int | `1000` | The most events to print, `0` for all of them. |

Reads `GET /v0/samples/{id}/{task}/logs/{log}.json` as a stream. Stops at the first error, ex. a
log that doesn't exist for the task.

```text
slib.hatching.kernel 261031-a1b2c3d4e5 behavioral1 --limit 100
```

### slib.hatching.download

Download a sample's file, task files, network captures, dropped files, or archive into the Axon.
Each downloaded file is modeled as a `file:bytes`.

```text
slib.hatching.download [--sample <sample>]... [--task <task>] [--file <name>] [--pcap] [--pcapng]
                       [--dumped] [--screenshot] [--archive tar|zip] [--yield]
```

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--sample` | str, repeatable | `[]` | A sample ID (or hash) to download from, once, instead of the inbound nodes. |
| `--task` | str | `null` | The task to download `--file` (or `--pcap`/`--pcapng`, or `--screenshot`) from. |
| `--file` | str | `null` | A file to download from `--task`, ex. `dump.pcap`, `screenshot.png`, or a dumped file's name (`files/0x...dat`). Requires `--task`. |
| `--pcap` | flag | `false` | Download `dump.pcap` of each reported behavioral task, or of `--task`. |
| `--pcapng` | flag | `false` | Download `dump.pcapng` of each reported behavioral task, or of `--task`. |
| `--dumped` | flag | `false` | Download every file dropped during each reported behavioral task. |
| `--screenshot` | flag | `false` | Download `screenshot.png` of a URL sample's task, `--task` or `urlscan1`. |
| `--archive` | str, one of `tar`, `zip` | `null` | Download an archive of the sample's reports and files (`GET /v0/samples/{id}/archive` or `/archive.zip`). |
| `--yield` | flag | `false` | Yield the downloaded `file:bytes` nodes instead of the inbound nodes. |

Inputs: `file:bytes`, `hash:md5`, `hash:sha1`, `hash:sha256`, and `hash:sha512`. Each node's hash
is resolved to a sample (see [Conventions](#conventions)). `--file` without `--task` raises
`BadArg`.

With none of the file options, it downloads the sample's own file
(`GET /v0/samples/{id}/sample`), which fails with a warning for a URL sample. The options can be
combined; each one adds its files. For `--pcap`/`--pcapng`, "each behavioral task" means the
tasks in the sample's metadata whose ID (minus the `<sample>-` prefix) starts with `behavioral`
and whose status is `reported`. For `--dumped`, it's the overview report's tasks of kind
`behavioral` (or named `behavioral*`) with the status `reported`; the dumped files are read from
each task's report (its `dumped` entries with a SHA256 and a name, except memory `region`s), and a
task report that can't be read is skipped with a warning.

Each file is streamed from the service into the Axon (`$lib.axon.upload()`), and the download
stops with an error once it passes `hatching:maxsize` bytes. For each saved file it prints
`Saved <what> (<size> bytes, <sha256>) to the Axon.` and creates a `file:bytes` with `:sha256`
and `:size`, its `:name` when the node has none (the sample's filename, the task file's base
name, the dropped file's original base name, or `<sample>.<fmt>` for an archive), and a
`-(seen)>` edge from the `meta:source`. A dropped file whose downloaded SHA256 differs from the
one in the task report is saved anyway, with a warning.

```text
// Download the samples of some hashes.
hash:sha256#my.tag | slib.hatching.download --yield

// Download the pcaps of every behavioral task.
slib.hatching.download --sample 261031-a1b2c3d4e5 --pcap

// Download the files dropped during the analysis.
slib.hatching.download --sample 261031-a1b2c3d4e5 --dumped --yield

// Download a single task file.
slib.hatching.download --sample 261031-a1b2c3d4e5 --task behavioral1 --file files/0x0003000000022c2b-1.dat
```

### slib.hatching.profile.list

List the account's analysis profiles (every page of `GET /v0/profiles`): `name`, `network`,
`geolocation`, `timeout`, `tags`, and `id`. No arguments.

### slib.hatching.resources

List the analysis environments (VMs) and the tags profiles use to pick them
(`GET /v0/resources`): `name` and `tags`. No arguments.

### slib.hatching.geolocations

List the regions analyses on the `vpn` network can exit from (`GET /v0/geolocations`): `name`
and `tags`. Use a name with `--geolocation`. No arguments.

### slib.hatching.stats

Print your usage stats as JSON (`GET /v0/stats/user`). No arguments.

### slib.hatching.yara.list

List the account's Yara rules (`GET /v0/yara`): `name` and the number of compiler `warnings`.
No arguments.

### slib.hatching.yara.get

Print Yara rules, or model them.

```text
slib.hatching.yara.get <name> [<name> ...] [--yield]
```

| Argument | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | str, one or more | required | The rule names (`GET /v0/yara/{name}`). |
| `--yield` | flag | `false` | Model each rule as an `it:app:yara:rule` and yield it, instead of printing its text. |

Each of a rule's compiler warnings is printed as a warning. With `--yield`, the node is
`it:app:yara:rule=({"name": <name>, "text": <rule>})` with `:name` and `:text` set, so the same
name and text always make the same node.

```text
slib.hatching.yara.get my_rule.yara --yield
```

### slib.hatching.apikey

Set, check, or delete your own Triage API key.

```text
slib.hatching.apikey [<apikey>] [--clear]
```

| Argument | Type | Default | Description |
| --- | --- | --- | --- |
| `apikey` | str, optional | `null` | Your Triage API key. |
| `--clear` | flag | `false` | Delete your key's vault. |

The key is stored in your user scoped vault of type `hatching` (secret `apikey`). If you don't
have one yet, it's created as `hatching:<username>`; otherwise its `apikey` secret is replaced.
With no argument it reports whether your key is set (and in which vault), or which key is used
instead. Your key takes precedence over the service-wide key. See
[API keys](deployment.md#api-keys), including the warning about query logs.

```text
slib.hatching.apikey ABCDEFG
slib.hatching.apikey
slib.hatching.apikey --clear
```

## Submit commands

All of these require `slib.hatching.submit`.

### slib.hatching.submit

Submit files (from the Axon) and URLs to Triage for analysis.

```text
slib.hatching.submit [--url <url>]... [--fetch] [--name <filename>] [--profile <profile>]...
                     [--password <password>] [--tag <tag>]... [--timeout <secs>]
                     [--network <network>] [--geolocation <region>] [--interactive]
                     [--wait <secs>] [--tasks] [--yield]
```

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--url` | str, repeatable | `[]` | A URL to submit, once, instead of the inbound nodes. |
| `--fetch` | flag | `false` | Have the sandbox download the file at each URL and analyze it (kind `fetch`), instead of browsing the URL (kind `url`). |
| `--name` | str | `null` | The filename to submit files as. By default the `file:bytes` `:name`, or its SHA256. |
| `--profile` | str, repeatable | `[]` | A profile to run, or `profile:file` to run a file in an archive with it. |
| `--password` | str | `null` | The password of an encrypted archive. |
| `--tag` | str, repeatable | `[]` | A tag to give the sample in Triage (`user_tags`). |
| `--timeout` | int | `null` | The analysis timeout in seconds, 1 to 3600, when the sandbox picks the profiles (`defaults.timeout`). |
| `--network` | str, one of `internet`, `drop`, `tor`, `sim200`, `sim404`, `simnx`, `vpn` | `null` | The analysis network when the sandbox picks the profiles (`defaults.network`). |
| `--geolocation` | str | `null` | With `--network vpn`, the region to exit from (see [`geolocations`](#slibhatchinggeolocations)). |
| `--interactive` | flag | `false` | Stop after static analysis, so profiles can be picked with [`sample.profile`](#slibhatchingsampleprofile). Can't be combined with `--profile`. |
| `--wait` | int | `0` | Wait up to this many seconds for each analysis, then model it. `0` doesn't wait. |
| `--tasks` | flag | `false` | With `--wait`, also model the behavioral tasks. |
| `--yield` | flag | `false` | With `--wait`, yield the modeled sample nodes instead of the inbound nodes. |

Inputs: `file:bytes` (submitted from the Axon by its `:sha256`) and `inet:url` (submitted as a URL
analysis, or a fetch with `--fetch`).

Validation, before anything is sent: `--timeout` must be between 1 and 3600, `--geolocation`
requires `--network vpn` (`A geolocation requires the vpn network.`), and `--profile` with
`--interactive` fails with `Profiles can't be picked for an interactive submission, pick them
with slib.hatching.sample.profile once its static analysis is done.` A `file:bytes` without
`:sha256`, or one the Axon doesn't have, fails with a warning.

A file is sent to the service 1 MiB at a time and spooled to disk there (see
[Internals](internals.md#submissions)); a file over `hatching:maxsize` fails with `The file is
larger than the max of <n> bytes.`, and an empty file with `The file is empty.`

For each submission it prints `Submitted <what> as sample <id> (<status>).` With `--wait`, it
then waits like `sample.wait` and models the sample like `enrich --sample`. An interactive
sample isn't waited on (it can't finish until its profiles are picked), and a sample that isn't
reported after `--wait` seconds is warned about with the command to model it later. `--yield`
only yields a node for samples that were modeled.

```text
// Submit files and model the results once they're reported.
file:bytes#my.tag | slib.hatching.submit --wait 600 --tasks --yield

// Analyze a URL in a browser.
slib.hatching.submit --url https://example.com/login

// Have the sandbox download and analyze a file.
slib.hatching.submit --url https://example.com/payload.exe --fetch

// Pick the profile and network, and tag the sample in Triage.
file:bytes=sha256:... | slib.hatching.submit --profile win10-internet --network drop --tag case.1234

// Run a file in an encrypted archive with a profile.
file:bytes=sha256:... | slib.hatching.submit --password infected --profile win10-internet:payload.exe
```

### slib.hatching.sample.profile

Pick the profiles of a sample submitted with `--interactive`, starting its analysis
(`POST /v0/samples/{id}/profile`).

```text
slib.hatching.sample.profile <sample> [--profile <profile>]... [--auto] [--pick <file>]...
```

| Argument | Type | Default | Description |
| --- | --- | --- | --- |
| `sample` | str | required | The sample ID. |
| `--profile` | str, repeatable | `[]` | A profile to run, or `profile:file` to run a file in an archive with it. |
| `--auto` | flag | `false` | Let the sandbox pick the profiles. |
| `--pick` | str, repeatable | `[]` | A file in an archive to analyze, with profiles the sandbox picks. |

At least one of `--profile`, `--pick`, or `--auto` is required, otherwise it warns
`Use --profile or --pick at least once, or --auto.` `--pick` without `--profile` turns on
`--auto`. The request body is `{"auto": true, "pick": [...]}` when `--auto` is on (any
`--profile` is not sent), and `{"auto": false, "profiles": [{"profile": ..., "pick": ...}]}`
otherwise (any `--pick` is not sent).

```text
slib.hatching.sample.profile 261031-a1b2c3d4e5 --profile win10-internet
slib.hatching.sample.profile 261031-a1b2c3d4e5 --profile win10-internet:payload.exe
slib.hatching.sample.profile 261031-a1b2c3d4e5 --auto --pick payload.exe
```

### slib.hatching.sample.import

Import public tria.ge samples into your private cloud instance (cloud instances only).

```text
slib.hatching.sample.import <sample> [<sample> ...]
```

| Argument | Type | Description |
| --- | --- | --- |
| `sample` | str, one or more | The public sample IDs or tria.ge URLs. |

Submits each as a `POST /v0/samples` of kind `import` with the value as its `url`, and prints
`Imported <sample> as <id> (<status>).`

```text
slib.hatching.sample.import 261031-a1b2c3d4e5
slib.hatching.sample.import https://tria.ge/261031-a1b2c3d4e5
```

### slib.hatching.sample.delete

Delete samples you submitted (`DELETE /v0/samples/{id}`).

```text
slib.hatching.sample.delete <sample> [<sample> ...]
```

Nothing in the Cortex is changed.

## Manage commands

All of these require `slib.hatching.manage`.

### slib.hatching.profile.add

Add an analysis profile (`POST /v0/profiles`).

```text
slib.hatching.profile.add <name> [--tag <tag>]... [--timeout <secs>] [--network <network>] [--geolocation <region>]
```

| Argument | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | str | required | The profile's name. |
| `--tag` | str, repeatable | `[]` | A resource tag that picks the analysis environment, ex. `os:windows10-2004-x64` (see [`resources`](#slibhatchingresources)). |
| `--timeout` | int | `null` | The analysis timeout in seconds, 1 to 3600. |
| `--network` | str, one of `internet`, `drop`, `tor`, `sim200`, `sim404`, `simnx`, `vpn` | `null` | The analysis network. |
| `--geolocation` | str | `null` | With `--network vpn`, the region to exit from. |

Prints `Added profile <name> (<id>).`

```text
slib.hatching.profile.add win10-drop --tag os:windows10-2004-x64 --network drop --timeout 300
slib.hatching.profile.add win10-us --tag os:windows10-2004-x64 --network vpn --geolocation us
```

### slib.hatching.profile.edit

Edit an analysis profile (`PUT /v0/profiles/{id}`). Unused options keep their current value.

```text
slib.hatching.profile.edit <profile> [--name <name>] [--tag <tag>]... [--timeout <secs>] [--network <network>] [--geolocation <region>]
```

| Argument | Type | Default | Description |
| --- | --- | --- | --- |
| `profile` | str | required | The profile's name or ID. |
| `--name` | str | `null` | A new name for the profile. |
| `--tag` | str, repeatable | `[]` | Replace the profile's tags (all of them). |
| `--timeout` | int | `null` | The analysis timeout in seconds, 1 to 3600. |
| `--network` | str, same choices as `profile.add` | `null` | The analysis network. |
| `--geolocation` | str | `null` | With the `vpn` network, the region to exit from. |

The API overwrites the whole profile, so the service reads the current profile and sends its
values for the options that weren't given. The current geolocation is kept only while the
network stays `vpn`; changing the network away from `vpn` drops it. Prints
`Updated profile <name>: network=<network> (<geolocation>) timeout=<timeout> tags=<tags>`.

```text
slib.hatching.profile.edit win10-drop --timeout 600
```

### slib.hatching.profile.del

Delete analysis profiles by name or ID (`DELETE /v0/profiles/{id}`).

```text
slib.hatching.profile.del <profile> [<profile> ...]
```

### slib.hatching.yara.add

Add (or replace, or rename) Yara rules, from `it:app:yara:rule` nodes or `--name`/`--text`.

```text
slib.hatching.yara.add [--name <name>] [--text <text>] [--update] [--rename <oldname>]
```

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--name` | str | `null` | The rule's name, to save it once instead of using the inbound nodes (which then pass through untouched). |
| `--text` | str | `null` | The rule's text, with `--name`. |
| `--update` | flag | `false` | Replace existing rules (`PUT /v0/yara/{name}`) instead of adding new ones (`POST /v0/yara`). |
| `--rename` | str | `null` | Rename this existing rule to `--name`, replacing its text with `--text` when given. Requires `--name`. |

Inputs: `it:app:yara:rule`. A node's rule is named `<:name>.yara` (a `:name` that already ends
in `.yara` is used as is) with its `:text`. A rule without a name, or without text (except
with `--rename`), is skipped with the warning `A rule needs a name and text.` `--rename` without `--name` raises `BadArg`. A rename sends
`PUT /v0/yara/<oldname>` with `{"name": <name>, "rule": <text>}`, reading the current text first
when `--text` isn't given.

```text
it:app:yara:rule#hunt | slib.hatching.yara.add
slib.hatching.yara.add --name my_rule.yara --text "rule my_rule { condition: true }" --update
slib.hatching.yara.add --name new_name.yara --rename old_name.yara
```

### slib.hatching.yara.del

Delete Yara rules by name (`DELETE /v0/yara/{name}`).

```text
slib.hatching.yara.del <name> [<name> ...]
```

## Admin commands

All of these require `slib.hatching.admin`. The organization commands (`admin.org`,
`admin.users`, `admin.user.*`) also need a Triage key with the `manage_company` permission.

### slib.hatching.admin.apikey

Set, clear, or check the service-wide Triage API key.

```text
slib.hatching.admin.apikey [<apikey>] [--clear]
```

| Argument | Type | Default | Description |
| --- | --- | --- | --- |
| `apikey` | str, optional | `null` | The API key to store in the service. |
| `--clear` | flag | `false` | Clear the stored key. |

With no argument it prints whether a service-wide key is set (the stored key or the
`hatching:apikey` option). The key is used by any user without their own key. Clearing the
stored key falls back to `hatching:apikey`, if it's set. See [API keys](deployment.md#api-keys).

### slib.hatching.admin.tags

Show or change how Triage's tags and families are applied as tags.

```text
slib.hatching.admin.tags [--prefix <tag>] [--enable] [--disable]
```

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--prefix` | str | `null` | The tag prefix, a valid tag name. Stored in the global `slib:hatching:tag:prefix` (default `rep.hatching`). |
| `--enable` | flag | `false` | Apply tags (global `slib:hatching:tag:enabled`, default `true`). |
| `--disable` | flag | `false` | Don't apply tags. |

The prefix must normalize as a `syn:tag` to its own lowercased, stripped value, so `""`,
`"rep triage"`, or `"#rep"` raise `BadArg` (`<prefix> isn't a valid tag name.`), and
`Rep.Hatching2` is stored as `rep.hatching2`. `--enable` with `--disable` raises `BadArg`. It
always prints the result, ex. `slib.hatching tags: enabled=true prefix=rep.hatching`.

Changing the prefix doesn't touch existing tags.

```text
slib.hatching.admin.tags
slib.hatching.admin.tags --prefix rep.triage
slib.hatching.admin.tags --disable
```

### slib.hatching.admin.request

Send a raw request to the Triage API and print the JSON response.

```text
slib.hatching.admin.request <path> [--method <method>] [--params <dict>] [--json <body>]
```

| Argument | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | str | required | The API path including the version, ex. `/v0/samples`. A missing leading `/` is added. It's appended to `<hatching:url><hatching:api_path>`. |
| `--method` | str | `get` | The HTTP method. |
| `--params` | any | `null` | A dict of URL params. |
| `--json` | any | `null` | The JSON body. |

An HTTP status of 400 or more fails with `Hatching Triage: <error> - <message> (HTTP <status>)`.

```text
slib.hatching.admin.request /v0/samples --params ({"subset": "org", "limit": 5})
```

### slib.hatching.admin.org

Print the organization's settings (`GET /v0/org/settings`) or usage stats (`--stats`,
`GET /v0/stats/org`), or turn magic links on or off (`--magic`, `PUT /v0/org/settings/magic`).

```text
slib.hatching.admin.org [--stats] [--magic on|off]
```

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--stats` | flag | `false` | Print the organization's usage stats. |
| `--magic` | str, one of `on`, `off` | `null` | Allow, or stop, creating magic links (see `sample.info --link`). Takes precedence over `--stats`. |

```text
slib.hatching.admin.org --magic on
```

### slib.hatching.admin.users

List the organization's users (every page of `GET /v0/users`): `email`, `name`, `role`,
`confirmed` (whether `email_confirmed_at` is set), `created`, and `id`.

```text
slib.hatching.admin.users [--limit <n>]
```

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--limit` | int | `null` | The most users to list. `null` or `0` lists all of them. |

### slib.hatching.admin.user.add

Add a user to the organization (`POST /v0/users`).

```text
slib.hatching.admin.user.add <login> [--password <password>] [--name <name>] [--role <role>] [--confirmed]
```

| Argument | Type | Default | Description |
| --- | --- | --- | --- |
| `login` | str | required | An email address, or a username (no `@`), which signs in as `<username>@triage.local`. |
| `--password` | str | `null` | The new user's password. |
| `--name` | str | `null` | The display name. |
| `--role` | str, one of `org_readonly`, `org_submit`, `org_read_own_samples`, `org_manage_own_samples`, `org_basic`, `org_advanced`, `org_admin` | `null` | The user's role, see the [users docs](https://tria.ge/docs/cloud-api/users/). `org_readonly` and `org_read_own_samples` can't use API keys. |
| `--confirmed` | flag | `false` | Confirm the email address (`email_confirmed`) so the user can sign in right away. Only sent for an email login. |

A login with `@` is sent as `email`, otherwise as `username`. Prints
`Added user <email> (<id>) with the role <role>.`

```text
slib.hatching.admin.user.add analyst --password correcthorsebatterystaple --role org_basic
slib.hatching.admin.user.add analyst@example.com --name "An Analyst" --role org_submit --confirmed
```

### slib.hatching.admin.user.del

Delete users by ID (`DELETE /v0/users/{id}`).

```text
slib.hatching.admin.user.del <user> [<user> ...]
```

### slib.hatching.admin.user.keys

List a user's API keys (`GET /v0/users/{id}/apikeys`): `name` and the key's first 4 characters.

```text
slib.hatching.admin.user.keys <user>
```

### slib.hatching.admin.user.key.add

Create an API key for a user (`POST /v0/users/{id}/apikeys`) and print it.

```text
slib.hatching.admin.user.key.add <user> <name> [--show]
```

| Argument | Type | Default | Description |
| --- | --- | --- | --- |
| `user` | str | required | The user ID. |
| `name` | str | required | The new key's name. |
| `--show` | flag | `false` | Print the whole key instead of its first 4 characters. |

:::{warning}
With `--show`, the key is in the command's output, which may be logged or kept in history.
Triage doesn't return it again later.
:::

### slib.hatching.admin.user.key.del

Delete a user's API keys by name (`DELETE /v0/users/{id}/apikeys/{name}`).

```text
slib.hatching.admin.user.key.del <user> <name> [<name> ...]
```
