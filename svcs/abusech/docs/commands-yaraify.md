# YARAify commands

The commands for [YARAify](https://yaraify.abuse.ch) (base URLs `yaraify` and
`yaraify:export`). Nodes they create are linked to the YARAify `meta:source` and tagged
`<prefix>.yaraify.*`. YARAify files are modeled like other samples, plus their YARA matches,
ClamAV results and unpacked files, see [the data model](model.md#yara-rules-and-matches).

## `slib.abusech.yaraify.lookup`

Look up files (`lookup_hash`) or scan tasks (`get_results`) and model the results: the file's
metadata, YARA matches (`it:app:yara:match`), ClamAV results, and the files YARAify's unpacker
extracted (`file:subfile`) with their YARA matches. Every task's results are merged into the
file.

```text
slib.abusech.yaraify.lookup [--hash <hash> ...] [--task <task id> ...] [--malpedia <token>] [--yield]
```

| Option | Type | Default | Meaning |
|---|---|---|---|
| `--hash` | str, repeatable | `[]` | An MD5, SHA1, SHA256, or SHA3-384 to look up instead of the inbound nodes. |
| `--task` | str, repeatable | `[]` | A scan task ID to get the results of. |
| `--malpedia` | str | `null` | A Malpedia token (sent as `malpedia-token`), to include TLP:AMBER/RED Malpedia YARA matches. |
| `--yield` | flag | `false` | Yield the `file:bytes` nodes instead of the inbound nodes. |

- Permission: `slib.abusech.user`
- Inputs: `file:bytes` (by `:sha256`, else `:sha1`, else `:md5`), `hash:md5`, `hash:sha1`,
  `hash:sha256`
- A task that isn't finished prints `slib.abusech.yaraify.lookup: Task <id> is <status>.`
  (ex. `queued`); an unknown task ID prints `unknown`.
- Matches of non-public rules (YARAify masks their name as `xxx`) aren't modeled.

```text
file:bytes#my.tag | slib.abusech.yaraify.lookup

slib.abusech.yaraify.lookup --task cfa49f83-6d98-11ed-a71a-42010aa4000b --yield
```

## `slib.abusech.yaraify.search`

Search YARAify for files and model them. Always yields the `file:bytes` nodes, and drops the
inbound nodes.

```text
slib.abusech.yaraify.search <by> <value> [--limit <n>]
```

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `by` | str, required | | What to search by, see below. |
| `value` | str, required | | The value to search for (`search_term`). |
| `--limit` | int | `25` | The max number of files (`result_max`, kept in 1-1000, `0` sends 1000). |

| `by` | Query |
|---|---|
| `yara` | `get_yara` (files matching a YARA rule) |
| `clamav` | `get_clamav` (files matching a ClamAV signature) |
| `imphash` | `get_imphash` |
| `gimphash` | `get_gimphash` |
| `dhash` | `get_dhash_icon` |
| `tlsh` | `get_tlsh` |
| `telfhash` | `get_telfhash` |

Files from a `yara` search get a match of that rule, and files from a `clamav` search get
that signature, even when the result doesn't list it.

- Permission: `slib.abusech.user`
- Prints `slib.abusech.yaraify.search: Found <n> files.`

```text
slib.abusech.yaraify.search yara CobaltStrikeBeacon --limit 50
```

## `slib.abusech.yaraify.scan`

Scan files with YARAify. An inbound `file:bytes` that's in the Axon (it has `:sha256` and
`:size`) is uploaded; other files, `hash:*` nodes, and `--rescan` are rescanned by hash
(`rescan_file`). Prints each task ID; `--wait` waits for the results and models them.

```text
slib.abusech.yaraify.scan [--hash <hash> ...] [--rescan] [--identifier <id>] [--unpack]
    [--share] [--noclamav] [--skipknown] [--skipnoisy] [--wait <secs>] [--yield]
```

| Option | Type | Default | Meaning |
|---|---|---|---|
| `--hash` | str, repeatable | `[]` | A hash of a known file to rescan instead of the inbound nodes. |
| `--rescan` | flag | `false` | Rescan inbound files by hash, even if they're in the Axon. |
| `--identifier` | str | `null` | Your YARAify identifier, to track the scans with (see `slib.abusech.yaraify.tasks`). Upload only. |
| `--unpack` | flag | `false` | Unpack the file and scan the unpacked files (`unpack=1`). Upload only. |
| `--share` | flag | `false` | Share the file with the community (`share_file=1`). YARAify shares by default; this command doesn't unless asked. Upload only. |
| `--noclamav` | flag | `false` | Don't scan with ClamAV (`clamav_scan=0`). Upload only. |
| `--skipknown` | flag | `false` | Don't scan files YARAify already knows (`skip_known=1`). Upload only. |
| `--skipnoisy` | flag | `false` | Skip the scan when the file was scanned at least 10 times in the past 24 hours, returning the latest task (`skip_noisy=1`). Upload only. |
| `--wait` | int | `0` | Seconds to wait for each scan to finish before modeling it, `0` to not wait. |
| `--yield` | flag | `false` | Yield the scanned `file:bytes` nodes (only with `--wait`) instead of the inbound nodes. |

- Permission: `slib.abusech.submit`
- Inputs: `file:bytes`, `hash:md5`, `hash:sha1`, `hash:sha256`
- Uploads are multipart (`file` and a `json_data` part with the options), capped at
  `abusech:maxsize`, and never retried after a 5xx or timeout. Rescans are never retried
  after a 5xx or timeout either.
- `--wait` polls `get_results` every 5 seconds until the task is done or the time is up, then
  prints `Task <id> is still <status>, check it later with slib.abusech.yaraify.lookup --task <id>`.

```text
file:bytes=<sha256> | slib.abusech.yaraify.scan --unpack --wait 120 --yield | -> it:app:yara:match -> it:app:yara:rule

slib.abusech.yaraify.scan --hash <sha256>
```

## `slib.abusech.yaraify.tasks`

List the scan tasks for an identifier (`list_tasks`), or generate a new identifier
(`generate_identifier`). Prints a table; models nothing.

```text
slib.abusech.yaraify.tasks [<identifier>] [--status queued|processed|all]
slib.abusech.yaraify.tasks --new
```

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `identifier` | str, optional | `null` | Your YARAify identifier. Required unless `--new` (`BadArg`). |
| `--status` | str, one of `queued`, `processed`, `all` | `processed` | The tasks to list (`task_status`; `all` omits it). |
| `--new` | flag | `false` | Generate a new (private) identifier and print it. |

The table columns are `task_id`, `time`, `sha256`, `file_name`.

- Permission: `slib.abusech.user`

```text
slib.abusech.yaraify.tasks --new

slib.abusech.yaraify.tasks <identifier> --status queued
```

## `slib.abusech.yaraify.rules`

Model YARAhub rules as `it:app:yara:rule` nodes, with their text, author and metadata. Runs
once and drops the inbound nodes.

```text
slib.abusech.yaraify.rules [--uuid <uuid> ...] [--recent] [--deployed] [--all [--limit <n>]] [--yield]
```

| Option | Type | Default | Meaning |
|---|---|---|---|
| `--uuid` | str, repeatable | `[]` | A YARAhub rule UUID to download (`get_yara_rule`). |
| `--recent` | flag | `false` | Model recently deployed rules (`recent_yararules`). |
| `--deployed` | flag | `false` | Model the rules you've deployed for live hunting (`show_deployed_yara_rules`). |
| `--all` | flag | `false` | Model every shared rule from YARAify's rule export (`<yaraify:export>/yarahub/yaraify-rules.zip`, read into memory and capped at `abusech:maxsize`). |
| `--limit` | int | `0` | The max number of rules to model with `--all`, `0` for all. |
| `--yield` | flag | `false` | Yield the `it:app:yara:rule` nodes. |

At least one of `--uuid`, `--recent`, `--deployed`, `--all` is required (`BadArg`).

Rule text is only available for rules the author shares (`yarahub_rule_sharing_tlp`
TLP:CLEAR, formerly TLP:WHITE); the others are modeled with their metadata only. `--recent` and
`--deployed` download each listed rule's text with `get_yara_rule`, one request per rule
(rules that can't be downloaded keep their metadata).

- Permission: `slib.abusech.user`

```text
slib.abusech.yaraify.rules --uuid 3e8a1b8e-1f6e-4f5e-9f2a-1d4b3c2a1e0f --yield
slib.abusech.yaraify.rules --recent --all
slib.abusech.yaraify.rules --deployed --yield
```

## `slib.abusech.yaraify.deploy`

Deploy YARA rules to YARAify for live hunting, or delete rules you've deployed. Inbound nodes
pass through; responses are printed.

```text
slib.abusech.yaraify.deploy [--text <rule text>] [--delete <uuid> ...]
```

| Option | Type | Default | Meaning |
|---|---|---|---|
| `--text` | str | `null` | YARA rule text to deploy (as `rule.yar`), in addition to the inbound nodes. |
| `--delete` | str, repeatable | `[]` | The YARAhub UUID of one of your deployed rules to delete (`delete_yara_rule`). |

- Permission: `slib.abusech.submit`
- Inputs: `it:app:yara:rule` with `:text`, uploaded as the multipart file `yara_file` named
  `<:name>.yar`. Rules without `:text`, and other forms, get a warning.
- YARAify requires these rule meta fields: `date`, `yarahub_uuid`, `yarahub_license`,
  `yarahub_rule_matching_tlp`, `yarahub_rule_sharing_tlp`, `yarahub_reference_md5`. Deploying
  a rule with an existing `yarahub_uuid` and name updates it.

```text
it:app:yara:rule#my.rules | slib.abusech.yaraify.deploy

slib.abusech.yaraify.rules --deployed --yield
slib.abusech.yaraify.deploy --delete 3e8a1b8e-1f6e-4f5e-9f2a-1d4b3c2a1e0f
```

## `slib.abusech.yaraify.download`

Download (shared) files from YARAify into the Axon, unzipped: submitted files with
`get_file`, or files YARAify's unpacker extracted with `get_unpacked`.

```text
slib.abusech.yaraify.download [--hash <sha256> ...] [--unpacked] [--yield]
```

| Option | Type | Default | Meaning |
|---|---|---|---|
| `--hash` | str, repeatable | `[]` | A SHA256 to download instead of the inbound nodes. |
| `--unpacked` | flag | `false` | Download a file YARAify unpacked from a sample (`get_unpacked`). |
| `--yield` | flag | `false` | Yield the downloaded `file:bytes` nodes instead of the inbound nodes. |

- Permission: `slib.abusech.download`
- Inputs: `file:bytes` (needs a `:sha256`), `hash:sha256`
- Behaves like [`slib.abusech.bazaar.download`](commands-bazaar.md).

```text
file:bytes#my.tag | slib.abusech.yaraify.download

// The files unpacked from a sample.
file:bytes=<sha256> -> file:subfile:parent :child -> file:bytes | slib.abusech.yaraify.download --unpacked
```
