# MalwareBazaar commands

The commands for [MalwareBazaar](https://bazaar.abuse.ch) (base URLs `bazaar` and
`bazaar:export`). Nodes they create are linked to the MalwareBazaar `meta:source` and tagged
`<prefix>.bazaar.*`. What a sample is modeled as is in
[the data model](model.md#samples-file-bytes).

## `slib.abusech.bazaar.lookup`

Look up samples with `get_info` and model everything MalwareBazaar knows about them: hashes
(including fuzzy hashes), name, MIME type, size, tags, malware family, ClamAV, YARA and vendor
results, code signing certificates, the reporter, comments, related samples, and reference
links.

```text
slib.abusech.bazaar.lookup [--hash <hash> ...] [--yield]
```

| Option | Type | Default | Meaning |
|---|---|---|---|
| `--hash` | str, repeatable | `[]` | An MD5, SHA1, or SHA256 to look up instead of the inbound nodes. |
| `--yield` | flag | `false` | Yield the `file:bytes` nodes instead of the inbound nodes. |

- Permission: `slib.abusech.user`
- Inputs: `file:bytes` (by `:sha256`, else `:sha1`, else `:md5`), `hash:md5`, `hash:sha1`,
  `hash:sha256`
- A SHA3-384 is refused by the service (`MalwareBazaar lookups require an MD5, SHA1, or
  SHA256 hash.`). A hash MalwareBazaar doesn't have prints `slib.abusech: <hash> is not in
  MalwareBazaar.`

```text
file:bytes#my.tag | slib.abusech.bazaar.lookup

slib.abusech.bazaar.lookup --hash 094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d --yield
```

## `slib.abusech.bazaar.search`

Search MalwareBazaar for samples and model them. Always yields the `file:bytes` nodes, and
drops the inbound nodes.

```text
slib.abusech.bazaar.search <by> [<value>] [--limit <n>]
```

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `by` | str, required | | What to search by, see below. |
| `value` | str, optional | `null` | The value to search for. Required except for `recent` and `detections`. |
| `--limit` | int | `100` | The max number of samples (kept in 1-1000, `0` means 1000). Not sent for `issuer`, `subject`, `serial`, `recent` and `detections`, but the result is still cut to it for `issuer`/`subject`/`serial`. |

| `by` | abuse.ch query (form field) | `value` |
|---|---|---|
| `tag` | `get_taginfo` (`tag`) | A tag, ex. `AgentTesla` |
| `signature` | `get_siginfo` (`signature`) | A malware family |
| `filetype` | `get_file_type` (`file_type`) | A file type, ex. `exe` |
| `clamav` | `get_clamavinfo` (`clamav`) | A ClamAV signature |
| `imphash` | `get_imphash` (`imphash`) | An imphash |
| `tlsh` | `get_tlsh` (`tlsh`) | A TLSH |
| `telfhash` | `get_telfhash` (`telfhash`) | A telfhash |
| `gimphash` | `get_gimphash` (`gimphash`) | A gimphash |
| `dhash` | `get_dhash_icon` (`dhash_icon`) | An icon dhash |
| `yara` | `get_yarainfo` (`yara_rule`) | A YARA rule name |
| `issuer` | `get_issuerinfo` (`issuer_cn`) | A certificate issuer CN |
| `subject` | `get_subjectinfo` (`subject_cn`) | A certificate subject CN |
| `serial` | `get_certificate` (`serial_number`) | A certificate serial number |
| `recent` | `get_recent` (`selector`) | `time` (default, the last hour) or `100` (the latest 100). Any other value is an error. |
| `detections` | `recent_detections` (`hours`) | Hours, default `48`, clamped to 1-168. Cast to an int in Storm. |

- Permission: `slib.abusech.user`
- Prints `slib.abusech.bazaar.search: Found <n> samples.`

```text
slib.abusech.bazaar.search signature AgentTesla --limit 50

slib.abusech.bazaar.search recent 100

slib.abusech.bazaar.search detections 24 | -> it:av:scan:result
```

## `slib.abusech.bazaar.cscb`

Model MalwareBazaar's Code Signing Certificate Blocklist (`get_cscb`) as `crypto:x509:cert`
nodes tagged `<prefix>.bazaar.cscb`, with the listing reason as a `meta:note`
(`:type=slib.abusech.bazaar.cscb`).

```text
slib.abusech.bazaar.cscb [--yield]
```

| Option | Type | Default | Meaning |
|---|---|---|---|
| `--yield` | flag | `false` | Yield the `crypto:x509:cert` nodes. |

- Permission: `slib.abusech.user`
- Prints `slib.abusech.bazaar.cscb: <n> blocklisted code signing certificates.`

## `slib.abusech.bazaar.download`

Download samples from MalwareBazaar (`get_file`) into the Axon, unzipped (abuse.ch's AES zips
use the password `infected`).

```text
slib.abusech.bazaar.download [--hash <sha256> ...] [--yield]
```

| Option | Type | Default | Meaning |
|---|---|---|---|
| `--hash` | str, repeatable | `[]` | A SHA256 to download instead of the inbound nodes. |
| `--yield` | flag | `false` | Yield the downloaded `file:bytes` nodes instead of the inbound nodes. |

- Permission: `slib.abusech.download`
- Inputs: `file:bytes` (needs a `:sha256`), `hash:sha256`
- Creates a `file:bytes` (by SHA256) with `:size` and `:name` (the file's name in the zip,
  set only when unset), linked to the MalwareBazaar `meta:source`. It doesn't do a lookup;
  run `slib.abusech.bazaar.lookup` for the metadata.
- Prints `slib.abusech.bazaar.download: Saved <sha256> (<size> bytes) to the Axon.` Warns
  when MalwareBazaar doesn't have the sample, when the input isn't a SHA256, or when the
  downloaded file's SHA256 differs from the one asked for.
- Downloads are capped at `abusech:maxsize`, and a zip with zero or several files is an error.

```text
file:bytes#my.tag | slib.abusech.bazaar.download

slib.abusech.bazaar.download --hash <sha256> --yield
```

## `slib.abusech.bazaar.submit`

Submit `file:bytes` nodes that are in the Axon to MalwareBazaar. Make sure you've read
MalwareBazaar's terms of service first.

```text
slib.abusech.bazaar.submit [--tag <tag> ...] [--delivery <method>] [--link <url> ...]
    [--ref <type>=<url> ...] [--comment <text>] [--dropped-by <sha256>] [--anonymous]
```

| Option | Type | Default | Meaning |
|---|---|---|---|
| `--tag` | str, repeatable | `[]` | A tag for the sample (`tags`). |
| `--delivery` | str, one of `email_attachment`, `email_link`, `web_download`, `web_drive-by`, `multiple`, `other` | `null` | How the sample was delivered (`delivery_method`). |
| `--link` | str, repeatable | `[]` | A reference URL (`references.links`). |
| `--ref` | str, repeatable | `[]` | A typed reference `<type>=<url>`, ex. `any_run=<url>`, `joe_sandbox=<url>`, `malpedia=<url>`, `twitter=<url>`, `urlhaus=<url>` (`references.<type>`). Anything without `=` raises `BadArg`. |
| `--comment` | str | `null` | A comment (`context.comment`). |
| `--dropped-by` | str | `null` | The SHA256 of the sample that dropped this one (`context.dropped_by_sha256`). |
| `--anonymous` | flag | `false` | Submit anonymously (`anonymous=1`). |

- Permission: `slib.abusech.submit`
- Inputs: `file:bytes` that has `:sha256` and `:size` and is in the Axon; other nodes get a
  warning. The file is named by its `:name`, else its SHA256.
- The file must be at most `abusech:maxsize` bytes, checked before it's read from the Axon.
- Sent as a multipart upload with a `json_data` part; `already known` responses
  (`exists`, `file_already_known`) count as success. Uploads are never retried after a 5xx or
  timeout.
- Nothing is modeled; the response is printed.

```text
file:bytes=<sha256> | slib.abusech.bazaar.submit --tag exe --tag AgentTesla --delivery email_attachment
```

## `slib.abusech.bazaar.update`

Comment on MalwareBazaar samples (`add_comment`), or add information to samples you
submitted (`update`).

```text
slib.abusech.bazaar.update [--hash <sha256> ...] [--comment <text>] [--add <key>=<value> ...]
```

| Option | Type | Default | Meaning |
|---|---|---|---|
| `--hash` | str, repeatable | `[]` | A SHA256 to update instead of the inbound nodes. |
| `--comment` | str | `null` | Add this comment (`add_comment`). |
| `--add` | str, repeatable | `[]` | A `<key>=<value>` update (`update`). |

`--add` keys: `add_tag`, `remove_tag`, `urlhaus`, `any_run`, `joe_sandbox`, `malpedia`,
`twitter`, `links`, `dropped_by_md5`, `dropped_by_sha256`, `dropped_by_malware`,
`dropping_md5`, `dropping_sha256`, `dropping_malware`, `comment`. Other keys are refused by the
service; a value without `=` is skipped with a warning.

- Permission: `slib.abusech.submit`
- Inputs: `file:bytes`, `hash:sha256`. The hash must be a SHA256 (others are skipped with a
  warning).
- At least one of `--comment` or `--add` is required (`BadArg`).
- A "not found" from abuse.ch is an error here, so a missing sample isn't reported as
  updated. Never retried after a 5xx or timeout.

```text
file:bytes=<sha256> | slib.abusech.bazaar.update --comment "Seen in a phishing campaign"

slib.abusech.bazaar.update --hash <sha256> --add add_tag=AgentTesla --add urlhaus=https://urlhaus.abuse.ch/url/1/
```

## `slib.abusech.bazaar.export`

Model the samples in a MalwareBazaar export. Runs once and drops the inbound nodes.

```text
slib.abusech.bazaar.export [<kind>] [--limit <n>] [--bulk [--reuse | --repull]] [--yield]
```

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `kind` | str, one of `recent`, `full`, `yara` | `recent` | The export, see below. |
| `--limit` | int | `0` | The max number of samples (or rules) to model, `0` for all. Ignored with `--bulk`. |
| `--bulk` | flag | `false` | Bulk import the whole export, see [Bulk imports](bulk.md). Not allowed with `yara` (`BadArg`). |
| `--reuse` | flag | `false` | With `--bulk`, import the last pull again instead of pulling a new one. |
| `--repull` | flag | `false` | With `--bulk`, pull a new copy even if one was pulled recently. |
| `--yield` | flag | `false` | Yield the `file:bytes` (or `it:app:yara:rule`) nodes. Not used with `--bulk`. |

| `kind` | File | Contents |
|---|---|---|
| `recent` | `recent.csv` | The samples added in the last 48 hours |
| `full` | `full.csv.zip` | Every sample. Streamed to a temporary file (capped at `abusech:bulk:maxsize`) and parsed row by row. Warns that it may take a while. |
| `yara` | `yara_rules.json` | The YARA rule statistics: every rule MalwareBazaar matches samples with, modeled as `it:app:yara:rule` (read into memory, capped at `abusech:maxsize`) |

CSV columns read: `first_seen_utc`, `sha256_hash`, `md5_hash`, `sha1_hash`, `reporter`,
`file_name`, `file_type_guess`, `mime_type`, `signature`, `clamav`, `vtpercent`, `imphash`,
`ssdeep`, `tlsh`. `vtpercent` becomes a `virustotal` `it:av:scan:result`.

- Permission: `slib.abusech.user`, plus `slib.abusech.bulk` for `--bulk`
- `--reuse`/`--repull` without `--bulk`, or both together, raise `BadArg`.
- Modeling in Storm runs at roughly 50 rows/second; use `--limit` or `--bulk` with `full`.

```text
slib.abusech.bazaar.export
slib.abusech.bazaar.export full --limit 10000
slib.abusech.bazaar.export yara --yield

// Bulk import the recent export, then rerun it on the same file after a service update.
slib.abusech.bazaar.export recent --bulk
slib.abusech.bazaar.export recent --bulk --reuse
background { slib.abusech.bazaar.export full --bulk }
```
