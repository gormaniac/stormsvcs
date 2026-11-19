# URLhaus commands

The commands for [URLhaus](https://urlhaus.abuse.ch) (base URLs `urlhaus`, `urlhaus:submit`
and `urlhaus:export`). Nodes they create are linked to the URLhaus `meta:source` and tagged
`<prefix>.urlhaus.*`. What a URL is modeled as is in [the data model](model.md#urls).

## `slib.abusech.urlhaus.lookup`

Look up URLs, hosts and payloads in URLhaus and model the results.

```text
slib.abusech.urlhaus.lookup [--url <url> ...] [--id <id> ...] [--host <host> ...]
    [--hash <hash> ...] [--yield]
```

| Option | Type | Default | Meaning |
|---|---|---|---|
| `--url` | str, repeatable | `[]` | A URL to look up (`/url/`). |
| `--id` | str, repeatable | `[]` | A URLhaus URL ID to look up (`/urlid/`). |
| `--host` | str, repeatable | `[]` | A host to look up (`/host/`): an FQDN or IPv4. URLhaus doesn't support IPv6; a value with `:` is refused by the service. |
| `--hash` | str, repeatable | `[]` | A payload MD5 or SHA256 to look up (`/payload/`). |
| `--yield` | flag | `false` | Yield the URL/host/file nodes instead of the inbound nodes. |

Any of `--url`, `--id`, `--host`, `--hash` makes the command ignore the inbound nodes.

| Inbound form | Query | Models |
|---|---|---|
| `inet:url` | `/url/` | The URL, its tags and status, host, reference, reporter and payloads |
| `inet:fqdn`, `inet:ipv4` | `/host/` | The host with its Spamhaus DBL/SURBL listings and URLhaus reference, and every URL URLhaus has seen on it |
| `file:bytes` (`:sha256`, else `:md5`), `hash:md5`, `hash:sha256` | `/payload/` | The payload sample, and every URL that served it (`inet:urlfile`) |

- Permission: `slib.abusech.user`
- URLs are tagged with their threat, URLhaus tags, and `status.<url_status>` (ex.
  `#rep.abusech.urlhaus.status.online`, replacing an older `status.*` tag), and `larted` when
  the URL was reported to its host. All of those tags carry the URL's added-to-last-online
  interval.

```text
inet:url#my.tag | slib.abusech.urlhaus.lookup

slib.abusech.urlhaus.lookup --host vertex.link --id 12345 --yield
```

## `slib.abusech.urlhaus.search`

Search URLhaus and model the results. Always yields the `inet:url` (or `file:bytes`) nodes,
and drops the inbound nodes.

```text
slib.abusech.urlhaus.search <by> [<value>] [--limit <n>]
```

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `by` | str, one of `tag`, `signature`, `recent-urls`, `recent-payloads` | | What to search by. |
| `value` | str, optional | `null` | The tag or signature. Required for `tag` and `signature` (`BadArg`). |
| `--limit` | int | `0` | The max number of results. |

| `by` | Endpoint | Yields | `--limit` |
|---|---|---|---|
| `tag` | `POST /tag/` | `inet:url` | `0` keeps every URL returned; otherwise the result is cut to it. |
| `signature` | `POST /signature/` | `inet:url` (with each URL's payload) | As for `tag`. Payloads with no signature get the searched signature as their family. |
| `recent-urls` | `GET /urls/recent/` or `/urls/recent/limit/<n>/` | `inet:url` | `0`: the last 3 days (URLhaus' default, at most 1000). Otherwise the latest `n`, clamped to 1000. |
| `recent-payloads` | `GET /payloads/recent/` or `/payloads/recent/limit/<n>/` | `file:bytes` | As for `recent-urls`. |

- Permission: `slib.abusech.user`
- For `tag`/`signature`, when URLhaus reports a `url_count` it prints `slib.abusech: URLhaus
  has <n> URLs for <by> <value> (first seen ..., last seen ...).`; every search prints
  `slib.abusech.urlhaus.search: Found <n> results.`

```text
slib.abusech.urlhaus.search tag Mozi

slib.abusech.urlhaus.search recent-urls --limit 100
```

## `slib.abusech.urlhaus.download`

Download payloads from URLhaus (`GET /download/<sha256>/`) into the Axon, unzipped.

```text
slib.abusech.urlhaus.download [--hash <sha256> ...] [--yield]
```

| Option | Type | Default | Meaning |
|---|---|---|---|
| `--hash` | str, repeatable | `[]` | A SHA256 to download instead of the inbound nodes. |
| `--yield` | flag | `false` | Yield the downloaded `file:bytes` nodes instead of the inbound nodes. |

- Permission: `slib.abusech.download`
- Inputs: `file:bytes` (needs a `:sha256`), `hash:sha256`
- Behaves like [`slib.abusech.bazaar.download`](commands-bazaar.md): a `file:bytes` with
  `:size` and `:name`, linked to the URLhaus `meta:source`; capped at `abusech:maxsize`.

## `slib.abusech.urlhaus.submit`

Report malware URLs to URLhaus. Every inbound `inet:url` and every `--url` are sent in **one**
submission, when the pipeline ends. Inbound nodes pass through. Make sure you've read
URLhaus' submission policy first.

```text
slib.abusech.urlhaus.submit [--url <url> ...] [--threat <threat>] [--tag <tag> ...] [--anonymous]
```

| Option | Type | Default | Meaning |
|---|---|---|---|
| `--url` | str, repeatable | `[]` | A URL to report, in addition to the inbound nodes. |
| `--threat` | str | `malware_download` | The threat type of the URLs. |
| `--tag` | str, repeatable | `[]` | A tag for the URLs. |
| `--anonymous` | flag | `false` | Report anonymously. |

- Permission: `slib.abusech.submit`
- Inputs: `inet:url` (other forms get a warning)
- The request is a JSON POST to `urlhaus:submit`:
  `{"anonymous": "0", "submission": [{"url": ..., "threat": ..., "tags": [...]}, ...]}`.
  URLhaus' plain-text response is printed. Never retried after a 5xx or timeout.

```text
inet:url#my.malware.urls | slib.abusech.urlhaus.submit --tag elf --tag Mozi
```

## `slib.abusech.urlhaus.export`

Model the URLs in a URLhaus CSV export. Runs once and drops the inbound nodes.

```text
slib.abusech.urlhaus.export [<kind>] [--limit <n>] [--bulk [--reuse | --repull]] [--yield]
```

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `kind` | str, one of `recent`, `online`, `full`, `payloads` | `recent` | The export, see below. |
| `--limit` | int | `0` | The max number of URLs to model, `0` for all. Ignored with `--bulk`. |
| `--bulk` | flag | `false` | Bulk import the whole export, see [Bulk imports](bulk.md). |
| `--reuse` | flag | `false` | With `--bulk`, import the last pull again. |
| `--repull` | flag | `false` | With `--bulk`, pull a new copy even if one was pulled recently. |
| `--yield` | flag | `false` | Yield the `inet:url` nodes. Not used with `--bulk`. |

| `kind` | File | Contents | Columns |
|---|---|---|---|
| `recent` | `recent.csv` | URLs added in the last 30 days | `id`, `dateadded`, `url`, `url_status`, `last_online`, `threat`, `tags`, `urlhaus_link`, `reporter` |
| `online` | `online.csv` | URLs that are currently online | as `recent` |
| `full` | `full.csv.zip` | URLs online or added in the last 90 days | as `recent` |
| `payloads` | `payload.csv.zip` | Every payload URLhaus collected, with the URL that served it | `firstseen`, `url`, `filetype`, `md5`, `sha256` |

Every export is streamed to a temporary file (capped at `abusech:bulk:maxsize`) and parsed
row by row. A `payloads` row is modeled as the URL with its payload (`inet:urlfile`, the
payload tagged `type.<filetype>`).

- Permission: `slib.abusech.user`, plus `slib.abusech.bulk` for `--bulk`
- `--reuse`/`--repull` without `--bulk`, or both together, raise `BadArg`.

```text
slib.abusech.urlhaus.export online
slib.abusech.urlhaus.export recent --bulk
slib.abusech.urlhaus.export recent --bulk --reuse
background { slib.abusech.urlhaus.export full --bulk }
```
