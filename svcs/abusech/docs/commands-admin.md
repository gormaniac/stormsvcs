# Auth-Key and admin commands

`slib.abusech.apikey` is for every user. The `slib.abusech.admin.*` commands require
`slib.abusech.admin`. All of them run once (their work is in the command's `init` block) and
pass inbound nodes through.

## `slib.abusech.apikey`

Set, clear, or check your own abuse.ch Auth-Key, stored in a user scoped Synapse vault of type
`abusech`. Your key takes precedence over the service-wide key (see
[Auth-Keys](deployment.md#auth-keys)).

```text
slib.abusech.apikey [<apikey>] [--clear]
```

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `apikey` | str, optional | `null` | Your Auth-Key. Without it (and without `--clear`) the command prints whether you have one set. |
| `--clear` | flag | `false` | Delete your vault. |

- Permission: `slib.abusech.user`
- With an existing `abusech` user vault, the key is updated in place (`secrets.apikey`).
  Otherwise a vault named `abusech:<your username>` is created with `$lib.vault.add()`; if that
  name is taken (ex. by a vault of another type or scope) it warns and suggests renaming or
  deleting that vault.

```text
slib.abusech.apikey ABCDEFG

slib.abusech.apikey --clear
```

## `slib.abusech.admin.apikey`

Set, clear, or check the service-wide Auth-Key, used when a user hasn't set their own. It's
stored in the service (`AbuseChSvc.setApiKey()`), not in the Cortex.

```text
slib.abusech.admin.apikey [<apikey>] [--clear]
```

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `apikey` | str, optional | `null` | The Auth-Key. Without it (and without `--clear`) the command prints whether the service has a key, stored or from `abusech:apikey`. |
| `--clear` | flag | `false` | Clear the stored key. The `abusech:apikey` config option, if set, still applies. |

- Permission: `slib.abusech.admin`
- Prints `Set the slib.abusech Auth-Key.` / `Cleared the slib.abusech Auth-Key.`, or
  `slib.abusech: A service-wide Auth-Key is set.` / `No service-wide Auth-Key is set.`

## `slib.abusech.admin.tags`

Configure the tags applied for abuse.ch's tags, malware families and statuses. Tags are
`<prefix>.<platform>.<tag>`; the default prefix is `rep.abusech`. Prints the current settings
(`slib.abusech tags: enabled=<bool> prefix=<prefix>`) after any change, or alone when run
without options.

```text
slib.abusech.admin.tags [--prefix <tag>] [--enable | --disable]
```

| Option | Type | Default | Meaning |
|---|---|---|---|
| `--prefix` | str | `null` | The tag prefix. It must be a valid tag name that `syn:tag` normalizes to itself (after stripping and lower casing), else `BadArg`. |
| `--enable` | flag | `false` | Enable tagging. |
| `--disable` | flag | `false` | Disable tagging. Using both raises `BadArg`. |

- Permission: `slib.abusech.admin`
- The settings are the Cortex globals `slib:abusech:tag:prefix` and
  `slib:abusech:tag:enabled`, read when the `slib.abusech.lib` module is imported (so once per
  command run) and when a bulk import starts building. Changing the prefix doesn't retag nodes
  that are already tagged.

```text
slib.abusech.admin.tags --prefix rep.abuse

slib.abusech.admin.tags --disable
```

## `slib.abusech.admin.request`

Send a raw request to an abuse.ch API and print the JSON response as indented JSON. An escape
hatch for queries and options the other commands don't cover. The Auth-Key is resolved as
usual (your key, then the service's).

```text
slib.abusech.admin.request <base> [--path <path>] [--method get|post] [--form <dict>]
    [--json <dict>] [--params <dict>]
```

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `base` | str, one of `bazaar`, `urlhaus`, `urlhaus:submit`, `threatfox`, `yaraify`, `hunting` | | The API (see [the base URLs](deployment.md#configuration)). |
| `--path` | str | `""` | The endpoint path below the base URL, ex. `url/` for URLhaus. |
| `--method` | str, one of `get`, `post` | `post` | The HTTP method. |
| `--form` | any | `null` | A dict sent as form data (MalwareBazaar, URLhaus). |
| `--json` | any | `null` | A dict sent as the JSON body (ThreatFox, YARAify, Hunting). |
| `--params` | any | `null` | A dict of query parameters. |

- Permission: `slib.abusech.admin`
- A POST with neither `--form` nor `--json` is sent as an empty form.
- The path is refused if it could leave the base URL: `.`/`..` segments (even URL-quoted),
  `://`, backslashes, `?`, `#`, whitespace or control characters. Put query parameters in
  `--params`.
- The response goes through the normal `query_status` checks, so abuse.ch errors are
  reported as warnings and a "not found" prints `null`. Raw requests may be writes, so they're
  only retried on failures that mean abuse.ch didn't process them (HTTP 429/503, connection
  failures).

```text
slib.abusech.admin.request bazaar --form ({"query": "get_info", "hash": "<sha256>"})

slib.abusech.admin.request threatfox --json ({"query": "ioc", "id": 41})

slib.abusech.admin.request urlhaus --path urls/recent/limit/3/ --method get
```

## `slib.abusech.admin.families.merge`

Merge the malware family nodes made before 0.4.0 into the current ones.

```text
slib.abusech.admin.families.merge [--apply]
```

| Option | Type | Default | Meaning |
|---|---|---|---|
| `--apply` | flag | `false` | Merge the nodes. Without it the command is a dry run that only prints what it would merge. |

Malware families (`risk:tool:software`) are keyed on their name and reporter (see
[Malware families](model.md#malware-families)). Before 0.4.0 they were keyed on their tag,
`({"tag": "<prefix>.<platform>.<family>"})`, when tagging was on, so a family could have one
node per platform and tag prefix, plus one for tagging off.

The command finds every `risk:tool:software:reporter:name="abuse.ch"` with `:soft:name` and
`:tag` whose guid is `$lib.guid((tag, <its :tag>))` (so nodes made some other way are left
alone), and merges each into the node for its name (`slib.abusech.model.familyGuid()`):

1. Props the current node doesn't have are copied; array props (ex. `:soft:names`) are
   combined; `.seen` is merged.
2. Tags (with their times) and light edges (both directions) are moved.
3. Props of other nodes that reference the old node (by guid, by ndef, or in an array) are
   re-pointed at the current node.
4. The old node is deleted. Tag props aren't moved.

An old node referenced by a read-only prop (ex. `meta:seen:node` or `edge:refs:n1`, part of the
referencing node's primary value) can't be re-pointed, so it's skipped with a warning naming
those nodes: recreate or delete them, then rerun.

- Permission: `slib.abusech.admin`, plus the node permissions to set props, tags and edges and
  to delete nodes (edits run as the calling user).
- Prints `Would merge ...` / `Merged ... into risk:tool:software=<guid>` per node, then a
  summary. A second `--apply` finds nothing to merge.

```text
slib.abusech.admin.families.merge
slib.abusech.admin.families.merge --apply
```

## `slib.abusech.admin.edges.migrate`

Rewrite the generic `-(refs)>` light edges made before 0.5.0 into the edges the model uses
now (see [Light edges](model.md#light-edges)).

```text
slib.abusech.admin.edges.migrate [--apply]
```

| Option | Type | Default | Meaning |
|---|---|---|---|
| `--apply` | flag | `false` | Rewrite the edges. Without it the command is a dry run that only prints the counts of each change. |

| Old edge | Becomes |
|---|---|
| `inet:url -(refs)> node` | `inet:url -(about)> node` (reference/report links) |
| `it:sec:stix:indicator -(refs)> node` | `-(detects)>` (ThreatFox IOC records) |
| `file:bytes -(refs)> file:bytes` | `-(linked)>`, same direction (related samples) |
| `file:bytes -(refs)> inet:passwd` | `-(uses)>` (archive passwords) |
| `file:bytes -(refs)> <ThreatFox IOC>` | `-(uses)>` (payloads listed with an IOC) |
| `file:bytes -(refs)> <C2 host, server, or URL>` | removed, the file's `it:sec:c2:config` has it |
| `inet:service:account -(refs)> node`, `file:bytes -(refs)> inet:url` (vendor-found URLs) | kept |

How it decides:

- Candidates are the `inet:url`, `it:sec:stix:indicator` and `file:bytes` nodes linked from
  an abuse.ch `meta:source` with `-(seen)>`, all collected before any are changed. Only edges
  to nodes also linked to an abuse.ch `meta:source` are changed (except `inet:passwd`, which
  never is, so only its file has to be).
- A file's edge to an observable is a ThreatFox IOC's when the file was seen by ThreatFox and a
  ThreatFox `it:sec:stix:indicator` refers to the observable (with `-(refs)>` or
  `-(detects)>`).
- Otherwise a file's edge to a C2 is removed when one of the file's abuse.ch
  `it:sec:c2:config` nodes has it in `:servers` (matched by URL, FQDN, IP, or IP and port).
- Before 0.5.0 a C2 given as a bare host (no port) wasn't put in `:servers`: when the file has
  exactly one config, `tcp://<host>` is added to it and the edge removed; with more, the edge
  is kept with a warning. A URL C2 can't be told from a URL the vendor found in the file, so its
  edge is kept until the next lookup of the file puts it in `:servers`.

- Permission: `slib.abusech.admin`, plus `node.edge.add` and `node.edge.del` (and
  `node.prop.set` for the `:servers` additions).
- A second `--apply` changes nothing. Bulk imports made before 0.5.0 made the old edges too,
  and the command rewrites those as well.

```text
slib.abusech.admin.edges.migrate
slib.abusech.admin.edges.migrate --apply
```
