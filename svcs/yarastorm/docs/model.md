# Data Model

The service uses the Synapse 2.x `it:app:yara:*` model. It reads `it:app:yara:rule` and
`file:bytes` nodes and writes only the nodes, props and edges below. It applies no tags, and has
no tag prefixes to configure.

## Forms read

| Form | Props used | How |
| --- | --- | --- |
| `it:app:yara:rule` (guid) | primary value, `:text`, `:enabled` | The guid is the rule's ID in the service (and its file name in `rule_dir`). `:text` is what gets compiled. `:enabled=(true)` is what `slib.yara.sync` treats as the desired rule set. |
| `file:bytes` | primary value, `:sha256` | `:sha256` is the key used to pull the bytes from the Axon. The primary value becomes the match's `:file`. |

The whole rule node is sent to the service with `$node.pack()`; the service only uses the form,
the primary value and `props["text"]`. Other `it:app:yara:rule` props (`:name`, `:author`,
`:version`, `:family`, ...) aren't used.

## Forms and props written

| Node | Written by | Props / edges |
| --- | --- | --- |
| `it:app:yara:rule` | `slib.yara.enable`, `slib.yara.disable` | `:enabled=(true)` after a successful compile, `:enabled=(false)` after a successful removal |
| `it:app:yara:match=(<rule>, <file>)` | `slib.yara.scan` | `:rule` and `:file` (comp fields, read-only), `.seen=now` |
| `meta:source=12bc0c8c1a37a29808d97972875d3913` | service `add` event, `slib.yara.scan` | `:name=slib.yara` |
| edge `meta:source -(seen)> it:app:yara:match` | `slib.yara.scan` | one per match node |

`it:app:yara:match` is a `comp` of `(rule: it:app:yara:rule, file: file:bytes)`. Its
`:version` prop is never set. The Storm that writes it ({src}`svcs/yarastorm/src/yarastorm/pkgproto/storm/modules/slib.yara.ingest.storm`):

```text
[ it:app:yara:match=($rule, $file) .seen=now ]
[ <(seen)+ { [ meta:source=$srcguid :name=slib.yara ] } ]
```

## Mapping from scan results

`YaraSvc.matchFile()` yields `YaraMatch` dicts; only `matched: true` results are modeled:

| `YaraMatch` field | Synapse |
| --- | --- |
| `rule` | `it:app:yara:match:rule` (the `it:app:yara:rule` guid) |
| `sha256` | not stored; the match uses the scanned node's value instead |
| `matched` | `true` creates the node; `false` writes nothing |

| Storm value | Synapse |
| --- | --- |
| `$node.repr()` of the scanned `file:bytes` | `it:app:yara:match:file` |
| scan time | `.seen` (an interval; repeated scans extend it) |

## Meta source

The service's `meta:source` guid is fixed: `12bc0c8c1a37a29808d97972875d3913`. It's defined as
`SVC_GUID` in {src}`svcs/yarastorm/src/yarastorm/defs.py` and hard-coded as `$srcguid` in
`slib.yara.ingest` (a test checks they match). It's created by the service's `add` event the first
time the service is added to a Cortex, and re-asserted on every match.

Find everything the service has matched:

```text
meta:source=12bc0c8c1a37a29808d97972875d3913 -(seen)> it:app:yara:match
```

## Idempotency

- `it:app:yara:match` is a comp of `(rule, file)`, so scanning the same file with the same rule
  again doesn't create a new node; it only widens `.seen`. The `seen` edge is also idempotent.
- A match is never removed. A rule that's later disabled, or a rule whose `:text` changed so it no
  longer matches, leaves its old match nodes in place.
- A file stored as two `file:bytes` nodes (ex. `sha256:...` and a `guid:...` with the same
  `:sha256`) gets a separate match node for each node scanned.

## Example

```text
// Before
it:app:yara:rule=7a1b...  :name=hello  :text='rule hello { strings: $a = "hello" condition: $a }'
file:bytes=sha256:2cf2...  :sha256=2cf2...

it:app:yara:rule=7a1b... | slib.yara.enable
file:bytes=sha256:2cf2... | slib.yara.scan

// After
it:app:yara:rule=7a1b...  :enabled=true
it:app:yara:match=(7a1b..., sha256:2cf2...)  :rule=7a1b...  :file=sha256:2cf2...  .seen=(<now>, <now+1>)
meta:source=12bc0c8c1a37a29808d97972875d3913  :name=slib.yara  -(seen)> it:app:yara:match=(7a1b..., sha256:2cf2...)
```
