# Commands

The `slib.yara` package has five commands. None of them takes arguments or options (no
`cmdargs`); they're driven entirely by the nodes piped into them, and `--help` prints the
command description. Every command accepts any node: a node of the wrong form is skipped with a
warning and passed through. Input nodes are always passed through to the next command.

Errors from the service are reported with `$lib.warn()`, never raised, so a failure on one node
doesn't stop the pipeline.

| Command | Input | Needs `slib.yara.admin` | Writes |
| --- | --- | --- | --- |
| [`slib.yara.check`](#slibyaracheck) | `it:app:yara:rule` | no | nothing |
| [`slib.yara.enable`](#slibyaraenable) | `it:app:yara:rule` | yes | `:enabled=(true)`, rule compiled into the service |
| [`slib.yara.disable`](#slibyaradisable) | `it:app:yara:rule` | yes | `:enabled=(false)`, rule removed from the service |
| [`slib.yara.sync`](#slibyarasync) | none | yes | service rule set only |
| [`slib.yara.scan`](#slibyarascan) | `file:bytes` | no | `it:app:yara:match`, `meta:source`, `seen` edges |

## Rule management

### slib.yara.check

Compile an `it:app:yara:rule`'s `:text` and report whether it's valid. The rule is only compiled,
it is not saved to the service, and the node is not modified.

```text
it:app:yara:rule | slib.yara.check
```

| | |
| --- | --- |
| Inputs | `it:app:yara:rule` |
| Permissions | `service.get` on the service |
| Calls | `slib.yara.lib.compile($node, (true))` -> `compileRule(<packed node>, True)` |

Output per node:

- Valid: `it:app:yara:rule=<guid> is a valid Yara rule!` (print).
- Invalid: `it:app:yara:rule=<guid> is not a valid Yara rule: <mesg>` (warn), where `<mesg>` is
  one of:
  - `Yara Compile Error - <yara-x error>` for a compile error.
  - `it:app:yara:rule=<guid> has no :text to compile.` when `:text` is unset or empty.
- Other forms: `slib.yara.check only supports it:app:yara:rule nodes, skipping <form>.` (warn).

Example:

```text
[ it:app:yara:rule=* :name=bad :text="test" ] | slib.yara.check
```

### slib.yara.enable

Compile a rule into the service, so scans use it, then set `:enabled=(true)`. A rule that fails to
compile is not enabled and the service's existing copy of it (if any) is untouched. Re-run it
after changing a rule's `:text`, since the service keeps the version it compiled.

```text
it:app:yara:rule:name=myrule | slib.yara.enable
```

| | |
| --- | --- |
| Inputs | `it:app:yara:rule` |
| Permissions | `slib.yara.admin`, `node.prop.set.it:app:yara:rule.enabled`, `service.get` |
| Calls | `slib.yara.lib.enableRule($node)` -> `compileRule(<packed node>)` |
| Modifies | `it:app:yara:rule:enabled=(true)` on success |

Messages:

- Without `slib.yara.admin`: `slib.yara.enable requires the slib.yara.admin permission.` is
  warned once (in the command's `init`), and every node passes through unchanged.
- On failure: `Unable to enable it:app:yara:rule=<guid>: <mesg>` (warn). `<mesg>` can be a compile
  error, the missing `:text` message, `The service user <name> needs the slib.yara.admin
  permission.`, or `Unable to save the rule: <error>`.
- Other forms: `slib.yara.enable only supports it:app:yara:rule nodes, skipping <form>.`

### slib.yara.disable

Remove a rule from the service, so scans skip it, then set `:enabled=(false)`. Disabling a rule
the service doesn't have is not an error (it still sets `:enabled=(false)`).

```text
it:app:yara:rule:name=myrule | slib.yara.disable
```

| | |
| --- | --- |
| Inputs | `it:app:yara:rule` |
| Permissions | `slib.yara.admin`, `node.prop.set.it:app:yara:rule.enabled`, `service.get` |
| Calls | `slib.yara.lib.disableRule($node)` -> `removeRule(<guid>)` |
| Modifies | `it:app:yara:rule:enabled=(false)` on success |

Messages mirror `slib.yara.enable`: `slib.yara.disable requires the slib.yara.admin permission.`,
`Unable to disable it:app:yara:rule=<guid>: <mesg>`, and the wrong-form warning.

### slib.yara.sync

Reconcile the service's compiled rules with the Cortex. Takes no input nodes; all of its work
happens in the command's `init` block, once per run.

```text
slib.yara.sync
```

| | |
| --- | --- |
| Inputs | none |
| Permissions | `slib.yara.admin`, `service.get` |
| Calls | `slib.yara.lib.sync()` |

What it does:

1. Lifts every `it:app:yara:rule:enabled=(true)` node and calls `compileRule()` for each,
   recompiling it from its current `:text`. A rule that fails is recorded as failed; the
   service's previous compiled copy of it, if any, is left in place.
2. Calls `listRules()` and `removeRule()`s every rule guid the service has that wasn't in the
   enabled set from step 1.
3. Warns `Unable to sync it:app:yara:rule=<guid>: <mesg>` for every failure (compile or remove),
   then prints a summary:

   ```text
   Synced the slib.yara rules: 1 compiled, 1 removed, 1 failed.
   ```

Run it when the Cortex and the service can drift:

- `:enabled` was set directly instead of with `slib.yara.enable`/`slib.yara.disable`.
- An enabled rule's `:text` changed.
- The service's `rule_dir` was reset (new volume) or the `yara-x` version changed.
- On a schedule, ex. a cron job:

  ```text
  cron.add --daily 03:00 { slib.yara.sync }
  ```

Without `slib.yara.admin` it warns `slib.yara.sync requires the slib.yara.admin permission.` and
does nothing.

## Scanning

### slib.yara.scan

Scan `file:bytes` nodes with every rule compiled into the service. The bytes are pulled from the
service's Axon (`axon_url`) by the node's `:sha256`, so a `file:bytes` without `:sha256` can't be
scanned. Each matching rule produces an `it:app:yara:match` node.

```text
file:bytes=sha256:<hex> | slib.yara.scan
```

| | |
| --- | --- |
| Inputs | `file:bytes` with `:sha256` (any primary value: `sha256:...` or `guid:...`) |
| Permissions | `service.get`, plus the node permissions to create the match (see [Deployment](deployment.md#permissions-for-cortex-users)) |
| Calls | `slib.yara.lib.ruleCount()` once in `init`; `slib.yara.lib.match(:sha256)` per node |
| Creates | `it:app:yara:match=(<rule guid>, <file:bytes value>)` with `.seen=now`, and a `seen` edge from `meta:source=12bc0c8c1a37a29808d97972875d3913` |

Per file, the service yields one result per compiled rule:

| Result | Output |
| --- | --- |
| Rule matched | Creates the match node and prints `it:app:yara:rule=<rule> matched file:bytes=<file>` |
| Rule didn't match | Nothing, unless `$lib.debug` is set: prints `it:app:yara:rule=<rule> did not match file:bytes=<file>` |
| Error for one rule | Warns `Unable to scan file:bytes=<file> with it:app:yara:rule=<rule>: <mesg>` and continues with the next rule |
| Error for the file | Warns `There was an error scanning file:bytes=<file>: <mesg>` and moves to the next node |

File-level `<mesg>` values come from `YaraSvc.matchFile()`:

| Message | Cause |
| --- | --- |
| `The yarastorm service has no axon_url configured.` | `axon_url` unset |
| `Invalid sha256: '<valu>'` | not 64 hex characters |
| `Unable to connect to the Axon within 10 seconds.` | Axon unreachable (`AXON_TIMEOUT`) |
| `The file is <n> bytes, more than the <max> byte max (max_size).` | file larger than `max_size` |
| `Bytes for file:bytes:sha256=<sha256> are not in the Axon.` | file missing, or zero bytes long |
| `Unable to read the file from the Axon: <error>` | any other error reading the file |

Other warnings:

- `The slib.yara service has no rules to scan with, enable rules with slib.yara.enable or run
  slib.yara.sync.` is warned once in `init` when the service has zero rules. Nodes are still
  passed to the service (and produce no results).
- `file:bytes=<file> has no :sha256 and can't be scanned.`
- `slib.yara.scan only supports file:bytes nodes, skipping <form>.`

The match's `:file` is the scanned node's own value, so scanning a `guid:` `file:bytes` links the
match to that node, not to a `sha256:` `file:bytes`.

To also see the rules that didn't match, run the query with Storm's `debug` runtime option set
(`opts={"debug": true}`), which sets `$lib.debug`.

Examples:

```text
// Scan every tagged file that has a sha256
file:bytes#cno.mal.sample +:sha256 | slib.yara.scan

// Pivot to what matched
file:bytes=sha256:<hex> -> it:app:yara:match :rule -> it:app:yara:rule
```

:::{note}
Matching is per `it:app:yara:rule` node, not per Yara rule. A node's `:text` can contain several
`rule` blocks; the node counts as matched if any of them matches. Which Yara rule names or
strings matched is not recorded.
:::
