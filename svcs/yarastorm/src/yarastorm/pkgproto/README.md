# yarastorm

A Synapse Storm service that adds Yara scanning features to a Synapse Cortex.

Rules are compiled with [Yara-X](https://virustotal.github.io/yara-x/) and saved in the service.
`slib.yara.enable` compiles an `it:app:yara:rule` into the service and sets `:enabled`,
`slib.yara.disable` removes it again. `slib.yara.scan` matches `file:bytes` nodes (by `:sha256`,
pulled from the configured Axon) against every rule saved in the service.

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `axon_url` | string | none | The Telepath URL of the Axon that files are pulled from for scanning. Without it, `slib.yara.scan` warns for every file. |
| `rule_dir` | string | `rules/` | The directory compiled rules are saved in. A relative path is relative to the service's storage directory (`dirn`), an absolute path is used as is. |
| `max_size` | integer | none | The largest file, in bytes, that is pulled from the Axon to scan. Larger files are skipped with a warning. No limit when unset. |
| `scan_timeout` | integer | `60` | The number of seconds one rule may spend scanning one file. A scan that takes longer is abandoned and warned about for that rule. |

Like any Synapse Cell, these can be set in the service's `cell.yaml` or with environment variables,
ex. `SYN_YARASVC_AXON_URL`.

Each file is read from the Axon into the service's memory in full before it's scanned, so a scan
of a large file needs that much memory (plus a little per concurrent scan). Set `max_size` to bound
it, ex. to the largest sample you expect to scan. Scans run in a worker thread, so a slow scan
doesn't block the service, and each rule's scan of a file is stopped after `scan_timeout` seconds.

Compiled rules are stored as one file per rule in `rule_dir`, named by the rule's
`it:app:yara:rule` guid. The files are the service's rule set: rule files added, replaced, or
removed in `rule_dir` while the service runs are picked up by the next scan, rule list, or rule
count. Files that aren't a guid and sub directories are ignored. A rule file that can't be read
(ex. a corrupt file, or one from an incompatible `yara-x` version) is logged once in the service's
log, and every scan warns about it for that rule until `slib.yara.sync` recompiles or removes it.

## Permissions

- `slib.yara.admin` (Cortex) - needed to run `slib.yara.enable`, `slib.yara.disable`, and
  `slib.yara.sync`, and to call the `slib.yara.lib` functions that change the service's rules.
- `slib.yara.admin` (service) - the service user that the Cortex connects to the service with needs
  this permission on the service to compile and remove rules. The service's `root` user, which is
  what most deployments connect as, already has it. Checking a rule and scanning don't need it.

Users also need the `service.get` permission for the slib.yara service, and these node permissions:

- `slib.yara.scan` - `node.add.it:app:yara:match`, `node.prop.set.it:app:yara:match` (for `.seen`
  and `:version`), `node.edge.add.seen`, `node.add.meta:source`, and
  `node.prop.set.meta:source.name`.
- `slib.yara.enable` and `slib.yara.disable` - `node.prop.set.it:app:yara:rule.enabled`.

The exact permission Synapse checks for `.seen` is `node.prop.set.it:app:yara:match..seen`, which
`auth.user.addrule` can't express (it splits a rule on every `.`), so grant
`node.prop.set.it:app:yara:match`.

## Commands

- `slib.yara.check` - Takes `it:app:yara:rule` nodes. Compiles the rule's `:text` and prints
  whether it's valid, or the compile error. The rule is not saved to the service.
- `slib.yara.enable` - Takes `it:app:yara:rule` nodes. Compiles the rule into the service and sets
  `:enabled=(true)`. A rule that doesn't compile is not enabled.
- `slib.yara.disable` - Takes `it:app:yara:rule` nodes. Removes the rule from the service and sets
  `:enabled=(false)`.
- `slib.yara.sync` - Takes no input. Compiles every `it:app:yara:rule:enabled=(true)` node into the
  service and removes the service's rule files that aren't enabled in the Cortex (including ones
  that can't be read). Enabled rules that fail to compile are reported and left as they are.
- `slib.yara.scan` - Takes `file:bytes` nodes with a `:sha256`. Scans the file with every rule in
  the service and creates an `it:app:yara:match` for each match (with `.seen` set, `:version` set
  to the rule's `:version` when it has one, and a `seen` edge from the service's `meta:source`).
  Set `$lib.debug` to also print the rules that didn't match. Warns if the service has no rules,
  or if it can't get the service's rule count.

Other forms passed to a command are skipped with a warning.

Matching is per `it:app:yara:rule` node, not per Yara rule: a node's `:text` can hold several
`rule` blocks, and the node counts as matched if any of them matches. Which Yara rule names or
strings matched is not recorded. A match's `:version` is the rule node's `:version` at scan time,
so it's only accurate if the service has the current `:text` compiled (see below).

## Keeping the Cortex and the service in sync

The service only scans with the rules that were compiled into it. They can drift from the Cortex
when:

- `:enabled` is set on a rule directly instead of with `slib.yara.enable`/`slib.yara.disable`.
- An enabled rule's `:text` is changed (the service keeps the old compiled version).
- The service's `rule_dir` is reset, ex. a new deployment without the old storage volume.

Run `slib.yara.sync` after any of these (it can also be run on a cron job) to bring the service in
line with the Cortex. If the service's rules can't be listed, `slib.yara.sync` warns
`Unable to sync the slib.yara rules: ...` after compiling the enabled rules, and removes nothing.
