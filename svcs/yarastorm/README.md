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

Like any Synapse Cell, these can be set in the service's `cell.yaml` or with environment variables,
ex. `SYN_YARASVC_AXON_URL`.

Compiled rules are stored as one file per rule in `rule_dir`, named by the rule's
`it:app:yara:rule` guid. Files that aren't a guid, sub directories, and files that can't be read
(ex. a corrupt rule) are skipped with a warning in the service's log.

## Permissions

- `slib.yara.admin` (Cortex) - needed to run `slib.yara.enable`, `slib.yara.disable`, and
  `slib.yara.sync`, and to call the `slib.yara.lib` functions that change the service's rules.
- `slib.yara.admin` (service) - the service user that the Cortex connects to the service with needs
  this permission on the service to compile and remove rules. The service's `root` user, which is
  what most deployments connect as, already has it. Checking a rule and scanning don't need it.

Users also need the `service.get` permission for the slib.yara service, and the usual node
permissions to create `it:app:yara:match` nodes and set `it:app:yara:rule:enabled`.

## Commands

- `slib.yara.check` - Takes `it:app:yara:rule` nodes. Compiles the rule's `:text` and prints
  whether it's valid, or the compile error. The rule is not saved to the service.
- `slib.yara.enable` - Takes `it:app:yara:rule` nodes. Compiles the rule into the service and sets
  `:enabled=(true)`. A rule that doesn't compile is not enabled.
- `slib.yara.disable` - Takes `it:app:yara:rule` nodes. Removes the rule from the service and sets
  `:enabled=(false)`.
- `slib.yara.sync` - Takes no input. Compiles every `it:app:yara:rule:enabled=(true)` node into the
  service and removes the service's rules that aren't enabled in the Cortex. Enabled rules that
  fail to compile are reported and left as they are.
- `slib.yara.scan` - Takes `file:bytes` nodes with a `:sha256`. Scans the file with every rule in
  the service and creates an `it:app:yara:match` for each match (with `.seen` set and a `seen`
  edge from the service's `meta:source`). Set `$lib.debug` to also print the rules that didn't
  match. Warns if the service has no rules.

Other forms passed to a command are skipped with a warning.

## Keeping the Cortex and the service in sync

The service only scans with the rules that were compiled into it. They can drift from the Cortex
when:

- `:enabled` is set on a rule directly instead of with `slib.yara.enable`/`slib.yara.disable`.
- An enabled rule's `:text` is changed (the service keeps the old compiled version).
- The service's `rule_dir` is reset, ex. a new deployment without the old storage volume.

Run `slib.yara.sync` after any of these (it can also be run on a cron job) to bring the service in
line with the Cortex.

## TODO

- Move yara rule storage to the Cell's LMDB slab.
