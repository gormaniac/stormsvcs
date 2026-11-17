# slib.capa

A Storm Service that runs Mandiant's [capa](https://github.com/mandiant/capa) against files in the Axon
and models the capa rules they match.

- Every capa rule is a `meta:rule` (with its documentation, YAML, ATT&CK techniques, and MBC behaviors),
  imported in bulk when the package loads.
- Every rule namespace is a documented `syn:tag`, ex. `host-interaction/process/create` is
  `#rep.capa.host_interaction.process.create`.
- Scanning a `file:bytes` links every matched rule to it with a `-(matches)>` edge and tags the file with
  the rules' namespaces.
- Custom capa rules can be written as `meta:rule` nodes (`:type=capa.custom`), scans use them with the
  official rules.

The service pulls the files from the Axon itself, by `:sha256`, so they're never sent through Storm.

## Commands

| Command | Perm | Description |
| --- | --- | --- |
| `slib.capa.scan` | `slib.capa.user` | Run capa against `file:bytes` nodes and model the matched rules. |
| `slib.capa.info` | `slib.capa.user` | Print the versions of capa and its rules, and the import and tag settings. |
| `slib.capa.admin.sync` | `slib.capa.admin` | Import the rules and the tag docs (runs automatically when the package loads). |
| `slib.capa.admin.tags` | `slib.capa.admin` | Change the tag prefix (`rep.capa`) or turn tagging on/off. |
| `slib.capa.admin.contacts.migrate` | `slib.capa.admin` | Migrate the `@handle` `:name` author contacts made before 0.5.0 to `:user` (dry run without `--apply`). |

```
// Scan files, already scanned files are skipped unless --force is used.
file:bytes#my.samples | slib.capa.scan

// Shellcode needs its format (sc32 or sc64), capa can't detect it.
file:bytes=<sha256> | slib.capa.scan --format sc64

// Yield the matched rules instead of the files.
file:bytes=<sha256> | slib.capa.scan --yield

// Every file that does process injection.
file:bytes#rep.capa.host_interaction.process.inject

// Files that match a rule, and the rule's ATT&CK techniques and MBC behaviors.
meta:rule:name="create process on windows" -(matches)> file:bytes
meta:rule:name="create process on windows" -(refs)> it:mitre:attack:technique
meta:rule:name="create process on windows" -(refs)> ou:technique

// Files that match a rule mapped to an MBC behavior.
ou:technique:ext:id=B0001 +:reporter:name=mbc <(refs)- meta:rule -(matches)> file:bytes
```

A file is skipped if it was already scanned with the same capa rules, custom rules, `--format`, `--os`,
and tag settings. Use `--force` to scan it again anyway.

Supported formats are `auto` (the default, capa detects PE, .NET, and ELF files), `pe`, `dotnet`, `elf`,
`sc32`, and `sc64`. Formats that describe another file aren't supported: sandbox reports (CAPE, DRAKVUF,
VMRay) and features frozen by capa (`freeze`). Their results are about the sample they came from, not the
file that was scanned.

The module API can also be used directly:

```
$capa = $lib.import(slib.capa.lib)
file:bytes=<sha256>
for $rule in $capa.scan($node, fmt=auto, osname=auto, force=(false)) { $lib.print($rule.props.name) }
```

## Custom rules

A custom capa rule is a `meta:rule` with a `:type` of `capa.custom` (or a type below it, ex.
`capa.custom.myteam`, but not a type that only starts with the same letters, ex. `capa.customer`) and the [capa rule](https://github.com/mandiant/capa-rules/blob/master/doc/format.md)'s
YAML in its `:text`:

```
[ meta:rule=* :name="my capa rule" :type=capa.custom :text=$yaml ]
```

- Every `slib.capa.scan` sends the custom rules in the view to the service, and capa runs with them and
  the official rules. Edits to a rule's `:text` are used by the next scan, deleted rules are dropped.
- Matches link the custom rule's own node with a `-(matches)>` edge, and tag the file with the rule's
  namespace, like the official rules. Custom namespaces don't get tag docs.
- The service never edits or deletes custom rule nodes, `slib.capa.admin.sync` only touches the official
  rules.
- Official rules win: a custom rule with the same name as an official rule is skipped (the node stays, and
  is used again if the official rule goes away). Invalid custom rules are skipped too. Both are warned
  about on every scan, and listed by `slib.capa.info`.
- Custom rules can use official rules (ex. `match: contain loop`) and each other. A custom rule capa can't
  load with the others (ex. it needs a rule that doesn't exist) fails the scans until it's fixed.
- A file's results record the custom rules it was scanned with, so a file is scanned again (without
  `--force`) when the custom rules change. The service keeps the 16 most recently used sets of custom
  rules, an older set is sent again by the next scan that uses it.

## Model

### Rules

The service loads every rule in its rules directory and, when the package loads (ex. when the service
is added, updated, or the Cortex restarts), the package imports any rules that changed since the last
import (or since `capa:rules:version` or `capa:rules:url` changed). Scans link the imported rule nodes,
they only model a rule that isn't in the Cortex yet. Each rule is a `meta:rule`:

| Prop | Value |
| --- | --- |
| guid | A guid of `("slib.capa", "rule", <rule name>)`, so a rule is the same node across versions of the rules. |
| `:name` | The rule's name. |
| `:type` | `capa`, or `capa.lib` for library rules (only used by other rules, never reported). |
| `:desc` | The rule's documentation: its description, namespace, scopes, authors, ATT&CK, MBC, MAEC, references, and examples. |
| `:text` | The rule's YAML. |
| `:url` | The rule's file on GitHub, at the version of the rules. |
| `:author` | A `ps:contact` for the rule's first author (all authors are in `:desc`): an email author's `:email`, an `@handle`'s `:user` (without the `@`), or else its `:name`. |

The rule's full meta is its `slib:capa` node data. Rules `-(refs)>` the `it:mitre:attack:technique`
nodes of their ATT&CK mappings and the `ou:technique` nodes of their
[MBC](https://github.com/MBCProject/mbc-markdown) behaviors (a rules update that drops a mapping
removes its edge), and each version of the rules is a
`meta:ruleset` that `-(has)>` its rules. Every node is linked to the `slib.capa` `meta:source` with a
`-(seen)>` edge. MAEC categories and families are only in `:desc` and the node data.

An MBC behavior or method (ex. `Anti-Behavioral Analysis::Debugger Detection::Software Breakpoints
[B0001.025]`) is an `ou:technique` with its ID as `:ext:id` and a `:reporter:name` of `mbc` (a guid made
from those two props, so another source's node for the same ID is reused), the last part of the entry as
its `:name` (unless it already has one), and a method's behavior (`B0001`) as its `:parent`.

Upgrading from 0.4.x imports the rules again on the next package load, to add the MBC behaviors and the
handle `:user` contacts. Contacts made for handles by older versions (with the `@handle` as their `:name`)
are left behind, the rules' `:author` points at the new contacts. To migrate them, run
`slib.capa.admin.contacts.migrate` (a dry run that prints what it would change), then
`slib.capa.admin.contacts.migrate --apply`.

It only touches the old contacts slib.capa made: the node the old `({"name": "@handle"})` ctor made
(its guid), for a handle that's the `:author` of a capa rule (`-(seen)>` by the `slib.capa`
`meta:source`), either still the old contact or already the new one. Other `ps:contact` nodes, even
with an `@` `:name`, are never touched. Each old contact is merged into the contact the current code
makes for its handle (`({"user": "handle"})`, made if it doesn't exist): props it doesn't have are
copied (not the `@handle` `:name`), array props are combined, and the tags (with their times), node
data it doesn't have, light edges (both directions), and the props of other nodes that reference it
(ex. a rule's `:author`) are moved, then the old node is deleted. An old contact that already has
the handle as its `:user` just has its `:name` removed. An old contact referenced by a read-only prop
(ex. `ou:contest:result:participant` or `meta:seen:node`, part of the referencing node's primary value) can't be
re-pointed, so it's skipped with a warning naming those nodes: recreate or delete them, then rerun.
Running it again after `--apply` finds nothing to migrate.

### Tags

Every rule namespace (and every namespace above it) is a `syn:tag` under the tag prefix, with a `:title`
and a `:doc` listing the rules in it. Namespaces are converted to tags the way Synapse normalizes tags,
`/` separates tag parts and `-` becomes `_`. Rules without a namespace, and library rules, don't add a
tag. The tag docs are imported with the rules, and again whenever the tag prefix changes.

`slib.capa.admin.tags --prefix` refuses a prefix that isn't a valid tag name (ex. `""` or one with
spaces). After a prefix change (or turning tagging on or off), files keep their old tags until they're
scanned again. The next scan of a file isn't skipped, it removes the tags under the old prefix and
applies the new ones. To move every file that has capa tags now:

```
slib.capa.admin.tags --prefix my.capa
file:bytes#rep.capa | slib.capa.scan
```

The `syn:tag` nodes under the old prefix (with their capa docs) are left in place, delete them once no
node has them anymore if they aren't wanted. Files scanned by slib.capa older than 0.1.4 didn't record
their tag prefix, so their next scan isn't skipped either.

### Results

Scanning a `file:bytes`:

- Removes the results of an earlier scan, so they only show the latest results: the `-(matches)>` edges
  from capa rules, and the tags that scan applied (saved in its node data, whatever the tag settings are
  now). Their parent tags, up to the prefix, are removed too if nothing else is left below them. Other
  tags are left alone, even under a shared prefix like `rep`.
- Adds a `-(matches)>` edge to it from every matched rule's `meta:rule`.
- Tags it with each matched rule's namespace, unless tagging is disabled.
- Saves the results in its `slib:capa` node data: the capa and rules versions, the format, arch, and OS
  capa detected (and the `--format`/`--os` the scan asked for), every matched rule with its match count
  and (up to 100) match addresses, and the tags it applied (with their prefix).

Like capa's own output, library rules and rules that only match parts of other rules aren't reported.
Rules matched in internal namespaces are, ex. `#rep.capa.internal.limitation.file` means capa found the
file is packed or an installer, so its results may be incomplete.

## Configuration

| Key | Default | Description |
| --- | --- | --- |
| `axon:url` | | The Telepath URL of the Axon to pull files from. Required to scan. |
| `capa:rules` | The bundled rules | The capa rules directory. |
| `capa:rules:version` | `v10.0.0` | The version of the rules, used for rule URLs and the ruleset name. |
| `capa:rules:url` | `https://github.com/mandiant/capa-rules/blob/{version}/{path}` | A template for each rule's `:url`, it may only use `{version}` and `{path}`. Set to `""` for none. |
| `capa:sigs` | The bundled signatures | FLIRT signatures capa uses to recognize library code in PE files. |
| `capa:timeout` | `900` | Seconds before a capa run is killed, and before a file's download from the Axon is stopped (connecting to the Axon times out after 30 seconds). |
| `capa:workers` | `2` | The max number of files capa analyzes at once. |
| `capa:maxsize` | `104857600` | The max size (in bytes) of a file the service will scan. |

The container image bundles the [capa-rules](https://github.com/mandiant/capa-rules) release that matches
its version of capa (pinned in `docker/prod/Dockerfile`, Apache 2.0) and capa's FLIRT signatures, and
sets `capa:rules` and `capa:sigs` to them (`SYN_CAPASVC_CAPA_RULES` and `SYN_CAPASVC_CAPA_SIGS`). To use
other rules, point `capa:rules` at them, set `capa:rules:version` (and `capa:rules:url`), restart the
service (or run `slib.capa.admin.sync --reload`), and the next package load imports them. Scans refuse
to run if the rules on disk changed since the service loaded them, so results always match the imported
rules.

capa runs in a subprocess per file, and caches its parsed rules in the service's storage. The cache is
built when the rules are loaded, and the caches of any other rules are deleted once it's built.

## Tests

```
uv run pytest tests
```

The tests run the real capa against a tiny shellcode sample with the rules in `tests/data/rules`. The tests
in `tests/test_live.py` import and scan with the full capa-rules release, set `SYN_CAPASVC_CAPA_RULES` to a
checkout of it (at the `capa:rules:version` tag) to run them. The test image runs them with its bundled
rules.
