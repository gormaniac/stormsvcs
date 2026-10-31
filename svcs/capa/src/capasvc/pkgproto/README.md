# slib.capa

A Storm Service that runs Mandiant's [capa](https://github.com/mandiant/capa) against files in the Axon
and models the capa rules they match.

- Every capa rule is a `meta:rule` (with its documentation, YAML, and ATT&CK techniques), imported in bulk
  when the package loads.
- Every rule namespace is a documented `syn:tag`, ex. `host-interaction/process/create` is
  `#rep.capa.host_interaction.process.create`.
- Scanning a `file:bytes` links every matched rule to it with a `-(matches)>` edge and tags the file with
  the rules' namespaces.

The service pulls the files from the Axon itself, by `:sha256`, so they're never sent through Storm.

## Commands

| Command | Perm | Description |
| --- | --- | --- |
| `slib.capa.scan` | `slib.capa.user` | Run capa against `file:bytes` nodes and model the matched rules. |
| `slib.capa.info` | `slib.capa.user` | Print the versions of capa and its rules, and the import and tag settings. |
| `slib.capa.admin.sync` | `slib.capa.admin` | Import the rules and the tag docs (runs automatically when the package loads). |
| `slib.capa.admin.tags` | `slib.capa.admin` | Change the tag prefix (`rep.capa`) or turn tagging on/off. |

```
// Scan files, already scanned files are skipped unless --force is used.
file:bytes#my.samples | slib.capa.scan

// Shellcode needs its format (sc32 or sc64), capa can't detect it.
file:bytes=<sha256> | slib.capa.scan --format sc64

// Yield the matched rules instead of the files.
file:bytes=<sha256> | slib.capa.scan --yield

// Every file that does process injection.
file:bytes#rep.capa.host_interaction.process.inject

// Files that match a rule, and the rule's ATT&CK techniques.
meta:rule:name="create process on windows" -(matches)> file:bytes
meta:rule:name="create process on windows" -(refs)> it:mitre:attack:technique
```

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
| `:author` | A `ps:contact` for the rule's first author (all authors are in `:desc`). |

The rule's full meta is its `slib:capa` node data. Rules `-(refs)>` the `it:mitre:attack:technique`
nodes of their ATT&CK mappings, and each version of the rules is a `meta:ruleset` that `-(has)>` its
rules. Every node is linked to the `slib.capa` `meta:source` with a `-(seen)>` edge.

### Tags

Every rule namespace (and every namespace above it) is a `syn:tag` under the tag prefix, with a `:title`
and a `:doc` listing the rules in it. Namespaces are converted to tags the way Synapse normalizes tags,
`/` separates tag parts and `-` becomes `_`. Rules without a namespace, and library rules, don't add a
tag. The tag docs are imported with the rules, and again whenever the tag prefix changes.

### Results

Scanning a `file:bytes`:

- Removes the results of an earlier scan, so they only show the latest results: the `-(matches)>` edges
  from capa rules, and the tags that scan applied (saved in its node data, whatever the tag settings are
  now). Their parent tags, up to the prefix, are removed too if nothing else is left below them. Other
  tags are left alone, even under a shared prefix like `rep`.
- Adds a `-(matches)>` edge to it from every matched rule's `meta:rule`.
- Tags it with each matched rule's namespace, unless tagging is disabled.
- Saves the results in its `slib:capa` node data: the capa and rules versions, the format, arch, and OS
  capa detected, every matched rule with its match count and (up to 100) match addresses, and the tags
  it applied (with their prefix).

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
| `capa:timeout` | `900` | Seconds before a capa run is killed. |
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
