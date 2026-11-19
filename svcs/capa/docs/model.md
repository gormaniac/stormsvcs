# Data model

All node edits are made by the Storm package, mostly in
{src}`svcs/capa/src/capasvc/pkgproto/storm/modules/slib.capa.model.storm`, from records the
service builds in {src}`svcs/capa/src/capasvc/rules.py` and
{src}`svcs/capa/src/capasvc/svc.py`.

## Overview

```text
meta:source (slib.capa) -(seen)-> meta:rule, meta:ruleset, ou:technique (MBC), file:bytes

meta:ruleset (capa-rules <version>) -(has)-> meta:rule
meta:rule :author -> ps:contact
meta:rule -(refs)-> it:mitre:attack:technique     (ATT&CK mappings)
meta:rule -(refs)-> ou:technique                  (MBC behaviors and methods)
ou:technique (method) :parent -> ou:technique (behavior)
meta:rule -(matches)-> file:bytes                 (scan results)
file:bytes #<prefix>.<namespace tag>              (scan results)
syn:tag <prefix>.<namespace tag> :title :doc      (namespace docs)
```

| Form | Created by | Guid / primary value |
| --- | --- | --- |
| `meta:source` | The service `add` event | `ee5999b4059645168272e22d7cd087e3` (`SVC_GUID`) |
| `meta:ruleset` | Rule import | `guid(("slib.capa", "ruleset", <capa:rules:version>))` |
| `meta:rule` (official) | Rule import, or a scan if missing | `guid(("slib.capa", "rule", <rule name>))` |
| `meta:rule` (custom) | The user | The user's own node, never edited by the package |
| `ps:contact` | Rule import | guid ctor of the first author, see [Authors](#authors) |
| `it:mitre:attack:technique` | Rule import | The ATT&CK ID, ex. `T1059.001` |
| `ou:technique` | Rule import | guid ctor `{"ext:id": <MBC ID>, "reporter:name": "mbc"}` |
| `syn:tag` | Tag doc import | `<prefix>` and `<prefix>.<namespace tag>` |
| `file:bytes` | Existing nodes | Scans only add edges, tags and node data |

## The meta:source

When the service is added, its `add` event runs:

```text
[(meta:source=ee5999b4059645168272e22d7cd087e3 :name="capa" :type=slib.capa
  :url=https://github.com/mandiant/capa)]
```

The package's `seen()` helper creates the same node (with only `:name=capa`) if it doesn't
exist, and adds `meta:source -(seen)> <node>` to the `meta:rule`, `meta:ruleset`, MBC
`ou:technique` and scanned `file:bytes` nodes it writes. ATT&CK techniques, contacts and tags
are not linked.

## Rules

### meta:rule

Every rule in `capa:rules` is a `meta:rule`, built from the record `rules.ruleRecord()`
returns (see [the rule record](api.md#rules)):

| Prop / data | Value | From |
| --- | --- | --- |
| guid | `guid(("slib.capa", "rule", <name>))`, so a rule is the same node across rules versions. | `meta.name` |
| `:name` | The rule's name. | `meta.name` |
| `:type` | `capa`, or `capa.lib` for library rules (only used by other rules, never reported). | `meta.lib` |
| `:desc` | A Markdown summary of the rule's documentation (below). Not set if empty. | `meta` |
| `:text` | The rule's YAML, as read from disk. | the rule file |
| `:url` | `capa:rules:url` formatted with `version` and the rule's relative path. Not set when the template is `""`. | `capa:rules:url` |
| `:author` | A `ps:contact` for the rule's first author (all authors are in `:desc`). | `meta.authors[0]` |
| node data `slib:capa` | The rule's full meta, JSON-safe (tuples and sets become lists, other objects strings). | `meta` |
| `-(refs)> it:mitre:attack:technique` | One per ATT&CK technique ID in `att&ck`. | `meta["att&ck"]` |
| `-(refs)> ou:technique` | One per MBC behavior or method in `mbc`. | `meta.mbc` |
| `<(has)- meta:ruleset` | The ruleset of the import. | |
| `<(seen)- meta:source` | | |

The `:desc` is built by `ruleDoc()`. Each part is only present when the meta has it:

```text
<description>

This is a capa library rule. It is only used by other rules, capa never reports it.

Namespace: host-interaction/process/create
Scopes: static: function, dynamic: call
Authors: someone@example.com, @someone

ATT&CK:
- Execution::Command and Scripting Interpreter [T1059]

MBC:
- Process::Create Process [C0017]

MAEC malware category:
- ...

MAEC malware family:
- ...

References:
- https://...

Examples:
- <md5>:0x401000
```

MAEC categories and families are only in `:desc` and the node data.

When the rules are re-imported, a rule's ATT&CK and MBC `-(refs)>` edges follow its current
mappings: edges to `it:mitre:attack:technique` nodes that aren't in its `att&ck` anymore, and
to `ou:technique` nodes with `:reporter:name=mbc` that aren't in its `mbc` anymore, are removed.
Its other `-(refs)>` edges (ex. to another source's `ou:technique`) are left alone.

### ATT&CK techniques

Each `att&ck` entry whose text ends with a bracketed technique ID (regex
`\[(T\d{4}(?:\.\d{3})?)\]\s*$`) becomes `it:mitre:attack:technique=<ID>`, deduplicated:

| `att&ck` entry | Node |
| --- | --- |
| `Execution::Command and Scripting Interpreter [T1059]` | `it:mitre:attack:technique=T1059` |
| `Execution::Command and Scripting Interpreter::PowerShell [T1059.001]` | `it:mitre:attack:technique=T1059.001` |

Only the primary value is set. Entries without an ID are left out of the edges (they're still
in `:desc`).

### MBC behaviors

Each `mbc` entry matching `^<path> [<ID>]$`, with an ID like `B0001`, `C0017` or `B0001.025`
(case-insensitive, upper-cased), becomes an `ou:technique`:

| Prop | Value |
| --- | --- |
| guid | ctor `{"ext:id": <ID>, "reporter:name": "mbc"}`, so another source's node with the same two props is reused. |
| `:ext:id` | The MBC ID, ex. `B0001.025`. |
| `:reporter:name` | `mbc` |
| `:name` | The last `::` part of the entry, ex. `Software Breakpoints`. Only set if the node has no `:name`. |
| `:parent` | For a method (an ID with a `.`), the `ou:technique` of its behavior (`B0001`), named with the entry's second to last part when the entry has three or more parts. |

Example: `Anti-Behavioral Analysis::Debugger Detection::Software Breakpoints [B0001.025]` is
`ou:technique` `:ext:id=B0001.025 :name="Software Breakpoints"` with
`:parent` `:ext:id=B0001 :name="Debugger Detection"`.

### Authors

`:author` is a `ps:contact` made with a guid ctor from the first entry of `authors`
(`rules.contact()`). Values are stripped and lower-cased:

| Author | Ctor | Example |
| --- | --- | --- |
| An email (`^[^@\s]+@[^@\s]+\.[^@\s]+$`) | `{"email": <email>}` | `test@example.com` |
| An `@handle` (`^@([^@\s]+)$`) | `{"user": <handle without @>}` | `@visi` is `:user=visi` |
| Anything else | `{"name": <author>}` | `Jane Doe` is `:name="jane doe"` |

Versions before 0.5.0 made `@handle` authors `{"name": "@handle"}`. See
[`slib.capa.admin.contacts.migrate`](commands.md#slibcapaadmincontactsmigrate).

### meta:ruleset

Each version of the rules is a `meta:ruleset` that `-(has)>` every rule imported with it:

| Prop / data | Value |
| --- | --- |
| guid | `guid(("slib.capa", "ruleset", <capa:rules:version>))` |
| `:name` | `capa-rules <version>` |
| `:type` | `capa` |
| `:desc` | `The capa rules (capa-rules <version>) of the slib.capa service, for capa <capa version>.` |
| node data `slib:capa` | `{"version", "sha256", "capa", "rules", "lib", "namespaces"}` from the rules info |

The ruleset guid only depends on the version. Rules loaded from another directory with the same
`capa:rules:version` go into the same ruleset.

### When rules are imported

The import is keyed by the rules' **sync key**, `guid((<rules sha256>, <capa:rules:version>,
<capa:rules:url>, MODEL_VERSION))` (`MODEL_VERSION = 2`). The last imported key is the Cortex
global `slib:capa:sync:rules`. The import runs when the key differs (or the ruleset node is
missing), or with `slib.capa.admin.sync --force`. Each import sets every prop again, so
edits to imported rule nodes are overwritten by the next import.

Scans don't rebuild imported rules: they only model a matched rule that isn't in the Cortex
(ex. deleted, or the import hasn't run), using the record the service returns.

## Tags

### Namespace tags

Every rule namespace is converted to a tag the way Synapse normalizes tags (`rules.nsTag()`):
the namespace is split on `/`, each part is lower-cased and its runs of `\w` characters joined
with `_` (Synapse's `tagpartre`), and empty parts are dropped.

| Namespace | Tag (without the prefix) |
| --- | --- |
| `host-interaction/process/create` | `host_interaction.process.create` |
| `anti-analysis/anti-debugging` | `anti_analysis.anti_debugging` |
| `Data-Manipulation//Encoding ` | `data_manipulation.encoding` |
| (none) | no tag |

Library rules and rules without a namespace don't add a tag.

### Tag prefix and settings

Two Cortex globals, set by [`slib.capa.admin.tags`](commands.md#slibcapaadmintags):

| Global | Default | Meaning |
| --- | --- | --- |
| `slib:capa:tag:prefix` | `rep.capa` | The prefix every namespace tag is under. |
| `slib:capa:tag:enabled` | `true` | Whether scans tag files. |

### Tag docs

Every namespace of a non-library rule, every namespace above it, and the prefix itself are a
`syn:tag` with a `:title` and `:doc` (`CapaRules.tagRecords()`):

| `syn:tag` | `:title` | `:doc` |
| --- | --- | --- |
| `<prefix>` | `capa` | `Files that matched capa rules (capa-rules <version>). Each tag below this one is a capa rule namespace, ex. anti-analysis/anti-debugging is anti_analysis.anti_debugging.` |
| `<prefix>.<tag>` | `capa: <namespace>` | `Files that matched a capa rule in the <namespace> namespace.` |

Each `:doc` is followed by `Rules:` and a list of the rules directly in the namespace, and (for
namespaces other than the prefix) `Plus <n> rules in the namespaces below this one.` when
there are rules further down. For example:

```text
Files that matched a capa rule in the testing/ops/xor namespace.

Rules:
- contain xor
```

Tag docs are imported with the rules, and again when the tag prefix changes. The last import
is the global `slib:capa:sync:tags` (`<prefix>:<sync key>`). They are imported even when
tagging is disabled. Custom rule namespaces don't get tag docs.

## Scan results

Scanning a `file:bytes` (`slib.capa.model.results()`):

1. **Removes the earlier results**: every `-(matches)>` edge to the file from a `meta:rule`
   with a `:type` of `capa` or below it (`+:type^=capa.`, so `capa`, `capa.lib`, `capa.custom...`,
   but not ex. `capability`), and the tags the earlier scan applied (from its node data,
   whatever the settings are now). Their parent tags up to the root (ex. `rep.capa`, `rep`) are
   removed too, deepest first, only when no other tag is left below them. Other tags are left
   alone, even under a shared prefix.
2. **Adds** `meta:rule -(matches)> file:bytes` for every matched rule.
3. **Tags** the file `<prefix>.<rule tag>` for every matched rule with a tag, unless tagging is
   disabled.
4. **Saves** the results in the `slib:capa` node data, and adds `meta:source -(seen)>`.

The matches are what capa itself reports: library rules and subscope rules (rules capa
generated from parts of other rules) are left out. Rules in internal namespaces are reported,
ex. `#rep.capa.internal.limitation.file` means capa found the file is packed or an installer,
so its results may be incomplete.

### file:bytes node data

The `slib:capa` node data of a scanned file:

```json
{
  "time": 1763520000000,
  "capa": "10.0.0",
  "rules": {"version": "v10.0.0", "sha256": "<rules sha256>", "custom": null},
  "flavor": "static",
  "format": "sc64",
  "arch": "amd64",
  "os": "windows",
  "extractor": "VivisectFeatureExtractor",
  "options": {"format": "sc64", "os": "auto"},
  "matches": [
    {
      "rule": "contain xor",
      "guid": "<meta:rule guid>",
      "namespace": "testing/ops/xor",
      "count": 1,
      "addrs": ["0x690000"]
    }
  ],
  "prefix": "rep.capa",
  "tags": ["rep.capa.testing.ops.xor"]
}
```

| Key | Meaning |
| --- | --- |
| `time` | When the service summarized the results (epoch millis). |
| `capa` | capa's version, from its result document. |
| `rules` | The official rules' version and SHA256, and the custom rules key (or `null`). |
| `flavor`, `format`, `arch`, `os`, `extractor` | What capa detected or used (`meta.flavor`, `meta.analysis.*`). |
| `options` | The `--format` and `--os` the scan asked for. Missing in results from older versions, which count as `auto`. |
| `matches` | Every reported rule: its name, `meta:rule` guid, namespace, match count, and up to 100 match addresses. |
| `prefix` | The tag prefix the scan used, `null` when tagging was disabled. |
| `tags` | The tags this scan applied, for the next scan to remove. |

Addresses are formatted by `fmtAddr()`: an absolute address is hex (`0x401000`), other address
kinds are `<kind>:<hex>` or `<kind>:<json>` (ex. a process or call address), and file scope
matches (`no address`) are left out of `addrs` but still counted in `count`.

## Idempotency

| What | How |
| --- | --- |
| Rules | Fixed guids from the name, rulesets from the version. Imports are skipped when the sync key is unchanged. |
| MBC techniques | Guid ctors on `:ext:id` + `:reporter:name`. `:name` is only set when missing. |
| Contacts | Guid ctors on the normalized author. |
| Tag docs | Skipped when `<prefix>:<sync key>` is unchanged. |
| Scans | Skipped when the file's node data matches the current rules SHA256, custom key, options and prefix. A scan replaces the previous scan's edges and tags, so results never accumulate. |
