# API

The service has two APIs: the Storm module `slib.capa.lib`, for Storm code that wants to scan
without the command, and the Telepath API the Storm package calls.

## Storm module API

### slib.capa.lib

{src}`svcs/capa/src/capasvc/pkgproto/storm/modules/slib.capa.lib.storm`. Importing it requires
`slib.capa.user` (through the `slib.capa.priv.user` module it imports). Errors are reported as
warnings, and the functions return `null` (or emit nothing) instead of raising.

```text
$capa = $lib.import(slib.capa.lib)
file:bytes=<sha256>
for $rule in $capa.scan($node, fmt=sc64) { $lib.print($rule.props.name) }
```

| Function | Returns | Meaning |
| --- | --- | --- |
| `info()` | dict or `null` | The service's rules info (see [`rulesInfo()`](#rulesinfo)), or `null` (with a warning) if the rules aren't loaded. |
| `customNodes()` | emits nodes | The view's custom rule nodes: `meta:rule:type^=capa.custom. +:text`. |
| `customInfo()` | dict or `null` | Sends the view's custom rules to the service's [`custom()`](#custom) and returns its result. Warns about every skipped rule. `null` if there are none or the call failed. |
| `customKey()` | str or `false` | The key of the view's custom rules, `false` if there are none to use. |
| `scanned(file, rinfo=(null), custom=(false), fmt=auto, osname=auto)` | bool | Whether a `file:bytes` was already scanned with these rules (`rinfo`, looked up if `null`), this custom key (`false` for none), options, and the current tag prefix. |
| `scan(file, fmt=auto, osname=auto, force=(false), rinfo=(null), custom=(null))` | emits nodes | Scan a `file:bytes` and model the results. Emits the matched `meta:rule` nodes. |

`scan()`'s `custom` argument is the key of the custom rules to use (from `customKey()`),
`false` for none, or `null` to look up the view's custom rules. That lookup is done once per
import of the module, so import it before lifting the files: edits to the custom rules during
the query aren't used until the next one.

The other modules are internal. Synapse doesn't check permissions when a module is imported
(a module's `perms` key isn't enforced, so the package doesn't set one): the unprivileged
modules are gated by the commands' `perms` and by the `priv` module each one imports.

| Module | Privilege | Contents |
| --- | --- | --- |
| `slib.capa.priv.user` | `asroot:perms` `slib.capa.user` | Wrappers around `$lib.service.get("slib.capa")`: `rulesInfo()`, `tags()`, `scan()`, `custom()`, `rules()`, and the tag settings and sync state globals (`tagSettings()`, `tagPrefix()`, `syncState()`). |
| `slib.capa.priv.admin` | `asroot:perms` `slib.capa.admin` | `setTagPrefix()`, `setTagsEnabled()`, `setSynced(kind, valu)`, `reload()`, and the read-only calls the admin commands need, from `slib.capa.priv.user` (imported as root): `tagSettings()`, `syncState()`, `rulesInfo()`, `tags()`, `rules()`. Not `scan()` or `custom()`. |
| `slib.capa.model` | none (runs as the caller) | The node edits, see [Data model](model.md). |
| `slib.capa.sync` | none | `onload()`, `sync()`, `syncRules()`, `syncTags()`, the rule and tag doc import. Only uses `slib.capa.priv.admin`. |
| `slib.capa.contacts` | none | The contact migration used by `slib.capa.admin.contacts.migrate`. |
| `slib.capa.util` | none | `failed(retn, what)` (warn on a failed call) and `nodes(items)`. |

## Telepath API

The `CellApi` is `CapaCellApi` in {src}`svcs/capa/src/capasvc/api.py`:

```python
class CapaCellApi(RetnApi, s_cell.CellApi, s_stormsvc.StormSvc):
    RETN_METHS = ("scan", "rulesInfo", "tags", "reload", "custom")
    GENR_METHS = ("rules",)
    RETN_ERRORS = (CapaSvcError, CapaRulesError)

    _storm_svc_name = "slib.capa"
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS   # the "add" event that creates the meta:source
    _storm_svc_pkgs = PKGDEFS    # the slib.capa Storm package
```

### TelepathRetn

Every method returns a `TelepathRetn` dict (from `stormlibpp.telepath`), and the generator
yields them. No method raises over Telepath
([StormLib++ `RetnApi`](https://docs.gormo.co/stormlibpp/), see {doc}`/dev/architecture`):

```json
{"status": true, "mesg": "", "data": "<the result>"}
{"status": false, "mesg": "Invalid SHA256: newp", "data": null}
```

| Error raised in the cell | `mesg` |
| --- | --- |
| `CapaSvcError`, `CapaRulesError` (`RETN_ERRORS`), or a Synapse `AuthDeny` | The error's own message. |
| `ValueError`, `TypeError`, `BadArg` | `Invalid input: <error>` |
| Anything else | `Unexpected error: <type>: <error>`, logged with its traceback. |

The generator yields one `status=False` item and stops at the first error. No redaction is
configured (`_retnRedact()` isn't overridden): the service has no secrets of its own.

Storm calls them through `slib.capa.priv.user` and checks `status` with `slib.capa.util.failed()`.

### scan

```python
scan(sha256: str, fmt: str = "auto", osname: str = "auto", custom: str | None = None) -> dict
```

Pull a file from the Axon, run capa on it, and return a summary of the results.

| Arg | Meaning |
| --- | --- |
| `sha256` | The file's SHA256. Stripped and lower-cased, must be 64 hex characters. |
| `fmt` | `auto`, `pe`, `dotnet`, `elf`, `sc32` or `sc64` (`FORMATS`). |
| `osname` | `auto`, `windows`, `linux` or `macos` (`OSES`). |
| `custom` | The key of a custom rule set from [`custom()`](#custom), to scan with alongside the official rules. `None` or `""` for none. |

`data`:

```json
{
  "sha256": "<sha256>", "md5": "<md5>", "sha1": "<sha1>",
  "time": 1763520000000,
  "capa": "10.0.0",
  "rules": {"version": "v10.0.0", "sha256": "<rules sha256>", "custom": null},
  "flavor": "static",
  "format": "sc64",
  "arch": "amd64",
  "os": "windows",
  "extractor": "VivisectFeatureExtractor",
  "matches": [
    {"rule": {"...": "the rule record, see rules()"}, "count": 1, "addrs": ["0x690000"]}
  ],
  "options": {"format": "sc64", "os": "auto"}
}
```

`matches` is sorted by rule name and leaves out library and subscope rules. Each `rule` is the
official rule's record, the custom rule's record (when `custom` is given), or, as a safety net,
a record built from the source capa reported for a rule the service doesn't know. `addrs` has
at most 100 entries (`MAX_ADDRS`); `count` is the number of matches.

Errors (`mesg`):

| Message | When |
| --- | --- |
| `Invalid SHA256: <sha256>` | Not 64 hex characters. |
| `Invalid format <fmt>, expected one of: auto, pe, dotnet, elf, sc32, sc64` | Bad `fmt`. |
| `Invalid OS <os>, expected one of: auto, windows, linux, macos` | Bad `osname`. |
| `The custom rules key must be a string (see custom()).` | `custom` isn't a string. |
| The rules load error, ex. `The slib.capa service has no capa:rules directory configured.` | The rules aren't loaded. |
| `Unknown custom capa rules (the service restarted, reloaded its rules, or deleted the set), send them again with custom().` | The custom key isn't a current set. |
| `capa can't use the custom rules: <capa's error>` | capa couldn't load the official and custom rules together (retried after 60 seconds). |
| `The slib.capa service has no axon:url configured.` | No Axon. |
| `Unable to connect to the Axon within 30 seconds.` | |
| `The file <sha256> is not in the Axon.` | `axon.size()` returned `None`, or `NoSuchFile`. |
| `The file <sha256> is <size> bytes, more than the <max> byte max (capa:maxsize).` | |
| `Downloading <sha256> from the Axon took longer than <n> seconds (capa:timeout).` | |
| `Unable to read <sha256> from the Axon: <error>` | Any other Axon error. |
| `The capa rules on disk changed since the service loaded them, reload them with: slib.capa.admin.sync --reload` | The rule files changed after the load. |
| `The capa rules on disk can't be read: <error>` | |
| `capa took longer than <n> seconds (capa:timeout).` | The capa process was killed. |
| `<exit code message>: <capa's log>` | capa exited non-zero, see below. |
| `capa returned invalid JSON: <capa's log>` | |

capa exit codes (`EXIT_CODES`, capa's `E_*` constants) become these messages, followed by
capa's condensed stderr:

| Code | Message |
| --- | --- |
| 10 | `capa could not find its rules` |
| 11 | `capa could not find the file` |
| 12 | `capa found an invalid rule` |
| 13 | `The file is corrupt` |
| 14 | `capa can't analyze the file (ex. it's packed or an installer)` |
| 15 | `capa found an invalid FLIRT signature` |
| 16 | `The file is not a format capa supports` |
| 17 | `The file is for an architecture capa doesn't support` |
| 18 | `The file is for an OS capa doesn't support` |
| 25 | `The input format is invalid` |
| 26 | `capa couldn't load a feature extractor for the file` |
| other | `capa failed (exit code <n>)` |

### rulesInfo

```python
rulesInfo() -> dict
```

A summary of the loaded rules and capa:

```json
{
  "path": "/opt/stormsvcs/capa/rules",
  "version": "v10.0.0",
  "sha256": "<sha256 of the rule paths and contents>",
  "key": "<sync key guid>",
  "ruleset": "<meta:ruleset guid>",
  "rules": 1000,
  "lib": 100,
  "namespaces": 300,
  "capa": "10.0.0"
}
```

`rules` counts every rule (library rules included), `lib` the library rules, `namespaces` the
distinct namespaces of non-library rules that make a tag. `key` is
`guid((sha256, version, capa:rules:url, MODEL_VERSION))`, see
[When rules are imported](model.md#when-rules-are-imported). Fails with the rules load error
when the rules aren't loaded.

### rules

```python
rules(names: list[str] | None = None) -> AsyncIterator[dict]   # generator
```

Yields the record of every rule (or the named ones), sorted by name. Errors:
`Rule names must be a list of strings.`, `Unknown capa rules: <names>`, or the rules load
error. A record (`rules.ruleRecord()`):

```json
{
  "guid": "<guid(('slib.capa', 'rule', name))>",
  "name": "contain slib-capa test marker",
  "namespace": "testing/slib-capa",
  "tag": "testing.slib_capa",
  "lib": false,
  "type": "capa",
  "custom": false,
  "desc": "<Markdown summary>",
  "text": "<the rule's YAML>",
  "path": "testing/contain-marker.yml",
  "url": "https://github.com/mandiant/capa-rules/blob/v10.0.0/testing/contain-marker.yml",
  "authors": [{"email": "test@example.com"}, {"user": "visi"}],
  "techniques": ["T1027", "T1059.001"],
  "mbc": [
    {"id": "B0032", "name": "Executable Code Obfuscation", "parent": null},
    {"id": "B0001.025", "name": "Software Breakpoints",
     "parent": {"id": "B0001", "name": "Debugger Detection", "parent": null}}
  ],
  "meta": {"...": "the rule's full meta, JSON-safe"}
}
```

`tag` is `null` for library rules and rules without a namespace. Custom rule records have the
custom node's guid, `"type": "capa.custom"`, `"custom": true`, and no `path` or `url`.

### tags

```python
tags() -> list[dict]
```

The tag record of the prefix, every namespace, and every namespace above them, sorted by tag:

```json
[
  {"tag": "", "namespace": "", "title": "capa", "doc": "Files that matched capa rules ..."},
  {"tag": "testing.ops.xor", "namespace": "testing/ops/xor",
   "title": "capa: testing/ops/xor",
   "doc": "Files that matched a capa rule in the testing/ops/xor namespace.\n\nRules:\n- contain xor"}
]
```

`tag` is relative to the prefix (`""` is the prefix itself). See [Tag docs](model.md#tag-docs).

### reload

```python
reload() -> dict
```

Reload the rules from `capa:rules` (and `capa:rules:version`, `capa:rules:url`), clear the
custom rule sets, and start building capa's cache of the new rules in the background. Returns
the new rules' info, the same as [`rulesInfo()`](#rulesinfo) (with the `capa` key). Fails with the load error,
and the service then has no rules until a reload succeeds:

| Message | Cause |
| --- | --- |
| `The slib.capa service has no capa:rules directory configured.` | `capa:rules` unset. |
| `The capa rules directory <path> does not exist.` / `... has no rules.` | |
| `Unable to read the capa rules directory <path>: <error>` / `Unable to read the capa rule <path>: <error>` | OS or UTF-8 errors. |
| `Invalid capa rule <path>: <error>` | capa can't parse a rule. |
| `Duplicate capa rule name '<name>' in <path> and <path>.` | |
| `Invalid capa:rules:url '<template>', it may only use {version} and {path}: <error>` | |

### custom

```python
custom(rules: list[dict]) -> dict
```

Check a set of custom rules, each `{"guid": <meta:rule guid>, "text": <YAML>}`, save them for
scans, and return:

```json
{
  "key": "<sha256 of the usable rules, or null>",
  "rules": [{"guid": "<guid>", "name": "my capa rule"}],
  "errors": [{"guid": "<guid>", "mesg": "Invalid capa rule: ..."}],
  "shadowed": [{"guid": "<guid>", "name": "create process on Windows"}]
}
```

`key` is `null` when no rule can be used. Errors: `Custom rules must be a list of {guid, text}
dicts.` or the rules load error. See [Custom rules](custom-rules.md) for the checks.
