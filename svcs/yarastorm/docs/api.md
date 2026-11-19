# API

## Storm modules

The package has two modules. Import them with `$lib.import()`.

### slib.yara.lib

{src}`svcs/yarastorm/src/yarastorm/pkgproto/storm/modules/slib.yara.lib.storm`. Its `init` block
binds `$svc = $lib.service.get(slib.yara)`, so importing it requires `service.get` on the service.
Functions that change the service's rules call `reqAdmin()` first and **raise** `AuthDeny`
(`Changing the slib.yara rules requires the slib.yara.admin permission.`) instead of warning, so
they're safe to call from automation. The rest return the service's `TelepathRetn` unchanged.

| Function | Args | Returns | Notes |
| --- | --- | --- | --- |
| `reqAdmin()` | none | `$lib.null` | Raises `AuthDeny` unless the current user has `slib.yara.admin`. |
| `getEnabledRules()` | none | generator of nodes | Emits every `it:app:yara:rule:enabled=(true)` node. |
| `match(sha256)` | `sha256`: hex str | generator of `TelepathRetn` | `$svc.matchFile($sha256)`. |
| `compile(rule, check=(false))` | `rule`: `it:app:yara:rule` node, `check`: bool | `TelepathRetn` | `$svc.compileRule($rule.pack(), $check)`. No admin check here; with `check=(false)` the service side still requires its own `slib.yara.admin`. |
| `ruleCount()` | none | `TelepathRetn`, `data` is an int | `$svc.getRuleCount()`. |
| `enableRule(rule)` | `rule`: node | `TelepathRetn` | `reqAdmin()`, compile and save, then `[ :enabled=(true) ]` on success. |
| `disableRule(rule)` | `rule`: node | `TelepathRetn` | `reqAdmin()`, `removeRule($rule.repr())`, then `[ :enabled=(false) ]` on success. |
| `sync()` | none | dict | `reqAdmin()`, then the reconcile described in [slib.yara.sync](commands.md#slibyarasync). Raises a `YaraError` (a `StormRaise` with `errname` `YaraError`, catch it with `catch YaraError as err`) if `listRules()` fails, after the enabled rules were compiled. |

`sync()` returns:

```json
{
  "compiled": 3,
  "failed": [{"rule": "<guid>", "mesg": "Yara Compile Error - ..."}],
  "removed": ["<guid>"]
}
```

Example from automation:

```text
$yara = $lib.import(slib.yara.lib)
$retn = $yara.sync()
if $retn.failed { $lib.warn(`{$lib.len($retn.failed)} rules failed to sync`) }

file:bytes=sha256:<hex>
for $r in $yara.match(:sha256) {
    if ($r.status and $r.data.matched) { $lib.print($r.data.rule) }
}
```

### slib.yara.ingest

{src}`svcs/yarastorm/src/yarastorm/pkgproto/storm/modules/slib.yara.ingest.storm`. Sets
`$srcguid = "12bc0c8c1a37a29808d97972875d3913"`.

| Function | Args | Returns | Notes |
| --- | --- | --- | --- |
| `ruleVersion(rule)` | `rule`: `it:app:yara:rule` guid | the rule's `:version`, or `$lib.null` | `$lib.null` if the rule has no `:version` or doesn't exist. |
| `yaraMatch(rule, file)` | `rule`: `it:app:yara:rule` guid, `file`: `file:bytes` value (its repr) | `$lib.null` | Creates `it:app:yara:match=($rule, $file)` with `.seen=now`, `:version` set to `ruleVersion($rule)` when it isn't `$lib.null`, and a `seen` edge from the service's `meta:source`. See [Data Model](model.md). |

## Telepath API

`yarastorm.api.YaraApi` ({src}`svcs/yarastorm/src/yarastorm/api.py`) subclasses
`stormlibpp.svc.RetnApi`, `synapse.lib.cell.CellApi` and `synapse.lib.stormsvc.StormSvc`. It
declares:

| Attribute | Value |
| --- | --- |
| `_storm_svc_name` | `slib.yara` |
| `_storm_svc_vers` | the package version as a tuple, ex. `(0, 8, 1)` |
| `_storm_svc_evts` | `{"add": {"storm": "[(meta:source=12bc0c8c1a37a29808d97972875d3913 :name=slib.yara)]"}}` |
| `_storm_svc_pkgs` | the `slib.yara` package definition (`PKGDEFS`) |
| `RETN_METHS` / `GENR_METHS` | empty (all methods are hand-written) |
| `RETN_ERRORS` | default, `(SvcError,)` |

Every method is hand-written because the cell methods build their own `TelepathRetn`s and some
add a permission check. `RetnApi` still guards each one, so an unexpected exception becomes a
`status=False` return instead of reaching Storm.

### The TelepathRetn convention

Every method returns (or yields) a `stormlibpp.telepath.TelepathRetn` dict:

| Key | Type | Meaning |
| --- | --- | --- |
| `status` | bool | `true` on success. |
| `mesg` | str | Error message when `status` is `false`; usually `""` on success. |
| `data` | any | The result. Usually `false`/`None` on failure, except `matchFile` per-rule errors (below). |

Errors the service code catches itself are returned with their own messages (listed below). An
exception that escapes a method is turned into a return by `RetnApi`:

| Exception | `mesg` |
| --- | --- |
| `SvcError` or `AuthDeny` | the error's own message |
| `ValueError`, `TypeError`, `BadArg` | `Invalid input: <message>` |
| anything else | `Unexpected error: <Type>: <message>` (also logged with a traceback as `Unexpected error in YaraApi.<method>.`) |

For a generator, an escaping exception yields one `status=False` item (`data: None`) and ends
the generator.

### Permission check

`compileRule` (without `check`) and `removeRule` require the **service-side** Telepath user to be
allowed `slib.yara.admin`. If not, they return:

```json
{"status": false, "mesg": "The service user <name> needs the slib.yara.admin permission.", "data": false}
```

### compileRule

```python
compileRule(yara_rule: NodeTuple, check: bool = False) -> BoolRetn
```

`yara_rule` is a packed node (`$node.pack()`). Compiles `props["text"]` with `yara_x.compile()`;
with `check=False` also saves it as `rule_dir/<guid>` and loads it for scans, replacing any
previous version.

| Result | `status` | `mesg` | `data` |
| --- | --- | --- | --- |
| Saved | `true` | `""` | `true` |
| Checked (`check=True`) | `true` | `Successfully compiled rule!` | `true` |
| Not a packed node | `false` | `Invalid packed node.` | `false` |
| Wrong form | `false` | `Expected an it:app:yara:rule node, got <form>.` | `false` |
| Primary value not a guid | `false` | `Invalid it:app:yara:rule guid: '<valu>'` | `false` |
| No `:text` | `false` | `it:app:yara:rule=<guid> has no :text to compile.` | `false` |
| Compile error | `false` | `Yara Compile Error - <yara_x.CompileError>` | `false` |
| Write failed | `false` | `Unable to save the rule: <error>` | `false` |
| Not allowed (`check=False`) | `false` | `The service user <name> needs the slib.yara.admin permission.` | `false` |

### removeRule

```python
removeRule(rule_id: str) -> BoolRetn
```

Removes `rule_dir/<rule_id>` and the in-memory copy. `data` is whether the service had the rule;
removing an unknown rule is a success with `data: false`.

| Result | `status` | `mesg` | `data` |
| --- | --- | --- | --- |
| Removed | `true` | `""` | `true` |
| Not present | `true` | `""` | `false` |
| Not a guid | `false` | `Invalid it:app:yara:rule guid: '<valu>'` | `false` |
| OS error | `false` | `Unable to remove the rule: <error>` | `false` |
| Not allowed | `false` | `The service user <name> needs the slib.yara.admin permission.` | `false` |

### listRules

```python
listRules() -> ListRetn
```

```json
{"status": true, "mesg": "", "data": ["<guid>", "<guid>"]}
```

The sorted guids of the rule files in `rule_dir`, read from disk on every call (rule files
added or removed outside the service are reflected). Includes rule files that can't be loaded, so
`slib.yara.sync` can recompile or remove them. No permission needed.

### getRuleCount

```python
getRuleCount() -> TelepathRetn
```

```json
{"status": true, "mesg": "", "data": 2}
```

The number of rules that loaded (the ones scans use), read from disk on every call like
`listRules`. Rule files that can't be loaded aren't counted.

### matchFile

```python
matchFile(file_sha256: str) -> AsyncGenerator[MatchRetn]
```

A generator. Pulls the file from the Axon, then brings the in-memory rules in line with the
rule files in `rule_dir` (see [Internals](internals.md#yararules)), yields one `status=false`
result per rule file that can't be loaded, then one `MatchRetn` per loaded rule. Each rule's scan
runs in a worker thread (off the event loop) with a `scan_timeout` second yara-x timeout. Never
raises.

`data` is a `YaraMatch` for per-rule results, or `None` for a file-level error (which is the only
item yielded):

```text
{"status": true, "mesg": "", "data": {"rule": "<guid>", "sha256": "<hex>", "matched": true}}
{"status": false, "mesg": "Error scanning with it:app:yara:rule=<guid>: <error>",
 "data": {"rule": "<guid>", "sha256": "<hex>", "matched": false}}
{"status": false, "mesg": "Bytes for file:bytes:sha256=<hex> are not in the Axon.", "data": null}
```

Per-rule error messages:

- `Couldn't load it:app:yara:rule=<guid> from the service's storage: <error>` - the rule file is
  corrupt or from an incompatible `yara-x`. `slib.yara.sync` recompiles (or removes) it.
- `Scanning with it:app:yara:rule=<guid> timed out after <n> seconds (scan_timeout).`
- `Error scanning with it:app:yara:rule=<guid>: <error>`

File-level messages are listed under [slib.yara.scan](commands.md#slibyarascan). With zero rules
loaded and a readable file, the generator yields nothing.

`matched` is `true` when the compiled `:text` has at least one matching rule
(`bool(scanner.scan(bytes).matching_rules)`). Which Yara rules or strings matched is not
returned.
