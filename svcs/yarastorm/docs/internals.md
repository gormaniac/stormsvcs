# Internals

## Source layout

| Path | What |
| --- | --- |
| {src}`svcs/yarastorm/src/yarastorm/__init__.py` | `__version__` and `YaraSvc` export |
| {src}`svcs/yarastorm/src/yarastorm/__main__.py` | `python -m yarastorm <dirn>` runs `YaraSvc.execmain()` |
| {src}`svcs/yarastorm/src/yarastorm/defs.py` | Package constants, the `SlibYaraPkg` `StormPkg`, `PKGDEFS` |
| {src}`svcs/yarastorm/src/yarastorm/api.py` | `YaraApi`, the Telepath API |
| {src}`svcs/yarastorm/src/yarastorm/svc.py` | `YaraSvc` (the Cell), `YaraRules` (rule storage), `isRuleId()`, result types |
| {src}`svcs/yarastorm/src/yarastorm/pkgproto/` | The `slib.yara` Storm package: `slib.yara.yaml`, `storm/commands/*.storm`, `storm/modules/*.storm`, `README.md` |
| {src}`svcs/yarastorm/tests/test_yarastorm.py` | Tests |

## defs.py

| Name | Value |
| --- | --- |
| `SVC_NAME` | `slib.yara` (service and package name) |
| `SVC_VER` | `__version__` |
| `SVC_GUID` | `12bc0c8c1a37a29808d97972875d3913` (`meta:source` guid) |
| `ADMIN_PERM` | `("slib", "yara", "admin")` |
| `SVC_EVTS` | the `add` event Storm that creates the `meta:source` |
| `SlibYaraPkg` | `StormPkg` subclass with `proto_name = "slib.yara"` |
| `PKGDEFS` | `(SlibYaraPkg().asdict(),)` |

`SlibYaraPkg()` loads `pkgproto/slib.yara.yaml` with Synapse's `genpkg` loader at import time
(`genopts.dotstorm: true` pulls in the `.storm` files, `docs` pulls in `README.md`) and syntax
checks all of the Storm. A Storm syntax error therefore fails at import, before the service
starts.

## svc.py

### Constants and types

- `RULE_FORM = "it:app:yara:rule"`.
- `AXON_TIMEOUT = 10`: seconds to wait for the Axon Telepath connection per scan.
- `isRuleId(rule_id)`: `True` only for a `str` that passes `synapse.common.isguid()`. Rule IDs
  are file names, so this is what stops path traversal (`../x`, `/etc/passwd`, ...).
- `YaraMatch` (`TypedDict`): `rule: str`, `sha256: str`, `matched: bool`.
- `MatchRetn(TelepathRetn)`: `data: YaraMatch | None`.

### YaraRules

Rule storage. `YaraRules(ruledir)` creates `ruledir` (`os.makedirs(exist_ok=True)`) and loads it.

| Member | Behaviour |
| --- | --- |
| `rules: dict[str, yara_x.Rules]` | The in-memory rule set, keyed by guid. Scans iterate this dict. |
| `load()` | For each entry in `ruledir`: skip names that aren't a guid, skip anything that isn't a regular file (sub directories), `load_rule()` the rest. |
| `load_rule(rpath)` | `yara_x.Rules.deserialize_from()`; stored under the file's basename. A missing file is ignored; any other error is logged as `Skipping unreadable compiled Yara rule <path>: <error>` (WARNING) and skipped. |
| `get(rule_id)` | `None` for a non-guid; otherwise loads from disk on demand if not in memory, and returns the rule or `None`. Never raises. |
| `add(rule_id, compiled)` | `BadArg` for a non-guid. Serializes to a `mkstemp(prefix=".tmp-")` file in `ruledir`, then `os.replace()`s it over `ruledir/<guid>`, so a crash can't leave a partial rule (and `.tmp-*` names are never loaded as rules). The temp file is removed on any failure. |
| `remove(rule_id)` | `BadArg` for a non-guid. Pops from memory and deletes the file; returns whether it existed in either place. |

On-disk format: one file per rule, the Yara-X serialized form of the compiled `:text`. There is
no index or metadata file; the file name is the only link to the Cortex node.

### YaraSvc

`YaraSvc(s_cell.Cell)`, `cellapi = YaraApi`. `confdefs` are documented in
[Deployment](deployment.md#cell-configuration).

`__anit__`:

1. Reads `axon_url` into `self.axonurl` and `max_size` into `self.maxsize`.
2. `self.rules = YaraRules(absjoin(self.dirn, rule_dir))`. `os.path.join` with an absolute
   `rule_dir` discards `dirn`, which is why absolute paths are used as is.
3. With `axon_url`: one long-lived `synapse.telepath.Client` (`self.axon`), which reconnects on
   its own, torn down with the cell (`onfini`). Without it: logs
   `The yarastorm service has no axon_url configured, slib.yara.scan will not be able to scan
   files.` at WARNING.

There are no background tasks, loops, slabs, or Axon writes.

`_getBytes(sha256)`:

1. `BadArg` if there's no Axon client, or `sha256` isn't a 64 character hex string.
2. `await self.axon.proxy(timeout=AXON_TIMEOUT)`; a `TimeoutError` propagates.
3. With `max_size` set: `axon.size()` first. `None` (missing) returns `None`; a size over the
   limit raises `BadArg`. Without `max_size` there's no size call.
4. Reads the whole file with `axon.get()` into memory and joins the chunks. `NoSuchFile` or zero
   chunks (an empty file) returns `None`.

The whole file is held in memory for the scan, so `max_size` is effectively the per-scan memory
bound.

`matchFile(sha256)`: maps `_getBytes` errors to one file-level `MatchRetn`
(`TimeoutError` -> `Unable to connect to the Axon within 10 seconds.`, `SynErr` -> its `mesg`,
anything else -> `Unable to read the file from the Axon: <error>`; `CancelledError` is
re-raised), and `None` to `Bytes for file:bytes:sha256=<sha256> are not in the Axon.`. It then
iterates a snapshot (`list(self.rules.rules)`) of the rule IDs and runs
`rule.scan(file_bytes)` for each, synchronously on the event loop, with yara-x's default scan
settings (no timeout set). Each rule is a separately compiled `yara_x.Rules`, so a file is
scanned once per enabled rule node.

`compileRule()`, `removeRule()`, `listRules()`, `getRuleCount()`: see [API](api.md#telepath-api).
`compileRule` unpacks the node with `stormlibpp.node.StormNode.unpack()`; a missing prop reads
as `None`, which is how a rule without `:text` is detected.

## api.py

`YaraApi._denied()` checks `self.user.allowed(("slib", "yara", "admin"))` (the Telepath session's
service user) and returns the failure `BoolRetn`, or `None`. `compileRule` calls it only when
`check` is false; `removeRule` always. The other methods delegate directly. Because `YaraApi`
subclasses `RetnApi`, each public coroutine/generator it defines is wrapped by `_guard()`, so a
raised exception becomes a `status=False` return (see
[StormLib++](https://docs.gormo.co/stormlibpp/)). `_retnRedact()` isn't overridden; there are no
secrets in the service's messages.

## Upstream

The only "upstream" is the Axon, over Telepath:

| Call | When |
| --- | --- |
| `Client.proxy(timeout=10)` | every `matchFile` |
| `axon.size(sha256 bytes)` | every `matchFile`, only when `max_size` is set |
| `axon.get(sha256 bytes)` | every `matchFile` that passes the size check |

There are no retries (beyond the client's own reconnect), no pagination, no caching of file
bytes, and no rate limits. Authentication is whatever is in `axon_url`.

## Storm package

`slib.yara.yaml`:

- `name: slib.yara`, `guid: f418c8589b13201801b9a4bf2b4f7842`, `version` (matches the service),
  `synapse_version: ">=2.248.0,<3.0.0"`.
- `perms`: one, `slib.yara.admin` with `gate: cortex`.
- `modules`: `slib.yara.lib`, `slib.yara.ingest`. No `onload`, no `configvars`.
- `commands`: `slib.yara.scan` (`cmdinputs: file:bytes`), `slib.yara.check`, `slib.yara.enable`,
  `slib.yara.disable` (`cmdinputs: it:app:yara:rule`), `slib.yara.sync` (none). No `cmdargs`.
- `docs`: the package's `README.md`, a copy of the service README (a test enforces they match).

Command structure: each command has an `init` block that imports `slib.yara.lib` (and
`slib.yara.ingest` for scan), and the admin commands evaluate
`$lib.auth.users.get().allowed(slib.yara.admin)` once there. The node body then
`switch`es on `$node.form()` and warns on unsupported forms. `slib.yara.sync` does all of its work
in `init`.

Permission enforcement happens twice for rule changes: in Storm (`slib.yara.admin` on the Cortex
user, warn in commands, `AuthDeny` in `slib.yara.lib`) and in the service (`slib.yara.admin` on
the service user, `status=False`).

## Tests

```bash
cd svcs/yarastorm && uv run pytest
```

`tests/conftest.py` loads the `stormlibpp.testing` plugin, which fails any test that triggers a
Synapse deprecation; `pyproject.toml` also turns `DeprecationWarning`s from `yarastorm` into
errors. See {doc}`/dev/testing`.

There are no fakes and no live tests: the upstream is a real Axon from Synapse's
`getTestAxon()`, filled with `axon.put()`, and the Cortex/service pair comes from
`getTestCoreProxSvc(YaraSvc, ssvc_conf=...)`. What's covered:

| Area | Tests |
| --- | --- |
| Packaging | README copies match, versions match in all four places (`assertVersionsMatch`), `python -m yarastorm --help` starts (`assertMainHelp`), package loads, commands and modules exist, `cmdinputs` forms exist, `$srcguid` equals `SVC_GUID`, `add` event creates the `meta:source` |
| Commands | check / enable / disable / sync / scan happy paths and wrong-form warnings; `$lib.debug` output; sync counts (`1 compiled, 1 removed, 1 failed`) and `:text` pickup; scanning a `guid:` `file:bytes`; missing `:sha256` |
| Errors | missing / empty file, unloadable rule, no `axon_url`, unreachable Axon (patched `AXON_TIMEOUT`), bad sha256, `max_size` exceeded, unexpected exceptions through `RetnApi` |
| Permissions | Cortex user without `slib.yara.admin` (warnings, `AuthDeny` from the module), service user without `slib.yara.admin` (`compileRule`/`removeRule` denied, check and reads allowed) |
| Storage | persistence across `YaraRules` instances, atomic write, on-demand load, corrupt / non-guid / sub-directory files skipped, path traversal refused, service starts with a corrupt rule file |

CI also runs the tests inside the test image built from the production image, and Synapse's
Storm linter over `src/`; see {doc}`/dev/ci` and {doc}`/dev/contract`.
