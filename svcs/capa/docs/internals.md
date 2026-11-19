# Internals

This page walks through the source of `capasvc` and the `slib.capa` Storm package. For the
shape every service shares, see {doc}`/dev/architecture`.

## Python modules

| Module | Contents |
| --- | --- |
| {src}`svcs/capa/src/capasvc/__init__.py` | `__version__` (`<version>`) and the `CapaSvc` export. |
| {src}`svcs/capa/src/capasvc/__main__.py` | `asyncio.run(CapaSvc.execmain(sys.argv[1:]))`, the entry point (`python -m capasvc <dirn>`). |
| {src}`svcs/capa/src/capasvc/defs.py` | `SVC_NAME` (`slib.capa`), `SVC_GUID` (the `meta:source` guid), `RULES_VERSION` (`v10.0.0`), `RULES_URL`, `SVC_EVTS` (the `add` event), and `SlibCapaPkg`, a `stormlibpp.StormPkg` that loads `pkgproto/slib.capa.yaml` into `PKGDEFS`. |
| {src}`svcs/capa/src/capasvc/api.py` | `CapaSvcError` and `CapaCellApi`, see [API](api.md#telepath-api). |
| {src}`svcs/capa/src/capasvc/svc.py` | `CapaSvc`, the Cell: config, rule loading, the capa cache, the custom rule sets, and scanning. |
| {src}`svcs/capa/src/capasvc/rules.py` | Loading a rules directory (`CapaRules`), and building the rule and tag records. |
| {src}`svcs/capa/src/capasvc/custom.py` | `CustomRules`, a checked set of custom rules saved to disk. |

### rules.py

`CapaRules(path, version, urlfmt)` loads a rules directory (in an executor thread, from
`CapaSvc.reload()`):

1. `checkUrlFmt()` formats `urlfmt` with dummy `version` and `path`; any other field (or a bad
   template) raises `CapaRulesError`.
2. `load()` takes a `rulesStat()` fingerprint first (so a change while reading shows up as a
   new stat), reads every rule file found by `capa.rules.collect_rule_file_paths()` as UTF-8
   (`readRules()`, sorted by relative path), and parses each with
   `capa.rules.Rule.from_yaml()`. Any unreadable or invalid rule, or a duplicate name, fails
   the whole load.
3. It stores `rules` (name to record), `sha256` (`hashRules()`: SHA256 over every
   `relpath\0text\0`), `stat`, and `cacheId`, capa's own cache identifier for these rule
   texts (`capa.rules.cache.compute_cache_identifier()`).

Helpers that build the records:

| Function | Does |
| --- | --- |
| `ruleGuid(name)` / `rulesetGuid(version)` | `s_common.guid(("slib.capa", "rule", name))` / `(("slib.capa", "ruleset", version))`. |
| `tagPart(text)` / `nsTag(namespace)` | Synapse's tag part normalization (`"_".join(tagpartre.findall(text.lower().strip()))`) without building a data model; a namespace's parts joined with `.`. |
| `contact(author)` | The `ps:contact` guid ctor for an author (email, `@handle`, or name). |
| `techniques(attack)` | ATT&CK IDs from `att&ck` entries. |
| `mbc(entries)` | MBC `{id, name, parent}` records. |
| `ruleDoc(meta)` | The Markdown `:desc`. |
| `ruleMeta(meta)` | A JSON-safe copy of the meta (for node data). |
| `ruleRecord(...)` | The full record, see [`rules()`](api.md#rules). |
| `rulesStat(path)` | SHA256 of every rule file's path, size and `st_mtime_ns`: a cheap "did anything change" check that doesn't read the rules. |

`CapaRules.info()` builds the rules info (the sync `key` includes `MODEL_VERSION = 3`; bump it
when what the package models from a rule changes, so the next package load re-imports the
rules). `namespaces()` and `tagRecords()` build the tag docs.

### custom.py

`CustomRules(official, rules, rootdir)` checks each `{guid, text}` (see
[Custom rules](custom-rules.md)), computes the set's `key` (SHA256 over sorted
`guid\0text\0`), writes the set to `rootdir/<key>/` (`_save()`: a `<key>.<uuid>.tmp`
directory renamed into place; if another registration won the race, the temporary directory is
removed), and computes the `cacheId` capa gives the official plus custom rules together.
`info()` is what `CapaSvc.custom()` returns.

### svc.py

#### Startup

`CapaSvc.__anit__()`:

1. Creates `capa/work`, `capa/cache` and `capa/nosigs` under the cell directory, deletes and
   recreates `capa/custom`, and deletes any leftover files in `capa/work`.
2. If `axon:url` is set, opens one `s_telepath.Client` for every scan (it reconnects on its
   own).
3. Creates the worker semaphore (`capa:workers`) and the set of running subprocesses (killed on
   `fini`).
4. Calls `reload()`. A `CapaSvcError`/`CapaRulesError` is swallowed so the service still
   starts: the message is kept in `rulesErr` and returned by every call that needs the rules.

#### Rules and capa's cache

`reload()` loads `CapaRules` in an executor, clears the custom sets, and schedules
`_warmCache()`. capa takes several seconds to parse its rules without a cache, and doesn't
write the cache atomically, so:

- `cacheReady` (an `asyncio.Event`) is cleared for each load, and every `scan()` waits for it.
- `_buildCache()` runs a subprocess,
  `python -c "capa.rules.get_rules([...], cache_dir=<capa/cache>)"`, bounded by
  `capa:timeout`. A failure only logs a warning (scans still work, without a warm cache).
- `cacheLock` serializes cache builds (capa skips a build if the cache file exists, even while
  another build is writing it). A build scheduled for rules that were since reloaded is skipped.
- `_cleanCache()` then deletes every other `capa-*.cache` file, except the caches of custom
  sets in use with the current rules.

#### Scanning

`scan()` validates the arguments, gets the rules, waits for `cacheReady`, and (with a custom
key) counts the set as in use and prepares it with `_prepCustom()` (which builds its cache once
under `cacheLock`, remembering the error and time of each build). Then `_scan()`, holding a
worker slot:

1. `_fetch()`: gets an Axon proxy (30 second `AXON_TIMEOUT`), then, bounded by `capa:timeout`,
   `_download()` checks `axon.size()` against `capa:maxsize` and streams `axon.get()` to
   `capa/work/<sha256>.<guid>` (the file is opened on the event loop so a cancelled scan can't
   leak a handle; writes run in an executor).
2. `_checkRules()`: compares `rulesStat()` with the loaded stat. If it differs, it hashes the
   rules again; unchanged contents just update the stat, changed contents fail the scan.
3. `_runCapa()`: runs

   ```bash
   python -m capa.main --json --quiet --rules <capa:rules> [--rules <custom set>] \
       --signatures <capa:sigs or capa/nosigs> --format <fmt> --os <os> <file>
   ```

   with `XDG_CACHE_HOME=<capa/cache>` (so capa reads the warm cache) and `COLUMNS=1000`, bounded
   by `capa:timeout`. A timeout, a cancelled scan, or the service shutting down kills the
   process. A non-zero exit becomes the `EXIT_CODES` message plus `stderrMesg()` of stderr
   (capa's rich log lines condensed to one line, without the level prefix, `file.py:123`
   suffix and separator lines). The JSON is parsed in an executor.
4. The file is deleted in a `finally`.
5. `_summarize()` condenses capa's result document (see [`scan()`](api.md#scan)), and `_scan()`
   adds `options`.

There is no upstream network API: capa runs locally, the only remote calls are the Axon's
`size()` and `get()`.

#### Custom rule sets

`custom()` builds a `CustomRules` in an executor and keeps it in `customSets` (an
`OrderedDict`, least recently used first) when it has a key and the official rules weren't
reloaded meanwhile. `_pruneCustom()` drops the least recently used sets past
`MAX_CUSTOM_SETS = 16`, skipping sets counted in `customUse`, and deletes their directory and
cache.

### Error handling

Cell methods raise `CapaSvcError` (or `CapaRulesError` from `rules.py`) with a user-facing
`mesg`. `CapaCellApi` lists both in `RETN_ERRORS`, so `RetnApi` returns their message as-is;
anything else becomes `Unexpected error: ...` with a logged traceback. Errors from the Axon and
from capa are wrapped in `CapaSvcError`s with the original message. The service holds no
secrets of its own, so `_retnRedact()` isn't overridden.

## The Storm package

{src}`svcs/capa/src/capasvc/pkgproto/slib.capa.yaml` (`genopts: dotstorm: true`, so each
module and command's Storm is in its own `.storm` file under `storm/`):

| Key | Value |
| --- | --- |
| `name` / `version` | `slib.capa` / `<version>` |
| `synapse_version` | `>=2.145.0,<3.0.0` |
| `onload` | `$lib.import(slib.capa.sync).onload()` |
| `perms` | `slib.capa.user`, `slib.capa.admin` (both `gate: cortex`) |
| `docs` | `README.md` (a copy of the service README, checked by a test) |

There are no `configvars`: the settings are Cortex globals (`slib:capa:tag:prefix`,
`slib:capa:tag:enabled`, `slib:capa:sync:rules`, `slib:capa:sync:tags`), read through
`$lib.globals.get()` in `slib.capa.priv.user` (which `slib.capa.priv.admin` re-exports) and
written by `slib.capa.priv.admin`.

Privilege is split so that only the two `priv` modules (`asroot:perms`) call the service or
write globals, and every node edit (in `slib.capa.model`, `slib.capa.sync`,
`slib.capa.contacts`) runs as the calling user, subject to their node permissions.
The `onload` runs as root. `slib.capa.priv.admin` imports `slib.capa.priv.user` in its own
(root) runtime and re-exports its read-only calls, so the admin commands and `slib.capa.sync`
only need `slib.capa.admin`, while `scan()` and `custom()` stay behind `slib.capa.user`. The
unprivileged modules have no `perms` key: Synapse doesn't check one on import, so they're gated
by the commands' `perms` and the `priv` module they import.

Storm notes from the code:

- The model helpers each `yield` one node in their own runtime (`seen()`, `addTag()`,
  `matches()`, ...), because a `for` loop running while a node is in a function's pipeline would
  send the node on after its first iteration.
- `slib.capa.scan` does its per-run lookups lazily in a `$state` dict on the first
  `file:bytes`, then uses `divert $cmdopts.yield` to yield either the matched rules or the
  inbound nodes.
- `syncRules()` clears `slib:capa:sync:rules` before importing and sets it only at the end, so
  an import that fails partway is done again by the next package load. Only an import that
  finishes removes the ruleset's edges to rules that are gone (`slib.capa.model.prune()`).
- The Storm code lints clean with `python -m synapse.tools.storm.lint`; CI runs it with
  `storm_lint: block` in {src}`.github/workflows/capa.yml`. The `noqa` comments mark the lint
  rules kept on purpose for Synapse 2.x (`$node.form()`, `$lib.globals.get/set`).

## Tests

```bash
cd svcs/capa && uv run pytest
```

The tests (see {doc}`/dev/testing`) run the real capa, not a fake: a 64-bit shellcode sample
(`SAMPLE` in {src}`svcs/capa/tests/capatest.py`, `xor rax, rax; xor rbx, rbx; ret` plus a marker
string) scanned with `--format sc64` against the six test rules in `tests/data/rules` (one is a
library rule, one never matches). Each scan takes a couple of seconds. `capaSvc()` starts a test
Axon, a Cortex using it, and the service, adds the service, and waits for the package's onload.

| File | Covers |
| --- | --- |
| `tests/test_rules.py` | `rules.py` helpers, `CapaRules` loading, errors, tag records, and that `RULES_VERSION` and the Dockerfile's `CAPA_VERSION` match the installed capa. |
| `tests/test_custom.py` | `CustomRules`, scans with custom rules, set restarts, the cache retry, build timeout and pruning. |
| `tests/test_svc.py` | `CapaSvc` and the Telepath API outside Storm: scans, argument and Axon errors, timeouts, cancellation, rules changing on disk, the cache. |
| `tests/test_capa_storm.py` | The Storm package: versions, `--help`, README copies, Storm lint, the onload import, sync, scans, tags, custom rules, MBC, permissions, contact migration. |
| `tests/test_live.py` | The full capa-rules release, skipped unless `SYN_CAPASVC_CAPA_RULES` is set. |

`tests/conftest.py` enables the shared `stormlibpp.testing` plugin, which fails tests that use
deprecated Synapse APIs, and `pyproject.toml` turns `DeprecationWarning`s from `capasvc` into
errors.

The live tests run in the test image (which has the bundled rules). Locally, point them at a
checkout of `mandiant/capa-rules` at the `RULES_VERSION` tag:

```bash
SYN_CAPASVC_CAPA_RULES=/path/to/capa-rules uv run pytest tests/test_live.py
```
