# Systemic fixes: move the service contract into code

The November 2026 code audit (181 findings, the "Stormsvcs Code Audit" doc) found the same
bugs in several services. The cause is structural, not per-service:

1. **StormLib++ has a return type but no runtime.** `stormlibpp.telepath` only defines the
   `TelepathRetn` shapes, so each service hand-rolls `_retn`/`_retnMeth`/`_errRetn`, and the
   copies differ. Raw exceptions escape to Storm in six audited services, and virustotal,
   written after the audit, catches only its own error types. The two path traversal Highs
   (yarastorm rule ids, pcap feed names) are the same gap: no shared path helpers.
2. **No shared test kit.** 11 copies of a ~115 line `conftest.py` harness (hatching's was
   missing it entirely), version tests written by hand per service (some skip `uv.lock`), and
   nothing requires the tests that catch the Highs.
3. **No shared Storm code.** Each package writes its own tag prefix admin command, source node
   handling, and command skeleton. Only capa validates its tag prefix.
4. **Build config is copied, not inherited.** 10 of 11 test Dockerfiles are hard-coded
   `FROM …:latest`, only pcap runs `docker_tests`, and pins drift (shodan on stormlibpp 0.10.1
   and `synapse_minversion`, yarastorm on synapse 2.248.0).
5. **Conventions live in prose.** `CLAUDE.md` and `copilot-instructions.md` state rules CI
   doesn't check: no Storm lint in CI, nothing reads `services.toml`.

The fix: put the contract in code (StormLib++), and check every service against it in CI
(`scripts/check_svcs.py`), with rules moving from reported to enforced as services migrate.

## Status

| Phase | What | Status |
| --- | --- | --- |
| 1 | StormLib++: `stormlibpp.svc`, `stormlibpp.testing` | Done: gormaniac/stormlibpp#51, released in stormlibpp 1.0.0 |
| 2 | stormsvcs: contract check, CI job, Storm lint step, pin fixes | Done, in gormaniac/stormsvcs#41 |
| 3 | Migrate each service onto the shared pieces | Done for all 10 services, in gormaniac/stormsvcs#41 (ip_api is exempt: #40 retires it) |
| 4 | Enforce the rules, trim the prose docs | Every rule enforced in #41; trimming the prose docs is left |
| 5 | Shared Storm code, base image testing, scaffold | Not started |

## Phase 1: StormLib++ (done, released in 1.0.0)

Merged in gormaniac/stormlibpp#51 and released in stormlibpp 1.0.0.

- `stormlibpp.svc`:
  - `RetnApi`: a `CellApi` mixin. `RETN_METHS`/`GENR_METHS` generate wrapped methods, and every
    public async method the subclass defines is guarded, so nothing raises to Storm.
    `RETN_ERRORS` (default `SvcError`) and `AuthDeny` keep their own message, bad input
    (`ValueError`, `TypeError`, `BadArg`) is `Invalid input: …`, and anything else is logged
    with a traceback and returned as `Unexpected error: <type>: …`. `_retnRedact()` scrubs
    every message (closes abusech's Auth-Key leak, ABUSE-PY-02).
  - `retn()`, `retnGenr()`, `errRetn()`, `SvcError`.
  - `safeJoin()`, `checkName()`, `checkGuid()` (for YARA-01 and PCAP-SVC-01).
- `stormlibpp.testing`: the deprecation harness as an opt-in pytest plugin, which now fails the
  run for deprecations logged outside of a test (REPO-09's import-time gap). Plus
  `stormlibpp.testing.checks`: `assertVersionsMatch()`, `stormLint()`, `assertMainHelp()`.

## Phase 2: repo level (done)

- `scripts/check_svcs.py` + `.github/workflows/contract.yml`: every rule reported in the job
  summary, the `[contract].enforce` rules in `services.toml` fail CI. Enforced now:
  `registered`, `workflow-paths`, `versions` (REPO-08's check, for every service).
- `_service.yml` runs the Storm linter (`storm_lint`: `report` by default, `block`, `off`).
  yarastorm lints clean and is on `block` (REPO-21).
- pcap's PR path filter includes the root `pyproject.toml` (REPO-07).
- shodan 0.15.1: stormlibpp 0.12.1, `synapse_version`, and its own `DeprecationWarning`s fail
  its tests (REPO-03, REPO-09, REPO-10).
- yarastorm 0.6.1: synapse 2.256.0 (REPO-04).

Run `python3 scripts/check_svcs.py` to see what's left. `--strict` shows it as failures.

## Phase 3: migrate each service (done, on stormlibpp 1.0.0)

One PR per service (or a few small ones together), each a **minor** bump, since error messages
returned to Storm change. Skip ip_api: gormaniac/stormsvcs#40 retires it.

Per service:

1. `pyproject.toml`: `stormlibpp>=1.0.0` in deps (pytest is already a dev dependency; or
   `stormlibpp[testing]` in the dev group), then `uv lock --upgrade-package stormlibpp`.
2. `api.py`: replace the hand-rolled wrappers with `RetnApi`. crtsh was trialled this way
   against a local stormlibpp; all 68 of its tests passed with one log assertion updated,
   and the change deleted 194 lines:

   ```python
   from stormlibpp.svc import RetnApi

   class CrtshCellApi(RetnApi, s_cell.CellApi, s_stormsvc.StormSvc):
       RETN_METHS = ("lookup", "get", "chain", "cas", "rawQuery")
       GENR_METHS = ("searchGenr", "issuedGenr", "pivotGenr")
       RETN_ERRORS = (CrtshDbError,)
       ...
   ```

   Tests that assert on the old log message (`getLoggerStream("<pkg>.api")`) now read the
   `stormlibpp.svc` logger, `Unexpected error in <Api>.<meth>.`. Services whose cell methods
   build a `TelepathRetn` themselves (yarastorm, and some of pcap's) keep those API methods
   hand-written; `RetnApi` guards them.
3. `tests/conftest.py`: `pytest_plugins = ["stormlibpp.testing"]`, plus anything
   service-specific the old file had. Fix what the outside-of-test check now catches.
4. Tests: `assertVersionsMatch(ROOT)` replaces the hand-written version test,
   `assertMainHelp("<pkg>")` covers `__main__` (0% today), and at least one test per CellApi
   for an unexpected error crossing Telepath.
5. Dockerfiles: `ARG BASE_IMAGE=<current FROM>` + `FROM ${BASE_IMAGE}` in prod and test, and
   `docker_tests: true` in the workflow (REPO-02). yarastorm's test image also needs
   shodan's `uv sync --locked` (not `--only-dev`) and `uv run --no-sync` lines (REPO-05).
6. Service-specific fixes that use the new helpers, in the same PR:
   - yarastorm: `checkGuid()` on rule ids (YARA-01), skip corrupt rule files (YARA-02).
   - pcap: `checkName()`/`safeJoin()` on feed names (PCAP-SVC-01).
   - abusech: `_retnRedact()` for the Auth-Key (ABUSE-PY-02).
   - virustotal: drop `ERRORS`, use `RETN_ERRORS` (the catch-all is now free).
7. If its Storm lints clean, `storm_lint: block` in its workflow.
8. Bump the version in all four places, `uv lock --check`, `python3 scripts/check_svcs.py <svc>`.

Order: virustotal and abusech first (the narrowest catches today), then yarastorm and pcap (the
path Highs), then the rest.

## Phase 4: enforce

As each rule passes for every service, add it to `[contract].enforce`: `pins`, `pkg-keys`,
`pytest-warnings` first (pass after phase 2 for all but the ones in flight), then
`test-plugin`, `version-test`, `retn-api`, `main-test`, `docker-base-arg`, `docker-tests`.
Then trim `CLAUDE.md` and `.github/copilot-instructions.md` to point at the check, and fix the
stale lines the audit found there (REPO-14).

## Phase 5: not started

- **Shared Storm code.** StormLib++ already has `slib.utils` for shared Storm, but a service
  package can't require another package be installed without friction. Proposal: `StormPkg`
  copies a set of shared Storm modules into each service package at build time (as
  `slib.<svc>.common`): a validated tag prefix setter (`$lib.cast(syn:tag, …)`, the audit's
  cross-cutting tag prefix rows), a source node getter that works in any view (the
  `meta:source` row), and a command skeleton that does value/flag driven work once in
  `init {}` (CRTSH-01, HATCH-01). Needs a design pass first.
- **Base image changes tested in PRs** (REPO-06): once every prod Dockerfile takes
  `BASE_IMAGE`, build the base in the PR run and pass it in, or push the base only after the
  services build.
- **Service scaffold**: a template (copier, or a `stormlibpp new-svc` command) that starts a
  service passing every enforced rule.
- Cleanups the check can then cover: dead `SVC_SYN_MIN_VER` constants (abusech, capa,
  shodan), `.dockerignore` and entrypoint shebangs (REPO-19), consistent `source-include`
  (REPO-11), the root `requires-python` (REPO-18), ruff on tests (REPO-17).
