# The Service Contract

The rules every service has to follow the same way are checked in code by
{src}`scripts/check_svcs.py`, not left as conventions in prose that can drift. The Service
Contract workflow (`.github/workflows/contract.yml`) runs it on every PR and every push to
`main`, and writes a pass/fail table per service and rule to the job summary.

```bash
python3 scripts/check_svcs.py              # every service
python3 scripts/check_svcs.py pcap capa    # some services
python3 scripts/check_svcs.py --strict     # treat every rule as enforced
python3 scripts/check_svcs.py --summary report.md
```

It only needs the standard library and Python 3.11 or later. Each service is printed as `ok`,
`todo` (it fails a rule that isn't enforced yet) or `FAIL` (it fails an enforced rule, which
makes the script exit 1).

## Configuration: `[contract]` in `services.toml`

```toml
[contract]
# The Synapse every service's uv.lock must have, and the lowest StormLib++ it may have.
synapse = "2.256.0"
stormlibpp = "1.0.0"
enforce = [
    "registered",
    "workflow-paths",
    "versions",
    # ... every other rule in the table below
]
```

A rule listed in `enforce` fails CI. Any other rule is only reported. When every service
passes a rule, add it to `enforce`, so that no service can regress on it and a new service
can't merge without it. Today every rule is enforced.

A service can be exempted from a rule in its own `services.toml` entry, with a reason. The
reason is shown in the report:

```toml
[stormsvcs.example.exempt]
docker-tests = "The full rule set is only in the image."
```

## The rules

| Rule | What it checks |
| --- | --- |
| `registered` | The service has a `[stormsvcs.*]` entry whose `src` is `svcs/<dir>/`. Its workflow exists, calls `./.github/workflows/_service.yml` with `service: <dir>`, and `_main.yml` runs it. |
| `workflow-paths` | The workflow's `pull_request.paths` include `svcs/<dir>/**`, the workflow itself, `.github/workflows/_service.yml`, and the root `pyproject.toml` (the ruff config). |
| `versions` | The version is the same in `pyproject.toml`, `src/<pkg>/__init__.py` (`__version__`), every `pkgproto/*.yaml` (`version:`), and the service's own `[[package]]` in `uv.lock`. See {doc}`versioning`. |
| `pins` | `uv.lock` has exactly `[contract].synapse`, and a StormLib++ of at least `[contract].stormlibpp`. |
| `pkg-keys` | No Storm package proto uses the deprecated `synapse_minversion` key (use `synapse_version`). |
| `pytest-warnings` | pytest's `filterwarnings` has `error::DeprecationWarning:<pkg>` for each package, so the service's own Python deprecations fail its tests. |
| `docker-base-arg` | `docker/prod/Dockerfile` and `docker/test/Dockerfile` declare `ARG BASE_IMAGE` *before* their first `FROM`, and build `FROM ${BASE_IMAGE}`, so CI can build them on an unpublished image. |
| `docker-tests` | The workflow sets `docker_tests: true`, so the tests also run inside the built image. |
| `test-plugin` | `tests/conftest.py` sets `pytest_plugins = ["stormlibpp.testing"]` and has no copy of the old deprecation harness. |
| `version-test` | A test calls `stormlibpp.testing.assertVersionsMatch()`. |
| `main-test` | A test calls `stormlibpp.testing.assertMainHelp()` on the entry point. |
| `retn-api` | A class in `src/<pkg>/*.py` subclasses `stormlibpp.svc.RetnApi`. See {doc}`architecture`. |
| `docs` | The service has its documentation in `docs/`, starting at `docs/index.md`. See {doc}`docs`. |

## Adding a rule

A rule is a function that takes the service (`Svc`: its directory, `services.toml` entry,
parsed `pyproject.toml`, lock lookups, globbing) and the `[contract]` table. It returns a list
of problems, which is empty when the service passes. Register it with the `@rule` decorator:

```python
@rule("my-rule", "One line on what it checks, shown in the job summary.")
def _myRule(svc: Svc, contract: dict) -> list[str]:
    if (svc.path / "something").is_file():
        return []
    return ["No something."]
```

A new rule starts as reported only. Fix every service, or exempt one with a reason, and then
add the rule to `enforce`.

## History

The contract came out of the November 2026 code audit, which found the same bugs copied
across services: hand-rolled Telepath wrappers that let exceptions escape to Storm, eleven
copies of a test harness, and pins that had drifted apart. The plan and its status are in
`.claude/plans/systemic-fixes.md`.
