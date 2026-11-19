# Adding a Service

Plan a new service before you write code. The `service-design-research` skill in
`.claude/skills/` produces a design document and research appendices in
`.claude/research/<svc>/`. Check the API, its auth, quotas and data shapes against the
upstream's official documentation, not against secondhand clients. The
`api-storm-client-audit` skill audits a finished service against those docs.

## 1. Scaffold the project

```bash
mkdir svcs/<svc> && cd svcs/<svc>
uv init --no-workspace --lib --build-backend uv --vcs none --no-pin-python
ln -s ../../LICENSE LICENSE
```

Edit `pyproject.toml`:

- `requires-python = ">=3.11,<3.12"`, which is the Synapse base image's Python.
- `dependencies = ["stormlibpp>=<[contract].stormlibpp>", ...]`. Synapse comes in through
  StormLib++. Lock it to exactly `[contract].synapse` (`uv lock --upgrade-package synapse`
  if needed).
- A `dev` dependency group with `pytest` and `pytest-asyncio`.
- `[tool.pytest]` with `asyncio_mode = "auto"` and
  `filterwarnings = ["error::DeprecationWarning:<pkg>"]`.

Name the Python package `<svc>svc` (for example `vtsvc` or `capasvc`) so it doesn't collide
with the upstream's own client library.

## 2. Write the service

Follow the layout in {doc}`architecture`:

- `defs.py`: `SVC_NAME = "slib.<svc>"`, `SVC_VER = __version__`, the permissions, the
  `SVC_EVTS` (usually a `meta:source` node created on `add`), and a `StormPkg` subclass
  with `proto_name = SVC_NAME`, plus `PKGDEFS = (MyPkg().asdict(),)`.
- `api.py`: the `RetnApi` `CellApi` with `RETN_METHS`/`GENR_METHS`/`RETN_ERRORS`, and
  `_retnRedact()` if there's a secret.
- `svc.py`: the `Cell`, with `cellapi = <Api>` and `confdefs` for its settings. Keep secrets
  out of logs and error messages.
- `__main__.py`: `asyncio.run(<Cell>.execmain(sys.argv[1:]))`.
- `pkgproto/slib.<svc>.yaml`: `name`, `version` (the service version), `synapse_version`
  (not `synapse_minversion`), `perms`, `modules`, `commands` (with `cmdinputs`, not
  `forms`), and `docs: [{title: README, path: README.md}]`.
- `README.md`: the user's README, which names every Storm command. Copy it to
  `pkgproto/README.md`.

Rules for the Storm side:

- Commands warn and continue when the service returns `status=False`. Modules may raise.
- Every user-facing setting (tag prefixes, defaults) has an admin-gated command, a sane
  default, and is validated when it's set, for example a tag prefix with
  `$lib.trycast(syn:tag, $prefix)`.
- Log more when `$lib.debug` is set.
- Shared Storm belongs in StormLib++'s `slib.utils` package.

## 3. Tests

- `tests/conftest.py`: `pytest_plugins = ["stormlibpp.testing"]`.
- A version test (`assertVersionsMatch`), an entry point test (`assertMainHelp`), and a
  README copy test.
- A strict fake upstream on localhost, unit tests for the client and normaliser, and Storm
  tests in a temporary Cortex with the service added.
- Live tests gated behind an opt-in flag.

See {doc}`testing`.

## 4. Docker

`docker/prod/Dockerfile` and `docker/test/Dockerfile`, each with `ARG BASE_IMAGE=...` before
the first `FROM`. Copy `svcs/yarastorm/docker/` and rename. Prod defaults to
`ghcr.io/gormaniac/stormsvcs/base:latest`, and test to the service's own published image.
Add a `.dockerignore` (`.venv/`, `**/__pycache__`, `**/*.pyc`, `**/.pytest_cache`).

## 5. Register it

- `services.toml`:

  ```toml
  [stormsvcs.<svc>]
  name = "Display Name"
  summary = "One line for the docs site's service index."
  src = "svcs/<svc>/"
  workflow = ".github/workflows/<svc>.yml"
  ```

- `.github/workflows/<svc>.yml` (copy `virustotal.yml`), and a job in `_main.yml`. See
  {doc}`ci`.
- The services list in the root `README.md`.

## 6. Document it

Write `svcs/<svc>/docs/`. See {doc}`docs`. The service joins this site automatically from
`services.toml`.

## 7. Check

```bash
python3 scripts/check_svcs.py <svc>
cd svcs/<svc> && uv lock --check && uv run pytest tests
uvx ruff check svcs/<svc> && uvx ruff format --check svcs/<svc>
uv run --group docs python scripts/build_docs.py <svc>
```

A new service must pass every enforced contract rule before it can merge.
