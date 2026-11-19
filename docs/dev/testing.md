# Testing

Every service has its own pytest suite in `svcs/<svc>/tests/`, run in the service's own
environment:

```bash
cd svcs/<svc>
uv sync --locked --all-extras --dev
uv run pytest tests
```

CI runs the same suite twice. It runs once on the runner (`_service.yml`'s `test` job) and
once inside the built image (`docker_tests`, see {doc}`ci`). The second run catches anything
that only exists in the image, such as system tools and bundled rule sets.

## The ground rules

- **Never call the real upstream by default.** Tests that reach a real API or database have
  to be gated behind an opt-in flag or environment variable. They're in `tests/test_live.py`,
  and each service's Internals page says how to enable them. Everything else runs offline.
- **Fake the upstream strictly.** Most services test against a fake server in `tests/` (for
  example `fakevt.py`, `fakeabusech.py`, `fakebgphe.py`) that serves the API's real response
  shapes on localhost. A fake that accepts what the real API rejects hides bugs, so it should
  be at least as strict as the real thing: the same auth, status codes, parameter validation
  and error bodies. `vcrpy` is an option for record and replay, but it isn't a Synapse
  dependency, so a service that uses it has to declare it.
- **Cover the Storm too.** Storm commands and modules are tested in a real, temporary
  Cortex (`synapse.tests.utils.SynTest` / `StormPkgTest`), with the service added to it. The
  tests make sure that the nodes, props, tags and edges a command creates are correct. They
  also check that commands warn instead of raising when the service returns `status=False`.
- **Every code path.** Error paths matter more here than usual, because they decide what a
  Storm user sees. Each `CellApi` should have at least one test of an unexpected error
  crossing Telepath (it should come back as `Unexpected error: ...`).

## The StormLib++ test plugin

`tests/conftest.py` has one line, which the `test-plugin` contract rule checks for:

```python
pytest_plugins = ["stormlibpp.testing"]
```

**Synapse deprecations fail the tests.** Synapse logs its deprecations instead of raising
Python warnings, so `filterwarnings` can't see them. The plugin collects three kinds of
deprecation for each test: `synapse.common.deprecated()` for Python APIs, Storm runtime warnings
(`$lib.dict()`, deprecated props, and similar), and deprecated package keys found when a
package loads. It fails the test if it saw any. Deprecations logged outside a test, for
example at import time, fail the whole run. Mark a test that has to use a deprecated API with:

```python
@pytest.mark.allow_synapse_deprecations
```

Write `({})` and `([])` instead of `$lib.dict()` and `$lib.list()`, use `synapse_version`
instead of `synapse_minversion`, and use `cmdinputs` instead of `forms`.

**Local fakes work behind a proxy.** The plugin adds `127.0.0.1` and `localhost` to
`NO_PROXY`.

The plugin also provides helpers that every service calls:

```python
from stormlibpp.testing import assertMainHelp, assertVersionsMatch

def test_versions_match(self):
    # The version in pyproject.toml, __init__.py, the package yaml, and uv.lock.
    assert assertVersionsMatch(SVCDIR) == __version__

def test_main(self):
    # `python -m <pkg> --help` starts and exits cleanly.
    assertMainHelp("<pkg>")
```

Each service's `pyproject.toml` also turns its *own* Python deprecations into errors (the
`pytest-warnings` rule):

```toml
[tool.pytest]
asyncio_mode = "auto"
filterwarnings = ["error::DeprecationWarning:<pkg>"]
```

## Lint

Ruff checks and format-checks every service, tests included, with the root
`pyproject.toml`'s config: Python 3.11 target, 100 character lines. A few test idioms are
ignored, with the reasons written next to each rule. Fix locally with:

```bash
uvx ruff check --fix svcs/<svc>
uvx ruff format svcs/<svc>
```

Synapse's Storm linter checks the package's `.storm` files:

```bash
cd svcs/<svc>
uv run python -m synapse.tools.storm.lint src
uv run python -m synapse.tools.storm.lint --v3-ready src   # the Synapse 3.x migration rules
```

A service that lints clean sets `storm_lint: block` in its workflow, so it stays clean.

## The README copy

The service README is packaged into its Storm package, at `src/<pkg>/pkgproto/README.md`, so
Storm users can read it in the Cortex. A test checks that the two copies are the same. Edit `README.md`, then copy it over.
