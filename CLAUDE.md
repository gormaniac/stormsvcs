# CLAUDE.md

See `.github/copilot-instructions.md` for the repo's architecture and conventions.

## Versioning

Every change to a service under `svcs/` must bump that service's version, in the same PR.

- **Patch** (`0.1.0` → `0.1.1`): fixes.
- **Minor** (`0.1.0` → `0.2.0`): most other changes, ex. new commands, options, or features.
- **Major** (`0.1.0` → `1.0.0`): major overhauls of the API, breaking changes, or when the maintainer asks for one.

The version lives in several places per service, and they must all match (only shodan's tests
check this so far, see `test_versions_match`):

- `svcs/<svc>/pyproject.toml` - `version`
- `svcs/<svc>/src/<pkg>/__init__.py` - `__version__`
- `svcs/<svc>/src/<pkg>/pkgproto/<storm pkg>.yaml` - `version`
- `svcs/<svc>/uv.lock` - the service's own `[[package]]` entry

Edit the `uv.lock` entry directly instead of running `uv lock`, so dependencies don't move, then
confirm with `uv lock --check`.
