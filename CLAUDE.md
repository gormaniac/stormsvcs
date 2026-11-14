# CLAUDE.md

See `.github/copilot-instructions.md` for the repo's architecture and conventions.

## Versioning

Every change to a service under `svcs/` must bump that service's version, in the same PR.

- **Patch** (`0.1.0` → `0.1.1`): fixes.
- **Minor** (`0.1.0` → `0.2.0`): most other changes, ex. new commands, options, or features.
- **Major** (`0.1.0` → `1.0.0`): major overhauls of the API, breaking changes, or when the maintainer asks for one.

The version lives in several places per service, and they must all match (CI checks this for
every service, see the `versions` rule in `scripts/check_svcs.py`):

- `svcs/<svc>/pyproject.toml` - `version`
- `svcs/<svc>/src/<pkg>/__init__.py` - `__version__`
- `svcs/<svc>/src/<pkg>/pkgproto/<storm pkg>.yaml` - `version`
- `svcs/<svc>/uv.lock` - the service's own `[[package]]` entry

Edit the `uv.lock` entry directly instead of running `uv lock`, so dependencies don't move, then
confirm with `uv lock --check`.

## Service contract

`scripts/check_svcs.py` checks every service against the rules every service must follow the
same way: how it's registered and built in CI, its Synapse and StormLib++ pins, and using the
shared StormLib++ pieces (`stormlibpp.svc.RetnApi`, the `stormlibpp.testing` pytest plugin)
instead of its own copies. Run `python3 scripts/check_svcs.py` before opening a PR.

The `[contract]` table in `services.toml` sets the pins and lists the `enforce`d rules, which
fail CI. The other rules are reported only. When every service passes a rule, add it to
`enforce`. A new service must pass every enforced rule. See
`.claude/plans/systemic-fixes.md` for the migration plan.
