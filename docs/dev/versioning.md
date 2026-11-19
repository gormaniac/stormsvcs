# Versioning

Each service has its own version, and the version is what lets a Cortex admin know what
changed. **Every change to a service under `svcs/` bumps that service's version, in the same
PR.**

| Bump | When | Example |
| --- | --- | --- |
| Patch | Fixes | `0.1.0` → `0.1.1` |
| Minor | Most other changes: new commands, options, features, changed error messages | `0.1.0` → `0.2.0` |
| Major | A major overhaul of the API, breaking changes, or when the maintainer asks for one | `0.1.0` → `1.0.0` |

## Where the version lives

There are four copies, and they all have to match. The `versions` contract rule and each
service's `assertVersionsMatch()` test both check this.

| File | Key |
| --- | --- |
| `svcs/<svc>/pyproject.toml` | `[project] version` |
| `svcs/<svc>/src/<pkg>/__init__.py` | `__version__` |
| `svcs/<svc>/src/<pkg>/pkgproto/<storm pkg>.yaml` | `version` |
| `svcs/<svc>/uv.lock` | The service's own `[[package]]` entry |

Edit the `uv.lock` entry by hand instead of running `uv lock`, so that no dependency moves as
a side effect. Then confirm that the lock is still consistent:

```bash
cd svcs/<svc>
uv lock --check
```

## What the version drives

- The service's `_storm_svc_vers` and its Storm package's `version`, which the Cortex shows
  (`service.list`, `pkg.list`). The Cortex loads the packages that the service reports each
  time the service connects, so deploying a new image is all it takes to upgrade the Storm
  package.
- The image tag: `ghcr.io/gormaniac/stormsvcs/<svc>:<version>` is pushed alongside `latest`
  and the commit SHA (see {doc}`ci`).
- The version shown in this site's service index.

## Synapse and StormLib++ pins

These aren't per-service choices. `[contract]` in `services.toml` sets the Synapse version
that every service's `uv.lock` must have, and the lowest StormLib++ it may have. The `pins`
rule enforces both (see {doc}`contract`). To move Synapse, bump `[contract].synapse` and
every service's lock (with `uv lock --upgrade-package synapse`) in one PR, and bump each
service's version.
