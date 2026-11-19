# Developer Guide

How the stormsvcs monorepo works, and how to build, test, ship and document a service in it.
To find out how a particular service works, see that service's **Internals** page.

stormsvcs is a collection of Synapse Advanced Power-Ups (Storm Services), each its own
Python project under `svcs/`, with its own dependencies, version, image and CI pipeline. What
the monorepo shares is the *contract* every service follows, the CI that enforces it, the base
image, and this documentation site. Shared code lives upstream in
[StormLib++](https://docs.gormo.co/stormlibpp/), not here.

## Quick reference

```bash
python3 scripts/check_svcs.py                          # the service contract
cd svcs/<svc> && uv sync --locked --all-extras --dev   # a service's environment
uv run pytest tests                                    # its tests
uv run python -m synapse.tools.storm.lint src          # its Storm lint
uv lock --check                                        # its lock, after a version bump
uvx ruff check --fix . && uvx ruff format .            # lint and format (root config)
uv run --group docs python scripts/build_docs.py       # this site (from the repo root)
```

## Repository layout

```text
services.toml          # Every service (name, summary, src, workflow) and the [contract]
scripts/check_svcs.py  # The service contract checker
scripts/build_docs.py  # The docs site builder
docker/Dockerfile      # The base image, ghcr.io/gormaniac/stormsvcs/base
docs/                  # The site's home page, Sphinx config, and this guide
pyproject.toml         # Repo dev tools only: ruff (and its config), pytest, the docs toolchain
.github/workflows/     # _service.yml, _main.yml, _base-image.yml, contract.yml, docs.yml, <svc>.yml
.claude/               # Plans, per-service research, and the design/audit skills
svcs/<svc>/            # One service: its own project, lock, image, tests and docs
```

```{toctree}
:maxdepth: 2

architecture
new-service
contract
testing
ci
versioning
docs
```
