# CI and Publishing

All CI is in GitHub Actions. Each service has a workflow of only a few lines, and those
workflows call shared, reusable pipelines.

## Workflows

| Workflow | Runs on | Does |
| --- | --- | --- |
| `<svc>.yml` | PRs that touch the service (and manual runs), and from `_main.yml` | Calls `_service.yml` for one service |
| `_service.yml` | `workflow_call` | Lint, test, build the image, test in the image, publish (main only) |
| `_main.yml` | Every push to `main`, weekly (Mon 03:17 UTC), manual | Rebuilds the base image if needed, then runs every service's workflow |
| `_base-image.yml` | PRs that touch `docker/`, `LICENSE`, `README.md`, `services.toml` or the workflow itself; from `_main.yml`; manual | Builds (and on main, pushes) the base image. In a PR it also builds every service on the new base |
| `contract.yml` | Every PR and push to `main` | `scripts/check_svcs.py`, see {doc}`contract` |
| `docs.yml` | PRs and pushes that touch the docs, manual | Builds this site, and on main publishes it, see [Docs](#docs) |

## A service's workflow

Copy `.github/workflows/virustotal.yml` and change the service name:

```yaml
name: VirusTotal Pipeline

on:
  workflow_dispatch:
  workflow_call:
  pull_request:
    paths:
      - "svcs/virustotal/**"
      - ".github/workflows/virustotal.yml"
      - ".github/workflows/_service.yml"
      - "pyproject.toml" # The root ruff config, used by the ruff steps in _service.yml

permissions:
  contents: read
  packages: write

jobs:
  pipeline:
    uses: ./.github/workflows/_service.yml
    with:
      service: virustotal
      storm_lint: block
      docker_tests: true
    secrets: inherit
```

The `registered` and `workflow-paths` contract rules check this file, and `docker-tests`
checks for `docker_tests: true`. Add the service to `_main.yml` as well, as a job that `needs:
base` with `if: ${{ !failure() && !cancelled() }}`, so it runs after the base image (even when
the base is skipped) but not after the base fails.

## `_service.yml`

Inputs:

| Input | Default | Meaning |
| --- | --- | --- |
| `service` | (required) | The folder under `svcs/`, also the image name |
| `dockerfile` | `docker/prod/Dockerfile` | The prod Dockerfile, relative to the service |
| `apt-packages` | `""` | System packages the host test job needs |
| `docker_tests` | `false` | Also run the tests in the test image, built on the new prod image |
| `storm_lint` | `report` | `report` shows findings, `block` fails on them, `off` skips the step |

The **test** job runs in `svcs/<svc>`:

1. `uvx ruff@<RUFF_VERSION> check` and `ruff format --check`, before anything is installed,
   so style problems fail fast. `RUFF_VERSION` is pinned to the ruff in the root `uv.lock`.
2. Optional `apt-get install` of `apt-packages`.
3. `uv python install`, then `uv sync --locked --all-extras --dev`.
4. `uv run python -m synapse.tools.storm.lint src`, which is `continue-on-error` unless
   `storm_lint: block`.
5. `uv run pytest tests`.

The **docker** job (`needs: test`):

1. Builds `svcs/<svc>` with Buildx for `linux/amd64`. It tags the image
   `ghcr.io/gormaniac/stormsvcs/<svc>:latest`, `:<pyproject version>` and `:<commit sha>`,
   and exports it to a tarball. The build cache is the GHA cache, per service
   (`scope=<svc>`, `mode=max`), so expensive stages such as pcap's engines built from source
   are reused.
2. With `docker_tests`, loads the image and builds `docker/test/Dockerfile` with
   `--build-arg BASE_IMAGE=ghcr.io/gormaniac/stormsvcs/<svc>:<sha>`, then runs it. The test
   image copies in `tests/`, runs `uv sync --locked` to add the dev dependencies to the
   production venv, and runs pytest from its entrypoint.
3. On PRs, and on manual runs off `main`, it uploads the image tarball as the
   `stormsvcs-<svc>` artifact (kept 7 days) and never touches the registry.
4. On `main`, it logs in to GHCR and runs `docker push --all-tags`. Every service pushes at
   once and they share the base image's layers, so GHCR sometimes answers `unknown blob`.
   Pushes are idempotent, so the push is retried up to four times with a growing backoff.

`PUBLISH` is decided by the *top-level* event, because in a called workflow
`github.event_name` is the caller's event. Images are only ever pushed from `main`.

## The base image

`docker/Dockerfile` builds `ghcr.io/gormaniac/stormsvcs/base`. Its base,
`vertexproject/vtx-base-image:py311`, is pinned by digest, and Dependabot opens a PR when
that tag moves. The root `README.md` and `LICENSE` are copied into the image, which is why
editing either one rebuilds it. `_main.yml`'s `changes` job rebuilds the base image when `docker/`,
`LICENSE`, `README.md` or `_base-image.yml` changed since the previous commit on `main`. It
also rebuilds when that diff can't be computed: manual and scheduled runs, or a force push.

The weekly scheduled run exists to pick up system package updates. Nothing in the Dockerfile
changes when the apt repositories do, so scheduled builds run with `no-cache`. Otherwise a
cached `apt-get upgrade` layer would republish the old packages.

In a PR that changes the base, `_base-image.yml` also lists every service whose prod
Dockerfile builds `FROM ${BASE_IMAGE}`, and builds each one, in a matrix, on the new base.
The new base is pushed to a `registry:2` service container that exists only for that job, so
a breaking base change fails the PR before it can break every service on `main`.

## Docs

`docs.yml` builds this site with `scripts/build_docs.py`, with Sphinx warnings as errors (see
{doc}`docs`). It runs on PRs that touch `docs/`, any `svcs/*/docs/`, `services.toml`, a
service's `pyproject.toml` or package YAML (the service index shows their names and
versions), the build script, or the root `pyproject.toml`/`uv.lock` (the `docs` dependency
group). The built site is uploaded as the `docs` artifact.

On `main` it also publishes the site the way docs.gormo.co expects. docs.gormo.co's build
(`make pull-docs`) downloads the `docs.tar.gz` asset from the **latest GitHub release** of
every repo in its `projects.txt` and extracts it to `docs/<repo>/`. That makes this site
`https://docs.gormo.co/stormsvcs/`. stormsvcs has no repo-wide releases, because each
service has its own version, so the publish job keeps one rolling release:

1. Moves the `docs` tag to the commit it built.
2. Uploads `docs.tar.gz` to the `docs` release (`--clobber`), or creates the release, and
   marks it latest.
3. Sends docs.gormo.co a `doc-release` `repository_dispatch` (the same event StormLib++'s
   release sends), which rebuilds and deploys the whole site.

Step 3 needs a `DOCS_DISPATCH_TOKEN` repository secret: a token that can create
repository dispatches on `gormaniac/docs.gormo.co`. Without it, the step warns and the site
updates on docs.gormo.co's next build.
