# Deployment

## The Docker image

The service is published as `ghcr.io/gormaniac/stormsvcs/hatching`, tagged `latest`, with the
service's version (the `version` in {src}`svcs/hatching/pyproject.toml`), and
with the commit SHA it was built from. Images are only pushed from `main` (see {doc}`/dev/ci`).

The production image ({src}`svcs/hatching/docker/prod/Dockerfile`) is built on the stormsvcs base
image, `ghcr.io/gormaniac/stormsvcs/base` (override it with `--build-arg BASE_IMAGE=...`). The
base image ({src}`docker/Dockerfile`) is `vertexproject/vtx-base-image:py311` (pinned by digest)
with `uv` added, `SYN_LOG_LEVEL=INFO`, ports `4443` (HTTPS) and `27492` (Telepath) exposed, and
`VOLUME /vertex/storage`. It installs no service specific system packages.

The service image then:

1. Copies `pyproject.toml`, `uv.lock`, `src/hatchingsvc/`, and `README.md` into
   `/opt/stormsvcs/hatching/`, and copies the repo `LICENSE` in.
2. Runs `uv sync --no-dev --locked`, so the venv in `/opt/stormsvcs/hatching/.venv` holds exactly
   the locked Synapse, StormLib++, and pyhatching versions.
3. Runs `tini -- /opt/stormsvcs/hatching/entrypoint.sh`, which is:

   ```bash
   exec uv run --no-sync --directory /opt/stormsvcs/hatching/ python -O -m hatchingsvc /vertex/storage
   ```

4. Declares a health check that runs `python -m synapse.tools.service.healthcheck -c
   cell:///vertex/storage/` every 30 seconds.

`python -m hatchingsvc` is Synapse's `Cell.execmain()`: it takes the storage directory as its only
positional argument, and listens for Telepath on `tcp://0.0.0.0:27492` and HTTPS on `4443` by
default (`--telepath`/`--https`, or the `SYN_HATCHINGSVC_TELEPATH`/`SYN_HATCHINGSVC_HTTPS`
environment variables).

The test image ({src}`svcs/hatching/docker/test/Dockerfile`) is built from the production image,
adds `tests/` and the dev dependencies, and runs `pytest` against the installed service. CI uses
it to test the image it just built.

## Configuration

The service's own options (`HatchingSvc.confdefs` in {src}`svcs/hatching/src/hatchingsvc/svc.py`):

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `hatching:apikey` | string or null | `null` | A Triage API key used when neither the calling user nor the service's stored key provides one (see [API keys](#api-keys)). |
| `hatching:url` | string | `https://tria.ge` | The Triage URL: `https://tria.ge` (public cloud), `https://private.tria.ge` (private cloud), or a self-hosted instance. Also used to build magic links. |
| `hatching:api_path` | string | `/api` | The path the versioned (`/v0`, `/v1`) endpoints live under. Requests go to `<hatching:url><hatching:api_path>/v0/...`. Use `""` for an API root like `https://api.tria.ge`. |
| `hatching:timeout` | number | `60` | Seconds before a single API request times out. Streaming requests (downloads, sample events, kernel logs) only use it as the connect timeout. |
| `hatching:maxsize` | integer | `104857600` (100 MiB) | The largest file, in bytes, the service submits or downloads. |

Options can be set in `/vertex/storage/cell.yaml`, or with environment variables. Synapse maps an
option to `SYN_<CELL CLASS>_<OPTION>`, with the class name uppercased and `:` replaced by `_`,
and parses the value as YAML:

| Option | Environment variable |
| --- | --- |
| `hatching:apikey` | `SYN_HATCHINGSVC_HATCHING_APIKEY` |
| `hatching:url` | `SYN_HATCHINGSVC_HATCHING_URL` |
| `hatching:api_path` | `SYN_HATCHINGSVC_HATCHING_API_PATH` |
| `hatching:timeout` | `SYN_HATCHINGSVC_HATCHING_TIMEOUT` |
| `hatching:maxsize` | `SYN_HATCHINGSVC_HATCHING_MAXSIZE` |

The standard Synapse Cell options apply too, ex. `SYN_HATCHINGSVC_AUTH_PASSWD` (bootstraps the
root user's password), `SYN_HATCHINGSVC_DMON_LISTEN`, or the `aha:*` options for an AHA
deployment. See the
[Synapse devops guide](https://synapse.docs.vertex.link/en/latest/synapse/devopsguide.html).

pyhatching's HTTP session is created with `trust_env=True`, so the service honors the standard
`HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` environment variables.

## API keys

Every Triage request needs an API key. The key for each request is resolved in this order
(`HatchingSvc.getApiKey`):

1. **The calling user's own key.** `slib.hatching.apikey <key>` stores it in a user scoped
   Synapse vault of type `hatching`, named `hatching:<username>`, with the secret `apikey`. The
   `slib.hatching.priv.*` modules read only the calling user's user scoped vault and pass the key
   to the service with each call.
2. **The service-wide key**, set with `slib.hatching.admin.apikey <key>`. It's stored in the
   service's own storage (the `apikey` key of the `slib:hatching` safe key-value store in the
   Cell's slab), not in the Cortex, so it can't be read back from Storm.
3. **The `hatching:apikey` option.**

If none of them is set, every call fails with `No Hatching Triage API key is available. Set your
own with slib.hatching.apikey, or ask an admin to set one with slib.hatching.admin.apikey.`

:::{warning}
A key given as an argument to `slib.hatching.apikey` or `slib.hatching.admin.apikey` is part of
the Storm query's text, so it can end up in query logs, history, and audit records. To avoid
that, create the user scoped vault yourself (ex. in the UI's vault manager) with type `hatching`,
user scope, and an `apikey` secret, and set the service-wide key with the `hatching:apikey`
option. `slib.hatching.apikey` with no argument then only reports on the vault.
:::

The organization commands (`slib.hatching.admin.users`, `admin.user.*`, `admin.org`) need a
Triage key with the `manage_company` permission. They use the same key resolution, so the admin
running them either sets their own key with that permission, or the service-wide key has it.

## Persistent state

Everything lives in the storage volume, `/vertex/storage`:

| Path | What |
| --- | --- |
| `cell.yaml`, `cell.guid`, `slabs/`, ... | The standard Cell files: config, auth, and the Cell's LMDB slab. |
| The `slib:hatching` safe key-value store (in the Cell's slab) | The service-wide API key (`apikey`). |
| `tmp/uploads/` | File uploads in progress (`slib.hatching.submit` of a `file:bytes`), one file per upload, named by a random guid. |

`tmp/uploads/` is emptied every time the service starts. An upload is deleted once it's submitted
(whether the submission worked or not), when it's been idle for an hour, when it would exceed
`hatching:maxsize`, or when it's the oldest of more than 16 open uploads. Leave room in the volume
for 16 files of `hatching:maxsize` bytes.

The Cortex side of the service keeps its state in the Cortex:

| Where | What |
| --- | --- |
| Storm global `slib:hatching:tag:enabled` | Whether Triage tags are applied (default `true`). |
| Storm global `slib:hatching:tag:prefix` | The tag prefix (default `rep.hatching`). |
| User scoped vaults of type `hatching` | Each user's own API key. |
| `meta:source=76172c35a9074f998791a9d2b69ff6d8` | The source every modeled node is linked to. |

The two globals and the `meta:source` node are created by the service's `add` event, which runs
the first time the service is added with `service.add`. The globals are only set when they don't
exist yet, so adding the service again keeps an existing tag configuration.

## Network egress

The service needs outbound HTTPS to the `hatching:url` host (ex. `tria.ge` or
`private.tria.ge`), directly or through an `HTTPS_PROXY`. It makes no other outbound connections.
The Cortex needs a Telepath connection to the service (port `27492` by default). The HTTPS port
(`4443`) is not used by the Storm package.

## docker-compose

```yaml
services:
  hatching:
    image: ghcr.io/gormaniac/stormsvcs/hatching:latest
    restart: unless-stopped
    volumes:
      - ./storage/hatching:/vertex/storage
    environment:
      SYN_HATCHINGSVC_AUTH_PASSWD: "change-me"
      # Optional, a service-wide Triage key. Can also be set with slib.hatching.admin.apikey.
      SYN_HATCHINGSVC_HATCHING_APIKEY: "<triage api key>"
      # Optional, for the private cloud or a self-hosted instance.
      SYN_HATCHINGSVC_HATCHING_URL: "https://private.tria.ge"
      SYN_HATCHINGSVC_HATCHING_TIMEOUT: "60"
      SYN_HATCHINGSVC_HATCHING_MAXSIZE: "104857600"
    ports:
      - "27492:27492"
```

## Adding the service to a Cortex

```text
service.add slib.hatching tcp://root:change-me@<host>:27492/*
service.list
```

When the service connects, it registers the `slib.hatching` Storm package (its version matches
the service's), and on the first `service.add` it runs its `add` event (the `meta:source` node and
the tag globals, see [Persistent state](#persistent-state)). Check it with:

```text
pkg.list
slib.hatching.admin.tags
slib.hatching.admin.apikey
```

The package requires Synapse `>=2.137.0,<3.0.0` in the Cortex.

:::{note}
The service's Telepath API has no per-method permission checks. Anyone who can connect to it
with the service's credentials can call every method, including `setApiKey`, and every call can
use the stored key. Keep the Telepath port reachable only by the Cortex, and only grant
`service.get` (which lets Storm call `$lib.service.get("slib.hatching")` directly) to admins.
Users don't need it: the `slib.hatching.priv.*` modules call the service for them.
:::

## Permissions

The package declares four permissions, all gated on the Cortex:

| Permission | Grants | Commands |
| --- | --- | --- |
| `slib.hatching.user` | Search, model analyses, read reports, download samples and task files, list profiles, Yara rules, resources, and geolocations, read usage stats, and set your own API key. | `enrich`, `search`, `samples`, `sample.info`, `sample.wait`, `events`, `report`, `kernel`, `download`, `profile.list`, `resources`, `geolocations`, `stats`, `yara.list`, `yara.get`, `apikey` |
| `slib.hatching.submit` | Submit files and URLs, pick profiles for interactive samples, import public samples, and delete samples. | `submit`, `sample.profile`, `sample.import`, `sample.delete` |
| `slib.hatching.manage` | Add, edit, and delete the account's analysis profiles and Yara rules. | `profile.add`, `profile.edit`, `profile.del`, `yara.add`, `yara.del` |
| `slib.hatching.admin` | The service-wide API key, tag settings, organization users and their API keys, organization settings and stats, and raw API requests. | `admin.apikey`, `admin.tags`, `admin.request`, `admin.org`, `admin.users`, `admin.user.add`, `admin.user.del`, `admin.user.keys`, `admin.user.key.add`, `admin.user.key.del` |

The permissions don't imply each other. A user that submits with `--wait` (which models the
result) needs `slib.hatching.user` too, since modeling uses `slib.hatching.lib` and
`slib.hatching.model`, which require it. `slib.hatching.yara.add` reads `it:app:yara:rule` nodes,
so its users usually need `slib.hatching.user` for `yara.get --yield` as well.

Node edits run as the calling user, so users that model (`enrich`, `--model`/`--yield`, `submit
--wait`, `download`, `yara.get --yield`) also need the normal node permissions for the forms,
props, tags, and edges they create (ex. `node.add`, `node.prop.set`, `node.tag.add`,
`node.edge.add`, or simply `node`). See [Model](model.md) for what's written.

```text
// An analyst that can search, model, download, and submit.
auth.user.addrule visi slib.hatching.user
auth.user.addrule visi slib.hatching.submit
auth.user.addrule visi node

// A team lead that also manages profiles and Yara rules.
auth.user.addrule lead slib.hatching.manage
```

## Upgrades

Pull the new image and recreate the container on the same volume. The Storm package is re-sent
to the Cortex each time the service connects, so the Cortex picks up the new package version
automatically. The API key, tag settings, and modeled nodes are kept. Upload files in
`tmp/uploads/` are dropped on restart, so any submission that was in progress has to be re-run.

The service's version, its Storm package's version, and the `pyproject.toml` version always
match (see {doc}`/dev/versioning`).
