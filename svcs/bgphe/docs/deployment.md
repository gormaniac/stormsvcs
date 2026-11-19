# Deployment

## Docker image

The service is published as `ghcr.io/gormaniac/stormsvcs/bgphe`. CI tags every build with
`latest`, the service version from {src}`svcs/bgphe/pyproject.toml` (ex. `0.3.1`), and the
commit SHA, and pushes the image only from `main` (see {doc}`/dev/ci`).

### How the image is built

{src}`svcs/bgphe/docker/prod/Dockerfile` builds on the stormsvcs base image
(`ghcr.io/gormaniac/stormsvcs/base:latest`, overridable with `--build-arg BASE_IMAGE=...`).
The base image is `vertexproject/vtx-base-image:py311` (pinned by digest) plus `uv`, with
`SYN_LOG_LEVEL=INFO`, ports `4443` and `27492` exposed, and `VOLUME /vertex/storage`.

The service's Dockerfile then:

1. Copies `pyproject.toml`, `uv.lock`, `src/bgphesvc`, and `README.md` into
   `/opt/stormsvcs/bgphe`, and the repo's `LICENSE` next to them.
2. Installs the locked dependencies, without the dev group:
   `uv sync --no-dev --locked --directory /opt/stormsvcs/bgphe`. The runtime dependencies are
   Synapse (via `stormlibpp`), `stormlibpp`, and `cryptography` (which parses the
   certificates). No extra system packages or tools are installed.
3. Runs {src}`svcs/bgphe/docker/prod/entrypoint.sh` under `tini`:

   ```bash
   exec uv run --no-sync --directory /opt/stormsvcs/bgphe/ python -O -m bgphesvc /vertex/storage
   ```

   so the cell's directory is `/vertex/storage`.
4. Declares a healthcheck (start period 10s, interval 30s, timeout 10s, 1 retry) that runs
   `python -m synapse.tools.service.healthcheck -c cell:///vertex/storage/`.

{src}`svcs/bgphe/docker/test/Dockerfile` builds on the production image, adds `tests/` and
the dev dependencies, and runs `pytest`. CI uses it to test the image it just built.

## Cell configuration

The service-specific options, from `BgpHeSvc.confdefs` in {src}`svcs/bgphe/src/bgphesvc/svc.py`:

| Option | Type | Default | Constraint | Meaning |
| --- | --- | --- | --- | --- |
| `bgphe:url` | string | `https://bgp.he.net` | | The base URL of the BGP Toolkit. A trailing `/` is stripped. Useful for a proxy or a test server. |
| `bgphe:interval` | number | `1.0` | `>= 0` | The minimum number of seconds between two requests. `0` disables the spacing (requests are still serialized). |
| `bgphe:timeout` | number | `60` | `>= 1` | The total timeout, in seconds, of a single HTTP request (an `aiohttp.ClientTimeout(total=...)`). |
| `bgphe:backoff` | number | `2.0` | `>= 0` | The base, in seconds, of the exponential backoff between retries: attempt *n* (from 0) waits `backoff * 2**n`. |

The values are read once, when the cell starts, so a change needs a restart.

:::{note}
bgp.he.net is a free community resource. Keep `bgphe:interval` polite. The interval applies
across every user of the service, because the cell has one client and one throttle.
:::

All of Synapse's standard `Cell` options (`dmon:listen`, `https:port`, `auth:passwd`,
`aha:*`, and so on) also apply. See the
[Synapse devops guide](https://synapse.docs.vertex.link/en/latest/synapse/devopsguide.html).
Two are needed for a typical deployment, since Synapse defaults both to unset:

| Option | Example | Why |
| --- | --- | --- |
| `dmon:listen` | `tcp://0.0.0.0:27492/` | The Telepath listener the Cortex connects to. |
| `auth:passwd` | `secret` | The password of the service's `root` user, used in the `service.add` URL. |

(Or provision the service with AHA, using `aha:provision`.)

### Environment variables

Synapse resolves cell config from environment variables named `SYN_<CELL CLASS>_<OPTION>`,
upper-cased, with `:` replaced by `_`. The cell class is `BgpHeSvc`, so the prefix is
`SYN_BGPHESVC_`:

| Variable | Option |
| --- | --- |
| `SYN_BGPHESVC_BGPHE_URL` | `bgphe:url` |
| `SYN_BGPHESVC_BGPHE_INTERVAL` | `bgphe:interval` |
| `SYN_BGPHESVC_BGPHE_TIMEOUT` | `bgphe:timeout` |
| `SYN_BGPHESVC_BGPHE_BACKOFF` | `bgphe:backoff` |
| `SYN_BGPHESVC_DMON_LISTEN` | `dmon:listen` |
| `SYN_BGPHESVC_AUTH_PASSWD` | `auth:passwd` |

Options can also be set in `/vertex/storage/cell.yaml`.

The HTTP session is created with `trust_env=True`, so the standard `HTTPS_PROXY`,
`HTTP_PROXY`, and `NO_PROXY` environment variables are honored for outbound requests.

## Secrets

The service has no secrets of its own: bgp.he.net needs no account or API key. The only
credential is the cell's own Telepath `root` password (`auth:passwd`), or an AHA
provisioning.

## Persistent state

`/vertex/storage` holds only the standard Synapse cell state (`cell.yaml`, `cell.guid`, the
auth slab, certificates, and so on). The service caches nothing and stores no results, every
call is a fresh query. Keep the volume anyway so the cell's identity and users survive a
restart.

## Network egress

The service needs outbound HTTPS to `bgp.he.net` (or the host in `bgphe:url`), port 443. It
calls only the endpoints listed in [Internals](internals.md#endpoints). Inbound, the Cortex
needs to reach the Telepath port (`27492` above).

## docker-compose

```yaml
services:
  bgphe:
    image: ghcr.io/gormaniac/stormsvcs/bgphe:latest
    restart: unless-stopped
    volumes:
      - bgphe-storage:/vertex/storage
    environment:
      SYN_BGPHESVC_DMON_LISTEN: "tcp://0.0.0.0:27492/"
      SYN_BGPHESVC_AUTH_PASSWD: "change-me"
      # Optional, the defaults are shown.
      SYN_BGPHESVC_BGPHE_INTERVAL: "1.0"
      SYN_BGPHESVC_BGPHE_TIMEOUT: "60"
      SYN_BGPHESVC_BGPHE_BACKOFF: "2.0"
      # Optional, an egress proxy.
      # HTTPS_PROXY: "http://proxy.internal:3128"

volumes:
  bgphe-storage:
```

## Adding the service to a Cortex

As a Cortex admin:

```text
service.add slib.bgphe tcp://root:change-me@bgphe:27492/*
service.list
```

`service.list` shows the service as ready, ex. `true (svc) (slib.bgphe @ 0.3.1)`, once the
Cortex has connected and loaded the `slib.bgphe` Storm package. The first time the service is
added, its `add` event runs (as root) and creates the service's `meta:source` node:

```text
[ (meta:source=5cb263934371467b8844e789c39f81aa :name="bgp.he.net" :type=slib.bgphe :url=https://bgp.he.net) ]
```

Check that the package and its commands loaded:

```text
pkg.list
help slib.bgphe
```

## Permissions

The package declares one permission:

| Permission | Gate | Allows |
| --- | --- | --- |
| `slib.bgphe.user` | cortex | Every `slib.bgphe.*` command, and importing the `slib.bgphe.lib` and `slib.bgphe.model` modules. |

Users don't need `service.get`: only the `slib.bgphe.priv` module calls the service, and it
runs as root for users with `slib.bgphe.user`. The node edits run as the calling user, so the
user also needs permission to make them (ex. `node.add`, `node.prop.set`, `node.data.set`,
`node.edge.add`, or simply `node`):

```text
auth.user.addrule analyst slib.bgphe.user
auth.user.addrule analyst node
```

A user without `slib.bgphe.user` gets `requires permission: slib.bgphe.user`. A user with it
but without the node permissions gets, ex., `must have permission node.add`.

## Upgrades

Pull the new image tag and recreate the container on the same volume. When the service
reconnects, the Cortex loads the Storm package bundled with that version (its version matches
the service's, see {doc}`/dev/versioning`). The `add` event does not run again. No data
migrations are needed, since the service stores nothing.
