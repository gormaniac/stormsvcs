# Deployment

## Docker image

The service is published as `ghcr.io/gormaniac/stormsvcs/yarastorm`. CI pushes it only from
`main`, tagged `latest`, the service version from `pyproject.toml`, and the commit
SHA. Pin a version tag in production.

### How the image is built

The production Dockerfile is {src}`svcs/yarastorm/docker/prod/Dockerfile`:

1. `FROM ${BASE_IMAGE}`, default `ghcr.io/gormaniac/stormsvcs/base:latest`. The base image
   ({src}`docker/Dockerfile`) is `vertexproject/vtx-base-image:py311` (pinned by digest) plus
   `uv`, with `SYN_LOG_LEVEL=INFO`, `EXPOSE 4443` and `EXPOSE 27492`, upgraded system packages,
   and `VOLUME /vertex/storage`.
2. Copies `pyproject.toml`, `uv.lock`, `src/yarastorm` and `README.md` to
   `/opt/stormsvcs/yarastorm/`, and copies the repo `LICENSE` in.
3. `uv sync --no-dev --locked` installs the locked dependencies: Synapse, StormLib++ and
   `yara-x` (a self-contained wheel; no system `libyara` is needed or installed).
4. The entrypoint ({src}`svcs/yarastorm/docker/prod/entrypoint.sh`) runs under `tini`:

   ```bash
   exec uv run --no-sync --directory /opt/stormsvcs/yarastorm python -O -m yarastorm /vertex/storage
   ```

   so the cell directory (`dirn`) is always `/vertex/storage`.
5. A `HEALTHCHECK` runs `python -m synapse.tools.service.healthcheck -c cell:///vertex/storage/`
   every 30 seconds (10 second timeout, 10 second start period, 1 retry).

The test image ({src}`svcs/yarastorm/docker/test/Dockerfile`) is built `FROM` the production
image, adds `tests/` and the dev dependencies, and runs `pytest`. It isn't meant for deployment.

## Cell configuration

The service-specific options, from `YaraSvc.confdefs` in {src}`svcs/yarastorm/src/yarastorm/svc.py`:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `axon_url` | string | unset | Telepath URL of the Axon that file bytes are pulled from. Unset: the service starts and logs a warning, and every scan returns `The yarastorm service has no axon_url configured.` |
| `rule_dir` | string | `rules/` | Directory the compiled rules are saved in. A relative path is joined to the cell's `dirn` (so `/vertex/storage/rules/` in the image); an absolute path is used as is. Created on startup if missing. |
| `max_size` | integer, `minimum: 1` | unset | Largest file, in bytes, the service pulls from the Axon. A larger file isn't scanned and the scan returns an error for it. Unset means no limit. |
| `scan_timeout` | integer, `minimum: 1` | `60` | Seconds one rule may spend scanning one file (yara-x's scanner timeout). A scan that runs longer is abandoned and reported as an error for that rule; the other rules still run. |

### Memory and CPU

The service reads each file from the Axon into memory in full, then scans it, so one scan holds
the whole file in memory, and each concurrent scan (one per Storm query running
`slib.yara.scan`; a query scans its files one at a time) holds its own. With `max_size` unset there's no
bound. Set `max_size` in production, to the largest file you expect to scan (ex. `52428800` for
50 MiB), and size the container's memory for a few files that size.

Scans are CPU bound. Each rule's scan of a file runs in a worker thread (Python's default
executor), so the service keeps answering Telepath calls while it scans, and `scan_timeout` stops
a single rule that takes too long (ex. a slow regex on a large file).

All the standard Synapse Cell options also apply (`dmon:listen`, `https:port`, `auth:passwd`,
`aha:*`, `nexslog:en`, ...); see the
[Synapse devops guide](https://synapse.docs.vertex.link/en/latest/synapse/devopsguide.html).
The service itself has no Storm-side configuration (no `configvars` or settings commands).

:::{note}
The config keys keep underscore names (`axon_url`, not `axon:url`) so existing `cell.yaml` files
and environment variables keep working.
:::

### Environment variables

Synapse reads config from `SYN_<CELLCLASS>_<KEY>`, with the cell class name upper-cased and `:`
in the key replaced by `_`. The cell class is `YaraSvc`, so the prefix is `SYN_YARASVC_`.
Values are parsed as YAML, so `SYN_YARASVC_MAX_SIZE=52428800` is an integer.

| Variable | Config key |
| --- | --- |
| `SYN_YARASVC_AXON_URL` | `axon_url` |
| `SYN_YARASVC_RULE_DIR` | `rule_dir` |
| `SYN_YARASVC_MAX_SIZE` | `max_size` |
| `SYN_YARASVC_SCAN_TIMEOUT` | `scan_timeout` |
| `SYN_YARASVC_DMON_LISTEN` | `dmon:listen` |
| `SYN_YARASVC_HTTPS_PORT` | `https:port` |
| `SYN_YARASVC_AUTH_PASSWD` | `auth:passwd` |

The same keys can be set in `/vertex/storage/cell.yaml`:

```yaml
dmon:listen: tcp://0.0.0.0:27492/
axon_url: tcp://root:secret@axon:27492/
max_size: 52428800
```

## Secrets

The service uses no upstream API keys. The only credentials involved are Telepath ones:

- The password (or certificate) in `axon_url`, which the service uses to read from the Axon.
  It's stored wherever the config lives (environment or `cell.yaml`).
- The credentials the Cortex uses to connect to this service, given in `service.add`.
  `auth:passwd` bootstraps the service's `root` password.

## Persistent state

Everything lives in the `/vertex/storage` volume:

| Path | Contents |
| --- | --- |
| `/vertex/storage/rules/` (`rule_dir`) | One serialized Yara-X `Rules` file per enabled rule, named by the `it:app:yara:rule` guid. |
| `/vertex/storage/` (other) | Standard Cell state: auth, nexus log, `cell.yaml`, `cell.guid`. |

The files in the rule directory are the service's rule set. The service reads the directory
again on every scan, rule list and rule count, so rule files added, replaced or removed while it
runs (ex. restored from a backup) take effect without a restart.

If the rule directory is lost (ex. a new volume), the Cortex still has `:enabled=(true)` on the
rules but the service has none. Run [`slib.yara.sync`](commands.md#slibyarasync) to recompile
them.

## Network

| Direction | Port / target | Purpose |
| --- | --- | --- |
| Inbound | `27492/tcp` (Telepath, when `dmon:listen` is set) | The Cortex calls the service. |
| Inbound | `4443/tcp` (HTTPS, optional) | Standard Cell HTTPS API; not used by the Storm package. |
| Outbound | the Axon in `axon_url` | Pull file sizes and bytes to scan. |

No internet egress is needed.

## Docker compose example

```yaml
services:
  axon:
    image: vertexproject/synapse-axon:v2.x.x
    environment:
      SYN_AXON_DMON_LISTEN: tcp://0.0.0.0:27492/
      SYN_AXON_AUTH_PASSWD: axonsecret
    volumes:
      - axon-storage:/vertex/storage

  yarastorm:
    image: ghcr.io/gormaniac/stormsvcs/yarastorm:<version>
    environment:
      SYN_YARASVC_DMON_LISTEN: tcp://0.0.0.0:27492/
      SYN_YARASVC_AUTH_PASSWD: yarasecret
      SYN_YARASVC_AXON_URL: tcp://root:axonsecret@axon:27492/
      SYN_YARASVC_MAX_SIZE: "104857600"
    volumes:
      - yarastorm-storage:/vertex/storage
    depends_on:
      - axon

volumes:
  axon-storage:
  yarastorm-storage:
```

The Axon must be the same one the Cortex stores file bytes in (the Cortex's `axon` config), or
the files a user scans won't be found.

## Adding the service to a Cortex

```text
service.add yara tcp://root:yarasecret@yarastorm:27492/
service.list
```

`service.list` shows the service as ready with the name you gave it, its Storm service name,
and version, ex. `true (yara) (slib.yara @ <version>)`. The `slib.yara` package (commands and modules) is loaded
automatically when the Cortex connects. The Storm code looks the service up with
`$lib.service.get(slib.yara)`, which matches the service's own name, so the name you pass to
`service.add` can be anything.

The first time the service is added, its `add` event runs:

```text
[(meta:source=12bc0c8c1a37a29808d97972875d3913 :name=slib.yara)]
```

### Service user

The user in the `service.add` URL is the service-side user every call runs as. Changing rules
(`compileRule` without `check`, `removeRule`) requires that user to have the `slib.yara.admin`
permission **on the service**. The service's `root` user has it. If you connect as a non-admin
service user, grant it the rule on the service, ex. with Synapse's `moduser` tool, run inside the service
container:

```bash
docker exec yarastorm uv run --no-sync --directory /opt/stormsvcs/yarastorm \
    python -m synapse.tools.service.moduser --svcurl cell:///vertex/storage/ \
    --allow slib.yara.admin cortexuser
```

Otherwise enable, disable and sync fail with
`The service user <name> needs the slib.yara.admin permission.`

## Permissions for Cortex users

| Permission | Needed for |
| --- | --- |
| `service.get.<service iden>` | Every command; the modules call `$lib.service.get(slib.yara)`. |
| `slib.yara.admin` (declared by the package, `gate: cortex`) | `slib.yara.enable`, `slib.yara.disable`, `slib.yara.sync`, and the `slib.yara.lib` functions `enableRule`, `disableRule`, `sync`. |
| `node.prop.set.it:app:yara:rule.enabled` | `slib.yara.enable` / `slib.yara.disable`. |
| `node.add.it:app:yara:match`, `node.prop.set.it:app:yara:match`, `node.edge.add.seen`, `node.add.meta:source`, `node.prop.set.meta:source.name` | `slib.yara.scan` writing matches. All five are needed, even when the `meta:source` and the match already exist. |

`slib.yara.check` and `slib.yara.scan` don't need `slib.yara.admin`.

For the match's `.seen` Synapse checks `node.prop.set.it:app:yara:match..seen` (or
`node.prop.set` with the full prop `it:app:yara:match.seen`), and for `:version`
`node.prop.set.it:app:yara:match.version`. `auth.user.addrule` splits a rule on every `.`, so it
can't grant the universal prop by itself; grant `node.prop.set.it:app:yara:match`, which covers
both. These were checked against Synapse 2.256.0 (a test runs the scan as a user with only these
permissions).

```text
auth.user.addrule analyst1 service.get
auth.user.addrule analyst1 node.add.it:app:yara:match
auth.user.addrule analyst1 node.prop.set.it:app:yara:match
auth.user.addrule analyst1 node.edge.add.seen
auth.user.addrule analyst1 node.add.meta:source
auth.user.addrule analyst1 node.prop.set.meta:source.name
```

Rule managers also need:

```text
auth.user.addrule analyst1 slib.yara.admin
```

## Upgrades

Pull the new image tag and recreate the container with the same `/vertex/storage` volume. The
Cortex reloads the `slib.yara` package from the service on reconnect. Compiled rules in
`rule_dir` are Yara-X serialized `Rules`; a rule file that a newer `yara-x` can't deserialize is
logged once (`Skipping unreadable compiled Yara rule ...`) and skipped, not fatal, and every
scan warns `Couldn't load it:app:yara:rule=<guid> from the service's storage: ...` for it until
it's recompiled or removed. After an upgrade
that changes the `yara-x` version, run `slib.yara.sync` to recompile every enabled rule.
