# Deployment

## Docker image

The published image is `ghcr.io/gormaniac/stormsvcs/crtsh`. CI pushes it only from `main`,
tagged `latest`, the `pyproject.toml` version, and the commit SHA. Pin a version
tag in production.

The production Dockerfile ({src}`svcs/crtsh/docker/prod/Dockerfile`) builds on the stormsvcs
base image, `ghcr.io/gormaniac/stormsvcs/base` (the `BASE_IMAGE` build arg, `latest` by
default). The base image ({src}`docker/Dockerfile`) is `vertexproject/vtx-base-image:py311`
pinned by digest, plus `uv`. It sets `SYN_LOG_LEVEL=INFO`, exposes ports 4443 and 27492, and
declares `VOLUME /vertex/storage`. The crtsh build then:

1. Copies `pyproject.toml`, `uv.lock`, `src/crtshsvc`, and `README.md` into
   `/opt/stormsvcs/crtsh/`, and copies the repo `LICENSE` from the base image.
2. Runs `uv sync --no-dev --locked` to install the locked dependencies (`synapse`, `asyncpg`,
   `cryptography`, `stormlibpp`) into the project venv.
3. Installs `docker/prod/entrypoint.sh` and runs it under `tini`:

   ```bash
   exec uv run --no-sync --directory /opt/stormsvcs/crtsh/ python -O -m crtshsvc /vertex/storage
   ```

4. Defines a `HEALTHCHECK` every 30s (10s start period, 10s timeout, 1 retry) that runs
   `python -m synapse.tools.service.healthcheck -c cell:///vertex/storage/`.

The image needs no extra system packages or tools. `asyncpg` speaks the PostgreSQL protocol
itself, so there's no `libpq` or `psql` in the image.

The test image ({src}`svcs/crtsh/docker/test/Dockerfile`) builds on the production image, adds
`tests/` and the dev dependencies, and runs `pytest` as its entrypoint. CI uses it to test the
built image.

## Cell configuration

These are the service's own config options (`CrtshSvc.confdefs` in
{src}`svcs/crtsh/src/crtshsvc/svc.py`). All of them are read once, when the cell starts, so
restart the service after you change one.

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `crtsh:dsn` | string | `postgresql://guest@crt.sh:5432/certwatch` | The PostgreSQL DSN of the certwatch database, or of a mirror of it. |
| `crtsh:timeout` | number | `660` | Seconds the service waits for one query before it gives up (client side). `0` means no timeout. Keep it a little longer than `crtsh:statement:timeout`, so the server cancels a slow query first. |
| `crtsh:statement:timeout` | number | `600` | The server `statement_timeout` of each of the service's own queries, in seconds. `0` means no limit. crt.sh's default of 30s cancels big queries. `slib.crtsh.admin.sql` doesn't use it, it runs under the server's own timeout. |
| `crtsh:retries` | integer | `3` | How many times a query is retried after the connection drops (also after a replica serialization cancel). |
| `crtsh:timeout:retries` | integer (min 0) | `1` | How many times a query is retried after the server cancels it for its statement timeout. `0` means no retries. |
| `crtsh:keepalive` | number | `10` | Seconds between keepalive checks of an open connection. |
| `crtsh:idle` | number | `300` | Seconds without a query before the connection is closed. |
| `crtsh:connect:timeout` | number | `300` | Seconds to keep retrying, with backoff, while crt.sh refuses a connection. |
| `crtsh:limit` | integer | `10000` | The most certificates any one call may return. A call's `limit` is capped at this, and a `limit` below 1 is an error. |
| `crtsh:sql:limit` | integer | `1000` | The most rows `slib.crtsh.admin.sql` (`rawQuery`) may return. |
| `crtsh:candidates` | integer | `10000` | The most full text search candidates a search filters (crt.sh's own search uses 10000). |

[Database access](database.md) explains exactly how the timeouts, retries, keepalive, and
idle close interact.

:::{warning}
Queries run one at a time on a single connection. If you set both `crtsh:timeout` and
`crtsh:statement:timeout` to `0`, one slow query can block every other call to the service.
:::

The usual Synapse cell options also apply (`auth:passwd`, `dmon:listen`, `https:port`, `aha:*`,
and so on). See the
[Synapse devops docs](https://synapse.docs.vertex.link/en/latest/synapse/devopsguide.html).

### Environment variables

Synapse resolves cell config from environment variables named `SYN_<CELLCLASS>_<OPTION>`. The
cell class here is `CrtshSvc`, so the prefix is `SYN_CRTSHSVC_`, and the option name is
uppercased with `:` replaced by `_`:

| Option | Environment variable |
| --- | --- |
| `crtsh:dsn` | `SYN_CRTSHSVC_CRTSH_DSN` |
| `crtsh:timeout` | `SYN_CRTSHSVC_CRTSH_TIMEOUT` |
| `crtsh:statement:timeout` | `SYN_CRTSHSVC_CRTSH_STATEMENT_TIMEOUT` |
| `crtsh:retries` | `SYN_CRTSHSVC_CRTSH_RETRIES` |
| `crtsh:timeout:retries` | `SYN_CRTSHSVC_CRTSH_TIMEOUT_RETRIES` |
| `crtsh:keepalive` | `SYN_CRTSHSVC_CRTSH_KEEPALIVE` |
| `crtsh:idle` | `SYN_CRTSHSVC_CRTSH_IDLE` |
| `crtsh:connect:timeout` | `SYN_CRTSHSVC_CRTSH_CONNECT_TIMEOUT` |
| `crtsh:limit` | `SYN_CRTSHSVC_CRTSH_LIMIT` |
| `crtsh:sql:limit` | `SYN_CRTSHSVC_CRTSH_SQL_LIMIT` |
| `crtsh:candidates` | `SYN_CRTSHSVC_CRTSH_CANDIDATES` |
| `auth:passwd` | `SYN_CRTSHSVC_AUTH_PASSWD` (the cell's root password, used for `service.add`) |

You can also set options in `/vertex/storage/cell.yaml`. The Telepath listener defaults to
`tcp://0.0.0.0:27492` (override it with `SYN_CRTSHSVC_TELEPATH`) and HTTPS to port 4443
(`SYN_CRTSHSVC_HTTPS`).

## Secrets

crt.sh's database needs no credentials: the DSN uses the password-less `guest` role. The only
secret is the cell's own root password (or whatever Telepath user you create for the Cortex).
If you point `crtsh:dsn` at a mirror that needs a password, the password is part of the DSN,
which is stored wherever you set the option (`cell.yaml` or the environment).

:::{note}
The service doesn't redact error messages (`CrtshCellApi` doesn't override `_retnRedact`).
Connection errors are returned as `Unable to connect to the crt.sh database: <error>`, with the
error from `asyncpg`.
:::

## Persistent state

The service keeps no data of its own. `/vertex/storage` holds only the standard cell state
(`cell.yaml`, the cell's identity, and its auth database). There's no Axon use and no files or
slabs of crt.sh data. All modeled data lives in the Cortex: nodes, the `slib:crtsh` node data,
and two Cortex global variables (`slib:crtsh:tag:enabled` and `slib:crtsh:tag:prefix`, see
[Tags](model.md#tags)).

## Network egress

The service needs outbound **TCP 5432 to `crt.sh`** (or to whatever host `crtsh:dsn` names).
It makes no HTTP calls. The `https://crt.sh/?id=<id>` links in the certificate details are
built locally.

crt.sh allows **one connection per client IP**. While the service holds its connection, other
clients behind the same IP (ex. `psql`, or a second instance of the service) are refused, and
the other way round. The service closes its connection after `crtsh:idle` seconds without a
query. Run only one instance per egress IP.

## docker-compose

```yaml
services:
  slib-crtsh:
    image: ghcr.io/gormaniac/stormsvcs/crtsh:<version>
    restart: unless-stopped
    volumes:
      - ./storage/slib-crtsh:/vertex/storage
    ports:
      - "27492:27492"
    environment:
      SYN_CRTSHSVC_AUTH_PASSWD: "change-me"
      # Optional, these are the defaults:
      # SYN_CRTSHSVC_CRTSH_DSN: "postgresql://guest@crt.sh:5432/certwatch"
      # SYN_CRTSHSVC_CRTSH_STATEMENT_TIMEOUT: "600"
      # SYN_CRTSHSVC_CRTSH_TIMEOUT: "660"
```

## Adding the service to a Cortex

```text
service.add slib.crtsh tcp://root:change-me@<host>:27492/*
service.list
```

`service.list` should show `true (svc) (slib.crtsh @ <version>)` for the service. When the Cortex
connects, the service pushes the `slib.crtsh` Storm package (`pkg.list` shows it). On
`service.add`, the service's `add` event runs Storm in the Cortex that:

- Creates the `slib.crtsh` `meta:source` node (guid `c7357722661f45a4b81c91ccfbbb37c0`,
  `:name="crt.sh"`, `:type=slib.crtsh`, `:url=https://crt.sh`).
- Sets the global `slib:crtsh:tag:enabled` to `true` and `slib:crtsh:tag:prefix` to
  `rep.crtsh`, but only if they aren't set already.

## Permissions

The package defines two permissions, both gated on the Cortex:

| Permission | Grants |
| --- | --- |
| `slib.crtsh.user` | `slib.crtsh.cert`, `slib.crtsh.search`, `slib.crtsh.pivot`, `slib.crtsh.chain`, `slib.crtsh.ca`, and importing the `slib.crtsh.lib` and `slib.crtsh.model` modules. |
| `slib.crtsh.admin` | `slib.crtsh.admin.tags` and `slib.crtsh.admin.sql`. |

```text
auth.user.addrule visi slib.crtsh.user
auth.role.addrule crtsh-admins slib.crtsh.admin
```

Users don't need `service.get`. Only the `slib.crtsh.priv.user` and `slib.crtsh.priv.admin`
modules call the service, and they run `asroot` for users who hold `slib.crtsh.user` or
`slib.crtsh.admin` respectively. Calling `$lib.service.get("slib.crtsh")` directly still
requires `service.get`.

Node edits run as the calling user, so users also need node permissions in the view they work
in. For the forms, props, tags, edges, and node data the service writes, see
[Data model](model.md). The tests grant the blanket `node` rule. A narrower set covers:

- `node.add` and `node.prop.set` for `crypto:x509:cert`, `crypto:key`, `rsa:key`,
  `crypto:x509:crl`, `crypto:x509:revoked`, and `meta:source`, plus any forms the props
  create (ex. `inet:fqdn`, `inet:url`, `file:bytes`).
- `node.tag.add` for the configured tag prefix (`rep.crtsh` by default).
- `node.edge.add.seen` and `node.edge.add.refs`.
- `node.data.set.slib:crtsh`.

## Upgrades

1. Pull the new tag and recreate the container with the same `/vertex/storage` volume. There's
   no service state to migrate.
2. When the service reconnects, the Cortex loads the new version of the `slib.crtsh` package.
   `service.list` shows the new version.
3. The `add` event only runs on `service.add`, so upgrading leaves the tag settings alone.
