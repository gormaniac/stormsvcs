# Deployment

## Docker image

The service is published as `ghcr.io/gormaniac/stormsvcs/shodan`, tagged `latest`, the
service's version (the `version` in {src}`svcs/shodan/pyproject.toml`), and the
commit SHA. Images are only pushed from `main`.

The production image ({src}`svcs/shodan/docker/prod/Dockerfile`) builds on the stormsvcs base
image, `ghcr.io/gormaniac/stormsvcs/base` (the `BASE_IMAGE` build arg, `latest` by default).
The base image ({src}`docker/Dockerfile`) is `vertexproject/vtx-base-image:py311` plus `uv`,
with `SYN_LOG_LEVEL=INFO`, upgraded system packages, `EXPOSE 4443` and `EXPOSE 27492`, and
`VOLUME /vertex/storage`.

The service's Dockerfile:

1. Copies `pyproject.toml`, `uv.lock`, `src/shodansvc` and `README.md` to
   `/opt/stormsvcs/shodan`, and copies the repo `LICENSE` from the base image.
2. Runs `uv sync --no-dev --locked`, so the image has exactly the locked Synapse, StormLib++ and
   `aiohttp` versions, and no test dependencies.
3. Sets the entrypoint to `tini -- /opt/stormsvcs/shodan/entrypoint.sh`, which runs
   `uv run --no-sync python -O -m shodansvc /vertex/storage`.
4. Adds a healthcheck (every 30s, 10s timeout, 10s start period, 1 retry) that runs
   `python -m synapse.tools.service.healthcheck -c cell:///vertex/storage/`.

The service installs no system packages or tools of its own. It only needs Python and
network access to Shodan.

A test image ({src}`svcs/shodan/docker/test/Dockerfile`) builds on the production image, adds
`tests/` and the dev dependencies, and runs `pytest`. CI uses it to test the image it just
built (see {doc}`/dev/ci`).

## Cell configuration

`ShodanSvc` adds these options to the standard Synapse Cell options
(`confdefs` in {src}`svcs/shodan/src/shodansvc/svc.py`):

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `shodan:apikey` | `string` or `null` | `null` | The last fallback API key, used when neither the calling user's vault key nor the stored service-wide key is set. See [API keys](#api-keys). |
| `shodan:ratelimit` | `number` | `1.0` | Max requests/second to the `api` and `trends` APIs (Shodan's key-based limit). Shared by every user. `0` or a negative number turns the limiter off. |
| `shodan:timeout` | `number` | `60` | Total timeout, in seconds, of one non-streaming request. Streams use the command's `--timeout` instead. |
| `shodan:urls` | `object` | `{}` | Overrides for the base URL of each API, keyed by `api`, `stream`, `trends`, `internetdb` or `cvedb`. Ex. a proxy, a mirror, or a test server. |

The default base URLs are:

| Key | URL | Needs a key | Rate limited |
| --- | --- | --- | --- |
| `api` | `https://api.shodan.io` | yes | yes |
| `stream` | `https://stream.shodan.io` | yes | no |
| `trends` | `https://trends.shodan.io` | yes | yes |
| `internetdb` | `https://internetdb.shodan.io` | no | no |
| `cvedb` | `https://cvedb.shodan.io` | no | no |

`it:exec:query:api:url` values are always built from these public URLs, even when
`shodan:urls` overrides them, so internal hosts are never recorded.

The standard Cell options also apply. The ones a deployment usually sets:

| Option | Meaning |
| --- | --- |
| `auth:passwd` | Bootstraps the service's `root` password, which the Cortex uses to connect. |
| `dmon:listen` | The Telepath listen URL. The entrypoint doesn't set it, and the Cell's command line defaults `--telepath` to `tcp://0.0.0.0:27492`. |
| `https:port` | The Cell's HTTPS port. The command line default is `4443`. The Storm package doesn't use it. |
| `aha:*` | AHA registration and provisioning, if you use AHA. |

Options can be set in `/vertex/storage/cell.yaml`, or with environment variables.

## Environment variables

Synapse reads Cell options from variables named `SYN_<CLASS>_<OPTION>`, where `<CLASS>` is the
Cell class name in upper case (`SHODANSVC`) and `<OPTION>` is the option name in upper case with
`:` replaced by `_`. Values are parsed as YAML, so numbers and objects work.

| Variable | Option |
| --- | --- |
| `SYN_SHODANSVC_SHODAN_APIKEY` | `shodan:apikey` |
| `SYN_SHODANSVC_SHODAN_RATELIMIT` | `shodan:ratelimit` |
| `SYN_SHODANSVC_SHODAN_TIMEOUT` | `shodan:timeout` |
| `SYN_SHODANSVC_SHODAN_URLS` | `shodan:urls`, ex. `{"cvedb": "https://cvedb.internal"}` |
| `SYN_SHODANSVC_AUTH_PASSWD` | `auth:passwd` |
| `SYN_SHODANSVC_DMON_LISTEN` | `dmon:listen` |
| `SYN_SHODANSVC_TELEPATH` | The `--telepath` listen URL (default `tcp://0.0.0.0:27492`) |
| `SYN_SHODANSVC_HTTPS` | The `--https` port (default `4443`) |
| `SYN_LOG_LEVEL` | Log level, `INFO` in the base image |

The HTTP session is created with `trust_env=True`, so `HTTP_PROXY`, `HTTPS_PROXY` and
`NO_PROXY` are honored for every request to Shodan.

## API keys

Every keyed request resolves its key in this order (`ShodanSvc.getApiKey()`):

1. **The calling user's key.** Set with `slib.shodan.apikey <key>`. It's stored in the Cortex
   in a user scoped Synapse vault of type `shodan` (named `shodan:<username>`), under the
   secret `apikey`. The `slib.shodan.priv.*` modules only read the calling user's own user
   scoped vault, so a key is only ever used for its owner's requests.
2. **The service-wide key.** Set with `slib.shodan.admin.apikey <key>`. It's stored in the
   service, not in the Cortex, in the Cell's slab (`/vertex/storage/slabs/cell.lmdb`, key-value
   store `slib:shodan`, key `apikey`). Storm can't read it back, only check whether it's set.
3. **The `shodan:apikey` option.**

InternetDB and CVEDB never get a key. When a keyed API is called without one, the call fails
with `No Shodan API key is configured. Add a 'shodan' vault or run slib.shodan.admin.apikey to
set a service-wide key.` `slib.shodan.host` checks first and falls back to InternetDB.

Keys go to Shodan as the `key` query parameter. They're never written to a node: the
`it:exec:query:opts` and `:api:url` the package records never contain one, and the service
removes the `api_key` field Shodan includes in scan results.

:::{warning}
A Cortex user with the `service.get` permission for this service can call its Telepath
methods directly from Storm (`$lib.service.get(slib.shodan)`), including `setApiKey()` and
`rawRequest()` with the service-wide key. The service itself checks no permissions. Grant
`service.get` only to admins, and use the `slib.shodan.*` permissions for everyone else.
:::

## Persistent state

Mount a volume at `/vertex/storage`. It holds the standard Cell state (users, the Cell's
`cell.guid`, `cell.yaml`, slabs) and the stored service-wide API key. Nothing else is written
to disk.

Kept only in memory, and lost on restart:

- The facet limit learned for each API key's plan (keyed by the SHA-256 of the key), trusted
  for 24 hours. See [internals](internals.md#countips-and-facet-limits).

Stored in the Cortex, not the service:

- User API keys (vaults), and the tag settings (the `slib:shodan:tag:enabled` and
  `slib:shodan:tag:prefix` Storm globals).
- File bytes the package saves while modeling banners go to the Cortex's Axon, for users with
  `axon.upload`. The service never talks to an Axon.

## Network

| Direction | Port / target | Purpose |
| --- | --- | --- |
| Inbound | `27492/tcp` (Telepath) | The Cortex calls the service. |
| Inbound | `4443/tcp` (HTTPS, optional) | The standard Cell HTTPS API. Not used by the Storm package. |
| Outbound | `api.shodan.io:443` | The main REST API. |
| Outbound | `stream.shodan.io:443` | The Streaming API (`slib.shodan.stream`). |
| Outbound | `trends.shodan.io:443` | Trends (`slib.shodan.trends`). |
| Outbound | `internetdb.shodan.io:443` | InternetDB (`slib.shodan.host --internetdb`, or no key). |
| Outbound | `cvedb.shodan.io:443` | CVEDB (`slib.shodan.cve`, `slib.shodan.cpe`, `slib.shodan.enrich`). |

Only the hosts for the features you use are needed. A proxy can be set with the standard
proxy variables, or the base URLs pointed elsewhere with `shodan:urls`.

## Docker compose example

```yaml
services:
  shodan:
    image: ghcr.io/gormaniac/stormsvcs/shodan:<version>
    environment:
      SYN_SHODANSVC_AUTH_PASSWD: shodansecret
      # Optional: a fallback key. slib.shodan.admin.apikey stores one in the service instead.
      SYN_SHODANSVC_SHODAN_APIKEY: ${SHODAN_API_KEY:-}
      SYN_SHODANSVC_SHODAN_TIMEOUT: "60"
      # Optional: send every request through a proxy.
      # HTTPS_PROXY: http://proxy.internal:3128
    volumes:
      - shodan-storage:/vertex/storage
    ports:
      - "27492:27492"

volumes:
  shodan-storage:
```

Leave `SYN_SHODANSVC_SHODAN_APIKEY` out entirely if you don't want a config key. An empty
string isn't a key (`getApiKey()` skips empty values).

## Adding the service to a Cortex

```text
service.add slib.shodan tcp://root:shodansecret@shodan:27492/
service.list
```

`service.list` shows the service as ready, ex. `true (slib.shodan) (slib.shodan @ <version>)`.
The `slib.shodan` package is loaded when the Cortex connects. The Storm code finds the service
with `$lib.service.get("slib.shodan")`, which matches the service's own Storm service name, so
the name given to `service.add` can be anything.

The user in the URL is the service-side user every call runs as. The service checks no
service-side permissions, so any service user works. `root` is the simplest.

The first time the service is added, its `add` event runs:

```text
[(meta:source=5c1b0a3d0e7f4b2e9a8c6d4f2b1e0a97 :name="shodan" :type=slib.shodan :url=https://www.shodan.io)] | spin |
if ($lib.globals.get("slib:shodan:tag:enabled") = null) { $lib.globals.set("slib:shodan:tag:enabled", (true)) }
if ($lib.globals.get("slib:shodan:tag:prefix") = null) { $lib.globals.set("slib:shodan:tag:prefix", "rep.shodan") }
```

It creates the service's `meta:source` and turns tagging on with the `rep.shodan` prefix,
unless the settings already exist.

## Permissions

The package declares four permissions, all with `gate: cortex`:

| Permission | Grants |
| --- | --- |
| `slib.shodan.user` | Lookups, search, count, hashes, DNS, CVEDB, Trends, streams, saved queries, account info, reference data, and setting your own key. |
| `slib.shodan.scan` | `slib.shodan.scan`, `slib.shodan.scan.status`, `slib.shodan.scan.internet`. |
| `slib.shodan.alert` | Network alerts and notifiers (`slib.shodan.alert.*`, `slib.shodan.notifier.*`). |
| `slib.shodan.admin` | The service-wide key, tag settings, the DNS cleanup, the organization, bulk data, and raw requests. |

```text
auth.user.addrule analyst slib.shodan.user
auth.user.addrule analyst slib.shodan.scan
auth.role.addrule shodan-admins slib.shodan.admin
```

Users don't need `service.get`. The commands also make nodes as the calling user, so users
need the usual node permissions for what they model (ex. `node.add`, `node.prop.set`,
`node.tag.add`, `node.edge.add`). Some features need more:

| Feature | Extra permissions |
| --- | --- |
| Saving files from banners to the Axon | `axon.upload` (without it, the `file:bytes` nodes are still made) |
| Hashing `file:bytes` (`slib.shodan.hash`, and search/count/trends of `file:bytes`) | `axon.has` and `axon.get` |
| `slib.shodan.scan --wait` (ingesting the results) | `slib.shodan.user` |
| `slib.shodan.admin.dns.cleanup --apply` | `node.del` for `inet:dns:a`/`inet:dns:aaaa`, edge delete permissions for `seen`, and `node.add` for `inet:dns:rev`/`inet:dns:rev6` |

A user can save their own key with `slib.shodan.apikey` with only `slib.shodan.user`: a user
scoped vault owned by the user doesn't need another permission.

## Upgrades

Pull the new image tag and restart the container with the same volume. When the Cortex
reconnects, it loads the new `slib.shodan` package. The `add` event doesn't run again, and the
tag settings it made are kept.

0.17.0 changed how some data is modeled. Older nodes aren't changed, except by
`slib.shodan.admin.dns.cleanup`, which replaces the `inet:dns:a`/`aaaa` nodes older versions
made from Shodan's hostnames with `inet:dns:rev`/`rev6` nodes. Run it once after upgrading
from before 0.17.0, first as a dry run:

```text
slib.shodan.admin.dns.cleanup
slib.shodan.admin.dns.cleanup --apply
```

See {ref}`shodan-cmd-admin-dns-cleanup` and the [model](model.md) page for what changed.
