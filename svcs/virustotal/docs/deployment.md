# Deployment

## Container image

The service is published as `ghcr.io/gormaniac/stormsvcs/virustotal`, tagged `latest`, the
service version from {src}`svcs/virustotal/pyproject.toml`, and the commit SHA.
Images are only pushed from `main`.

The production image ({src}`svcs/virustotal/docker/prod/Dockerfile`) is built on the
monorepo's base image, `ghcr.io/gormaniac/stormsvcs/base` (override it with the
`BASE_IMAGE` build arg). The base image ({src}`docker/Dockerfile`) is
`vertexproject/vtx-base-image:py311` (pinned by digest) plus `uv`, with
`SYN_LOG_LEVEL=INFO`, ports `4443` and `27492` exposed, upgraded system packages, and
`VOLUME /vertex/storage`.

The service's build:

1. Copies `pyproject.toml`, `uv.lock`, `src/vtsvc`, and `README.md` to
   `/opt/stormsvcs/virustotal/`, and the monorepo `LICENSE` next to them.
2. Runs `uv sync --no-dev --locked` there, installing exactly the locked Synapse and
   StormLib++ (and the service itself) into `/opt/stormsvcs/virustotal/.venv`.
3. Sets the entrypoint to `tini -- /opt/stormsvcs/virustotal/entrypoint.sh`, which runs:

   ```bash
   exec uv run --no-sync --directory /opt/stormsvcs/virustotal/ python -O -m vtsvc /vertex/storage
   ```

4. Adds a healthcheck (every 30s, 10s timeout, 10s start period, 1 retry) that runs
   `python -m synapse.tools.service.healthcheck -c cell:///vertex/storage/`.

No extra system packages or tools are installed; the service only needs Python, `aiohttp`
(from Synapse), and network access to VirusTotal.

The test image ({src}`svcs/virustotal/docker/test/Dockerfile`) is built on the production
image, adds `tests/` and the dev dependencies, and runs `pytest` as its entrypoint. CI uses it
to run the tests against the image it just built.

## Ports, storage, and egress

| What | Value |
| --- | --- |
| Telepath | `tcp://0.0.0.0:27492` (the Synapse cell default, `--telepath` / `SYN_VTSVC_TELEPATH`) |
| HTTPS | `4443` (the cell default, `--https` / `SYN_VTSVC_HTTPS`). The service defines no HTTP API of its own. |
| Storage | `/vertex/storage` (the cell directory). Mount a volume here. |
| Egress | HTTPS to `www.virustotal.com` (or whatever `vt:url` is set to). For files over 32MB, also the one time upload URL VirusTotal returns from `GET /files/upload_url`. |

The HTTP session is created with `trust_env=True`, so the standard `HTTPS_PROXY`,
`HTTP_PROXY`, and `NO_PROXY` environment variables are honored for outbound requests.

What lives in the cell directory:

| Where | What |
| --- | --- |
| `slabs/cell.lmdb`, SafeKeyVal `slib:vt` | `apikey`: the service-wide API key set with `slib.vt.admin.apikey`, stored as plain text. |
| `slabs/cell.lmdb`, SafeKeyVal `slib:vt:quota` | The rate limiter's per key request times and daily/monthly counts, keyed by a hash of the key (see [Rate limits and quotas](quota.md#persisted-state)). |
| `cell.yaml`, cell auth, etc. | The standard Synapse cell files. |

The response cache is in memory only and is empty after a restart.

## Configuration

The service's options, from `VtSvc.confdefs` in {src}`svcs/virustotal/src/vtsvc/svc.py`. Set
them in `/vertex/storage/cell.yaml`, as environment variables, or as command line flags.

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `vt:apikey` | string or null | `null` | A VirusTotal API key used when neither the calling user's own key (`slib.vt.apikey`) nor the stored service-wide key (`slib.vt.admin.apikey`) is set. |
| `vt:community` | boolean | `true` | The keys are Public API keys: enforce `vt:limit:*` per key, and only allow the relationships a Public API key can read. Set `false` for premium keys. |
| `vt:limit:minute` | integer, min 0 | `4` | Max requests per minute (a 61 second sliding window), per key, while `vt:community` is true. `0` disables the per minute limit. |
| `vt:limit:day` | integer, min 0 | `500` | Max requests per UTC day, per key, while `vt:community` is true. `0` for no limit. |
| `vt:limit:month` | integer, min 0 | `15500` | Max requests per UTC month, per key, while `vt:community` is true. `0` for no limit. |
| `vt:limit:maxwait` | number, min 0 | `600` | The most seconds a request waits for room under the per minute limit (or a 429 cooldown) before it fails. `0` waits as long as it takes. |
| `vt:cache:ttl` | number, min 0 | `3600` | Seconds a cacheable successful GET is cached. `0` disables the cache. |
| `vt:cache:size` | integer, min 0 | `1000` | The most responses kept in the cache (LRU). `0` disables the cache. |
| `vt:verdict:malicious` | integer, min 1 | `3` | Engines that must say malicious for an overall malicious verdict; fewer detections are suspicious. |
| `vt:timeout` | number, min 1 | `120` | Total timeout, in seconds, of one HTTP request. |
| `vt:url` | string | `https://www.virustotal.com/api/v3` | The API's base URL (useful for a proxy or tests). |

All options are read once at startup; change them and restart the service. The limits apply
to all keys; there is no per key configuration.

The standard Synapse cell options (`auth:passwd`, `aha:*`, `dmon:listen`, `https:port`,
`nexslog:en`, `backup:dir`, ...) also apply; see the
[Synapse devops docs](https://synapse.docs.vertex.link/en/latest/synapse/devopsguide.html).

### Environment variables

Synapse maps every option to `SYN_VTSVC_<OPTION>`: the option name upper cased, with `:`
replaced by `_` (the prefix comes from the cell class name, `VtSvc`). Values are parsed as
YAML.

| Option | Environment variable | CLI flag |
| --- | --- | --- |
| `vt:apikey` | `SYN_VTSVC_VT_APIKEY` | (none) |
| `vt:community` | `SYN_VTSVC_VT_COMMUNITY` | `--vt-community` |
| `vt:limit:minute` | `SYN_VTSVC_VT_LIMIT_MINUTE` | `--vt-limit-minute` |
| `vt:limit:day` | `SYN_VTSVC_VT_LIMIT_DAY` | `--vt-limit-day` |
| `vt:limit:month` | `SYN_VTSVC_VT_LIMIT_MONTH` | `--vt-limit-month` |
| `vt:limit:maxwait` | `SYN_VTSVC_VT_LIMIT_MAXWAIT` | `--vt-limit-maxwait` |
| `vt:cache:ttl` | `SYN_VTSVC_VT_CACHE_TTL` | `--vt-cache-ttl` |
| `vt:cache:size` | `SYN_VTSVC_VT_CACHE_SIZE` | `--vt-cache-size` |
| `vt:verdict:malicious` | `SYN_VTSVC_VT_VERDICT_MALICIOUS` | `--vt-verdict-malicious` |
| `vt:timeout` | `SYN_VTSVC_VT_TIMEOUT` | `--vt-timeout` |
| `vt:url` | `SYN_VTSVC_VT_URL` | `--vt-url` |

`vt:apikey` has no command line flag (its type is a string or null); use the environment
variable or `cell.yaml`.

## API keys

The key for each request is resolved in this order (`VtSvc.getApiKey()`):

1. The calling user's own key: the `apikey` secret of their user scoped vault of type
   `virustotal`, set with [`slib.vt.apikey`](commands.md#slib-vt-apikey). The Storm package
   reads it and passes it to the service with each call.
2. The service-wide key stored in the service's slab, set with
   [`slib.vt.admin.apikey`](commands.md#slib-vt-admin-apikey).
3. The `vt:apikey` config option.

Without any key, every call fails with `No VirusTotal API key is configured. Run
slib.vt.apikey to set your own key, or slib.vt.admin.apikey to set a service-wide key.`

Limits are counted per key, so a user with their own key has their own quota, and everyone
else shares the service-wide key's quota. Keys are sent in the `x-apikey` header.

:::{warning}
The service's Telepath API is not permission gated per method: anything that can connect to
the service over Telepath can call `setApiKey`, `rawRequest`, and every other method, and its
calls use the service-wide key. Storm users reach the service only through the package's
`asroot` modules, which check the `slib.vt.*` permissions. Keep the Telepath port reachable
only by the Cortex and protect the service's user credentials.
:::

## docker-compose

```yaml
services:
  slib-vt:
    image: ghcr.io/gormaniac/stormsvcs/virustotal:<version>
    restart: unless-stopped
    environment:
      # Bootstraps the root user's password, used in the Cortex's service.add URL.
      SYN_VTSVC_AUTH_PASSWD: "change-me"
      # Optional fallback key. A key set with slib.vt.admin.apikey takes precedence.
      SYN_VTSVC_VT_APIKEY: "${VT_API_KEY:-}"
      # Public API limits are the defaults; for a premium key:
      # SYN_VTSVC_VT_COMMUNITY: "false"
      SYN_VTSVC_VT_CACHE_TTL: "3600"
    volumes:
      - slib-vt:/vertex/storage
    ports:
      - "27492:27492"

volumes:
  slib-vt:
```

If `VT_API_KEY` is unset this sets `vt:apikey` to an empty string, which the service treats
as no key. Omit the variable entirely if you only use stored or per user keys.

## Adding the service to a Cortex

```text
service.add slib.vt tcp://root:change-me@slib-vt:27492
service.list
```

`service.list` shows the service as `true (svc) (slib.vt @ <version>)` once the Cortex has
connected and loaded the `slib.vt` Storm package. The package is provided by the service
(`_storm_svc_pkgs`), so it is loaded and upgraded automatically.

When the service is first added, its `add` event runs once, as root:

```text
[(meta:source=176fcd24cf1f42bfa5d95a013eec1487 :name=virustotal :type=slib.vt
    :url=https://www.virustotal.com)]
// and, only if they're unset:
$lib.globals.set("slib:vt:tag:enabled", (true))
$lib.globals.set("slib:vt:tag:prefix", "rep.vt")
```

Then set a key and try it:

```text
slib.vt.admin.apikey <key>
slib.vt.enrich --fqdn example.com
slib.vt.quota
```

## Permissions

The package declares three permissions (gate `cortex`):

| Permission | Grants |
| --- | --- |
| `slib.vt.user` | Lookups: `slib.vt.enrich`, `slib.vt.related`, `slib.vt.comments`, `slib.vt.search`, `slib.vt.analysis`, `slib.vt.quota`, `slib.vt.apikey`. Also needed to import `slib.vt.lib`. |
| `slib.vt.submit` | Sending data to VirusTotal: `slib.vt.submit`, `slib.vt.rescan`, `slib.vt.comment`, `slib.vt.vote`. Submissions are shared with the VirusTotal community. |
| `slib.vt.admin` | `slib.vt.admin.apikey`, `slib.vt.admin.tags`, `slib.vt.admin.request`. |

Users don't need `service.get`: only the `asroot` modules talk to the service. The node edits
run as the calling user, so users also need node permissions for what gets modeled, ex. a
broad `node` rule, or `node.add.*`, `node.prop.set.*`, `node.tag.add.<prefix>`,
`node.tag.del.<prefix>`, and `node.edge.add.*` for the forms on the [Data model](model.md)
page. `slib.vt.submit` also reads files from the Axon (as root, inside the `asroot` module).

```text
auth.role.add vtusers
auth.user.addrule visi slib.vt.user
auth.user.grant visi vtusers
auth.role.addrule vtusers node
// Optional
auth.user.addrule visi slib.vt.submit
```

## Upgrades

Pull the new image tag and restart the container with the same volume. The Cortex reconnects
and loads the new package version. The service-wide key, the tag settings (Cortex globals),
and the rate limiter's counts persist; the response cache starts empty. Per user keys live in
the Cortex's vaults and are not affected.

Version history follows {doc}`/dev/versioning`. Node guids are kept stable across versions
(the tests check the guids the 0.2.0 package generated), so re-enriching after an upgrade
updates existing nodes rather than duplicating them.
