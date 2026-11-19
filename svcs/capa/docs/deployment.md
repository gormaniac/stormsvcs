# Deployment

## Docker image

The service is published as `ghcr.io/gormaniac/stormsvcs/capa`. CI pushes it only from `main`,
tagged `latest`, the service version from `pyproject.toml`, and the commit SHA.
Pin a version tag in production.

### How the image is built

The production Dockerfile is {src}`svcs/capa/docker/prod/Dockerfile`. It has two stages.

**Stage 1, `capa-data`** (`alpine:3.22` with `git`) fetches the data capa needs, pinned to the
release that matches the locked `flare-capa`:

| Build arg | Value | Use |
| --- | --- | --- |
| `CAPA_VERSION` | `v10.0.0` | The tag cloned from both `mandiant/capa-rules` and `mandiant/capa`. |
| `CAPA_RULES_COMMIT` | `805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5` | The build fails unless the capa-rules tag resolves to this commit. |
| `CAPA_COMMIT` | `85813ebc5b99ccdbe43147e46796d0bd6700f30a` | The build fails unless the capa tag resolves to this commit. |

The capa-rules checkout (without `.git` and `.github`) becomes `/capa/rules`, and a sparse
checkout of capa's `sigs/` directory (its FLIRT signatures) becomes `/capa/sigs`.
`tests/test_rules.py` checks that `capasvc.defs.RULES_VERSION` is `v` plus the installed capa
version, and that the Dockerfile's `CAPA_VERSION` is `RULES_VERSION`.

**Stage 2** is `FROM ${BASE_IMAGE}`, default `ghcr.io/gormaniac/stormsvcs/base:latest`. The
base image ({src}`docker/Dockerfile`) is `vertexproject/vtx-base-image:py311` (pinned by digest)
plus `uv`, with `SYN_LOG_LEVEL=INFO`, `EXPOSE 4443` and `EXPOSE 27492`, upgraded system
packages, and `VOLUME /vertex/storage`. The service stage then:

1. Copies `pyproject.toml`, `uv.lock`, `src/capasvc` and `README.md` to
   `/opt/stormsvcs/capa/`, and copies the repo `LICENSE` in.
2. Runs `uv sync --no-dev --locked`, installing the locked dependencies: Synapse `2.256.0`,
   StormLib++ `1.0.0` and `flare-capa==10.0.0` (with its analysis backends, ex. vivisect).
3. Copies the rules to `/opt/stormsvcs/capa/rules` (Apache 2.0, see `rules/LICENSE.txt`) and
   the signatures to `/opt/stormsvcs/capa/sigs`, and points the service at them:

   ```text
   ENV SYN_CAPASVC_CAPA_RULES="/opt/stormsvcs/capa/rules"
   ENV SYN_CAPASVC_CAPA_SIGS="/opt/stormsvcs/capa/sigs"
   ```

4. Runs the entrypoint ({src}`svcs/capa/docker/prod/entrypoint.sh`) under `tini`:

   ```bash
   exec uv run --no-sync --directory /opt/stormsvcs/capa/ python -O -m capasvc /vertex/storage
   ```

   so the cell directory (`dirn`) is always `/vertex/storage`.
5. A `HEALTHCHECK` runs `python -m synapse.tools.service.healthcheck -c cell:///vertex/storage/`
   every 30 seconds (10 second timeout, 10 second start period, 1 retry).

No system packages are added beyond the base image: capa runs as the Python module
`capa.main` from the service's own virtualenv.

The test image ({src}`svcs/capa/docker/test/Dockerfile`) is built `FROM` the production image
CI just built, adds `tests/`, `docker/prod/Dockerfile` and the dev dependencies, and runs
`pytest`. Because the production image sets `SYN_CAPASVC_CAPA_RULES`, the live tests
(`tests/test_live.py`) run there against the full bundled rules. It isn't meant for deployment.

## Cell configuration

The service-specific options, from `CapaSvc.confdefs` in {src}`svcs/capa/src/capasvc/svc.py`:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `axon:url` | string | unset | Telepath URL of the Axon files are pulled from. Unset: the service starts, but every scan returns `The slib.capa service has no axon:url configured.` |
| `capa:rules` | string | unset (the image sets `/opt/stormsvcs/capa/rules`) | The capa rules directory. Unset, or a directory that can't be loaded: the service starts, but every call that needs the rules returns the load error (ex. `The slib.capa service has no capa:rules directory configured.`). |
| `capa:rules:version` | string | `v10.0.0` | The version of the rules in `capa:rules`. Used in each rule's `:url`, the `meta:ruleset` name and guid, and the tag docs. |
| `capa:rules:url` | string | `https://github.com/mandiant/capa-rules/blob/{version}/{path}` | A `str.format` template for each rule's `:url`, given `{version}` and `{path}` (the rule's path relative to `capa:rules`). Any other field fails the rules load. `""` sets no URLs. |
| `capa:sigs` | string | unset (the image sets `/opt/stormsvcs/capa/sigs`) | A directory of FLIRT signatures capa uses to recognize library code in PE files. Unset: capa gets an empty directory, so library code is analyzed like any other code. |
| `capa:timeout` | integer, `minimum: 1` | `900` | Seconds before a capa run (or a rules cache build) is killed, and before a file's download from the Axon is stopped. |
| `capa:workers` | integer, `minimum: 1` | `2` | The max number of files fetched and analyzed at once. Further scans wait for a free worker. |
| `capa:maxsize` | integer, `minimum: 1` | `104857600` (100 MiB) | The max size in bytes of a file the service will scan, checked with `axon.size()` before the download. |

Connecting to the Axon has its own fixed timeout of 30 seconds (`AXON_TIMEOUT`), separate from
`capa:timeout`.

All the standard Synapse Cell options also apply (`dmon:listen`, `https:port`, `auth:passwd`,
`aha:*`, `nexslog:en`, ...); see the
[Synapse devops guide](https://synapse.docs.vertex.link/en/latest/synapse/devopsguide.html).

The Storm package has its own settings, stored as Cortex globals and changed with
[`slib.capa.admin.tags`](commands.md#slibcapaadmintags): the tag prefix (default `rep.capa`) and
whether scans tag files (default on).

### Environment variables

Synapse reads config from `SYN_<CELLCLASS>_<KEY>`, with the cell class name upper-cased and `:`
in the key replaced by `_`. The cell class is `CapaSvc`, so the prefix is `SYN_CAPASVC_`.
Values are parsed as YAML, so `SYN_CAPASVC_CAPA_WORKERS=4` is an integer.

| Variable | Config key |
| --- | --- |
| `SYN_CAPASVC_AXON_URL` | `axon:url` |
| `SYN_CAPASVC_CAPA_RULES` | `capa:rules` |
| `SYN_CAPASVC_CAPA_RULES_VERSION` | `capa:rules:version` |
| `SYN_CAPASVC_CAPA_RULES_URL` | `capa:rules:url` |
| `SYN_CAPASVC_CAPA_SIGS` | `capa:sigs` |
| `SYN_CAPASVC_CAPA_TIMEOUT` | `capa:timeout` |
| `SYN_CAPASVC_CAPA_WORKERS` | `capa:workers` |
| `SYN_CAPASVC_CAPA_MAXSIZE` | `capa:maxsize` |
| `SYN_CAPASVC_DMON_LISTEN` | `dmon:listen` |
| `SYN_CAPASVC_HTTPS_PORT` | `https:port` |
| `SYN_CAPASVC_AUTH_PASSWD` | `auth:passwd` |

The same keys can be set in `/vertex/storage/cell.yaml`:

```yaml
dmon:listen: tcp://0.0.0.0:27492/
axon:url: tcp://root:axonsecret@axon:27492/
capa:workers: 4
capa:timeout: 600
```

### Using other rules

To use rules other than the bundled release (ex. a fork, or a newer capa-rules tag that the
bundled capa can load):

1. Point `capa:rules` at the directory (mount it into the container), and set
   `capa:rules:version` (and `capa:rules:url`, or `""` for no URLs).
2. Restart the service, or run `slib.capa.admin.sync --reload` if only the files in the
   existing `capa:rules` directory changed.
3. The next package load (a restart reloads the package too) or `slib.capa.admin.sync` imports
   the changed rules.

Every rule in the directory must load, and rule names must be unique, or the whole load fails.
Scans refuse to run once the rule files on disk differ from the loaded rules (`The capa rules
on disk changed since the service loaded them, reload them with: slib.capa.admin.sync
--reload`), so results always match the imported rules.

## Secrets

The service uses no upstream API keys. The only credentials are Telepath ones:

- The password (or certificate) in `axon:url`, which the service uses to read from the Axon.
  It's stored wherever the config lives (environment or `cell.yaml`).
- The credentials the Cortex uses to connect to this service, given in `service.add`.
  `auth:passwd` bootstraps the service's `root` password.

## Persistent state

Everything lives in the `/vertex/storage` volume. The service's own directories are under
`/vertex/storage/capa/`:

| Path | Contents | Lifetime |
| --- | --- | --- |
| `capa/work/` | Each file being scanned, as `<sha256>.<guid>`. | Deleted after each scan, and emptied at startup. |
| `capa/cache/` | capa's parsed-rules caches (`capa-<id>.cache`), for the official rules and for each official plus custom rule set in use. | Built when rules load. Caches of other rules are deleted once the current one is built. |
| `capa/custom/<key>/` | One `<meta:rule guid>.yml` file per custom rule in a set. | Deleted at startup, and when the set is pruned (16 sets max). |
| `capa/nosigs/` | An empty directory passed to capa as `--signatures` when `capa:sigs` is unset. | Permanent. |
| (other) | Standard Cell state: auth, nexus log, `cell.yaml`, `cell.guid`. | Permanent. |

None of it is precious: losing the volume only loses the service's users and cached state.
The rules come from `capa:rules`, and the custom rules live in the Cortex.

## Network

| Direction | Port / target | Purpose |
| --- | --- | --- |
| Inbound | `27492/tcp` (Telepath, when `dmon:listen` is set) | The Cortex calls the service. |
| Inbound | `4443/tcp` (HTTPS, optional) | Standard Cell HTTPS API; not used by the Storm package. |
| Outbound | the Axon in `axon:url` | File sizes and bytes to scan. |

No internet egress is needed at runtime: capa, its rules and its signatures are in the image.
Building the image needs `github.com` (to clone `mandiant/capa-rules` and `mandiant/capa`) and
the Python package index.

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

  capa:
    image: ghcr.io/gormaniac/stormsvcs/capa:<version>
    environment:
      SYN_CAPASVC_DMON_LISTEN: tcp://0.0.0.0:27492/
      SYN_CAPASVC_AUTH_PASSWD: capasecret
      SYN_CAPASVC_AXON_URL: tcp://root:axonsecret@axon:27492/
      SYN_CAPASVC_CAPA_WORKERS: "2"
      SYN_CAPASVC_CAPA_TIMEOUT: "900"
    volumes:
      - capa-storage:/vertex/storage
    depends_on:
      - axon

volumes:
  axon-storage:
  capa-storage:
```

The Axon must be the one the Cortex stores file bytes in (the Cortex's `axon` config), or
the files a user scans won't be found (`The file <sha256> is not in the Axon.`).

capa is CPU and memory hungry: each worker runs one capa process, and a large binary can take
minutes. Size `capa:workers` to the container's CPUs, and raise `capa:timeout` for big files.

## Adding the service to a Cortex

```text
service.add slib.capa tcp://root:capasecret@capa:27492/
service.list
```

When the service is added:

1. The service's `add` event runs, creating the `slib.capa` `meta:source` node:

   ```text
   [(meta:source=ee5999b4059645168272e22d7cd087e3 :name="capa" :type=slib.capa
     :url=https://github.com/mandiant/capa)]
   ```

2. The `slib.capa` Storm package (`version: <version>`, `synapse_version: >=2.145.0,<3.0.0`) is
   loaded, with its commands, modules and permissions.
3. The package's `onload` runs `$lib.import(slib.capa.sync).onload()` as root, in the default
   view. It waits up to 300 seconds for the service, then imports the rules and tag docs (see
   [`slib.capa.admin.sync`](commands.md#slibcapaadminsync)). Its prints and warnings go to the
   Cortex log (`slib.capa onload output: ...`). If the service isn't ready in time it warns
   `slib.capa: The service wasn't ready, the capa rules weren't imported. Run
   slib.capa.admin.sync.`

The `onload` runs whenever the package loads: when the service is added, when the service
reconnects with a new version, and when the Cortex restarts. It's a no-op unless the rules
(or the tag prefix) changed since the last import. The first import of the full capa-rules
release creates around a thousand `meta:rule` nodes and their techniques, so it takes a while.

The rule import writes to the view `onload` runs in (the default view). Run
`slib.capa.admin.sync --force` in another view to import the rules there too.

## Permissions

The package declares two permissions, both gated on the Cortex:

| Permission | Grants |
| --- | --- |
| `slib.capa.user` | `slib.capa.scan`, `slib.capa.info`, and importing the `slib.capa.lib` module. |
| `slib.capa.admin` | `slib.capa.admin.sync`, `slib.capa.admin.tags`, `slib.capa.admin.contacts.migrate`. |

```text
auth.user.addrule analyst slib.capa.user
auth.user.addrule capaadmin slib.capa.admin
auth.user.addrule capaadmin slib.capa.user
```

:::{important}
Only the two `slib.capa.priv.*` modules call the service, and they run as root only for users
with their `asroot:perms`. Every node edit (scan results, rule imports, contact migration) runs
in unprivileged modules, as the calling user. So:

- Users who scan also need node permissions for what a scan writes: adding `meta:rule`,
  `ps:contact`, `it:mitre:attack:technique`, `ou:technique`, `meta:source` nodes (when a matched
  rule isn't imported yet), setting their props, `-(matches)>`, `-(refs)>` and `-(seen)>` edges,
  tags under the prefix (and removing them), and node data on `file:bytes`. The tests grant
  `node`.
- `slib.capa.admin.sync` and `slib.capa.admin.tags` import `slib.capa.priv.user`, which requires
  `slib.capa.user`. Grant admins both permissions, plus node permissions for the rule import
  (`meta:rule`, `meta:ruleset`, `syn:tag` and the nodes above).
:::

## Upgrades

1. Pull the new image tag and restart the container. The volume can be kept; the service
   empties `capa/work/` and `capa/custom/` at startup.
2. When the service reconnects, the Cortex loads the new Storm package and its `onload`
   re-imports the rules if their sync key changed. The key is a guid of the rules' SHA256,
   `capa:rules:version`, `capa:rules:url` and the service's model version (`MODEL_VERSION = 2`),
   so a new rules release or a change in what the package models from a rule triggers it.
3. Upgrading from 0.4.x imports the rules again (model version 2 added the MBC behaviors and
   the `@handle` `:user` contacts). Run
   [`slib.capa.admin.contacts.migrate`](commands.md#slibcapaadmincontactsmigrate) to merge the
   old `@handle` contacts.

Files keep their old results until scanned again. A file whose results were made with other
rules (a different rules SHA256) isn't skipped by the next scan.
