# Deployment

## Docker image

The service is published as `ghcr.io/gormaniac/stormsvcs/malpedia`. CI pushes it only from
`main`, with three tags:

| Tag | Meaning |
| --- | --- |
| `latest` | The newest build from `main`. |
| `<version>` | The service version from `pyproject.toml`, for example `0.3.1`. |
| `<commit sha>` | The commit it was built from. |

### How the image is built

{src}`svcs/malpedia/docker/prod/Dockerfile` builds on the shared base image
`ghcr.io/gormaniac/stormsvcs/base:latest` (the `BASE_IMAGE` build arg). That image
({src}`docker/Dockerfile`) is `vertexproject/vtx-base-image:py311` plus `uv`. It sets
`SYN_LOG_LEVEL=INFO`, exposes ports `4443` (HTTPS) and `27492` (Telepath), and declares the
volume `/vertex/storage`. The service's Dockerfile then:

1. Copies `pyproject.toml`, `uv.lock`, `src/malpediasvc` and `README.md` to
   `/opt/stormsvcs/malpedia/`, and copies the repo `LICENSE` in.
2. Runs `uv sync --no-dev --locked`, which installs the locked Synapse, StormLib++ and
   `aiohttp` into `/opt/stormsvcs/malpedia/.venv`.
3. Installs `docker/prod/entrypoint.sh` and runs it under `tini`:

   ```bash
   exec uv run --no-sync --directory /opt/stormsvcs/malpedia/ python -O -m malpediasvc /vertex/storage
   ```

4. Adds a `HEALTHCHECK` (every 30s, 10s timeout, 10s start period, 1 retry). It runs
   `python -m synapse.tools.service.healthcheck -c cell:///vertex/storage/`.

The service needs no system packages or external tools beyond the base image.
{src}`svcs/malpedia/docker/test/Dockerfile` layers the tests and dev dependencies on top of
the production image, for CI.

## Cell configuration

The service-specific options are in `MalpediaSvc.confdefs`
({src}`svcs/malpedia/src/malpediasvc/svc.py`):

| Option | Type | Default | Constraint | Meaning |
| --- | --- | --- | --- | --- |
| `malpedia:url` | string | `https://malpedia.caad.fkie.fraunhofer.de/api` | | Base URL of Malpedia's REST API. Useful for a proxy or mirror. A trailing `/` is stripped. |
| `malpedia:interval` | number | `2.0` | `>= 0` | Minimum seconds between two requests to Malpedia. Retries are spaced this way too. |
| `malpedia:timeout` | number | `300` | `>= 1` | Total timeout, in seconds, of one request. The bulk endpoints are several MB. |
| `malpedia:backoff` | number | `5.0` | `>= 0` | Base, in seconds, of the exponential backoff between retries (`backoff * 2**attempt`). |
| `malpedia:pull:minage` | number | `12` | `>= 0` | Hours after a version check before a sync checks again. Syncs inside this window model the snapshot without any requests. Forced syncs and syncs after a failed pull ignore it. |
| `malpedia:yara:fullage` | number | `7` | `>= 0` | Days after the last full YARA download (one ~4MB zip) before a pull downloads every rule again. `0` means only the first pull and forced pulls do. |
| `malpedia:autosync` | boolean | `true` | | When the service is added to a Cortex, schedule the daily `slib.malpedia.sync` cron job and start the initial sync. |

All the standard Synapse cell options (`auth:passwd`, `dmon:listen`, `https:port`,
`aha:*`, ...) apply as well. See the
[Synapse devops guide](https://synapse.docs.vertex.link/en/latest/synapse/devopsguide.html).

Options can be set in `/vertex/storage/cell.yaml`:

```yaml
malpedia:pull:minage: 12
malpedia:yara:fullage: 7
malpedia:autosync: true
```

### Environment variables

The cell class is `MalpediaSvc`, so Synapse reads options from environment variables
prefixed `SYN_MALPEDIASVC_`. The rest of the name is the option name, uppercased, with `:`
replaced by `_`. Values are parsed as YAML.

| Variable | Option |
| --- | --- |
| `SYN_MALPEDIASVC_MALPEDIA_URL` | `malpedia:url` |
| `SYN_MALPEDIASVC_MALPEDIA_INTERVAL` | `malpedia:interval` |
| `SYN_MALPEDIASVC_MALPEDIA_TIMEOUT` | `malpedia:timeout` |
| `SYN_MALPEDIASVC_MALPEDIA_BACKOFF` | `malpedia:backoff` |
| `SYN_MALPEDIASVC_MALPEDIA_PULL_MINAGE` | `malpedia:pull:minage` |
| `SYN_MALPEDIASVC_MALPEDIA_YARA_FULLAGE` | `malpedia:yara:fullage` |
| `SYN_MALPEDIASVC_MALPEDIA_AUTOSYNC` | `malpedia:autosync` |
| `SYN_MALPEDIASVC_AUTH_PASSWD` | `auth:passwd`, the `root` user's password, used in the `service.add` URL |
| `SYN_MALPEDIASVC_TELEPATH` | The Telepath listen URL (default `tcp://0.0.0.0:27492`) |
| `SYN_MALPEDIASVC_HTTPS` | The HTTPS port (default `4443`) |

`SYN_LOG_LEVEL` (`INFO` in the base image) sets the log level.

## Secrets

The service has **no API keys**. Malpedia's public endpoints need no account, and no
`Authorization` header is ever sent. The only secret is the cell's own `root` password
(`auth:passwd`), which the Cortex uses to connect.

## Persistent state

Everything is stored in the cell directory `/vertex/storage`, so mount a volume there. The
service's slab holds four key/value stores. See [Internals](internals.md#state).

| Store | Holds |
| --- | --- |
| `slib:malpedia:info` | Pull bookkeeping: Malpedia version and date, check and pull times, failures, gaps, the random daily sync time. |
| `slib:malpedia:snap` | The normalized snapshot: every `news`, `actor`, `family`, `yara` record and its hash. |
| `slib:malpedia:views` | For each view and kind, the record versions the view has modeled. |
| `slib:malpedia:viewinfo` | Per view: when it last synced, the Malpedia version, and the tag prefixes it used. |

Losing the volume costs one more bulk pull (on the next sync), plus one full re-model of
every view, because the per-view tracking is gone too.

The Cortex also keeps some state for the package, in Storm globals:

| Global | Meaning |
| --- | --- |
| `slib:malpedia:tag:prefix` | The tag prefix (default `rep.malpedia`). |
| `slib:malpedia:tag:tlp` | The YARA TLP tag prefix (default `rep.malpedia.tlp`). |
| `slib:malpedia:cron` | The iden of the sync cron job. |

## Network egress

The service only needs outbound HTTPS to `malpedia.caad.fkie.fraunhofer.de` (or whatever
`malpedia:url` points at), and only sends `GET` requests. The `aiohttp` session is created with
`trust_env=True`, so the standard `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` environment
variables (and `~/.netrc`) are honored.

A daily pull costs either one tiny request (Malpedia is unchanged) or about 8-10 requests and
~5MB, plus the ~4MB YARA zip once every `malpedia:yara:fullage` days. See
[Syncing](syncing.md#what-a-pull-requests).

## docker-compose example

```yaml
services:
  malpedia:
    image: ghcr.io/gormaniac/stormsvcs/malpedia:0.3.1
    restart: unless-stopped
    environment:
      SYN_MALPEDIASVC_AUTH_PASSWD: "${MALPEDIA_ROOT_PASSWD}"
      # Optional, these are the defaults.
      SYN_MALPEDIASVC_MALPEDIA_PULL_MINAGE: "12"
      SYN_MALPEDIASVC_MALPEDIA_YARA_FULLAGE: "7"
      SYN_MALPEDIASVC_MALPEDIA_AUTOSYNC: "true"
      # Only if egress goes through a proxy.
      # HTTPS_PROXY: "http://proxy.internal:3128"
    volumes:
      - malpedia:/vertex/storage
    # Only expose Telepath to the Cortex's network, it carries the root password.
    expose:
      - "27492"

volumes:
  malpedia:
```

## Adding the service to a Cortex

```text
service.add slib.malpedia tcp://root:<password>@malpedia:27492/
service.list
```

Once the Cortex connects, it loads the `slib.malpedia` Storm package (version `0.3.1`, needs
Synapse `>=2.234.0,<3.0.0`) and runs the service's `add` event as root. The event:

1. creates the `malpedia` `meta:source` (`15b7f8ff9cef4e8fa9fedd9f2b10c1a5`),
2. sets `slib:malpedia:tag:prefix` to `rep.malpedia` and `slib:malpedia:tag:tlp` to
   `rep.malpedia.tlp`, unless they're already set,
3. starts a one-time cron job named `slib.malpedia (initial setup and sync)`. Unless
   `malpedia:autosync` is off, the job schedules the daily sync and runs the initial sync.

The service isn't ready to answer calls while the `add` event runs, so the event can't do
step 3 itself. [Syncing](syncing.md#registration-and-the-initial-bulk-pull) has the details.

Check the package:

```text
pkg.list
slib.malpedia.status
slib.malpedia.admin.schedule
```

### Removing the service

`service.del` runs the `del` event (as root, after the package is removed). It deletes the
cron job named by `slib:malpedia:cron`, pops that global, and deletes any cron job named
`slib.malpedia (initial setup and sync)`. The tag prefix globals and every node are kept, so
adding the service again tags nodes the same way.

## Permissions

The package declares three permissions, all with the `cortex` gate:

| Permission | Grants |
| --- | --- |
| `slib.malpedia.user` | `slib.malpedia.search`, `slib.malpedia.status`. |
| `slib.malpedia.sync` | `slib.malpedia.sync`, `slib.malpedia.refresh` (create and edit Malpedia's nodes in the current view). |
| `slib.malpedia.admin` | `slib.malpedia.admin.*`, `slib.malpedia.sync --force`, `slib.malpedia.refresh --no-limit`. |

Users never need `service.get`: only the privileged (`asroot`) modules talk to the service.

Syncing and refreshing edit nodes as root. So the commands also check that the user may add
each of `media:news`, `risk:threat`, `risk:tool:software` and `it:app:yara:rule` to the
current view's write layer (`node.add.<form>`, with the layer as the gate). Otherwise they
raise `AuthDeny`.

```text
auth.user.addrule analyst slib.malpedia.user
auth.user.addrule analyst slib.malpedia.sync
auth.user.addrule analyst node.add
auth.user.addrule lead slib.malpedia.admin
```

## Upgrades

Pull the new image tag and recreate the container on the same volume. The snapshot and
per-view state survive. When the Cortex reconnects, it loads the new package version.

If the service stopped while a pull was writing the snapshot, the next start logs
`The last pull was interrupted, the next one repairs it.` It also forgets the stored version,
so the next pull downloads everything again. See [Internals](internals.md#crash-safety).

### Upgrading from 0.2.x

- 0.2.x linked articles with `-(about)>` edges. Syncs now use `-(refs)>`, and replace the
  `-(about)>` edge of every article they model. To replace them all at once, run
  `slib.malpedia.sync --full --no-pull` once in each view.
- Views synced without the `malpedia` `meta:source` have no `-(seen)>` edges.
  `slib.malpedia.sync --full --no-pull` adds them.
- 0.2.x didn't record the tag prefixes a view was synced with. So the old tags from a prefix
  change made before the upgrade aren't removed.
- The first pull after the upgrade downloads every YARA rule.
