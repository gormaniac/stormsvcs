# Deployment

This page is for Synapse admins: how the image is built, how to configure and run the service,
where it keeps state, what it needs to reach, and how to connect it to a Cortex.

## Docker image

The image is `ghcr.io/gormaniac/stormsvcs/abusech`. CI ({src}`.github/workflows/abusech.yml`,
which calls the shared `_service.yml`) tags each build `latest`, the `pyproject.toml` version,
and the commit SHA, and pushes only from `main`.

### How it's built

The production Dockerfile ({src}`svcs/abusech/docker/prod/Dockerfile`) builds on the stormsvcs
base image, `ghcr.io/gormaniac/stormsvcs/base` (override with `--build-arg BASE_IMAGE=...`).
The base image ({src}`docker/Dockerfile`) is `vertexproject/vtx-base-image:py311` (pinned by
digest) plus `uv`, with `SYN_LOG_LEVEL=INFO`, ports `4443` and `27492` exposed, upgraded
system packages, and `VOLUME /vertex/storage`. On top of that the service image:

1. Copies `pyproject.toml`, `uv.lock`, `src/abusechsvc` and `README.md` to
   `/opt/stormsvcs/abusech/`, and the repo's `LICENSE` next to them.
2. Runs `uv sync --no-dev --locked` there, installing exactly the locked versions of Synapse,
   StormLib++, `pyzipper` (to decrypt abuse.ch's AES sample zips) and their dependencies.
3. Sets the entrypoint to `tini -- /opt/stormsvcs/abusech/entrypoint.sh`, which runs:

   ```bash
   uv run --no-sync --directory /opt/stormsvcs/abusech/ python -O -m abusechsvc /vertex/storage
   ```

4. Adds a health check, every 30 seconds, using Synapse's healthcheck tool against the cell:

   ```bash
   uv run --no-sync --directory /opt/stormsvcs/abusech \
       python -m synapse.tools.service.healthcheck -c cell:///vertex/storage/
   ```

No other system packages or tools are installed; the service is pure Python.

A test image ({src}`svcs/abusech/docker/test/Dockerfile`) is built on the production image in
CI: it adds `tests/` and the dev dependencies and runs `pytest`.

### Ports

| Port | Purpose | Default from |
|---|---|---|
| `27492` | Telepath, which the Cortex connects to | Synapse's cell `--telepath` default `tcp://0.0.0.0:27492` (env `SYN_ABUSECHSVC_TELEPATH`) |
| `4443` | The cell's HTTPS API (not used by the package) | Synapse's cell `--https` default (env `SYN_ABUSECHSVC_HTTPS`) |

## Configuration

The service's own options are the `confdefs` of `AbuseChSvc`
({src}`svcs/abusech/src/abusechsvc/svc.py`). Like every Synapse cell option, each can be set in
`/vertex/storage/cell.yaml`, or with an environment variable named
`SYN_ABUSECHSVC_<OPTION>` (the option upper cased, `:` replaced with `_`). Environment values
are parsed as YAML, so numbers and objects work.

| Option | Env var | Type | Default | Meaning |
|---|---|---|---|---|
| `abusech:apikey` | `SYN_ABUSECHSVC_ABUSECH_APIKEY` | string or null | `null` | A fallback Auth-Key, used when neither the calling user nor the service's stored key provides one (see [Auth-Keys](#auth-keys)). |
| `abusech:ratelimit` | `SYN_ABUSECHSVC_ABUSECH_RATELIMIT` | number | `5.0` | Max requests per second sent to abuse.ch, shared by every platform. `0` disables the limit. |
| `abusech:timeout` | `SYN_ABUSECHSVC_ABUSECH_TIMEOUT` | number | `120` | Seconds before a single request times out. For the streamed downloads (the MalwareBazaar, URLhaus and ThreatFox exports, `--bulk` pulls, and the YARAhub rule export) it's the connect and per-read timeout instead, with no total timeout. |
| `abusech:maxsize` | `SYN_ABUSECHSVC_ABUSECH_MAXSIZE` | integer | `67108864` (64 MiB) | Max bytes of a file downloaded from or submitted to abuse.ch, of any response or dataset read into memory, and of anything unzipped (each file, and all of a zip's files together). |
| `abusech:bulk:maxsize` | `SYN_ABUSECHSVC_ABUSECH_BULK_MAXSIZE` | integer | `17179869184` (16 GiB) | Max bytes of an export streamed to disk: a bulk import's staged copy (and the unzipped ThreatFox export it parses), and the CSV exports the export commands stream without `--bulk`. |
| `abusech:bulk:maxjobs` | `SYN_ABUSECHSVC_ABUSECH_BULK_MAXJOBS` | integer | `4` | Max bulk import jobs at once. |
| `abusech:urls` | `SYN_ABUSECHSVC_ABUSECH_URLS` | object | `{}` | Overrides for abuse.ch base URLs (ex. a proxy or mirror), keyed by the names below. |

The base URL names and their defaults (`BASE_URLS` in
{src}`svcs/abusech/src/abusechsvc/client.py`):

| Name | Default | Auth-Key |
|---|---|---|
| `bazaar` | `https://mb-api.abuse.ch/api/v1` | required (header) |
| `bazaar:export` | `https://mb-api.abuse.ch/v2/files/exports` | required (URL path) |
| `urlhaus` | `https://urlhaus-api.abuse.ch/v1` | required (header) |
| `urlhaus:submit` | `https://urlhaus.abuse.ch/api` | required (header) |
| `urlhaus:export` | `https://urlhaus-api.abuse.ch/v2/files/exports` | required (URL path) |
| `threatfox` | `https://threatfox-api.abuse.ch/api/v1` | required (header) |
| `threatfox:export` | `https://threatfox-api.abuse.ch/v2/files/exports` | required (URL path) |
| `yaraify` | `https://yaraify-api.abuse.ch/api/v1` | required (header) |
| `yaraify:export` | `https://yaraify.abuse.ch` | sent when available |
| `hunting` | `https://hunting-api.abuse.ch/api/v1` | required (header) |
| `feodo` | `https://feodotracker.abuse.ch/downloads` | sent when available |
| `sslbl` | `https://sslbl.abuse.ch/blacklist` | sent when available |

Example `cell.yaml`:

```yaml
abusech:ratelimit: 2
abusech:timeout: 300
abusech:bulk:maxjobs: 2
abusech:urls:
  feodo: https://mirror.example.com/feodo
```

Standard Synapse cell options also apply, ex. `auth:passwd` (`SYN_ABUSECHSVC_AUTH_PASSWD`) to
bootstrap the service's `root` password, and `SYN_ABUSECHSVC_TELEPATH` /
`SYN_ABUSECHSVC_HTTPS` / `SYN_ABUSECHSVC_NAME` for the listeners (see the
[Synapse devops docs](https://synapse.docs.vertex.link/en/latest/)).

The HTTP session is created with `trust_env=True`, so the standard `HTTP_PROXY`,
`HTTPS_PROXY` and `NO_PROXY` environment variables are honored.

## Auth-Keys

Every abuse.ch API requires a free Auth-Key from https://auth.abuse.ch/; one key works for
every platform. For each request the key is resolved in this order
(`AbuseChSvc.getApiKey()`):

1. **The calling user's own key**, set with `slib.abusech.apikey <key>`. It's stored in a
   user scoped Synapse vault of type `abusech` (named `abusech:<username>` when the command
   creates it), and read by `slib.abusech.util.userKey()` with
   `$lib.vault.bytype(abusech, scope=user)`, so only that user's requests use it. The priv
   modules pass it to the service as the `apikey` argument.
2. **The service-wide key**, set with `slib.abusech.admin.apikey <key>`. It's stored in the
   service's own LMDB slab (the `slib:abusech` safe key/value store, key `apikey`), not in the
   Cortex, so it can't be read back from Storm. The command can only set, clear, or report
   whether one is set.
3. **The `abusech:apikey` config option.**

The Feodo Tracker and SSL Blacklist blocklists and the YARAhub rule export don't need a key
(one is sent when available). A keyed API called without any key fails before a request is
sent, with: `No abuse.ch Auth-Key is configured. Get one for free at https://auth.abuse.ch/
then run slib.abusech.apikey (or slib.abusech.admin.apikey for a service-wide key).`

The MalwareBazaar, URLhaus and ThreatFox exports take the key in the URL path
(`<base>/<Auth-Key>/<file>`). Keys are scrubbed from error messages twice: the transport
replaces the request's key (raw and URL-quoted) with `<auth-key>`, and the Telepath API
replaces the stored and configured keys with `<redacted>` in every error returned to Storm.

## Persistent state

Everything lives under the cell directory, `/vertex/storage` in the image. Mount it as a volume.

| Path / store | Contents |
|---|---|
| The cell's slab, key/value store `slib:abusech` | The service-wide Auth-Key (`apikey`). |
| `tmp/bulk/<job id>/` | A bulk import job's staged export (`source`) and built nodes (`export.nodes`). Removed when the job finishes or fails, after 6 hours idle, and all of `tmp/bulk/` on every start. Size it for the largest export you'll bulk import (see `abusech:bulk:maxsize`). |
| Standard cell files | `cell.yaml`, `cell.guid`, the auth database, logs, etc. |

State kept in the Cortex, not the service:

| Where | What |
|---|---|
| Per-user vaults of type `abusech` | Users' own Auth-Keys (`secrets.apikey`). |
| Global `slib:abusech:tag:enabled` | Whether tags are applied (default `true`, set by the `add` event). |
| Global `slib:abusech:tag:prefix` | The tag prefix (default `rep.abusech`, set by the `add` event). |
| Global `slib:abusech:datasets` | The record of each bulk import pull, see [Bulk imports](bulk.md#the-datasets-global). |
| The Cortex's Axon | Downloaded samples, export files pulled by `--bulk`, and the `.nodes` files they were built into. |

## Network egress

The service needs outbound HTTPS to the hosts it uses (or to the hosts in `abusech:urls`):

- `mb-api.abuse.ch` - MalwareBazaar API, downloads and exports
- `urlhaus-api.abuse.ch` - URLhaus API, downloads and exports
- `urlhaus.abuse.ch` - URLhaus URL submission
- `threatfox-api.abuse.ch` - ThreatFox API and exports
- `yaraify-api.abuse.ch` - YARAify API
- `yaraify.abuse.ch` - the YARAhub rule export (`/yarahub/yaraify-rules.zip`)
- `hunting-api.abuse.ch` - the false positive list
- `feodotracker.abuse.ch` - Feodo Tracker blocklists
- `sslbl.abuse.ch` - SSL Blacklist blocklists

The Cortex only needs to reach the service's Telepath port. The service never connects to
the Cortex or its Axon: samples, uploads and bulk files move through the Storm runtime.

## docker-compose example

```yaml
services:
  slib-abusech:
    image: ghcr.io/gormaniac/stormsvcs/abusech:<version>
    restart: unless-stopped
    volumes:
      - ./storage/slib-abusech:/vertex/storage
    environment:
      SYN_ABUSECHSVC_AUTH_PASSWD: "change-me"
      # Optional: a service-wide fallback Auth-Key.
      SYN_ABUSECHSVC_ABUSECH_APIKEY: "<auth-key>"
      SYN_ABUSECHSVC_ABUSECH_RATELIMIT: "5"
      SYN_ABUSECHSVC_ABUSECH_BULK_MAXJOBS: "2"
      # Optional: an outbound proxy.
      # HTTPS_PROXY: "http://proxy.example.com:3128"
    ports:
      - "27492:27492"
```

## Adding the service to a Cortex

As a Cortex admin, add the service **under the name `slib.abusech`**: every priv module calls
`$lib.service.get("slib.abusech")`, so another name breaks the package.

```text
service.add slib.abusech tcp://root:<passwd>@<host>:27492/*
service.list
```

Use a dedicated service user instead of `root` if you prefer; the API methods do no
per-user permission checks of their own (any Telepath user of the service may call them),
so whoever can reach the service's Telepath port with valid credentials has full access.

When the Cortex connects it loads the `slib.abusech` package, and runs the service's `add`
event as root (`SVC_EVTS` in {src}`svcs/abusech/src/abusechsvc/defs.py`). The event:

- Creates a `meta:source` per platform (fixed guids, `:type=slib.abusech.<platform>`,
  `:name`, `:url`), see [the data model](model.md#meta-sources).
- Adds the `file:bytes` extended props `_sha3_384`, `_tlsh`, `_telfhash`, `_gimphash` and
  `_dhash_icon` when they don't exist yet.
- Sets the `slib:abusech:tag:enabled` global to `true` and `slib:abusech:tag:prefix` to
  `rep.abusech` when they aren't set.

Check the package loaded with `pkg.list` (look for `slib.abusech`) and that the commands
exist with `help slib.abusech`.

## Permissions

The package declares five permissions, all with `gate: cortex`:

| Permission | Grants |
|---|---|
| `slib.abusech.user` | Lookups, searches, exports, blocklists, reference data, `slib.abusech.enrich`, and setting your own Auth-Key. Required by most commands. |
| `slib.abusech.download` | Downloading malware samples into the Axon (`*.download` commands). |
| `slib.abusech.submit` | Sending data to abuse.ch: samples, sample updates and comments, URLs, IOCs, YARAify scans and rescans, and YARA rule deploys/deletes. |
| `slib.abusech.bulk` | `--bulk` on the export commands (pulls exports into the Axon and records them in the datasets global). The export commands also need `slib.abusech.user`. |
| `slib.abusech.admin` | The service-wide Auth-Key, tag settings, raw API requests, and the data migration commands. |

Users don't need `service.get` or Axon permissions: the `slib.abusech.priv.*` modules are
`asroot:perms` modules, elevated only for users holding the matching permission (importing
one without it fails with `AuthDeny`). Node edits are made by the unprivileged modules as the
calling user, so users also need the normal node permissions for what the commands create:
`node.add`, `node.prop.set`, `node.tag.add` and `node.edge.add` (and `node.tag.del` for the
URLhaus/Feodo `status.*` tags that are replaced). A `--bulk` import is ingested with
`$lib.feed.fromAxon()` as the calling user, which needs the `node` permission on the layer.
`slib.abusech.admin.edges.migrate` needs `node.edge.add` and `node.edge.del`, and
`slib.abusech.admin.families.merge` needs permission to set props, tags and edges and to
delete `risk:tool:software` nodes.

Example roles:

```text
auth.role.add abusech.analysts
auth.role.addrule abusech.analysts slib.abusech.user
auth.role.addrule abusech.analysts node.add
auth.role.addrule abusech.analysts node.prop.set
auth.role.addrule abusech.analysts node.tag.add
auth.role.addrule abusech.analysts node.tag.del
auth.role.addrule abusech.analysts node.edge.add

auth.role.add abusech.hunters
auth.role.addrule abusech.hunters slib.abusech.download
auth.role.addrule abusech.hunters slib.abusech.submit
```

## Upgrades

1. Pull the new image tag and recreate the container with the same volume. Bulk jobs in
   progress are lost (`tmp/bulk/` is cleared on start); the Storm side reports the failure.
2. The Cortex reconnects and loads the new package version automatically. The `add` event
   only fills in what's missing, so it never changes your tag settings.
3. Read the release notes for model changes. Two releases changed how existing data is
   modeled and ship migration commands (both dry runs unless `--apply`):
   - 0.4.0 keyed malware families on their name: run
     `slib.abusech.admin.families.merge`.
   - 0.5.0 replaced the generic `-(refs)>` edges: run `slib.abusech.admin.edges.migrate`.

   See [Admin commands](commands-admin.md) and [the data model](model.md).
4. Bulk imports record the node builder version they used (`builder` in the datasets
   global, currently `3`). Rerunning a full export's `--bulk` after an upgrade reuses the last
   pull, so the same data is rebuilt with the new builder without downloading it again.
