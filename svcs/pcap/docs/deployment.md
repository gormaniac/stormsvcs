# Deployment

## Docker image

The service is published as `ghcr.io/gormaniac/stormsvcs/pcap`. CI pushes it only from `main`,
tagged `latest`, the service version from `pyproject.toml`, and the commit SHA.
Pin a version tag in production.

### How the image is built

The production Dockerfile is {src}`svcs/pcap/docker/prod/Dockerfile`. Every engine is built from
source in its own stage (so CI caches each one separately), and only its install directory is
copied into the final image. Source tarballs are fetched by BuildKit with pinned SHA-256
checksums, in `*-src` stages that can be overridden with a local mirror
(`docker buildx build --build-context wireshark-src=./mirror/wireshark ...`).

| Stage | Builds | Installed to |
| --- | --- | --- |
| `tshark-build` | Wireshark `4.6.9`, only `tshark`, with `-DENABLE_LUA=OFF -DENABLE_PLUGINS=OFF` (no scripts or plugins run in it), no Kerberos/GnuTLS/codecs. TLS key log decryption only needs libgcrypt. | `/opt/wireshark` |
| `snort-build` | libdaq `3.0.28` and Snort `3.12.4.0`. Only `snort`, `snort2lua`, the DAQ modules, and the default configs are kept. `--build-arg SNORT=no` skips it (an empty `/opt/snort`, the service then runs without Snort). | `/opt/snort` |
| `suricata-build` | Suricata `8.0.8` (with Rust from `rust:1.88-slim-bookworm`, release tarballs vendor every crate), `--disable-shared --disable-suricata-update`, plus `make install-conf`. | `/opt/suricata` (config in `/opt/suricata/etc`) |

The final stage:

1. `FROM ${BASE_IMAGE}`, default `ghcr.io/gormaniac/stormsvcs/base:latest`. The base image
   ({src}`docker/Dockerfile`) is `vertexproject/vtx-base-image:py311` (pinned by digest) plus
   `uv`, with `SYN_LOG_LEVEL=INFO`, `EXPOSE 4443` and `EXPOSE 27492`, upgraded system packages,
   and `VOLUME /vertex/storage`.
2. Installs the engines' runtime libraries from Debian 12 (libglib2.0, libgcrypt20, libpcap,
   libpcre2, libnghttp2, libluajit, libhwloc, libdumbnet, libyaml, libjansson, libmagic, ...).
3. Copies `/opt/wireshark`, `/opt/snort`, `/opt/suricata`, and sets
   `PATH=/opt/wireshark/bin:/opt/snort/bin:/opt/suricata/bin:$PATH` and
   `LD_LIBRARY_PATH=/opt/snort/lib`.
4. Creates the engine user: `useradd --system --uid 2000 slib-pcap-engine` (no home, `nologin`
   shell), and makes `/opt/suricata/etc`, `/opt/snort`, `/opt/wireshark` world readable
   (Suricata installs its config `0600`).
5. Copies `pyproject.toml`, `uv.lock`, `src/pcapsvc` and `README.md` to `/opt/stormsvcs/pcap/`
   and runs `uv sync --no-dev --locked` (Synapse, StormLib++, `dpkt`, `cryptography`).
6. The entrypoint ({src}`svcs/pcap/docker/prod/entrypoint.sh`) runs under `tini`:

   ```bash
   exec uv run --no-sync --directory /opt/stormsvcs/pcap/ python -O -m pcapsvc /vertex/storage
   ```

7. A `HEALTHCHECK` runs `python -m synapse.tools.service.healthcheck -c cell:///vertex/storage/`
   every 30 seconds (10 second timeout, 10 second start period, 1 retry).

The service runs as root in the image, so engines are dropped to `slib-pcap-engine` (uid 2000)
by the sandbox. See [Sandbox](sandbox.md).

The test image ({src}`svcs/pcap/docker/test/Dockerfile`) is built `FROM` the production image,
adds `tests/` and the dev dependencies, and runs pytest with `SLIB_PCAP_REQUIRE=1` (tests that
need an engine fail instead of skipping). It isn't meant for deployment.

## Cell configuration

Every option is in `PcapSvc.confdefs` ({src}`svcs/pcap/src/pcapsvc/svc.py`). Sizes are bytes,
times are seconds unless noted.

### Captures and files

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `axon:url` | string or null | `null` | Telepath URL of the Cortex's Axon (the one `$lib.axon` uses). With it, the service reads captures and key logs from the Axon itself and uploads every extracted file there. Without it Storm streams each capture to the service, and extracted files are only counted. The URL's user needs read and write on the Axon. |
| `pcap:timeout` | integer, min 0 | `300` | Default seconds a flow can be idle before the next packet between the same endpoints starts a new flow. `0` never times flows out. |
| `pcap:limit` | integer, min 1 | `100000` | Max flows per capture. Also caps `--limit`. Packets of further flows are dropped and counted. |
| `pcap:handshake` | integer, min 0 | `1024` | Default max characters kept of each side's first text payload (`:src:handshake`/`:dst:handshake`), `0` for none. |
| `pcap:maxsize` | integer, min 0 | `1073741824` (1 GiB) | Max capture size, `0` for no limit. Checked against the Axon's size before download, and per chunk for uploads. |
| `pcap:maxsize:decompressed` | integer, min 0 | `4294967296` (4 GiB) | Max size a gzip compressed capture may decompress to, `0` for no limit. |
| `pcap:workers` | integer, min 1 | `2` | Captures analyzed at once (an `asyncio.Semaphore`), the rest wait. |
| `pcap:uploads` | integer, min 1 | `16` | Max uploads (captures and key logs streamed by Storm, without an Axon) held at once. |
| `pcap:files` | boolean | `true` | Extract the files sent in flows by default (`--no-files` turns it off per run). |
| `pcap:files:maxsize` | integer, min 0 | `67108864` (64 MiB) | Largest extracted file, `0` for no limit. Also sets Suricata's HTTP body limits (`maxsize + 1`). |
| `pcap:files:limit` | integer, min 0 | `10000` | Max files extracted per capture, `0` for no limit. |

### Rule feeds

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `pcap:feeds` | array of objects | the five default feeds | Feeds the service starts with, each `{name, url, engine, enabled, exclude, desc}`. Only read the first time the service starts (it sets `feeds:seeded` in its slab), after that feeds are managed with `slib.pcap.admin.feed`. |
| `pcap:feeds:secrets` | object | `{}` | Secrets feed URLs reference as `${name}`: `{"<name>": {"value": "...", "hosts": ["..."]}}` (both required, no other keys). A secret is only sent to its hosts (exact, or `*.example.com`). |
| `pcap:feeds:interval` | number, min 0 | `24` | Hours between downloads of a feed. A sync only downloads a feed that's due, `0` downloads every feed on every sync. |
| `pcap:feeds:timeout` | number, min 1 | `300` | Seconds before a feed download times out (aiohttp total timeout). |
| `pcap:feeds:maxsize` | integer, min 1 | `268435456` (256 MiB) | Max size of a download, and of the rules it unpacks to. |

See [Rules and feeds](rules.md#feeds) for the default feeds.

### Engines

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `suricata:enabled` | boolean | `true` | Run Suricata (when installed) by default. |
| `suricata:bin` | string | `suricata` | The Suricata binary, a path or a name on `PATH`. |
| `suricata:conf` | string or null | `null` | The base `suricata.yaml`, the service's outputs and settings are applied over it. Defaults to `<prefix>/etc/suricata/suricata.yaml` of the binary. |
| `suricata:vars` | object | `HOME_NET: "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"`, `EXTERNAL_NET: "any"` | Suricata `vars.address-groups`. |
| `suricata:set` | object | `{}` | Overrides of the generated Suricata config as dotted keys, like `suricata --set` (ex. `{"stream.memcap": "2gb"}`, numbers index lists: `outputs.0.eve-log.enabled`). Applied last, so they win over the service's settings and can break what it needs. A key that can't apply stops the service at startup (`BadConfValu`). |
| `suricata:timeout` | number, min 0 | `900` | Seconds before a Suricata run is killed, `0` for no limit. |
| `snort:enabled` | boolean | `true` | Run Snort (when installed) by default. |
| `snort:bin` | string | `snort` | The Snort 3 binary. |
| `snort:snort2lua` | string | `snort2lua` | The binary that converts Snort 2.x rules to Snort 3. |
| `snort:conf` | string or null | `null` | The base `snort.lua`. Defaults to `<prefix>/etc/snort/snort.lua` of the binary. Relative includes are found in its directory (`--include-path`). |
| `snort:vars` | object | same as `suricata:vars` | Snort variables. Only variables the base config assigns (a `NAME = ...` line) can be set, anything else fails the Snort run. |
| `snort:args` | array of strings | `[]` | Extra arguments for every Snort run (rule builds and scans). |
| `snort:timeout` | number, min 0 | `900` | Seconds before a Snort run (rule build, check, or scan) is killed, `0` for no limit. |
| `tshark:enabled` | boolean | `true` | Run tshark (when installed) by default. |
| `tshark:path` | string | `tshark` | The tshark binary. |
| `tshark:args` | array of strings | `[]` | Extra tshark arguments for every run, ex. `["-d", "tcp.port==2222,ssh"]`. |
| `tshark:protocols` | array of strings or null | `pcapsvc.tshark.PROTOCOLS` | The only dissectors tshark runs (`--only-protocols`), `null` for all. Protocols named by Decode As rules are added per run. See [Internals](internals.md#tshark). |
| `tshark:keylog:maxsize` | integer, min 0 | `16777216` (16 MiB) | Max size of all the TLS key logs of one run together, `0` for no limit. |
| `tshark:timeout` | number, min 0 | `600` | Seconds a tshark run may take, `0` for no limit. |

### Sandbox

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `sandbox:mode` | `best-effort`, `strict`, `off` | `best-effort` | `best-effort` applies every layer the host supports, `strict` refuses to run an engine without all of them, `off` runs engines directly (only the timeout and output cap apply). |
| `sandbox:user` | string or null | `slib-pcap-engine` | The user engines run as when the service runs as root. `null` keeps the service's user. |
| `sandbox:rlimits` | object | `as: 4294967296`, `cpu: 3600`, `fsize: 4294967296`, `nofile: 4096`, `core: 0`, `nproc: 256` | Engine resource limits, merged over the defaults. `0` is unlimited (except `core`). `nproc` only applies when engines run as `sandbox:user`. |
| `sandbox:seccomp` | boolean | `true` | Load the seccomp filter that only allows Unix sockets. |

The standard Synapse Cell options also apply (`dmon:listen`, `https:port`, `auth:passwd`,
`aha:*`, ...), see the
[Synapse devops guide](https://synapse.docs.vertex.link/en/latest/synapse/devopsguide.html).

### Settings that live in the Cortex

Some settings are Cortex admin choices, saved in Storm globals by the package rather than in
the service's config, and sent to the service with every run:

| Global | Set with | Holds |
| --- | --- | --- |
| `slib:pcap:vars` | `slib.pcap.admin.vars` | Network variables for every run, over `suricata:vars` and `snort:vars`. |
| `slib:pcap:decode` | `slib.pcap.admin.decode` | Decode As rules for every run. |
| `slib:pcap:cron` | the add event, `slib.pcap.admin.schedule` | The iden of the sync cron job. |
| `slib:pcap:rules:view` | the add event, `slib.pcap.admin.schedule --period` | The view the service's rules come from. |

`tshark:args`, `snort:args`, `suricata:conf` and `suricata:set` are only reachable from the
service's config, not from Storm: tshark options like `-X lua_script:` run code and `-w`
writes files.

### Environment variables

Synapse reads config from `SYN_<CELLCLASS>_<KEY>`, with the class name upper-cased and `:` in the
key replaced by `_`. The cell class is `PcapSvc`, so the prefix is `SYN_PCAPSVC_`. Values are
parsed as YAML, so lists and objects can be given inline.

| Variable | Config key |
| --- | --- |
| `SYN_PCAPSVC_AXON_URL` | `axon:url` |
| `SYN_PCAPSVC_PCAP_WORKERS` | `pcap:workers` |
| `SYN_PCAPSVC_PCAP_MAXSIZE` | `pcap:maxsize` |
| `SYN_PCAPSVC_PCAP_FEEDS_SECRETS` | `pcap:feeds:secrets` |
| `SYN_PCAPSVC_SURICATA_SET` | `suricata:set` |
| `SYN_PCAPSVC_SANDBOX_MODE` | `sandbox:mode` |
| `SYN_PCAPSVC_DMON_LISTEN` | `dmon:listen` |
| `SYN_PCAPSVC_AUTH_PASSWD` | `auth:passwd` |

The same pattern applies to every other key (ex. `SYN_PCAPSVC_TSHARK_KEYLOG_MAXSIZE`).

A `cell.yaml` in `/vertex/storage` works too:

```yaml
dmon:listen: tcp://0.0.0.0:27492/
axon:url: tcp://pcap:secret@axon:27492/
pcap:workers: 4
pcap:feeds:secrets:
  talos:oinkcode: {value: "<oinkcode>", hosts: ["www.snort.org", "snort.org"]}
suricata:set:
  stream.memcap: 2gb
```

## Secrets

| Secret | Where it lives | Who can see it |
| --- | --- | --- |
| `pcap:feeds:secrets` values (ex. a Talos oinkcode, an ET Pro code) | The service's config (env or `cell.yaml`) | Only the operator. Storm only sees feed URLs with their `${name}` placeholders. A value is URL-quoted into the URL and only sent to the hosts listed for it, and every feed error message is redacted (the value and its quoted form are replaced by `${name}`) before it's saved or returned. |
| The password in `axon:url` | The service's config | The operator. |
| The service's Telepath password (`auth:passwd`, used in `service.add`) | The service's config / auth | The operator, and the Cortex's service definition. |

Keep the storage directory's files that hold secrets (`cell.yaml`) `0600`. Without Landlock the
sandbox doesn't open up directories to the engine user (see
[Sandbox](sandbox.md#directory-access)), so it can't read them anyway, but a mode of `0600`
matters if you make directories searchable yourself.

TLS key logs (`--keylog`) are read with the same `slib.pcap.user` permission as captures, so a
key log in the Axon is readable by anyone with that permission.

## Persistent state

Everything lives in the `/vertex/storage` volume (the cell's `dirn`):

| Path | Contents |
| --- | --- |
| `slabs/cell.lmdb` | The cell slab. The service's own keyvals: `slib:pcap:rules` (pushed rules, guid -> (text, engine)), `slib:pcap:ruleinfo` (build state), `slib:pcap:ruleerrs`, `slib:pcap:rulewarns`, `slib:pcap:feeds` (feed definitions), `slib:pcap:feedinfo` (download and sync state). |
| `rules/active/` | The loaded rules files, `snort-<build>.rules` and `suricata-<build>.rules`, each with a `.index.json` (`gid:sid` -> `{guid, rev}`). A file is deleted once no run uses it and a newer build replaced it. |
| `rules/feeds/<name>.mpk` | A feed's parsed rule records from its last download (msgpack). |
| `rules/feeds/synced/<name>/<view>.mpk` | A copy of the records last synced into each view, to compute the next sync's changes. |
| `snort/` | The generated `snort.lua`, and scratch directories of rule builds and scans. |
| `suricata/` | Scratch directories of rule builds and checks. |
| `tmp/` | Uploads and one directory per analysis (capture, key log, engine output, extracted files). Deleted when the service starts, and each run's directory when the run ends. |

If the rules files are lost (ex. a new volume with the old slab, or the build failed), the
service rebuilds them at startup from the pushed rules in its slab, and the next push rebuilds
too (`_needsBuild`).

## Network

| Direction | Target | Purpose |
| --- | --- | --- |
| Inbound | `27492/tcp` (Telepath, when `dmon:listen` is set) | The Cortex calls the service. |
| Inbound | `4443/tcp` (optional HTTPS) | Standard Cell HTTPS API, not used by the package. |
| Outbound | the Axon in `axon:url` | Read captures and key logs, upload extracted files. |
| Outbound | feed hosts over HTTPS | The default feeds: `www.snort.org`, `rules.emergingthreats.net`, and (disabled by default) `sslbl.abuse.ch`, `feodotracker.abuse.ch`, `urlhaus.abuse.ch`, plus any feed an admin adds. |

Feeds are downloaded with an `aiohttp.ClientSession(trust_env=True)`, so `HTTPS_PROXY`,
`HTTP_PROXY` and `NO_PROXY` are honored. The engines never get network access (see
[Sandbox](sandbox.md)).

## Host requirements

- Landlock is a feature of the host kernel, not the image: Linux 5.13+ (ABI 1), 6.7+ to also
  refuse TCP connect/bind (ABI 4), 6.15+ for audit logging of denials (ABI 7). Without it,
  `best-effort` runs engines without Landlock and `strict` refuses to run them.
- The seccomp filter supports `x86_64` and `aarch64`.
- Every layer works in a default Docker container: no extra capabilities and no seccomp or
  AppArmor profile changes.
- `--pids-limit` (or the compose `pids_limit`) caps the whole container's processes, a backstop
  for the engines' own `nproc` limit.
- Memory: an engine may use up to `sandbox:rlimits.as` (4 GiB) of address space, and up to
  `pcap:workers` captures run at once, each with up to three engines.

`slib.pcap.status` shows what the host supports.

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

  pcap:
    image: ghcr.io/gormaniac/stormsvcs/pcap:<version>
    environment:
      SYN_PCAPSVC_DMON_LISTEN: tcp://0.0.0.0:27492/
      SYN_PCAPSVC_AUTH_PASSWD: pcapsecret
      SYN_PCAPSVC_AXON_URL: tcp://root:axonsecret@axon:27492/
      SYN_PCAPSVC_PCAP_WORKERS: "2"
      SYN_PCAPSVC_PCAP_FEEDS_SECRETS: '{"talos:oinkcode": {"value": "<oinkcode>", "hosts": ["www.snort.org"]}}'
    pids_limit: 1024
    volumes:
      - pcap-storage:/vertex/storage
    depends_on:
      - axon

volumes:
  axon-storage:
  pcap-storage:
```

The Axon must be the one the Cortex stores file bytes in (the Cortex's `axon` config), or the
captures users analyze won't be found and extracted files won't be where `file:bytes` nodes
point.

## Adding the service to a Cortex

```text
service.add slib.pcap tcp://root:pcapsecret@pcap:27492/
service.list
pkg.list
```

When the service is added, its `add` event runs as root in the current (default) view
(`pcapsvc.defs._addStorm`):

1. Creates the `meta:source=cae9b5f5923a48b9a1a691f851a77429` node (`:name=slib.pcap`,
   `:type=slib.pcap`).
2. If `slib:pcap:cron` isn't set, creates a cron job running `slib.pcap.sync` with period
   `hourly@:17` (named `slib.pcap.sync`), and saves its iden in `slib:pcap:cron`.
3. If `slib:pcap:rules:view` isn't set, saves the current view's iden in it.

The `del` event pops `slib:pcap:rules:view` and `slib:pcap:cron` and deletes the cron job.

The default cron job runs as root (the add event did). `slib.pcap.admin.schedule --period`
replaces it with one that runs as the admin, in the admin's current view. The Cortex has no
rules in the service until the first sync, run `slib.pcap.sync` once after adding the service.

## Permissions

The package declares four permissions, all `gate: cortex`:

| Permission | Grants |
| --- | --- |
| `slib.pcap.user` | Analyze captures (`slib.pcap.flows`, `slib.pcap.lib`), check rules, view the status, rule errors, and feeds. |
| `slib.pcap.rules` | Add, enable, and disable rules (pushing them to the service). |
| `slib.pcap.sync` | Sync the feeds into the Cortex (as root) and push every enabled rule. |
| `slib.pcap.admin` | Manage the feeds, the sync schedule, and the network variables and Decode As rules for every run. |

```text
auth.role.addrule analysts slib.pcap.user
auth.role.addrule detection slib.pcap.rules
auth.user.addrule <sync user> slib.pcap.sync
auth.user.addrule <admin> slib.pcap.admin
```

Users don't need `service.get` or Axon permissions: the `slib.pcap.priv.*` modules are the only
code that calls the service and the Axon, and they run `asroot` for callers that hold the
matching permission. Node edits run as the calling user, so users also need the node
permissions for what's created: `inet:flow`, `file:bytes`, `file:attachment`,
`crypto:x509:cert`, `crypto:key`, `inet:fqdn`, `inet:dns:request`, `inet:dns:answer`,
`inet:dns:soa`, `it:app:snort:hit`, `it:app:suricata:matched`, the `meta:source`, the edges,
and tags given with `--tag`. `slib.pcap.rules` holders need edit permissions on the rule nodes.
`slib.pcap.sync` checks that the caller may add `it:app:snort:rule` and `it:app:suricata:rule`
nodes to the current layer, the rest of a sync's edits run as root.

## Upgrades

- Pull the new tag and recreate the container on the same volume. The Cortex reloads the
  `slib.pcap` package when the service reconnects with a new version.
- `tmp/` is cleared at startup. Rules, feed state, and sync snapshots are kept.
- Default feeds that were retired are removed at startup if their URL is unchanged (today:
  `abusech-sslbl-c2`). New default feeds aren't added to an existing service, since
  `pcap:feeds` is only read on first start, add them with `slib.pcap.admin.feed add`.
- Flow guids are versioned (`FLOW_IDEN_VERSION`, currently `2`), so a release that changes how
  flows are identified creates new nodes instead of colliding with old ones.
- The package requires Synapse `>=2.234.0,<3.0.0`.
