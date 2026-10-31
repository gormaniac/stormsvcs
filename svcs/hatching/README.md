# hatching

A Synapse Advanced Power-Up (Storm Service) for the [Hatching Triage](https://tria.ge) sandbox,
built on [pyhatching](https://github.com/gormaniac/pyhatching). It supports the whole Triage API:

- Submitting files (from the Axon) and URLs (browsed, or fetched and analyzed), interactive
  submissions and profile selection, and deleting samples.
- Searching, listing (owned, org, and public), and following samples (events).
- Modeling analyses: the overview and static reports, and every behavioral task report.
- Reading the overview, static, task, summary, and kernel monitor reports.
- Downloading samples, task files (pcaps, screenshots, dropped files), and archives into the Axon.
- Managing analysis profiles and Yara rules.
- Managing users and their API keys on private and self-hosted instances.

The service registers the `slib.hatching` Storm package. Everything is namespaced under `slib.hatching`.

## Deploying

The service is published as `ghcr.io/gormaniac/stormsvcs/hatching`.

```bash
docker run -d --name slib-hatching \
    -v /srv/slib-hatching:/vertex/storage \
    -e SYN_HATCHINGSVC_HATCHING_APIKEY=<optional service-wide key> \
    -p 27492:27492 \
    ghcr.io/gormaniac/stormsvcs/hatching:latest
```

Then add it to a Cortex:

```
service.add slib.hatching tcp://<user>:<passwd>@<host>:27492/*
```

### Configuration

| Option | Env var | Default | Description |
|---|---|---|---|
| `hatching:apikey` | `SYN_HATCHINGSVC_HATCHING_APIKEY` | none | Fallback API key, see [API keys](#api-keys). |
| `hatching:url` | `SYN_HATCHINGSVC_HATCHING_URL` | `https://tria.ge` | The Triage instance, ex. `https://private.tria.ge` or a self-hosted one. |
| `hatching:api_path` | `SYN_HATCHINGSVC_HATCHING_API_PATH` | `/api` | The path the `/v0` and `/v1` endpoints live under (use `""` for `https://api.tria.ge`). |
| `hatching:timeout` | `SYN_HATCHINGSVC_HATCHING_TIMEOUT` | `60` | Seconds before a single request times out (downloads and events only use it to connect). |
| `hatching:maxsize` | `SYN_HATCHINGSVC_HATCHING_MAXSIZE` | `104857600` | The largest file, in bytes, that's submitted or downloaded. |

The service honors the standard `HTTP(S)_PROXY` environment variables.

## API keys

Keys are resolved in this order, per request:

1. **The calling user's own key** - set with `slib.hatching.apikey <key>`. It's stored in a
   user scoped Synapse vault (type `hatching`), so it is only ever used for that user's requests.
2. **The service-wide key** - set with `slib.hatching.admin.apikey <key>`. It's stored by the
   service, not the Cortex, so it can't be read back from Storm.
3. **The `hatching:apikey` config option.**

Every Triage API requires a key.

## Permissions

| Permission | Grants |
|---|---|
| `slib.hatching.user` | Search, model analyses, read reports, download files, list profiles and Yara rules, and set your own key. |
| `slib.hatching.submit` | Submit files and URLs, pick profiles for interactive samples, and delete samples. |
| `slib.hatching.manage` | Add, edit, and delete analysis profiles and Yara rules. |
| `slib.hatching.admin` | The service-wide key, tag settings, users and their API keys, and raw API requests. |

Users don't need the `service.get` permission. The `slib.hatching.priv.*` modules talk to the
service and elevate privileges only for users that hold the matching permission. Users still
need the normal node permissions for the nodes the commands create.

## Commands

| Command | Description |
|---|---|
| `slib.hatching.enrich` | Model the newest reported analysis of `file:bytes`, `hash:*`, and `inet:url` nodes, or `--sample` IDs. `--tasks` also models the behavioral tasks. |
| `slib.hatching.submit` | Submit `file:bytes` (from the Axon) and `inet:url` nodes, or `--url`s (`--fetch` to analyze the downloaded file). `--profile`, `--network`, `--timeout`, `--password`, `--tag`, `--interactive`. `--wait` models the results. |
| `slib.hatching.search` | Search Triage and print the samples, or model them with `--model`/`--yield`. |
| `slib.hatching.samples` | List the newest `owned`, `org`, or `public` samples. |
| `slib.hatching.sample.info` | Print a sample's metadata, or `--summary`. |
| `slib.hatching.sample.wait` | Wait for samples to be reported, then optionally model them. |
| `slib.hatching.sample.profile` | Pick the profiles of an interactive sample (or `--auto`). |
| `slib.hatching.sample.delete` | Delete samples. |
| `slib.hatching.events` | Print the status changes of a sample, or all of your running samples. |
| `slib.hatching.report` | Print the overview, static (`--static`), or a task's (`--task`) report. |
| `slib.hatching.kernel` | Print a task's kernel monitor events. |
| `slib.hatching.download` | Download a sample's file, `--task`/`--file`, `--pcap`/`--pcapng`, `--dumped` files, or `--archive` into the Axon. |
| `slib.hatching.profile.list` / `.add` / `.edit` / `.del` | Manage analysis profiles. |
| `slib.hatching.yara.list` / `.get` / `.add` / `.del` | Manage Yara rules (`.add` takes `it:app:yara:rule` nodes, `.get --yield` creates them). |
| `slib.hatching.apikey` | Set or clear your own API key. |
| `slib.hatching.admin.apikey` | Set or clear the service-wide API key. |
| `slib.hatching.admin.tags` | Change the tag prefix or turn tagging off. |
| `slib.hatching.admin.request` | Send a raw request to any Triage endpoint. |
| `slib.hatching.admin.users` / `.user.add` / `.user.del` | Manage users (private and self-hosted instances). |
| `slib.hatching.admin.user.keys` / `.user.key.add` / `.user.key.del` | Manage users' API keys. |

## Modeling

Each sample is modeled as a `file:bytes` (or `inet:url`, for URL analyses) with:

- Triage's tags as tags under the prefix (`#rep.hatching.<tag>`, ex. `#rep.hatching.cobaltstrike`,
  `#rep.hatching.backdoor`, `#rep.hatching.botnet.1234`), with the analysis time as the interval.
- An `it:av:scan:result` for Triage's verdict (scores 8-10 are malicious, 6-7 suspicious, and 1-5 benign).
- A `risk:tool:software` per malware family (with `:tag` set to its tag).
- `-(uses)> it:mitre:attack:technique` for the ATT&CK techniques of its signatures.
- `-(refs)>` edges to the IOCs Triage reported, URLs from droppers and ransom notes, and dropped files.
- An `it:sec:c2:config` per extracted malware config, with its C2 servers (and their hosts)
  tagged `#rep.hatching.c2` and the family.

With `--tasks`, each behavioral task adds `it:exec:proc`, `inet:flow`, `inet:dns:request`,
`inet:dns:a`/`aaaa`/`cname`, `inet:http:request`, and `it:exec:file:add` nodes, linked to the
sample with `:sandbox:file`.

Every node is linked to the service's `meta:source` (`hatching triage`) with a `-(seen)>` edge.
Modeling a sample again updates the same nodes.

## Testing

```bash
uv sync --dev
uv run pytest tests
```

The tests run against `pyhatching.testing.FakeTriage`. `tests/test_live.py` runs against the real
API when `HATCHING_LIVE_APIKEY` is set (and `HATCHING_LIVE_URL`, for a non-public instance).
