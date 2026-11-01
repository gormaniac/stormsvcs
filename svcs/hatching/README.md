# hatching

A Synapse Advanced Power-Up (Storm Service) for the [Hatching Triage](https://tria.ge) sandbox,
built on [pyhatching](https://pypi.org/project/pyhatching/) (1.0.0+). It covers the documented
[Triage API](https://tria.ge/docs/) (see [API coverage](#api-coverage)):

- Submitting files (from the Axon) and URLs (browsed, or fetched and analyzed), with profiles,
  networks (including VPN geolocations), interactive profile selection, and importing public
  samples into a private cloud. Deleting samples.
- Searching, listing (owned, org, and public), and following samples (events).
- Modeling analyses: the overview and static reports, and every behavioral task report.
- Reading the overview, static, task, UrlScan, summary, and kernel monitor reports, and
  creating magic links to share analyses.
- Downloading samples, task files (pcaps, screenshots, dropped files), and archives into the Axon.
- Managing analysis profiles and Yara rules, and listing the analysis environments (resources),
  VPN geolocations, and usage stats.
- Managing your organization's users, their API keys, and its settings.

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
| `slib.hatching.user` | Search, model analyses, read reports, download files, list profiles, Yara rules, resources, and geolocations, and set your own key. |
| `slib.hatching.submit` | Submit files and URLs, import public samples, pick profiles for interactive samples, and delete samples. |
| `slib.hatching.manage` | Add, edit, and delete analysis profiles and Yara rules. |
| `slib.hatching.admin` | The service-wide key, tag settings, users and their API keys, organization settings, and raw API requests. |

Users don't need the `service.get` permission. The `slib.hatching.priv.*` modules talk to the
service and elevate privileges only for users that hold the matching permission. Users still
need the normal node permissions for the nodes the commands create.

## Commands

| Command | Description |
|---|---|
| `slib.hatching.enrich` | Model the newest reported analysis of `file:bytes`, `hash:*`, and `inet:url` nodes, or `--sample` IDs. `--tasks` also models the behavioral tasks. |
| `slib.hatching.submit` | Submit `file:bytes` (from the Axon) and `inet:url` nodes, or `--url`s (`--fetch` to analyze the downloaded file). `--profile`, `--network` (`vpn` with `--geolocation`), `--timeout`, `--password`, `--tag`, `--interactive`. `--wait` models the results. |
| `slib.hatching.sample.import` | Import public tria.ge samples into a private cloud instance. |
| `slib.hatching.search` | Search Triage and print the samples, or model them with `--model`/`--yield`. |
| `slib.hatching.samples` | List the newest `owned`, `org`, or `public` samples. |
| `slib.hatching.sample.info` | Print a sample's metadata, `--summary`, or a shareable magic `--link`. |
| `slib.hatching.sample.wait` | Wait for samples to be reported, then optionally model them. |
| `slib.hatching.sample.profile` | Pick the profiles of an interactive sample (or `--auto`). |
| `slib.hatching.sample.delete` | Delete samples. |
| `slib.hatching.events` | Print the status changes of a sample, or all of your running samples. |
| `slib.hatching.report` | Print the overview, static (`--static`), a task's (`--task`), or a URL sample's UrlScan (`--urlscan`) report. |
| `slib.hatching.kernel` | Print a task's kernel monitor events. |
| `slib.hatching.download` | Download a sample's file, `--task`/`--file`, `--pcap`/`--pcapng`, `--dumped` files, a URL sample's `--screenshot`, or `--archive` into the Axon. |
| `slib.hatching.profile.list` / `.add` / `.edit` / `.del` | Manage analysis profiles (`--network vpn --geolocation <region>` for VPN profiles). |
| `slib.hatching.resources` | List the analysis environments and the tags profiles pick them with. |
| `slib.hatching.geolocations` | List the VPN regions. |
| `slib.hatching.stats` | Print your usage stats. |
| `slib.hatching.yara.list` / `.get` / `.add` / `.del` | Manage Yara rules (`.add` takes `it:app:yara:rule` nodes, `.get --yield` creates them, `.add --rename` renames one). |
| `slib.hatching.apikey` | Set or clear your own API key. |
| `slib.hatching.admin.apikey` | Set or clear the service-wide API key. |
| `slib.hatching.admin.tags` | Change the tag prefix or turn tagging off. |
| `slib.hatching.admin.request` | Send a raw request to any Triage endpoint. |
| `slib.hatching.admin.users` / `.user.add` / `.user.del` | Manage your organization's users (by email or username, with a `--role`). |
| `slib.hatching.admin.user.keys` / `.user.key.add` / `.user.key.del` | Manage users' API keys. |
| `slib.hatching.admin.org` | Print the organization's settings or `--stats`, or turn `--magic` links on or off. |

The `admin.user*` and `admin.org` commands need a Triage key with the `manage_company` permission.

## Modeling

Each sample is modeled as a `file:bytes` (or `inet:url`, for URL analyses) with:

- Triage's tags as tags under the prefix (`#rep.hatching.<tag>`, ex. `#rep.hatching.cobaltstrike`,
  `#rep.hatching.backdoor`, `#rep.hatching.botnet.1234`), with the analysis time as the interval.
- An `it:av:scan:result` for Triage's verdict, using [Triage's scoring](https://tria.ge/docs/scoring/):
  scores 8-10 are malicious, 5-7 suspicious, and 1-4 benign.
- An `it:av:scan:result` per matched signature (`:signame`, its own verdict, its tags as
  `:categories`, and `-(uses)>` its techniques), linked to the verdict with `:multi:scan`.
- A `risk:tool:software` per malware family (with `:tag` set to its tag).
- `-(uses)> it:mitre:attack:technique` for the ATT&CK techniques of its signatures.
- `-(refs)>` edges to the IOCs Triage reported, URLs from droppers and ransom notes, credentials
  (`auth:creds`), and dropped files.
- For archives, a `file:subfile` (with `:path`) per analyzed member, each tagged with its own
  Triage tags and families.
- An `it:sec:c2:config` per extracted malware config: its C2 servers (and their hosts) tagged
  `#rep.hatching.c2` and the family, `:mutex` (the rest are `-(refs)>` from the sample),
  `:decoys`, `:listens`, `:dns:resolvers`, `:campaigncode`, the whole config as `:raw`, and
  `-(refs)> auth:creds` for its credentials.

With `--tasks`, each behavioral task adds, linked to the sample with `:sandbox:file`:

- `it:exec:proc` nodes (the original process's `:exe` is the sample, or the archive member the
  task ran).
- `inet:flow` nodes with the client and server, the process, byte and packet counts, and
  `-(refs)>` the domain and TLS server name, plus `inet:tls:ja3:sample` and
  `inet:tls:ja3s:sample` nodes for its TLS fingerprints.
- `inet:dns:request` nodes (with the query type and server), and `inet:dns:a`/`aaaa`/`cname`.
- `inet:http:request` nodes with the method, URL, headers, server, and the response's code,
  reason, and headers.
- `it:exec:file:add` nodes for dropped files (with their name, path, hashes, and process).
- Triage's ASN and country (`:asn`, `:loc`) for the IPs, when the graph doesn't have them yet.

Every node is linked to the service's `meta:source` (`hatching triage`) with a `-(seen)>` edge.
Modeling a sample again updates the same nodes. Failures Triage reports in an analysis (ex. a
task that couldn't run) are printed as warnings.

### Not modeled

- Ransom note and config cryptocurrency wallets (Triage doesn't say which currency they're for),
  config `keys`, `webinject`, `command_lines`, and `attr` (they stay in the config's `:raw`).
- Dropper source code, ransom note text, and signature indicators and descriptions.
- Relative timestamps (process start, flow first/last seen, request times): they're offsets into
  the analysis, not times.
- The static report beyond the sample's MIME type (the overview report covers its tags and
  signatures), kernel monitor events (print them with `slib.hatching.kernel`), and UrlScan
  reports (Triage documents their shape as subject to change, print them with
  `slib.hatching.report --urlscan`).
- URL analyses' behavioral nodes can't set `:sandbox:file`, which needs a `file:bytes`.

## API coverage

| Triage API | Commands |
|---|---|
| `POST /samples` (`file`, `url`, `fetch`, `import`) | `submit`, `sample.import` |
| `GET /samples`, `/search`, `/samples/{id}`, `/summary`, `/events` | `samples`, `search`, `enrich`, `sample.info`, `sample.wait`, `events` |
| `POST /samples/{id}/profile`, `DELETE /samples/{id}` | `sample.profile`, `sample.delete` |
| `GET /samples/{id}/magic` | `sample.info --link` |
| Overview, static, task, UrlScan, and kernel reports | `enrich`, `report`, `kernel` |
| Sample, task file, pcap, screenshot, and archive downloads | `download` |
| `/profiles` | `profile.*` |
| `/yara` | `yara.*` |
| `/resources`, `/geolocations`, `/stats/user` | `resources`, `geolocations`, `stats` |
| `/users`, `/users/{id}/apikeys` | `admin.users`, `admin.user.*` |
| `/org/settings`, `/org/settings/magic`, `/stats/org` | `admin.org` |
| Anything else | `admin.request` |

Out of scope: SAML configuration (it's done in the Triage web UI).

## Testing

```bash
uv sync --dev
uv run pytest tests
```

The tests run against `pyhatching.testing.FakeTriage`. `tests/test_live.py` runs against the real
API when `HATCHING_LIVE_APIKEY` is set (and `HATCHING_LIVE_URL`, for a non-public instance).
