# Hatching Triage

`hatching` is a Synapse Advanced Power-Up (a Storm Service) for the
[Hatching Triage](https://tria.ge) malware sandbox. It runs as its own Synapse Cell
(`hatchingsvc.HatchingSvc`), talks to the Triage REST API through the
[pyhatching](https://pypi.org/project/pyhatching/) client, and registers the `slib.hatching`
Storm package in the Cortex. Every command, module, and permission is namespaced under
`slib.hatching`.

It works against the public cloud (`https://tria.ge`), the private cloud
(`https://private.tria.ge`), or a self-hosted Triage instance (the `hatching:url` option).

## What it does

| Area | What the service does | Commands |
| --- | --- | --- |
| Submission | Submits `file:bytes` from the Axon and URLs (browsed, or with `--fetch` downloaded by the sandbox and analyzed), with profiles, networks, VPN geolocations, archive passwords, Triage tags, and interactive profile selection. Imports public tria.ge samples into a private cloud. Deletes samples. | `slib.hatching.submit`, `slib.hatching.sample.profile`, `slib.hatching.sample.import`, `slib.hatching.sample.delete` |
| Finding samples | Searches Triage, lists owned, org, or public samples, prints sample metadata, summaries, and magic links, waits for analyses, and follows status events. | `slib.hatching.search`, `slib.hatching.samples`, `slib.hatching.sample.info`, `slib.hatching.sample.wait`, `slib.hatching.events` |
| Modeling | Turns a reported analysis (overview, static, and optionally every behavioral task report) into Synapse nodes: the sample, Triage's verdict and signatures, families, ATT&CK techniques, IOCs, credentials, malware configs, archive members, and, with `--tasks`, processes, network flows, DNS and HTTP requests, and dropped files. | `slib.hatching.enrich`, and `--model`/`--yield` on `search`, `sample.wait`, and `submit --wait` |
| Reports | Prints the overview, static, task, UrlScan, and kernel monitor reports. | `slib.hatching.report`, `slib.hatching.kernel` |
| Downloads | Streams the sample, task files (pcap, pcapng, screenshots, dropped files), and tar/zip archives into the Axon as `file:bytes`. | `slib.hatching.download` |
| Account management | Analysis profiles, Yara rules, analysis environments (resources), VPN geolocations, and usage stats. | `slib.hatching.profile.*`, `slib.hatching.yara.*`, `slib.hatching.resources`, `slib.hatching.geolocations`, `slib.hatching.stats` |
| Administration | The service-wide API key, the tag prefix, organization users and their API keys, organization settings and magic links, and raw API requests. | `slib.hatching.admin.*`, `slib.hatching.apikey` |

## Architecture

```text
 Storm user
     |  slib.hatching.* commands (perms: slib.hatching.user/submit/manage/admin)
     v
 slib.hatching Storm package (in the Cortex)
     |  slib.hatching.lib / .model / .util       - run as the calling user (node edits)
     |  slib.hatching.priv.{user,submit,manage,admin} - asroot, the only modules that call the service
     v
 Telepath  ($lib.service.get("slib.hatching"))
     |  HatchingCellApi (stormlibpp.svc.RetnApi) - every call returns {status, mesg, data}
     v
 HatchingSvc (synapse.lib.cell.Cell)
     |  pyhatching.PyHatchingClient, one per API key (Authorization: Bearer <key>)
     v
 Hatching Triage REST API  (<hatching:url><hatching:api_path>/v0/..., /v1/...)
```

The Python service owns every HTTP call and the normalization of Triage's reports
(`hatchingsvc.norm`). The Storm package owns the entry points (commands), permission checks,
the calling user's API key (a user scoped Synapse vault), and the translation of the
normalized data into nodes (`slib.hatching.model`). See [Internals](internals.md) for the
module-by-module walkthrough.

## Quick start

1. Run the service (see [Deployment](deployment.md) for every option):

   ```bash
   docker run -d --name slib-hatching \
       -v /srv/slib-hatching:/vertex/storage \
       -e SYN_HATCHINGSVC_AUTH_PASSWD=<root password> \
       -e SYN_HATCHINGSVC_HATCHING_APIKEY=<optional service-wide Triage key> \
       -p 27492:27492 \
       ghcr.io/gormaniac/stormsvcs/hatching:latest
   ```

2. Add it to the Cortex, and check that the `slib.hatching` package loaded:

   ```text
   service.add slib.hatching tcp://root:<root password>@<host>:27492/*
   service.list
   pkg.list
   ```

3. Set an API key, either service-wide (admin) or your own:

   ```text
   slib.hatching.admin.apikey <service-wide key>
   slib.hatching.apikey <your own key>
   ```

4. Grant permissions to analysts (see [permissions](deployment.md#permissions)):

   ```text
   auth.user.addrule visi slib.hatching.user
   auth.user.addrule visi slib.hatching.submit
   ```

5. Run a first command:

   ```text
   // Model the newest reported analysis of a file, with its behavioral tasks.
   file:bytes#my.tag | slib.hatching.enrich --tasks

   // Submit a URL, wait up to 10 minutes, model the result, and yield its node.
   slib.hatching.submit --url https://example.com/login --wait 600 --yield
   ```

```{toctree}
:maxdepth: 2

deployment
commands
model
api
internals
```
