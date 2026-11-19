# abuse.ch

`abusech` is a Synapse Advanced Power-Up (a Storm Service) that connects a Synapse Cortex to
every abuse.ch platform and models what they return. It registers the `slib.abusech` Storm
package, and every Storm command, module, permission, global and `meta:source` it creates is
namespaced under `slib.abusech`.

| | |
|---|---|
| Python package | `abusechsvc` ({src}`svcs/abusech/src/abusechsvc`) |
| Cell class | `abusechsvc.AbuseChSvc` |
| Storm package | `slib.abusech` 0.5.0 (requires Synapse `>=2.256.0,<3.0.0`) |
| Docker image | `ghcr.io/gormaniac/stormsvcs/abusech` |
| Service name in the Cortex | `slib.abusech` (the Storm code looks the service up by this name) |

## What it covers

| Platform | What the service does with it | Commands |
|---|---|---|
| MalwareBazaar | Sample lookups and searches, the Code Signing Certificate Blocklist, sample downloads, sample submission and updates, the CSV exports and the YARA rule statistics | [MalwareBazaar commands](commands-bazaar.md) |
| URLhaus | URL, URL ID, host and payload lookups, tag/signature searches, recent URLs and payloads, payload downloads, URL submission, the CSV exports | [URLhaus commands](commands-urlhaus.md) |
| ThreatFox | IOC lookups (by value, ID, IP, sample hash), recent/tag/malware searches, reference data, IOC submission, the JSON exports | [ThreatFox commands](commands-threatfox.md) |
| YARAify | File lookups and searches, scan task results, file scans and rescans, task lists and identifiers, YARAhub rules, rule deployment, file downloads | [YARAify commands](commands-yaraify.md) |
| Feodo Tracker | The `all`, `recommended` and `aggressive` botnet C2 blocklists | [Blocklist commands](commands-blocklists.md) |
| SSL Blacklist (SSLBL) | The malicious TLS certificate (SHA1) and JA3 fingerprint lists | [Blocklist commands](commands-blocklists.md) |
| Hunting | The abuse.ch false positive list | [Blocklist commands](commands-blocklists.md) |

On top of the per-platform commands:

- `slib.abusech.enrich` enriches any supported node (files and hashes, URLs, FQDNs, IPs,
  servers) from every platform that knows its form.
- The export commands take `--bulk`, which builds the nodes for a whole export inside the
  service and ingests them with `$lib.feed.fromAxon()` (see [Bulk imports](bulk.md)).
- Auth-Keys can be set per user (in a Synapse vault) or service-wide (in the service's own
  storage), see [Auth-Keys](deployment.md#auth-keys).
- Admin commands set the tag prefix, send raw API requests, and migrate data modeled by older
  versions of the package (see [Admin commands](commands-admin.md)).

## Architecture

```text
 Storm user
     |
     |  slib.abusech.* commands  (run as the user)
     v
 slib.abusech.lib / .model / .download     unprivileged modules: node edits run as the user
     |
     |  slib.abusech.priv.*  (asroot:perms, gated on slib.abusech.<perm>)
     v
 $lib.service.get("slib.abusech")  ---- Telepath ---->  AbuseChCellApi (RetnApi)
                                                           |
                                                           v
                                                        AbuseChSvc (synapse Cell)
                                                           |  norm.py / bulk.py
                                                           v
                                                        AbuseChClient (aiohttp)
                                                           |  HTTPS, Auth-Key header
                                                           v
                                                        abuse.ch APIs and datasets
```

- The **cell** ({src}`svcs/abusech/src/abusechsvc/svc.py`) has one method per abuse.ch
  endpoint or dataset. Methods named after an endpoint return abuse.ch's data as-is; the
  `norm*` variants and the generators return it normalized into a few shared shapes
  ({src}`svcs/abusech/src/abusechsvc/norm.py`).
- The **Telepath API** ({src}`svcs/abusech/src/abusechsvc/api.py`) wraps every method in a
  StormLib++ `TelepathRetn` (`{"status", "mesg", "data"}`), so errors reach Storm as
  `status=False` instead of exceptions. See [Telepath and Storm API](api.md).
- The **Storm package** ({src}`svcs/abusech/src/abusechsvc/pkgproto/slib.abusech.yaml`)
  is the entry point. Only the `slib.abusech.priv.*` modules talk to the service (and the
  Axon); they run as root for users holding the matching `slib.abusech.*` permission, so
  users need neither `service.get` nor Axon permissions. All modeling happens in
  `slib.abusech.model`, which runs as the calling user, so normal node permissions apply.
- The **transport** ({src}`svcs/abusech/src/abusechsvc/client.py`) handles each API's
  request style (form, JSON, multipart, file downloads), abuse.ch's `query_status`
  convention, rate limiting, retries, size caps, zips and Auth-Key scrubbing. See
  [Internals](internals.md).

## Quick start

1. Run the service (see [Deployment](deployment.md) for every option):

   ```bash
   docker run -d --name slib-abusech \
       -v /srv/slib-abusech:/vertex/storage \
       -e SYN_ABUSECHSVC_AUTH_PASSWD=<root password for the service> \
       -p 27492:27492 \
       ghcr.io/gormaniac/stormsvcs/abusech:latest
   ```

2. Add it to the Cortex, as an admin, under the name `slib.abusech`. Adding it runs the
   service's `add` event, which creates the `meta:source` nodes, the `file:bytes` extended
   props, and the tag settings:

   ```text
   service.add slib.abusech tcp://root:<passwd>@<host>:27492/*
   service.list
   ```

3. Set an Auth-Key (free from https://auth.abuse.ch/, one key works for every platform),
   either your own or one for every user:

   ```text
   slib.abusech.apikey <your Auth-Key>
   slib.abusech.admin.apikey <service-wide Auth-Key>
   ```

4. Grant users the permissions they need (see [Permissions](deployment.md#permissions)),
   ex. `auth.user.addrule analyst slib.abusech.user`.

5. Run a first command:

   ```text
   // Everything abuse.ch knows about some nodes.
   #my.tag | slib.abusech.enrich

   // The Feodo Tracker recommended blocklist (no Auth-Key needed).
   slib.abusech.feodo recommended --yield
   ```

```{toctree}
:maxdepth: 2

deployment
commands
commands-bazaar
commands-urlhaus
commands-threatfox
commands-yaraify
commands-blocklists
commands-admin
model
api
internals
bulk
```
