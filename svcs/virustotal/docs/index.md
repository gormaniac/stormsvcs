# VirusTotal (slib.vt)

`slib.vt` is a Synapse Storm Service (Advanced Power-Up) for the VirusTotal **Public
(community) API v3**. It looks up files, URLs, domains, and IP addresses in VirusTotal and
models the reports in a Cortex, follows VirusTotal relationships (resolutions, contacted
domains, communicating files, ...), and can submit files and URLs, request rescans, comment,
and vote.

It is built for free VirusTotal Community API keys, whose limits are small (4 requests per
minute, 500 per day, 15,500 per month per key) and whose terms forbid working around them. By
default every request the service sends first reserves a slot in a persistent, per API key
rate limiter, so the service never sends more than the Public API allows. Premium keys work
too: set `vt:community` to `false`.

| | |
| --- | --- |
| Python package | `vtsvc` ({src}`svcs/virustotal/src/vtsvc`) |
| Cell class | `vtsvc.svc.VtSvc` |
| Storm package | `slib.vt` |
| Service name (as added to a Cortex) | `slib.vt` |
| Image | `ghcr.io/gormaniac/stormsvcs/virustotal` |
| Synapse | `>=2.234.0,<3.0.0` (the Storm package's `synapse_version`) |

## Features

- **Enrichment** (`slib.vt.enrich`): file reports (hashes, size, names, ssdeep, imphash, PE
  compile time, sandbox verdicts, crowdsourced YARA / IDS / Sigma matches), domain reports
  (DNS records, whois, last HTTPS certificate), IP reports (ASN, country, whois, HTTPS
  certificate, JARM), and URL reports (redirects, final response content). Optionally the
  sandbox behaviour summary of a file (DNS lookups, traffic, HTTP requests, mutexes, dropped
  files, MITRE ATT&CK techniques).
- **AV results**: the latest multi-engine scan of every object as an `it:av:scan:result`,
  plus one `it:av:scan:result` per engine (detections only, all, or none).
- **Reputation tags** under a configurable prefix (`rep.vt` by default): verdict, VirusTotal
  tags, threat family, threat category, behaviour.
- **Relationships** (`slib.vt.related`) a Public API key can read, paged 40 objects per request.
- **Community** data: comments (`slib.vt.comments`) as `meta:note` nodes; adding comments
  and votes.
- **Submissions** (`slib.vt.submit`, `slib.vt.rescan`, `slib.vt.analysis`): files read from
  the Axon (up to 650MB, using a one time upload URL above 32MB) and URLs, with optional
  polling of the analysis.
- **Quota handling**: a per key sliding window for the per minute limit, daily and monthly
  counters persisted in the service's storage, a cooldown after HTTP 429, a response cache,
  and `slib.vt.quota` to inspect it all. See [Rate limits and quotas](quota.md).
- **API keys** per user (a user scoped `virustotal` vault) or service-wide; the service-wide
  key is never readable from Storm.

## Architecture

```text
 Storm user
    |  slib.vt.* commands (perms: slib.vt.user / slib.vt.submit / slib.vt.admin)
    v
 slib.vt Storm package (in the Cortex)
    |  slib.vt.lib / slib.vt.model     run as the calling user, make the node edits
    |  slib.vt.priv.{user,submit,admin} asroot modules, the only code that calls the service
    v
 Telepath  -- $lib.service.get("slib.vt").<method>(...) -> {status, mesg, data}
    v
 VtSvc (Synapse Cell, vtsvc.svc)
    |  VtCellApi (stormlibpp.svc.RetnApi): every call returns a TelepathRetn
    |  vtsvc.norm: flattens VirusTotal objects for the Storm model
    |  vtsvc.client.VtClient: HTTP, retries, response cache
    |  vtsvc.quota.QuotaLimiter: per key limits, persisted in the cell slab
    v
 https://www.virustotal.com/api/v3  (x-apikey header)
```

The Python service owns the HTTP calls, rate limiting, caching, and normalization; the Storm
package owns permissions, API key lookup from the user's vault, and turning the normalized
dicts into nodes. See [Internals](internals.md).

## Quick start

Run the service (see [Deployment](deployment.md) for the full options):

```bash
docker run -d --name slib-vt \
    -v /srv/slib-vt:/vertex/storage \
    -e SYN_VTSVC_AUTH_PASSWD=secret \
    -p 27492:27492 \
    ghcr.io/gormaniac/stormsvcs/virustotal:latest
```

Add it to a Cortex, then set a key and look something up:

```text
service.add slib.vt tcp://root:secret@<host>:27492
service.list

// A service-wide key, used by everyone without their own (slib.vt.apikey).
slib.vt.admin.apikey <your VirusTotal API key>

slib.vt.enrich --fqdn example.com --yield
slib.vt.quota
```

Grant analysts `slib.vt.user` (and `slib.vt.submit` if they may send data to VirusTotal),
plus the node permissions to create what the service models. See
[Permissions](deployment.md#permissions).

```{toctree}
:maxdepth: 2

deployment
commands
model
api
internals
quota
```
