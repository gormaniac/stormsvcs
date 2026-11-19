# Shodan

The Shodan service (`shodan`) is a Synapse Advanced Power-Up that puts Shodan's APIs in a
Cortex: host lookups, search and the free count API, on-demand scans, network alerts and
notifiers, DNS, the Streaming API, Trends, the saved query directory, bulk data, organization
management, and the free InternetDB and CVEDB APIs. The service makes the HTTP calls and
reshapes Shodan's responses into flat dicts. The `slib.shodan` Storm package turns those dicts
into Synapse nodes.

| | |
| --- | --- |
| Python package | `shodansvc` |
| Storm package | `slib.shodan` |
| Storm service name | `slib.shodan` |
| Cell class | `shodansvc.svc.ShodanSvc` |
| Telepath API class | `shodansvc.api.ShodanCellApi` (a `stormlibpp.svc.RetnApi`) |
| Docker image | `ghcr.io/gormaniac/stormsvcs/shodan` |
| Synapse | `>=2.256.0,<3.0.0` (the Storm package's `synapse_version`) |
| Python | `>=3.11,<3.12` |

## Why a service

Storm can make HTTP requests, but a Shodan integration needs more than a request. The service
keeps the service-wide API key out of the Cortex, applies Shodan's 1 request/second limit to
every user's calls at once, retries HTTP 429s, reads the Streaming API, and pages through
searches and the DNS API. It also learns each plan's facet limit, computes Shodan's MurmurHash3
banner, favicon and HTML hashes, and normalizes the many shapes Shodan returns (banners,
hosts, InternetDB, CVEDB CVEs, GHSAs, EUVD entries). The Storm package only picks which nodes
to send and how to model the results.

## Features

- **Hosts.** Model an IP and every banner Shodan has for it: `inet:server`, `inet:banner`, the
  ASN and its owner, location, reverse DNS names, software, vulns, TLS certs, JARM and JA3S,
  SSH host keys, HTTP requests and headers, and every file a web server returned. Uses
  InternetDB when there is no API key ({ref}`shodan-cmd-host`).
- **Host history.** `--history` adds Shodan's 90 day banner history, and an IP's history can be
  kept as a `meta:timeline` with one `meta:event` per banner.
- **Search.** Run a query, or build one from inbound nodes (banners, certs, favicons, CPEs,
  CVEs, ASNs, netblocks and more). Each run is recorded as an `it:exec:query` linked to what it
  found ({ref}`shodan-cmd-search`).
- **Free IP lists.** `slib.shodan.count` lists the IPs matching a query with the count API's
  `ip` facet, which uses no query credits ({ref}`shodan-cmd-count`).
- **Local hashes.** Shodan's banner `hash`, `http.favicon.hash` and `http.html_hash`, computed
  for nodes from any source ({ref}`shodan-cmd-hash`).
- **Streaming API.** All 8 stream types, bounded by a banner limit and a timeout
  ({ref}`shodan-cmd-stream`).
- **DNS.** Domain records and subdomains, forward and reverse resolution.
- **Vulnerabilities.** CVE, GHSA and EUVD details from CVEDB, with CVSS scores, KEV status,
  EPSS, references and CWEs, and CVE searches by CPE or product.
- **Trends.** Monthly historical counts and facets.
- **Saved queries.** Copy Shodan's query directory into the Cortex as `meta:rule` nodes, save
  local queries, and run any of them.
- **Scans, alerts, notifiers.** Submit scans (and ingest the results), create and edit network
  alerts, and manage notifiers.
- **Administration.** A service-wide API key, tag settings, organization members, bulk
  datasets, a raw request escape hatch, and a cleanup for pre-0.17.0 DNS nodes.

The Exploits API (`exploits.shodan.io`) and the Honeyscore API (`/labs/honeyscore`) aren't
called by the service.

## Architecture

```text
 Storm user                    Cortex                                   shodan service (ShodanSvc)
 ----------                    ------                                   --------------------------
 inet:ipv4=8.8.8.8 | slib.shodan.host
        |
        v
 slib.shodan.* commands
        |
        v
 slib.shodan.lib / slib.shodan.model     (run as the calling user, make the nodes)
        |
        v
 slib.shodan.priv.{user,scan,alert,admin} (asroot modules, read the user's vault key)
        |   $lib.service.get("slib.shodan")
        +---------------- Telepath ------------------> ShodanCellApi (RetnApi)
                                                              |  TelepathRetn {status, mesg, data}
                                                              v
                                                       ShodanSvc methods -> norm.py
                                                              |
                                                              v
                                                       ShodanClient (aiohttp, rate limit, retries)
                                                              |
                     api / stream / trends / internetdb / cvedb .shodan.io (HTTPS)
```

1. A command finds the input values (IPs, a query, CVE IDs) from its inbound nodes or options.
2. It calls a function in a `slib.shodan.priv.*` module. These modules run as root, so users
   don't need the `service.get` permission. Only users holding the module's
   `slib.shodan.<user|scan|alert|admin>` permission can import them. They add the calling
   user's own API key (from a user scoped vault of type `shodan`), if any.
3. The call reaches `ShodanCellApi` over Telepath. Every method returns a `TelepathRetn`
   (`{"status": bool, "mesg": str, "data": ...}`) and never raises (see [api](api.md)).
4. `ShodanSvc` resolves the API key, sends the request through `ShodanClient`, and normalizes
   the response with `shodansvc.norm`.
5. `slib.shodan.model` makes the nodes as the calling user, so normal node permissions apply.
   Every node is linked to the service's `meta:source` with a `-(seen)>` edge (see
   [model](model.md)).

## Quick start

1. Run the service with a root password (see [Deployment](deployment.md) for a compose file):

   ```bash
   docker run -d --name slib-shodan \
       -v /srv/slib-shodan:/vertex/storage \
       -e SYN_SHODANSVC_AUTH_PASSWD=secret \
       -p 27492:27492 \
       ghcr.io/gormaniac/stormsvcs/shodan:latest
   ```

2. Add it to the Cortex and check that it's ready:

   ```text
   service.add slib.shodan tcp://root:secret@<host>:27492/
   service.list
   ```

3. Set a service-wide Shodan API key (needs `slib.shodan.admin`), or let each user set their
   own with `slib.shodan.apikey`:

   ```text
   slib.shodan.admin.apikey <key>
   ```

4. Grant users `slib.shodan.user` (and `slib.shodan.scan`, `slib.shodan.alert` or
   `slib.shodan.admin` as needed), then run a first command:

   ```text
   slib.shodan.info
   slib.shodan.host --ip 8.8.8.8 --yield
   ```

Without any API key, `slib.shodan.host` warns and uses InternetDB, and the CVEDB commands
(`slib.shodan.cve`, `slib.shodan.cpe`) work as-is.

```{toctree}
:maxdepth: 2

deployment
commands
commands-hosts
commands-search
commands-vulns
commands-scan-alert
commands-admin
model
api
internals
```
