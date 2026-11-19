# PCAP

`slib.pcap` is a Synapse Advanced Power-Up (Storm Service) that analyzes packet captures. It
models every network flow in a capture as an `inet:flow` node, with everything the capture says
about it (TLS certificates, SSH host keys, software names and CPEs, DNS, RDP client details, the
files each side sent), and matches the capture against the Snort and Suricata rules in the
Cortex, modeling the matches as `it:app:snort:hit` and `it:app:suricata:matched` nodes.

The Python package is `pcapsvc` ({src}`svcs/pcap/src/pcapsvc`), the cell class is `PcapSvc`,
and the Storm package it registers is `slib.pcap`.

## What it does

A capture goes through up to four engines. Flows are always built by the first one, the others
only add details to them, so a flow is the same node whichever engines ran:

| Engine | Always | Does |
| --- | --- | --- |
| Flows (`dpkt`, pure Python) | yes | Reads pcap/pcapng (and gzip of either), decodes IP and transport headers, aggregates packets into bidirectional flows: endpoints, VLANs, per-direction packet and byte counts, TCP flags and state, duration, the first text payload of each side, the [Community ID](https://github.com/corelight/community-id-spec). |
| Suricata 8 | no | Application layer parsing (TLS, HTTP, HTTP/2, DNS, QUIC, SMB, Kerberos, SSH, RDP, FTP, SMTP, SIP), file extraction, protocol anomalies, and the Suricata rules (`it:app:suricata:rule`). |
| Snort 3 | no | The Snort 3 and Snort 2.x rules (`it:app:snort:rule`, Snort 2 rules converted with `snort2lua`). |
| tshark | no | The gaps Suricata leaves (SSH host keys and full banners, SIP `User-Agent`/`Server`, whole emails), TLS 1.2/1.3 decryption with a key log, and all of the application layer when Suricata isn't available. |

Engine output is joined to flows by frame number (Suricata's `pcap_cnt`, Snort's `pkt_num`,
tshark's `frame.number`), and by Community ID and time for the records that have no frame
number. Every engine is optional, and every engine run is [sandboxed](sandbox.md): an
unprivileged user, Landlock, a seccomp filter, `no_new_privs`, resource limits, a timeout, and
an output cap, with alerts when an engine does something it shouldn't.

Rules live in the Cortex. The service downloads rule feeds (the Snort 3 Community Ruleset and
ET Open by default), Storm models their rules as nodes, and every enabled rule node is pushed back
to the service, which builds one rules file per engine. See [Rules and feeds](rules.md).

## Architecture

```text
 Storm user / cron job
        |  slib.pcap.* commands, slib.pcap.lib
        v
 +----------------------------+   Telepath (port 27492)    +-------------------------------+
 | Cortex                     | -------------------------> | PcapSvc (pcapsvc.svc)         |
 |  slib.pcap package:        |   flows(), rule*, feed*,   |  RuleMixin (pcapsvc.rulesvc)  |
 |   priv.* modules (asroot)  |   push*, upload*, status   |  flows / enrich / eve         |
 |   model (node edits)       | <------------------------- |  Sandbox -> _sbxexec.py       |
 +----------------------------+   TelepathRetn             |    -> tshark, suricata, snort |
        |                                                   +-------------------------------+
        | $lib.axon (only without axon:url)                    |  axon:url            |  HTTPS
        v                                                      v                      v
     Axon  <-------------------- captures, key logs, extracted files            rule feeds
```

- **Cell** ({src}`svcs/pcap/src/pcapsvc/svc.py`): downloads the capture from the Axon (or takes
  it from an upload Storm streamed), runs the engines concurrently, correlates their output,
  builds the flows, uploads extracted files to the Axon, and returns the flows.
- **Telepath API** ({src}`svcs/pcap/src/pcapsvc/api.py`): a `stormlibpp.svc.RetnApi`, every
  method returns (or yields) a `TelepathRetn`. See [Telepath API](api.md).
- **Storm package** ({src}`svcs/pcap/src/pcapsvc/pkgproto/slib.pcap.yaml`): 13 commands, the
  `slib.pcap.priv.*` modules that are the only code talking to the service (run `asroot` for
  callers with the matching permission), and `slib.pcap.model`, which turns the service's data
  into nodes as the calling user.
- **Upstream**: there is no API. The "upstreams" are the local engines (built into the image)
  and the rule feed URLs.

## Quick start

1. Run the image with an Axon and a Telepath listener (full example in
   [Deployment](deployment.md#docker-compose-example)):

   ```bash
   docker run -d --name slib-pcap \
       -v /srv/slib-pcap:/vertex/storage \
       -e SYN_PCAPSVC_DMON_LISTEN="tcp://0.0.0.0:27492/" \
       -e SYN_PCAPSVC_AUTH_PASSWD="<passwd>" \
       -e SYN_PCAPSVC_AXON_URL="tcp://<user>:<passwd>@<axon host>:27492/" \
       -p 27492:27492 \
       --pids-limit 1024 \
       ghcr.io/gormaniac/stormsvcs/pcap:latest
   ```

2. Add it to the Cortex. The service's add event creates its `meta:source`, the hourly
   `slib.pcap.sync` cron job, and binds the service's rules to the current view:

   ```text
   service.add slib.pcap tcp://root:<passwd>@<host>:27492/
   ```

3. Grant permissions (see [Deployment](deployment.md#permissions)):

   ```text
   auth.role.addrule analysts slib.pcap.user
   ```

4. Check the engines, the sandbox, and the Axon, then load the rules now instead of waiting for
   the cron job:

   ```text
   slib.pcap.status
   slib.pcap.sync
   ```

5. Analyze a capture that's already a `file:bytes` in the Axon:

   ```text
   file:bytes=sha256:<sha256> | slib.pcap.flows --yield
   ```

:::{note}
Quote `sha256:` values that start with digits on the Storm command line (ex.
`slib.pcap.flows "sha256:6010e3..."`). Storm's parser can read an unquoted value like
`6010E3...` as a number with an exponent.
:::

## Pages

```{toctree}
:maxdepth: 2

deployment
commands
model
api
internals
rules
sandbox
```
