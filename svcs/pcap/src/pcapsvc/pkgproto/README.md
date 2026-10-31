# pcap

A Synapse Advanced Power-Up (Storm Service) that reads packet captures from an Axon and models
every network flow in them as an `inet:flow` node.

Analysis happens in two passes:

1. **Flows (dpkt, always).** The service downloads a capture by SHA-256 from its Axon, decodes
   every packet's IP and transport headers, and aggregates the packets into bidirectional flows:
   endpoints, packet and byte counts per direction, TCP flags, duration, and the first text
   payload each side sent (ex. an HTTP request line, SMTP banner, or SSH version string).
2. **Application layer details (tshark, optional).** When tshark is installed (it is in the
   Docker image), the service also runs it over the capture for everything else `inet:flow` can
   hold: TLS certificates, SSH host keys, RDP client details, software names and CPEs, and the
   files each side sent, which are extracted into the Axon. See [Modeling](#modeling).

tshark's output is matched to flows by frame number, so flows are always built the same way
whether or not tshark ran; tshark only adds details to them.

The service registers the `slib.pcap` Storm package.

Supported captures:

- **Formats:** libpcap (micro- and nanosecond, either byte order), pcapng (every interface keeps
  its own link type, timestamp resolution, and offset; multiple sections), and gzip compressed
  versions of either. Truncated captures are read up to where they're cut off.
- **Link types:** Ethernet (including VLAN/QinQ and PPPoE), raw IP, BSD loopback (`NULL`/`LOOP`),
  Linux cooked capture (`SLL` and `SLL2`), and PPP.
- **Protocols:** IPv4 and IPv6. TCP and UDP flows are keyed by address and port, every other
  IP protocol (ICMP, ICMPv6, GRE, ESP, etc.) by address.

## Deploying

```bash
docker run -d --name slib-pcap \
    -v /srv/slib-pcap:/vertex/storage \
    -e SYN_PCAPSVC_AXON_URL="aha://axon..." \
    -p 27492:27492 \
    ghcr.io/gormaniac/stormsvcs/pcap:latest
```

```
service.add slib.pcap tcp://<user>:<passwd>@<host>:27492/*
```

`axon:url` must point at the Axon the Cortex stores files in (the one `$lib.axon` uses), so the
service can read the captures Storm users have uploaded. The service also uploads the files it
extracts from flows there, so the URL's user needs write access. Captures and extracted files are
spooled to a temp directory under the service's storage directory (not held in memory) and
deleted once they're analyzed.

Without Docker, install tshark from your OS packages (ex. `apt-get install tshark`). Any version
works; fields an older tshark doesn't have (ex. JA4 needs 4.2) are left out. tshark parses
untrusted input with a lot of C code, keep it patched, or set `tshark:enabled` to `false` to only
use the pure Python flow pass.

### Configuration

| Option | Default | Description |
|---|---|---|
| `axon:url` | | The Telepath URL of the Axon captures are read from. Required. |
| `pcap:timeout` | `300` | The default seconds a flow can be idle before the next packet between the same endpoints starts a new flow, `0` to never time out. |
| `pcap:limit` | `100000` | The max number of flows for one capture. Packets for any more flows are dropped (and counted). |
| `pcap:handshake` | `1024` | The default max characters kept from each side's first text payload, `0` for none. |
| `pcap:maxsize` | `1073741824` | The max capture size in bytes (1 GiB), `0` for no limit. |
| `pcap:files` | `true` | Extract the files sent in flows into the Axon by default (needs tshark). |
| `pcap:files:maxsize` | `67108864` | The largest file extracted from a flow (64 MiB), `0` for no limit. |
| `pcap:files:limit` | `10000` | The max number of files extracted from one capture, `0` for no limit. |
| `tshark:enabled` | `true` | Use tshark, when it's installed, by default. |
| `tshark:path` | `tshark` | The tshark binary, a path or a name on the `PATH`. |
| `tshark:args` | `[]` | Extra tshark arguments, ex. `["-d", "tcp.port==2222,ssh"]` to decode SSH on a non-standard port. |
| `tshark:timeout` | `600` | Seconds a tshark run may take before it's killed, `0` for no limit. |

## Usage

```
// Analyze PCAPs that are already file:bytes nodes.
file:bytes:mime=application/vnd.tcpdump.pcap | slib.pcap.flows

// Yield the flows, tag them, and set the sensor that captured them.
file:bytes=sha256:<sha256> | slib.pcap.flows --yield --tag cno.case.123 --host <it:host guid>

// Analyze by SHA-256 (the file:bytes node is created if needed).
slib.pcap.flows <sha256> --yield | +inet:flow:dst:port=443

// Every flow from a PCAP.
file:bytes=sha256:<sha256> -(refs)> inet:flow
```

> Quote SHA-256s that start with `sha256:` on the command line. Storm's parser splits unquoted
> values like `sha256:6010E3...` at what looks like an exponent.

| Option | Default | Description |
|---|---|---|
| `sha256s` | | SHA-256s of captures to analyze instead of the inbound `file:bytes` nodes. |
| `--timeout` | `pcap:timeout` | Seconds a flow can be idle before a new flow starts, `0` to never time out. |
| `--limit` | `pcap:limit` | The max number of flows to model per capture (capped by `pcap:limit`). |
| `--handshake` | `pcap:handshake` | The max characters kept from each side's first text payload. |
| `--tag` | | A tag to add to every flow. |
| `--host` | | The `it:host` that captured the traffic, set as each flow's `:capture:host`. |
| `--sandbox-file` | | The `file:bytes` a sandbox ran to make the capture, set as each flow's `:sandbox:file`. |
| `--no-tshark` | | Skip tshark, only model the packet level details. |
| `--no-files` | | Don't extract the files sent in flows into the Axon. |
| `--yield` | | Yield the `inet:flow` nodes instead of the inbound nodes. |

The command prints how many flows were modeled, and warns if the capture was truncated, had more
flows than `--limit`, had files over the extraction limits, or tshark failed. With `$lib.debug`
set it also prints the capture's full summary (format, link types, packet counts, why any packets
were skipped, the tshark version, and file counts).

For automations, `slib.pcap.lib` has `flows()`, which emits the `inet:flow` nodes and raises
`slib.pcap.Error` instead of warning:

```
$pcap = $lib.import(slib.pcap.lib)
for $flow in $pcap.flows($sha256, timeout=(60), opts=({"tag": "my.tag"})) { yield $flow }
```

### Permissions

| Permission | Description |
|---|---|
| `slib.pcap.user` | Analyze captures in the Axon and model their flows. |

Node edits run as the calling user, so they also need permission to create the nodes
(`inet:flow`, `file:bytes`, `inet:client`/`inet:server`, `inet:ipv4`/`inet:ipv6`, etc.).

## Modeling

Each flow is an `inet:flow`. Every property the form has that a capture can tell you is set:

| Property | Value | Needs |
|---|---|---|
| `:time` | When the flow's first packet was captured. | |
| `.seen` | The first and last packet times. | |
| `:duration` | Seconds between the first and last packets (rounded). | |
| `:src` / `:dst` | The client and server as `inet:client`/`inet:server` (TCP, UDP, ICMP, and GRE only). | |
| `:src:ipv4` / `:src:ipv6`, `:src:port`, `:src:proto` | The client's address, port, and protocol (`:dst:*` for the server). | |
| `:src:txcount` / `:src:txbytes` | Packets and bytes the client sent (`:dst:*` for the server). | |
| `:tot:txcount` / `:tot:txbytes` | Packets and bytes sent both ways. | |
| `:src:handshake` / `:dst:handshake` | The first payload each side sent, if it's text (binary payloads like TLS are skipped). | |
| `:ip:proto` | The IP protocol number. | |
| `:ip:tcp:flags` | Every TCP flag seen in the flow, OR'd together. | |
| `:src:ssl:cert` / `:dst:ssl:cert` | The leaf `crypto:x509:cert` each side sent in its TLS handshake. | tshark, TLS <= 1.2 |
| `:dst:ssh:key` | The server's SSH host key, a `crypto:key`. | tshark |
| `:src:rdp:hostname` / `:src:rdp:keyboard:layout` | The RDP client's computer name and keyboard layout. | tshark, standard RDP security |
| `:src:softnames` / `:dst:softnames` | Software each side identified itself as: HTTP `User-Agent`/`Server`, SSH banners, SIP, email clients (`User-Agent`/`X-Mailer`), gQUIC. | tshark |
| `:src:cpes` / `:dst:cpes` | CPEs for well known software in the softnames (OpenSSH, Dropbear, nginx, Apache, IIS, lighttpd, curl, Wget, Thunderbird) with a version. | tshark |
| `:src:txfiles` / `:dst:txfiles` | `file:attachment`s for the files each side sent. | tshark |
| `:capture:host` | The `it:host` given with `--host`. | |
| `:sandbox:file` | The `file:bytes` given with `--sandbox-file`. | |
| `:from` | A guid shared by every flow from the same capture. | |
| `:raw` | Everything the service found, including the TCP state (`closed`, `reset`, or `open`), flag names, ICMP types, per-direction payload bytes, TLS SNIs and JA3/JA3S/JA4 fingerprints, and HTTP hosts and requests. | |

Every flow is linked to its capture with `file:bytes -(refs)> inet:flow`, and to the service's
`meta:source` with `meta:source -(seen)> inet:flow`. Flow guids are derived from the capture's
SHA-256 and the flow's endpoints and start time, so analyzing the same capture again updates the
same nodes instead of creating duplicates.

### Application layer details

- **TLS certificates** are modeled like `slib.crtsh` models them: `crypto:x509:cert` nodes
  deconflicted by SHA-256 with their subject, issuer, serial, validity, signature, SANs, and
  identities, and `:file` pointing at the DER (uploaded to the Axon). The rest of the chain a
  side sent is linked with `inet:flow -(refs)> crypto:x509:cert`. TLS 1.3 encrypts certificates,
  so only TLS 1.2 and older handshakes have them.
- **TLS server names** (SNI) clients asked for are linked with `inet:flow -(refs)> inet:fqdn`.
- **SSH host keys** are `crypto:key` nodes deconflicted by the SHA-256 of the key's wire format
  blob (the hash OpenSSH fingerprints), with the blob as `:public`, its SHA-1 and MD5, and the
  key type as `:algorithm`. The service rebuilds the blob from tshark's fields for RSA, DSA,
  ECDSA, Ed25519, and Ed448 keys and checks it against the length on the wire.
- **RDP** client details are only in cleartext with standard RDP security. With TLS or
  CredSSP (NLA), the default on modern Windows, they're encrypted. The keyboard layout is its
  locale (ex. `en_us`), or its 8 digit KLID (ex. `00010409`, US Dvorak) when it isn't one.
- **Software names** are the whole value each side sent, lowercased and single spaced, ex.
  `openssh_9.6p1 ubuntu-3ubuntu13.20` and `nginx/1.24.0`.
- **Files** are extracted into the Axon and modeled as `file:bytes` (with `:size`, and `:mime`
  from the Content-Type when the node doesn't have one) and a `file:attachment` per flow side:
  - HTTP request and response bodies (de-chunked and decompressed by tshark). Multipart uploads
    are split into their files. `:name` is the file name at the end of a GET's URI, or a
    multipart part's file name.
  - FTP transfers (`RETR`, `STOR`, `STOU`, `APPE`, not directory listings), reassembled from the
    data connection, named by the command's path. Transfers with bytes missing from the capture
    are still extracted, and marked `complete: false` in `:raw`.
  - Emails tshark dissects (ex. sent over SMTP), as the whole message (`message/rfc822`, with its subject as
    `:text`), plus each attachment with its file name.
- **Not from a capture:** `:src:host`/`:dst:host`, `:src:proc`/`:dst:proc`, and
  `:src:exe`/`:dst:exe` describe the hosts and processes behind the traffic, which packets don't
  carry, and `:src:ssh:key` (a client's key is only sent after encryption starts). Set
  `:capture:host` and `:sandbox:file` with `--host` and `--sandbox-file`.

tshark only dissects protocols on their usual ports. Use `tshark:args` (ex.
`["-d", "tcp.port==8443,tls"]`) for anything else.

### How packets become flows

- Bytes are counted at the IP layer, from the IP header's length fields, so they're the bytes on
  the wire even when the capture's snaplen truncated the packet.
- The client (`:src`) is the side that sent the TCP SYN (or received the SYN-ACK), or the ICMP
  echo/timestamp/info/mask request. Otherwise it's the first sender, unless the capture joined a
  TCP connection mid-stream or the first UDP packet came from a privileged port (< 1024) to an
  unprivileged one; then the side using the privileged (or lower, for TCP) port is the server.
- A flow ends when it's idle for `--timeout` seconds, or when a TCP SYN reuses the ports of a
  connection that was reset or closed by both sides. The next packet starts a new flow.
- Non-IP packets (ex. ARP), unsupported link types, malformed packets, packets cut off before the
  end of their transport header, and IP fragments after the first (they have no ports) are
  skipped and counted in the summary.

## Testing

```bash
cd svcs/pcap
uv sync
uv run pytest tests
```

The flow tests build every capture they use (pcap, pcapng, gzip, each link type) in
`tests/pcapgen.py`. The tshark tests use real traffic recorded on loopback in `tests/data/`
(HTTP, TLS 1.2 with a client certificate, SSH, FTP, SMTP with an attachment, and RDP), see
`tests/data/capture.py` to re-record them. They're skipped when tshark isn't installed; CI
installs it. No test calls out to external services.
