# pcap

A Synapse Advanced Power-Up (Storm Service) that reads packet captures from an Axon and models
every network flow in them as an `inet:flow` node.

The service downloads a capture by SHA-256 from its Axon, decodes every packet's IP and transport
headers, and aggregates the packets into bidirectional flows. Storm then models each flow with its
endpoints, packet and byte counts per direction, TCP flags, duration, and the first text payload
each side sent (ex. an HTTP request line, SMTP banner, or SSH version string).

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
service can read the captures Storm users have uploaded. Captures are spooled to a temp file under
the service's storage directory (not held in memory) and deleted once they're analyzed.

### Configuration

| Option | Default | Description |
|---|---|---|
| `axon:url` | | The Telepath URL of the Axon captures are read from. Required. |
| `pcap:timeout` | `300` | The default seconds a flow can be idle before the next packet between the same endpoints starts a new flow, `0` to never time out. |
| `pcap:limit` | `100000` | The max number of flows for one capture. Packets for any more flows are dropped (and counted). |
| `pcap:handshake` | `1024` | The default max characters kept from each side's first text payload, `0` for none. |
| `pcap:maxsize` | `1073741824` | The max capture size in bytes (1 GiB), `0` for no limit. |

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
| `--yield` | | Yield the `inet:flow` nodes instead of the inbound nodes. |

The command prints how many flows were modeled, and warns if the capture was truncated or had more
flows than `--limit`. With `$lib.debug` set it also prints the capture's full summary (format,
link types, packet counts, and why any packets were skipped).

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

Each flow is an `inet:flow` with:

| Property | Value |
|---|---|
| `:time` | When the flow's first packet was captured. |
| `.seen` | The first and last packet times. |
| `:duration` | Seconds between the first and last packets (rounded). |
| `:src` / `:dst` | The client and server as `inet:client`/`inet:server` (TCP, UDP, ICMP, and GRE only). |
| `:src:ipv4` / `:src:ipv6`, `:src:port`, `:src:proto` | The client's address, port, and protocol (`:dst:*` for the server). |
| `:src:txcount` / `:src:txbytes` | Packets and bytes the client sent (`:dst:*` for the server). |
| `:tot:txcount` / `:tot:txbytes` | Packets and bytes sent both ways. |
| `:src:handshake` / `:dst:handshake` | The first payload each side sent, if it's text (binary payloads like TLS are skipped). |
| `:ip:proto` | The IP protocol number. |
| `:ip:tcp:flags` | Every TCP flag seen in the flow, OR'd together. |
| `:capture:host` | The `it:host` given with `--host`. |
| `:from` | A guid shared by every flow from the same capture. |
| `:raw` | Everything the service found, including the TCP state (`closed`, `reset`, or `open`), flag names, ICMP types, and per-direction payload bytes. |

Every flow is linked to its capture with `file:bytes -(refs)> inet:flow`, and to the service's
`meta:source` with `meta:source -(seen)> inet:flow`. Flow guids are derived from the capture's
SHA-256 and the flow's endpoints and start time, so analyzing the same capture again updates the
same nodes instead of creating duplicates.

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

Tests build every capture they use (pcap, pcapng, gzip, each link type) in
`tests/pcapgen.py`, so there are no binary fixtures and no external calls.
