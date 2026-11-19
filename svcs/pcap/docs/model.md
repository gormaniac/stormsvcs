# Data model

The service returns plain dicts, the Storm package turns them into nodes in
{src}`svcs/pcap/src/pcapsvc/pkgproto/storm/modules/slib.pcap.model.storm`. Node edits run as
the calling user (as root during `slib.pcap.sync`). The package targets Synapse 2.x
(`>=2.234.0,<3.0.0`), so it uses `it:app:snort:hit` and `.seen`, which 3.x renames.

## Overview

```text
meta:source=cae9b5f5...  -(seen)>  inet:flow, it:app:snort:hit, it:app:suricata:matched
file:bytes (capture)     -(refs)>  inet:flow, it:app:snort:hit, it:app:suricata:matched
inet:flow                -(refs)>  crypto:x509:cert, inet:fqdn, inet:dns:request
inet:flow :src/:dst            ->  inet:client / inet:server
inet:flow :src:ssl:cert / :dst:ssl:cert -> crypto:x509:cert
inet:flow :dst:ssh:key / :src:ssh:key   -> crypto:key
inet:flow :src:txfiles / :dst:txfiles   -> file:attachment -> file:bytes
inet:dns:answer :request       ->  inet:dns:request
it:app:snort:hit :rule, :flow  ->  it:app:snort:rule, inet:flow
it:app:suricata:matched :rule, :target -> it:app:suricata:rule, inet:flow
meta:ruleset             -(has)>   it:app:snort:rule, it:app:suricata:rule
it:app:*:rule            -(detects)> it:sec:cve
it:app:*:rule            -(refs)>  inet:url, hash:md5, hash:sha256
```

## Meta source

The service's add event creates `meta:source=cae9b5f5923a48b9a1a691f851a77429` with
`:name=slib.pcap` and `:type=slib.pcap` (`SVC_GUID` in {src}`svcs/pcap/src/pcapsvc/defs.py`).
Every flow (`flowNode`) and match (`hit`) gets a `<(seen)+` edge from it.

## inet:flow

One node per flow. The guid is computed by the service (`Flow.asdict`):

```python
s_common.guid(("slib.pcap.flow", FLOW_IDEN_VERSION, <capture sha256>, ipproto,
               client_ip, client_port, server_ip, server_port, [vlan ids], start_ns))
```

`FLOW_IDEN_VERSION` is `2`. Analyzing the same capture again (with the same `--timeout`, which
decides where flows split) updates the same nodes.

| Prop | Value | From |
| --- | --- | --- |
| `:time` | First packet time (ms). | `time` |
| `.seen` | `(time, last)`, first and last packet. | `time`, `last` |
| `:duration` | Seconds between first and last packet, rounded. | `duration` |
| `:from` | `$lib.guid(slib.pcap, pcap, <sha256>)`, shared by every flow of a capture. | |
| `:ip:proto` | IP protocol number. | `ipproto` |
| `:ip:tcp:flags` | Every TCP flag seen, OR'd (TCP only). | `tcp:flags` |
| `:tot:txcount` / `:tot:txbytes` | Packets / bytes both ways. | `pkts`, `bytes` |
| `:src` / `:dst` | `inet:client` / `inet:server`, ex. `tcp://10.0.0.1:50000`, `icmp://10.0.0.1`. Only for TCP, UDP, ICMP (and ICMPv6) and GRE. | `src.addr`, `dst.addr` |
| `:src:ipv4`/`:src:ipv6`, `:dst:ipv4`/`:dst:ipv6` | Endpoint addresses (by whether the IP has a `:`). | `src.ip`, `dst.ip` |
| `:src:port` / `:dst:port` | Ports (TCP, UDP, SCTP). | `src.port`, `dst.port` |
| `:src:proto` / `:dst:proto` | Protocol name: `tcp`, `udp`, `icmp` (also for ICMPv6), `igmp`, `gre`, `esp`, `ah`, `ospf`, `sctp`. | `proto` |
| `:src:txcount`/`:src:txbytes`, `:dst:*` | Packets and IP-layer bytes each side sent. | `src.pkts`, `src.bytes` |
| `:src:handshake` / `:dst:handshake` | The start (`--handshake` chars) of each side's first payload, if at least 90% of it is printable ASCII. | `src.handshake` |
| `:src:ssl:cert` / `:dst:ssl:cert` | The leaf `crypto:x509:cert` each side sent. | Suricata `tls.chain`/`client.chain`, tshark `tls.handshake.certificate` |
| `:dst:ssh:key` (and `:src:ssh:key` if seen) | The SSH host key, a `crypto:key`. | tshark |
| `:src:rdp:hostname` / `:src:rdp:keyboard:layout` | The RDP client's name (lowercased) and keyboard layout (locale like `en_us`, or 8 digit KLID hex like `00010409`). Only set on `:src`, `inet:flow` has no `:dst:rdp:*`. | Suricata `rdp` `connect_request`, tshark `rdp.client.name`/`rdp.keyboardLayout` |
| `:src:softnames` / `:dst:softnames` | Software each side identified as, lowercased and single spaced. | see below |
| `:src:cpes` / `:dst:cpes` | CPE 2.3 strings for well known software with a version. | see below |
| `:src:txfiles` / `:dst:txfiles` | `file:attachment`s of the files each side sent. | Suricata file store, tshark |
| `:capture:host` | `--host`. | |
| `:sandbox:file` | `--sandbox-file`. | |
| `:raw` | The whole flow dict the service returned (see [`:raw`](#raw)). | |
| `#<tag>` | `--tag`. | |

Props `inet:flow` has that a capture can't fill are never set: `:src:host`/`:dst:host`,
`:src:proc`/`:dst:proc`, `:src:exe`/`:dst:exe`.

### How packets become flows

- Packets are keyed by `(ipproto, vlans, sorted((src, sport), (dst, dport)))`. TCP, UDP and
  SCTP keys include ports, every other protocol is keyed by address only.
- The client (`:src`) is: for a TCP SYN, the sender (the receiver for a SYN-ACK); for ICMP, the
  sender of an echo, timestamp, info or mask request (the receiver for a reply). Otherwise the
  first sender, except a TCP flow joined mid-stream where the sender's port is lower and
  `< 1024`, or a UDP packet from a port `< 1024` to one `>= 1024`: then the sender is the server.
- A flow ends when it's idle longer than `--timeout`, or when a SYN without ACK arrives on a
  flow that was reset or FIN'd by both sides. The next packet starts a new flow.
- Bytes are counted from the IP header's length fields (`ip.len`, `40 + ip6.plen`), so they're
  bytes on the wire even when the snaplen cut the packet.
- Skipped and counted (`summary.skipped`): unsupported link types (`linktype`), malformed
  packets (`malformed`), non-IP packets (`nonip`), IP fragments after the first (`fragment`),
  packets cut off inside the TCP/UDP/SCTP header (`truncated`), and pcapng packets of an
  unknown interface (`badiface`).
- More than `--limit` flows: packets of the extra flows are counted as `dropped`.

### Software names and CPEs

Software names come from HTTP and HTTP/2 `User-Agent` (client) and `Server` (server), SSH
banners (`SSH-2.0-<software>`), SIP `User-Agent`/`Server`, SMB `native_os`/`native_lm`, email
`User-Agent`/`X-Mailer`, QUIC `ua` and gQUIC `uaid`. When two engines report the same software
differently (ex. Suricata's `openssh_9.6p1` and tshark's `openssh_9.6p1 ubuntu-3ubuntu13.20`),
only the longest name that starts with the other is kept.

CPEs are added for names that match (lowercased, from the start):

| Pattern | CPE |
| --- | --- |
| `openssh[_-]<x.y>(p<n>)?` | `cpe:2.3:a:openbsd:openssh:<x.y>:<pN or *>:...` |
| `dropbear[_-]<yyyy.n>` | `cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:<v>:...` |
| `nginx/<x.y.z>` | `cpe:2.3:a:f5:nginx:<v>:...` |
| `apache/<x.y.z>` | `cpe:2.3:a:apache:http_server:<v>:...` |
| `microsoft-iis/<x.y>` | `cpe:2.3:a:microsoft:internet_information_services:<v>:...` |
| `lighttpd/<x.y.z>` | `cpe:2.3:a:lighttpd:lighttpd:<v>:...` |
| `curl/<x.y.z>` | `cpe:2.3:a:haxx:curl:<v>:...` |
| `wget/<x.y[.z]>` | `cpe:2.3:a:gnu:wget:<v>:...` |
| `thunderbird/<x.y[.z]>` | `cpe:2.3:a:mozilla:thunderbird:<v>:...` |

### :raw

`:raw` is the flow dict exactly as the service returned it:

```json
{
  "iden": "<guid>", "index": 0, "version": 4, "ipproto": 6, "proto": "tcp", "vlans": [],
  "community_id": "1:...",
  "time": 1700000000000, "last": 1700000003000, "duration": 3, "durationms": 3000,
  "pkts": 9, "bytes": 1234,
  "tcp:flags": 27, "tcp:flagnames": ["fin", "syn", "psh", "ack"], "tcp:state": "closed",
  "tcp:syn": true, "icmp:types": null,
  "src": {
    "ip": "10.0.0.1", "port": 50000, "addr": "tcp://10.0.0.1:50000",
    "pkts": 5, "bytes": 600, "payload": 120, "handshake": "GET / HTTP/1.1 ...",
    "ssl:cert": null, "ssl:certs": [], "ssh:key": null,
    "rdp:hostname": null, "rdp:keyboard:layout": null,
    "softnames": ["curl/8.5.0"], "cpes": ["cpe:2.3:a:haxx:curl:8.5.0:*:*:*:*:*:*:*"],
    "txfiles": []
  },
  "dst": {"...": "the same keys"},
  "tls": {"sni": [], "ja3": [], "ja3s": [], "ja4": [], "versions": [], "alpn": []},
  "http": {"hosts": ["example.com"], "requests": [{"method": "GET", "uri": "/", "status": 200}]},
  "quic": null, "smb": null, "krb5": null, "sip": null, "smtp": null, "ftp": null,
  "anomalies": null, "app_proto": ["http"],
  "dns": null,
  "hits": []
}
```

- `tcp:state` is `closed` (both FINs), `reset`, or `open` (TCP only). `icmp:types` lists the ICMP
  types seen (ICMP only).
- `payload` is the transport payload bytes each side sent.
- `tls` and `http` are `null` when empty. `tls.versions` and `tls.alpn` only appear when
  Suricata logged them.
- `quic`: `{version, sni, ua, cyu}` per event. `smb`: `command`, `status`, `dialect`, `share`,
  `share_type`, `filename`, `disposition`, `client_dialects`, `server_guid`, `ntlmssp`,
  `native`. `krb5`: `msg_type`, `cname`, `realm`, `sname`, `encryption`, `weak_encryption`,
  `error_code`, `failed_request`, `ticket_encryption`, `ticket_weak_encryption`. `sip`:
  `method`, `uri`, `version`, `code`, `reason`. `smtp`: `helo`, `from`, `to`, `subject`. `ftp`:
  `command`, `data`, `codes`. `anomalies`: `type`, `event`, `layer`. Each list keeps at most 1000
  records.
- `app_proto`: the application protocols Suricata's `flow` events detected.
- `txfiles` entries: `{sha256, size, name, mime, text, proto, complete}`. `complete` is `false`
  when bytes were missing from the capture (FTP gaps, Suricata `gaps`/`TRUNCATED`).
- `hits`: see [Rule matches](#rule-matches).
- Certificates in `ssl:cert`/`ssl:certs` are the full parsed dicts (see below).

## Certificates: crypto:x509:cert

Every certificate a side sent (Suricata's base64 `chain`, or tshark's hex
`tls.handshake.certificate`) is parsed by `pcapsvc.x509.parseCert` and modeled like `slib.crtsh`
models certificates, deconflicted by SHA-256: `crypto:x509:cert=({"sha256": <sha256>})`.

| Prop | Value |
| --- | --- |
| `:sha256`, `:sha1`, `:md5` | Hashes of the DER. |
| `:file` | `sha256:<sha256>`, only when the DER was uploaded to the Axon (an Axon and file extraction on). |
| `:serial` | Even-length hex (two's complement if negative). |
| `:version` | X.509 version value. |
| `:subject`, `:issuer` | RFC 4514 strings. |
| `:validity:notbefore`, `:validity:notafter` | UTC times. |
| `:algo` | Signature algorithm OID. |
| `:signature` | Signature hex. |
| `:selfsigned` | Subject equals issuer, and the AKI is missing or equals the SKI. |
| `:rsa:key` | `(modulus hex, exponent)` for RSA keys. |
| `:ext:sans` | `(type, value)` for `dns`, `email`, `uri`, `ip`, `dirname`, `registeredid`, `othername`. |
| `:identities:fqdns`, `:emails`, `:ipv4s`, `:ipv6s`, `:urls` | From the SANs and subject CN. Wildcards become their base domain (`*.example.com` -> `example.com`). |

A certificate that can't be parsed still gets its hashes (and the parse `error` in `:raw`), and
no other props. The leaf is the flow side's `:src:ssl:cert`/`:dst:ssl:cert`, and every
certificate the side sent (the leaf included) is linked with `inet:flow -(refs)> crypto:x509:cert`.
TLS 1.3 encrypts certificates, so TLS 1.3 handshakes only have them with a key log.

## TLS and QUIC server names

Every SNI (TLS and QUIC, lowercased) is linked with `inet:flow -(refs)> inet:fqdn` (values that
aren't valid FQDNs are skipped).

## SSH host keys: crypto:key

`crypto:key=({"public:sha256": <sha256>})`, where the hash is of the key's wire format blob
(what OpenSSH fingerprints):

| Prop | Value |
| --- | --- |
| `:algorithm` | The key type, ex. `ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`. |
| `:public` | The blob, hex. |
| `:public:sha256`, `:public:sha1`, `:public:md5` | Hashes of the blob. |

The blob is rebuilt from tshark's fields for `ssh-rsa` (`e`, `n`), `ssh-dss` (`p`, `q`, `g`,
`y`), `ecdsa-sha2-*` (curve id, `q`), and `ssh-ed25519`/`ssh-ed448`, or from
`ssh.host_key.data` for other types, and discarded if its length doesn't match
`ssh.host_key.length`. Only tshark reports host keys.

## Files: file:bytes and file:attachment

Each extracted file is uploaded to the Axon (if it doesn't have it) and modeled as:

- `file:bytes=<sha256>` with `:size`, and `:mime` (the Content-Type without parameters) only when
  the node has none.
- `file:attachment=(slib.pcap, attachment, <flow guid>, <src|dst>, <sha256>, <name>)` with
  `:file`, `:name` and `:text`, added to the sending side's `:src:txfiles`/`:dst:txfiles`.

| Source | `:name` | Engine |
| --- | --- | --- |
| HTTP request and response bodies (de-chunked, decompressed) | The last URI path component, for requests and for responses to GETs. | Suricata, tshark |
| Multipart uploads | tshark splits them into each part with a file name, with that name and MIME type. | tshark (`http.file_data`), Suricata (named like a request body) |
| HTTP/2 bodies | Like HTTP/1.1. | Suricata, tshark (with a key log) |
| FTP `RETR`, `STOR`, `STOU`, `APPE` transfers | The command's path basename. | Suricata, tshark |
| SMB reads and writes | The file's basename. | Suricata |
| SMTP emails | The whole message, `mime=message/rfc822`, `:text` is the subject. Plus each named attachment. | tshark (`imf`); Suricata extracts attachments too (`decode-mime`) |

Files over `pcap:files:maxsize`, or past `pcap:files:limit`, are skipped and counted. Without an
Axon nothing is saved, the files are counted as `unsaved`.

## DNS

From Suricata's `dns` events (tshark doesn't extract DNS). Requests and responses are matched by
DNS ID, query name (lowercased) and type.

`inet:dns:request=(slib.pcap.dns, <flow guid>, <id>, <rrname>, <rrtype>)`:

| Prop | Value |
| --- | --- |
| `:query:name` | The query name. |
| `:query:type` | The type number, for `A` 1, `NS` 2, `CNAME` 5, `SOA` 6, `PTR` 12, `MX` 15, `TXT` 16, `AAAA` 28, `SRV` 33, `SVCB` 64, `HTTPS` 65, `ANY` 255. |
| `:query` | `(<flow :src>, <name>, <type>)`, when all three are known. |
| `:server` | The flow's `:dst`. |
| `:time` | The earliest event time. |
| `:reply:code` | The response's rcode: `NOERROR` 0, `FORMERR` 1, `SERVFAIL` 2, `NXDOMAIN` 3, `NOTIMP` 4, `REFUSED` 5. |
| `:sandbox:file` | `--sandbox-file`. |

linked with `inet:flow -(refs)> inet:dns:request`.

`inet:dns:answer=(slib.pcap.dns.answer, <request guid>, <rrname>, <rrtype>, <rdata>)` with
`:request` and `:ttl`, and one of:

| Answer type | Prop |
| --- | --- |
| `A` | `:a=(rrname, rdata)` |
| `AAAA` | `:aaaa=(rrname, rdata)` |
| `CNAME` | `:cname=(rrname, rdata)` |
| `NS` | `:ns=(rrname, rdata)` |
| `MX` | `:mx=(rrname, rdata)` |
| `TXT` | `:txt=(rrname, rdata)` |
| `PTR` | `:rev=(ipv4, rdata)` or `:rev6=(ipv6, rdata)`, from the `in-addr.arpa`/`ip6.arpa` name. Other PTR names aren't modeled. |
| `SOA` | `:soa` = `inet:dns:soa=(slib.pcap.dns.soa, rrname, mname, rname)` with `:fqdn`, `:ns` (mname), `:email` (the rname's first label `@` the rest). |

Other answer types (ex. `SRV`, `HTTPS`) have no `inet:dns:answer` prop and aren't modeled.

## Rule matches

Alerts are grouped by the service into one hit per engine, rule and flow (`pcapsvc.eve.hits`).
Only alerts whose `gid:sid` is in the engine's loaded rules index become hits. The rest are
counted in the summary's `events`: `builtin` (gid other than 1, the engines' decoder and
inspector rules) and `unknown` (gid 1, a rule the service no longer has), by
`<engine>:<gid>:<sid>`.

Each hit: `{engine, rule, key, rev, msg, action, count, time, last}`. The guid is
`$lib.guid(slib.pcap.hit, <engine>, <flow guid>, <rule guid>)`.

| Form | Props |
| --- | --- |
| `it:app:snort:hit` (Snort) | `:rule`, `:flow`, `:src`/`:dst` (the flow's `inet:client`/`inet:server` as `inet:addr`), `:src:ipv4`/`:src:ipv6`, `:dst:ipv4`/`:dst:ipv6`, `:src:port`, `:dst:port` |
| `it:app:suricata:matched` (Suricata) | `:rule`, `:target` (the `inet:flow`) |
| both | `:version` (the alert's `rev`, else the rule's, as `it:semver`, ex. rev 2 -> `2.0.0`), `:time` and `.seen` (first and last alert), `:sensor` (`--host`) |

Each hit has `meta:source -(seen)>` and `file:bytes (capture) -(refs)>` edges. The flow's
`:raw.hits` also lists them with their message, action and count.

## Rules

Rule nodes are made by `slib.pcap.rule.add` (from `ruleParse`) and `slib.pcap.sync` (from a
feed's rule records), both through `slib.pcap.model.rule`:

| Prop | Value |
| --- | --- |
| form | `it:app:snort:rule` (Snort 3 and 2.x) or `it:app:suricata:rule` |
| `:engine` | `3` (snort3) or `2` (snort2), Snort rules only |
| `:family` | The first `malware_family` metadata value, `_` replaced with spaces, Snort rules only |
| `:id` | The sid, or `gid:sid` when the gid isn't 1 |
| `:text` | The rule, a comment marker removed and multi-line rules joined |
| `:version` | The `rev`, as `it:semver` |
| `:name` | The `msg` |
| `:created` / `:updated` | ET style `created_at`/`updated_at` metadata (`YYYY_MM_DD`) |
| `:enabled` | Set on add, and when a rule joins or leaves a feed's ruleset |

Guids:

| Rule | Guid |
| --- | --- |
| A feed's rule | `guid(("slib.pcap.rule", <feed name>, gid, sid))` |
| A custom rule | `guid(("slib.pcap.custom", "snort" or "suricata", gid, sid))` |

References (`reference:<scheme>,<value>`) are cleaned by the service (`pcapsvc.rules.cleanRefs`)
and become edges. Other schemes, and values Synapse can't norm (warned about), are skipped:

| Scheme | Edge |
| --- | --- |
| `cve` (`YYYY-NNNN`, with or without `cve-`) | `-(detects)> it:sec:cve` |
| `url` (`http://` added if there's no scheme, malformed hosts skipped) | `-(refs)> inet:url` |
| `md5` (32 hex) | `-(refs)> hash:md5` |
| `sha256` (64 hex) | `-(refs)> hash:sha256` |

### Rulesets

Each feed's rules are in a `meta:ruleset=guid(("slib.pcap.ruleset", <feed name>))` with
`:name` (the feed's name), `:type=slib.pcap.feed`, `:desc`, and `:updated` (the last download),
linked with `meta:ruleset -(has)> <rule>`. See [Rules and feeds](rules.md#syncing) for when
rules join and leave.

```text
// Every capture with a match for a CVE.
it:sec:cve=cve-2021-44228 <(detects)- it:app:snort:rule <- it:app:snort:hit <(refs)- file:bytes
```
