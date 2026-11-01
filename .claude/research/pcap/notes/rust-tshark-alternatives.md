# Rust alternatives to tshark (first pass)

Research from 2026-10-31, done before the unified plan. It asked whether a memory-safe (Rust) tool could
replace tshark for dissecting untrusted captures in `slib.pcap`. The deeper follow-ups are in
`rust-helper.md`, `suricata-analysis-engine.md`, and `sandboxing.md`, and the plan that came out of all of
it is `../unified-pcap-snort-suricata-plan.md`. This file records the first pass as it was reported,
claims and sources included; where later notes corrected it, that's marked.

## Bottom line

There is no Rust tshark replacement for this field list. No open-source Rust tool combines TLS key-log
decryption with broad application-layer dissection. The biggest memory-safety win is Suricata 8 offline
for most fields, with tshark kept only for decryption and the fields Suricata lacks, sandboxed.

## Candidates

| Project | Covers (vs. our fields) | TCP reassembly | Key-log decryption | Maturity | From Python | License |
|---|---|---|---|---|---|---|
| rshark / rusty-shark | Ethernet and IP only | No | No | Abandoned, one 0.0.1 release in 2015 | No | MIT/Apache |
| rusticata tls-parser | TLS records, handshakes, extensions, SNI (JA3 computed by you) | No ("extra code needed") | No (FAQ: "not implemented") | 121 stars, 0.12.x, fuzzed | Library only, needs PyO3 or a CLI | MIT/Apache |
| x509-parser / der-parser | Certificate DER | n/a | n/a | Mature, used by Suricata | Library | MIT/Apache |
| ssh-parser | Banner, KEXINIT, `DiffieHellmanReply.pubkey_and_cert` | No | n/a | 0.5.0, low activity | Library | MIT/Apache (see correction 1) |
| pcap-parser | pcap and pcapng | n/a | n/a | Mature | Library | MIT/Apache |
| rusticata pcap-analyzer | Plugin framework, 5-tuple flows, defrag; no protocol plugins listed | Undocumented | No | ~106 stars, low activity | CLI with log output | MIT/Apache |
| huginn-net | p0f-style TCP, HTTP/1 and HTTP/2, JA4 (no JA3) | Undocumented | No | ~220 stars, v2.x | No Python bindings | MIT/Apache |
| etherparse / pnet / pdu | L2 to L4 only | No | No | Mature | No | MIT/Apache |
| pcapsql-core | Claims TLS 1.2/1.3 key-log decryption, HTTP/1.1, HTTP/2 | Unclear | Claimed | Brand new, v0.3.1, ~200 downloads | No | MIT |
| Zeek / Spicy | Many protocols | Yes | Experimental, TLS 1.2 with one cipher only | Mature | Logs | BSD |

Zeek is C++ and Spicy generates C++, so neither is a memory-safety gain. Python's `cryptography`
already parses X.509 in Rust, so parsing certificate DER with it is memory safe today.

Sources: [tls-parser](https://github.com/rusticata/tls-parser),
[ssh-parser DhReply](https://docs.rs/ssh-parser/latest/ssh_parser/struct.SshPacketDhReply.html),
[pcap-analyzer](https://github.com/rusticata/pcap-analyzer),
[huginn-net](https://github.com/biandratti/huginn-net),
[rusty-shark](https://github.com/musec/rusty-shark),
[pcapsql-core](https://crates.io/api/v1/crates/pcapsql-core),
[Zeek TLS decryption](https://docs.zeek.org/en/lts/frameworks/tls-decryption.html).

## Suricata (8.0)

- Rust parsers: SSH, RDP, SIP (TCP and UDP), x509, JA4, MIME, and HTTP/1 (libhtp is a Rust crate as of
  8.0). C: the TLS parser (`app-layer-ssl.c`), SMTP's state machine, decoders, defrag, stream reassembly,
  and detection. See correction 2 for FTP.
  ([8.0.0 release](https://forum.suricata.io/t/suricata-8-0-0-released/5854),
  [rust/src](https://github.com/OISF/suricata/tree/main/rust/src))
- Offline: `suricata -r file.pcap` writes EVE JSON with the 5-tuple, timestamp, `flow_id`, and
  `pcap_cnt`.
- Coverage against our fields ([EVE format](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html)):
  TLS SNI, subject, issuer, serial, JA3/JA3S, opt-in JA4, and certificates/chain via custom fields;
  SSH banners and HASSH but **no host key**; RDP client name and keyboard layout; HTTP UA, host, URL
  (Server via custom headers) and bodies via file-store; FTP data events and files; SMTP headers and
  attachments; SIP request and response lines.
- **No TLS decryption.** [Redmine #7796](https://redmine.openinfosecfoundation.org/issues/7796) is open
  and untargeted.
- License: GPLv2, fine to run as a subprocess.

## Advisory history (rough, as reported)

- Wireshark ([index](https://www.wireshark.org/security/)): 10 in 2022, 29 in 2023, 15 in 2024, 8 in
  2025, and 110 so far in 2026. The 2026 ones include TLS (one "possible code execution"), SSH, RDP,
  HTTP/HTTP3, pcapng, X.509IF, zlib, and LZ77.
- Suricata ([advisories](https://github.com/OISF/suricata/security/advisories)): about 151 since February
  2024, mostly in 2026. They're mostly DoS, quadratic, or bypass bugs, but some memory corruption happens
  (a detect use-after-free, a datasets stack overflow, a TLS null dereference). No advisory titles for
  the Rust parsers described memory corruption.
- Both projects jumped in 2026, so year-over-year counts are noisy.

## Options as first framed

- **A. Keep tshark:** full coverage, but the largest C attack surface. Harden it (no network, read-only,
  `--disable-protocol`).
- **B. Replace it with Suricata 8:** loses the SSH host key, TLS decryption, exact frame numbers, maybe
  raw SMTP, and SIP UA/Server. TLS, SMTP, and stream code are still C.
- **C. Pure Rust (custom binary or PyO3):** means writing TCP reassembly, HTTP, FTP, SMTP, RDP, SIP, and
  decryption ourselves. A big build.
- **D. Hybrid (recommended at the time):** Suricata 8 for most fields, a small Rust helper for the SSH
  host key and per-frame certificates, tshark only with a key log, and `cryptography` for DER.

## Corrections from the follow-up research

1. ssh-parser 0.5.0 (the released version) is LGPL-2.1+ and passes KEX messages through as raw bytes.
   The unreleased 0.6.0 is MIT/Apache and parses KEX replies, but not OpenSSH's default
   `sntrup761x25519-sha512` or `mlkem768x25519-sha256` (see `rust-helper.md`).
2. FTP's main parser in Suricata 8.0 is still C (`app-layer-ftp.c`) with Rust helpers, and EVE doesn't
   log SIP User-Agent/Server (see `suricata-analysis-engine.md`).
3. The plan drops the Rust helper: pure Python (dpkt and `cryptography`) or tshark closes both gaps.
