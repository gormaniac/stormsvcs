# Rust PCAP helper (TLS certs and SSH host key) for a Python 3.11 Synapse service

Research date: 2026-10-31. Crate metadata comes from the crates.io API (`https://crates.io/api/v1/crates/<name>`), queried on that date. Source-code claims come from shallow clones of the GitHub repos taken the same day. "Inference" marks my reasoning, not something a source states.

## 1. rusticata crates: versions, maintenance, MSRV, licenses, fuzzing, capabilities

### Takeaway
pcap-parser, tls-parser, x509-parser and der-parser are mature and dual MIT/Apache. All four sit under the same maintainer, and Suricata itself depends on tls-parser, x509-parser and der-parser. tls-parser leaves TCP reassembly and TLS-record defragmentation to the caller. The **published** ssh-parser (0.5.0, 2021, LGPL) has no KEX-reply parsing. The **unreleased master** (0.6.0, Sept 2025, MIT/Apache) does, but only for classic DH, ECDH, curve25519, GEX and the old OQS kyber drafts. It returns `UnknownProtocol` for OpenSSH's defaults, `sntrup761x25519-sha512` and `mlkem768x25519-sha256`. None of these crates has its own OSS-Fuzz project.

### Cited Findings
**Versions and metadata (crates.io, latest release):**

| Crate | Version | Released | MSRV | License |
|---|---|---|---|---|
| pcap-parser | 0.17.0 | 2025-07-25 | 1.65 | MIT/Apache-2.0 |
| tls-parser | 0.12.2 | 2024-09-09 | 1.63 (master Cargo.toml says 1.70) | MIT/Apache-2.0 |
| ssh-parser | 0.5.0 | 2021-09-13 | not declared | **LGPL-2.1-or-later** |
| x509-parser | 0.18.1 | 2026-02-05 | 1.67.1 | MIT OR Apache-2.0 |
| der-parser | 10.0.0 | 2025-01-21 | 1.63 | MIT OR Apache-2.0 |

Sources: [pcap-parser](https://crates.io/crates/pcap-parser), [tls-parser](https://crates.io/crates/tls-parser), [ssh-parser](https://crates.io/crates/ssh-parser), [x509-parser](https://crates.io/crates/x509-parser), [der-parser](https://crates.io/crates/der-parser).

- Last commits on master as of 2026-10-31 — [pcap-parser](https://github.com/rusticata/pcap-parser), [tls-parser](https://github.com/rusticata/tls-parser), [ssh-parser](https://github.com/rusticata/ssh-parser), [x509-parser](https://github.com/rusticata/x509-parser):
  - pcap-parser: 2025-11-20 (CI action bump)
  - tls-parser: 2025-08-13 (`cargo update`)
  - ssh-parser: 2025-09-17 ("Add support for post-quantum hybrid key exchange")
  - x509-parser: 2026-08-06
  - Maintenance is active but slow. tls-parser has had no release in two years.
- ssh-parser master's Cargo.toml has version 0.6.0, `license = "MIT OR Apache-2.0"` and `rust-version = "1.63"`. This is not on crates.io; the latest published release is still 0.5.0 under LGPL. To use it today you would need a git dependency. — [ssh-parser repo](https://github.com/rusticata/ssh-parser/blob/master/Cargo.toml); [crates.io](https://crates.io/crates/ssh-parser)
- In the **published** ssh-parser 0.5.0 API, `parse_ssh_packet` maps message codes 30..=34 to an opaque `SshPacket::DiffieHellmanKEX(MaybeDiffieHellmanKEX(SshPacketUnparsed))`. You get the raw payload but no parsed K_S. It also has `parse_ssh_identification` (banner) and KEXINIT parsing, including `server_host_key_algs`. — [ssh.rs](https://github.com/rusticata/ssh-parser/blob/master/src/ssh.rs)
- ssh-parser master's `src/kex.rs` (875 lines) defines several things — [kex.rs](https://github.com/rusticata/ssh-parser/blob/master/src/kex.rs):
  - `SSH_MSG_KEXDH_REPLY = 31`, `SSH_MSG_KEXECDH_REPLY = 31`, `SSH_MSG_KEX_DH_GEX_REPLY = 33`, `SSH_MSG_KEX_HYBRID_REPLY = 31`.
  - `SshPacketDHKEXReply { pubkey_and_cert: &[u8], f, signature }`. `pubkey_and_cert` is the K_S blob.
  - `SshKEX::init(client_kexinit, server_kexinit)`, which negotiates the algorithm and returns a per-method state machine.
- `SshKEX::init` in master handles these algorithms — [kex.rs](https://github.com/rusticata/ssh-parser/blob/master/src/kex.rs):
  - `diffie-hellman-group{1,14,16,18}-*`
  - `curve25519-sha256[@libssh.org]`, `curve448-sha512`, `ecdh-sha2-nistp{256,384,521}`
  - `diffie-hellman-group-exchange-sha{1,256}`
  - three `ecdh-nistp*-kyber-*-d00@openquantumsafe.org` hybrids
  - Every other algorithm returns `Err(SshKEXError::UnknownProtocol)`. `sntrup761x25519-sha512[@openssh.com]` and `mlkem768x25519-sha256` are not in the list.
- tls-parser README: "It implements structures and parsing functions for records and messages, but need additional code to handle fragmentation" and "Some additional work is required if reading packets from the network, to support reassembly of TCP segments and reassembly of TLS records". It points to `rusticata/src/tls.rs` as the reference defragmenting parser. It also provides a TLS state machine (`tls_states.rs`). — [tls-parser README](https://github.com/rusticata/tls-parser)
- pcap-parser README: it supports pcap and pcapng "with multiple sections, interfaces, and endianness" "while using only safe code". It offers `create_reader` for format auto-detection and `LegacyPcapReader` for streaming. `InterfaceDescriptionBlock` exposes `if_tsresol`, `if_tsoffset` and `ts_resolution()`, so per-interface timestamp resolution is handled. — [pcap-parser](https://github.com/rusticata/pcap-parser)
- Fuzzing in-repo — [tls-parser/fuzz](https://github.com/rusticata/tls-parser/tree/master/fuzz), [x509-parser/fuzz](https://github.com/rusticata/x509-parser/tree/master/fuzz):
  - tls-parser has cargo-fuzz targets `parse_tls_plaintext`, `parse_tls_extension` and `parse_dtls_plaintext`.
  - x509-parser has `x509_parse`, `x509_with_mutator`, `crl` and `certreq`.
  - The pcap-parser and ssh-parser clones have no `fuzz/` directory, only `tests/`.
- OSS-Fuzz: a 2026-10-31 listing of `google/oss-fuzz/projects` has no rusticata, pcap-parser, tls-parser or x509-parser projects. Related projects that are present include suricata, wireshark, zeek, cryptography, scapy, openssh, libssh, nom, ntopng and pcapplusplus. — [OSS-Fuzz projects dir](https://github.com/google/oss-fuzz/tree/master/projects)
- Suricata's `rust/Cargo.toml.in` on main pins `tls-parser = "~0.11.0"`, `x509-parser = "~0.16.0"` and `der-parser = "~9.0.0"`, along with several other rusticata parsers. ssh-parser is not among them; Suricata's SSH parser is its own. — [Suricata Cargo.toml.in](https://github.com/OISF/suricata/blob/main/rust/Cargo.toml.in)

### Inferences
- Because Suricata is on OSS-Fuzz and links tls-parser, x509-parser and der-parser, those crates get indirect fuzz coverage. That coverage applies to the older versions Suricata pins (0.11 / 0.16 / 9.0), not necessarily to the latest releases.
- For K_S extraction, ssh-parser's value is small. You would need a git dependency on unreleased code, and you would still have to special-case the two algorithms that matter most for modern OpenSSH. The cheaper route is to use `parse_ssh_packet` only for binary packet framing, then read the first `string` of the code-31 payload yourself. That works for every non-GEX method (see section 6).
- The license change from LGPL to MIT/Apache matters only if you vendor the published 0.5.0. Using master avoids the LGPL question.

### Gaps
- I could not confirm that ssh-parser 0.6.0 has a planned release date. The GitHub API was blocked in this session, so I could not check issues or PRs.
- I did not run the fuzz targets or check how recently the fuzz corpora were updated.

## 2. TCP reassembly in Rust, and how much you actually need

### Takeaway
No dominant, well-maintained general TCP reassembly crate exists. The candidates are tiny or single-author. huginn-net-tls has ClientHello-only reassembly built in. The practical choice is a custom "first N KB per direction" buffer of roughly 150 to 300 lines on top of etherparse or pdu. Suricata's stream engine is C and is not reusable.

### Cited Findings
- crates.io search results for "tcp reassembly" (2026-10-31) — [crates.io search](https://crates.io/search?q=tcp%20reassembly), [protolens](https://github.com/chunhuitrue/protolens), [tcpstreams](https://github.com/bsamseth/tcpstreams):

| Crate | Version | Updated | Downloads | License / notes |
|---|---|---|---|---|
| `protolens` | 0.2.3 | 2025-06-19 | ~2.7k | MIT/Apache; TCP reassembly plus app-layer parsing |
| `tcpstreams` | 0.1.3 | 2026-08-07 | 118 | Unlicense; "TCP stream reassembly from PCAP/PCAPNG files" |
| `parse-tcp` | 0.1.0 | 2024-06-13 | ~1.3k | none noted |
| `packet-dissector-reassembly` | 0.6.1 | 2026-10-01 | ~2.8k | offset-based buffer with gap tracking |

- L2-L4 parsing — [etherparse](https://crates.io/crates/etherparse), [pdu](https://crates.io/crates/pdu), [pktparse](https://crates.io/crates/pktparse):
  - `etherparse` 0.21.0 (2026-07-21): MSRV 1.83, MIT OR Apache-2.0, about 12.4M downloads.
  - `pdu` 1.5.1 (2026-08-04): Apache-2.0, about 355k downloads.
  - `pktparse` 0.7.1 (2021-12-26): LGPL-3.0, effectively unmaintained.
- huginn-net-tls source says flows are hashed to one worker "for proper TCP reassembly and ClientHello parsing". `client_hello_reader.rs` parses the ClientHello "from reassembled buffer". This reassembly is scoped to the ClientHello, not general. — [huginn-net-tls](https://github.com/biandratti/huginn-net/tree/master/huginn-net-tls)

### Inferences
- What the extraction needs:
  - The TLS ClientHello is usually one to two segments. ServerHello, Certificate and ServerHelloDone are often 3 to 10 KB in the server-to-client direction. A large chain can reach about 16 KB or more.
  - SSH needs the banner and KEXINIT in each direction, plus the server's KEX reply. With mlkem768x25519 or sntrup761x25519, the reply carries roughly 1.1 KB of KEM ciphertext plus K_S and the signature, so it typically fits in the first 4 to 8 KB server-to-client.
  - A 32 to 64 KB per-direction cap covers almost all cases.
- Simplified reassembly is enough:
  - Seed the ISN from the SYN, or from the first-seen sequence number if the SYN is missing.
  - Do in-order append, a small out-of-order hold queue and retransmission dedup (first-wins), and stop at the cap.
  - Record which frame numbers contributed to each byte range, so you can map a parsed message back to the frame that completes it. That mapping is what gives per-frame attribution, which Suricata lacks.
- Overlap policy: segments that overlap with differing content are an evasion vector. For extracting forensic metadata, first-wins plus a "conflict" flag in the output is adequate.

### Gaps
- I did not evaluate the code quality or fuzzing of `protolens`, `tcpstreams` or `packet-dissector-reassembly`. Their download counts are too low to treat them as vetted.

## 3. Other useful crates: JA3/JA4, Community ID, huginn-net, etherparse/pdu

### Takeaway
huginn-net (2.2.1, 2026-10-17) is a passive fingerprinting suite: p0f-style TCP, JA4 TLS and HTTP/1/2. It is not a general extractor, and Suricata already emits JA3/JA4 and Community ID. A Rust helper does not need these crates unless you want fingerprints Suricata lacks, such as JA4S, JA4X or p0f OS guesses.

### Cited Findings
- `huginn-net` 2.2.1 (2026-10-17): MSRV 1.85, MIT OR Apache-2.0, about 4.9k downloads — [crates.io](https://crates.io/crates/huginn-net), [README](https://github.com/biandratti/huginn-net)
  - The README calls it "Huginn Net fingerprints TCP, HTTP, and TLS traffic passively" using "p0f v3 for TCP, FoxIO's JA4 for TLS, and the Akamai HTTP/2 fingerprinting spec".
  - Sub-crates: `huginn-net-tcp` (SYN/SYN+ACK fingerprints, MTU, uptime), `huginn-net-http`, `huginn-net-tls` ("JA4 and stable JA4_s1 / JA4_s1r signatures") and `huginn-net-db`.
  - PCAP analysis runs in "sequential mode".
  - `huginn-net-tls` depends on `tls-parser`, `pcap-file`, `pnet` and `sha2`. Note that it uses `pcap-file`, not pcap-parser.
- `ja4` 0.1.0 (2026-06-23, Codeberg, MSRV 1.87, about 772 downloads): very new and unproven. `ja3` 0.5.1 (2020, BSD-3-Clause): stale. — [ja4](https://crates.io/crates/ja4), [ja3](https://crates.io/crates/ja3)
- `community-id` 0.2.4 (2025-09-17): MIT OR Apache-2.0, about 8.9M downloads. — [crates.io](https://crates.io/crates/community-id)
- Suricata EVE `tls` events — [Suricata EVE format](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html):
  - Default fields: `subject`, `issuer`, `session_resumed`.
  - Extended fields: `serial`, `fingerprint`, `sni`, `version`, `notbefore`, `notafter`, `ja3`/`ja3s` (with `ja3-fingerprints: yes`), `ja4` (with `ja4-fingerprints: yes`), `client_alpns`, `server_alpns`.
  - Custom-only fields: `certificate` and `chain` (base64), `client_handshake`, `server_handshake`.
- Suricata EVE `ssh` events have only `proto_version`, `software_version` and `hassh` (`hash` and `string`, with `hassh: yes`), per client and server. There is **no host-key field**. — [Suricata EVE format](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html)

### Inferences
- Community ID is a SHA1 over the 5-tuple, about 40 lines in either language, so a dependency isn't needed. Suricata already emits it per flow.
- etherparse (`SlicedPacket::from_ethernet` / `from_ip`, with VLAN, IPv4/6 and TCP/UDP slicing) is the most widely used and actively maintained L2-L4 slicer. Use it over pdu or pktparse.

### Gaps
- I did not verify whether huginn-net exposes JA4S or JA4X, or handles TLS ServerHello and certificates at all. The README mentions only client-side JA4.

## 4. Packaging: PyO3/maturin wheel vs static CLI for a Synapse Cell (asyncio)

### Takeaway
Both options are well supported. A **subprocess CLI** (static musl binary emitting JSON lines) is the better fit here:
- It gives crash and DoS isolation (kill on timeout, rlimits, seccomp, separate user).
- It needs no ABI or wheel matrix.
- It slots into the existing pattern of shelling out to tshark and Suricata via `asyncio.create_subprocess_exec`.

An in-process PyO3 module is faster to call. Its weaknesses are that a panic surfaces as `PanicException` (a `BaseException`), and that a hang or memory blow-up takes the Cell down with it.

### Cited Findings
- `pyo3` 0.30.1 (2026-10-14, MSRV 1.85) and `maturin` 1.16.0 (2026-10-29, MSRV 1.89). — [pyo3](https://crates.io/crates/pyo3), [maturin](https://crates.io/crates/maturin)
- From the PyO3 guide — [PyO3 building & distribution](https://pyo3.rs/latest/building-and-distribution.html):
  - abi3 restricts PyO3 to the stable API. `abi3-py311` sets the lowest Python version the wheel supports.
  - Wheels are tagged like `cp39-abi3-manylinux...`.
  - Free-threaded CPython can't load abi3 wheels; it needs `abi3t`, which maturin supports from 1.14.
  - Maturin 1.9.4 and later sets `PYO3_BUILD_EXTENSION_MODULE` automatically.
- From the maturin docs — [maturin distribution](https://www.maturin.rs/distribution.html):
  - Linux wheels must comply with manylinux/musllinux, built in a manylinux Docker image or with `--zig`.
  - Rust requires at least manylinux2014 (glibc 2.17).
  - `maturin generate-ci github` generates a GitHub Actions workflow, and `maturin-action` handles manylinux and cross-compilation.
- PyO3's `PanicException` docstring: "The exception raised when Rust code called from Python panics. Like SystemExit, this exception is derived from BaseException so that it will typically propagate all the way through the stack and cause the Python interpreter to exit." — [pyo3 src/panic.rs](https://github.com/PyO3/pyo3/blob/main/src/panic.rs)

### Inferences
- **uv:** a maturin project is a normal PEP 517 build backend (`[build-system] requires = ["maturin>=1.16,<2"]`). `uv build` and `uv sync` can build it as a path or workspace dependency, but every CI job and the Docker image then needs a Rust toolchain unless prebuilt wheels are published to an index. The repo's rule of editing `uv.lock` by hand gets harder with a local native dependency. (Not verified against uv docs in this session.)
- **CLI pattern:**
  - Build with `cargo build --release --target x86_64-unknown-linux-musl`, producing one static binary of roughly 2 to 5 MB.
  - Copy it into the service image the same way tshark is installed.
  - Invoke it as `pcapx --max-bytes 65536 --max-flows N file.pcap`, writing JSON lines to stdout.
  - In Python: `asyncio.create_subprocess_exec` with a wall-clock timeout, `resource.setrlimit` (AS/CPU) via `preexec_fn` or a `prlimit` wrapper, and optionally bubblewrap/nsjail or seccomp.
  - This matches how Suricata and tshark are already isolated, and no wheel/ABI pipeline is needed.
- **Security argument:**
  - Safe Rust removes memory-corruption RCE classes in either deployment.
  - The remaining risks are panics (bugs on malformed input), unbounded allocation, and algorithmic or quadratic blow-ups such as many flows or out-of-order queues. These are availability problems.
  - In-process, all of them hit the Cell's event loop (PyO3 calls hold the GIL unless the code releases it with `py.allow_threads` / `detach`) and its memory.
  - In a subprocess, they become a killed child and an error result.
  - `panic = "abort"` makes things worse in-process but is fine in a CLI.
- **PyO3 advantage:** zero-copy return of structured data and no JSON round trip. For a one-off batch pass over a PCAP file, this is negligible next to file I/O.

### Gaps
- I did not fetch uv's documentation on building maturin projects, or the maturin-action README version.

## 5. Effort estimate for the helper

### Takeaway
Roughly 1,200 to 2,000 lines of Rust, plus tests and fuzz targets, using pcap-parser + etherparse + tls-parser + a hand-written SSH framer. Expect about 2 to 4 engineer-weeks to reach production quality, including fuzzing and tshark frame-number parity tests (inference).

### Cited Findings
- Reference points:
  - ssh-parser's entire source is 1,477 lines (`kex.rs` 875, `ssh.rs` 394, `mpint.rs` 76, `serialize.rs` 110, `lib.rs` 22). — [ssh-parser src](https://github.com/rusticata/ssh-parser/tree/master/src)
  - tls-parser explicitly needs caller-side TCP and TLS-record defragmentation (see section 1). — [tls-parser README](https://github.com/rusticata/tls-parser)

### Inferences
Component estimate (lines of Rust):
| Component | LoC | Notes |
|---|---|---|
| pcap/pcapng reader loop, frame counter, per-interface linktype and timestamps | 120-200 | pcap-parser `create_reader`; frame number = 1-based count of packet blocks (EPB/SPB/OPB/legacy records), which should match tshark `frame.number` |
| L2-L4 decode (Ethernet/VLAN/SLL/raw IP, IPv4/IPv6, TCP), 5-tuple and flow key | 100-200 | etherparse; IP fragment reassembly skipped (log only) |
| Bounded TCP reassembly per direction, with frame-range map | 200-350 | ISN, OOO hold queue, cap N KB, first-wins overlap, max flows |
| TLS: record defrag, handshake defrag across records, ClientHello/ServerHello/Certificate (<=1.2) via tls-parser; SNI, ALPN, versions, ciphers, cert DER list | 250-400 | certificates passed through as DER/base64; x509 parsing left to Python `cryptography` |
| SSH: banner, binary packet framing (pre-NEWKEYS, unencrypted), KEXINIT name-lists, KEX reply K_S extraction for codes 31 (DH/ECDH/hybrid) and 33 (GEX) | 150-250 | read `string K_S` directly; key type = first string inside K_S |
| JSON lines output (serde), CLI args, limits, error records | 100-150 | |
| Tests (fixtures, tshark parity) and cargo-fuzz targets | 300-600 | |
- Verify frame-number parity against tshark on multi-interface pcapng and on files with non-packet blocks such as DSB, NRB, ISB and custom blocks.

### Gaps
- None of these line counts come from an existing project. They are estimates.

## 6. Pure-Python alternative and recommendation

### Takeaway
For the two stated gaps (SSH server host key, and per-frame certificates), **pure Python is enough**:
- K_S is the first length-prefixed `string` of the server's message-31 payload, for every DH, ECDH, sntrup761x25519 and mlkem768x25519 method. For GEX it is in message 33.
- dpkt 1.9.8 already ships TLS record, handshake, ClientHello, ServerHello and Certificate classes.
- `cryptography` (48.x) parses both X.509 and SSH public keys, and computes SSH fingerprints in vetted code.

Python's risk is DoS (exceptions, slow paths, memory), not memory corruption. You can bound it with the same reassembly caps, or by running the parser in a worker subprocess. My recommendation: **skip the Rust helper for now**. Revisit only if profiling shows Python reassembly is too slow on large PCAPs, or if you want a sandboxed CLI anyway.

### Cited Findings
- OpenSSH KEX defaults — [OpenSSH release notes](https://www.openssh.com/releasenotes.html):
  - 9.0 (2022-04-08): "use the hybrid Streamlined NTRU Prime + x25519 key exchange method by default ("sntrup761x25519-sha512@openssh.com")".
  - 10.0 (2025-04-09): "the hybrid post-quantum algorithm mlkem768x25519-sha256 is now used by default for key agreement".
  - 9.9 introduced mlkem768x25519-sha256.
  - The current release is 10.6 (2026-10-06).
- ML-KEM hybrid draft, draft-ietf-sshm-mlkem-hybrid-kex-10 (updated 2026-08-31, not yet an RFC): `byte SSH_MSG_KEX_HYBRID_REPLY; string K_S, server's public host key; string S_REPLY; ...` with `#define SSH_MSG_KEX_HYBRID_REPLY 31`. — [IETF draft](https://www.ietf.org/archive/id/draft-ietf-sshm-mlkem-hybrid-kex-10.txt)
- sntrup761x25519 draft, draft-ietf-sshm-ntruprime-ssh-06 (2026-04-10, not yet an RFC): "The protocol flow and the SSH_MSG_KEX_ECDH_INIT and SSH_MSG_KEX_ECDH_REPLY messages are identical" to RFC 5656/8731 ECDH, with Q_S holding the server's KEM ciphertext concatenated with its X25519 key. — [IETF draft](https://www.ietf.org/archive/id/draft-ietf-sshm-ntruprime-ssh-06.txt)
- ssh-parser master confirms code 31 is shared by KEXDH_REPLY, KEXECDH_REPLY and KEX_HYBRID_REPLY, but means `SSH_MSG_KEX_DH_GEX_GROUP` (p, g) under group exchange, where the reply with K_S is code 33. — [kex.rs](https://github.com/rusticata/ssh-parser/blob/master/src/kex.rs). RFC 4253 section 8 (DH reply: `string K_S, mpint f, string signature`) and RFC 5656 / RFC 8731 (ECDH reply: `string K_S, string Q_S, string signature`) are cited by those sources but were not fetched here.
- dpkt 1.9.8 `dpkt/ssl.py` (from the local uv cache):
  - Classes: `TLSRecord`, `TLSHandshake`, `TLSClientHello`, `TLSServerHello`, `TLSCertificate`, `TLSUnknownHandshake`, plus `tls_multi_factory(buf)`.
  - It raises `dpkt.NeedData` on truncated input and `SSL3Exception` on bad versions or types.
  - Source: dpkt package source, also at [dpkt/ssl.py](https://github.com/kbandla/dpkt/blob/master/dpkt/ssl.py).
- cryptography 48.0.1 `hazmat/primitives/serialization/ssh.py` (from the local uv cache):
  - Provides `load_ssh_public_key`, `load_ssh_public_identity` (keys or certificates) and `ssh_key_fingerprint(key, MD5|SHA256)`.
  - It has internal wire-format helpers (`_get_sshstr`, `_get_mpint`).
  - Source: [cryptography ssh.py](https://github.com/pyca/cryptography/blob/main/src/cryptography/hazmat/primitives/serialization/ssh.py).

### Inferences
- **SSH K_S in Python** (about 80 to 150 lines including framing):
  1. Collect the server-to-client stream up to the cap. Skip any pre-banner lines, then read the `SSH-2.0-...` line.
  2. Loop over binary packets: `uint32 packet_length`, `byte padding_length`, payload, padding (no MAC before NEWKEYS). Bound `packet_length` to at most 35000 per RFC 4253's minimum supported size, or to the cap.
  3. Track both KEXINITs (code 20) to learn the negotiated KEX, which tells you whether the reply is code 31 or 33.
  4. Read `string K_S` from the reply. Then `key_type = first string of K_S`, and SHA256 fingerprint = `base64(sha256(K_S))`, which is what OpenSSH prints.
  5. Optionally build `key_type + " " + base64(K_S)` and pass it to `load_ssh_public_key` for typed key data. Wrap this in try/except, because post-quantum or unknown host-key types (for example `ssh-ed25519-cert-v01@openssh.com` certificates, or `sk-*`) may need `load_ssh_public_identity`.
  6. Fallback heuristic when the KEXINITs are missing: if code 31's first string parses as a valid SSH key blob, treat it as K_S. Otherwise, if a code 33 exists, use that.
- **TLS certificates per frame in Python:** reassemble the server-to-client direction (capped), keeping a byte-offset-to-frame map. Use `tls_multi_factory`, or a hand-written 5-byte record header loop. Handshake messages span records, so concatenate record payloads of content type 22 before parsing handshake headers, because dpkt doesn't do this for you. Map the Certificate message's end offset to its frame number, then hand the DER to `cryptography.x509.load_der_x509_certificate`. This matches tshark's "reassembled in frame N" semantics.
- **Risk profile:**
  - Pure Python cannot corrupt memory. `cryptography`'s X.509 and ASN.1 parsing is Rust and is fuzzed on OSS-Fuzz (it is in the project list).
  - The realistic threats are uncaught exceptions (handle per flow), unbounded buffering (cap per direction and in total), many-flow memory exhaustion (cap the flow count), and slowness. The same threats exist in Rust.
  - Running the Python extractor in a `ProcessPoolExecutor` or subprocess with rlimits gives isolation equivalent to the Rust CLI.
- **Where a Rust helper would earn its keep:**
  - CPU-bound passes over multi-GB PCAPs, where per-packet Python and dpkt overhead dominates.
  - A desire to drop dpkt flow building entirely and have one native pass emit flows, frames, TLS and SSH together.
  - Sharing a single hardened, fuzzable binary across services.
  - None of these is required to close the SSH host key or per-frame certificate gaps.
- **tshark already covers part of this:** the planned TLS key-log decryption pass runs tshark anyway. tshark exposes `ssh.host_key.*` fields (e.g. `ssh.host_key.type`) and `tls.handshake.certificate` per frame. If that pass already runs over every flow, extracting these fields from it may be the cheapest option of all. I did not verify this in this session; check the field names with `tshark -G fields | grep -E 'ssh.host_key|tls.handshake.certificate'`.

### Gaps
- I did not fetch RFC 4253, RFC 5656 or RFC 8731 directly. The reply layouts are taken from the drafts and ssh-parser source, which cite them.
- I did not benchmark dpkt-based reassembly against Rust on a large PCAP.
- I did not verify tshark's `ssh.host_key.*` field names or its frame attribution for the reassembled KEX reply.
- I did not check uv's documentation on maturin builds, so the uv integration notes in section 4 are inference.
