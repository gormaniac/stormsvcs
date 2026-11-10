# Migrating services to pure Storm packages in StormLib++

**Status:** PLAN. No code yet.
**Date:** 2026-11-10
**Targets:** Synapse 2.256 Storm runtime (checked against its source) · StormLib++ `src/pkgs/` conventions
**Scope:**
- Migrate `ip_api`, `bgphe`, `malpedia` and `virustotal` to Rapid Power-Ups in `gormaniac/stormlibpp`.
- Size up `abusech` and `hatching`.

---

## 1. Why, and the rule

Each service in this repo costs a container, a Docker image, a CI workflow, a `uv.lock`, a version
kept in four places, and a `service.add` per Cortex. A Rapid Power-Up is one JSON file loaded with
`pkg.load`. It runs where the data already lives.

**Rule (as proposed):**
- Services that handle files or need special tooling stay as services.
- Everything else moves to pure Storm, unless the Storm would be too complex (for example, large
  API client libraries).

**Suggested refinement (from this research):** "handles files" is too broad. Storm can pass files
between the Axon and an HTTP API natively:
- `$lib.axon.wget` downloads with headers.
- `$lib.inet.http.post(fields=[{"sha256": ...}])` streams an Axon file as multipart. Today both
  services instead read the whole file into memory over Telepath in 1 MiB chunks.

What Storm *cannot* do is **open or transform** a file. It has no zip, tar or AES support (only
in-memory gzip, bzip2 and zlib), no X.509 or ASN.1 parser, no streaming HTTP response bodies, and
no raw sockets. A better line is:

> A feature stays in a service if it has to **parse, unpack or transform file contents**, needs a
> non-Storm tool or library, needs a streaming connection, or does heavy bulk processing.
> Passing a file between the Axon and an API does not count.

Under that line, **hatching qualifies for pure Storm**. **abusech** is split: its lookups qualify,
its zip handling and bulk work do not. See §6 and §7.

## 2. Summary

| Service | Python LOC (src) | Verdict | Effort | Blockers / main risk |
|---|---|---|---|---|
| ip_api | ~300 | Migrate. Merge into the `ipinfo` package (§4.1) | **S** | Rate limit shared across queries (45/min) |
| bgphe | ~2,550 | Migrate | **L** | X.509 DER parsing (`cryptography`) has no Storm equivalent: decide how much cert detail to keep |
| virustotal | ~1,950 | Migrate | **L** | Quota accounting without a lock; normalization port (~760 LOC) |
| malpedia | ~2,200 | Migrate | **L** | Initial YARA zip (switch endpoint); snapshot and per-view sync state |
| hatching | ~1,800 | **Migrate** (recommended) | **L** | Live event stream becomes polling; normalization port (~700 LOC) |
| abusech | ~4,400 | **Hybrid** recommended; a full port is XL | **XL** full / **L + S** hybrid | Encrypted sample zips, multi-GB zipped exports, bulk speed, normalization port (~1,600 LOC) |

Normalization is the cost driver in almost every service, not the transport. Every service keeps a
`norm.py` that reshapes upstream JSON into dicts. The existing `*.model.storm` modules already
consume those dicts. **Every port keeps the dict shapes identical**, so the model modules,
commands and most tests carry over unchanged. Only the `priv.*` modules (the `$lib.service.get`
glue) get rewritten.

## 3. Shared groundwork (do first, in StormLib++)

These pieces are written once and reused by every port. Without them, each package would
re-implement retry, backoff and throttling slightly differently.

### 3.1 `slib.utils.http`: a Storm HTTP client helper

Add it to the `slib.utils` package as a new module.

`request(meth, url, headers, params, json, body, fields, timeout, retry)` returns the familiar
`({"status", "mesg", "data", "code", "headers"})` envelope. The existing command code already
checks `status` and `mesg`, so it barely changes.

The helper handles:
- **Retries:** exponential backoff on connection errors (`code = -1`) and HTTP 429/500/502/503/504.
- **`Retry-After`:** parsed as seconds or as an HTTP date via `$lib.time.parse(..., errok=(true))`,
  with a maximum cap.
- **Params:** strips `null` values and lowercases booleans first. `strifyHttpArg` would otherwise
  send the strings `"None"` and `"True"`.
- **Error messages:** pulled from the common body keys (`error`, `message`, `detail`).
  Configurable strings, such as API keys, are scrubbed from them.
- **Never returning the raw response object.** `inet:http:resp` and the `wget` result both carry
  the request headers, which include the API key. Callers get only the parsed body and status
  fields. This is a **security requirement**: asroot modules would otherwise leak keys to
  non-admin users.

### 3.2 `slib.utils.throttle`: pacing and limits shared across queries

Storm has no mutex. Every service today serializes requests with an `asyncio.Lock`, so the
replacement is the same everywhere:

- **v1 (best effort):** a `$lib.globals` "next allowed time" (or a sliding-window list), keyed per
  API key ID. The read-check-write runs with no network await in between, and the caller
  `$lib.time.sleep`s until its slot. This can overshoot by one under concurrency. The upstream 429
  plus a cooldown then catches it.
- **v2 (strict, only if needed):** a `$lib.queue` per key holding one token. `pop(wait=true)` is
  atomic and returns null if another consumer already took the item. To guard against tokens lost
  when a query is cancelled (Storm has no `finally`), store a lease timestamp. A later caller can
  then put back a token that has gone stale.

Both are per-Cortex, which matches today: no service coordinates across Cortexes either.

### 3.3 Config and secrets conventions

| Today (service) | Pure Storm |
|---|---|
| Cell `confdefs` (URLs, intervals, timeouts, limits) | `$lib.globals` under `slib:<pkg>:*`, set by a `slib.<pkg>.admin.config` command (admin perm). The defaults live in the package. |
| Service-stored API key (slab, never readable from Storm) | A **global-scope `$lib.vault`** of the package's type, read only inside asroot modules. Per-user keys already use user-scope vaults today (abusech, hatching, vt, shodan), so that part stays the same. |
| Service `add` event (meta:source, tag globals, crons) | Package `onload`. It runs on every load, so it must be idempotent: check before creating. |
| Slab state (snapshots, quotas) | Small state in `$lib.globals` or `$lib.jsonstor` (asroot). Large blobs go in the Axon as jsonlines, with the sha256 kept in jsonstor. |

**Security trade-off to accept explicitly.** A service-wide key moves from "never readable from
Storm" to "readable by vault editors and Cortex admins". Users without permissions still can't
read it, because only asroot modules can. Document this in each package README.

### 3.4 Test harness

StormLib++ package tests today use `StormPkgTest` plus vcrpy cassettes (dnsstorm), or no HTTP at
all (ipinfo). The services have rich aiohttp fake servers (`tests/fake*.py`). These record requests
and bodies, change state between pulls, and inject 429 and 5xx errors. Retry, quota, incremental
sync and paging tests depend on them.

- Move each fake into `stormlibpp/tests/pkgs/<pkg>/` and drop the service half of it.
- Point the package at the fake by setting its `slib:<pkg>:url` global in `initTestCore`. Don't set
  `assetdir`, so VCR stays off for these tests.
- Port the `norm` and `bib` unit tests as `core.callStorm('return($lib.import(slib.x.norm).f($v))')`
  calls against the existing fixtures. These are the parity guard for the rewrite.
- Copy the deprecation-failing `conftest.py` behaviour; StormLib++ already has it.
- Running `make lint-storm` and `test_all_pkgs.py` covers syntax for free.
- Hatching's tests need `pyhatching` as a StormLib++ dev dependency for its `FakeTriage` server, or
  the fake has to be vendored.

### 3.5 Migration runbook (applies to every package)

1. Release StormLib++ with the new package. The package JSON goes in the release `dist/`.
2. On each Cortex, record the service's config and key, then run
   `service.del <iden>` (the package name is the same, so the service's package has to go first).
3. `pkg.load` the new package, re-enter the service-wide key with `slib.<pkg>.admin.apikey`, and
   re-apply the config with `slib.<pkg>.admin.config`.
4. Retire the service in this repo:
   - remove its `svcs/<svc>/` directory, its `services.toml` entry and its
     `.github/workflows/<svc>.yml`
   - leave a README note pointing to StormLib++
   - keep the last published image tag for anyone who pins it.

**Versioning:** every migrated package ships as **1.0.0**. The deployment model and config
surface break, even where commands don't. Package versions in StormLib++ are independent of the
StormLib++ Python version. Each migration also gets a CHANGELOG entry under "Unreleased".

**Naming:** keep the existing `slib.<svc>` package names and guids, so commands and docs don't
change. The package directory in StormLib++ follows its `src/pkgs/<name>/<name>.yaml` convention.

## 4. Migrations

### 4.1 ip_api: merge into `ipinfo` (S)

**Today:**
- one endpoint (`http://ip-api.com/json/<ip>?fields=...`, free tier is HTTP only)
- no auth
- a FIFO queue honouring 45 req/min using the `X-Rl` (requests left) and `X-Ttl` (seconds to reset)
  headers, with sleep-and-retry on 429
- renames `as` to `as_`

The modeling is already entirely Storm (`slib.ipapi.lib.modelResult`), as are the tag-prefix admin
commands. The Python side is only the HTTP call and the queue.

**Interpretation of "reuse the other ip info package":** fold ip-api into StormLib++'s existing
`ipinfo` package directory, so there is one IP-enrichment package with two providers. The ip-api
modeling is the richer of the two (geo:place, geo:telem, :loc, ASN owner org, hosting/proxy/mobile
tags). ipinfo's Lite modeling is a subset of it: ASN plus owner. Use the ip-api model functions
(ASN/org builders) for both providers.

**Plan:**
1. `src/pkgs/ipinfo/`:
   - add a `slib.ipapi.lib` module: HTTP call, rate limiting via §3.2 (sleep until the stored
     "reset at" time once `X-Rl` ≤ 1; on 429, sleep `X-Ttl` and retry), and the existing
     `modelResult`
   - keep `slib.ipapi.privsep` and `slib.ipapi.admin`
   - keep the commands `slib.ipapi.query` and `slib.ipapi.admin.{settag,disabletag,enabletag}`
     with the same args. The perms stay `slib.ipapi.user`/`admin`.
2. Refactor `slib.ipinfo.lib.getOrBuildAsn` to share the ASN/org builder.
   - Fix the ipinfo command's TODOs on the way: validate input with `$lib.trycast`, and use
     `repr()` for IPv4.
   - Its token handling via `slib.utils.getUserOrSystemOpt` stays.
3. Package identity:
   - **Option A (recommended):** two packages living side by side in StormLib++, `slib.ipinfo` and
     `slib.ipapi`, with the shared builder in `slib.utils`. This keeps the guids, perms and install
     story unchanged.
   - **Option B:** one package (`slib.ipinfo`) exposing both command sets. This is cleaner, but
     existing `slib.ipapi` installs need a `pkg.del`, and its perms namespace moves. It's a
     maintainer call (open question 1).
4. Tests: turn the five VCR cassettes in `svcs/ip_api/tests/vcr_cassettes/` into `StormPkgTest`
   assets. Port `test_ipapi_storm.py` (507 lines) nearly 1:1.
5. Behaviour change: the FIFO is now approximate across concurrent queries. With 45/min and
   header-driven pacing, the worst case is an extra 429, which the code retries.

**Estimate:** about 150 new Storm lines. One PR.

### 4.2 bgphe (L)

**Today:** HTTPS JSON from `bgp.he.net`. There is no WHOIS over port 43 and no HTML scraping, and no
auth. It does use:
- a global 1s request throttle
- retries honouring `Retry-After`
- RDAP, falling back to whois text
- whois/RDAP parsers (`whois.py` 685, `rdap.py` 306, `norm.py` 192)
- an X.509 DER parser built on `cryptography` (`certs.py`, 570)

**What ports cleanly:**
- Everything except `certs.py`:
  - `ipaddress` → `$lib.trycast(inet:cidr4/6)`
  - IDNA → `inet:fqdn` norm
  - strptime → `$lib.time.parse(errok=true)`
  - base64 and hashes → `$lib.base64.decode(urlsafe=(false))` and `$lib.crypto.hashes.*`
- The whois parser is the biggest single piece (about 500 Storm lines). Named regex groups must
  be rewritten to positional ones, because `$lib.regex.search` returns `.groups()`.

**Decision needed: certificate detail** (open question 2):
- **(a) Baseline: use bgp.he.net's summary fields.** The Python already falls back to them
  (`heFallback`). They give serial, subject, issuer, validity, SANs and the precert flag. Hashes
  still come from the DER.
  - `:subject` and `:issuer` change format (`C=US, O=…, CN=…` instead of RFC 4514
    `CN=…,O=…,C=US`) unless the RDNs are reversed.
- **(b) Add a small DER TLV walker** (about 150–250 lines, using `bytes.unpack` and `.slice`) for:
  - precert TBS detection
  - version and signature-algorithm OID (from a hex lookup table)
  - SPKI bytes → `crypto:key` and the `cert -(refs)> crypto:key` edge
  - RSA modulus and exponent
  - self-signed check
- **(c) Descope** the full extension parsing (KU, EKU, policies, AIA, SKI/AKI, curve names). Today it
  mostly feeds node data and `:crl:urls`.
- **Recommendation: (a)+(b).** This keeps the graph shape (keys, precert identity) and drops only
  node-data detail. Watch performance: up to 10,000 certs per lookup go through a byte-level Storm
  walk.

**Plan:**
1. New modules: `slib.bgphe.priv` (rewritten as the HTTP client on §3.1/§3.2, same function
   signatures), `slib.bgphe.norm`, `slib.bgphe.rdap`, `slib.bgphe.whois` and `slib.bgphe.certs`.
2. Config `slib:bgphe:{url,interval,timeout,backoff}` goes into globals. There are no secrets.
3. `meta:source` is created in `onload`. `seen()` already upserts it.
4. Keep the commands, args, node-data keys and modeling contract. Drop the 64 MB body cap; Storm
   can't enforce it.
5. Tests:
   - Port `test_norm.py`, `test_rdap.py` and the whois tests as Storm-call tests over the 22 fixtures
     in `tests/data`. Cert tests keep generating DER with `cryptography` (a Synapse dependency).
   - Port `test_bgphe_storm.py` against `FakeBgpHe`.

**Estimate:** about 1,000–1,300 new Storm lines, plus the ~450 existing lines kept.

**Phasing:**
1. HTTP client + norm + ASN/prefixes/subdomains/hosts
2. RDAP + whois
3. certs

### 4.3 virustotal (L)

**Today:**
- the VT v3 API (lookup, related with cursor paging, comments, votes, rescan, URL and file submit
  including the >32 MB `upload_url` path, analysis polling, behaviour summary, search, quota, raw
  request)
- an `x-apikey` header, looked up as user vault → service key → config
- retries
- an in-memory TTL cache
- a persisted per-key quota limiter (4/min sliding window, 500/day, 15.5k/month, 60s cooldown on
  429)
- `norm.py` (761 lines)

**Better in Storm:** file submission becomes a single `$lib.inet.http.post(fields=[{"name": "file",
"sha256": $sha, ...}])`. It streams from the Axon instead of holding up to 650 MB in memory. (It
needs `storm.lib.axon.wput`, which asroot covers.) Note that it uses the Axon's proxy and SSL
config.

**Plan:**
1. `slib.vt.priv.api` (asroot):
   - transport on §3.1
   - key resolution: user vault → global vault
   - endpoint wrappers that replace `svc.py`
   - `PUBLIC_RELS` and `REL_EDGES` as constant dicts
2. **Quota** on §3.2:
   - keys `slib:vt:quota:<kid>:{recent,day:<d>,month:<m>,cooldown}`, where `kid` is the first 16
     hex characters of sha256(key), so raw keys are never stored
   - day and month counters fail fast with the time left until reset; the minute window sleeps up
     to `maxwait`
   - start with the best-effort mode; move to the queue-token mode if strict 4/min is a hard
     requirement (open question 3)
3. **Cache:** descope for v1, and rely on the graph and node data. If it's wanted later, use
   `$lib.jsonstor.cacheset/cacheget(asof=...)` with a prune cron, storing normalized objects
   rather than raw reports.
4. `slib.vt.norm` (about 450 lines) returns today's dicts. `test_norm.py` ports 1:1.
5. Config `slib:vt:{url,community,limits...,verdict:malicious,timeout}` is set via
   `slib.vt.admin.config`. `slib.vt.admin.apikey` writes the global vault.
6. Commands, args, perms (`user`/`submit`/`admin`) and the "service key never readable by users"
   test all stay the same.
7. Tests:
   - port `fakevt.py`, `test_vt_storm.py` and `test_norm.py`
   - rewrite `test_quota.py` to move the stored timestamps instead of injecting a clock
   - add a concurrency test that fires N `stormlist` queries at once and asserts on what the fake
     server saw
   - drop `test_client.py`'s cache tests

**Estimate:** about 900–1,100 new Storm lines. About 1,100 existing lines are reused.

### 4.4 malpedia (L)

**Today:**
- no auth
- a throttled (2s) client with retries
- one daily pull of version/actors/families/references/bib/YARA, normalized into a slab snapshot
  with record hashes, a shrink guard and gap filling
- per-view `changes()`/`synced()` diffs that drive `slib.malpedia.model` (already Storm,
  418 lines)
- the BibTeX parser (`bib.py`)
- the initial YARA load reads `/get/yara/tlp_white/zip` with `zipfile`

**Findings:**
- **There is no JSON alternative to BibTeX** for article metadata. The live `/get/bib` file
  (6.8 MB, 18.9k entries) is strictly line-regular, so a line-regex parser in Storm works. Measured:
  22–47 s per full parse. That's fine for a daily cron that only runs when the version changes.
- **Zip:** replace it with `/get/yara/after/2000-01-01`, which has the same JSON shape as the
  incremental path. **Verify live that it returns every rule** (open question 4). The fallback is
  `/get/yara/tlp_white/raw`, split on `^rule` and mapped to `/list/yara`.

**Plan:**
1. New modules:
   - `slib.malpedia.priv.api`: HTTP client
   - `.bib`: line parser
   - `.norm`: about 350–400 lines, covering ActorIndex, the actor-ID resolution, and the
     bib×references×library join for news
   - `.store`: snapshot and state
2. **Snapshot:**
   - one jsonlines blob per kind in the Axon (`$lib.axon.put` / `jsonlines`), with the sha256s and
     the `info` doc in `$lib.jsonstor` at `slib/malpedia/*`
   - keeps the hash per record, the shrink guard and rejected-version memory
3. **Per-view state:**
   - store `{hash, DROP_FIELDS values}` as node data (`malpedia:rec`) on each modeled node; node
     data is per layer, so it is per view
   - removals = nodes `-(seen)>` from the meta:source whose key isn't in the current snapshot
   - behaviour change: a forked view inherits its parent's sync state instead of re-modeling
     everything
4. **Scheduling:**
   - `onload` creates the daily cron once (guarded by the existing `slib:malpedia:cron` global, at
     a random time picked once and stored)
   - `slib:malpedia:autosync` becomes a global
   - a `pulling` flag with an expiry stands in for the asyncio lock
5. Commands, perms, globals and the modeling stay the same. Config goes to globals via an admin
   config command.
6. Tests:
   - port `fakemalpedia.py`, `test_malpedia_storm.py`, `test_norm.py` and `test_bib.py`
   - fold `test_svc.py`'s scenarios (incremental, rename, gaps, shrink, failure keeps the snapshot)
     into Storm-level assertions
   - drop the unzip and body-cap tests
7. **Migration:** per-view state in the slab is lost. Each view's first sync behaves like `--full`.
   Edits are idempotent, but for that one cycle anything that changed upstream before the migration
   isn't undone.

**Estimate:** about 900–1,100 new Storm lines. About 945 existing lines are reused.

**Do early:** benchmark the per-view diff (about 26k node-data reads) on a real Cortex.

## 5. Order and milestones

1. **Shared groundwork (§3).** Build `slib.utils.http` and `slib.utils.throttle`, and the
   fake-server test pattern. About 250 lines. It gets proven by the next step.
2. **ip_api.** The smallest port; it validates the groundwork, the runbook and the release flow.
3. **virustotal.** Most used. It validates vault keys, quota, and Axon multipart.
4. **bgphe.** In phases; the certs decision blocks phase 3 only.
5. **malpedia.** Validates crons, Axon-backed state and node-data view state.
6. **hatching** (if approved, §6).
7. **abusech** hybrid (if approved, §7).

Each step is one StormLib++ PR (package, tests, docs page under `doc/pkgs/`, CHANGELOG), followed by
one stormsvcs PR that retires the service once the package is released.

## 6. hatching: how big the lift is (L, and recommended)

**Not as file-heavy as it looks.** It never parses a file:
- **Submit:** multipart `_json` + `file` → `$lib.inet.http.post(fields=[{"name": "_json", "value":
  $req}, {"name": "file", "sha256": $sha, ...}])`. JSON and file parts in one request are checked in
  Synapse's `axon.postfiles`. This improves on today's chunked approach.
- **Downloads** (sample, pcap, pcapng, screenshot, dropped files, tar/zip archives) →
  `$lib.axon.wget(url, headers=({"Authorization": ...}))`. The archive is stored as-is, which is
  what the service does today too.

**Feature mapping:**

| Feature | Storm port |
|---|---|
| ~45 CRUD/report/profile/YARA/user/stats endpoints, pagination | Trivial |
| Submit, downloads, `wait` | Easy. `wait` becomes polling `GET /samples/{id}` with sleep |
| `normSample` (~700 lines of norm) | M–L |
| Kernel log (NDJSON) | wget into the Axon + `jsonlines` |
| **`slib.hatching.events`** (live NDJSON stream) | **Blocked**: Storm reads whole response bodies. It becomes polling of status changes |

Specific risks:
- `maxsize` can only be checked **after** a download (wget has no size cap).
- Error bodies land in the Axon.
- The wget result contains the Authorization header, so it must never be returned (§3.1).
- Task reports are fetched one after another instead of with `asyncio.gather`.
- norm's HTTP request/response pairing is O(n²) and needs a dict index in Storm.

**Effort:**
- about 1,200–1,500 new Storm lines: HTTP core ~400, norm ~650–900, submit/download ~100,
  wait/events ~80
- about 255 lines of priv glue removed
- about 1,300 existing lines kept

**A hybrid isn't worth it.** The only gap is event streaming, which doesn't justify keeping a
service.

## 7. abusech: how big the lift is (XL full, or L + S hybrid)

**Feature classification:**

| Class | Features |
|---|---|
| **Trivial** | All MalwareBazaar, URLhaus, ThreatFox, YARAify and Hunting JSON/form lookups, searches, reference lists and writes. Feodo and SSLBL blocklists. "Recent" exports (plain CSV/JSON). Raw request. MalwareBazaar submit and YARAify scan via Axon multipart (cleaner than today). |
| **Effort** | 5 req/s rate limit shared by every user (§3.2, weaker than the lock). YARA rule text parsing. Exports put the **API key in the URL path**, so it can end up in Axon and Cortex debug or exception logs: a security regression. |
| **Blocked** | **Sample downloads** (MalwareBazaar, URLhaus, YARAify, YARAify unpacked) come as AES/ZipCrypto zips with password `infected`. Storm has no AES or zip support. **Full exports** (`full.csv.zip`, `payload.csv.zip`, `full.json.zip`) are multi-GB zips with no uncompressed variant. **`--bulk`** builds msgpack `.nodes` at ~280 rows/s, compared with ~51 rows/s for Storm modeling today. |

**Work the agent proved out, with limits.** An unencrypted deflate zip *can* be decoded in Storm by
rewrapping its stream as gzip (`$lib.pack` + `$lib.compression.gzip.un`). It runs entirely in Cortex
memory, so it suits only small zips (the YARAhub rules export, maybe ThreatFox full), never the
GB-scale exports.

**The real cost is `norm.py` (1,577 lines → ~1,300–1,800 Storm lines).** It includes 12 vendor intel
readers (one big `switch` in Storm), sample merging, `verdict`, YARA parsing and STIX patterns.
Every option pays for it, because the lookups need it.

**Expected performance with norm in Storm:** about 20–40 rows/s (estimate, needs benchmarking).

| Export | Time |
|---|---|
| ThreatFox recent | minutes |
| URLhaus recent | about 1–1.5 h |
| Full exports | days, not viable |

**Options:**

| Option | Effort | Keeps | Loses |
|---|---|---|---|
| (i) Full pure Storm | **XL**: ~2,600–3,100 Storm lines + ~1,500–2,000 test lines | Lookups, submits, recent exports | Unzipped downloads (4 commands), full exports (4), fast bulk, strict global rate limit, key secrecy in export URLs |
| (ii-A) **Pure-Storm `slib.abusech` + a generic `slib.unzip` helper service** | **L** (package, ~2,300–2,800 lines) + **S** (helper, ~150–250 Python lines) | Everything except fast `--bulk` | Fast bulk |
| (ii-B) (ii-A) + keep `bulk.py` in the helper | L + M | Everything | Normalization lives in two languages, and `test_bulk` has to keep guarding parity |
| (iii) Descoped: no downloads, no full exports, no helper | ≈ L | Lookups, submits, recent exports | As in (i) |

**Recommendation: (ii-A).**
- The helper ("given an Axon sha256 and a password, extract the members into the Axon") is
  generic and fits the rule: it handles files.
- capa, yarastorm and pcap could use it too.
- Full exports go through the helper, then `$lib.axon.csvrows`.
- Drop `--bulk`, or keep it for the recent exports only at Storm speed. A cron polling the recent
  exports builds up the same data over time.
- Fix the key-in-URL logging before shipping, or document it.

Before committing:
- spike Storm-side norm throughput
- spike `$lib.feed.genr('syn.nodes', …)` with Storm-built node definitions (which may roughly
  double throughput)

## 8. Open questions for the maintainer

1. **ip_api packaging:** two packages side by side with a shared ASN/org builder (A,
   recommended), or one merged `slib.ipinfo` package (B)?
2. **bgphe certs:** summary fields only (a), plus a DER walker (b, recommended), or descope?
   Is changing the `:subject`/`:issuer` format OK?
3. **virustotal quota:** is best effort (it can overshoot by one under concurrency) acceptable, or
   is strict 4/min required (queue token)? Should the cache be dropped for v1?
4. **malpedia:** OK to switch the first YARA load to `yara/after/2000-01-01` (pending a live check)?
   OK for per-view state to move to node data, so forks inherit their parent's sync state?
5. **Key secrecy:** is "readable by vault editors and admins, never by plain users" acceptable for
   service-wide keys?
6. **Versioning:** 1.0.0 for every migrated package (recommended), or keep the service version
   lines? CLAUDE.md's version rule covers `svcs/` only, so StormLib++ needs its own note.
7. **hatching:** approve the migration, with events degraded to polling?
8. **abusech:** approve the hybrid (ii-A) and a generic unzip helper service in this repo?
9. **Rule wording:** adopt the "parse/unpack/transform file contents" refinement from §1?
