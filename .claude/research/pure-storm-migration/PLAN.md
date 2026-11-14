# Migrating services to pure Storm packages in StormLib++

**Status:** PLAN with maintainer decisions (2026-11-14, see §8). The first piece of code is in:
`slib.utils.x509` (§4.2), on the StormLib++ branch `claude/hopeful-heisenberg-feq5rv`.
**Date:** 2026-11-10, updated 2026-11-14
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
| ip_api | ~300 | Migrate as `slib.ipapi`, side by side with `slib.ipinfo`; shared ASN code in `slib.utils` (§4.1) | **S** | Rate limit shared across queries (45/min) |
| bgphe | ~2,550 | Migrate | **L** (certs part done) | Certificate parsing is solved by `slib.utils.x509` (§4.2); Storm parses about 0.1 s per certificate |
| virustotal | ~1,950 | Migrate | **L** | Quota enforcement still open (§4.3, Appendix A.6); normalization port (~760 LOC) |
| malpedia | ~2,200 | Migrate | **L** | Snapshot and per-view sync state. The zip load is replaced, verified live (§4.4) |
| hatching | ~1,800 | **Migrate** (approved) | **L** | Live event stream becomes polling; normalization port (~700 LOC) |
| abusech | ~4,400 | **Deferred** (skipped for now) | **XL** full / **L + S** hybrid | Encrypted sample zips, multi-GB zipped exports, bulk speed, normalization port (~1,600 LOC) |

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
- **v2 (strict, only if needed):** package queues used as locks and token buckets. A queue's
  `pop()` is atomic. This is an implementation option, not a requirement; see
  **Appendix A** for the verified behaviour, patterns and caveats.

Both are per-Cortex, which matches today: no service coordinates across Cortexes either.

### 3.3 Config and secrets conventions

| Today (service) | Pure Storm |
|---|---|
| Cell `confdefs` (URLs, intervals, timeouts, limits) | `$lib.globals` under `slib:<pkg>:*`, set by a `slib.<pkg>.admin.config` command (admin perm). The defaults live in the package. Option: package vars (`$lib.pkg.vars("<pkg>")`) instead, which are scoped to the package and gated by `power-ups.<pkg>.admin` (see Appendix A.2). |
| Service-stored API key (slab, never readable from Storm) | A **global-scope `$lib.vault`** of the package's type, read only inside asroot modules. Per-user keys already use user-scope vaults today (abusech, hatching, vt, shodan), so that part stays the same. |
| Service `add` event (meta:source, tag globals, crons) | Package `onload`. It runs on every load, so it must be idempotent: check before creating. |
| Slab state (snapshots, quotas) | Small state in `$lib.globals` or `$lib.jsonstor` (asroot). Large blobs go in the Axon as jsonlines, with the sha256 kept in jsonstor. |

**Keys (decided 2026-11-14).** Users can save their own keys in a user-scope vault, which takes
precedence for their queries. The global key is managed by admins, in a global-scope vault that
only the asroot modules read. A service-wide key moving from "never readable from Storm" to
"readable by vault editors and Cortex admins" is a known, accepted risk. Plain users still can't
read it. Document this in each package README.

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

**Versioning (decided):** every migrated package ships as **1.0.0**. The deployment model and config
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

**Decided (2026-11-14):** the two packages stay side by side for now: `slib.ipapi` gets its own
`src/pkgs/ipapi/` directory next to `src/pkgs/ipinfo/`. The ASN and owner org modeling they share
moves into the `slib.utils` package (for example a `slib.utils.inet` module with an
`asnNode(asn, owner)` function), and both packages call it. The ip-api modeling is the richer of
the two (geo:place, geo:telem, :loc, ASN owner org, hosting/proxy/mobile tags). ipinfo's Lite
modeling is a subset of it: ASN plus owner.

**Plan:**
1. `src/pkgs/ipapi/` (a new package directory, `slib.ipapi`, keeping its guid):
   - a `slib.ipapi.lib` module: HTTP call, rate limiting via §3.2 (sleep until the stored
     "reset at" time once `X-Rl` ≤ 1; on 429, sleep `X-Ttl` and retry), and the existing
     `modelResult`
   - keep `slib.ipapi.privsep` and `slib.ipapi.admin`
   - keep the commands `slib.ipapi.query` and `slib.ipapi.admin.{settag,disabletag,enabletag}`
     with the same args. The perms stay `slib.ipapi.user`/`admin`.
2. Move the ASN/org builders into `slib.utils`, and have `slib.ipinfo.lib.getOrBuildAsn` and
   `slib.ipapi.lib` use them. Both packages then depend on `slib.utils`, as ipinfo already does.
   - Fix the ipinfo command's TODOs on the way: validate input with `$lib.trycast`, and use
     `repr()` for IPv4.
   - Its token handling via `slib.utils.getUserOrSystemOpt` stays.
3. Package identity: two packages, so the guids, perms and install story stay as they are. Merging
   them into one package stays possible later.
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

**Certificates (decided, and built):** a complete certificate parser lives in the `slib.utils`
package, as the `slib.utils.x509` module (slib.utils 0.2.0, StormLib++ commit `cb06ae6` on
`claude/hopeful-heisenberg-feq5rv`). bgphe doesn't need a cert parser of its own.

- `parse(valu)` takes DER bytes, PEM or base64, and handles certificates and bare CT
  precertificate TBSCertificates. Its output uses the same keys as bgphe's `certs.parseCert()`
  (`sha256`, `serial`, `subject.dn`/`attrs`, `pubkey.rsa`, `sans`, `crls`, `selfsigned`, ...), so
  `slib.bgphe` only needs a thin adapter for bgp.he.net's metadata (`he`), `identities()` (also
  in the module) and the summary-field fallback.
- Coverage:
  - RFC 5280 fields and extensions (SAN/IAN with every GeneralName type, basic constraints,
    key usage, EKU, SKI/AKI, CRL DPs, freshest CRL, AIA/SIA, policies with CPS and user
    notices, name constraints, policy constraints and mappings, inhibitAnyPolicy, private key
    usage period, TLS feature, OCSP no check, CT poison).
  - RFC 6962 SCT lists.
  - RFC 4514 DNs, written exactly like cryptography's `rfc4514_string()`, so `:subject` and
    `:issuer` values don't change.
  - RFC 5952 IPv6 text.
  - RSA, RSA-PSS (with parameters), EC (named, explicit and implicit curves), DSA, Ed25519,
    Ed448, X25519 and X448 keys.
  - Every ASN.1 string type, and UTCTime/GeneralizedTime in all their X.680 forms.
- Edge cases: recoverable DER and RFC 5280 deviations become `warnings` instead of errors. For
  example non-minimal encodings, negative or long serials, encoded DEFAULTs, odd time forms,
  duplicate extensions and trailing data. Malformed DER raises `BadCert`. An extension that fails
  to parse records its own `error`, and the rest of the certificate is still parsed. Unknown
  critical extensions are listed in `unhandled`.
- **Verified:**
  - Matches Python cryptography field for field on 137 real certificates (the system and
    certifi root stores, plus bgphe's CT fixtures).
  - The committed tests cover 16 varied roots, the CT fixtures (including precertificate TBS
    entries), generated certificates for every key type and extension, and about 40 hand built
    DER edge cases.
- **Performance:** about **100–120 ms per certificate**. Storm is interpreted, with function
  calls at about 165 µs and simple statements at 15–20 µs. OIDs and names are cached within a
  query.
  - This is the main cost of moving bgphe: the default `--limit 200` takes about 20–25 s, and the
    maximum of 10,000 certificates about 17–20 minutes, against about 1 s in Python today.
  - Recommendation: lower the command's maximum `--limit` (e.g. to 1,000), or parse in batches
    with progress output.
- Nothing is lost compared with `cryptography`. The parser also keeps certificates that
  cryptography rejects (duplicate extensions, unsupported GeneralName types, trailing data),
  where bgphe falls back to the summary fields today.

**Plan:**
1. New modules: `slib.bgphe.priv` (rewritten as the HTTP client on §3.1/§3.2, same function
   signatures), `slib.bgphe.norm`, `slib.bgphe.rdap` and `slib.bgphe.whois`. `slib.bgphe.certs`
   is a thin adapter over `slib.utils.x509`.
2. Config `slib:bgphe:{url,interval,timeout,backoff}` goes into globals. There are no secrets.
3. `meta:source` is created in `onload`. `seen()` already upserts it.
4. Keep the commands, args, node-data keys and modeling contract. Drop the 64 MB body cap; Storm
   can't enforce it.
5. Tests:
   - Port `test_norm.py`, `test_rdap.py` and the whois tests as Storm-call tests over the 22 fixtures
     in `tests/data`. Cert tests keep generating DER with `cryptography` (a Synapse dependency).
   - Port `test_bgphe_storm.py` against `FakeBgpHe`.

**Estimate:** about 900–1,100 new Storm lines (the cert parser is already built), plus the ~450
existing lines kept.

**Phasing:**
1. HTTP client + norm + ASN/prefixes/subdomains/hosts
2. RDAP + whois
3. certs (adapter over `slib.utils.x509`)

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
   - **still open (open question 3):** best-effort counters, or queue token buckets. Appendix A.6
     has the resilience test results that decision needs. In short: queue buckets never
     double-grant, a minute bucket needs size 1 refilled every 16 s to guarantee ≤4 in any
     60 s window, and cancelled queries can leak tokens. That's harmless for buckets but means
     a short under-use until the next refill or reset.
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
- **Zip: replaced by `/get/yara/after/2000-01-01` (decided, verified live on 2026-11-14).**
  - It returns `{"tlp_white": {filename: text}}`, the same JSON shape as the incremental path.
  - It has the same 2,280 TLP:WHITE rules as the zip (4.0 MB) and `/list/yara`, with nothing
    missing or extra.
  - 1,826 rule texts are byte-identical. The other 454 differ only in trailing newlines or
    whitespace.
  - The service hashes rule text for its change detection (`norm.normYara`), and nothing in the
    model uses that hash. So the only effect is that those 454 rules re-model once on the first
    Storm sync, idempotently.
  - The response is 15.4 MB of JSON, against a 4.0 MB zip, which is fine for a daily cron.
  - The service's own first pull could switch to this endpoint now too, which drops `zipfile`
    and `unzipRules` before the migration.

**Plan:**
1. New modules:
   - `slib.malpedia.priv.api`: HTTP client (no zip handling)
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
4. **bgphe.** In phases; its cert parser (`slib.utils.x509`) is already built.
5. **malpedia.** Validates crons, Axon-backed state and node-data view state.
6. **hatching** (approved, §6).

abusech is deferred (§7).

Each step is one StormLib++ PR (package, tests, docs page under `doc/pkgs/`, CHANGELOG), followed by
one stormsvcs PR that retires the service once the package is released.

## 6. hatching: how big the lift is (L, approved)

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

## 7. abusech: how big the lift is (XL full, or L + S hybrid). Deferred

**Decided (2026-11-14): skip abuse.ch for now.** It stays a service. The analysis below is kept
for when it's revisited.

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

## 8. Decisions (2026-11-14) and open questions

| # | Question | Decision |
|---|---|---|
| 1 | ip_api packaging | Side by side for now: `slib.ipapi` next to `slib.ipinfo`. The shared ASN code moves into `slib.utils` (§4.1). |
| 2 | bgphe certs | Write a complete cert parser in `slib.utils`, handling the RFC edge cases. **Done:** `slib.utils.x509` (§4.2). |
| 3 | virustotal quota | **Open.** The maintainer asked how resilient the queue approach is first: see Appendix A.6. The cache question (drop it for v1) is open too. |
| 4 | malpedia | Move away from the zip load: **checked and confirmed** (§4.4). Per-view state on node data is taken as accepted with the same "yes"; confirm if not. |
| 5 | Keys | Known, accepted risk. Users can save their own keys; global keys are managed by admins (§3.3). |
| 6 | Versioning | Every migrated package starts at 1.0.0 (§3.5). StormLib++ still needs its own versioning note, since CLAUDE.md's rule only covers `svcs/`. |
| 7 | hatching | Approved: hatching moves (§6). |
| 8 | abusech | Skipped for now (§7). |
| 9 | Rule wording | **Open:** adopt the "parse, unpack or transform file contents" refinement from §1? |

---

## Appendix A. Implementation option: queue-based locks and rate limiters

**Status:** an option on record, not a decision. The best-effort throttle in §3.2 v1 may be enough
for every package. Use this only where a package needs strict mutual exclusion or exact quotas.

Researched 2026-11-10 to 2026-11-14 against the Synapse 2.256 source. Each behaviour below was
checked on a throwaway test Cortex (`SynTest.getTestCore`). The test scripts are not in the repo.

### A.1 What makes queues usable as locks

- `$lib.queue` and `$lib.pkg.queues` share the same storage (`lmdbslab.MultiQueue`). Both are
  persistent and shared across the whole Cortex.
- `pop()` is a change-log write (`coreQueuePop` / `stormPkgQueuePop`, `@onPushAuto`). Writes are
  applied one at a time. If another query already took the item, `pop()` returns `null`, so a
  caller loops until it gets a non-null item.
- `pop(wait=(true))` blocks until an item exists. Every waiter wakes and races for it (an
  `asyncio.Event`), so waiters are **not served FIFO**.
- On a mirror, the write is forwarded to the leader, so this should hold under mirroring too.
  That was not tested.

**Measured, with 20 concurrent queries each doing read, sleep 50 ms, write on a global counter:**

| Variant | Result |
|---|---|
| No lock | 2–3 of 20 increments survived |
| One-token queue as a mutex | 20 of 20, ~1.1 s total, 1 token left; 35 failed (`null`) pops along the way |
| Token bucket: 5 tokens, then 5 refills, 20 waiting consumers | exactly 5 ran, then exactly 10; 0 tokens left |

**Pipes (`$lib.pipe`) don't help here.** A pipe lives in memory and is reachable only from the query
that created it and its filler subquery. Within one command it is a bounded producer/consumer
buffer (max 10,000 items, `put` blocks when full). That could still be useful, for example to
overlap hatching's task-report fetches with modeling.

### A.2 Use package queues and package vars, not global ones

`$lib.pkg.queues("<pkg>")` gives `add`/`gen`/`get`/`del`/`list`. The queue object has
`put`/`puts`/`get`/`gets`/`pop`/`cull`/`size`, the same pop semantics as above.

- **Namespaced** per package (the queue key is `guid((pkgname, name))`), so names can't collide
  across the Cortex.
- **Gated by `power-ups.<pkg>.admin`.** A plain user calling it directly gets `AuthDeny`
  (verified). The package's asroot modules can use it, which matches how packages already guard
  their keys.
- **Survives `pkg.del` and reloads (verified).** Tokens and counters persist across upgrades. So:
  - `onload` must create queues with `.gen(name)`. It must not add a token on every load, or
    reloads keep adding tokens. Check `size()` first or keep an "initialized" package var.
  - Uninstalling leaves the queues behind. Delete them explicitly if a cleanup command is wanted.
- **`$lib.pkg.vars("<pkg>")`** has the same scope and permission model. It's a fit for the
  package's config and for lease records.

### A.3 Patterns

**Token bucket (preferred: nothing to release).**
- Consumers pop one token per request and never return it.
- A Storm daemon (`$lib.dmon`) refills it at the allowed rate up to a cap:
  `while (true) { if ($q.size() < $cap) { $q.put(1) } $lib.time.sleep($interval) }`.
  A cron also works for coarse intervals.
- The refiller needs no API key, so the "a daemon runs as one user" problem doesn't come up.
- A token lost to a cancelled query is one missed slot. The next refill makes up for it.

Candidate uses:

| Package | Bucket |
|---|---|
| virustotal | per key ID: minute bucket (cap 4, +1 every 15 s); day bucket (500, a cron resets it at 00:00 UTC by culling and refilling); month bucket (15,500). Pops are atomic, so these quotas become exact instead of "can go one over". |
| ip-api | cap 45, refilled per minute, with the `X-Rl`/`X-Ttl` headers as a backstop |
| bgphe | 1 token per `interval` |
| abusech | 5 per second (check the daemon's sleep granularity at that rate) |

Retries count against the bucket, the same as today.

**Mutex (only where mutual exclusion is truly needed, e.g. malpedia's single pull).**
- One token. Acquire with `pop(wait=(true))`, looping on `null`. Release with `put`.
- **Semaphore:** the same pattern with N tokens, which caps how many queries run at once.

### A.4 Releasing a mutex: `fini` is not `finally`

A Storm `fini` block (`ast.FiniBlock`) runs only after the node stream finishes normally. It is not
a `try/finally`. Verified:

| How the query ends | `fini` ran? | Mutex token |
|---|---|---|
| Normal completion | yes | returned |
| `stop` | **no** | — |
| `$lib.raise(...)` | **no** | **lost** |
| Query cancelled or timed out | **no** | **lost** |

A Cortex restart while the token is held also loses it, because the pop is already persisted.

So a mutex needs three layers:
1. **`fini`** releases on the normal path.
2. **`try { ... } catch * as err { release, then re-raise or warn }`** around the locked section
   covers Storm errors. `catch` does not run on cancellation, a restart, or `stop`.
3. **A lease as the backstop.** On acquire, write `{holder, expires}` to a package var. A cron
   puts the token back when the queue is empty and the lease has expired. Keep locked sections
   short and the lease generous, so a slow holder doesn't outlive its lease and end up with two
   holders. A lease counter (epoch) checked before committing work would remove that risk if it
   ever matters.

### A.5 Costs

- Every `pop` is a persisted write, failed pops included. That's fine at API request rates, but
  don't use a queue to guard a tight loop.
- Waiters aren't served in order. Under heavy contention a waiter can keep losing; the services'
  `asyncio.Lock`s were first-come, first-served.
- Like everything in §3.2, this is per-Cortex. Nothing coordinates across Cortexes, the same as
  today.

### A.6 Resilience testing (2026-11-14)

Asked for before deciding virustotal's quota enforcement (§8 question 3). Tested on Synapse 2.256
test Cortexes, including a leader with a mirror. Counts come from wrapping the Cortex's queue
methods, so measuring added no writes. The test scripts are not in the repo.

**Correctness: no double grants anywhere.**

| Test | Result |
|---|---|
| Mutex, 100 and 200 concurrent consumers | Every one got the lock exactly once, max 1 holder, 1 token left |
| Bucket: 50 tokens to 100 waiters, 100 tokens to 200 waiters, a 100-token burst to 100 waiters | Exactly 50, 100 and 100 grants |
| 50 leader + 50 mirror consumers on one mutex | 100 grants, max 1 holder. Mirror pops are forwarded to the leader, so atomicity holds |

**Token loss: the real risk.** `NexsRoot.eat()` runs the change-log write under `asyncio.shield`.
Cancelling a query does not stop a pop already in flight: the token is removed and the result is
thrown away.

| Scenario (500 random trials each) | Tokens lost |
|---|---|
| Waiter blocked on an empty queue, cancelled, then a token is put | 0 of 500 |
| Tight pop/put loop, 1 consumer, cancelled at random | 227 of 500 |
| Same, 5 consumers (also counting cancels while holding the token) | survived in only 83 of 500 |

- A held token is also lost if the Cortex stops. Tokens at rest survive a restart.
- What counts as a cancel: `ps.kill`, a client disconnect, disabling or deleting a cron or
  dmon, and Cortex shutdown.
- **For buckets this is harmless:** one lost slot, and the next refill or reset restores it.
- **For a mutex it is a deadlock:** a mutex needs the lease and watchdog from A.4.

**Waste under contention.**
- `pop(wait=true)` wakes every waiter, and each losing pop is still a change-log write.
- With 100 waiters that was about 43 writes per acquire; with 200 it was about 100. The waste
  grows with the square of the number of waiters.
- A non-blocking `pop()` on an empty queue writes nothing.
- Polling with `pop()` and a 25–75 ms jittered sleep cut it to about 19 writes per acquire at 100
  waiters.

**Refill daemon.**

| Refill | 1 s interval | 0.2 s interval |
|---|---|---|
| Naive (`size() < cap → put; sleep`) | 0.15% slow | 0.8% slow |
| Drift-corrected (schedule `$next += interval`, sleep until it) | exact | exact |

- Drift only ever goes slow, which is the safe direction for a quota.
- A dmon that errors restarts after about 1 s, with its variables reset.
- Dmons come back after a Cortex restart, and run only on the leader.
- A deleted dmon or queue leaves waiters blocked forever, with no error.

**Burst limits.** A bucket of size *c* refilled at rate *r* allows *c + r·T* grants in any window
*T*.
- *c = 4*, refilled every 15 s, allows up to **8** in a sliding minute.
- To guarantee **≤ 4 in any 60 s window**, use *c = 1* refilled every **16 s** (3.75/min).
- A fixed reset of 4 tokens on each minute boundary allows 8 across a boundary.

**Day and month resets.**
- A cron doing `cull(huge)` + `puts(N)` never exceeded N with 20 consumers draining. There was a
  brief empty gap.
- Two resets running at once doubled the bucket. Cron doesn't overlap with itself, but a manual
  run plus the cron would. Guard it with a stored "last reset" date.
- Topping up with `puts(cap - size())` races and comes out slightly under.

**Growth.**
- Change-log entries are about 76 bytes each, and Synapse never trims the log by default
  (`nexslog:en` is on; trimming takes an explicit `trimNexsLog`).

| Use | Change-log growth |
|---|---|
| virustotal at its 500/day cap | about 2k entries, ~150 KB a day |
| 4/min minute bucket, running continuously | ~0.9 MB a day |
| A saturated 5/s bucket (abusech, deferred) | ~66 MB a day |

- The queue slab itself plateaus, because LMDB reuses freed pages.

**Other gotchas.**
- `pop()` returns `(offs, item)`, so put back `$tok.1`, not `$tok`.
- A bare `put(1)` stores the string `"1"`. Use `put((1))`.
- `pop()` has no timeout.
- A mirror `pop()` can return null while items exist, so always loop.
- On a mirror whose leader is down, a pop raises LinkErr after 30 s.

**Verdicts.**

| Use | Verdict |
|---|---|
| Minute limit (virustotal 4/min) | **Good.** Bucket of 1, refilled every 16 s by a drift-corrected dmon. Loss heals at the next refill. |
| Day (500) and month (15.5k) quotas | **Good, with guards.** Cron reset with a "last reset" date marker. Take tokens with non-blocking `pop()` and fail fast with "quota exhausted". A cancel can leak a few tokens until the next reset (conservative). |
| Mutex for a single sync job (malpedia) | **Only with a lease and watchdog.** Prefer cron's built-in no-overlap when the job only runs from one cron. |
| Best-effort globals (§3.2 v1) | Simpler and leak-free, but can overshoot by one under concurrency. VT's 429 plus a cooldown then catches it. |

If virustotal goes with buckets:
- Acquire the minute token first, since a blocking wait there loses nothing if cancelled. Then
  take the day token, then the month token.
- Show the refill daemon's health (`$lib.dmon.get` has an error flag) in `slib.vt.quota`.
