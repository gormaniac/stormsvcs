# Internals

This page walks through the source in {src}`svcs/bgphe/src/bgphesvc` and the Storm package,
for developers maintaining the service. See {doc}`/dev/architecture` for how every service in
the repo is laid out.

## Module map

| Module | Role |
| --- | --- |
| `__init__.py` | `__version__` and the `BgpHeSvc` export. |
| `__main__.py` | `python -m bgphesvc <dirn>` runs `BgpHeSvc.execmain()`. |
| `defs.py` | `SVC_NAME` (`slib.bgphe`), `SVC_VER`, `SVC_GUID` (the `meta:source` guid), `SVC_EVTS` (the `add` event), and `PKGDEFS` (the Storm package, loaded by `stormlibpp.StormPkg` from `pkgproto/slib.bgphe.yaml`). |
| `api.py` | `BgpHeCellApi`, the Telepath API (see [API](api.md#telepath-api)). |
| `svc.py` | `BgpHeSvc`, the cell: config, the HTTP session and client, and the six service methods. |
| `client.py` | `BgpHeClient`, the HTTP transport: throttling, retries, body limits, error messages, and one method per endpoint. |
| `norm.py` | Input normalization (domains, ASNs, IPs/CIDRs) and the simple responses (subdomains, hosts, prefixes). |
| `certs.py` | Certificate DER and TBSCertificate parsing, with `cryptography`. |
| `rdap.py` | RDAP (RFC 9083) domain records and jCard (RFC 7095) parsing. |
| `whois.py` | Domain and ASN whois text parsing, and shared cleaning helpers. |

## svc.py

`BgpHeSvc.__anit__` creates one `aiohttp.ClientSession(trust_env=True)` (closed on fini) and
one `BgpHeClient` from the `bgphe:*` config. Nothing else is set up: there are no slabs, no
Axon use, no files, and no background tasks. The service docstring says it plainly: nothing is
stored, every call is a fresh query.

Each public method normalizes its input with `_norm()`, which turns `norm.BadValu` into a
`BgpHeSvcError` (so the message reaches Storm as-is), then calls the client and a parser:

| Method | Client calls | Parser |
| --- | --- | --- |
| `certs()` | `certsByDomain()` per page | `certs.heCert()`, `certs.certKey()` |
| `subdomains()` | `certDomains()` | `norm.normSubdomains()` |
| `hosts()` | `certsByPrefix(addr, len)` | `norm.normPrefix()`, `norm.normHosts()` |
| `whoisDomain()` | `rdapDomain()`, then maybe `whoisDomain()` | `rdap.parseDomain()` or `whois.fixText()` + `whois.parseDomain()` |
| `whoisAsn()` | `whoisAsn()` | `whois.fixText()` + `whois.parseAsn()` |
| `prefixes()` | `prefixesOriginated()` | `norm.normPrefixes()` |

`certs()` details:

- `_limit()` rejects anything but a positive `int` (`bool` included) with
  `Invalid limit: <valu>, it must be a positive integer.` and caps it at `MAX_CERTS`
  (`10000`, 50 pages).
- It loops over pages (the first request has no `page` parameter), stopping when `limit`
  certificates have been yielded (`more=True` if any were left), a page is empty, or the page
  number reaches `pagination.total_pages`.
- Entries that aren't dicts or have no usable DER count as `invalid`. Duplicates by
  `certKey()` (the SHA-256, or `tbs:<sha256>`) are skipped silently. `valid=True` drops
  certificates outside `notbefore <= now <= notafter` (`isValid()`, a missing `notafter`
  is invalid); `precerts=False` drops precertificates. Both count as `skipped`.

`whoisDomain()` catches `BgpHeApiError` and `rdap.BadRdap` from the RDAP step and falls back
to the whois text, remembering the reason as `rdaperr`. A whois text failure after an RDAP
failure is re-raised as one `BgpHeApiError` naming both reasons.

## client.py

### Endpoints

All requests are `GET` with `User-Agent: slib.bgphe (Synapse Storm Service;
https://github.com/gormaniac/stormsvcs)`, `Accept: application/json`, and
`Accept-Encoding: gzip, deflate`. There is no authentication.

| Method | Endpoint | Expected response |
| --- | --- | --- |
| `certsByDomain(domain, page=1)` | `/certs/api/domain?domain=<fqdn>[&page=<n>]` | `{"certificates": [...], "pagination": {"total_certificates", "total_pages", "page_size", ...}}`, 200 per page (`CERT_PAGE_SIZE`). |
| `certDomains(domain)` | `/certs/api/list?domain=<fqdn>` | `{"domains": [{"domain", "certificate_count"}], "total_certificates", "truncated", ...}` |
| `certsByPrefix(addr, length)` | `/certs/api/certificates/by-prefix?prefix=<ip>&len=<n>` | `{"entries": [{"ip", "hostnames"}], "total_ips", "total_hostnames", "has_more", ...}` |
| `rdapDomain(domain)` | `/rdap/dns/<fqdn>` | `[<registry record>, [<registrar records>] or null]`. HTTP 404 when there is no RDAP. |
| `whoisDomain(domain)` | `/whois/dns/<fqdn>` | `{"data": "<whois text>"}` |
| `whoisAsn(asn)` | `/whois/as<asn>` | `{"data": "<whois text>"}` |
| `prefixesOriginated(asn)` | `/super-lg/report/api/v1/prefixes/originated/<asn>` | `{"prefixes": [{"Prefix", "Count", "Total"}]}`. A missing `prefixes` is an empty list. |

Path segments are quoted with `seg()` (`urllib.parse.quote(..., safe="")`); query strings
with `urlencode()`. There's no pagination except the certificate pages, and no caching.

### Throttling and retries

- **Throttle.** `Throttle(interval)` holds an `asyncio.Lock`: every attempt (including
  retries) waits until at least `bgphe:interval` seconds have passed since the previous one
  started. So requests are serialized across all callers of the cell.
- **Retries.** Up to `MAX_RETRIES` (`3`) retries, 4 attempts in all:
  - A connection error or timeout (`aiohttp.ClientError`, `TimeoutError`) waits
    `backoff * 2**attempt` and retries; after the last attempt it raises
    `Unable to connect to bgp.he.net (<path>): <error>`.
  - HTTP `429`, `500`, `502`, `503`, `504` (`RETRY_CODES`) wait
    `max(backoff * 2**attempt, Retry-After)`. A `Retry-After` (seconds or an HTTP date) over
    `MAX_RETRY_AFTER` (`300` seconds) raises
    `bgp.he.net asked to wait <n> seconds before retrying <path> (HTTP <code>), not retrying.`
  - After the last attempt, the error response is returned and handled like any other.
- **Timeout.** `aiohttp.ClientTimeout(total=bgphe:timeout)` per attempt.
- **Body limit.** `MAX_BODY` (64 MiB). A larger `Content-Length`, or a streamed body that
  exceeds it, raises `The response from <path> is too large ...`.

### Errors

`_getAny()` decodes the body as UTF-8 (with replacement) and parses JSON (a non-JSON body is
`None`). For HTTP `>= 400` it raises `BgpHeApiError(errMesg(...), code=<status>)`:

| Response | Message |
| --- | --- |
| A JSON object with `error`, `message`, or `detail` | `bgp.he.net returned HTTP <code> for <path>: <value>` |
| 404 otherwise | `bgp.he.net returned HTTP 404 for <path>: not found.` |
| Non-HTML text | `bgp.he.net returned HTTP <code> for <path>: <first 300 chars>` |
| HTML or empty | `bgp.he.net returned HTTP <code> for <path>.` |

`getJson()` (every endpoint but RDAP) also requires a JSON object, and raises for a truthy
`error` key (`bgp.he.net returned an error for <path>: <error>`) or `"success": false`. Each
endpoint method then checks its key (`certificates`, `domains`, `entries` must be lists;
whois `data` must be a string) and raises `Unexpected response from <path>: ...` otherwise.
`rdapDomain()` accepts a list or object, and raises for an object with an `error`.

`BgpHeApiError` is a `stormlibpp.svc.SvcError` with an extra `code` (the HTTP status, or
`None`). No secrets pass through the client, so there's nothing to redact.

## norm.py

| Function | Behavior |
| --- | --- |
| `normFqdn(valu)` | Strip, lowercase, drop a trailing `.` and a leading `*.`, IDNA encode, and match `FQDN_RE` (at least two labels, at most 253 characters). Returns `None` if invalid. |
| `normDomain(valu)` | `normFqdn()`, raising `BadValu("Invalid domain: ...")`. |
| `normAsn(valu)` | An `int` or a digit string with an optional `AS` prefix, `0` to `2**32 - 1`. Rejects `bool`. |
| `normPrefix(valu)` | `ipaddress.ip_network(valu, strict=False)` to `{"addr", "len", "cidr", "version"}`. |
| `normPrefixes(rows)` | Valid, unique networks, sorted by (version, address, length). |
| `normHosts(prefix, data)` | Valid IPs, each with its sorted, unique, normalized hostnames. |
| `normSubdomains(domain, data)` | Normalized domains with their highest count, sorted by count descending. |

## certs.py

`heCert(item)` builds a certificate's details from one bgp.he.net entry:

1. Base64-decode `certificate_der` (strictly). No usable DER returns `None` (the entry is
   skipped), since a certificate can't be identified without it.
2. `isTbs(der)` checks whether the DER is a bare TBSCertificate: a Certificate's first child
   is a SEQUENCE, a TBSCertificate's is the `[0]` version (`0xA0`) or the serial INTEGER
   (`0x02`). CT logs store precertificates this way.
3. A certificate is parsed by `parseCert()`. A TBSCertificate is wrapped by `wrapTbs()` in a
   Certificate with the TBSCertificate's own signature algorithm and an empty BIT STRING
   signature, parsed the same way, and then its `sha256`/`sha1`/`md5`/`size`/`signature` are
   set to `None` and `tbs` to the TBSCertificate's SHA-256 (`parseTbs()`).
4. If parsing raises, `heFallback()` uses bgp.he.net's summary fields (`serial`, `subject`,
   `issuer`, `notbefore`/`notafter` in `%b %d %H:%M:%S %Y %z` form, and
   `subject_alternative_names`) and sets `error`.
5. `heMeta()` adds `he` (IDs, shards, log time, and a link to
   `https://bgp.he.net/certs/#_SearchTab?cert_id=<id>&shard_id=<shard>`), and `precert` is
   OR'd with bgp.he.net's `pre_cert` (the poison extension is removed from precertificates
   in CT logs).

`parseCert()` is best effort throughout: a malformed extension list yields no extensions, an
unsupported key type yields `{"algo": null, "size": null}`. Everything returned is
msgpack-safe (bytes are hex, times epoch millis) so it can cross Telepath. Serials are even
length big-endian hex (`serialHex()`), matching Synapse.

## rdap.py

- `records(payload)` splits the payload into the registry record and the registrar records
  (only `objectClassName` `domain`, which is also assumed when it's missing). No domain
  record raises `BadRdap`.
- `vcard()` reads a jCard into `{name: [(params, value)]}`; `_adr()`, `_tel()` (voice or
  untyped, or fax), and `_email()` pull out contact fields, passing every value through
  `whois.clean()`, so redacted values become `None`.
- `contact()` returns `None` when everything but the type is empty.
- `parseDomain()`: the registry record wins for times (by action, then record), nameservers
  and status (first record that has them). Contacts are taken from the registrar's records
  first. `asof` comes only from the registry record.
- `registrar()` prefers the registry's registrar entity, except `whois` (`port43`), which
  comes from the registrar's own record first.

## whois.py

Domain whois (`parseDomain()`), best effort over three shapes:

- ICANN style `Key: Value` lines.
- Sectioned records (ex. Nominet's `.uk`): a `Key:` line with no value starts a section, and
  more-indented lines are its values.
- Terse records (ex. DENIC's `.de`: `Nserver:`, `Changed:`).

Lines starting with `%`, `#`, `>>>`, or `--` end a section and are skipped. Keys are
lowercased and matched against `DOMAIN_KEYS` aliases; contact keys
(`<registrant|owner|holder|admin|administrative|tech|technical|billing> <field>`, with an
optional `registry ` prefix) are matched against `CONTACT_FIELDS`. The first value that cleans
(and, for times, parses) wins. Nominet's `[Tag = ...]` suffix is removed from the registrar.

ASN whois (`parseAsn()`): `blocks()` splits the text into objects (dropping `%`/`#` comments,
joining continuation lines, and stripping ` # ` trailing comments). If any object has
`ASNumber`, it's ARIN (`_arin()`), otherwise RPSL (`_rpsl()`), which finds the `aut-num`
object whose range covers the ASN and resolves the `org`, `abuse-c`/`admin-c`/`tech-c`, and
`mnt-irt` references through an index of the other objects. See
[Model](model.md#asns) for the field mapping.

Shared helpers:

| Helper | Behavior |
| --- | --- |
| `fixText()` | Undoes UTF-8 text that was decoded as Latin-1 (ex. from LACNIC), line by line. |
| `parseTime()` | Tries `TIME_FORMATS` in order after dropping trailing `UTC`/`GMT`/`Z` notes. Naive times are UTC. Returns epoch millis. |
| `clean()` | Collapses whitespace, strips trailing commas, and returns `None` for empty or redacted values (`REDACTED_RE`). |
| `emailOf()`, `phone()`, `joinParts()`, `uniq()` | Email extraction (lowercased), `tel:` removal, `, ` joining, order-preserving dedup. |

## The Storm package

{src}`svcs/bgphe/src/bgphesvc/pkgproto/slib.bgphe.yaml` defines:

- `synapse_version: ">=2.234.0,<3.0.0"`, `genopts.dotstorm: true` (Storm code in
  `storm/commands/*.storm` and `storm/modules/*.storm`), and the README as package docs.
- One perm, `slib.bgphe.user` (cortex gate).
- Four modules: `slib.bgphe.priv` with `asroot:perms: [[slib, bgphe, user]]`,
  `slib.bgphe.lib` and `slib.bgphe.model` with `perms: [[slib, bgphe, user]]`, and
  `slib.bgphe.util` with no perms.
- Six commands, each with `perms: [[slib, bgphe, user]]` and `cmdinputs`.

There are no configvars, no onload, and no tag prefixes. The service's `add` event (in
`defs.py`) creates the `meta:source`.

Command bodies share one pattern:

```text
init {
    $bgphe = $lib.import(slib.bgphe.lib)
    $util = $lib.import(slib.bgphe.util)
}

if $cmdopts.domains {
    spin |
    for $domain in $cmdopts.domains {
        for $n in $bgphe.certs($domain, ...) { yield $n }
    }
}
else {
    if ($node.form() != "inet:fqdn") {
        $lib.warn(...)
        if $cmdopts.yield { spin }
    } else {
        divert $cmdopts.yield $util.nodes($bgphe.certs($node.repr(), ...))
    }
}
```

`divert` needs a node generator, so `util.nodes()` re-yields what the `lib` emitters emit.
The work sits in the `else` because statements after an `if` block still run for a node that
leaves it.

Notes recorded in the modules:

- `slib.bgphe.lib`: functions that emit must end early with `stop`, since `return()` raises
  in an emitter.
- `slib.bgphe.model`: a `for` loop that runs while a node is in a function's pipeline sends
  the node downstream after its first iteration, ending the function early. So functions only
  yield a node when they don't loop, and loops call helpers (`seen`, `seenAt`, `addValu`,
  `refs`, `setOwner`) that edit the node in their own runtime.
- Some lines carry `noqa` markers for the Storm linter (ex. `M001`/`M002`/`M004` for 2.x model
  forms that 3.x changes, `R002`, `P001`). CI runs the linter with `storm_lint: block` for
  this service.

## Tests

Run them from the service directory:

```bash
cd svcs/bgphe
uv sync
uv run pytest
```

| File | Covers |
| --- | --- |
| `tests/fakebgphe.py` | `FakeBgpHe`, an aiohttp server on `127.0.0.1` serving every endpoint from mutable `state` (filled from `tests/data/*.json`, trimmed copies of real responses), paginating certificates like bgp.he.net (`state["pagesize"]`), recording `requests` and `headers`, and failing on demand (`state["errors"][path]`: HTTP codes, `(code, Retry-After)` tuples, or `"html"`). `bgpheSvc(test)` yields `(core, svc, fake)`: a Cortex with the service added and pointed at the fake, with `bgphe:interval` and `bgphe:backoff` set to `0`. |
| `tests/test_client.py` | Endpoint parsing, error messages, retries and `Retry-After`, the body limit, the throttle, and the helpers. |
| `tests/test_norm.py` | Certificate parsing (full, precertificate TBS, fallback, extensions, keys), input normalization, and the whois parsers. |
| `tests/test_rdap.py` | RDAP parsing, jCards, EPP status names, and RDAP/whois agreement. |
| `tests/test_svc.py` | The cell methods (paging, filters, lookups), the Telepath API's `TelepathRetn` errors, and that the README and `pkgproto/README.md` match. |
| `tests/test_bgphe_storm.py` | The package: load, `service.list`, the `meta:source`, every command and its messages, modeling, idempotency, the `lib` module, and perms. Also `assertVersionsMatch()` and `assertMainHelp()`. |
| `tests/test_live.py` | One request to each real endpoint, asserting on shapes. Skipped unless `SLIB_BGPHE_LIVE=1`. |

`tests/conftest.py` loads the `stormlibpp.testing` plugin, which fails a test that uses a
deprecated Synapse API and lets the fake on localhost bypass any proxy. `pyproject.toml`
turns `DeprecationWarning`s from `bgphesvc` into errors. See {doc}`/dev/testing`.

```bash
# The live tests, against the real bgp.he.net.
SLIB_BGPHE_LIVE=1 uv run pytest tests/test_live.py

# The Storm linter, as CI runs it.
uv run python -m synapse.tools.storm.lint src/
```
