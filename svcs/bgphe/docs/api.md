# API

The service has two APIs: the `slib.bgphe.lib` Storm module, for Storm code, and the cell's
Telepath API, which only the package's privileged module calls.

## Storm modules

| Module | Perms to import | Runs as | Purpose |
| --- | --- | --- | --- |
| `slib.bgphe.lib` | `slib.bgphe.user` | the user | The user API: query, model, and emit or return nodes. |
| `slib.bgphe.model` | `slib.bgphe.user` | the user | The node edits (see [Model](model.md)). |
| `slib.bgphe.priv` | (internal) | root, for users with `slib.bgphe.user` (`asroot:perms`) | The only module that calls the service. |
| `slib.bgphe.util` | none | the user | Shared helpers for the commands. |

### The slib.bgphe.lib module

```text
$bgphe = $lib.import(slib.bgphe.lib)
```

Each function queries the service, models the results, and emits (or returns) the nodes.
Errors are printed as warnings (`slib.bgphe: <what> failed: <mesg>`), never raised: an
emitter stops, a function that returns returns `null`.

| Function | Kind | Returns / emits |
| --- | --- | --- |
| `certs(domain, limit=(200), valid=(false), precerts=(true))` | emitter | The `crypto:x509:cert` nodes. |
| `subdomains(domain, print=(false))` | emitter | The `inet:fqdn` nodes, most certificates first. |
| `hosts(valu, print=(false))` | emitter | The `inet:dns:a`/`inet:dns:aaaa` nodes for an IP or CIDR. |
| `whois(domain, print=(false), rdap=(true))` | returns | The `inet:whois:rec` node, or `null`. |
| `asn(valu, print=(false))` | returns | `({"asn": <inet:asn node>, "org": <ou:org node or null>})`, or `null`. |
| `prefixes(valu)` | emitter | The `inet:asnet4`/`inet:asnet6` nodes. |
| `whoisNodes(domain, print=(false), rdap=(true))` | emitter | The `inet:whois:rec` node of `whois()`. |
| `asnNodes(valu, print=(false), org=(false))` | emitter | The `inet:asn` node of `asn()`, or with `org=(true)` its `ou:org`. |

The arguments mean the same as the commands' options (`precerts=(false)` is
`--no-precerts`, `rdap=(false)` is `--no-rdap`). The functions print the same messages as the
commands (see [Commands](commands.md)), ex. `prefixes()` prints the IPv4/IPv6 counts when
`$lib.debug` is set.

```text
$bgphe = $lib.import(slib.bgphe.lib)

for $cert in $bgphe.certs(vertex.link, valid=(true)) { $lib.print($cert.repr()) }

$rec = $bgphe.whois(microsoft.com)
if $rec { $lib.print($rec.props.registrar) }

$res = $bgphe.asn(15169)
if ($res and $res.org) { $lib.print($res.org.props.name) }
```

### The slib.bgphe.priv module

Thin wrappers that return (or emit, for `certs`) the service's `TelepathRetn` dicts
unchanged:

| Function | Calls |
| --- | --- |
| `certs(domain, limit=(200), valid=(false), precerts=(true))` | `certs(domain, limit=..., valid=..., precerts=...)`, emits each item |
| `subdomains(domain)` | `subdomains(domain)` |
| `hosts(valu)` | `hosts(valu)` |
| `whoisDomain(domain, rdap=(true))` | `whoisDomain(domain, useRdap=rdap)` |
| `whoisAsn(asn)` | `whoisAsn(asn)` |
| `prefixes(asn)` | `prefixes(asn)` |

It gets the service with `$lib.service.get("slib.bgphe")`, which needs `service.get` unless
the module runs as root. Calling the service directly as an ordinary user fails with
`must have permission service.get`.

### The slib.bgphe.util module

| Function | Purpose |
| --- | --- |
| `failed(retn, what)` | Warn `slib.bgphe: <what> failed: <mesg>` and return `true` if `retn.status` is false. |
| `table(columns, rows)` | Print a `$lib.tabular` table; `columns` is a list of `(name, width)`. |
| `str(valu)` | The value, or `-` for `null`. |
| `date(valu)` | An epoch millis time as `%Y-%m-%d`, or `-`. |
| `nodes(items)` | Yield the nodes an emitter emits, so they can be `divert`ed. |

## Telepath API

`BgpHeCellApi` ({src}`svcs/bgphe/src/bgphesvc/api.py`) subclasses `stormlibpp.svc.RetnApi`,
`synapse.lib.cell.CellApi`, and `synapse.lib.stormsvc.StormSvc`:

```python
RETN_METHS = ("subdomains", "hosts", "whoisDomain", "whoisAsn", "prefixes")
GENR_METHS = ("certs",)
```

`RETN_ERRORS` isn't overridden, so it is the default `(SvcError,)`. The service's own errors,
`BgpHeApiError` (bgp.he.net failed) and `BgpHeSvcError` (a bad value), are both `SvcError`s.

### TelepathRetn

Every method returns (or, for `certs`, yields) a `TelepathRetn` from StormLib++
(`stormlibpp.telepath`):

```text
{"status": true, "mesg": "", "data": { ... }}
```

| Key | Meaning |
| --- | --- |
| `status` | `true` on success, `false` on error. |
| `mesg` | `""` on success, the error message otherwise. |
| `data` | The cell method's return value on success, `null` on error. |

Methods never raise. `RetnApi` turns an exception into `status=false`:

| Error | `mesg` |
| --- | --- |
| A `SvcError` (`BgpHeApiError`, `BgpHeSvcError`), or a Synapse `AuthDeny` | The error's own message, ex. `Invalid ASN: 'ASX'`, `bgp.he.net returned HTTP 400 for /whois/as99: unallocated asn`. |
| `ValueError`, `TypeError`, or Synapse `BadArg` | `Invalid input: <error>` |
| Anything else | `Unexpected error: <type>: <error>`, and the traceback is logged as `Unexpected error in BgpHeCellApi.<method>.` |

`_retnRedact()` isn't overridden: the service has no secrets to scrub.

For the generator, `certs`, each item is wrapped in its own `TelepathRetn`. An error ends the
generator after one `status=false` item, so a consumer should stop at the first failure.

The service also declares, as a `StormSvc`, its name (`slib.bgphe`), version, the
`slib.bgphe` package, and the `add` event that creates the `meta:source`.

### certs

```python
certs(domain: str, limit: int = 200, valid: bool = False, precerts: bool = True)
```

A generator of the CT log certificates with `domain` itself in their SANs or subject.
`limit` must be a positive `int` (not a `bool`) and is capped at `MAX_CERTS` (`10000`).
Pages of 200 are requested until `limit` certificates were yielded, the last page was read,
or a page was empty.

Yields, for each certificate:

```text
{"type": "cert", "cert": { ... }}
```

where `cert` is the parsed certificate (see [Model](model.md#certificate-node-data)), then
exactly one summary:

```json
{"type": "summary", "domain": "gormo.co", "total": 12, "returned": 2, "skipped": 0,
 "invalid": 0, "pages": 1, "more": true}
```

| Key | Meaning |
| --- | --- |
| `domain` | The normalized domain. |
| `total` | bgp.he.net's `pagination.total_certificates` from the first page. |
| `returned` | Certificates yielded. |
| `skipped` | Certificates removed by `valid` or `precerts=False`. |
| `invalid` | Entries without a usable DER (not a dict, or a DER that doesn't decode or parse), which are dropped. `slib.bgphe.certs` reports it as `unparsable` with `$lib.debug`. |
| `pages` | Pages requested. |
| `more` | Whether `limit` stopped the lookup with certificates left. |

Duplicates (by SHA-256, or `tbs:<sha256>` for precertificates) are dropped and not counted.

### subdomains

```python
subdomains(domain: str) -> dict
```

```json
{"domain": "gormo.co",
 "domains": [{"fqdn": "url.gormo.co", "certs": 13}, {"fqdn": "gormo.co", "certs": 12},
             {"fqdn": "www.gormo.co", "certs": 10}, {"fqdn": "docs.gormo.co", "certs": 2}],
 "certs": 27, "truncated": false}
```

`domains` is sorted by `certs` descending, then name. A domain listed twice keeps its highest
count. `certs` is bgp.he.net's `total_certificates`; `truncated` its `truncated` flag.

### hosts

```python
hosts(valu: str) -> dict
```

`valu` is an IP or CIDR.

```json
{"prefix": "8.8.8.0/24",
 "entries": [{"ip": "8.8.8.4", "version": 4, "fqdns": ["sabievtimbers.co.za", "test.radium.red"]},
             {"ip": "8.8.8.8", "version": 4, "fqdns": ["1w3.cc", "8.8.8.8.nip.io", "..."]}],
 "ips": 2, "hostnames": 73882, "truncated": true}
```

`entries` are sorted by IP version then address, `fqdns` sorted and deduplicated. `ips` and
`hostnames` are bgp.he.net's `total_ips` and `total_hostnames`, which can be much more than
returned when `truncated` (its `has_more`) is set.

### whoisDomain

```python
whoisDomain(domain: str, useRdap: bool = True) -> dict
```

```text
{"fqdn": "microsoft.com", "source": "rdap", "text": "[\n [ ...", "rec": { ... },
 "rdap": [ ... ], "rdaperr": null}
```

| Key | Meaning |
| --- | --- |
| `fqdn` | The normalized domain. |
| `source` | `rdap` or `whois`. |
| `text` | The whois text, or the RDAP payload as JSON (`indent=1`). |
| `rec` | The parsed record (below). |
| `rdap` | The raw RDAP payload, or `null`. |
| `rdaperr` | Why RDAP wasn't used, or `null` (also when `useRdap=False`). |

`rec` has the same keys from either source:

```text
{"fqdn": "...", "asof": 1793443379000, "created": ..., "updated": ..., "expires": ...,
 "registrar": {"name": ..., "url": ..., "whois": ..., "ianaid": ..., "email": ..., "phone": ...},
 "registrant": "Microsoft Corporation",
 "status": ["clientDeleteProhibited", "..."],
 "nameservers": ["ns1-39.azure-dns.com", "..."],
 "dnssec": "unsigned",
 "contacts": [{"type": "registrant", "id": ..., "name": ..., "orgname": ..., "address": ...,
               "city": ..., "state": ..., "postalcode": ..., "country": ...,
               "phone": ..., "fax": ..., "email": ...}],
 "emails": ["..."]}
```

Times are epoch millis (or `null`). See [Model](model.md#domain-whois) for the field sources.
When RDAP isn't usable and the whois text fails too, the error is
`No RDAP or whois record for <domain>. RDAP: <why> Whois: <why>` (with the whois error's HTTP
code).

### whoisAsn

```python
whoisAsn(asn: int | str) -> dict
```

```text
{"asn": 15169, "text": "<the RIR whois text>", "rec": { ... }}
```

`asn` accepts `15169`, `"15169"`, or `"AS15169"`. See [Model](model.md#asns) for `rec`.

### prefixes

```python
prefixes(asn: int | str) -> dict
```

```json
{"asn": 15169,
 "prefixes": [{"prefix": "8.8.4.0/24", "version": 4, "count": 1061, "total": 1065}, "..."],
 "v4": 4, "v6": 2}
```

`prefixes` is deduplicated and sorted by IP version, address, and length. Rows that aren't
valid networks are dropped; `count`/`total` are `null` unless integers. An ASN with no
`prefixes` in the response returns an empty list.
