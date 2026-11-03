# slib.bgphe

A Storm Service for [Hurricane Electric's BGP Toolkit](https://bgp.he.net) (bgp.he.net):

- **Certificates** from CT logs, by domain, by a domain's subdomains, or by IP/CIDR, modeled as `crypto:x509:cert` with their complete details.
- **Domain whois** (RDAP first, whois text as a fallback) as `inet:whois:rec`, with nameservers, contacts, and emails.
- **ASN whois** (from the ASN's RIR): the AS name and the organization (`ou:org`) behind it.
- **Originated prefixes** of an ASN (from HE's Super Looking Glass) as `inet:asnet4`/`inet:asnet6`.

bgp.he.net needs no account or API key. It has no documented API either: the service uses the JSON endpoints bgp.he.net's own pages call, so they may change without notice.

## Commands

| Command | Inputs | Models | `--yield` |
| --- | --- | --- | --- |
| `slib.bgphe.certs` | `inet:fqdn` | `crypto:x509:cert` (+ `crypto:key`) | the certificates |
| `slib.bgphe.certs.subdomains` | `inet:fqdn` | `inet:fqdn` | the domain and its subdomains |
| `slib.bgphe.certs.ip` | `inet:ipv4`, `inet:ipv6`, `inet:cidr4`, `inet:cidr6` | `inet:dns:a`, `inet:dns:aaaa` | the DNS nodes |
| `slib.bgphe.whois` | `inet:fqdn` | `inet:whois:rec`, `inet:whois:recns`, `inet:whois:contact`, `inet:whois:email` | the whois record |
| `slib.bgphe.asn` | `inet:asn` | `inet:asn` (`:name`, `:owner`), `ou:org` | the `ou:org` |
| `slib.bgphe.asn.prefixes` | `inet:asn` | `inet:asnet4`, `inet:asnet6` | the prefixes |

Every command takes values as arguments instead of inbound nodes, and then yields what it modeled. With inbound nodes, they're passed through unless `--yield` is given. Unsupported inbound nodes are passed through with a warning (or dropped, with `--yield`).

```
// Every certificate for a domain, then for each of its subdomains.
slib.bgphe.certs vertex.link --valid
inet:fqdn=vertex.link | slib.bgphe.certs.subdomains --yield | slib.bgphe.certs --no-precerts

// The hostnames on certificates that resolve to an IP (or a CIDR), then their certificates.
inet:ipv4=1.1.1.1 | slib.bgphe.certs.ip --yield | -> inet:fqdn | slib.bgphe.certs

// Whois, the org behind an ASN, and its prefixes.
inet:fqdn=vertex.link | slib.bgphe.whois --yield
slib.bgphe.asn 15169 --print
inet:asn=15169 | slib.bgphe.asn.prefixes --yield | +inet:asnet4
```

The `slib.bgphe.lib` module has the same functionality for use from Storm (ex. `$lib.import(slib.bgphe.lib).certs(vertex.link)`).

## Modeling

Every node the service models is linked to the `slib.bgphe` `meta:source` with a `-(seen)>` edge.

### Certificates

`slib.bgphe.certs` asks bgp.he.net for the certificates with the domain itself in their SANs or subject. bgp.he.net returns them 200 per request, with their DER, so the service parses every detail itself:

- Every prop the Synapse model has a place for: hashes, serial, subject, issuer, validity, version, signature (algorithm and value), `:selfsigned`, `:rsa:key`, `:ext:sans`, `:crl:urls`/`:ext:crls`, and the `:identities:*` (wildcards become their base domain).
- The public key as a `crypto:key` (deconflicted by its SPKI SHA-256), linked with `-(refs)>`.
- Everything else (key usage, EKUs, SKI/AKI, OCSP and CA issuer URLs, policies, bgp.he.net's certificate IDs, CT log shards, and a link to the certificate on bgp.he.net) in the `slib:bgphe` node data.
- `.seen` covers when bgp.he.net saw the certificate logged.

**Precertificates.** bgp.he.net only has the TBSCertificate of a precertificate (what's in the CT log, without its signature), so a precertificate has no fingerprints. Those `crypto:x509:cert` nodes are deconflicted by the TBSCertificate's SHA-256 (`(slib.bgphe, tbs, <sha256>)`) instead of `:sha256`, and have every other prop. Popular domains have far more precertificates than certificates, `--no-precerts` skips them.

`--limit` (default 200, at most 10000) caps the certificates per domain, and so the requests (one per 200). `--valid` only models currently valid certificates.

### Subdomains and IPs

`slib.bgphe.certs.subdomains` models the domain and its subdomains that have certificates as `inet:fqdn` nodes, `--print` lists them with their certificate counts. bgp.he.net limits how much it reads per CT log, a warning says when the list was truncated.

`slib.bgphe.certs.ip` models the hostnames on certificates that resolve to an IP (or any IP in a CIDR) as `inet:dns:a`/`inet:dns:aaaa`. bgp.he.net only returns a sample (up to ~1000 hostnames) per query, with no way to page through the rest, a warning says when there are more.

### Whois

`slib.bgphe.whois` models a domain's whois record as an `inet:whois:rec` with its `:created`, `:updated`, and `:expires` times, `:registrar`, and `:registrant:name`, plus:

- an `inet:whois:recns` for each nameserver,
- an `inet:whois:contact` for each registrant/admin/tech/billing contact that isn't redacted, and one for the registrar (`:orgname`, abuse `:email`/`:phone`, `:url`, `:whois:fqdn`, and the IANA ID as `:id`),
- an `inet:whois:email` for each contact's email. (Synapse also adds one for every email in the record's text.)

The record comes from **RDAP** when bgp.he.net has it (`/rdap/dns/<domain>`): the TLD registry's RDAP record, plus the registrar's own RDAP record it links to, which usually has the registrant and other contacts. RDAP often has more than the whois text, ex. the registrant (or the privacy service standing in for it) that the text redacts. The registry is preferred for the domain's dates, status, and nameservers, the registrar for contacts.

When bgp.he.net has no RDAP record for the domain (it returns HTTP 404, ex. for many ccTLDs like `.de` and `.co`), RDAP fails, or its response isn't a domain record, the whois **text** (`/whois/dns/<domain>`) is parsed instead. `--no-rdap` skips RDAP and always uses the text. Either way, the same props are set.

The record's `:text` is the whois text, or with RDAP, the RDAP records as indented JSON. The Synapse model lowercases `:text`, its `slib:bgphe` node data has the original, plus the parsed record, the `source` (`rdap` or `whois`), the raw RDAP payload, and `rdaperr` (why RDAP wasn't used). `$lib.debug` prints which source was used.

bgp.he.net caches whois records. A record's `:asof` is when the registry answered the query if the record says (RDAP's `last update of RDAP database` event, or whois text's `>>> Last update of whois database`), or its last update time, or now. So looking a domain up again doesn't make a new record unless the record changed.

Whois text has no single format, the parser handles ICANN style records, sectioned ones (ex. Nominet's `.uk`), and terse ones (ex. DENIC's `.de`), best effort.

### ASNs

`slib.bgphe.asn` parses ARIN records and the RPSL objects of RIPE, APNIC, AFRINIC, and LACNIC, and models:

- the `inet:asn`'s `:name` (the AS name, ex. `google`) and `:owner`,
- the `ou:org` (deconflicted by name, like `gen.ou.org`) with its `:country:code`,
- the record's raw text and everything parsed from it (handle, description, org ID and address, registration dates, status, and the abuse/admin/tech/NOC contacts and emails) in the `inet:asn`'s `slib:bgphe:whois` node data.

`slib.bgphe.asn.prefixes` models each prefix an ASN originates as an `inet:asnet4`/`inet:asnet6` and extends its `.seen` to now. bgp.he.net reports each prefix's visibility, which is stored in its `slib:bgphe` node data as `{"count": ..., "total": ...}`. HE doesn't document these numbers, they appear to be how many of the Super Looking Glass's peers see the route originated by the ASN, out of how many carry the prefix.

## Permissions

`slib.bgphe.user` allows using every command and the `slib.bgphe.lib` module. Users don't need `service.get`, the privileged `slib.bgphe.priv` module talks to the service. Node edits run as the user, so they also need permission to make them.

## Configuration

The service's cell config:

| Option | Default | Description |
| --- | --- | --- |
| `bgphe:url` | `https://bgp.he.net` | The base URL of the BGP Toolkit. |
| `bgphe:interval` | `1.0` | The minimum number of seconds between two requests. |
| `bgphe:timeout` | `60` | Timeout, in seconds, for a single request. |
| `bgphe:backoff` | `2.0` | The base, in seconds, of the exponential backoff between retries. |

bgp.he.net is a free resource, please keep the interval polite. Requests are serialized, identify the service in their `User-Agent`, and HTTP 429/5xx responses are retried (honoring `Retry-After`).
