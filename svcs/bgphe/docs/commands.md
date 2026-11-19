# Commands

The `slib.bgphe` package has six commands. All of them require the `slib.bgphe.user`
permission, plus permission to make the node edits they do (see
[Deployment](deployment.md#permissions)). The package has no settings or admin commands: the
service's only configuration is its cell config (see
[Deployment](deployment.md#cell-configuration)).

## Common behavior

Every command works the same way:

- **Values or inbound nodes.** Each command takes values (domains, IPs/CIDRs, or ASNs) as
  positional arguments. When values are given, the command looks them up once (not once per
  inbound node), yields the nodes it modeled, and drops any inbound nodes. Without values, it
  looks up each inbound node.
- **Inbound nodes are passed through** unless `--yield` is given, in which case the modeled
  nodes are yielded instead (via `divert`).
- **Unsupported inbound nodes** (a form the command doesn't take) are passed through with a
  warning, ex. `slib.bgphe.certs: Unable to look up inet:ipv4 1.2.3.4, it needs an
  inet:fqdn.`, or dropped with `--yield`.
- **Errors are warnings.** A failed lookup (an invalid value, an error from bgp.he.net, or an
  unexpected service error) prints `slib.bgphe: <what> failed: <mesg>` as a warning and the
  command carries on with the next value or node. Commands don't raise.
- **Provenance.** Every node modeled is linked from the `slib.bgphe` `meta:source` with a
  `-(seen)>` edge (see [Model](model.md#provenance)).

Values are normalized by the service before any request is made:

| Kind | Accepts | Normalization |
| --- | --- | --- |
| Domain | An FQDN with at least two labels | Stripped, lowercased, trailing `.` and a leading `*.` removed, IDNA encoded. Anything else is `Invalid domain: '<valu>'`. |
| IP or CIDR | An IPv4/IPv6 address or network | An IP is its `/32` (or `/128`). Host bits are dropped (`10.1.2.3/8` is `10.0.0.0/8`). Anything else is `Invalid IP or CIDR: '<valu>'`. |
| ASN | `15169`, `"15169"`, `AS15169` (any case) | `0` to `4294967295`. Anything else is `Invalid ASN: '<valu>'`. |

## Certificates

### slib.bgphe.certs

Look up the CT log certificates for domains in bgp.he.net and model their complete details.
It matches certificates with the domain **itself** in their SANs or subject, not its
subdomains (use [`slib.bgphe.certs.subdomains`](#slibbgphecertssubdomains) for those).

```text
slib.bgphe.certs [domains ...] [--limit <int>] [--valid] [--no-precerts] [--yield]
```

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `domains` | str, `nargs=*` | | Domains to look up instead of the inbound nodes. Yields the certificates. |
| `--limit` | int | `200` | The most certificates per domain. Capped at `10000`. Must be a positive integer. bgp.he.net returns 200 certificates per request, so this also caps the requests (`ceil(limit / 200)`). |
| `--valid` | flag | `false` | Only model certificates that are currently valid (`notbefore <= now <= notafter`). |
| `--no-precerts` | flag | `false` | Skip precertificates. |
| `--yield` | flag | `false` | Yield the `crypto:x509:cert` nodes instead of the inbound nodes. |

**Inputs:** `inet:fqdn`.

**Models:** a `crypto:x509:cert` per certificate, with every prop the model has a place for,
its public key as a `crypto:key` (linked with `-(refs)>`), and the full parsed details in its
`slib:bgphe` node data. See [Model](model.md#certificates).

Duplicates across pages (same SHA-256, or the same TBSCertificate SHA-256 for
precertificates) are modeled once. Certificates removed by `--valid` or `--no-precerts`
still count towards the requests but not towards `--limit`.

**Messages:**

| When | Message |
| --- | --- |
| No certificate was modeled | warning: `slib.bgphe: bgp.he.net has no matching certificates for <domain>.` |
| `--limit` was reached with more left | `slib.bgphe: Modeled <n> of the <total> certificates for <domain>, raise --limit for more.` |
| `$lib.debug` is set | `slib.bgphe: <domain>: <n> certificates (<skipped> filtered, <invalid> unparsable) from <pages> pages, of <total> in bgp.he.net.` Unparsable entries (no usable DER) are dropped. |

**Examples:**

```text
// Every currently valid certificate for vertex.link.
slib.bgphe.certs vertex.link --valid

// Up to 1000 certificates (5 requests), no precertificates, yielding the certificates.
inet:fqdn=vertex.link | slib.bgphe.certs --limit 1000 --no-precerts --yield

// The certificates of a domain and each of its subdomains.
inet:fqdn=vertex.link | slib.bgphe.certs.subdomains --yield | slib.bgphe.certs
```

### slib.bgphe.certs.subdomains

Find a domain's subdomains that have CT log certificates in bgp.he.net, and model them (and
the domain itself, when it has certificates) as `inet:fqdn` nodes.

```text
slib.bgphe.certs.subdomains [domains ...] [--print] [--yield]
```

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `domains` | str, `nargs=*` | | Domains to look up instead of the inbound nodes. Yields the subdomains. |
| `--print` | flag | `false` | Print a table of each domain and its certificate count. |
| `--yield` | flag | `false` | Yield the `inet:fqdn` nodes (the domain and its subdomains) instead of the inbound nodes. |

**Inputs:** `inet:fqdn`.

**Models:** an `inet:fqdn` for each domain bgp.he.net lists, emitted with the most
certificates first (ties by name). One request (`/certs/api/list`) per domain.

**Messages:**

| When | Message |
| --- | --- |
| Nothing found | warning: `slib.bgphe: bgp.he.net has no certificates for <domain> or its subdomains.` |
| bgp.he.net truncated the list | warning: `slib.bgphe: bgp.he.net truncated the subdomains of <domain>, some may be missing.` |
| `--print` | `<n> domains with <certs> certificates under <domain>:`, then a `domain`/`certs` table. |

bgp.he.net limits how many (subdomain, certificate) rows it reads per CT log shard, hence the
truncation warning.

```text
slib.bgphe.certs.subdomains vertex.link --print

inet:fqdn=vertex.link | slib.bgphe.certs.subdomains --yield
```

### slib.bgphe.certs.ip

Find the hostnames on CT log certificates that resolve to an IP (or to any IP in a CIDR), and
model them as `inet:dns:a`/`inet:dns:aaaa` nodes.

```text
slib.bgphe.certs.ip [valus ...] [--print] [--yield]
```

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `valus` | str, `nargs=*` | | IPs or CIDRs to look up instead of the inbound nodes. Yields the DNS nodes. |
| `--print` | flag | `false` | Print each IP and its hostnames, ex. `8.8.8.4: sabievtimbers.co.za, test.radium.red`. |
| `--yield` | flag | `false` | Yield the `inet:dns:a`/`inet:dns:aaaa` nodes instead of the inbound nodes. |

**Inputs:** `inet:ipv4`, `inet:ipv6`, `inet:cidr4`, `inet:cidr6`.

**Models:** an `inet:dns:a` (IPv4) or `inet:dns:aaaa` (IPv6) of `(<hostname>, <ip>)` for each
hostname bgp.he.net lists on each IP. Hostnames are normalized like domains (so a `*.`
wildcard becomes its base domain), invalid ones are dropped. One request per value.

**Messages:**

| When | Message |
| --- | --- |
| Nothing found | warning: `slib.bgphe: bgp.he.net has no certificate hostnames on <cidr>.` |
| bgp.he.net has more | warning: `slib.bgphe: bgp.he.net only returned a sample of the <total> certificate hostnames on <cidr>.` |

bgp.he.net returns a sample (up to ~1000 hostnames) per query with no way to page through the
rest. Query smaller prefixes to see more.

```text
slib.bgphe.certs.ip 8.8.8.8 --print

// The hostnames on certificates that resolve to an IP, then their certificates.
inet:ipv4=1.1.1.1 | slib.bgphe.certs.ip --yield | -> inet:fqdn | slib.bgphe.certs

inet:cidr4=8.8.8.0/24 | slib.bgphe.certs.ip --yield
```

## Whois

### slib.bgphe.whois

Look up a domain's whois record and model it as an `inet:whois:rec`, with its nameservers,
contacts, and emails.

```text
slib.bgphe.whois [domains ...] [--print] [--no-rdap] [--yield]
```

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `domains` | str, `nargs=*` | | Domains to look up instead of the inbound nodes. Yields the whois records. |
| `--print` | flag | `false` | Print the raw whois text (or, with RDAP, the RDAP records as indented JSON). |
| `--no-rdap` | flag | `false` | Skip RDAP and only use the whois text. |
| `--yield` | flag | `false` | Yield the `inet:whois:rec` nodes instead of the inbound nodes. |

**Inputs:** `inet:fqdn`.

**Source selection.** RDAP (`/rdap/dns/<domain>`) is tried first. The whois text
(`/whois/dns/<domain>`) is used instead when:

- bgp.he.net has no RDAP record for the domain (it returns HTTP 404, ex. for many ccTLDs
  such as `.de` and `.co`),
- the RDAP request fails for any other reason, or
- the RDAP response has no domain record (`Unusable RDAP response for <domain>: ...`).

If the whois text lookup fails too, the warning gives both reasons:
`No RDAP or whois record for <domain>. RDAP: <why> Whois: <why>`. With `--no-rdap`, only the
whois text error is reported.

**Models:** `inet:whois:rec`, `inet:whois:recns`, `inet:whois:contact` (registrant, admin,
tech, billing, and registrar), and `inet:whois:email`. See
[Model](model.md#domain-whois). Either source sets the same props.

**Messages:** with `$lib.debug` set, `slib.bgphe: The whois of <domain> is from <rdap|whois>.`
and, when RDAP wasn't used, `slib.bgphe: RDAP wasn't used: <why>`.

```text
slib.bgphe.whois vertex.link

slib.bgphe.whois vertex.link --no-rdap --print

inet:fqdn=vertex.link | slib.bgphe.whois --yield
```

## ASNs

### slib.bgphe.asn

Look up an ASN's whois record (from its RIR, via bgp.he.net) and model the AS name and the
organization responsible for it.

```text
slib.bgphe.asn [asns ...] [--print] [--yield]
```

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `asns` | str, `nargs=*` | | ASNs (ex. `15169` or `AS15169`) to look up instead of the inbound nodes. Yields the `inet:asn` nodes. |
| `--print` | flag | `false` | Print a summary of each record. |
| `--yield` | flag | `false` | Yield the `ou:org` nodes instead of the inbound `inet:asn` nodes (values always yield the `inet:asn` nodes). |

**Inputs:** `inet:asn`.

**Models:** the `inet:asn`'s `:name` and `:owner`, the `ou:org` (deconflicted by name with
`gen.ou.org`, with `:country:code`), and the parsed record and raw text in the `inet:asn`'s
`slib:bgphe:whois` node data. See [Model](model.md#asns).

:::{note}
What is yielded depends on how the command is called: with values it yields the **`inet:asn`**
nodes. With inbound nodes and `--yield`, it yields the **`ou:org`** nodes (nothing, for a
record with no organization name).
:::

**`--print`** prints one line per record, then one per contact, with `-` for missing values:

```text
AS15169 GOOGLE: Google LLC (US), arin, registered 2000-03-30, updated 2012-02-24
    abuse: ABUSE5250-ARIN Abuse network-abuse@google.com +1-650-253-0000
    tech: ZG39-ARIN Google LLC arin-contact@google.com +1-650-253-0000
```

ARIN records and the RPSL objects of RIPE, APNIC, AFRINIC, and LACNIC are parsed (see
[Internals](internals.md#whoispy)).

```text
slib.bgphe.asn 15169 --print

inet:asn=15169 | slib.bgphe.asn --yield
```

### slib.bgphe.asn.prefixes

Look up the prefixes an ASN originates, according to HE's Super Looking Glass, and model them
as `inet:asnet4`/`inet:asnet6` nodes.

```text
slib.bgphe.asn.prefixes [asns ...] [--yield]
```

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `asns` | str, `nargs=*` | | ASNs (ex. `15169` or `AS15169`) to look up instead of the inbound nodes. Yields the prefixes. |
| `--yield` | flag | `false` | Yield the `inet:asnet4`/`inet:asnet6` nodes instead of the inbound nodes. |

**Inputs:** `inet:asn`.

**Models:** an `inet:asnet4`/`inet:asnet6` of `(<asn>, <prefix>)` per prefix, IPv4 first,
with `.seen` extended to now and the prefix's visibility in its `slib:bgphe` node data as
`{"count": ..., "total": ...}`. See [Model](model.md#originated-prefixes).

**Messages:**

| When | Message |
| --- | --- |
| `$lib.debug` is set | `slib.bgphe: AS<asn> originates <v4> IPv4 and <v6> IPv6 prefixes.` |
| No prefixes | warning: `slib.bgphe: AS<asn> doesn't originate any prefixes.` |

```text
slib.bgphe.asn.prefixes 15169

inet:asn=15169 | slib.bgphe.asn.prefixes --yield | +inet:asnet4
```
