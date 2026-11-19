# Data Model

All modeling happens in the `slib.bgphe.model` Storm module
({src}`svcs/bgphe/src/bgphesvc/pkgproto/storm/modules/slib.bgphe.model.storm`), from the
plain dicts the service returns (see [API](api.md#telepath-api)). Node edits run as the
calling user. The service applies no tags: it has no tag prefixes or other settings.

Props are set with `?=` (skipped if the value doesn't norm) unless noted. Array props are
added to one value at a time with `?+=`, so existing values are kept.

## Provenance

The service's `meta:source` node:

| Prop | Value |
| --- | --- |
| guid | `5cb263934371467b8844e789c39f81aa` (`SVC_GUID` in {src}`svcs/bgphe/src/bgphesvc/defs.py`) |
| `:name` | `bgp.he.net` |
| `:type` | `slib.bgphe` |
| `:url` | `https://bgp.he.net` |

It is created by the service's `add` event (once, as root). Every node the package models is
linked from it with a `-(seen)>` edge, and the edge's helper also (re)sets `:name`, so the node
is created as the user if it is missing.

```text
meta:source=5cb263934371467b8844e789c39f81aa -(seen)> *
```

## Edges and node data

| Edge / node data key | On | Contents |
| --- | --- | --- |
| `meta:source -(seen)>` | every modeled node | Provenance, see above. |
| `crypto:x509:cert -(refs)> crypto:key` | certificates | The certificate's public key. |
| `slib:bgphe` | `crypto:x509:cert` | The full parsed certificate (see [below](#certificate-node-data)). |
| `slib:bgphe` | `inet:whois:rec` | The whois result: `{"fqdn", "source", "text", "rec", "rdap", "rdaperr"}` (see [API](api.md#whoisdomain)). |
| `slib:bgphe:whois` | `inet:asn` | The ASN whois result: `{"asn", "text", "rec"}` (see [API](api.md#whoisasn)). |
| `slib:bgphe` | `inet:asnet4`/`inet:asnet6` | The prefix's visibility, `{"count": ..., "total": ...}`. |

Node data is overwritten on every lookup.

## Certificates

`slib.bgphe.certs` models each certificate as a `crypto:x509:cert`.

### Deconfliction

| Certificate | Node |
| --- | --- |
| A certificate (has a DER with a signature) | `crypto:x509:cert=({"sha256": <sha256 of the DER>})` |
| A precertificate (bgp.he.net has only its TBSCertificate) | `crypto:x509:cert=(slib.bgphe, tbs, <sha256 of the TBSCertificate>)` |

bgp.he.net only has the TBSCertificate of a precertificate (the CT log entry, without the
signature), so a precertificate has no fingerprints: `:sha256`, `:sha1`, `:md5`, `:file`, and
`:signature` aren't set. Its node is a guid of the TBSCertificate's SHA-256 instead, so looking
it up again finds the same node. Every other prop is set. Use `--no-precerts` to skip them.

Repeated lookups are idempotent: the same certificate maps to the same node.

### Props

| Prop | From | Notes |
| --- | --- | --- |
| `:sha256`, `:sha1`, `:md5` | Hashes of the DER | Set with `=`. Certificates only. |
| `:file` | `sha256:<sha256>` | A `file:bytes` for the DER. Certificates only. |
| `:serial` | The serial number | Hex. Synapse zero-pads it. Negative serials (seen in CT logs) use their two's complement DER bytes. |
| `:subject`, `:issuer` | The RFC 4514 DN | ex. `CN=gormo.co`, `CN=YE1,O=Let's Encrypt,C=US` |
| `:validity:notbefore`, `:validity:notafter` | Validity period | |
| `:version` | X.509 version value | `2` is v3. |
| `:algo` | Signature algorithm OID | ex. `1.2.840.10045.4.3.3` |
| `:signature` | Signature bytes, hex | Certificates only. |
| `:selfsigned` | Subject DN equals issuer DN, and the AKI is absent or equals the SKI | Set with `=`. |
| `:rsa:key` | `(modulus hex, exponent)` | RSA keys only. |
| `:ext:sans` | SubjectAltName | `(type, value)`: `dns`, `email`, `uri`, `ip`, `dirname`, `registeredid`, `othername`. |
| `:crl:urls` | CRL distribution point URIs | |
| `:ext:crls` | Same, as `(uri, <url>)` SANs | |
| `:identities:fqdns` | DNS SANs and subject CNs | Lowercased. A `*.` wildcard becomes its base domain. |
| `:identities:emails` | Email SANs, and CNs with an `@` | Lowercased. |
| `:identities:ipv4s`, `:identities:ipv6s` | IP SANs, and CNs that are IPs | |
| `:identities:urls` | URI SANs | |
| `.seen` | bgp.he.net's `timestamp` (when it saw the certificate logged) | Extended, not replaced. |

`:version`, `:algo`, `:signature`, `:selfsigned`, `:rsa:key`, and the `crypto:key` are only
set when the DER parsed. When it doesn't (see [Internals](internals.md#certspy)), the
details come from bgp.he.net's summary fields: serial, subject, issuer, validity, and SANs.

### The public key

The certificate's public key is a `crypto:key`, deconflicted by its SubjectPublicKeyInfo
SHA-256, so a key reused across renewals is one node:

| Prop | Value |
| --- | --- |
| guid | `({"public:sha256": <sha256 of the SPKI DER>})` |
| `:public:sha256` | SHA-256 of the SPKI DER |
| `:public:sha1` | SHA-1 of the SPKI DER |
| `:public` | The SPKI DER, hex |
| `:algorithm` | `rsa`, `ec`, `dsa`, `ed25519`, or `ed448` |

The certificate refers to it: `crypto:x509:cert -(refs)> crypto:key`. No key is modeled when
the key type isn't one `cryptography` supports.

### Certificate node data

The `slib:bgphe` node data holds everything parsed, including what the model has no place
for. An example (trimmed):

```json
{
  "sha256": "869203ef...", "sha1": "ab551042...", "md5": "30cca418...", "size": 910,
  "version": 2,
  "serial": "05cb8356da8d277b8bbdd4ec4c01d2bdeda9",
  "subject": {"dn": "CN=gormo.co", "attrs": {"cn": ["gormo.co"]}},
  "issuer": {"dn": "CN=YE1,O=Let's Encrypt,C=US",
             "attrs": {"c": ["US"], "o": ["Let's Encrypt"], "cn": ["YE1"]}},
  "notbefore": 1783185381000, "notafter": 1790961380000,
  "sigalgo": {"oid": "1.2.840.10045.4.3.3", "name": "ecdsa-with-SHA384", "hash": "sha384"},
  "signature": "3065...",
  "pubkey": {"algo": "ec", "size": 256, "curve": "secp256r1",
             "spki": "3059...", "sha256": "d6ffca4c...", "sha1": "2c3d30b5..."},
  "selfsigned": false,
  "identities": {"fqdns": ["gormo.co"], "emails": [], "ipv4s": [], "ipv6s": [], "urls": []},
  "sans": [["dns", "*.gormo.co"], ["dns", "gormo.co"]],
  "ca": false, "pathlen": null,
  "keyusage": ["digital_signature"],
  "extkeyusage": [{"oid": "1.3.6.1.5.5.7.3.1", "name": "serverAuth"}],
  "ski": "94ed6c0d...", "aki": "bb20ca47...",
  "crls": ["http://ye1.c.lencr.org/42.crl"], "ocsp": [], "caissuers": ["http://ye1.i.lencr.org/"],
  "policies": ["2.23.140.1.2.1"],
  "precert": false,
  "he": {"id": 1669182371, "shard": 113,
         "shards": ["tiger2026h2", "wyvern2026h2", "sphinx2026h2", "trustasia2026a", "trustasia2026b"],
         "logged": 1783188896409, "precert": false,
         "url": "https://bgp.he.net/certs/#_SearchTab?cert_id=1669182371&shard_id=113"}
}
```

- `pubkey` has `rsa: {"mod": <hex>, "exp": <int>}` for RSA keys, and `curve` for EC keys.
- `subject.attrs`/`issuer.attrs` use short names (`cn`, `o`, `ou`, `c`, `st`, `l`, `street`,
  `postalcode`, `email`, `serialnumber`, `dc`, `businesscategory`, `jurisdiction:c`,
  `jurisdiction:st`, `jurisdiction:l`, `organizationidentifier`, `givenname`, `surname`,
  `title`), and the dotted OID for anything else.
- A precertificate has `sha256`/`sha1`/`md5`/`size`/`signature` set to `null` and a `tbs`
  key (the TBSCertificate's SHA-256).
- A certificate whose DER couldn't be parsed has only the hashes, `serial`, `subject`,
  `issuer` (`dn` only), `notbefore`, `notafter`, `sans`, `identities`, `precert`, `he`, and
  `error` (`Unable to parse certificate: <why>`).
- `precert` is true when the certificate has the CT poison extension
  (`1.3.6.1.4.1.11129.2.4.3`), is a bare TBSCertificate, or bgp.he.net flags it
  (`pre_cert`).

### Upstream fields

From each entry of `/certs/api/domain`'s `certificates`:

| bgp.he.net field | Used for |
| --- | --- |
| `certificate_der` | Base64 DER, the source of every detail. Entries without a usable DER are skipped. |
| `timestamp` | `.seen`, `he.logged` (epoch millis, when it was logged) |
| `id`, `shard_id` | `he.id`, `he.shard`, and `he.url` |
| `shards` (or `shard`) | `he.shards`, the CT log shards |
| `pre_cert` | `he.precert`, and `precert` |
| `serial`, `subject`, `issuer`, `notbefore`, `notafter`, `subject_alternative_names` | Only when the DER can't be parsed. |

## Subdomains

`slib.bgphe.certs.subdomains` models `inet:fqdn=<domain>` for each domain in
`/certs/api/list`'s `domains[].domain`, normalized like any domain. The certificate counts
(`certificate_count`) are only printed (`--print`), not stored.

## Certificate hostnames on IPs

`slib.bgphe.certs.ip` models, for each `entries[]` item of
`/certs/api/certificates/by-prefix` and each of its `hostnames`:

| IP version | Node |
| --- | --- |
| 4 | `inet:dns:a=(<hostname>, <ip>)` |
| 6 | `inet:dns:aaaa=(<hostname>, <ip>)` |

## Domain whois

`slib.bgphe.whois` models one `inet:whois:rec` per lookup, then its nameservers, emails, and
contacts.

### inet:whois:rec

The node is `inet:whois:rec=(<fqdn>, <asof>)`, where `asof` is the first of:

1. when the registry answered the query, if the record says: RDAP's
   `last update of RDAP database` event (registry record only), or the whois text's
   `>>> Last update of whois database: ... <<<` or `WHOIS lookup made at ...` line,
2. the record's `updated` time,
3. now.

bgp.he.net caches whois records, so this makes a repeated lookup land on the same node until
the record changes (as long as the record has one of the first two times).

| Prop | From |
| --- | --- |
| `:text` | The whois text, or with RDAP the RDAP records as indented JSON (set with `=`). The model lowercases it, the node data has the original. |
| `:created` | RDAP `registration` event, or whois `Creation Date` (and aliases) |
| `:updated` | RDAP `last changed` event, or whois `Updated Date` (and aliases) |
| `:expires` | RDAP `expiration`/`registrar expiration` event, or whois `Registry Expiry Date` (and aliases) |
| `:registrar` | The registrar's name |
| `:registrant:name` | The registrant contact's organization, or its name |

Setting `:text` also makes Synapse add an `inet:whois:email` for every email address in the
text (Synapse's own `inet:whois:rec:text` handler).

### inet:whois:recns

`inet:whois:recns=(<nameserver>, <rec>)` for each nameserver, lowercased, without a trailing
dot. With RDAP, the first record (registry, then registrar) that lists nameservers is used.

### inet:whois:email

`inet:whois:email=(<fqdn>, <email>)` for the email of each modeled contact (except the
registrar's).

### inet:whois:contact

`inet:whois:contact=(<rec>, <type>)` for each `registrant`, `admin`, `tech`, and `billing`
contact with at least one non-redacted value:

| Prop | Value |
| --- | --- |
| `:id` | The contact's handle / registry ID |
| `:name` | The contact's name |
| `:orgname` | The organization |
| `:address` | Street address, parts joined with `, ` |
| `:city`, `:state` | |
| `:country` | Two letter country code (only when it is two letters) |
| `:phone`, `:fax` | Phone numbers (a `tel:` prefix is removed) |
| `:email` | The email address, lowercased |

Values that registries put in place of personal data (matching `redacted`, `not disclosed`,
`data protected`, `non-public`, `statutory masking`, `please query the rdds`,
`contact privacy`, or `gdpr`, case-insensitively) are dropped. The parsed postal code is kept
in the node data only, since `inet:whois:contact` has no prop for it.

Plus one `inet:whois:contact=(<rec>, registrar)`, when the registrar has a name, email, URL,
or whois server:

| Prop | Value |
| --- | --- |
| `:id` | The registrar's IANA ID |
| `:orgname` | The registrar's name |
| `:email`, `:phone` | The registrar's abuse email and phone |
| `:url` | The registrar's URL (`http://` added when it has no scheme) |
| `:whois:fqdn` | The registrar's whois server |

### RDAP field mapping

bgp.he.net's RDAP payload is `[<registry record>, [<registrar records>] or null]`. The
registry is preferred for dates, status, and nameservers; the registrar's records for
contacts (see [Internals](internals.md#rdappy)).

| Parsed field | RDAP source |
| --- | --- |
| `created` | `events[]` with `eventAction` `registration` |
| `updated` | `last changed` |
| `expires` | `expiration`, then `registrar expiration` |
| `asof` | `last update of rdap database` (registry record only) |
| `nameservers` | `nameservers[].ldhName` |
| `status` | `status[]`, converted to EPP names (`client delete prohibited` is `clientDeleteProhibited`) |
| `dnssec` | `secureDNS.delegationSigned`: `signedDelegation` or `unsigned` |
| contacts | `entities[]` with `roles` `registrant`, `administrative`, `technical`, `billing`; jCard `fn`, `org`, `adr`, `tel` (voice / fax), `email`, and the entity `handle` |
| registrar `name`, `url`, `ianaid` | The `registrar` entity's jCard `fn` (or `org`), `url`, and `publicIds[]` of an IANA type |
| registrar `email`, `phone` | The registrar entity's `abuse` sub-entity |
| registrar `whois` | `port43`, the registrar's record first |

`status` and `dnssec` are not modeled as props, they are in the node data's `rec`.

## ASNs

`slib.bgphe.asn` models:

| Node | Props |
| --- | --- |
| `inet:asn=<asn>` | `:name` from the AS name (ex. `GOOGLE`, the model lowercases it); `:owner` the `ou:org` (set with `=`) |
| `ou:org` | Made by `gen.ou.org <orgname>`, so deconflicted by `ou:name`; `:country:code` from the record's country |

The `ou:org` is only modeled when the record has an organization name: ARIN's `OrgName`, an
RPSL `organisation` object's `org-name`, LACNIC's `owner`, or else the `aut-num`'s first
`descr`.

The `inet:asn`'s `slib:bgphe:whois` node data has the raw text and the parsed record, ex.:

```json
{
  "asn": 15169,
  "text": "...",
  "rec": {
    "asn": 15169, "registry": "arin", "name": "GOOGLE", "handle": "AS15169",
    "desc": "Please note that the recommended way to file abuse complaints are ...",
    "orgname": "Google LLC", "orgid": "GOGL", "country": "US",
    "address": "1600 Amphitheatre Parkway, Mountain View, CA, 94043",
    "created": 954374400000, "updated": 1330041600000, "status": null,
    "contacts": [
      {"type": "abuse", "handle": "ABUSE5250-ARIN", "name": "Abuse",
       "email": "network-abuse@google.com", "phone": "+1-650-253-0000"},
      {"type": "tech", "handle": "ZG39-ARIN", "name": "Google LLC",
       "email": "arin-contact@google.com", "phone": "+1-650-253-0000"}
    ],
    "emails": ["network-abuse@google.com", "arin-contact@google.com"]
  }
}
```

| Parsed field | ARIN | RPSL (RIPE, APNIC, AFRINIC, LACNIC) |
| --- | --- | --- |
| `registry` | `arin` | The `aut-num`'s `source` (lowercased), or `lacnic` when it has an `owner` |
| `name` | `ASName` | `as-name` |
| `handle` | `ASHandle` | `AS<asn>` |
| `desc` | The ASN's and org's `Comment` lines | The `descr` lines |
| `orgname` | `OrgName` | `org-name` of the `org` object, or `owner`, or the first `descr` |
| `orgid` | `OrgId` | `org` (or `ownerid`) |
| `country` | The org's `Country` | `country` (the `aut-num`'s, then the org's) |
| `address` | `Address`, `City`, `StateProv`, `PostalCode` | The org's (or the `aut-num`'s) `address` lines |
| `created` | `RegDate` (the ASN's, or the org's) | `created` |
| `updated` | `Updated` | `last-modified` (or `changed`) |
| `status` | | `status` |
| `contacts` | `OrgAbuse*`, `OrgTech*`, `OrgNOC*`, `OrgRouting*`, `OrgDNS*`, `OrgAdmin*`, `RAbuse*`, `RTech*`, `RNOC*`, `RRouting*` (`Handle`, `Name`, `Phone`, `Email`) | `abuse-c`, `admin-c`, `tech-c` (of the `aut-num` and the org) resolved to their `role`/`person` objects, and `mnt-irt` |
| `emails` | Every contact email, then emails in the comments | Every contact email, then emails in `descr` and `remarks` |

Contact types are `abuse`, `admin`, `tech`, `noc`, `routing`, and `dns`. Only `:name` and
`:owner` are props: the rest stays in node data.

## Originated prefixes

`slib.bgphe.asn.prefixes` models, for each row of
`/super-lg/report/api/v1/prefixes/originated/<asn>`:

| Prefix | Node |
| --- | --- |
| IPv4 | `inet:asnet4=(<asn>, <prefix>)` |
| IPv6 | `inet:asnet6=(<asn>, <prefix>)` |

with `.seen = now` (extending the interval on each lookup), and `slib:bgphe` node data of the
row's `{"count": <Count>, "total": <Total>}`. HE doesn't document these numbers. They appear to
be the route's visibility: how many of the Super Looking Glass's peers see the prefix
originated by the ASN, out of how many carry the prefix at all.
