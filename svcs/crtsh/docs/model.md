# Data model

Everything the service models is written by the `slib.crtsh.model` Storm module
({src}`svcs/crtsh/src/crtshsvc/pkgproto/storm/modules/slib.crtsh.model.storm`), as the calling
user, from the certificate details the service returns (see
[Certificate details](api.md#certificate-details)).

## Overview

| Form | Deconflicted by | When |
| --- | --- | --- |
| `crypto:x509:cert` | `:sha256` (`crypto:x509:cert=({"sha256": ...})`) | Every certificate returned |
| `crypto:key` | `:public:sha256`, the SHA-256 of the DER SubjectPublicKeyInfo | The key could be parsed |
| `rsa:key` | `(modulus, exponent)` | RSA keys |
| `crypto:x509:crl` | `{"url": <first CRL distribution point>}`, or the guid `(slib.crtsh, crl, <issuer crt.sh CA ID>)` | Revoked certificates |
| `crypto:x509:revoked` | `(<crl>, <cert>)` | crt.sh lists the certificate on a CRL |
| `meta:source` | guid `c7357722661f45a4b81c91ccfbbb37c0` | Created on `service.add`, linked to everything |

Synapse creates the nodes that prop values point to (ex. `inet:fqdn` for
`:identities:fqdns`, `file:bytes` for `:file`). Running a command again finds the same nodes,
so repeat runs update nodes instead of duplicating them.

## crypto:x509:cert

| Prop | Value | Source |
| --- | --- | --- |
| `:sha256` | SHA-256 of the DER | computed |
| `:sha1` | SHA-1 of the DER | computed |
| `:md5` | MD5 of the DER | computed |
| `:file` | `sha256:<sha256>` (a `file:bytes`) | computed |
| `:serial` | The serial, as even-length hex (Synapse zero pads it) | X.509 serialNumber. Negative serials use their two's complement DER bytes. |
| `:version` | `0`, `1`, or `2` (v1 to v3) | X.509 version |
| `:subject` | The RFC 4514 subject DN, ex. `CN=www.vertex.link,OU=Engineering,O=The Vertex Project,C=US` | X.509 subject |
| `:issuer` | The RFC 4514 issuer DN | X.509 issuer |
| `:validity:notbefore` | notBefore | X.509 validity |
| `:validity:notafter` | notAfter | X.509 validity |
| `:algo` | The signature algorithm OID, ex. `1.2.840.10045.4.3.2` | signatureAlgorithm |
| `:signature` | The signature, as hex | signatureValue |
| `:selfsigned` | Subject DN equals issuer DN, and the AKI is absent or equals the SKI | computed |
| `:rsa:key` | `(modulus, exponent)` | RSA public key |
| `:ext:sans` | `(type, value)` for every SAN: `dns`, `email`, `uri`, `ip`, `dirname`, `registeredid`, `othername` | subjectAltName |
| `:crl:urls` | The URI CRL distribution points | cRLDistributionPoints |
| `:ext:crls` | `(uri, <url>)` for each URI CRL distribution point | cRLDistributionPoints |
| `:identities:fqdns` | DNS SANs, plus a CN that's a domain. Lowercased, trailing `.` removed, a leading `*.` removed. Only values with a `.` and no spaces or `*`. | SAN, subject CN |
| `:identities:emails` | Email SANs, subject emailAddress, and a CN with `@`, lowercased | SAN, subject |
| `:identities:ipv4s` | IPv4 SANs and an IPv4 CN | SAN, subject CN |
| `:identities:ipv6s` | IPv6 SANs and an IPv6 CN | SAN, subject CN |
| `:identities:urls` | URI SANs | SAN |
| `:issuer:cert` | The preferred parent certificate | set only by chains (see below) |
| `.seen` | Covers the first and last CT log entry timestamps | crt.sh `ct_log_entry.ENTRY_TIMESTAMP` |

Array values are added with `?+=`, so a value that doesn't normalize is skipped and values
already on the node are kept. Scalar X.509 props are set with `?=`, so a bad value is skipped
instead of failing the edit. `:sha1`, `:md5`, and `:file` are always set, and `:selfsigned`
is set for every certificate that could be parsed. Every
cert node gets a `-(seen)>` edge from the `slib.crtsh` `meta:source`.

### Node data

The complete details are stored in the `slib:crtsh` node data key, overwritten on every run.
That includes what the model has no place for: EC curves, key sizes, key usage, EKU, policies,
OCSP and CA issuer URLs, SCTs, the AKI/SKI, path length, Must-Staple, every extension's OID and
criticality, the PEM, CT log entries, crt.sh IDs, and the revocation time and reason. See
[Certificate details](api.md#certificate-details) for the full shape. For example:

```text
crypto:x509:cert:sha256=<sha256> $d = $node.data.get("slib:crtsh") $lib.print($d.crtsh.url)
```

### Unparsable certificates

CT logs contain certificates that `cryptography` can't parse. Their details only hold the
hashes, a PEM, the crt.sh data, and an `error` (`Unable to parse certificate: ...`). Their
nodes only get `:sha256`, `:sha1`, `:md5`, `:file`, `.seen`, the `-(seen)>` edge, and the node
data. They get no key, tags, or chain.

## Keys

`crypto:key`: `:public` (the DER SubjectPublicKeyInfo, as hex), `:public:sha1`,
`:public:sha256`, and `:algorithm` (`rsa`, `ec`, `dsa`, `ed25519`, or `ed448`). The cert gets a
`-(refs)> crypto:key` edge. A key type `cryptography` can't load has no hashes, so it gets no
`crypto:key` node.

`rsa:key`: `:mod` and `:pub:exp` (from the comp value), and `:bits` (the key size). The cert's
`:rsa:key` points to it.

The SPKI hashes in `:public:sha256` and `:public:sha1` are the values the `spki` and `spkisha1`
lookups and the `--by key` pivot use.

## Revocation

When crt.sh has a `crl_revoked` row for the certificate (the same issuing CA and serial), the
service models:

- `crypto:x509:crl`: `{"url": <url>}` with `:url` set to the certificate's first URI CRL
  distribution point. If it has none, it's the guid `(slib.crtsh, crl, <issuer crt.sh CA ID>)`
  with no props, one per issuing CA.
- `crypto:x509:revoked=(<crl>, <cert>)`.

The revocation time and reason are only in the node data (`crtsh.revoked`), since the model
has no props for them.

## Chains

[`slib.crtsh.chain`](commands.md#slibcrtshchain) and `--chain` model every certificate in the
chain as above, then set each child's `:issuer:cert` to its preferred parent. Every possible
parent (cross-signs, reissues) is only in the chain data the service returns (`links`), not in
the Cortex.

## Tags

When tagging is enabled, each certificate gets these tags under the prefix (`rep.crtsh` by
default):

| Tag | When |
| --- | --- |
| `<prefix>.precert` | The certificate has the CT precertificate poison extension (`1.3.6.1.4.1.11129.2.4.3`). |
| `<prefix>.revoked` | crt.sh lists it on a CRL. |
| `<prefix>.ca` | basicConstraints `cA` is true. |
| `<prefix>.root` | It's a CA and self-signed. |

Tags are only added, never removed. A certificate that's no longer revoked keeps its tag.

The settings are two Cortex globals, set by [`slib.crtsh.admin.tags`](commands.md#slibcrtshadmintags):

| Global | Default (set on `service.add`) | Meaning |
| --- | --- | --- |
| `slib:crtsh:tag:enabled` | `true` | Whether to tag. |
| `slib:crtsh:tag:prefix` | `rep.crtsh` | The tag prefix. |

The settings are read at the start of each lookup, search, pivot, chain, or CA call. If a stored prefix isn't a valid tag name (it was set
before validation existed, or set directly), no tags are applied and the user gets the warning
`slib.crtsh: The tag prefix <prefix> isn't a valid tag name, no tags are applied. Fix it with
slib.crtsh.admin.tags --prefix.`, instead of every node edit failing.

## meta:source

On `service.add` the service creates
`meta:source=c7357722661f45a4b81c91ccfbbb37c0` with `:name="crt.sh"`, `:type=slib.crtsh`, and
`:url=https://crt.sh`. The guid is `SVC_GUID` in {src}`svcs/crtsh/src/crtshsvc/defs.py`, passed to
the model module as its `modconf`. Every node the model creates (certs, keys, `rsa:key`, CRLs,
revocations) gets a `-(seen)>` edge from it:

```text
meta:source=c7357722661f45a4b81c91ccfbbb37c0 -(seen)> crypto:x509:cert
```

## Field mapping

How the crt.sh data in a certificate's details maps to the model:

| Details field | crt.sh column | Model |
| --- | --- | --- |
| `crtsh.id` | `certificate.ID` | node data only |
| `crtsh.url` | `https://crt.sh/?id=<ID>` | node data only |
| `crtsh.issuer.id`, `crtsh.issuer.name` | `certificate.ISSUER_CA_ID`, `ca.NAME` | node data; the issuer ID names the fallback CRL guid |
| `crtsh.caids` | `ca_certificate.CA_ID` | node data only |
| `crtsh.ctlog[]` | `ct_log_entry` joined to `ct_log` | node data |
| `crtsh.logged` | min/max of `ct_log_entry.ENTRY_TIMESTAMP` | `.seen` |
| `crtsh.revoked` | `crl_revoked.REASON_CODE`, `REVOCATION_DATE` | `crypto:x509:revoked`, `<prefix>.revoked`, and the node data |
