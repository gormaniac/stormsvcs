# API

## Storm modules

The package has five modules
({src}`svcs/crtsh/src/crtshsvc/pkgproto/storm/modules/`):

| Module | Permission to import | Role |
| --- | --- | --- |
| `slib.crtsh.lib` | `slib.crtsh.user` | The user API: query, model, and emit nodes. |
| `slib.crtsh.model` | `slib.crtsh.user` | Models certificate details as nodes (see [Data model](model.md)). |
| `slib.crtsh.util` | none | Helpers: warnings, tag prefix validation, tables, time casts, node keys. |
| `slib.crtsh.priv.user` | `asroot` for `slib.crtsh.user` | The only user-level caller of the service. |
| `slib.crtsh.priv.admin` | `asroot` for `slib.crtsh.admin` | Tag settings and `rawQuery`. |

### slib.crtsh.lib

Each function queries the service, models the results as the calling user, and emits (or
returns) `crypto:x509:cert` nodes. A failed call becomes a warning
(`slib.crtsh: <what> failed: <mesg>`) and the function stops, so the functions never raise for
a service error. Times are epoch milliseconds (use `$lib.cast(time, ...)` to convert).

| Function | Emits / returns |
| --- | --- |
| `lookup(valus, kind=(null), limit=(100), chain=(false))` | Emits the certificates matching `valus` (a value or a list). `kind` is a lookup type (see [slib.crtsh.cert](commands.md#slibcrtshcert)), guessed when null. Warns when nothing matches. |
| `search(opts, chain=(false))` | Emits search results. `opts` is a dict with the keys `dns`, `cn`, `org`, `ou`, `email`, `ip`, `uri`, `subject`, `identity`, `issuer`, `caids`, `exact`, `valid`, `since`, `until`, `expires_after`, `expires_before`, `precerts`, and `limit`. A missing key reads as null, and a null `precerts` excludes precertificates while a null `limit` means `crtsh:limit`, so pass every key, as `slib.crtsh.search` does. |
| `pivot(valu, by, kind=(null), valid=(false), precerts=(true), limit=(100), chain=(false))` | Emits the certificates related to `valu` (see [slib.crtsh.pivot](commands.md#slibcrtshpivot)). |
| `issued(caids=(null), valu=(null), kind=(null), valid=(false), since=(null), until=(null), precerts=(true), limit=(100), chain=(false), expires_after=(null), expires_before=(null))` | Emits the certificates issued by the crt.sh CAs `caids`, or by the CA that certificate `valu` belongs to. |
| `chain(valu, kind=(null))` | Emits every certificate in `valu`'s chains, the leaf first. |
| `chainOf(valu, kind=(null), tagPrefix=(null))` | Returns `{"data": <chain>, "nodes": {<sha256>: <node>}}` (see [`chain`](#chain)), or null on failure. |
| `ingest(c, chain=(false), tagPrefix=(null))` | Models one certificate details dict (and its chain), returns the node. |

```text
$crtsh = $lib.import(slib.crtsh.lib)
for $cert in $crtsh.lookup((1234567,)) { $lib.print($cert) }

$opts = ({"dns": "vertex.link", "cn": null, "org": null, "ou": null, "email": null,
          "ip": null, "uri": null, "subject": null, "identity": null, "issuer": null,
          "caids": ([]), "exact": false, "valid": true, "since": null, "until": null,
          "expires_after": null, "expires_before": null, "precerts": false, "limit": 50})
for $n in $crtsh.search($opts) { $lib.print($n.repr()) }
```

### slib.crtsh.model

`cert(c, tagPrefix=(null))` models a details dict and returns the `crypto:x509:cert` node.
`chain(data, tagPrefix=(null))` models a chain and returns `{<sha256>: <node>}`, setting each
preferred parent as `:issuer:cert`. The lower level functions (`certNode`, `keyNode`,
`rsaKeyNode`, `crlNode`, `revokedNode`, `seen`, `addTag`, and so on) build single nodes. A
`tagPrefix` of null means no tags.

### slib.crtsh.priv.user

`$lib.service.get("slib.crtsh")` wrapped `asroot`. Every function returns the service's
`TelepathRetn`, or emits them for the generators: `tagPrefix()`, `lookup(kind, valus,
limit=(100))`, `chain(valu, kind=(null))`, `cas(name=(null), caids=(null), certs=(false),
limit=(100))`, `search(opts)`, `issued(...)`, and `pivot(valu, by, kind=(null), valid=(false),
precerts=(true), limit=(100))`. `tagPrefix()` returns the prefix to tag with, or null when
tagging is off or the stored prefix is invalid.

### slib.crtsh.priv.admin

`tagSettings()` returns `{"enabled", "prefix"}`. `setTagPrefix(prefix)` and
`setTagsEnabled(enabled)` set the globals without validating them (the command validates the
prefix). `rawQuery(sql, args=(null), limit=(100))` calls the service.

## Telepath API

`CrtshCellApi` ({src}`svcs/crtsh/src/crtshsvc/api.py`) subclasses
`stormlibpp.svc.RetnApi`, `synapse.lib.cell.CellApi`, and `synapse.lib.stormsvc.StormSvc`.
`RetnApi` generates one Telepath method for each name in:

- `RETN_METHS = ("lookup", "get", "chain", "cas", "rawQuery")`: each calls the cell method and
  returns a single `TelepathRetn`.
- `GENR_METHS = ("searchGenr", "issuedGenr", "pivotGenr")`: each is a generator that yields a
  `TelepathRetn` per item.

The arguments are those of the `CrtshSvc` methods in {src}`svcs/crtsh/src/crtshsvc/svc.py`.

### TelepathRetn

Every method returns (or yields) a dict:

```json
{"status": true, "mesg": "", "data": "<the result>"}
```

On failure, `status` is false, `data` is null, and `mesg` explains why. The API never raises
to Storm. How `mesg` is built (`stormlibpp.svc.errRetn`):

| Error | `mesg` |
| --- | --- |
| `CrtshDbError` (`RETN_ERRORS`), or a Synapse `AuthDeny` | The error's own message, ex. `Invalid limit 0, it must be at least 1.` |
| `ValueError`, `TypeError`, `BadArg` | `Invalid input: <error>` |
| Anything else | `Unexpected error: <type>: <error>`, and the traceback is logged on the service |

A generator that fails yields one `status=false` item and stops. Items it already yielded stand.

`CrtshDbError` covers every validation error (bad identifiers, limits, times, IPs, unknown kinds
or pivots, missing required arguments) and every database failure. The database messages are:

| Message | Cause |
| --- | --- |
| `Unable to connect to the crt.sh database: <error>` | Connecting failed with a non-transient error, or kept failing for `crtsh:connect:timeout`. |
| `crt.sh canceled the query (statement timeout) after <n>s, try a narrower search: <error>` | The server canceled the query (SQLSTATE 57014) and the retries ran out, or it wasn't a statement timeout. |
| `crt.sh query timed out after <crtsh:timeout>s.` | The client-side `crtsh:timeout` expired. |
| `crt.sh query failed: <error>` | Any other PostgreSQL error, or connection errors after `crtsh:retries` retries. |

### lookup

`lookup(kind, valus, limit=100) -> list[dict]`

Certificates matching a unique identifier, newest first. `kind` is `id`, `sha256`, `sha1`,
`serial`, `ski`, `spki`, `spkisha1`, `subjectsha1`, or null to guess each value (`id`,
`sha256`, or `sha1`). `valus` is a value or a list. `limit` is capped at `crtsh:limit`. `data` is
a list of [certificate details](#certificate-details).

### get

`get(valu, kind=None) -> dict | None`

The newest certificate matching one identifier, or null when crt.sh doesn't have it. It asks
crt.sh for one row for `id` and `sha256`, and up to 100 otherwise. It's not used by the Storm
package.

### chain

`chain(valu, kind=None, maxdepth=10, maxcerts=100) -> dict`

Every chain from a certificate up to its root(s), in one recursive query:

```json
{
  "leaf": "<sha256 of the certificate>",
  "certs": ["<details>", "..."],
  "links": [{"child": "<sha256>", "parent": "<sha256>", "preferred": true}],
  "paths": [["<leaf sha256>", "<intermediate sha256>", "<root sha256>"]]
}
```

- `certs` holds at most `maxcerts` certificates, the leaf first, ordered by depth and then
  crt.sh ID.
- `links` holds every (child, possible parent) pair among `certs`. Exactly one parent of each
  child is `preferred`: a parent whose validity covers the child's notBefore beats one that
  doesn't, a non-precertificate beats a precertificate, and then the latest notAfter wins.
- `paths` holds at most 50 leaf-to-root paths, preferred parents first. A path never repeats a
  certificate.
- The SQL stops at `maxdepth` levels and 500 rows. Fails with `crt.sh has no certificate with
  <kind> <valu>` when the certificate isn't there.

### cas

`cas(name=None, caids=None, certs=False, limit=100) -> list[dict]`

crt.sh CAs whose name contains `name` (case-insensitively) or whose ID is in `caids` (an int or
a list of ints). At most `limit` CAs, ordered by ID:

```json
[{"id": 2, "name": "C=US, O=Test Trust, CN=Test Issuing CA 1", "certs": [2, 4]}]
```

`certs` holds the crt.sh IDs of the CA's own certificates, or their full details with
`certs=True`. Fails with `A CA name or ID is required.` without either argument.

### rawQuery

`rawQuery(sql, args=None, limit=None) -> list[dict]`

A read-only raw query (see [Raw SQL](database.md#raw-sql)). `args` must be a list or tuple
(`Invalid args, expected a list of positional query arguments.`). `limit` defaults to, and is
capped at, `crtsh:sql:limit`. Each row is a dict of column name to value. Bytes are hex, and
`datetime`s are epoch milliseconds. Lists are converted item by item. A str, int, float, bool,
or null is kept, and anything else is passed through `str()`.

### searchGenr

`searchGenr(dns=None, cn=None, org=None, ou=None, email=None, ip=None, uri=None, subject=None,
identity=None, issuer=None, caids=None, exact=False, valid=False, since=None, until=None,
precerts=True, limit=100, expires_after=None, expires_before=None)`

Yields [certificate details](#certificate-details), newest first. The fields and options work as
described for [slib.crtsh.search](commands.md#slibcrtshsearch). `since`, `until`,
`expires_after`, and `expires_before` are epoch milliseconds. `caids` is an int or a list. Empty
strings count as not given. Errors include `A search needs at least one certificate field or an
issuer.`, `A prefix search (<valu>) can't be exact.`, and `The expires after time must be before
the expires before time.`.

The whole result is fetched in one query and sorted before the first item is yielded. The
generator streams the items to Storm, not the query.

### issuedGenr

`issuedGenr(caids=None, kind=None, valu=None, valid=False, since=None, until=None,
precerts=True, limit=100, expires_after=None, expires_before=None)`

Yields the newest certificates issued by the crt.sh CAs `caids`, and/or by the CA that the
certificate `kind`/`valu` belongs to. Every certificate of a CA shares its name and key, so
certificates issued under any of them are returned. Fails with `A CA ID or certificate is
required.`, or `crt.sh doesn't know of a CA for certificate <valu>, it may not be a CA
certificate.`.

### pivotGenr

`pivotGenr(valu, by, kind=None, valid=False, precerts=True, limit=100)`

Yields the certificates related to `valu`, excluding itself. `by` is `issued`, `siblings`, `key`,
`subject`, `serial`, or `ski` (see [slib.crtsh.pivot](commands.md#slibcrtshpivot)). `issued`
calls `issuedGenr(kind=kind, valu=valu, ...)`.

## Certificate details

Every certificate is returned as one dict, built by `crtshsvc.norm.certDetails()`
({src}`svcs/crtsh/src/crtshsvc/norm.py`). It only holds Telepath-safe values: bytes are
lowercase hex and times are epoch milliseconds. The example below is abbreviated and its values
are illustrative (most are from the tests' fake PKI).

```json
{
  "sha256": "<hex>", "sha1": "<hex>", "md5": "<hex>",
  "version": 2,
  "serial": "5a0b1c2d3e4f",
  "subject": {
    "dn": "CN=www.vertex.link,OU=Engineering,O=The Vertex Project,C=US",
    "attrs": {"c": ["US"], "o": ["The Vertex Project"], "ou": ["Engineering"], "cn": ["www.vertex.link"]},
    "sha1": "<SHA-1 of the DER name>"
  },
  "issuer": {"dn": "...", "attrs": {}, "sha1": "..."},
  "notbefore": 1767225600000, "notafter": 1775001600000,
  "sigalgo": {"oid": "1.2.840.10045.4.3.2", "name": "ecdsa-with-SHA256", "hash": "sha256"},
  "signature": "<hex>",
  "pubkey": {
    "algo": "ec", "size": 256, "curve": "secp256r1",
    "spki": "<hex DER SubjectPublicKeyInfo>", "sha256": "<hex>", "sha1": "<hex>"
  },
  "selfsigned": false,
  "identities": {"fqdns": [], "emails": [], "ipv4s": [], "ipv6s": [], "urls": []},
  "sans": [["dns", "www.vertex.link"], ["ip", "2001:db8::1"]],
  "ca": false, "pathlen": null,
  "keyusage": ["digital_signature"],
  "extkeyusage": [{"oid": "1.3.6.1.5.5.7.3.1", "name": "serverAuth"}],
  "ski": "<hex>", "aki": "<hex>",
  "crls": ["http://crl.test.example/issuing1.crl"],
  "ocsp": [], "caissuers": [], "policies": ["2.23.140.1.2.1"],
  "scts": [{"logid": "<hex>", "time": 1767225600000, "version": "v1"}],
  "precert": false, "mustStaple": false,
  "extensions": [{"oid": "2.5.29.17", "name": "subjectAltName", "critical": false}],
  "pem": "-----BEGIN CERTIFICATE-----\n...",
  "crtsh": {
    "id": 10,
    "url": "https://crt.sh/?id=10",
    "issuer": {"id": 2, "name": "C=US, O=Test Trust, CN=Test Issuing CA 1"},
    "ctlog": [{"log": "Test Log A", "url": "...", "operator": "...", "index": 123, "time": 1767225600000}],
    "logged": [1767225600000, 1767225600000],
    "revoked": null,
    "caids": []
  }
}
```

| Key | Meaning |
| --- | --- |
| `subject.attrs`, `issuer.attrs` | Attribute values by short name (`cn`, `o`, `ou`, `c`, `st`, `l`, `street`, `postalcode`, `email`, `serialnumber`, `dc`, `businesscategory`, `jurisdiction:c`, `jurisdiction:st`, `jurisdiction:l`, `organizationidentifier`, `givenname`, `surname`, `title`), or by dotted OID for anything else. |
| `pubkey` | `algo` is `rsa`, `ec`, `dsa`, `ed25519`, `ed448`, or null. RSA keys add `rsa: {"mod": <hex>, "exp": <int>}`, and EC keys add `curve`. A key `cryptography` can't load has only `algo: null, size: null`. |
| `sans` | `[type, value]` pairs: `dns`, `email`, `uri`, `ip`, `dirname` (RFC 4514), `registeredid` (OID), `othername` (`<oid>:<hex>`). |
| `keyusage` | `digital_signature`, `content_commitment`, `key_encipherment`, `data_encipherment`, `key_agreement`, `key_cert_sign`, `crl_sign`, and `encipher_only`/`decipher_only` with key agreement. |
| `precert` | Has the CT poison extension `1.3.6.1.4.1.11129.2.4.3`. |
| `mustStaple` | The TLS feature extension includes status_request (5). |
| `crtsh.caids` | The crt.sh CAs this certificate belongs to (it's a CA certificate when non-empty). |
| `crtsh.logged` | `[first, last]` CT log entry times, or null. |
| `crtsh.revoked` | `{"time", "reason", "code"}` from crt.sh's CRL data, or null. `reason` is the RFC 5280 name (ex. `keyCompromise`), or the code as a string for unknown codes. |
| `error` | Only on certificates that couldn't be parsed. They have only `sha256`, `sha1`, `md5`, `pem`, `error`, and `crtsh`. |
