# Commands

Every command is defined in {src}`svcs/crtsh/src/crtshsvc/pkgproto/slib.crtsh.yaml`, with its
Storm in `pkgproto/storm/commands/`. All of them end in `| uniq`, so a node is yielded at most
once.

## Common behaviour

These apply to every command below except `slib.crtsh.admin.*`.

Explicit values or inbound nodes
: Explicit values (`slib.crtsh.cert <valus>`, `--cert`, or any search field, `--issuer`, or
  `--caid` of `slib.crtsh.search`) are queried **once**, in the command's `fini` block, and the
  inbound nodes are dropped. Without explicit values, each inbound node the command accepts is
  queried on its own. A node the command can't use gets a warning (ex. `slib.crtsh.pivot:
  Unable to pivot from inet:fqdn vertex.link, it needs a crypto:x509:cert with a SHA-256 or
  SHA-1.`) and is dropped. With neither explicit values nor inbound nodes, the command warns
  (ex. `slib.crtsh.cert: Nothing to look up, give values or inbound nodes.`).

`crypto:x509:cert` inbound nodes
: These are looked up by `:sha256`, or by `:sha1` when there's no `:sha256`. A node with
  neither is skipped with a warning.

Errors
: A failed service call becomes a warning, not an exception: `slib.crtsh: <what> failed:
  <mesg>`, ex. `slib.crtsh: Lookup failed: crt.sh canceled the query (statement timeout) after
  31s, try a narrower search: ...`. The command carries on with the next inbound node. Only bad
  option combinations (`slib.crtsh.ca` without a name or `--id`, and `slib.crtsh.admin.tags
  --enable --disable`) raise `BadArg`.

Order and limits
: The service returns certificates newest first (by notBefore, then highest crt.sh ID).
  Every `--limit` is capped by the service's `crtsh:limit` (10000 by default). A limit below 1
  is an error.

`--chain`
: Builds and models each yielded certificate's chain (as
  [`slib.crtsh.chain`](#slibcrtshchain) does) with one extra query per certificate. The chain's
  nodes aren't yielded. Certificates that couldn't be parsed are skipped.

Times
: `--since`, `--until`, `--expires-after`, and `--expires-before` take anything Synapse can cast
  to a `time`, ex. `2025-01-01`, `"2025-01-01 12:00"`, or `"-30 days"`. An empty string means
  not set.

What gets modeled
: Every certificate that's returned is modeled in full (see [Data model](model.md)). Tags are
  applied when tagging is enabled (see [`slib.crtsh.admin.tags`](#slibcrtshadmintags)).

## Lookups

### slib.crtsh.cert

Look up certificates by a unique identifier and model their complete details.

```text
slib.crtsh.cert [<valus> ...] [--type <type>] [--limit <n>] [--chain] [--yield]
```

Requires `slib.crtsh.user`.

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `valus` | str, `*` | none | Identifiers to look up instead of the inbound nodes. |
| `--type` | str | guessed | The identifier type: `id`, `sha256`, `sha1`, `serial`, `ski`, `spki`, `spkisha1`, or `subjectsha1`. |
| `--limit` | int | `100` | The most certificates per lookup. |
| `--chain` | flag | false | Also model each certificate's chain. |
| `--yield` | flag | false | With inbound nodes, yield the `crypto:x509:cert` nodes instead of the inbound nodes. |

Identifier types:

| `--type` | Matches | Value |
| --- | --- | --- |
| `id` | `certificate.ID` | A crt.sh certificate ID (an integer). |
| `sha256` | `digest(CERTIFICATE, 'sha256')` | 64 hex characters. |
| `sha1` | `digest(CERTIFICATE, 'sha1')` | 40 hex characters. |
| `serial` | `x509_serialNumber(CERTIFICATE)` | Hex. Matched with and without a leading `00` sign byte, so either encoding finds it. |
| `ski` | `x509_subjectKeyIdentifier(CERTIFICATE)` | Hex, an even number of characters. |
| `spki` | SHA-256 of `x509_publicKey(CERTIFICATE)` | 64 hex characters. |
| `spkisha1` | SHA-1 of `x509_publicKey(CERTIFICATE)` | 40 hex characters. |
| `subjectsha1` | SHA-1 of `x509_name(CERTIFICATE)` (the DER subject) | 40 hex characters. |

Hex values may use any case, `:` and space separators, and a `0x` prefix. Without `--type`, the
service guesses each value's type: digits only and shorter than 20 characters is an `id`, 64
hex characters is a `sha256`, and 40 is a `sha1`. Anything else fails with `Unable to tell what
kind of identifier <valu> is, specify one of: ...`. Values of different guessed types can be
mixed in one call. Every value in a call is looked up in one query, so `--limit` caps the
whole call.

Inbound forms:

| Form | Looked up by |
| --- | --- |
| `crypto:x509:cert` | `:sha256`, or `:sha1` |
| `hash:sha256` | the hash, as `sha256` |
| `hash:sha1` | the hash, as `sha1` |

For inbound nodes, `--type` is ignored and the node's own hash type is used. When nothing
matches, the command warns `slib.crtsh: crt.sh has no certificates for: <values>`.

Yields
: With explicit values, the `crypto:x509:cert` nodes found. With inbound nodes, the inbound
  nodes, or the found `crypto:x509:cert` nodes with `--yield`.

```text
slib.crtsh.cert 12337892544 --yield
slib.crtsh.cert 0a1b2c3d4e5f --type serial
slib.crtsh.cert 3f0b1c...e9 --type spki --limit 500
crypto:x509:cert | slib.crtsh.cert --chain
hash:sha256=<sha256> | slib.crtsh.cert --yield
```

## Searches

### slib.crtsh.search

Search crt.sh certificates by their properties and model every match. Yields the
`crypto:x509:cert` nodes, newest first.

```text
slib.crtsh.search [--dns <d>] [--cn <s>] [--org <s>] [--ou <s>] [--email <s>] [--ip <ip>]
                  [--uri <s>] [--subject <dn>] [--identity <s>] [--issuer <name>]
                  [--caid <id> ...] [--exact] [--valid] [--since <time>] [--until <time>]
                  [--expires-after <time>] [--expires-before <time>] [--no-precerts]
                  [--limit <n>] [--chain]
```

Requires `slib.crtsh.user`.

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--dns` | str | none | A domain in a DNS SAN or the CN. Includes subdomains unless `--exact`. A leading `*.` or `.` is ignored. |
| `--cn` | str | none | The subject common name. Whole words or domains, or a trailing `*` for a prefix. |
| `--org` | str | none | The subject organization (O). Whole words. |
| `--ou` | str | none | The subject organizational unit (OU). Whole words. |
| `--email` | str | none | An email address (or its domain) in an rfc822Name SAN or the subject emailAddress. |
| `--ip` | str | none | An IP address SAN. Always matched exactly, in any notation. |
| `--uri` | str | none | A URI SAN. |
| `--subject` | str | none | The full subject DN. |
| `--identity` | str | none | Any identity (any SAN or subject attribute), like crt.sh's own search. |
| `--issuer` | str | none | A substring of the issuing CA's name. Filters the text search's candidates. |
| `--caid` | int, repeatable | `[]` | An issuing crt.sh CA ID. Filters the text search's candidates. |
| `--exact` | flag | false | Values must match whole field values. Can't be combined with a prefix. |
| `--valid` | flag | false | Only certificates that haven't expired. |
| `--since` | time | none | Only certificates issued (notBefore) on or after this time. |
| `--until` | time | none | Only certificates issued (notBefore) before this time. |
| `--expires-after` | time | none | Only certificates that expire (notAfter) on or after this time. |
| `--expires-before` | time | none | Only certificates that expire (notAfter) before this time. A certificate without a notAfter never matches. Must be after `--expires-after`. |
| `--no-precerts` | flag | false | Exclude precertificates (those with the CT poison extension). |
| `--limit` | int | `100` | The most certificates to model (per inbound node). |
| `--chain` | flag | false | Also model each certificate's chain. |

Every given option must match. Without any field, `--issuer`, or `--caid`, the inbound nodes
are searched. In that case the other options (`--exact`, `--valid`, the times,
`--no-precerts`, `--limit`) still apply to each node's search:

| Inbound form | Searched as |
| --- | --- |
| `inet:fqdn` | `--dns`, including subdomains |
| `inet:email` | `--email` |
| `inet:ipv4`, `inet:ipv6` | `--ip` |
| `inet:url` | `--uri` |
| `ou:name` | `--org` |
| `ou:org` | `--org`, using `:name` (nodes without `:name` are skipped with a warning) |

#### How matching works

crt.sh searches identities with PostgreSQL full text search, which matches whole words,
domains, and addresses, not substrings. A search works the way crt.sh's own does:

1. The service picks the most specific field given, in this order: `dns`, `email`, `ip`,
   `cn`, `uri`, `org`, `ou`, `subject`, `identity`.
2. crt.sh's full text index (`identities()`) finds candidate certificates for that field's
   text. For every field but `subject`, the candidates are also matched identity by identity
   in the `certificate_and_identities` view, with an `ILIKE` pattern and the field's name
   types, before the candidate limit is applied.
3. `--issuer`/`--caid` filter the candidates afterwards (see below).
4. The service parses every candidate and checks **every** given field against the parsed
   certificate, then drops precertificates with `--no-precerts`, sorts newest first, and cuts
   to `--limit`.

How each field matches in step 4:

| Field | Matched against | Default match | With `--exact` | With a trailing `*` |
| --- | --- | --- | --- | --- |
| `dns` | DNS SANs and CN | the domain or any subdomain (`*.` stripped from the certificate's names) | equal | a word starts with it |
| `cn` | CN | substring | equal | a word starts with it |
| `org` | O | substring | equal | a word starts with it |
| `ou` | OU | substring | equal | a word starts with it |
| `email` | email SANs and subject emailAddress | substring | equal | a word starts with it |
| `ip` | IP SANs | equal, after normalizing the address | equal | not a prefix |
| `uri` | URI SANs | substring | equal | a word starts with it |
| `subject` | the RFC 4514 subject DN | substring | equal | substring |
| `identity` | every SAN value, every subject attribute, and the DN | substring | equal | a word starts with it |

Matches ignore case. "A word starts with it" means the value appears at the start of the field
or right after a non-alphanumeric character.

So `--org vertex` matches "The Vertex Project" and `--cn vertex.link` matches `www.vertex.link`
(crt.sh indexes every parent domain as a word). But `--cn old` doesn't match `old.vertex.link`,
and `--email visi` doesn't match `visi@vertex.link`, because the text has to be a whole word
somewhere in the certificate. For `--subject`, the attribute names are removed before the full
text search (identities only index values), so `--subject "O=Vertex, CN=x"` searches the words
`Vertex x` and then matches the whole DN.

For `--ip`, the address is normalized first (`2001:0db8::1` becomes `2001:db8::1`) and an
invalid address fails with `Invalid IP address: <valu>`. IPv6 addresses are searched in
crt.sh's uncompressed, uppercase form (`:2001:DB8:0:0:0:0:0:1`).

#### Prefix searches

A trailing `*` makes the last word of a value a prefix, which becomes the tsquery
`'microsoft':*`. `--cn "microsoft*"` matches any indexed word that starts with `microsoft`.
crt.sh indexes every parent domain as a word, so it matches `microsoftonline.com` and
`login.microsoftonline.com`. Other words in the value are still whole words
(`--org "Vertex Proj*"`). There's no suffix or substring search, so `fakemicrosoft.com` doesn't
match `microsoft*`.

- A prefix can't be `--exact` (`A prefix search (<valu>) can't be exact.`).
- The prefix is one quoted, lowercased tsquery operand, so no user text is read as tsquery
  syntax, and punctuation stays in the word (`microsoft-sup*` matches `microsoft-support.ph`).
- A leading `*.` or `%.` and any other `%` are removed from the text. A `*` inside a word splits
  it.
- Prefixes of common words are much heavier than whole words. With `--valid` or `--since` on
  recent certificates they can hit the statement timeout. A query the server cancels for its
  statement timeout is retried once by default (`crtsh:timeout:retries`), since a rerun often
  finishes on crt.sh's warm cache.

#### Candidates and issuer filters

The full text search returns at most a fixed number of candidates. Without `--issuer`/`--caid`
that is `min(max(5 * limit, 500), crtsh:candidates)`. With either one it is `crtsh:candidates`
(10000 by default). Like crt.sh's own search, the candidates are an arbitrary subset, not the
newest, when more certificates match.

`--issuer` (CAs whose name contains the text, at most 1000 CAs) and `--caid` filter the
candidates **after** that limit. Nothing indexes a word and an issuer together, so a common word
with a rare issuer (`--cn microsoft --issuer "Let's Encrypt"`) only finds the matches among the
first candidates. `--since`, `--valid`, and the expiry bounds are applied inside the candidate
query, so they move the candidates to the certificates you want.

With only `--issuer` and/or `--caid` (no field), the search lists the newest certificates issued
by each matching CA instead, like `slib.crtsh.ca --issued`.

#### Validity and expiry bounds

- `--valid`: notAfter is now or later.
- `--since`/`--until`: notBefore is at or after / before the time.
- `--expires-after` (inclusive) and `--expires-before` (exclusive): bounds on notAfter.

crt.sh range partitions `certificate` on `coalesce(x509_notAfter(CERTIFICATE), 'infinity')`.
The recent partitions are quarterly, ex. `c2027q1` holds notAfter in 2027 Q1. Every bound that
implies a notAfter bound (`--valid`, `--since`, and both expiry bounds) is also written on that
expression, so PostgreSQL only scans the partitions in range. The expiry bounds are the way to
keep a heavy search to one partition:

```text
slib.crtsh.search --cn "microsoft*" --issuer "Let's Encrypt" --expires-after 2027-01-01 --expires-before 2027-04-01
```

Examples:

```text
slib.crtsh.search --dns vertex.link --valid
slib.crtsh.search --dns www.vertex.link --exact --no-precerts
slib.crtsh.search --cn "microsoft*" --issuer "Let's Encrypt" --since "-7 days"
slib.crtsh.search --org "Vertex Project" --issuer "Let's Encrypt" --since 2025-01-01
slib.crtsh.search --ip 2001:db8::1
slib.crtsh.search --caid 183267 --valid --limit 50
inet:fqdn=vertex.link | slib.crtsh.search --no-precerts
ou:org:name="the vertex project" | slib.crtsh.search --valid
```

## Pivots

### slib.crtsh.pivot

Pivot from certificates to related certificates in crt.sh and model them. The source
certificate itself is never returned.

```text
slib.crtsh.pivot --by <how> [--cert <valu> ...] [--valid] [--no-precerts] [--limit <n>] [--chain]
```

Requires `slib.crtsh.user`.

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--by` | str, required | | How to pivot, see below. |
| `--cert` | str, repeatable | `[]` | A crt.sh ID, SHA-256, or SHA-1 to pivot from instead of the inbound nodes. |
| `--valid` | flag | false | Only certificates that haven't expired. |
| `--no-precerts` | flag | false | Exclude precertificates. |
| `--limit` | int | `100` | The most certificates to model per source certificate. |
| `--chain` | flag | false | Also model each certificate's chain. |

| `--by` | Returns | Shared value |
| --- | --- | --- |
| `issued` | Certificates issued by the source certificate's CA. The source must be a CA certificate. Newest first. | `ISSUER_CA_ID` = the CA the source certificate belongs to (`ca_certificate`) |
| `siblings` | Other certificates issued by the same CA, newest first. | `ISSUER_CA_ID` |
| `key` | Certificates with the same public key. | SHA-256 of `x509_publicKey()` |
| `subject` | Certificates with the same subject name. | SHA-1 of `x509_name()` |
| `serial` | Certificates with the same serial, ex. a precertificate and its certificate, or certificates from other CAs. | `x509_serialNumber()` |
| `ski` | Certificates with the same subject key identifier. | `x509_subjectKeyIdentifier()` |

For `key`, `subject`, `serial`, and `ski`, crt.sh returns any `--limit` matches (not
necessarily the newest), which the service then sorts newest first. With `--no-precerts`, the
service asks crt.sh for twice `--limit` so precertificates don't use up the limit.

Inbound forms: `crypto:x509:cert`. Yields the related `crypto:x509:cert` nodes.

When a pivot finds nothing, the service explains why with a warning where it can:

- `crt.sh has no certificate with <kind> <valu>`: the source isn't in crt.sh.
- `Unable to pivot by <by>: Unable to parse certificate: ...`: the source couldn't be parsed.
- `The certificate has no <by> to pivot on.`: ex. no SKI extension.
- `crt.sh doesn't know of a CA for certificate <valu>, it may not be a CA certificate.`:
  `--by issued` from a certificate that isn't a CA's.

```text
crypto:x509:cert#rep.crtsh.ca | slib.crtsh.pivot --by issued --valid --limit 500
crypto:x509:cert=* | slib.crtsh.pivot --by key
slib.crtsh.pivot --by serial --cert 12337892544
```

### slib.crtsh.chain

Model every chain from certificates up to their roots and yield every certificate in them.

```text
slib.crtsh.chain [--cert <valu> ...] [--print]
```

Requires `slib.crtsh.user`.

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--cert` | str, repeatable | `[]` | A crt.sh ID, SHA-256, or SHA-1 to build the chain of instead of the inbound nodes. |
| `--print` | flag | false | Print each chain, one line per certificate: `crt.sh ID <id>: <subject DN>`. |

crt.sh groups certificates by CA (a name and key pair), so a certificate's issuer may have
several certificates: cross-signs and reissues. Each one is a possible parent, so a certificate
can have several chains. The service builds all of them in one recursive query:

- It walks up through every certificate of the issuing CA, at most 10 levels and 500 rows.
- A self-issued root (a certificate that belongs to the CA that issued it) ends a chain.
- Each path never revisits a certificate, so cross-signing loops end.
- At most 100 certificates, the closest to the leaf, are returned, and at most 50 paths.

Each certificate's `:issuer:cert` is set to its **preferred** parent: one that was valid when
the child was issued (child notBefore within the parent's validity), preferring
non-precertificates, then the one that expires last.

Inbound forms: `crypto:x509:cert`. Yields every certificate in the chains, the leaf first.

```text
crypto:x509:cert:sha256=<sha256> | slib.crtsh.chain --print
slib.crtsh.chain --cert 12337892544
```

`--print` output looks like this:

```text
Chain 1:
    crt.sh ID 10: CN=www.vertex.link,OU=Engineering,O=The Vertex Project,C=US
    crt.sh ID 2: CN=Test Issuing CA 1,O=Test Trust,C=US
    crt.sh ID 1: CN=Test Root R1,O=Test Trust,C=US
Chain 2:
    ...
```

## CAs

### slib.crtsh.ca

Find crt.sh CAs by name or ID and print them. Optionally model their own certificates, or the
certificates they issued.

```text
slib.crtsh.ca [<name>] [--id <caid> ...] [--certs] [--issued] [--valid] [--since <time>]
              [--until <time>] [--expires-after <time>] [--expires-before <time>]
              [--no-precerts] [--limit <n>] [--chain]
```

Requires `slib.crtsh.user`.

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | str, optional | none | A substring of the CA's name (its DN), matched case-insensitively. |
| `--id` | int, repeatable | `[]` | A crt.sh CA ID. |
| `--certs` | flag | false | Model and yield the CAs' own certificates. |
| `--issued` | flag | false | Model and yield the certificates the CAs issued. |
| `--valid` | flag | false | With `--issued`, only certificates that haven't expired. |
| `--since` | time | none | With `--issued`, only certificates issued on or after this time. |
| `--until` | time | none | With `--issued`, only certificates issued before this time. |
| `--expires-after` | time | none | With `--issued`, only certificates that expire on or after this time. |
| `--expires-before` | time | none | With `--issued`, only certificates that expire before this time. |
| `--no-precerts` | flag | false | With `--issued`, exclude precertificates. |
| `--limit` | int | `100` | The most CAs, and the most issued certificates. |
| `--chain` | flag | false | With `--issued`, also model each certificate's chain. |

A name or `--id` is required (`BadArg: slib.crtsh.ca requires a CA name or --id.`). A name and
IDs together match CAs that satisfy either. The CAs (at most `--limit`, lowest crt.sh CA ID
first) are printed as a table:

```text
ca id      certs  name
2          2      C=US, O=Test Trust, CN=Test Issuing CA 1
```

`certs` is the number of certificates crt.sh has for that CA (here, the tests' issuing CA,
which has a certificate signed by each of two roots). When nothing matches, it prints
`slib.crtsh.ca: No matching CAs.`.

The command takes no inbound nodes (they're dropped). Without `--certs` or `--issued` it yields
nothing. `--issued` returns the newest certificates of every matching CA (each CA walks the
`(ISSUER_CA_ID, notBefore)` index newest first), and then the service keeps the newest
`--limit` across all of them.

```text
slib.crtsh.ca "Let's Encrypt"
slib.crtsh.ca --id 183267 --certs
slib.crtsh.ca --id 183267 --issued --valid --limit 1000
```

## Admin commands

### slib.crtsh.admin.tags

Configure the tags slib.crtsh applies. Prints the settings, and changes them when options are
given.

```text
slib.crtsh.admin.tags [--prefix <tag>] [--enable | --disable]
```

Requires `slib.crtsh.admin`.

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--prefix` | str | none | The tag prefix to use. |
| `--enable` | flag | false | Enable tagging. |
| `--disable` | flag | false | Disable tagging. |

The prefix must already be a normalized tag name, apart from case and surrounding whitespace.
`My.Tags` is stored as `my.tags`, but `my tags` or `#my.tags` are refused
(`BadArg: slib.crtsh.admin.tags: <prefix> isn't a valid tag name.`) instead of being silently
rewritten. `--enable` and `--disable` together raise `BadArg`. The settings are stored in the
Cortex globals `slib:crtsh:tag:prefix` and `slib:crtsh:tag:enabled`. The command prints:

```text
slib.crtsh tags: enabled=true prefix=rep.crtsh
```

The tags themselves are described in [Data model](model.md#tags).

```text
slib.crtsh.admin.tags
slib.crtsh.admin.tags --prefix my.crtsh
slib.crtsh.admin.tags --disable
```

### slib.crtsh.admin.sql

Run a raw SQL query against the crt.sh database and print the rows as JSON.

```text
slib.crtsh.admin.sql <sql> [--args <list>] [--limit <n>]
```

Requires `slib.crtsh.admin`.

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `sql` | str | | The SQL to run. |
| `--args` | any | none | A list of positional query arguments for `$1`, `$2`, and so on. |
| `--limit` | int | `100` | The most rows to return. Capped by `crtsh:sql:limit` (1000 by default). |

It prints `<n> rows` (or `<n> rows (the --limit, there may be more)` when exactly `--limit`
came back), then the rows as indented JSON. In the rows, bytes are lowercase hex, timestamps are
epoch milliseconds, arrays are lists, and any other type that isn't a str, int, float, bool, or
null is converted with `str()`.

The SQL must be a single query that returns rows (`SELECT`, `VALUES`, `TABLE`, or
`WITH ... SELECT`). It is wrapped as `SELECT * FROM (<sql>) q LIMIT <limit>`, so statements like
`SET`, `COMMIT`, `SHOW`, `EXPLAIN`, or data-modifying statements are rejected by PostgreSQL.
Trailing semicolons and whitespace are stripped. In the same statement, the wrapper also:

- sets `transaction_read_only` before the query runs,
- sets back any session setting the query changed, before its rows are returned,
- releases every session advisory lock (`pg_advisory_unlock_all()`).

Queries that mention `pg_advisory_lock`, `pg_advisory_lock_shared`, `pg_try_advisory_lock`, or
`pg_try_advisory_lock_shared` anywhere (even in a comment or string), or that use a Unicode
escaped identifier (`U&"..."`), are refused. The `pg_advisory_xact_lock` functions are allowed.

The arguments stay query parameters, so the query runs as one plain extended-protocol
statement under the **server's** `statement_timeout` (30s on crt.sh), not
`crtsh:statement:timeout`. Narrow heavy queries, for example with a notAfter window on the
partition key. [Raw SQL](database.md#raw-sql) has the details and limits.

Arguments must have the type the SQL expects. In Storm, `((183267),)` is a list holding an int,
and `(183267,)` a list holding a str:

```text
slib.crtsh.admin.sql "SELECT id, name FROM ca WHERE id = $1" --args ((183267),)
slib.crtsh.admin.sql "SELECT count(*) FROM ct_log" --limit 1
```

## Library

The commands are thin wrappers around the `slib.crtsh.lib` Storm module, which you can also
use directly:

```text
$crtsh = $lib.import(slib.crtsh.lib)
for $cert in $crtsh.lookup((1234567,)) { $lib.print($cert) }
```

See [Storm modules](api.md#storm-modules).
