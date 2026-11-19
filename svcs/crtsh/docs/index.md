# crt.sh

`crtsh` is a Synapse Advanced Power-Up (Storm Service) for [crt.sh](https://crt.sh), the
certificate transparency (CT) search engine. It doesn't scrape the website or call a web API.
Instead it queries crt.sh's public, read-only PostgreSQL database (`certwatch`) directly, the
database you would reach with:

```bash
psql -h crt.sh -p 5432 -U guest certwatch
```

The service registers the `slib.crtsh` Storm package. The Python package is `crtshsvc`. The
current version is 0.6.0.

## What it does

- **Lookups** by crt.sh ID, SHA-256, SHA-1, serial number, subject key identifier (SKI), SPKI
  hash (SHA-256 or SHA-1), or subject name hash
  ([`slib.crtsh.cert`](commands.md#slibcrtshcert)).
- **Searches** of certificate identities (DNS names, CN, O, OU, email, IP, URI, the whole
  subject DN, or any identity), filtered by issuer, crt.sh CA ID, validity, notBefore, and
  notAfter. These use crt.sh's own full text index, and a trailing `*` turns the last word into
  a prefix ([`slib.crtsh.search`](commands.md#slibcrtshsearch)).
- **Pivots** from a certificate to the certificates its CA issued, its siblings (the same
  issuing CA), and certificates with the same public key, subject, serial, or SKI
  ([`slib.crtsh.pivot`](commands.md#slibcrtshpivot)).
- **Chains**: every path from a certificate up to its root(s), including cross-signs and
  reissues, in one recursive query
  ([`slib.crtsh.chain`](commands.md#slibcrtshchain)).
- **CAs**: crt.sh CAs by name or ID, their own certificates, and the certificates they issued
  ([`slib.crtsh.ca`](commands.md#slibcrtshca)).
- **Raw SQL** for admins, read-only and row-limited
  ([`slib.crtsh.admin.sql`](commands.md#slibcrtshadminsql)).

The service pulls every certificate as DER and parses it fully (with `cryptography`), so every
certificate a lookup, search, or pivot returns has the same complete set of details: hashes,
serial, subject and issuer, validity, signature, public key, SANs, extensions (basic
constraints, key usage, EKU, SKI/AKI, CRL/OCSP/CA issuer URLs, policies, SCTs), and precert
status. It adds crt.sh's own data from the same query: the crt.sh ID, the issuing CA, CA
membership, CT log entries, and CRL revocation. Each certificate is modeled as a
`crypto:x509:cert` with every prop the Synapse model has a place for. The complete details are
stored in the node's `slib:crtsh` node data (see [Data model](model.md)).

## Architecture

```text
Storm user
   |  slib.crtsh.* commands, $lib.import(slib.crtsh.lib)
   v
slib.crtsh Storm package (in the Cortex)
   |  slib.crtsh.priv.user / priv.admin (asroot) -> $lib.service.get("slib.crtsh")
   v  Telepath (TelepathRetn {status, mesg, data})
CrtshSvc cell (crtshsvc.svc) -- CrtshCellApi (stormlibpp.svc.RetnApi)
   |  validation, normalization (crtshsvc.norm), sorting, filtering
   v
CrtshDb (crtshsvc.db): one queued asyncpg connection
   |  PostgreSQL wire protocol, TCP 5432
   v
crt.sh PgBouncer (statement pooling) -> certwatch read-only replica
```

- The **cell** ({src}`svcs/crtsh/src/crtshsvc/svc.py`) owns the compute. It turns identifiers
  into database values, picks the query, parses each certificate's DER, sorts newest first,
  and applies the search filters that SQL can't express.
- **`CrtshDb`** ({src}`svcs/crtsh/src/crtshsvc/db.py`) is the only code that talks to
  PostgreSQL. crt.sh is slow per round trip (often 20s or more, even for trivial queries), so
  every operation is one query. The certificate's metadata, an issuer's name, and a pivot's
  source certificate are all subqueries. crt.sh's PgBouncer allows one connection per client
  IP and pools by statement, so the service uses a single queued connection and never opens an
  explicit transaction (see [Database access](database.md)).
- The **Storm package** ({src}`svcs/crtsh/src/crtshsvc/pkgproto/slib.crtsh.yaml`) is the entry
  point. It calls the service through privileged modules, so users don't need `service.get`.
  It models the results as the calling user.

## Quick start

1. Run the container. The host needs outbound TCP 5432 to `crt.sh`:

   ```bash
   docker run -d --name slib-crtsh \
       -v /srv/slib-crtsh:/vertex/storage \
       -e SYN_CRTSHSVC_AUTH_PASSWD=secret \
       -p 27492:27492 \
       ghcr.io/gormaniac/stormsvcs/crtsh:latest
   ```

2. Add it to the Cortex and check that the package loaded:

   ```text
   service.add slib.crtsh tcp://root:secret@<host>:27492/*
   service.list
   ```

3. Grant users `slib.crtsh.user` (lookups, searches, pivots, chains) and the node permissions
   needed to write what it models. Grant admins `slib.crtsh.admin` (see
   [Permissions](deployment.md#permissions)).

4. Run a first command:

   ```text
   slib.crtsh.search --dns vertex.link --valid --limit 20
   ```

The defaults point at crt.sh itself (`postgresql://guest@crt.sh:5432/certwatch`), so you don't
need any configuration. Tagging is on by default under `rep.crtsh`.

```{toctree}
:maxdepth: 2

deployment
commands
model
api
internals
database
```
