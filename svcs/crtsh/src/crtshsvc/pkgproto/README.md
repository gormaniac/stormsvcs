# crtsh

A Synapse Advanced Power-Up (Storm Service) for [crt.sh](https://crt.sh). It queries crt.sh's
public, read-only PostgreSQL database directly instead of scraping the website:

```bash
psql -h crt.sh -p 5432 -U guest certwatch
```

Every certificate a lookup, search, or pivot returns is pulled as DER and fully parsed, so each
one is modeled with its complete details: hashes, serial, subject/issuer, validity, signature,
public key, SANs, extensions (basic constraints, key usage, EKU, SKI/AKI, CRL/OCSP/CA issuer URLs,
policies, SCTs), precert status, plus crt.sh's own data: crt.sh ID, issuing CA, CT log entries,
and CRL revocation.

The service registers the `slib.crtsh` Storm package.

> **Status:** work in progress. The SQL in `src/crtshsvc/db.py` follows the certwatch schema
> (https://github.com/crtsh/certwatch_db) but hasn't been validated against the live database yet.

## Deploying

```bash
docker run -d --name slib-crtsh \
    -v /srv/slib-crtsh:/vertex/storage \
    -p 27492:27492 \
    ghcr.io/gormaniac/stormsvcs/crtsh:latest
```

```
service.add slib.crtsh tcp://<user>:<passwd>@<host>:27492/*
```

The host needs outbound access to `crt.sh` on TCP 5432.

### Configuration

| Option | Default | Description |
|---|---|---|
| `crtsh:dsn` | `postgresql://guest@crt.sh:5432/certwatch` | The database DSN (or a mirror's). |
| `crtsh:poolsize` | `2` | Max connections. crt.sh limits connections per IP. |
| `crtsh:timeout` | `120` | Seconds before a query times out. |
| `crtsh:retries` | `2` | Retries for transient failures (replica conflicts, dropped connections). |
| `crtsh:limit` | `10000` | Max certificates any call returns. |
| `crtsh:candidates` | `20000` | Max full text search candidates a search filters. |

## Permissions

| Permission | Grants |
|---|---|
| `slib.crtsh.user` | Lookups, searches, pivots, and chains. |
| `slib.crtsh.admin` | Tag settings and raw SQL. |

## Commands

| Command | Description |
|---|---|
| `slib.crtsh.cert` | Look up certs by crt.sh ID, SHA-256, SHA-1, serial, SKI, SPKI hash, or subject hash. |
| `slib.crtsh.search` | Search by `--dns`, `--cn`, `--org`, `--ou`, `--email`, `--ip`, `--uri`, `--subject`, `--identity`, `--issuer`, `--caid`, with `--valid`, `--since`, `--until`, `--no-precerts`. |
| `slib.crtsh.pivot` | From certs to related certs: `--by issued`, `siblings`, `key`, `subject`, `serial`, `ski`. |
| `slib.crtsh.chain` | Model every chain from a cert up to its root(s), setting `:issuer:cert`. |
| `slib.crtsh.ca` | Find CAs by name/ID, model their certs (`--certs`) or what they issued (`--issued`). |
| `slib.crtsh.admin.tags` | Configure the `precert`, `revoked`, `ca`, and `root` tags (prefix `rep.crtsh`). |
| `slib.crtsh.admin.sql` | Run raw read-only SQL against crt.sh. |

## Modeling

Each certificate is a `crypto:x509:cert` (deconflicted by `:sha256`) with every prop the model
supports, `:rsa:key`, a `-(refs)>` edge to its `crypto:key`, `crypto:x509:revoked` when it's on
a CRL, `.seen` covering its CT log entries, and a `-(seen)>` edge from the `slib.crtsh`
`meta:source`. The complete details are stored in the node's `slib:crtsh` node data.
