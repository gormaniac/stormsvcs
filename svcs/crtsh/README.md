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

> **Status:** the SQL in `src/crtshsvc/db.py` follows the certwatch schema
> (https://github.com/crtsh/certwatch_db) and libx509pq sources, every query uses one of crt.sh's
> indexes, and every query runs against a PostgreSQL stub of crt.sh (see [Testing](#testing)).

crt.sh's database is slow per round trip (often 20s+ even for trivial queries) rather than per
row, so every operation is a single query: lookups, searches, and pivots return each certificate
with its crt.sh metadata (issuer CA, CA membership, CT log entries, CRL revocation) in the same
query, a chain is one recursive query, and an issuer's name or a pivot's source certificate are
subqueries.

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

crt.sh's database is behind PgBouncer, which allows **one connection per client** and drops
idle clients quickly. The service uses a single connection, queues every query on it, keeps
it alive while it's busy, closes it after `crtsh:idle` seconds, and reconnects with backoff
when crt.sh refuses a new connection. While the service holds the connection, other clients
on the same IP (ex. psql) are refused, and vice versa.

### Configuration

| Option | Default | Description |
|---|---|---|
| `crtsh:dsn` | `postgresql://guest@crt.sh:5432/certwatch` | The database DSN (or a mirror's). |
| `crtsh:timeout` | `0` | Seconds before a query times out, `0` for none. crt.sh can be very slow. |
| `crtsh:retries` | `3` | Retries when the connection drops mid-query. |
| `crtsh:keepalive` | `10` | Seconds between keepalive pings while the connection is in use. |
| `crtsh:idle` | `300` | Seconds without a query before the connection is closed. |
| `crtsh:connect:timeout` | `300` | Seconds to keep retrying (with backoff) when crt.sh refuses a connection. |
| `crtsh:limit` | `10000` | Max certificates any call returns. |
| `crtsh:candidates` | `10000` | Max full text search candidates a search filters. |

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

## Testing

```bash
uv run pytest tests
```

The tests never touch crt.sh. `tests/fakecrtsh.py` is an in-memory crt.sh: a small PKI (two
roots, an intermediate cross-signed by both, a leaf and its precertificate, plus revoked,
expired, reissued, and unparsable certificates) answering every query `CrtshDb` makes. The
tests cover 100% of the Python (lines and branches, `uv run pytest tests --cov`) and every Storm
command, option, inbound form, and error path.

Every query against a real PostgreSQL (16 is fine), using a stub of crt.sh's schema (the same
tables, partitions, indexes, and view, with SQL stubs for libx509pq's functions) loaded with the
same test certificates. The database's public schema is replaced:

```bash
SLIB_CRTSH_PGDSN=postgresql://postgres@127.0.0.1:5432/certwatch uv run pytest tests/test_pg.py
```

Against the real crt.sh (one connection per IP, so close psql first; takes a few minutes):

```bash
SLIB_CRTSH_LIVE=1 uv run pytest tests/test_live.py -v
```

Every query the service runs, as a psql script, generated from `CrtshDb` by `tests/sqlgen.py`:

```bash
uv run python -m tests.sqlgen > tests/live_queries.sql
psql -h crt.sh -p 5432 -U guest certwatch -f tests/live_queries.sql
```

`--stub` generates the same queries with values from the test certificates, for the stub database.
