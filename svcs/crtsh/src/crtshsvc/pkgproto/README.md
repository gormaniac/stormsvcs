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
> indexes, every query runs against a PostgreSQL stub of crt.sh, directly and behind PgBouncer in
> statement pooling mode like crt.sh's, and the live test passed against crt.sh itself (2026-10,
> about 6.5 minutes, before the statement pooling fix in 0.6.0). See [Testing](#testing).

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

crt.sh's PgBouncer pools by **statement**: each statement may run on a different server
connection, explicit transactions (`BEGIN`, savepoints) are refused ("transaction blocks not
allowed in statement pooling mode"), and a session `SET` only reaches the server connection that
ran it (where it stays, for other clients). Its guest role's `statement_timeout` is 30s. So every
query is a single round trip without an explicit transaction, which also works behind
transaction or session pooling and against plain PostgreSQL:

- The service's own queries are one simple-query message, `SET statement_timeout = <ms>;
  SET LOCAL bytea_output = hex; SET TRANSACTION READ ONLY; COPY (<query as JSON rows>) TO STDOUT;
  RESET statement_timeout`. The statements of one message run in one implicit transaction on
  one server connection, so the query gets `crtsh:statement:timeout` and read-only mode. The
  timeout is a session `SET` because crt.sh's PostgreSQL 12 ignores a `SET LOCAL` there (it still
  cancels at its own timeout, checked live); the `RESET` ends it, and if the query fails the
  aborted implicit transaction reverts it, so it never stays on the shared server connection. A simple
  query has no parameters, so their arguments are inlined as escaped literals (user text is only
  ever an argument). If the server refuses the `SET`s, the queries run under its own timeout.
- Startup parameters can't set the timeout: PgBouncer rejects `statement_timeout` as an
  "unsupported startup parameter", ignores it when it's in `ignore_startup_parameters`, and can't
  track it (PostgreSQL doesn't report it), and a `set_config()` inside a query only affects later
  statements.
- `slib.crtsh.admin.sql` queries keep their parameters, so they run as one plain query under
  crt.sh's 30s (see [Raw SQL](#raw-sql)).

Queries run one at a time, so every query is bounded: by its `statement_timeout`, and the service
stops waiting after `crtsh:timeout`. Setting both to `0` lets one slow query block every other
call.

crt.sh's guest role is read-only and its database is a read-only replica, so dropping explicit
`BEGIN READ ONLY` transactions doesn't allow writes there. The service's queries still run read-only
(`SET TRANSACTION READ ONLY`), and admin.sql queries too (see below).

### Configuration

| Option | Default | Description |
|---|---|---|
| `crtsh:dsn` | `postgresql://guest@crt.sh:5432/certwatch` | The database DSN (or a mirror's). |
| `crtsh:timeout` | `660` | Seconds before the service gives up waiting on a query, `0` for none. Keep it longer than `crtsh:statement:timeout`. |
| `crtsh:statement:timeout` | `600` | The `statement_timeout` of each of the service's queries (a `SET LOCAL` sent with the query), in seconds, `0` for none. crt.sh's default (30s) cancels big queries. admin.sql runs under crt.sh's. |
| `crtsh:retries` | `3` | Retries when the connection drops mid-query. |
| `crtsh:timeout:retries` | `1` | Retries of a query crt.sh cancels for its statement timeout (a heavy search often finishes when rerun on crt.sh's warm cache), `0` for none. |
| `crtsh:keepalive` | `10` | Seconds between keepalive pings while the connection is in use. |
| `crtsh:idle` | `300` | Seconds without a query before the connection is closed. |
| `crtsh:connect:timeout` | `300` | Seconds to keep retrying (with backoff) when crt.sh refuses a connection. |
| `crtsh:limit` | `10000` | Max certificates any call returns. Limits below 1 are errors. |
| `crtsh:sql:limit` | `1000` | Max rows `slib.crtsh.admin.sql` returns. |
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
| `slib.crtsh.search` | Search by `--dns`, `--cn`, `--org`, `--ou`, `--email`, `--ip`, `--uri`, `--subject`, `--identity` (whole words, or a prefix with a trailing `*`), `--issuer`, `--caid`, with `--valid`, `--since`, `--until`, `--expires-after`, `--expires-before`, `--no-precerts`. See [Search matching](#search-matching). |
| `slib.crtsh.pivot` | From certs to related certs: `--by issued`, `siblings`, `key`, `subject`, `serial`, `ski`. |
| `slib.crtsh.chain` | Model every chain from a cert up to its root(s), setting `:issuer:cert`. |
| `slib.crtsh.ca` | Find CAs by name/ID, model their certs (`--certs`) or what they issued (`--issued`, with `--valid`, `--since`, `--until`, `--expires-after`, `--expires-before`). |
| `slib.crtsh.admin.tags` | Configure the `precert`, `revoked`, `ca`, and `root` tags (prefix `rep.crtsh`). A `--prefix` that isn't a valid tag name is refused. |
| `slib.crtsh.admin.sql` | Run a raw SQL query against crt.sh, at most `--limit` rows. |

Explicit values (`slib.crtsh.cert <valus>`, `--cert`, or any `slib.crtsh.search` option) are
queried once and replace the inbound nodes. Without values or inbound nodes, the commands warn.

### Search matching

crt.sh searches identities with PostgreSQL full text search, which matches whole words, domains,
and addresses, not substrings. `--org vertex` matches "The Vertex Project" and `--cn vertex.link`
matches `www.vertex.link`, but `--cn old` doesn't match `old.vertex.link` and `--email visi`
doesn't match `visi@vertex.link`. `--dns` matches the domain and its subdomains (a leading `*.` or
`.` is ignored), `--ip` matches the address exactly (in any notation), and `--exact` requires
whole field values.

A trailing `*` makes the last word a prefix (the tsquery `'microsoft':*`):
`--cn "microsoft*"` matches any indexed word that starts with `microsoft`, and crt.sh indexes
every parent domain as a word, so it matches `microsoftonline.com` and
`login.microsoftonline.com`. Other words in the value are still whole words (`--org "Vertex
Proj*"`). There's no suffix or substring search: `fakemicrosoft.com` doesn't match
`microsoft*`. A prefix can't be `--exact`. The prefix is one quoted, lowercased
tsquery operand, so no user text is read as tsquery syntax, and punctuation stays in the word
(`microsoft-sup*` matches `microsoft-support.ph`).

Prefixes of common words are much heavier than exact words, and with `--valid` or `--since` on
recent certificates (the newest partitions) they may time out. Heavy searches can time out on
crt.sh's cold cache and then finish when rerun, so a query crt.sh cancels for its statement
timeout is retried once (`crtsh:timeout:retries`, logged as a warning). A search that still
times out fails with the usual "crt.sh canceled the query (statement timeout)" error.

`--since`/`--until` bound when a certificate was issued (notBefore), `--expires-after`
(inclusive) and `--expires-before` (exclusive) when it expires (notAfter). crt.sh partitions
`certificate` on notAfter (`coalesce(x509_notAfter(CERTIFICATE), 'infinity')`; the recent
partitions are quarterly, ex. `c2027q1` holds notAfter in 2027 Q1), and the expiry bounds are
written on that expression, so PostgreSQL only scans the partitions in range. They're the way to
keep a heavy search to one partition, ex. `--cn "microsoft*" --issuer "Let's Encrypt"
--expires-after 2027-01-01 --expires-before 2027-04-01`. A certificate without a notAfter never
matches `--expires-before`. They take the same times as `--since` and combine with `--valid`,
`--since`, and `--until`; `--expires-after` must be before `--expires-before`.

Searches work like crt.sh's own: the text is found with crt.sh's full text index first (up to
`crtsh:candidates` certificates), so it must be a whole word (or a prefix of one) somewhere in
the certificate (ex. `microsoft` finds `microsoft--web-hosting.tk` and
`O=Microsoft Corporation`, but not `login.microsoftonline.com` alone), and the candidates are
then matched field by field. `--issuer`/`--caid` filter those candidates too: nothing indexes a
word and an issuer together, so a common word with a rare issuer (`--cn microsoft --issuer
"Let's Encrypt"`) only finds the matches among the first `crtsh:candidates` candidates.
`--since` and `--valid` move the candidates to newer certificates.

### Raw SQL

`slib.crtsh.admin.sql` runs a single query that returns rows (`SELECT`, `VALUES`, `TABLE`, or
`WITH ... SELECT`), wrapped as `SELECT * FROM (<sql>) q LIMIT <limit>`. Statements like `SET`,
`COMMIT`, `SHOW`, or `EXPLAIN` aren't accepted, and neither are data-modifying ones.

Its arguments stay query parameters, so it's one plain (extended protocol) statement and runs
under crt.sh's own `statement_timeout` (30s), not `crtsh:statement:timeout`: narrow heavy queries
(ex. an expiry window on the `certificate` partition key, see the searches above), or run them
in psql with `SET statement_timeout = 0 \;` in front and `\; RESET statement_timeout` after
(see [Testing](#testing)).

With statement pooling there's no transaction to roll back, so the wrapper does it in the same
statement, ordered by the plan (`RAW_SQL` in `db.py`, checked with `EXPLAIN ANALYZE` and against
PgBouncer by `test_pg.py`):

- `transaction_read_only` is set before the query runs, so functions that write (ex.
  `nextval`, `lo_create`) fail, and the query can't turn it back off.
- The session's settings are snapshotted first and any the query changed (ex.
  `set_config('search_path', ..., false)`) are set back before its rows are returned. A query
  that fails aborts its implicit transaction, which undoes them too. Placeholder settings a query
  creates (`set_config('x.y', ...)`) aren't removed.
- Every session advisory lock is released (`pg_advisory_unlock_all()`) after the query and
  before its rows are returned, even ones taken through dynamic SQL (ex. `query_to_xml`) or by a
  query that returns no rows. As a first line, queries that mention `pg_advisory_lock` and
  friends anywhere (even in a comment or string) are refused, as are Unicode escaped identifiers
  (`U&"..."`) that could spell them; the `pg_advisory_xact_lock` ones work.
- **Limitation:** a query that takes a session advisory lock (only possible through dynamic SQL)
  and then *fails* can't release it in its statement. The service sends
  `SELECT pg_advisory_unlock_all()` next, which reaches the same session directly or behind
  session pooling, but behind statement pooling (crt.sh) or transaction pooling it may land on
  another server connection, leaving the lock on that PgBouncer server connection until
  PgBouncer closes it. The service's own queries never take advisory locks, so they aren't
  affected.
- These protections run inside the statement the raw SQL is part of, so they guard against
  mistakes and dynamic SQL, not deliberately malformed SQL (ex. unbalanced parentheses that
  restructure the wrapper). On crt.sh the read-only guest role and replica are what keep data
  from changing; only point `crtsh:dsn` at a writable account if everyone allowed to run
  admin.sql may write.

The library behind the commands is the `slib.crtsh.lib` Storm module, ex.
`for $cert in $lib.import(slib.crtsh.lib).lookup((1234567,)) { $lib.print($cert) }`.

## Modeling

Each certificate is a `crypto:x509:cert` (deconflicted by `:sha256`) with every prop the model
supports, `:rsa:key` (with the `rsa:key`'s `:bits`), a `-(refs)>` edge to its `crypto:key`, `crypto:x509:revoked` when it's on
a CRL, `.seen` covering its CT log entries, and a `-(seen)>` edge from the `slib.crtsh`
`meta:source`. The complete details are stored in the node's `slib:crtsh` node data, including
what the model has no place for (EC curves and key sizes, revocation times and reasons).

## Testing

```bash
uv run pytest tests
```

The tests never touch crt.sh. `tests/fakecrtsh.py` is an in-memory crt.sh: a small PKI (two
roots, an intermediate cross-signed by both, a leaf and its precertificate, plus revoked,
expired, reissued, and unparsable certificates) answering every query `CrtshDb` makes. The
tests cover 100% of the Python (lines and branches, `uv run pytest tests --cov`) and every Storm
command, option, inbound form, and error path. The fakes match full text searches the way crt.sh
does: `identityText()` ports crt.sh's `identities()`, and `tsTokens()` makes the words PostgreSQL's
parser does of it (checked against crt.sh's live output, and against PostgreSQL by `test_pg.py`).

CI also runs every query against a real PostgreSQL (16 is fine), using a stub of crt.sh's schema (the same
tables, partitions, indexes, and view, with SQL stubs for libx509pq's functions) loaded with the
same test certificates. The database's public schema is replaced:

```bash
SLIB_CRTSH_PGDSN=postgresql://postgres@127.0.0.1:5432/certwatch uv run pytest tests/test_pg.py
```

CI runs them a second time through PgBouncer in statement pooling mode, like crt.sh's, which
refuses explicit transactions. Locally, with a `pgbouncer.ini` of `pool_mode = statement` in
front of the same database (ex. on port 6432):

```bash
SLIB_CRTSH_PGDSN=postgresql://postgres@127.0.0.1:6432/certwatch uv run pytest tests/test_pg.py
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

Each query is sent as `SET statement_timeout = '600s' \; <query> \; RESET statement_timeout`:
psql's `\;` sends them in one message, one implicit transaction, so the timeout reaches the
query behind statement pooling and doesn't stay on the server connection (`SET LOCAL` doesn't
take effect on crt.sh's PostgreSQL 12). A plain `SET statement_timeout = 0;`
line (or `SET ...; SELECT ...;` on one line, which psql sends as two messages) only reaches
whichever server connection ran it, and stays there.

`--stub` generates the same queries with values from the test certificates, for the stub database.
