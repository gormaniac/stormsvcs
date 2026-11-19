# Database access

All database access is in `CrtshDb` ({src}`svcs/crtsh/src/crtshsvc/db.py`), the only class that
talks to PostgreSQL. This page covers how it connects, how each query is sent, how timeouts
and retries work, and the SQL behind each operation.

## crt.sh's database

crt.sh exposes its `certwatch` database to anyone as a read-only replica
(`postgresql://guest@crt.sh:5432/certwatch`, no password). The queries only depend on these
parts of the [certwatch schema](https://github.com/crtsh/certwatch_db):

| Object | Used for |
| --- | --- |
| `certificate (ID, ISSUER_CA_ID, CERTIFICATE)` | Every certificate and precertificate, as DER. Range partitioned on notAfter. |
| `ca (ID, NAME)` | Every issuing CA (a name and key pair). |
| `ca_certificate (CERTIFICATE_ID, CA_ID)` | Which certificates belong to a CA (one CA each). |
| `ct_log (ID, NAME, URL, OPERATOR)`, `ct_log_entry (CERTIFICATE_ID, CT_LOG_ID, ENTRY_ID, ENTRY_TIMESTAMP)` | Where and when each certificate was logged. |
| `crl_revoked (CA_ID, SERIAL_NUMBER, REASON_CODE, REVOCATION_DATE)` | CRL revocations. |
| `certificate_and_identities` | A view with a row per certificate identity (`NAME_TYPE`, `NAME_VALUE`). |
| `digest()` (pgcrypto), `identities()`, `x509_serialNumber`, `x509_subjectKeyIdentifier`, `x509_publicKey`, `x509_name`, `x509_notBefore`, `x509_notAfter` (libx509pq) | The indexed functions crt.sh's own web UI searches with. |

Everything else about a certificate is parsed from its DER by `crtshsvc.norm`, not by the
database.

Three facts about crt.sh shape the design:

- **It's slow per round trip** (often 20s or more even for trivial queries, since PgBouncer
  queues clients), much more than per row. So every operation is **one query**.
- **PgBouncer allows one connection per client** and drops idle clients
  (`client_idle_timeout`). So the service uses **one queued connection**.
- **PgBouncer pools by statement.** Each statement may run on a different server connection.
  Explicit transactions (`BEGIN`, savepoints) are refused ("transaction blocks not allowed in
  statement pooling mode", and the client is disconnected). A session `SET` lands on whichever
  server connection ran it, and stays there for other clients. So **no query uses an explicit
  transaction**. The guest role's own `statement_timeout` is 30s.

The approach also works behind transaction or session pooling, and against plain PostgreSQL.

## The connection

`CrtshDb` holds a single `asyncpg` connection and an `asyncio.Lock`. Every query waits for the
lock (FIFO), so queries run one at a time, in order.

Opening
: The connection is opened lazily, on the first query, so the service starts even when crt.sh
  is unreachable. It connects with `asyncpg.connect(dsn, statement_cache_size=0, timeout=30)`:
  no prepared statement cache (statement pooling can't keep them), and 30s per connection
  attempt. No startup parameters are sent, since PgBouncer rejects ones it doesn't know.

Backoff
: Reconnecting right after a drop is often refused (`max_client_conn`) until crt.sh notices the
  old connection is gone. A connection attempt that fails with a transient error is retried
  after `delay + random.uniform(0, delay)` seconds. `delay` starts at 1s and doubles up to 30s.
  It stops when the next delay would pass `crtsh:connect:timeout` (300s) from the first
  attempt, and raises `Unable to connect to the crt.sh database: <error>`. A non-transient error
  raises at once. These count as transient:

  - errors whose message contains `max_client_conn`, `too many connections`, `the database
    system is starting up`, `the database system is in recovery mode`, `cannot connect now`,
    `client_idle_timeout`, `server conn crashed`, `server_login_retry`, `query_wait_timeout`,
    or `terminating connection` (case-insensitive),
  - `ConnectionDoesNotExistError`, `InterfaceError`, `ConnectionError`, `OSError`,
    `TimeoutError`, `CannotConnectNowError`, and `TooManyConnectionsError`.

Keepalive and idle close
: Connecting starts a background keepalive task. Every `crtsh:keepalive` (10) seconds it
  checks the connection. If a query holds the lock, it does nothing. Otherwise it takes the
  lock and:

  - if no query has run for `crtsh:idle` (300) seconds, it closes the connection and exits,
    which frees crt.sh's one slot for that IP (ex. for `psql`),
  - else it runs `SELECT 1` (30s timeout) so PgBouncer doesn't drop the client,
  - if that fails, it drops the connection and exits. The next query reconnects.

  So an unused connection closes between `crtsh:idle` and `crtsh:idle + crtsh:keepalive`
  seconds after the last query. A new keepalive task starts with the next connection.

Closing
: The cell's `fini` calls `close()`, which cancels the keepalive and closes the connection
  (5s timeout, then `terminate()`).

## How a query is sent

The service's own queries (everything but raw SQL) are sent as **one simple-query message**:

```sql
SET statement_timeout = 600000; SET LOCAL bytea_output = hex; SET TRANSACTION READ ONLY;
COPY (SELECT row_to_json(crtsh_r)::text FROM (
<the query, with its arguments inlined>
) crtsh_r) TO STDOUT (FORMAT binary); RESET statement_timeout
```

- The statements of one simple-query message run in one implicit transaction, on one server
  connection, even behind statement pooling. So the query gets its own `statement_timeout`
  (`crtsh:statement:timeout` in milliseconds, `0` for none) and runs read-only.
- The timeout is a **session** `SET`, not `SET LOCAL`. On crt.sh's PostgreSQL 12, a
  `SET LOCAL statement_timeout` in the same message doesn't take effect (checked live). The
  `RESET` ends it on success. When the query fails, the implicit transaction aborts and the
  `SET` is reverted. Either way it never stays on the shared server connection.
- Startup parameters can't set the timeout. PgBouncer rejects `statement_timeout` as an
  "unsupported startup parameter", ignores it when it's in `ignore_startup_parameters`, and
  can't track it (PostgreSQL doesn't report it). A `set_config()` inside the query only affects
  later statements.
- `asyncpg`'s `fetch` uses the extended protocol (one statement per message), and its
  simple-query `execute` discards rows. The only simple-query path that returns data is
  `COPY ... TO STDOUT`. So the rows are copied out as one JSON object each (`row_to_json`), in
  binary COPY format so nothing is escaped. The service calls asyncpg's protocol-level
  `copy_out` (what `Connection.copy_from_query` uses), since the public method wraps the
  statement itself.
- A simple query has no parameters, so the arguments are **inlined as literals**
  (`_inline`/`_literal`). This is only done for SQL the service builds itself, where user text
  only ever reaches the query as an argument, so every `$n` is a parameter. It's one regex pass,
  so a literal is never rescanned. The literals:

  | Python value | SQL literal |
  | --- | --- |
  | `None` | `NULL` |
  | `bool` | `TRUE` / `FALSE` |
  | `int` | the decimal number |
  | `float` | `'<repr>'::float8` (NaN and infinity are refused) |
  | `str` | `E'...'` with every `\` and `'` escaped (NUL is refused) |
  | `bytes` | `E'\\x<hex>'::bytea` |
  | `list`/`tuple` | `ARRAY[...]`, or `'{}'` when empty (nested lists are refused) |

- `_copyRows` parses the binary COPY stream (`PGCOPY` signature, header extension, then one
  text column per row) and `json.loads` each row. The `der` column comes back as `\x<hex>`
  (with `bytea_output = hex`) and is decoded back to bytes.

### Fallback to a plain query

If the server refuses the `SET`s (`InsufficientPrivilegeError`, `CantChangeRuntimeParamError`,
or `UndefinedObjectError` with "parameter" in the message), or if the installed asyncpg's
protocol has no `copy_out`, the service logs a warning and runs its queries as plain
`conn.fetch(sql, *args)` calls from then on, until it restarts. Those run under the server's
own `statement_timeout`, without the explicit read-only mode.

## Timeouts and retries

There are two timeouts:

- `crtsh:statement:timeout` (600s) is the server-side `statement_timeout` described above. It
  applies to the service's own queries, not raw SQL.
- `crtsh:timeout` (660s, `0` for none) is a client-side backstop, passed to `copy_out` or
  `fetch`. It covers a query the server never cancels. Keep it longer than the statement
  timeout.

`fetch()` handles each error of a query like this:

| Error | What happens |
| --- | --- |
| `QueryCanceledError` (57014) whose message has "statement timeout" | Retried after 5s, up to `crtsh:timeout:retries` (1) times, logged as a warning (a heavy query can time out on crt.sh's cold cache and finish when rerun). Then `crt.sh canceled the query (statement timeout) after <n>s, try a narrower search: <error>`. |
| `QueryCanceledError` for another reason (ex. "canceling statement due to user request") | Not retried, raised with the same message. |
| Client-side `TimeoutError` | The connection is mid-query, so it's dropped. Raised as `crt.sh query timed out after <crtsh:timeout>s.` |
| `SerializationError` (the replica canceled the query to apply replication) | Retried on the same connection. |
| A connection error (`ConnectionDoesNotExistError`, `InterfaceError`, `ConnectionError`, `OSError`) or a message from the reconnect/backoff lists above | The connection is dropped and the query retried on a new one. |
| Any other PostgreSQL error | Raised as `crt.sh query failed: <error>`, the connection is kept. |
| Any other exception | The connection's state is unknown, so it's dropped and the error re-raised (returned as `Unexpected error: ...`). |
| `asyncio.CancelledError` (the caller went away) | The connection is mid-query, so it's terminated, and the cancel propagates. |

Serialization and connection retries share one counter: the query runs at most
`crtsh:retries + 1` (4) times, then fails with `crt.sh query failed: <last error>`. Statement
timeout retries don't count against it. Reconnecting uses the backoff above. While a query
retries, it keeps the lock, so the queued calls wait.

:::{note}
Because the queries run one at a time, the worst-case wait for a call is the time of every
query queued ahead of it. Each one is bounded by the statement timeout (and its retry) and by
`crtsh:timeout`.
:::

## The queries

Every query that returns certificates is wrapped by `_withMeta`. The certificates are selected
into a materialized CTE `m` (after their `LIMIT`), and the crt.sh metadata is added with
correlated subqueries, like crt.sh's own `certificate_lifecycle` view. So the metadata is only
looked up for the rows actually returned:

```sql
WITH m AS MATERIALIZED (<inner query: ID, ISSUER_CA_ID, CERTIFICATE ...>)
SELECT m.ID AS id, m.ISSUER_CA_ID AS issuer_ca_id, m.CERTIFICATE AS der,
       ca.NAME AS issuer_name,
       ARRAY(SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = m.ID) AS caids,
       (SELECT json_agg(json_build_object(
                    'log', ctl.NAME, 'url', ctl.URL, 'operator', ctl.OPERATOR, 'index', ctle.ENTRY_ID,
                    'time', (extract(epoch FROM ctle.ENTRY_TIMESTAMP) * 1000)::bigint)
                ORDER BY ctle.ENTRY_TIMESTAMP)
            FROM ct_log_entry ctle JOIN ct_log ctl ON ctl.ID = ctle.CT_LOG_ID
            WHERE ctle.CERTIFICATE_ID = m.ID)::text AS ctlog,
       (SELECT json_build_object(
                    'code', cr.REASON_CODE,
                    'time', (extract(epoch FROM cr.REVOCATION_DATE) * 1000)::bigint)
            FROM crl_revoked cr
            WHERE cr.CA_ID = m.ISSUER_CA_ID AND cr.SERIAL_NUMBER = x509_serialNumber(m.CERTIFICATE)
            LIMIT 1)::text AS revoked
    FROM m LEFT JOIN ca ON ca.ID = m.ISSUER_CA_ID
```

### Lookups: `certs()`

```sql
SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c
WHERE (<cond for kind 1> OR <cond for kind 2> ...) LIMIT $n
```

Each kind's condition matches one of crt.sh's indexed expressions against an array argument:

| Kind | Condition |
| --- | --- |
| `id` | `c.ID = ANY($1::bigint[])` |
| `sha256` | `digest(c.CERTIFICATE, 'sha256') = ANY($1::bytea[])` |
| `sha1` | `digest(c.CERTIFICATE, 'sha1') = ANY($1::bytea[])` |
| `serial` | `x509_serialNumber(c.CERTIFICATE) = ANY($1::bytea[])` |
| `ski` | `x509_subjectKeyIdentifier(c.CERTIFICATE) = ANY($1::bytea[])` |
| `spki` | `digest(x509_publicKey(c.CERTIFICATE), 'sha256') = ANY($1::bytea[])` |
| `spkisha1` | `digest(x509_publicKey(c.CERTIFICATE), 'sha1') = ANY($1::bytea[])` |
| `subjectsha1` | `digest(x509_name(c.CERTIFICATE), 'sha1') = ANY($1::bytea[])` |

A serial is passed in every DER encoding it may have: without leading zero bytes, with a
`00` sign byte when the high bit is set, and as given.

### Searches: `certsByIdentity()`

The full text condition is `<tsquery> @@ identities(c.CERTIFICATE)`. The tsquery is
`plainto_tsquery('certwatch', $1)` for whole words, `$2::tsquery` (a quoted literal like
`'microsoft':*`, lowercased, its quotes and backslashes escaped) for prefixes, or both joined
with `&&`. The prefix literal is cast straight to `tsquery`, not passed to `to_tsquery`, which
would rerun the text parser and turn `'foo-bar':*` into a phrase that never matches crt.sh's
position-less `identities()`.

Without a field pattern (a `--subject` search), the candidates come straight from
`certificate`:

```sql
SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c WHERE <tsquery> @@ identities(c.CERTIFICATE) AND <filters> LIMIT $n
```

With a pattern (every other field), they come from `certificate_and_identities`, with a row
per matching identity that is grouped back into one. The `NAME_TYPE` condition is only added
for fields that have name types (every field but `identity`):

```sql
WITH cand AS MATERIALIZED (
  SELECT c.CERTIFICATE_ID AS ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate_and_identities c
  WHERE <tsquery> @@ identities(c.CERTIFICATE) AND c.NAME_VALUE ILIKE $2
    AND c.NAME_TYPE = ANY($3::text[]) AND <filters> LIMIT $4),
m AS MATERIALIZED (SELECT cand.ID, cand.ISSUER_CA_ID, cand.CERTIFICATE FROM cand
  [WHERE <issuer filters>] GROUP BY cand.ID, cand.ISSUER_CA_ID, cand.CERTIFICATE)
...
```

The name types (as crt.sh's own `web_apis` uses them):

| Field | `NAME_TYPE`s | `ILIKE` pattern |
| --- | --- | --- |
| `dns` | `san:dNSName`, `2.5.4.3` | `%<domain>` (just `<domain>` with `--exact`) |
| `cn` | `2.5.4.3` | `%<value>%` |
| `org` | `2.5.4.10` | `%<value>%` |
| `ou` | `2.5.4.11` | `%<value>%` |
| `email` | `san:rfc822Name`, `1.2.840.113549.1.9.1` | `%<value>%` |
| `ip` | `san:iPAddress` | the address, exactly |
| `uri` | `san:uniformResourceIdentifier` | `%<value>%` |
| `identity` | any | `%<value>%` |

`--exact` patterns have no wildcards, and prefix patterns are `%<word>%`. The value is escaped
for `LIKE` (`\`, `%`, and `_`).

The issuer filters (`cand.ISSUER_CA_ID = ANY($n::int[])` for `--caid`, and
`cand.ISSUER_CA_ID IN (SELECT ca.ID FROM ca WHERE ca.NAME ILIKE '%<issuer>%' LIMIT 1000)` for
`--issuer`) are applied to the materialized candidates, **after** their `LIMIT`. Nothing indexes
a word and an issuer together, so filtering by issuer inside the limit would make PostgreSQL
recheck every certificate with the word until enough are from the issuer. That never finishes
for common words (ex. "microsoft" matches hundreds of millions of certificates, few from Let's
Encrypt). Without an issuer filter or a pattern, the candidate query is the inner query.

### Validity filters: `_filters()`

All bounds are epoch seconds passed to `to_timestamp(...) AT TIME ZONE 'UTC'`. `NOTAFTER_KEY` is
`coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp)`, the expression `certificate`
is partitioned on. A condition on exactly that expression lets PostgreSQL skip whole partitions.

| Option | Conditions |
| --- | --- |
| `valid` | `NOTAFTER_KEY >= date_trunc('year', now() AT TIME ZONE 'UTC')` and `x509_notAfter(c.CERTIFICATE) >= now() AT TIME ZONE 'UTC'` |
| `since` | `x509_notBefore(...) >= t` and `NOTAFTER_KEY >= t` (a certificate can't expire before it was issued) |
| `until` | `x509_notBefore(...) < t` |
| `expires_after` | `x509_notAfter(...) >= t` and `NOTAFTER_KEY >= t` |
| `expires_before` | `x509_notAfter(...) < t` and `NOTAFTER_KEY < t` |

### Issued by a CA: `certsByIssuer()`

```sql
SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM (<CA sources, UNIONed>) cas
CROSS JOIN LATERAL (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c
  WHERE c.ISSUER_CA_ID = cas.CA_ID AND <filters>
  ORDER BY x509_notBefore(c.CERTIFICATE) DESC LIMIT $n) c
```

The CA sources are `SELECT unnest($1::int[]) AS CA_ID` for IDs, the CAs named like the issuer
(at most 1000), and/or the CA of a certificate
(`SELECT cac.CA_ID FROM ca_certificate cac WHERE cac.CERTIFICATE_ID = (SELECT s.ID FROM
certificate s WHERE <lookup> LIMIT 1)`). Each CA is joined `LATERAL` with
`ISSUER_CA_ID = <the CA>`: crt.sh runs PostgreSQL 12, which can only walk the
`(ISSUER_CA_ID, x509_notBefore)` index newest first for a single CA. With `= ANY(...)` it would
read and sort every certificate the CAs ever issued, which times out for big CAs. The `LIMIT`
applies per CA. The service then keeps the newest `limit` overall.

### Pivots: `related()`

```sql
SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE FROM certificate c
WHERE <expr on c> = (SELECT <expr on s> FROM certificate s WHERE <lookup on s> LIMIT 1)
  AND NOT <lookup on c> [AND <valid filters>] [ORDER BY x509_notBefore(c.CERTIFICATE) DESC] LIMIT $n
```

The expression is `digest(x509_publicKey(...), 'sha256')` (key), `digest(x509_name(...),
'sha1')` (subject), `x509_serialNumber(...)` (serial), `x509_subjectKeyIdentifier(...)` (ski), or
`ISSUER_CA_ID` (siblings, the only one ordered newest first). The source certificate is a
subquery, so a pivot is one round trip.

### Chains: `chain()`

```sql
WITH RECURSIVE chain AS (
  (SELECT c.ID, c.ISSUER_CA_ID, c.CERTIFICATE, NULL::bigint AS CHILD_ID, 0 AS DEPTH,
          ARRAY[c.ID] AS PATH FROM certificate c WHERE <lookup> LIMIT 1)
  UNION ALL
  SELECT p.ID, p.ISSUER_CA_ID, p.CERTIFICATE, ch.ID, ch.DEPTH + 1, ch.PATH || p.ID FROM chain ch
  JOIN ca_certificate cac ON cac.CA_ID = ch.ISSUER_CA_ID
  JOIN certificate p ON p.ID = cac.CERTIFICATE_ID
  WHERE ch.DEPTH < $2 AND NOT p.ID = ANY(ch.PATH) AND NOT EXISTS (
    SELECT 1 FROM ca_certificate r WHERE r.CERTIFICATE_ID = ch.ID AND r.CA_ID = ch.ISSUER_CA_ID)),
m AS MATERIALIZED (SELECT ID, ISSUER_CA_ID, CERTIFICATE, CHILD_ID, DEPTH FROM chain LIMIT $3)
...
```

Every certificate of the issuing CA is a possible parent. `PATH` stops cycles through
cross-signs (ex. Sectigo's, USERTrust's, and AAA's roots), and the `NOT EXISTS` ends a chain at
a self-issued root (a certificate belonging to the CA that issued it). The rows add `child_id`
and `depth`, and a certificate can be a row once per child. `maxdepth` is 10 and `maxrows` 500.

### CAs: `cas()`

```sql
WITH cas AS MATERIALIZED (SELECT ca.ID, ca.NAME FROM ca WHERE ca.ID = ANY($1::int[]) OR ca.NAME ILIKE $2
                          ORDER BY ca.ID LIMIT $3)
SELECT cas.ID AS ca_id, cas.NAME AS ca_name, cac.CERTIFICATE_ID AS id
FROM cas LEFT JOIN ca_certificate cac ON cac.CA_ID = cas.ID
```

With `certs=True`, the CA certificates are joined in (`LEFT JOIN certificate c ON c.ID =
cac.CERTIFICATE_ID`) and wrapped by `_withMeta`, with the extra `ca_id` and `ca_name` columns.

## Raw SQL

`slib.crtsh.admin.sql` (`rawQuery`, then `CrtshDb.raw`) is the one path where SQL that isn't
the service's own reaches the database. Raw SQL is **never inlined**. Its `$n` parameters stay
parameters, and the row limit is one more parameter. So it runs as one plain extended-protocol
statement (`conn.fetch`) under the **server's** `statement_timeout` (30s on crt.sh), and with
`crtsh:timeout` as the client-side timeout.

Before it's sent, trailing whitespace and `;` are stripped, empty SQL is refused (`No SQL to
run.`), and SQL matching
`(?<![a-z0-9_$])pg_(try_)?advisory_lock(_shared)?(?![a-z0-9_$])|\bu&"` (case-insensitive) is
refused. That catches any mention of the session advisory lock functions, even in a comment or
string, and any Unicode escaped identifier that could spell one. The SQL is then wrapped in
`RAW_SQL`:

```sql
WITH crtsh_pre AS MATERIALIZED (
    SELECT set_config('transaction_read_only', 'on', true) AS ro,
           array_agg(name) AS names, array_agg(setting) AS vals FROM pg_settings),
crtsh_q AS MATERIALIZED (SELECT * FROM (
<sql>
) q WHERE (SELECT crtsh_pre.ro FROM crtsh_pre) IS NOT NULL LIMIT $<n+1>),
crtsh_undo AS MATERIALIZED (
    SELECT pg_advisory_unlock_all() AS unlocked, (
        SELECT count(set_config(b.name, b.val, false)) FROM crtsh_pre p
        CROSS JOIN LATERAL unnest(p.names, p.vals) AS b(name, val)
        JOIN pg_settings a ON a.name = b.name
        WHERE a.setting IS DISTINCT FROM b.val AND b.name NOT LIKE 'transaction%') AS restored
    FROM (SELECT count(*) FROM crtsh_q) n)
SELECT crtsh_q.* FROM crtsh_q WHERE (SELECT crtsh_undo.restored FROM crtsh_undo) IS NOT NULL
```

With statement pooling there's no transaction to roll back, so the protections are ordered by
the query plan, inside the one statement (checked with `EXPLAIN ANALYZE` and against PgBouncer
by `tests/test_pg.py`):

1. `crtsh_q`'s `WHERE` is an uncorrelated subquery, so it's an InitPlan in a One-Time Filter
   that runs before the raw query is scanned. It evaluates `crtsh_pre`, which snapshots every
   session setting and turns `transaction_read_only` on for the rest of the statement. So
   functions that write (ex. `nextval`, `lo_create`) fail, and the query can't turn read-only
   back off.
2. The final `WHERE` is the same kind of filter, so `crtsh_undo` runs before any row is returned.
   It counts `crtsh_q`, which runs the raw query to completion into the CTE's tuplestore. Then it
   releases every session advisory lock and sets back every session setting the raw query
   changed (ex. `set_config('search_path', ..., false)`). Both run even when the query returns
   no rows.
3. Then `crtsh_q`'s rows are returned.

The wrapper also means the SQL must be one query that returns rows (`SELECT`, `VALUES`, `TABLE`,
`WITH ... SELECT`). Session statements (`SET`, `COMMIT`) and top-level data-modifying statements
are syntax errors inside it.

Limits:

- A query that **fails** aborts its implicit transaction, which undoes its setting changes, but
  can't release a session advisory lock it took (only possible through dynamic SQL, ex.
  `query_to_xml('SELECT pg_advisory_lock(1)', ...)`). So the service sends
  `SELECT pg_advisory_unlock_all()` next (30s timeout, and the connection is dropped if that
  fails). Directly or behind session pooling that reaches the same session. Behind statement
  (crt.sh) or transaction pooling it may land on another server connection, and the lock stays
  on that PgBouncer server connection until PgBouncer closes it. The service's own queries never
  take advisory locks.
- Placeholder settings a query creates (`set_config('x.y', ...)`) aren't removed.
- These protections guard against mistakes and dynamic SQL, not deliberately malformed SQL (ex.
  unbalanced parentheses that restructure the wrapper). On crt.sh, the read-only guest role and
  replica are what keep data from changing. Only point `crtsh:dsn` at a writable account if
  everyone allowed to run `slib.crtsh.admin.sql` may write.

To run a heavy query by hand without the 30s limit, use psql and write it as
`SET statement_timeout = '600s' \; <query> \; RESET statement_timeout`. psql sends
`\;`-separated statements as one message, so they share one implicit transaction and one server
connection. `tests/live_queries.sql` (generated by `tests/sqlgen.py`, see
[Testing](internals.md#tests)) is written this way.

A plain `SET statement_timeout = 0;` line (or `SET ...; SELECT ...;` on one line, which psql
sends as two messages) only reaches whichever server connection ran it, and stays there.
