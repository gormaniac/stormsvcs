# Internals

This page is for maintainers. It walks through the Python source module by module, the Storm
package, and the tests. The database layer has its own page: [Database access](database.md).
For the conventions every service follows, see {doc}`/dev/architecture` and
{doc}`/dev/contract`.

## Layout

```text
svcs/crtsh/
  pyproject.toml, uv.lock        version <version>, deps: asyncpg, cryptography, stormlibpp (synapse)
  docker/prod/, docker/test/     the images (see Deployment)
  src/crtshsvc/
    __init__.py                  __version__, exports CrtshSvc
    __main__.py                  python -m crtshsvc <dirn> -> CrtshSvc.execmain()
    defs.py                      SVC_NAME, SVC_VER, SVC_GUID, SVC_EVTS, the Storm package
    api.py                       CrtshCellApi (Telepath)
    svc.py                       CrtshSvc (the cell): validation, orchestration, sorting, chains
    db.py                        CrtshDb: the connection and every SQL statement
    norm.py                      DER parsing into Telepath-safe dicts, field matching
    pkgproto/                    slib.crtsh.yaml, README.md (a copy), storm/commands, storm/modules
  tests/                         see Tests
```

## Modules

### defs.py

- `SVC_NAME = "slib.crtsh"` and `SVC_VER = __version__`.
- `SVC_GUID = "c7357722661f45a4b81c91ccfbbb37c0"`, the guid of the `slib.crtsh` `meta:source`.
  It's defined only here. `_pkgdef()` injects it as the `modconf` of the `slib.crtsh.model`
  module (`{"source": SVC_GUID}`), which reads it as `$modconf.source`.
- `SVC_EVTS["add"]` is the Storm that runs on `service.add`. It creates the `meta:source` and
  sets the two tag globals if they're unset.
- `SlibCrtshPkg(StormPkg)` with `proto_name = "slib.crtsh"` loads
  `pkgproto/slib.crtsh.yaml` through StormLib++'s `StormPkg`, which uses Synapse's
  `tryLoadPkgProto`. `PKGDEFS = (_pkgdef(),)`.

### api.py

`CrtshCellApi(RetnApi, s_cell.CellApi, s_stormsvc.StormSvc)` declares `RETN_METHS`,
`GENR_METHS`, `RETN_ERRORS = (CrtshDbError,)`, and the StormSvc attributes
(`_storm_svc_name`, `_storm_svc_vers` from `normver(SVC_VER)`, `_storm_svc_evts`,
`_storm_svc_pkgs`). It has no hand-written methods and doesn't override `_retnRedact`. See
[Telepath API](api.md#telepath-api).

### svc.py

`CrtshSvc(s_cell.Cell)` with `cellapi = CrtshCellApi`, the `confdefs` (see
[Cell configuration](deployment.md#cell-configuration)), and `__anit__`, which builds
`self.db = CrtshDb(...)` from the config and registers `self.db.close` with `onfini`. No
connection is made at startup.

Input handling (module-level helpers):

- `lookupValu(kind, valu)` converts an identifier to the values it may be stored as. `id` must
  parse as an int. Everything else is hex, normalized by `norm.normHex` (lowercase, `:` and
  spaces removed) and stripped of `0x`. The hash kinds must have the right length, and other
  kinds an even one. `serial` becomes `_serialVariants()`: the bare bytes, with a `00` sign byte
  if the high bit is set, and the original bytes.
- `guessKind(valu)`: an int, or digits shorter than 20 characters, is `id`. 64 hex characters is
  `sha256`, and 40 is `sha1`.
- `identityQuery(field, valu, exact)` returns `(text, like)` for `certsByIdentity`: the full
  text search text and the `ILIKE` pattern (see
  [Searches](database.md#searches-certsbyidentity)). It drops DN attribute names for
  `subject`, rewrites IPs into crt.sh's form, and strips a leading `*.`/`.` from domains.
- `isPrefix`, `normDomain`, `normIp`, `toInt`, `toCaids`, `toMillis`, and `toExpires` validate
  arguments from Storm and raise `CrtshDbError` with a user-facing message. `bool` is refused as
  an int.
- `_limit(limit, conf)` returns the configured max for `None`, refuses values below 1, and
  otherwise returns `min(limit, max)`.

Results:

- `_parse(rows)` drops duplicate rows by crt.sh ID and calls `norm.certDetails` on each.
- `_sort(items)` sorts newest notBefore first, then highest crt.sh ID (`norm.certTime` returns
  the negated notBefore).
- `searchGenr` (see [How matching works](commands.md#slibcrtshsearch)) picks the most
  specific field, sizes the candidate limit, runs `certsByIdentity` (or `certsByIssuer` for an
  issuer-only search), then filters every field with `norm.matches` in the right mode
  (`exact`, `contains`, `suffix`, or `prefix`).
- `issuedGenr` and `pivotGenr` ask for `2 * limit` rows with `precerts=False`, since most
  certificates have a precertificate twin, and drop precerts afterwards. When a pivot or
  `issued` call returns nothing, they make one more query (`_one`) to explain why.
- `chain` sorts the rows by `(depth, id)`, keeps the first `maxcerts` unique certificates,
  builds the `links` (each child to each candidate parent, `preferred` from
  `_preferredParent`), and walks them into `paths` (`_paths`, at most 50, preferred parents
  first, no repeats).
- `cas` groups the rows per CA.
- `rawQuery` converts each row with `_safeRow`.

The generator methods do all the work, including the one query, before they yield the first
item, so they hold no database state while Storm consumes them.

### norm.py

`parseCert(der)` loads the certificate with `cryptography.x509.load_der_x509_certificate` and
returns every field (see [Certificate details](api.md#certificate-details)). Highlights:

- `normName` returns the RFC 4514 DN (falling back to `str(name)` for malformed names),
  attributes by short name or OID, and the SHA-1 of the DER name. That's the same value as
  crt.sh's `digest(x509_name(...), 'sha1')`, so a `subjectsha1` lookup can use it.
- `normPublicKey` returns the algorithm, size, the RSA modulus and exponent or the EC curve, the
  DER SPKI, and its SHA-256 and SHA-1. A key type `cryptography` can't load returns only
  `algo`/`size` as null.
- `normExtensions` reads every extension into flat fields. A malformed extension makes the
  whole list unreadable in `cryptography`, so that case returns empty extension fields.
- `serialHex` encodes serials as even-length hex, and negative serials (invalid, but present in
  CT logs) as their two's complement DER bytes.
- `identities(sans, subject)` builds the `crypto:x509:cert:identities:*` values.
- `selfsigned` is true when the subject DN equals the issuer DN and the AKI is absent or equals
  the SKI.

`certDetails(row)` adds the crt.sh data (`crtsh.*`) from the query's metadata columns, and on a
parse failure returns only the hashes, a PEM made from the DER, `error`, and `crtsh`.
`matches(details, field, valu, mode)` and `fieldValues(details, field)` implement the search
filters. `CRTSH_URL` (`https://crt.sh/`) is only used to build `crtsh.url`.

### db.py

See [Database access](database.md). Module-level pieces: `DEFAULT_DSN`, `NAME_TYPES`,
`NOTAFTER_KEY`, `LOOKUPS`, `RELATED`, `META`, `RAW_SQL`, the error message lists
(`CONN_ERRORS`, `RECONNECT_MESGS`, `BACKOFF_MESGS`), `CrtshDbError`, `Params` (hands out `$n`
placeholders), `_lookup`, `_filters`, `_withMeta`, `_issuerName`, `tsquery`, `prefixQuery`,
`likeEscape`, the literal inliner (`_literal`, `_inline`, `PARAM_RE`), and the COPY parser
(`COPY_SIG`, `BYTEA_COLS`, `_copyRows`).

## The upstream client

| Aspect | Behaviour |
| --- | --- |
| Protocol | PostgreSQL wire protocol via `asyncpg`, TCP 5432. No HTTP. |
| Auth | The DSN (`guest`, no password, by default). |
| Connections | One, lazily opened, queued behind an `asyncio.Lock`. Closed after `crtsh:idle`. |
| Rate limits | crt.sh's one connection per IP, enforced by PgBouncer. Refusals back off for up to `crtsh:connect:timeout`. |
| Timeouts | 30s per connection attempt, `crtsh:statement:timeout` on the server, `crtsh:timeout` on the client, 30s for keepalive and unlock pings. |
| Retries | Connection drops and replica serialization cancels: `crtsh:retries`. Statement timeouts: `crtsh:timeout:retries`, after 5s. |
| Pagination | None. Every call is one query with a `LIMIT`. |
| Caching | None. No prepared statement cache either (`statement_cache_size=0`). |

## State

The service stores nothing: no slabs, files, or Axon blobs. Its state is in memory: the
connection, the lock, the time of the last query, the keepalive task, and `_useCopy` (false
once the server refuses the per-query `SET`s). Everything persistent is in the Cortex (nodes,
node data, and the two `slib:crtsh:tag:*` globals).

The only background task is the keepalive loop (see [The connection](database.md#the-connection)).

## Error handling

- `CrtshDb` raises `CrtshDbError` for database failures (see
  [Timeouts and retries](database.md#timeouts-and-retries)), and re-raises other exceptions
  after dropping the connection.
- `CrtshSvc` raises `CrtshDbError` for every validation error.
- `RetnApi` turns every exception into a `status=False` `TelepathRetn`. `CrtshDbError` keeps its
  message, input errors become `Invalid input: ...`, and anything else is logged with its
  traceback and returned as `Unexpected error: ...`.
- In Storm, `slib.crtsh.util.failed()` turns `status=False` into a `slib.crtsh: <what> failed:
  <mesg>` warning, and the `slib.crtsh.lib` functions stop.
- There's no secret redaction. The default DSN has no password.

## Storm package internals

The package ({src}`svcs/crtsh/src/crtshsvc/pkgproto/slib.crtsh.yaml`) has `name: slib.crtsh`,
`version: <version>`, `synapse_version: ">=2.145.0,<3.0.0"`, `genopts.dotstorm: true` (Storm lives
in `.storm` files), and the README as its doc. It has no `onload` and no package config vars.
Settings are Cortex globals.

Privilege split:

- `slib.crtsh.priv.user` and `slib.crtsh.priv.admin` are the only modules that call
  `$lib.service.get("slib.crtsh")`. They run `asroot` for holders of `slib.crtsh.user` and
  `slib.crtsh.admin`, so users don't need `service.get`.
- `slib.crtsh.lib` and `slib.crtsh.model` require `slib.crtsh.user` to import, and are not
  `asroot`. Node edits run as the calling user.
- `slib.crtsh.util` has no permissions.

Commands follow one pattern (ex. `slib.crtsh.pivot`):

1. `init` builds the options and sets `$explicit` when explicit values were given.
2. `-$explicit` drops every inbound node when there are explicit values.
3. `{ $state.inbound = (true) }` runs in a subquery, so it only runs for real inbound nodes.
4. The node's key is computed (`util.certKeyOf`, `lookupKey`, or `searchKey`). Nodes without
   one get a warning and are dropped.
5. `divert` yields the generator's nodes per inbound node (`slib.crtsh.cert` diverts only with
   `--yield`). `util.nodes()` adapts the emitting `slib.crtsh.lib` functions to a node
   generator.
6. `fini` runs the explicit query once, or warns when there were neither values nor inbound
   nodes.
7. `| uniq`.

The model module's functions only `yield` a node when they don't loop. A `for` loop with a node
in a function's pipeline sends the node on after its first iteration and ends the function, so
the loops call helpers (`addValu`, `seenAt`, `addTag`, `refs`) that edit the node in their own
runtime. The code lints clean with Synapse's Storm linter, with and without `--v3-ready` (CI
runs it with `storm_lint: block`). The `// noqa` comments mark 2.x APIs the 3.x rules flag.

## Tests

```bash
cd svcs/crtsh && uv run pytest
uv run pytest tests --cov          # line and branch coverage of crtshsvc
```

The unit tests never touch crt.sh. `tests/conftest.py` loads the `stormlibpp.testing` plugin,
which fails any test that uses a deprecated Synapse API (see {doc}`/dev/testing`).

| File | Covers |
| --- | --- |
| `fakecrtsh.py` | `FakeCrtshDb`, an in-memory crt.sh with every `CrtshDb` query method, answered from a small PKI built with `cryptography`. It records every call (`calls`, `last()`, `called()`) and can be made to fail (`fail`). `crtshSvc(test)` yields a Cortex with the service added and its `db` swapped for the fake. |
| `test_crtsh.py` | Parsing smoke tests, `assertVersionsMatch`, `assertMainHelp`, the README copy matching (and naming every command), and the package loading into a Cortex. |
| `test_norm.py` | Every certificate detail `norm` parses, including bad extensions, odd keys, and `matches`. |
| `test_svc.py` | `CrtshSvc` and the Telepath API against the fake: lookups, limits, search fields, prefixes, expiry bounds, issued, pivots, chains, CAs, raw SQL, bad arguments, and the config being passed to `CrtshDb`. |
| `test_crtsh_storm.py` | Every Storm command, option, inbound form, error path, the model, tags, and permissions. |
| `test_crtsh_db.py` | `CrtshDb` against fake asyncpg connections and a fake PgBouncer (`FakeServer`): the queue, reconnects, backoff, retries, statement timeout retries, keepalive and idle close, statement pooling, the `SET`s, the COPY fallback, literals, COPY parsing, cancellation, and the SQL each method builds. |
| `test_pg.py` | Runs every query against a real PostgreSQL loaded with `pgstub.py`. Skipped unless `SLIB_CRTSH_PGDSN` is set. |
| `pgstub.py` | A stub of crt.sh's schema: the same tables, `certificate` partitioned on notAfter, the expression and GIN indexes, the `certificate_and_identities` view, and SQL stubs of the libx509pq functions, loaded with the fake PKI. It replaces the database's `public` schema. |
| `test_live.py` | Live tests against crt.sh. Skipped unless `SLIB_CRTSH_LIVE=1`. |
| `sqlgen.py`, `live_queries.sql` | A psql script of every query the service runs, generated from `CrtshDb`. |

The fakes match full text searches the way crt.sh does. `identityText()` ports crt.sh's
`identities()` function, and `tsTokens()` produces the words PostgreSQL's parser does from it.
Both are checked against crt.sh's live output (`tests/data/live_identities.json`) and against
PostgreSQL by `test_pg.py`.

PostgreSQL, directly and behind PgBouncer in statement pooling mode (which CI also runs, see
{src}`.github/workflows/crtsh.yml`):

```bash
SLIB_CRTSH_PGDSN=postgresql://postgres@127.0.0.1:5432/certwatch uv run pytest tests/test_pg.py
# with a pgbouncer.ini of pool_mode = statement in front of the same database:
SLIB_CRTSH_PGDSN=postgresql://postgres@127.0.0.1:6432/certwatch uv run pytest tests/test_pg.py
```

Live, against crt.sh. It uses one connection per IP, so close `psql` first, and it takes a few
minutes:

```bash
SLIB_CRTSH_LIVE=1 uv run pytest tests/test_live.py -v
```

The query script:

```bash
uv run python -m tests.sqlgen > tests/live_queries.sql
psql -h crt.sh -p 5432 -U guest certwatch -f tests/live_queries.sql
uv run python -m tests.sqlgen --stub | psql <stub dsn> -v ON_ERROR_STOP=1
```

See {doc}`/dev/testing` and {doc}`/dev/ci` for how the tests run in CI, and
{doc}`/dev/versioning` for the version bump every change needs.
