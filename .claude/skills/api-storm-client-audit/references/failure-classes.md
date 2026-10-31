# Discrepancy classes

These are the classes of doc-vs-code and live-vs-code discrepancies that real audits found. Check
each class against every platform. Each entry says what goes wrong and how to detect it.

## Transport and status handling

- **Auth failures that look like "no results".** A broad "not found" rule (ex. any status starting
  with `unknown_`) swallows `unknown_auth_key`. With a revoked key, every lookup is silently empty.
  *Detect:* call once with a bad key; it must raise. Check the HTTP 401/403 handling *before* the
  not-found check.
- **"Not found" on a write reported as success.** Updating or commenting on a missing item returns
  a not-found status, which the read path turns into an empty result, and the command prints success.
  *Detect:* writes need a strict mode where not-found raises.
- **Harmless write outcomes raised as errors**, ex. `exists` or `file_already_known`.
- **Responses without the usual envelope.** Most endpoints return `{"status": ..., "data": ...}`,
  but some return the object itself or a flat dict keyed by ID. Reading `resp["data"]` yields
  nothing. *Detect:* call every endpoint live and look at the top-level keys.
- **Errors carried in a success envelope**, ex. `{"status": "error", "data": "unknown_task_id"}`, or
  `{"status": "ok", "data": "no results"}` (a string where a list was expected).
- **Error detail dropped.** The status says `error` and the reason is in `data`; surface both.
- **Secrets in errors.** Export URLs that carry the key in the path leak it through connection
  error messages. Scrub it.
- **Multipart part types.** Upload APIs may expect the options part as `application/json`.

## URLs, datasets, and lifecycle

- **Moved endpoints.** Old export/download URLs return 410 Gone or 301 to an HTML page. The docs'
  curl examples are sometimes stale while the page's own download link is current; use the link.
- **Auth moved into the URL** (ex. `/v2/files/exports/<key>/<file>`), and file names changed.
  *Detect:* probe candidate names with range requests, printing only status codes.
- **Deprecated datasets that still return 200**, with only a comment line saying they're
  deprecated, so they parse to zero rows. *Detect:* read the first lines of every dataset; make the
  client raise on deprecation notices; remove the choice.
- **Stale datasets** (not updated in years); say so in the help text.
- **A derived dataset when a richer one exists**, ex. joining an IP-only list with a full list when
  the provider publishes the full-field version of the smaller list.

## Requests and limits

- **Silent limit resets.** A value just over the documented max is treated as the default instead of
  being capped (ex. 1001 → 25 results). Always clamp to the documented maximum.
- **Client-side truncation.** Applying a default `limit` to an endpoint that has no server-side
  limit throws away most of the results. Default to "everything" when the API returns everything.
- **Exact vs wildcard search semantics.** An exact search for an IP never matches `ip:port` values.
  Use a wildcard search and filter the results client-side.
- **Search-by-X vs lookup-by-X.** "IOCs associated with a hash" differs from "the hash itself as an
  IOC"; query both and dedupe.
- **Unsupported input types accepted**, ex. a hash type the endpoint rejects, or IPv6 where only
  IPv4/FQDN are allowed. Reject them up front with a clear message, or route them elsewhere.
- **Wrong update keys or values in help text**, ex. `tags=` when the API key is `add_tag`. Validate
  against the documented key list.
- **Single values where lists are documented**, ex. context/reference fields that take arrays.

## Response fields

- **Guessed keys for heterogeneous sub-sources.** A dict of vendors/sandboxes, each with its own
  fields, read through shared key lists misreads verdicts as family names (ex. "Legit File" as a
  malicious family), and substring matching misfires (ex. "NO_THREAT" matching "threat"). Give
  each source its own reader, built from a real record, plus a generic fallback.
- **Score scales.** 0-1, 1-10, and 0-100 scores mixed together; normalize each source explicitly.
- **Self-references.** An unpacker lists the sample itself among its "children", so the sample
  becomes its own subfile.
- **Masked or placeholder values** modeled as real entities, ex. non-public rule names masked as
  "xxx", "Unknown Stealer"/"Unknown Loader"/"Unknown malware" families, filename "na"/"n/a".
- **Context-dependent dates.** In some endpoints `firstseen`/`lastseen` mean "this payload on this
  URL", not "this URL"; using them as the parent's dates is wrong.
- **Fields only present on child records**, ex. a filename only on each URL entry, or a family
  only implied by the search term (inject it).
- **Normalized but never modeled.** The normalizer produces a field the model never reads (ex. a
  `names` list when the model reads only `name`).
- **Format drift across endpoints**, ex. a fuzzy hash with and without a version prefix.
- **Fields the docs don't mention** but live responses include (ex. `sightings`, extracted malware
  configs with C2s, URLs a sandbox found). Decide whether to model or document them.
- **Fabricated defaults.** Booleans defaulted to False when the field is absent; use None.
- **Rarely-populated nested fields** (ex. extracted malware configs) that the fixture never
  exercised. Find a live record where they're populated.
- **Hash-only entities.** Items known only by a hash the data model doesn't key on (ex. SHA3-384);
  the model returns null and the item is dropped. Rows that list one item once per hash type should
  be merged.

## Storm / Synapse specifics

- **Lists cross Telepath as tuples.** `isinstance(v, list)` fails in the service for values that
  came from Storm; accept `(list, tuple)`.
- **Loops with a node in the function's pipeline.** In a Storm function, a `for` loop that runs
  while a node is in the pipeline sends the node downstream after the first iteration and ends the
  function early. Create the node in a helper that returns it, then loop.
- **Runtsafe variables.** A variable assigned both from `$node` and from constants in a command
  body can be treated as runtsafe and evaluated without a node ("used before assignment"). Move
  per-node logic into an `init`-defined function that returns values.
- **Barewords in expressions.** Inside `(...)` expressions strings must be quoted:
  `($x = "done")`, not `($x = done)`.
- **Name shadowing.** A module function name can be shadowed by a variable of the same name
  (ex. `$tag`); give helpers distinct names.
- **Pivot-then-filter in tests.** `-(refs)> inet:fqdn=x` doesn't filter; use
  `-(refs)> inet:fqdn +inet:fqdn=x`.
- **Lazy lifts in tests.** A broad lift (`file:bytes | cmd`) also picks up nodes the command creates
  while it runs; lift exact values.
