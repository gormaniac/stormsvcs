# Rate limits and quotas

VirusTotal's Public API allows, per API key, 4 requests per minute, 500 per day (reset at
00:00 UTC), and 15,500 per month. Requests over them are rejected with HTTP 429, and the
terms of service forbid working around them. `vtsvc.quota.QuotaLimiter`
({src}`svcs/virustotal/src/vtsvc/quota.py`) makes sure the service never goes over them:
every request to VirusTotal first reserves a slot with it. This page describes exactly what
it does.

## Constants and settings

| Name | Value | Configured by |
| --- | --- | --- |
| `MINUTE_LIMIT` | `4` | `vt:limit:minute` (default `4`, `0` disables) |
| `DAY_LIMIT` | `500` | `vt:limit:day` (default `500`, `0` disables) |
| `MONTH_LIMIT` | `15500` | `vt:limit:month` (default `15500`, `0` disables) |
| `maxwait` | `600.0` | `vt:limit:maxwait` (default `600`, `0` waits forever) |
| `WINDOW` | `61.0` seconds | fixed: a minute plus one second of slack for clock differences with VirusTotal |
| `COOLDOWN` | `60.0` seconds | fixed: how long a key is held off after an HTTP 429 |
| `enforce` | `vt:community` | default `true` |

The clock is `time.time()` (wall clock epoch seconds), because the counts are persisted and
compared across restarts; days and months are UTC.

## What a request does

`VtClient.request()` ({src}`svcs/virustotal/src/vtsvc/client.py`) for every request:

1. Fails with `NoApiKeyError` if there's no key (nothing is counted).
2. For a cacheable GET, returns a cached response if there is one. **Cache hits are never
   counted or limited.**
3. Calls `QuotaLimiter.acquire(apikey)`, which waits for a slot, or raises `VtQuotaError`.
4. Sends the request.
5. On a transient error (VirusTotal `TransientError` or `DeadlineExceededError`, or HTTP 502,
   503, 504) it sleeps `5 * 2**attempt` seconds (5, then 10) and goes back to step 3, at most
   twice. **Each retry acquires, and counts, another slot.**
6. On HTTP 429 it calls `QuotaLimiter.cooldown(apikey)` and raises `VtQuotaError`
   (`VirusTotal rejected the request for going over a quota: ...`). 429s are never retried.

A slot is taken *before* the request is sent, so a request is counted whether it succeeds,
fails with an HTTP error, times out, or can't connect.

## acquire()

```text
kid = sha256(apikey)[:16]          # the key's id, see Persisted state
start = now
checkTotals(kid, start)            # may raise: daily or monthly quota used up
with lock[kid]:                    # one asyncio.Lock per key, FIFO
    loop:
        now = clock()
        checkTotals(kid, now)      # re-checked after every wait
        wait = windowWait(kid, now)
        if wait <= 0: break
        if maxwait and (now - start) + wait > maxwait:
            raise VtQuotaError("Timed out waiting for room ...")
        sleep(wait)
    record(kid, clock())           # count the request
```

### Daily and monthly limits

`checkTotals()` does nothing unless `enforce` is true. Otherwise:

- If `vt:limit:day` is non zero and the key's count for the current UTC day
  (`YYYY-MM-DD`) is `>=` it, it raises right away:
  `The VirusTotal daily quota (500 requests) for this API key is used up, it resets at
  00:00 UTC (in <h>h <m>m).`
- If `vt:limit:month` is non zero and the count for the current UTC month (`YYYY-MM`) is
  `>=` it: `The VirusTotal monthly quota (15500 requests) for this API key is used up.` It
  clears when the UTC month changes.

These fail immediately instead of waiting, since the wait would be hours. A refused request
isn't counted. Because the totals are checked again inside the loop, a request that was
queued behind others fails as soon as the requests ahead of it use up the quota.

### Per minute window

`windowWait()` returns `0` unless `enforce` is true. Otherwise the wait is the larger of:

- **Cooldown**: if the key's `cooldown` time is in the future, the seconds until then.
- **Window**: if `vt:limit:minute` is non zero, take the key's request times in the last
  `WINDOW` (61) seconds, sorted. If there are at least `minute` of them, the wait is
  `recent[-minute] + 61 - now`: the time until the oldest request that's in the way leaves
  the window.

So there are never more than `vt:limit:minute` requests in any 61 second window, per key.
With the defaults, a burst of requests runs 4 at once, then 4 more 61 seconds after the
first, and so on: about 236 requests an hour, and enriching 100 nodes takes about 25
minutes.

The lock serializes the waiters of one key in FIFO order, so a burst from several Storm
queries is spread out evenly rather than racing. Different keys never wait on each other.

### maxwait

Before sleeping, a request checks that the time it has already spent (including time queued
behind the lock, measured from `start`) plus the wait would not exceed `vt:limit:maxwait`.
If it would, it fails without sleeping and without being counted:

```text
Timed out waiting for room under the VirusTotal rate limit of 4 requests per minute
(vt:limit:maxwait is 600s). Try again later, or with fewer nodes.
```

`maxwait` covers cooldown waits too. With `vt:limit:maxwait` `0` a request waits as long as
it takes. In practice, with 4 per minute and the default 600 seconds, roughly 40 requests can
be queued for one key before later ones start failing.

### Recording a request

`record()` runs for every request, whether or not limits are enforced:

- Appends `now` to the key's `recent` list, keeping only the newest
  `max(vt:limit:minute, 4)` times that are inside the window.
- Increments the key's counters for the current UTC day and month.
- Prunes the key's day and month counters for any earlier day or month.

## cooldown()

After an HTTP 429, `cooldown(apikey, secs=60)` stores `now + 60` as the key's `cooldown`
time. While it's in the future, every request for that key waits for it (subject to
`maxwait`) when limits are enforced. It's the safety net for a key that is also used by
other clients, whose requests the service can't see. With `vt:community` false the cooldown
is stored but ignored.

## Not enforced (vt:community false)

With `vt:community` false (premium keys):

- `checkTotals()` and `windowWait()` do nothing, so no request waits or is refused by the
  service, and the 429 cooldown is ignored.
- Requests are still counted: the day and month counters keep growing, so `slib.vt.quota`
  still reports usage.
- Every relationship is allowed, and `waitAnalysis()` polls at least every 1 second instead
  of 15.

## Persisted state

The limiter stores its state in the cell slab (`/vertex/storage/slabs/cell.lmdb`), in the
SafeKeyVal named `slib:vt:quota`. API keys are never stored there; each key is identified by
`keyId()`, the first 16 hex characters of the SHA256 of the key.

| Key | Value |
| --- | --- |
| `<kid>:recent` | List of epoch seconds (floats) of the key's latest requests. |
| `<kid>:day:<YYYY-MM-DD>` | Requests on that UTC day (int). Only the current day is kept. |
| `<kid>:month:<YYYY-MM>` | Requests in that UTC month (int). Only the current month is kept. |
| `<kid>:cooldown` | Epoch seconds until which the key is held off. Never deleted; once in the past it has no effect. |

Because the state is persisted, a restart neither resets the daily and monthly counts nor
allows a burst over the per minute limit. The per key locks are in memory, so the limits are
only coordinated within one service process: two service instances (or other clients) using
the same key each count only their own requests. Stale day and month counters are pruned
only when that key next sends a request.

## Per key

Counts are per key. A user who set their own key with `slib.vt.apikey` has their own limits
and counts. Everyone without one shares the service-wide key's limits (the stored key, or
`vt:apikey`). The configured limits are the same for every key.

## Inspecting usage

`slib.vt.quota` (Telepath `quota()`) returns `QuotaLimiter.status()` for the resolved key,
plus two fields from the service:

| Field | Meaning |
| --- | --- |
| `enforced` | `vt:community`. |
| `limits` | `{"minute", "day", "month"}`: the configured limits (`0` = no limit, shown as `none`). |
| `used.minute` | Requests in the last 61 seconds. At most `max(vt:limit:minute, 4)`, since only that many times are kept. |
| `used.day`, `used.month` | Requests this UTC day and month. |
| `wait` | Seconds (rounded to 0.1) until the key can send a request: the cooldown or window wait, `0` when not enforced. It doesn't include requests already queued. |
| `resets` | The next 00:00 UTC, as epoch millis (the daily reset; the monthly count resets when the month changes). |
| `cached` | Responses in the response cache, for all keys (expired entries are counted until they're evicted or looked up). |
| `remote` | With `--remote`: VirusTotal's own `api_requests_hourly`, `api_requests_daily`, and `api_requests_monthly` (`allowed`, `used`) from `GET /users/{key}/overall_quotas`. |

`--remote` is one request, counted and limited like any other, and the local counts shown are
taken before it's sent. VirusTotal's counts include requests from every client using the key,
so they can be higher than the service's. The Public API's hourly quota (240) is not enforced
separately; the per minute limit keeps the service under it.

## Saving quota

- **Response cache** (`vt:cache:ttl`, default 3600 seconds; `vt:cache:size`, default 1000
  entries, LRU). Cacheable: `getObject` / `lookup` (unless `slib.vt.enrich --no-cache`),
  relationship pages (`related`, `comments`), `behaviour`, `search`, `threatCategories`, and
  `attackTechnique`. Only successful GETs are cached, keyed by `(keyId, url, sorted params)`,
  so different keys don't share entries. Not cached: analyses, submissions, rescans,
  comments, votes, `quota --remote`, and `rawRequest`. The cache is in memory and empty after
  a restart.
- **Public relationship check**: with `vt:community` true, a relationship a Public API key
  can't read is refused before any request.
- **Page sizes**: relationship and search pages are requested at up to 40 objects, the
  maximum, and `related()` stops as soon as it has `limit` objects or VirusTotal returns no
  cursor.
- **Analysis polling**: at least 15 seconds between polls with `vt:community` true.

## Tuning

| Situation | Setting |
| --- | --- |
| Long running batches with a Public key | Raise `vt:limit:maxwait`, or set it to `0`, so queued requests wait instead of failing. Storm queries will run for a long time. |
| Interactive use, fail fast | Lower `vt:limit:maxwait`, ex. `60`. |
| The key is shared with other tools | Lower `vt:limit:day` / `vt:limit:month` to leave them room. The service can't see their requests. |
| A premium key | `vt:community: false`. Requests are still counted. |
| A premium key with its own contractual limits | Keep `vt:community: true` and set `vt:limit:*` to the contract's limits. This also keeps the Public relationship check. |
