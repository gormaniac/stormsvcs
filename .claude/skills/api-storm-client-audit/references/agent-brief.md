# Auditor brief template

Fill in the `<...>` parts per platform and launch one auditor per platform (group small ones), all
in a single message. Keep the brief self-contained: the auditor knows nothing else.

```
You are auditing a <Storm service / API client> that wraps the <Provider> **<Platform>** API,
comparing the implementation against the official docs. The service was originally written
without access to the docs<, and <other platform> already turned out to have <missing endpoints /
a wrong URL / ...>>. Assume there are discrepancies and look hard.

**The docs:** `<path to extracted docs text>` (from <docs URL>)<, and `<path>` (from <URL>)>.
Read them in full.<If a docs site is blocked or login-gated: "The <X> docs aren't reachable from
this environment; for <X>, use a live read-only call instead: <exact request> and compare its real
shape to <normalizer>.">

**The code** (repo at `<repo path>`):
- `<client/transport file>`: <BASE_URLS, request/response handling, status handling>
- `<service file>`: the `<section marker>` section, `<endpoint/dataset maps>`
- `<normalizer file>`: `<functions that parse this platform's responses>`
- `<Storm model module>`: `<functions that turn normalized data into nodes>`
- `<package yaml>` and `<command files for this platform>`

**Check:**
1. **Coverage.** Every documented endpoint/query/dataset/export (lookups, searches, recent/feed
   lists, downloads, uploads/submissions, updates/comments/deletes, reference lists, statistics
   files, every export format) has a service method and a command. List any that are missing, and for
   each say whether it's worth adding (modelable data) or reasonably out of scope (a redundant
   format, IDS/firewall rules, bulk malware archives). Note anything the docs mark deprecated or
   discontinued that the code still offers.
2. **Requests.** For each implemented endpoint: URL/path, HTTP method, body encoding (form, JSON,
   multipart, and the multipart part content types), auth placement (header, query, path),
   parameter names and types, allowed values, defaults, and limits/maxima match the docs, including
   what happens just past a limit.
3. **Responses.** Every field in the docs' example responses (and in real responses) is read from
   the right key, normalized, AND modeled (or deliberately skipped per the README). Check nested
   structures, list-vs-dict shapes, string-vs-number types, date formats, score scales, placeholder
   or masked values, and fields that differ by endpoint. Name every field that's dropped or misread.
4. **Statuses.** Every documented and observed status value (success, not found, empty, auth
   failure, invalid input, server error, "queued/processing") versus the client's handling: not
   found must return empty for reads, auth failures and invalid input must raise, successes
   (including harmless write outcomes) must not raise, and responses without the usual envelope
   must still parse.

**Live calls are allowed but READ-ONLY.** The credential is in env var `<VAR>`; send it as
<header/param/path>. Never print it. Never <submit, upload, update, comment, delete, rescan, deploy,
or call anything that creates server-side state>. Peek at datasets with `curl -r 0-3000` instead
of downloading them. Don't modify any files in the repo. Scratch files go in `<scratch dir>`.

**Report back:** a concise list of discrepancies, each with what the docs say (quote briefly),
what the code does (file:function), and the impact (broken / wrong data / missing data / cosmetic).
Separate "confirmed live" from "docs-only". Then list what you checked that matches, in one short
paragraph. Keep it under ~<600-700> words.
```

## Grouping guidance

- One auditor per large platform (a big API reference page).
- Group small platforms (a blocklist page, a dataset page, a single-query API) into one auditor.
- Give the auditor whose surface overlaps a recent fix the list of what was already fixed, so it
  verifies the fix rather than re-reporting it.
