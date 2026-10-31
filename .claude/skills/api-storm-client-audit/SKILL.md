---
name: api-storm-client-audit
description: Audit a Storm service (Synapse Advanced Power-Up) or any API client against the upstream API's official docs and live behavior, then fix every discrepancy. Use when asked to audit, verify, or check a service/client against its API docs, when asking "is this PR ready to merge" for an API integration, when a service was built without access to the real docs or from secondhand sources (sample scripts, community clients, memory), or after one doc-vs-code miss is found and the rest of the integration needs checking.
---

# API / Storm client audit

Systematically compares an API integration against the provider's **official docs** and **live
responses**, finds every discrepancy (missing endpoints, wrong requests, dropped or misread fields,
mishandled statuses, deprecated datasets), fixes them, and proves the fixes with tests built from
real response shapes.

## Why this is needed

Unit tests prove the code matches the fake server, and the fake server was written from the same
assumptions as the code. When a client was built without the real docs, a passing suite says
nothing about correctness. One confirmed doc-vs-code miss means there are more: audit everything.

## 0. Preconditions

Check these before starting, and tell the user what's missing.

- **Docs reachable.** Fetch each docs page. If hosts are blocked (proxy 403, DNS failure), ask the
  user to allow them (in a cloud session, the environment's network settings). Some docs pages are
  login-gated, so note which and plan to verify those parts live instead.
- **API reachable with a credential.** You need a **read-only** key in an environment variable,
  never pasted into chat. Never print the key; it may also appear in URL paths (export endpoints),
  so keep it out of command echoes and error messages.
- **A clean branch.** Pull first: another session may have pushed. Check CI state.

## 1. Inventory

1. List every platform/API surface the service covers, and every docs page for each: API reference,
   export/dataset pages, blocklist pages, submission docs.
2. Download each page and extract its text into a scratch dir (ex. `/tmp/audit/<platform>.txt`),
   stripping script/style tags and HTML. Record each page's size and whether it's login-gated.
3. Note the code layout the auditors need: the transport/client, the service methods, the
   normalizers, the Storm model module, the package YAML, and the commands. Use file paths and
   section names (ex. "`svc.py`: the `# ---- Foo ----` section").

## 2. Fan out one auditor per platform

Docs are long (tens of thousands of chars per platform), so give each platform (or group of small
ones) its own subagent, all launched **in one message** so they run in parallel. Use the brief in
[references/agent-brief.md](references/agent-brief.md), filled in per platform. Every brief must:

- Name the docs files and the exact code sections to compare.
- Give the **four checks**: endpoint coverage, request shape, response fields (normalized **and**
  modeled), and status/error handling. Also ask about deprecations and limits.
- Allow **read-only** live calls only: no submissions, uploads, updates, deletes, rescans, or
  anything that creates server-side state. Datasets are peeked with HTTP range requests, not downloaded.
- Forbid repo edits, so auditors don't race each other or you.
- Ask for findings split into **confirmed live** vs **docs-only**, each with what the docs say, what
  the code does (file:function), and the impact (broken / wrong data / missing data / cosmetic),
  under a word budget.

While they run, don't edit the code they're reading. Summarize each report for the user as it
arrives.

## 3. Consolidate and triage

Merge the reports into one list and dedupe them; cross-platform root causes (ex. client status
handling) show up in several reports. Triage in this order:

1. **Broken.** A feature that returns nothing or errors: wrong envelope assumptions, wrong URLs,
   wrong status handling, unsupported inputs accepted.
2. **Wrong data.** Things modeled incorrectly: misread verdicts, wrong dates, fake entities.
3. **Missing data.** Fields that are returned but dropped, or normalized but never modeled.
4. **Missing endpoints/datasets.** Decide which to add and which are deliberately out of scope
   (redundant formats, non-data formats like IDS rules). Document the out-of-scope ones.
5. **Cosmetic.** Help text, defaults, and naming.

[references/failure-classes.md](references/failure-classes.md) is the catalog of discrepancy
classes to look for. Use it as a checklist if a report seems thin.

## 4. Capture real shapes before fixing

For every finding that touches a response shape, get a **real example** first: from the auditors'
scratch files, or with your own read-only calls. Don't fix from the docs' example alone; docs
examples are often stale or idealized. Specifically:

- One real record per variant (ex. every vendor in a "vendor intel" dict, every IOC type).
- The empty, not-found, error, and bad-auth responses (status code + body).
- Each dataset's header lines and column order.
- Any rarely-populated nested field (find a record where it's non-empty, ex. by searching a
  family known to have it).

## 5. Fix

- **Transport first.** Central status handling fixes many findings at once: auth failures always
  raise; "not found" returns empty for reads but raises for writes; harmless write outcomes (ex.
  "already exists") aren't errors; deprecation notices raise; secrets are scrubbed from errors.
- **Normalizers** read each real shape. When a list of sub-sources (vendors, sandboxes) has
  heterogeneous fields, give each its own reader plus a generic fallback for unknown future ones;
  key-guessing heuristics are how misreads happen. Normalize each source's score scale and verdict
  vocabulary explicitly.
- **Model** every normalized field, or list it as deliberately not modeled (pure counters, etc.)
  in the README. A field that's normalized but never read by the model is a bug.
- **Commands/YAML.** Expose new endpoints by extending existing commands where they fit, fix help
  text that contradicts the docs, and remove choices for dead datasets.
- For Storm-specific pitfalls hit while fixing, see the Storm section of
  [references/failure-classes.md](references/failure-classes.md).

## 6. Prove it

1. **Rebuild fake-server fixtures from the live shapes** captured in step 4: unwrapped responses,
   real error bodies, real field names, real vendor entries. Don't edit assertions to match the
   old fake; replace the fake's data.
2. Add a test per finding at the lowest level that shows it (normalizer, service method, Storm
   command), including the negative cases (bad key raises, masked values dropped, deprecated
   dataset raises, write to a missing item raises).
3. Run the full suite and the linter (no new findings beyond the existing baseline).
4. Run the **live** test suite, then a live end-to-end check that exercises each fix through the
   real API **and** through Storm (commands complete without warnings or errors, expected nodes
   exist). Update the live tests for anything removed or added.
5. Update the README: the command table, the endpoint coverage table, the data model table, the
   "not modeled" list, and the "deliberately out of scope" datasets.

## 7. Report and commit

- Commit with a message grouped by **Broken / Wrong data / Missing data / Missing endpoints**, and
  push. Update the PR description's testing section with what was verified live and what wasn't
  (ex. write endpoints).
- Give the user a merge verdict: ready only when every confirmed finding is fixed or explicitly
  deferred, offline and live suites pass, CI is green, and the remaining unverified surface (usually
  writes) is named.
