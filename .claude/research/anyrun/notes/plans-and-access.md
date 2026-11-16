# ANY.RUN plans and API access

Checked 2026-11-03 against https://any.run/plans/ and the error lists in ANY.RUN's API specs
(https://files.any.run/schema/SandboxV1.json and https://files.any.run/schema/TIV1.json).

| Plan | Price | API access |
|---|---|---|
| Community | Free | **None.** The Sandbox spec's 403 errors include "API is not available on the free plan". |
| Hunter | Contact sales | Unclear. The spec says submitting tasks, IOCs, AI summaries, and tier 1 reports need "an active subscription to a Hunter or Enterprise plan", but the plans page only lists API quotas under Enterprise Suite. Hunter does list JSON and MISP exports. |
| Enterprise Suite | Contact sales | "1,500+ API tasks/mo", "Task history via API", and "TI Lookup & YARA Premium". |

The Threat Intelligence APIs (TI Lookup, YARA Search, and the TAXII TI Feeds) need a separate TI
license on top of that. The TI spec's errors include `NO_TI_LICENSE_ERROR` ("TI license not
found"), `API_LOOKUP_DISABLED_ERROR`, `API_YARA_DISABLED_ERROR`, and a trial quota for YARA
(`YARA_DISABLED_ERROR`, "Your trial request limit has been reached"). TI Lookup responses have an
`isTrial` flag, so trial access exists, but nothing says it's available without a sales contact.

Every API takes the same `Authorization: API-Key <key>` header. What a key can do depends on its
plan and licenses.

## Before building this again

Get a key first and confirm what it can do with read-only calls:

- `GET https://api.any.run/v1/user` shows the API limits and parallel task slots. It fails on
  plans without API access.
- `GET https://api.any.run/v1/intelligence/keycheck` is used by the SDK to check TI access
  without using quota. It's not in the spec, so its response shape is unknown.

Scope the service to what the key's plan includes. Without a TI license, finding the task for a
hash or URL only works through the account's own task history (the newest 100 tasks).
