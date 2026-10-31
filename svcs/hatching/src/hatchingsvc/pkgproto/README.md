# slib.hatching

A Storm Service for the Hatching Triage Sandbox (tria.ge, the private cloud, or a
self-hosted instance): submit files and URLs, model analyses, download samples, pcaps, and
dropped files, read every report, and manage profiles, Yara rules, and users.

Run any `slib.hatching.*` command with `--help` for its options and examples.

## API keys

Keys are resolved per request, in this order:

1. Your own key, set with `slib.hatching.apikey <key>` (stored in a user scoped vault of type `hatching`).
2. The service-wide key, set by an admin with `slib.hatching.admin.apikey <key>`.
3. The service's `hatching:apikey` config option.

## Permissions

- `slib.hatching.user` - Search, model analyses, read reports, and download files.
- `slib.hatching.submit` - Submit files and URLs, pick profiles, and delete samples.
- `slib.hatching.manage` - Analysis profiles and Yara rules.
- `slib.hatching.admin` - The service-wide key, tag settings, users, and raw requests.

## Examples

```
// Model the newest analysis of some files, including their behavioral tasks.
file:bytes#my.tag | slib.hatching.enrich --tasks

// Submit files from the Axon and model the results once they're reported.
file:bytes#my.tag | slib.hatching.submit --wait 600 --yield

// Download the files a sample dropped.
slib.hatching.download --sample 261031-a1b2c3d4e5 --dumped --yield
```

Triage's tags and malware families are tagged under `rep.hatching` by default (ex.
`#rep.hatching.cobaltstrike`). Change it with `slib.hatching.admin.tags`.
