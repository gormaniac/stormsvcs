# DESIGN.md outline

The section structure of a service design document, as used by `.claude/research/velo/DESIGN.md`
(the reference example — read it when in doubt about depth or tone). Keep the numbering; drop a
section only when it's genuinely inapplicable and say so.

Header block: status (DESIGN — no code yet), date, pinned targets (external system version range,
Synapse version, "stormsvcs conventions"), pointers to the research appendices and the claim that
every form/field is verified against them.

1. **Overview** — 1.1 Goal (what the service models, ending with the one-command acceptance
   statement); 1.2 Non-goals for v1 (each with a reason); 1.3 Why this is hard (the 3–5 forcing
   problems the design must solve).
2. **Background (condensed)** — one paragraph on the external system's object model; a bulleted
   "Synapse model anchors" list (verified forms/edges/deprecations/tags/precedent). Point to the
   appendices for field-level detail.
3. **Naming & repo integration** — a table: service folder, python package, storm package name,
   command namespace, tag prefix, services.toml entry, CI workflow, starting version +
   version-sync rule, LICENSE symlink, synapse_minversion (+ how to pin it). New dependencies and
   their risks.
4. **Service architecture** — component/file layout tree; the Python client design (transport,
   auth, paging, retries, streaming, health/version probe); credential & multi-tenant/profile
   handling (storage, never-readable-from-Storm posture, expiry); the Telepath API surface table;
   version-compatibility strategy.
5. **Data model mapping** (the heart; longest section) —
   5.1 identity/provenance/guid-seed table (deployment-scoped, idempotent);
   5.2+ one subsection per object class (devices, collections, per-record-type mapper table with
   verbatim column→prop pairings, file/bytes pipeline, logs/events, alerts/findings, the hub node
   (incident/campaign/case), timelines, analyst artifacts);
   a **generic lossless fallback** subsection; a closing **tags & taxonomies** summary table.
6. **Sync & orchestration** — modes table (backfill pull / live tail / scheduled delta),
   incremental-correctness rules (watermarks, ordering, second-pass fixups, deletions, retention),
   scale controls with defaults.
7. **Storm package surface** — permissions table (split by blast radius), full command list with
   flags and cmdinputs, priv/unpriv module split, README/docs plan.
8. **Python implementation notes** — confdefs, module-by-module responsibilities, concurrency,
   injection-safety mechanics.
9. **Testing strategy** — the fake server design, fixture policy (encode the verbatim schemas +
   the nasty cases), Python unit targets, StormPkgTest suites (modeling, idempotency, perms,
   lifecycle end-to-end), gated live tests, CI notes.
10. **Docker & deployment** — image, secrets mounting, network prerequisites.
11. **Performance & scale budget** — a table of dimensions → targets → mechanisms.
12. **Security considerations** — credential handling, least-privilege on both sides, hostile-data
    handling (row content is attacker-controlled), action-command gating.
13. **Worked example / acceptance narrative** — a copy-pasteable Storm session that doubles as the
    integration-test storyline, plus explicit acceptance criteria.
14. **Deferred / v2+ candidates** — scope cuts with one-line rationale each.
15. **Open questions** — numbered, each with the decision needed and how to resolve it.
16. **Phased roadmap** — table: phase → scope → exit criteria, one version bump per phase per
    CLAUDE.md rules.
