---
name: service-design-research
description: Research, plan, and document a new Storm service (Synapse Advanced Power-Up) before any code is written. Use when asked to research, plan, scope, or design a new service or integration for this repo (including wish-list services), to produce a design doc for a complex external system (EDR, sandbox, intel platform, database), or to plan a major rework of an existing service. Produces a DESIGN.md plus research appendices under .claude/research/<svc>/ — never code.
---

# Service design research

Plans a new stormsvcs service the way the Velociraptor service was planned (see
`.claude/research/velo/` for the reference example): two parallel deep-research tracks grounded in
primary sources, synthesized into a single design document that an implementer can build from
without re-researching anything.

## Why this exists

A Storm service design fails in two predictable ways: the external system's API/data model is
assumed from memory or secondhand sources (sample scripts, blog posts, stale training data), or the
Synapse data model is assumed (forms that don't exist, deprecated forms, wrong property names).
Both are cured by the same medicine: verify every load-bearing fact against primary sources
*before* designing, and record the evidence so the implementer never has to trust the designer.

## Output contract

- Everything goes in **`.claude/research/<svc>/`** — never under `svcs/` (code trees stay clean
  until implementation starts):
  - `DESIGN.md` — the design document (structure: `references/design-doc-outline.md`).
  - One research appendix per track (e.g. `<system>-research.md`, `synapse-model-research.md`),
    written by the research agents, kept verbatim as the evidence base.
- **No code.** No service skeleton, no services.toml entry, no CI workflow — the design doc's repo
  checklist lists those as implementation-phase work.
- Commit on a branch; do not open a PR unless asked.

## Phase 0 — Repo grounding (do this yourself, ~15 min)

Read, in order: `CLAUDE.md` (versioning rules), `.github/copilot-instructions.md` (architecture +
conventions), `README.md` (per-service requirements), then the **most mature existing service** as
the reference implementation (currently `svcs/shodan/`): its `svc.py`/`api.py`/`defs.py`/`norm.py`,
the package YAML (perms, priv-module split, command conventions), `model.storm` (meta:source
`-(seen)>` provenance, tag-prefix globals, node-builder patterns), tests (fake server, versions-match
test), and docker/CI files. The design must conform to these; cite them instead of inventing.

## Phase 1 — Parallel deep research (two subagents, launched together)

Launch both as background general-purpose agents with **exhaustive briefs**. The brief is the main
quality lever: state the goal (a Storm service ingesting X into Synapse), enumerate every topic the
report must cover, name the primary sources to fetch, demand field-level tables, and require the
report be written to `.claude/research/<svc>/<track>.md` with inline URL citations and an explicit
"could not verify" list. Ask each agent to reply with only a short summary + file path.

**Track A — the external system.** Must cover, with actual field/column names from primary sources
(official docs, the project's GitHub source — protos/OpenAPI/schema files beat prose docs — and the
official client library):

1. Architecture and object model (every object class, its ID scheme, its schema).
2. The API: transport, auth, pagination/streaming model, rate/size limits, the complete
   enumeration surface, what's stable vs explicitly internal.
3. Current stable version + version landmines (breaking changes across recent releases).
4. Whatever the service domain's core concepts are (for an EDR: artifacts/detections/timelines;
   for a sandbox: submissions/reports/IOCs; adapt).
5. Output schemas for the highest-value data types, verbatim from source.
6. File/binary content retrieval, if any (feeds the Axon pipeline).
7. Existing integrations with other platforms (the patterns to copy).
8. A numbered **gotchas** list (auth pitfalls, unit mixes, truncation, injection surfaces).

**Track B — the Synapse data model, as ground truth.** The non-negotiable technique: **install the
current synapse release into a venv, start a temp Cortex, and dump `getModelDict()`** — then answer
from the dump, not from memory or even from docs pages alone. Must cover:

1. Candidate forms for every concept in the integration, with full property tables
   (name/type/doc), generated from the dump.
2. The declared lightweight-edge table and which verbs apply (`-(seen)>`, `-(found)>`,
   `-(about)>`, `-(refs)>`, `-(uses)>`, `-(targets)>`…).
3. **Deprecations** touching any candidate form/prop (the dump flags them) — these are design
   vetoes.
4. Explicit verification of load-bearing assumptions ("does form X exist? what links A to B?") —
   and, where a form does NOT exist, a recommended workaround using real forms + evidentiary tags.
5. Precedent: how Vertex's own Rapid Power-Ups model the same domain (fetch their user guides);
   confirm no existing power-up collides with the planned namespace.
6. Conventions: `$lib.guid()` seeding, `$lib.gen.*` helpers, `rep.<reporter>.*`/`cno.*` tags,
   `meta:source`/`meta:feed` ingest-state props.

While the agents run, finish Phase 0 and draft the repo-integration/naming sections.

## Phase 2 — Synthesis checks (yourself, before writing)

Read both reports fully. Then resolve the design's hinge points explicitly — the ones that are
expensive to get wrong:

- **Identity & idempotency:** a deterministic guid-seed table covering every node the service
  creates, scoped by deployment/tenant where external IDs aren't globally unique. Re-ingest must be
  a no-op; analyst edits must survive (`?=` discipline).
- **Lossless fallback:** the plan for data the mappers don't know (generic form + raw payload +
  taxonomy), so "everything the system exposes lives on the model" is guaranteed, not aspirational.
- **Connectivity:** every node must be reachable from the service's hub nodes (source/query/
  incident) via tag or ≤2 edge hops — name the mechanism per node class.
- **Model-constraint collisions:** where a Synapse constraint fights the domain (single-valued
  props, missing forms, comp-form shapes), pick a resolution and record the rejected alternative.
- **Scale and permission blast-radius:** row-count caps and watermarks; separate perms for
  read / heavy-bytes / endpoint-touching / fleet-touching / admin operations.

## Phase 3 — Write DESIGN.md

Follow `references/design-doc-outline.md` section by section. Rules of quality:

- Every form/prop/edge named must exist in the Track B dump (or be explicitly marked a workaround);
  every API field must appear in Track A with a citation trail.
- Mapping tables pair **verbatim external fields** with **verbatim Synapse props** — an implementer
  should never need the upstream docs open.
- Unresolved decisions go in a numbered **Open questions** section — flagged, not fudged.
- End with a phased roadmap where each phase is a shippable version bump per `CLAUDE.md` rules.

## Phase 4 — Deliver

Send the user `DESIGN.md`, summarize the key decisions (not the table of contents), and offer to
commit on a branch (`claude/<svc>-service-design`). Remind them nothing is implemented and point at
the open-questions list as the pre-implementation checklist.
