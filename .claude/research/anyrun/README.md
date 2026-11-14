# anyrun research

Research for an ANY.RUN (Interactive Sandbox and Threat Intelligence) service, `slib.anyrun`,
done 2026-11-02 and 2026-11-03. The service was built and then **scrapped before it was merged**,
because ANY.RUN's API needs a paid plan (see [plans and access](notes/plans-and-access.md)) and
there's no API account to use it with.

The code was removed in the commit that added these notes, but it's still in the history of the
`claude/anyrun-service-g6ylf1` branch. Its last version is commit
`38931731f99c9a49a40808ccbe493bda582de0a4` (`svcs/anyrun/`), in case it's ever rebuilt.

Start with the access check: none of this is usable without an API plan.

| Notes | Covers |
|---|---|
| [`notes/plans-and-access.md`](notes/plans-and-access.md) | Which plans get the Sandbox API, TI Lookup, YARA Search, and the TI Feeds (the free Community plan gets none of them) |
| [`notes/api-reference.md`](notes/api-reference.md) | The Sandbox and TI APIs from ANY.RUN's OpenAPI specs and official SDK: hosts, auth, every endpoint's request and response shapes, error shapes, rate limits, and where the SDK is wrong |
| [`notes/modeling-design.md`](notes/modeling-design.md) | How the scrapped service modeled tasks in Synapse 2.x, and the decisions made along the way, so a rebuild doesn't have to redo them |

Nothing was ever run against the live API (no key), so every response shape here comes from
the specs and the SDK. The api-reference marks what neither source confirms as UNVERIFIED.
