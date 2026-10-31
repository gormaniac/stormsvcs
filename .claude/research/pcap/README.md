# pcap research

Research behind `svcs/pcap` (PR #16), done 2026-10-31. It covers planning the merge of the pcap, Snort
(PR #17), and a future Suricata service into one service, plus a tshark sandbox. This is planning
material only. Nothing here has been implemented yet.

Start with the plan:

- [`unified-pcap-snort-suricata-plan.md`](unified-pcap-snort-suricata-plan.md): The recommended
  architecture, data flow, flow identity scheme, Synapse modeling (including Synapse 3.x renames),
  Storm surface, rule feeds and licensing, sandbox design, Docker packaging, PR #16/#17 migration,
  phased rollout, risks, and open questions.

Supporting notes, cited by the plan:

| Notes | Covers |
|---|---|
| [`notes/existing-services-and-models.md`](notes/existing-services-and-models.md) | The designs of PR #16 and PR #17, repo conventions, and Synapse 2.256 and 3.x model forms for rules, matches, and flows |
| [`notes/rule-compatibility.md`](notes/rule-compatibility.md) | Snort 2.9 vs. Snort 3 vs. Suricata rule syntax, converters, rulesets and licensing, load error reporting |
| [`notes/suricata-analysis-engine.md`](notes/suricata-analysis-engine.md) | What Suricata 8's EVE output covers, matching it back to flows (`pcap_cnt`, Community ID), running and packaging Suricata |
| [`notes/sandboxing.md`](notes/sandboxing.md) | Sandboxing tshark and Suricata in Docker (Landlock, seccomp, rlimits, tshark flags), with test results |
| [`notes/rust-helper.md`](notes/rust-helper.md) | rusticata crates, PyO3 vs. a CLI, effort estimate, why pure Python is enough |
| [`notes/rust-tshark-alternatives.md`](notes/rust-tshark-alternatives.md) | The first pass on Rust tshark alternatives, with later corrections noted |
| [`prototypes/landlock_exec.py`](prototypes/landlock_exec.py) | The research's Landlock exec wrapper, see below |

Caveats:

- The notes are research records. Each one separates sourced facts from inference and lists its own
  gaps. Things the plan says need testing (Snort `pkt_num` vs. frame numbers, Suricata build
  dependencies, rule load times, Debian 12's tshark version) haven't been verified.
- Some notes contain paths from the research environment (ex. `/home/user/stormsvcs/...`). They mean
  the matching paths in this repo.
- Advisory counts and version facts are as of 2026-10-31.
- Synapse 3 facts were corrected against the released 3.7.0 wheel. The first version wrongly said
  Synapse 3 was unreleased and had dropped the `it:app:suricata:*` forms. 3.7.0 keeps separate Snort
  and Suricata rule and `matched` forms, renames `it:app:snort:hit` to `it:app:snort:matched`, and
  requires Python 3.14.
- `prototypes/landlock_exec.py` is an unreviewed ~25 line ctypes proof of concept from the sandboxing
  research. Usage: `python landlock_exec.py <comma separated allowed paths> <command> [args...]`. It
  limits the command to reading system directories and the listed paths, then execs it. It isn't part
  of the service and isn't production code.
