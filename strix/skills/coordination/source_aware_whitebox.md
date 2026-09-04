---
name: source-aware-whitebox
description: Coordination playbook for source-aware white-box testing with static triage and dynamic validation
---

# Source-Aware White-Box Coordination

Use this coordination playbook when repository source code is available.

## Objective

Increase white-box coverage by combining source-aware triage with dynamic validation. Source-aware tooling is expected by default when source is available.

## Recommended Workflow

1. Build a quick source map before deep exploitation, including at least one AST-structural pass (`sg` or `tree-sitter`) scoped to relevant paths.
   - For `sg` baseline, derive `sg-targets.txt` from `semgrep.json` scope first (`paths.scanned`, fallback to unique `results[].path`) and run `xargs ... sg run` on that list.
   - Only fall back to path heuristics when semgrep scope is unavailable.
2. Run first-pass static triage to rank high-risk paths.
3. Use triage outputs to prioritize dynamic PoC validation.
4. Keep findings evidence-driven: no report without validation.

## Source-Aware Triage Stack

- `semgrep`: fast security-first triage and custom pattern scans
- `ast-grep` (`sg`): structural pattern hunting and targeted repo mapping
- `tree-sitter`: syntax-aware parsing support for symbol and route extraction
- `gitleaks` + `trufflehog`: complementary secret detection (working tree and history coverage)
- `trivy fs`: dependency, misconfiguration, license, and secret checks

Coverage target per repository:
- one `semgrep` pass
- one AST structural pass (`sg` and/or `tree-sitter`)
- one secrets pass (`gitleaks` and/or `trufflehog`)
- one `trivy fs` pass

## Agent Delegation Guidance

- **Partition by entry-point-map slice, not by vulnerability class.** One
  agent's mandate should span every relevant sink/guard class (injection,
  access control, file handling, SSRF, etc. — see whatever framework
  skill's own catalog applies) for the entry points it's assigned, not one
  agent per class. Splitting by class instead of by slice multiplies agent
  count — and duplicated context cost — without adding coverage; see
  `coordination/root_agent.md`'s "Consolidate Related Classes."
- **Every subagent reads `/workspace/.source-aware/entry_points.md` before
  doing anything else, and does not re-run the baseline scanners or
  re-derive the map from source.** The map is the assignment, not a
  suggestion to double-check by starting over.
- Scale beyond one agent only when the map is large enough to need it, and
  split by dividing its rows across agents of the *same* mandate shape
  (agent A gets rows 1-N, agent B gets N+1-2N) — never by spinning up a
  second agent for a different vulnerability class over the same rows.
- Keep a **separate, dedicated agent for business-logic QA** (see
  `vulnerabilities/business_logic.md`) working from the map's
  "logic-bearing functions" list — that reasoning is different in kind
  from sink-tracing and deserves its own focused pass rather than being
  folded into the injection/access-control agent's mandate.
- Prefer creating child agents with the `source_aware_sast` skill (and
  whatever framework skill matched, e.g. `wordpress`) for source-heavy
  subtasks.
- Use source findings — including business-logic hypotheses from the QA
  agent — to shape payloads and endpoint selection for dynamic testing.

## Validation Guardrails

- Static findings are hypotheses until validated.
- Dynamic exploitation evidence is still required before vulnerability reporting.
- Keep scanner output concise, deduplicated, and mapped to concrete code locations.
