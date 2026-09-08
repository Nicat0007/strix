---
name: candidate-triage
description: A categorical (never numeric) priority queue for ordering which untested candidate to investigate next, from attack_surface.md/mutation_candidates.md/trust_boundaries.md rows or an ad hoc black-box list — a sort key, never a gate
---

# Candidate Triage

`custom/source_aware_sast.md`'s Attack Surface Compiler,
`analysis/parameter_mutation_testing.md`'s Family Sweep, and
`reconnaissance/trust_boundary_mapping.md`'s Test Pairs each already
produce a list of untested rows to work through. None of them say which
row to start with — an agent facing several open rows in its own
entry-point slice has been ordering them ad hoc. This file is a fixed,
explicit lookup table for that ordering decision, nothing else.

**Categorical in, categorical out — no numbers ever reach the model.**
Every input is one of three labels; the output is one of four buckets.
The lookup table below was generated from a simple internal scheme (shown
so every cell can be checked, not asserted) but that arithmetic is never
something you compute or reason about — you read three labels off a
candidate and look up its bucket, the same way you'd look up a word in a
dictionary.

## Where This Applies

Rows from whichever of these already exists for the current candidate —
never a new artifact, never a fourth parallel list:

- `attack_surface.md`'s per-route rows (whitebox) — `evidence_strength`
  reads almost directly off the row's own source/sink/auth-check facts.
- `mutation_candidates.md`'s family rows (black-box or whitebox).
- `trust_boundaries.md`'s Test Pairs (actor-replay candidates).
- An ad hoc candidate list you're keeping yourself, when none of the
  above exists yet (pure black-box, pre-recon-artifact stage).

This is applied **internally, by whichever agent is working its own
slice** — not a root-agent gate, and not a shared, cross-agent ledger.
Each agent already owns triage of its own assigned rows under the
existing entry-point-slice delegation model
(`coordination/source_aware_whitebox.md`'s Agent Delegation Guidance);
this file just gives that private decision a fixed rubric instead of ad
hoc judgment reinvented per agent, per scan.

## The Three Labels

Each is `high` / `medium` / `low`, judged from what you already have in
front of you — never a new investigation just to fill in a label:

- **`impact`** — the potential severity if this candidate turns out to
  be real, per `analysis/severity_calibration.md`'s rubric applied
  *prospectively* (before confirmation, not as a final rating). An
  admin-only action, a cross-tenant object, or a code-execution-shaped
  sink is `high`; a cosmetic or purely internal difference is `low`.
- **`evidence_strength`** — how much existing *structural* evidence
  already supports this being worth checking, not a guess at the odds
  it's real. A tainted source reaching a sink with no auth-check found
  in `attack_surface.md`'s window is `high`; a route that exists but
  matched no source/sink/auth pattern at all is `low`.
- **`test_cost`** — how expensive checking is. A single grep/read that
  confirms or rules out the candidate is `low`; a multi-step live
  exploitation needing multiple accounts, chained requests, or a fragile
  timing window is `high`.

## The Lookup Table

| impact | evidence_strength | test_cost | bucket |
|---|---|---|---|
| high | high | high | P1 |
| high | high | medium | P0 |
| high | high | low | P0 |
| high | medium | high | P1 |
| high | medium | medium | P1 |
| high | medium | low | P0 |
| high | low | high | P2 |
| high | low | medium | P1 |
| high | low | low | P1 |
| medium | high | high | P1 |
| medium | high | medium | P1 |
| medium | high | low | P0 |
| medium | medium | high | P2 |
| medium | medium | medium | P1 |
| medium | medium | low | P1 |
| medium | low | high | P3 |
| medium | low | medium | P2 |
| medium | low | low | P1 |
| low | high | high | P2 |
| low | high | medium | P1 |
| low | high | low | P1 |
| low | medium | high | P3 |
| low | medium | medium | P2 |
| low | medium | low | P1 |
| low | low | high | P3 |
| low | low | medium | P3 |
| low | low | low | P2 |

**How this was generated** (for auditing the table, not for you to
recompute): `impact` and `evidence_strength` each score 2/1/0 for
high/medium/low; `test_cost` scores 2/1/0 for low/medium/high (cheap is
good). Sum the three (range 0-6): 5-6 → P0, 3-4 → P1, 2 → P2, 0-1 → P3.

**The cells worth explaining, not just asserting:**

- **`high / low / high` → P2, not P3.** A potentially critical bug never
  gets buried at the bottom of the queue just because it's hard to check
  and the evidence for it is currently thin — the downside of missing a
  real high-impact issue outweighs the queue-position cost of checking
  it before the easy stuff runs out.
- **`high / low / low` → P1, not P0.** Cheap enough to just check
  regardless of weak evidence, but P0 is reserved for candidates with at
  least some real evidence behind them — cheap-and-unproven queues ahead
  of most things, not ahead of everything.
- **`low / high / low` → P1.** A cheap, well-evidenced check is worth
  doing early even though the payoff if confirmed is small — it clears
  fast and stops competing for attention later.
- **`high / high / high` → P1, not P0.** Genuinely worth doing, but
  expensive enough that it shouldn't jump ahead of equally strong
  candidates that cost less to resolve.
- **`low / low / low` → P2, the least intuitive cell.** Low payoff either
  way, but it's free — a zero-cost check should never sit at the very
  bottom just because nobody expects much from it. Clearing a free check
  off the list costs nothing; leaving it to rot at P3 alongside genuinely
  expensive, low-value work does not reflect its real cost.

## Non-Negotiable

**This is a sort key on your own worklist, never a filter and never a
gate.** A P3 candidate you can rule out in thirty seconds while you're
already looking at the file is worth doing regardless of queue position
— nothing here blocks acting on your own judgment about a specific
candidate. The table orders a backlog when you have several open rows
and no other reason to prefer one; it does not override a reason you
already have.

## What This Does Not Do

No numeric score, no confidence percentage, no LLM-generated priority
value — the bucket comes from a fixed table over three labels you
assign by reading what's already in front of you. `impact` here is a
prospective estimate for ordering purposes only; it never substitutes
for `analysis/severity_calibration.md`'s actual post-confirmation rating
once a candidate becomes a finding.

## Cross-References

- `custom/source_aware_sast.md` — `attack_surface.md` is the primary
  source of `evidence_strength` for whitebox candidates.
- `analysis/parameter_mutation_testing.md` — `mutation_candidates.md`'s
  family rows are one of the row sources this triages.
- `reconnaissance/trust_boundary_mapping.md` — `trust_boundaries.md`'s
  Test Pairs are another.
- `coordination/source_aware_whitebox.md` — the entry-point-slice
  delegation model this triage runs inside, per-agent, per-slice.
- `analysis/severity_calibration.md` — governs the real, post-confirmation
  severity rating; `impact` here is a prospective estimate only.
