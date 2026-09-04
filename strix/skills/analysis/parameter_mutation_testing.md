---
name: parameter-mutation-testing
description: Shared three-way mutation set and diff-and-classify engine behind mass assignment, BFLA, and IDOR testing — generates no candidate values itself, consumes per-class values from those skills and produces one structured diff record they all read the same way
---

# Parameter Mutation Testing

`mass_assignment.md`'s Shape Variants, `broken_function_level_authorization.md`'s
verb sweep, and `idor.md`'s Enumeration Techniques each independently invented
their own "send a modified request, see what changed" step. The values worth
trying are genuinely different per vuln class — that part stays where it is.
What was duplicated, inconsistently, was everything *after* the request went
out: how many variants to send, what "changed" means, and what counts as
noise versus signal. This file is that shared core. It has three layers:

- **Layer A** — the three-way mutation set: what to send, and why three.
- **Layer B** — the shared diff record: what comes back, as one schema every
  consumer reads the same way.
- **Layer C** — nothing lives here. The per-class value catalogs stay in
  `mass_assignment.md`, `idor.md`, `broken_function_level_authorization.md`,
  and `business_logic.md` — see "Class-Specific Generators Stay Put" below.

## Layer A — The Three-Way Mutation Set

For one candidate parameter (a field, an object-reference, a path segment),
capture exactly three requests relative to one baseline:

1. **Control (C)** — the original, legitimately-authorized request, sent
   again rather than reused from an earlier capture, so response
   nondeterminism (timestamps, nonces, request IDs) is visible up front
   rather than mistaken later for a mutation effect.
2. **Boundary Mutation (T)** — the same slot, a class-appropriate
   *structural or type* mutation from Layer C's catalog (alternate type,
   edge value, duplicate key, shape variant) that does **not** cross an
   authorization or ownership boundary — same principal, same tenant, same
   role. This is a negative control: if T produces a diff, the sink is
   reacting to *any* shape change, not specifically to a boundary crossing.
3. **Adversarial Mutation (X)** — the same slot, a class-appropriate value
   that *does* cross a trust boundary from Layer C's catalog (a foreign
   object ID, an elevated field, another principal's identifier, a
   disallowed verb). This is the actual candidate.

A bare before/after diff (C vs X alone) cannot distinguish "X changed
something" from "anything changes something here." Diffing T against C
establishes the sink's own noise floor and shape-sensitivity; diffing X
against C and comparing that diff to T's diff is what lets you say X caused
a change T didn't — a real signal, not an artifact of resending a slightly
different request. This is the same discipline `counterevidence.md` already
asks for when ruling something out ("send the payload that should work...
show it is blocked, while a benign variant succeeds") — T is that benign
variant, generated up front instead of after the fact.

**Reusing the Control.** Capture C once per family (see Family Sweep below),
not once per mutation. A family with five candidate fields across three
members needs one Control capture and up to fifteen T/X sends, not fifteen
independent C/T/X triples — re-fetching an unchanged Control repeatedly
burns request budget for zero new information.

## Layer B — Shared Diff Record

### Caller Contract

Layer C supplies, per mutated field/path, what a correct server would do
with it:

```
expectations: {
  "<json-path-or-header>": "unchanged"                  // must equal Control exactly
                          | "reflects_mutation:<value>"  // must equal what was just sent
                          | "bounded:<min>,<max>"         // server-recomputed numeric (totals, balances)
}
```

An undeclared path still gets its delta recorded but `out_of_expected_range`
stays `null` — undeclared means not yet informative, never safe.

### Diff Record Schema

One record per Control-vs-Candidate pair (Control-vs-T and Control-vs-X are
two separate records):

```jsonc
{
  "comparison_id": "orders:GET:/orders/{id}:X-cross-owner",
  "status":  { "baseline_code": 200, "candidate_code": 200, "changed": false },
  "size":    { "baseline_bytes": 842, "candidate_bytes": 850, "delta_bytes": 8,
               "delta_pct": 0.95, "beyond_noise": false },
  "headers": { "added": [], "removed": [], "changed": {} },
  "body_shape": {
    "same_key_set": true,
    "top_level_keys_added": [], "top_level_keys_removed": [],
    "array_length_deltas": {},
    "type_changes": {},
    "value_deltas": {}
  },
  "timing": { "baseline_ms_median": 120, "candidate_ms_median": 118, "samples": 3, "usable": false },
  "retry_required": false,
  "signal_class": "none",
  "noise_filtered_fields": ["headers.Date", "value_deltas.meta.request_id"],
  "notes": ""
}
```

- `size.beyond_noise` = `abs(delta_bytes) > max(32, 0.02 * baseline_bytes)`
  — an absolute floor for tiny bodies, a proportional one for large ones.
- `headers` is diffed **after** stripping a fixed ignore-list — `Date`,
  `Set-Cookie` (session/CSRF token components), `X-Request-Id`,
  `X-Trace-Id`/`X-Correlation-Id`, `ETag` (unless ETag itself is the field
  under test), `Server-Timing` — so these never surface as false
  `headers.changed` entries.
- `array_length_deltas` excludes any array whose length change is fully
  explained by a pagination/limit parameter the mutation itself changed.
- `timing.usable` only becomes `true` at `samples >= 3` per side (median);
  a single-sample timing delta is never a standalone signal — timing is
  the noisiest channel here and gets the highest bar.
- `retry_required` is set when either status code lands in the flaky set
  `{429, 503}`; one backoff retry happens before classification, not a
  verdict on the first flaky response.

### Deriving `signal_class`

Deterministic, computed by Layer B directly — no LLM call needed for this
step:

1. `retry_required` → `"inconclusive"` until the retry resolves it.
2. `status.changed` (and not the flaky-retry case) → `"status"`.
3. else `same_key_set == false`, or any `type_changes`, or any non-zero
   non-pagination `array_length_deltas` entry → `"structural"`.
4. else any `value_deltas[...].out_of_expected_range == true`, or
   `size.beyond_noise` → `"value"`.
5. else → `"none"`.

`signal_class` never carries a security verdict. `"structural"` means "a
new field appeared" or "an array grew" — whether that's a mass-assignment
win, an IDOR content leak, or a BFLA side-effect is the calling skill's
reading, and `counterevidence.md` still gates whether a `signal_class` hit
becomes a filed finding (see "Using a Diff Record" below).

## Class-Specific Generators Stay Put

This file never invents a candidate value. Each vuln skill keeps owning its
own catalog and feeds it into Layer A as the T/X value source:

- `mass_assignment.md` — Parameter Strategies, Shape Variants, Encodings and
  Channels (field names, alternate shapes, content-type switches)
- `idor.md` — Enumeration Techniques, UUID/Opaque ID Sources (alternate
  types, edge values, parameter pollution, cross-principal IDs)
- `broken_function_level_authorization.md` — Systematic Verb and Endpoint
  Enumeration (verbs, header trust variants, route aliases)
- `business_logic.md`'s Source-Code QA Methodology — calculation/state
  values for the white-box QA reading, when a live target exists to
  dynamically confirm a candidate found by reading code

## Family Sweep

Running the three-way set per-endpoint is correct but wasteful when many
endpoints share the same shape and the same mutation strategy applies to
all of them. Group endpoints into families first; generate and reuse one
mutation plan per family.

### Family Key

`(static path segments, path-parameter positions, endpoint kind)`, where
`endpoint kind` ∈ `{item, collection-list, collection-create, action}`,
inferred from verb plus trailing-segment shape. Verb-within-kind and
content-type are swept *inside* a family, not used to split it — the same
object gets probed as JSON/form/multipart per `mass_assignment.md`'s
existing Encodings and Channels dimension without re-deriving a new family.
Static segments are held fixed, not abstracted away — same parameter arity
alone is not enough to group two endpoints (see the `/orders/{id}` vs
`/invoices/{id}` row below).

### Worked Example

Synthetic API: `/orders`, `/orders/{id}`, `/orders/{id}/items`,
`/orders/{id}/items/{itemId}`, `/invoices`, `/invoices/{id}`,
`/invoices/{id}/download`, `/invoices/{id}/void`, `/users/{id}`,
`/users/{id}/orders`, `/users/{id}/orders/{orderId}`.

| Family | Endpoints | Kind | Grouped/split because |
|---|---|---|---|
| F1 | `GET/PATCH/DELETE /orders/{id}` | item | same prefix, 1 param, item verbs — grouped; content-type swept within |
| F2 | `GET /orders` | collection-list | 0 params, list semantics — split from F1, mutation strategy is filter/pagination, not ID-swap |
| F3 | `POST /orders` | collection-create | same static path as F2, but verb signals a different kind (body mass-assignment, no baseline object) — split from F2 too |
| F4 | `GET /orders/{id}/items` | collection-list, nested | own family — has a *parent* binding to test that F2 doesn't |
| F5 | `GET /orders/{id}/items/{itemId}` | item, depth 2 | split from F1 (depth) and F4 (item, not list) — runs `idor.md`'s swap-child-only / swap-parent-only / swap-both test |
| F6 | `GET /invoices/{id}` | item | **not** grouped with F1 despite identical shape — different resource prefix, different ownership semantics |
| F7 | `GET /invoices/{id}/download` | item, binary | own family — different prefix from F6 anyway; body-shape diffing degrades to size/hash-only here |
| F8 | `POST /invoices/{id}/void` | action | trailing static verb segment + POST → action kind, not item, despite sharing `invoices/{id}` with F6 — `business_logic.md`'s state-machine strategy, not an ID-swap |
| F9 | `GET/PATCH /users/{id}` | item | own family |
| F10 | `GET /users/{id}/orders` | collection-list, nested | own family, parallel to F4 |
| F11 | `POST /users/{id}/orders` | collection-create, nested | split from F10, same kind-split as F2/F3 |
| F12 | `GET /users/{id}/orders/{orderId}` | item, depth 2 | **not** grouped with F5 despite identical shape (1+1 params) — different static chain |

F1 and F12 both address the same underlying order object through two
different families — `idor.md`'s "Alternate API Versions and Channels"
pattern. Family grouping is a generation-efficiency device only; it does
not merge F1/F12, and testing whether authorization differs between the two
routes for the same object is its own worklist item, run across families
rather than folded into either family's sweep.

### Where the Family Map Lives — `mutation_candidates.md`

`entry_points.md` (`custom/source_aware_sast.md`) is white-box-only — built
inside the sandbox from static scanning, and never produced on a pure
black-box target. Mutation testing has to run in both modes, so the family
map is a **separate** artifact: `/workspace/recon/mutation_candidates.md`,
following the same reuse-don't-rederive convention `asset_discovery.md`
already established for everything else under `/workspace/recon/`.

- Built from whatever endpoint inventory the scan already has: recon's
  crawled/enumerated endpoint list in black-box mode, cross-referenced
  against `entry_points.md`'s route/handler rows when white-box source is
  also available (a whitebox scan gets the richer of the two, never a
  third redundant list).
- One row per family: family key, member endpoints, kind, and open
  mutation candidates (which T/X pairs are untested vs already run, and
  their last `signal_class`) — a worklist ledger, not a hit list, matching
  `entry_points.md`'s own "map to read from, not a report" framing.
- Any of `mass_assignment.md`/`broken_function_level_authorization.md`/
  `idor.md`'s testing agents read this file before generating their own
  family list, and update a family's row (not append a duplicate) when
  they run its sweep — the same shared-ledger discipline
  `counterevidence.md` already requires of `record_coverage`.

## Using a Diff Record

A `signal_class` other than `"none"` is a lead, not a verdict. Read it
through whichever vuln skill generated the mutation:

- `"structural"` on a mass-assignment X candidate (a new top-level key
  appeared, e.g. `"role"` in the response that wasn't there for T) → the
  candidate for `mass_assignment.md`'s Testing Methodology step 5
  (compare state).
- `"structural"`/`"value"` on an IDOR X candidate (different top-level
  content, or a `value_delta` showing another principal's data) → the
  candidate for `idor.md`'s Impact Escalation gate — still needs the real
  content proof that gate demands, the diff record only gets you there
  faster.
- `"status"` on a BFLA X candidate (200 where T got 403) → the candidate
  for `broken_function_level_authorization.md`'s Impact Escalation gate,
  same caveat.

Every one of these still passes through `counterevidence.md`'s full
closure discipline before it becomes `confirmed` — a diff record narrows
where to look, it does not replace the PoC.

## Cost Discipline

The point of Layers A/B/Family Sweep together is the same one behind
`custom/source_aware_sast.md`'s `entry_points.md` (§11 of this project's
build log): compute the cheap, deterministic part once and let every
consumer read it, instead of each vuln-class agent re-deriving its own
request/diff loop from scratch and burning tokens re-establishing what
"changed" means for the tenth time on the same endpoint family.

## Cross-References

- `mass_assignment.md`, `broken_function_level_authorization.md`,
  `idor.md` — each supplies Layer C values and reads Layer B's output
  through its own lens (see "Using a Diff Record").
- `analysis/counterevidence.md` — governs whether a `signal_class` hit
  ever becomes `confirmed`; this file only produces leads.
- `custom/source_aware_sast.md` — `entry_points.md` is this file's
  white-box sibling artifact, not a section to merge into; see "Where the
  Family Map Lives".

## Summary

Three requests, not one ad hoc mutation: a Control to find the noise
floor, a Boundary mutation as a negative control, and an Adversarial
mutation as the actual candidate. One diff schema turns all three vuln
skills' "did anything change" question into the same deterministic
`signal_class`, computed once per family instead of once per endpoint —
the candidate values stay vuln-specific; the request/diff/classify loop
around them does not.
