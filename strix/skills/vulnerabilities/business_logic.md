---
name: business-logic
description: Business logic testing for workflow bypass, state manipulation, and domain invariant violations, including authenticated multi-account collusion patterns and a white-box source-code QA methodology for authorization-order, calculation, state-machine, and invariant bugs
---

# Business Logic Flaws

Business logic flaws exploit intended functionality to violate domain invariants: move money without paying, exceed limits, retain privileges, or bypass reviews. They require a model of the business, not just payloads.

## Attack Surface

- Financial logic: pricing, discounts, payments, refunds, credits, chargebacks
- Account lifecycle: signup, upgrade/downgrade, trial, suspension, deletion
- Authorization-by-logic: feature gates, role transitions, approval workflows
- Quotas/limits: rate/usage limits, inventory, entitlements, seat licensing
- Multi-tenant isolation: cross-organization data or action bleed
- Event-driven flows: jobs, webhooks, sagas, compensations, idempotency

## High-Value Targets

- Pricing/cart: price locks, quote to order, tax/shipping computation
- Discount engines: stacking, mutual exclusivity, scope (cart vs item), once-per-user enforcement
- Payments: auth/capture/void/refund sequences, partials, split tenders, chargebacks, idempotency keys
- Credits/gift cards/vouchers: issuance, redemption, reversal, expiry, transferability
- Subscriptions: proration, upgrade/downgrade, trial extension, seat counts, meter reporting
- Refunds/returns/RMAs: multi-item partials, restocking fees, return window edges
- Admin/staff operations: impersonation, manual adjustments, credit/refund issuance, account flags
- Quotas/limits: daily/monthly usage, inventory reservations, feature usage counters

## Reconnaissance

### Workflow Mapping

- Derive endpoints from the UI and proxy/network logs; map hidden/undocumented API calls, especially finalize/confirm endpoints
- Identify tokens/flags: stepToken, paymentIntentId, orderStatus, reviewState, approvalId; test reuse across users/sessions
- Document invariants: conservation of value (ledger balance), uniqueness (idempotency), monotonicity (non-decreasing counters), exclusivity (one active subscription)

### Input Surface

- Hidden fields and client-computed totals; server must recompute on trusted sources
- Alternate encodings and shapes: arrays instead of scalars, objects with unexpected keys, null/empty/0/negative, scientific notation
- Business selectors: currency, locale, timezone, tax region; vary to trigger rounding and ruleset changes

### State and Time Axes

- Replays: resubmit stale finalize/confirm requests
- Out-of-order: call finalize before verify; refund before capture; cancel after ship
- Time windows: end-of-day/month cutovers, daylight saving, grace periods, trial expiry edges

## Key Vulnerabilities

### State Machine Abuse

- Skip or reorder steps via direct API calls; verify server enforces preconditions on each transition
- Replay prior steps with altered parameters (e.g., swap price after approval but before capture)
- Split a single constrained action into many sub-actions under the threshold (limit slicing)

### Concurrency and Idempotency

- Parallelize identical operations to bypass atomic checks (create, apply, redeem, transfer)
- Abuse idempotency: key scoped to path but not principal → reuse other users' keys; or idempotency stored only in cache
- Message reprocessing: queue workers re-run tasks on retry without idempotent guards; cause duplicate fulfillment/refund

### Numeric and Currency

- Floating point vs decimal rounding; rounding/truncation favoring attacker at boundaries
- Cross-currency arbitrage: buy in currency A, refund in B at stale rates; tax rounding per-item vs per-order
- Negative amounts, zero-price, free shipping thresholds, minimum/maximum guardrails

### Quotas, Limits, and Inventory

- Off-by-one and time-bound resets (UTC vs local); pre-warm at T-1s and post-fire at T+1s
- Reservation/hold leaks: reserve multiple, complete one, release not enforced; backorder logic inconsistencies
- Distributed counters without strong consistency enabling double-consumption

### Refunds and Chargebacks

- Double-refund: refund via UI and support tool; refund partials summing above captured amount
- Refund after benefits consumed (downloaded digital goods, shipped items) due to missing post-consumption checks

### Feature Gates and Roles

- Feature flags enforced client-side or at edge but not in core services; toggle names guessed or fallback to default-enabled
- Role transitions leaving stale capabilities (retain premium after downgrade; retain admin endpoints after demotion)

## Advanced Techniques

### Event-Driven Sagas

- Saga/compensation gaps: trigger compensation without original success; or execute success twice without compensation
- Outbox/Inbox patterns missing idempotency → duplicate downstream side effects
- Cron/backfill jobs operating outside request-time authorization; mutate state broadly

### Microservices Boundaries

- Cross-service assumption mismatch: one service validates total, another trusts line items; alter between calls
- Header trust: internal services trusting X-Role or X-User-Id from untrusted edges
- Partial failure windows: two-phase actions where phase 1 commits without phase 2, leaving exploitable intermediate state

### Multi-Tenant Isolation

- Tenant-scoped counters and credits updated without tenant key in the where-clause; leak across orgs
- Admin aggregate views allowing actions that impact other tenants due to missing per-tenant enforcement
- The full systematic tenant-boundary methodology (tenant-ID enumeration,
  tenant-admin/global-admin confusion, signup collision, cross-tenant
  search leaks) lives in `idor.md`'s `## Multi-Tenant / Tenant-Boundary
  Testing` — this entry stays the logic-invariant framing (conservation
  of value across tenant boundaries); load `idor` alongside this skill
  when tenant isolation is in scope

## Authenticated Multi-Account Abuse

Everything above works from a single session. The moment you hold two or more real accounts (see `reconnaissance/account_provisioning.md`), a distinct class of bugs opens up — one account's state feeds another's, and no single-session test would reveal it. Provision the accounts before this pass; a same-account replay does not prove any of these claims.

- **Workflow-step skipping**: with a real session, call the checkout/confirmation/finalize endpoint directly without the required prior steps (cart, address, payment method) in between — the authenticated form of State Machine Abuse above, where many flows only enforce ordering in the UI
- **Coupon/discount reuse across accounts**: apply a single-use or per-user code on Account A, then attempt the same code on Account B; check whether "per-user" is keyed on session/cookie rather than the actual account or payment identity
- **Referral and invite abuse**: use Account A to refer/invite Account B (both attacker-controlled) and claim both sides' bonus; chain referrals through several throwaway accounts to multiply a reward meant to be one-time
- **Loyalty/points abuse**: transfer, gift, or redeem points between Account A and B faster than the ledger reconciles; check whether balances are recomputed server-side or trusted from a client-supplied total
- **Booking/reservation races (double-book, overbook)**: fire concurrent reservation requests from Account A and B for the same slot/seat/room/inventory unit — see `race_conditions.md` for the concurrency mechanics (HTTP/2 multiplexing, last-byte sync); this section is about *what* to race in a booking flow, that one is about *how*
- **Collusion patterns**: one account performs an action whose benefit only the other consumes — Account A approves/reviews/vouches for something that benefits only Account B, a buyer (A) and seller (B) fake a transaction for a reward or rating boost, or an admin-adjacent action on A grants a privilege that only B redeems

## Bypass Techniques

- Content-type switching (JSON/form/multipart) to hit different code paths
- Method alternation (GET performing state change; overrides via X-HTTP-Method-Override)
- Client recomputation: totals, taxes, discounts computed on client and accepted by server
- Cache/gateway differentials: stale decisions from CDN/APIM that are not identity-aware

## Special Contexts

### E-commerce

- Stack incompatible discounts via parallel apply; remove qualifying item after discount applied; retain free shipping after cart changes
- Modify shipping tier post-quote; abuse returns to keep product and refund

### Banking/Fintech

- Split transfers to bypass per-transaction threshold; schedule vs instant path inconsistencies
- Exploit grace periods on holds/authorizations to withdraw again before settlement

### SaaS/B2B

- Seat licensing: race seat assignment to exceed purchased seats; stale license checks in background tasks
- Usage metering: report late or duplicate usage to avoid billing or to over-consume

## Chaining Attacks

- Business logic + race: duplicate benefits before state updates
- Business logic + IDOR: operate on others' resources once a workflow leak reveals IDs
- Business logic + CSRF: force a victim to complete a sensitive step sequence
- Business logic + BFLA: use a second, role-differentiated account to reach a workflow step meant to require staff/admin approval

## Source-Code QA Methodology (White-Box)

Everything above assumes a live target to poke at. Reading the source
directly finds the same class of bug earlier and cheaper, and reaches some
a black-box test never can — an admin-only, cron-only, or webhook-only path
no live session gives you access to. The central question, applied to
every function the entry-point map flagged as logic-bearing (see
`custom/source_aware_sast.md`'s Entry-Point Map): **what does this
function ASSUME, and can an attacker violate that assumption before this
line runs?**

This generates hypotheses to verify, not verdicts to report — see
"Discipline" at the end before filing anything.

### 1. Authorization-Order Flaws

The checked value and the used value are not the same one, or the check
runs on a path that doesn't cover every way to reach the use. The classic
shape: the function checks one identifier and then reads or mutates using
a different one.

```
# Vulnerable — the checked value and the used value are not the same one
if current_user.id == request.post['user_id']:
    return get_profile(request.get['user_id'])   # attacker controls this one

# Safe — one value, checked and used
target_id = request.post['user_id']
if current_user.id == target_id:
    return get_profile(target_id)
```

Also watch for: an early `return`/`continue` on one branch that skips a
check a later branch still relies on; a check performed in middleware that
doesn't wrap every route registered on the same controller; a check
against a cached/session-stored role read before the point where it could
have changed. This is the exact class that produced the REST IDOR in the
Ultimate Member calibration — authentication was present, authorization on
the *specific object* was not. Proven high-value; read for it first.

### 2. Calculation / Amount Manipulation

Find every function computing a price, quantity, total, balance, discount,
or refund. Ask: is it computed server-side from state the server already
trusts, or does it read (and merely range-check) a client-supplied number?
Is it computed once and trusted downstream, or re-derived at each step
that matters — a total validated at order confirmation is not
automatically still valid at payment capture if nothing re-checks it there.

```
# Vulnerable — server trusts the client's arithmetic
total = request.post['total']
if total < 0:
    reject()
charge(total)

# Safe — server recomputes from line items it controls
total = sum(item.price * item.qty for item in order.items)
charge(total)
```

Check sign and rounding too: does the code explicitly reject a negative
quantity/amount, or does it just not expect one (a negative quantity
flowing into a stock-adjustment or refund calculation reverses the
intended effect)? Does rounding/truncation always favor the platform, or
can attacker-chosen inputs (currency, item split, quantity) steer it the
other way?

### 3. State-Machine / Workflow-Step Bypass

Enumerate the states and transitions a workflow defines, then for each
transition-performing function ask whether it verifies the *current* state
before applying the transition — **on every code path that can call it**,
not just the one the UI normally uses. An admin tool, a cron job, a
webhook handler, or a second REST route reaching the same underlying
transition function is a separate path with its own reachability, and it's
usually the one that skips the check the main controller has.

```
# Vulnerable — a second route calls the transition directly, skipping the
# state check the main checkout controller performs
def mark_shipped(order):
    order.status = 'shipped'
    trigger_fulfillment(order)

# Safe — the guard lives in the function every caller goes through, not
# only in the caller that happens to check first
def mark_shipped(order):
    if order.status != 'paid':
        raise InvalidTransition(order.status)
    order.status = 'shipped'
    trigger_fulfillment(order)
```

The bug is rarely that *no* caller checks the state — it's that *one*
caller does and every other assumes the check already happened upstream.

### 4. Invariant Violations

State the invariant a piece of domain state depends on in one plain
sentence — "this record is always owned by the account that created it,"
"the ledger balance always equals the sum of its entries," "a coupon is
redeemed at most once per account." Then find *every* code path that
writes the field(s) the invariant depends on, and check whether each one
re-derives or re-checks the invariant, or simply trusts that whoever wrote
it last already did.

The common shape: the invariant is enforced in the primary, most-reviewed
write path (the normal purchase flow) and quietly assumed — not enforced —
in a secondary one (an admin override, a bulk import, a data-migration
script, a retry/replay handler). The secondary path is almost always the
one nobody tested against the invariant.

### 5. Trust-Boundary Confusion

The key question for source code specifically: **if I called this
function directly, with any value in this parameter, bypassing every
normal caller — would it still be safe?** A function that is safe only
because its one current caller happens to sanitize or validate first is a
bug waiting for a second caller: a route added later, an internal
RPC/queue consumer, a different framework entry point (REST vs. AJAX vs.
CLI) reaching the same shared function. Read the function on its own
terms, not through the lens of the caller you happened to start from.

```
# Looks safe read top-down from its one current caller...
def apply_discount(code, cart):
    return cart.total * discounts[code]   # unchecked dict access

# ...but is a bug the moment a second caller reaches it without the
# validate_discount_code() the first caller happened to run first
```

### 6. Logic-Level TOCTOU (Check-Then-Act)

Find check-then-act pairs on shared state — check balance then debit,
check seat availability then reserve, check "not yet redeemed" then
redeem — where the check and the act are not one atomic operation: not a
single SQL statement whose `WHERE` clause re-asserts the precondition, not
inside a transaction at the isolation level the invariant needs, not a
compare-and-swap. A `SELECT` followed later by an `UPDATE`/`INSERT` with no
lock or atomic condition in between is the shape to look for.

This section is *where* in the code logic a race matters; `race_conditions.md`
is *how* to actually fire one (HTTP/2 request multiplexing, last-byte
synchronization) — read that skill for the exploitation mechanics once
you've found a candidate here.

### QA Reading Protocol

Work from the entry-point map's flagged logic-bearing functions, not from
a cold read of the whole tree:

1. Pick a flagged function. State its assumption or invariant in one
   sentence — if you can't state it in one sentence, you don't understand
   it well enough yet to judge it.
2. Enumerate **every** caller and every path that reaches it — grep for
   the function name/route across the whole tree, not just the obvious
   controller. Include admin tools, cron/scheduled jobs, webhooks, queue
   consumers, and every framework entry point (REST/AJAX/CLI) that can
   reach it.
3. For each path, check whether it upholds the assumption before the
   function runs (or re-checks it after, for a downstream invariant).
4. Any path that doesn't is a candidate — label it with which technique
   (1-6 above) it matches, the specific file:line of the missing or weak
   check, and the specific file:line of the call site that reaches the
   function unguarded.

### Discipline

**This methodology generates hypotheses, not verdicts.** Every candidate
it produces still passes `counterevidence.md`'s full gate before it
becomes a report: a named, checked control at a specific location, on a
path you've confirmed is actually reachable — not "I read the function and
didn't see a check" (that's `open_proof_gap` until you've read every
caller, not `confirmed`). Where a live target exists, the dynamic
Validation section below still applies — a static trace is a lead, a
working PoC against a running system is proof. Quality up means more real
logic bugs found *and* fewer false positives, never more noise: a
business-logic bug reported to a CNA that turns out to have a guard you
simply didn't read burns reputation exactly the way a bad SQLi report
does.

## Testing Methodology

1. **Enumerate state machine** - Per critical workflow (states, transitions, pre/post-conditions); note invariants
2. **Build Actor × Action × Resource matrix** - Unauth, basic user, premium, staff/admin; identify actions per role
3. **Test transitions** - Step skipping, repetition, reordering, late mutation
4. **Introduce variance** - Time, concurrency, channel (mobile/web/API/GraphQL), content-types
5. **Validate persistence boundaries** - All services, queues, and jobs re-enforce invariants
6. **Provision two+ real accounts** - See `reconnaissance/account_provisioning.md`; test coupon/referral/loyalty/collusion patterns across them, not within one session

## Validation

1. Show an invariant violation (e.g., two refunds for one charge, negative inventory, exceeding quotas)
2. Provide side-by-side evidence for intended vs abused flows with the same principal
3. Demonstrate durability: the undesired state persists and is observable in authoritative sources (ledger, emails, admin views)
4. Quantify impact per action and at scale (unit loss × feasible repetitions)

## False Positives

- Promotional behavior explicitly allowed by policy (documented free trials, goodwill credits)
- Visual-only inconsistencies with no durable or exploitable state change
- Admin-only operations with proper audit and approvals

## Impact

- Direct financial loss (fraud, arbitrage, over-refunds, unpaid consumption)
- Regulatory/contractual violations (billing accuracy, consumer protection)
- Denial of inventory/services to legitimate users through resource exhaustion
- Privilege retention or unauthorized access to premium features

## Pro Tips

1. Start from invariants and ledgers, not UI—prove conservation of value breaks
2. Test with time and concurrency; many bugs only appear under pressure
3. Recompute totals server-side; never accept client math—flag when you observe otherwise
4. Treat idempotency and retries as first-class: verify key scope and persistence
5. Probe background workers and webhooks separately; they often skip auth and rule checks
6. Validate role/feature gates at the service that mutates state, not only at the edge
7. Explore end-of-period edges (month-end, trial end, DST) for rounding and window issues
8. Use minimal, auditable PoCs that demonstrate durable state change and exact loss
9. Chain with authorization tests (IDOR/Function-level access) to magnify impact
10. When in doubt, map the state machine; gaps appear where transitions lack server-side guards
11. Provision accounts before this pass, not during it — retrofitting a second account mid-scan wastes a hunting wave

## Summary

Business logic security is the enforcement of domain invariants under adversarial sequencing, timing, and inputs. If any step trusts the client or prior steps, expect abuse.
