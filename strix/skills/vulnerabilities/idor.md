---
name: idor
description: IDOR/BOLA testing for object-level authorization failures and cross-account data access
---

# IDOR

Object-level authorization failures (BOLA/IDOR) lead to cross-account data exposure and unauthorized state changes across APIs, web, mobile, and microservices. Treat every object reference as untrusted until proven bound to the caller.

## Attack Surface

**Scope**
- Horizontal access: access another subject's objects of the same type
- Vertical access: access privileged objects/actions (admin-only, staff-only)
- Cross-tenant access: break isolation boundaries in multi-tenant systems
- Cross-service access: token or context accepted by the wrong service

This file's home axis is horizontal (object-level, BOLA) — a caller
reaching an object they should not. Systematic vertical-access depth
(actor×action matrix, per-role token sweep, framework-specific
enforcement gaps) lives in `broken_function_level_authorization.md`;
treat the vertical technique below as the object-reference variant of
that axis, not a substitute for it. Run both skills together whenever the
target has any privilege tiers at all.

The Enumeration Techniques below generate this class's candidate object
references; the three-way mutation set and diff-and-classify mechanics
that turn a swapped ID into a signal are shared with
`broken_function_level_authorization.md` and `mass_assignment.md`, in
`analysis/parameter_mutation_testing.md` — load it alongside this skill,
and see its Family Sweep section for grouping endpoints (including the
nested/second-order case below) before sweeping them individually. When
2+ accounts are provisioned (`account_provisioning.md`), that same file's
"Actor Replay (Differential Authorization)" section is the highest-signal
black-box BOLA technique available — read `owner_scope_verdict`, not
`signal_class`, when using it. `reconnaissance/trust_boundary_mapping.md`'s
Test Pairs, when built, name the specific same-role pairs worth trying
first instead of picking two accounts arbitrarily.

**Reference Locations**
- Paths, query params, JSON bodies, form-data, headers, cookies
- JWT claims, GraphQL arguments, WebSocket messages, gRPC messages

**Identifier Forms**
- Integers, UUID/ULID/CUID, Snowflake, slugs
- Composite keys (e.g., `{orgId}:{userId}`)
- Opaque tokens, base64/hex-encoded blobs

**Relationship References**
- parentId, ownerId, accountId, tenantId, organization, teamId, projectId, subscriptionId

**Expansion/Projection Knobs**
- `fields`, `include`, `expand`, `projection`, `with`, `select`, `populate`
- Often bypass authorization in resolvers or serializers

## High-Value Targets

- Exports/backups/reporting endpoints (CSV/PDF/ZIP)
- Messaging/mailbox/notifications, audit logs, activity feeds
- Billing: invoices, payment methods, transactions, credits
- Healthcare/education records, HR documents, PII/PHI/PCI
- Admin/staff tools, impersonation/session management
- File/object storage keys (S3/GCS signed URLs, share links)
- Background jobs: import/export job IDs, task results
- Multi-tenant resources: organizations, workspaces, projects

## Reconnaissance

**Parameter Analysis**
- Pagination/cursors: `page[offset]`, `page[limit]`, `cursor`, `nextPageToken` (often reveal or accept cross-tenant/state)
- Directory/list endpoints as seeders: search/list/suggest/export often leak object IDs for secondary exploitation
- Find undocumented params with `arjun -u <url>` (GET) or `arjun -u <url> -m POST` —
  surfaces hidden filters like `?include_deleted=1`, `?as_user=…`, `?owner_id=…`
  that frequently widen the IDOR surface.

**Enumeration Techniques**
- Alternate types: `{"id":123}` vs `{"id":"123"}`, arrays vs scalars, objects vs scalars
- Edge values: null/empty/0/-1/MAX_INT, scientific notation, overflows
- Duplicate keys/parameter pollution: `id=1&id=2`, JSON duplicate keys `{"id":1,"id":2}` (parser precedence)
- Case/aliasing: userId vs userid vs USER_ID; alt names like resourceId, targetId, account
- Path traversal-like in virtual file systems: `/files/user_123/../../user_456/report.csv`

**UUID/Opaque ID Sources**
- Logs, exports, JS bundles, analytics endpoints, emails, public activity
- Time-based IDs (UUIDv1, ULID) may be guessable within a window

## Key Vulnerabilities

### Horizontal & Vertical Access

- Swap object IDs between principals using the same token to probe horizontal access
- Repeat with lower-privilege tokens to probe vertical access
- Target partial updates (PATCH, JSON Patch/JSON Merge Patch) for silent unauthorized modifications

### Bulk & Batch Operations

- Batch endpoints (bulk update/delete) often validate only the first element; include cross-tenant IDs mid-array
- CSV/JSON imports referencing foreign object IDs (ownerId, orgId) may bypass create-time checks

### Secondary IDOR

- Use list/search endpoints, notifications, emails, webhooks, and client logs to collect valid IDs
- Fetch or mutate those objects directly
- Pagination/cursor manipulation to skip filters and pull other users' pages

### Alternate API Versions and Channels

The same object is frequently reachable through more than one route — a
legacy endpoint kept for backward compatibility, a mobile-specific API
surfaced only in app-bundle traffic, an internal/partner API fronting the
same data store — and object-level authorization is re-implemented (or
skipped) independently on each one. This is BFLA's "legacy vs v2, mobile
vs web" pattern applied to the object dimension rather than the action
dimension: the object binding check itself, not just the action gate, can
differ per route.

- Diff the same object fetch across every version/channel discovered in
  recon (`/api/v1/orders/{id}` vs `/api/v2/orders/{id}`, web API vs the
  endpoints a mobile app bundle or network capture reveals) using an ID
  the caller does not own
- Weaker versions are usually the older ones, but not always — a newer
  mobile-first API rushed to ship can skip a check the mature web API has
  had for years
- Treat each version/channel as its own candidate in the Subject × Object
  × Action matrix, not a rerun of the same test

### Nested and Second-Order Object References

Authorization checked on a parent object does not imply it was re-checked
on a child reached by walking a relationship from that parent — the
classic shape is a caller who is legitimately allowed to fetch object A
(their own), where A contains a reference to object B (`A.attachmentId`,
`A.commentId`, `A.linkedInvoiceId`), and the endpoint that resolves B from
that reference trusts "the caller could read A" as sufficient proof they
can read B, without independently checking B's own ownership.

- Look for endpoints shaped like `GET /orders/{orderId}/items/{itemId}`,
  `GET /projects/{projectId}/files/{fileId}`, or any nested-resource route
  — then swap only the *child* ID while keeping a parent ID the caller
  legitimately owns; a check that only validates the parent leaves the
  child unbound
- Also test the reverse: swap the *parent* ID to one the caller doesn't
  own while keeping a child ID they do — reveals whether the binding runs
  in the direction the developer assumed
- Multi-hop references (A references B references C) compound this —
  don't stop validating at the first hop once one level checks out

### Job/Task Objects

- Access job/task IDs from one user to retrieve results for another (`export/{jobId}/download`, `reports/{taskId}`)
- Cancel/approve someone else's jobs by referencing their task IDs

### File/Object Storage

- Direct object paths or weakly scoped signed URLs
- Attempt key prefix changes, content-disposition tricks, or stale signatures reused across tenants
- Replace share tokens with tokens from other tenants; try case/URL-encoding variations

### GraphQL

- Enforce resolver-level checks: do not rely on a top-level gate
- Verify field and edge resolvers bind the resource to the caller on every hop
- Abuse batching/aliases to retrieve multiple users' nodes in one request
- Global node patterns (Relay): decode base64 IDs and swap raw IDs
- Overfetching via fragments on privileged types

```graphql
query IDOR {
  me { id }
  u1: user(id: "VXNlcjo0NTY=") { email billing { last4 } }
  u2: node(id: "VXNlcjo0NTc=") { ... on User { email } }
}
```

Mutations are the write-side of the same bug and get less scrutiny than
queries — a resolver that correctly scopes reads by caller identity often
forgets to re-scope the object argument a mutation writes to:

```graphql
mutation TransferOwnership {
  updateDocument(id: "RG9jdW1lbnQ6OTAx", input: { content: "pwned" }) {
    id
  }
}
```

Sent with a token that owns a *different* document — if `id` resolves
without checking it against `context.user`, this is write-capable BOLA,
not a read. Chase the same class through `delete*`, `update*`,
`transfer*`, `share*`, and `revoke*` mutations named in the schema.

### Microservices & Gateways

- Token confusion: token scoped for Service A accepted by Service B due to shared JWT verification but missing audience/claims checks
- Trust on headers: reverse proxies or API gateways injecting/trusting headers like `X-User-Id`, `X-Organization-Id`; try overriding or removing them
- Context loss: async consumers (queues, workers) re-process requests without re-checking authorization

### Multi-Tenant

Tenant isolation is cross-tenant IDOR at the account/organization level
rather than the individual-object level — the full systematic methodology
(tenant-ID enumeration, admin-confusion, signup collision, existence
leaks) is consolidated in `## Multi-Tenant / Tenant-Boundary Testing`
below; this entry marks it as a Key Vulnerabilities candidate the same as
every other row in this section.

### WebSocket

- Authorization per-subscription: ensure channel/topic names cannot be guessed (`user_{id}`, `org_{id}`)
- Subscribe/publish checks must run server-side, not only at handshake
- Try sending messages with target user IDs after subscribing to own channels

### gRPC

- Direct protobuf fields (`owner_id`, `tenant_id`) often bypass HTTP-layer middleware
- Validate references via grpcurl with tokens from different principals

### Integrations

- Webhooks/callbacks referencing foreign objects (e.g., `invoice_id`) processed without verifying ownership
- Third-party importers syncing data into wrong tenant due to missing tenant binding

## Multi-Tenant / Tenant-Boundary Testing

Cross-tenant access is BOLA at the organization/account level instead of
the individual-object level — the same checked-vs-used binding failure,
scoped one level up. This section is the consolidated methodology; the
pieces it draws together are the `### Multi-Tenant` entry above (per-object
tenant scoping), `business_logic.md`'s `### Multi-Tenant Isolation` and
`## Authenticated Multi-Account Abuse` (tenant-scoped counters/credits,
collusion patterns once you hold two real accounts), and
`coordination/root_agent.md`'s account-provisioning phase (obtaining the
two tenants this section needs before testing starts). Reference those for
their existing depth rather than re-deriving it here — this section adds
the patterns none of them cover yet.

**Proof discipline**: everything below needs two real tenants, the same
way `idor.md`'s core methodology needs two principals — a single-tenant
session can only observe a boundary claim, never disprove it. Provision
both before this pass (see `reconnaissance/account_provisioning.md`); a
same-tenant retest proves nothing.

### Tenant-ID Enumeration via Shared Infrastructure

- Resource IDs (order numbers, ticket IDs, invoice numbers) that increment
  across the *whole platform* rather than per-tenant leak the existence
  and approximate volume of other tenants purely from your own ID's
  position in the sequence — walk the ID space adjacent to your own
  tenant's objects and check what a shared-infrastructure ID actually
  scopes to
- This is a reconnaissance/existence-leak finding on its own
  (`information_disclosure.md`-adjacent) even before any single object is
  successfully read — record it as a lead and continue toward object
  access, don't stop at "IDs are sequential"

### Tenant-Admin vs Global-Admin Confusion

- Many multi-tenant apps have two distinct admin roles: a tenant-scoped
  admin (manages their own org) and a platform/global admin (manages every
  tenant) — test whether a tenant-admin token can reach global-admin
  endpoints, or whether an endpoint gated only by "is this caller *an*
  admin" (any tenant) rather than "is this caller *this tenant's* admin"
  grants unintended cross-tenant reach
- This is the tenant-scoped instance of BFLA's Actor × Action matrix — run
  it as its own row, not folded into the object-access tests above, since
  the bug is in the role check rather than the object binding

### Self-Service Signup Tenant Collision

- Where tenant creation is self-service (sign up, get a new org), test
  whether choosing an identifier (org slug, subdomain, company name/domain
  used for auto-join) that collides with or is a variant of an existing
  tenant's identifier grants any unintended association — auto-join-by-email-domain
  features are the highest-value target here: register a new tenant using
  an email domain that an existing customer's employees use, and check
  whether the new signup is offered to join, or silently joined to, the
  existing tenant
- Also test near-miss collisions deliberately (trailing whitespace,
  case variation, homoglyph/Unicode lookalikes, a slug that normalizes to
  an existing one) against whatever uniqueness check the signup flow
  actually performs

### Cross-Tenant Search / Autocomplete Existence Leaks

- Typeahead, autocomplete, and search-suggest endpoints are frequently
  implemented against a shared index and filtered late (or not at all) —
  query for a string you know belongs to another tenant's data (a
  guessed/leaked customer name, email domain, project name) and check
  whether suggestions surface it, even if the full record is correctly
  blocked on direct fetch
- This mirrors `idor.md`'s general "list/search endpoints are rich ID
  seeders" principle (see Pro Tips), applied specifically across the
  tenant boundary rather than within one tenant's own object space —
  existence confirmation alone is a real finding (scored per
  `analysis/severity_calibration.md`'s tenant-boundary guidance) even
  before any content is retrieved

## Bypass Techniques

**Parser & Transport**
- Content-type switching: `application/json` ↔ `application/x-www-form-urlencoded` ↔ `multipart/form-data`
- Method tunneling: `X-HTTP-Method-Override`, `_method=PATCH`; or using GET on endpoints incorrectly accepting state changes
- JSON duplicate keys/array injection to bypass naive validators

**Parameter Pollution**
- Duplicate parameters in query/body to influence server-side precedence (`id=123&id=456`); try both orderings
- Mix case/alias param names so gateway and backend disagree (userId vs userid)

**Cache & Gateway**
- CDN/proxy key confusion: responses keyed without Authorization or tenant headers expose cached objects to other users
- Manipulate Vary and Accept headers
- Redirect chains and 304/206 behaviors can leak content across tenants

**Race Windows**
- Time-of-check vs time-of-use: change the referenced ID between validation and execution using parallel requests

**Blind Channels**
- Use differential responses (status, size, ETag, timing) to detect existence
- Error shape often differs for owned vs foreign objects
- HEAD/OPTIONS, conditional requests (`If-None-Match`/`If-Modified-Since`) can confirm existence without full content

## Chaining Attacks

- IDOR + CSRF: force victims to trigger unauthorized changes on objects you discovered
- IDOR + Stored XSS: pivot into other users' sessions through data you gained access to
- IDOR + SSRF: exfiltrate internal IDs, then access their corresponding resources
- IDOR + Race: bypass spot checks with simultaneous requests

## Testing Methodology

1. **Build matrix** - Subject × Object × Action matrix (who can do what to which resource)
2. **Obtain principals** - At least two: owner and non-owner (plus admin/staff if applicable); two distinct tenants if `## Multi-Tenant / Tenant-Boundary Testing` applies
3. **Collect IDs** - Capture at least one valid object ID per principal from list/search/export endpoints
4. **Cross-channel testing** - Exercise every action (R/W/D/Export) while swapping IDs, tokens, tenants
5. **Transport variation** - Test across web, mobile, API, GraphQL, WebSocket, gRPC
6. **Consistency check** - Same rule must hold regardless of transport, content-type, serialization, or gateway

## Validation

1. Demonstrate access to an object not owned by the caller (content or metadata)
2. Show the same request fails with appropriately enforced authorization when corrected
3. Prove cross-channel consistency: same unauthorized access via at least two transports (e.g., REST and GraphQL)
4. Document tenant boundary violations (if applicable)
5. Provide reproducible steps and evidence (requests/responses for owner vs non-owner)

## Impact Escalation

A status-code or existence diff confirms the oracle, not the finding. Push
every `confirmed` finding to actual cross-user data before filing:

- Retrieve and show real content from another principal's object (not just
  a 200 vs 403, or a size/title diff).
- For write-capable IDOR, demonstrate the state change taking effect
  (before/after read of the modified object).

If the object genuinely has no readable sensitive content, or extraction
needs a session/scope you don't hold, record `open_proof_gap` /
`needs_follow_up` with the blocker named — don't file on the oracle alone.

## False Positives

- Public/anonymous resources by design
- Soft-privatized data where content is already public
- Idempotent metadata lookups that do not reveal sensitive content
- Correct row-level checks enforced across all channels
- Empty array / null returned for another user's resource — silent enforcement, not exposure; compare against the owner's view to confirm the data is actually missing rather than just hidden from the response shape

## Impact

- Cross-account data exposure (PII/PHI/PCI)
- Unauthorized state changes (transfers, role changes, cancellations)
- Cross-tenant data leaks violating contractual and regulatory boundaries
- Regulatory risk (GDPR/HIPAA/PCI), fraud, reputational damage

## Pro Tips

1. Always test list/search/export endpoints first; they are rich ID seeders
2. Build a reusable ID corpus from logs, notifications, emails, and client bundles
3. Toggle content-types and transports; authorization middleware often differs per stack
4. In GraphQL, validate at resolver boundaries; never trust parent auth to cover children
5. In multi-tenant apps, vary org headers, subdomains, and path params independently
6. Check batch/bulk operations and background job endpoints; they frequently skip per-item checks
7. Inspect gateways for header trust and cache key configuration
8. Treat UUIDs as untrusted; obtain them via OSINT/leaks and test binding
9. Use timing/size/ETag differentials for blind confirmation when content is masked
10. Prove impact with precise before/after diffs and role-separated evidence

## Summary

Authorization must bind subject, action, and specific object on every request, regardless of identifier opacity or transport. If the binding is missing anywhere, the system is vulnerable.
