---
name: broken-function-level-authorization
description: BFLA testing for action-level authorization failures across endpoints, admin functions, and API operations, including framework-specific authorization gaps and chaining methodology
---

# Broken Function Level Authorization (BFLA)

BFLA is action-level authorization failure: callers invoke functions (endpoints, mutations, admin tools) they are not entitled to. It appears when enforcement differs across transports, gateways, roles, or when services trust client hints. Bind subject × action at the service that performs the action.

This file's axis is which function a caller may invoke, regardless of
target object — the complementary axis, which specific object a call may
act on, is `idor.md`. A privileged action reached with the *wrong* object
ID (an admin action on someone else's resource) is both at once; see
"Chaining Attacks" below for that combination.

The verb/endpoint enumeration below generates this class's candidate
requests; the three-way mutation set and diff-and-classify mechanics that
turn a candidate into a signal are shared with `mass_assignment.md` and
`idor.md`, in `analysis/parameter_mutation_testing.md` — load it alongside
this skill for a systematic sweep instead of hand-rolling the
before/after comparison per endpoint.

## Attack Surface

- Vertical authz: privileged/admin/staff-only actions reachable by basic users
- Feature gates: toggles enforced at edge/UI, not at core services
- Transport drift: REST vs GraphQL vs gRPC vs WebSocket with inconsistent checks
- Gateway trust: backends trust X-User-Id/X-Role injected by proxies/edges
- Background workers/jobs performing actions without re-checking authz

## High-Value Actions

- Role/permission changes, impersonation/sudo, invite/accept into orgs
- Approve/void/refund/credit issuance, price/plan overrides
- Export/report generation, data deletion, account suspension/reactivation
- Feature flag toggles, quota/grant adjustments, license/seat changes
- Security settings: 2FA reset, email/phone verification overrides

## Reconnaissance

### Surface Enumeration

- Admin/staff consoles and APIs, support tools, internal-only endpoints exposed via gateway
- Hidden buttons and disabled UI paths (feature-flagged) mapped to still-live endpoints
- GraphQL schemas: mutations and admin-only fields/types; gRPC service descriptors (reflection)
- Mobile clients often reveal extra endpoints/roles in app bundles or network logs

### Signals

- 401/403 on UI but 200 via direct API call; differing status codes across transports
- Actions succeed via background jobs when direct call is denied
- Changing only headers (role/org) alters access without token change

### Systematic Verb and Endpoint Enumeration

For every endpoint recon already mapped (`/workspace/recon/` — see `reconnaissance/asset_discovery.md`), don't just replay it as found:

- Test every HTTP verb (`GET`/`POST`/`PUT`/`PATCH`/`DELETE`, plus `OPTIONS` to read the `Allow` header) against each endpoint with a low-privileged token — a route built for `GET` often shares a controller action with a `DELETE`/`PUT` handler that has a weaker or missing guard
- Take every admin/staff route surfaced by JS-bundle extraction or known-file discovery (recon's Application-Layer Recon phase) and replay it with a basic customer token, not just unauthenticated — most BFLA needs *a* valid session, just not a privileged one
- Diff what the UI exposes against what the API still serves: load the app as a low-priv user, note every button/menu item that's hidden or disabled, then call the corresponding endpoint directly — a hidden button is a recon lead, not a control
- Treat this as exhaustive coverage, not spot-checking: every actor × action cell in the matrix gets tried, not just the handful of admin actions that looked interesting

## Key Vulnerabilities

### Verb Drift and Aliases

- Alternate methods: GET performing state change; POST vs PUT vs PATCH differences; X-HTTP-Method-Override/_method
- Alternate endpoints performing the same action with weaker checks (legacy vs v2, mobile vs web)

### Edge vs Core Mismatch

- Edge blocks an action but core service RPC accepts it directly; call internal service via exposed API route or SSRF
- Gateway-injected identity headers override token claims; supply conflicting headers to test precedence

### Feature Flag Bypass

- Client-checked feature gates; call backend endpoints directly
- Admin-only mutations exposed but hidden in UI; invoke via GraphQL or gRPC tools

### Batch Job Paths

- Create export/import jobs where creation is allowed but finalize/approve lacks authz; finalize others' jobs
- Replay webhooks/background tasks endpoints that perform privileged actions without verifying caller

### Content-Type Paths

- JSON vs form vs multipart handlers using different middleware: send the action via the most permissive parser

## Advanced Techniques

### GraphQL

- Resolver-level checks per mutation/field; do not assume top-level auth covers nested mutations or admin fields
- Abuse aliases/batching to sneak privileged fields; persisted queries sometimes bypass auth transforms

```graphql
mutation Promote($id:ID!){
  a: updateUser(id:$id, role: ADMIN){ id role }
}
```

### gRPC

- Method-level auth via interceptors must enforce audience/roles; probe direct gRPC with tokens of lower role
- Reflection lists services/methods; call admin methods that the gateway hid

### WebSocket

- Handshake-only auth: ensure per-message authorization on privileged events (e.g., admin:impersonate)
- Try emitting privileged actions after joining standard channels

### Multi-Tenant

- Actions requiring tenant admin enforced only by header/subdomain; attempt cross-tenant admin actions by switching selectors with same token

### Microservices

- Internal RPCs trust upstream checks; reach them through exposed endpoints or SSRF; verify each service re-enforces authz

## Framework-Specific

Real BFLA bugs live in these stack-specific mistakes more often than in generic verb tricks — check the deployed framework first.

### Spring (Java)

- `@PreAuthorize`/`@Secured`/`@RolesAllowed` at the class level does not always propagate to every method — audit each controller action individually rather than assuming the class annotation covers all of them
- Method security requires `@EnableMethodSecurity`/`@EnableGlobalMethodSecurity` and a proxied bean; an internal same-class call (`this.method()` instead of through the interface/proxy) bypasses the check entirely — a 200 from an action that has a `@PreAuthorize` annotation directly above it is the field signal for this
- Any `@RequestMapping`/`@GetMapping`/`@PostMapping` method with no security annotation at all inherits nothing from siblings — grep every controller for actions missing an annotation, don't assume coverage
- `.antMatchers()`/`.requestMatchers()` security-filter-chain rules apply in declaration order; a broad early rule can shadow a narrower admin-only rule declared later

### Django / DRF (Python)

- `permission_classes` set at the ViewSet class level covers default actions, but a custom `@action(detail=..., methods=...)` method can silently omit its own `permission_classes` and fall back to a weaker default — check every custom action independently
- `get_queryset()` not scoped by `request.user` is BFLA-adjacent even when `permission_classes` looks correct: the permission class gates the endpoint, `get_queryset` gates which rows return — the two are independently forgettable
- Function-based views (`@api_view`) need an explicit `@permission_classes([...])` decorator; a missing one falls back to DRF's global `DEFAULT_PERMISSION_CLASSES` (which may be `AllowAny`) — grep for `@api_view` without a paired `@permission_classes`
- `has_permission()` (object-agnostic, runs on list/create) vs `has_object_permission()` (only runs when the view calls `check_object_permissions()`, which a custom `retrieve`/`update` override can skip) — the object-level check is the one that gets lost

### Rails

- `skip_before_action :authenticate_user!, only:/except:` is a common accidental-exposure source — grep every controller for it and confirm the skipped actions are actually meant to be public
- Pundit: a controller action missing `authorize @record` passes silently unless `after_action :verify_authorized` is set globally — test every action for enforcement rather than trusting the policy class exists
- CanCanCan: `load_and_authorize_resource` covers standard CRUD but custom member/collection routes need an explicit `authorize! :action, @record` — probe custom routes specifically
- Namespaced admin controllers (`Admin::UsersController`) relying on a shared `Admin::BaseController` `before_action` — a new admin controller copy-pasted from a non-admin one and not inheriting from the base silently loses the check

### Express / Node.js

- Middleware applied per-route (`router.get('/x', requireAdmin, handler)`) rather than per-router — a sibling route added later without copying the middleware call is unprotected; diff every route in a router file for the same middleware chain
- Middleware order matters: an auth-check registered after the route handler, or after a permissive `cors()`/static-file middleware that already responded, never runs
- Route-parameter overlap: a generic `router.get('/users/:id/settings', ...)` registered before a more specific guarded route can match first and swallow it depending on registration order

### GraphQL and gRPC Auth Libraries

- `graphql-shield`/`type-graphql` `@Authorized()`: decorators apply per-resolver, not per-field-return-type — a guarded query resolver can return an object whose nested field resolvers are unguarded, exposing the same data through a different query shape
- Apollo-style context-based auth (`context.user` checked in resolver body) is easy to add to some resolvers and forget on ones added later — diff resolver files for the presence of the check rather than assuming schema-wide middleware exists
- gRPC: auth interceptors are usually registered once for the whole server with per-method exemptions (health checks, reflection); a prefix-matched exemption list can accidentally include a real method — read the interceptor's allowlist/denylist logic itself when source is available

## Bypass Techniques

### Header Trust

- Supply X-User-Id/X-Role/X-Organization headers; remove or contradict token claims; observe which source wins

### Route Shadowing

- Legacy/alternate routes (e.g., /admin/v1 vs /v2/admin) that skip new middleware chains

### Idempotency and Retries

- Retry or replay finalize/approve endpoints that apply state without checking actor on each call

### Cache Key Confusion

- Cached authorization decisions at edge leading to cross-user reuse; test with Vary and session swaps

## Chaining Attacks

- BFLA + IDOR: reach an admin-only action, then supply another tenant's or user's object ID to act on their specific resource instead of your own
- BFLA + Mass Assignment: an under-guarded update endpoint accepts both the action and a `role`/`isAdmin` field in the same request — one bug delivers access and escalation together
- BFLA + Information Disclosure: an exposed admin/staff listing endpoint leaks other users' IDs, emails, or internal identifiers that seed further BFLA/IDOR targets
- BFLA + Business Logic: a reachable-but-unintended approval/finalize action lets you skip or reorder a workflow step that should require a privileged actor

## Testing Methodology

1. **Build Actor × Action matrix** - Unauth, basic, premium, staff/admin; enumerate actions per role
2. **Obtain tokens/sessions** - For each role
3. **Exercise every action** - Across all transports and encodings (JSON, form, multipart), including method overrides
4. **Vary headers and selectors** - Org/tenant/project; test behind gateway vs direct-to-service
5. **Include background flows** - Job creation/finalization, webhooks, queues; confirm re-validation
6. **Sweep verbs and framework holes** - Every verb per endpoint from recon's inventory; check the deployed framework's specific gaps (see Framework-Specific)

## Validation

1. Show a lower-privileged principal successfully invokes a restricted action (same inputs) while the proper role succeeds and another lower role fails
2. Provide evidence across at least two transports or encodings demonstrating inconsistent enforcement
3. Demonstrate that removing/altering client-side gates (buttons/flags) does not affect backend success
4. Include durable state change proof: before/after snapshots, audit logs, and authoritative sources

## Impact Escalation

A blocked-vs-allowed diff confirms the oracle, not the finding. Push every
`confirmed` finding to the action's actual effect before filing:

- Show the privileged action's real result (role changed, refund issued,
  record deleted/exported) with before/after evidence — not just "the
  request returned 200 for a lower-privileged token".
- Prefer the least destructive action that still proves full impact (a
  reversible role grant over an irreversible deletion) when several
  privileged actions are available.

If the action cannot be safely triggered in scope (destructive with no
reversible option, or genuinely out of authorization), record
`open_proof_gap` / `needs_follow_up` naming the constraint — don't file on
the access check alone.

## False Positives

- Read-only endpoints mislabeled as admin but publicly documented
- Feature toggles intentionally open to all roles for preview/beta with clear policy
- Simulated environments where admin endpoints are stubbed with no side effects
- An action with no explicit per-method annotation/decorator that is genuinely covered by a verified secure-by-default global config (DRF's `DEFAULT_PERMISSION_CLASSES` denying by default, a Rails base controller's inherited `before_action`, a Spring filter-chain rule matching the path) — confirm the default actually applies to this exact action before ruling it out

## Impact

- Privilege escalation to admin/staff actions
- Monetary/state impact: refunds/credits/approvals without authorization
- Tenant-wide configuration changes, impersonation, or data deletion
- Compliance and audit violations due to bypassed approval workflows

## Pro Tips

1. Start from the role matrix; test every action with basic vs admin tokens across REST/GraphQL/gRPC
2. Diff middleware stacks between routes; weak chains often exist on legacy or alternate encodings
3. Inspect gateways for identity header injection; never trust client-provided identity
4. Treat jobs/webhooks as first-class: finalize/approve must re-check the actor
5. Prefer minimal PoCs: one request that flips a privileged field or invokes an admin method with a basic token
6. When source is available, grep for the framework's specific gap pattern first (`skip_before_action`, `@action` without `permission_classes`, a controller method with no security annotation) — it's faster than blind verb fuzzing
7. Chain immediately once an admin action is reached: a bare access-control win is worth less than the same win paired with IDOR or mass assignment to show concrete cross-user impact

## Summary

Authorization must bind the actor to the specific action at the service boundary on every request and message. UI gates, gateways, or prior steps do not substitute for function-level checks.
