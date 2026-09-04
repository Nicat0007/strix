---
name: cors-misconfiguration
description: CORS misconfiguration testing — reflected-Origin-with-credentials, null-origin and regex/prefix/suffix bypasses, preflight and cache-poisoning flaws, with strict credentialed-exfiltration proof discipline
---

# CORS Misconfiguration

Cross-Origin Resource Sharing is a trust decision, not a header to echo back.
The server states, per response, which origins may read it from a browser —
and the moment `Access-Control-Allow-Origin` reflects an attacker-chosen
value alongside `Access-Control-Allow-Credentials: true`, that decision has
been handed to the attacker. Treat every reflected or wildcarded CORS
response the same way `idor.md` treats an unbound object reference: guilty
until a working credentialed cross-origin read proves otherwise.

This skill covers the CORS response layer specifically. `csrf.md`'s "CORS
Profile" recon step and `information_disclosure.md`'s "Cross-Origin
Signals" section both flag permissive CORS in passing — this file is the
full methodology behind that flag: how the bypass classes work, what
actually proves exploitability, and what does not.

## Attack Surface

- Every endpoint that returns `Access-Control-Allow-Origin` — API routes,
  auth/session endpoints, internal admin APIs occasionally exposed by a
  shared CORS middleware, static asset servers with overly broad rules
- Preflight (`OPTIONS`) responses, separate from the actual response — a
  server can get one right and the other wrong
- CDN/reverse-proxy layers that add or rewrite CORS headers independently
  of the origin service
- Any endpoint returning session-bound or authenticated data: profile,
  billing, admin dashboards, internal APIs, GraphQL over HTTP

## Reconnaissance

- For every endpoint, send `Origin: https://attacker-controlled.example`
  and record whether `Access-Control-Allow-Origin` reflects it verbatim,
  echoes `*`, or returns a fixed allowlisted value
- Check `Access-Control-Allow-Credentials` on the *same* response — this is
  the single bit that turns a permissive origin policy from noise into a
  finding
- Diff preflight (`OPTIONS` with `Access-Control-Request-Method`/`-Headers`)
  against the real response; a preflight can be strict while the actual
  `GET`/`POST` response is permissive, or vice versa
- Enumerate per-endpoint, not just per-app — CORS policy is frequently
  implemented per-route or per-blueprint (Express `cors()` middleware
  mounted on some routers, not all; Spring `@CrossOrigin` on individual
  controllers) and one hardened endpoint says nothing about its siblings
- Check whether the policy varies by method — an allowlisted `GET` and a
  reflected `POST` on the same resource is common when CORS is
  hand-rolled per verb

## Key Vulnerabilities

### Reflected-Origin-with-Credentials (the dangerous combo)

```
Request:
  GET /api/account HTTP/1.1
  Origin: https://attacker.example

Response:
  Access-Control-Allow-Origin: https://attacker.example
  Access-Control-Allow-Credentials: true
```

This is the finding. A page on `attacker.example` can now issue a
credentialed `fetch()`/`XMLHttpRequest` to the victim's cookie-authenticated
session and read the response in JavaScript — full cross-origin data theft,
not just a CSRF-shaped write. Note the spec constraint that makes this
combination the actual bug: `Access-Control-Allow-Origin: *` is **not
legal** alongside `Access-Control-Allow-Credentials: true` per the Fetch
spec, so a server exhibiting both is almost always doing origin
*reflection* (echoing the request's `Origin` header back), not a genuine
wildcard — confirm reflection by sending two different `Origin` values and
watching the response change to match each one.

### Null-Origin Bypass

- A sandboxed iframe (`<iframe sandbox="allow-scripts">`), a `data:` URI
  navigation, or a redirect chain through certain proxies sends
  `Origin: null`
- Some CORS implementations special-case `null` as an accepted value
  (present in an allowlist literally as the string `"null"`, or matched by
  a permissive regex that doesn't anchor), intending to support local file
  testing or specific legacy clients — but any page can generate a `null`
  Origin, so this is equivalent to allowing every origin
- Test explicitly: `Origin: null` is a distinct probe from `Origin:
  https://attacker.example`, not a fallback case — some servers accept one
  and correctly reject the other

### Regex / Prefix / Suffix Bypass Patterns

Hand-rolled origin validation is the most common root cause. Test each
pattern against the actual validator, not just against a wildcard guess:

- **Suffix match without anchoring**: `trusted-domain.com.evil.com` passes
  a check like `origin.endsWith("trusted-domain.com")` or an unanchored
  regex `trusted-domain\.com$` without a preceding `.` requirement
- **Prefix match**: `evil-trusted-domain.com` or
  `trustedomain.com.attacker.net` passes a check like
  `origin.startsWith("https://trusted")` or a regex missing a trailing
  boundary
- **Substring match**: `trusted-domain.com` anywhere in the string —
  `https://trusted-domain.com.attacker.com/`, or even
  `https://attacker.com/?trusted-domain.com`, passes a naive `includes()`
  check
- **Subdomain wildcard over-trust**: `*.trusted-domain.com` in the
  allowlist, then either register/find an attacker-controlled subdomain
  (dangling DNS, forgotten dev/staging host — cross-reference
  `subdomain_takeover.md` and `reconnaissance/infrastructure_lifecycle.md`
  for how to actually claim one) or find any subdomain with a client-side
  vulnerability (XSS, open redirect used to relay the credentialed
  response) that turns "in the allowlist" into "attacker-controlled"
- **Scheme/port confusion**: an allowlist entry matched without checking
  scheme (`http://trusted.com` accepted when only `https://trusted.com`
  was intended) or port (any port on the allowlisted host accepted)
- **Case sensitivity and encoding**: origin comparison that's
  case-sensitive where the browser normalizes case, or fails to reject
  unusual but browser-valid origin encodings

### Preflight Handling Flaws

- Preflight (`OPTIONS`) response allows a method or header the actual
  endpoint then acts on without re-validating the simple-request rules —
  e.g. preflight approves `Content-Type: application/json` cross-origin,
  letting an attacker skip the "simple request" content-type restriction
  that would otherwise limit CSRF-style delivery (see `csrf.md`'s Simple
  Content-Type CSRF for what this unlocks when combined with a
  state-changing endpoint)
- Preflight caching (`Access-Control-Max-Age`) set very long, combined with
  a policy that later tightens — a cached permissive preflight can outlive
  a server-side fix if the client doesn't re-preflight
- Preflight validates the origin but the real response handler is a
  different code path (different framework layer, different middleware
  order) that doesn't re-check — test preflight and the real request as
  two independent probes, never assume one implies the other

### CORS Response Cache Poisoning

- A CDN or reverse proxy caches a CORS response (including its
  `Access-Control-Allow-Origin` header) keyed without `Vary: Origin` — the
  first requester's reflected-origin response gets served to every
  subsequent visitor regardless of their own `Origin`, turning a
  same-origin-looking cached response into a cross-origin-readable one for
  whoever the cache serves next
- Confirm by requesting with a distinctive `Origin`, then re-requesting
  from a *different* simulated origin (or checking `Vary`) to see whether
  the cached, attacker-tagged response is replayed

## Where It Chains

- A reflected-Origin-with-credentials bug is the delivery mechanism that
  turns a passive information-disclosure finding into an active one:
  anything `information_disclosure.md` would otherwise log as "owner-only,
  not attacker-reachable" becomes attacker-reachable the moment CORS lets
  a hostile page read it in the victim's session — re-check disclosure
  candidates against any permissive CORS response found on the same
  endpoint
- CORS + IDOR/BOLA (`idor.md`): a horizontal-access endpoint that requires
  authentication to reach still leaks cross-account when CORS lets any
  origin issue that authenticated request and read the response — this is
  often a *faster* path to the same proof `idor.md` asks for (real
  cross-user content) since the victim's own session does the fetching
- CORS + business logic (`business_logic.md`): a permissive endpoint that
  returns pricing, quota, or account state lets an attacker page silently
  read a victim's session-scoped business data, not just PII
- CORS is not a CSRF defense and does not replace one — `csrf.md`'s
  Origin/Referer and token controls are the write-side mitigation; this
  skill is the read-side (data-theft) counterpart. A server can be
  correctly CSRF-hardened and still be CORS-vulnerable, and vice versa.

## Testing Methodology

1. **Enumerate endpoints returning any CORS header** — sweep recon's
   endpoint inventory (`/workspace/recon/`), not just the login/API-root
   endpoints
2. **Probe reflection** — send two or more distinct `Origin` values
   (`https://evil.example`, `https://<target>.evil.example`,
   `https://<target-suffix>attacker.com`, `null`) per endpoint; a value
   that changes the response is reflection, not a fixed allowlist
3. **Confirm the credentials flag** — record `Access-Control-Allow-Credentials`
   alongside every reflection result; without it, stop and see False
   Positives below before spending more time on that endpoint
4. **Test the regex/prefix/suffix patterns** above against the specific
   allowlist logic observed, not a generic payload list — infer the
   validator's shape from which of several crafted origins it accepts
5. **Diff preflight vs actual response** per endpoint and per method
6. **Check cache behavior** — repeat a request through any CDN/proxy layer
   with varying `Origin` and inspect `Vary`

## Validation

A permissive header alone is a **lead**, not a finding. Confirm only with
a working, reproducible credentialed cross-origin read:

1. Build a minimal PoC page (hosted on, or simulating, the bypassing
   origin) that issues a `fetch()`/`XHR` with `credentials: 'include'` to
   the target endpoint
2. Show the response body is readable in the PoC page's JavaScript context
   — actual data, not just a successful network request (a `no-cors`
   opaque response proves nothing; the read must be script-visible)
3. Use a real authenticated session (cookie-based) as the victim, not the
   attacker's own session, to prove this crosses the identity boundary
4. For the regex/prefix/suffix classes, use the exact bypass origin
   identified in reconnaissance — a generic `evil.com` failing does not
   rule out a suffix/prefix bypass that a crafted origin would pass
5. For the subdomain-wildcard class, either demonstrate actual control of
   the trusted subdomain (owned test host, or a confirmed takeover per
   `subdomain_takeover.md`) or record `open_proof_gap` naming the missing
   control if you cannot claim one — do not file on "the pattern would
   theoretically allow it"

## False Positives

- **`Access-Control-Allow-Origin: *` without `Access-Control-Allow-Credentials`**
  — this is usually intentional and safe: no cookies/HTTP-auth are sent
  cross-origin under the wildcard per the Fetch spec, so there is no
  session to steal. Confirm the endpoint genuinely returns no
  authenticated/session-bound data before ruling out, since a wildcard on
  an endpoint gated by a bearer token in a custom header (not a cookie)
  can still leak if the token is otherwise obtainable — but the wildcard
  itself is not the bug in that case.
- A fixed, correctly anchored allowlist (`origin === "https://app.example.com"`,
  or a properly anchored regex `^https://([a-z0-9-]+\.)?trusted-domain\.com$`)
  that rejects every crafted bypass origin tested
- Reflection present but `Access-Control-Allow-Credentials` absent or
  `false`, and the endpoint's data is not otherwise sensitive to
  unauthenticated readers (i.e. it would be equally exposed to a direct
  unauthenticated request)
- `Origin: null` correctly rejected while named origins are correctly
  validated
- CORS permissive on an endpoint that is *also* fully public/unauthenticated
  by design — no boundary is actually being crossed

## Impact

- Full cross-origin theft of session-authenticated API responses: PII,
  account data, tokens, internal identifiers
- Amplifies any information-disclosure candidate into an actively
  attacker-reachable one
- Chains into account takeover when the leaked response contains a
  session token, API key, or password-reset flow data
- Severity scales with data sensitivity and whether the affected endpoint
  is authenticated (per-user impact) or reveals cross-tenant data (systemic
  impact) — calibrate per `analysis/severity_calibration.md`

## Pro Tips

1. Always send at least two distinct `Origin` values before concluding
   reflection vs. a fixed allowlist — one probe cannot distinguish them
2. The credentials flag is the whole finding; a permissive origin policy
   without it is very rarely worth reporting on its own
3. Test per-endpoint and per-method — CORS middleware is often mounted
   inconsistently across a route tree
4. Infer the allowlist's exact matching logic from which crafted origins
   it accepts, then target that specific bypass class rather than
   spraying a generic payload list
5. A working PoC page with a real victim session is the bar — a curl
   response header is not proof of browser-exploitable data theft

## Summary

CORS is a per-response trust grant, not a default-safe header. The
dangerous state is reflected or under-anchored origin validation combined
with `Access-Control-Allow-Credentials: true` — everything else is either
a lead worth checking against that combination, or noise. File only once a
real credentialed cross-origin read is demonstrated.
