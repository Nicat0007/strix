---
name: disclosed_patterns
description: "Cross-class catalog of the specific, non-obvious attack MECHANISMS and bypass variants that actually paid out in real disclosed bug-bounty reports — the delta between 'ran the standard test, nothing' and a first-to-report finding. Organized by the highest-payout, lowest-duplication classes per 2024-2026 trend data (broken access control / IDOR incl. blind, business logic, multi-stage chains, SSRF incl. cloud, auth/SSO/token, LLM app). De-emphasizes XSS/SQLi (declining, heavily duplicated). Extends — does not replace — the deep per-class skills (idor.md, business_logic.md, ssrf.md, oauth.md, etc.); load it alongside them when the standard per-class test comes up empty and you need the variant that others missed."
---

# Disclosed-Report Attack Mechanisms (the variant catalog that beats duplicates)

Duplicates come from testing what everyone tests. This file is the opposite: the
specific variants that turned a "not vulnerable" into a paid report in real disclosures.
**Discipline is unchanged** — every entry is a *lead*, gated by `analysis/counterevidence.md`
(prove real impact, don't inflate), filed per its class skill, and run within program
rules (no DoS, no bulk data, no bruteforce/scanner where banned). Use this list when the
obvious test failed: the per-class skill tells you the class; this tells you the 10 ways
it still hides.

**Where to spend (per 2024-2026 payout/dup data):** Broken Access Control is #1
(~38% of valid reports, IDOR rewards rising); business logic and multi-stage chains pay
the most and dup the least; SSRF is now the top chain primitive; LLM prompt injection is
the fastest-growing class. XSS/SQLi are declining and heavily duplicated — test them, but
don't camp there. Steer budget to the sections below in roughly that order.

## 1. Broken Access Control / IDOR / BOLA — the #1 class (see `idor.md`, `broken_function_level_authorization.md`)
Standard swap failed? Try the variants that still work:
- **Blind IDOR** — no visible response, but the *action* happens: delete/cancel/email-change/
  transfer on another user's object returns 200/204 with no body. Confirm out-of-band
  (the victim object changed state) — this is massively under-tested because there's nothing
  to "see".
- **ID-source leaks** — the object id you "can't guess" is handed to you elsewhere: a UUID in
  a different endpoint's response, a sequential sibling, an email/username→id lookup, an
  autocomplete/search/export that leaks ids, a referral link, a websocket frame, a JS bundle.
  Sourcing the id *is* the exploit.
- **HTTP method / verb swap** — `GET` is locked but `POST`/`PUT`/`PATCH`/`DELETE` isn't (or
  vice versa); `X-HTTP-Method-Override: PUT`; HEAD bypassing a GET filter.
- **Content-type / body-shape swap** — endpoint checks authz on JSON but not on
  form-encoded / multipart / XML; wrap the id in an array `[id]`, an object `{"id":{"id":x}}`,
  or send it twice (parameter pollution) so the authz check reads one copy and the sink reads
  the other.
- **Nested / second-order reference** — authz checked on the parent (`/orgs/{mine}/...`) but
  the child id in the path/body points to another tenant's object; or an id stored now and
  dereferenced later by a job/export with no re-check.
- **Alternate channel / version** — `/api/v1` (legacy) weaker than `/api/v2`; the mobile/
  partner/GraphQL/gRPC endpoint skips the web app's authz; internal/admin host on an odd port
  (`service_enumeration.md`).
- **GraphQL mutation BOLA** — `updateX`/`transferOwnership`/`deleteX` with another id;
  introspection off ≠ safe (field suggestions, aliasing, batching).
- **Mass-assignment → authz** — the create/update body accepts `role`/`owner_id`/`tenant_id`/
  `is_admin` you weren't supposed to set (`mass_assignment.md`); bind it, then read back.
- **Cross-tenant via shared infra id** — incrementing global ids across tenants; tenant-admin
  vs global-admin confusion; signup email-domain auto-join collision.

## 2. Business logic — unscannable, lowest-dup (see `business_logic.md`)
- **Quantity/amount abuse** — negative quantity (credit instead of charge), decimal/fraction
  (`0.0001`, `1e-5`), integer overflow, leading zeros, extra precision, array of quantities.
- **Currency / rounding / FX** — pay in a weaker currency the server trusts client-side;
  rounding that always favors the buyer; refund in a different currency than charged.
- **Payment-step bypass** — client-trusted `amount`/`total`/`price` in the request; skip the
  capture step (order created `paid` before gateway confirms); manipulate the
  success-redirect/`status` param (`?status=success`); replay a valid payment callback;
  coupon applied after total computed.
- **Coupon / referral / loyalty** — stack single-use codes via race (`race_conditions.md`),
  self-referral, reset free-trial by re-signup/email alias, points/cashback replay.
- **Workflow / state-machine** — skip a step (go straight to the final endpoint), re-enter a
  completed/closed state, perform an action out of order (approve your own request, ship
  before pay), TOCTOU between check and act.
- **Limit / entitlement** — exceed a per-plan limit by racing or by hitting the raw API;
  access a paid feature by flipping a client-side flag the server trusts.
- **Cross-account collusion** — account A's action benefits account B (transfer, gift,
  team-invite escalation).

## 3. Multi-stage chains — the top payout (see `root_agent.md` attack graph + `counterevidence.md`)
The chains that repeatedly paid critical:
- **SSRF → cloud metadata → account takeover** (see §4) — SSRF to `169.254.169.254` → creds →
  cloud control plane.
- **Open redirect / lax `redirect_uri` → OAuth code/token theft → ATO** (`oauth.md`,
  `open_redirect.md`).
- **Subdomain takeover → cookie/OAuth `redirect_uri`/CSP bypass on the parent** (`subdomain_takeover.md`).
- **Info-leak (id/email/token) → IDOR / blind IDOR** consuming it (§1).
- **Self/low XSS → read CSRF token / call authed API → ATO** (`xss.md`, `csrf.md`).
- **File upload → stored XSS (SVG/HTML) or SSRF (SVG/XXE) → ATO or internal access**
  (`insecure_file_uploads.md`).
- **Prototype pollution → gadget → RCE (Node) / XSS (client) / auth bypass** (`prototype_pollution.md`).
- **Leaked JS secret / dev-flag → the API or credential it unlocks** (`asset_discovery.md` JS dive).
- **Weak identity primitive (auth bypass yielding only a userId) → write endpoint that trusts a
  client `userId` → read back another principal's data.**
Record each as an edge in the attack graph the moment a component is found; validate the
end-to-end PoC before elevating to combined severity.

## 4. SSRF — top chain primitive (see `ssrf.md`)
- **Parser-diff URL bypasses** — `http://attacker.com@internal/`, `http://internal#@attacker/`,
  `http://internal%2f@attacker`, `//internal`, embedded credentials, backslashes, mixed case,
  trailing dot, `http://127.0.0.1.attacker.com`.
- **IP encodings** — decimal (`2130706433`), octal (`0177.0.0.1`), hex (`0x7f000001`),
  IPv6 (`[::1]`, `[::ffff:127.0.0.1]`), short forms (`127.1`), `0.0.0.0`.
- **DNS rebinding** — a hostname that resolves public on first lookup, internal on the second
  (TOCTOU between validation and fetch).
- **Redirect-to-internal** — the allowlisted URL 302s to an internal target; follow-redirects on.
- **Protocol smuggling** — `gopher://` (to Redis/SMTP/HTTP), `dict://`, `file://`, `ftp://`.
- **Blind SSRF via OOB** — no response shown → use an interactsh/collaborator canary
  (`run_oob_test`); confirm the source IP is the target server, not your own egress.
- **Per-cloud metadata** — AWS IMDSv1 (`/latest/meta-data/iam/security-credentials/`), IMDSv2
  (needs the `X-aws-ec2-metadata-token` PUT — chain it if the SSRF allows header control),
  GCP (`metadata.google.internal` + `Metadata-Flavor: Google`), Azure
  (`/metadata/identity/oauth2/token` + `Metadata: true`), Alibaba/DO/Oracle equivalents.
- **Sinks that fetch for you** — URL preview/unfurl, webhook, PDF/thumbnail/image generator
  (SVG/HTML→PDF often reaches `file://`), XML (`xxe.md`), `img`/`avatar` by URL, import-from-URL,
  SSO metadata URL, OpenGraph scraper, RSS/feed reader, `url=` params.
- **Internal port pivot** — point SSRF at the odd ports in `host_ports.json` (`service_enumeration.md`).

## 5. Auth / SSO / token (see `oauth.md`, `saml.md`, `authentication_jwt.md`, `weak_password_detection.md`)
- **OAuth** — `redirect_uri` parser diffs (path traversal `/../`, open-redirect on an allowlisted
  host, subdomain/suffix match, `redirect_uri` not bound to client), missing/weak `state` (CSRF/
  fixation), `code` leak via Referer/`window.name`/log, code reuse, `response_type`/`response_mode`
  switch, PKCE downgrade, `prompt=none` iframe, account-link CSRF.
- **JWT** — `alg:none`, `RS256→HS256` key confusion (sign with the public key as HMAC secret),
  `kid` path traversal / SQLi, `jku`/`x5u` pointing at attacker JWKS (SSRF-adjacent), weak HMAC
  secret (crack), expired/`nbf` not checked, audience/issuer not validated, JWE `alg:dir`.
- **SAML** — XML signature wrapping (XSW) variants, unsigned-assertion acceptance, signature
  stripping, recipient/audience/destination confusion, assertion replay, `NameID` comment injection.
- **Password reset** — host-header poisoning redirecting the token link, token in Referer leak,
  predictable/short/non-expiring/reusable token, token for user A valid for user B, no rate limit
  on the *validation* side, reset without invalidating sessions.
- **Session / MFA** — session fixation, session not rotated on login/privilege change, email/
  password change with no re-auth → ATO, MFA bypass (response `success:false`→`true`, brute the
  OTP where no throttle, backup-code brute, "remember device" forgeable, skip the MFA step by
  going straight to the post-MFA endpoint).

## 6. LLM / AI app — fastest-growing (+540% prompt injection) (see `llm_prompt_injection.md`, `agentic_system_security.md`)
- **Direct & indirect prompt injection** — inject via user input, or via content the model
  ingests (a doc/web page/email/filename/support ticket the agent reads) → override instructions.
- **System-prompt / data extraction** — coax the system prompt, hidden tools, other users' data
  out of context/RAG.
- **Tool / function-call abuse** — make the agent call a privileged tool (shell, HTTP, DB, file)
  with attacker args → RCE/SSRF/IDOR through the agent; over-scoped tool permissions.
- **RAG / memory poisoning** — plant content that later steers the model for other users.
- **Output-handling** — model output rendered as HTML/markdown → stored XSS; output used in a
  SQL/command sink without validation.
- **Encoding/exfil** — ASCII-smuggling (invisible Unicode tag chars), markdown-image exfil of
  secrets to an attacker URL, multi-turn jailbreak.

## How to use this file
1. Load it alongside the per-class skill for whatever you're hunting (e.g. `idor` + this).
2. When the standard test is clean, walk the relevant section's variant list — one of them is
   usually the uncontested find.
3. Prioritize sections 1–3 (access control, logic, chains) for ranking impact; they pay most and
   dup least. Treat every hit as a lead → `counterevidence.md` → the class skill's reporting.
