---
name: underserved_families
description: Concrete agent-driven methodology for families with no dedicated executor and no prior skill — LDAP injection, XPath injection, HTTP parameter pollution, WebSocket security (incl. CSWSH), and web cache poisoning/deception. Loaded by next_coverage_task for those families. No dedicated executor exists; these run through curl/proxy/agent_browser under analysis/family_assessment's 8-point frame.
---

# Underserved families (agent-driven, no dedicated executor)

These five families previously had no methodology in the skill tree. There is
**no dedicated executor** for them — they run agent-driven through `exec_command`
(curl), the proxy, and `agent_browser`, under `analysis/family_assessment`'s
8-point structure and `analysis/counterevidence.md`'s closure bar. Record the
exact tested boundary with `assess_coverage` and file scoped hypotheses; a
negative covers only the boundary tested. State-changing checks follow the
existing read-only/test-object policy.

## LDAP injection (`ldap_injection`)
- **Signal/applicability:** a parameter that plausibly reaches a directory
  lookup — login, user/group search, address book, "find user". Not every param;
  assess whether a directory backend is in play (error strings, LDAP filter
  syntax leaking, AD-backed login).
- **Prereqs:** a reachable search/auth input; a baseline response for a valid and
  an absent value.
- **Test branches:** filter-breaking metacharacters `*`, `(`, `)`, `|`, `&`,
  `\00`; an always-true filter (`*)(uid=*))(|(uid=*`) vs an always-false one;
  auth-bypass filters on login. Compare result-set size/behavior, not just status.
- **Evidence / false positives:** a boolean-differential (always-true returns
  more/all entries; always-false returns none) that a benign control does not
  reproduce. False positives: generic input validation errors, WAF 403s, apps
  that echo `*` literally. Reflection of metachars is not injection.
- **Blocked/unstable:** WAF/challenge → `blocked`; inconsistent result counts
  across repeats → re-baseline, else `inconclusive`.

## XPath injection (`xpath_injection`)
- **Signal/applicability:** a parameter reaching an XML document query (XML-backed
  search, config lookups, SOAP). Assess whether XML is the backend.
- **Prereqs:** a reachable input + valid/absent baselines.
- **Test branches:** `'`/`"` to break the expression; boolean `' or '1'='1` vs
  `' or '1'='2`; `count(/*)`-style blind-boolean extraction for structure.
  Compare true/false response differentials.
- **Evidence / false positives:** a true/false differential a benign control
  doesn't reproduce; XML parse errors naming XPath. False positives: generic 500s,
  reflected quotes. Distinguish from SQLi by backend evidence.
- **Blocked/unstable:** as above; XXE is a *separate* family (`xxe`).

## HTTP parameter pollution (`parameter_pollution`)
- **Signal/applicability:** any endpoint taking a parameter that might be parsed
  by two layers (proxy vs app, framework quirks). Assess duplicate-parameter
  handling.
- **Prereqs:** a parameter whose single-value behavior is baselined first.
- **Test branches:** send the parameter twice (`?x=a&x=b`), in query+body, and
  with array syntax (`x[]=`); observe which value wins and whether a
  WAF/authorization check reads a different occurrence than the sink (the classic
  bypass). Drive via curl/proxy so you control raw duplication.
- **Evidence / false positives:** a demonstrated divergence where a guard reads
  one occurrence and the sink another (e.g. authz check bypassed). Mere
  last-wins/first-wins with no security effect is **not** a finding.
- **Blocked/unstable:** proxy normalization collapsing duplicates → note the
  boundary; `inconclusive` if you cannot control raw duplication.

## WebSocket security (`websocket`, incl. CSWSH)
- **Signal/applicability:** a `ws://`/`wss://` upgrade or a WebSocket in the app's
  JS. Assess what the socket authorizes.
- **Prereqs:** the WS URL; a provisioned authenticated actor; the message schema.
- **Test branches:** (1) **CSWSH** — open the socket from a foreign origin and
  check whether the server honors the cookie session without an `Origin`/token
  check (an authorization boundary, like CSRF for WS); (2) message-level authz /
  injection — replay another actor's object ids over the socket;
  (3) missing TLS (`ws://`). Drive with `agent_browser` (`eval` a `new
  WebSocket(...)` from the page origin and from `about:blank`) and the proxy's
  WebSocket history.
- **Evidence / false positives:** CSWSH requires showing a cross-origin socket
  receiving the victim's authenticated data — a connection that then rejects
  unauthenticated frames is NOT CSWSH. Keep normal browser security on.
- **Blocked/unstable:** no browser/WS support reachable → `blocked`/`unsupported`,
  not negative.

## Web cache poisoning / deception (`cache_poisoning`)
- **Signal/applicability:** a CDN/cache in front (via `Age`, `X-Cache`,
  `CF-Cache-Status`, `Via`). Assess whether a response is cached and on what key.
- **Prereqs:** an endpoint whose response is cached; a benign unkeyed input to
  probe (headers like `X-Forwarded-Host`, `X-Forwarded-Scheme`), and — for
  deception — a path-confusion vector (`/account/foo.css`).
- **Test branches:** **poisoning** — send an unkeyed header that reflects into the
  response, then re-request WITHOUT it and check the poisoned value is served from
  cache (cross-user); **deception** — request a sensitive page with a static-like
  suffix/path and check the cache stores private content a later anonymous request
  retrieves. Drive via curl with a unique cache-buster so you never poison a key
  real users share.
- **Evidence / false positives:** a second, independent request retrieving the
  injected/private content from cache (`Age`/`X-Cache: HIT`). A reflected header
  that is NOT cached is not poisoning. **Test-impact constraint:** always use a
  unique cache-busting key so you do not poison a production cache entry real
  users hit — this is a hard scope/impact boundary.
- **Blocked/unstable:** no cache fronting → `not_applicable` only with the
  evidence (no cache headers on repeated probes); otherwise `inconclusive`.

Request smuggling (`request_smuggling`) is a *separate* family with its own skill
(`http_request_smuggling`) — cache poisoning via desync cross-links to it but is
assessed here on the cache axis.
