---
name: websocket
description: "WebSocket security — Cross-Site WebSocket Hijacking (CSWSH — the headline bug — a WS handshake authenticated only by cookies with no Origin check and no CSRF token lets an attacker page open an authenticated socket for the victim), plus message-layer flaws (injection/IDOR/authz inside WS messages that skip the REST middleware), missing per-message authorization, and transport downgrade. The handshake is an HTTP request (testable in the proxy); the message stream is not — it needs a real WS client."
---

# WebSocket Security

Two layers, tested differently: the **handshake** (an HTTP `Upgrade` request —
capture and replay it like any request) and the **message stream** (frames after
`101 Switching Protocols` — needs a WS client, e.g. `wscat`, a python
`websockets` script, or `agent_browser`). Grounded in PortSwigger's CSWSH /
WebSocket research.

## Attack Surface

- Any `ws://`/`wss://` endpoint (find them in JS bundles: `new WebSocket(...)`,
  `/socket.io/`, `/ws`, `/cable` (Rails ActionCable), `/graphql` over WS,
  SignalR/`/hub`, `/livewire`, `/_next/webpack-hmr`).
- The handshake request (`GET` with `Upgrade: websocket`, `Sec-WebSocket-Key`,
  `Origin`, cookies) — capture it in the proxy.
- The message protocol (JSON/binary frames) — subscribe, command, RPC.

## Key Vulnerabilities

### Cross-Site WebSocket Hijacking (CSWSH) — the headline

The WS handshake is a normal cross-origin request. If it is authenticated **only
by cookies** (ambient auth), the server does **not** validate `Origin`, and there
is **no CSRF-style token** in the handshake, then an attacker's page can open an
authenticated socket as the victim and read/drive their data — WebSocket's
"CSRF with a two-way channel".

Test it:
1. Capture the handshake; note what authenticates it (cookie? a token in the URL/
   a sub-protocol/first message?).
2. Replay the handshake with the **`Origin` header changed** to an attacker origin
   (or removed). If it still returns `101` and a working authenticated session →
   no origin enforcement → CSWSH candidate.
3. **Prove it from a real cross-origin context**: an HTML PoC on a different
   origin that `new WebSocket("wss://target/...")`, relies on the browser sending
   the victim's cookies, and exfiltrates a received authenticated message. A
   handshake `101` alone is `needs_validation`; the cross-origin read is the proof
   (cross-link `csrf.md` for the delivery and `analysis/counterevidence.md`).

False positive: auth is **not** cookie-only (a token in the first message / URL
that an attacker can't forge) → `Origin` not being checked is lower impact; or
the server DOES check `Origin`/sends a CSRF token in the handshake.

### Message-layer flaws (the middleware-skip trap)

Frames often bypass the HTTP middleware stack (auth filters, input validation,
rate limits, WAF) that guards the REST API — so the same bugs reappear deeper:

- **Injection** — a field in a WS message reaching SQL/NoSQL/command/template
  sinks with none of the REST sanitization (load `sql_injection.md`/`xss.md`/etc.;
  a WS-delivered XSS that renders in another user's UI is stored XSS).
- **IDOR / BOLA** over WS — subscribe to / fetch another user's object id in a
  frame; authorization is frequently checked at connect but **not per message**
  (load `idor.md`).
- **Missing per-message authorization / command authz** — a privileged action
  (`{"action":"admin.deleteUser"}`) accepted on a low-priv socket (load
  `broken_function_level_authorization.md`).
- **Auth downgrade / no re-auth** — the socket stays authorized after the session
  should have expired; privilege changes not reflected on the live socket.

## Testing Methodology

1. **Discover** WS endpoints from JS bundles / the sitemap; capture a handshake.
2. **CSWSH**: replay the handshake with a foreign/removed `Origin`; if `101` +
   authenticated, build the cross-origin browser PoC to prove the read.
3. **Message testing** needs a client — `wscat -c wss://... -H "Cookie: ..."`, a
   python `websockets` snippet, or `agent_browser` to drive the app's own socket.
   Enumerate message types, then replay each vuln class per message (injection,
   IDOR per id, privileged action on a low-priv socket), with two actors for the
   authz classes (`reconnaissance/account_provisioning.md`).
4. **Per-message authz**: connect as a low-priv actor, send a high-priv action /
   another actor's object id; a success is the finding.

## Validation

- CSWSH: a working cross-origin PoC that reads/acts on the victim's data using
  only ambient cookies — not just a `101` with a changed Origin.
- Message authz/IDOR: real cross-user content or a state change, two actors, per
  `idor.md`'s Impact Escalation — not a status/echo diff.
- Injection over WS: the same proof bar as the HTTP class.

## Impact

Full session hijack / data read over a persistent channel (CSWSH), cross-user
data access and privileged actions that bypass the REST authz layer, stored XSS
delivered via sockets. High when it reaches authenticated or cross-user data.

## Tooling

- `wscat -c <url> -H "Cookie: ..."` / a python `websockets` client for frames.
- The proxy to capture + replay the **handshake** (Origin tampering).
- `agent_browser` to drive the app's own socket and for the cross-origin CSWSH
  PoC. No dedicated executor — this runs under `analysis/family_assessment.md`'s
  8-point frame; a WS block/limit is `blocked`, never `ruled_out` (`waf_evasion.md`).

## Summary

CSWSH (cookie-auth handshake + no Origin check + no token → cross-origin
authenticated socket) is the headline; the message stream is a second,
middleware-skipping attack surface where injection/IDOR/BFLA reappear per frame.
Prove CSWSH with a real cross-origin read, and message bugs with the same per-class
proof bar — a `101` or an echo is `needs_validation`, not a finding.
