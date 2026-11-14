---
name: cache-poisoning
description: "Web cache poisoning and cache deception — an unkeyed input (a header the cache ignores when building the cache key, e.g. X-Forwarded-Host/-Scheme, or a path/query normalization quirk) influences a response that is then cached and served to OTHER (victim) requests. Two distinct bugs — poisoning (attacker stores a harmful response for a shared key) and deception (attacker tricks the cache into storing a victim's private/authenticated response at a cacheable path the attacker can then read)."
---

# Web Cache Poisoning & Cache Deception

Two related CDN/cache classes, both second-order and cross-user by construction —
the attacker's request and the victim's request are different, joined by the
cache. Grounded in James Kettle's "Practical Web Cache Poisoning" / "Web Cache
Entanglement" research and Omer Gil's Web Cache Deception.

## Attack Surface

- Any CDN / reverse proxy / caching layer in front of the origin (Cloudflare,
  Fastly, Akamai, Varnish, nginx proxy_cache, CloudFront). `X-Cache`, `Age`,
  `CF-Cache-Status`, `X-Served-By` headers are the tell.
- Pages that reflect request data into the response: an absolute URL/link built
  from `Host`/`X-Forwarded-Host`, a `<base href>`, a canonical link, a redirect,
  an analytics/config blob, a CSP/`report-uri`.
- Static-ish paths and "cache everything" rules (the deception target).

## Cache Poisoning — unkeyed input

1. **Find an unkeyed input that reflects.** The cache computes its key from
   (usually) method+host+path+query; headers like `X-Forwarded-Host`,
   `X-Forwarded-Scheme`/`-Proto`, `X-Host`, `X-Forwarded-Server`,
   `X-Original-URL`, `X-Rewrite-URL`, and sometimes a `Cookie`/`Accept-Encoding`
   are **not** in the key but still influence the response. Inject a unique inert
   marker in each and see which reflects (into the body or a response header).
2. **Prove it persists in the cache.** Send the poisoned request, then a CLEAN
   request (no injected header) for the same key — if the marker is still served,
   the poisoned response was cached and will be served to victims. This is the
   line between "reflected unkeyed input" (a lead) and "cache poisoning"
   (impact).
3. **Escalate to real impact.** A benign host echo is not a finding — the
   poisoned value must be dangerous: an attacker host in a `<script src>`/import
   (→ stored XSS for every victim, cross-link `xss.md`), a redirect
   (cross-link `open_redirect.md`), a `report-uri`/CSP, or a DoS (cache an error).

## Cache Deception — key confusion

Trick the cache into storing a victim's private/authenticated response under a
URL the attacker can then fetch unauthenticated:
- Append a cache-triggering suffix/segment to a sensitive authenticated path:
  `/account` → `/account/nonexistent.css`, `/account%0a.css`, `/account;.css`,
  `/account%2f%2e%2e%2fstatic` (path normalization differentials between the
  cache and the origin). If the origin serves the account page but the cache
  caches it as a static `.css`, the attacker loads that URL and reads the
  victim's data.
- Test the cache-vs-origin path-normalization gap explicitly (Kettle's 2024 WCD):
  different parsers for `..`, `;`, `%2e`, `%2f`, trailing extensions.

## Testing Methodology

> **Preferred path — `run_cache_poisoning_test`.** For a `cache_poisoning`
> hypothesis with a captured GET, call
> `run_cache_poisoning_test(hypothesis_id=..., request_ref=...)`. It injects each
> unkeyed header with a unique marker, checks reflection, then sends ONE clean
> request to test cache persistence, and reports the header + any cache
> indicators. A clean request served the marker is `needs_validation` (strong);
> reflection-without-persistence or none is `testing`, never `ruled_out`. Pass
> `extra_headers` for app-specific unkeyed inputs. It records the attempt on the
> worklist automatically. (The executor covers the poisoning path; cache
> *deception* path-confusion is driven by hand per the section above.)

1. Fingerprint the cache (indicator headers, `Cache-Control`, `Vary`).
2. Enumerate unkeyed inputs and find which reflect (the executor automates this).
3. Prove persistence with a clean request (the executor's phase 2).
4. For deception: enumerate path-normalization suffixes against an authenticated
   page and check whether the cache stores it.

## Validation

- A finding requires **cache persistence demonstrated** — a clean request (or a
  second client) served the attacker-influenced content — not merely that an
  unkeyed header reflected. A reflected-but-not-cached response is a lead
  (`testing`/`open_proof_gap`), not a finding (per `analysis/counterevidence.md`).
- Confirm the poisoned entry is keyed on something a real victim shares (path/
  query), not a cache-buster unique to your own request — otherwise you only
  poisoned your own view.
- For deception, demonstrate reading another user's authenticated content from
  the cached URL, with the two-actor discipline from `idor.md`.

## False Positives

- A unique per-request cache key (cache-buster) that means you only ever see your
  own response — not poisoning.
- `Vary: X-Forwarded-Host` (the input IS keyed) → reflection is not poisoning.
- `Cache-Control: no-store`/`private` with no actual caching layer → nothing to
  poison; confirm with the indicator headers.
- A benign reflected value with no script/redirect/sensitive effect.

## Impact

Poisoning: stored XSS / redirect / content-spoof / DoS served to **every** victim
hitting the poisoned key — one of the highest-blast-radius web classes. Deception:
mass disclosure of victims' authenticated/private responses. Both are cross-user.

## Summary

Unkeyed input reflects **and** the response is cached and served to a different
request. Prove both halves — reflection plus persistence — and that the value is
dangerous and the key is shared, before reporting. `run_cache_poisoning_test`
automates the poisoning two-step; deception path-confusion is manual.
