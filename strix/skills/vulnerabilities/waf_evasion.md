---
name: waf_evasion
description: 403/406/429/WAF block handling — a block means you touched something defended, not that the bug is absent. Classify the block, then work an escalation ladder (encoding, syntax variants, request-shape, header/edge bypass, origin bypass) before ever closing a surface. A block is `blocked`, never `ruled_out`.
---

# WAF / 403 Evasion — Don't Stop at a Block

The single most common recall failure in automated black-box testing is reading
a WAF `403` (or `406`/`429`/`501`/a challenge page) as "not vulnerable" and
moving on. A block is a signal that you **touched something defended** — it is a
prompt to escalate, never proof the vulnerability is absent. Closing a surface
because the first payload was blocked throws away exactly the findings a WAF is
there to hide.

## First: classify the block (don't assume "WAF")

A wrong diagnosis wastes the whole ladder. Decide which of these you hit:

- **Edge WAF/CDN** vs **app-level 401/403** — check `Server`/headers
  (`cloudflare`, `akamai`, `X-Amz-Cf-Id`, `Sucuri`, F5 `BigIP`/`X-WA-Info`), the
  body (a branded block page + a ref/trace id), and timing. `wafw00f <url>`
  fingerprints the vendor. A branded block page = WAF; a plain app JSON/HTML
  error = authz.
- **Payload-triggered** vs **endpoint-wide** — send a *benign* request to the
  same endpoint. Benign passes, payload `403`s → the WAF is scoring the payload
  (work the ladder). Benign *also* `403`s → it's access control on the path, not
  a payload filter (see "Reaching a 403'd path" below).
- **`429`** = rate-limit, not a payload filter — slow down / rotate, see
  `weak_password_detection.md`'s Rate-Limit section, don't mutate the payload.
- **`406`/`400`/`501`** usually = parser/normalization rejection — very often
  bypassable by a request-shape transform (content-type, encoding).

## The escalation ladder (apply in order; record each rung)

Record progress with `record_endpoint_test(..., status="blocked")` /
`record_coverage` so the exact rung reached is visible, never a silent drop.
Binary-search the payload first to find the *single token* that trips the block —
you usually only need to disguise that one token.

1. **Encoding transforms.** URL-encode, **double**-encode, unicode / overlong
   UTF-8, HTML entities, mixed case, null byte, `CR`/`LF`/tab inside keywords.
2. **Syntax variants (per class — load the class skill).** SQL: inline comments
   `UN/**/ION`, `/**/`-for-space, `%0a`/`+`, concat, case toggle (see
   `sql_injection.md`). XSS: the full catalog in `xss.md`'s "Bypass Techniques".
   Command injection: `$IFS`, quotes, `\`, brace expansion (`rce.md`). Path:
   `....//`, `%2e%2e%2f`, UNC, over-long (`path_traversal_lfi_rfi.md`).
3. **Request-shape transforms.** Switch method (`GET`↔`POST`), content-type
   (`application/json` ↔ form ↔ `text/plain` ↔ `multipart`), parameter pollution
   (duplicate params, `x[]=` array syntax), **move the parameter**
   (query→body→header→cookie→JSON field), chunked transfer-encoding.
4. **Header / edge bypass.** `X-Forwarded-For` / `X-Real-IP` /
   `X-Originating-IP` / `CF-Connecting-IP` (spoof an allowlisted/origin IP),
   `X-Forwarded-Host`, `Referer`. For a *path* blocked at the edge:
   `X-Original-URL: /admin`, `X-Rewrite-URL`, a trailing `.`/`;`/`%2e`, or path
   case — these reach a 403'd path when the WAF and the app disagree on URL
   normalization.
5. **Origin bypass (the big one).** The WAF is usually only at the edge. Find the
   origin IP behind the CDN — historical DNS / `crt.sh`, SPF/MX records, an SSRF
   leak, Shodan/Censys on a response fingerprint — and hit it directly, skipping
   the WAF entirely. Cross-link `reconnaissance/asset_discovery.md` and
   `information_disclosure.md`.
6. **Fragment / timing.** Split the payload across multiple params so no single
   value scores as malicious; slow the request rate to stay under anomaly
   scoring; for request smuggling / desync against the WAF see
   `http_request_smuggling.md`.

## Reaching a 403'd path (access control, not a payload WAF)

When the whole path is `403`/`401` (verb-independent), it's authorization, and a
different toolkit applies — a `403` on `/admin` is a lead, not a dead end:

- **Path tricks:** `/admin/.`, `/admin/..;/`, `/admin%2f`, `//admin`, `/%2e/admin`,
  `/ADMIN`, trailing `/`, append `.json`/`;.css`/`?`.
- **Verb tampering:** `GET`→`POST`/`HEAD`/`OPTIONS`/`PUT`/`PATCH`,
  `X-HTTP-Method-Override: GET`, `X-Original-URL`/`X-Rewrite-URL` to the target.
- **Protocol/version:** HTTP/1.0 vs 2, case, trailing slash variants.
- Cross-link `broken_function_level_authorization.md` — a path reachable this way
  that shouldn't be is a BFLA finding, and the bypass is the PoC.

## Closure discipline (counterevidence)

- A block is `blocked`, **never** `ruled_out`. You may close a surface as
  not-vulnerable **only after** the ladder has failed **and** a benign negative
  control proves the endpoint itself is reachable (so you're seeing the payload
  class rejected, not the whole path being down or you being IP-banned).
- Record the exact rung reached and *why* it stopped — true block vs
  budget/stability/ban — so the gap surfaces in the report instead of reading as
  a clean "not vulnerable."
- A raw "WAF bypass" is not a finding by itself. The bypass is the means; the
  vulnerability it reaches (SQLi, the admin action, the data) is the finding —
  score and report *that*, per `analysis/severity_calibration.md`.

## Tooling

- `wafw00f <url>` — fingerprint the vendor (tunes which transforms work).
- The proxy (`repeat_request`) to mutate a single request by hand; `ffuf` to
  fuzz one parameter across a transform wordlist; `nuclei -tags waf` for known
  bypasses; `agent_browser` for JS-rendered challenge pages.
- The dedicated executors already follow this discipline: a blocked baseline is
  classified and a bounded continuation is recommended, never read as a negative
  (see `sqli_executor`/`run_sqli_test`).
