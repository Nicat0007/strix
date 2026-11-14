---
name: xpath_injection
description: "XPath / XQuery injection — user input concatenated into an XPath query over an XML document or XML database, letting an attacker alter the query. Highest-value forms — authentication bypass via tautology, and blind char-by-char extraction of the ENTIRE document (XPath has no access control, so one injectable query can read every node). Common behind XML-backed login, config/catalog lookups, and legacy SOAP/XML apps."
---

# XPath / XQuery Injection

User input built into an XPath expression over XML without escaping. Like SQLi in
shape but with a critical twist: **XPath has no table/row access control** — a
single injectable query can traverse and extract the *whole* XML document, so
blind extraction is especially powerful.

## Attack Surface

- **Login / auth** backed by an XML user store (`//users/user[name/text()='X' and
  password/text()='Y']`) — the classic bypass target.
- Catalog/config/content lookups over XML, XML databases (eXist, BaseX),
  legacy **SOAP**/XML web services, and apps that store data in XML files.
- Any parameter that ends up inside an XPath/XQuery string.

## Key Vulnerabilities

### Authentication bypass (tautology)

If login does `//user[name='<u>' and password='<p>']`, inject to make it
always-true or comment out the password:

- username: `' or '1'='1` , `' or 1=1 or ''='` , `admin' or '1'='1`
- username: `' or ''='` , `x' or name()='user' or 'x'='y`
- to select the first user: `' or position()=1 or ''='`

Proof: an authenticated session without valid credentials (ideally as a specific,
real principal), not just a status/length change.

### Blind full-document extraction (char-by-char)

XPath exposes the entire document to an injectable query — extract it blindly via
a boolean oracle:

- Node count: `' or count(/*)=1 or ''='` → true/false response difference.
- String length: `' or string-length(//user[1]/password)=8 or ''='`.
- Char-by-char: `' or substring(//user[1]/password,1,1)='a' or ''='`, walk each
  position/char (the XPath analogue of blind SQLi — but reads ANY node).
- Structure discovery: `name(/*[1])`, `//*[1]/name()` to learn element names, then
  walk siblings/children to dump the tree.

### Error-based & out-of-band

- A malformed expression (`'`, `"`, `]`, `(`, `count(//*`) that triggers an XPath
  parser error confirms injection and often leaks the query/structure.
- XQuery on some engines allows functions (`doc()`, `fn:doc()`,
  `unparsed-text()`) → file read / SSRF — cross-link `xxe.md`/`ssrf.md` when the
  backend is a full XQuery processor.

## Testing Methodology (under `analysis/family_assessment.md`'s 8-point frame)

1. **Prerequisite:** a parameter that plausibly reaches an XPath/XML query (XML/
   SOAP backend, XML-store login/lookup) — reachable param is the signal.
2. **Break the expression:** send `'`, `"`, `]`, `) `, `count(//*`; an XPath/XQuery
   error or a result change confirms the input reaches the query.
3. **Auth bypass:** try the tautology payloads; prove a real session.
4. **Blind extraction:** build a boolean oracle (true vs false response diff), then
   walk `substring()`/`string-length()`/`count()` to dump nodes.
5. **Record** each probe; a WAF on quotes/`or` is `blocked`, never `ruled_out`
   (`waf_evasion.md` — try encodings, `&#39;`, XML entities, double-encoding).

## Validation

- Auth bypass: demonstrate a logged-in session (ideally as a named principal).
- Extraction: recover a specific real value (a password node, a config secret) via
  the boolean oracle — "the expression is manipulable" alone is `needs_validation`.
- Negative control: a benign same-shape value behaves normally while the payload
  changes results (`analysis/counterevidence.md`).

## False Positives

- Input is passed as a **parameterized** XPath variable (precompiled XPath with
  `$var` / `XPathExpression` variables) or properly entity-escaped → literal, not
  injectable.
- A generic `500` unrelated to query structure (confirm with the benign control).
- Reflected quotes in HTML (that's XSS, not XPath) — confirm an XPath parser error
  or a query-logic change, not mere reflection.

## Impact

Authentication bypass, and — because XPath ignores access control — disclosure of
the **entire** backing XML document (credentials, config, PII), plus file read/
SSRF where a full XQuery engine exposes `doc()`. Often high/critical.

## Summary

User input in an XPath/XQuery string → tautology bypass or boolean char-by-char
dump of the whole document (XPath has no row-level authz). Confirm the input
reaches the query (parser error/diff), then prove a session or a recovered value —
not just a manipulable expression. No dedicated executor; runs under
`family_assessment.md` with the proxy/`curl`.
