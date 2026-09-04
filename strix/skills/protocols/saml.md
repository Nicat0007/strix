---
name: saml
description: SAML 2.0 SSO testing covering XML signature wrapping, assertion replay, recipient/audience confusion, IdP-initiated flow abuse, and XXE in SAML parsing — the enterprise B2B SSO protocol OAuth/OIDC coverage does not reach
---

# SAML 2.0

SAML is the SSO protocol behind most enterprise B2B logins — it hands
control of a session to whichever party the Service Provider (SP) decides
to trust an XML assertion from. Every attack here targets the same gap:
the assertion the SP's XML signature validator *checked* is not always the
assertion the SP's business logic then *consumes*. Treat that
validated-vs-consumed mismatch as the central question for the whole
protocol, the same way `idor.md` treats a checked-vs-used object reference
as its central question.

Complements `protocols/oauth.md` — that skill covers OAuth 2.0/OIDC; this
one covers SAML 2.0 specifically, since real-world enterprise SSO
frequently means SAML, not OAuth, and the two protocols fail in different
ways. A target may run both (an OIDC bridge in front of a SAML IdP, or
vice versa) — test each independently.

## Attack Surface

**Flows**
- SP-initiated: SP redirects to IdP with an `AuthnRequest`, IdP posts back
  a `Response` containing one or more `Assertion` elements
- IdP-initiated: user starts at the IdP, which posts an unsolicited
  `Response` directly to the SP's Assertion Consumer Service (ACS) — no
  `AuthnRequest`/`InResponseTo` to bind against, a structurally weaker flow
- Single Logout (SLO), front-channel and back-channel

**Endpoints**
- SP: Assertion Consumer Service (ACS) URL, metadata endpoint
  (`/saml/metadata`), SLO endpoint
- IdP: SSO endpoint, SLO endpoint, metadata endpoint

**Message Types**
- `AuthnRequest` (SP → IdP), `Response`/`Assertion` (IdP → SP), `LogoutRequest`/`LogoutResponse`

**Bindings**
- HTTP-Redirect (URL-encoded, deflate-compressed), HTTP-POST (base64 in a
  form field), HTTP-Artifact (indirect, via a back-channel resolve)

## Reconnaissance

**Discovery**
```
GET /saml/metadata
GET /.well-known/saml-configuration   (nonstandard but seen)
```
Extract from SP/IdP metadata XML: `EntityID`, ACS `Location`/`Binding`,
`X509Certificate` (signing/encryption keys), `NameIDFormat`,
`SingleLogoutService` endpoints.

**Message Capture**
- Intercept the base64-encoded `SAMLResponse` form-POST parameter (HTTP-POST
  binding) or the deflate-compressed, URL-encoded `SAMLRequest`/`SAMLResponse`
  query parameter (HTTP-Redirect binding) — decode/inflate before editing,
  re-encode/deflate before replaying
- Identify which fields are inside the `<ds:Signature>` (protected) versus
  outside it (freely attacker-modifiable) by reading the signature's
  `<ds:Reference URI="...">` — this tells you exactly what any tampering
  attempt must route around

## Key Vulnerabilities

### XML Signature Wrapping (XSW) — the classic

The signature validator and the business logic that reads assertion
content are frequently two different code paths that don't agree on
*which* element in the document is "the" assertion. XSW exploits that
disagreement: keep a legitimately-signed assertion in the document (so
signature validation passes), but restructure the XML so the SP's
business logic reads a different, attacker-modified assertion instead.

```
Vulnerable — the signature reference and the consumed element diverge:

<samlp:Response>
  <saml:Assertion ID="evil-forged" >          <!-- attacker-crafted, unsigned,
                                                    consumed by business logic -->
    <saml:Subject>...admin@victim.com...</saml:Subject>
  </saml:Assertion>
  <saml:Assertion ID="original-signed">        <!-- legitimately signed,
                                                    moved aside, ignored by
                                                    the parser's first-match -->
    <ds:Signature>
      <ds:Reference URI="#original-signed">...</ds:Reference>
    </ds:Signature>
    <saml:Subject>...real-user@victim.com...</saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

Concrete XSW variants to try, in order of how commonly a given parser is
vulnerable to each:
1. **Duplicate assertion, original moved to a sibling/wrapper position**
   (original XSW) — clone the signed assertion, insert the forged one
   before it as the first child the consumer's XPath/XML-DOM traversal
   would hit
2. **Signed assertion wrapped inside a new parent element** the consumer
   doesn't expect (e.g. an `Extensions` block or a cloned `Response`
   wrapper) — signature still validates against the original, but the
   consumer's simpler traversal picks up the forged sibling instead
3. **Comment injection inside `NameID`**: `<NameID>legit-admin<!-- -->@attacker.com</NameID>`
   — some XML parsers strip comments *before* the consumer reads the text
   content but *after* the signature was computed over the raw bytes (or
   vice versa), so the signed value and the parsed value differ; test both
   comment placement and whether the signature covers pre- or
   post-comment-stripped content
4. **Duplicate `Response`-level wrapping** — nest a second `Response`
   around the signed one and see which the consumer's top-level parse
   picks

The tell that this class is present: the signature is checked with a
generic "does *a* valid signature exist somewhere in this document,
referencing *some* element with a matching digest" check, rather than
"does the signature cover the exact element the business logic is about to
read." Confirm by submitting a wrapped assertion with a *different*
`NameID`/`Subject` than the signed original and observing whether the SP
authenticates you as the forged identity.

### Assertion Replay

- Capture a valid `SAMLResponse` and resubmit it later, or from a
  different session/browser
- Check whether the SP enforces `NotOnOrAfter`/`NotBefore` on
  `<Conditions>` and `<SubjectConfirmationData>` — a missing or generously
  padded window allows extended replay
- Check for one-time-use enforcement: does the SP track consumed
  assertion `ID`s (or `InResponseTo` values) and reject a repeat, or does
  it accept the same assertion indefinitely as long as the time window
  holds?
- SP-initiated flows should bind `InResponseTo` in the assertion to the
  `AuthnRequest` `ID` the SP itself issued — an assertion with no
  `InResponseTo` check accepted anyway is a replay/IdP-initiated-abuse
  signal (see below)

### Recipient / Audience / Destination Confusion

- `<SubjectConfirmationData Recipient="...">` should match the exact ACS
  URL the assertion was meant for — test whether an assertion issued for
  a *different* SP (a second tenant, a staging environment, a partner
  integration using the same IdP) is accepted by this SP; this is the
  SAML equivalent of OAuth's audience/client confusion in `oauth.md`
- `<Audience>` inside `<AudienceRestriction>` should match this SP's
  `EntityID` — probe whether the SP checks it at all, or checks it against
  a substring/prefix rather than an exact match
- `<samlp:Response Destination="...">` should match the literal endpoint
  URL the response was posted to — a mismatch here combined with a
  multi-tenant or multi-environment IdP (one IdP serving several SPs) is
  high-value: an assertion meant for tenant A's ACS URL, replayed against
  tenant B's ACS URL, crossing a tenant boundary the same way
  `idor.md`'s Multi-Tenant section describes for object references —
  except here the "object" is an entire authenticated identity

### IdP-Initiated Flow Abuse

- IdP-initiated responses have no corresponding `AuthnRequest`, so there's
  nothing for `InResponseTo` to bind against — an SP that accepts
  IdP-initiated SSO *must* rely entirely on `Recipient`/`Audience`/time-window
  checks, since the request-binding defense that SP-initiated flows get
  for free doesn't exist here
- Test whether an SP that only expects SP-initiated flow still accepts an
  unsolicited POST to its ACS URL — this is often true even when the SP's
  UI never generates that path, because the ACS endpoint itself doesn't
  distinguish the two
- If IdP-initiated is intentionally supported, this is exactly where
  replay and recipient-confusion checks matter most — retest both classes
  specifically against the IdP-initiated path, not just the SP-initiated
  one

### Unsigned Assertion Acceptance

- Strip the `<ds:Signature>` element entirely (or the signature covering
  the assertion specifically, in a response with multiple assertions) and
  submit — a misconfigured SP that only requires the outer `Response` to
  be signed, or that has signature validation disabled/optional by
  config, accepts a fully attacker-forged identity
- Check whether the SP enforces signing on the `Response`, the
  `Assertion`, or both — a signed `Response` wrapping an *unsigned*
  `Assertion` (or the reverse) is a common half-configured state; test
  each element's presence independently

### XXE in SAML XML Parsing

- SAML messages are XML; an SP or IdP parsing them with an XXE-vulnerable
  parser configuration is exploitable through the same `SAMLResponse`/`SAMLRequest`
  parameter used for everything else in this file — see `xxe.md` for the
  general technique and no-egress local-DTD-reuse approach
- Try both bindings: HTTP-POST (base64-decode, inject, re-encode) and
  HTTP-Redirect (inflate, inject, deflate, URL-encode) — a parser hardened
  against one delivery path is not necessarily hardened against the other
  if they're handled by different code

## Advanced Techniques

**Attribute/Role Injection**

- If the SP trusts SAML attribute statements for authorization (group
  membership, role, entitlement claims) rather than just identity, treat
  attribute values the same way `mass_assignment.md` treats unexpected
  body fields — inject or elevate a role/group attribute in a forged or
  wrapped assertion and check whether the SP applies it without
  re-validating against its own authoritative source

**Certificate/Key Confusion**

- If the SP trusts multiple signing certificates (key rollover periods,
  multiple configured IdPs), test whether an assertion signed by a
  *different but still-trusted* certificate — one meant for a different
  IdP or tenant in a multi-IdP setup — is accepted for an identity/tenant
  it wasn't meant to authenticate

**Encoding/Canonicalization Differentials**

- XML canonicalization (C14N) has known edge cases around whitespace,
  attribute ordering, and namespace declarations; a signature computed
  over one canonical form but validated after independent re-parsing can
  admit small structural changes that don't invalidate the signature but
  do change what a downstream XPath/DOM read returns — closely related to
  the comment-injection XSW variant above, generalize the same idea to
  other canonicalization edge cases if the library's C14N implementation
  is known to be weak

## Testing Methodology

1. **Capture and decode** a full valid SP-initiated login flow — both
   bindings if the SP supports more than one
2. **Map the signature reference** — identify exactly which element(s)
   `<ds:Reference URI>` covers, and what falls outside it
3. **XSW sweep** — try each wrapping variant above, checking whether the
   forged identity is accepted
4. **Replay** — resubmit the captured, unmodified response after a delay
   and from a different session
5. **Recipient/Audience swap** — if a second SP/tenant/environment sharing
   the IdP is in scope, test cross-acceptance directly; otherwise test
   with a deliberately wrong `Audience`/`Recipient` value in an
   otherwise-valid-signed message where the signature does *not* cover
   that field (confirm via the reference map from step 2 first)
6. **IdP-initiated probe** — POST a still-valid assertion directly to the
   ACS URL with no preceding `AuthnRequest`
7. **Strip signatures** — test unsigned `Response`, unsigned `Assertion`,
   and both, independently
8. **XXE probe** — inject an external entity per `xxe.md`'s technique into
   both binding paths

## Validation

1. Show the SP authenticates the session as an identity (`NameID`,
   attributes) that the *signed* portion of the assertion does not
   actually assert — for XSW, this means proving the forged `Subject`,
   not the signed one, drove the login
2. For replay, show a session established from a captured-and-resubmitted
   assertion, ideally after its original session ended
3. For recipient/audience confusion, show authentication into SP/tenant B
   using an assertion issued for SP/tenant A
4. For unsigned acceptance, show a fully attacker-controlled `NameID`
   accepted with no valid signature present
5. Provide the raw `SAMLResponse` (decoded) alongside the resulting
   authenticated session as before/after evidence — the XML diff between
   what was signed and what was consumed is the core of the proof for XSW
   specifically

## False Positives

- Signature validation confirmed to cover the exact element the business
  logic reads (checked by reference URI matching the consumed element's
  ID, and confirmed no sibling/duplicate election is possible) — this
  rules out XSW specifically; it does not rule out the other classes here,
  each needs its own check per `analysis/counterevidence.md`
- `NotOnOrAfter`/`NotBefore` enforced with a tight window, and consumed
  assertion IDs tracked and rejected on reuse
- `Recipient`/`Audience`/`Destination` validated against exact string
  match, itself covered by the signature reference (not attacker-editable
  without breaking the signature)
- IdP-initiated flow explicitly disabled at the SP (unsolicited POST to
  ACS correctly rejected) — or enabled but with recipient/replay checks
  independently confirmed
- Both `Response` and `Assertion` require and correctly validate a
  signature from a certificate the SP actually trusts for this tenant

## Impact

- Full authentication bypass / account takeover as any identity the
  attacker chooses to forge into the assertion — typically **the highest
  per-bug payout in the SSO category**, since a successful SAML break is
  usually a complete bypass of the org's federated login, not a
  single-account compromise
- Cross-tenant authentication in multi-tenant SaaS sharing one IdP —
  recipient/audience confusion turning into full tenant-boundary bypass
- Privilege escalation via attribute/role injection if authorization
  trusts SAML claims directly

## Pro Tips

1. Always map the signature reference *before* attempting any tampering —
   it tells you exactly which fields are free to edit and which aren't
2. XSW succeeds against parsers that validate "a signature exists and is
   valid somewhere" rather than "the signature covers the element I'm
   about to read" — that's the root cause behind nearly every variant here
3. Test IdP-initiated and SP-initiated as fully separate surfaces; a
   hardened SP-initiated flow says nothing about IdP-initiated handling
4. In a multi-tenant SaaS sharing one IdP across customers, recipient/audience
   confusion is the highest-value single test to run — it's the SAML
   analogue of `idor.md`'s cross-tenant access, at the identity layer
   instead of the object layer
5. Chain a forged/wrapped assertion's resulting session directly into
   `broken_function_level_authorization.md`/`business_logic.md` testing —
   an authentication bypass is worth far more paired with concrete
   post-auth impact than reported alone

## Summary

SAML security depends on the signature validator and the assertion
consumer agreeing, byte-for-byte, on which element was actually signed —
plus strict recipient, audience, and time-window enforcement on top of
that agreement. A gap in any one of those checks is usually a full
authentication bypass, not a partial one.
