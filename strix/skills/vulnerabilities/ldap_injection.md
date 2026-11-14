---
name: ldap_injection
description: "LDAP injection — user input concatenated into an LDAP search filter (RFC 4515) or a DN, letting an attacker alter the filter logic. Highest-value forms — authentication bypass via filter tautology (e.g. a star-paren filter break), and blind attribute/value extraction by boolean/char-by-char filter manipulation. Common behind corporate login, address-book/people search, and group-membership checks."
---

# LDAP Injection

User input built into an LDAP **filter** or **DN** without escaping. Different
metacharacter set from SQL — `(`, `)`, `*`, `\`, `/`, `&`, `|`, `=`, NUL — and the
filter grammar (prefix/Polish notation: `(&(a=1)(b=2))`) is what you manipulate.

## Attack Surface

- Corporate/SSO/intranet **login** backed by LDAP/Active Directory (the classic
  auth-bypass target).
- **People / address-book / directory search** (`(cn=<input>*)`), group lookups,
  "is user X in group Y" checks, role resolution.
- Any field a directory service consumes: username, email, employee id, group
  name, OU/DN components.

## Key Vulnerabilities

### Authentication bypass (filter tautology)

If login builds `(&(uid=<user>)(userPassword=<pass>))` (or binds with a
filter-selected DN), injecting filter syntax can make it always-true or drop the
password clause:

- username `*)(uid=*))(|(uid=*` , `admin)(&)` , `*)(|(uid=*))`
- username `admin*`, `*`  (wildcards matching any entry)
- password `*` where the password clause isn't a bind

Proof: logging in without valid credentials, or as a different/first directory
entry. A 200/redirect difference alone is a lead — demonstrate an authenticated
session as a real principal.

### Blind data extraction (boolean / char-by-char)

Search filters rarely echo data, so extract it by yes/no filter manipulation:

- Presence: `(&(cn=admin)(objectClass=*))` vs a false variant — compare
  result-count / page difference.
- Char-by-char: `(&(uid=victim)(userPassword=a*))`, then `b*`, ... walking each
  character via the differential (the LDAP analogue of blind SQLi).
- Attribute discovery: toggle `(mail=*)`, `(memberOf=*)`, `(telephoneNumber=*)` to
  learn which attributes exist and are queryable.

### DN injection & scope/attribute abuse

Input placed into a DN (`uid=<input>,ou=users,dc=x`) or controlling the search
base/scope/returned-attributes can read entries or attributes outside intent
(e.g. pull `userPassword`/hashes if the bind account can read them).

## Testing Methodology (under `analysis/family_assessment.md`'s 8-point frame)

1. **Establish the prerequisite:** a parameter that plausibly reaches an LDAP/
   directory query (login, people search, group check) — a reachable param alone
   is the signal, backend unknown.
2. **Break the filter:** send a lone `(` , `)` , `*` , `\` , `&` , `|` and a
   malformed filter; an LDAP error, a `500`, or a result-count change confirms the
   input reaches a filter (vs generic input).
3. **Auth bypass:** on a login, try the tautology payloads above; prove a real
   authenticated session.
4. **Blind extraction:** build a boolean oracle (true vs false filter → stable
   response difference), then walk characters/attributes.
5. **Record** each probe with `record_coverage`; a block/WAF on the metacharacters
   is `blocked`, never `ruled_out` (`waf_evasion.md` — try encodings/`\28`/`\2a`).

## Validation

- Auth bypass: demonstrate a logged-in session as a real directory principal, not
  just a status/length diff.
- Extraction: recover a specific real attribute value (a user's `mail`, a group
  membership, a hash the bind can read) via the boolean oracle — a bare
  "filter is manipulable" is `needs_validation`, not the finding.
- Negative control: a benign same-shape value behaves normally while the filter
  payload changes results (per `analysis/counterevidence.md`).

## False Positives

- Input is passed as a **search value** through a properly parameterized/escaped
  API (`\28`/`\29`/`\2a` escaping, or the SDK's escape function) → metacharacters
  are literal, not a bug.
- A `500` from generic bad input unrelated to filter structure (confirm with the
  benign control).
- A WAF blocking `*`/`(` is a block to work, not proof of safety.

## Impact

Authentication bypass into corporate/AD-backed apps (often admin), disclosure of
directory data (users, emails, group membership, sometimes password hashes),
and enumeration of the internal org structure. Frequently high/critical because
the directory is the identity backbone.

## Summary

User input in an LDAP filter/DN with no escaping → tautology auth-bypass or
boolean char-by-char extraction. Confirm the input reaches a filter (metachar
error/diff), then prove a real session (bypass) or a recovered attribute value
(extraction) — not just a manipulable filter. No dedicated executor; runs under
`family_assessment.md` with the proxy/`curl`.
