---
name: weak-password-detection
description: Weak password detection, credential stuffing, and brute-force testing using common passwords, system-generated credentials, and HTTP fuzzing / NSE brute-force tooling
---

# Weak Password Detection / Credential Brute-Force

Weak or default credentials remain one of the most prevalent and high-impact vulnerabilities. This skill covers systematic detection of weak passwords through dictionary attacks, credential stuffing, system-generated password prediction, and brute-force tooling.

## Attack Surface

- Login portals (web, API, mobile, SSH, FTP, Telnet, RDP)
- Admin panels, dashboards, and management interfaces
- Default or hardcoded credentials in applications and devices
- Self-registration flows with weak password policies
- Password reset flows that generate predictable tokens or passwords
- API key and token authentication with weak secrets

## Reconnaissance

### Identify Authentication Endpoints

- Standard login forms: `/login`, `/signin`, `/auth`, `/authenticate`, `/api/login`
- Admin panels: `/admin`, `/administrator`, `/manage`, `/console`, `/cpanel`
- API auth: `/api/v1/token`, `/oauth/token`, `/api/auth`, `/graphql` (login mutations)
- Service ports: SSH (22), FTP (21), Telnet (23), SMB (445), RDP (3389), MySQL (3306), PostgreSQL (5432), Redis (6379), MongoDB (27017)
- Mobile app login endpoints and deep-link auth handlers

### Determine Authentication Mechanism

- Form-based (POST with username/password fields)
- Basic Authentication (Base64 `Authorization: Basic ...`)
- Bearer token / JWT (password grant flow)
- API key in header, query parameter, or body
- Multi-step authentication (username first, then password)
- CAPTCHA presence and type (reCAPTCHA, hCaptcha, image-based, math)
- Rate limiting indicators (429 responses, lockout messages, delays)

### Enumerate Valid Usernames

- Error message differentiation: "Invalid username" vs "Invalid password"
- Registration page username availability checks
- Password reset flow: response timing or message leakage
- Public profiles, API responses, or metadata exposing usernames
- Common patterns: `admin`, `administrator`, `root`, `user`, `test`, `guest`, `support`, `service`, `api`, `dev`, `ops`
- Email format derivation from company domain patterns

## Key Vulnerabilities

### Weak Password Policies

- No minimum length or complexity requirements
- Allowing common passwords: `password`, `123456`, `qwerty`, `admin`, `letmein`
- Not checking against breached password databases (Have I Been Pwned)
- Case-insensitive password storage
- No password history enforcement
- Excessively short maximum length (indicates plaintext or weak hashing)

### Default and Hardcoded Credentials

- Vendor defaults: `admin/admin`, `admin/password`, `root/root`, `guest/guest`
- Application frameworks: `django/admin`, `tomcat/tomcat`, `weblogic/weblogic`
- IoT devices, routers, cameras: manufacturer-specific defaults
- Database defaults: `postgres/postgres`, `sa/sa`, `root/(empty)`
- Cloud defaults: AWS instance metadata, Azure default service principals
- Hardcoded in source code, configuration files, or documentation

### Credential Stuffing

- Users reuse passwords across services
- Breached credential lists (COMB, Collection #1-5, etc.) enable mass account takeover
- No multi-factor authentication allows direct access with valid credentials
- Missing breach detection or forced password rotation after known leaks

### Predictable System-Generated Passwords

- Sequential or pattern-based: `Password1`, `Welcome2025!`, `CompanyName123`
- Time-based generation: passwords derived from registration timestamp
- Weak randomness: predictable PRNG seeds in password generators
- Reset tokens that double as temporary passwords with short expiration

### Brute-Force Vulnerabilities

- No rate limiting on login attempts
- Absent or ineffective account lockout (client-side only, easily bypassed)
- IP-based blocking without session/user correlation (rotate IPs via proxy)
- CAPTCHA bypassable or only triggered after excessive attempts
- Parallel login attempts not tracked (race conditions on attempt counters)
- Verbose error messages revealing valid usernames

## Advanced Techniques

### Targeted Password Lists

- Generate custom wordlists from:
  - Company name, product names, and domain components
  - Geographic location, industry terms
  - Season + year patterns: `Summer2025!`, `Winter2026@`
  - Keyboard walks and leet speak variations
  - Previously breached passwords for the target domain
- Scrape the target site to build a content-derived wordlist (e.g. a small custom Python crawler that harvests unique words)

### Credential Stuffing Workflows

- Use breach databases filtered by target domain or related domains
- Test email:password pairs where email matches target domain
- Test username:password pairs with common username derivations
- Validate successful logins without triggering MFA by checking session endpoints

### Multi-Step Authentication Bypass

- Username enumeration → password brute-force on second step
- Session fixation between steps: manipulate step identifiers
- Skip steps via direct URL access to later stages
- Response manipulation to bypass verification checks

### API and Mobile-Specific

- GraphQL login mutations: batch brute-force via array inputs
- Mobile APIs often lack rate limiting compared to web frontends
- JWT password grant flows: brute-force against `/token` endpoint
- OAuth2 password grant: test `grant_type=password` with weak credentials

### Service-Level Brute-Force

- HTTP login endpoints: `ffuf` or custom scripts (see Tooling)
- SSH/FTP/SMB/Telnet and other services: `nmap` NSE `*-brute` scripts, e.g. `nmap -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt target.com`
- Databases (MySQL, PostgreSQL, MongoDB, Redis): weak/default credentials via the matching NSE brute script (`mysql-brute`, `pgsql-brute`, `mongodb-brute`, `redis-brute`) or a custom client script
- Any protocol lacking a ready script: custom Python

## MFA / 2FA Bypass

This is the home of the `mfa` coverage family. Weak passwords plus missing or
bypassable MFA is a critical chain, and MFA is frequently enforced in only one
place. Work each angle; several double as `account_provisioning.md` entry points.

- **Enforcement gaps (test first — cheapest).** MFA on the web login but not on
  the API / mobile / `grant_type=password` token endpoint — hit `/token` or the
  mobile login directly. MFA never re-checked on sensitive actions (no step-up).
  MFA optional, and a session minted *before* enrollment stays valid.
- **Session issued before the second factor.** The login response already carries
  a usable cookie/JWT *before* the OTP step — try an authenticated endpoint with
  that token without ever submitting a code. This is the highest-yield MFA bug.
- **OTP brute / weak keyspace.** A 4–6 digit code with no throttle **on the verify
  endpoint** (not just login) is brute-forceable (10^4–10^6). Confirm where the
  throttle actually sits (see Rate-Limit section). GraphQL/array batching tests
  many codes per request, side-stepping per-request limits.
- **Response manipulation.** The verify decision reflected in a client-visible
  status/body a proxy can flip (`{"mfaRequired":true}`→false, 403→200).
- **Backup / recovery codes.** Predictable, unthrottled, or not invalidated after
  use; the email/SMS recovery flow weaker than the primary factor (a downgrade).
- **Remember-device / trust cookie.** A forgeable or guessable "trusted device"
  token that skips MFA, or one not bound to the user.
- **WebAuthn / passkey downgrade.** A passkey-capable login that still offers a
  weaker fallback (OTP/password) an attacker can force by selecting or omitting
  the factor, and the server accepts the downgrade.
- **Race on verify.** Parallel OTP submissions racing a non-atomic attempt counter
  (cross-link `race_conditions.md`).

**Validation:** a real authenticated session reached without a valid second
factor — per `analysis/counterevidence.md`, show a benign control that *should*
be blocked is blocked, while the bypass path succeeds. A missing re-prompt alone,
with no session actually obtained, is not a finding.

## Rate-Limit and Timing-Bypass (systematic)

This is the home of the `rate_limit` family — a per-endpoint methodology, not a
footnote to brute-force. Its value is almost never standalone; it's what the
bypass *unlocks* (OTP brute → ATO, password spray, enumeration).

- **Classify the control first — "no rate limit" without this is a false
  negative.** Four distinct states: (1) **hard lockout** (account disabled after
  N), (2) **soft IP-throttle** (429 by source IP), (3) **CAPTCHA-injection**
  (challenge after N), (4) **silent shadow-throttle** (responses look normal but
  requests are dropped/delayed server-side). Establish a benign baseline
  success-rate *before* concluding anything — 50 requests with no 429 may be 50
  silently dropped.
- **Per-endpoint, not global.** A limit on `/login` rarely covers `/verify-otp`,
  `/reset`, `/api/v2/login`, the GraphQL login mutation, or the mobile endpoint.
  Enumerate each sensitive action separately from `query_attack_surface`.
- **IP-rotation header spoofing** against an IP-keyed throttle: `X-Forwarded-For`,
  `X-Real-IP`, `X-Client-IP`, `X-Originating-IP`, `CF-Connecting-IP`,
  `True-Client-IP`, `Forwarded` — rotate the value per request (cross-link
  `header_injection.md`). A changing value that resets the counter proves the
  limit keys on a spoofable header.
- **Counter-reset tricks.** Rotate username/casing, add padding params, vary path
  case (`/Login`), trailing dot host, or re-authenticate to reset a per-session
  counter.
- **Parallelism / race window.** Many limits check-then-increment non-atomically —
  a simultaneous burst all passes before the counter updates (cross-link
  `race_conditions.md`); HTTP/2 multiplexing / single-packet for the tightest
  window.
- **GraphQL / batch.** Array-batched credentials in one request bypass
  per-request counting.

**Closure discipline (counterevidence):** prove the bypass with a real negative
control — N requests blocked *without* the trick, N+ succeeding *with* it — never
"I sent many and none were blocked" (indistinguishable from shadow-throttling).
Report at the severity of what the bypass reaches, not the missing control alone.

## Tooling

### ffuf (primary for web logins)

- Login brute-force with multiple users and passwords:
  `ffuf -w users.txt:USER -w passwords.txt:PASS -u https://target.com/login -X POST -d "username=USER&password=PASS" -fr "Invalid"`
- JSON body / custom headers via `-H` and a JSON `-d` payload
- Filter by response size, status code, or regex to identify successes

### nmap NSE (service brute-force)

- `*-brute` scripts cover many non-HTTP services:
  `nmap -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt target.com`
- Available scripts include `ssh-brute`, `ftp-brute`, `smb-brute`, `telnet-brute`, `mysql-brute`, `pgsql-brute`, `mongodb-brute`, `redis-brute`, `http-brute`, `http-form-brute`.

### Custom Python Scripts

- Use `requests` with threading for high-speed API brute-force
- Implement jitter and proxy rotation to evade rate limiting
- Parse CSRF tokens dynamically between requests

### Wordlists

No password wordlists ship in the sandbox by default — download what you need into `/home/pentester/tools/wordlists` at runtime:
- Common passwords (e.g. `rockyou.txt`) from its upstream source
- SecLists `Passwords/` and `Passwords/Default-Credentials/` (vendor defaults) from https://github.com/danielmiessler/SecLists
- Custom lists from target-specific scraping
- Breach compilation subsets filtered by target relevance

## Validation

1. Confirm successful login with captured credentials (session token, cookie, or JWT)
2. Verify account access level: admin vs user privileges
3. Check if MFA is enforced post-login or can be bypassed
4. Test credential reuse across other endpoints or services
5. Document password policy weaknesses that allowed the breach
6. Verify if the same credentials work on staging, dev, or related domains

## False Positives

- Honey accounts or honeypot responses designed to mislead attackers
- Temporary lockouts that resolve quickly (distinguish from permanent bans)
- Different error messages that don't actually indicate valid username enumeration
- CAPTCHA or WAF blocking that appears as a failed login
- Rate limiting that returns 429 instead of 401 (adjust timing)

## Impact

- Complete account takeover for affected users
- Administrative access leading to full system compromise
- Lateral movement via reused credentials across services
- Data exfiltration, privilege escalation, and persistence
- Reputational damage and compliance violations (GDPR, PCI-DSS)

## Pro Tips

1. Always start with default credentials and vendor-specific lists before broad brute-force
2. Enumerate usernames first; password brute-force without valid users is inefficient
3. Use small, targeted wordlists before massive lists like rockyou.txt
4. Monitor for rate limiting and adapt delays; aggressive brute-force causes IP bans and alerts
5. Test for password spraying (one password, many users) before targeted brute-force
6. Check for concurrent session limits; successful logins may kick out legitimate users
7. GraphQL batching can test multiple credentials in a single request, bypassing per-request limits
8. Document the password policy and recommend minimum standards (length, complexity, breach checking)
9. For web logins prefer `ffuf`; for other services use `nmap` NSE `*-brute` scripts or custom scripts with equivalent logic
10. Combine with MFA testing: weak passwords plus missing MFA is a critical finding

## Summary

Weak password detection requires systematic enumeration of authentication surfaces, intelligent wordlist selection, and careful brute-force execution. The highest impact often comes from default credentials, password spraying, and credential stuffing rather than exhaustive brute-force. Always validate findings with confirmed logins and assess the full scope of account compromise.
