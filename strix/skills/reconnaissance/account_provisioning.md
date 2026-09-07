---
name: account-provisioning
description: Obtaining authenticated sessions before vuln-hunting — self-registration, OTP-bypass discovery, human-in-the-loop verification via the operator, multi-account provisioning for cross-tenant testing, and the operator-credential fallback when self-service is blocked
---

# Account Provisioning

IDOR, BFLA, business logic, and multi-tenant isolation are where the real value is, and every one of them requires a real authenticated session to test. A scan that can't obtain a token doesn't fail quietly on that surface — it skips the surface that mattered most. Run this skill after recon has mapped the target and before the vulnerability-hunting waves start, so hunters begin with tokens already in hand.

Work through the fallback tiers in order: automated self-registration and OTP-bypass first, then asking the operator directly for a verification code (Human-in-the-Loop Verification), then an operator-supplied credential file, and only then `needs_follow_up`. Each tier is cheaper and more autonomous than the next; don't skip ahead to a later one just because an earlier one takes a few more requests.

## Map the Auth Model First

Pull this from recon output (`/workspace/recon/`, JS-bundle extraction, `asset_discovery.md`'s auth-classified hosts) before attempting anything:

- **Registration flow**: signup endpoint, required fields, email/phone verification step
- **Login flow**: endpoint, credential format, MFA/2FA presence
- **OTP/verification**: SMS vs email vs TOTP vs magic link; where the code is submitted; whether attempts are rate-limited
- **Password reset**: flow shape — occasionally a secondary path to a token, always useful context
- **Self-service roles**: does signup let you pick a role/org type (vendor vs buyer, org-creator vs invited-member)? That's a free path to a role-differentiated account
- **Session mechanics**: cookie vs bearer JWT vs opaque session ID — determines how you capture and hand off the token afterward

## Self-Registration Attempt

Register with a throwaway, attacker-controlled identifier only, then attempt verify, then login. Watch the full network traffic in `agent_browser`, not just the rendered UI — the signals below often appear in a response the page never displays.

### OTP/Verification Bypass Techniques

These double as findings in their own right — a working bypass is both your way in and a reportable authentication flaw:

- **Dev-code leaks**: look for `developmentCode`, `testOtp`, `debug_otp`, or the code mirrored back in a response body/header meant for a non-prod environment
- **Predictable/unthrottled OTP**: a 4-6 digit code with no attempt-rate-limit is brute-forceable; check whether the endpoint throttles after N wrong attempts before investing in a full brute force
- **Verification-step bypass**: submit an empty/null code, a fixed guess like `000000`, or omit the parameter entirely and see if verify still succeeds
- **Client-side-only verification**: the OTP gate is enforced in JS before calling a `/complete-signup`-style endpoint — call that endpoint directly, skipping verification
- **Response manipulation**: an "invalid code" decision made from a client-visible status/body that a proxy can flip
- **OTP reuse/collision**: register two accounts in quick succession and check whether the code or its validity window collides

Record every attempt via `record_coverage`; a working bypass gets a full PoC and a report per `analysis/counterevidence.md` — don't just use it silently and move on to hunting.

## Human-in-the-Loop Verification

When automated bypass fails and the code genuinely goes out-of-band (a real email/SMS you cannot read), don't drop straight to `needs_follow_up` — ask the operator. This is the preferred fallback over an operator-supplied token: it lets you drive the whole registration/login flow yourself, with the operator only supplying the one thing you can't get automatically.

**Getting an identifier.** Check `--instruction`/scan setup notes first for an operator-supplied email or phone (e.g. "register with email X, I'll supply the code"). If none was given and the run is interactive, ask for one with `respond_to_user` before registering — you need an identifier the operator actually controls and can read a code from; never substitute a real third party's.

**Getting the code.** `respond_to_user` is the actual mechanism Strix agents use to pause and ask the operator a question mid-run — any agent, root or subagent, gets this tool whenever the scan runs interactively (the default; only `strix --non-interactive` removes it). Calling it delivers your message and parks you until the operator replies, then resumes you with everything you'd done intact:

```
respond_to_user(message="A verification code was sent to <identifier> to complete registration on <target>. Please reply with the code.")
```

Submit the returned code to the verification endpoint and continue to a token exactly as the automated path would.

**Constraints on this path:**

- Only usable when the run is interactive — if `respond_to_user` isn't in your toolset at all, the run is non-interactive and this path doesn't exist; go straight to the operator-credential fallback below
- The wait is indefinite (no auto-timeout) — use it deliberately, not speculatively. If you already know you'll need two codes for two accounts, say so in the message rather than pausing twice without warning
- The identifier must be one the operator supplies and controls — same discipline as below, just satisfied by asking instead of guessing

If two accounts are needed, repeat with a second operator-supplied identifier — one `respond_to_user` round-trip per account is normal, not excessive use.

## Provisioning Two Accounts

Cross-account claims need two real principals, not one session replayed:

- Two low-privileged accounts (A and B) via the same self-registration path, each with its own object created under it — the floor for horizontal IDOR proof
- A role-differentiated pair when self-service role selection exists (vendor/buyer, org-creator/invited-member) — gives vertical/BFLA proof without ever touching a real privileged account
- Two separate tenants/orgs, not just two users in one org, when cross-tenant isolation is in scope — that's a different boundary than cross-user-same-tenant
- Scale past two only if a specific finding needs a third role or tenant; two is the floor, not a hard cap
- **Record the object you just created, immediately** — its type and ID, against the account that created it, in `auth_accounts.jsonl` (see "Saving Tokens for Reuse" below). This is the one piece of state `reconnaissance/trust_boundary_mapping.md` cannot recover later if it's skipped: nothing else in this scan writes down which account owns which object.

## Operator-Credential Fallback

Reach for this only when human-in-the-loop verification isn't available or didn't resolve it — the run is non-interactive, or the operator has no code-receiving identifier to offer. Don't drop the authenticated surface yet. Check, in order:

1. `/workspace/auth/` for operator-supplied credentials or tokens (e.g. `/workspace/auth/tokens.txt`, `/workspace/auth/credentials.json`) — read and use whatever is there
2. Scan config/instructions passed at setup for credentials, an API key, or a note on how to obtain a token
3. If neither exists, record the exact blocker as `open_proof_gap` / `needs_follow_up` — e.g. "registration requires SMS OTP to a real phone number; no dev bypass found; not interactive, so human-in-the-loop wasn't available; no operator credentials supplied" — so it surfaces as a named gap in the final report instead of a silent skip

## Saving Tokens for Reuse

Write every obtained credential/token to `/workspace/recon/auth_tokens.txt` (or a structured `auth_accounts.jsonl` — principal, role, tenant, token/cookie, how it was obtained), the same shared-artifact convention the rest of recon uses (see `asset_discovery.md`, `coordination/root_agent.md`). Every subagent doing authenticated testing reads this file first instead of re-registering — including `analysis/parameter_mutation_testing.md`'s "Actor Replay (Differential Authorization)" section, which is inert below 2 recorded actors here and is the highest-signal black-box BOLA/BFLA technique available once this file has provisioned them.

**Use the structured `auth_accounts.jsonl` form, not the flat `auth_tokens.txt` one, whenever `reconnaissance/trust_boundary_mapping.md` will run** (which is whenever 2+ accounts get provisioned at all) — it is the only form that carries the fields that skill needs, and it cannot recover them from a plain token dump after the fact. One JSON object per line:

```json
{"principal": "testuser_a@example.com", "role": "org-creator", "tenant": "org-1", "token": "Bearer eyJ...", "obtained_via": "self-registration", "owned_objects": [{"type": "project", "id": "5001"}]}
```

`owned_objects` is a list because an account can accumulate more than one object over a scan — append to it rather than overwriting the row each time a new object is created under this account.

## Discipline

- Never send an OTP or verification code to a real third party's phone number or email — only identifiers you control as throwaways, or ones the operator explicitly supplies and confirms they control for this purpose
- Never attempt to take over, guess into, or gain access to a real user's existing account — this skill creates new test accounts, it does not compromise real ones
- If the only path to a token crosses either line, stop and record `needs_follow_up`. A blocked authenticated surface is an honest gap; a compromised real user is not an acceptable substitute for one

## Validation

1. An OTP/verification-bypass finding needs a reproducible request sequence that reaches an authenticated session without a valid code
2. A dev-code leak needs the actual leaked value shown succeeding at a real login, not just "the field looked suspicious"
3. A provisioned account is validated by a real authenticated response under its token (e.g. a profile/`me` endpoint), not just a 200 on the registration call — this holds whether the token came from automated bypass, an operator-supplied code, or a fallback credential

## False Positives

- A "development" OTP field present only in a local/staging build not reachable in the actual scanned environment
- Rate limiting or CAPTCHA that only engages at real-world scale, not within the small sample tested
- An OTP that looks predictable from a handful of samples but is confirmed cryptographically random at a larger sample size

## Impact

- Authentication/verification bypass is itself a critical finding when registration or OTP verification is skippable
- Unlocks the entire authenticated surface (IDOR, BFLA, business logic, multi-tenant isolation) that would otherwise go untested
- Two provisioned accounts are what make horizontal and cross-tenant claims provable at all — without a second principal, most IDOR/BFLA findings can't clear the counterevidence bar

## Pro Tips

1. Try the OTP-bypass techniques before assuming you're blocked — a dev-code leak or missing server-side check costs only a handful of requests to find
2. Provision two accounts as an early move on any multi-user target; retrofitting a second account mid-scan wastes a hunting wave
3. Watch registration/verification network traffic in `agent_browser`, not just the rendered page — dev-code leaks live in responses the UI never shows
4. When falling back to operator credentials, still document what self-registration would have required — useful context for the report even when unused
5. Scale past two accounts only when a specific finding needs a third role or tenant — don't provision more than the plan calls for
6. If you already know two accounts are needed and both require a human-supplied code, ask for both in one `respond_to_user` message rather than parking twice back-to-back

## Summary

Authenticated surfaces are where IDOR, BFLA, and business logic actually live, and a scan without a token can't test any of it. Map the auth model, attempt self-registration with OTP-bypass techniques that are findings in their own right, ask the operator for a code via `respond_to_user` when automation genuinely can't get one, provision at least two accounts before the hunting waves start, fall back to an operator-supplied credential file only when neither path works, and never cross into a real user's identity to get there.
