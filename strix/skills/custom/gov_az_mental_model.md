---
name: gov-az-mental-model
description: Target-class mental model for Azerbaijani government / public-sector web apps (*.gov.az and the local-CMS archetype) — the priors about how these systems are built, an Azerbaijani entry-point keyword map with P0/P1 scoring, Azerbaijani PII field-name recognition, and the four highest-yield bug patterns (exposed panels, default creds, sequential IDOR on citizen data, old/custom CMS with known CVEs), with PII-handling and authorized-scope discipline.
---

# Gov.az Mental Model

A **mental model**, not a scanner script: priors about how a whole *class* of
targets is built and where that class predictably breaks, so recon and the
hypothesis worklist (`strix/tools/hypotheses`) start from informed bets instead
of a blank crawl. **Apply this first** when the target is a `*.gov.az` host (or
any Azerbaijani-language public-sector portal on a bespoke/local CMS): the four
high-yield patterns below are the *first* hypotheses to file, not an
afterthought once generic scanning turns up nothing. The archetype generalizes
to other under-resourced regional government platforms; the keyword and
field-name vocabularies are Azerbaijani-specific.

> **Authorized scope only.** These are real government systems holding real
> citizen PII (national `FIN` codes, ID-document scans, applications,
> complaints). Test only what the engagement authorizes. When a finding *proves*
> itself by exposing another person's data, prove it with the **minimum**
> record needed and redact it in the report (see `analysis/counterevidence.md`
> and reporting discipline) — never bulk-exfiltrate citizen data to
> "demonstrate impact." Out-of-scope `*.gov.az` siblings found during recon are
> recorded `not_applicable`, never tested (see `coordination/root_agent.md`'s
> Program Scope).

## The Target Archetype (priors)

Treat these as *strong priors to disprove*, not facts — but file them as
hypotheses up front, because across this target class they pay off far more
often than a blank generic scan:

- **Built by a local contractor on a bespoke or old CMS.** Expect a custom PHP
  app (often older PHP 5.x/7.x, hand-rolled MVC), an older **ASP.NET Webforms**
  portal (ViewState — see `hunt-aspnet`), **WordPress or Joomla** (frequently
  outdated → known-CVE territory, see `frameworks/wordpress.md` and
  `custom/dependency_cve_scanning.md`), or a **custom Azerbaijani CMS** reused
  across agencies. Fingerprint it precisely (generator meta tag, favicon hash,
  `/administrator` vs `/wp-admin` vs a custom panel path, cookie names, copyright
  string) and check its version against public CVEs *first* — an unpatched
  known CVE is a faster, higher-confidence path than blind fuzzing.
- **Hand-written SQL in search and filter forms.** With no ORM between input and
  query, `axtarış`/filter parameters concatenate straight into SQL far more
  often than on a mainstream stack — the single most reliable SQLi surface here.
- **Exposed admin panels, default creds never changed.** `/admin`, `/idareetme`,
  `/idarəetmə`, `/panel`, `/administrator`, `/cp`, `/backend` reachable with no
  IP allowlist, defended only by a login — and the contractor's install-time
  credentials (vendor defaults, `admin/admin`, leftover test accounts) are often
  never rotated.
- **Sequential-integer reference numbers.** Document, application, and complaint
  reference numbers (`müraciət`/`ərizə`/`sənəd` ids) are typically
  auto-increment integers with **no object-level authorization** — decrement or
  increment the id and read another citizen's record. This is the
  highest-impact pattern in the class (mass PII).
- **File upload without validation.** `yüklə`/document-submission handlers that
  accept any extension/content-type → web-shell RCE, or store to a predictable
  path (IDOR/traversal on the stored file).
- **Perimeter, not per-request, security.** Debug flags, directory listing, and
  backup artifacts (`.git/`, `backup.sql`, `site.zip`, `*.bak`, `phpinfo.php`)
  are often left enabled in production — frequently a faster path to impact than
  exploiting the app blind (see `information_disclosure.md`).
- **Weak identity plumbing.** SMS-OTP via a local gateway (Azercell/Bakcell/Nar)
  with little rate limiting; identity keyed on the 7-char national **`FIN`**
  code or a sequential citizen id — both are *enumeration primitives*, not
  secrets.

## Entry-Point Keyword Map and Scoring

URL/segment keywords (and transliteration variants — `ş→s`, `ü→u`, `ə→e`,
`ç→c`, `ğ→g`, `ı→i`, `ö→o`, or left as unicode) signal the attack surface and a
starting priority. **Score each crawled endpoint by the keyword it matches**,
then let the hypothesis worklist and entry-point-slice delegation work the P0s
first:

| Keyword (variants) | Meaning | First-look vuln class | Priority |
|---|---|---|---|
| `axtarış` / `axtaris` / `axtar` / `search` / `sorgu` | search / query | SQLi (hand-written), reflected XSS, LFI in a `file`/`template` param | **P0** |
| `yüklə` / `yukle` / `yukleme` / `fayl` / `upload` | file upload | unrestricted upload → RCE, path traversal, IDOR on stored file path | **P0** |
| `admin` / `idarəetmə` / `idareetme` / `panel` / `administrator` / `cp` / `backend` | admin panel | exposed panel, default/weak creds, auth bypass | **P0** |
| `müraciət` / `muraciet` / `ərizə` / `erize` / `şikayət` / `sikayet` | citizen application / appeal / complaint | **sequential-integer IDOR on PII**, upload, business-logic / state bypass | **P0** |
| `sənəd` / `sened` / `document` | document | IDOR / direct-object file access, LFI | **P0** |
| `nəticə` / `netice` / `result` | results (exam/application, often keyed by `FIN`) | IDOR / enumeration by `FIN` or id | **P0** |
| `hesabat` / `report` / `çap` / `cap` / `export` / `print` | report / export | information disclosure, IDOR, SSRF via "fetch URL" export | **P1** |
| `şəxsi kabinet` / `kabinet` / `profil` | personal cabinet / profile | horizontal IDOR, account-takeover surface | **P1** |
| `xidmət` / `xidmet` / `e-xidmet` / `service` | e-service | business logic, IDOR, mass assignment | **P1** |
| `giriş` / `giris` / `daxil` / `qeydiyyat` / `login` / `register` | auth | OTP/credential brute (weak rate limit), user enumeration, weak session | **P1** |

Record each mapped endpoint in the attack-surface inventory (`record_endpoint`
with its `discovery_source`) and open a concrete hypothesis (`create_hypothesis`)
naming the keyword-implied class and *why*. The P-score here is a
target-class prior that feeds `analysis/candidate_triage.md` (it raises
`impact`/lowers `test_cost` for a matched P0), not a replacement for its
categorical rubric.

## Azerbaijani PII Field Names (raise severity on a hit)

Form/body/query fields with these names carry citizen PII — an IDOR, mass
assignment, or injection that reaches them is **high severity**, not routine
(see `analysis/severity_calibration.md`). Recognize them when scoring a
parameter for mutation (`analysis/parameter_mutation_testing.md`):

| Field (variants) | Meaning |
|---|---|
| `ad` | first name |
| `soyad` | surname |
| `ata_adi` / `ataadi` | patronymic (father's name) |
| `seriya` | ID-document series |
| `fin_kod` / `fin` / `finkod` | national `FIN` code (identity key — also an enumeration primitive) |
| `dogum_tarixi` / `dtarix` | date of birth |
| `unvan` | address |
| `telefon` / `mobil` | phone |

## The Four High-Yield Patterns

### 1. Exposed panels
Probe predictable admin surfaces on the host and likely subdomains (`/admin`,
`/idareetme`, `/administrator`, `/panel`, `admin.<host>`, `cp.<host>`). A
reachable admin login is a lead (attack surface), not yet a finding — it becomes
one via pattern 2 (creds) or an auth bypass (login SQLi, parameter tampering,
forced browsing to an authenticated page that skips the gate). Fold every panel
into the inventory and flag it for patterns 2–4.

### 2. Default / weak credentials
Try documented vendor defaults for the fingerprinted CMS first, then a *small,
bounded* set of common weak pairs (`admin/admin`, `admin/admin123`,
`admin/123456`, `test/test`). **Not a brute-force engagement** — respect lockout
and rate-limit behavior; a block is recorded `blocked`, not "no vuln"
(mirrors `sql_injection.md`'s blocked-not-negative rule). Leftover test/demo
accounts and predictable password-reset tokens are the same pattern by another
door.

### 3. Sequential IDOR on citizen data (highest impact)
`müraciət`/`ərizə`/`sənəd`/`nəticə` endpoints routinely expose auto-increment
integer ids (`?id=1041`, `/muraciet/1041`) or `FIN`-keyed lookups with **no
object-level authorization**. Decrement/increment the id or substitute another
`FIN` to read another citizen's record. Drive this through the two-principal /
actor-replay discipline in `idor.md` and `analysis/parameter_mutation_testing.md`
(Actor Replay): an identical 2xx body for a non-owner actor is the leak signal
(`owner_scope_verdict: leak_suspected`), not "nothing happened." **Impact proof,
minimally:** confirm with *one* other-subject record, redact it, and stop — the
single cross-subject read already proves BOLA; range-walking real citizen PII is
unnecessary and harmful. Clear `idor.md`'s Impact Escalation bar, then
`update_hypothesis(status="confirmed", ...)`.

### 4. Old / custom CMS with known CVEs and hand-written flaws
Fingerprint and CVE-check the CMS first (pattern above). Then, because there is
often no framework escaping between input and sink, the `axtarış` param is a
live SQLi/XSS candidate and the `yüklə` handler a live upload-RCE/traversal
candidate far more often than on a mainstream stack — prioritize
`sql_injection.md`, `xss.md`, `hunt-file-upload`, `path_traversal_lfi_rfi.md`
accordingly. Keep executor discipline: a `run_sqli_test` positive is
`needs_validation`, never `confirmed`; a reflected payload is a lead until a
real-context PoC exists.

## Shared-Codebase Pivoting
When a bug is confirmed on one `*.gov.az` site, immediately check the
fingerprint-matched siblings from the recon inventory for the *same* code path
(same param, same endpoint shape). Report each confirmed sibling as its own
finding referencing the shared root cause — but only against in-scope hosts.

## Discipline
- Every candidate still passes `analysis/counterevidence.md`'s closure gate; a
  tool hit never auto-confirms (`strix/tools/hypotheses` enforces this).
- A government target that disputes a bad report costs more than a missed bug —
  prefer `open_proof_gap` / low confidence over a rounded-up claim.
- Cross-references: `coordination/root_agent.md` (Form Hypotheses Before
  Hunting; entry-point-slice delegation), `idor.md` (BOLA / actor replay),
  `broken_function_level_authorization.md` (panel action authz),
  `analysis/parameter_mutation_testing.md` (mutation + Actor Replay engine),
  `analysis/candidate_triage.md` (the P-score consumer),
  `reconnaissance/asset_discovery.md` (the `*.gov.az` inventory + CMS
  fingerprint), `information_disclosure.md` (debug/backup artifacts),
  `frameworks/wordpress.md` / `hunt-aspnet` / `hunt-file-upload` for
  stack-specific depth.
