---
name: client_bundle_analysis
description: Treat a JS-heavy SPA's shipped client bundle as a near-white-box oracle — reconstruct the full API contract (every endpoint, every field, every type, including fields no form exposes) and turn every client-side computation/validation into a concrete, EXECUTABLE server-trust tamper test, instead of noting bundle findings as vague leads.
---

# Client-Bundle Analysis — The Near-White-Box Oracle

Most modern targets (React / Next / Vue / Angular SPAs) ship their entire client
logic to the browser. For black-box testing that bundle is a **near-white-box
oracle**: it contains the full API contract and every server-trust assumption.
The recurring failure — proven in practice — is mining it only for routes and
secrets, noting client logic as a vague "lead", and then being unable to act on
it (e.g. finding a client price function but giving up when the order endpoint
`500`s). This skill converts the bundle into two concrete, executable products.

## 1. Reconstruct the full API contract

Recover readable source first (source maps, `retire`, `js-beautify`; see
`reconnaissance/asset_discovery.md`), then extract **every** API call the client
makes — not just the ones a visible form exposes:

- Grep for the HTTP client (`fetch(`, `axios.`, `XMLHttpRequest`, `$.ajax`, a
  generated SDK / `api.*`) and for `/api/`-shaped strings. For each call record:
  **method, path (with path-params), the EXACT request body object (every field
  name), each field's expected type, and the response shape.**
- The body object is the prize: it reveals fields **no UI control shows** —
  hidden identifiers (`userId`, `ownerId`, `restaurantId`, `tenantId`, `role`,
  `status`, `isAdmin`, `price`), optional flags, nested structures. Every such
  field is an injection / **mass-assignment** target you would never find by
  watching forms (`vulnerabilities/mass_assignment.md`).
- Feed the result into the inventory (`record_endpoint` with param names +
  locations) so **every** hunter gets the full parameter set, not just the
  visible ones.

**Extract it deterministically first — don't ask the model to read minified JS.**
Run this once over the crawled bundle; it is mechanical and reliable, where a
model reading minified JS by eye is slow and lossy. It recovers URLs and methods
reliably and body/query **field names** where they appear as object keys near a
call (minified code mangles locals, so treat fields as *candidates to confirm*,
not gospel):

```python
import json, re, sys, pathlib
js_dir = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "/workspace/recon/js")
path_re = re.compile(r"""["'`](/(?:api|v\d)[A-Za-z0-9_\-./{}:$]+)["'`]""")
method_re = re.compile(r"""(?:method\s*:\s*["']|\.)(get|post|put|patch|delete)\b""", re.I)
key_re = re.compile(r"""[{,]\s*["']?([A-Za-z_][A-Za-z0-9_]{1,40})["']?\s*:""")
eps = {}
for f in js_dir.rglob("*.js"):
    try: src = f.read_text(errors="replace")
    except Exception: continue
    for m in path_re.finditer(src):
        w = src[max(0, m.start()-300):min(len(src), m.end()+600)]
        r = eps.setdefault(m.group(1), {"methods": set(), "fields": set()})
        r["methods"].update(x.group(1).upper() for x in method_re.finditer(w))
        r["fields"].update(key_re.findall(w))
out = [{"path": p, "methods": sorted(v["methods"]) or ["GET?"],
        "candidate_fields": sorted(v["fields"])[:40]} for p, v in sorted(eps.items())]
pathlib.Path("/workspace/recon/api_contract.json").write_text(json.dumps(out, indent=2))
print(f"{len(out)} endpoints -> /workspace/recon/api_contract.json")
for e in out[:50]: print(e["methods"], e["path"], "| fields:", ",".join(e["candidate_fields"][:12]))
```

Read `api_contract.json`, then `record_endpoint` each route with its candidate
fields. The **hidden fields** it surfaces (a body `userId`/`role`/`price` no form
shows) are the mass-assignment/injection surface; confirm each against a live
request.

**This directly produces the valid baseline for any complex request.** When a
write endpoint `500`s on a hand-built request, the bundle shows exactly what a
working one looks like — build it from the contract + live data (`GET /menu/{code}`,
a real id), get the 200, *then* tamper. Never conclude an endpoint is
"untestable" while its request shape is sitting in the bundle you already have.

## 2. Build the server-trust tamper worklist

Every value the **client** computes or validates is a value the **server** may
trust — and each is a concrete tamper test, not a vague lead. For each, write the
exact request to send (from the contract in step 1), then execute it:

- **Computed amounts** — a client price/total/discount/tax helper (a
  `calcTotal()`-style function): send the real items with the computed field
  overridden (`billedAmount: 0`, `1`, negative, huge), then **read the order
  back** to see if the server recomputed or trusted it (`business_logic.md`).
- **Client-side role/permission gates** — `if (user.role === 'admin')` guarding a
  route/button: call the underlying endpoint directly with a low-priv / no
  session — the frontend gate is not a server control (`broken_function_level_authorization.md`).
- **Client-set identifiers** — a body `userId` / `ownerId` / `tenantId` the
  client fills from local auth state: set it to another principal's id and read
  the result back (`idor.md`; also the mass-assignment case above).
- **Client-side validation** — length/format/range checks done only in JS:
  bypass them by calling the API directly with out-of-range input.
- **Hardcoded identity / constants** — a static auth token, API key, or a
  constant identity the client ships (a "default"/"demo" tenant id, a baked-in
  bearer): verified live, these are findings in their own right and often an
  auth-bypass primitive — **chase them, don't just note them.**

File each as a hypothesis WITH its exact request (`create_hypothesis`) and drive
it; a client assumption is confirmed only by a server-side test per
`analysis/counterevidence.md`.

## Discipline

- The bundle tells you what the frontend *expects*, never what the backend
  *enforces* — every item is tested server-side before it is more than a lead.
- A client-side-only route / gate / validation is not a finding by itself; the
  finding is the server accepting what the client would have blocked.
- Feed every recovered endpoint/field/identity back into the inventory so the
  contract compounds across agents instead of being re-derived.
