---
name: asset-discovery
description: Passive asset and attack-surface discovery via certificate transparency, TLS SAN pivoting, passive DNS, and ASN/IP enumeration, plus application-layer crawling, deep JS analysis (source maps, hidden routes, secrets, dev-flags), endpoint/parameter mapping, and attack-queue prioritization
---

# Asset Discovery

> **Black-box artifact note:** For black-box targets, `entry_points.md` is **NOT** produced here — it is a white-box-only artifact built inside the sandbox by `custom/source_aware_sast.md`. The black-box equivalents are `/workspace/recon/assets.jsonl` (Layer 2 structured host inventory), `/workspace/recon/attack_queue.md` (the prioritized worklist), and `/workspace/recon/mutation_candidates.md`. **Do not reference `entry_points.md` in black-box agents** — point them at these three instead.

Most engagements start from a small seed (one domain, one org name) but the real attack surface is far larger: forgotten hosts, staging/internal-named services, acquisitions, and infrastructure that never appears in a wordlist. Build a broad, deduplicated inventory using passive intelligence — certificate transparency, TLS certificate metadata, passive DNS, and ASN/IP data — then collapse it into a probed, classified attack surface. The aim is coverage and pivoting: every certificate, DNS record, and IP is a lead to more assets.

Only use this skill when all subdomains and related assets of the target are in scope — broad discovery pulls in hosts far beyond the seed.

Consolidation gets you a live, classified host — that is an entry point, not the attack surface. See **Application-Layer Recon** below to go past the host and map its endpoints, parameters, and hidden content.

Before or alongside the pipeline below, also run `dorking` — it needs only the seed, costs no traffic to the target's own infrastructure, and often produces the single highest-value finding of the engagement (a live committed credential).

## Layered Execution Model (Noise Gradient)

Run recon as four ordered layers, quietest first, so a loud step never fires before the passive surface is built. **This ordering is a skill-first convention the agent follows by reading these instructions — it is not runtime-enforced.** Nothing in the engine blocks a tool call if the order is ignored; the gate checks below, and the run-state file they read, are only as reliable as the agent's adherence. Treat them as a checklist you are responsible for honoring, not a sandbox that enforces them.

Stage state lives in `/workspace/recon/recon_state.json`, written/read by the `strix-recon-state` script (see Pipeline Scripts, below). It is **run-specific**: every entry is tagged with the current `run_id` and a `scope_id` (a hash of the sorted in-scope seeds), and a state file left by any earlier run or a different scope reads back as `pending` — previous-run state never authorizes current-run work. Each stage is one of `pending | partial | completed | failed | skipped`. Export `RUN_ID` (the scan's run name) and `SCOPE_ID` (`printf '%s\n' <sorted-seeds> | sha256sum`) once at the start so every state call shares them.

| Layer | What runs | Target traffic | Documented in |
|---|---|---|---|
| **1 — Passive / OSINT** | CT (crt.sh), `subfinder -all`, passive DNS, ASN/IP, `gau`/`waybackurls`, dorking | **Zero** to target | High-Value Sources, `dorking` |
| **2 — Active light** | `httpx` probe+`-td`+`-tls-grab` → per-origin `assets.jsonl`; `naabu --top-ports 1000` → `host_ports.json`; `katana` crawl + bounded headless XHR | Low (browser/crawler-like) | Consolidation & Probing |
| **3 — Param / endpoint discovery** | `arjun`, `ffuf`/`dirsearch` content discovery, known-path probing | **High** (obvious bruteforce) | Application-Layer Recon steps 2–4 |
| **4 — Vuln fingerprinting** | `nuclei`, a **per-origin** selector manifest (never one tag list across every origin) | Moderate, bounded | Layer 4 (below) |

### Ordering conventions (agent-honored, not enforced)

Before starting a layer, check the prior stage: `strix-recon-state get "$RUN_ID" "$SCOPE_ID" <stage>` — proceed only if it reads `completed` or `skipped`. Set state when you finish (`completed`), finish partially (`partial`), fail (`failed`), or deliberately skip (`skipped`).

1. **Layer 1 → 2.** Finish passive enumeration (CT + `subfinder` + historical URLs under `/workspace/recon/`), set `layer1=completed`, before any active probe. If a passive source is unreachable, record it and continue on authorized seeds — the stage is `completed`/`partial`, never a silent block.
2. **Layer 2 → 3.** Probe, fingerprint, classify into `assets.jsonl`, set `layer2=completed`, before any directory/parameter bruteforce. An empty or unknown tech fingerprint does **not** block this — it is a recorded `probe_state`, not a failure (see Layer 2).
3. **Layer 3 scope.** Run `arjun`/`ffuf`/`dirsearch`/content discovery only against origins whose `assets.jsonl` `class` is `api`/`app`/`admin`/`auth`, plus specific Layer 1/2 leads — not the full inventory. Marketing/CDN/static origins are excluded.
4. **Layer 4.** Reads `assets.jsonl`, emits a per-origin selector manifest; gated by scan mode (standard/deep only). A `skipped` Layer 4 (quick mode) satisfies the ordering check and must not block anything downstream.

A `skipped` optional stage satisfies the ordering check and never deadlocks a later stage; `failed`/`partial`/`pending` do not — redo or explicitly skip. The real artifacts other agents consume are `subs.jsonl` / `assets.jsonl` / `host_ports.json` / `attack_queue.md` / `nuclei.jsonl`, per the reuse convention in `coordination/root_agent.md`.

## Attack Surface

- Hosts discoverable via issued certificates (CT logs) but absent from DNS brute force
- Internal/staging/pre-prod hostnames leaked in certificate SAN lists
- Sibling and acquisition domains sharing certificates, ASNs, or IP ranges with the seed
- Wildcard and short-lived certs revealing naming conventions (`*.internal.example.com`, `k8s-*`, `argocd.*`)
- ASN-owned IP ranges hosting services with no DNS name at all
- Virtual hosts co-located on shared IPs (multiple apps behind one address)
- Non-HTTP services on discovered hosts (databases, brokers, admin ports)

## High-Value Sources

### Certificate Transparency (CT)

CT logs record nearly every publicly-trusted certificate. Query by domain (matches SAN/CN) and by organization name.

- **crt.sh** (free, no key):
  - By domain incl. subdomains: `curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | sed 's/^\*\.//' | sort -u`
  - By organization: `https://crt.sh/?O=Example+Inc&output=json`
- **Censys / Shodan / Fofa** (API keys): search certs by `parsed.names`, `parsed.subject.organization`, or a specific `fingerprint_sha256`, then pivot to every host serving that cert.
- Cross-check multiple indexes (`certspotter`, Google CT, `chaos`) — no single log is complete.
- **Wildcards** (`*.corp.example.com`) reveal internal naming schemes even when individual hosts resolve privately; use them to seed targeted guesses (`grafana.corp`, `ci.corp`, `vault.corp`).

### TLS Certificate SAN/CN

- **SAN expansion**: one cert often lists many hostnames (marketing + api + admin + internal) — extract every SAN, not just the queried name.
- **Shared-cert pivot**: the same cert fingerprint served on multiple IPs ties disparate assets to one owner.
- **Issuer/org pivot**: certs sharing `subject.organization`/`organizationalUnit` frequently belong to the same target.
- **Active read** catches names never submitted to public CT: `echo | openssl s_client -connect HOST:443 -servername HOST 2>/dev/null | openssl x509 -noout -text | grep -A1 'Subject Alternative Name'`
- **Internal leak signal**: SANs like `localhost`, `*.internal`, `*.svc.cluster.local`, `*.local`, or RFC1918-style names on a public cert expose internal naming and sometimes internal services fronted publicly.

### Passive DNS

- Forward-resolve every name (A/AAAA/CNAME); keep CNAME chains — they reveal third-party providers and CDNs.
- **Reverse DNS (PTR)** on discovered IPs surfaces co-located hostnames.
- **Historical/passive DNS** (SecurityTrails, VirusTotal, `chaos`, passivedns providers) recovers names that no longer resolve but may still front live infra.

### ASN & IP Ranges

- Map a known IP to its ASN and netblock: `whois -h whois.cymru.com " -v <IP>"` or a BGP/ASN lookup.
- If the org runs its own ASN, enumerate all announced prefixes and treat them as candidate assets.
- For cloud-hosted targets the IP belongs to the provider, not the org — pivot via cert/vhost instead of netblock.

## Recommended Tooling

These tools are available in the sandbox and are pipeline-friendly with JSON output. Write every output file under `/workspace/recon/` (e.g. `/workspace/recon/subs.jsonl`) — it is the shared inventory location other agents read from instead of re-running discovery (see `coordination/root_agent.md`).

- **`subfinder`** — passive subdomain aggregation across many sources incl. CT: `subfinder -d example.com -all -recursive -silent -oJ -o subs.jsonl`
- **`httpx`** — live probing plus cert/SAN grab in one pass: `httpx -l hosts.txt -tls-grab -json` (see methodology).
- **`naabu`** — port sweep for non-HTTP services: `naabu -list hosts.txt -top-ports 100 -verify -silent`
- **`curl` + `jq`** — direct **crt.sh** JSON queries for CT (no key needed) and other index APIs.
- **`openssl s_client`** — active read of a live host's cert to extract SANs/CN.
- **`dig`** / **`nslookup`** — forward/reverse (PTR) resolution and CNAME chains.
- **`whois`** — ASN/netblock lookups (e.g. `whois -h whois.cymru.com`).

Cross-source results — CT + passive DNS + `subfinder` together beat any single source. If you need a tool that is not installed, install it into the sandbox at runtime.

## Key Techniques

### Iterative Seed Expansion

Every new name, PTR result, CNAME target, and cert SAN becomes a fresh seed. Loop CT → SAN extraction → passive DNS → ASN/range expansion until the asset set stops growing.

### Cert-Fingerprint Pivoting

Search Censys/Shodan by a cert's `fingerprint_sha256` to find every other host presenting the same certificate — the strongest cross-asset link for tying acquisitions and shadow infra to the target.

### Naming-Convention Inference

Wildcard SANs and observed hostnames expose the org's naming scheme; generate targeted candidates from it (`<service>.<env>.example.com`) rather than blind brute force.

### IP-First Discovery

For ASN-owned ranges, sweep IPs directly with `naabu`/`httpx` and read served certs (`httpx -tls-grab`, or `openssl s_client`) to find services that have no DNS name at all.

## Advanced Techniques

- **Active SAN harvesting** across whole ranges with `httpx -tls-grab` (or `openssl s_client`) recovers internal hostnames never logged to public CT.
- **Favicon and response hashing** (`httpx -favicon`, hash pivots in Shodan) clusters instances of the same app across unrelated hostnames.
- **Vhost differentials**: probe a single IP with multiple `Host:` values to unmask co-located apps behind one address.
- **Historical CT/DNS diffing** highlights recently issued certs and newly appearing hosts — high-signal for fresh or misconfigured deployments.

## Consolidation & Probing

1. **Dedupe** names and IPs into one inventory; record source(s) per asset for confidence.
2. **Live probe** with `httpx`, capturing status/title/tech/server, CDN, and cert SANs in one pass — each grabbed SAN feeds back as a new seed. Write the raw probe to `httpx_raw.jsonl`; it is normalized into the canonical `assets.jsonl` (schema below):
   `httpx -l hosts.txt -sc -title -server -td -tls-grab -cdn -json -o httpx_raw.jsonl`
   The `-td` (tech-detect) field feeds Layer 4's template mapping. An empty `tech` is **fine and does not block Layer 2** — the normalizer records that origin's `probe_state` as `unknown_tech`, and Layer 4 falls back to a bounded baseline for it (see Layer 4).
3. **Classify** assets by function from title/tech/path signals and record the result in each `assets.jsonl` record's `class` field — one of `api`, `app`, `admin`, `auth`, `marketing`, `cdn`, `storage`, `observability`, `other`. Cluster by role, not by a specific product. **Gate Rule 3 reads this field** to decide which hosts Layer 3 may touch.
4. **Port sweep** hosts with `naabu --top-ports 1000` for non-HTTP services (DBs, caches, brokers, mgmt ports): `naabu -list hosts.txt -top-ports 1000 -json -silent -o naabu.jsonl`. Confirm service versions with `nmap -sV` only on the hosts/ports naabu flags open. Optionally fingerprint WAFs with `wafw00f -i hosts.txt -f json -o wafw00f.json`. Both feed the `ports[]` and `waf` fields of `assets.jsonl` below.
5. **Prioritize** by exposure and value, then hand each finding to the right specialist skill:
   - Exposed dashboards / debug / observability / metadata leaks → `information_disclosure`
   - Login/admin panels with default or weak creds → `weak_password_detection`
   - Dangling DNS / unclaimed provider resources → `subdomain_takeover`
   - Cloud consoles/metadata surfaces → `aws` / `gcp` / `kubernetes`

### Layer 2 Output — `assets.jsonl` (one record per *origin*)

Normalize the raw `httpx`/`naabu`/`wafw00f` outputs into **one record per web origin**, where an origin's identity is **scheme + normalized host + effective port** — *not* bare hostname. `http://h`, `https://h`, and `https://h:8443` are three distinct origins with independent fingerprints; collapsing them onto one host record is how one service's tech gets wrongly attributed to another. Run the `strix-recon-normalize` script (Pipeline Scripts, below) — do not hand-roll host parsing; it uses a real URL parser and handles default/explicit ports, host casing, IPv6, duplicate observations, and redirects.

It writes two artifacts, kept deliberately separate:

- **`assets.jsonl`** — origin-level records (tech, WAF, TLS, status, class are all origin-scoped):

```json
{
  "origin": "https://shop.example.com:443",
  "scheme": "https", "host": "shop.example.com", "port": 443,
  "requested_origin": "https://shop.example.com:443",
  "observed_origin": "https://shop.example.com:443",
  "redirected_offhost": false,
  "url": "https://shop.example.com",
  "status_code": 200, "title": "Example Shop", "webserver": "nginx",
  "tech": ["PHP", "WordPress:6.5"],
  "cdn": "cloudflare", "waf": "Cloudflare",
  "tls_info": {"version": "tls13", "cipher": "...", "subject_cn": "shop.example.com", "sans": ["*.example.com"]},
  "ports": [443],
  "class": null,
  "probe_state": "completed",
  "probe_reason": "probe succeeded with tech fingerprint",
  "takeover_candidate": false
}
```

- **`host_ports.json`** — `{host: [open ports]}` from naabu, a **host-level** observation kept out of the origin records. An origin's `ports` field is just its own port; a host having 8443 open does not put 8443 on the 443 origin's record. Each open port not already an HTTP origin is a candidate to probe as a new origin (feed it back to `httpx`).

Field provenance (verified against the installed tools' real JSON): `tech[]`←httpx `tech` (needs `-td`); `cdn`←`cdn_name`; `tls_info`←`tls.{tls_version,cipher,subject_cn,subject_an}`; `status_code`/`title`/`webserver`←same-named httpx fields (httpx says `webserver`, not `server`). `waf`←wafw00f `firewall` when `detected`, **joined by the origin parsed from the wafw00f URL** (never broadcast to every origin of a host). `class`←the classification step (3), the field the Layer 3 scope convention keys on.

**`probe_state`** distinguishes `completed` (tech found), `unknown_tech` (probe OK, no fingerprint), `failed` (httpx `failed:true`), and `no_response` (a host in the optional `hosts.txt` input that produced no probe line at all). This is how a legitimately empty inventory is told apart from a discovery failure, and how an unknown fingerprint continues instead of blocking. **`requested_origin`/`observed_origin`/`redirected_offhost`** preserve a redirect: the record is always keyed to the *requested* origin, so an off-host redirect destination is recorded as metadata and **never auto-promoted** into the inventory — scope-check it first (see Validation) before probing it as its own seed.

## Application-Layer Recon

Consolidation hands you a live, classified host. Don't stop there — for every in-scope host worth attacking, crawl it, extract what its JS reveals, probe for known paths and specs, brute-force what's still hidden, and pull hidden parameters out of anything dynamic. Then rank the result into a queue instead of handing over a flat list. Write this phase's output under `/workspace/recon/` alongside the host inventory, same as above.

### 1. Crawl & JS Extraction

This is where the disproportionate value is on modern JS-heavy targets (Next.js/React/Angular) — a room101-class lead (a `developmentCode` OTP leak, hardcoded credentials) comes from this step, not from running the same scanners every other tool runs. Crawl first, then treat the deep dive below as mandatory, not optional polish.

- Crawl each host with `katana`, JS-aware: `katana -u https://host.tld -d 3 -jc -jsl -kf all -ct 10m -fsu -c 10 -p 10 -rl 50 -j -o crawl/host.jsonl` (see `tooling/katana.md`).
- Run `gospider -s https://host.tld -d 3 -c 10 -t 20` as a second pass on hosts where katana output looks thin.
- `~/tools/JS-Snooper/js_snooper.sh` and `~/tools/jsniper.sh/jsniper.sh` automate a first-pass sweep per domain — treat their output as a starting inventory, not the finish line.

**JS-heavy fingerprint check and conditional headless pass**

The crawl above is static — it never executes JS, so it never sees an API
call a SPA only fires at runtime (on page load, scroll, or client-side
routing). A real headless pass catches those, but it is not cheap: a
direct depth-2 headless crawl of an ordinary, non-heavy site measured
**119x slower than the equivalent static crawl** (49 minutes vs. 25
seconds) in testing. Making headless the default for every host would
make recon unusable on anything but a tiny target — so run it only when
a cheap, deterministic signal says the static crawl likely missed
something, and keep it hard-bounded even then.

- After the static crawl, test each host's root-page response body
  (already captured in `crawl/host.jsonl`, no extra fetch needed) with a
  concrete thinness check — strip `<script>`/`<style>` content and all
  remaining tags, then measure what visible text is left, and separately
  count non-script/style/meta/link opening tags:
  ```python
  import re

  def is_js_heavy(body: str) -> bool:
      text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", body, flags=re.S | re.I)
      text = re.sub(r"<[^>]+>", " ", text)
      text = re.sub(r"\s+", " ", text).strip()
      content_tags = len(re.findall(
          r"<(?!script|style|meta|link|br|hr|noscript)[a-zA-Z][^>]*>", body, flags=re.I
      ))
      return len(text) < 500 or content_tags < 20
  ```
  Calibrated against real pages: a genuine SPA shell (TodoMVC's React
  build) measured 86 chars / 10 tags; an ordinary content page (a
  Django-templated site) measured 1700+ chars / 138+ tags — the
  thresholds sit well inside that gap. The check is deliberately
  recall-leaning: a handful of genuinely tiny static sites (not SPAs)
  will also cross it and get the follow-up pass below — that's an
  acceptable, intentional tradeoff, since the follow-up is now
  hard-bounded rather than the unconditional multi-hour risk it would
  otherwise be.
- When a host trips the check, run one bounded headless follow-up —
  never unconditionally:
  ```
  katana -u https://host.tld -hl -scp /usr/bin/chromium -nos -xhr \
    -d 2 -ct 5m -mdp 50 -silent -j -o crawl/host_headless.jsonl
  ```
  `-ct 5m` is a hard wall-clock cap enforced independently of `-mdp` —
  confirmed by direct testing (a `-ct 1m` run against a slow target
  stopped at 1m0s with 59 records, not left running to a depth/page
  target). `-mdp 50` bounds page count on top of that; neither alone is
  enough on a genuinely slow SPA, both together are what makes this safe
  to run unattended. The `-scp` path (not `-sc`) is required to actually
  use the sandbox's installed Chromium — see `tooling/katana.md`.
- Fold `response.xhr_requests[]` from the headless output into the same
  endpoint inventory the static crawl feeds, using the same `endpoint`
  key katana already uses for both — they're the same underlying schema
  (`xhr_requests` entries are literally the same `Request` type as a
  normal crawled URL), so no field-renaming or second schema is needed:
  ```python
  import json
  from pathlib import Path

  for line in Path("crawl/host_headless.jsonl").read_text().splitlines():
      rec = json.loads(line)
      page_url = (rec.get("request") or {}).get("endpoint", "")
      for xhr in ((rec.get("response") or {}).get("xhr_requests") or []):
          print(json.dumps({
              "endpoint": xhr.get("endpoint"),
              "method": xhr.get("method"),
              "body": xhr.get("body"),
              "source": f"headless_xhr:{page_url}",
          }))
  ```
  Append this alongside the static crawl's own records — downstream
  steps (Parameter Discovery, the attack queue) read one consistent
  `endpoint`/`method` shape regardless of which pass found the URL.

**Source map extraction**
- Probe every `.js` file for a trailing `//# sourceMappingURL=` comment, and try `<file>.js.map` directly even when the comment is absent — maps are frequently deployed but the reference stripped
- A recovered `.map` reconstructs original filenames, comments, and unminified source (any source-map consumer, or walk the `sources`/`sourcesContent` fields with `jq` directly) — grep the reconstructed tree exactly like a whitebox checkout
- Next.js specifically ships `_next/static/<build-id>/_buildManifest.js` and per-route chunks under `_next/static/chunks/` — pull the build manifest to enumerate every route Next.js knows about, including ones with no visible link in the rendered UI

**Hidden endpoint/route extraction**
- Parse every JS bundle, not just the entry point, for path-shaped string literals: `/api/`, `/admin/`, `/internal/`, `/v1/`, `/graphql`, UUID-shaped segments — a regex sweep beats reading, but read the surrounding code for anything that looks gated
- Framework route tables are a goldmine: React Router route arrays, Next.js `pages`/`app` manifests, Angular route modules — these enumerate the application's *intended* full route set, including routes never linked from the nav
- **Client-only-gated routes are the highest-value find here**: a route rendered behind `if (user.role === 'admin')` in JS with no corresponding server-side check is a live BFLA lead — the frontend enforces it, nothing else may. Record every such route and hand it to `vulnerabilities/broken_function_level_authorization.md`'s verb/endpoint enumeration; don't just note it and move on

**Secret and config hunting**
- Grep for API-key-shaped strings, cloud credential patterns, Firebase config objects (`apiKey`/`authDomain`/`projectId` blocks), JWT secrets, and hardcoded basic-auth credentials — the same pattern catalog as `dorking.md`'s GitHub dork list, applied to shipped JS instead of git history
- Feed every candidate through `trufflehog filesystem <path> --results=verified` or `gitleaks detect --source <path>` (both already in the sandbox) for live-credential confirmation before treating anything as more than a lead
- A client-side Firebase/Supabase/Stripe-publishable-style key isn't inherently a secret — confirm which key type you're looking at (check `technologies/firebase.md`/`technologies/supabase.md`) before assuming exposure; report confirmed secrets per `vulnerabilities/information_disclosure.md`'s triage rubric

**Feature-flag, debug-mode, and dev-artifact discovery**
- Grep for flag-shaped identifiers: `isDebug`, `debugMode`, `testMode`, `devMode`, `staging`, `mock`, `bypassAuth`, `skipVerification`, `developmentCode` — this exact class of string is what surfaced the room101 OTP-leak lead, so run it as a named, systematic search every time, not a lucky grep
- Commented-out code blocks and dead branches (`// TODO`, `/* disabled for prod */`, unreachable `if (false)` guards) often reveal a feature or bypass path that still exists server-side even though the client no longer exposes it
- Any flag that looks like it toggles a verification/auth requirement is worth testing directly against the API regardless of what the current UI shows — the flag proves the *existence* of a code path even if the client no longer triggers it

**Client-side trust assumptions**
- Price/total/tax computation done in JS and merely displayed, not recomputed server-side on submit — a lead for `vulnerabilities/business_logic.md`'s Numeric and Currency section
- Role/permission checks (`canEdit`, `isOwner`, `hasAccess`) that gate UI rendering only — a lead for `vulnerabilities/idor.md`/`broken_function_level_authorization.md`
- Input validation (length, format, allowed values) enforced only in a form component — a lead for injection classes once the same field is sent directly to the API
- Every trust assumption found here is a **lead**, not a finding: it says what the frontend expects the backend to enforce, not that the backend fails to. Test it server-side before recording anything beyond `record_coverage`

**Interactive follow-up for click/type-gated API calls**
- Both crawls above are automatic and blind — neither understands that a
  search box needs a real query, a "load more" button needs a click, or
  a filter dropdown needs a real selection to reveal the API call behind
  it. Katana's headless mode auto-fills forms with synthetic values; it
  does not perform meaningful, semantically-aware interaction — that gap
  is what this step exists to close.
- After the crawls, read the rendered page (`agent-browser snapshot -i`,
  see `tooling/agent_browser.md`) for interactive elements that plausibly
  gate a hidden API call — search inputs, pagination/"load more"
  controls, filter/sort dropdowns, modals — and drive up to **2-3** of
  the highest-value ones per host with network capture around the
  interaction:
  ```
  agent-browser open https://host.tld
  agent-browser network har start
  agent-browser snapshot -i
  agent-browser fill @e3 "<realistic query>"
  agent-browser press Enter
  agent-browser wait --load networkidle
  agent-browser network har stop /workspace/recon/host_interactive.har
  ```
- This is a deliberate, agent-judged step, not an automatic trigger for
  every UI pattern found — blindly clicking everything on every host is
  its own budget risk. Pick the 2-3 elements most likely to gate real
  backend calls (a working search box beats a "subscribe to newsletter"
  button), and record what you skipped via `record_coverage` so the
  choice is visible, not silent.

A secret is only reported once verified live or clearly valid (per `analysis/counterevidence.md`) — a dead/rotated key is `open_proof_gap`, not a finding. A client-side-only route or trust assumption is a lead to test server-side, never a finding by itself. Every extracted endpoint, route, secret, and flag is a new asset regardless — feed it back into the inventory, not into a scratch note.

### 2. Known Paths & API Specs

- Probe fixed high-signal paths on every live host: `httpx -l hosts.txt -path /robots.txt,/sitemap.xml,/.well-known/security.txt,/swagger.json,/openapi.json,/api-docs,/graphql -sc -title -silent -j -o known_paths.jsonl`.
- `-kf all` in step 1 already covers `robots.txt`/`sitemap.xml`-linked discovery; treat this probe as the targeted complement, not a replacement.
- Found a spec → load `custom/api_spec_testing.md` and drive the API from its schema. Found `/graphql` → load `protocols/graphql.md`.

### 3. Content Discovery

**Layer 3 (loud) — scope convention:** this step and Parameter Discovery below run **only** on origins classified `api`/`app`/`admin`/`auth` in `assets.jsonl` (plus specific Layer 1/2 leads), never across the full inventory. Confirm `strix-recon-state get "$RUN_ID" "$SCOPE_ID" layer2` reads `completed`/`skipped` first, and set `layer3` state when the loud steps finish. (This is an agent-honored convention, not a runtime-enforced gate — see the Layered Execution Model.)

- Fuzz hosts that show a CMS/framework fingerprint or thin crawl output: `ffuf -w wordlist.txt -u https://host.tld/FUZZ -mc 200,204,301,302,307,401,403 -ac -t 20 -rate 50 -noninteractive -of json -o ffuf_host.json` (see `tooling/ffuf.md`).
- `dirsearch -u https://host.tld -e php,html,js,json` for a fast broad sweep when no specific wordlist angle exists yet.
- Calibrate wordlist and depth to what the host actually is (fingerprinted tech, paths already found) — one huge generic wordlist against every host in a large inventory burns budget and buries real hits in noise.

### 4. Parameter Discovery

- On endpoints that look dynamic or DB-backed (query strings, form posts, REST resource paths), run `arjun -u <url>` (GET) and `arjun -u <url> -m POST` to surface parameters absent from the crawl.
- This is a recon step, not just an IDOR trick — hidden parameters (`debug`, `role`, `format`, `redirect`, `filter`) reshape an endpoint's whole attack surface before any specific vuln class is tested.
- Feed every discovered parameter back into the endpoint inventory with its source (crawl, JS, or `arjun`).

### 5. Prioritization — Attack Queue

Turn the flat endpoint/host inventory into an ordered queue, not a routing table:

1. **Auth/session surfaces and API endpoints** - login, token issuance/refresh, session management, any discovered API base path. Highest value: breaking these has the widest blast radius.
2. **Admin panels and user-data CRUD** - anything reading/writing another user's data or exposing privileged functionality.
3. **Anything with parameters reaching a backend** - endpoints with query/body/path parameters from the crawl or `arjun`, especially ones touching IDs, file paths, or format/type switches.
4. **Static/marketing content** - lowest priority; worth only a pass for information disclosure.

Within a tier, boost hosts with a newly-issued cert or CT diff (from the passive phase) and hosts whose probe response (title/tech/status) changed since the last pass — fresh or actively-deployed code is more likely to carry undiscovered bugs. Hand exploitation agents this ranked list, not the flat classified-host list from Consolidation & Probing step 3.

### Coverage Discipline

Every crawled endpoint, extracted JS route, and discovered parameter not actually exploited in this pass is a candidate, not a dead end. Record it with `record_coverage(outcome="needs_follow_up")` as an `open_proof_gap` (see `analysis/counterevidence.md`) instead of letting it silently drop when crawl output is large. A big inventory with no follow-up trail is exactly how real endpoints get missed.

## Layer 4 — Tech-Matched Nuclei Fingerprinting

The final layer runs `nuclei`, but **scoped per origin to that origin's own detected stack** — never the full ~10k-template firehose, and never one combined tag list across every origin. **Scan-mode gate:** `standard`/`deep` only; **skip in `quick`** (set `layer4=skipped`) — it is the loudest, slowest layer.

### Per-origin selectors (no cross-origin leakage)

The old approach — collect every `tech[]` value across `assets.jsonl` into one `-tags` list and run it against all targets — leaks WordPress templates onto unrelated API origins. Instead run the `strix-recon-selectors` script (Pipeline Scripts, below): it builds a selector set **per origin**, groups origins only when their normalized selector sets are *identical*, validates each product tag against the installed templates (`nuclei -tags <t> -tl`), and writes `/workspace/recon/nuclei_manifest.json` recording each group's origins, tags, template paths, and the reason for every selection. WordPress detected on one origin never causes WordPress templates to run on another.

Tech→tag rules it applies: normalize each tech (lowercase, strip `:version`), map via its table (`wordpress`→`wordpress`, `nginx`→`nginx`, `apache`/`httpd`→`apache`, `php`, `laravel`, `drupal`, `joomla`, `tomcat`, `jira`, `jenkins`, `gitlab`, `grafana`, `spring`, `kubernetes`, …). Products map to **`-tags`**, not a `-t http/cves/<product>/` path: nuclei organizes `http/cves/` **by year, not product**, so that path does not exist and matches nothing (`-tags wordpress` spans 1709 templates; the path, 0). An unmapped tech is tried as a tag and kept **only if it validates to a non-empty set** — a dead selector is dropped, recorded in the manifest with its reason.

### Selection discipline (not severity alone, not everything-on-everything)

- **Conditional categories, not always-on.** `http/default-logins/` and `http/exposed-panels/` run only on origins classed `admin`/`auth` (panel/auth evidence). `http/takeovers/` runs only when `takeover_candidate` is set from Layer-1 DNS/provider evidence — never blanket against every origin. The engagement must permit default-login/takeover probing; if not, drop those categories.
- **A bounded baseline, by category not severity.** Every in-scope origin (including `unknown_tech`) gets `http/exposures/` + `http/misconfiguration/` — useful low-noise exposure/misconfig leads that a `-s critical,high`-only filter would miss. Detection-only results stay recon enrichment (see below); severity is applied on top, it is not the selector.
- **Empty selectors never broaden.** An origin with no validated product tags gets **only** its baseline paths — the runner must never emit a bare `-tags ` (which scans broadly). The manifest marks such groups `tags: []`.

### Run per group via `strix-recon-nuclei-run`

`nuclei` treats `-t <path>` + `-tags` as an **AND filter**, not additive (`-t http/exposed-panels/ -tags wordpress` → 1576 templates become 3), so tags and paths must run as *separate passes*. Rather than hand-type that per group, run the `strix-recon-nuclei-run` executor (Pipeline Scripts, below) over `nuclei_manifest.json`:

```bash
RUN_ID="$RUN_ID" python run_nuclei.py        # reads nuclei_manifest.json
python merge_nuclei.py /workspace/recon/nuclei_run_${RUN_ID}_*.jsonl
```

The executor enforces, in code, what skill text can only advise:

- **Validated selectors only.** Only a group's `tags_validated` reach the `-tags` pass. `tags_unverified` (nuclei was unavailable when the manifest was built) are **re-validated at execution time** — if nuclei now confirms templates they run, otherwise they are logged to `nuclei_skipped.json` ("nuclei unavailable at validation time") and never passed to the subprocess. `tags_invalid` never run.
- **Hard rate/concurrency flags.** `-rl 50 -c 20 -bs 20 -timeout 10 -retries 1 -ni` are fixed on every `nuclei` argv the executor builds — enforced by the tool, not a number the agent is trusted to type. Groups/passes run sequentially (one process at a time), so the per-process caps are the effective caps.
- **Baseline template cap.** The baseline path set is capped at `MAX_BASELINE_TEMPLATES` (50) resolved templates: the executor sizes each path with `-tl`, keeps paths greedily until the cap, and truncates the rest with a logged reason rather than silently running hundreds.

It writes per-run `nuclei_run_${RUN_ID}_g*_*.jsonl` files plus `nuclei_commands.json` (every argv, for audit), `nuclei_skipped.json`, and `nuclei_layer4_summary.json`. `merge_nuclei.py` then dedup-merges those per-run files into the shared `nuclei.jsonl` (keyed on template-id + matched location + matcher) — it reads **only** the files you pass and overwrites `nuclei.jsonl`, so it never appends to a stale result from an earlier run.

**Still advisory (not enforced):** that Layer 4 runs at all is gated by scan mode and the agent's adherence; the cumulative budget across *groups* is bounded only by running them sequentially (the executor does one group at a time, but nothing stops an agent from launching several executors in parallel). `-ni` disables OAST/interactsh unless callbacks are expected and permitted.

### Every hit is a lead, not a finding

A nuclei match is a **candidate**, never an auto-reported finding. Route every `nuclei.jsonl` entry through `analysis/counterevidence.md`'s closure discipline before it becomes anything more:

- Re-fetch and confirm the match is live and reproducible right now — templates carry false positives, and a matcher can fire on an error page, a honeypot, or a WAF block page.
- A detection-only template (`http/technologies/*`, a version banner) is recon enrichment, not a vulnerability — fold it back into `assets.jsonl`'s `tech[]`, do not report it.
- A `critical`/`high` template that genuinely fires becomes a candidate for the matching `vulnerabilities/*` skill, carried with the same `record_coverage` / `open_proof_gap` discipline as every other recon lead. The template firing is the start of verification, not the end.

## Pipeline Scripts (run inside the sandbox)

These five stdlib scripts implement the deterministic mechanics the layers above reference. Write each to `/workspace/recon/` and run it there (cwd = `/workspace/recon`). They are the single source of truth for normalization, selector grouping, run-state, Layer-4 execution, and result merging — do not re-derive this logic ad hoc. `strix-recon-selectors` and `strix-recon-nuclei-run` resolve templates via `$STRIX_NUCLEI_BIN` (defaults to `nuclei` on PATH).

**`normalize_assets.py`** — raw httpx/naabu/wafw00f → per-origin `assets.jsonl` + host-level `host_ports.json`:

```python
# === strix-recon-normalize ===
# Build per-ORIGIN assets.jsonl (scheme + normalized host + effective port is
# the identity) from raw httpx/naabu/wafw00f output. Host-level port
# observations are kept in a SEPARATE host_ports.json and are never copied onto
# an origin's application fingerprint. Pure stdlib; run in /workspace/recon.
import json
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_PORT = {"http": 80, "https": 443}


def load_jsonl(p):
    f = Path(p)
    if not f.exists():
        return []
    out = []
    for line in f.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def split_origin(url):
    """(scheme, host, port, origin_str) or None. Lowercases host, brackets
    IPv6, applies the scheme default port when none is explicit."""
    if not url:
        return None
    if "://" not in url:
        url = "http://" + url
    u = urlsplit(url)
    scheme = (u.scheme or "http").lower()
    host = (u.hostname or "").lower()
    if not host:
        return None
    try:
        port = u.port
    except ValueError:
        port = None
    if port is None:
        port = DEFAULT_PORT.get(scheme, 80)
    disp = f"[{host}]" if ":" in host else host  # re-bracket IPv6 literals
    return scheme, host, port, f"{scheme}://{disp}:{port}"


# host-level ports from naabu (no scheme) -> host_ports.json, kept separate
host_ports = {}
for r in load_jsonl("naabu.jsonl"):
    h = (r.get("host") or r.get("ip") or "").lower()
    p = r.get("port")
    if h and p is not None:
        host_ports.setdefault(h, set()).add(int(p))
host_ports = {h: sorted(v) for h, v in host_ports.items()}
Path("host_ports.json").write_text(json.dumps(host_ports, indent=2))

# WAF joined by ORIGIN parsed from the wafw00f url, never broadcast to a host
waf_by_origin = {}
wf = Path("wafw00f.json")
if wf.exists():
    try:
        for r in json.loads(wf.read_text() or "[]"):
            o = split_origin(r.get("url", ""))
            if o and r.get("detected"):
                waf_by_origin[o[3]] = r.get("firewall")
    except json.JSONDecodeError:
        pass

# optional Layer-2 input list: lets us tell "discovery failure" (host requested
# but no probe line) from a legitimately empty inventory
requested = []
hl = Path("hosts.txt")
if hl.exists():
    requested = [l.strip() for l in hl.read_text().splitlines() if l.strip()]

origins = {}
seen_origins = set()
for r in load_jsonl("httpx_raw.jsonl"):
    req = r.get("input") or r.get("url")
    obs = r.get("url") or req
    ro = split_origin(req)
    oo = split_origin(obs)
    key_o = ro or oo        # identity = REQUESTED origin; an off-host redirect
    if not key_o:           # destination is recorded as metadata, never promoted
        continue
    scheme, host, port, origin = key_o
    seen_origins.add(origin)
    tls = r.get("tls") or {}
    failed = bool(r.get("failed"))
    tech = [t for t in (r.get("tech") or []) if t]
    if failed:
        state, reason = "failed", "httpx reported a failed probe"
    elif not tech:
        state, reason = "unknown_tech", "probe succeeded, no tech fingerprint"
    else:
        state, reason = "completed", "probe succeeded with tech fingerprint"
    redirected_offhost = bool(ro and oo and ro[1] != oo[1])
    rec = {
        "origin": origin, "scheme": scheme, "host": host, "port": port,
        "requested_origin": ro[3] if ro else None,
        "observed_origin": oo[3] if oo else None,
        "redirected_offhost": redirected_offhost,
        "url": obs,
        "status_code": r.get("status_code"),
        "title": r.get("title"),
        "webserver": r.get("webserver"),
        "tech": sorted(set(tech)),
        "cdn": r.get("cdn_name"),
        "waf": waf_by_origin.get(origin),
        "tls_info": {
            "version": tls.get("tls_version"), "cipher": tls.get("cipher"),
            "subject_cn": tls.get("subject_cn"), "sans": tls.get("subject_an") or [],
        } if tls else None,
        "ports": [port],            # ORIGIN port only; host ports -> host_ports.json
        "class": None,              # filled by the classification step
        "probe_state": state, "probe_reason": reason,
        "takeover_candidate": False,  # set true by Layer-1 subdomain_takeover triage
    }
    prev = origins.get(origin)
    if prev is None:
        origins[origin] = rec
    else:  # duplicate observation of one origin: union tech, keep best state
        union = sorted(set(prev["tech"]) | set(rec["tech"]))
        order = {"completed": 3, "unknown_tech": 2, "failed": 1, "no_response": 0}
        winner = rec if order.get(rec["probe_state"], 0) >= order.get(prev["probe_state"], 0) else prev
        winner["tech"] = union
        origins[origin] = winner

# origins requested but never probed -> explicit no_response (discovery failure).
# Tracked by full origin, so https://host:443 responding does NOT suppress a
# no_response record for https://host:8443 on the same host.
for h in requested:
    o = split_origin(h)
    if o and o[3] not in seen_origins:
        origins.setdefault(o[3], {
            "origin": o[3], "scheme": o[0], "host": o[1], "port": o[2],
            "requested_origin": o[3], "observed_origin": None,
            "redirected_offhost": False, "url": None, "status_code": None,
            "title": None, "webserver": None, "tech": [], "cdn": None, "waf": None,
            "tls_info": None, "ports": [], "class": None,
            "probe_state": "no_response",
            "probe_reason": "requested host produced no probe line",
            "takeover_candidate": False,
        })

with open("assets.jsonl", "w") as out:
    for rec in origins.values():
        out.write(json.dumps(rec) + "\n")
print(f"assets.jsonl: {len(origins)} origin(s); host_ports.json: {len(host_ports)} host(s)")
```

**`build_selectors.py`** — per-origin `assets.jsonl` → grouped, validated `nuclei_manifest.json`:

```python
# === strix-recon-selectors ===
# Build PER-ORIGIN nuclei selectors, group origins only when their normalized
# selector sets are identical, validate product tags against the installed
# template metadata, and write a machine-readable manifest. No cross-origin tag
# leakage. An empty product-tag set never becomes a bare "-tags" (which would
# scan broadly); such origins get only the bounded baseline paths.
import json, os, re, subprocess
from pathlib import Path

NUCLEI_BIN = os.environ.get("STRIX_NUCLEI_BIN", "nuclei")

TECH_TAG_MAP = {
    "wordpress": "wordpress", "drupal": "drupal", "joomla": "joomla",
    "laravel": "laravel", "nginx": "nginx", "apache": "apache",
    "apache httpd": "apache", "httpd": "apache", "tomcat": "tomcat",
    "php": "php", "jira": "jira", "jenkins": "jenkins", "gitlab": "gitlab",
    "grafana": "grafana", "spring": "spring", "kubernetes": "kubernetes",
}

# bounded baseline: an explicit subdirectory allowlist, never whole parent dirs
# (http/exposures/ + http/misconfiguration/ are hundreds of templates). The
# runner (strix-recon-nuclei-run) additionally caps the resolved template count
# at MAX_BASELINE_TEMPLATES.
BASELINE_PATHS = [
    "http/exposures/configs/",
    "http/exposures/files/",
    "http/exposures/tokens/",
    "http/misconfiguration/generic/",
    "http/misconfiguration/proxy/",
]


def norm_tech(t):
    t = (t or "").strip().lower()
    t = t.split(":", 1)[0]                        # "wordpress:6.5" -> "wordpress"
    t = re.sub(r"[\s/_-]*v?\d[\d.]*$", "", t)     # strip a trailing version token
    return t.strip()


def load_jsonl(p):
    f = Path(p)
    return [json.loads(l) for l in f.read_text().splitlines() if l.strip()] if f.exists() else []


_tl_cache = {}
def tag_has_templates(tag):
    if tag in _tl_cache:
        return _tl_cache[tag]
    try:
        out = subprocess.run([NUCLEI_BIN, "-tags", tag, "-tl"],
                             capture_output=True, text=True, timeout=60)
        ok = any(line.strip().endswith(".yaml") for line in out.stdout.splitlines())
    except (FileNotFoundError, subprocess.SubprocessError):
        ok = None                                 # nuclei unavailable -> unverified
    _tl_cache[tag] = ok
    return ok


groups = {}
for rec in load_jsonl("assets.jsonl"):
    if rec.get("probe_state") not in ("completed", "unknown_tech"):
        continue
    origin = rec["origin"]
    cls = (rec.get("class") or "").lower()

    # three-state classification: validated | unverified | invalid.
    # Only `validated` tags are safe to execute. `unverified` (nuclei was
    # unavailable at validation time) are NOT executed here; the runner
    # re-validates them before use. `invalid` (nuclei confirmed no match) are
    # dropped. A raw tech name with no table entry is treated the same way.
    validated, unverified, invalid, reasons = [], [], [], {}
    for t in rec.get("tech") or []:
        n = norm_tech(t)
        tag = TECH_TAG_MAP.get(n) or n
        if not tag:
            continue
        v = tag_has_templates(tag)
        if v is True:
            validated.append(tag)
            reasons[f"tag:{tag}"] = "validated"
        elif v is None:
            unverified.append(tag)
            reasons[f"tag:{tag}"] = "unverified (nuclei unavailable at validation time)"
        else:
            invalid.append(tag)
            reasons[f"tag:{tag}"] = "invalid: no template carries this tag"
    validated, unverified, invalid = sorted(set(validated)), sorted(set(unverified)), sorted(set(invalid))

    paths = list(BASELINE_PATHS)
    for p in BASELINE_PATHS:
        reasons[f"path:{p}"] = "bounded baseline (all in-scope origins)"
    if cls in ("admin", "auth"):
        paths += ["http/default-logins/", "http/exposed-panels/"]
        reasons["path:http/default-logins/"] = f"class={cls} (panel/auth evidence)"
        reasons["path:http/exposed-panels/"] = f"class={cls} (panel/auth evidence)"
    if rec.get("takeover_candidate"):
        paths.append("http/takeovers/")
        reasons["path:http/takeovers/"] = "takeover_candidate=true (DNS/provider evidence)"

    # group only when the executable selector picture is identical; `invalid`
    # tags never execute, so they are excluded from the grouping signature.
    sig = (tuple(validated), tuple(unverified), tuple(sorted(set(paths))))
    g = groups.setdefault(sig, {"origins": [], "tags_validated": validated,
                                "tags_unverified": unverified, "tags_invalid": invalid,
                                "template_paths": sorted(set(paths)), "reasons": {}})
    g["origins"].append(origin)
    g["tags_invalid"] = sorted(set(g["tags_invalid"]) | set(invalid))
    g["reasons"].update(reasons)

manifest = {"groups": list(groups.values()),
            "nuclei_validation": dict(_tl_cache)}
Path("nuclei_manifest.json").write_text(json.dumps(manifest, indent=2))

n_orig = sum(len(g["origins"]) for g in manifest["groups"])
print(f"nuclei_manifest.json: {len(manifest['groups'])} group(s), {n_orig} origin(s)")
for g in manifest["groups"]:
    if not g["tags_validated"] and not g["tags_unverified"]:
        print(f"  group {g['origins']}: no product tags -> baseline paths only, "
              f"NO -tags pass (an empty -tags would scan broadly)")
```

**`recon_state.py`** — run-specific stage state (replaces the old static `layer*_complete.flag`):

```python
# === strix-recon-state ===
# Run-specific stage state, superseding the old static layer*_complete.flag
# files. State is honored ONLY for the current run_id + scope_id; a file left by
# any earlier run or a different scope reads back as "pending" (never authorizes
# current-run work). Stages: pending|partial|completed|failed|skipped.
import json, sys
from pathlib import Path

STATE = Path("recon_state.json")
VALID = {"pending", "partial", "completed", "failed", "skipped"}


def _stages(run_id, scope_id):
    if not STATE.exists():
        return {}
    try:
        d = json.loads(STATE.read_text())
    except json.JSONDecodeError:
        return {}
    if d.get("run_id") != run_id or d.get("scope_id") != scope_id:
        return {}                     # stale / different scope -> ignore entirely
    return d.get("stages", {})


def main(argv):
    # get <run_id> <scope_id> <stage>
    # set <run_id> <scope_id> <stage> <status>
    op, run_id, scope_id, stage = argv[1], argv[2], argv[3], argv[4]
    stages = _stages(run_id, scope_id)
    if op == "get":
        print(stages.get(stage, "pending"))
    elif op == "set":
        status = argv[5]
        if status not in VALID:
            sys.exit(f"invalid status: {status}")
        stages[stage] = status
        STATE.write_text(json.dumps(
            {"run_id": run_id, "scope_id": scope_id, "stages": stages}, indent=2))
        print(f"{stage}={status}")
    else:
        sys.exit(f"unknown op: {op}")


if __name__ == "__main__":
    main(sys.argv)
```

**`merge_nuclei.py`** — dedup-merge per-run nuclei outputs into a fresh `nuclei.jsonl`:

```python
# === strix-recon-merge ===
# Merge the per-run, per-group nuclei output files passed as arguments into one
# deduplicated nuclei.jsonl. Dedup key = (template-id, matched location, matcher
# name). Reads ONLY the files given as args and overwrites nuclei.jsonl, so it
# never appends to results left by an earlier run.
import json, sys
from pathlib import Path


def key(r):
    tid = r.get("template-id") or r.get("templateID") or ""
    loc = r.get("matched-at") or r.get("matched_at") or r.get("host") or ""
    matcher = r.get("matcher-name") or r.get("matcher_name") or ""
    return (tid, loc, matcher)


seen, merged = set(), []
for path in sys.argv[1:]:
    p = Path(path)
    if not p.exists():
        continue
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        k = key(r)
        if k in seen:
            continue
        seen.add(k)
        merged.append(r)

with open("nuclei.jsonl", "w") as out:
    for r in merged:
        out.write(json.dumps(r) + "\n")
print(f"nuclei.jsonl: {len(merged)} unique finding(s) from {len(sys.argv) - 1} input file(s)")
```

**`run_nuclei.py`** — execute Layer 4 per manifest group with enforced flags, validated-only selectors, and a hard baseline cap:

```python
# === strix-recon-nuclei-run ===
# Execute Layer-4 nuclei per manifest group. Enforces three things the skill
# text can only advise: (1) -rl/-c/-bs and -ni are hard flags on the actual
# subprocess argv, (2) only VALIDATED selectors reach the -tags pass --
# `unverified` tags are RE-VALIDATED here (nuclei may now be available) and run
# only if they resolve, else logged skipped; `invalid` never run, (3) the
# baseline path set is capped at MAX_BASELINE_TEMPLATES resolved templates,
# truncating (with a logged reason) rather than silently running more.
import json, os, subprocess
from pathlib import Path

NUCLEI_BIN = os.environ.get("STRIX_NUCLEI_BIN", "nuclei")
RUN_ID = os.environ.get("RUN_ID", "run")
MAX_BASELINE_TEMPLATES = 50
# hard, enforced caps on every nuclei invocation (not advisory text)
BASE_FLAGS = ["-rl", "50", "-c", "20", "-bs", "20", "-timeout", "10",
              "-retries", "1", "-ni", "-silent", "-j"]

commands, skipped, summary = [], [], []


def tl_count(sel):
    """Template count selected by `sel` (e.g. ['-t', path] or ['-tags', x]);
    None when nuclei is unavailable."""
    try:
        out = subprocess.run([NUCLEI_BIN, *sel, "-tl"],
                             capture_output=True, text=True, timeout=120, check=False)
        return sum(1 for ln in out.stdout.splitlines() if ln.strip().endswith(".yaml"))
    except (FileNotFoundError, subprocess.SubprocessError):
        return None


def run(sel, out_file):
    cmd = [NUCLEI_BIN, "-l", "layer4_targets.txt", *sel, *BASE_FLAGS, "-o", out_file]
    commands.append(cmd)
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=1800, check=False)
    except subprocess.SubprocessError:
        pass


manifest = json.loads(Path("nuclei_manifest.json").read_text())
for i, g in enumerate(manifest["groups"]):
    group = f"g{i}"
    Path("layer4_targets.txt").write_text("\n".join(g["origins"]) + "\n")

    # -tags pass: validated tags execute; unverified are re-validated now
    tags = list(g.get("tags_validated", []))
    for t in g.get("tags_unverified", []):
        c = tl_count(["-tags", t])
        if c is None:
            skipped.append({"group": group, "tag": t,
                            "reason": "nuclei unavailable at validation time"})
        elif c > 0:
            tags.append(t)
        else:
            skipped.append({"group": group, "tag": t, "reason": "invalid on re-validation"})
    tags = sorted(set(tags))
    if tags:
        run(["-tags", ",".join(tags), "-s", "critical,high"],
            f"nuclei_run_{RUN_ID}_{group}_tags.jsonl")

    # -t baseline/category pass: hard MAX_BASELINE_TEMPLATES cap (truncate, warn)
    kept, total = [], 0
    for p in g.get("template_paths", []):
        c = tl_count(["-t", p])
        if c is None:
            skipped.append({"group": group, "path": p,
                            "reason": "nuclei unavailable at validation time"})
            continue
        if total + c > MAX_BASELINE_TEMPLATES:
            skipped.append({"group": group, "path": p,
                            "reason": f"baseline cap {MAX_BASELINE_TEMPLATES} reached "
                                      f"(+{c} would exceed; have {total})"})
            continue
        kept.append(p)
        total += c
    if kept:
        sel = []
        for p in kept:
            sel += ["-t", p]
        run(sel, f"nuclei_run_{RUN_ID}_{group}_paths.jsonl")
    summary.append({"group": group, "tags_run": tags,
                    "baseline_paths_kept": kept, "baseline_total": total})

Path("nuclei_commands.json").write_text(json.dumps(commands, indent=2))
Path("nuclei_skipped.json").write_text(json.dumps(skipped, indent=2))
Path("nuclei_layer4_summary.json").write_text(json.dumps(summary, indent=2))
print(f"ran {len(commands)} nuclei pass(es); skipped {len(skipped)} selector(s)")
if skipped:
    print("WARNING: skipped selectors (see nuclei_skipped.json): "
          + ", ".join(sorted({s['reason'] for s in skipped})))
```

## Testing Methodology

1. **Seed** - domains, org/legal names, known IPs, email domains, code-host org
2. **Dorking** - GitHub/Google dorking and historical URL mining from the seed alone, in parallel with the steps below (see `dorking`)
3. **Certificate transparency** - pull all logged certs per seed domain and org name (crt.sh, Censys/Shodan)
4. **SAN/CN extraction** - parse every Subject CN and SAN with `httpx -tls-grab` (or `openssl s_client`); each new name is a new seed
5. **Passive DNS** - resolve forward and reverse with `dig`; harvest historical records
6. **ASN/IP mapping** - `whois` the netblock/ASN to expand owned ranges, then sweep for live hosts
7. **Active TLS pivot** - `httpx -tls-grab` on live IPs/ports to grab SANs missing from public CT
8. **Consolidate & probe** - dedupe, `httpx` probe, classify, and route to specialists
9. **Application-layer recon** - crawl and extract JS, probe known paths/specs, content-discover, mine parameters, then rank into an attack queue (see Application-Layer Recon)
10. **Tech-matched vuln fingerprinting** - `nuclei` scoped **per origin** via `nuclei_manifest.json` (no cross-origin tag leakage), results dedup-merged, every hit a lead (see Layer 4; `standard`/`deep` modes only)

## Validation

1. Confirm each discovered asset actually resolves and serves content (live `httpx` result, not just a passive hit)
2. Attribute assets to the target via matching cert org, shared cert fingerprint, or DNS under a seed domain
3. Deduplicate vhost aliases and CDN edges down to distinct origins so the surface is not inflated
4. Record provenance (which source produced each asset) for reproducibility
5. **Scope-check redirect destinations before promoting them.** When `assets.jsonl` marks an origin `redirected_offhost`, its `observed_origin` is only a lead — confirm the destination is in scope (per `coordination/root_agent.md`'s Program Scope) before probing it as its own seed. The normalizer never auto-promotes it.

## False Positives

- CDN/edge hostnames and provider default names that are not org-owned
- Shared-hosting neighbors on the same IP (vhost co-tenancy, not the target's asset)
- Stale historical DNS entries pointing at reassigned infrastructure
- Wildcard-cert-implied hostnames that never actually resolve or serve content

## Impact

- Expanded attack surface: forgotten, staging, and internal-named hosts brute force misses
- Discovery of misconfigured or unauthenticated services fronted by leaked internal hostnames
- Attribution of shadow infra, acquisitions, and sibling domains to the target
- A prioritized, classified inventory that feeds every downstream specialist skill

## Pro Tips

1. Loop the pipeline — every SAN, PTR, and CNAME target is a new seed until the set converges.
2. crt.sh is the cheapest high-yield source (no key); Censys/Shodan add cert-fingerprint and vhost pivoting when keys exist.
3. Always cert-grab live hosts with `httpx -tls-grab` (or `openssl s_client`) — active SANs catch internal hostnames never sent to public CT.
4. Internal-looking SANs (`*.internal`, `*.svc.cluster.local`, staging names) are the highest-signal leads.
5. Wildcard SANs reveal naming conventions — seed targeted guesses instead of blind brute force.
6. Cluster by function, not product name, so the workflow generalizes to any exposed service.
7. Keep JSON output throughout so stages chain cleanly (`subfinder` → `dig` → `httpx` → `naabu`).

## Summary

Broad passive discovery — CT + TLS SAN pivoting + passive DNS + ASN/IP mapping, looped until convergence — finds the assets brute force misses, especially internal-named and forgotten services leaked through certificates. Build the inventory with `subfinder`, `httpx`, `naabu`, and CT/DNS/cert queries, probe and classify it generically, then route each interesting asset to the specialist skill for its class.
