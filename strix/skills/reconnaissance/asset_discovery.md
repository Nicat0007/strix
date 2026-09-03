---
name: asset-discovery
description: Passive asset and attack-surface discovery via certificate transparency, TLS SAN pivoting, passive DNS, and ASN/IP enumeration, plus application-layer crawling, deep JS analysis (source maps, hidden routes, secrets, dev-flags), endpoint/parameter mapping, and attack-queue prioritization
---

# Asset Discovery

Most engagements start from a small seed (one domain, one org name) but the real attack surface is far larger: forgotten hosts, staging/internal-named services, acquisitions, and infrastructure that never appears in a wordlist. Build a broad, deduplicated inventory using passive intelligence — certificate transparency, TLS certificate metadata, passive DNS, and ASN/IP data — then collapse it into a probed, classified attack surface. The aim is coverage and pivoting: every certificate, DNS record, and IP is a lead to more assets.

Only use this skill when all subdomains and related assets of the target are in scope — broad discovery pulls in hosts far beyond the seed.

Consolidation gets you a live, classified host — that is an entry point, not the attack surface. See **Application-Layer Recon** below to go past the host and map its endpoints, parameters, and hidden content.

Before or alongside the pipeline below, also run `dorking` — it needs only the seed, costs no traffic to the target's own infrastructure, and often produces the single highest-value finding of the engagement (a live committed credential).

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
2. **Live probe** with `httpx`, capturing status/title/tech/server and cert SANs in one pass — each grabbed SAN feeds back as a new seed:
   `httpx -l hosts.txt -sc -title -server -td -tls-grab -json -o assets.jsonl`
3. **Classify** assets by function from title/tech/path signals: app, API, marketing, auth, CI/CD, observability, storage, admin, VCS, mail. Cluster by role, not by a specific product.
4. **Port sweep** interesting hosts with `naabu` for non-HTTP services (DBs, caches, brokers, mgmt ports).
5. **Prioritize** by exposure and value, then hand each finding to the right specialist skill:
   - Exposed dashboards / debug / observability / metadata leaks → `information_disclosure`
   - Login/admin panels with default or weak creds → `weak_password_detection`
   - Dangling DNS / unclaimed provider resources → `subdomain_takeover`
   - Cloud consoles/metadata surfaces → `aws` / `gcp` / `kubernetes`

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

## Validation

1. Confirm each discovered asset actually resolves and serves content (live `httpx` result, not just a passive hit)
2. Attribute assets to the target via matching cert org, shared cert fingerprint, or DNS under a seed domain
3. Deduplicate vhost aliases and CDN edges down to distinct origins so the surface is not inflated
4. Record provenance (which source produced each asset) for reproducibility

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
