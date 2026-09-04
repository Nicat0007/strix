---
name: dorking
description: GitHub and Google dorking plus historical URL mining for committed secrets, exposed files/panels, and archived endpoints — verified before reporting
---

# Dorking

Crawling only finds what the live application currently links to. Dorking finds what it doesn't: secrets a developer committed and force-pushed over, files a search engine indexed before anyone noticed, and endpoints old enough to be forgotten but still reachable. Run it early — it needs only the seed (domain/org name), not a built host inventory — and it costs zero traffic to the target's own infrastructure until you follow up on a specific hit.

GitHub dorking searches public GitHub broadly by org/domain string, which can surface repos and forks outside a narrowly-scoped engagement — confirm the repo actually belongs to the target org before treating a hit as in-scope.

## Attack Surface

- Secrets committed to git history: API keys, cloud credentials, private keys, connection strings, hardcoded passwords — often still present in history even after being "removed" in a later commit
- Files and panels indexed by search engines that were never meant to be public: `.env`, backups, admin panels, directory listings, exposed API specs
- Historical/archived URLs no longer linked from the current site but still live on the origin server

## GitHub Dorking

### Dork Catalog

Scope every dork to the target with `org:<target-org>` or the domain string itself alongside the pattern:

- **Cloud credentials**: `"AWS_SECRET_ACCESS_KEY"`, `filename:.env AKIA`, `filename:credentials aws_access_key_id`, `"private_key" "client_email" filename:.json` (GCP service account), `"DefaultEndpointsProtocol=https" AccountKey` (Azure)
- **Generic API keys/tokens**: `"api_key"`, `"apikey"`, `"secret_key"` combined with `filename:.env` or `filename:config`
- **Private keys**: `filename:id_rsa`, `"-----BEGIN RSA PRIVATE KEY-----"`, `filename:*.pem`, `filename:*.ppk`
- **Env/config files**: `filename:.env`, `filename:.env.production`, `filename:application.yml password`, `filename:settings.py SECRET_KEY`, `filename:wp-config.php`
- **Connection strings**: `"mongodb+srv://"`, `"postgres://" password`, `filename:database.yml`
- **Hardcoded passwords**: `"password" language:python -test -example`
- **JWT secrets**: `"JWT_SECRET"`, `"jwt.secret"`
- **Internal hostnames/infra**: internal domain strings inside `extension:yml`/`extension:tf`/`extension:json` (Kubernetes manifests, Terraform state, CI config)
- **S3 bucket names**: `"s3.amazonaws.com/<org>"`, `"s3://<org>-"`, `filename:.travis.yml s3_bucket`

### Running GitDorker

`gitdorker` (installed at `/home/pentester/.local/bin/gitdorker`, wrapping the cloned repo at `~/tools/GitDorker`) runs a dork list against the GitHub Search API:

```bash
export GITHUB_TOKEN=<your_pat>
gitdorker -q "<target-org-or-domain>" -d ~/tools/GitDorker/Dorks/alldorksv3 -o gitdorker_results
```

The wrapper materializes a token file from `$GITHUB_TOKEN` automatically (GitDorker's own `-tf` flag expects a file, not an env var) — never write the token into a command line argument or a committed file. `Dorks/alldorksv3` is the full ~240-dork catalog; `Dorks/medium_dorks.txt` is a faster, narrower pass. The API is rate-limited to 30 requests/minute with a built-in sleep, so a full `alldorksv3` run takes several minutes — use multiple tokens (`-tf` file with one per line) if you need it faster and have more than one available.

### Sweeping Hits with trufflehog and gitleaks

GitDorker's output is a list of candidate repos/files, not proof of a live secret. Verify every hit:

```bash
# Verified-only: trufflehog checks the credential against the actual provider API where possible
trufflehog github --org=<target-org> --results=verified --json
trufflehog git https://github.com/<owner>/<repo>.git --results=verified

# gitleaks scans full git history by pattern/entropy — no liveness check
gitleaks detect --source /path/to/cloned/repo --report-format json --report-path gitleaks.json
```

`trufflehog --results=verified` is the fast path to a reportable finding — it only returns credentials it confirmed still work. `gitleaks` hits (and any raw GitDorker/dork-pattern match) are leads: pattern-matched but not liveness-checked, so treat them as `open_proof_gap` until confirmed live by trufflehog or a manual authenticated call using the credential.

## Google Dorking

The sandbox has no direct search-engine API — run these through the agent's `web_search` tool using standard dork syntax. This is fully passive: every request goes to the search engine, not to the target, until you follow up on a specific result URL.

### Dork Catalog

- **Config/env exposure**: `site:target.com filetype:env`, `site:target.com filetype:yml "password"`, `site:target.com filetype:log`, `site:target.com filetype:sql`
- **Admin/login panels**: `site:target.com inurl:admin`, `site:target.com inurl:login intitle:admin`, `site:target.com inurl:wp-admin`
- **Backup/dump files**: `site:target.com filetype:bak OR filetype:old OR filetype:backup`, `site:target.com "index of" backup`
- **Directory listings**: `site:target.com intitle:"index of /"`, `site:target.com intitle:"index of" "parent directory"`
- **Exposed API/docs**: `site:target.com inurl:swagger`, `site:target.com inurl:api-docs`, `site:target.com filetype:json "openapi"`
- **Cloud storage referencing the target**: `site:s3.amazonaws.com "<target>"`, `site:blob.core.windows.net "<target>"`
- **Error/debug pages**: `site:target.com intext:"stack trace"`, `site:target.com intext:"Fatal error"`
- **Sensitive data exports**: `site:target.com filetype:xls OR filetype:csv "password"`

A hit is a lead pointing at a URL — fetching it to confirm is normal follow-up traffic to the target, distinct from the dorking step itself, which stays entirely off-target.

## Historical URL Mining

`gau` and `waybackurls` (both in the sandbox) pull every URL an archive has ever seen for a domain — including endpoints the current site no longer links to but the origin server may still serve:

```bash
gau --subs target.com | sort -u > /workspace/recon/gau_urls.txt
waybackurls target.com | sort -u > /workspace/recon/wayback_urls.txt
```

Output is typically huge and mostly redundant (thousands of near-identical URLs differing only in a query value). Reduce before acting on it:

- Group by path + parameter names, not full URL, to collapse near-duplicates: `awk -F'?' '{print $1}' gau_urls.txt | sort -u` for path-only dedup, or `grep -oP '^\S+\?\K.*' gau_urls.txt | tr '&' '\n' | cut -d= -f1 | sort -u` to see the distinct parameter names in play
- Filter to what's actually interesting: parameterized endpoints, uncommon extensions (`.json`, `.bak`, `.sql`, `.zip`), and paths that look administrative or API-shaped
- Confirm liveness on survivors with `httpx` before doing anything else with them — an archived URL from 2019 is a lead, not a live endpoint, until probed

Feed surviving live, parameterized URLs into `asset_discovery.md`'s Application-Layer Recon phase — they're exactly the input the Parameter Discovery (`arjun`) step and the Prioritization attack queue expect, and they routinely surface endpoints the current crawl never found because nothing on the live site links to them anymore.

## Where Findings Go

- **Committed secret, verified live** (trufflehog `--results=verified` hit, or a manually confirmed authenticated call) → report via `information_disclosure`, severity scaled to what the key unlocks per its triage rubric — a broad-privilege cloud key is Critical/High, a narrowly-scoped or low-value key is lower.
- **Committed secret, pattern-matched only** (gitleaks hit or raw dork match with no liveness confirmation) → `open_proof_gap` / `needs_follow_up`, not a report. A dead or rotated key is exactly the false-positive class this discipline exists to prevent — see `analysis/counterevidence.md`.
- **Exposed file/panel/misconfig from Google dorking** → confirm it's actually reachable and actually exposes something right now (not a stale search-engine cache of a since-remediated page) before treating it as more than a lead. Route to `information_disclosure`, or to the specific class the exposure enables (default-credential admin panel → `weak_password_detection`; exposed metrics/actuator endpoint → `information_disclosure`).
- **Historical/archived parameterized URLs** → feed into the attack queue and parameter discovery in `asset_discovery.md`. These are recon leads, not findings in themselves.

## Validation

1. A committed secret is reportable only when confirmed live — verifier tool success (`trufflehog --results=verified`) or a successful authenticated call using the credential. Pattern match alone is a lead.
2. An exposed file/panel is reportable only when a fresh fetch shows it still serves the sensitive content/functionality — not a search-engine snapshot of a page since fixed.
3. Record the exact dork query, source (repo/commit URL, or search result URL), and verification method for every finding.

## False Positives

- Example/placeholder secrets in test fixtures, documentation, or `.env.example` files clearly unused in production
- Rotated/revoked keys that fail live verification
- Search-engine cached content for a page that no longer serves that content on a fresh fetch
- Public/intentionally open repos or files (an open-source project's own published key, public API docs)

## Impact

- Full cloud/infrastructure compromise via a live leaked cloud credential
- Source code and business-logic disclosure from private-repo leaks surfaced by org-wide dorking
- Direct account or data exposure from a misconfigured public file or panel
- Expanded attack surface from historical endpoints no longer linked but still live

## Pro Tips

1. Run GitHub and Google dorking early, in parallel with the passive discovery pipeline — zero traffic to the target's own infrastructure, pure upside if it lands
2. Always pair a GitDorker hit with `trufflehog --results=verified`; a raw dork match on `"AKIA"` is not evidence of a live key
3. Use multiple GitHub tokens if a large dork run hits rate limits — GitDorker throttles to 30 requests/minute per token
4. Dedupe `gau`/`waybackurls` output by path+parameter pattern before feeding it into `httpx`/`arjun`, not URL by URL — the raw output is mostly near-duplicates
5. Google dork results decay fast (search-index lag); always live-confirm before reporting, a cached hit can be months stale

## Summary

Dorking finds what crawling can't: secrets committed to history, files indexed before anyone noticed, and endpoints old enough to be forgotten but still live. Run it early and passively, and never report a hit until it's verified live — an unconfirmed dork or pattern match is a lead, not a finding.
