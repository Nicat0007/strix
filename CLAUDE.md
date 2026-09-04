# Strix (Custom Fork) — Persistent Memory

Read this file first. Jump straight to the relevant file below instead of
re-exploring the codebase. Repo root: `/home/kalimonad/strix-custom`.

## 1. PROJECT OVERVIEW

- This is a personal fork of **Strix**, an open-source AI pentesting agent,
  run from source via an **editable pip install** in a WSL venv
  (`venv/lib/python3.12/site-packages/_editable_impl_strix_agent.pth`).
- LLM backend: **DeepSeek** (`deepseek/deepseek-chat`), routed through
  `strix/config/models.py`'s `StrixProvider` (a thin wrapper over litellm so
  users can type `deepseek/deepseek-chat` instead of `litellm/deepseek/...`).
- **Key insight: the agent's real "intelligence" lives in the skill `.md`
  files and prompt templates, not in hard-coded Python logic.** Behavior
  changes (methodology, false-positive discipline, recon approach, tool
  usage patterns) are made by editing prompts/skills first — only reach for
  Python when the change is structural (limits, plumbing, model config).
- Note: there is ALSO a top-level `skills/` directory (outside `strix/`) —
  that one holds Claude-Code-facing skill packages for *using* Strix as a
  CLI tool (e.g. `penetration-testing-with-strix/SKILL.md`). It is unrelated
  to the agent's own brain. The agent's actual skills live under
  `strix/skills/` — don't confuse the two.

## 2. ARCHITECTURE MAP

| Path | What it's for |
|---|---|
| `strix/skills/*.md` (recursive) | Agent methodology & behavior — the "brain". Loaded dynamically into agent system prompts (up to 5 skills per sub-agent, see `strix/skills/README.md`). |
| `strix/report/dedupe.py` | False-positive deduplication judge. Contains `DEDUPE_SYSTEM_PROMPT` (~line 66) plus dependency-identity/CVE matching helpers used before LLM comparison. |
| `strix/agents/prompt.py` + `strix/agents/prompts/system_prompt.jinja` | System prompt rendering. `prompt.py` has `_resolve_skills()` (which skills get loaded) and `render_system_prompt()`. The jinja file is the actual prompt template text. |
| `strix/tools/` | Agent tool implementations, one subfolder per tool: `agent_browser` (own browser automation tool, no Playwright dep), `agents_graph` (sub-agent spawning/coordination), `apply_patch`, `coverage`, `finish`, `load_skill`, `mcp`, `notes`, `proxy` (Caido integration, see `caido_api.py`), `reporting`, `respond`, `shell`, `thinking`, `threat_model`, `todo`, `view_image`, `web_search`. |
| `strix/report/` | Reporting pipeline: `coverage.py` (coverage tracking), `dedupe.py` (false-positive dedup), `pricing.py` (LLM cost calc), `sarif.py` (SARIF export), `state.py`, `usage.py` (token/usage accounting), `writer.py` (report writing). |
| `strix/config/` | `settings.py` (top-level `Settings` + `LlmSettings`, `DedupeSettings`, `ContextSettings`, `RuntimeSettings`, `TelemetrySettings`, `IntegrationSettings`, `ViewerSettings`), `models.py` (model registry incl. DeepSeek model list ~line 581-598, `StrixProvider`), `tool_call_limits.py` (`TurnToolCallLimiter` — caps tool calls per assistant turn to stop degenerate poll-loop generations), `tool_call_ids.py`, `loader.py`, `codex.py`. |
| `strix/interface/` | CLI entry points and TUI. `cli.py` / `main.py` / `cli_args.py` (entry point + args), `interactive.py` / `scan_setup.py` (interactive setup flow), `tui/` (Go-based sidecar TUI: `sidecar.py`, `live_view.py`, `runtime.py`, `history.py`, plus a `go.mod`/`go.sum` — this TUI IS a compiled Go binary component), `viewer/` (report viewer: `server.py`, `report_pdf.py`, `transcript.py`, `auth.py`). |
| `strix/runtime/` | Docker sandbox client & session lifecycle: `docker_client.py`, `session_manager.py`, `backends.py`, `status.py`, `caido_bootstrap.py` / `caido_handle.py` (Caido proxy sandbox integration). |
| `containers/Dockerfile` | Sandbox image build. Confirmed tools installed: `nmap`, `sqlmap`, `nuclei` (+ `nuclei -update-templates`), `subfinder`, `naabu`, `ffuf`, `httpx`, `katana`, `gospider`, `gau`, `waybackurls` (go install), `arjun`, `dirsearch`, `wafw00f`, `semgrep`, `bandit` (pipx), `trufflehog`, `gitleaks` (release binaries), `gitdorker` (cloned + venv wrapper, needs `$GITHUB_TOKEN` at runtime), `jwt_tool`, `caido-cli` + `caido-sdk-client` (proxy). **No Playwright** — browser automation is Strix's own `agent_browser` tool, not Playwright. |
| `containers/docker-entrypoint.sh` | Sandbox container entrypoint script. |

Only `containers/Dockerfile` changes require an image rebuild; everything
else under `strix/` and `strix/skills/` takes effect immediately (see §8).

## 3. SKILLS INDEX (`strix/skills/`)

**analysis/** — cross-cutting judgment skills, always relevant to quality:
- `counterevidence.md` — Counterevidence and Closure Discipline: how/when to disprove your own findings before reporting (core to false-positive reduction).
- `fix_verification.md` — Fix Verification: confirming a patched/fixed finding is actually closed.
- `severity_calibration.md` — Severity Calibration: how to score/rate finding severity consistently.
- `source_aware_discovery.md` — Source-Aware Discovery: using available source code to guide black-box testing.
- `parameter_mutation_testing.md` — shared three-way (Control/Boundary/Adversarial) mutation set and diff-and-classify engine behind `mass_assignment.md`/`broken_function_level_authorization.md`/`idor.md`; not auto-loaded (like the other three above except counterevidence/severity_calibration — see `_resolve_skills()`), load it explicitly alongside those skills for a systematic sweep.

**cloud/** — cloud provider security testing:
- `aws.md`, `azure.md`, `gcp.md`, `kubernetes.md` — provider-specific test methodology.

**coordination/** — how the multi-agent system organizes itself:
- `root_agent.md` — Root Agent: top-level orchestrator behavior/responsibilities, incl. Program Scope and Payout Model (hard scope boundary, program-severity calibration) and Chain Findings Before Finishing (post-wave chain enumeration + PoC validation before the report is compiled).
- `source_aware_whitebox.md` — Source-Aware White-Box Coordination: coordinating sub-agents when source code is available.

**custom/** — bespoke/community skills (good place for your own additions):
- `api_spec_testing.md` — testing against an OpenAPI/Swagger spec.
- `dependency_cve_scanning.md` — SCA / supply-chain CVE scanning methodology.
- `npx_confusion.md` — npx dependency confusion technique.
- `source_aware_sast.md` — Source-Aware SAST Playbook: static analysis workflow when source is available.

**frameworks/** — framework-specific testing:
- `django.md`, `fastapi.md`, `nestjs.md`, `nextjs.md`, `wordpress.md` (WP
  **plugin**-focused: AJAX/REST entry points, `$wpdb` injection incl. the
  `ORDER BY`-identifier trap, nonce/capability guard verification, CVE-quality
  reporting; WP core is explicitly out of scope).

**protocols/**:
- `graphql.md` — GraphQL testing patterns.
- `oauth.md` — OAuth 2.0 / OIDC testing patterns.
- `saml.md` — SAML 2.0 SSO: XML signature wrapping (XSW), assertion
  replay, recipient/audience/destination confusion, IdP-initiated flow
  abuse, unsigned-assertion acceptance, XXE-in-SAML. Cross-linked with
  `oauth.md` (enterprise B2B SSO is often SAML, not OAuth/OIDC).

**reconnaissance/**:
- `asset_discovery.md` — Asset Discovery: passive host enumeration + Application-Layer Recon phase (deep JS extraction — source maps, hidden/Next.js routes, secret hunting w/ trufflehog+gitleaks verification, dev-flag/debug-artifact discovery, client-trust-assumption leads — known paths/specs, content discovery, param discovery, attack-queue prioritization). Writes to `/workspace/recon/`.
- `infrastructure_lifecycle.md` — Infrastructure Lifecycle Trust: stale/orphaned infra, subdomain/asset lifecycle risks.
- `dorking.md` — GitHub/Google dorking + historical URL mining (gau/waybackurls), verified-secret discipline. Wired into `asset_discovery.md`'s Testing Methodology as an early, parallel step.
- `account_provisioning.md` — obtaining authenticated sessions before the vuln-hunting waves. Fallback tiers in order: (1) self-registration + OTP-bypass discovery (also a finding in its own right), (2) human-in-the-loop — pauses via `respond_to_user` to ask the operator for an out-of-band code, (3) `/workspace/auth/` operator-credential fallback, (4) `needs_follow_up`. Two-account/multi-tenant provisioning; tokens saved to `/workspace/recon/auth_tokens.txt`. Wired into `coordination/root_agent.md`'s phase ordering (after threat model, before hunting waves).

**scan_modes/** — controls scan depth/behavior:
- `quick.md`, `standard.md`, `deep.md` — Quick/Standard/Deep Testing Mode.
- `diff.md` — Diff-Scoped Review: scanning only what changed.

**technologies/** — third-party service specific:
- `active_directory.md`, `auth0.md`, `electron_desktop_apps.md`, `firebase.md`, `grafana_prometheus.md`, `llm_applications.md` (LLM app security), `supabase.md`.

**tooling/** — CLI playbooks for sandboxed tools (how the agent should actually invoke each):
- `agent_browser.md` — agent-browser core (the custom browser tool).
- `ffuf.md`, `httpx.md`, `hurl.md` (security regression testing), `hypothesis.md` (differential testing), `katana.md`, `naabu.md`, `nmap.md`, `nuclei.md`, `python.md` (Python in the sandbox), `semgrep.md`, `sqlmap.md`, `subfinder.md`.

**vulnerabilities/** — per-vuln-class deep methodology (largest category, ~27 files):
- `agentic_system_security.md`, `argument_injection.md`, `authentication_jwt.md`, `broken_function_level_authorization.md` (BFLA), `browser_security.md`, `business_logic.md`, `cors_misconfiguration.md` (reflected-Origin-with-credentials, null-origin/regex/prefix/suffix bypass, preflight/cache-poisoning flaws — cross-linked from `csrf.md` and `information_disclosure.md`), `csrf.md`, `header_injection.md`, `http_request_smuggling.md`, `idor.md`, `information_disclosure.md`, `insecure_deserialization.md`, `insecure_file_uploads.md`, `llm_prompt_injection.md`, `mass_assignment.md`, `nosql_injection.md`, `open_redirect.md`, `path_traversal_lfi_rfi.md`, `prototype_pollution.md`, `race_conditions.md`, `rce.md`, `semantic_confusion.md`, `sql_injection.md`, `ssrf.md`, `ssti.md`, `subdomain_takeover.md`, `weak_password_detection.md`, `xss.md`, `xxe.md`.
- `idor.md` now carries a consolidated `## Multi-Tenant / Tenant-Boundary
  Testing` section (tenant-ID enumeration, tenant-admin/global-admin
  confusion, signup collision, cross-tenant search leaks) and is
  cross-linked with `broken_function_level_authorization.md` (horizontal
  vs vertical axis split — see §13).

`strix/skills/README.md` explains the loading mechanism: an agent is created
with `skills="skill1,skill2"` and up to 5 get dynamically injected into its
system prompt (see `_resolve_skills()` in `strix/agents/prompt.py`).

## 4. MY GOALS

- **Reduce false positives** — strengthen counterevidence/dedup discipline.
  Primary files: `strix/skills/analysis/counterevidence.md`,
  `strix/skills/analysis/severity_calibration.md`,
  `strix/report/dedupe.py` (`DEDUPE_SYSTEM_PROMPT`).
- **Add my own recon methodology** into `strix/skills/reconnaissance/`
  (currently `asset_discovery.md`, `infrastructure_lifecycle.md`) — or a new
  file there / under `strix/skills/custom/`.
- **Optimize prompts for DeepSeek**: cheap, stable tool-calling, fewer
  wasted iterations. Relevant files: `strix/agents/prompts/system_prompt.jinja`,
  `strix/agents/prompt.py`, `strix/config/models.py` (DeepSeek model
  handling), `strix/config/tool_call_limits.py` (guards against degenerate
  tool-call generations — relevant if DeepSeek does this more than other
  models).

## 5. SKILL-STRENGTHENING PROGRESS (bug-bounty depth initiative)

Priority shifted from cost-cutting to maximum bug-bounty result depth. An
audit of all 29 `strix/skills/vulnerabilities/*.md` files ranked gaps by
real-world payout impact. Strengthened so far (each extends, doesn't
rewrite, the original file):

- **Done:** `vulnerabilities/xss.md` — added WAF/filter-evasion catalog
  (`## Bypass Techniques`, organized by context), DOM clobbering, blind/OOB
  XSS workflow, deeper DOM source→sink map + bundle-tracing guidance.
- **Done:** `vulnerabilities/broken_function_level_authorization.md` —
  added framework-specific gaps (Spring/Django-DRF/Rails/Express/GraphQL+gRPC
  auth libs), systematic verb/endpoint enumeration tied to `/workspace/recon/`,
  a `## Chaining Attacks` section.
- **Done:** `reconnaissance/dorking.md` (new file) — GitHub dorking
  (GitDorker + trufflehog/gitleaks verification), Google dorking via
  `web_search`, gau/waybackurls historical URL mining. Wired into
  `asset_discovery.md` as an early testing-methodology step. Required
  **Dockerfile additions** (see below) — needs an image rebuild to take effect.

**Dockerfile additions (rebuild required):** `gau`, `waybackurls` (go
install, gobuilder stage), `GitDorker` (git clone + venv
requirements + `/home/pentester/.local/bin/gitdorker` wrapper that builds a
`-tf` token file from `$GITHUB_TOKEN` at runtime — never hardcode a token).
`trufflehog` and `gitleaks` were already present before this initiative.

**Remaining candidates, ranked by the original audit** (not yet touched):
1. `weak_password_detection.md` — no MFA/WebAuthn/passkey downgrade or
   modern anti-automation bypass coverage.
2. `mass_assignment.md` — hidden-field discovery lacks explicit
   `arjun`/schema-diff tooling call-out.
3. `xxe.md` — missing the no-egress local-DTD-reuse technique.
4. `authentication_jwt.md` — JWE named in scope but has zero dedicated
   attack technique (no `alg: dir`/padding-oracle coverage).
5. `sql_injection.md` — missing stacked/batched-query injection and
   explicit second-order (stored-now, triggered-later) SQLi.
6. `insecure_deserialization.md` — Node.js (`node-serialize`)/Kryo named
   in scope but never get a worked payload.
7. `prototype_pollution.md` — thinnest file in the set; gadget chains stop
   at the classic ones.

All other vulnerability skills were rated strong in the audit — no action
needed unless new gaps surface in testing.

## 6. AUTHENTICATED-SURFACE INITIATIVE

Trigger: the room101 run couldn't obtain an auth token (real-phone WhatsApp
OTP), so the entire authenticated surface (IDOR, BFLA, business logic) went
untested. Goal: the tool should try to obtain its own accounts/tokens, and
do deep multi-account authenticated testing with whatever it gets.

**Done:**
- **New file** `reconnaissance/account_provisioning.md` — auth-model
  mapping, self-registration + OTP-bypass techniques (dev-code leaks,
  unthrottled/predictable OTP, verification-step bypass, client-side-only
  verification — each also independently reportable), two-account/
  multi-tenant provisioning, `/workspace/auth/` operator-credential
  fallback, tokens saved to `/workspace/recon/auth_tokens.txt`.
- `vulnerabilities/business_logic.md` — new `## Authenticated Multi-Account
  Abuse` section: workflow-step skipping, coupon/referral/loyalty abuse
  across accounts, booking/reservation races (cross-links `race_conditions.md`),
  collusion patterns (one account's action benefits another).
- `coordination/root_agent.md` — new `## Provision Accounts Before
  Hunting` phase, ordered after the threat model and before the
  vulnerability-hunting waves; instructs the root agent to hand both
  accounts to IDOR/BFLA/business-logic hunters when provisioning succeeds,
  and to record a named `needs_follow_up` (not a silent skip) when it's
  blocked.
- **Extended** `reconnaissance/account_provisioning.md` with a
  `## Human-in-the-Loop Verification` tier, ordered between OTP-bypass and
  the operator-credential-file fallback. Uses `respond_to_user`
  (`strix/tools/respond/tool.py`) — the real, verified pause/ask/resume
  mechanism, confirmed by reading `strix/agents/factory.py`: it's given to
  every agent (root and subagents) whenever the run is interactive, which
  is the CLI default (`--non-interactive` is the opt-out). The wait is
  indefinite (`strix/core/execution.py`'s auto-resume timeout only applies
  to agents waiting on other agents, never on the user) — the skill notes
  to use it deliberately and batch multi-account requests into one ask.

`idor.md`/`broken_function_level_authorization.md` already assumed
two-principal testing in their existing Testing Methodology steps — left
unedited; they now get their accounts from the new skill via the root
agent's spawn instructions rather than needing their own change.

## 7. BUG-BOUNTY CAPABILITY UPGRADE, PHASE 1

Theme: the tool's edge is what happens after recon (deep JS analysis,
orchestration-level chaining, scope discipline), not running the same
scanners everyone runs. Three skill-only changes, one batch:

- **Done (JS deep analysis):** `reconnaissance/asset_discovery.md`'s
  Application-Layer Recon step 1 ("Crawl & JS Extraction") extended into a
  full deep-dive: source map extraction (incl. Next.js build
  manifest/chunk enumeration), hidden endpoint/route extraction
  (client-only-gated routes flagged as BFLA leads), secret/config hunting
  (fed through `trufflehog`/`gitleaks` for live verification), feature-flag
  and dev-artifact discovery (the exact `developmentCode`-class pattern
  from the room101 lead, named explicitly), and client-side trust
  assumptions (price calc, role checks, validation → server-side test
  leads for `business_logic.md`/`idor.md`/`bfla.md`). Discipline preserved:
  secrets need live verification, client-only routes/assumptions are leads
  not findings.
- **Done (chaining intelligence):** `coordination/root_agent.md` — new
  `## Chain Findings Before Finishing` section, ordered after the
  hunting waves report and before coverage reconciliation. Root agent
  enumerates plausible chains from actual findings/leads (info-disclosure
  + IDOR, open redirect + OAuth theft, self-XSS + CSRF, BFLA + mass
  assignment, JS-leaked secret + the route/credential it unlocks, race +
  business-logic invariant), spawns a validation subagent per chain to
  attempt a real end-to-end PoC, and reports a *validated* chain as its
  own higher-severity finding referencing the component reports. An
  unvalidated chain stays a named hypothesis; components keep their own
  individually-assessed severity — counterevidence discipline applied at
  the chain level.
- **Done (scope awareness):** `coordination/root_agent.md`'s existing
  `## Scope Decomposition` extended with `### Program Scope and Payout
  Model` — accepts a scope definition via `--instruction` or
  `/workspace/scope.txt` (in-scope wildcards, explicit exclusions,
  program rules); hard boundary on out-of-scope assets found during recon
  (recorded `not_applicable`, never tested, framed as a ban risk not just
  an invalid finding); calibrates reported severity to a program-supplied
  payout table on top of `analysis/severity_calibration.md`'s existing
  honest-rating discipline; single-target runs now say explicitly in the
  report that no broader scope was supplied.

No new files this phase; all three are extensions of existing skills.
Next test run (the room101 authenticated run) exercises all three
together with the account-provisioning and chaining/JS work from
earlier phases.

## 8. PHASE 2 — CROSS-SESSION MEMORY (audit done, design not yet approved)

**Goal:** re-running the same target should not start from zero — endpoints,
auth model, techniques tried/failed, and findings/leads should carry over
between separate `strix` invocations. The target-memory-store design below
(read/write hooks in `build_root_task()`, `~/.strix/target_memory/`,
possible new agent-facing tools) is **not implemented** — still awaiting a
design approval.

**Correction (found during a later git-hygiene audit, git-status-2026-09-04):**
Option A's stated first step — "hoist that helper out to a shared
location" — **is done and committed** (same batch as §9's
`is_whitebox_targets()` fix, committed together as their own commit on
2026-09-04): `strix/utils/target_identity.py` now holds
`target_identity()`/`local_directory()`/`remote_authority()`, and
`strix/tools/threat_model/tools.py` was refactored to import from it
rather than keep its own private copies (verified complete, not
mid-refactor — no leftover duplicate helpers, every call site updated,
`tests/test_target_identity.py` 10/10, broader
`-k "threat_model or target_identity"` sweep 39/39). This is groundwork
Option A would need either way (a shared identity function usable outside
`threat_model/tools.py`), not a decision to proceed with Option A itself —
the memory-store design proper is still unimplemented and unapproved.

**Key findings from reading `strix/report/state.py`, `strix/report/writer.py`,
`strix/core/paths.py`, `strix/core/runner.py`, `strix/core/execution.py`,
`strix/core/sessions.py`, `strix/core/agents.py`, `strix/runtime/session_manager.py`,
`strix/runtime/docker_client.py`, `strix/interface/cli.py`, `strix/interface/cli_args.py`,
`strix/tools/notes/tools.py`, `strix/tools/coverage/tools.py`,
`strix/tools/threat_model/tools.py`:

1. **Everything Strix persists today is keyed by `run_name`, not by target.**
   `strix_runs/<run_name>/` holds `run.json`, the executive report, SARIF,
   `vulnerabilities.json`/`.csv`/`vulnerabilities/*.md`, and `.state/`
   (`agents.json` — full `AgentCoordinator` graph snapshot; `agents.db` — a
   SQLite `SQLiteSession` per agent, i.e. **full LLM conversation history**;
   `coverage.json`, `notes.json`, `threat_models.json`, `todos.json` — mirrors
   of module-level in-memory stores). A fresh run = fresh `run_name` = all of
   these start empty, by design — `threat_model/tools.py` and
   `notes/tools.py` say so explicitly in their own docstrings ("nothing
   carries over from an earlier run"). All of it does survive indefinitely
   on the host disk, but nothing ever reads an *old* run's directory again
   unless you `--resume` that exact `run_name`.
2. **`--resume` is a continuation mechanism, not a memory system.** It
   requires the same `run_name`, refuses `--target`/`--target-list` (see
   `cli_args.py`'s `_load_resume_state`), restores the full agent graph
   *and replays every non-terminal agent's entire prior LLM conversation*
   from `agents.db`. That's expensive (opposite of the token-saving goal)
   and shaped for "pick this interrupted run back up," not "start a new
   assessment against a target I've scanned before." Bending it to do the
   latter would mean loosening the scope/authorization guard in
   `build_scope_context` (`authorization_source: strix_platform_verified_targets`)
   and touching the `is_resume` branch that drives `AgentCoordinator`
   restoration in `runner.py` — high blast radius for the wrong-shaped tool.
   **Not recommended as the vehicle for Phase 2.**
3. **`/workspace/recon/` (the skill convention in `asset_discovery.md` /
   `root_agent.md`'s "Reuse Recon Artifacts") is 100% ephemeral for
   black-box (URL/IP) targets.** The sandbox container is destroyed by
   `session_manager.cleanup()` at the end of every run (default
   `cleanup_on_exit=True`); the only cross-process cache
   (`_SESSION_CACHE`) is in-memory and dies with the CLI process. It only
   *looks* persistent for white-box targets because a `local_code`/
   `repository` target is a host directory bind-mounted read-write — an
   incidental side effect of source mounting, not a recon-persistence
   feature. So today, re-running a black-box target really does re-crawl
   from nothing, confirming the suspicion behind this phase.
4. **The right foundation already exists, just scoped to the wrong lifetime.**
   `notes/tools.py`, `coverage/tools.py`, and `threat_model/tools.py` are
   plain `@function_tool`s that run in the **host** Python process (not
   inside the sandbox) — they already have host filesystem access, keep a
   module-level dict, mirror it to `{state_dir}/*.json`, and hydrate on
   startup via `hydrate_X_from_disk(state_dir)` (called from
   `run_strix_scan()` in `runner.py`). `threat_model/tools.py` additionally
   already has `_target_identity()` — a normalizer that collapses a
   URL/host/repo-checkout's many spellings (scp vs. https git remotes,
   path vs. URL, trailing slash, default ports) onto one canonical key.
   That's exactly the "same target across separate runs" identity function
   Phase 2 needs, already written and battle-tested by threat models within
   a run.

**Design options, ranked (none implemented):**

- **A — Recommended. Target-scoped host-side memory store**, same shape as
  `threat_model/tools.py` but keyed by `_target_identity()` (hoist that
  helper out to a shared location) and stored *outside* any single run's
  `.state/` dir — e.g. `~/.strix/target_memory/<hash>.json`, alongside the
  existing `~/.strix/cli-config.json`. Content is a **curated distillation**
  (known endpoints/auth model, confirmed findings by id/severity/status,
  techniques tried and their outcome, open `needs_follow_up` leads) written
  once at scan end (from the data `finish_scan`/coverage/vulnerabilities
  already have), not a raw dump — token cost stays low. Read at scan start
  and folded into `build_root_task()` (pure Python string, no jinja
  changes needed — same pattern as `_render_diff_scope`). Touches none of
  `execution.py`/`sessions.py`/`runtime/`/Docker; fails open on any error
  like the existing coverage/SARIF writers do. Lowest blast radius.
- **B — Manual stopgap, zero code.** Hand-copy/curate a summary from one
  run's `.state/notes.json` or `threat_models.json` and pass it back in via
  `--workspace-file` on the next run against the same target, with a skill
  telling agents to read it first. Works today, but is operator-driven,
  doesn't dedupe/match target identity automatically, and doesn't compound
  on its own — a bridge, not the real answer.
- **C — Extend `--resume` to reload more.** Rejected: fights `--resume`'s
  existing contract (see finding 2), forces loosening scope validation,
  and even if done would just reimplement Option A behind a worse-fitting
  interface.
- **D — Persist raw `/workspace/recon/*` artifacts across runs** (export on
  teardown, bind-mount back in keyed by target identity). Higher blast
  radius (touches `session_manager.py`/sandbox bring-up, the highest-risk
  code in the system) and no staleness/invalidation story (a subdomain
  list or JS bundle from three weeks ago presented as current truth is
  worse than nothing). Worth layering on top of A later, not a Phase 2
  opener.

**Skill-vs-code split:** the persistence + identity-keyed read/write
plumbing genuinely requires a small Python module (Option A) — there is no
existing tool an agent can call that reaches another run's directory, and
skill instructions alone cannot invent that access. Once that plumbing
exists, essentially everything else is skill work, matching this repo's
usual approach (§1): what's worth remembering, how to phrase it, and —
important — how much to *trust* a prior finding versus re-verify it
(a target may have patched something; a WAF rule may have changed since a
technique "failed") belongs in `root_agent.md` / `counterevidence.md`, not
in the persistence code.

**Not yet decided / needs a design pass before any code:** exact storage
schema and size cap, whether target memory is auto-managed (engine reads/
writes automatically, no new agent-facing tool) or exposed as
`get_target_memory`/`update_target_memory` tools, how multi-target scans
key their memory, and how "stale" entries get flagged to the agent rather
than trusted blindly.

## 9. SOURCE-AWARE SAST AUDIT (separate track — real CVE-hunting in OSS repos)

Goal: use Strix to read open-source projects' code on GitHub and find real,
exploitable, CVE-worthy bugs — not black-box web testing. **Audit only, no
code changed.** Read `strix/skills/analysis/source_aware_discovery.md`,
`strix/skills/coordination/source_aware_whitebox.md`,
`strix/skills/custom/source_aware_sast.md`,
`strix/skills/custom/dependency_cve_scanning.md`,
`strix/skills/analysis/counterevidence.md`, `strix/skills/analysis/fix_verification.md`,
and traced the actual code path.

**Headline finding — a real bug, top priority to fix before anything else:**
`strix --target https://github.com/user/repo` (the first example in
`cli_args.py`'s own `--help` epilog) **never enables source-aware mode.**
`infer_target_type()` classifies a GitHub/git URL as `"repository"`, which
does get cloned and bind-mounted into `/workspace` (`collect_local_sources()`
handles both `local_code` and `repository` targets) — but the flag that
actually turns on source-aware mode, `is_whitebox = any(t.get("type") ==
"local_code" for t in targets)` in `strix/core/runner.py:346`, only checks
for `"local_code"`, never `"repository"`. That flag drives `_resolve_skills()`
in `strix/agents/prompt.py`, which is the ONLY place that auto-loads
`coordination/source_aware_whitebox`, `custom/source_aware_sast`,
`analysis/source_aware_discovery`, and `analysis/fix_verification`. Net
effect: the entire SAST toolchain/methodology below silently never runs for
a `repository` target — the code sits in `/workspace` and gets the default
black-box-oriented skillset instead. `strix/interface/utils.py`'s
`is_whitebox_scan()` (used for telemetry only) has the identical
`"local_code"`-only bug, and `root_agent.md` itself says *"When the target
includes a repository, derive [the threat model] up front"* — strong
evidence this is an unintentional gap, not a design choice. **Today, the
only way to get real source-aware mode is to `git clone` yourself and pass
`--target ./local-clone`.**

**Methodology quality (once source-aware mode actually fires) — genuinely
strong:** `source_aware_discovery.md`'s family-sweep catalog (deserialization/
codec enumeration, XML parser factories, zip-slip containment-before-write,
SAML's validated-vs-consumed mismatch, auth state-machine rebind bugs) reads
like real vulnerability-research methodology, not linter categories.
`source_aware_sast.md` explicitly refuses scanner output as final truth and
requires a traced PoC before reporting; `counterevidence.md`'s
confirmed/ruled_out/open_proof_gap discipline with its list of non-excuses
(generic library trust, safe sibling, fail-open control, missing info ≠
safety) is exactly the FP-control rigor CVE credibility needs.
`dependency_cve_scanning.md`'s SCA pipeline is CVE-submission-quality: a real
reachability evidence ladder (`not_imported → imported →
vulnerable_symbol_used → reachable_call_path`), transitive-CVE attribution,
contextual CVSS re-scoring — and the tool itself (`create_dependency_report`)
rejects an unevidenced `reachability` claim. **No dedicated taint/dataflow
engine, though** — no CodeQL, no Semgrep taint mode; source-to-sink tracing
is the LLM agent manually reading code per the discovery methodology (strong
given how well-written that methodology is, but not deterministic/complete
like a real interprocedural taint tool). The one place with a genuine
call-graph tool is Go SCA reachability via `govulncheck`; every other
ecosystem falls back to import+symbol grep, which the skill itself honestly
flags as weak against dynamic dispatch/DI/reflection.

**Ranked gaps for real CVE-hunting, after the gating bug:**
1. No CodeQL — the single highest-value missing tool for finding real
   interprocedural dataflow bugs in OSS repos specifically (free for OSS,
   many target repos already have CodeQL configs to cross-reference).
2. No language-detection-driven tool selection — the baseline bundle
   hardcodes `semgrep --config p/default,p/golang,p/secrets`; only Go gets
   its own registry pack. **Bandit is installed in the image but only ever
   invoked from `frameworks/django.md`** — a non-Django Python project gets
   no bandit run at all by the generic path.
3. Reachability rigor is uneven — real call-graph analysis only for Go
   (govulncheck); every other ecosystem is grep-level.
4. No git-history/cross-version diffing technique (mining commit history or
   tag diffs for undisclosed "silent" security fixes to find N-days in
   still-deployed older versions) — a classic high-yield real-world
   technique, absent entirely. `scan_modes/diff.md` is PR-review scoping,
   not this.
5. No responsible-disclosure / CVE-submission guidance — everything targets
   Strix's own internal report format for an engagement/bug-bounty program;
   nothing about coordinated disclosure to OSS maintainers, GHSA/CNA
   submission format, or embargo timing before a public PoC.
6. Framework-specific sink catalogs (e.g. `frameworks/django.md`'s good
   bandit/semgrep/pip-audit list) are siloed — `source_aware_sast.md` never
   says "detect the stack, then load the matching `frameworks/*` skill."

**Reuse confirmed:** black-box and white-box share almost everything —
`_resolve_skills()` *adds* whitebox skills on top of the always-loaded base
rather than branching, so `counterevidence.md`, `severity_calibration.md`,
the coverage ledger, the threat-model tool, `create_vulnerability_report`/
`create_dependency_report`, the full `vulnerabilities/*.md` library, and
`root_agent.md`'s chaining pass are identical in both modes. Recon
(`asset_discovery.md`) is the one appropriately-separate piece — it doesn't
apply to pure source, so `source_aware_discovery.md` is its own
purpose-built white-box analog rather than a reuse. This is the right
design; it just never engages today because of the gating bug above.

**Fixed** (isolated patch, nothing else from the ranked list touched yet):
`is_whitebox` now also fires for `repository` targets, not just
`local_code`. Rather than patching the same `t.get("type") == "local_code"`
expression in two places again (that duplication is exactly how the bug
happened — `core/runner.py:346` and `interface/utils.py`'s
`is_whitebox_scan()` had it independently), both now delegate to one new
shared predicate: `is_whitebox_targets()` in `strix/core/inputs.py` (next to
`build_scope_context`/`build_scan_targets`, which already deal with target
dicts the same way), checking `t.get("type") in {"local_code",
"repository"}`. `core/runner.py` already imported from `core.inputs`, so its
fix is a one-line call-site swap; `interface/utils.py` gained one new
import (`strix.core.inputs` — correct layering direction, interface already
depends on core elsewhere; core has zero interface imports, so no cycle) and
`is_whitebox_scan()` now just delegates. Traced `_resolve_skills()` and all
four source-aware skill files first to confirm nothing downstream assumes a
`local_code`-only path (`apply_patch` is wired unconditionally per-run
regardless of target type; the "this is the user's real directory" wording
in `build_root_task()` is already keyed off target *type* directly, not
`is_whitebox`, so it correctly never mislabels a temp clone) — safe to widen.
Added regression tests in `tests/test_local_sources.py`
(`test_a_cloned_repository_target_is_whitebox` + siblings covering
local_code / web-only / mixed / no-targets cases). Full suite: 1209 passed,
1 skipped (pre-existing unrelated failure in `test_pricing.py` for a stale
litellm model-pricing entry, confirmed present before this change too, not
touched). End-to-end check: a bare `repository` target now resolves all four
skills (`coordination/source_aware_whitebox`, `custom/source_aware_sast`,
`analysis/source_aware_discovery`, `analysis/fix_verification`) through
`_resolve_skills()`. Ranked methodology gaps (CodeQL, language-aware tool
selection, etc.) are still untouched — next phase.

## 10. WORDPRESS PLUGIN SAST SKILL (new track — real CVE-hunting)

Goal: use the now-working source-aware mode (§9) specifically to find real,
CVE-worthy vulnerabilities in WordPress **plugins** — a security model
(nonces, capability checks, `$wpdb->prepare`, `esc_*`/`sanitize_*` APIs,
`wp_ajax_*`/`wp_ajax_nopriv_*`) that generic PHP SAST doesn't understand.
Skill-only, no Dockerfile change (WP-specific semgrep rules are a planned
future addition, not added yet).

**New file:** `strix/skills/frameworks/wordpress.md`, matching
`django.md`'s structure (Attack Surface / Key Vulnerabilities / Testing
Methodology / Validation / False Positives / Impact / Tooling / Summary,
plus two new sections this domain specifically needed):

- **Entry Points** — explicit instance discipline (every `wp_ajax_nopriv_*`
  action, REST route, shortcode, admin-post handler, widget, meta box, and
  settings sanitizer is its own candidate, per `source_aware_discovery.md`'s
  "one root cause is not one candidate" rule), with concrete `rg`/`ast-grep`
  enumeration commands for each.
- **Dangerous Sinks by Vulnerability Class** — SQLi (`$wpdb`, including the
  `ORDER BY`/identifier trap that placeholders don't cover — this is the
  exact shape of CVE-2024-1071-class bugs), XSS (`esc_*` context-matching),
  CSRF (nonce action-string binding), broken access control
  (`current_user_can()` capability-strength, not just presence), file
  handling (traversal/upload RCE), PHP object injection (with an explicit
  gadget-chain caveat), SSRF (`wp_remote_*` vs. `wp_safe_remote_*`), LFI/RFI.
- **The Real Control — Verify the Guard, Don't Assume It** — the
  `counterevidence.md` discipline applied to WP-specific guards: a
  `prepare()` call, a `current_user_can()` check, or a nonce check can each
  *look* present and still not cover the reachable path (wrong capability
  string, mismatched nonce action, `check_ajax_referer($die=false)` with the
  return value never checked, a guard on `wp_ajax_*` that doesn't exist on
  the `wp_ajax_nopriv_*` sibling). This section is the FP-control core of
  the whole skill.
- **Reporting for CVE Credibility** — affected version from the
  `Stable tag:`/`Version:` header, full source-to-sink trace with
  `file:line` per hop, a literal PoC request, WP-context impact, and an
  explicit routing note: this is 0-day discovery in first-party plugin
  code, so it files via `create_vulnerability_report`, never
  `create_dependency_report` (that tool is for already-published CVEs
  found via lockfile/manifest scanning — not applicable here).

**Wiring:** confirmed `frameworks/*.md` skills have no existing
code-level auto-detection — they're loaded only by root-agent judgment
(`skills=` at spawn time or the `load_skill` tool), and no other framework
skill (django/fastapi/nestjs/nextjs) was wired anywhere before this either.
Added one paragraph to `custom/source_aware_sast.md` (always loaded for
every whitebox scan since §9's fix), matching its existing "load skill X
when Y" precedent (the same paragraph shape already used for
`npx_confusion`/`infrastructure_lifecycle`/`llm_applications`): detect a
`Plugin Name:`/`Theme Name:` header, a WordPress-style `readme.txt`, a
`wp-content/plugins|themes/` path, or heavy `add_action`/`$wpdb` usage, then
`load_skill(["wordpress"])`. Did not touch `root_agent.md` — the
already-established convention lives in `source_aware_sast.md`, and it
reaches root + every subagent it spawns without a second wiring point.

**Verified (skill-only change, no methodology test run yet — user will
calibrate against Ultimate Member 2.8.2 / CVE-2024-1071 directly):**
`load_skills(["wordpress"])` resolves with no name ambiguity against the
other 4 framework skills; `get_available_skills()`'s `frameworks` category
now lists `wordpress`; the wiring paragraph is present in the loaded
`source_aware_sast` body; `tests/test_skill_dir_extension.py` (20 tests,
covers skill resolution/loading generally) still passes unchanged.

**Extended same file with a "0-Day Hunting" track** (the user's actual
goal — finding *new*, undisclosed bugs in under-scrutinized plugins and
getting CVEs assigned, not just confirming known ones): added a new
`## 0-Day Hunting — Target Triage and Exhaustive Coverage` section (between
"The Real Control" and "Testing Methodology") with three parts —
**target-selection signals** (bug-likelihood triage: attack-surface presence
× low-maturity code smells — raw `$_REQUEST` at a sink, no `prepare()`, no
nonce/capability call anywhere in a handler, `mysql_*`/`extract($_POST)`-era
patterns, thin `readme.txt` maintenance history, low install count with real
functionality); **exhaustive-coverage discipline** as the 0-day false-negative
guard (no known CVE to anchor on, so every entry point must be enumerated
before any single one is deep-traced, with `record_coverage` on every swept
surface including clean ones); and an explicit "**FP discipline is absolute**"
callout (a disputed 0-day submission burns reputation permanently — no
exceptions, `open_proof_gap`/low confidence over any rounded-up claim).
Also extended `## Reporting for CVE Credibility` (retitled `...and
Responsible Disclosure`) with two fields the original pass omitted — a
required `CWE-NNN` (CNA intake forms ask for it explicitly) and a
`remediation_steps`-only "suggested fix" (explicitly *not* routed through
`fix_before`/`fix_after`/`apply_patch`, since there's no working tree of
someone else's plugin to patch) — plus a new **Responsible Disclosure**
subsection with a hard guardrail: Strix has no maintainer-contact/CNA-filing
tool, and even though `agent_browser`/`web_search` could technically reach a
submission form, the skill explicitly forbids using them to submit or
publish anything — disclosure is stated as a human/operator decision the
report hands off to, never an autonomous agent action.

## 11. COST-EFFICIENT ORCHESTRATION + BUSINESS-LOGIC QA (design approved)

New track: two reinforcing goals — (1) deterministic tools (free) do the
heavy entry-point mapping once, LLM tokens spend only on logic reasoning
(fixes the calibration run's 7-agents-each-re-reading-everything pattern),
and (2) a source-code business-logic QA methodology (scanners can't find
"the logic is simply wrong" bugs — authz ordering, calculation
manipulation, state-machine bypass — only a code-reading QA pass can).
Audit confirmed both gaps precisely: `root_agent.md` already has "Reuse
Recon Artifacts" for black-box but **no white-box equivalent** (triage
artifacts sit in `/workspace/.source-aware/` as raw tool JSON with no
instruction that later agents should read them instead of re-deriving their
own map); `business_logic.md` is **100% black-box/dynamic** (every verb
assumes a live target — zero "read this function, name its invariant, walk
every caller" methodology); and the 7-agent fan-out traces partly to
`wordpress.md`'s own "Dangerous Sinks by Vulnerability Class" reading as 8
separate per-class headers with no explicit "one agent, one entry-point
slice, all classes" instruction — despite `root_agent.md` already stating
that principle generically ("Consolidate Related Classes," "Bound
Parallelism").

**Step 1 done (orchestration only; `business_logic.md`'s QA methodology is
Step 2, not started):**

- **`custom/source_aware_sast.md`** — new `## Entry-Point Map (Build Once,
  Reuse Everywhere)` section right after the baseline bundle. Folds
  semgrep + ast-grep hits into one flat, file:line-sorted list and — same
  pass, zero LLM cost — greps for logic-bearing function names (price/
  total/amount/balance/calculate/etc., and can_/validate_/check_/authorize/
  transition/approve/etc.) into `/workspace/.source-aware/entry_points.md`,
  explicitly for the future business-logic QA agent to prioritize from.
  Semgrep/gitleaks/trivy/ast-grep commands themselves untouched, exactly as
  instructed. **Caught and fixed a real bug before finalizing:** the first
  draft `json.loads()`'d `ast-grep.json` as one blob, but `sg run
  --json=stream` (already used earlier in this same file) emits **NDJSON**
  — one JSON object per line — so that would have silently dropped every
  ast-grep hit via the `except: continue` on any file with more than one
  match. Fixed to parse it line-by-line; verified against synthetic
  multi-line NDJSON that all hits now appear, correctly sorted alongside
  semgrep's.
- **`coordination/source_aware_whitebox.md`**'s "Agent Delegation
  Guidance" — replaced "keep child agents specialized by vulnerability/
  component as usual" with: partition by entry-point-map slice (not vuln
  class — one agent's mandate spans every sink/guard class for its
  assigned rows), every subagent reads `entry_points.md` first and does
  not re-run scanners or re-derive the map, parallelism scales by
  splitting map rows across same-mandate agents, and a dedicated separate
  agent for business-logic QA (not folded into the injection/access-control
  agent — different reasoning in kind).
- **`coordination/root_agent.md`**'s "Reuse Recon Artifacts" → retitled
  "Reuse Recon and Triage Artifacts", with a new paragraph extending the
  exact same discipline to white-box: point subagents at
  `/workspace/.source-aware/entry_points.md` instead of re-reading source
  from scratch, symmetric with the existing recon-artifact paragraph.
- **`frameworks/wordpress.md`** — one line after its entry-point `rg`
  sweeps noting hits should fold into the shared `entry_points.md` map
  rather than a separate scratch note.

**Verified:** both Python heredocs in `source_aware_sast.md` (the
pre-existing `sg-targets.txt` builder and the new entry-point folder)
syntax-check clean; the new distillation logic tested against synthetic
semgrep + multi-line NDJSON ast-grep fixtures produces correct, sorted
output; the logic-bearing-function `rg` command tested against synthetic
PHP and matches `calculate_total`/`current_user_can_edit`/`validate_order`
as intended. End-to-end: `_resolve_skills(requested=['wordpress'],
is_whitebox=True, is_root=True)` still resolves cleanly, and the loaded
content of all four edited files carries the expected cross-references
(`entry_points.md` in both `source_aware_sast` and `wordpress`,
"Partition by entry-point-map slice" in `source_aware_whitebox`, "Reuse
Recon and Triage Artifacts" in `root_agent`). `tests/test_skill_dir_extension.py`
(20 tests) still passes unchanged. Note: internal-category skills
(`coordination/*`, `analysis/*`, `scan_modes/*`) are deliberately excluded
from `get_all_skill_names()`/bare-name `load_skill` lookup by design
(`_INTERNAL_SKILL_CATEGORIES` in `strix/skills/__init__.py`) — they only
resolve via their qualified `category/name` path, which is how
`_resolve_skills()` actually loads them; an initial bare-name sanity check
against `source_aware_whitebox` was a false alarm on my part, not a real
bug, confirmed by loading it qualified.

**Step 2 done:** new `## Source-Code QA Methodology (White-Box)` section in
`vulnerabilities/business_logic.md`, inserted between "Chaining Attacks"
and the existing (untouched) "Testing Methodology" — extends, doesn't
rewrite; every prior black-box section is unchanged. Centered on one
question per logic-bearing function from the entry-point map: *"what does
this function ASSUME, and can an attacker violate that assumption before
this line runs?"* Six techniques, each with a short vulnerable/safe
pseudocode pair: **authorization-order flaws** (checked value ≠ used
value — named as the exact class behind the Ultimate Member REST IDOR:
authentication present, object-level authorization absent), **calculation/
amount manipulation** (client-trusted totals, once-computed-vs-re-derived,
sign/rounding), **state-machine bypass** (every caller — not just the UI
controller — must recheck current state; admin/cron/webhook/second-route
paths are where the guard is usually missing), **invariant violations**
(name the invariant in one sentence, then audit every write path for
whether it re-derives or just trusts the caller), **trust-boundary
confusion** (the source-specific test: "if I called this function
directly, bypassing every normal caller, would it still be safe?"), and
**logic-level TOCTOU** (check-then-act pairs with no atomic guarantee —
explicitly cross-linked to `race_conditions.md` as "where to look" vs.
"how to fire it"). Followed by a **QA Reading Protocol** (state the
assumption → enumerate every caller/path, including non-obvious ones →
check each → any that fails is a candidate) and a **Discipline** closing
section stating explicitly this generates hypotheses, not verdicts —
every candidate still passes `counterevidence.md`'s full gate, dynamic
Validation still applies where a live target exists, and a disputed
logic-bug submission burns reputation exactly like a bad SQLi report.
Also updated the skill's frontmatter `description` to mention the new
white-box coverage, for skill-selection discoverability.

**Verified:** all new section headers render correctly (`## Source-Code QA
Methodology (White-Box)` through 6 numbered `###` subsections, `###  QA
Reading Protocol`, `### Discipline`), skill still loads via
`get_all_skill_names()`/`load_skills(["business_logic"])` (19,920 chars),
every key phrase confirmed present in the loaded content (whitespace-
normalized, since the file's existing ~78-80-char soft-wrap style split
one check phrase across lines in a naive substring test — a false alarm on
my part, not a bug in the file). Confirmed a business-logic-focused
subagent spawned with `skills=["wordpress", "business_logic"]` in a
whitebox scan actually resolves both alongside `source_aware_discovery`/
`source_aware_sast` (the map it reads from) via `_resolve_skills()`.
`tests/test_skill_dir_extension.py` + the Phase-2/target-identity test
files (90 tests total) still pass unchanged.

**Both steps of this track are now done.** Next: batch-test cost (Step 1's
entry-point-map reuse + lean agent partitioning) and quality (Step 2's QA
methodology) together on a real plugin, per user's plan.

## 12. DEV WORKFLOW RULES

- Skill `.md` files are read at runtime — editing them takes effect on the
  **next `strix` run**, no rebuild/reinstall needed.
- Python changes under `strix/` also take effect immediately — this is an
  **editable install** (`pip install -e`).
- Only `containers/Dockerfile` (or `docker-entrypoint.sh`) changes require
  rebuilding the sandbox Docker image before they take effect.
- **I run `strix` myself from a WSL terminal — you can edit files but
  cannot execute `strix` from here.** When a change needs testing, tell me
  the exact command to run (e.g. `strix --target <url> --mode quick`) rather
  than attempting to run it yourself.
- Keep every change small and reversible. Note what changed and why, so
  changes can be cleanly reverted with `git` if a prompt/skill edit makes
  DeepSeek behave worse.

## 13. ACCESS-CONTROL COVERAGE AUDIT + 2024-25 BOUNTY-TREND GAP LIST
   (audit + design only — plan approved by user, not yet implemented)

Two linked audits, both read-only. Read `vulnerabilities/idor.md`,
`vulnerabilities/broken_function_level_authorization.md`,
`vulnerabilities/business_logic.md`, `analysis/counterevidence.md`,
`analysis/severity_calibration.md`, `protocols/oauth.md`, and grepped the
whole skill tree for CORS/tenant/default-creds/metadata/SAML coverage.

**Task 1 — vertical vs horizontal access-control scorecard:**

- **Vertical (priv-esc): A-.** Real home is `bfla.md` — Actor×Action
  matrix, exhaustive verb/endpoint sweep against every recon'd endpoint
  with a low-priv token ("every actor × action cell... not just the
  handful that looked interesting"), 5 framework-specific gap catalogs
  (Spring/DRF/Rails/Express/GraphQL+gRPC), UI-vs-API diffing, chaining.
  `idor.md` only gestures at vertical as a one-line variant of its own
  swap technique — correctly deferring depth to bfla.md.
- **Horizontal (BOLA/cross-tenant): A.** `idor.md` is the deepest file
  audited — 2-principal minimum in its own Testing Methodology, dedicated
  GraphQL/gRPC/WebSocket/microservices/multi-tenant/file-storage/job-object/
  secondary-IDOR sections, a full Bypass Techniques catalog, and an Impact
  Escalation gate that forces real cross-user content/state-change proof
  before filing (not just a status-code diff).
- **BOLA vs BFLA separation: B.** Conceptually clean (idor.md's own scope
  lists Horizontal/Vertical/Cross-tenant/Cross-service as distinct rows),
  but **zero cross-references exist between `idor.md` and
  `broken_function_level_authorization.md`** despite bfla.md's own
  Chaining section naming "BFLA + IDOR" — cheap fix, not a structural
  blur.
- **Write/delete IDOR depth** (the $20K GitLab / $15K Snapchat point):
  genuinely strong, not an afterthought — Bulk & Batch Operations, Job/Task
  Objects (cancel/approve others' jobs), Impact Escalation explicitly
  demanding before/after proof of state change for write-capable IDOR, and
  `severity_calibration.md:48-51` hard-codes "read → write on protected
  objects" as a High-severity bump factor.
- **Non-obvious IDOR surfaces**: import/export ✅, bulk/batch ✅,
  UUID-not-enough/leaked-ID sourcing ✅ (own section + Pro Tip). Partial:
  mobile/legacy-API-version is only an incidental scope sentence — BFLA
  has the equivalent named pattern ("legacy vs v2, mobile vs web... weaker
  checks") that IDOR lacks the object-level mirror of. Gaps: no GraphQL
  *mutation* BOLA example (only a query example — BFLA's mutation example
  is role-escalation, function-level, not this), and nested/second-order
  object-reference pivoting (auth checked on the parent, not the child you
  pivot to) is not named as its own technique despite relationship-field
  names being listed.

**Task 2 — ranked gap list vs 2024-25 HackerOne/Bugcrowd trends** (access
control/misconfig rising, XSS declining, business-logic/chaining as the
AI-resistant value zone), ranked by real payout impact if added, none
implemented yet:

1. **CORS misconfiguration has no dedicated methodology** — only 2 passing
   mentions in the whole tree (`csrf.md:55`, `information_disclosure.md:83`).
   No reflected-Origin-with-credentials testing, null-origin bypass,
   regex-bypass patterns (`evil-example.com`, subdomain-takeover-feeds-CORS),
   or preflight-cache-poisoning. **New file** `vulnerabilities/cors_misconfiguration.md`,
   cross-linked from `information_disclosure.md` and `idor.md`/
   `business_logic.md` (CORS is how a reflected-Origin bug becomes
   session/data theft). Skill-only. Highest-ranked: thinnest spot found,
   matches the stated misconfiguration-rising trend directly.
2. **No SAML coverage anywhere in black-box protocol skills** — enterprise
   B2B SSO is very often SAML (XML signature wrapping, assertion replay,
   recipient/audience confusion, IdP-initiated abuse), and the only mention
   in the repo is one white-box-only line in `source_aware_discovery.md`.
   **New file** `protocols/saml.md`. Skill-only. Lower frequency than CORS
   but typically full org account-takeover when it hits — among the
   highest per-bug payouts in the SSO category.
3. **Multi-tenant boundary testing is correct but scattered**, not a
   systematic checklist — split across `idor.md`'s Multi-Tenant subsection,
   `business_logic.md`'s Multi-Tenant Isolation + Authenticated
   Multi-Account Abuse, and `root_agent.md`'s spawn instruction. Missing:
   tenant-ID enumeration via incrementing shared-infra IDs,
   tenant-admin-vs-global-admin confusion, self-service-signup tenant
   collision, cross-tenant search/autocomplete existence leaks.
   **Extension**: consolidate + deepen into a new `## Systematic
   Tenant-Boundary Testing` section in `idor.md` (it's BOLA at tenant
   scope). Skill-only.
4. **IDOR small surface gaps** from Task 1: GraphQL mutation BOLA example,
   explicit legacy/mobile-API-version pattern, named second-order/nested
   object-reference pivoting. **Extension** to `idor.md`. Skill-only.
   Marginal but cheap — already the strongest file audited.
5. **Default-credentials testing is siloed** in one technology file
   (`grafana_prometheus.md`) instead of a generalized fingerprint→known-creds
   recon step. (Cloud metadata and exposed admin/debug endpoints are
   already well covered — `ssrf.md`'s per-cloud-provider metadata section,
   `information_disclosure.md`'s Debug/Admin sections — no gap there.)
   **Extension** to `reconnaissance/asset_discovery.md`. Skill-only.
   High-frequency/low-effort finds, individually lower payout.
6. **`idor.md` ↔ `bfla.md` have zero cross-references** despite bfla.md's
   Chaining section naming "BFLA + IDOR". One-line **extension** to both
   files. Skill-only. Cheapest item; tightens the Task-1 axis-separation
   grade.
7. **Chain-pattern naming gap**: `root_agent.md`'s "Chain Findings Before
   Finishing" list has "info-disclosure + IDOR" (horizontal) but no named
   "info-disclosure reveals admin token/key → vertical escalation"
   example, even though the general chaining mechanism already covers it
   if an agent thinks of it. One-line **extension** to `root_agent.md`.
   Skill-only. Lowest priority — mechanism already exists.

**Items 1-3 implemented in one batch** — see §14. Items 4-7 (small IDOR
surface additions, default-creds sweep, remaining cross-refs, chain-naming)
were pulled forward into that same batch too where cheap (4 and 6 are
done; 5 and 7 remain open). Not yet decided: whether 5/7 get a follow-up
pass or stay parked.

## 14. ACCESS-CONTROL BATCH — CORS + SAML + TENANT-BOUNDARY (implemented)

Implemented the top 3 ranked items from §13 in one batch, skill-only, no
Dockerfile/Python changes. Counterevidence/PoC discipline preserved
throughout — each new file's Validation section requires a working proof,
not a header/oracle alone, matching `analysis/counterevidence.md`'s
closure-state rules.

- **New file** `vulnerabilities/cors_misconfiguration.md` — the CORS
  methodology CSRF/info-disclosure only gestured at. Covers
  reflected-Origin-with-credentials (the actual dangerous combo — named
  explicitly, with the Fetch-spec detail that `ACAO: *` + `ACAC: true` is
  illegal, so that pairing means reflection, not a real wildcard),
  null-origin bypass, regex/prefix/suffix bypass patterns
  (`trusted.com.evil.com`, `evil-trusted.com`, subdomain-wildcard
  over-trust cross-linked to `subdomain_takeover.md`), preflight handling
  flaws, and CORS response cache poisoning (missing `Vary: Origin`). A
  dedicated **Validation** section states the FP-control rule from the
  task explicitly: a permissive header is a lead; confirmed only with a
  working PoC page demonstrating a script-visible, credentialed
  cross-origin read against a real victim session. **False Positives**
  explicitly rules out `ACAO: *` without `ACAC: true` as the common
  non-bug case. Cross-linked from `csrf.md`'s CORS Profile step and
  `information_disclosure.md`'s Cross-Origin Signals bullet (both existing
  mentions now point here instead of stopping at "overly permissive
  CORS").
- **New file** `protocols/saml.md` — SAML 2.0 SSO, matching
  `oauth.md`'s structure. Centered on one framing sentence mirrored from
  `idor.md`'s checked-vs-used framing: the assertion the signature
  *validates* is not always the assertion the consumer *reads*. Covers
  XML Signature Wrapping with 4 named variants (duplicate/moved
  assertion, wrapped-parent, `NameID` comment-injection, duplicate
  `Response` wrapping) ranked by real-world parser-vulnerability
  frequency, assertion replay (`NotOnOrAfter`/one-time-use enforcement),
  recipient/audience/destination confusion (the SAML analogue of
  `idor.md`'s cross-tenant access, at the identity layer), IdP-initiated
  flow abuse (no `InResponseTo` binding to fall back on), unsigned-assertion
  acceptance, XXE-in-SAML (cross-linked to `xxe.md`), plus advanced
  attribute/role-injection and cert/key-confusion techniques. Impact
  section states explicitly why this ranked #2: successful SAML breaks
  are usually full org account-takeover, the highest per-bug SSO payout.
  Cross-linked bidirectionally with `oauth.md` (OAuth file now has an
  intro paragraph pointing to SAML for B2B SSO; a target can run both).
- **Extension** `idor.md` — consolidated the scattered tenant material
  into one new `## Multi-Tenant / Tenant-Boundary Testing` section
  (placed after the existing Key Vulnerabilities list, before Bypass
  Techniques), explicitly referencing rather than duplicating
  `business_logic.md`'s Multi-Tenant Isolation + Authenticated
  Multi-Account Abuse and `root_agent.md`'s account-provisioning phase.
  The old `### Multi-Tenant` entry under Key Vulnerabilities was trimmed
  to a one-line pointer into the new section rather than left duplicated.
  Added the 4 missing patterns named in the task: tenant-ID enumeration
  via shared-infrastructure incrementing IDs (an existence-leak finding
  on its own), tenant-admin-vs-global-admin confusion (framed as BFLA's
  actor×action matrix at tenant scope), self-service-signup tenant
  collision (auto-join-by-email-domain named as the highest-value target),
  and cross-tenant search/autocomplete existence leaks. Proof discipline
  stated explicitly: needs two real tenants, mirroring the file's
  existing two-principal rule — a same-tenant retest proves nothing.
  Also added `business_logic.md`'s Multi-Tenant Isolation with a one-line
  pointer back to this new section for discoverability when only
  `business_logic` is loaded.
- **Extension** `idor.md` — the 3 small surface gaps from Task 1: a
  GraphQL **mutation** BOLA example (`updateDocument`/`transferOwnership`-style,
  distinct from the existing query-only example) with the
  `delete*`/`update*`/`transfer*`/`share*`/`revoke*` naming sweep;
  `### Alternate API Versions and Channels` naming the legacy/mobile
  weaker-version pattern IDOR lacked (BFLA already had the actor/action
  mirror of this); `### Nested and Second-Order Object References` naming
  the parent-checked/child-unbound pivot pattern, including a note to test
  both directions (swap child with parent held constant, and vice versa)
  and multi-hop chains.
- **Extension** `idor.md` ↔ `broken_function_level_authorization.md` —
  one-paragraph cross-reference in each, stating which axis is "home" for
  that file (horizontal/object in idor.md, vertical/action in bfla.md) and
  pointing to the other for the complementary axis. Closes the Task-1 "B"
  grade on axis-separation clarity from §13.

**Verified before calling this done:** re-read the full edited `idor.md`
top to bottom after all edits to confirm no duplication survived (the old
Multi-Tenant subsection is now a pointer, not a second copy of the
content) and that section ordering stays coherent (Key Vulnerabilities →
new Multi-Tenant section → Bypass Techniques → Chaining, unchanged
elsewhere). Skill-name resolution confirmed by reading
`strix/skills/__init__.py`: skills resolve by file stem, so
`vulnerabilities/cors_misconfiguration.md` → `cors_misconfiguration` and
`protocols/saml.md` → `saml`, matching the filenames used throughout this
batch and in the CLAUDE.md index update.

**Not yet done, no test run performed** — user will batch-test these
against a real target next, per their instruction. §13 items 5
(default-creds fingerprint sweep) and 7 (chain-naming addition to
`root_agent.md`) remain open, unranked as to whether they get a follow-up
pass.

## 15. MOBILE APP ANALYSIS (APK/IPA) — FEASIBILITY AUDIT
   (audit + design only — plan not yet approved, nothing implemented)

New direction: static and (where feasible) dynamic analysis of Android
`.apk` and iOS `.ipa` files, not just web/source-code targets. Read-only
audit against the live environment — grepped the skills tree and
Dockerfile, then verified tool availability against the actual
`kali-rolling` `Packages` index (not guessed) and checked this
WSL/Docker environment's real virtualization capabilities
(`strix/runtime/docker_client.py`, `/dev/kvm` presence).

**Current state: zero mobile support, fully greenfield.** Every
`apk/ipa/android/ios/mobile` hit in the skills tree is incidental (web
skills using "mobile" generically for client/API-version testing) — no
file, directory, or Dockerfile line touches mobile analysis at all.
`technologies/electron_desktop_apps.md` is the right structural template
(per-platform trust-boundary skill, cross-linked to relevant vuln skills,
Validation/False Positives/Remediation sections) — nothing else reusable
from it beyond format.

**Feasibility scorecard:**

- **Static APK — feasible, clean apt install.** Verified against the live
  `kali-rolling` package index: `apktool` 2.7.0, `jadx` 1.5.6, `dex2jar`
  2.1, `android-sdk` 28.0.2 (has `aapt`), `apksigner` 35.0.2 all resolve.
  `apktool`/`jadx` depend on `default-jre-headless`/`default-jre`, pulled
  automatically — no manual JDK pinning. `androguard` (Python static-APK
  library) is on PyPI, fits the existing venv pattern. Decompiles to
  genuinely readable Java — the good case.
- **Static IPA — feasible but shallower, real ceiling.** IPA is just a
  zip; `Info.plist`/entitlements/`embedded.mobileprovision` parse natively
  via Python's **stdlib** `plistlib` (binary + XML, zero extra dep) — ATS
  config, usage-description strings, URL schemes, embedded frameworks all
  extract cleanly and cheaply. But the compiled Mach-O binary resists real
  decompilation on Linux: `otool` is macOS-only, `class-dump` is not
  packaged for Linux at all (confirmed absent from the repo). Best real
  option: **Ghidra 12.1.2** is apt-installable, cross-platform, and does
  genuine Mach-O/ARM64 pseudo-C decompilation — better than expected, but
  still meaningfully worse output than jadx's Java. `radare2` (also
  apt-available) covers fast symbol/string/disassembly work. Net: strong
  extraction, weak decompilation — expect leads, not fully-traced logic
  bugs, from the binary itself.
- **Dynamic APK — hard/impractical here, not flatly impossible.**
  Confirmed no `/dev/kvm` in this environment, and
  `strix/runtime/docker_client.py` creates sandbox containers with only
  targeted caps (`NET_ADMIN`/`NET_RAW`/`SYS_ADMIN` for nmap/fuse) — no
  device passthrough, not privileged. Even on a host with KVM, Docker
  Desktop's WSL2/Hyper-V backing VM makes real nested-KVM passthrough into
  a container unreliable-to-absent. Software-only QEMU emulation is
  technically bootable but 10-50x slower and needs multi-GB system
  images — a bad fit for a fresh, ephemeral, fast-spin-up container per
  scan. Would need real infrastructure investment (persistent emulator
  service, or the user bridging their own device/emulator over ADB) — out
  of scope for a Dockerfile tool addition.
- **Dynamic IPA — flatly impossible here, full stop.** iOS Simulator is
  macOS-exclusive software, does not run on Linux under any
  configuration — an OS-exclusivity gap, not a licensing/config one. Real
  dynamic iOS analysis needs a jailbroken physical device or a Mac. No
  workaround exists inside Linux/Docker. User's own prior read was
  correct; confirmed, not softened.

**Honest static-only ceiling:** several high-value categories (cleartext/
ATS misconfig, WebView-bridge RCE, insecure-storage exploitation) can be
*found* statically but not fully *proven* without dynamic capability.
This is not a new discipline to invent — `analysis/counterevidence.md`'s
existing rule already covers it exactly: a complete static trace with
runtime reproduction genuinely out of reach is reportable at
`medium`/`low` confidence with the missing runtime proof named
explicitly in `confidence_rationale`, never inflated to `high`.

**Payoff ranking (static-only), for scoping which findings matter most:**
1. **Backend endpoint/API discovery** — highest-value output; a
   decompiled app is a map to undocumented API surface, feeding directly
   into `idor.md`/`bfla.md`/`business_logic.md`/`sql_injection.md` — the
   mobile analog of `asset_discovery.md`'s JS-bundle-mining, probably the
   fastest real path to payouts.
2. Hardcoded secrets/cloud keys in strings/resources — same payoff class
   as existing dorking/secret-hunting work.
3. Exported Android components (`exported=true`, no permission) reachable
   by any other app — established bug class (auth bypass, data leak,
   content-provider SQLi).
4. Insecure WebView + exposed JS bridge — RCE-adjacent when reachable
   from untrusted content.
5. Deep-link/URL-scheme hijacking — chains directly into existing
   `oauth.md` work (redirect_uri theft via scheme collision).
6. Medium/caveated: insecure network config (misconfig confirmable
   statically, MITM exploitation not, without dynamic), weak/broken
   crypto, insecure local storage (usually needs physical/rooted device
   access to exploit — calibrate down the way
   `information_disclosure.md`'s triage rubric already treats
   "requires local access"), backup/debuggable flags (low alone, a real
   multiplier when chained).

**Reuse of existing work:**
- **Android: strong, near-direct.** Decompiled APK (`apktool`+`jadx`
  output) is structurally a white-box `local_code` target —
  `source_aware_discovery.md`'s family-sweep methodology,
  `source_aware_sast.md`'s semgrep+ast-grep entry-point mapping, and
  `business_logic.md`'s white-box QA methodology apply close to
  verbatim. Forces fixing an already-known gap from §9's audit (still
  open): `source_aware_sast.md`'s semgrep baseline has `p/golang` but no
  `p/java` — cheap, skill-only, needed either way. Argues for a
  `frameworks/android.md` skill built like `wordpress.md` (§10 precedent):
  Entry Points / Dangerous Sinks / "verify the guard" / Testing
  Methodology / Reporting, wired into `source_aware_sast.md`'s existing
  "detect X, load skill Y" convention.
- **iOS: weaker reuse.** Shallow decompilation means an `ios.md` skill
  leans on structured extraction (plist/entitlements/strings/endpoint
  harvesting) rather than full source-level logic tracing — a
  deliberately asymmetric skill design vs. Android, not a copy of it.
- **Plumbing gap surfaced, not skill-only**: `is_whitebox_targets()` (the
  §9 fix, in `strix/core/inputs.py`) only fires for `local_code`/
  `repository` target types. An `.apk`/`.ipa` `--target` maps to neither
  today — something (most likely self-extraction into a `local_code`-
  shaped workspace) needs to happen at the Python layer before
  source-aware mode would ever engage for a mobile target. A real design
  decision for Phase 1, not something skill files can paper over.

**Phased plan, none started:**
1. **Static APK** (recommended first — highest value/lowest risk).
   Dockerfile: `apktool`, `jadx`, `dex2jar`, `android-sdk`, `androguard`
   (pip). Skill: new `frameworks/android.md`. Fix: add `p/java` to
   `source_aware_sast.md`'s semgrep baseline. Design decision needed
   first: how an `.apk` target becomes a `local_code`-shaped workspace.
2. **Static IPA.** Dockerfile: `radare2` (cheap), `ghidra` (heavier —
   flag size/JRE cost, consider gating behind "deep dive on one
   suspicious binary" rather than a default always-run step). Skill: new
   `ios.md`, framed around extraction-and-leads with the counterevidence
   static-confidence framing built in from the start.
3. **Dynamic APK — parked, not recommended now.** Opt-in path requiring
   the user's own external emulator/device over an ADB network bridge —
   real infra work, not a Dockerfile addition. Not scoped further unless
   revisited later.
4. **Dynamic IPA — not on the roadmap.** No phase; flatly excluded per
   the scorecard above.

**Not yet decided**: whether to proceed with Phase 1 (static APK), and if
so whether to resolve the `is_whitebox_targets()` plumbing question before
or alongside the `frameworks/android.md` skill work. No Dockerfile or
skill changes made in this session — audit only.

**Decision made**: build **static APK only**, strong. No IPA, no dynamic —
both parked per §15's scorecard. Proceeding in small ordered steps
(plumbing → Dockerfile → skill → semgrep p/java), each reviewed/tested
before the next.

## 16. STATIC APK PLUMBING DESIGN (design only, not implemented)

Traced the actual code paths (`strix/interface/utils.py`'s
`infer_target_type`/`clone_repository`/`stage_api_specs`,
`strix/interface/scan_setup.py`'s `prepare_run`, `strix/core/inputs.py`'s
`is_whitebox_targets`/`build_root_task`/`build_scope_context`,
`strix/runtime/session_manager.py`'s bind-mount mechanism,
`containers/docker-entrypoint.sh`) to design how an `.apk` target becomes
a decompiled, `local_code`-shaped workspace.

**Key correction to the original plan**: the audit's own suggestion to
mirror `clone_repository` (host-side tool execution) turned out to be the
wrong precedent. The closer, safer match already in the codebase is
`stage_api_specs()` — copy-a-file-to-a-staging-dir, no host tool
execution. Reason: an APK is hostile input (attacker-influenced
bytecode, real apktool/jadx CVE history parsing malformed archives) —
running the decompiler against untrusted bytes belongs **inside** the
Docker sandbox that exists to contain hostile-target interaction, not on
the operator's host machine the way `git clone` (comparatively low-risk,
well-audited) already does. So the design splits "clone → decompile"
into two different layers: host-side is staging only (mirrors
`stage_api_specs`), sandbox-side is the actual `apktool`/`jadx` decompile,
run once by `docker-entrypoint.sh` at container boot — deterministic,
before the agent's first turn, costing zero agent tool-calls, and never
requiring apktool/jadx/a JRE on the operator's host.

**Design:**
- **New target type `mobile_app`** (not a reuse of `local_code` —
  `local_code`'s directory validation/metadata-protection assumes a real
  user directory that doesn't apply to a single `.apk` file). Mirrors
  `repository`'s two-phase shape (inferred once, gains a derived path
  later) without inheriting `local_code`'s directory semantics.
- **Host side**: `infer_target_type()` gains a `.apk`-extension branch
  (ordered before `detect_spec_format` so an `.apk` never gets
  mis-probed as an API spec) → `("mobile_app", {"target_apk": path,
  "mobile_platform": "android"})`. New `stage_mobile_apps()` in
  `interface/utils.py`, shaped exactly like `stage_api_specs()`: copies
  the raw `.apk` to `tempfile.gettempdir()/strix_mobile_apps/<run_name>/`,
  new fixed `MOBILE_APP_WORKSPACE_SUBDIR = "mobile-apps"` constant,
  returns one `local_sources` entry. Called from `prepare_run()` in
  `scan_setup.py` alongside the existing `stage_api_specs()` call.
- **Sandbox side**: `docker-entrypoint.sh` gets a new block before
  `cd /workspace; exec "$@"` — for each `*.apk` under
  `/workspace/mobile-apps/`, run `apktool d` (decodes
  `AndroidManifest.xml` + `res/` incl. `network_security_config.xml` to
  plain XML — free, reliable) into `<name>-decompiled/smali-resources/`,
  then `jadx` (best-effort, can legitimately fail on obfuscated/malformed
  DEX) into `<name>-decompiled/java/`. Every decompile invocation
  individually guarded (`|| echo WARNING...`, `timeout`-wrapped) so a
  corrupt/hostile APK warns and continues rather than aborting the whole
  container boot (`set -e` is active for the entire script) — must stay a
  near-instant no-op when no `.apk` is present, since this block now runs
  on every scan type.
- **Manifest-summary file deferred to the skill step, not this plumbing
  step** — `apktool d`'s decoded manifest/resources are the raw material;
  the actual Android-specific `entry_points.md`-equivalent distillation
  (exported components, permissions, min/target SDK, network-security
  config) is agent-driven work per `frameworks/android.md`, matching how
  `source_aware_sast.md`'s existing `entry_points.md` is agent-built via
  documented semgrep/ast-grep commands rather than baked into container
  boot. Keeps the entrypoint change purely mechanical.
- `strix/core/inputs.py`: `_WHITEBOX_TARGET_TYPES` gains `"mobile_app"`
  (immediately loads the full source-aware skillset for any mobile_app
  target, even before `android.md` exists — Steps 1+2 alone already
  produce a working generic source-aware scan over decompiled Java, a
  real incremental-testability checkpoint); `build_root_task()` gains a
  `"Mobile Applications"` section/branch (prompt text only);
  `build_scope_context()`'s `value_keys` gains `"mobile_app":
  "target_apk"`.
- `collect_local_sources()` and `dedupe_local_targets()`: **no change** —
  `mobile_app` bypasses both entirely, the same way `api_spec` does
  today.

**Blast-radius/what-could-break notes**: the entrypoint block is the one
piece that touches every scan type unconditionally (must no-op fast when
idle); `infer_target_type()`'s new branch must be ordered before the
existing spec-format probe; `_WHITEBOX_TARGET_TYPES` is the established
single source of truth (§9) so both skill-selection and telemetry pick up
`mobile_app` consistently by construction, nothing to reconcile there.

**Step order (approved, none built yet):**
1. This plumbing design — done, under review.
2. Dockerfile: `apktool`, `jadx`, `default-jre-headless` (auto-pulled),
   `android-sdk`, `androguard`. Testable in isolation.
3. Python plumbing above, tested end-to-end against a real `.apk` before
   any skill exists (confirm decompiled tree + `is_whitebox_targets()`).
4. `frameworks/android.md` skill (Entry Points / Dangerous Sinks /
   verify-the-guard / manifest-summary generation / Testing Methodology /
   Reporting — per §15's payoff ranking), wired into
   `source_aware_sast.md`'s existing "detect X, load skill Y" convention.
5. Add `p/java` to `source_aware_sast.md`'s semgrep baseline.

**Not yet implemented — design only, awaiting approval before Step 2.**

## 17. CUSTOM HIGH-PRECISION SAST/SECRET RULES (implemented, awaiting commit approval)

Separate track from mobile (§15/§16), addressing the audit from the
"do gitleaks/semgrep have custom rules" conversation: previously **zero**
custom rules existed anywhere — every tool ran with public/default configs
only (`p/default`/`p/golang`/`p/secrets` registry packs, gitleaks' bare
default ruleset), and FP-control lived entirely in LLM reasoning via
`counterevidence.md`. Goal here: add narrow, high-precision detection at
the scanner-input layer to surface the highest-signal candidates earlier
without adding noise — philosophy unchanged, final truth still stays with
the LLM. Built and empirically tested against a real target (the
optistate WordPress plugin at `/home/kalimonad/targets/optistate/optistate`,
38 PHP files) with an isolated semgrep 1.176.0 test venv and a
freshly-downloaded current gitleaks 8.30.1 binary (matching what the
Dockerfile actually installs) — not assumed correct, actually run.

**New files:**
- `strix/skills/custom/semgrep-rules/wordpress-secrets-and-sinks.yml` — 4
  rules, each with an inline precision-boundary comment:
  1. `hardcoded-cloud-key-literal-to-sink` — key-shaped literal
     (Google/AWS/Stripe/Anthropic-DeepSeek-shaped) reaching a call whose
     name suggests encrypt/default/option. This is the literal optistate
     bug: a real Google API key hardcoded as the default arg to
     `OPTISTATE_Utils::encrypt_data()` inside `get_default_settings()`.
  2. `hardcoded-cloud-key-literal-in-defaults-array` — same key shapes,
     direct array-value form (`"*_api_key" => "AIza..."`), no wrapping
     call needed.
  3. `unserialize-tainted-without-class-restriction` — taint-mode rule,
     `$_POST`/`$_GET`/`$_REQUEST`/`$_FILES`/`$_COOKIE`/`file_get_contents()`
     reaching `unserialize()`/`maybe_unserialize()`. Real security-relevant
     distinction found during testing: the actual safe control is
     `allowed_classes => false`/`=> []`, not `is_serialized()` (a format
     check, kept as a secondary sanitizer since the operator had already
     accepted it as safe in the reference file). `maybe_unserialize()` has
     no way to pass that option at all, so any tainted call to it
     unconditionally matches.
  4. `wpdb-tainted-query-without-escaping` — taint-mode rule, same sources
     reaching `$wpdb->query()`/`get_results()`/`get_var()`/`get_row()`/
     `get_col()`. **Caught and fixed a real bug before finalizing**: a
     first draft that only excluded `$wpdb->prepare()`-wrapped calls
     produced 34 false positives against `restore-engine.php` — a file
     already manually verified safe — because `prepare()` can only
     parameterize values, never table/column identifiers, so the real
     WordPress-idiomatic safe pattern for dynamic identifiers is
     concatenation *after* an identifier-escaping call
     (`esc_sql()`/a plugin's own `*escape_identifier*` helper) or an
     int/float cast. Fixed by switching to taint mode with `prepare()`
     AND any `*escape*`/`*esc_sql*`/`*esc_like*`/`*sanitize*`/`intval`/
     `absint`/`quote_identifier`-named call AND casts as sanitizers —
     brought optistate back to 0 findings, kept the raw-concatenation
     true positive.
  - **Test results**: exactly 1 finding (the real AIza key) across the
    full 38-file optistate codebase; exactly 7/7 true positives fired
    correctly across 15 purpose-built false-positive fixtures (comments,
    non-sink-reaching literals, `allowed_classes`-restricted unserialize,
    `is_serialized()`-guarded paths, hardcoded non-tainted values,
    `prepare()`/`esc_sql()`/identifier-escaper/int-cast-guarded queries,
    static SQL strings) — all confirmed clean, none of the safe patterns
    fired.
- `strix/skills/custom/gitleaks-rules/strix.gitleaks.toml` — extends
  (`useDefault = true`), does not replace, gitleaks' default ruleset.
  **Deliberately does NOT redefine Google/AWS/Stripe/Anthropic rules** —
  confirmed via the current default ruleset (fetched from
  `gitleaks/gitleaks` master) that all four are already covered
  (`gcp-api-key`, `aws-access-token`, `stripe-access-token`,
  `anthropic-api-key`/`anthropic-admin-api-key`); the optistate Google key
  is caught by gitleaks' own unmodified default with zero extra config.
  Redefining any of those would create a driftable stale copy of a rule
  gitleaks actively maintains. Only two additions:
  1. `deepseek-api-key` — confirmed genuinely missing (OpenAI's rule
     requires an embedded `T3BlbkFJ` marker, Anthropic's requires the
     `sk-ant-api03-...AA` shape; neither matches a plain `sk-<32 hex>`
     key). Relevant since CLAUDE.md documents DeepSeek as this project's
     own LLM backend. Explicitly flagged in-file as best-effort since
     DeepSeek publishes no official fixed key format the way Stripe/AWS
     do. Tested clean against random hex IDs, nonces, UUIDs, MD5/SHA1
     hashes, and hex-shaped WordPress option constants (none carry the
     `sk-` prefix).
  2. A global `[allowlist]` for WordPress's `*_KEY`-suffixed
     lowercase_snake_case option-name constant idiom
     (`STATE_KEY_PREFIX = "plugin_ls_state_v4"`), which gitleaks' own
     `generic-api-key` default rule false-positived on in an initial test
     against a stale local gitleaks 8.18.4 binary. Not currently
     triggered against optistate by the actual-latest gitleaks 8.30.1 the
     Dockerfile installs (upstream appears to have tightened
     `generic-api-key` since), kept as a defensive backstop since real
     keys are virtually never pure lowercase_snake_case, so it costs
     nothing in recall.
  - **Version-compatibility finding, documented in-file**: a stray local
    gitleaks 8.18.4 binary completely broke (`0 findings` on everything,
    including the real true positive) when `[extend] useDefault = true`
    was combined with a custom `[allowlist]` — re-tested against a
    freshly-downloaded current 8.30.1 and confirmed working correctly.
    Since the Dockerfile always installs "latest" at build time, this
    doesn't affect the shipped image, but is noted in the config file's
    own header comment as a real compatibility trap for anyone testing
    locally against an old cached binary.
- `containers/Dockerfile` — `COPY --chown=pentester:pentester` for both
  new directories into `/home/pentester/tools/semgrep-rules` and
  `/home/pentester/tools/gitleaks-rules`, mirroring the existing
  `caido_api.py` COPY precedent. **Necessary correction to the literal
  request**: custom rule files must be baked into the sandbox image at a
  fixed path, since `source_aware_sast.md`'s scanner commands run inside
  the sandbox against the *target's* mounted source (cwd), not against
  this repo — a bare "add a rules file to the repo" would never actually
  reach the running scan without this wiring.
- `strix/skills/custom/source_aware_sast.md` — updated both semgrep
  invocations (baseline bundle + standalone "Semgrep First Pass") to add
  `--config /home/pentester/tools/semgrep-rules`; both gitleaks
  invocations to add `--config /home/pentester/tools/gitleaks-rules/strix.gitleaks.toml`;
  fixed the trufflehog flag inconsistency found in the earlier audit —
  **picked verified-only as the default everywhere** (dropped
  `--no-verification` from the baseline bundle, matching the standalone
  section which already had it off), with the reasoning stated inline
  (an unverified hit is exactly the noise the LLM has to spend a
  proof-gap pass ruling out; a verified hit is already high-confidence
  and can go straight to reported) and a documented, explicitly-commented
  `--no-verification` fallback line for offline/unreachable targets where
  live provider verification is impossible. Added a short intro paragraph
  to the Baseline Coverage Bundle section pointing at the new rule files
  and reaffirming `counterevidence.md` still gates reporting regardless
  of which layer produced a hit.

**Not yet committed** — diffs shown to user for review per their request
("show me the rule files and the trufflehog fix as a diff before I
approve committing"). No entry_points.md distillation logic, agent
delegation, or counterevidence.md touched, per their constraint.

**Update — end-to-end verification found 3 more real bugs, all fixed, entry_points.md scope reopened by user request:**

Before committing, ran the actual baseline bundle commands from
`source_aware_sast.md` standalone against optistate (isolated local
semgrep 1.176.0 venv, a freshly-downloaded current gitleaks 8.30.1 —
matching what the Dockerfile installs, not an unrelated stale local
8.18.4 — trufflehog 3.95.9 pinned to the Dockerfile's exact version, and
ast-grep via npm), not assumed working. Found and fixed three more real,
pre-existing bugs this surfaced (none introduced by §17's own changes,
all in the same scanner-input-layer scope):

1. **`gitleaks detect --source .` (as previously documented, no
   `--no-git`) scans git commit history by default** and silently returns
   **0 findings** on any target with no `.git` — exactly the shape of a
   real bug-bounty target (a plain extracted plugin tree, not a clone).
   Reproduced directly: gitleaks found 0 on optistate without the flag,
   1 (the real key) with it. Fixed by adding `--no-git` to all 4
   gitleaks/ast-grep invocations in `source_aware_sast.md`.
2. **`xargs -n 200` (ast-grep step) without `-d '\n'` splits on any
   whitespace**, silently truncating any file/directory path containing a
   space — live on optistate, which has one. Fixed with `xargs -d '\n'`
   at both occurrences.
3. **The bigger one**: `entry_points.md`'s distillation folded semgrep's
   curated hits and ast-grep's *ruleless* `$F($$$ARGS)` sweep (matches
   every function call in the codebase) into one file:line-sorted list.
   Measured against the real 38-file optistate run: ast-grep alone
   produced ~14,600 entries, and the genuine hardcoded-credential hit
   from §17's own semgrep rule landed at **line 11,981 of a 14,664-line
   file** — the exact "budget ran out at 97% before the key got
   reported" failure shape the user built this whole track to prevent,
   now proven to still exist even with the new rules in place. This is a
   structural problem in the distillation script from the earlier
   entry-point-map track (§11), not something #1's audit conversation
   introduced.

Item 3 directly conflicts with this same conversation's own stated
constraint ("do not touch entry_points.md distillation logic"). Flagged
this explicitly rather than silently fixing or silently shipping a false
"confirmed" — user chose to reopen the constraint and fix it now.
**Fix**: split the distillation into two tiers — `## High-Precision Hits`
(semgrep + **newly added** gitleaks + trufflehog parsing, sorted by
file:line — gitleaks/trufflehog were never folded into entry_points.md
before this fix, a related gap worth closing at the same time since the
whole point is early visibility) printed first, `## General Structural
Sweep` (the raw ast-grep dump, explicitly labeled "a map to grep for a
specific call site by name, NOT a hit list to read top to bottom")
printed last. Re-verified against the same real optistate run with the
corrected script: **High-Precision Hits is 43 lines total**, and the
credential now appears at **lines 17-19 of that 44-line section**,
corroborated by all three tools on the same file:line (semgrep custom
rule, gitleaks `gcp-api-key`, trufflehog `GoogleGeminiAPIKey` —
unverified, correctly, since a stale test key falls to `open_proof_gap`
rather than auto-reporting under the new verified-only trufflehog
default). Success criterion actually met and verified, not assumed.

**Committed**: all of §17 plus the three additional fixes above, in one
commit. Docker image rebuild required before the sandbox picks up the
new `COPY` layers (semgrep-rules/gitleaks-rules) or the
`source_aware_sast.md` command changes take effect for a fresh scan.

**Refinement — user caught a scoping gap in the two-tier fix, corrected
before the commit above's design could drift:** the committed two-tier
split put **all** semgrep results (42 on optistate, including the 41 from
the public `p/default`/`p/golang`/`p/secrets` packs) into
`High-Precision Hits`, not just the 4 project-authored rules. User wanted
that section scoped to the project's own rules specifically. Fixing it by
literally dropping the other 41 would have silently discarded real
signal, so this became a **three-tier** split instead of the two the user
described, flagged and explained rather than silently expanded in scope:

1. `## High-Signal Findings` — the 4 `custom/semgrep-rules/` rules
   (matched by bare rule id via `check_id.rsplit(".", 1)[-1]`, robust to
   the config path differing between a local test and the sandbox's
   `/home/pentester/tools/semgrep-rules`) + gitleaks + trufflehog.
2. `## Public-Pack Scanner Hits` — every other semgrep result (the
   registry packs) — still curated, just not project-authored, kept
   instead of dropped.
3. `## General Structural Sweep` — unchanged, the raw ast-grep dump.

Also cleaned up the implementation itself: the first version bridged two
separate `python3` heredoc invocations via a `/tmp/.entry_points_public_pack.pkl`
pickle file, which was fragile (cross-process temp file, no real reason
for two processes) — collapsed into one Python pass that prints both
section headers and bodies from the same parsed data.

**Re-verified against the same real optistate run**: entry_points.md is
now 14,675 lines total; `High-Signal Findings` starts at line 3, and the
credential finding is at **lines 5-7** — the first three findings in the
file, immediately after the header line. `Public-Pack Scanner Hits`
(line 9) holds the 11 other real findings from the public packs
(tainted-callable, tainted-sql-string, unlink-use, exec-use,
unserialize-use, md5-loose-equality) that a strict two-tier cut would
have discarded. `General Structural Sweep` starts at line 55, holding
the ~14,600-line ast-grep dump.

**Committed as a new commit** (not amended onto the prior one — keeps
the iteration, first pass then user-caught refinement, visible in
history rather than rewritten) on top of the semgrep/gitleaks-rules
commit above.

## 18. BLACK-BOX RECON AUDIT + JS-HEAVY SPA FIX (implemented)

Audit track (parallel to §17's white-box scanner-rules work), triggered
by a request to assess four black-box-testing depth questions: OTP/
human-in-the-loop, differential/mutation testing, JS-heavy SPA recon
depth, and rate-limit/timing bypass. Audited by reading the actual skill
files (not guessing):

- **OTP/human-in-the-loop**: already strong — `account_provisioning.md`'s
  4-tier fallback (auto OTP-bypass → `respond_to_user` human-in-the-loop →
  operator-credential file → `needs_follow_up`) already covers this,
  built in §6. No gap.
- **Differential/mutation testing**: the actual techniques exist
  (`mass_assignment.md`'s Shape Variants, `broken_function_level_authorization.md`'s
  verb sweep, `idor.md`'s Enumeration Techniques) but are scattered
  per-vuln-class rather than one cross-cutting discipline. Noted, not
  yet acted on.
- **Rate-limit/timing bypass**: the IP-spoof-header technique
  (`X-Forwarded-For`/`X-Real-IP`/etc. against rate-limited endpoints) is
  already documented in `header_injection.md`, but as one bullet in a
  general header-injection catalog, not a systematic per-endpoint
  methodology with its own closure discipline. Noted, not yet acted on.
- **JS-heavy SPA recon depth**: the one concrete, closeable gap found —
  `reconnaissance/asset_discovery.md`'s crawl step (`katana ... -jc -jsl`)
  is 100% static (parses fetched JS as text, never executes it), so it
  never sees an XHR/fetch call a SPA only fires at runtime. The
  capability to fix this already existed in two tool playbooks
  (`tooling/katana.md`'s `-hl -xhr` headless mode,
  `tooling/agent_browser.md`'s `network har`) but neither was wired into
  the actual recon methodology. Implemented below.

**Implementation — all empirically verified inside the real
`strix-sandbox:dev` image (Chromium + katana already present from §17's
work), not assumed:**

- **`strix/skills/tooling/katana.md` — fixed a real, independent bug found
  while verifying**: `-sc`/`-system-chrome` (documented as "use local
  Chrome for headless mode") does **not** reliably wire to the installed
  Chromium. Traced katana's actual Go source
  (`internal/runner/options.go`, `pkg/engine/headless/headless.go`): the
  crawler engine reads the Chrome binary path from `SystemChromePath`,
  populated only by the separate `-scp <path>` flag. Confirmed live:
  `-sc` alone triggered katana downloading its own ~90MB Chromium build
  from `storage.googleapis.com` (killed after 90s at 84%); `-scp
  /usr/bin/chromium` resolved it immediately (4s for a 1-page crawl).
  Both documented headless example commands and the failure-recovery
  bullet fixed to use `-scp`.
- **Real katana JSON schema traced from source** (`pkg/navigation/
  response.go`, `pkg/navigation/request.go`, `pkg/output/result.go`),
  not assumed: the URL field is `endpoint`, not `url`; `xhr_requests[]`
  nests per-page under `response`; each XHR entry is the exact same
  `Request` struct/shape as a normal crawled URL (`method`, `endpoint`,
  `body`, `headers`) — no separate `params` field, no schema mismatch to
  normalize between static-crawl and XHR-captured URLs.
- **Real cost benchmark, not an estimate**: ran static vs. headless
  crawls of the same real site (`quotes.toscrape.com`, depth 2) inside
  the built sandbox image. Static: 24.8s / 2369 results. Headless (with
  the `-scp` fix): **49m 8s / 267 results — ~119x slower, fewer results**.
  This ruled out "always-on by default" outright and is cited directly
  in both edited skill files as the reason the headless pass must stay
  conditional and hard-bounded.
- **`-ct` (wall-clock cap) confirmed to enforce independently of `-mdp`
  (page-count cap)** by direct test: `-ct 1m` against the same slow
  target stopped at 1m0.28s with 59 records, not left running toward a
  depth/page target. Both are required as a hard default
  (`-d 2 -ct 5m -mdp 50`) — `-mdp` alone doesn't bound wall-clock on a
  genuinely slow SPA.
- **`strix/skills/reconnaissance/asset_discovery.md`** — new
  "JS-heavy fingerprint check and conditional headless pass" subsection
  in Application-Layer Recon step 1:
  - A concrete, deterministic thinness check (strip script/style +
    tags, measure visible text length and non-script/style/meta/link tag
    count; `len(text) < 500 or content_tags < 20`) run against the
    static crawl's already-captured root-page body — no extra fetch.
    Calibrated against real pages, not guessed: a genuine SPA shell
    (TodoMVC's React build) measured 86 chars / 10 tags; an ordinary
    content-rich page (Django-templated) measured 1700+/138+ — a large,
    unambiguous gap. Tested the exact committed function against both:
    correctly `False` on the content-rich site, `True` on the real SPA.
    Documented explicitly as recall-leaning by design (some genuinely
    tiny static sites will also trip it) since the follow-up is now
    bounded, not the prior unconditional risk.
  - The bounded headless follow-up itself
    (`-hl -scp /usr/bin/chromium -nos -xhr -d 2 -ct 5m -mdp 50`), gated
    on the fingerprint check, never default.
  - An XHR-folding snippet normalizing `response.xhr_requests[]` into
    the same `endpoint`/`method` shape the static crawl already
    produces (verified: they're the same schema at the source, so this
    is literally zero-renaming folding, not a translation layer) —
    tested against a synthetic multi-XHR record to confirm the
    extraction logic itself is correct.
  - New "Interactive follow-up for click/type-gated API calls"
    subsection at the end of step 1: explains why katana's headless mode
    (generic link-following + synthetic auto-form-fill) can't trigger a
    real search query, "load more" click, or filter selection the way a
    judged `agent_browser` interaction can — confirmed complementary,
    not redundant, by reading katana's headless engine source
    (`AutomaticFormFill` is generic, not semantically aware). Explicit
    agent instruction, not automatic per-UI-pattern triggering, capped
    at 2-3 interactive elements per host per the user's request.

**Not yet done**: differential/mutation testing's cross-cutting
methodology and a dedicated rate-limit/timing-bypass module remain
audit-only findings from this track, not implemented.

## 19. DIFFERENTIAL/MUTATION TESTING — SHARED ENGINE (implemented)

Closed the "Differential/mutation testing" gap noted but not acted on in
§18: `mass_assignment.md`'s Shape Variants, `broken_function_level_authorization.md`'s
verb sweep, and `idor.md`'s Enumeration Techniques each independently
generated candidate values *and* independently invented their own
before/after comparison step — the second half duplicated across three
files with no shared definition of "changed" or "noise." Design was
reviewed and corrected before implementation (schema and family-grouping
boundary shown and confirmed first, per the user's request, since a
schema change after three consumers depend on it is expensive):

**New file** `strix/skills/analysis/parameter_mutation_testing.md` — three
layers:
- **Layer A (three-way mutation set)** — Control (resent, not reused, to
  surface response nondeterminism up front), Boundary mutation (T: a
  same-class structural/type change that stays inside the same
  authorization boundary — a negative control), Adversarial mutation (X:
  the actual boundary-crossing candidate). Diffing X against C and
  comparing that to T's diff is what proves X caused a change T didn't,
  rather than "any modification changes something here." Ties directly to
  `counterevidence.md`'s existing negative-control guidance ("send the
  payload that should work... show it is blocked, while a benign variant
  succeeds") — T is that benign variant, generated up front.
- **Layer B (shared diff record)** — one schema every consumer reads the
  same way: `status`/`size`/`headers`/`body_shape`
  (`same_key_set`/`array_length_deltas`/`type_changes`/`value_deltas`)/
  `timing`, plus a deterministic `signal_class` (`status`/`structural`/
  `value`/`none`/`inconclusive`) computed with no LLM call. Noise
  threshold: `beyond_noise = |delta_bytes| > max(32, 0.02*baseline_bytes)`
  (absolute floor for tiny bodies, proportional for large ones); a fixed
  header ignore-list (`Date`/`Set-Cookie`/`X-Request-Id`/`X-Trace-Id`/
  `ETag`/`Server-Timing`) strips volatile fields before diffing rather
  than after; timing is never a standalone signal below 3 samples per
  side; a `429`/`503` status gets one backoff retry before classification
  instead of an immediate verdict. Caller contract: Layer C declares an
  `expectations` map per mutated field (`unchanged`/
  `reflects_mutation:<value>`/`bounded:<min>,<max>`) so `out_of_expected_range`
  is driven by what the vuln-class generator actually expects, not a
  guess by the diff engine. `signal_class` never carries a security
  verdict — that reading stays with the calling skill, and
  `counterevidence.md` still gates whether it becomes `confirmed`.
- **Layer C (unchanged)** — explicitly documents that the per-class value
  catalogs stay exactly where they already were
  (`mass_assignment.md`/`idor.md`/`broken_function_level_authorization.md`/
  `business_logic.md`'s white-box QA methodology); this file generates no
  candidate values itself.

**Family Sweep** — endpoints are grouped before sweeping, by
`(static path segments, path-parameter positions, endpoint kind)` where
kind ∈ `{item, collection-list, collection-create, action}`; verb-within-kind
and content-type are swept inside a family, not used to split it. Worked
example against a synthetic `/orders`/`/invoices`/`/users/{id}/orders`
API caught and corrected a real boundary error in the original
sketch: same parameter arity is not enough to group two endpoints
(`/orders/{id}` and `/invoices/{id}` share shape but not resource
identity — kept as separate families); a trailing static verb segment
(`/invoices/{id}/void`) splits an endpoint into `action` kind even though
it shares a prefix with an `item`-kind sibling. The example also
surfaced, and explicitly did not try to solve inside the family-grouping
mechanism, a same-object/different-route case
(`/orders/{id}` vs `/users/{id}/orders/{orderId}` addressing the same
order) — flagged as `idor.md`'s existing "Alternate API Versions and
Channels" pattern, run as its own cross-family worklist item instead of
being folded into family grouping's scope.

**`mutation_candidates.md`** — a **separate** artifact from
`entry_points.md`, not a new section in it, because `entry_points.md` is
white-box-only (built inside the sandbox by `custom/source_aware_sast.md`
from static scanning) while mutation testing has to run in black-box
scans too. Lives at `/workspace/recon/mutation_candidates.md`, following
the existing `/workspace/recon/` reuse convention from
`reconnaissance/asset_discovery.md`; built from the crawled/enumerated
endpoint inventory in black-box mode, cross-referenced against
`entry_points.md`'s route rows when white-box source is also available
(never a third redundant list). One row per family — key, members, kind,
open vs already-run T/X candidates and their last `signal_class` — read
and updated (not duplicated) by whichever of the three vuln-testing
agents runs a family's sweep, the same shared-ledger discipline
`counterevidence.md` already requires of `record_coverage`.

**Cross-references added** (one paragraph each, matching the existing
axis-separation cross-reference style from §14): `mass_assignment.md`,
`broken_function_level_authorization.md`, `idor.md` each now point to
`analysis/parameter_mutation_testing.md` for the shared mechanics,
stating explicitly that their own catalogs (Shape Variants, verb
enumeration, Enumeration Techniques) remain the candidate-value source.

**Verified before committing**: `analysis/*` is an internal skill
category excluded from bare-name `load_skill`/`get_all_skill_names()`
lookup by design (confirmed in §11) — an initial bare-name check was a
false alarm, not a bug; `load_skills(["analysis/parameter_mutation_testing",
"mass_assignment", "broken_function_level_authorization", "idor"])`
resolves all four with no collisions, and each of the three vuln files'
loaded content contains the new cross-reference paragraph pointing at
`parameter_mutation_testing.md`. `tests/test_skill_dir_extension.py`
(20 tests) still passes unchanged. Not wired into `_resolve_skills()`'s
always-loaded set (deliberately — matches `source_aware_discovery`/
`fix_verification`'s precedent of being explicit-load-only, not
counterevidence/severity_calibration's always-on treatment); the root
agent's spawn instructions for a mutation-sweep-focused subagent are the
mechanism that actually combines it with the three vuln skills, not new
code.

Skill-only change, no Python/Dockerfile touched.

**Commit-hygiene correction (found during a later git-status audit,
git-status-2026-09-04):** the commit made for this track, `209563c`, is
broader than its message describes. Staging `idor.md` and
`broken_function_level_authorization.md` for their cross-reference
paragraphs staged and committed each **whole file** — which silently
swept in pre-existing uncommitted content that predates this track:
`idor.md`'s diff in `209563c` also carries all of §13/§14's
Multi-Tenant/Tenant-Boundary Testing section, the Alternate-API-Versions
and Nested/Second-Order-Reference additions, and an `## Impact Escalation`
section; `broken_function_level_authorization.md`'s diff also carries
§5's original framework-specific-gaps/verb-enumeration/Chaining-Attacks
work plus its own `## Impact Escalation` section. `mass_assignment.md`'s
commit was clean (no prior uncommitted content existed for it). Nothing
was lost or overwritten — the bundled content is real, already-described
work — but §5's and §13/§14's "implemented"/"committed" status for those
specific pieces only became true in git incidentally, via this commit,
not via a commit scoped to describe them. Left as-is per user decision
(git history not rewritten); noting it here for anyone reading `git log`
later.

