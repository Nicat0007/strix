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
- **Named pattern: the "obvious API is secretly stale/inverted" bug
  shape.** The single highest-value thing this project's testing
  discipline has repeatedly caught — three confirmed instances so far,
  all in the cost-reduction track (§21-§24), each found by actually
  tracing data flow or building a test rather than trusting how an API
  *reads*:
  1. Piece 2's `attack_surface.md` window — a forward-only
     registration-to-next-marker window silently missed a guard that
     was defined *before* the route registration (a common real
     WordPress layout), because "the window looks right" was never
     checked against a realistic fixture.
  2. Piece 3's `signal_class` — reusing the existing diff engine
     "unchanged" for actor-replay comparisons would have silently read
     an identical response (the actual leak signal) as `"none"`, the
     same value that means "boring" everywhere else the field is used —
     an inverted-polarity trap invisible from the schema alone.
  3. Piece 8's `ReportState.get_total_llm_usage()` — reads as "the
     current usage," is actually a cache only refreshed twice in the
     whole codebase near scan start/end, so it silently shows stale
     near-zero numbers for a running agent's entire lifetime.
  The fix in all three cases was the same: **build the actual test
  scenario (or trace the actual call graph) before trusting what a
  function's name or return-shape implies**, not just review the design
  on paper. When implementing anything that reads from an existing
  system (a cache, a window, a shared diff engine), spend the extra
  step confirming the read is live/correctly-oriented/complete against
  a concrete case, even when the code "looks right." This has been the
  actual value of this project's per-piece testing requirement — not
  confidence theater, a real bug catch nearly every time it's been
  applied seriously.

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

## 20. TWO UNDER-LOGGED EDITS FROM THE §8/§9 BATCH (implemented, now committed)

Found during the same git-hygiene audit as §19's note: `scan_modes/quick.md`
and `vulnerabilities/sql_injection.md` carried uncommitted edits with no
matching CLAUDE.md section. Confirmed via matching mtimes (identical to
the second) that both were written in the same 2026-08-30 batch as §8's
`target_identity.py` hoist and §9's `is_whitebox_targets()` fix — real
prior work, just never written up for these two files specifically, not
a foreign or unrequested change.

- `scan_modes/quick.md` — shallow-recon cost discipline for Quick mode:
  caps application-layer recon to one fast `katana -jc` pass at depth
  ≤2 (no `-jsl`/gospider second pass, no ffuf/dirsearch sweep, `arjun`
  only on already-flagged high-value endpoints), instructs reusing
  `/workspace/recon/` instead of re-crawling, adds deep JS
  extraction/secondary crawlers to the existing skip-list, and caps
  subagent creation at 2-3 concurrent, consolidated by check rather than
  one per vuln class.
- `sql_injection.md` — a new `## Impact Escalation` section mirroring
  the pattern already used in `idor.md`/`broken_function_level_authorization.md`:
  a confirmed oracle is the start of exploitation, not the end; requires
  extracting a real sensitive record (not just `version()`/`database()`/
  `current_user()` or a bare oracle) before filing, and a demonstrated
  real effect for write-capable SQLi rather than stopping at "UPDATE
  appears injectable"; genuine extraction blockers go to
  `open_proof_gap`/`needs_follow_up`, never filed metadata-only.

Committed together as their own small commit (grouped only because both
were small and under-logged, not because they're related to each other).

## 21. INFRASTRUCTURE-LEVEL IMPROVEMENTS FROM AN EXTERNAL ARCHITECTURE
    REVIEW — THREE PIECES, PIECE 1 IMPLEMENTED

New track from an external architecture review, deliberately scoped to
extend existing systems (`coverage.py`, `entry_points.md`,
`parameter_mutation_testing.md`'s Layer B) rather than introduce new
LLM-judgment mechanisms — explicitly avoiding fake-precision numeric
scores (confidence percentages etc.), matching this project's existing
"real judgment stays with the LLM, tools just gather evidence" principle.
Three pieces, designed together, implemented one at a time, each reviewed
before the next starts.

**Piece 1 — Negative Knowledge (persistent ruled-out cache): implemented
and committed.** `record_coverage`'s `ruled_out`/`no_issue_found` entries
live only in one scan's ledger (`{state_dir}/coverage.json`) and vanish
after `finish_scan`. A verdict like "this WordPress search-replace
serializer is safe because it rewrites `s:<len>` headers correctly before
writing back" is not target-specific — the same defensive pattern recurs
across every plugin in that family — so re-deriving it from scratch on
every future scan wastes exactly the reasoning this cache exists to carry
forward.

**Design correction found during the design pass, before any code was
written**: the matching key `(framework, vulnerability_class,
mechanism_signature)` cannot be known before an agent has actually read
the code, unlike the target-identity key from the parked Phase-2 design
(§8) which is known before any agent runs. So this could not be a
pre-dispatch text injection into `build_root_task()` the way §8 sketched
— it had to be a runtime tool call an agent makes mid-investigation. Also
decided: promotion to the persistent cache is a **separate, explicit**
tool call, never an automatic mirror of every `ruled_out`/`no_issue_found`
coverage entry — most such entries are target-specific ("this IP
allowlists our runner") and would poison a cross-target cache if
auto-promoted. This keeps the judgment call ("does this reasoning
generalize") with the LLM as a binary decision, never a score.

**Built:**
- **New module** `strix/tools/negative_knowledge/tools.py` (+
  `__init__.py`) — mirrors `strix/tools/coverage/tools.py`'s shape
  (module-level dict + `RLock` + atomic tempfile-rename persist,
  `hydrate_*_from_disk()` entry point) but persists to a **fixed
  cross-scan path**, `~/.strix/negative_knowledge.json`, not a run's own
  `.state/` dir — same `~/.strix/*.json` convention as `cli-config.json`/
  `mcp-servers.json`/`update-check.json`, all plain JSON with atomic
  writes; no SQLite anywhere in this codebase to match, so JSON was the
  right call, not a new pattern.
  - **Matching key**: `(framework, vulnerability_class, signature_hash)`,
    entry dict key literally `f"{framework}||{vulnerability_class}||{signature_hash}"`
    for O(1) exact-tier lookup and a natural upsert (no separate
    duplicate-detection pass needed, unlike `coverage.py`'s
    `_duplicate_of_locked`, because the composite key *is* the identity
    here). `vulnerability_class` is validated against
    `get_available_skills()["vulnerabilities"]` — the same canonical
    skill-name vocabulary `strix/report/coverage.py` already treats as
    authoritative — rather than inventing a second taxonomy.
    `signature_hash` is `sha256` of the sorted, deduped, lowercased
    `mechanism_signature` token list — a pure function of the token
    *set*, never the order or casing the agent happened to use, and
    never an LLM-invented string. Tokens must be ≥2 and are documented
    (in the tool docstring and in `counterevidence.md`) as
    library/framework/language built-in API names only, never
    project-specific identifiers — that discipline (not fuzzy matching)
    is what keeps the key from being "too strict to ever match" while
    staying "too loose" -resistant. Considered and explicitly deferred: a
    fuzzy/Jaccard token-overlap tier between exact and bucket matching —
    real, deterministic, non-LLM math, but added complexity not needed
    for a first cut; noted as a possible v2.
  - **Two-tier query result**: `exact_match` (identical key — a strong
    prior) and `related_in_bucket` (same `framework`+`vulnerability_class`,
    different signature — background context only, explicitly documented
    as carrying no signal about the current candidate).
  - **`corroborations`**: a plain count of *distinct* `source_target_hash`
    values that have confirmed this exact signature — never a confidence
    score. `source_target_hash` is `sha256` of this scan's
    `target_identity()` (reusing the §8/§9 utility from
    `strix/utils/target_identity.py` via `build_scan_targets()` +
    `strix.report.state.get_global_report_state()`), stored only as a
    hash so the cache file never becomes a readable client list, and
    stripped entirely from the agent-facing `_public_entry()` response.
    Re-recording from the *same* target does not double-count (tracked
    via an internal `source_target_hashes` list per entry); a genuinely
    different target increments it by exactly one.
  - `hydrate_negative_knowledge_from_disk(path=None)` takes a full file
    path (not a directory to join, unlike `coverage.py`'s
    `hydrate_coverage_from_disk(state_dir)`) since this store isn't
    per-run-state-dir-shaped; defaults to `~/.strix/negative_knowledge.json`.
    `_persist_locked()` is a no-op until hydrate has run — same guard as
    `coverage.py` — so a caller that forgets to hydrate (e.g. a test) can
    never accidentally write into the real host `~/.strix/` path.
- **New settings**: `NegativeKnowledgeSettings.enabled` (env
  `STRIX_NEGATIVE_KNOWLEDGE`, default `true`) in `strix/config/settings.py`
  + `strix/config/__init__.py` export — same single-field-toggle shape as
  `TelemetrySettings`. Disabling skips hydration entirely in
  `core/runner.py` (the store never even reads the file), and both tools'
  wrapper functions short-circuit to a `success: true, enabled: false`
  response that persists nothing — so a run against confidential/regulated
  code can opt out of both reading and writing the cross-scan cache.
- **Wiring**: `strix/agents/factory.py`'s always-on `_BASE_TOOLS` tuple
  gains `query_negative_knowledge`/`record_negative_knowledge` next to
  `record_coverage`/`update_coverage`/`list_coverage`. `strix/core/runner.py`
  gains one more `hydrate_*_from_disk()` call alongside the existing
  todos/notes/coverage/threat-model ones, gated on
  `settings.negative_knowledge.enabled`.
- **`analysis/counterevidence.md`** — new "Negative Knowledge — A Prior
  From a Past Scan, Never a Skip" section (placed right after "What DOES
  Rule Out a Candidate", since this is a persistent variant of exactly
  that discipline): when to query (once concrete API names are known, not
  before), what a hit means (strong prior on an exact match, background
  noise on a bucket-only match, never a skip either way — one fast
  re-verification of the matched guard, same as any other `ruled_out`),
  and when to promote (reasoning transfers across codebases of the same
  framework, never "this deployment happens to be fine").

**Verified, not assumed:**
- Manual two-*process* test (genuinely separate `python3` invocations
  sharing a temp `negative_knowledge.json`, in
  `/tmp/.../scratchpad/nk_scan1.py` + `nk_scan2.py`, not kept in the repo):
  scan 1 recorded an entry; scan 2, a fresh interpreter, queried it with
  deliberately different casing (`WordPress-Plugin` vs `wordpress-plugin`)
  and token order and got the exact-tier hit back with the schema intact;
  re-recording from a second simulated target incremented
  `corroborations` from 1→2; re-recording again from that *same* simulated
  target did not double-count; a different signature in the same bucket
  showed up only under `related_in_bucket`, never as `exact_match`;
  `source_target_hashes` never appeared in any agent-facing response.
- `tests/test_negative_knowledge_tool.py` — 21 new tests (validation,
  exact/bucket matching, corroboration counting incl. concurrent writers
  via a `ThreadPoolExecutor` + `threading.Barrier` mirroring
  `test_coverage_tool.py`'s own concurrency test shape, disabled-mode
  no-op, disk round-trip via re-hydrate).
- **Full suite regression, and a real bug it caught**: the first full run
  (1218 passed / 15 failed) surfaced that 5 pre-existing test fixtures —
  `tests/test_runner_{interrupt,mcp,rate_limit,root_prompt,teardown}.py`
  — build a `types.SimpleNamespace` settings stub for `runner.py` that
  didn't have a `negative_knowledge` attribute, so the new
  `settings.negative_knowledge.enabled` read in `run_strix_scan()`
  crashed every one of them with `AttributeError`. Fixed by adding
  `negative_knowledge=types.SimpleNamespace(enabled=False)` to each
  fixture (one line per file, same shape as the existing `runtime=`
  entry each already had) rather than making `runner.py` defensively
  `getattr` around a real settings field — the stub was incomplete, not
  the production code wrong. Re-ran full suite clean after the fix:
  **1232 passed, 1 skipped**, only `test_pricing.py::test_resolves_common_bare_model_names`
  still failing — confirmed via `git stash` to fail identically on `main`
  before any of this work (a stale `grok-4.5` → `xai/grok-4.5` litellm
  alias that upstream has since routed through `openrouter/x-ai/grok-4.5`
  instead), unrelated and pre-existing, not touched.

**Committed** as `998ebf1` — code + skill + the 5 test-fixture fixes in
one commit (13 files, 917 insertions).

**Piece 2 — Attack Surface Compiler: implemented and committed.** New
`## Attack Surface Compiler (Structural Facts, Not Judgment)` section in
`strix/skills/custom/source_aware_sast.md`, placed immediately after the
Entry-Point Map section, producing a new sibling artifact
`/workspace/.source-aware/attack_surface.md` — a compact per-route
summary (routes/hooks, tainted sources, sinks by category, auth-check
presence) rather than a fourth tier merged into `entry_points.md`, since
the two answer different questions (entry_points.md: where a scanner
found something; this one: what a route's own surrounding code
structurally contains). Skill-only, no Python/Dockerfile touched.

**Simplification found while implementing, before it shipped**: the
original design (in this same conversation) proposed a new `sg run`
per-language function-declaration pass for real AST block boundaries,
worried a line-window heuristic would be too crude. Building it,
`entry_points.md`'s own established idiom for this shape of sweep — plain
`rg -n -e PATTERN .` directly over the tree, the same as this file's own
pre-existing "Logic-bearing functions" section already does — turned out
sufficient: empirically verified (see below) that a direct `rg` sweep for
route/source/sink/auth-check keywords, bucketed by a same-file
line-window in pure Python, produces the same result as a much heavier
xargs-batched-file-list variant modeled on the ast-grep pipeline, with
none of that variant's complexity. No new external tool, no per-language
AST patterns.

**Real design flaw caught by testing against a realistic fixture, fixed
before shipping**: a first version windowed auth-check presence
*forward only* from a route registration line
(`[route_line, next_route_line - 1]`). Tested against a synthetic but
realistic WordPress shape — `add_action('hook', 'handle_save')` naming a
handler function *defined earlier in the file* (a very common real
plugin layout: all registrations grouped at the bottom, handler bodies
scattered above) — and the forward-only window never saw the guard at
all, since it lived at a lower line number than the registration. Fixed
by resolving the registration's callback name (the WordPress
`add_action`/`add_filter` string-callback and `array($this, 'method')`
shapes specifically) to an actual `function <name>(` definition anywhere
in the same file via one more keyword sweep (`function_def`), and
windowing around *that* definition instead — bounded by the next
detected route-or-function-definition line in the file, or a `+60`
fallback, same rule as before. When no callback name resolves (an inline
handler, a non-WordPress framework), it falls back to the original
forward-only window from the registration line — inline-handler
frameworks (Express/Flask/FastAPI-style, body written at the registration
site) are exactly the case that heuristic already covers correctly. Both
paths are labeled `approximate` in the rendered output; this is
deliberately recall-leaning (a guard just outside the window reads as
"none found") over precision, matching the artifact's own stated
"lead, not a verdict" framing.

**Verified, not assumed:**
- Extracted the exact Python heredoc and bash `declare -A` block from the
  committed skill file (not a hand-typed re-creation) and ran both
  against synthetic fixtures on the host: `bash -n` for the extracted
  shell block, `python3 -m py_compile` plus an actual run for the
  extracted Python, path-substituted only (the hardcoded
  `/workspace/.source-aware` swapped for a scratch dir; no logic
  changed) since this host has no `/workspace`.
- A realistic 2-route WordPress-shaped fixture (a guarded
  `wp_ajax_save_settings` handler defined before its registration, an
  unguarded `wp_ajax_nopriv_*` sibling reaching the same tainted
  `$_POST`/`$wpdb->query` path) correctly resolved the guarded handler's
  window to its true definition line and found the `current_user_can()`
  check there, while the nopriv sibling correctly reported "none found"
  — exactly the priv/nopriv guard-gap shape this compiler exists to
  surface as a lead, cited directly in the skill text's own closing
  paragraph.
- A regression check against the original (non-realistic) synthetic
  fixture set — multiple routes in one file with no resolvable callback
  name, and a file with hits but no detected route at all (the
  file-level-summary fallback path) — confirmed unchanged, correct
  output after the callback-resolution fix was added.
- One caught test-fixture bug of my own during this: an early fixture
  accidentally placed a fake "route" line for `other/no-route.php` in
  the *route* raw file, so the "no detected route" fallback path never
  actually ran until the fixture was corrected — a bug in the test data,
  not the script; re-verified after fixing it.
- Confirmed `rg` on the actual host is a Claude-Code-tooling shell
  function (re-execs the Claude binary under `ARGV0=rg`), not real
  ripgrep — there is no ripgrep binary on this dev host at all, so the
  bash extraction commands themselves could not be run verbatim here.
  Validated the one genuinely novel mechanical question (does `xargs
  -d '\n' -n N <tool> -- < filelist` correctly preserve a
  space-containing filename as one argument and batch correctly) against
  real `grep` with identical `-n -H` flag semantics instead, then
  simplified away from that xargs/file-list form entirely once testing
  showed the simpler direct `rg -n -e PATTERN .` form (no file list, no
  batching) produces identical output — real ripgrep's own flag surface
  (`-n`, `-H`, `--no-heading`, `-e`) was not independently re-verified on
  this host, since the file already relies on those exact flags
  elsewhere (`custom/source_aware_sast.md`'s own pre-existing
  "Logic-bearing functions" section) and this is standard, stable
  ripgrep behavior.
- `tests/test_skill_dir_extension.py` (20 tests) unchanged; skill file
  still loads cleanly via `_qualified_skill_file_for_name` with a
  balanced code-fence count. Full suite re-run clean: 1232 passed, 1
  skipped, only the same pre-existing/unrelated `test_pricing.py` litellm
  alias failure.

**Committed** as its own commit, separate from Piece 1 and from Piece
1's CLAUDE.md write-up commit (`33164fc`) — skill-only change, no
Python/tests touched, so no shared blast radius with Piece 1's plumbing.

**Not yet started**: Piece 3 (Differential Authorization — extending
`parameter_mutation_testing.md`'s Layer B with tiered multi-actor replay
for black-box BOLA/BFLA, gated on 2+ provisioned accounts from
`account_provisioning.md`). Full design already exists in this
conversation; next step is starting it.

**Piece 3 — Differential Authorization: implemented and committed.** New
`### Actor Replay (Differential Authorization)` subsection in
`analysis/parameter_mutation_testing.md`'s Layer B, extending — not
replacing — the existing single-actor three-way mutation engine with
tiered multi-actor replay for black-box BOLA/BFLA, gated on 2+
provisioned actors from `account_provisioning.md`. Skill-only, no
Python/Dockerfile touched.

**A real design gap found while building the worked test (item 6 of the
plan), fixed before shipping — the most important finding of this
piece.** The original design said an actor-replay comparison reuses
Layer B's existing `signal_class` engine "unchanged." Building the
required test scenario (a single-actor mutation test that looks clean,
an actor-replay comparison that catches the same endpoint's real leak)
surfaced that this is subtly wrong: `signal_class`'s existing 5 rules
compute `"none"` when two responses are identical — correct as "boring,
nothing happened" for a mutation-vs-control comparison, but for an
actor-replay comparison where a non-owner's response is *supposed* to
differ from the owner's, an identical response (`"none"`) is the
strongest possible leak signal, not the absence of one. Applying the
unmodified rules naively would have silently read the worst case as
`"none"` and moved on — exactly the wrong direction. Fixed by adding one
new field, `owner_scope_verdict` (`not_applicable` / `isolated` /
`leak_suspected`), computed from the *same* underlying diff record via
its own small, deterministic rule set (still no LLM judgment, still not
a score) rather than changing `signal_class` itself, which stays correct
and meaningful for the far more common mutation-axis case:
- `not_applicable` — no `owner_scoped:<actor_id>` expectation declared
  (every mutation-axis record; the default, backward-compatible case).
- `isolated` (safe/expected) — owner declared, replaying actor isn't the
  owner, and the two responses differed (`signal_class != "none"`).
- `leak_suspected` — owner declared, replaying actor isn't the owner,
  the two responses are identical (`signal_class == "none"`), **and**
  the shared status is a 2xx success — that last guard specifically
  rules out two actors coincidentally sharing an identical denial/empty
  response (also `signal_class: "none"`, but not a content leak), a
  false-positive shape confirmed and guarded against in the test below.

**Design correction, generalizing an initially IDOR-flavored term**: the
first draft of `owner_scoped:<actor_id>` was written purely in
object-ownership language ("declares which actor owns the object"),
which doesn't fit `broken_function_level_authorization.md`'s privilege
axis (there's no "object" being owned, just an action a role either can
or can't invoke). Reworded to "the actor legitimately entitled to a real,
successful response to this exact request" — object owner for IDOR,
sufficiently-privileged actor for BFLA — so the same expectation kind
and the same `owner_scope_verdict` reading serve both cross-referencing
skills without a second, parallel mechanism.

**Also added, per the design**: `comparison_axis: "mutation" |
"actor_replay"` on the Diff Record Schema (additive, so existing
mutation-axis records are unaffected); the trigger tiers exactly as
designed (every already-flagged family member + one representative
member per family always, bounding the always-run cost at O(families)
rather than O(members)); `actor_replay_status` added to
`mutation_candidates.md`'s per-family row schema; cross-reference
sentences in `idor.md` and `broken_function_level_authorization.md`
pointing at the new subsection (each also told to read
`owner_scope_verdict`, not `signal_class`, for these records); one
sentence in `account_provisioning.md` noting `parameter_mutation_testing.md`
consumes the tokens it saves.

**Verified, not assumed** — since this piece is schema/spec-only (no
Python implementation exists anywhere for Layer B's engine; it's a
skill file an LLM agent interprets at request-time, not code this repo
runs), "testing" it meant implementing the documented algorithm exactly
as written in a throwaway Python simulation and checking it against a
synthetic scenario, the same standard Piece 2 was held to:
- **The exact "looks clean, actor-replay catches it" scenario the
  design claims to handle**: a single-actor mutation test using a
  synthetic (non-existent) candidate object ID against a backend that
  wraps a "not found" condition in the same 200-status/same-shape
  envelope as a real success (a real, common API anti-pattern) —
  correctly produces `signal_class: "none"` on the single-actor side,
  masking a genuinely missing ownership check. The corresponding
  actor-replay comparison — a second real provisioned actor requesting
  the first actor's real, existing object ID, byte-identical request,
  no mutation — correctly produces `signal_class: "none"` (same
  response) and `owner_scope_verdict: "leak_suspected"`, exactly the
  case mutation testing alone could not have caught (it never had a
  second real object ID to try).
- **Negative control 1**: a properly isolated endpoint (a denied,
  differently-shaped response) correctly reads `isolated`, not a false
  positive.
- **Negative control 2, the one that specifically validates the 2xx
  guard added during design**: two actors coincidentally sharing an
  identical 404 (`signal_class: "none"` too, since both responses are
  identical) correctly reads `isolated`, not `leak_suspected` — proving
  the guard against the "shared denial" false-positive shape actually
  works, not just that it was written down.
- **Tiering logic**: a synthetic 3-member family (one representative/
  clean, one already-flagged by its own single-actor signal, one clean
  and non-representative) correctly selects exactly 2 of 3 members for
  replay — confirming the O(families) cost bound is real, not just
  asserted.
- **Sanity checks**: a mutation-axis record (`owner_declared=False`)
  and the owner's own replay of their own object both correctly read
  `not_applicable`.
- All 5 edited skill files confirmed to still load cleanly via
  `_qualified_skill_file_for_name` with balanced code-fence counts.
  `tests/test_skill_dir_extension.py` (20 tests) unchanged. Full suite
  re-run clean: 1232 passed, 1 skipped, same pre-existing/unrelated
  `test_pricing.py` litellm-alias failure as Pieces 1 and 2.

**Committed** as its own commit — skill-only, no shared blast radius
with Pieces 1/2's Python plumbing or Piece 2's bash/Python distillation
script.

**Follow-up gap caught in review, fixed the same night**: the committed
version fully documented `owner_scope_verdict`'s polarity inversion in
the "Actor Replay" subsection itself, but `mutation_candidates.md`'s own
schema description (the "Where the Family Map Lives" bullet) still said
only "their last `signal_class`" for a family's candidates, with no
mention of what an actor-replay candidate should log instead. A future
agent — or session — populating or reading that ledger without
re-reading the whole Actor Replay subsection first could reuse
`signal_class` there and reintroduce the exact ambiguity this piece
exists to resolve, one layer up, in the artifact a later agent actually
reads first. Fixed with two additions, not one — a sentence in the
ledger-schema bullet itself ("for an actor-replay candidate
specifically, log its last `owner_scope_verdict`, not `signal_class`")
and a closing paragraph in the Actor Replay subsection stating the same
rule from the other direction — deliberate redundancy, since this is
exactly the kind of cross-cutting invariant worth restating wherever a
reader might land rather than defining once and hoping it's found.
Verified: skill file still loads cleanly (balanced fences, 22679 chars,
up from 21733), `tests/test_skill_dir_extension.py` unchanged, full
suite re-run clean (1232 passed, 1 skipped, same pre-existing
`test_pricing.py` failure). Committed as a small follow-up on top of
Piece 3's own commit.

**All three pieces from the external architecture review are now
implemented and committed.** None introduced an LLM-generated
fake-precision score anywhere: Piece 1's `corroborations` is a plain
count of distinct confirming targets, Piece 2's structural facts carry
no vulnerability judgment at all, and Piece 3's `owner_scope_verdict`
is a categorical read of a deterministic diff, never a confidence
number — the stated constraint from the start of this track held
through all three.

## 22. TRUST BOUNDARY MAPPER (PIECE 4) — IMPLEMENTED AND COMMITTED

Continuation of §21's external-architecture-review track. Two more
pieces from the same review: Piece 4 (Trust Boundary Mapper) and Piece 5
(Progressive Context). Piece 4 done first, per plan.

**Research finding that changed the plan, caught before any code was
written** — same "verify, don't assume" discipline that caught Piece 2's
window-direction bug and Piece 3's `signal_class` polarity bug: read
`account_provisioning.md` closely and confirmed it does **not** actually
capture what a trust-boundary mapper needs to formalize.
- The only artifact it *always* instructs writing is `auth_tokens.txt` —
  a flat, unstructured token dump, zero fields. The structured
  `auth_accounts.jsonl` form was offered only as a parenthetical
  alternative, and even that form's documented fields (`principal, role,
  tenant, token/cookie, how it was obtained`) carry `role` as free text
  with no hierarchy — nothing in the codebase said whether "vendor"
  outranks "buyer."
- **Object ownership was never recorded anywhere.** "Provisioning Two
  Accounts" already instructed creating "its own object created under
  it" per account, but never said to write down *which* object (type +
  ID) — so there was no ownership graph to formalize; it had to be
  captured at the source first.
- A second, related gap surfaced while designing the concrete
  distillation script (not from the initial account_provisioning.md
  read, but from checking what Piece 4 would actually read hierarchy
  evidence from): `broken_function_level_authorization.md` describes
  building an "Actor × Action matrix" as a methodology step but never
  persists it anywhere — no artifact existed for a role-hierarchy
  derivation to read. Flagged and fixed as part of this piece rather
  than silently worked around, since without it the "falls back to
  unordered set when no BFLA matrix has run yet" behavior would have
  been vacuously true (there was never a matrix to fall back from).

**Fixed at the source, both additive, before building the mapper
itself:**
- `account_provisioning.md`'s "Provisioning Two Accounts" — new bullet:
  record the just-created object's `(type, id)` against its owning
  account immediately, in `auth_accounts.jsonl`, "the one piece of state
  trust_boundary_mapping.md cannot recover later if it's skipped." Its
  "Saving Tokens for Reuse" section promotes the structured
  `auth_accounts.jsonl` form from a parenthetical option to the
  recommended default whenever 2+ accounts get provisioned, with a
  concrete schema example including the new `owned_objects: [{"type":
  ..., "id": ...}]` field.
- `broken_function_level_authorization.md`'s Testing Methodology step 1
  — one added sentence: append each actor×action cell's result to
  `/workspace/recon/actor_action_matrix.jsonl`
  (`{"principal", "role", "action", "result": "allowed"|"denied"}`) as
  the matrix is built, naming `trust_boundary_mapping.md` as the sole
  consumer.

**New file** `strix/skills/reconnaissance/trust_boundary_mapping.md` —
builds `/workspace/recon/trust_boundaries.md` from `auth_accounts.jsonl`
(required) and `actor_action_matrix.jsonl` (optional). Purely descriptive
extraction, same discipline as §21's Attack Surface Compiler: no
hypotheses, no scores, no predicted leaks. Four sections:
- **Actors** — principal/role/tenant/owned_objects, one row per
  provisioned account, role reported verbatim, never reworded or ranked.
- **Role Relationships** — derived **only** from observed
  `actor_action_matrix.jsonl` results, never from role names. Four
  honest outcomes rather than a forced binary: a confirmed superset edge
  (real evidence, cited to how many actions were compared), peers (tied
  on everything tested), **divergent** (each role beat the other on at
  least one tested action — genuinely incomparable, not a data gap and
  not silently merged into "peers"), and insufficient data (nothing
  tested against both roles yet). With no matrix at all, every role is
  an explicit unordered set — exactly the "don't force a linear order
  onto a system that doesn't have one" instruction from the design pass.
- **Object Type → Owner Map** — per object type (normalized
  singular/plural-insensitively, e.g. `projects`/`project` collapse to
  one type), which actors own an instance, which share a role
  (horizontal/BOLA candidate pool), which differ by role (vertical/BFLA
  candidate pool).
- **Test Pairs** — the actual worklist: horizontal pairs from same-role
  co-ownership; vertical pairs **only** where a real superset edge
  justifies one, always phrased as the lower-privileged actor replaying
  the higher one's object — the interesting direction, since the
  reverse (a senior role reaching a junior's object) is often by design.

**Feeds Piece 3 without changing its cost bound**: `parameter_mutation_testing.md`'s
Actor Replay subsection gained a paragraph — when `trust_boundaries.md`
exists, its Test Pairs choose *which* pair fills the already-mandated
one-representative-per-family slot (same-role pair for `item`/`collection`
kind families, vertical pair for `action` kind families) instead of an
arbitrary two accounts. Still exactly one representative per family;
this only improves which pair fills that slot. Explicitly a no-op
("this paragraph is a no-op") when `trust_boundaries.md` doesn't exist —
Piece 3's original arbitrary-pair fallback is unchanged.

**Wiring**: `coordination/root_agent.md`'s "Provision Accounts Before
Hunting" phase gained one paragraph running `trust_boundary_mapping.md`
immediately after provisioning, still before the hunting waves; one-line
cross-references added to `idor.md` (Test Pairs name the horizontal
pairs) and `broken_function_level_authorization.md` (Test Pairs name
the vertical pairs); a Cross-References entry in
`parameter_mutation_testing.md`.

**Verified, not assumed** — same standard as Pieces 2/3, since this is
another skill-file distillation script with no existing Python
implementation to reuse: wrote the exact algorithm as a standalone
script first, tested against four synthetic scenarios before embedding
it in the skill file, then **re-extracted the actual embedded heredoc
from the committed skill file** (not the standalone copy) and re-ran it
against all four to confirm byte-identical output — same discipline as
Piece 2's extraction-and-rerun check:
1. **The user's requested scenario**: 3 accounts, two same-role peers
   each owning a `project`/`projects` object (confirming the
   singular/plural normalizer), one lower-privileged role with no
   object. With no `actor_action_matrix.jsonl` present: correctly
   produces the unordered-set fallback and exactly one horizontal (BOLA)
   pair, zero vertical pairs (no hierarchy evidence to justify one).
2. **Same accounts, matrix added** showing the lower role denied on 2
   actions the higher role was allowed, tied on 1: correctly produces a
   superset edge and two vertical (BFLA) pairs (one per owned object),
   in addition to the unchanged horizontal pair.
3. **A 3-role, 2-comparison-shape scenario** built specifically to
   exercise the two subtler buckets: two roles tied on every tested
   action correctly read as peers; two roles each denied on the other's
   allowed action correctly read as divergent (not forced into either
   peers or a hierarchy); a third role pair with no actions tested
   against both correctly read as insufficient data.
4. **No `auth_accounts.jsonl` at all**: correctly reports nothing to
   build rather than guessing.
5. A real Python bug caught and fixed *before* the standalone script was
   even first run (not after): `edges` was referenced outside the scope
   where it was defined, and a garbled `if "edges" in dir() else []`
   placeholder from initial drafting — both fixed before the first test
   run, not discovered by testing this time, but worth noting the
   category is the same as Piece 2's caught bugs: a scripting mistake,
   not a design mistake.
6. All 6 edited/new skill files confirmed to load cleanly with balanced
   code-fence counts, new skill name `trust_boundary_mapping` resolves
   with no collisions against the other 4 `reconnaissance/*` skills.
   `tests/test_skill_dir_extension.py` (20 tests) unchanged. Full suite
   re-run clean: 1232 passed, 1 skipped, same pre-existing/unrelated
   `test_pricing.py` litellm-alias failure as every prior piece in this
   track.

**Committed** as its own commit — skill-only, no Python/Dockerfile
changes.

## 23. PROGRESSIVE CONTEXT (PIECE 5) — IMPLEMENTED AND COMMITTED

Final piece of §21/§22's external-architecture-review track — a
cost-reduction discipline, no new judgment mechanism.

**Research findings, both confirmed rather than assumed:**
- **No existing "read small, escalate" pattern anywhere in the skill
  tree.** Grepped for it before writing anything; the only remotely
  related sentence in the whole repo is `custom/source_aware_sast.md`'s
  "restrict to changed files first, then expand only when needed" — and
  that governs which *files* a diff-scoped scan touches, not how much of
  one file to read. So this wasn't "formalizing scattered existing
  practice," as the original framing assumed — it needed to be authored
  fresh, in the tone `analysis/counterevidence.md` already established
  (targeted-not-exhaustive), not copied from anywhere.
- **No new tool needed, confirmed by checking `strix/tools/` directly**:
  there is no dedicated file-read tool in Strix's own tool set at all —
  every file read an agent makes goes through the sandbox's
  `exec_command` shell access (`cat`, `sed -n`, `rg -n -A/-B/-C`,
  `awk`), which already supports an arbitrary windowed read as cheaply
  as a whole-file one. This piece is documentation only.

**Implemented**: new `## Progressive Context — Read the Minimum First`
section in `strix/skills/analysis/source_aware_discovery.md` (already
always-loaded for whitebox scans per §9), placed right after "Instance
Discipline" since it's about reading mechanics, before "Where the Real
Control Lives." A 5-rung ladder — route+metadata (free, already in
`entry_points.md`/`attack_surface.md`) → the enclosing function/route
body (one windowed read, explicitly reusing §22's `attack_surface.md`
window when it already exists rather than re-deriving the boundary) →
caller/callee one hop (not a transitive closure) → whole file →
cross-file (base class, shared module, middleware/decorator registered
elsewhere) — with concrete triggers for each escalation (an
undefined-in-range `self.prop`/bare identifier → whole file; a
resolved caller/callee not present anywhere in the current file →
cross-file), and an explicit instruction to **stop** escalating the
moment the specific question is answered rather than reading further
"just in case."

Cross-referenced to `parameter_mutation_testing.md`'s "Cost Discipline"
and `custom/source_aware_sast.md`'s `entry_points.md` (the same
compute/read-the-cheap-thing-first philosophy already established
elsewhere in this project) and to `analysis/counterevidence.md`'s
"confirm *that* call, in *that* context" (the same targeted-not-
exhaustive discipline, applied here to how much gets read rather than
what counts as proof).

Scoped explicitly to white-box code-reading, where this skill already
lives — noted, not silently decided, that the same principle could
extend to black-box JS-bundle mining in `asset_discovery.md` later.

**Verified**: skill file loads cleanly (balanced fences, 14058 chars,
up from ~11.4k), `tests/test_skill_dir_extension.py` (20 tests)
unchanged, full suite re-run clean (1232 passed, 1 skipped, same
pre-existing/unrelated `test_pricing.py` failure as every other piece
in this track). Only the one file changed — no Python/Dockerfile
touched, matching the "documentation only" finding above.

**Committed** as its own commit.

**All five pieces from the external architecture review (§21-§23) are
now implemented, tested, documented, and committed.** None introduced
an LLM-generated fake-precision score anywhere across any of them.

## 24. CONTEXT CACHE (PIECE 6) + FRAMEWORK-TRIGGER CONSOLIDATION
    (PIECE 7, DOWNGRADED) + TOKEN ROI TRACKING (PIECE 8) — ALL IMPLEMENTED
    AND COMMITTED — COST-REDUCTION TRACK COMPLETE

Continuation of the cost-reduction track (§21-§23), three more proposed
pieces from the same review: Piece 6 (Context Cache), Piece 7 (Adaptive
Scan), Piece 8 (Token ROI Tracking). Research done first for 6 and 7
before any code; both findings changed the plan.

**Piece 7 finding, before any design work**: read `_resolve_skills()` in
`strix/agents/prompt.py` directly. Skill loading is **already fully
selective** — a small fixed baseline auto-loads (scan mode, tooling,
`counterevidence`/`severity_calibration`, root/whitebox extras); every
`vulnerabilities/*.md`/`frameworks/*.md` file loads only via an explicit
`skills=` list at spawn time, capped at 5 per agent
(`validate_requested_skills`). There is no code path where an agent gets
the full ~50-file skill set — the cap makes that structurally
impossible. Piece 7's stated problem ("avoid loading all ~50+ skill
files into every agent") does not exist. **Downgraded, not built as
originally scoped**: no new fingerprint/gating machinery. Instead, a
much smaller, purely informational consolidation (see below).

**Piece 6 finding**: `custom/source_aware_sast.md`'s Attack Surface
Compiler (§21 Piece 2) already solves cross-agent duplication for
*route-shaped* mechanical facts — that pipeline is a deterministic
script's output, built once, shared by existing convention
(`coordination/source_aware_whitebox.md`'s "does not re-derive the map
from source"), so there's nothing to cache there. What it doesn't cover:
non-route files — shared base classes, utility/trait modules — that
`analysis/source_aware_discovery.md`'s Progressive Context ladder (§23
Piece 5) explicitly sends multiple agents into independently when their
different candidates depend on the same shared helper (the user's own
example: a multi-agent scan's likely overlapping reads of shared base
classes). Grepped the whole coordination tree — nothing addresses this;
`root_agent.md` mentions "redundant work" once, generically, no
mechanism. Piece 6 is real, scoped narrower than originally framed:
non-route files specifically, not a re-implementation of what Piece 2
already solved.

**Piece 6 — implemented.** New module `strix/tools/file_context_cache/tools.py`
(+ `__init__.py`), mirroring `coverage`/`negative_knowledge`'s
hydrate/lock/atomic-persist shape but **scoped to this run's own
`state_dir`** (`{state_dir}/file_context_cache.json`), not
`negative_knowledge`'s fixed cross-scan `~/.strix/` path — a file
summary is only trustworthy for as long as this scan's own checkout is
the one being read, so nothing here should outlive the run. Considered
reusing `notes/tools.py` — rejected: it's a linear, uuid-keyed, free-text
ledger with no hash-lookup, so a "does this exact content already have a
summary" query would mean unenforced substring-scanning for an embedded
hash.

**Design correction found while specifying it, before any code was
written** — same discipline as every prior piece in this track: a naive
version would have the host-side tool open the file itself to hash it,
but host-side tools run in the host process with no reliable path back
from the container's `/workspace/...` spelling to a host filesystem
location. **Fixed**: the calling agent hashes the file itself
(`sha256sum <file>`, it already has full shell access) and passes the
digest as an argument — the tool is a pure key-value store with zero
file I/O of its own, exactly mirroring how `negative_knowledge` takes
agent-named API tokens rather than deriving a key from file access.

- `query_file_summary(file_path, content_hash)` — exact sha256-hash
  match, read-only. A hit is keyed on content, not path, so a
  duplicate/vendored copy at a different location still hits, and one
  byte of drift correctly misses.
- `record_file_summary(file_path, content_hash, summary)` — upsert on
  the same hash (a second confirmation or a refined summary replaces
  rather than duplicates).
- `content_hash` is validated as a 64-char lowercase hex string
  (enforcing sha256 specifically, so every caller's key space aligns) —
  rejected otherwise with a clear error rather than silently mismatching.

Wired into `analysis/source_aware_discovery.md`'s Progressive Context
ladder (§23) at exactly rung 5, "Cross-file" — the ladder already names
the moment an agent is about to read a shared base class/utility module;
this just adds "check the cache first, record a summary after" at that
existing decision point rather than inventing a new one.
`strix/agents/factory.py`'s `_BASE_TOOLS` gains both tools;
`strix/core/runner.py` gains one more `hydrate_*_from_disk(state_dir)`
call, unconditional (no settings toggle, unlike `negative_knowledge` —
this cache never outlives the run, so there's no cross-scan retention
concern to opt out of).

**Verified**: `tests/test_file_context_cache_tool.py` (7 tests)
including the exact scenario requested — agent 1 records a summary for
a shared base class, agent 2 (a different path, identical content)
queries and gets the cached summary back, `recorded_by`/
`first_recorded_for_path` intact — plus different-content-same-path
miss, upsert-not-duplicate, malformed-hash rejection, empty-field
rejection, disk round-trip, and hash case-insensitivity. Skill file
loads cleanly (balanced fences). `tests/test_skill_dir_extension.py`
(20 tests) unchanged. Full suite re-run clean: 1239 passed (up 7 from
the new test file), 1 skipped, same pre-existing/unrelated
`test_pricing.py` litellm-alias failure as every other piece in this
track.

**Piece 7, downgraded scope — implemented.** New
`## Framework and Technology Detection Triggers (Reference)` section in
`custom/source_aware_sast.md`, placed right after "Fast Start." A
6-row table indexing every existing "detect X, load skill Y" trigger
already documented later in the same file (`wordpress`, `npx_confusion`,
`infrastructure_lifecycle`, `llm_applications`, `semantic_confusion`,
`dependency_cve_scanning`) — gathered while grepping the whole skill
tree for `load_skill(` and `` Load `X` `` phrasing to confirm the list
is accurate and complete, not guessed. **Purely informational**: no
enforcement change, no trigger removed or narrowed, each row points back
to the section that explains it in full — an index, not a replacement.
Interesting secondary finding: every trigger already lived in this one
file, not scattered across many different skill files as the original
framing assumed — the "scattered" problem was really "scattered across
one file's prose," which a single index still fixes.

**Verified**: skill file loads cleanly (balanced fences, 31126 chars, up
from ~29.2k), `tests/test_skill_dir_extension.py` unchanged.

**Committed separately** — Piece 6 (new tool + factory/runner wiring +
`source_aware_discovery.md`) as one commit, the Piece 7 consolidation
(`source_aware_sast.md` only) as its own commit, since they touch
disjoint files and are independently revertable.

**Piece 8 — Token ROI Tracking: implemented and committed.** Gives the
root agent real, non-fabricated per-agent numbers for wind-down
judgment, surfaced in `view_agent_graph()` — the existing "who's
running/waiting" tool — rather than a new one.

**Grounding, checked before writing code**: `strix/report/usage.py`'s
`LLMUsageLedger` already tracks per-agent tokens/cost
(`_agent_usage[agent_id]`); `coverage/tools.py`'s entries already carry
`agent_id`. Neither needed new tracking. The one thing genuinely
missing anywhere: a cumulative per-agent tool-call count —
`TurnToolCallLimiter` (`strix/config/tool_call_limits.py`) only caps
calls within a single turn and resets, no running total exists. Also
considered and rejected: deriving tool-call counts by querying each
agent's persisted SQLite session history (`agents.db`) instead of a live
counter — correct in principle, but would mean a full session read on
every `view_agent_graph` call, and the SDK's session interface doesn't
expose a cheap count-only query; a lightweight in-memory counter at a
single shared choke point is far cheaper and was already the original
design.

**New module** `strix/tools/agent_metrics/tools.py` — `record_tool_call(agent_id)`
/ `get_tool_call_count(agent_id)`, in-memory only, deliberately **not
persisted** (unlike `coverage`/`notes`): these numbers inform the
*current* process's root-agent judgment, not a resumed scan, and adding
a disk-write path for metrics-only counters wasn't justified.
`record_tool_call` never raises — this runs on every single tool call in
the system, so a bug in it must never break a real tool invocation.

**The hook point, found by tracing rather than guessed**: every tool
call in `strix/agents/factory.py` passes through one of four wrapping
functions depending on (tool type × chat-completions vs. Responses API):
`_function_tool_with_error_result`, `_custom_tool_as_function_tool`,
`_bound_custom_tool`, `_with_bounded_result`. Initially added the counter
to only the first — **caught before finalizing that this would have
undercounted dramatically**, since `CustomTool`s (`exec_command`,
`write_stdin`, `patch` — the most frequently called tools in any real
scan) go through the other three paths entirely. Fixed by adding
`_record_tool_call_metric(ctx)` to all four.

**Verified the hook doesn't double-count in production** — traced
whether any of the four wrapping functions could be applied more than
once to the same shared tool object (which would nest the counter call
and inflate counts): `_BASE_TOOLS`'s function-tool singletons (e.g.
`view_agent_graph`) only ever pass through `_with_bounded_result`, which
already carries a pre-existing `_strix_bounded` idempotency guard (added
by the original maintainers, not by this change) — confirms tools get
wrapped exactly once regardless of how many agents get built in one
process. The other three wrapping functions apply only to each agent's
own freshly-constructed sandbox `Filesystem`/`Shell` capability tools
(`Filesystem(configure_tools=...)`/`Shell(...)` construct fresh
`CustomTool` instances per `SandboxAgent(...)` call), never a shared
singleton — so no double-wrap risk there either.

**`view_agent_graph()` extended**, not replaced: `strix/tools/agents_graph/tools.py`
gained `_agent_roi_suffix(agent_id)`, rendering three real numbers for
`running`/`waiting` agents only (a finished agent's numbers are frozen
and less relevant to a wind-down decision): tokens + cost share (from
`LLMUsageLedger`), cumulative `tool_calls` (the new counter), and
coverage entries recorded (total, plus a trailing-window count).

**A second real bug caught by tracing the data flow before shipping,
not by testing after the fact**: the natural read, `ReportState.get_total_llm_usage()`,
turned out to return a **cached snapshot** (`run_record["llm_usage"]`)
that's only refreshed by `_sync_llm_usage_record()`, itself called only
from `save_run_data()` — which greping confirmed is called just twice in
the whole codebase, both near scan start/end, never on a periodic tick.
Using it would have shown stale, near-zero numbers for a still-running
agent's entire lifetime — exactly defeating this piece's purpose. Fixed
with a small, clean addition: `ReportState.get_live_llm_usage()`, a
one-line public method delegating straight to
`self._llm_usage.to_record()`, avoiding both the stale cache and a
private-attribute reach-around from `agents_graph/tools.py`.

**Windowing decision** (left to implementation-time judgment per the
plan): wall-clock (last 10 minutes), not tool-call-count-based, because
coverage entries already carry a timestamp and nothing tracks
"tool-call count at time of recording" — computing the alternative would
mean touching `coverage/tools.py`'s schema for a metrics-only piece.
Documented inline in the code as an explicit choice, not a default no
one decided.

New `**Reading Agent ROI**` subsection in `coordination/root_agent.md`
(after "Bound Parallelism" — no existing wind-down section to extend)
gives the root agent a plain-language reading of the numbers: rough
signal (tool-call volume with no new coverage growth suggests circling,
not a rule to automate), and prefers asking an agent to wrap up over
`stop_agent` so it can still hand off partial findings. Explicitly no
score, no threshold, no auto-stop anywhere in this piece.

**Verified, including one test-isolation trap worth recording**:
`tests/test_agent_roi.py` (5 tests) — the tool-call counter increments
independently per agent, `get_live_llm_usage()` demonstrably differs
from the stale `get_total_llm_usage()` (proving the bug fix is real, not
assumed), `_agent_roi_suffix()` renders the exact requested scenario (a
simulated 62-tool-call agent with 3 coverage entries) correctly, graceful
handling with no report state/no activity, and a full SDK-level
`view_agent_graph()` invocation (via a real `ToolContext`, not a bare
`RunContextWrapper` — the SDK's error-handling path needs the former)
confirming the rendered line for a running agent carries ROI and a
completed agent's line does not. **One test failure surfaced only in the
full suite, not in isolation, traced to ground before touching
anything**: `view_agent_graph` is the real shared module-level
`FunctionTool` singleton, and an earlier test elsewhere in the suite
building a real agent had already wrapped it in place (via the
idempotent `_with_bounded_result`) — so the test's own direct call to
`.on_invoke_tool()` was itself a real, counted tool call once that
wrapping existed, which is correct production behavior the test's
hardcoded `== 2` assertion didn't account for. Fixed the test (assert
`>=` a captured baseline, with the reasoning documented inline), not the
production code, since the trace confirmed there was nothing wrong with
the code. Full suite re-run clean: 1244 passed, 1 skipped, same
pre-existing/unrelated `test_pricing.py` failure as every other piece in
this track.

**Committed** as its own commit.

**This closes the cost-reduction track's original eight-piece list**
(§21-§24 combined): Pieces 1-5 fully implemented, Piece 6 implemented
narrower than originally scoped (route-shaped duplication was already
solved by Piece 2; the real gap was non-route shared files), Piece 7
downgraded to a small documentation consolidation after research showed
its stated problem didn't exist, Piece 8 implemented as designed. No
piece introduced an LLM-generated score, confidence percentage, or
prediction anywhere — every new field across all eight pieces is either
a plain count, a categorical read of deterministic data, or free text a
human/agent judgment already governs elsewhere (`counterevidence.md`,
`severity_calibration.md`). Five real bugs were caught by actually
building tests/tracing data flow rather than trusting design review
alone (Piece 2's window-direction bug, Piece 3's `signal_class` polarity
bug, Piece 4's unrecorded object-ownership and unpersisted BFLA-matrix
gaps, Piece 8's stale-cache bug) — the throughline of the whole track.

## 25. THREE MORE COST/QUALITY PIECES — STOP-LOSS, CHAIN REASONER,
    PRIORITY QUEUE

A follow-on to §21-§24's track, from further discussion: Piece 9
(Stop-Loss / Marginal Information Gain — turns Piece 8's metrics into
an execution signal), Piece 10 (Attack-Chain Reasoner — a mechanical
pre-pass for root_agent.md's existing chaining step), Piece 11
(Hypothesis Priority Queue — categorical triage rubric). Same
discipline: no fake-precision scores, each extends an existing system.
Implementing in order 10, 9, 11 per the user's request (touch the most
heavily-used core tool first, want it stable before building on top).

### Piece 10 — Attack-Chain Reasoner: implemented and committed

**Research finding, the biggest one in this batch**: `root_agent.md`'s
"Chain Findings Before Finishing" section **already existed**, and
already covers most of what this piece originally described — enumerate
plausible chains from confirmed findings, spawn a validation subagent
per chain, report a validated chain at combined severity, and refuse to
elevate an unvalidated one (`counterevidence.md`'s discipline applied at
chain level), with named example chain patterns. The gap wasn't the
methodology — that section is **100% LLM reasoning, zero tooling
support**: step 1 says "enumerate plausible chains... from the actual
confirmed findings" with nothing but the root agent's own cold re-read
of every finding. Piece 10's real value is a mechanical pre-pass that
narrows that search, the same relationship Piece 2 has to
vulnerability-hunting.

**Second finding, which changed the concrete design**: read
`create_vulnerability_report`'s full ~20-parameter signature — every
field is free-text prose (`title`, `description`, `evidence`,
`technical_analysis`, ...) plus `endpoint`/`method`/`code_locations` for
location. **No structured field anywhere captures "what this discloses"
or "what this requires."** A textual/schema match per the original ask
("finding A discloses `booking_id`; finding B requires `booking_id`")
wasn't checkable without either fragile prose-regex (unreliable, not
really mechanical) or two new optional fields captured at the one point
they're cheaply known — same lesson as Piece 4's account-ownership gap.
User approved adding the fields directly rather than a separate
"tag after the fact" tool, for the same forgotten-step reason Piece 4
already established.

**Third finding**: findings live in `ReportState.vulnerability_reports`,
a **host-process, in-memory** list — not a sandbox file the agent's
shell can read mid-scan (`vulnerabilities.json` only gets written at
scan end, via `save_run_data()`, itself called from
`add_vulnerability_report` on every single filed finding — a more
frequent call pattern than §24's Piece 8 audit found for the *other*
`save_run_data()` call sites it grepped for, worth noting so a future
read of that section doesn't over-generalize "only twice in the
codebase" to every caller). Either way, this can't be a
`custom/source_aware_sast.md`-style embedded shell script like
`entry_points.md`/`attack_surface.md` — it needed a real tool.

**Built**:
- `strix/report/state.py`'s `add_vulnerability_report` — two new
  optional parameters, `discloses: list[str] | None` and
  `requires: list[str] | None`, stored as cleaned (stripped,
  empty-filtered) lists only when non-empty — fully backward compatible,
  every existing caller unaffected.
- `strix/tools/reporting/tool.py`'s `create_vulnerability_report` — same
  two optional parameters threaded through `_do_create`, with docstring
  guidance: plain identifier/field names only, not descriptions; most
  findings won't set either; used only for `list_chain_candidates`'
  mechanical cross-referencing, never for judgment or severity.
- **New tool** `list_chain_candidates` — host-side, reads
  `ReportState.vulnerability_reports` directly (already in memory, zero
  file I/O), computes every `discloses`/`requires` pairwise set-overlap
  across all filed findings (`_normalize_identifier`: lowercase +
  whitespace-collapse only — deliberately not underscore/space-equivalent,
  confirmed by a dedicated test after an early draft of the test itself
  assumed otherwise), returns candidate pairs
  (`discloses_report_id`/`requires_report_id`/`shared_identifiers`).
  Bidirectional overlaps (A discloses X that B requires, **and** B
  discloses Y that A requires) correctly produce two distinct directional
  candidates, not one collapsed row — a real chain runs a specific
  direction. An empty result carries an explicit `note` that this does
  not mean no chains exist, since most findings won't set these fields.
- Wired as a new **step 0** in `root_agent.md`'s existing "Chain Findings
  Before Finishing" — read before step 1's own enumeration, narrows but
  never replaces it.

**Verified**: `tests/test_chain_candidates.py` (6 tests) — the exact
requested scenario (finding A discloses `booking_id`, finding B
requires it, correctly surfaces as a candidate), a non-overlapping pair
correctly produces no candidate (with the explicit `note`),
case/whitespace-insensitive matching (and confirmed underscore/space
are *not* treated as equivalent — a real bug in the test's own first
draft, fixed in the test, not the code, once traced), untagged findings
counted but never candidates, no-report-state graceful handling, and the
bidirectional two-candidates case. Full existing reporting test suites
(`test_list_reports.py`, `test_reporting_fields.py`, 102 tests)
confirmed unaffected by the new optional parameters. Skill file loads
cleanly. Full suite re-run clean: 1250 passed (up 6), 1 skipped, same
pre-existing/unrelated `test_pricing.py` failure as every other piece in
this track.

**Committed** as its own commit.

