---
name: source-aware-sast
description: Practical source-aware SAST and AST playbook for semgrep, ast-grep, gitleaks, and trivy fs
---

# Source-Aware SAST Playbook

Use this skill for source-heavy analysis where static and structural signals should guide dynamic testing.

## Fast Start

Run tools from repo root and store outputs in a dedicated artifact directory:

```bash
mkdir -p /workspace/.source-aware
```

## Baseline Coverage Bundle (Recommended)

Run this baseline once per repository before deep narrowing. Both
semgrep and gitleaks below load a project-authored rule/config file
(`/home/pentester/tools/semgrep-rules`,
`/home/pentester/tools/gitleaks-rules/strix.gitleaks.toml`, baked into the
sandbox image) on top of the public registry packs and gitleaks' own
default ruleset — narrow, high-precision additions written and tested
against a real WordPress plugin, not broad `AIza.*`-style scans. See the
comments in those files for what each rule matches, what it deliberately
does not, and why. This does not change the FP-control model:
`counterevidence.md` still governs whether any hit — from a public pack
or from these — becomes a report.

```bash
ART=/workspace/.source-aware
mkdir -p "$ART"

semgrep scan --config p/default --config p/golang --config p/secrets \
  --config /home/pentester/tools/semgrep-rules \
  --metrics=off --json --output "$ART/semgrep.json" .
# Build deterministic AST targets from semgrep scope (no hardcoded path guessing)
python3 - <<'PY'
import json
from pathlib import Path

art = Path("/workspace/.source-aware")
semgrep_json = art / "semgrep.json"
targets_file = art / "sg-targets.txt"

try:
    data = json.loads(semgrep_json.read_text(encoding="utf-8"))
except Exception:
    targets_file.write_text("", encoding="utf-8")
    raise

scanned = data.get("paths", {}).get("scanned") or []
if not scanned:
    scanned = sorted(
        {
            r.get("path")
            for r in data.get("results", [])
            if isinstance(r, dict) and isinstance(r.get("path"), str) and r.get("path")
        }
    )

bounded = scanned[:4000]
targets_file.write_text("".join(f"{p}\n" for p in bounded), encoding="utf-8")
print(f"sg-targets: {len(bounded)}")
PY
# -d '\n' keeps a path containing spaces as one xargs argument instead of
# splitting it into two - without it, any target with a space in a file or
# directory name silently drops matches in that path (found by testing
# against a real target with a space-containing directory name).
xargs -r -d '\n' -n 200 sg run --pattern '$F($$$ARGS)' --json=stream < "$ART/sg-targets.txt" \
  > "$ART/ast-grep.json" 2> "$ART/ast-grep.log" || true
# --no-git: gitleaks's `detect` subcommand scans git COMMIT HISTORY by
# default and silently reports zero findings on a target with no .git at
# all (a plain extracted plugin/source tree, not a clone) - confirmed by
# testing against exactly that shape of target. --no-git switches it to
# scanning the working tree, which is what a source-aware scan wants.
gitleaks detect --source . --no-git --config /home/pentester/tools/gitleaks-rules/strix.gitleaks.toml \
  --report-format json --report-path "$ART/gitleaks.json" || true
# Verified-only by default: an unverified "secret" is exactly the noise the
# LLM has to spend a proof-gap pass ruling out, while a verified hit is
# already high-confidence and can go straight to reported. Verification
# makes a live API call to the credential's own provider, so it needs real
# network reachability — use the --no-verification form below instead when
# the target is offline/airgapped and that reachability doesn't exist.
trufflehog filesystem --no-update --json . > "$ART/trufflehog.json" || true
# Offline/unreachable-target fallback (verification impossible): trades
# confidence for coverage — every hit here is unverified and must go
# through the normal open_proof_gap path, never straight to reported.
#   trufflehog filesystem --no-update --json --no-verification . > "$ART/trufflehog.json" || true
# Keep trivy focused on vuln/misconfig (secrets already covered above) and increase timeout for large repos
trivy fs --scanners vuln,misconfig --timeout 30m --offline-scan \
  --format json --output "$ART/trivy-fs.json" . || true
```

## Entry-Point Map (Build Once, Reuse Everywhere)

The baseline bundle above produces raw tool JSON — useful, but every
subagent that reads it pays the token cost of re-parsing and
re-interpreting the same output. Run this distillation exactly **once**
per repository, immediately after the baseline bundle, into
`/workspace/.source-aware/entry_points.md`. Every subagent spawned after
this point reads that file instead of re-deriving the map from source or
re-running the scanners — see `source_aware_whitebox.md`'s Agent
Delegation Guidance and `root_agent.md`'s "Reuse Recon and Triage
Artifacts" for the reuse discipline this artifact exists to support.

**Three tiers, ordered by signal, deliberately not one merged list.** An
earlier version of this distillation folded semgrep's curated hits and
ast-grep's *ruleless* `$F($$$ARGS)` sweep (which matches literally every
function call in the codebase) into one file:line-sorted list. Tested
against a real 38-file WordPress plugin: the ast-grep sweep alone
produced ~14,600 entries, and a genuine hardcoded-credential hit from a
curated semgrep rule landed at line 11,981 of a 14,664-line file —
buried under 82% of undifferentiated noise, with nothing distinguishing
"a rule flagged this as a hardcoded credential" from "this line calls
`get_option()`". That is exactly the shape of miss this artifact exists
to prevent, so the structure below is three tiers:

1. **High-Signal Findings** — the project-authored rules from
   `custom/semgrep-rules/` plus gitleaks and trufflehog. Small (single
   digits to low tens of lines on a real plugin), rule-authored, this is
   what to read before anything else.
2. **Public-Pack Scanner Hits** — every other semgrep result (the
   `p/default`/`p/golang`/`p/secrets` registry packs). Still curated
   (semgrep matched a specific rule, not "any call"), but broader and
   less precision-tuned than tier 1 — kept as its own tier rather than
   merged into tier 1 (diluting the small, high-confidence set) or
   silently dropped (losing real signal).
3. **General Structural Sweep** — the raw ast-grep dump, last, explicitly
   labeled as a map to grep through when tracing a specific call site,
   never a list to read top to bottom.

Same pass, same zero LLM cost, also flag functions whose name suggests
they compute a value with real-world consequence or gate a state
transition, so the business-logic reasoning agent (see
`vulnerabilities/business_logic.md`) gets a prioritized starting list
instead of reading the whole tree cold:

```bash
ART=/workspace/.source-aware
{
  echo "# Entry-Point Map"
  echo
  python3 - <<'PY'
import json
from pathlib import Path

art = Path("/workspace/.source-aware")
high_signal = []
public_pack = []

# Bare rule ids from custom/semgrep-rules/wordpress-secrets-and-sinks.yml.
# Semgrep prefixes check_id with the config path it was loaded from (which
# differs between a local test run and the sandbox's
# /home/pentester/tools/semgrep-rules), so match on the id's own suffix
# rather than hardcoding a path.
CUSTOM_RULE_IDS = {
    "hardcoded-cloud-key-literal-to-sink",
    "hardcoded-cloud-key-literal-in-defaults-array",
    "unserialize-tainted-without-class-restriction",
    "wpdb-tainted-query-without-escaping",
}

# semgrep.json is one JSON object with a top-level "results" array.
try:
    data = json.loads((art / "semgrep.json").read_text(encoding="utf-8"))
    for r in data.get("results", []):
        if not isinstance(r, dict):
            continue
        p = r.get("path")
        start = r.get("start")
        line = start.get("line") if isinstance(start, dict) else None
        check_id = r.get("check_id") or "semgrep"
        if not p:
            continue
        bare_id = check_id.rsplit(".", 1)[-1]
        row = (p, line or 0, f"semgrep: {check_id}")
        if bare_id in CUSTOM_RULE_IDS:
            high_signal.append(row)
        else:
            public_pack.append(row)
except Exception:
    pass

# gitleaks.json is a top-level JSON array (empty array, not missing, when clean).
try:
    data = json.loads((art / "gitleaks.json").read_text(encoding="utf-8"))
    for r in data or []:
        if not isinstance(r, dict):
            continue
        p = r.get("File")
        line = r.get("StartLine")
        rule = r.get("RuleID") or "gitleaks"
        if p:
            high_signal.append((p, line or 0, f"gitleaks: {rule}"))
except Exception:
    pass

# trufflehog.json is NDJSON, one match per line, NOT a single JSON blob.
try:
    for line_text in (art / "trufflehog.json").read_text(encoding="utf-8").splitlines():
        line_text = line_text.strip()
        if not line_text:
            continue
        try:
            r = json.loads(line_text)
        except Exception:
            continue
        if not isinstance(r, dict):
            continue
        fs = (((r.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {})
        p = fs.get("file")
        line = fs.get("line")
        rule = r.get("DetectorName") or "trufflehog"
        verified = "verified" if r.get("Verified") else "unverified"
        if p:
            high_signal.append((p, line or 0, f"trufflehog: {rule} ({verified})"))
except Exception:
    pass

print("## High-Signal Findings (project-authored semgrep rules + gitleaks + trufflehog — read this section first)")
print()
for p, line, rule in sorted(high_signal, key=lambda t: (t[0], t[1])):
    print(f"- {p}:{line} — {rule}")
print()
print("## Public-Pack Scanner Hits (semgrep p/default + p/golang + p/secrets — broader, less precision-tuned than the section above)")
print()
for p, line, rule in sorted(public_pack, key=lambda t: (t[0], t[1])):
    print(f"- {p}:{line} — {rule}")
PY
  echo
  echo "## Logic-bearing functions (candidates for business-logic QA)"
  rg -n --type-add 'code:*.{php,py,js,ts,go,java,rb}' -tcode \
    -e '\b(function|def|func)\s+\w*(price|total|amount|balance|quantity|discount|refund|charge|calculate|compute)\w*' \
    -e '\b(function|def|func)\s+\w*(can_|validate_|check_|authorize|transition|approve)\w*' \
    . || true
  echo
  echo "## General Structural Sweep (ast-grep — every function call in the codebase; a map to grep for a specific call site by name, NOT a hit list to read top to bottom)"
  python3 - <<'PY'
import json
from pathlib import Path

art = Path("/workspace/.source-aware")
rows = []

# ast-grep.json comes from `sg run --json=stream`: NDJSON, one match per
# line, NOT a single JSON blob — do not json.loads() the whole file.
try:
    for line_text in (art / "ast-grep.json").read_text(encoding="utf-8").splitlines():
        line_text = line_text.strip()
        if not line_text:
            continue
        try:
            r = json.loads(line_text)
        except Exception:
            continue
        if not isinstance(r, dict):
            continue
        p = r.get("file") or r.get("path")
        rng = r.get("range") or {}
        start = rng.get("start") if isinstance(rng, dict) else None
        line_no = start.get("line") if isinstance(start, dict) else None
        if p:
            rows.append((p, line_no or 0))
except Exception:
    pass

for p, line in sorted(rows, key=lambda t: (t[0], t[1])):
    print(f"- {p}:{line}")
PY
} > "$ART/entry_points.md"
```

Add any additional entry points a loaded framework skill's own sweeps
surface (e.g. `wordpress.md`'s `wp_ajax_*`/`register_rest_route` greps) to
this same file rather than leaving them in a separate scratch note — one
map, one place every later agent looks.

## Attack Surface Compiler (Structural Facts, Not Judgment)

`entry_points.md`'s "General Structural Sweep" tier is a flat, ruleless
call-site dump — on a real plugin it runs into the tens of thousands of
lines, useful to grep by name but not something a reviewing agent can
query for "which routes lack an auth check" without reading the whole
tree. This step, run once per repository immediately after the
Entry-Point Map above, converts route/hook registrations, tainted
sources, sinks, and auth-check presence into a compact, queryable
per-route summary: `/workspace/.source-aware/attack_surface.md`. It is a
**separate, sibling artifact**, not a fourth tier merged into
`entry_points.md` — the two answer different questions (`entry_points.md`:
"where did a scanner or a ruleless sweep find something"; this one: "what
does this route's own surrounding code structurally contain").

**This is descriptive extraction only. It makes no vulnerability
judgment.** "Auth-check keywords found in range: none" is a statement
about text proximity inside a heuristic window, never a claim that no
guard exists — see `frameworks/wordpress.md`'s "Verify the Guard, Don't
Assume It" for the exact discipline this artifact feeds into: a
reviewing agent still opens the file before treating an absence as a
finding.

**The window heuristic, stated plainly.** A route/hook registration
often names its handler by string (`add_action('hook', 'handle_x')`)
rather than defining it inline, and the handler can be defined *above or
below* the registration line — grouping all registrations together at
the bottom of a file, with handler bodies scattered above in unrelated
order, is a common real WordPress-plugin shape. So this compiler first
tries to resolve the registration's callback name to an actual `function
<name>(` definition anywhere in the same file, and windows around *that*
definition (bounded by the next detected route/function-definition line
in the file, or a fixed `+60` line fallback) instead of the registration
line itself. When no callback name resolves (an inline handler, a
non-string reference, a framework this pass doesn't specifically parse),
it falls back to a forward-only window from the registration line, same
bounding rule. Both cases are explicitly labeled as approximate in the
output — this is deliberately calibrated toward recall (a guard just
outside the window reads as "none found") over precision, since a
missed-guard *lead* costs a quick file read to rule out, while a
confident false "structurally clean" claim costs a real bug.

```bash
ART=/workspace/.source-aware

# Small, extensible keyword sets. Framework skills that layer on top of
# this pass (wordpress.md, a future android.md, etc.) can widen a set
# with their own -e patterns the same way asset_discovery.md's
# framework-specific greps already extend other shared artifacts here —
# not a closed list.
declare -A ATTACK_SURFACE_PATTERNS=(
  [route]='add_action\(|add_filter\(|register_rest_route\(|add_shortcode\(|@app\.route|@router\.(get|post|put|delete|patch)|\bapp\.(get|post|put|delete|patch)\(|\brouter\.(get|post|put|delete|patch)\(|\br\.(GET|POST|PUT|DELETE|PATCH)\(|\bpath\(|re_path\(|http\.HandleFunc'
  [function_def]='\bfunction\s+[A-Za-z_][A-Za-z0-9_]*\s*\('
  [source]='\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_FILES|\$_SERVER|request\.args|request\.form|request\.json|request\.GET|request\.POST|req\.query|req\.body|req\.params'
  [sink_db]='\$wpdb->|cursor\.execute\(|->execute\(|\.query\('
  [sink_file]='fopen\(|file_put_contents\(|unlink\(|os\.remove\(|\bopen\('
  [sink_deserialize]='\bunserialize\(|maybe_unserialize\(|pickle\.loads\(|yaml\.load\('
  [sink_output]='\becho\b|print_r\(|\bprint\(|res\.send\(|response\.write\('
  [auth_check]='current_user_can\(|check_ajax_referer\(|wp_verify_nonce\(|permission_classes|@login_required|requireAuth|is_authenticated'
)
for label in "${!ATTACK_SURFACE_PATTERNS[@]}"; do
  rg -n -H --no-heading -e "${ATTACK_SURFACE_PATTERNS[$label]}" . \
    > "$ART/attack-surface-$label.txt" 2>/dev/null || true
done

python3 - <<'PY'
import re
from collections import defaultdict
from pathlib import Path

art = Path("/workspace/.source-aware")

CATEGORY_LABELS = {
    "route": "route/hook",
    "function_def": "function definition",
    "source": "source",
    "sink_db": "sink:db",
    "sink_file": "sink:file",
    "sink_deserialize": "sink:deserialize",
    "sink_output": "sink:output",
    "auth_check": "auth-check",
}

# WordPress add_action/add_filter callback shapes: a bare string name, or
# array($this, 'name') for a method. Other frameworks fall back to the
# forward-window heuristic below rather than a resolved definition.
CALLBACK_NAME_RE = re.compile(
    r"add_(?:action|filter)\(\s*['\"][^'\"]+['\"]\s*,\s*"
    r"(?:array\(\s*\$this\s*,\s*)?['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]"
)
FUNCTION_DEF_NAME_RE = re.compile(r"function\s+([A-Za-z_][A-Za-z0-9_]*)")


def load(label):
    path = art / f"attack-surface-{label}.txt"
    hits = []
    if not path.exists():
        return hits
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        file_path, line_no, text = parts
        try:
            line_no = int(line_no)
        except ValueError:
            continue
        hits.append((file_path, line_no, text.strip().replace("`", "'")))
    return hits


by_category = {label: load(label) for label in CATEGORY_LABELS}

by_file = defaultdict(lambda: defaultdict(list))
for label, hits in by_category.items():
    for file_path, line_no, text in hits:
        by_file[file_path][label].append((line_no, text))

WINDOW_FALLBACK = 60
lines_out = [
    "# Attack Surface Summary",
    "",
    "Descriptive extraction only - no vulnerability judgment. \"Auth-check: "
    "none found in range\" is a fact about text proximity within a heuristic "
    "window, never a verdict that no guard exists. See "
    "frameworks/wordpress.md's \"Verify the Guard, Don't Assume It\" - the "
    "same discipline applies here: open the file before treating an "
    "absence as a finding.",
    "",
]

for file_path in sorted(by_file):
    cats = by_file[file_path]
    routes = sorted(cats.get("route", []))
    func_defs = sorted(cats.get("function_def", []))
    def_line_by_name: dict[str, int] = {}
    for ln, text in func_defs:
        m = FUNCTION_DEF_NAME_RE.search(text)
        if m and m.group(1) not in def_line_by_name:
            def_line_by_name[m.group(1)] = ln
    all_marker_lines = sorted({ln for ln, _ in routes} | set(def_line_by_name.values()))

    if not routes:
        any_hits = any(cats.get(c) for c in CATEGORY_LABELS if c not in ("route", "function_def"))
        if not any_hits:
            continue
        lines_out.append(f"### {file_path} (no detected route/hook - file-level summary)")
        for label in (
            "source", "sink_db", "sink_file", "sink_deserialize", "sink_output", "auth_check",
        ):
            hits = sorted(cats.get(label, []))
            if hits:
                locs = ", ".join(str(ln) for ln, _ in hits[:20])
                lines_out.append(f"- {CATEGORY_LABELS[label]}: lines {locs}")
        lines_out.append("")
        continue

    def window_end_after(start_line: int) -> int:
        later = [m for m in all_marker_lines if m > start_line]
        return (later[0] - 1) if later else start_line + WINDOW_FALLBACK

    for route_line, route_text in routes:
        m = CALLBACK_NAME_RE.search(route_text)
        callback_name = m.group(1) if m else None
        def_line = def_line_by_name.get(callback_name) if callback_name else None

        if def_line is not None:
            window_start, window_end = def_line, window_end_after(def_line)
            lines_out.append(
                f"### Route: {file_path}:{route_line} -> handler {callback_name}() "
                f"at {file_path}:{window_start}-{window_end}"
            )
        else:
            window_start, window_end = route_line, window_end_after(route_line)
            lines_out.append(f"### Route: {file_path}:{route_line}-{window_end}")

        lines_out.append(f"- Registration: `{route_text}`")
        for label in ("source", "sink_db", "sink_file", "sink_deserialize", "sink_output"):
            in_range = sorted(
                (ln, text) for ln, text in cats.get(label, []) if window_start <= ln <= window_end
            )
            if in_range:
                rendered = ", ".join(f"{ln}: {text[:80]}" for ln, text in in_range[:10])
                lines_out.append(f"- {CATEGORY_LABELS[label]} in range: {rendered}")
        auth_in_range = sorted(
            (ln, text) for ln, text in cats.get("auth_check", []) if window_start <= ln <= window_end
        )
        if auth_in_range:
            rendered = ", ".join(f"{ln}: {text[:80]}" for ln, text in auth_in_range[:5])
            lines_out.append(f"- Auth-check keywords found in range: {rendered}")
        else:
            lines_out.append(
                f"- Auth-check keywords found in range: none "
                f"(window: {window_start}-{window_end}, approximate - verify before "
                "treating as a gap)"
            )
        lines_out.append("")

(art / "attack_surface.md").write_text("\n".join(lines_out) + "\n", encoding="utf-8")
print(f"attack_surface.md: {len(by_file)} file(s) summarized")
PY
```

Query it the same way `entry_points.md` is queried — grep for a file or
category (`grep -A5 "Route: includes/ajax.php" attack_surface.md`,
`grep "Auth-check keywords found in range: none"` to list every route
with no nearby guard) rather than reading it top to bottom. A hit here is
a **lead**, exactly like a `entry_points.md` structural-sweep hit: it
tells you where to look, not what you'll find. The priv/`_nopriv`
sibling-route pattern this compiler surfaces directly (one registration
with a guard, a sibling registration for the same handler shape without
one) is a real, common CVE shape in WordPress plugins — see
`frameworks/wordpress.md`'s BFLA-adjacent guard-verification section.

## Semgrep First Pass

Use Semgrep as the default static triage pass:

```bash
# Preferred deterministic profile set (works with --metrics=off)
semgrep scan --config p/default --config p/golang --config p/secrets \
  --config /home/pentester/tools/semgrep-rules \
  --metrics=off --json --output /workspace/.source-aware/semgrep.json .

# If you choose auto config, do not combine it with --metrics=off
semgrep scan --config auto --config /home/pentester/tools/semgrep-rules \
  --json --output /workspace/.source-aware/semgrep-auto.json .
```

If diff scope is active, restrict to changed files first, then expand only when needed.

## AST-Grep Structural Mapping

Use `sg` for structure-aware code hunting:

```bash
# Ruleless structural pass over deterministic target list (no sgconfig.yml required)
# -d '\n': see the Baseline Coverage Bundle above for why this matters.
xargs -r -d '\n' -n 200 sg run --pattern '$F($$$ARGS)' --json=stream \
  < /workspace/.source-aware/sg-targets.txt \
  > /workspace/.source-aware/ast-grep.json 2> /workspace/.source-aware/ast-grep.log || true
```

Target high-value patterns such as:
- missing auth checks near route handlers
- dynamic command/query construction
- unsafe deserialization or template execution paths
- file and path operations influenced by user input

## Tree-Sitter Assisted Repo Mapping

Use tree-sitter CLI for syntax-aware parsing when grep-level mapping is noisy:

```bash
tree-sitter parse -q <file>
```

Use outputs to improve route/symbol/sink maps for subsequent targeted scans.

## Cross-Component Semantic Mapping

Pattern scanners find local sinks but often miss a security decision in one component followed by a different interpretation in another. For complex middleware, proxies, frameworks, and plugin systems:

1. Identify shared request/context fields and every writer/reader.
2. Order the readers and writers by lifecycle phase: parse, route, authenticate, rewrite, authorize, dispatch, render.
3. Mark fields whose semantic type changes (URL/path, MIME/handler, alias/package, external/internal route).
4. Trace normal, error, retry, subrequest, and internal-redirect paths separately.
5. Compare the representation checked by security code with the representation consumed by the final sink.

Load `semantic_confusion` when this graph reveals overloaded fields, multiple parsers, normalization steps, or protocol translation.

## Resolution and Namespace Risks

In repositories with developer tooling, plugins, templates, or package runners, inspect lookup order rather than only dependency versions:

- command runners that fall back from local binaries or `PATH` to a public registry
- scoped/private package names exposing unscoped binary or alias names
- plugin, template, module, and autoload search paths writable by a lower-privileged actor
- CI/composite actions and devcontainer/bootstrap scripts that transitively execute package commands
- missing local artifacts that silently activate a remote or broader fallback

Record candidate names and verify ownership/existence without claiming or publishing them. A namespace gap is reportable only when the target actually resolves or executes the attacker-contestable name under realistic conditions.

For npm/JavaScript, distinguish the package name from the executable name and
model the actual working directory, dependency tree, global bin directory,
cache, and registry configuration. `load_skill(["npx_confusion"])` when a bare
`npx`/`npm exec` command may fall back from a missing executable to a public
package. Trivy cannot detect this class because no installed package version
needs to be vulnerable.

Load `infrastructure_lifecycle` when source, images, firmware, or history contain abandoned domains, provider resources, package namespaces, update URLs, mail identities, telemetry, or control endpoints. Use targeted string/dataflow analysis when this is the research question; the full baseline scanner bundle is not required merely to trace one endpoint consumer.

A `Plugin Name:`/`Theme Name:` header block in the main PHP file, a
`readme.txt` with WordPress-style headers (`Stable tag:`, `Tested up to:`), a
`wp-content/plugins/`/`wp-content/themes/` path, or heavy
`add_action`/`add_filter`/`$wpdb`/`register_rest_route` usage marks
WordPress plugin or theme code. `load_skill(["wordpress"])` before running
the generic baseline against it — WordPress's own security model (nonces,
capability checks, `$wpdb->prepare`, the `esc_*`/`sanitize_*` APIs) is not
something the generic `p/php` semgrep pack understands, and the real
CVE-yielding bugs live in exactly those WordPress-specific gaps.

## Secret and Supply Chain Coverage

Detect hardcoded credentials:

```bash
# --no-git: see the Baseline Coverage Bundle above for why this matters.
gitleaks detect --source . --no-git --config /home/pentester/tools/gitleaks-rules/strix.gitleaks.toml \
  --report-format json --report-path /workspace/.source-aware/gitleaks.json
# Verified-only by default — see the Baseline Coverage Bundle above for why,
# and for the --no-verification offline/unreachable-target fallback form.
trufflehog filesystem --no-update --json . > /workspace/.source-aware/trufflehog.json
```

Run repository-wide dependency and config checks:

```bash
trivy fs --scanners vuln,misconfig --timeout 30m --offline-scan \
  --format json --output /workspace/.source-aware/trivy-fs.json . || true
```

Known-CVE dependency findings are the one exception to the "report only after
dynamic validation" rule below: report each one with `create_dependency_report`
(not `create_vulnerability_report`), setting `advisory_cvss` from the published
advisory. `load_skill(["dependency_cve_scanning"])` for the full SCA workflow.

## JavaScript-Side Coverage

For frontends and Node services, layer these on top of the language-agnostic
passes above:

```bash
retire --path . --outputformat json --outputpath /workspace/.source-aware/retire.json || true
eslint --no-config-lookup --rule '{"no-eval":2,"no-implied-eval":2}' \
  -f json -o /workspace/.source-aware/eslint.json . || true
```

When you hit a minified bundle, run `js-beautify <file>` for a readable
view before greppping — and use `jshint --reporter=unix <file>` as a
lighter syntax/anti-pattern check when ESLint is over-eager. The
`JS-Snooper` / `jsniper.sh` tools (in `katana.md`) are the right next
step to mine those bundles for endpoint candidates.

## Converting Static Signals Into Exploits

When source contains model-provider SDKs, prompt templates, retrieval/vector stores, tool/function calling, model loading, training/feedback pipelines, or token/agent-loop accounting, load `llm_applications`. Use its OWASP 2026 LLM01-LLM10 map to trace data provenance, model output, retrieval authorization, tool authority, and resource multipliers rather than treating the provider call as the sink.

1. Rank candidates by impact and exploitability.
2. Trace source-to-sink flow for top candidates.
3. Build dynamic PoCs that reproduce the suspected issue.
4. Report only after dynamic validation succeeds.

## Anti-Patterns

- Do not treat scanner output as final truth.
- Do not spend full cycles on low-signal pattern matches.
- Do not report source-only findings without validation evidence.
