"""Durable coverage matrix for black-box assessments (BLACKBOX #6 Part B).

Every authorized application must receive an EXPLICIT assessment of every
vulnerability family — applicability tracked SEPARATELY from execution — so that
missing prerequisites, unsupported execution, blocked tests and unfinished work
stay visible. This is NOT a checklist that proves security: a matrix full of
`unknown`/`not_started` is the honest default, and a `tested` cell only ever
covers the one surface it names.

It does not duplicate the existing stores — it layers on top of them:
- the attack-surface inventory (`attack_surface`) is the structural input the
  deterministic planner reads (origins/routes/parameters/actors);
- the hypotheses worklist (`hypotheses`) holds the executable bets and attempts;
- the coverage ledger (`report/coverage`) records what a *skill* examined.
The matrix adds the one thing none of those represents: a durable
surface x family grid of (applicability, execution) with evidence, planned
checks, linked hypotheses/attempts, blocking prerequisites and capability.

Hard rules (enforced here, not just documented):
- A missing discovery signal is NOT proof of non-applicability — the planner
  only ever upgrades a family to `applicable` on a concrete structural signal
  and never sets `not_applicable`.
- `not_applicable` requires a rationale AND at least one evidence reference.
- One negative never closes a family: cells are keyed per surface, and there is
  no operation that closes a family across surfaces.
- Budget exhaustion / instability → `blocked`, never `tested`.
- New inventory evidence re-opens or expands: re-planning adds new cells and
  flips a stale `tested` route cell back to `in_progress` when a NEW parameter/
  actor signal appears for that same surface.
- Resume preserves planning and flags evidence on in-flight/attempted cells as
  stale so it is re-verified.
- A family with no executor/skill surfaces as a `missing` capability gap.
"""

from __future__ import annotations

import json
import logging
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.agent_metrics.tools import record_activity_tick
from strix.tools.attack_surface.tools import _query_impl as _surface_query
from strix.tools.hypotheses.tools import _create_impl as _create_hypothesis


logger = logging.getLogger(__name__)

_SCHEMA_VERSION = 1

# Canonical family vocabulary — every one is assessed per origin.
FAMILIES: tuple[str, ...] = (
    "auth", "password_reset", "mfa", "session_fixation", "jwt", "oauth",
    "idor_bola", "bfla", "tenant_isolation", "field_authz",
    "sqli", "nosqli", "command_injection", "ssti", "ldap_injection", "xpath_injection", "xxe",
    "xss", "csrf", "cors", "clickjacking", "postmessage",
    "upload", "path_traversal", "lfi_rfi", "ssrf", "deserialization",
    "mass_assignment", "parameter_pollution", "graphql", "websocket",
    "workflow_bypass", "race_condition", "rate_limit", "price_manipulation",
    "state_manipulation", "misconfiguration", "exposed_secrets", "cache_poisoning",
    "request_smuggling", "component_vuln",
)

SURFACE_TYPES = ("origin", "route", "parameter", "actor_context", "component")
APPLICABILITY = ("applicable", "not_applicable", "unknown")
EXECUTION = ("not_started", "in_progress", "tested", "blocked", "deferred")
CAPABILITY = ("executor", "agent_tools", "manual", "missing")

# Family -> capability registry (the source of truth). skill = the real skill
# stem an agent `load_skill`s (verified to exist under vulnerabilities/ or
# protocols/), "" where NO dedicated skill exists (an honest capability gap, not
# a manufactured not_applicable). capability: executor (dedicated run_* tool),
# agent_tools (a skill + general tools), or missing (no skill/executor -> a
# visible gap needing manual follow-up). prereqs: what an applicability
# assessment must ESTABLISH before a scoped test (never the vulnerability itself).
FAMILY_MAP: dict[str, dict[str, Any]] = {
    "auth": {"skill": "authentication_jwt", "capability": "agent_tools",
             "prereqs": ["a login flow", "a valid and an invalid credential set"]},
    "password_reset": {"skill": "authentication_jwt", "capability": "agent_tools",
                       "prereqs": ["a reset flow", "a controlled mailbox/token channel"]},
    "mfa": {"skill": "weak_password_detection", "capability": "agent_tools",
            "prereqs": ["an account with MFA enrolled", "the MFA challenge surface"]},
    "session_fixation": {"skill": "authentication_jwt", "capability": "agent_tools",
                         "prereqs": ["pre- and post-auth session tokens"]},
    "jwt": {"skill": "authentication_jwt", "capability": "agent_tools",
            "prereqs": ["a JWT in use", "its header/alg"]},
    "oauth": {"skill": "oauth", "capability": "agent_tools",
              "prereqs": ["an OAuth/OIDC flow", "client/redirect parameters"]},
    "idor_bola": {"skill": "idor", "capability": "executor",
                  "prereqs": ["an object + its id", "2 provisioned actors", "expected owner"]},
    "bfla": {"skill": "broken_function_level_authorization", "capability": "executor",
             "prereqs": ["a privileged action", "a low-priv actor", "expected role policy"]},
    "tenant_isolation": {"skill": "idor", "capability": "agent_tools",
                         "prereqs": ["2 tenants", "a tenant-scoped object"]},
    "field_authz": {"skill": "broken_function_level_authorization", "capability": "agent_tools",
                    "prereqs": ["an object with per-field read/write", "2 actors"]},
    "sqli": {"skill": "sql_injection", "capability": "executor", "prereqs": ["a reachable param"]},
    "nosqli": {"skill": "nosql_injection", "capability": "agent_tools",
               "prereqs": ["a reachable param", "a NoSQL-backed operation"]},
    "command_injection": {"skill": "rce", "capability": "agent_tools",
                          "prereqs": ["a param reaching an OS/command sink"]},
    "ssti": {"skill": "ssti", "capability": "agent_tools",
             "prereqs": ["a param reflected through a template engine"]},
    "ldap_injection": {"skill": "underserved_families", "capability": "agent_tools",
                       "prereqs": ["a param reaching an LDAP/directory query"]},
    "xpath_injection": {"skill": "underserved_families", "capability": "agent_tools",
                        "prereqs": ["a param reaching an XPath/XML query"]},
    "xxe": {"skill": "xxe", "capability": "agent_tools",
            "prereqs": ["an XML-accepting endpoint"]},
    "xss": {"skill": "xss", "capability": "executor", "prereqs": ["a reflected/stored param"]},
    "csrf": {"skill": "csrf", "capability": "agent_tools",
             "prereqs": ["a state-changing request", "cookie auth without a token"]},
    "cors": {"skill": "cors_misconfiguration", "capability": "agent_tools",
             "prereqs": ["an endpoint emitting ACAO", "a credentialed read"]},
    "clickjacking": {"skill": "browser_security", "capability": "agent_tools",
                     "prereqs": ["a sensitive action framable without protection"]},
    "postmessage": {"skill": "browser_security", "capability": "agent_tools",
                    "prereqs": ["a postMessage handler"]},
    "upload": {"skill": "insecure_file_uploads", "capability": "agent_tools",
               "prereqs": ["a real upload handler + storage/retrieval"]},
    "path_traversal": {"skill": "path_traversal_lfi_rfi", "capability": "agent_tools",
                       "prereqs": ["a param reaching the filesystem"]},
    "lfi_rfi": {"skill": "path_traversal_lfi_rfi", "capability": "agent_tools",
                "prereqs": ["a param controlling an include/path"]},
    "ssrf": {"skill": "ssrf", "capability": "agent_tools",
             "prereqs": ["a param the server fetches"]},
    "deserialization": {"skill": "insecure_deserialization", "capability": "agent_tools",
                        "prereqs": ["a serialized blob accepted from the client"]},
    "mass_assignment": {"skill": "mass_assignment", "capability": "agent_tools",
                        "prereqs": ["an object-create/update binding client fields"]},
    "parameter_pollution": {"skill": "underserved_families", "capability": "agent_tools",
                            "prereqs": ["duplicate-parameter handling to probe"]},
    "graphql": {"skill": "graphql", "capability": "agent_tools",
                "prereqs": ["a GraphQL endpoint (introspection or known schema)"]},
    "websocket": {"skill": "underserved_families", "capability": "agent_tools",
                  "prereqs": ["a WebSocket channel", "an authenticated actor"]},
    "workflow_bypass": {"skill": "business_logic", "capability": "agent_tools",
                        "prereqs": ["a multi-step workflow with an enforced order"]},
    "race_condition": {"skill": "race_conditions", "capability": "agent_tools",
                       "prereqs": ["a limited/idempotent-sensitive operation"]},
    "rate_limit": {"skill": "weak_password_detection", "capability": "agent_tools",
                   "prereqs": ["an operation expected to be throttled"]},
    "price_manipulation": {"skill": "business_logic", "capability": "agent_tools",
                           "prereqs": ["a priced/quantity-bearing operation"]},
    "state_manipulation": {"skill": "business_logic", "capability": "agent_tools",
                           "prereqs": ["a state machine with client-visible transitions"]},
    "misconfiguration": {"skill": "information_disclosure", "capability": "agent_tools",
                         "prereqs": ["reachable admin/debug/config surface"]},
    "exposed_secrets": {"skill": "information_disclosure", "capability": "agent_tools",
                        "prereqs": ["retrievable JS/responses/artifacts"]},
    "cache_poisoning": {"skill": "underserved_families", "capability": "agent_tools",
                        "prereqs": ["a cache fronting the origin", "an unkeyed input to probe"]},
    "request_smuggling": {"skill": "http_request_smuggling", "capability": "agent_tools",
                          "prereqs": ["a front-end/back-end proxy chain"]},
    "component_vuln": {"skill": "component_research", "capability": "agent_tools",
                       "prereqs": ["an observed component + usable version"]},
}

# Families with a dedicated executable executor (vs agent-driven skills).
_EXECUTOR_FAMILIES = {"sqli", "xss", "idor_bola", "bfla"}
# Above this many distinct origins, seeding all 40 families on every origin is an
# O(origins*40) grid the agent then works cell-by-cell — the matrix's biggest
# uncapped cost. Past the cap, only the busiest origins get the full family sweep;
# long-tail origins get the high-value CORE set, and other families there are
# assessed on demand (assess_coverage seeds any cell) if a core finding warrants.
_FULL_MATRIX_ORIGIN_CAP = 10
_CORE_FAMILIES = frozenset(
    {"auth", "idor_bola", "bfla", "sqli", "xss", "ssrf",
     "misconfiguration", "exposed_secrets", "component_vuln"}
)
_CORE_FAMILIES_ORDERED = tuple(f for f in FAMILIES if f in _CORE_FAMILIES)
# Families where a single structural signal (a parameter) is itself a sufficient
# trigger to PROBE, with no further prerequisite to establish first — so the
# planner may auto-create one deduplicated hypothesis. idor/bfla are executor
# families too, but their prerequisites (ownership / distinct principals) are NOT
# established by structure, so they get an assessment task, not an auto-bet.
_AUTO_HYPOTHESIS_FAMILIES = {"sqli", "xss"}
_STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}

_store: dict[str, dict[str, Any]] = {}
_lock = threading.RLock()
_path: Path | None = None


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _capability_for(family: str) -> str:
    return FAMILY_MAP.get(family, {}).get("capability", "agent_tools")


def _key(surface_type: str, surface_id: str, family: str) -> str:
    return f"{surface_type}|{surface_id}|{family}"


# --------------------------------------------------------------------------- #
# Persistence (run-scoped; carries no secrets)
# --------------------------------------------------------------------------- #


def hydrate_coverage_matrix_from_disk(state_dir: Path) -> None:
    """Load this run's matrix. On resume, PRESERVE all planning but flag evidence
    on in-flight/attempted cells as stale so it is re-verified (mirrors the
    hypotheses/attack-surface resume discipline)."""
    global _path  # noqa: PLW0603
    _path = state_dir / "coverage_matrix.json"
    with _lock:
        _store.clear()
        if not _path.exists():
            return
        try:
            data = json.loads(_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception("coverage_matrix.json at %s unreadable; starting empty", _path)
            return
        entries = data.get("cells") if isinstance(data, dict) else None
        if isinstance(entries, dict):
            for k, e in entries.items():
                if not isinstance(e, dict):
                    continue
                if e.get("execution") == "in_progress" or e.get("attempt_refs"):
                    e["evidence_stale"] = True
                _store[k] = e
        logger.info("coverage matrix hydrated from %s (%d cells)", _path, len(_store))


def _persist_locked() -> None:
    path = _path
    if path is None:
        return
    try:
        payload = json.dumps({"schema_version": _SCHEMA_VERSION, "cells": _store},
                             ensure_ascii=False, indent=2, default=str)
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=str(path.parent),
                                         prefix=f".{path.name}.", suffix=".tmp",
                                         delete=False) as tmp:
            tmp.write(payload)
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
    except Exception:
        logger.exception("coverage matrix persist to %s failed", path)


# --------------------------------------------------------------------------- #
# Core upsert
# --------------------------------------------------------------------------- #


def _blank(surface_type: str, surface_id: str, family: str) -> dict[str, Any]:
    return {
        "surface_type": surface_type, "surface_id": surface_id, "family": family,
        "applicability": "unknown", "execution": "not_started",
        "applicability_rationale": "", "capability": _capability_for(family),
        "evidence_refs": [], "planned_checks": [], "hypothesis_refs": [], "attempt_refs": [],
        "tested_boundaries": [], "remaining_work": "", "blocking_prereqs": [],
        "evidence_stale": False, "created_at": _now(), "updated_at": _now(),
    }


def _merge_list(dst: list[Any], add: Any) -> list[Any]:
    for x in add or []:
        if x not in dst:
            dst.append(x)
    return dst


def assess_impl(
    *, surface_type: str, surface_id: str, family: str,
    applicability: str = "", execution: str = "", applicability_rationale: str = "",
    evidence_refs: list[str] | None = None, planned_checks: list[str] | None = None,
    capability: str = "", blocking_prereqs: list[str] | None = None,
    remaining_work: str = "", tested_boundaries: list[str] | None = None,
) -> dict[str, Any]:
    st, fam = surface_type.strip().lower(), family.strip().lower()
    sid = surface_id.strip()
    if st not in SURFACE_TYPES:
        return {"success": False, "error": f"surface_type must be one of {SURFACE_TYPES}"}
    if fam not in FAMILIES:
        return {"success": False, "error": f"unknown family {family!r}"}
    if not sid:
        return {"success": False, "error": "surface_id is required"}
    appl = (applicability or "").strip().lower()
    exe = (execution or "").strip().lower()
    if appl and appl not in APPLICABILITY:
        return {"success": False, "error": f"applicability must be one of {APPLICABILITY}"}
    if exe and exe not in EXECUTION:
        return {"success": False, "error": f"execution must be one of {EXECUTION}"}
    evid = [e for e in (evidence_refs or []) if str(e).strip()]
    if appl == "not_applicable" and (not applicability_rationale.strip() or not evid):
        return {"success": False, "rejected": "not_applicable_needs_evidence",
                "error": "not_applicable requires an applicability_rationale AND >=1 evidence_ref "
                         "(a missing discovery signal is not proof of non-applicability)"}
    with _lock:
        k = _key(st, sid, fam)
        entry = _store.get(k) or _blank(st, sid, fam)
        if appl:
            entry["applicability"] = appl
        if exe:
            entry["execution"] = exe
        if applicability_rationale.strip():
            entry["applicability_rationale"] = applicability_rationale.strip()[:600]
        if capability.strip().lower() in CAPABILITY:
            entry["capability"] = capability.strip().lower()
        if remaining_work.strip():
            entry["remaining_work"] = remaining_work.strip()[:600]
        _merge_list(entry["evidence_refs"], evid)
        _merge_list(entry["planned_checks"], [str(c).strip() for c in (planned_checks or [])])
        _merge_list(entry["blocking_prereqs"], [str(b).strip() for b in (blocking_prereqs or [])])
        _merge_list(entry["tested_boundaries"], [str(t).strip() for t in (tested_boundaries or [])])
        entry["evidence_stale"] = False
        entry["updated_at"] = _now()
        _store[k] = entry
        _persist_locked()
        return {"success": True, **_public(entry)}


def link_hypothesis_impl(surface_type: str, surface_id: str, family: str,
                         hypothesis_id: str) -> dict[str, Any]:
    with _lock:
        entry = _store.get(_key(surface_type.strip().lower(), surface_id.strip(),
                                family.strip().lower()))
        if entry is None:
            return {"success": False, "error": "no such coverage cell"}
        if hypothesis_id.strip():
            _merge_list(entry["hypothesis_refs"], [hypothesis_id.strip()])
            if entry["execution"] == "not_started":
                entry["execution"] = "in_progress"
            entry["updated_at"] = _now()
            _persist_locked()
        return {"success": True, **_public(entry)}


def record_attempt_ref_impl(surface_type: str, surface_id: str, family: str,
                            attempt_ref: str) -> dict[str, Any]:
    with _lock:
        entry = _store.get(_key(surface_type.strip().lower(), surface_id.strip(),
                                family.strip().lower()))
        if entry is None:
            return {"success": False, "error": "no such coverage cell"}
        _merge_list(entry["attempt_refs"], [attempt_ref.strip()])
        entry["evidence_stale"] = False
        entry["updated_at"] = _now()
        _persist_locked()
        return {"success": True, **_public(entry)}


def _public(entry: dict[str, Any]) -> dict[str, Any]:
    return {k: entry[k] for k in (
        "surface_type", "surface_id", "family", "applicability", "execution",
        "applicability_rationale", "capability", "evidence_refs", "planned_checks",
        "hypothesis_refs", "attempt_refs", "tested_boundaries", "remaining_work",
        "blocking_prereqs", "evidence_stale", "updated_at")}


# --------------------------------------------------------------------------- #
# Deterministic planner — reads the real attack-surface inventory
# --------------------------------------------------------------------------- #

_ID_HINTS = ("id", "uuid", "user", "account", "order", "invoice", "doc", "file", "object", "ref")
_FILE_HINTS = ("file", "upload", "download", "path", "dir", "attachment", "document")
_SSRF_HINTS = ("url", "uri", "host", "dest", "callback", "webhook", "redirect", "next", "target")


def _route_signals(ep: dict[str, Any]) -> dict[str, str]:
    """Map ONE inventory endpoint's STRUCTURAL facts to candidate families. Each
    value is a DISCOVERY SIGNAL + the bounded applicability-assessment it calls
    for — never a satisfied prerequisite, an executed test, or a finding. The
    planner keeps these cells `unknown` (see plan_coverage_impl): structure alone
    does not establish ownership, distinct principals, an upload handler, a
    server-side fetch, cookie-auth exposure, or an injection backend."""
    out: dict[str, str] = {}
    method = str(ep.get("method", "")).upper()
    path = str(ep.get("path", "")).lower()
    params = ep.get("parameters", []) or []
    pnames = [str(p.get("name", "")).lower() for p in params]
    actors = ep.get("actors_observed", []) or []
    joined = path + " " + " ".join(pnames)
    if params:
        # Parameter presence is a sufficient trigger to PROBE input injection even
        # when the backend is unknown — do not suppress exploratory testing.
        for fam in ("sqli", "nosqli", "xss", "command_injection", "ssti",
                    "parameter_pollution", "mass_assignment"):
            out[fam] = (f"signal: parameter(s) {pnames or '[body]'} reach a handler "
                        "(backend unknown; probe, do not assume a specific sink)")
    if any(h in n for n in pnames for h in _ID_HINTS) or ep.get("resource_count"):
        out["idor_bola"] = ("signal: id-shaped parameter/object refs — NOT proof of ownership; "
                            "assess by provisioning 2 actors and confirming cross-actor access")
        out["field_authz"] = ("signal: object with fields reachable via a parameter; assess which "
                              "fields are read/writable per actor")
    if len(actors) > 1:
        out["bfla"] = (f"signal: {len(actors)} actor LABELS observed — labels are NOT proof of "
                       "distinct principals/privilege; assess real role separation")
        out["tenant_isolation"] = ("signal: multiple actor labels — assess whether they are "
                                   "separate tenants and whether data is isolated")
    if method in _STATE_CHANGING:
        out["csrf"] = (f"signal: state-changing {method} — NOT proof of cookie-auth exposure; "
                       "assess the session mechanism (cookie vs token) and anti-CSRF token")
        out["race_condition"] = (f"signal: state-changing {method}; assess whether a limited/"
                                 "idempotent-sensitive operation exists")
    if any(h in joined for h in _FILE_HINTS):
        out["upload"] = ("signal: file/path-shaped route/param — NOT proof of an upload handler; "
                         "assess whether a real upload/store exists")
        out["path_traversal"] = ("signal: file/path-shaped — assess whether a path reaches the "
                                 "filesystem")
        out["lfi_rfi"] = "signal: file/path-shaped — assess local/remote file-inclusion reach"
    if any(h in n for n in pnames for h in _SSRF_HINTS):
        out["ssrf"] = ("signal: url/callback-shaped parameter — NOT proof of a server-side fetch; "
                       "assess whether the server retrieves it")
    if "graphql" in path:
        out["graphql"] = "signal: graphql route — introspect and assess object/field authz"
    return out


def applicable_untested_summary(limit: int = 25) -> dict[str, Any]:
    """Cells the scan CONFIRMED `applicable` but never `tested` — the strongest
    'finishing with known-untested surface' signal, used by the finish-scan soft
    gate. (A still-`unknown` cell is not counted: nobody claimed it applies.)"""
    with _lock:
        rows = [
            {
                "surface_type": c.get("surface_type"),
                "surface": c.get("surface_id"),
                "family": c.get("family"),
            }
            for c in _store.values()
            if c.get("applicability") == "applicable" and c.get("execution") != "tested"
        ]
    return {"count": len(rows), "cells": rows[:limit]}


def plan_coverage_impl(*, create_hypotheses: bool = True) -> dict[str, Any]:
    """Seed/expand the matrix from the current attack-surface inventory,
    deterministically and WITHOUT fabricating applicability:

    - Every origin gets an explicit `unknown` cell for EVERY family, each with a
      bounded applicability-assessment task — so no family is silently skipped.
    - A structural signal on a route produces a route cell that stays `unknown`
      with a planned applicability assessment + rationale (a signal is not a
      satisfied prerequisite). The planner NEVER sets `applicable` or
      `not_applicable` — that is a judgement for `assess_coverage` after the
      assessment runs.
    - For families where a parameter alone is a sufficient PROBE trigger
      (sqli/xss), it creates ONE deduplicated hypothesis and links it. Families
      with real prerequisites (idor/bfla/upload/ssrf/csrf/...) get an assessment
      task, not an auto-hypothesis.
    - Re-running expands and re-opens a `tested` route cell whose signal changed;
      it does not regenerate the routes x params x actors x families product."""
    inv = _surface_query(origin=None, actor_ref=None, method=None, param_location=None,
                         test_status=None, test_category=None, limit=500)
    endpoints = inv.get("endpoints", [])
    origins = sorted({str(ep.get("origin")) for ep in endpoints if ep.get("origin")})
    seeded_origin_cells = 0
    signaled_route_cells = 0
    hypotheses_created = 0

    # Full 40-family sweep for the busiest origins (where the app really is);
    # long-tail origins get the CORE set only. Small inventories (<= cap) are
    # unchanged — every origin stays a full sweep.
    if len(origins) > _FULL_MATRIX_ORIGIN_CAP:
        ep_count: dict[str, int] = {}
        for ep in endpoints:
            o = str(ep.get("origin") or "")
            if o:
                ep_count[o] = ep_count.get(o, 0) + 1
        ranked = sorted(origins, key=lambda o: (-ep_count.get(o, 0), o))
        full_origins = set(ranked[:_FULL_MATRIX_ORIGIN_CAP])
    else:
        full_origins = set(origins)

    for origin in origins:
        fams = FAMILIES if origin in full_origins else _CORE_FAMILIES_ORDERED
        for fam in fams:
            k = _key("origin", origin, fam)
            with _lock:
                if k not in _store:
                    cell = _blank("origin", origin, fam)
                    cell["evidence_refs"] = [origin]
                    note = "" if origin in full_origins else (
                        " [long-tail origin: core-family seed; assess other "
                        "families here on demand if a core finding warrants]")
                    cell["planned_checks"] = [
                        (f"assess applicability of {fam} at this origin (discover features/inputs; "
                         f"do not assume present or absent){note}")]
                    _store[k] = cell
                    seeded_origin_cells += 1

    for ep in endpoints:
        eid = str(ep.get("endpoint_id") or "")
        if not eid:
            continue
        for fam, rationale in _route_signals(ep).items():
            with _lock:
                existing = _store.get(_key("route", eid, fam))
                reopen = bool(existing and existing.get("execution") == "tested"
                              and rationale not in existing.get("applicability_rationale", ""))
            # A signal keeps the cell UNKNOWN with a bounded assessment task — it
            # is a relevant test surface, not established applicability.
            assess_impl(surface_type="route", surface_id=eid, family=fam,
                        applicability="unknown",
                        execution="in_progress" if reopen else "",
                        applicability_rationale=rationale, evidence_refs=[eid],
                        planned_checks=[rationale], capability=_capability_for(fam))
            signaled_route_cells += 1
            if create_hypotheses and fam in _AUTO_HYPOTHESIS_FAMILIES:
                created = _create_hypothesis(
                    endpoint_id=eid, vuln_category=_hyp_category(fam),
                    resource=str(ep.get("path") or ""), actor_ref="",
                    param_name=(ep.get("parameters", [{}]) or [{}])[0].get("name", "")
                    if ep.get("parameters") else "",
                    param_location="query", operation="",
                    rationale=rationale, next_action=f"targeted {fam} probe", priority={},
                    evidence=[], agent_id=None, agent_name=None)
                hid = created.get("hypothesis_id")
                if hid:
                    if created.get("created"):
                        hypotheses_created += 1
                    link_hypothesis_impl("route", eid, fam, hid)
    return {"success": True, "origins": len(origins), "seeded_origin_cells": seeded_origin_cells,
            "signaled_route_cells": signaled_route_cells,
            "hypotheses_created": hypotheses_created, "total_cells": len(_store)}


def _hyp_category(family: str) -> str:
    return {"idor_bola": "idor", "bfla": "broken_function_level_authorization",
            "sqli": "sql_injection", "xss": "xss"}.get(family, family)


# --------------------------------------------------------------------------- #
# Queries / gaps
# --------------------------------------------------------------------------- #


def query_impl(*, surface_type: str = "", family: str = "", applicability: str = "",
               execution: str = "", limit: int = 200) -> dict[str, Any]:
    st, fam = surface_type.strip().lower(), family.strip().lower()
    appl, exe = applicability.strip().lower(), execution.strip().lower()
    with _lock:
        cells = [dict(e) for e in _store.values()]
    out = [c for c in cells
           if (not st or c["surface_type"] == st)
           and (not fam or c["family"] == fam)
           and (not appl or c["applicability"] == appl)
           and (not exe or c["execution"] == exe)]
    return {"success": True, "total": len(out),
            "cells": [_public(c) for c in out[: max(1, min(limit, 1000))]]}


def coverage_gaps_impl() -> dict[str, Any]:
    """Cells that represent unresolved work: applicable-but-not-tested, still
    unknown, blocked/deferred, stale-after-resume, or a missing capability. The
    report uses this to disclose gaps — a scan is never 'fully tested' while any
    of these remain."""
    with _lock:
        cells = [dict(e) for e in _store.values()]
    gaps: list[dict[str, Any]] = []
    for c in cells:
        unresolved = (
            c["capability"] == "missing"
            or c["evidence_stale"]
            or (c["applicability"] == "applicable" and c["execution"] != "tested")
            or (c["applicability"] == "unknown")
            or (c["execution"] in ("blocked", "deferred", "in_progress"))
        )
        if unresolved:
            gaps.append(_public(c))
    tested = sum(1 for c in cells if c["execution"] == "tested")
    return {"success": True, "total_cells": len(cells), "tested_cells": tested,
            "gap_count": len(gaps), "gaps": gaps[:500]}


def next_coverage_task_impl(count: int = 1) -> dict[str, Any]:
    """Dispense the next pending coverage-assessment task(s) over the ONE matrix
    store (not a competing scheduler). Deterministic + anti-starvation: the
    least-progressed family is served first, so SQLi/XSS route cells (already
    in_progress from planner-linked hypotheses) never crowd out families that
    have had no assessment. A dispensed cell is CLAIMED (not_started ->
    in_progress) so repeated calls advance and rotate; it names the skill to load
    and the prerequisites to establish — claiming is not testing."""
    tasks: list[dict[str, Any]] = []
    fam_order = {f: i for i, f in enumerate(FAMILIES)}
    for _ in range(max(1, min(count, 20))):
        with _lock:
            # Claimable = never-started cells, PLUS stranded claims: a cell left
            # in_progress with no real progress (no hypothesis/attempt) that a
            # resume/worker-failure flagged stale. This guarantees a claim can
            # never strand permanently — it is re-offered.
            claimable = [
                c for c in _store.values()
                if c["execution"] == "not_started"
                or (c["execution"] == "in_progress" and c.get("evidence_stale")
                    and not c.get("hypothesis_refs") and not c.get("attempt_refs"))
            ]
            if not claimable:
                break
            progressed: dict[str, int] = {}
            for c in _store.values():
                real_progress = c["execution"] in ("tested", "blocked", "deferred") or (
                    c["execution"] == "in_progress"
                    and (c.get("hypothesis_refs") or c.get("attempt_refs")))
                if real_progress:
                    progressed[c["family"]] = progressed.get(c["family"], 0) + 1
            claimable.sort(key=lambda c: (progressed.get(c["family"], 0),
                                          fam_order.get(c["family"], 99),
                                          0 if c["surface_type"] == "origin" else 1,
                                          c["surface_id"]))
            cell = claimable[0]
            cell["execution"] = "in_progress"  # claim (or re-claim a stranded cell)
            cell["evidence_stale"] = False
            cell["updated_at"] = _now()
            _persist_locked()
            info = FAMILY_MAP.get(cell["family"], {})
            tasks.append({
                "family": cell["family"], "surface_type": cell["surface_type"],
                "surface_id": cell["surface_id"], "load_skill": info.get("skill") or None,
                "capability": cell["capability"], "prereqs": info.get("prereqs", []),
                "planned_check": (cell["planned_checks"] or [""])[0],
                "shared_guidance": "analysis/family_assessment",
            })
    with _lock:
        remaining = sum(
            1 for c in _store.values()
            if c["execution"] == "not_started"
            or (c["execution"] == "in_progress" and c.get("evidence_stale")
                and not c.get("hypothesis_refs") and not c.get("attempt_refs")))
    return {"success": True, "tasks": tasks, "remaining_not_started": remaining,
            "note": ("claim-and-assess: load the named skill (or follow shared_guidance when "
                     "load_skill is null — a capability gap), establish the prerequisites, then "
                     "file a scoped hypothesis/test. A claimed task is in_progress, not tested; "
                     "budget exhaustion leaves the rest pending and visible in the report.")}


# --------------------------------------------------------------------------- #
# Agent tools
# --------------------------------------------------------------------------- #


def _agent_id(ctx: RunContextWrapper) -> str | None:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    a = inner.get("agent_id")
    return a if isinstance(a, str) else None


@function_tool
async def plan_coverage(ctx: RunContextWrapper, create_hypotheses: bool = True) -> str:
    """Seed/expand the durable coverage matrix from the current attack-surface
    inventory. Every origin gets an explicit assessment of EVERY vulnerability
    family (default `unknown`); families are upgraded to `applicable` only where a
    concrete structural signal (parameters, actors, method, path shape) exists —
    never fabricated. Optionally creates one deduplicated hypothesis per
    applicable executor-family route and links it. Re-run after new crawl
    evidence to expand/re-open cells."""
    result = plan_coverage_impl(create_hypotheses=create_hypotheses)
    record_activity_tick(_agent_id(ctx))
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool
async def assess_coverage(
    ctx: RunContextWrapper, surface_type: str, surface_id: str, family: str,
    applicability: str = "", execution: str = "", applicability_rationale: str = "",
    capability: str = "", remaining_work: str = "",
) -> str:
    """Record or update one surface x family assessment. `not_applicable` requires
    an applicability_rationale AND evidence (a missing discovery signal is not
    proof of non-applicability). A `tested` execution covers ONLY this surface —
    never its siblings or the whole family; budget exhaustion/instability is
    `blocked`, never `tested`."""
    result = assess_impl(surface_type=surface_type, surface_id=surface_id, family=family,
                         applicability=applicability, execution=execution,
                         applicability_rationale=applicability_rationale, capability=capability,
                         remaining_work=remaining_work)
    record_activity_tick(_agent_id(ctx))
    return json.dumps(result, ensure_ascii=False, default=str)


def mark_families_blocked_impl(
    *, surface_type: str, surface_id: str, families: list[str],
    blocking_prereq: str, rationale: str = "", evidence_ref: str = "",
) -> dict[str, Any]:
    """Mark many families `blocked` on ONE shared prerequisite in a single call."""
    prereq = (blocking_prereq or "").strip()
    if not prereq:
        return {"success": False, "error": "blocking_prereq is required (the one thing that blocks them all)"}
    fams = [f.strip().lower() for f in (families or []) if f.strip()]
    if not fams:
        # Empty / "all" means every applicable-or-unknown family on this surface
        # that isn't already `tested` — the exact session-blocked cluster.
        sid = surface_id.strip()
        st = surface_type.strip().lower()
        with _lock:
            fams = sorted({
                c["family"] for c in _store.values()
                if c.get("surface_type") == st and c.get("surface_id") == sid
                and c.get("execution") != "tested"
            })
        if not fams:
            fams = list(FAMILIES)
    updated, skipped = [], []
    for fam in fams:
        r = assess_impl(
            surface_type=surface_type, surface_id=surface_id, family=fam,
            execution="blocked", remaining_work=prereq,
            applicability_rationale=rationale or f"Blocked: {prereq}",
            blocking_prereqs=[prereq],
            evidence_refs=[evidence_ref] if evidence_ref.strip() else None,
        )
        (updated if r.get("success") else skipped).append(fam)
    return {"success": True, "surface_id": surface_id.strip(), "blocking_prereq": prereq,
            "blocked_count": len(updated), "blocked_families": updated, "skipped": skipped}


@function_tool
async def mark_families_blocked(
    ctx: RunContextWrapper, surface_type: str, surface_id: str,
    blocking_prereq: str, families: list[str] | None = None,
    rationale: str = "", evidence_ref: str = "",
) -> str:
    """Record a whole CLUSTER of families as `blocked` on ONE shared prerequisite in
    a single call — instead of a separate `assess_coverage` per family.

    Use this when many families can't be tested for the *same* reason (the common
    case: an SSO-only target where no session was obtained blocks IDOR/BFLA/mass-
    assignment/upload/SSRF/stored-XSS/workflow/race all at once). Reconciling each
    of those one-by-one at scan end is pure bookkeeping that spends budget without
    finding anything — do it in one call and get back to hunting.

    Leave `families` empty to block every not-yet-`tested` family on this surface
    (the session-blocked cluster). Pass an explicit list to block a subset. This is
    the right tool for the "blocked on auth" reconciliation; it is NOT a way to
    close a family as safe — `blocked` means untested, and it still shows in the
    report as an open gap, which is the honest outcome.

    Args:
        surface_type: `origin`/`route`/... (usually `origin`).
        surface_id: the surface, e.g. `https://host:443`.
        blocking_prereq: the single shared blocker, e.g. "no MyGov session obtained".
        families: optional subset; empty = all not-yet-tested families here.
        rationale: optional shared rationale.
        evidence_ref: optional shared evidence id/path.
    """
    result = mark_families_blocked_impl(
        surface_type=surface_type, surface_id=surface_id, families=families or [],
        blocking_prereq=blocking_prereq, rationale=rationale, evidence_ref=evidence_ref)
    record_activity_tick(_agent_id(ctx))
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool
async def query_coverage_matrix(ctx: RunContextWrapper, surface_type: str = "", family: str = "",
                                applicability: str = "", execution: str = "") -> str:
    """List coverage cells, optionally filtered by surface_type/family/
    applicability/execution."""
    return json.dumps(query_impl(surface_type=surface_type, family=family,
                                 applicability=applicability, execution=execution),
                      ensure_ascii=False, default=str)


@function_tool
async def list_coverage_gaps(ctx: RunContextWrapper) -> str:
    """List unresolved coverage (applicable-not-tested, unknown, blocked/deferred,
    stale-after-resume, missing-capability) for honest completion/reporting. A
    scan must never be reported 'fully tested' while gaps remain."""
    return json.dumps(coverage_gaps_impl(), ensure_ascii=False, default=str)


@function_tool
async def next_coverage_task(ctx: RunContextWrapper, count: int = 1) -> str:
    """Claim the next pending coverage-assessment task(s) from the matrix so EVERY
    family — not just SQLi/XSS — gets a turn. Deterministic and anti-starvation
    (least-progressed family first); each task names the `load_skill` to pull (or
    null for a capability gap, with `shared_guidance: analysis/family_assessment`)
    and the prerequisites to establish before a scoped hypothesis/test. Claiming
    sets the cell to `in_progress` (not `tested`); run this in a loop as the
    black-box worklist driver alongside the executors."""
    result = next_coverage_task_impl(count=count)
    record_activity_tick(_agent_id(ctx))
    return json.dumps(result, ensure_ascii=False, default=str)
