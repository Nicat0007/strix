"""Component/version observation + advisory-research workflow (BLACKBOX #6 Part B).

A traceable chain, each step kept DISTINCT and never collapsed:

    observed component -> identity/version evidence -> current advisory research
      -> affected-range / prerequisite analysis -> relevant hypothesis
      -> bounded validation -> sourced result.

Discipline (enforced here, not just documented):
- A banner/version match is a CANDIDATE, never a confirmed vulnerability — this
  store has no "confirmed" verdict; confirmation lives on the hypothesis worklist
  after validation.
- An unknown/low-confidence version stays `uncertain`; it can never be
  `applicable`.
- A front-end library does NOT prove a vulnerable backend — a frontend
  observation is capped at `candidate`.
- An unavailable research service is `research_pending`, never "no CVEs".
- "No matching advisory" (`no_advisory_found`) does NOT establish security.
- `not_applicable` needs an evidence-backed reason (a fixed version in range, a
  disabled module/config, unreachable feature).
- Retrieved pages / PoC repos are untrusted data; this store records only
  sourced URLs + structured fields and never executes anything. Credentials and
  private request contents are never written here.
- Whitebox package evidence (lockfile/manifest -> create_dependency_report) stays
  distinct from this blackbox inference; record the evidence source accordingly.
"""

from __future__ import annotations

import json
import logging
import re
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.agent_metrics.tools import record_activity_tick
from strix.tools.attack_surface.tools import _redact_secrets


logger = logging.getLogger(__name__)

_SCHEMA_VERSION = 1
_CONFIDENCE = ("high", "medium", "low", "unknown")
_VERDICTS = ("candidate", "applicable", "not_applicable", "uncertain", "research_pending")
_RESEARCH_STATES = ("research_pending", "researched", "no_advisory_found", "research_unavailable")

_store: dict[str, dict[str, Any]] = {}
_lock = threading.RLock()
_path: Path | None = None


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _clean(v: str | None, cap: int = 400) -> str:
    return _redact_secrets((v or "").strip())[:cap]


def _key(location: str, product: str) -> str:
    return f"{location.strip().lower()}||{product.strip().lower()}"


# --------------------------------------------------------------------------- #
# Deterministic version comparison (NEVER lexicographic) + range evaluation
# --------------------------------------------------------------------------- #

_UNSUPPORTED_VER = re.compile(r"[A-Za-z]|[-+*~^ ]")


def _version_tuple(s: str) -> tuple[int, ...] | None:
    """Parse a PURE dotted-numeric version to an int tuple. Returns None for
    anything this numeric evaluator cannot compare semantically — empty,
    prereleases/build metadata (`1.2.0-rc1`, `1.2.0b1`), wildcards or range
    operators (`1.2.*`, `~1.2`, `^1`) — so unsupported syntax stays UNKNOWN
    rather than being silently misclassified by dropping the suffix. Numeric
    padding is handled by the comparator (1.2 == 1.2.0), not here."""
    s = (s or "").strip()
    if s[:1] in ("v", "V"):
        s = s[1:]
    if not s or _UNSUPPORTED_VER.search(s):
        return None
    parts = s.split(".")
    nums: list[int] = []
    for p in parts:
        if not p.isdigit():
            return None
        nums.append(int(p))
    return tuple(nums) or None


def _vcmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    la, lb = len(a), len(b)
    for i in range(max(la, lb)):
        av = a[i] if i < la else 0
        bv = b[i] if i < lb else 0
        if av != bv:
            return -1 if av < bv else 1
    return 0


def _satisfies_spec(ver: tuple[int, ...], spec: str) -> bool | None:
    """Evaluate one comparator like '<1.21.0', '>=1.2', '==3.4.1'. None = can't
    parse the spec's version (stay uncertain)."""
    spec = spec.strip()
    for op in ("<=", ">=", "==", "<", ">", "="):
        if spec.startswith(op):
            rhs = _version_tuple(spec[len(op):])
            if rhs is None:
                return None
            c = _vcmp(ver, rhs)
            return {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0,
                    "==": c == 0, "=": c == 0}[op]
    rhs = _version_tuple(spec)  # bare version => exact match
    return None if rhs is None else _vcmp(ver, rhs) == 0


def evaluate_version_range(observed: str, affected_ranges: list[str],
                           backport_possible: bool = False) -> dict[str, Any]:
    """Deterministically decide whether `observed` falls in ANY affected range.
    A range string may AND several comma-separated comparators (e.g.
    '>=1.2,<3.5.0'). Returns {in_affected: True/False/None, reason}. Unknown or
    unparseable versions, or a possible distribution backport, stay None
    (uncertain) — never a lexicographic guess, never an auto-conclusion."""
    ver = _version_tuple(observed)
    if ver is None:
        return {"in_affected": None, "reason": "observed version unknown/unparseable"}
    if not (affected_ranges or []):
        return {"in_affected": None, "reason": "no affected range provided"}
    if backport_possible:
        return {"in_affected": None,
                "reason": "distribution backport possible — a version string cannot settle it"}
    any_match = False
    saw_uncertain = False
    for rng in affected_ranges or []:
        specs = [s for s in rng.split(",") if s.strip()]
        results = [_satisfies_spec(ver, s) for s in specs]
        if None in results:
            saw_uncertain = True
            continue
        if specs and all(results):
            any_match = True
    if any_match:
        return {"in_affected": True, "reason": "observed version within an affected range"}
    if saw_uncertain and not affected_ranges:
        return {"in_affected": None, "reason": "no parseable affected range"}
    if saw_uncertain:
        return {"in_affected": None, "reason": "affected range not fully parseable"}
    return {"in_affected": False, "reason": "observed version outside all affected ranges"}


def hydrate_component_research_from_disk(state_dir: Path) -> None:
    """Load this run's component observations. On resume, a version observed in a
    prior process is flagged for re-verification (fingerprints can drift) and any
    non-terminal research is left `research_pending`."""
    global _path  # noqa: PLW0603
    _path = state_dir / "component_research.json"
    with _lock:
        _store.clear()
        if not _path.exists():
            return
        try:
            data = json.loads(_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception("component_research.json at %s unreadable; starting empty", _path)
            return
        comps = data.get("components") if isinstance(data, dict) else None
        if isinstance(comps, dict):
            for k, e in comps.items():
                if isinstance(e, dict):
                    e["version_stale_after_resume"] = True
                    _store[k] = e
        logger.info("component research hydrated from %s (%d)", _path, len(_store))


def _persist_locked() -> None:
    path = _path
    if path is None:
        return
    try:
        payload = json.dumps({"schema_version": _SCHEMA_VERSION, "components": _store},
                             ensure_ascii=False, indent=2, default=str)
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=str(path.parent),
                                         prefix=f".{path.name}.", suffix=".tmp",
                                         delete=False) as tmp:
            tmp.write(payload)
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
    except Exception:
        logger.exception("component research persist to %s failed", path)


def record_component_impl(
    *, product: str, location: str, vendor: str = "", observed_version: str = "",
    version_confidence: str = "unknown", version_evidence: str = "", is_frontend: bool = False,
    fingerprint_conflicts: list[str] | None = None, evidence_source: str = "blackbox_inference",
) -> dict[str, Any]:
    prod, loc = product.strip(), location.strip()
    if not prod or not loc:
        return {"success": False, "error": "product and location are required"}
    conf = version_confidence.strip().lower()
    if conf not in _CONFIDENCE:
        return {"success": False, "error": f"version_confidence must be one of {_CONFIDENCE}"}
    ver = observed_version.strip()
    conflicts = [_clean(c, 120) for c in (fingerprint_conflicts or []) if str(c).strip()]
    # A version is only usable if present AND not low/unknown confidence AND not
    # contradicted by a conflicting fingerprint.
    version_usable = bool(ver) and conf in ("high", "medium") and not conflicts
    with _lock:
        k = _key(loc, prod)
        entry = _store.get(k) or {
            "product": prod, "vendor": _clean(vendor, 120), "location": _clean(loc, 200),
            "advisories": [], "hypothesis_refs": [], "created_at": _now(),
        }
        entry["observed_version"] = _clean(ver, 80)
        entry["version_confidence"] = conf
        entry["version_evidence"] = _clean(version_evidence, 300)
        entry["is_frontend"] = bool(is_frontend)
        entry["fingerprint_conflicts"] = conflicts
        entry["evidence_source"] = (evidence_source.strip().lower()
                                    if evidence_source.strip().lower()
                                    in ("blackbox_inference", "whitebox_manifest") else
                                    "blackbox_inference")
        entry["observed_at"] = _now()
        entry["version_usable"] = version_usable
        entry["version_stale_after_resume"] = False
        entry.setdefault("research_state", "research_pending")
        entry["applicability_verdict"] = (
            "uncertain" if (not version_usable) else entry.get("applicability_verdict",
                                                               "research_pending"))
        entry["updated_at"] = _now()
        _store[k] = entry
        _persist_locked()
        return {"success": True, **_public(entry)}


def record_advisory_candidate_impl(
    *, product: str, location: str, advisory_id: str, source_url: str, retrieved_at: str,
    affected_ranges: list[str] | None = None, fixed_versions: list[str] | None = None,
    required_modules: list[str] | None = None, required_config: str = "",
    auth_required: str = "", reachable_feature: str = "", applicability_verdict: str = "candidate",
    remaining_verification: str = "", research_state: str = "researched",
    distribution_backport_possible: bool = False,
) -> dict[str, Any]:
    with _lock:
        entry = _store.get(_key(location, product))
    if entry is None:
        return {"success": False, "error": "record the component first (record_component)"}
    if not advisory_id.strip() or not source_url.strip():
        return {"success": False, "error": "advisory_id and source_url are required (no citations "
                                            "from memory — provide the retrieved source URL)"}
    verdict = applicability_verdict.strip().lower()
    if verdict not in _VERDICTS:
        return {"success": False, "error": f"applicability_verdict must be one of {_VERDICTS}"}
    rstate = research_state.strip().lower()
    if rstate not in _RESEARCH_STATES:
        return {"success": False, "error": f"research_state must be one of {_RESEARCH_STATES}"}
    affected = [_clean(a, 80) for a in (affected_ranges or []) if str(a).strip()]
    fixed = [_clean(f, 80) for f in (fixed_versions or []) if str(f).strip()]
    # Deterministic range evaluation (never lexicographic). Uses the component's
    # observed version only if it is usable; a backport possibility keeps it
    # uncertain regardless.
    range_check = evaluate_version_range(
        entry.get("observed_version", "") if entry.get("version_usable") else "",
        affected, backport_possible=distribution_backport_possible)
    reason = ""
    # Enforce the uncertainty ladder — a match is never more than a candidate
    # without a usable version, an IN-RANGE affected spec, and a reachable feature.
    if not entry.get("version_usable") and verdict == "applicable":
        verdict, reason = "uncertain", "version unknown/low-confidence/conflicting"
    elif entry.get("is_frontend") and verdict == "applicable":
        verdict, reason = "candidate", "front-end observation does not prove a vulnerable backend"
    elif verdict == "applicable" and range_check["in_affected"] is False:
        verdict, reason = "not_applicable", f"version-range check: {range_check['reason']}"
    elif verdict == "applicable" and range_check["in_affected"] is None:
        verdict, reason = "candidate", f"affected range not settled: {range_check['reason']}"
    elif verdict == "applicable" and not reachable_feature.strip():
        verdict, reason = "candidate", "in-range but reachable feature not established"
    if verdict == "not_applicable" and not (fixed or required_config.strip()
                                            or remaining_verification.strip()
                                            or range_check["in_affected"] is False):
        return {"success": False, "rejected": "not_applicable_needs_evidence",
                "error": "not_applicable needs evidence (a fixed version in range, a disabled "
                         "module/config, or an unreachable feature)"}
    advisory = {
        "advisory_id": _clean(advisory_id, 80), "source_url": _clean(source_url, 400),
        "retrieved_at": _clean(retrieved_at, 60) or _now(),
        "affected_ranges": affected, "fixed_versions": fixed,
        "required_modules": [_clean(m, 80) for m in (required_modules or []) if str(m).strip()],
        "required_config": _clean(required_config, 300), "auth_required": _clean(auth_required, 80),
        "reachable_feature": _clean(reachable_feature, 300),
        "applicability_verdict": verdict, "verdict_downgrade_reason": reason,
        "remaining_verification": _clean(remaining_verification, 300),
        "range_check": range_check,
        "distribution_backport_possible": bool(distribution_backport_possible),
        # The URL + time are AGENT-ASSERTED — the host did not retrieve the page,
        # so this is provenance, not proof of retrieval.
        "source_provenance": "agent_asserted",
    }
    with _lock:
        entry["advisories"].append(advisory)
        entry["research_state"] = rstate
        # Component roll-up is the strongest advisory verdict, but never beyond
        # what a single advisory earned (still only a candidate/applicable lead).
        order = {"research_pending": 0, "uncertain": 1, "not_applicable": 1, "candidate": 2,
                 "applicable": 3}
        cur = entry.get("applicability_verdict", "research_pending")
        if order.get(verdict, 0) >= order.get(cur, 0):
            entry["applicability_verdict"] = verdict
        entry["updated_at"] = _now()
        _persist_locked()
        return {"success": True, "recorded_verdict": verdict,
                "downgraded": bool(reason), "reason": reason, **_public(entry)}


def _public(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "product": entry["product"], "vendor": entry.get("vendor", ""),
        "location": entry["location"], "observed_version": entry.get("observed_version", ""),
        "version_confidence": entry.get("version_confidence", "unknown"),
        "version_usable": entry.get("version_usable", False),
        "is_frontend": entry.get("is_frontend", False),
        "fingerprint_conflicts": entry.get("fingerprint_conflicts", []),
        "evidence_source": entry.get("evidence_source", "blackbox_inference"),
        "research_state": entry.get("research_state", "research_pending"),
        "applicability_verdict": entry.get("applicability_verdict", "research_pending"),
        "version_stale_after_resume": entry.get("version_stale_after_resume", False),
        "advisory_count": len(entry.get("advisories", [])),
        "advisories": entry.get("advisories", [])[:20],
        "hypothesis_refs": entry.get("hypothesis_refs", []),
    }


def query_impl() -> dict[str, Any]:
    with _lock:
        comps = [_public(e) for e in _store.values()]
    return {"success": True, "total": len(comps), "components": comps}


def _agent_id(ctx: RunContextWrapper) -> str | None:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    a = inner.get("agent_id")
    return a if isinstance(a, str) else None


@function_tool
async def record_component(
    ctx: RunContextWrapper, product: str, location: str, vendor: str = "",
    observed_version: str = "", version_confidence: str = "unknown", version_evidence: str = "",
    is_frontend: bool = False, evidence_source: str = "blackbox_inference",
) -> str:
    """Record an observed component and its version evidence (distinguish a CDN/
    proxy/front-end observation from origin software). A version is only usable
    with medium/high confidence and no conflicting fingerprint; otherwise the
    component stays `uncertain`. `evidence_source` is `blackbox_inference` (banner/
    fingerprint) or `whitebox_manifest` (lockfile) — keep them distinct."""
    result = record_component_impl(product=product, location=location, vendor=vendor,
                                   observed_version=observed_version,
                                   version_confidence=version_confidence,
                                   version_evidence=version_evidence, is_frontend=is_frontend,
                                   evidence_source=evidence_source)
    record_activity_tick(_agent_id(ctx))
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool
async def record_advisory_candidate(
    ctx: RunContextWrapper, product: str, location: str, advisory_id: str, source_url: str,
    retrieved_at: str, affected_ranges: list[str] | None = None, required_config: str = "",
    auth_required: str = "", reachable_feature: str = "", applicability_verdict: str = "candidate",
    remaining_verification: str = "", research_state: str = "researched",
    distribution_backport_possible: bool = False,
) -> str:
    """Attach a researched advisory (with its SOURCE URL + retrieval time — an
    AGENT-ASSERTED provenance, never a citation from memory and never host-proof
    of retrieval) to a recorded component. `affected_ranges` are evaluated against
    the observed version with real version comparison (never lexicographic): a
    banner/version match is at most a `candidate`; `applicable` requires a usable
    IN-RANGE version AND a reachable feature; a front-end observation caps at
    `candidate`; a possible distribution backport keeps it uncertain;
    `not_applicable` needs evidence. An unavailable research service is
    `research_unavailable`/`research_pending`, never "no CVEs"."""
    result = record_advisory_candidate_impl(
        product=product, location=location, advisory_id=advisory_id, source_url=source_url,
        retrieved_at=retrieved_at, affected_ranges=affected_ranges, required_config=required_config,
        auth_required=auth_required, reachable_feature=reachable_feature,
        applicability_verdict=applicability_verdict, remaining_verification=remaining_verification,
        research_state=research_state,
        distribution_backport_possible=distribution_backport_possible)
    record_activity_tick(_agent_id(ctx))
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool
async def query_component_research(ctx: RunContextWrapper) -> str:
    """List recorded components, their version/confidence, researched advisories
    and applicability verdicts (candidate/applicable/not_applicable/uncertain/
    research_pending)."""
    return json.dumps(query_impl(), ensure_ascii=False, default=str)
