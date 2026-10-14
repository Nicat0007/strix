"""Evidence-backed hypothesis worklist (BLACKBOX improvement #3).

Connects the durable attack-surface inventory (#1) and the actor-aware crawl /
replay evidence (#2) into an explicit, resumable worklist an agent drives:

    query discovered endpoints (attack_surface)
      -> record a CONCRETE security hypothesis (endpoint + resource + actor +
         param/operation + vuln category + rationale)
      -> attach request/observation evidence, replay-resolved through the proxy
      -> pick the next test/tool and record WHY it applies
      -> record the attempt's outcome + what validation is still required
      -> continue / block / rule out / (separately, explicitly) confirm.

Discipline carried from the earlier pieces and `analysis/counterevidence.md`:

- A tool finding alone never confirms. ``record_test_attempt`` can move a
  hypothesis to testing / needs_validation / blocked / ruled_out, but NOT to
  confirmed. Confirmation is a separate, explicit ``update_hypothesis`` call that
  requires a validated-PoC note AND at least one evidence reference.
- Deduplicate equivalent hypotheses, but a different resource, actor, or
  parameter location is a DIFFERENT hypothesis — never merged.
- Replay readiness: a request reference is resolved through the existing proxy
  (``proxy.caido_api.view_request``) before it is treated as usable. A missing /
  stale / unresolvable reference is recorded as such, with a suggestion to
  capture or revalidate — never fabricated. On ``--resume`` a prior process's
  resolution is downgraded to stale.
- Hypothesis status is kept separate from the inventory's per-endpoint test
  bookkeeping (``record_endpoint_test``) and from the coverage ledger / scan
  completion. Blocked or inconclusive work stays visible via ``pending_only``.
- The general record stores names/ids/categories/outcomes only; agent free text
  is secret-redacted and bounded; no response bodies are stored.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.skills import get_available_skills
from strix.tools.agent_metrics.tools import record_activity_tick
from strix.tools.attack_surface.tools import (
    VALID_PARAM_LOCATIONS,
    _redact_secrets,
    lookup_endpoint,
)


logger = logging.getLogger(__name__)

_SCHEMA_VERSION = 1

_store: dict[str, dict[str, Any]] = {}
_lock = threading.RLock()
_path: Path | None = None

_TEXT_MAX = 1000
_QUERY_LIMIT_DEFAULT = 100
_QUERY_LIMIT_MAX = 500
_ATTEMPTS_RETURNED = 20
_EVIDENCE_RETURNED = 30

STATUS_UNTESTED = "untested"
STATUS_TESTING = "testing"
STATUS_NEEDS_VALIDATION = "needs_validation"
STATUS_BLOCKED = "blocked"
STATUS_RULED_OUT = "ruled_out"
STATUS_CONFIRMED = "confirmed"
VALID_STATUSES: tuple[str, ...] = (
    STATUS_UNTESTED, STATUS_TESTING, STATUS_NEEDS_VALIDATION,
    STATUS_BLOCKED, STATUS_RULED_OUT, STATUS_CONFIRMED,
)
#: Statuses a raw tool attempt may set — never 'confirmed' (a tool finding alone
#: does not confirm) and never 'untested' (an attempt was made).
ATTEMPT_RESULT_STATUSES: tuple[str, ...] = (
    STATUS_TESTING, STATUS_NEEDS_VALIDATION, STATUS_BLOCKED, STATUS_RULED_OUT,
)
#: Statuses that still need attention (the actionable worklist).
PENDING_STATUSES: tuple[str, ...] = (
    STATUS_UNTESTED, STATUS_TESTING, STATUS_NEEDS_VALIDATION, STATUS_BLOCKED,
)

_LABELS: frozenset[str] = frozenset({"high", "medium", "low"})
_BUCKETS: frozenset[str] = frozenset({"p0", "p1", "p2", "p3"})

#: Replay-resolution states for a request reference attached as evidence.
RESOLVED = "resolved"
RESOLVED_MISSING = "missing"  # proxy reachable, id not found (stale/never-captured)
RESOLVED_UNAVAILABLE = "unresolvable_now"  # proxy not reachable this process
RESOLVED_STALE = "stale_after_resume"  # resolved in a prior process; must re-check
NOT_APPLICABLE = "not_applicable"  # observation/note evidence, nothing to replay

_CAPTURE_HINT = (
    "no usable replayable request — capture the request in the proxy and attach its "
    "id, or revalidate the reference, rather than relying on this evidence"
)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _clean_text(value: str | None) -> str:
    return _redact_secrets((value or "").strip())[:_TEXT_MAX]


# --------------------------------------------------------------------------- #
# Persistence (same shape as attack_surface / crawl_executor stores)
# --------------------------------------------------------------------------- #


def hydrate_hypotheses_from_disk(state_dir: Path) -> None:
    """Load this run's worklist from ``{state_dir}/hypotheses.json``.

    Unconditional, alongside the other ``hydrate_*`` calls in ``core/runner``.
    On resume, every request-evidence reference that was ``resolved`` in a prior
    process is downgraded to ``stale_after_resume`` — a replay confirmed before a
    resume cannot be trusted afterwards (mirrors #1's verified-ref downgrade and
    #2's job revalidation)."""
    global _path  # noqa: PLW0603
    _path = state_dir / "hypotheses.json"
    with _lock:
        _store.clear()
        if not _path.exists():
            return
        try:
            data = json.loads(_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception("hypotheses.json at %s is unreadable; starting empty", _path)
            return
        entries = data.get("hypotheses") if isinstance(data, dict) else None
        if isinstance(entries, dict):
            for key, entry in entries.items():
                if not isinstance(entry, dict):
                    continue
                for ev in entry.get("evidence", []):
                    if ev.get("resolved_state") == RESOLVED:
                        ev["resolved_state"] = RESOLVED_STALE
                _store[key] = entry
        logger.info("hypothesis worklist hydrated from %s (%d)", _path, len(_store))


def lookup_hypothesis(hypothesis_id: str) -> dict[str, Any] | None:
    """Public, read-only projection of one hypothesis by id, or None if unknown.

    Lets an executor (e.g. the targeted SQLi runner) read a hypothesis's category,
    endpoint, resource, actor, and subject before testing it and recording an
    attempt via ``record_test_attempt``."""
    with _lock:
        entry = _store.get((hypothesis_id or "").strip())
        return _public_hypothesis(entry) if entry else None


def _persist_locked() -> None:
    path = _path
    if path is None:
        return
    try:
        payload = json.dumps(
            {"schema_version": _SCHEMA_VERSION, "hypotheses": _store},
            ensure_ascii=False, indent=2, default=str,
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=str(path.parent),
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as tmp:
            tmp.write(payload)
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
    except Exception:
        logger.exception("hypothesis worklist persist to %s failed", path)


# --------------------------------------------------------------------------- #
# Identity / normalization
# --------------------------------------------------------------------------- #


def _subject(param_name: str, param_location: str, operation: str) -> tuple[str, dict[str, str]]:
    """The thing-under-test token used in the dedup key, plus its fields. A
    parameter (name+location) or an operation; distinct locations never merge."""
    op = operation.strip()
    if op:
        return f"op:{op.lower()}", {"operation": op}
    name = param_name.strip()
    if name:
        loc = param_location.strip().lower() or "unknown"
        if loc not in VALID_PARAM_LOCATIONS:
            loc = "unknown"
        return f"param:{loc}:{name.lower()}", {"param_name": name, "param_location": loc}
    return "endpoint", {}


def _hypothesis_id(
    endpoint_id: str, resource: str, actor_ref: str, subject: str, vuln_category: str
) -> str:
    key = f"{endpoint_id}||{resource}||{actor_ref}||{subject}||{vuln_category}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


def _valid_category(vuln_category: str) -> bool:
    try:
        entries = get_available_skills().get("vulnerabilities", [])
    except OSError:
        return True  # cannot enumerate — don't block the agent, just skip the hint
    names = {e["name"] for e in entries if isinstance(e, dict) and e.get("name")}
    return vuln_category in names


def _priority(impact: str, evidence_strength: str, test_cost: str, bucket: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in (
        ("impact", impact), ("evidence_strength", evidence_strength), ("test_cost", test_cost)
    ):
        v = (value or "").strip().lower()
        if v in _LABELS:
            out[key] = v
    b = (bucket or "").strip().lower()
    if b in _BUCKETS:
        out["bucket"] = b.upper()
    return out


# --------------------------------------------------------------------------- #
# Replay-readiness resolution (reuses the existing proxy facility)
# --------------------------------------------------------------------------- #


async def _default_request_resolver(request_id: str) -> dict[str, Any] | None:
    """Resolve a request id through the existing Caido proxy. Returns a tiny
    non-secret summary (method + status only) or None if not found. Raises if the
    proxy is unreachable (caller treats that as unresolvable-now)."""
    # Lazy: avoid importing the Caido SDK at module load and any import cycle with
    # the proxy package; the worklist must load even when the proxy is absent.
    from strix.tools.proxy import caido_api  # noqa: PLC0415

    result = await caido_api.view_request(request_id, part="request")
    if result is None:
        return None
    req = getattr(result, "request", result)
    method = getattr(req, "method", None)
    resp = getattr(result, "response", None)
    status = getattr(resp, "status_code", None) if resp is not None else None
    return {"method": method, "status": status}


def _strip_scheme(ref: str) -> str:
    ref = ref.strip()
    return ref.split(":", 1)[1] if ref.lower().startswith("caido:") else ref


async def _resolve_request_evidence(
    ref: str, resolver: Any, note: str
) -> dict[str, Any]:
    """Build a request-evidence record, replay-resolving the reference. Stores the
    id, the resolved state, a method/status summary (never a body), and — when
    unusable — a capture/revalidate suggestion."""
    request_id = _strip_scheme(ref)
    evidence: dict[str, Any] = {
        "kind": "request", "ref": ref[:256], "note": _clean_text(note),
        "checked_at": _now(),
    }
    try:
        summary = await resolver(request_id)
    except Exception:  # noqa: BLE001 — any proxy failure degrades to unresolvable, never crashes
        evidence["resolved_state"] = RESOLVED_UNAVAILABLE
        evidence["suggestion"] = _CAPTURE_HINT
        return evidence
    if summary is None:
        evidence["resolved_state"] = RESOLVED_MISSING
        evidence["suggestion"] = _CAPTURE_HINT
        return evidence
    evidence["resolved_state"] = RESOLVED
    method = summary.get("method")
    status = summary.get("status")
    # Method + status only — no URL (query values) and no body.
    evidence["summary"] = f"{method or '?'} -> {status if status is not None else '?'}"
    return evidence


async def _collect_evidence(
    *, request_ref: str, observation_ref: str, evidence_note: str, resolver: Any
) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    if request_ref.strip():
        evidence.append(await _resolve_request_evidence(request_ref, resolver, evidence_note))
    if observation_ref.strip():
        evidence.append({
            "kind": "observation", "ref": observation_ref.strip()[:256],
            "resolved_state": NOT_APPLICABLE, "note": _clean_text(evidence_note),
        })
    return evidence


# --------------------------------------------------------------------------- #
# Core implementations (sync, under lock)
# --------------------------------------------------------------------------- #


def _create_impl(
    *,
    endpoint_id: str,
    vuln_category: str,
    resource: str,
    actor_ref: str,
    param_name: str,
    param_location: str,
    operation: str,
    rationale: str,
    next_action: str,
    priority: dict[str, str],
    evidence: list[dict[str, Any]],
    agent_id: str | None,
    agent_name: str | None,
) -> dict[str, Any]:
    endpoint_id = (endpoint_id or "").strip()
    if not endpoint_id:
        return {"success": False, "error": "endpoint_id is required (from query_attack_surface)"}
    category = (vuln_category or "").strip().lower()
    if not category:
        return {"success": False,
                "error": "vuln_category is required (e.g. 'idor', 'sql_injection')"}
    diagnostics: list[str] = []
    if not _valid_category(category):
        diagnostics.append(f"vuln_category {category!r} is not a known vulnerability skill name")

    resource = resource.strip()
    actor = actor_ref.strip() or "anonymous"
    subject, subject_fields = _subject(param_name, param_location, operation)
    hid = _hypothesis_id(endpoint_id, resource, actor, subject, category)

    now = _now()
    endpoint = lookup_endpoint(endpoint_id)
    with _lock:
        entry = _store.get(hid)
        created = entry is None
        if entry is None:
            entry = {
                "hypothesis_id": hid,
                "endpoint_id": endpoint_id,
                "origin": (endpoint or {}).get("origin"),
                "method": (endpoint or {}).get("method"),
                "path": (endpoint or {}).get("path"),
                "resource": resource,
                "actor_ref": actor,
                "vuln_category": category,
                "subject": subject,
                "status": STATUS_UNTESTED,
                "rationale": "",
                "next_action": "",
                "priority": {},
                "evidence": [],
                "counterevidence": [],
                "attempts": [],
                "created_at": now,
                "updated_at": now,
            }
            entry.update(subject_fields)
            _store[hid] = entry
        if endpoint is None and created:
            diagnostics.append(
                f"endpoint_id {endpoint_id!r} not found in the inventory yet; "
                "recorded anyway — denormalized origin/method/path are empty"
            )

        if rationale.strip():
            entry["rationale"] = _clean_text(rationale)
        if next_action.strip():
            entry["next_action"] = _clean_text(next_action)
        if priority:
            entry["priority"].update(priority)
        _merge_evidence(entry, evidence)
        entry["updated_at"] = now
        _persist_locked()

    record_activity_tick(agent_id)
    result = {"success": True, "hypothesis_id": hid, "created": created,
              "status": _store[hid]["status"], "deduplicated": not created}
    if diagnostics:
        result["diagnostics"] = diagnostics
    return result


def _merge_evidence(entry: dict[str, Any], new_evidence: list[dict[str, Any]]) -> None:
    existing = entry.setdefault("evidence", [])
    seen = {(e.get("kind"), e.get("ref")) for e in existing}
    for ev in new_evidence:
        key = (ev.get("kind"), ev.get("ref"))
        if key in seen:
            # Refresh the resolved state of an existing reference rather than dup.
            for e in existing:
                if (e.get("kind"), e.get("ref")) == key:
                    e.update(ev)
                    break
        else:
            seen.add(key)
            existing.append(ev)


def _update_impl(
    *,
    hypothesis_id: str,
    status: str,
    next_action: str,
    rationale: str,
    add_counterevidence: str,
    confirmation: str,
    priority: dict[str, str],
    new_evidence: list[dict[str, Any]],
    agent_id: str | None,
    agent_name: str | None,
) -> dict[str, Any]:
    hid = (hypothesis_id or "").strip()
    new_status = status.strip().lower()
    if new_status and new_status not in VALID_STATUSES:
        return {"success": False,
                "error": f"Invalid status {status!r}; one of {list(VALID_STATUSES)}"}
    with _lock:
        entry = _store.get(hid)
        if entry is None:
            return {"success": False, "error": f"No hypothesis {hypothesis_id!r}"}
        if new_evidence:
            _merge_evidence(entry, new_evidence)
        if new_status == STATUS_CONFIRMED:
            # A confirmation must be an explicit, evidence-backed judgement — never
            # the automatic consequence of a tool signal.
            if not confirmation.strip():
                return {"success": False,
                        "error": "confirming requires a validated-PoC note in 'confirmation'; "
                                 "a tool signal alone does not confirm a finding"}
            if not entry.get("evidence"):
                return {"success": False,
                        "error": "confirming requires at least one attached evidence reference"}
            entry["confirmation"] = _clean_text(confirmation)
        if new_status:
            entry["status"] = new_status
        if next_action.strip():
            entry["next_action"] = _clean_text(next_action)
        if rationale.strip():
            entry["rationale"] = _clean_text(rationale)
        if add_counterevidence.strip():
            entry.setdefault("counterevidence", []).append(_clean_text(add_counterevidence))
        if priority:
            entry.setdefault("priority", {}).update(priority)
        entry["updated_at"] = _now()
        _persist_locked()

    record_activity_tick(agent_id)
    return {"success": True, "hypothesis_id": hid, "status": _store[hid]["status"]}


def _record_attempt_impl(
    *,
    hypothesis_id: str,
    tool: str,
    tool_rationale: str,
    outcome: str,
    result_status: str,
    validation_required: str,
    signal: str,
    input_evidence: dict[str, Any] | None,
    agent_id: str | None,
    agent_name: str | None,
) -> dict[str, Any]:
    hid = (hypothesis_id or "").strip()
    status = result_status.strip().lower()
    if status not in ATTEMPT_RESULT_STATUSES:
        return {
            "success": False,
            "error": f"result_status must be one of {list(ATTEMPT_RESULT_STATUSES)} — a tool "
                     "attempt never sets 'confirmed' (confirm explicitly via update_hypothesis) "
                     "or 'untested'",
        }
    if not tool.strip():
        return {"success": False, "error": "tool is required (e.g. 'sqlmap', 'manual', 'dalfox')"}
    if not tool_rationale.strip():
        return {"success": False,
                "error": "tool_rationale is required — record WHY this tool fits this evidence, "
                         "not just that a parameter name looked interesting"}
    with _lock:
        entry = _store.get(hid)
        if entry is None:
            return {"success": False, "error": f"No hypothesis {hypothesis_id!r}"}
        attempt = {
            "tool": tool.strip()[:120],
            "tool_rationale": _clean_text(tool_rationale),
            "outcome": _clean_text(outcome),
            "result_status": status,
            "validation_required": _clean_text(validation_required),
            "signal": signal.strip().lower()[:60],
            "at": _now(),
        }
        if agent_name:
            attempt["agent_name"] = agent_name
        if input_evidence:
            attempt["input_evidence"] = input_evidence
            _merge_evidence(entry, [input_evidence])
        entry.setdefault("attempts", []).append(attempt)
        entry["status"] = status
        entry["updated_at"] = _now()
        _persist_locked()

    record_activity_tick(agent_id)
    return {"success": True, "hypothesis_id": hid, "status": status,
            "attempts": len(entry["attempts"])}


# --------------------------------------------------------------------------- #
# Query / projection
# --------------------------------------------------------------------------- #


def _public_hypothesis(entry: dict[str, Any]) -> dict[str, Any]:
    attempts = list(entry.get("attempts", []))
    evidence = list(entry.get("evidence", []))
    view = {
        k: entry.get(k)
        for k in (
            "hypothesis_id", "endpoint_id", "origin", "method", "path", "resource",
            "actor_ref", "vuln_category", "subject", "param_name", "param_location",
            "operation", "status", "rationale", "next_action", "confirmation",
            "created_at", "updated_at",
        )
        if entry.get(k) is not None
    }
    view["priority"] = dict(entry.get("priority", {}))
    view["counterevidence"] = list(entry.get("counterevidence", []))[-_EVIDENCE_RETURNED:]
    view["evidence"] = evidence[-_EVIDENCE_RETURNED:]
    view["evidence_truncated"] = len(evidence) > _EVIDENCE_RETURNED
    view["attempts"] = attempts[-_ATTEMPTS_RETURNED:]
    view["attempt_count"] = len(attempts)
    # A quick readable flag for downstream: does any attached request need a
    # (re)capture/revalidation before it can be replayed?
    view["needs_replay_evidence"] = any(
        e.get("kind") == "request" and e.get("resolved_state") != RESOLVED
        for e in evidence
    ) or not any(e.get("kind") == "request" for e in evidence)
    return view


def _query_impl(
    *,
    status: str | None,
    vuln_category: str | None,
    actor_ref: str | None,
    endpoint_id: str | None,
    origin: str | None,
    priority_bucket: str | None,
    pending_only: bool,
    limit: int,
) -> dict[str, Any]:
    bounded = max(1, min(limit or _QUERY_LIMIT_DEFAULT, _QUERY_LIMIT_MAX))
    want_status = (status or "").strip().lower() or None
    want_cat = (vuln_category or "").strip().lower() or None
    want_actor = (actor_ref or "").strip() or None
    want_endpoint = (endpoint_id or "").strip() or None
    want_origin = (origin or "").strip().lower() or None
    want_bucket = (priority_bucket or "").strip().upper() or None

    with _lock:
        entries = [dict(e) for e in _store.values()]

    matched = []
    for e in entries:
        if want_status and e.get("status") != want_status:
            continue
        if pending_only and e.get("status") not in PENDING_STATUSES:
            continue
        if want_cat and e.get("vuln_category") != want_cat:
            continue
        if want_actor and e.get("actor_ref") != want_actor:
            continue
        if want_endpoint and e.get("endpoint_id") != want_endpoint:
            continue
        if want_origin and want_origin not in str(e.get("origin", "")).lower():
            continue
        if want_bucket and e.get("priority", {}).get("bucket") != want_bucket:
            continue
        matched.append(e)

    matched.sort(key=lambda e: str(e.get("created_at", "")))
    page = matched[:bounded]
    status_counts: dict[str, int] = {}
    for e in entries:
        status_counts[str(e.get("status"))] = status_counts.get(str(e.get("status")), 0) + 1
    return {
        "success": True,
        "hypotheses": [_public_hypothesis(e) for e in page],
        "returned": len(page),
        "total_matched": len(matched),
        "total_hypotheses": len(entries),
        "status_counts": status_counts,
        "truncated": len(matched) > bounded,
    }


# --------------------------------------------------------------------------- #
# Agent tools
# --------------------------------------------------------------------------- #


def _caller_identity(ctx: RunContextWrapper) -> tuple[str | None, str | None]:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    raw_agent_id = inner.get("agent_id")
    agent_id = raw_agent_id if isinstance(raw_agent_id, str) else None
    agent_name: str | None = None
    coordinator = inner.get("coordinator")
    if agent_id is not None and coordinator is not None:
        names = getattr(coordinator, "names", {})
        if isinstance(names, dict):
            raw_name = names.get(agent_id)
            agent_name = raw_name if isinstance(raw_name, str) else None
    return agent_id, agent_name


def _resolver_for(ctx: RunContextWrapper) -> Any:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    override = inner.get("request_resolver")
    return override if callable(override) else _default_request_resolver


@function_tool(timeout=60)
async def create_hypothesis(
    ctx: RunContextWrapper,
    endpoint_id: str,
    vuln_category: str,
    resource: str = "",
    actor_ref: str = "anonymous",
    param_name: str = "",
    param_location: str = "",
    operation: str = "",
    rationale: str = "",
    next_action: str = "",
    request_ref: str = "",
    observation_ref: str = "",
    evidence_note: str = "",
    impact: str = "",
    evidence_strength: str = "",
    test_cost: str = "",
    priority_bucket: str = "",
) -> str:
    """Record a concrete, evidence-backed security hypothesis against a discovered endpoint.

    Use the attack-surface inventory (`query_attack_surface`) to pick the
    `endpoint_id`, concrete `resource`, and `actor_ref`, then state exactly what
    you think is wrong and why. A hypothesis is a *reasoned* claim — not "this
    parameter is named id so maybe IDOR". The `rationale` must say what observation
    or structural fact motivates it.

    Identity is `(endpoint_id, resource, actor_ref, param/operation, vuln_category)`:
    recreating the same tuple deduplicates (updates) rather than duplicating, but a
    different resource, actor, or parameter location is a DIFFERENT hypothesis and
    is kept separate.

    Attach evidence by reference only. A `request_ref` (a proxy/Caido request id)
    is replay-resolved before it is trusted; if it is missing/stale/unresolvable,
    that is recorded with a suggestion to capture or revalidate — nothing is
    fabricated. No request/response bodies are stored.

    Args:
        endpoint_id: Inventory endpoint id (from `query_attack_surface`).
        vuln_category: A vulnerability skill name (`idor`, `sql_injection`, `xss`,
            `broken_function_level_authorization`, ...).
        resource: The concrete object under test (e.g. `/orders/1`), if any.
        actor_ref: Actor context (`anonymous`, `actor-a`, ...).
        param_name / param_location: The parameter under test and where it lives
            (query/body/path/header/cookie). Use these OR `operation`.
        operation: The operation under test (e.g. `DELETE /orders/{id}`) when it
            is not a single parameter.
        rationale: Why this is plausibly vulnerable — the motivating observation
            or fact. Required in spirit; a bare name match is not a rationale.
        next_action: The specific next test/tool you intend.
        request_ref: A proxy request id to attach as replay evidence.
        observation_ref: A non-replayable observation reference (e.g. a recon note).
        evidence_note: A short note about the attached evidence (secret-redacted).
        impact / evidence_strength / test_cost: candidate-triage labels
            (high/medium/low) — see `analysis/candidate_triage.md`.
        priority_bucket: A triage bucket `P0`-`P3`.
    """
    agent_id, agent_name = _caller_identity(ctx)
    evidence = await _collect_evidence(
        request_ref=request_ref, observation_ref=observation_ref,
        evidence_note=evidence_note, resolver=_resolver_for(ctx),
    )
    result = await asyncio.to_thread(
        _create_impl,
        endpoint_id=endpoint_id, vuln_category=vuln_category, resource=resource,
        actor_ref=actor_ref, param_name=param_name, param_location=param_location,
        operation=operation, rationale=rationale, next_action=next_action,
        priority=_priority(impact, evidence_strength, test_cost, priority_bucket),
        evidence=evidence, agent_id=agent_id, agent_name=agent_name,
    )
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=60)
async def update_hypothesis(
    ctx: RunContextWrapper,
    hypothesis_id: str,
    status: str = "",
    next_action: str = "",
    rationale: str = "",
    add_counterevidence: str = "",
    confirmation: str = "",
    request_ref: str = "",
    observation_ref: str = "",
    evidence_note: str = "",
    impact: str = "",
    evidence_strength: str = "",
    test_cost: str = "",
    priority_bucket: str = "",
) -> str:
    """Update a hypothesis: status, next action, rationale, counterevidence, evidence, priority.

    Status is one of untested / testing / needs_validation / blocked / ruled_out /
    confirmed. **Confirming is deliberately hard**: set `status="confirmed"` only
    with a `confirmation` note describing the validated PoC, and only when at least
    one evidence reference is attached. A tool signal by itself is never enough —
    record those via `record_test_attempt` (which cannot set confirmed).

    Keep counterevidence attached: a negative control that failed to reproduce, a
    benign variant that behaved identically, or a guard you confirmed present all
    belong in `add_counterevidence` and stay visible on the hypothesis.

    Args:
        hypothesis_id: The id from `create_hypothesis`/`query_hypotheses`.
        status: New status (see above).
        next_action: Updated next test/tool.
        rationale: Updated rationale.
        add_counterevidence: A disconfirming observation to append (kept, never
            overwritten).
        confirmation: Required to set `confirmed` — the validated-PoC description.
        request_ref / observation_ref / evidence_note: More evidence to attach
            (request refs are replay-resolved).
        impact / evidence_strength / test_cost / priority_bucket: triage labels.
    """
    agent_id, agent_name = _caller_identity(ctx)
    new_evidence = await _collect_evidence(
        request_ref=request_ref, observation_ref=observation_ref,
        evidence_note=evidence_note, resolver=_resolver_for(ctx),
    )
    result = await asyncio.to_thread(
        _update_impl,
        hypothesis_id=hypothesis_id, status=status, next_action=next_action,
        rationale=rationale, add_counterevidence=add_counterevidence,
        confirmation=confirmation,
        priority=_priority(impact, evidence_strength, test_cost, priority_bucket),
        new_evidence=new_evidence, agent_id=agent_id, agent_name=agent_name,
    )
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=60)
async def record_test_attempt(
    ctx: RunContextWrapper,
    hypothesis_id: str,
    tool: str,
    tool_rationale: str,
    outcome: str,
    result_status: str,
    validation_required: str = "",
    signal: str = "",
    input_evidence_ref: str = "",
) -> str:
    """Record one test/tool attempt against a hypothesis and set its (non-confirmed) status.

    This is the tool-handoff record: WHICH tool you ran, WHY it fits the evidence,
    the input evidence it consumed, what happened, and what validation is still
    required. It can move the hypothesis to `testing`, `needs_validation`,
    `blocked`, or `ruled_out` — never `confirmed` (confirming is a separate,
    evidence-gated `update_hypothesis` call). A raw tool hit is `needs_validation`,
    not a finding.

    Do not run a tool merely because a parameter name resembles `id`/`search` —
    `tool_rationale` must tie the tool to the hypothesis's actual evidence.

    Args:
        hypothesis_id: The id from `query_hypotheses`.
        tool: The tool/technique used (`sqlmap`, `dalfox`, `manual`, `nuclei`, ...).
        tool_rationale: Why this tool is appropriate for this hypothesis/evidence.
        outcome: What the attempt produced (secret-redacted; no response bodies).
        result_status: `testing`, `needs_validation`, `blocked`, or `ruled_out`.
        validation_required: What still must be proven before this could be
            confirmed (e.g. "extract a real cross-user record", "reproduce with a
            second account").
        signal: A short categorical signal label if useful (e.g. `oracle`,
            `reflected`, `none`).
        input_evidence_ref: A proxy request id the attempt used (replay-resolved).
    """
    agent_id, agent_name = _caller_identity(ctx)
    input_evidence: dict[str, Any] | None = None
    if input_evidence_ref.strip():
        input_evidence = await _resolve_request_evidence(
            input_evidence_ref, _resolver_for(ctx), "attempt input"
        )
    result = await asyncio.to_thread(
        _record_attempt_impl,
        hypothesis_id=hypothesis_id, tool=tool, tool_rationale=tool_rationale,
        outcome=outcome, result_status=result_status,
        validation_required=validation_required, signal=signal,
        input_evidence=input_evidence, agent_id=agent_id, agent_name=agent_name,
    )
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def query_hypotheses(
    ctx: RunContextWrapper,
    status: str = "",
    vuln_category: str = "",
    actor_ref: str = "",
    endpoint_id: str = "",
    origin: str = "",
    priority_bucket: str = "",
    pending_only: bool = False,
    limit: int = _QUERY_LIMIT_DEFAULT,
) -> str:
    """Query the hypothesis worklist for actionable pending work (or any filter).

    The SQLi / XSS / authorization skills use this to pull the hypotheses that
    apply to them instead of re-deriving candidates. Output is bounded and carries
    each hypothesis's evidence (with replay-resolution state), counterevidence,
    attempt history, and triage priority.

    Use `pending_only=true` for the live worklist (untested / testing /
    needs_validation / blocked) — a blocked or inconclusive hypothesis stays here,
    visible as follow-up, which is why this is kept separate from the inventory's
    per-endpoint test bookkeeping and from scan completion.

    Args:
        status: Exact status filter.
        vuln_category: e.g. `sql_injection`, `xss`, `idor`.
        actor_ref: Only hypotheses in this actor's context.
        endpoint_id: Only hypotheses on this endpoint.
        origin: Case-insensitive origin substring.
        priority_bucket: `P0`-`P3`.
        pending_only: Only still-actionable hypotheses.
        limit: Max to return (capped at 500).
    """
    result = await asyncio.to_thread(
        _query_impl,
        status=status or None, vuln_category=vuln_category or None,
        actor_ref=actor_ref or None, endpoint_id=endpoint_id or None,
        origin=origin or None, priority_bucket=priority_bucket or None,
        pending_only=pending_only, limit=limit,
    )
    return json.dumps(result, ensure_ascii=False, default=str)
