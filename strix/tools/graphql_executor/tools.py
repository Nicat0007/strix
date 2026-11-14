"""Targeted GraphQL exposure executor (BLACKBOX improvement #15).

Explicitly invoked for ONE selected `graphql` hypothesis — never an automatic
scanner. It sends a small, bounded set of probes against a captured GraphQL
request and reports which schema-exposure / amplification features are enabled:

    hypothesis (worklist #3)
      -> RETRIEVE the stored GraphQL request through the proxy (NO traffic)
      -> validate origin+port+path against operator scope BEFORE any traffic
      -> PROBE (bounded, one attempt slot for the set):
         * introspection: a minimal __schema query — if it returns the schema,
           the full attack surface is disclosed
         * field suggestions: a deliberately-misspelled field — a "Did you mean"
           response leaks schema even when introspection is disabled
         * query batching: an array of queries — multiple results means batching
           is enabled (rate-limit / brute-force amplification)
      -> EXPOSED if any probe fires -> needs_validation (with which ones);
         HARDENED if none -> testing
      -> verdict + sanitized findings + record on the worklist.

Hard rules: detection only (it reads schema/feature state; it does not dump data,
run expensive nested queries, or brute-force through batching); a positive is
`needs_validation`, never `confirmed` — the agent escalates to object/field
authz (idor/bfla), DoS via nested queries, or batching-amplified brute-force and
proves real impact; scope checked before any traffic; budget via the shared
hypothesis attempt ledger; secrets never returned.

The retrieve and the probe send are injected so the orchestration / scope /
probe-building / exposure-classification logic is deterministically tested with
no network; the default send uses the proxy `replay_send_raw` (contract-based).
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.agent_metrics.tools import record_activity_tick
from strix.tools.attack_surface.tools import _redact_secrets
from strix.tools.hypotheses.tools import (
    DEFAULT_ATTEMPT_BUDGET,
    RESOLVED,
    RESOLVED_MISSING,
    RESOLVED_STALE,
    SLOT_COMPLETED,
    SLOT_FAILED,
    STATUS_BLOCKED,
    STATUS_NEEDS_VALIDATION,
    STATUS_TESTING,
    _record_attempt_impl,
    lookup_hypothesis,
    mark_dispatched,
    reserve_attempt,
    settle_attempt,
)
from strix.tools.oob_executor.tools import _inject_value, _scope_check, _strip_scheme
from strix.tools.open_redirect_executor.tools import _send_and_capture


logger = logging.getLogger(__name__)

_CATEGORY = "graphql"
_MAX_ATTEMPTS = DEFAULT_ATTEMPT_BUDGET
_SEND_TIMEOUT_S = 30.0
_BODY_SCAN_CAP = 200_000

VERDICT_EXPOSED = "graphql_exposed"
VERDICT_HARDENED = "hardened_this_run"
VERDICT_BLOCKED = "blocked"
VERDICT_CANCELLED = "cancelled"

_INTROSPECTION_QUERY = (
    "query{__schema{queryType{name} types{name kind}}}"
)


def _clean(value: str | None) -> str:
    return _redact_secrets((value or "").strip())


def _probe_bodies(token: str) -> dict[str, str]:
    """The three probe bodies. The suggestion probe's bogus field carries the
    token so a reflected suggestion is attributable to this attempt."""
    bogus = f"zzz_{token}"
    return {
        "introspection": json.dumps({"query": _INTROSPECTION_QUERY}),
        "suggestions": json.dumps({"query": "query{__typename " + bogus + "}"}),
        "batching": json.dumps([{"query": "{__typename}"}, {"query": "{__typename}"}]),
    }


def _introspection_enabled(body: str) -> bool:
    low = (body or "")[:_BODY_SCAN_CAP]
    return '"__schema"' in low or ('"queryType"' in low and '"types"' in low)


def _suggestions_enabled(body: str) -> bool:
    return "did you mean" in (body or "")[:_BODY_SCAN_CAP].lower()


def _batching_enabled(body: str) -> bool:
    text = (body or "").strip()[:_BODY_SCAN_CAP]
    if not text.startswith("["):
        return False
    try:
        arr = json.loads(text)
    except json.JSONDecodeError:
        return False
    return isinstance(arr, list) and len(arr) >= 2


_PROBE_CHECKS = {
    "introspection": _introspection_enabled,
    "suggestions": _suggestions_enabled,
    "batching": _batching_enabled,
}


async def _retrieve_request(request_id: str) -> dict[str, Any] | None:
    from strix.tools.proxy import caido_api  # noqa: PLC0415

    result = await caido_api.view_request(request_id, part="request")
    if result is None or getattr(result.request, "raw", None) is None:
        return None
    raw = result.request.raw.decode("utf-8", errors="replace")
    components = caido_api.parse_raw_request(raw)
    url = caido_api.full_url_from_components(result.request, components, {})
    return {"found": True, "raw": raw, "url": url,
            "method": str(components.get("method", "POST"))}


def _record(
    *, hypothesis_id: str, result_status: str, verdict: str, rationale: str,
    outcome: str, validation_required: str, input_evidence: dict[str, Any] | None,
    agent_id: str | None, agent_name: str | None,
) -> None:
    _record_attempt_impl(
        hypothesis_id=hypothesis_id, tool="graphql_probe", tool_rationale=rationale,
        outcome=outcome, result_status=result_status, validation_required=validation_required,
        signal=verdict, input_evidence=input_evidence, agent_id=agent_id, agent_name=agent_name,
    )


def _validation_for(verdict: str, enabled: list[str]) -> str:
    if verdict == VERDICT_EXPOSED:
        return (f"GraphQL exposes {enabled} — attack-surface/amplification, not yet a "
                "vulnerability: use introspection/suggestions to map objects+fields then test "
                "object/field authorization (idor.md/bfla.md); use batching to amplify a "
                "brute-force or bypass a per-request rate limit; prove impact before confirming")
    return ("not closed: introspection/suggestions/batching were not observed this run — the "
            "schema may still be reachable via a known/leaked query, persisted queries, or a "
            "different endpoint; object/field authz is testable without introspection too")


async def _run_graphql_impl(
    transport: Any,  # the sandbox session (unused: this executor works through the proxy)
    *,
    hypothesis_id: str,
    request_ref: str,
    retrieve: Any = None,
    send: Any = None,
    caido_client: Any = None,
    scan_targets: list[str] | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    hid = (hypothesis_id or "").strip()
    ref = (request_ref or "").strip()

    hypothesis = lookup_hypothesis(hid)
    if hypothesis is None:
        return {"success": False, "error": f"no hypothesis {hypothesis_id!r} (create it first)"}
    if hypothesis.get("vuln_category") != _CATEGORY:
        return {"success": False, "error": f"hypothesis {hid} is not '{_CATEGORY}'"}
    if not ref:
        return {"success": False, "error": "request_ref is required (a stored GraphQL request)"}

    token = f"gq{uuid.uuid4().hex[:10]}"
    intended_actor = str(hypothesis.get("actor_ref") or "anonymous")
    rationale = (f"targeted GraphQL exposure probe (introspection + field-suggestion + batching); "
                 f"intended_actor={intended_actor}")

    def _blocked(outcome: str, validation: str, resolved: str,
                 extra: dict[str, Any] | None = None) -> dict[str, Any]:
        ev = {"kind": "request", "ref": ref[:256], "resolved_state": resolved}
        _record(hypothesis_id=hid, result_status=STATUS_BLOCKED, verdict=VERDICT_BLOCKED,
                rationale=rationale, outcome=outcome, validation_required=validation,
                input_evidence=ev, agent_id=agent_id, agent_name=agent_name)
        out = {"success": True, "hypothesis_id": hid, "ran": False,
               "result_status": STATUS_BLOCKED, "intended_actor": intended_actor,
               "outcome": outcome, "suggestion": validation}
        if extra:
            out.update(extra)
        return out

    retrieve_fn = retrieve or _retrieve_request
    send_fn = send or _send_and_capture

    try:
        got = await retrieve_fn(_strip_scheme(ref))
    except Exception:  # noqa: BLE001
        return _blocked("proxy unavailable; could not retrieve the stored request",
                        "capture the GraphQL request and attach its id, then retry",
                        RESOLVED_MISSING)
    if not got or not got.get("found") or not got.get("raw"):
        return _blocked("stored request not found for this reference",
                        "capture the GraphQL request and attach its id, then retry",
                        RESOLVED_MISSING)
    raw = str(got["raw"])
    url = str(got.get("url") or "")

    in_scope, scope_reason = _scope_check(url, scan_targets)
    if not in_scope:
        return _blocked(f"destination not in operator scope: {scope_reason}; not testing",
                        "confirm the target (host/port/path) is authorized with the operator",
                        RESOLVED, {"in_scope": False})

    probes = _probe_bodies(token)
    reservation = reserve_attempt(hid, tool="graphql_probe", max_attempts=_MAX_ATTEMPTS)
    if not reservation.get("reserved"):
        return _blocked(
            f"attempt budget exhausted for this hypothesis "
            f"({reservation.get('used')}/{reservation.get('max')} used this run)",
            "do not auto-retry; escalate to manual review or deliberately raise the budget",
            RESOLVED,
            {"attempt_budget": {"used": reservation.get("used"), "max": reservation.get("max"),
                                "remaining": 0}})
    rid = str(reservation["reservation_id"])
    input_evidence = {"kind": "request", "ref": ref[:256], "resolved_state": RESOLVED,
                      "summary": f"{got.get('method', '?')} GraphQL x{len(probes)} probes"}

    mark_dispatched(hid, rid)
    enabled: list[str] = []
    sent_any = False
    try:
        for name, body in probes.items():
            mutated = _inject_value(raw, "", "body_raw", body)
            if mutated is None:
                continue
            try:
                resp = await asyncio.wait_for(
                    send_fn(caido_client, mutated_raw=mutated, url=url), timeout=_SEND_TIMEOUT_S
                )
            except Exception:  # noqa: BLE001
                resp = {"sent": False}
            if not resp.get("sent"):
                continue
            sent_any = True
            if _PROBE_CHECKS[name](resp.get("body") or ""):
                enabled.append(name)
    except asyncio.CancelledError:
        settle_attempt(hid, rid, state=SLOT_FAILED)
        _record(hypothesis_id=hid, result_status=STATUS_BLOCKED, verdict=VERDICT_CANCELLED,
                rationale=rationale,
                outcome="graphql probe cancelled after dispatch; attempt consumed",
                validation_required="re-run the targeted probe", input_evidence=input_evidence,
                agent_id=agent_id, agent_name=agent_name)
        raise

    if not sent_any:
        settle_attempt(hid, rid, state=SLOT_FAILED)
        return _blocked("no probe could be sent (target unreachable or replay failed) — not a "
                        "GraphQL result", "re-verify connectivity/session and retry",
                        RESOLVED_STALE)

    verdict = VERDICT_EXPOSED if enabled else VERDICT_HARDENED
    result_status = STATUS_NEEDS_VALIDATION if enabled else STATUS_TESTING
    validation = _validation_for(verdict, enabled)
    outcome = _clean(f"graphql probe verdict={verdict}"
                     + (f"; enabled={enabled}" if enabled else ""))
    settle = settle_attempt(hid, rid, state=SLOT_COMPLETED)
    _record(hypothesis_id=hid, result_status=result_status, verdict=verdict, rationale=rationale,
            outcome=outcome, validation_required=validation, input_evidence=input_evidence,
            agent_id=agent_id, agent_name=agent_name)
    record_activity_tick(agent_id)

    return {
        "success": True, "hypothesis_id": hid, "ran": True, "in_scope": True,
        "intended_actor": intended_actor, "result_status": result_status, "verdict": verdict,
        "enabled_features": enabled,
        "attempt_budget": {"used": settle.get("used"), "max": settle.get("max"),
                           "remaining": settle.get("remaining")},
        "note": "detection only; exposed introspection/suggestions/batching is needs_validation "
                "(attack-surface/amplification), never confirmed — escalate to object/field "
                "authz, nested-query DoS, or batching-amplified brute-force and prove impact. "
                "Hardened is testing, not ruled_out (object/field authz is testable without it).",
    }


def _caller_identity(ctx: RunContextWrapper) -> dict[str, Any]:
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
    retrieve = inner.get("graphql_retrieve")
    send = inner.get("graphql_send")
    return {
        "agent_id": agent_id, "agent_name": agent_name,
        "retrieve": retrieve if callable(retrieve) else None,
        "send": send if callable(send) else None,
        "scan_targets": inner.get("scan_targets"),
        "caido_client": inner.get("caido_client"),
        "session": inner.get("sandbox_session"),
    }


@function_tool(timeout=120)
async def run_graphql_test(
    ctx: RunContextWrapper,
    hypothesis_id: str,
    request_ref: str,
) -> str:
    """Probe ONE GraphQL hypothesis for introspection / field-suggestion / batching exposure.

    Explicitly invoked for a single `graphql` hypothesis — NOT an automatic
    scanner. It retrieves the hypothesis's stored GraphQL request through the proxy
    (no traffic), validates scope BEFORE sending, then sends three bounded probes:
    a minimal `__schema` introspection query, a deliberately-misspelled field (to
    catch "Did you mean" suggestion leakage even when introspection is off), and a
    two-query batch (to detect query batching). It reports which are enabled.

    Any enabled feature is `needs_validation` (attack-surface / amplification),
    never `confirmed`: escalate to object/field authorization (idor/bfla), nested-
    query DoS, or batching-amplified brute-force and prove real impact. None
    enabled is `testing`, never `ruled_out` (object/field authz is testable without
    introspection). The attempt is recorded on the worklist automatically.

    Args:
        hypothesis_id: A `graphql` hypothesis id from `query_hypotheses`.
        request_ref: The stored GraphQL POST request to probe.
    """
    ident = _caller_identity(ctx)
    if ident["session"] is None:
        return json.dumps({"success": False, "error": "no sandbox session available"})
    result = await _run_graphql_impl(
        ident["session"], hypothesis_id=hypothesis_id, request_ref=request_ref,
        retrieve=ident["retrieve"], send=ident["send"], caido_client=ident["caido_client"],
        scan_targets=ident["scan_targets"], agent_id=ident["agent_id"],
        agent_name=ident["agent_name"],
    )
    return json.dumps(result, ensure_ascii=False, default=str)
