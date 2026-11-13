"""Targeted race-condition executor (BLACKBOX improvement #11).

Explicitly invoked for ONE selected `race_conditions` hypothesis — never an
automatic scanner. It fires a bounded number of copies of the hypothesis's stored
request as concurrently as the transport allows and reports how many SUCCEEDED —
the signal for a TOCTOU / limit-overrun race (double-spend, one-time-coupon
reuse, balance or quantity overrun, concurrent-redemption):

    hypothesis (worklist #3)
      -> RETRIEVE the stored request through the proxy (NO traffic)
      -> validate origin+port+path against operator scope BEFORE any traffic
      -> fire `concurrency` identical copies via asyncio.gather (launched together)
      -> classify: >=2 successes = a race is suspected (the operation the agent
         asserts is once-only succeeded more than once); exactly 1 = the control
         appears to hold; 0 = inconclusive
      -> verdict + sanitized success/outcome counts + record on the worklist.

Hard rules: a positive is `needs_validation`, never `confirmed` — the agent must
assert (in the hypothesis) that the operation is meant to be once-only/idempotent
and then prove the real effect (e.g. two coupon redemptions, a balance that went
negative); scope checked before any traffic; bounded concurrency; budget via the
shared hypothesis attempt ledger; secrets never returned.

Limitation stated honestly: this is high-concurrency PARALLEL send (asyncio.gather
over the proxy), NOT a true single-packet / last-byte-sync attack. It catches the
common app-layer races; for a very tight window use Turbo Intruder's single-packet
mode by hand. Because it sends `concurrency` STATE-CHANGING requests, the agent
must pick a safe, reversible operation / disposable test object and have operator
authorization — the executor fires exactly the request it was given and never
escalates.

The retrieve and the concurrent send are injected so the orchestration / scope /
concurrency / success-classification logic is deterministically tested with no
network; the default send uses the proxy's `replay_send_raw` (contract-based).
"""

from __future__ import annotations

import asyncio
import json
import logging
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
from strix.tools.oob_executor.tools import _scope_check, _strip_scheme
from strix.tools.open_redirect_executor.tools import _send_and_capture


logger = logging.getLogger(__name__)

_CATEGORY = "race_conditions"
_MAX_ATTEMPTS = DEFAULT_ATTEMPT_BUDGET
_SEND_TIMEOUT_S = 30.0

# Bounds — clamped, never trusted from the caller.
_DEFAULT_CONCURRENCY = 15
_MAX_CONCURRENCY = 30
_BODY_SCAN_CAP = 8192
_DIAG_MAX = 40

VERDICT_RACE_SUSPECTED = "race_suspected"
VERDICT_NO_RACE = "no_race_this_run"
VERDICT_INCONCLUSIVE = "inconclusive"
VERDICT_BLOCKED = "blocked"
VERDICT_CANCELLED = "cancelled"


def _clean(value: str | None) -> str:
    return _redact_secrets((value or "").strip())


def _is_success(
    resp: dict[str, Any], success_statuses: frozenset[int], markers: list[str], anti: list[str]
) -> bool:
    """A response counts as a successful completion of the operation under race.
    Default: a 2xx with no failure marker; narrowed by agent-supplied success
    markers / anti-markers when given."""
    if not resp.get("sent"):
        return False
    status = resp.get("status")
    blob = ((resp.get("body") or "")[:_BODY_SCAN_CAP]).lower()
    if any(a.lower() in blob for a in anti):
        return False
    if markers:
        return any(m.lower() in blob for m in markers)
    return isinstance(status, int) and 200 <= status < 300


def _retrieve_default() -> Any:
    async def _retrieve_request(request_id: str) -> dict[str, Any] | None:
        from strix.tools.proxy import caido_api  # noqa: PLC0415

        result = await caido_api.view_request(request_id, part="request")
        if result is None or getattr(result.request, "raw", None) is None:
            return None
        raw = result.request.raw.decode("utf-8", errors="replace")
        components = caido_api.parse_raw_request(raw)
        url = caido_api.full_url_from_components(result.request, components, {})
        return {"found": True, "raw": raw, "url": url,
                "method": str(components.get("method", "GET"))}
    return _retrieve_request


def _record(
    *, hypothesis_id: str, result_status: str, verdict: str, rationale: str,
    outcome: str, validation_required: str, input_evidence: dict[str, Any] | None,
    agent_id: str | None, agent_name: str | None,
) -> None:
    _record_attempt_impl(
        hypothesis_id=hypothesis_id, tool="race_probe", tool_rationale=rationale,
        outcome=outcome, result_status=result_status, validation_required=validation_required,
        signal=verdict, input_evidence=input_evidence, agent_id=agent_id, agent_name=agent_name,
    )


def _validation_for(verdict: str, successes: int) -> str:
    if verdict == VERDICT_RACE_SUSPECTED:
        return (f"{successes} of the concurrent requests succeeded; if this operation is meant "
                "to succeed only once (one-time coupon, single withdrawal, single redemption), "
                "that is a race — prove the real, durable effect (two redemptions applied, a "
                "balance driven negative, quantity overrun) before confirming. Multiple 2xx is "
                "needs_validation, and confirm the app truly treated each as a committed operation")
    if verdict == VERDICT_NO_RACE:
        return ("exactly one concurrent request succeeded — the once-only control appears to hold "
                "for this operation. Not ruled out for the class: try a tighter window (Turbo "
                "Intruder single-packet), a different step, or a different invariant")
    return ("inconclusive: no request clearly succeeded — re-check the success markers, the "
            "session/baseline, and that the captured request is a valid state-changing operation")


async def _run_race_impl(
    transport: Any,  # the sandbox session (unused: this executor works through the proxy)
    *,
    hypothesis_id: str,
    request_ref: str,
    concurrency: int | None = None,
    success_markers: list[str] | None = None,
    failure_markers: list[str] | None = None,
    retrieve: Any = None,
    send: Any = None,
    caido_client: Any = None,
    scan_targets: list[str] | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    hid = (hypothesis_id or "").strip()
    ref = (request_ref or "").strip()
    m = max(2, min(int(concurrency or _DEFAULT_CONCURRENCY), _MAX_CONCURRENCY))
    markers = [s for s in (success_markers or []) if isinstance(s, str) and s.strip()][:20]
    anti = [s for s in (failure_markers or []) if isinstance(s, str) and s.strip()][:20]

    hypothesis = lookup_hypothesis(hid)
    if hypothesis is None:
        return {"success": False, "error": f"no hypothesis {hypothesis_id!r} (create it first)"}
    if hypothesis.get("vuln_category") != _CATEGORY:
        return {"success": False, "error": f"hypothesis {hid} is not '{_CATEGORY}'"}
    if not ref:
        return {"success": False, "error": "request_ref is required (a stored proxy request id)"}

    intended_actor = str(hypothesis.get("actor_ref") or "anonymous")
    rationale = (
        f"targeted race probe: {m} concurrent copies of the stored state-changing request fired "
        f"together; success counted by {'markers' if markers else '2xx'}; "
        f"intended_actor={intended_actor}"
    )

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

    retrieve_fn = retrieve or _retrieve_default()
    send_fn = send or _send_and_capture

    try:
        got = await retrieve_fn(_strip_scheme(ref))
    except Exception:  # noqa: BLE001
        return _blocked("proxy unavailable; could not retrieve the stored request",
                        "capture the request in the proxy and attach its id, then retry",
                        RESOLVED_MISSING)
    if not got or not got.get("found") or not got.get("raw"):
        return _blocked("stored request not found for this reference",
                        "capture the request in the proxy and attach its id, then retry",
                        RESOLVED_MISSING)
    raw = str(got["raw"])
    url = str(got.get("url") or "")

    in_scope, scope_reason = _scope_check(url, scan_targets)
    if not in_scope:
        return _blocked(f"destination not in operator scope: {scope_reason}; not testing",
                        "confirm the target (host/port/path) is authorized with the operator",
                        RESOLVED, {"in_scope": False})

    reservation = reserve_attempt(hid, tool="race_probe", max_attempts=_MAX_ATTEMPTS)
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
                      "summary": f"{got.get('method', '?')} x{m} concurrent"}

    async def _one() -> dict[str, Any]:
        try:
            return await asyncio.wait_for(
                send_fn(caido_client, mutated_raw=raw, url=url), timeout=_SEND_TIMEOUT_S
            )
        except Exception:  # noqa: BLE001
            return {"sent": False}

    mark_dispatched(hid, rid)
    try:
        responses = await asyncio.gather(*[_one() for _ in range(m)])
    except asyncio.CancelledError:
        settle_attempt(hid, rid, state=SLOT_FAILED)
        _record(hypothesis_id=hid, result_status=STATUS_BLOCKED, verdict=VERDICT_CANCELLED,
                rationale=rationale,
                outcome="race probe cancelled after dispatch; attempt consumed",
                validation_required="re-run the targeted probe", input_evidence=input_evidence,
                agent_id=agent_id, agent_name=agent_name)
        raise

    sent = sum(1 for r in responses if r.get("sent"))
    if sent == 0:
        settle_attempt(hid, rid, state=SLOT_FAILED)
        return _blocked("no request could be sent (target unreachable or replay failed) — not a "
                        "race result", "re-verify connectivity/session and retry", RESOLVED_STALE)
    success_statuses = frozenset(range(200, 300))
    successes = sum(1 for r in responses if _is_success(r, success_statuses, markers, anti))
    statuses: dict[str, int] = {}
    for r in responses:
        key = str(r.get("status")) if r.get("sent") else "no_send"
        statuses[key] = statuses.get(key, 0) + 1

    if successes >= 2:
        verdict, result_status = VERDICT_RACE_SUSPECTED, STATUS_NEEDS_VALIDATION
    elif successes == 1:
        verdict, result_status = VERDICT_NO_RACE, STATUS_TESTING
    else:
        verdict, result_status = VERDICT_INCONCLUSIVE, STATUS_TESTING

    validation = _validation_for(verdict, successes)
    outcome = _clean(f"race probe verdict={verdict}; fired={m} sent={sent} successes={successes}; "
                     f"status_distribution={statuses}")
    settle = settle_attempt(hid, rid, state=SLOT_COMPLETED)
    _record(hypothesis_id=hid, result_status=result_status, verdict=verdict, rationale=rationale,
            outcome=outcome, validation_required=validation, input_evidence=input_evidence,
            agent_id=agent_id, agent_name=agent_name)
    record_activity_tick(agent_id)

    return {
        "success": True, "hypothesis_id": hid, "ran": True, "in_scope": True,
        "intended_actor": intended_actor, "fired": m, "sent": sent, "successes": successes,
        "status_distribution": dict(list(statuses.items())[:_DIAG_MAX]),
        "result_status": result_status, "verdict": verdict,
        "attempt_budget": {"used": settle.get("used"), "max": settle.get("max"),
                           "remaining": settle.get("remaining")},
        "note": "high-concurrency parallel send, NOT a true single-packet attack; >=2 concurrent "
                "successes is needs_validation (prove the operation is once-only and the effect is "
                "durable), never confirmed. Exactly one success is testing, not ruled_out.",
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
    retrieve = inner.get("race_retrieve")
    send = inner.get("race_send")
    return {
        "agent_id": agent_id, "agent_name": agent_name,
        "retrieve": retrieve if callable(retrieve) else None,
        "send": send if callable(send) else None,
        "scan_targets": inner.get("scan_targets"),
        "caido_client": inner.get("caido_client"),
        "session": inner.get("sandbox_session"),
    }


@function_tool(timeout=120)
async def run_race_test(
    ctx: RunContextWrapper,
    hypothesis_id: str,
    request_ref: str,
    concurrency: int | None = None,
    success_markers: list[str] | None = None,
    failure_markers: list[str] | None = None,
) -> str:
    """Test ONE race-condition hypothesis by firing concurrent copies of a request.

    Explicitly invoked for a single `race_conditions` hypothesis — NOT an automatic
    scanner. It retrieves the hypothesis's stored request through the proxy (no
    traffic), validates scope BEFORE sending, then fires `concurrency` identical
    copies as concurrently as the transport allows and counts how many succeeded.
    >=2 successes on an operation the hypothesis asserts is once-only (one-time
    coupon, single withdrawal/redemption, balance/quantity limit) is a race lead.

    This is high-concurrency PARALLEL send, not a true single-packet attack — it
    catches common app-layer races; for a very tight window use Turbo Intruder's
    single-packet mode by hand. It sends `concurrency` STATE-CHANGING requests, so
    choose a safe, reversible operation / disposable test object and ensure
    operator authorization. A race is `needs_validation`, never `confirmed`: prove
    the durable effect (two redemptions, a negative balance). Exactly one success
    is `testing`, never `ruled_out`. The attempt is recorded automatically.

    Args:
        hypothesis_id: A `race_conditions` hypothesis id from `query_hypotheses`.
        request_ref: The stored proxy request id to fire concurrently.
        concurrency: How many copies to fire together (default 15, capped 30).
        success_markers: Body strings that mark a successful operation (e.g.
            "coupon applied", "order confirmed"). Default success = any 2xx.
        failure_markers: Body strings that mark a rejected/duplicate operation
            (e.g. "already used") — a response matching one is NOT counted a success.
    """
    ident = _caller_identity(ctx)
    if ident["session"] is None:
        return json.dumps({"success": False, "error": "no sandbox session available"})
    result = await _run_race_impl(
        ident["session"], hypothesis_id=hypothesis_id, request_ref=request_ref,
        concurrency=concurrency, success_markers=success_markers, failure_markers=failure_markers,
        retrieve=ident["retrieve"], send=ident["send"], caido_client=ident["caido_client"],
        scan_targets=ident["scan_targets"], agent_id=ident["agent_id"],
        agent_name=ident["agent_name"],
    )
    return json.dumps(result, ensure_ascii=False, default=str)
