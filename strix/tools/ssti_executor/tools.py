"""Targeted server-side template injection (SSTI) executor (BLACKBOX #9).

Explicitly invoked for ONE selected `ssti` hypothesis — never an automatic
scanner. It injects, in a single request, a set of arithmetic polyglots (one per
common template engine), each carrying a DISTINCT product, replays once, and
classifies by whether a product actually appears in the response while its
literal expression does not — the difference between real server-side evaluation
and mere reflection (which is an XSS lead, not SSTI):

    hypothesis (worklist #3)
      -> RETRIEVE the stored request through the proxy (NO traffic)
      -> validate origin+port+path against operator scope BEFORE any traffic
      -> inject per-engine arithmetic polyglots (distinct large products) at ONE
         named location
      -> replay ONCE and capture the response
      -> EVALUATED: a product appears AND its literal expression does not (maps to
         the engine) ; REFLECTED_ONLY: the literal expression echoes back (an XSS
         lead, not SSTI) ; NO_EVAL: neither
      -> verdict + engine(s) + sanitized evidence + record on the worklist.

Hard rules: detection only (arithmetic probe, never an RCE/read gadget — the
agent escalates a confirmed engine to RCE separately); a positive is
`needs_validation`, never `confirmed`; a negative applies only to the tested
parameter/location, never the class; scope checked before any traffic; budget
via the shared hypothesis attempt ledger; secrets never returned.

The request retrieve and single send+capture are injected so the orchestration /
scope / injection / evaluation-vs-reflection logic is deterministically tested
with no network; the default send uses the proxy's `replay_send_raw`
(contract-based, verify live).
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
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

_CATEGORY = "ssti"
_VALID_LOCATIONS = ("query", "body", "cookie", "header")
_MAX_ATTEMPTS = DEFAULT_ATTEMPT_BUDGET
_SEND_TIMEOUT_S = 40.0
_BODY_SCAN_CAP = 200_000
_DIAG_MAX = 40

VERDICT_EVALUATED = "template_evaluated"
VERDICT_REFLECTED_ONLY = "reflected_not_evaluated"
VERDICT_NO_EVAL = "no_evaluation_this_run"
VERDICT_BLOCKED = "blocked"
VERDICT_CANCELLED = "cancelled"

#: (engine, how to wrap `a*b`). Each engine evaluates only its own syntax, so all
#: can be injected together; a distinct product per engine maps a hit back to it.
_ENGINES: tuple[tuple[str, str], ...] = (
    ("jinja2/twig", "{{%d*%d}}"),
    ("freemarker/el/spel", "${%d*%d}"),
    ("erb/ruby", "<%%= %d*%d %%>"),
    ("smarty", "{%d*%d}"),
    ("razor", "@(%d*%d)"),
)


def _clean(value: str | None) -> str:
    return _redact_secrets((value or "").strip())


def _build_probes() -> list[dict[str, Any]]:
    """One probe per engine with a DISTINCT, large, non-round product so a hit is
    not a coincidental page number. Returns [{engine, expr, product}]."""
    probes: list[dict[str, Any]] = []
    used: set[int] = set()
    for engine, wrap in _ENGINES:
        while True:
            a = secrets.randbelow(900) + 100          # 100..999
            b = secrets.randbelow(9000) + 1000         # 1000..9999
            product = a * b
            if product not in used:
                used.add(product)
                break
        probes.append({"engine": engine, "expr": wrap % (a, b), "product": str(product)})
    return probes


def _probe_payload(probes: list[dict[str, Any]]) -> str:
    # A separator keeps each engine's expression lexically distinct in the body so
    # reflection can be detected per-engine; engines ignore each other's syntax.
    return "zx".join(p["expr"] for p in probes)


def _classify(body: str, probes: list[dict[str, Any]]) -> tuple[str, list[str], list[str]]:
    """(verdict, evaluated_engines, reflected_engines). EVALUATED needs the product
    present AND the literal expression absent (real server-side math, not echo)."""
    snippet = (body or "")[:_BODY_SCAN_CAP]
    evaluated: list[str] = []
    reflected: list[str] = []
    for p in probes:
        if p["expr"] in snippet:
            reflected.append(p["engine"])
        elif p["product"] in snippet:
            evaluated.append(p["engine"])
    if evaluated:
        return VERDICT_EVALUATED, evaluated, reflected
    if reflected:
        return VERDICT_REFLECTED_ONLY, evaluated, reflected
    return VERDICT_NO_EVAL, evaluated, reflected


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


def _record(
    *, hypothesis_id: str, result_status: str, verdict: str, rationale: str,
    outcome: str, validation_required: str, input_evidence: dict[str, Any] | None,
    agent_id: str | None, agent_name: str | None,
) -> None:
    _record_attempt_impl(
        hypothesis_id=hypothesis_id, tool="ssti_probe", tool_rationale=rationale,
        outcome=outcome, result_status=result_status, validation_required=validation_required,
        signal=verdict, input_evidence=input_evidence, agent_id=agent_id, agent_name=agent_name,
    )


def _validation_for(verdict: str, engines: list[str]) -> str:
    if verdict == VERDICT_EVALUATED:
        return (f"server-side template evaluation confirmed for engine(s) {engines}; escalate "
                "deliberately and safely to the engine's RCE/read gadget (sandbox-aware) and prove "
                "real impact before confirming — an arithmetic probe is needs_validation, not RCE")
    if verdict == VERDICT_REFLECTED_ONLY:
        return ("the expression reflected but did NOT evaluate — this is input reflection, not "
                "SSTI. Re-route to xss.md (reflected-XSS lead); it does not confirm SSTI")
    return ("not closed: no evaluation for THIS parameter/location does not rule out the class — "
            "try other contexts, encodings, or an engine not covered by the default polyglots")


async def _run_ssti_impl(
    transport: Any,  # the sandbox session (unused: this executor works through the proxy)
    *,
    hypothesis_id: str,
    request_ref: str,
    param_name: str,
    injection_location: str = "query",
    retrieve: Any = None,
    send: Any = None,
    probes: list[dict[str, Any]] | None = None,
    caido_client: Any = None,
    scan_targets: list[str] | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    hid = (hypothesis_id or "").strip()
    ref = (request_ref or "").strip()
    param = (param_name or "").strip()
    location = (injection_location or "query").strip().lower()

    hypothesis = lookup_hypothesis(hid)
    if hypothesis is None:
        return {"success": False, "error": f"no hypothesis {hypothesis_id!r} (create it first)"}
    if hypothesis.get("vuln_category") != _CATEGORY:
        return {"success": False, "error": f"hypothesis {hid} is not '{_CATEGORY}'"}
    if not ref:
        return {"success": False, "error": "request_ref is required (a stored proxy request id)"}
    if location not in _VALID_LOCATIONS:
        return {"success": False, "error": f"injection_location must be one of {_VALID_LOCATIONS}"}
    if not param:
        return {"success": False, "error": "param_name is required"}

    probe_set = probes or _build_probes()
    intended_actor = str(hypothesis.get("actor_ref") or "anonymous")
    rationale = (
        f"targeted SSTI arithmetic polyglot probe (distinct product per engine) injected at "
        f"{location} param {param!r}; intended_actor={intended_actor}"
    )

    def _blocked(outcome: str, validation: str, resolved: str,
                 extra: dict[str, Any] | None = None) -> dict[str, Any]:
        ev = {"kind": "request", "ref": ref[:256], "resolved_state": resolved}
        _record(hypothesis_id=hid, result_status=STATUS_BLOCKED, verdict=VERDICT_BLOCKED,
                rationale=rationale, outcome=outcome, validation_required=validation,
                input_evidence=ev, agent_id=agent_id, agent_name=agent_name)
        out = {"success": True, "hypothesis_id": hid, "ran": False,
               "result_status": STATUS_BLOCKED, "injection_location": location,
               "intended_actor": intended_actor, "outcome": outcome, "suggestion": validation}
        if extra:
            out.update(extra)
        return out

    retrieve_fn = retrieve or _retrieve_request
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

    mutated = _inject_value(raw, param, location, _probe_payload(probe_set))
    if mutated is None:
        return _blocked(
            f"parameter {param!r} not found in location {location!r}, or the location is ambiguous",
            "re-check the parameter's actual location, or capture a request that carries it",
            RESOLVED)

    reservation = reserve_attempt(hid, tool="ssti_probe", max_attempts=_MAX_ATTEMPTS)
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
                      "summary": f"{got.get('method', '?')} injected at {location}"}

    mark_dispatched(hid, rid)
    try:
        try:
            resp = await asyncio.wait_for(
                send_fn(caido_client, mutated_raw=mutated, url=url), timeout=_SEND_TIMEOUT_S
            )
        except Exception:  # noqa: BLE001
            resp = {"sent": False}
    except asyncio.CancelledError:
        settle_attempt(hid, rid, state=SLOT_FAILED)
        _record(hypothesis_id=hid, result_status=STATUS_BLOCKED, verdict=VERDICT_CANCELLED,
                rationale=rationale,
                outcome="SSTI probe cancelled after dispatch; attempt consumed",
                validation_required="re-run the targeted probe", input_evidence=input_evidence,
                agent_id=agent_id, agent_name=agent_name)
        raise

    if not resp.get("sent"):
        settle_attempt(hid, rid, state=SLOT_FAILED)
        return _blocked("the injected request could not be sent (target unreachable or replay "
                        "failed) — not an SSTI result",
                        "re-verify connectivity/session and retry", RESOLVED_STALE)

    verdict, evaluated, reflected = _classify(resp.get("body") or "", probe_set)
    result_status = STATUS_NEEDS_VALIDATION if verdict == VERDICT_EVALUATED else STATUS_TESTING
    validation = _validation_for(verdict, evaluated)
    outcome = _clean(f"SSTI probe verdict={verdict}"
                     + (f"; engines={evaluated}" if evaluated else "")
                     + (f"; reflected={reflected}" if reflected else ""))
    settle = settle_attempt(hid, rid, state=SLOT_COMPLETED)
    _record(hypothesis_id=hid, result_status=result_status, verdict=verdict, rationale=rationale,
            outcome=outcome, validation_required=validation, input_evidence=input_evidence,
            agent_id=agent_id, agent_name=agent_name)
    record_activity_tick(agent_id)

    return {
        "success": True, "hypothesis_id": hid, "ran": True, "in_scope": True,
        "injection_location": location, "intended_actor": intended_actor,
        "response_status": resp.get("status"),
        "result_status": result_status, "verdict": verdict,
        "evaluated_engines": evaluated, "reflected_engines": reflected[:_DIAG_MAX],
        "attempt_budget": {"used": settle.get("used"), "max": settle.get("max"),
                           "remaining": settle.get("remaining")},
        "note": "detection only (arithmetic probe); template evaluation is needs_validation, "
                "never confirmed — escalate safely to the engine's RCE gadget to prove impact. "
                "Reflection without evaluation is an XSS lead, not SSTI. No evaluation is testing, "
                "not ruled_out.",
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
    retrieve = inner.get("ssti_retrieve")
    send = inner.get("ssti_send")
    return {
        "agent_id": agent_id, "agent_name": agent_name,
        "retrieve": retrieve if callable(retrieve) else None,
        "send": send if callable(send) else None,
        "scan_targets": inner.get("scan_targets"),
        "caido_client": inner.get("caido_client"),
        "session": inner.get("sandbox_session"),
    }


@function_tool(timeout=120)
async def run_ssti_test(
    ctx: RunContextWrapper,
    hypothesis_id: str,
    request_ref: str,
    param_name: str,
    injection_location: str = "query",
) -> str:
    """Test ONE SSTI hypothesis by injecting per-engine arithmetic polyglots.

    Explicitly invoked for a single `ssti` hypothesis — NOT an automatic scanner.
    It retrieves the hypothesis's stored request through the proxy (no traffic),
    validates the destination against operator scope BEFORE sending, injects a set
    of arithmetic polyglots (Jinja2/Twig, Freemarker/EL/SpEL, ERB/Ruby, Smarty,
    Razor) — each with a DISTINCT large product so a hit maps to the engine — at
    the named location, replays ONCE, and classifies the response:

    - `template_evaluated`: a product appears AND its literal expression does not —
      real server-side evaluation (`needs_validation`); the engine(s) are reported.
    - `reflected_not_evaluated`: the expression echoes back verbatim — input
      reflection, an XSS lead, NOT SSTI (`testing`; re-route to xss.md).
    - `no_evaluation_this_run`: neither (`testing`, never `ruled_out`).

    An arithmetic hit is `needs_validation`, never `confirmed`: escalate safely to
    the engine's RCE/read gadget and prove impact before confirming. The attempt
    is recorded on the hypothesis automatically.

    Args:
        hypothesis_id: An `ssti` hypothesis id from `query_hypotheses`.
        request_ref: The stored proxy request id to inject into and replay.
        param_name: The parameter (or header name) to inject the polyglots into.
        injection_location: query / body / cookie / header (default query).
    """
    ident = _caller_identity(ctx)
    if ident["session"] is None:
        return json.dumps({"success": False, "error": "no sandbox session available"})
    result = await _run_ssti_impl(
        ident["session"], hypothesis_id=hypothesis_id, request_ref=request_ref,
        param_name=param_name, injection_location=injection_location,
        retrieve=ident["retrieve"], send=ident["send"], caido_client=ident["caido_client"],
        scan_targets=ident["scan_targets"], agent_id=ident["agent_id"],
        agent_name=ident["agent_name"],
    )
    return json.dumps(result, ensure_ascii=False, default=str)
