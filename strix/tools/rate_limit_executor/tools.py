"""Targeted rate-limit / anti-automation executor (BLACKBOX improvement #10).

Explicitly invoked for ONE selected `weak_password_detection` hypothesis — the
room101-class gap (an unthrottled OTP / login / password-reset endpoint). It is a
rate-limit PRESENCE test, not a credential brute-force: it replays the SAME stored
request a bounded number of times and observes if/when throttling fires, then
tests whether an IP-rotation header defeats it:

    hypothesis (worklist #3)
      -> RETRIEVE the stored request through the proxy (NO traffic)
      -> validate origin+port+path against operator scope BEFORE any traffic
      -> PASS 1: replay the identical request up to `attempts` times, paced,
         recording the first response classified as a block (429/403/challenge)
      -> if a block fired AND header-bypass testing is on, PASS 2: replay again
         rotating X-Forwarded-For/X-Real-IP; if the block no longer fires, that is
         a rate-limit bypass lead
      -> verdict + sanitized counts + record on the worklist.

Hard rules: this replays an IDENTICAL request (no password/OTP guessing — an
actual brute-force is a separate, explicitly-authorized step the agent runs after
confirming the endpoint is unthrottled); detection only; a positive is
`needs_validation`, never `confirmed`; scope checked before any traffic; bounded
attempts/pacing/total-time; budget via the shared hypothesis attempt ledger;
secrets never returned. An IP-rotation bypass is a finding about the control, not
proof of account takeover — that still requires the (authorized) brute-force.

The retrieve and per-attempt send are injected so the orchestration / scope /
pacing / block-classification / bypass logic is deterministically tested with no
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
from strix.tools.oob_executor.tools import _scope_check, _split_raw, _strip_scheme
from strix.tools.open_redirect_executor.tools import _send_and_capture


logger = logging.getLogger(__name__)

_CATEGORY = "weak_password_detection"
_MAX_ATTEMPTS = DEFAULT_ATTEMPT_BUDGET
_SEND_TIMEOUT_S = 20.0

# Bounds — clamped, never trusted from the caller.
_DEFAULT_N = 12
_MAX_N = 25
_DEFAULT_SPACING_S = 0.1
_MAX_SPACING_S = 5.0
_MAX_TOTAL_S = 180.0
_BODY_SCAN_CAP = 8192
_DIAG_MAX = 40

_DEFAULT_BLOCK_STATUSES = frozenset({429, 403})
_BLOCK_MARKERS = (
    "too many", "rate limit", "rate-limit", "ratelimited", "try again later",
    "slow down", "temporarily blocked", "captcha", "verifying you are human",
)
_ROTATE_HEADERS = ("X-Forwarded-For", "X-Real-IP", "X-Client-IP")

VERDICT_NO_LIMIT = "no_rate_limit_observed"
VERDICT_LIMITED = "rate_limited"
VERDICT_HEADER_BYPASS = "rate_limit_header_bypass"
VERDICT_BLOCKED = "blocked"
VERDICT_CANCELLED = "cancelled"


def _clean(value: str | None) -> str:
    return _redact_secrets((value or "").strip())


def _set_header(raw: str, name: str, value: str) -> str:
    """Replace the named header's value, or add it if absent (CRLF-stripped)."""
    parsed = _split_raw(raw)
    if parsed is None:
        return raw
    request_line, sep, header_lines, body = parsed
    safe = value.replace("\r", "").replace("\n", "")
    low = name.lower()
    done = False
    for i, hl in enumerate(header_lines):
        hname, _, _hval = hl.partition(":")
        if hname.strip().lower() == low:
            header_lines[i] = f"{hname}: {safe}"
            done = True
            break
    if not done:
        header_lines.append(f"{name}: {safe}")
    return "\n".join([request_line, *header_lines]) + sep + body


def _rotate_raw(raw: str, idx: int) -> str:
    out = raw
    ip = f"10.{(idx // 256) % 256}.{idx % 256}.{(idx * 7) % 251 + 1}"
    for h in _ROTATE_HEADERS:
        out = _set_header(out, h, ip)
    return out


def _is_block(
    resp: dict[str, Any], block_statuses: frozenset[int], extra_markers: list[str]
) -> bool:
    if not resp.get("sent"):
        return False
    status = resp.get("status")
    if isinstance(status, int) and status in block_statuses:
        return True
    headers = resp.get("headers") or {}
    if any(str(k).lower() == "retry-after" for k in headers):
        return True
    blob = ((resp.get("body") or "")[:_BODY_SCAN_CAP]).lower()
    markers = (*_BLOCK_MARKERS, *(m.lower() for m in extra_markers))
    return any(m in blob for m in markers)


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


async def _replay_pass(
    send_fn: Any, caido_client: Any, *, base_raw: str, url: str, n: int, spacing: float,
    rotate: bool, block_statuses: frozenset[int], markers: list[str], deadline: float,
) -> dict[str, Any]:
    """Replay up to n identical (or IP-rotated) requests, paced. Returns counts and
    the 1-based index of the first blocked response (or None)."""
    sent = 0
    blocked = 0
    first_block_at: int | None = None
    for i in range(n):
        if asyncio.get_event_loop().time() > deadline:
            break
        raw_i = _rotate_raw(base_raw, i) if rotate else base_raw
        try:
            resp = await asyncio.wait_for(
                send_fn(caido_client, mutated_raw=raw_i, url=url), timeout=_SEND_TIMEOUT_S
            )
        except Exception:  # noqa: BLE001
            resp = {"sent": False}
        if not resp.get("sent"):
            continue
        sent += 1
        if _is_block(resp, block_statuses, markers):
            blocked += 1
            if first_block_at is None:
                first_block_at = sent
        if spacing > 0 and i < n - 1:
            await asyncio.sleep(spacing)
    return {"sent": sent, "blocked": blocked, "first_block_at": first_block_at}


def _record(
    *, hypothesis_id: str, result_status: str, verdict: str, rationale: str,
    outcome: str, validation_required: str, input_evidence: dict[str, Any] | None,
    agent_id: str | None, agent_name: str | None,
) -> None:
    _record_attempt_impl(
        hypothesis_id=hypothesis_id, tool="rate_limit_probe", tool_rationale=rationale,
        outcome=outcome, result_status=result_status, validation_required=validation_required,
        signal=verdict, input_evidence=input_evidence, agent_id=agent_id, agent_name=agent_name,
    )


def _validation_for(verdict: str) -> str:
    if verdict == VERDICT_NO_LIMIT:
        return ("no throttling observed across the bounded identical replays; if this is a "
                "security-relevant endpoint (OTP, login, password reset, 2FA), confirm it by "
                "demonstrating a real, authorized brute-force reaches the keyspace — a missing "
                "limit on an identical replay is needs_validation, not yet account takeover")
    if verdict == VERDICT_HEADER_BYPASS:
        return ("the rate limit fired on repeated requests but NOT when an IP-rotation header was "
                "varied — a real bypass lead; confirm the header is actually attacker-controlled "
                "end-to-end (not stripped at the edge) and demonstrate authorized brute-force "
                "through it before confirming")
    if verdict == VERDICT_LIMITED:
        return ("a rate limit fired — the control appears present. Note the observed threshold; "
                "consider whether it is strong enough for the endpoint's sensitivity, and whether "
                "a soft/IP-based throttle can be evaded by other means")
    return "re-establish connectivity/baseline and retry; the run was inconclusive"


async def _run_rate_limit_impl(
    transport: Any,  # the sandbox session (unused: this executor works through the proxy)
    *,
    hypothesis_id: str,
    request_ref: str,
    attempts: int | None = None,
    spacing_s: float | None = None,
    test_header_bypass: bool = True,
    block_markers: list[str] | None = None,
    retrieve: Any = None,
    send: Any = None,
    caido_client: Any = None,
    scan_targets: list[str] | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    hid = (hypothesis_id or "").strip()
    ref = (request_ref or "").strip()
    n = max(2, min(int(attempts or _DEFAULT_N), _MAX_N))
    spacing = max(0.0, min(spacing_s if spacing_s is not None else _DEFAULT_SPACING_S,
                           _MAX_SPACING_S))
    markers = [m for m in (block_markers or []) if isinstance(m, str) and m.strip()][:20]

    hypothesis = lookup_hypothesis(hid)
    if hypothesis is None:
        return {"success": False, "error": f"no hypothesis {hypothesis_id!r} (create it first)"}
    if hypothesis.get("vuln_category") != _CATEGORY:
        return {"success": False, "error": f"hypothesis {hid} is not '{_CATEGORY}'"}
    if not ref:
        return {"success": False, "error": "request_ref is required (a stored proxy request id)"}

    intended_actor = str(hypothesis.get("actor_ref") or "anonymous")
    rationale = (
        f"targeted rate-limit PRESENCE probe: up to {n} identical replays, paced {spacing}s, "
        f"then IP-rotation-header bypass if throttled; intended_actor={intended_actor}"
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

    reservation = reserve_attempt(hid, tool="rate_limit_probe", max_attempts=_MAX_ATTEMPTS)
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
                      "summary": f"{got.get('method', '?')} replayed up to {n}x"}
    deadline = asyncio.get_event_loop().time() + _MAX_TOTAL_S

    mark_dispatched(hid, rid)
    try:
        pass1 = await _replay_pass(
            send_fn, caido_client, base_raw=raw, url=url, n=n, spacing=spacing, rotate=False,
            block_statuses=_DEFAULT_BLOCK_STATUSES, markers=markers, deadline=deadline,
        )
        bypass: dict[str, Any] | None = None
        if pass1["first_block_at"] is not None and test_header_bypass:
            bypass = await _replay_pass(
                send_fn, caido_client, base_raw=raw, url=url, n=n, spacing=spacing, rotate=True,
                block_statuses=_DEFAULT_BLOCK_STATUSES, markers=markers, deadline=deadline,
            )
    except asyncio.CancelledError:
        settle_attempt(hid, rid, state=SLOT_FAILED)
        _record(hypothesis_id=hid, result_status=STATUS_BLOCKED, verdict=VERDICT_CANCELLED,
                rationale=rationale,
                outcome="rate-limit probe cancelled after dispatch; attempt consumed",
                validation_required="re-run the targeted probe", input_evidence=input_evidence,
                agent_id=agent_id, agent_name=agent_name)
        raise

    if pass1["sent"] == 0:
        settle_attempt(hid, rid, state=SLOT_FAILED)
        return _blocked("no request could be sent (target unreachable or replay failed) — not a "
                        "rate-limit result", "re-verify connectivity/session and retry",
                        RESOLVED_STALE)

    if pass1["first_block_at"] is None:
        verdict, result_status = VERDICT_NO_LIMIT, STATUS_NEEDS_VALIDATION
    elif bypass is not None and bypass["sent"] > 0 and bypass["first_block_at"] is None:
        verdict, result_status = VERDICT_HEADER_BYPASS, STATUS_NEEDS_VALIDATION
    else:
        verdict, result_status = VERDICT_LIMITED, STATUS_TESTING

    validation = _validation_for(verdict)
    outcome = _clean(
        f"rate-limit probe verdict={verdict}; pass1 sent={pass1['sent']} blocked={pass1['blocked']}"
        f" first_block_at={pass1['first_block_at']}"
        + (f"; rotated pass sent={bypass['sent']} blocked={bypass['blocked']}"
           f" first_block_at={bypass['first_block_at']}" if bypass else "")
    )
    settle = settle_attempt(hid, rid, state=SLOT_COMPLETED)
    _record(hypothesis_id=hid, result_status=result_status, verdict=verdict, rationale=rationale,
            outcome=outcome, validation_required=validation, input_evidence=input_evidence,
            agent_id=agent_id, agent_name=agent_name)
    record_activity_tick(agent_id)

    return {
        "success": True, "hypothesis_id": hid, "ran": True, "in_scope": True,
        "intended_actor": intended_actor, "result_status": result_status, "verdict": verdict,
        "pass1": pass1, "rotated_pass": bypass,
        "attempt_budget": {"used": settle.get("used"), "max": settle.get("max"),
                           "remaining": settle.get("remaining")},
        "note": "rate-limit PRESENCE test via identical replays — NOT a brute-force. No limit / "
                "a header bypass is needs_validation, never confirmed; prove impact with an "
                "authorized brute-force separately. A fired limit is testing. Counts only.",
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
    retrieve = inner.get("rate_limit_retrieve")
    send = inner.get("rate_limit_send")
    return {
        "agent_id": agent_id, "agent_name": agent_name,
        "retrieve": retrieve if callable(retrieve) else None,
        "send": send if callable(send) else None,
        "scan_targets": inner.get("scan_targets"),
        "caido_client": inner.get("caido_client"),
        "session": inner.get("sandbox_session"),
    }


@function_tool(timeout=220)
async def run_rate_limit_test(
    ctx: RunContextWrapper,
    hypothesis_id: str,
    request_ref: str,
    attempts: int | None = None,
    spacing_s: float | None = None,
    test_header_bypass: bool = True,
    block_markers: list[str] | None = None,
) -> str:
    """Test ONE rate-limit hypothesis by bounded identical replays (NOT a brute-force).

    Explicitly invoked for a single `weak_password_detection` hypothesis (an OTP /
    login / password-reset / 2FA endpoint suspected unthrottled). It retrieves the
    stored request through the proxy (no traffic), validates scope BEFORE sending,
    then replays the IDENTICAL request up to `attempts` times, paced, recording if
    and when throttling fires (429/403/Retry-After/"too many"/captcha). If a block
    fires and `test_header_bypass` is on, it replays again rotating
    X-Forwarded-For/X-Real-IP/X-Client-IP to test an IP-rotation bypass.

    This is a rate-limit PRESENCE test, not a credential brute-force — it sends the
    same request, never guesses passwords/OTPs. An actual brute-force is a separate,
    explicitly-authorized step you run AFTER confirming the endpoint is unthrottled.
    No limit / a header bypass is `needs_validation`, never `confirmed`; a fired
    limit is `testing`. The attempt is recorded on the worklist automatically.

    Args:
        hypothesis_id: A `weak_password_detection` hypothesis id from `query_hypotheses`.
        request_ref: The stored proxy request id to replay.
        attempts: How many identical replays per pass (default 12, capped 25).
        spacing_s: Seconds between replays (default 0.1, capped 5; total time is
            hard-bounded regardless).
        test_header_bypass: If a limit fires, also test IP-rotation-header bypass
            (default true).
        block_markers: Extra app-specific body strings that indicate a throttle
            response, on top of the built-in 429/403/Retry-After/captcha defaults.
    """
    ident = _caller_identity(ctx)
    if ident["session"] is None:
        return json.dumps({"success": False, "error": "no sandbox session available"})
    result = await _run_rate_limit_impl(
        ident["session"], hypothesis_id=hypothesis_id, request_ref=request_ref,
        attempts=attempts, spacing_s=spacing_s, test_header_bypass=test_header_bypass,
        block_markers=block_markers, retrieve=ident["retrieve"], send=ident["send"],
        caido_client=ident["caido_client"], scan_targets=ident["scan_targets"],
        agent_id=ident["agent_id"], agent_name=ident["agent_name"],
    )
    return json.dumps(result, ensure_ascii=False, default=str)
