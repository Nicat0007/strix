"""Targeted web-cache-poisoning executor (BLACKBOX improvement #16).

Explicitly invoked for ONE selected `cache_poisoning` hypothesis — never an
automatic scanner. It tests the defining two-step shape of a cache-poisoning bug:
an UNKEYED input (a header the cache ignores when computing the cache key)
influences the response, and that response is then cached and served to a
different (victim) request:

    hypothesis (worklist #3)
      -> RETRIEVE the stored GET request through the proxy (NO traffic)
      -> validate origin+port+path against operator scope BEFORE any traffic
      -> PHASE 1: for each candidate unkeyed header (X-Forwarded-Host/-Scheme/
         -Proto/X-Host/X-Original-URL/...), replay with a UNIQUE marker and check
         whether the marker is reflected in the response (body or a header)
      -> PHASE 2: if anything reflected, send ONE CLEAN request (no injected
         header) and check whether a reflected marker STILL appears — that means
         the poisoned response was cached and served back
      -> POISONED (clean request served the marker) -> needs_validation;
         REFLECTED_UNKEYED (reflected but not persisted this run) -> testing;
         NO_REFLECTION -> testing
      -> verdict + which header + cache indicators + record on the worklist.

Hard rules: a cache-served poison is `needs_validation`, never `confirmed` — the
agent proves real impact (a victim actually gets attacker-controlled content/
redirect/script) and that the poisoned entry affects real victim keys, not just
the tester's own request; the injected marker is an inert host (no payload);
scope checked before any traffic; bounded header set + one clean request; budget
via the shared hypothesis attempt ledger; secrets never returned.

The retrieve and the sends are injected so the orchestration / scope / header
injection / reflection+persistence classification is deterministically tested
with no network; the default send uses the proxy `replay_send_raw`.
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
from strix.tools.oob_executor.tools import _scope_check, _strip_scheme
from strix.tools.open_redirect_executor.tools import _send_and_capture
from strix.tools.rate_limit_executor.tools import _set_header


logger = logging.getLogger(__name__)

_CATEGORY = "cache_poisoning"
_MAX_ATTEMPTS = DEFAULT_ATTEMPT_BUDGET
_SEND_TIMEOUT_S = 30.0
_BODY_SCAN_CAP = 200_000
_DIAG_MAX = 40

_DEFAULT_HEADERS = ("X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto",
                    "X-Host", "X-Forwarded-Server", "X-Original-URL", "X-Rewrite-URL")
_CACHE_INDICATOR_HEADERS = ("x-cache", "age", "cf-cache-status", "x-cache-hits",
                            "x-served-by", "x-cache-status")

VERDICT_POISONED = "cache_served_poison"
VERDICT_REFLECTED_UNKEYED = "unkeyed_reflected_not_cached"
VERDICT_NO_REFLECTION = "no_reflection_this_run"
VERDICT_BLOCKED = "blocked"
VERDICT_CANCELLED = "cancelled"


def _clean(value: str | None) -> str:
    return _redact_secrets((value or "").strip())


def _reflects(resp: dict[str, Any], marker: str) -> bool:
    """True when the marker appears in the response body or any header value."""
    if not resp.get("sent"):
        return False
    body = (resp.get("body") or "")[:_BODY_SCAN_CAP]
    if marker in body:
        return True
    headers = resp.get("headers") or {}
    return any(marker in str(v) for v in headers.values())


def _cache_indicators(resp: dict[str, Any]) -> list[str]:
    headers = resp.get("headers") or {}
    return sorted({f"{k}: {v}" for k, v in headers.items()
                   if str(k).lower() in _CACHE_INDICATOR_HEADERS})


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
        hypothesis_id=hypothesis_id, tool="cache_poisoning_probe", tool_rationale=rationale,
        outcome=outcome, result_status=result_status, validation_required=validation_required,
        signal=verdict, input_evidence=input_evidence, agent_id=agent_id, agent_name=agent_name,
    )


def _validation_for(verdict: str, header: str) -> str:
    if verdict == VERDICT_POISONED:
        return (f"a CLEAN request was served a response poisoned via the unkeyed {header!r} "
                "header — strong, but confirm real victim impact: that the poisoned value is "
                "actually dangerous (an attacker host in a link/script/redirect, not a benign "
                "echo) AND that the poisoned cache entry is keyed on something a real victim "
                "shares (path/query), not just your own request — then it is a confirmed finding")
    if verdict == VERDICT_REFLECTED_UNKEYED:
        return (f"the unkeyed {header!r} header is reflected but the clean request did not serve "
                "it this run — the response may not be cacheable, or the cache key/TTL differs; "
                "retry with a cache-buster path, check Cache-Control/Vary, or try another header")
    return ("not closed: no unkeyed header reflected this run — try other unkeyed inputs "
            "(headers, cookies, odd methods), a cacheable static-ish path, or cache deception")


async def _run_cache_poisoning_impl(
    transport: Any,  # the sandbox session (unused: this executor works through the proxy)
    *,
    hypothesis_id: str,
    request_ref: str,
    extra_headers: list[str] | None = None,
    retrieve: Any = None,
    send: Any = None,
    caido_client: Any = None,
    scan_targets: list[str] | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    hid = (hypothesis_id or "").strip()
    ref = (request_ref or "").strip()
    headers = [*_DEFAULT_HEADERS, *[h.strip() for h in (extra_headers or []) if h.strip()][:10]]

    hypothesis = lookup_hypothesis(hid)
    if hypothesis is None:
        return {"success": False, "error": f"no hypothesis {hypothesis_id!r} (create it first)"}
    if hypothesis.get("vuln_category") != _CATEGORY:
        return {"success": False, "error": f"hypothesis {hid} is not '{_CATEGORY}'"}
    if not ref:
        return {"success": False, "error": "request_ref is required (a stored GET request)"}

    token = f"cp{uuid.uuid4().hex[:10]}"
    intended_actor = str(hypothesis.get("actor_ref") or "anonymous")
    rationale = (f"targeted cache-poisoning probe: unkeyed headers {headers} with unique markers, "
                 f"then a clean-request persistence check; intended_actor={intended_actor}")

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
                        "capture the GET request and attach its id, then retry", RESOLVED_MISSING)
    if not got or not got.get("found") or not got.get("raw"):
        return _blocked("stored request not found for this reference",
                        "capture the GET request and attach its id, then retry", RESOLVED_MISSING)
    raw = str(got["raw"])
    url = str(got.get("url") or "")

    in_scope, scope_reason = _scope_check(url, scan_targets)
    if not in_scope:
        return _blocked(f"destination not in operator scope: {scope_reason}; not testing",
                        "confirm the target (host/port/path) is authorized with the operator",
                        RESOLVED, {"in_scope": False})

    reservation = reserve_attempt(hid, tool="cache_poisoning_probe", max_attempts=_MAX_ATTEMPTS)
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
                      "summary": f"{got.get('method', '?')} + {len(headers)} unkeyed-header probes"}

    mark_dispatched(hid, rid)
    reflected: list[tuple[str, str]] = []   # (header, marker)
    sent_any = False
    cache_ind: list[str] = []
    try:
        for i, header in enumerate(headers):
            marker = f"{token}-{i}.poison.invalid"
            mutated = _set_header(raw, header, marker)
            try:
                resp = await asyncio.wait_for(
                    send_fn(caido_client, mutated_raw=mutated, url=url), timeout=_SEND_TIMEOUT_S
                )
            except Exception:  # noqa: BLE001
                resp = {"sent": False}
            if not resp.get("sent"):
                continue
            sent_any = True
            cache_ind = cache_ind or _cache_indicators(resp)
            if _reflects(resp, marker):
                reflected.append((header, marker))

        poisoned: list[str] = []
        if reflected:
            try:
                clean = await asyncio.wait_for(
                    send_fn(caido_client, mutated_raw=raw, url=url), timeout=_SEND_TIMEOUT_S
                )
            except Exception:  # noqa: BLE001
                clean = {"sent": False}
            if clean.get("sent"):
                poisoned = [h for h, mk in reflected if _reflects(clean, mk)]
    except asyncio.CancelledError:
        settle_attempt(hid, rid, state=SLOT_FAILED)
        _record(hypothesis_id=hid, result_status=STATUS_BLOCKED, verdict=VERDICT_CANCELLED,
                rationale=rationale,
                outcome="cache-poisoning probe cancelled after dispatch; attempt consumed",
                validation_required="re-run the targeted probe", input_evidence=input_evidence,
                agent_id=agent_id, agent_name=agent_name)
        raise

    if not sent_any:
        settle_attempt(hid, rid, state=SLOT_FAILED)
        return _blocked("no probe could be sent (target unreachable or replay failed) — not a "
                        "cache result", "re-verify connectivity/session and retry", RESOLVED_STALE)

    if poisoned:
        verdict, result_status, hdr = VERDICT_POISONED, STATUS_NEEDS_VALIDATION, poisoned[0]
    elif reflected:
        verdict, result_status, hdr = (VERDICT_REFLECTED_UNKEYED, STATUS_TESTING, reflected[0][0])
    else:
        verdict, result_status, hdr = VERDICT_NO_REFLECTION, STATUS_TESTING, ""
    validation = _validation_for(verdict, hdr)
    outcome = _clean(f"cache-poisoning probe verdict={verdict}"
                     + (f"; poisoned_via={poisoned}" if poisoned else "")
                     + (f"; reflected_via={[h for h, _ in reflected]}" if reflected else "")
                     + (f"; cache_indicators={cache_ind}" if cache_ind else ""))
    settle = settle_attempt(hid, rid, state=SLOT_COMPLETED)
    _record(hypothesis_id=hid, result_status=result_status, verdict=verdict, rationale=rationale,
            outcome=outcome, validation_required=validation, input_evidence=input_evidence,
            agent_id=agent_id, agent_name=agent_name)
    record_activity_tick(agent_id)

    return {
        "success": True, "hypothesis_id": hid, "ran": True, "in_scope": True,
        "intended_actor": intended_actor, "result_status": result_status, "verdict": verdict,
        "poisoned_headers": poisoned[:_DIAG_MAX],
        "reflected_headers": [h for h, _ in reflected][:_DIAG_MAX],
        "cache_indicators": cache_ind[:_DIAG_MAX],
        "attempt_budget": {"used": settle.get("used"), "max": settle.get("max"),
                           "remaining": settle.get("remaining")},
        "note": "detection only; a clean request served the poisoned marker is needs_validation, "
                "never confirmed — prove the poisoned value is dangerous and that the cache entry "
                "hits real victim keys, not just your own request. Reflection-only / no-reflection "
                "is testing, not ruled_out.",
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
    retrieve = inner.get("cache_poisoning_retrieve")
    send = inner.get("cache_poisoning_send")
    return {
        "agent_id": agent_id, "agent_name": agent_name,
        "retrieve": retrieve if callable(retrieve) else None,
        "send": send if callable(send) else None,
        "scan_targets": inner.get("scan_targets"),
        "caido_client": inner.get("caido_client"),
        "session": inner.get("sandbox_session"),
    }


@function_tool(timeout=120)
async def run_cache_poisoning_test(
    ctx: RunContextWrapper,
    hypothesis_id: str,
    request_ref: str,
    extra_headers: list[str] | None = None,
) -> str:
    """Test ONE cache-poisoning hypothesis: unkeyed-header reflection + cache persistence.

    Explicitly invoked for a single `cache_poisoning` hypothesis — NOT an automatic
    scanner. It retrieves the hypothesis's stored GET request through the proxy (no
    traffic), validates scope BEFORE sending, then for each candidate unkeyed header
    (X-Forwarded-Host/-Scheme/-Proto/X-Host/X-Original-URL/...) replays with a UNIQUE
    inert marker and checks reflection; if anything reflects, it sends ONE CLEAN
    request (no injected header) and checks whether a marker STILL appears — meaning
    the poisoned response was cached and served back.

    A clean request served the marker is `needs_validation` (strong), never
    `confirmed`: prove the poisoned value is actually dangerous and that the cache
    entry hits real victim keys, not just your own request. Reflection-without-
    persistence or no reflection is `testing`, never `ruled_out`. The attempt is
    recorded on the worklist automatically.

    Args:
        hypothesis_id: A `cache_poisoning` hypothesis id from `query_hypotheses`.
        request_ref: The stored GET request to probe (ideally a cacheable path).
        extra_headers: Extra unkeyed header NAMES to probe, on top of the built-in
            X-Forwarded-* / X-Host / X-Original-URL set.
    """
    ident = _caller_identity(ctx)
    if ident["session"] is None:
        return json.dumps({"success": False, "error": "no sandbox session available"})
    result = await _run_cache_poisoning_impl(
        ident["session"], hypothesis_id=hypothesis_id, request_ref=request_ref,
        extra_headers=extra_headers, retrieve=ident["retrieve"], send=ident["send"],
        caido_client=ident["caido_client"], scan_targets=ident["scan_targets"],
        agent_id=ident["agent_id"], agent_name=ident["agent_name"],
    )
    return json.dumps(result, ensure_ascii=False, default=str)
