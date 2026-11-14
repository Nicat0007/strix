"""Targeted mass-assignment / auto-binding executor (BLACKBOX improvement #14).

Explicitly invoked for ONE selected `mass_assignment` hypothesis — never an
automatic scanner. It injects privileged field names a client should not control
(role/is_admin/verified/status/owner_id/...) into a captured create or update
request, replays it ONCE, and checks whether the server BOUND any of them — in
the write response and, when supplied, a re-read of the object:

    hypothesis (worklist #3)
      -> RETRIEVE the stored write request through the proxy (NO traffic)
      -> validate origin+port+path against operator scope BEFORE any traffic
      -> inject a bounded set of privileged fields; string fields carry a UNIQUE
         token so a hit is attributable (not a coincidental echo)
      -> replay ONCE; optionally re-read the object (a supplied GET ref)
      -> ACCEPTED: a token-bearing injected field appears in the response/re-read
         (the server bound a field the client shouldn't set) -> needs_validation;
         IGNORED: none bound -> testing
      -> verdict + which fields bound + sanitized evidence + record on the worklist.

Hard rules: a positive is `needs_validation`, never `confirmed` — binding a field
is not yet privilege escalation; the agent proves real impact (e.g. the role
actually grants access, the price actually charges less). Boolean-only fields
(is_admin:true) are *sent* but confirmed behaviourally, not by reflection, and
reported as "sent, verify by behaviour". Scope checked before any traffic; a
negative applies only to the tested request; budget via the shared hypothesis
attempt ledger; secrets never returned; no destructive field values.

The retrieve, the single write send, and the optional re-read are injected so the
orchestration / scope / field-injection / binding-classification logic is
deterministically tested with no network; defaults use the proxy
`replay_send_raw` (contract-based, verify live).
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any
from urllib.parse import quote

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

_CATEGORY = "mass_assignment"
_MAX_ATTEMPTS = DEFAULT_ATTEMPT_BUDGET
_SEND_TIMEOUT_S = 40.0
_BODY_SCAN_CAP = 200_000
_DIAG_MAX = 40
_MAX_EXTRA_FIELDS = 30

VERDICT_ACCEPTED = "field_bound"
VERDICT_IGNORED = "no_field_bound_this_run"
VERDICT_BLOCKED = "blocked"
VERDICT_CANCELLED = "cancelled"

#: Privileged string fields — each carries the unique token so a reflected/stored
#: hit is attributable to THIS attempt, not a coincidental page value.
_STRING_FIELDS = ("role", "status", "owner_id", "user_id", "account_id", "permissions", "plan",
                  "tier", "group", "organization_id")
#: Privileged boolean fields — SENT, but confirmed behaviourally (a reflected
#: `true` is weak evidence), so they are reported separately.
_BOOL_FIELDS = ("is_admin", "admin", "is_staff", "is_superuser", "verified", "is_verified",
                "email_verified", "is_active", "approved")


def _clean(value: str | None) -> str:
    return _redact_secrets((value or "").strip())


def _build_fields(token: str, extra: list[str]) -> tuple[dict[str, Any], dict[str, str]]:
    """Return (fields_to_inject, token_by_string_field). String fields carry the
    token; booleans are True. Agent `extra` names are treated as string fields."""
    token_by: dict[str, str] = {}
    fields: dict[str, Any] = {}
    for name in (*_STRING_FIELDS, *[e.strip() for e in extra if e.strip()][:_MAX_EXTRA_FIELDS]):
        val = f"strix_{name}_{token}"
        fields[name] = val
        token_by[name] = val
    for name in _BOOL_FIELDS:
        fields[name] = True
    return fields, token_by


def _inject_fields(raw: str, fields: dict[str, Any]) -> str | None:
    """Add fields to a JSON-object or form-encoded body. Returns the modified raw
    request, or None if the body is not an injectable shape (caller records
    blocked)."""
    parsed = _split_raw(raw)
    if parsed is None:
        return None
    request_line, sep, header_lines, body = parsed
    stripped = body.strip()
    if stripped.startswith("{"):
        try:
            obj = json.loads(body)
        except json.JSONDecodeError:
            return None
        if not isinstance(obj, dict):
            return None
        obj.update(fields)
        return "\n".join([request_line, *header_lines]) + sep + json.dumps(obj)
    if stripped and "{" not in stripped and "=" in stripped:
        def _form(v: Any) -> str:
            return "true" if v is True else ("false" if v is False else str(v))
        extra = "&".join(f"{quote(k)}={quote(_form(v))}" for k, v in fields.items())
        new_body = body + ("&" if body.strip() else "") + extra
        return "\n".join([request_line, *header_lines]) + sep + new_body
    return None


def _classify(body: str, reread: str, token_by: dict[str, str]) -> tuple[str, list[str]]:
    """(verdict, bound_string_fields). A string field is 'bound' when its unique
    token value appears in the write response or the re-read."""
    haystack = ((body or "") + " " + (reread or ""))[: _BODY_SCAN_CAP * 2]
    bound = [name for name, val in token_by.items() if val in haystack]
    return (VERDICT_ACCEPTED if bound else VERDICT_IGNORED), bound


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


async def _reread(caido_client: Any, read_ref: str) -> str:
    """Re-read the object via a supplied stored GET request; returns its body or
    empty on any failure (the re-read is best-effort; the write response is the
    primary signal)."""
    try:
        from strix.tools.proxy import caido_api  # noqa: PLC0415

        replay = await caido_api.repeat_request(_strip_scheme(read_ref))
        if not isinstance(replay, dict) or replay.get("status") == "ERROR":
            return ""
        parsed = caido_api.parse_raw_response(replay.get("response_raw")) or {}
        return str(parsed.get("body") or "")
    except Exception:  # noqa: BLE001
        return ""


def _record(
    *, hypothesis_id: str, result_status: str, verdict: str, rationale: str,
    outcome: str, validation_required: str, input_evidence: dict[str, Any] | None,
    agent_id: str | None, agent_name: str | None,
) -> None:
    _record_attempt_impl(
        hypothesis_id=hypothesis_id, tool="mass_assignment_probe", tool_rationale=rationale,
        outcome=outcome, result_status=result_status, validation_required=validation_required,
        signal=verdict, input_evidence=input_evidence, agent_id=agent_id, agent_name=agent_name,
    )


def _validation_for(verdict: str, bound: list[str]) -> str:
    if verdict == VERDICT_ACCEPTED:
        return (f"the server BOUND client-supplied privileged field(s) {bound} — but binding is "
                "not yet escalation: prove the real effect (the role/flag actually grants access "
                "or changes authz, the price/status actually takes effect for the account) before "
                "confirming. Also re-test the boolean fields behaviourally (is_admin/verified/...) "
                "since a reflected true is weak evidence")
    return ("not closed: no token-bearing field was bound in THIS request — the boolean fields "
            "were still sent and may bind without reflecting, so verify behaviourally (does the "
            "account now have the flag?); try other field names/casings or another update route")


async def _run_mass_assignment_impl(
    transport: Any,  # the sandbox session (unused: this executor works through the proxy)
    *,
    hypothesis_id: str,
    request_ref: str,
    read_request_ref: str = "",
    extra_fields: list[str] | None = None,
    retrieve: Any = None,
    send: Any = None,
    reread: Any = None,
    caido_client: Any = None,
    scan_targets: list[str] | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    hid = (hypothesis_id or "").strip()
    ref = (request_ref or "").strip()
    read_ref = (read_request_ref or "").strip()
    extra = extra_fields or []

    hypothesis = lookup_hypothesis(hid)
    if hypothesis is None:
        return {"success": False, "error": f"no hypothesis {hypothesis_id!r} (create it first)"}
    if hypothesis.get("vuln_category") != _CATEGORY:
        return {"success": False, "error": f"hypothesis {hid} is not '{_CATEGORY}'"}
    if not ref:
        return {"success": False,
                "error": "request_ref is required (a stored create/update request)"}

    token = f"ma{uuid.uuid4().hex[:12]}"
    fields, token_by = _build_fields(token, extra)
    intended_actor = str(hypothesis.get("actor_ref") or "anonymous")
    rationale = (
        f"targeted mass-assignment probe: {len(fields)} privileged fields injected into the write "
        f"body (string fields token-tagged); intended_actor={intended_actor}"
    )

    def _blocked(outcome: str, validation: str, resolved: str,
                 extra_out: dict[str, Any] | None = None) -> dict[str, Any]:
        ev = {"kind": "request", "ref": ref[:256], "resolved_state": resolved}
        _record(hypothesis_id=hid, result_status=STATUS_BLOCKED, verdict=VERDICT_BLOCKED,
                rationale=rationale, outcome=outcome, validation_required=validation,
                input_evidence=ev, agent_id=agent_id, agent_name=agent_name)
        out = {"success": True, "hypothesis_id": hid, "ran": False,
               "result_status": STATUS_BLOCKED, "intended_actor": intended_actor,
               "outcome": outcome, "suggestion": validation}
        if extra_out:
            out.update(extra_out)
        return out

    retrieve_fn = retrieve or _retrieve_request
    send_fn = send or _send_and_capture
    reread_fn = reread or _reread

    try:
        got = await retrieve_fn(_strip_scheme(ref))
    except Exception:  # noqa: BLE001
        return _blocked("proxy unavailable; could not retrieve the stored request",
                        "capture the create/update request and attach its id, then retry",
                        RESOLVED_MISSING)
    if not got or not got.get("found") or not got.get("raw"):
        return _blocked("stored request not found for this reference",
                        "capture the create/update request and attach its id, then retry",
                        RESOLVED_MISSING)
    raw = str(got["raw"])
    url = str(got.get("url") or "")

    in_scope, scope_reason = _scope_check(url, scan_targets)
    if not in_scope:
        return _blocked(f"destination not in operator scope: {scope_reason}; not testing",
                        "confirm the target (host/port/path) is authorized with the operator",
                        RESOLVED, {"in_scope": False})

    mutated = _inject_fields(raw, fields)
    if mutated is None:
        return _blocked("the request body is not an injectable shape (need a JSON object or a "
                        "form-encoded body)",
                        "capture a create/update request with a JSON or form body", RESOLVED)

    reservation = reserve_attempt(hid, tool="mass_assignment_probe", max_attempts=_MAX_ATTEMPTS)
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
                      "summary": f"{got.get('method', '?')} + {len(fields)} injected fields"}

    mark_dispatched(hid, rid)
    try:
        try:
            resp = await asyncio.wait_for(
                send_fn(caido_client, mutated_raw=mutated, url=url), timeout=_SEND_TIMEOUT_S
            )
        except Exception:  # noqa: BLE001
            resp = {"sent": False}
        reread_body = ""
        if resp.get("sent") and read_ref:
            reread_body = await reread_fn(caido_client, read_ref)
    except asyncio.CancelledError:
        settle_attempt(hid, rid, state=SLOT_FAILED)
        _record(hypothesis_id=hid, result_status=STATUS_BLOCKED, verdict=VERDICT_CANCELLED,
                rationale=rationale,
                outcome="mass-assignment probe cancelled after dispatch; attempt consumed",
                validation_required="re-run the targeted probe", input_evidence=input_evidence,
                agent_id=agent_id, agent_name=agent_name)
        raise

    if not resp.get("sent"):
        settle_attempt(hid, rid, state=SLOT_FAILED)
        return _blocked("the injected request could not be sent (target unreachable or replay "
                        "failed) — not a mass-assignment result",
                        "re-verify connectivity/session and retry", RESOLVED_STALE)

    verdict, bound = _classify(resp.get("body") or "", reread_body, token_by)
    result_status = STATUS_NEEDS_VALIDATION if verdict == VERDICT_ACCEPTED else STATUS_TESTING
    validation = _validation_for(verdict, bound)
    outcome = _clean(f"mass-assignment probe verdict={verdict}"
                     + (f"; bound={bound}" if bound else "")
                     + (f"; booleans sent (verify behaviourally): {list(_BOOL_FIELDS)}"
                        if verdict != VERDICT_ACCEPTED else ""))
    settle = settle_attempt(hid, rid, state=SLOT_COMPLETED)
    _record(hypothesis_id=hid, result_status=result_status, verdict=verdict, rationale=rationale,
            outcome=outcome, validation_required=validation, input_evidence=input_evidence,
            agent_id=agent_id, agent_name=agent_name)
    record_activity_tick(agent_id)

    return {
        "success": True, "hypothesis_id": hid, "ran": True, "in_scope": True,
        "intended_actor": intended_actor, "response_status": resp.get("status"),
        "result_status": result_status, "verdict": verdict,
        "bound_fields": bound[:_DIAG_MAX], "boolean_fields_sent": list(_BOOL_FIELDS),
        "re_read": bool(read_ref),
        "attempt_budget": {"used": settle.get("used"), "max": settle.get("max"),
                           "remaining": settle.get("remaining")},
        "note": "detection only; a bound field is needs_validation, never confirmed — prove the "
                "field actually changes authz/price/state for the account. Boolean fields are sent "
                "but confirmed behaviourally, not by reflection. No binding is testing, not "
                "ruled_out.",
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
    retrieve = inner.get("mass_assignment_retrieve")
    send = inner.get("mass_assignment_send")
    reread = inner.get("mass_assignment_reread")
    return {
        "agent_id": agent_id, "agent_name": agent_name,
        "retrieve": retrieve if callable(retrieve) else None,
        "send": send if callable(send) else None,
        "reread": reread if callable(reread) else None,
        "scan_targets": inner.get("scan_targets"),
        "caido_client": inner.get("caido_client"),
        "session": inner.get("sandbox_session"),
    }


@function_tool(timeout=120)
async def run_mass_assignment_test(
    ctx: RunContextWrapper,
    hypothesis_id: str,
    request_ref: str,
    read_request_ref: str = "",
    extra_fields: list[str] | None = None,
) -> str:
    """Test ONE mass-assignment hypothesis by injecting privileged fields into a write request.

    Explicitly invoked for a single `mass_assignment` hypothesis — NOT an automatic
    scanner. It retrieves the hypothesis's stored create/update request through the
    proxy (no traffic), validates scope BEFORE sending, injects a bounded set of
    privileged fields the client should not control (role/status/owner_id/... as
    token-tagged strings, and is_admin/verified/... as booleans), replays ONCE, and
    checks whether the server bound any — in the write response and, if you supply
    `read_request_ref`, a re-read of the object.

    A token-bearing field appearing in the response/re-read is `needs_validation`
    (the server bound a field the client shouldn't set), never `confirmed`: binding
    is not escalation — prove the field actually changes authz/price/state. Boolean
    fields are sent but confirmed behaviourally (a reflected `true` is weak). No
    binding is `testing`, never `ruled_out`. The attempt is recorded automatically.

    Args:
        hypothesis_id: A `mass_assignment` hypothesis id from `query_hypotheses`.
        request_ref: The stored create/update request (JSON-object or form body).
        read_request_ref: Optional stored GET that returns the object, for a
            re-read confirmation (strongest evidence a field actually persisted).
        extra_fields: Extra privileged field NAMES to inject (token-tagged
            strings), on top of the built-in role/is_admin/verified/... set.
    """
    ident = _caller_identity(ctx)
    if ident["session"] is None:
        return json.dumps({"success": False, "error": "no sandbox session available"})
    result = await _run_mass_assignment_impl(
        ident["session"], hypothesis_id=hypothesis_id, request_ref=request_ref,
        read_request_ref=read_request_ref, extra_fields=extra_fields,
        retrieve=ident["retrieve"], send=ident["send"], reread=ident["reread"],
        caido_client=ident["caido_client"], scan_targets=ident["scan_targets"],
        agent_id=ident["agent_id"], agent_name=ident["agent_name"],
    )
    return json.dumps(result, ensure_ascii=False, default=str)
