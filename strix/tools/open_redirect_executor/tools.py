"""Targeted open-redirect executor (BLACKBOX improvement #8).

Explicitly invoked for ONE selected `open_redirect` hypothesis — never an
automatic scanner. It injects a uniquely-marked off-origin redirect target at
exactly one location of the hypothesis's stored request, replays the request
ONCE, and classifies the response's redirect behaviour by whether the app tries
to send the client to the injected (attacker-controlled) host:

    hypothesis (worklist #3)
      -> RETRIEVE the stored request through the proxy (NO traffic)
      -> validate origin+port+path against operator scope BEFORE any traffic
      -> inject a payload carrying a UNIQUE marker host (or an agent
         `{OOB}`/`{OOB_URL}` bypass template) at one named location
      -> replay ONCE and capture the response
      -> classify: a Location header redirect to the marker host (browser-lenient
         parse, so `//h`, `https:/h`, `\\h`, `https:h` variants are caught) is a
         strong lead; a meta-refresh / JS `location` to the marker in the body is
         a weaker (body-based) lead; same-origin or no redirect is negative
      -> verdict + sanitized evidence + record on the hypothesis worklist.

Hard rules: detection only; a positive is `needs_validation`, never `confirmed`
(an open redirect's real impact — OAuth token theft, SSRF pivot, phishing — is
proven by the agent, not by the reflection); a negative applies only to the
tested parameter/location, never the class; scope is checked before any traffic;
budget via the shared hypothesis attempt ledger; secrets never returned.

The request retrieve and the single send+capture are injected so the
orchestration / scope / injection / redirect-classification logic is
deterministically tested with no network; the default send uses the proxy's
`replay_send_raw` (contract-based, verify live).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from typing import Any
from urllib.parse import urlsplit

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
from strix.tools.oob_executor.tools import (
    _build_payload,
    _inject_value,
    _scope_check,
    _strip_scheme,
    _url_parts,
)


logger = logging.getLogger(__name__)

_CATEGORY = "open_redirect"
_VALID_LOCATIONS = ("query", "body", "cookie", "header")
_MAX_ATTEMPTS = DEFAULT_ATTEMPT_BUDGET
_SEND_TIMEOUT_S = 40.0
_BODY_SCAN_CAP = 65536
_DIAG_MAX = 40

VERDICT_REDIRECTS = "redirects_to_marker"
VERDICT_BODY_REDIRECT = "body_redirect_to_marker"
VERDICT_NO_REDIRECT = "no_redirect_this_run"
VERDICT_BLOCKED = "blocked"
VERDICT_CANCELLED = "cancelled"

#: meta refresh / JS redirect sinks that carry a URL in the response body.
_META_RE = re.compile(r"(?i)<meta[^>]+http-equiv=['\"]?refresh['\"]?[^>]*url=([^'\"> ]+)")
_JS_LOC_RE = re.compile(
    r"(?i)(?:location(?:\.href)?\s*=|location\.replace\s*\(|window\.open\s*\()\s*['\"]([^'\"]+)"
)


def _clean(value: str | None) -> str:
    return _redact_secrets((value or "").strip())


def _redirect_target_host(value: str) -> str:
    """Resolve a redirect-target string to its effective host the way a browser
    would — backslashes become slashes, a scheme-relative `//h` or a
    missing-slash `https:h` / `https:/h` all resolve to host `h`. Empty on
    failure."""
    v = (value or "").strip().replace("\\", "/")
    if not v:
        return ""
    if v.startswith("//"):
        v = "http:" + v
    elif re.match(r"(?i)^https?:/{2,}", v):
        v = re.sub(r"(?i)^(https?):/+", r"\1://", v)
    elif re.match(r"(?i)^https?:/?(?!/)", v):
        v = re.sub(r"(?i)^(https?):/?", r"\1://", v)
    try:
        return (urlsplit(v).hostname or "").lower()
    except ValueError:
        return ""


def _analyze_redirect(
    status: int | None, headers: dict[str, Any], body: str, token: str
) -> tuple[str, str, list[str]]:
    """Classify whether the response redirects the client to the marked host.
    Returns (verdict, confidence, reasons). A Location-header redirect to the
    marker is strong; a body-based (meta/JS) redirect is a weaker lead."""
    tok = token.lower()
    reasons: list[str] = []
    location = ""
    for k, v in (headers or {}).items():
        if str(k).lower() == "location":
            location = str(v)
            break
    if location and tok in _redirect_target_host(location):
        reasons.append(f"Location header redirects to the injected marker host (status={status})")
        return VERDICT_REDIRECTS, "high", reasons

    snippet = (body or "")[:_BODY_SCAN_CAP]
    for rx, label in ((_META_RE, "meta-refresh"), (_JS_LOC_RE, "javascript location")):
        for m in rx.finditer(snippet):
            if tok in _redirect_target_host(m.group(1)):
                reasons.append(f"{label} in the body targets the injected marker host")
                return VERDICT_BODY_REDIRECT, "medium", reasons

    if location:
        reasons.append(f"a Location header is present but does not target the marker "
                       f"(status={status}) — same-site or unrelated redirect")
    else:
        reasons.append(f"no redirect to the marker observed (status={status})")
    return VERDICT_NO_REDIRECT, "low", reasons


# --------------------------------------------------------------------------- #
# Default request adapters (contract-based; injected in tests)
# --------------------------------------------------------------------------- #


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


async def _send_and_capture(caido_client: Any, *, mutated_raw: str, url: str) -> dict[str, Any]:
    """Send the ONE mutated request via the proxy and parse the response
    (status + headers + body — all needed to classify the redirect)."""
    from caido_sdk_client.types import ConnectionInfoInput  # noqa: PLC0415

    from strix.tools.proxy import caido_api  # noqa: PLC0415

    scheme, host, port, _path = _url_parts(url)
    if not host:
        return {"sent": False}
    conn = ConnectionInfoInput(host=host, port=port or (443 if scheme == "https" else 80),
                               is_tls=scheme == "https")
    result = await caido_api.replay_send_raw(
        caido_client, raw=mutated_raw.encode("utf-8"), connection=conn
    )
    if not isinstance(result, dict) or result.get("status") == "ERROR":
        return {"sent": False}
    parsed = caido_api.parse_raw_response(result.get("response_raw")) or {}
    return {"sent": True, "status": parsed.get("status_code"),
            "headers": parsed.get("headers") or {}, "body": parsed.get("body") or ""}


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def _record(
    *, hypothesis_id: str, result_status: str, verdict: str, rationale: str,
    outcome: str, validation_required: str, input_evidence: dict[str, Any] | None,
    agent_id: str | None, agent_name: str | None,
) -> None:
    _record_attempt_impl(
        hypothesis_id=hypothesis_id, tool="open_redirect_probe", tool_rationale=rationale,
        outcome=outcome, result_status=result_status, validation_required=validation_required,
        signal=verdict, input_evidence=input_evidence, agent_id=agent_id, agent_name=agent_name,
    )


def _validation_for(verdict: str) -> str:
    if verdict in (VERDICT_REDIRECTS, VERDICT_BODY_REDIRECT):
        base = ("the app reflects an attacker-controlled host into its redirect target; "
                "demonstrate real impact to confirm — e.g. OAuth/OIDC authorization-code or "
                "token theft via a controlled redirect_uri, an SSRF pivot, or a credible phishing "
                "landing — a reflected redirect alone is needs_validation")
        if verdict == VERDICT_BODY_REDIRECT:
            base += (". NOTE: this is a BODY-based (meta/JS) redirect — confirm it actually "
                     "executes in a browser and is not inert/escaped before relying on it")
        return base
    return ("not closed: no redirect to the marker for THIS parameter/location does not rule out "
            "the class — try bypass templates (//marker, https:/marker, \\marker, whitelisted-"
            "prefix tricks) or another parameter")


async def _run_open_redirect_impl(
    transport: Any,  # the sandbox session (unused: this executor works through the proxy)
    *,
    hypothesis_id: str,
    request_ref: str,
    param_name: str,
    injection_location: str = "query",
    payload_template: str = "",
    retrieve: Any = None,
    send: Any = None,
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

    token = f"orc{uuid.uuid4().hex[:14]}"
    marker = f"{token}.redirect-check.invalid"
    template = payload_template.strip() or "{OOB_URL}"
    intended_actor = str(hypothesis.get("actor_ref") or "anonymous")
    rationale = (
        f"targeted open-redirect probe: a uniquely-marked off-origin target injected at {location} "
        f"param {param!r}; intended_actor={intended_actor}"
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

    payload = _build_payload(template, marker, "https")
    mutated = _inject_value(raw, param, location, payload)
    if mutated is None:
        return _blocked(
            f"parameter {param!r} not found in location {location!r}, or the location is ambiguous",
            "re-check the parameter's actual location, or capture a request that carries it",
            RESOLVED)

    reservation = reserve_attempt(hid, tool="open_redirect_probe", max_attempts=_MAX_ATTEMPTS)
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
                rationale=rationale, outcome="open-redirect probe cancelled after dispatch; "
                "attempt consumed", validation_required="re-run the targeted probe",
                input_evidence=input_evidence, agent_id=agent_id, agent_name=agent_name)
        raise

    if not resp.get("sent"):
        settle_attempt(hid, rid, state=SLOT_FAILED)
        return _blocked("the injected request could not be sent (target unreachable or replay "
                        "failed) — not a redirect result",
                        "re-verify connectivity/session and retry", RESOLVED_STALE)

    verdict, confidence, reasons = _analyze_redirect(
        resp.get("status"), resp.get("headers") or {}, resp.get("body") or "", token
    )
    if verdict in (VERDICT_REDIRECTS, VERDICT_BODY_REDIRECT):
        result_status = STATUS_NEEDS_VALIDATION
    else:
        result_status = STATUS_TESTING
    validation = _validation_for(verdict)
    outcome = _clean(f"open-redirect probe verdict={verdict} (confidence={confidence}); "
                     + "; ".join(reasons))
    settle = settle_attempt(hid, rid, state=SLOT_COMPLETED)
    _record(hypothesis_id=hid, result_status=result_status, verdict=verdict, rationale=rationale,
            outcome=outcome, validation_required=validation, input_evidence=input_evidence,
            agent_id=agent_id, agent_name=agent_name)
    record_activity_tick(agent_id)

    return {
        "success": True, "hypothesis_id": hid, "ran": True, "in_scope": True,
        "injection_location": location, "intended_actor": intended_actor,
        "marker_host": marker, "response_status": resp.get("status"),
        "result_status": result_status, "verdict": verdict, "confidence": confidence,
        "reasons": reasons[:_DIAG_MAX],
        "attempt_budget": {"used": settle.get("used"), "max": settle.get("max"),
                           "remaining": settle.get("remaining")},
        "note": "detection only; a reflected redirect to an attacker host is needs_validation, "
                "never confirmed — demonstrate real impact (OAuth token theft / SSRF / phishing). "
                "No redirect is testing, not ruled_out.",
    }


# --------------------------------------------------------------------------- #
# Agent tool
# --------------------------------------------------------------------------- #


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
    retrieve = inner.get("open_redirect_retrieve")
    send = inner.get("open_redirect_send")
    return {
        "agent_id": agent_id, "agent_name": agent_name,
        "retrieve": retrieve if callable(retrieve) else None,
        "send": send if callable(send) else None,
        "scan_targets": inner.get("scan_targets"),
        "caido_client": inner.get("caido_client"),
        "session": inner.get("sandbox_session"),
    }


@function_tool(timeout=120)
async def run_open_redirect_test(
    ctx: RunContextWrapper,
    hypothesis_id: str,
    request_ref: str,
    param_name: str,
    injection_location: str = "query",
    payload_template: str = "",
) -> str:
    """Test ONE open-redirect hypothesis by injecting a uniquely-marked off-origin target.

    Explicitly invoked for a single `open_redirect` hypothesis — NOT an automatic
    scanner. It retrieves the hypothesis's stored request through the proxy (no
    traffic), validates the destination against operator scope BEFORE sending,
    injects a payload carrying a UNIQUE marker host at the named location, replays
    the request ONCE, and classifies whether the response redirects the client to
    the marker — via the Location header (browser-lenient parse, so `//h`,
    `https:/h`, `\\h`, `https:h` bypass shapes are caught) or a meta-refresh / JS
    `location` in the body. It records the attempt on the hypothesis automatically.

    A redirect to the marker is `needs_validation`, never `confirmed`: the real
    impact (OAuth/OIDC token theft, SSRF pivot, phishing) is proven by you. A
    body-based (meta/JS) redirect is flagged lower-confidence. No redirect is
    `testing`, never `ruled_out`.

    Args:
        hypothesis_id: An `open_redirect` hypothesis id from `query_hypotheses`.
        request_ref: The stored proxy request id to inject into and replay.
        param_name: The parameter (or header name) carrying the redirect target.
        injection_location: query / body / cookie / header (default query).
        payload_template: Optional bypass payload containing `{OOB}` (the bare
            marker host) and/or `{OOB_URL}` (`https://marker/`). Empty = `{OOB_URL}`.
            Use e.g. `//{OOB}`, `https:/{OOB}`, `\\{OOB}`, `/x/../{OOB}` for bypasses.
    """
    ident = _caller_identity(ctx)
    if ident["session"] is None:
        return json.dumps({"success": False, "error": "no sandbox session available"})
    result = await _run_open_redirect_impl(
        ident["session"], hypothesis_id=hypothesis_id, request_ref=request_ref,
        param_name=param_name, injection_location=injection_location,
        payload_template=payload_template, retrieve=ident["retrieve"], send=ident["send"],
        caido_client=ident["caido_client"], scan_targets=ident["scan_targets"],
        agent_id=ident["agent_id"], agent_name=ident["agent_name"],
    )
    return json.dumps(result, ensure_ascii=False, default=str)
