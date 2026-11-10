"""Evidence-backed authorization replay executor (BLACKBOX improvement #5).

Explicitly invoked for ONE selected IDOR/BOLA/BFLA hypothesis. It replays a
captured request as a *different* actor and compares real semantic evidence, so
an authorization boundary is tested with two actors and genuine ownership/
privilege evidence — never guessed from an id-shaped parameter or a role name.

Flow (per call):

    hypothesis (#3) + captured request + reference actor + comparison actor
      -> resolve each actor's COMPLETE auth context from the provisioned sessions
         (never merge actor-a and actor-b credentials)
      -> retrieve the stored request (no traffic); validate origin+port+path vs
         operator scope BEFORE any request, including controls
      -> baseline: replay as the reference actor (must be authorized + semantic)
      -> controls: anonymous (expect denial); comparison actor's OWN object
         (expect success — proves a valid, distinct session); expected-denial
      -> test: replay the SAME concrete resource/operation as the comparison
         actor; compare resource identity + approved semantic evidence, not just
         status/length
      -> re-check auth after testing; downgrade if validity becomes uncertain
      -> verdict + sanitized evidence + record on the hypothesis worklist.

Hard rules: a positive is `needs_validation`, never auto-`confirmed`; a negative
applies only to the tested actor/resource/operation (never closes siblings/the
class); two actors receiving the same denial is NEVER a leak; a failed baseline
is never a vulnerability; generic 200/login/shared-error bodies are not
authorized access; a 403->200 alone is not a bypass. Operator/agent "expected
access" inputs are treated as ASSERTIONS with provenance, not facts. Detection /
read comparison only; state-changing vertical tests require an operator-
authorized test object + a safe verification plan or they are deferred to manual
follow-up. No credential attacks, no WAF bypass while measuring authorization,
no object enumeration, no destructive operations.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import uuid
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.agent_metrics.tools import record_activity_tick
from strix.tools.attack_surface.tools import _redact_secrets
from strix.tools.crawl_executor.tools import CrawlTransport, _actor_headers, _read_capped
from strix.tools.hypotheses.tools import (
    RESOLVED,
    RESOLVED_MISSING,
    RESOLVED_STALE,
    SLOT_CANCELLED,
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
from strix.tools.sqli_executor.tools import (
    _MAX_ATTEMPTS,
    _classify_block,
    _sanitized_meta,
    _scope_check,
    _strip_scheme,
)


logger = logging.getLogger(__name__)

_AUTHZ_CATEGORIES = ("idor", "broken_function_level_authorization")
_DEFAULT_ACCOUNTS_PATH = "/workspace/recon/auth_accounts.jsonl"
_BODY_SCAN_CAP = 8192
_DIAG_MAX = 40
#: Every header that can carry an actor's auth context — stripped wholesale
#: before a different actor's context is injected (no credential bleed).
_AUTH_HEADER_NAMES = frozenset({
    "cookie", "authorization", "x-api-key", "api-key", "apikey", "x-auth-token",
    "x-access-token", "x-session-token", "proxy-authorization",
})
#: Session-bound material this executor cannot reliably rebuild for another actor
#: -> block/hand off rather than send a broken or actor-a-signed request.
_UNSUPPORTED_AUTH_HINTS = frozenset({
    "x-csrf-token", "x-xsrf-token", "csrf-token", "x-signature", "x-hmac",
    "signature", "x-amz-date", "authorization-signature",
})
_STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_LOGIN_HINTS = ("login", "sign in", "signin", "log in", "authenticate", "session expired")

TEST_HORIZONTAL = "horizontal"
TEST_VERTICAL = "vertical"

VERDICT_BYPASS = "potential_authorization_bypass"
VERDICT_DENIED = "denied_this_test"
VERDICT_INSUFFICIENT = "insufficient_evidence"
VERDICT_INVALID_SESSION = "invalid_session"
VERDICT_BLOCKED = "blocked"
VERDICT_UNSTABLE = "unstable_result"
#: The reference actor's baseline returned 2xx but not the marker, with no
#: concrete auth-loss signal (login/401/403) — cannot confirm the marker
#: identifies the resource; NOT proven to be a session loss. Inconclusive.
VERDICT_BASELINE_UNVERIFIED = "baseline_unverified"
#: Anonymous access is permitted by policy (anonymous_expectation=allow) and the
#: resource is reachable anonymously — there is no cross-actor READ boundary to
#: violate. A neutral, expected outcome, NOT a denial.
VERDICT_EXPECTED_PUBLIC = "expected_public_access"


def _clean(value: str | None) -> str:
    return _redact_secrets((value or "").strip())


# --------------------------------------------------------------------------- #
# Proxy adapters — retrieve (no traffic) and actor-swap replay (rebuilt raw)
# --------------------------------------------------------------------------- #


def _rebuild_headers(captured: dict[str, str], override: dict[str, str] | None) -> dict[str, str]:
    """Produce the headers for a replay. ``override is None`` keeps the captured
    auth as-is (reference actor). Otherwise ALL auth-bearing headers are stripped
    and the override actor's complete context is injected — actor-a and actor-b
    credentials are never merged."""
    if override is None:
        return dict(captured)
    stripped = {k: v for k, v in captured.items() if k.lower() not in _AUTH_HEADER_NAMES}
    stripped.update(override)
    return stripped


def _unsupported_auth(raw: str) -> str | None:
    """If the request carries session-bound signing/CSRF that cannot be rebuilt
    for another actor, return a reason to block/hand off; else None."""
    low = raw.lower()
    for name in _UNSUPPORTED_AUTH_HINTS:
        if f"\n{name}:" in low or low.startswith(f"{name}:"):
            return (f"request carries {name!r} (actor-specific signing/CSRF) that cannot be "
                    "reliably rebuilt for another actor")
    return None


async def _default_retrieve(request_id: str) -> dict[str, Any] | None:
    from strix.tools.proxy import caido_api  # noqa: PLC0415

    result = await caido_api.view_request(request_id, part="request")
    if result is None or getattr(result.request, "raw", None) is None:
        return None
    raw = result.request.raw.decode("utf-8", errors="replace")
    components = caido_api.parse_raw_request(raw)
    url = caido_api.full_url_from_components(result.request, components, {})
    return {"found": True, "raw": raw, "url": url,
            "method": str(components.get("method", "GET"))}


async def _default_replay(request_id: str, override: dict[str, str] | None) -> dict[str, Any]:
    """Replay a stored request with a complete, rebuilt auth context. Sends ONE
    request via the proxy and parses the response (status/headers/body)."""
    from strix.tools.proxy import caido_api  # noqa: PLC0415

    result = await caido_api.view_request(request_id, part="request")
    if result is None or getattr(result.request, "raw", None) is None:
        return {"replayed": False}
    raw = result.request.raw.decode("utf-8", errors="replace")
    components = caido_api.parse_raw_request(raw)
    url = caido_api.full_url_from_components(result.request, components, {})
    headers = _rebuild_headers(components.get("headers") or {}, override)
    connection, raw_bytes = caido_api.build_raw_request(
        method=str(components.get("method", "GET")), url=url, headers=headers,
        body=str(components.get("body", "")),
    )
    replay = await caido_api.call_with_client(
        lambda c: caido_api.replay_send_raw(c, raw=raw_bytes, connection=connection)
    )
    if not isinstance(replay, dict) or replay.get("status") == "ERROR":
        return {"replayed": False}
    parsed = caido_api.parse_raw_response(replay.get("response_raw"))
    if not parsed:
        return {"replayed": False, "timing_ms": replay.get("elapsed_ms")}
    return {"replayed": True, "status": parsed.get("status_code"),
            "headers": parsed.get("headers") or {}, "body": parsed.get("body") or "",
            "body_truncated": bool(parsed.get("body_truncated")),
            "timing_ms": replay.get("elapsed_ms")}


# --------------------------------------------------------------------------- #
# Semantic comparison (identity + approved evidence, not status/length alone)
# --------------------------------------------------------------------------- #


def _looks_like_login(body: str, meta: dict[str, Any]) -> bool:
    low = body[:_BODY_SCAN_CAP].lower()
    loc = (meta.get("redirect_location") or "").lower()
    status = meta.get("status")
    if status is not None and 300 <= status < 400 and any(h in loc for h in ("login", "signin",
                                                                              "auth")):
        return True
    return any(h in low for h in _LOGIN_HINTS)


def _is_denied(meta: dict[str, Any], body: str, denied_marker: str) -> bool:
    status = meta.get("status")
    if status in (401, 403, 404):
        return True
    if status is not None and 300 <= status < 400 and _looks_like_login(body, meta):
        return True
    return bool(denied_marker and denied_marker.lower() in body[:_BODY_SCAN_CAP].lower())


def _has_resource(meta: dict[str, Any], body: str, resource_marker: str) -> bool:
    """Approved semantic evidence that THIS response actually contains the
    reference actor's protected resource — a specific marker, a 2xx status, and
    NOT a login/denied page. Status/length alone never qualify."""
    status = meta.get("status")
    if status is None or not (200 <= status < 300):
        return False
    if _looks_like_login(body, meta):
        return False
    return bool(resource_marker) and resource_marker.lower() in body[:_BODY_SCAN_CAP].lower()


def _auth_loss_evidence(body: str, meta: dict[str, Any]) -> bool:
    """Explicit AUTHENTICATION-loss evidence — a login page/redirect, or a 401
    (an authentication challenge). A 403 is AUTHORIZATION (forbidden): the
    session is valid but not permitted, which is NOT proof the session is
    invalid. 403/404/5xx/timeout therefore never establish session loss here;
    only this independent signal does."""
    return _looks_like_login(body, meta) or meta.get("status") == 401


def _meta_of(replay: dict[str, Any]) -> dict[str, Any]:
    return _sanitized_meta(replay) if replay.get("replayed") else {"status": None}


_OP_READ = "read"
_OP_STATE_CHANGE = "state_change"
_ANON_EXPECT = ("deny", "allow", "unknown")


def _auth_context_hash(headers: dict[str, str]) -> str:
    """A stable, NON-reversible fingerprint of an actor's auth context (the
    values of its auth-bearing headers). Used to prove two actors are distinct
    credential contexts WITHOUT exposing or storing the credentials."""
    material = "\n".join(
        f"{k.lower()}={v}" for k, v in sorted(headers.items())
        if k.lower() in _AUTH_HEADER_NAMES
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16] if material else ""


def _captured_auth_headers(raw: str) -> dict[str, str]:
    """Extract the reference actor's auth-bearing headers from the captured raw
    request (its session lives there), for the distinctness check only."""
    out: dict[str, str] = {}
    for line in raw.split("\n")[1:]:
        if ":" not in line or line.strip() == "":
            if line.strip() == "":
                break
            continue
        name, _, value = line.partition(":")
        if name.strip().lower() in _AUTH_HEADER_NAMES:
            out[name.strip()] = value.strip()
    return out


def _reflected(marker: str, raw: str) -> bool:
    """True if the marker appears in the REQUEST itself — then its presence in a
    response is an echo, not evidence of protected-resource access."""
    return bool(marker) and marker.lower() in raw.lower()


def _effective_op_class(method: str, operation_class: str) -> str:
    """A state-changing HTTP method is a floor: it can never be reclassified as a
    read. Otherwise the caller's explicit classification governs (method alone
    does not prove the absence of side effects)."""
    if method.upper() in _STATE_CHANGING:
        return _OP_STATE_CHANGE
    return (operation_class or "").strip().lower()


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def _record(*, hypothesis_id: str, result_status: str, verdict: str, rationale: str,
            outcome: str, validation: str, evidence: dict[str, Any] | None,
            agent_id: str | None, agent_name: str | None) -> None:
    _record_attempt_impl(
        hypothesis_id=hypothesis_id, tool="authorization_replay", tool_rationale=rationale,
        outcome=outcome, result_status=result_status, validation_required=validation,
        signal=verdict, input_evidence=evidence, agent_id=agent_id, agent_name=agent_name,
    )


async def _run_authz_impl(  # noqa: PLR0911, PLR0912, PLR0915
    *,
    hypothesis_id: str,
    request_ref: str,
    reference_actor: str,
    comparison_actor: str,
    test_intent: str,
    resource_marker: str = "",
    ownership_assertion: str = "",
    privilege_assertion: str = "",
    operation_class: str = "",
    anonymous_expectation: str = "deny",
    reference_identity_marker: str = "",
    comparison_identity_marker: str = "",
    denied_marker: str = "",
    comparison_own_ref: str = "",
    operator_test_object: bool = False,
    verification_plan: str = "",
    accounts_text: str = "",
    retrieve: Any = None,
    replay: Any = None,
    scan_targets: list[str] | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    hid = (hypothesis_id or "").strip()
    ref = (request_ref or "").strip()
    ref_actor = (reference_actor or "").strip()
    cmp_actor = (comparison_actor or "").strip()
    intent = (test_intent or "").strip().lower()
    hypothesis = lookup_hypothesis(hid)
    rationale = (f"actor-aware authorization replay ({intent}): reference={ref_actor!r} vs "
                 f"comparison={cmp_actor!r} on the hypothesis's concrete request")

    def _result(result_status: str, verdict: str, outcome: str, validation: str,
                extra: dict[str, Any] | None = None, resolved: str = RESOLVED) -> dict[str, Any]:
        _record(hypothesis_id=hid, result_status=result_status, verdict=verdict,
                rationale=rationale, outcome=_clean(outcome), validation=validation,
                evidence={"kind": "request", "ref": ref[:256], "resolved_state": resolved},
                agent_id=agent_id, agent_name=agent_name)
        out = {"success": True, "hypothesis_id": hid, "verdict": verdict,
               "result_status": result_status, "test_intent": intent,
               "reference_actor": ref_actor, "comparison_actor": cmp_actor,
               "intended_actor": ref_actor, "outcome": outcome, "next_action": validation}
        if extra:
            out.update(extra)
        return out

    # 1) Explicit test subject — missing pieces are actionable, never guessed.
    if hypothesis is None:
        return {"success": False, "error": f"no hypothesis {hypothesis_id!r}"}
    if hypothesis.get("vuln_category") not in _AUTHZ_CATEGORIES:
        return {"success": False,
                "error": f"hypothesis {hid} category must be one of {_AUTHZ_CATEGORIES}"}
    if not ref:
        return {"success": False, "error": "request_ref is required (a captured proxy request)"}
    if intent not in (TEST_HORIZONTAL, TEST_VERTICAL):
        return {"success": False, "error": "test_intent must be 'horizontal' or 'vertical'"}
    if not ref_actor or not cmp_actor:
        return {"success": False, "error": "reference_actor and comparison_actor are required"}
    if ref_actor.lower() == cmp_actor.lower():
        return _result(STATUS_BLOCKED, VERDICT_INSUFFICIENT,
                       "reference and comparison actors are the same — not a boundary test",
                       "pick two distinct provisioned actors")
    if not resource_marker.strip():
        return _result(STATUS_BLOCKED, VERDICT_INSUFFICIENT,
                       "no resource_marker (semantic identity evidence) supplied",
                       "supply a string that uniquely identifies the reference actor's protected "
                       "resource/result, so authorized access can be told from a generic page")
    if intent == TEST_HORIZONTAL and not ownership_assertion.strip():
        return _result(STATUS_BLOCKED, VERDICT_INSUFFICIENT,
                       "horizontal test needs ownership evidence that the reference actor owns "
                       "this resource (an assertion with provenance, not an id guess)",
                       "provide ownership_assertion (e.g. 'actor-a created object 5001 during "
                       "provisioning'); ownership is treated as an assertion, not a fact")
    if intent == TEST_VERTICAL and not privilege_assertion.strip():
        return _result(STATUS_BLOCKED, VERDICT_INSUFFICIENT,
                       "vertical test needs an explicit expected privilege boundary (assertion "
                       "with provenance) — role names are not evidence",
                       "provide privilege_assertion (e.g. 'only admin may call this per operator "
                       "policy / observed permission matrix')")
    if operation_class.strip().lower() not in (_OP_READ, _OP_STATE_CHANGE):
        return _result(STATUS_BLOCKED, VERDICT_INSUFFICIENT,
                       "operation_class is required — classify the operation's side-effect "
                       "profile ('read' or 'state_change'); the HTTP method alone does not prove "
                       "the absence of side effects",
                       "set operation_class='read' for a true read, or 'state_change' (which is "
                       "deferred to manual follow-up in this slice)")
    if anonymous_expectation.strip().lower() not in _ANON_EXPECT:
        return _result(STATUS_BLOCKED, VERDICT_INSUFFICIENT,
                       f"anonymous_expectation must be one of {_ANON_EXPECT}",
                       "state the policy: does anonymous access to this resource get denied, "
                       "allowed, or is it unknown?")

    # 2) Resolve BOTH actors' complete sessions — never merged.
    cmp_headers, cmp_diag = _actor_headers(accounts_text, cmp_actor)
    if not cmp_headers:
        return _result(STATUS_BLOCKED, VERDICT_INSUFFICIENT,
                       f"no usable provisioned session for comparison actor {cmp_actor!r}: "
                       f"{'; '.join(cmp_diag)}",
                       "provision the comparison actor (account_provisioning) and record its "
                       "session in auth_accounts.jsonl, then retry", resolved=RESOLVED_MISSING)

    retrieve_fn = retrieve or _default_retrieve
    replay_fn = replay or _default_replay

    # 3) Retrieve (no traffic) + scope + unsupported-auth guard.
    try:
        got = await retrieve_fn(_strip_scheme(ref))
    except Exception:  # noqa: BLE001
        return _result(STATUS_BLOCKED, VERDICT_BLOCKED, "proxy unavailable; could not retrieve "
                       "the stored request", "capture the request and retry",
                       resolved=RESOLVED_MISSING)
    if not got or not got.get("found") or not got.get("raw"):
        return _result(STATUS_BLOCKED, VERDICT_INSUFFICIENT, "stored request not found",
                       "capture the request in the proxy and attach its id, then retry",
                       resolved=RESOLVED_MISSING)
    url = str(got.get("url") or "")
    method = str(got.get("method", "GET")).upper()
    in_scope, scope_reason = _scope_check(url, scan_targets)
    if not in_scope:
        return _result(STATUS_BLOCKED, VERDICT_BLOCKED,
                       f"destination not in operator scope: {scope_reason}; not testing",
                       "confirm host/port/path authorization with the operator",
                       {"in_scope": False})
    raw = str(got["raw"])
    unsupported = _unsupported_auth(raw)
    if unsupported:
        return _result(STATUS_BLOCKED, VERDICT_BLOCKED, unsupported,
                       "rebuild the request for the comparison actor manually, or hand off to a "
                       "session-aware workflow; do not send an actor-a-signed request as actor-b")

    # 4) Read-only boundary. A state-changing method, OR an operation the agent
    #    classified state_change, is ALWAYS deferred to manual follow-up in this
    #    slice — operator_test_object / verification_plan are free text and do NOT
    #    constitute executable verification or cleanup, so a mutation is never
    #    sent just because they are present.
    effective_op = _effective_op_class(method, operation_class)
    if effective_op == _OP_STATE_CHANGE:
        why = ("HTTP method is state-changing" if method in _STATE_CHANGING
               else "operation classified state_change")
        extra_note = (" (operator_test_object/verification_plan are recorded but do not authorize "
                      "an automated mutation in this slice)") if operator_test_object else ""
        return _result(STATUS_BLOCKED, VERDICT_INSUFFICIENT,
                       f"state-changing operation ({why}, {method}) is deferred to MANUAL "
                       f"follow-up — not executed{extra_note}",
                       "a human must perform and verify/clean up any state-changing authorization "
                       "test on an operator-authorized object; this executor is read-only here")

    # 5) Reflected-marker guard: a marker echoed in the request cannot prove
    #    protected-resource access (it would be an echo, not authorized data).
    if _reflected(resource_marker, raw):
        return _result(STATUS_BLOCKED, VERDICT_INSUFFICIENT,
                       "resource_marker is reflected in the request itself — it cannot distinguish "
                       "authorized access from an echo",
                       "use a response-only, resource-specific marker (e.g. a stored field value "
                       "that does not appear in the request)")

    # 6) Distinct principals — different actor_ref labels are NOT enough. Require
    #    either differing application-identity markers, or (fallback) differing
    #    credential contexts. Identical credential contexts are rejected WITHOUT
    #    exposing the credentials (compared by one-way hash).
    ref_ctx = _auth_context_hash(_captured_auth_headers(raw))
    cmp_ctx = _auth_context_hash(cmp_headers)
    ref_m = reference_identity_marker.strip()
    cmp_m = comparison_identity_marker.strip()
    markers_distinct = bool(ref_m and cmp_m and ref_m != cmp_m)
    contexts_distinct = bool(ref_ctx and cmp_ctx and ref_ctx != cmp_ctx)
    if ref_ctx and cmp_ctx and ref_ctx == cmp_ctx:
        return _result(STATUS_BLOCKED, VERDICT_INSUFFICIENT,
                       "reference and comparison actors share the SAME credential context "
                       "(identical session) — not a two-principal boundary test",
                       "use two genuinely distinct provisioned sessions")
    if not markers_distinct and not contexts_distinct:
        return _result(STATUS_BLOCKED, VERDICT_INSUFFICIENT,
                       "could not establish that the two actors are distinct authenticated "
                       "principals (no distinguishing identity markers, and credential contexts "
                       "are not both present/different)",
                       "provide reference_identity_marker and comparison_identity_marker (app "
                       "identity evidence), or ensure each actor has its own distinct session")
    # Identity distinctness is NEVER machine-verified here. Markers are agent-
    # supplied assertions; a differing credential-context hash is only a weak
    # signal (two sessions of the SAME account also differ by hash). Carried so a
    # bypass is capped at needs_validation with the real-principal check deferred.
    identity_confidence = "asserted_markers" if markers_distinct else "weak_hash"
    identity_evidence = {
        "distinct_by": ("agent_asserted_identity_markers" if markers_distinct
                        else "credential_context_hash"),
        "machine_verified": False,
        "identity_confidence": identity_confidence,
        "note": ("identity markers are AGENT-SUPPLIED assertions, not machine-verified"
                 if markers_distinct else
                 "only a credential-context hash differs; two sessions of the SAME account also "
                 "differ by hash — this does NOT prove two distinct principals"),
        "reference_context_hash": ref_ctx, "comparison_context_hash": cmp_ctx,
    }
    ownership_provenance = {
        "source": ("operator_assertion" if intent == TEST_HORIZONTAL
                   else "operator_policy_assertion"),
        "value": _clean(ownership_assertion or privilege_assertion),
        "machine_established": False,
    }

    # Reserve a cumulative attempt slot (shared budget with #4, per hypothesis).
    reservation = reserve_attempt(hid, tool="authorization_replay", max_attempts=_MAX_ATTEMPTS)
    if not reservation.get("reserved"):
        return _result(STATUS_BLOCKED, VERDICT_BLOCKED,
                       f"attempt budget exhausted ({reservation.get('used')}/"
                       f"{reservation.get('max')} used this run)",
                       "escalate to manual review or deliberately raise the budget",
                       {"attempt_budget": {"used": reservation.get("used"),
                                           "max": reservation.get("max"), "remaining": 0}})
    rid = str(reservation["reservation_id"])
    dispatch = {"on": False}  # set True by _execute just before the first request
    try:
        return await _execute(
            hid=hid, ref=ref, intent=intent, ref_actor=ref_actor, cmp_actor=cmp_actor,
            cmp_headers=cmp_headers, resource_marker=resource_marker, denied_marker=denied_marker,
            comparison_own_ref=comparison_own_ref,
            comparison_identity_marker=comparison_identity_marker,
            anonymous_expectation=anonymous_expectation.strip().lower(),
            identity_evidence=identity_evidence, identity_confidence=identity_confidence,
            ownership_provenance=ownership_provenance,
            retrieve_fn=retrieve_fn, scan_targets=scan_targets, replay_fn=replay_fn, rid=rid,
            dispatch=dispatch, rationale=rationale, _result=_result,
            agent_id=agent_id, agent_name=agent_name,
        )
    except asyncio.CancelledError:
        # Cancel BEFORE dispatch releases the slot; cancel AFTER dispatch (traffic
        # may have been sent) CONSUMES it — never a refund.
        settle_attempt(hid, rid, state=SLOT_FAILED if dispatch["on"] else SLOT_CANCELLED)
        _record(hypothesis_id=hid, result_status=STATUS_BLOCKED, verdict=VERDICT_BLOCKED,
                rationale=rationale,
                outcome=("authorization replay cancelled after dispatch; attempt consumed"
                         if dispatch["on"] else "authorization replay cancelled before dispatch; "
                         "reservation released"),
                validation="re-run the targeted authorization test",
                evidence={"kind": "request", "ref": ref[:256], "resolved_state": RESOLVED},
                agent_id=agent_id, agent_name=agent_name)
        raise
    except Exception:  # noqa: BLE001
        settle_attempt(hid, rid, state=SLOT_FAILED)
        return _result(STATUS_BLOCKED, VERDICT_BLOCKED, "authorization replay failed unexpectedly",
                       "retry once; if it persists, escalate to manual review")


async def _execute(  # noqa: PLR0911, PLR0915
    *, hid: str, ref: str, intent: str, ref_actor: str, cmp_actor: str,
    cmp_headers: dict[str, str], resource_marker: str, denied_marker: str,
    comparison_own_ref: str, comparison_identity_marker: str, anonymous_expectation: str,
    identity_evidence: dict[str, Any], identity_confidence: str,
    ownership_provenance: dict[str, Any],
    retrieve_fn: Any, scan_targets: list[str] | None, replay_fn: Any, rid: str,
    dispatch: dict[str, bool], rationale: str, _result: Any,
    agent_id: str | None, agent_name: str | None,
) -> dict[str, Any]:
    controls: list[dict[str, Any]] = []

    # Persist dispatch BEFORE any traffic: from here a cancel consumes the attempt.
    mark_dispatched(hid, rid)
    dispatch["on"] = True

    # Baseline — reference actor replays as captured. This proves ACCESSIBILITY
    # only (the actor can reach the resource) — NOT ownership; ownership is an
    # operator assertion carried in ownership_provenance.
    base = await replay_fn(_strip_scheme(ref), None)
    base_meta = _meta_of(base)
    if not base.get("replayed"):
        settle_attempt(hid, rid, state=SLOT_FAILED)
        return _result(STATUS_BLOCKED, VERDICT_INVALID_SESSION,
                       "baseline replay as the reference actor did not succeed — not a finding",
                       "re-verify connectivity/session and recapture, then retry",
                       resolved=RESOLVED_STALE)
    base_status_code = base_meta.get("status")
    if base_status_code == 429 or base_meta.get("challenge_indicators") or (
        base_status_code is not None and base_status_code >= 502
    ):
        category, confidence, reasons = _classify_block(base_meta, "")
        settle_attempt(hid, rid, state=SLOT_COMPLETED)
        return _result(STATUS_BLOCKED, VERDICT_BLOCKED,
                       f"reference baseline is blocked (classified {category}, {confidence}) — "
                       "cannot measure the authorization boundary now",
                       "resolve the block (session/rate/challenge) and retry; do not attempt a "
                       "WAF bypass while measuring authorization",
                       {"block_classification": {"category": category, "confidence": confidence,
                                                  "reasons": reasons}, "controls": controls})
    if not _has_resource(base_meta, base.get("body", ""), resource_marker):
        settle_attempt(hid, rid, state=SLOT_COMPLETED)
        base_body = base.get("body", "")
        # A missing marker is only a SESSION LOSS when there is INDEPENDENT
        # authentication-loss evidence (a login page/redirect, or a 401). A 403 is
        # authorization, not authentication, and a 2xx page without the marker may
        # simply mean the marker is wrong or the content changed — neither proves
        # an expired session, so both stay inconclusive (baseline_unverified).
        if _auth_loss_evidence(base_body, base_meta):
            return _result(STATUS_BLOCKED, VERDICT_INVALID_SESSION,
                           "the reference actor's baseline returned explicit authentication-loss "
                           "evidence (login page / 401) instead of the resource — session invalid",
                           "re-provision the reference session, then retry",
                           {"controls": controls}, resolved=RESOLVED_STALE)
        is_2xx = base_status_code is not None and 200 <= base_status_code < 300
        detail = ("returned 2xx but WITHOUT the resource_marker"
                  if is_2xx else
                  f"returned status {base_status_code} (authorization/other, NOT an "
                  "authentication challenge)")
        return _result(STATUS_BLOCKED, VERDICT_BASELINE_UNVERIFIED,
                       f"the reference baseline {detail} and showed no authentication-loss "
                       "evidence — a 403 is authorization not a session loss, and a missing marker "
                       "may just be wrong; inconclusive, not a proven session loss",
                       "verify/correct resource_marker against the reference actor's real "
                       "response, or re-provision the session if it is genuinely expired, "
                       "then retry",
                       {"controls": controls})

    # Control: anonymous — observed, and compared to the stated policy expectation.
    anon = await replay_fn(_strip_scheme(ref), {})
    anon_meta = _meta_of(anon)
    anon_denied = _is_denied(anon_meta, anon.get("body", ""), denied_marker) \
        or not _has_resource(anon_meta, anon.get("body", ""), resource_marker)
    controls.append({"control": "anonymous", "status": anon_meta.get("status"),
                     "denied": anon_denied, "policy_expectation": anonymous_expectation})

    # Control: comparison actor's OWN object — scope-checked separately, and it
    # must identify the COMPARISON actor (its own marker), never actor-a's. The
    # outcome is TRI-STATE: 'verified' (session proven valid), 'session_dead'
    # (explicit auth-loss evidence), or 'inconclusive' (the control failed for a
    # NON-auth reason — 404/5xx/timeout/missing marker — which does NOT prove the
    # session is invalid). Only 'session_dead' establishes session loss.
    cmp_own_state: str | None = None  # None = control not run
    if comparison_own_ref.strip():
        own_url = ""
        with contextlib.suppress(Exception):
            own_got = await retrieve_fn(_strip_scheme(comparison_own_ref))
            own_url = str((own_got or {}).get("url") or "")
        own_in_scope, _own_reason = _scope_check(own_url, scan_targets) if own_url else (False, "")
        if not own_in_scope:
            controls.append({"control": "comparison_own_object", "skipped": "out_of_scope"})
        else:
            own = await replay_fn(_strip_scheme(comparison_own_ref), cmp_headers)
            own_meta = _meta_of(own)
            own_body = own.get("body", "")
            own_status = own_meta.get("status")
            marker_ok = (not comparison_identity_marker.strip()
                         or comparison_identity_marker.lower()
                         in own_body[:_BODY_SCAN_CAP].lower())
            if (bool(own.get("replayed")) and own_status is not None
                    and 200 <= own_status < 300
                    and not _looks_like_login(own_body, own_meta) and marker_ok):
                cmp_own_state = "verified"
            elif _auth_loss_evidence(own_body, own_meta):
                cmp_own_state = "session_dead"
            else:
                cmp_own_state = "inconclusive"
            controls.append({"control": "comparison_own_object", "status": own_status,
                             "result": cmp_own_state,
                             "identity_confirmed": bool(comparison_identity_marker.strip())
                             and marker_ok})

    # The test — comparison actor replays the SAME concrete resource/operation.
    test = await replay_fn(_strip_scheme(ref), cmp_headers)
    test_meta = _meta_of(test)
    test_body = test.get("body", "")
    test_truncated = bool(test.get("body_truncated"))
    if not test.get("replayed"):
        settle_attempt(hid, rid, state=SLOT_FAILED)
        return _result(STATUS_BLOCKED, VERDICT_UNSTABLE,
                       "comparison actor replay did not complete — inconclusive",
                       "re-establish a stable baseline and retry", {"controls": controls})
    # Session loss is only established by EXPLICIT auth-loss evidence: a login
    # page on the tested resource, or the own-object control returning auth-loss
    # (session_dead). An own-object control that merely failed for a non-auth
    # reason (inconclusive) is NOT a session loss — it leaves validity unproven,
    # handled downstream (a denial with an unproven session is inconclusive).
    test_is_login = _looks_like_login(test_body, test_meta)
    if test_is_login or cmp_own_state == "session_dead":
        settle_attempt(hid, rid, state=SLOT_COMPLETED)
        why = ("the tested resource returned a login page" if test_is_login
               else "the comparison actor's own-object control returned auth-loss evidence "
                    "(login page / 401)")
        return _result(STATUS_BLOCKED, VERDICT_INVALID_SESSION,
                       f"comparison actor {cmp_actor!r} session is invalid: {why} — cannot "
                       "conclude an authorization boundary",
                       "re-provision the comparison actor's session, then retry",
                       {"controls": controls}, resolved=RESOLVED_STALE)

    comparison_denied = _is_denied(test_meta, test_body, denied_marker)
    comparison_got_resource = _has_resource(test_meta, test_body, resource_marker)
    # A denial STATUS alone — especially a bare 403 — does not establish an
    # APPLICATION-level authorization decision: it can originate from a WAF or an
    # intermediary just as easily as from the app's access control. The
    # independent control that establishes app intent is a caller-supplied
    # denied_marker matched in the body; WAF/challenge fingerprints are positive
    # evidence the denial is NOT the application's. Without app-level evidence the
    # meaning of the denial is preserved as uncertain, never a clean verdict.
    comparison_waf_suspected = bool(test_meta.get("challenge_indicators"))
    denial_app_established = bool(
        denied_marker.strip()
        and denied_marker.lower() in test_body[:_BODY_SCAN_CAP].lower()
        and not comparison_waf_suspected
    )

    # POST re-check (auth freshness): re-replay the reference and confirm its
    # session still returns the resource. If not, the environment changed mid-
    # test and any verdict is uncertain -> downgrade.
    post = await replay_fn(_strip_scheme(ref), None)
    post_meta = _meta_of(post)
    session_lost = not (post.get("replayed") and _has_resource(post_meta, post.get("body", ""),
                                                               resource_marker))
    controls.append({"control": "reference_recheck", "status": post_meta.get("status"),
                     "still_valid": not session_lost})

    # The comparison session is only PROVEN valid when its own-object control
    # passed ('verified'). Absent the control, or when it was inconclusive, its
    # validity is unproven — a denial could be a real authz decision OR an
    # invalid/expired session (never silently treated as either).
    comparison_session_verified = cmp_own_state == "verified"
    semantic = {
        "reference_accessibility": True,
        "reference_accessibility_note": ("proves the reference actor can access content matching "
                                         "the marker — NOT proof of ownership"),
        "reference_ownership": ownership_provenance,  # assertion, NOT machine-established
        "comparison_session_state": cmp_own_state or "control_not_run",
        "identity_evidence": identity_evidence,
        "comparison_got_resource": comparison_got_resource,
        "comparison_denied": comparison_denied,
        "comparison_denial_app_established": denial_app_established,
        "comparison_waf_suspected": comparison_waf_suspected,
        "comparison_session_verified": comparison_session_verified,
        "anonymous_denied": anon_denied,
        "anonymous_expectation": anonymous_expectation,
        "comparison_body_truncated": test_truncated,
        "resource_marker_provenance": "caller-supplied, response-only, resource-specific assertion",
        "fingerprints": {"reference": base_meta.get("body_fingerprint"),
                         "comparison": test_meta.get("body_fingerprint"),
                         "anonymous": anon_meta.get("body_fingerprint")},
    }
    base_status = _sanitized_authz(base_meta, test_meta, anon_meta, controls, semantic)
    settle = settle_attempt(hid, rid, state=SLOT_COMPLETED)
    budget = {"used": settle.get("used"), "max": settle.get("max"),
              "remaining": settle.get("remaining")}

    verdict, status, outcome, validation = _verdict(
        cmp_actor=cmp_actor, session_lost=session_lost, comparison_denied=comparison_denied,
        comparison_got_resource=comparison_got_resource, anon_denied=anon_denied,
        anonymous_expectation=anonymous_expectation, test_truncated=test_truncated,
        comparison_session_verified=comparison_session_verified,
        denial_app_established=denial_app_established, waf_suspected=comparison_waf_suspected,
        identity_confidence=identity_confidence,
    )
    out = _result(status, verdict, outcome, validation, base_status)
    out["semantic"] = semantic
    out["attempt_budget"] = budget
    out["session_lost"] = session_lost
    return out


def _identity_caveat(identity_confidence: str) -> str:
    if identity_confidence == "asserted_markers":
        return (" Identity distinctness rests on AGENT-SUPPLIED markers (not machine-verified) — "
                "confirm the two actors are genuinely different principals during validation.")
    return (" Identity distinctness rests only on a differing credential-context hash, which does "
            "NOT prove two distinct principals (two sessions of the SAME account differ too) — "
            "confirm genuinely different principals during validation.")


def _verdict(  # noqa: PLR0911
    *, cmp_actor: str, session_lost: bool, comparison_denied: bool,
    comparison_got_resource: bool, anon_denied: bool, anonymous_expectation: str,
    test_truncated: bool, comparison_session_verified: bool,
    denial_app_established: bool, waf_suspected: bool, identity_confidence: str,
) -> tuple[str, str, str, str]:
    if session_lost:
        return (VERDICT_UNSTABLE, STATUS_BLOCKED,
                ("the reference session no longer returned the resource after testing — the "
                 "environment changed mid-test; results are uncertain and discarded"),
                "re-provision/re-verify sessions and re-run; retained as follow-up")
    if comparison_denied:
        if not comparison_session_verified:
            # A denial from an invalid/expired comparison session is
            # indistinguishable from a real authorization denial. Without a
            # passing own-object control we must NOT report a clean denial — that
            # would be a false negative hiding a real bypass.
            return (VERDICT_INSUFFICIENT, STATUS_BLOCKED,
                    (f"comparison actor {cmp_actor!r} was denied, but its session validity was NOT "
                     "independently confirmed (no passing own-object control) — a denial from an "
                     "invalid/expired session is indistinguishable from a real authorization "
                     "denial; inconclusive, not a safe result"),
                    ("supply comparison_own_ref (+comparison_identity_marker) so the comparison "
                     "session is proven valid, then retry"))
        if not denial_app_established:
            # Session is valid, but a bare denial status (esp. 403) does not prove
            # the APPLICATION made an authorization decision — a WAF or an
            # intermediary can return the same. Preserve uncertainty.
            waf_note = (" WAF/challenge fingerprints are present, so the denial is most likely an "
                        "intermediary, not the app." if waf_suspected else
                        " It may originate from the app, a WAF, or an intermediary.")
            return (VERDICT_INSUFFICIENT, STATUS_BLOCKED,
                    (f"comparison actor {cmp_actor!r} received a denial status (e.g. 403) with a "
                     "valid session, but no independent evidence that it is the APPLICATION's "
                     f"authorization decision.{waf_note} A bare status alone is not an "
                     "application-level denial — the meaning is uncertain"),
                    ("supply a denied_marker that identifies the application's own authorization-"
                     "denied response (or otherwise establish the denial source), then retry"))
        return (VERDICT_DENIED, STATUS_TESTING,
                (f"comparison actor {cmp_actor!r} was denied (session proven valid by the "
                 "own-object control AND an application-level denial marker confirms the app "
                 "itself denied this actor) — correct authorization for THIS actor/resource/"
                 "operation (does not close siblings or the class)"),
                "negative applies only to this actor/resource/operation")
    if comparison_got_resource:
        if anon_denied:
            return (VERDICT_BYPASS, STATUS_NEEDS_VALIDATION,
                    (f"comparison actor {cmp_actor!r} obtained the reference actor's resource "
                     "(resource-specific marker present, 2xx, not login/generic) while anonymous "
                     "access was denied — the endpoint IS auth-gated"),
                    ("needs_validation: manually reproduce and confirm the body is the other "
                     "actor's PRIVATE data (not shared/public); NEVER auto-confirmed."
                     + _identity_caveat(identity_confidence)))
        if anonymous_expectation == "allow":
            return (VERDICT_EXPECTED_PUBLIC, STATUS_TESTING,
                    ("anonymous access is permitted by policy and the resource is reachable "
                     "anonymously — expected public access, no cross-actor READ boundary to "
                     "violate here"),
                    ("scoped to this resource/actor only. NOTE: this only establishes the MARKED "
                     "resource is public; it does NOT verify that confidential fields are absent "
                     "from the anonymous response — audit field-level exposure to anonymous "
                     "separately"))
        extra = (" NOTE: anonymous access contradicts the stated 'deny' expectation — investigate "
                 "an anonymous authorization bypass separately."
                 if anonymous_expectation == "deny" else
                 " Set anonymous_expectation explicitly to disambiguate.")
        return (VERDICT_DENIED, STATUS_TESTING,
                "the resource is reachable anonymously too — not a cross-actor leak." + extra,
                "scoped to this resource/actor only")
    if test_truncated:
        return (VERDICT_INSUFFICIENT, STATUS_BLOCKED,
                ("the comparison response was truncated before the resource marker could be "
                 "confirmed — inconclusive, not a denial"),
                "raise the capture size or use a shorter/earlier resource marker, then retry")
    return (VERDICT_INSUFFICIENT, STATUS_BLOCKED,
            ("comparison response neither clearly returned the resource nor clearly denied it "
             "(no semantic match, no denial signal) — inconclusive"),
            "gather a sharper resource_marker / denied_marker and retry")


def _sanitized_authz(base_meta: dict[str, Any], test_meta: dict[str, Any],
                     anon_meta: dict[str, Any], controls: list[dict[str, Any]],
                     semantic: dict[str, Any]) -> dict[str, Any]:
    """Sanitized evidence bundle — statuses, structural fingerprints, booleans
    and provenance, controls. No raw bodies / credentials / object contents."""
    return {
        "baseline": {k: base_meta.get(k) for k in ("status", "body_fingerprint", "timing_ms")},
        "comparison": {k: test_meta.get(k) for k in ("status", "body_fingerprint", "timing_ms")},
        "anonymous_control": {k: anon_meta.get(k) for k in ("status", "body_fingerprint")},
        "controls": controls[:_DIAG_MAX],
    }


# --------------------------------------------------------------------------- #
# Agent tool
# --------------------------------------------------------------------------- #


def _caller(ctx: RunContextWrapper) -> dict[str, Any]:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    raw_agent_id = inner.get("agent_id")
    agent_id = raw_agent_id if isinstance(raw_agent_id, str) else None
    agent_name: str | None = None
    coordinator = inner.get("coordinator")
    if agent_id is not None and coordinator is not None:
        names = getattr(coordinator, "names", {})
        if isinstance(names, dict):
            raw = names.get(agent_id)
            agent_name = raw if isinstance(raw, str) else None
    return {
        "agent_id": agent_id, "agent_name": agent_name,
        "session": inner.get("sandbox_session"),
        "scan_targets": inner.get("scan_targets"),
        "retrieve": inner.get("authz_retrieve"),
        "replay": inner.get("authz_replay"),
        "accounts_text": inner.get("authz_accounts_text"),
    }


async def _read_accounts(transport: CrawlTransport, workdir: str, job: str) -> str:
    text, _ = await _read_capped(transport, _DEFAULT_ACCOUNTS_PATH, 2_000_000, workdir, job)
    return text


@function_tool(timeout=300)
async def run_authorization_test(
    ctx: RunContextWrapper,
    hypothesis_id: str,
    request_ref: str,
    reference_actor: str,
    comparison_actor: str,
    test_intent: str,
    resource_marker: str,
    operation_class: str,
    ownership_assertion: str = "",
    privilege_assertion: str = "",
    anonymous_expectation: str = "deny",
    reference_identity_marker: str = "",
    comparison_identity_marker: str = "",
    denied_marker: str = "",
    comparison_own_ref: str = "",
    operator_test_object: bool = False,
    verification_plan: str = "",
) -> str:
    """Replay a captured request as a different actor to test an authorization boundary.

    Explicitly invoked for one IDOR/BOLA/BFLA hypothesis — NOT an automatic
    scanner and NOT object enumeration. It resolves each actor's COMPLETE session
    (never merging actor-a and actor-b credentials), validates operator scope
    before any request, baselines the reference actor, runs anonymous/own-object
    controls, replays the SAME concrete resource/operation as the comparison
    actor, and compares real semantic evidence (a resource_marker identifying the
    protected content) — not status or length alone.

    Verdicts: potential_authorization_bypass (needs_validation, never auto-
    confirmed), denied_this_test (scoped to this actor/resource only — never
    closes siblings/the class; a CLEAN denial requires a passing own-object
    control proving the comparison session is valid, else the result is
    inconclusive to avoid a false negative), expected_public_access (anonymous
    access permitted by policy — neutral, not a denial), baseline_unverified
    (reference baseline returned 2xx without the marker and no auth-loss signal —
    inconclusive, not a proven session loss), insufficient_evidence,
    invalid_session, blocked, unstable_result. Two actors receiving the same
    denial is never a leak; a failed baseline is never a vulnerability; a login/
    generic page is not authorized access. Identity distinctness is never
    machine-verified (markers are agent assertions; a differing credential hash is
    a weak signal) — a bypass stays needs_validation with the principal check
    deferred. Ownership/privilege inputs are ASSERTIONS with provenance,
    not facts. State-changing vertical tests need an operator-authorized test
    object + a safe verification plan or they are deferred to manual follow-up.

    Args:
        hypothesis_id: An `idor` or `broken_function_level_authorization` id.
        request_ref: The captured proxy request of the reference actor accessing
            the resource/operation.
        reference_actor: The actor who legitimately accesses it (its session is
            the captured one).
        comparison_actor: A DISTINCT actor who should NOT have access.
        test_intent: `horizontal` (cross-object/BOLA) or `vertical` (privilege/
            BFLA).
        resource_marker: A string uniquely identifying the reference actor's
            protected resource/result (the semantic identity evidence).
        operation_class: REQUIRED — `read` or `state_change`. A state-changing
            method (POST/PUT/PATCH/DELETE) is always treated as `state_change` and
            is DEFERRED to manual follow-up; only a `read` is executed. The HTTP
            method alone does not prove the absence of side effects, so classify
            explicitly.
        ownership_assertion: Horizontal — evidence/provenance that the reference
            actor owns this resource (an assertion, e.g. "created at provisioning").
            The reference baseline proves accessibility only, not ownership.
        privilege_assertion: Vertical — the explicit expected privilege boundary
            and its provenance (provisioning / operator policy / observed matrix).
        anonymous_expectation: `deny` (default), `allow`, or `unknown` — the
            policy for anonymous access, so an anonymous success is interpreted
            against an explicit expectation rather than assumed.
        reference_identity_marker / comparison_identity_marker: application
            identity evidence (e.g. each actor's own username in its responses)
            proving the two actors are DISTINCT principals — labels alone are not
            enough. If absent, distinctness falls back to differing credential
            contexts.
        denied_marker: Optional string that marks a denial/error body.
        comparison_own_ref: Optional captured request id of the comparison
            actor's OWN object — a scope-checked control proving its session is
            valid and (with comparison_identity_marker) identifies that actor.
        operator_test_object / verification_plan: recorded only; they do NOT
            authorize an automated mutation — state-changing tests are deferred.
    """
    ident = _caller(ctx)
    accounts_text = ident["accounts_text"]
    if accounts_text is None:
        if ident["session"] is None:
            return json.dumps({"success": False, "error": "no sandbox session available"})
        with contextlib.suppress(Exception):
            accounts_text = await _read_accounts(
                ident["session"], "/workspace/.authz", f"authz_{uuid.uuid4().hex[:8]}"
            )
    result = await _run_authz_impl(
        hypothesis_id=hypothesis_id, request_ref=request_ref, reference_actor=reference_actor,
        comparison_actor=comparison_actor, test_intent=test_intent,
        resource_marker=resource_marker, operation_class=operation_class,
        ownership_assertion=ownership_assertion, privilege_assertion=privilege_assertion,
        anonymous_expectation=anonymous_expectation,
        reference_identity_marker=reference_identity_marker,
        comparison_identity_marker=comparison_identity_marker, denied_marker=denied_marker,
        comparison_own_ref=comparison_own_ref, operator_test_object=operator_test_object,
        verification_plan=verification_plan, accounts_text=accounts_text or "",
        retrieve=ident["retrieve"] if callable(ident["retrieve"]) else None,
        replay=ident["replay"] if callable(ident["replay"]) else None,
        scan_targets=ident["scan_targets"], agent_id=ident["agent_id"],
        agent_name=ident["agent_name"],
    )
    record_activity_tick(ident["agent_id"])
    return json.dumps(result, ensure_ascii=False, default=str)
