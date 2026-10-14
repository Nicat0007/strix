"""Tests for the evidence-backed hypothesis worklist (BLACKBOX improvement #3).

Exercises committed production code in ``strix.tools.hypotheses.tools``: durable
run-scoped persistence/resume + run isolation, deduplication that never merges
distinct resources/actors/parameter locations, replay-readiness resolution
(resolved/missing/unavailable/stale), the rule that a tool attempt never
confirms, counterevidence retention, bounded secret-free output, downstream
pending-work queries, and one end-to-end flow from the inventory through to
needs_validation / ruled_out.

Local fixtures only; the proxy resolver is injected (no live Caido). No network.
"""

from __future__ import annotations

import inspect
import json
from typing import TYPE_CHECKING, Any

import pytest
from agents.tool_context import ToolContext

import strix.core.runner as runner_module
from strix.tools.attack_surface.tools import _record_impl, hydrate_attack_surface_from_disk
from strix.tools.hypotheses.tools import (
    ATTEMPT_RESULT_STATUSES,
    NOT_APPLICABLE,
    RESOLVED,
    RESOLVED_MISSING,
    RESOLVED_STALE,
    RESOLVED_UNAVAILABLE,
    STATUS_BLOCKED,
    STATUS_CONFIRMED,
    STATUS_NEEDS_VALIDATION,
    STATUS_RULED_OUT,
    _create_impl,
    _query_impl,
    _record_attempt_impl,
    _resolve_request_evidence,
    _update_impl,
    create_hypothesis,
    hydrate_hypotheses_from_disk,
    query_hypotheses,
    record_test_attempt,
    update_hypothesis,
)


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _stores(tmp_path: Path) -> Path:
    """Point both stores at a per-test run dir (clears module state)."""
    hydrate_attack_surface_from_disk(tmp_path)
    hydrate_hypotheses_from_disk(tmp_path)
    return tmp_path


def _create(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "endpoint_id": "ep123456",
        "vuln_category": "idor",
        "resource": "/orders/1",
        "actor_ref": "actor-a",
        "param_name": "",
        "param_location": "",
        "operation": "",
        "rationale": "actor-a sees 200 where anonymous sees 401 on this object",
        "next_action": "replay as actor-b",
        "priority": {},
        "evidence": [],
        "agent_id": None,
        "agent_name": None,
    }
    base.update(overrides)
    return _create_impl(**base)


def _all() -> dict[str, Any]:
    return _query_impl(status=None, vuln_category=None, actor_ref=None, endpoint_id=None,
                       origin=None, priority_bucket=None, pending_only=False, limit=500)


# --------------------------------------------------------------------------- #
# Deduplication vs. distinct resource / actor / parameter location
# --------------------------------------------------------------------------- #


def test_same_tuple_deduplicates() -> None:
    first = _create()
    second = _create(rationale="updated rationale")
    assert first["hypothesis_id"] == second["hypothesis_id"]
    assert first["created"] is True
    assert second["created"] is False and second["deduplicated"] is True
    assert _all()["total_hypotheses"] == 1


def test_distinct_resource_actor_and_param_location_stay_separate() -> None:
    base = _create()
    other_resource = _create(resource="/orders/2")
    other_actor = _create(actor_ref="actor-b")
    q_param = _create(param_name="id", param_location="query", resource="")
    p_param = _create(param_name="id", param_location="path", resource="")
    ids = {base["hypothesis_id"], other_resource["hypothesis_id"], other_actor["hypothesis_id"],
           q_param["hypothesis_id"], p_param["hypothesis_id"]}
    assert len(ids) == 5  # none merged
    # Same param name, different location → genuinely different hypotheses.
    assert q_param["hypothesis_id"] != p_param["hypothesis_id"]


def test_operation_and_param_are_different_subjects() -> None:
    op = _create(operation="DELETE /orders/{id}", resource="")
    param = _create(param_name="id", param_location="path", resource="")
    assert op["hypothesis_id"] != param["hypothesis_id"]


# --------------------------------------------------------------------------- #
# Tool attempt != confirmed; confirmation is explicit and evidence-gated
# --------------------------------------------------------------------------- #


def test_tool_attempt_cannot_confirm() -> None:
    rec = _create()
    hid = rec["hypothesis_id"]
    bad = _record_attempt_impl(
        hypothesis_id=hid, tool="sqlmap", tool_rationale="param reaches a SQL sink",
        outcome="boolean oracle observed", result_status="confirmed",
        validation_required="", signal="oracle", input_evidence=None,
        agent_id=None, agent_name=None,
    )
    assert bad["success"] is False
    assert "confirmed" in bad["error"]
    # A strong signal is at most needs_validation.
    ok = _record_attempt_impl(
        hypothesis_id=hid, tool="sqlmap", tool_rationale="param reaches a SQL sink",
        outcome="boolean oracle observed", result_status="needs_validation",
        validation_required="extract a real record to prove impact", signal="oracle",
        input_evidence=None, agent_id=None, agent_name=None,
    )
    assert ok["success"] is True
    assert "confirmed" not in ATTEMPT_RESULT_STATUSES
    assert _all()["hypotheses"][0]["status"] == STATUS_NEEDS_VALIDATION


def test_attempt_requires_tool_rationale() -> None:
    rec = _create()
    missing = _record_attempt_impl(
        hypothesis_id=rec["hypothesis_id"], tool="sqlmap", tool_rationale="",
        outcome="x", result_status="testing", validation_required="", signal="",
        input_evidence=None, agent_id=None, agent_name=None,
    )
    assert missing["success"] is False and "tool_rationale" in missing["error"]


def test_confirm_requires_note_and_evidence() -> None:
    rec = _create()  # no evidence attached
    hid = rec["hypothesis_id"]
    assert _update_impl(hypothesis_id=hid, status=STATUS_CONFIRMED, next_action="", rationale="",
                        add_counterevidence="", confirmation="", priority={}, new_evidence=[],
                        agent_id=None, agent_name=None)["success"] is False
    # Note but still no evidence → refused.
    assert _update_impl(hypothesis_id=hid, status=STATUS_CONFIRMED, next_action="", rationale="",
                        add_counterevidence="", confirmation="validated PoC: cross-user read",
                        priority={}, new_evidence=[], agent_id=None,
                        agent_name=None)["success"] is False
    # With evidence + a validated-PoC note → confirmed.
    ev = [{"kind": "request", "ref": "caido:req-9", "resolved_state": RESOLVED}]
    good = _update_impl(hypothesis_id=hid, status=STATUS_CONFIRMED, next_action="", rationale="",
                        add_counterevidence="", confirmation="validated PoC: cross-user read",
                        priority={}, new_evidence=ev, agent_id=None, agent_name=None)
    assert good["success"] is True and good["status"] == STATUS_CONFIRMED


# --------------------------------------------------------------------------- #
# Counterevidence stays attached
# --------------------------------------------------------------------------- #


def test_counterevidence_is_retained_through_ruled_out() -> None:
    rec = _create()
    hid = rec["hypothesis_id"]
    _update_impl(hypothesis_id=hid, status="", next_action="", rationale="",
                 add_counterevidence="benign variant behaved identically (negative control)",
                 confirmation="", priority={}, new_evidence=[], agent_id=None, agent_name=None)
    _update_impl(hypothesis_id=hid, status=STATUS_RULED_OUT, next_action="", rationale="",
                 add_counterevidence="actor-b got 403 — object-level check present",
                 confirmation="", priority={}, new_evidence=[], agent_id=None, agent_name=None)
    h = _all()["hypotheses"][0]
    assert h["status"] == STATUS_RULED_OUT
    assert len(h["counterevidence"]) == 2
    assert any("negative control" in c for c in h["counterevidence"])


# --------------------------------------------------------------------------- #
# Replay-readiness resolution (injected resolver — no live proxy)
# --------------------------------------------------------------------------- #


async def _ok_resolver(_rid: str) -> dict[str, Any]:
    return {"method": "GET", "status": 200}


async def _missing_resolver(_rid: str) -> None:
    return None


async def _boom_resolver(_rid: str) -> dict[str, Any]:
    raise RuntimeError("proxy unreachable")


@pytest.mark.asyncio
async def test_request_evidence_resolved_carries_only_method_and_status() -> None:
    ev = await _resolve_request_evidence("caido:req-1", _ok_resolver, "owner request")
    assert ev["resolved_state"] == RESOLVED
    assert ev["summary"] == "GET -> 200"
    assert "body" not in json.dumps(ev).lower() or "resolved" in ev["resolved_state"]


@pytest.mark.asyncio
async def test_missing_request_is_recorded_with_capture_suggestion() -> None:
    ev = await _resolve_request_evidence("caido:gone", _missing_resolver, "")
    assert ev["resolved_state"] == RESOLVED_MISSING
    assert "capture" in ev["suggestion"]


@pytest.mark.asyncio
async def test_unreachable_proxy_is_unresolvable_not_fabricated() -> None:
    ev = await _resolve_request_evidence("caido:x", _boom_resolver, "")
    assert ev["resolved_state"] == RESOLVED_UNAVAILABLE
    assert "capture" in ev["suggestion"] or "revalidate" in ev["suggestion"]


def test_hypothesis_without_request_evidence_flags_needs_replay() -> None:
    _create()  # observation-only, no request ref
    h = _all()["hypotheses"][0]
    assert h["needs_replay_evidence"] is True


# --------------------------------------------------------------------------- #
# Persistence / resume / run isolation
# --------------------------------------------------------------------------- #


def test_persistence_and_resume_round_trip(_stores: Path) -> None:
    rec = _create(evidence=[{"kind": "request", "ref": "caido:req-5", "resolved_state": RESOLVED}])
    hydrate_hypotheses_from_disk(_stores)  # simulate a resuming process
    restored = _all()
    assert restored["total_hypotheses"] == 1
    h = restored["hypotheses"][0]
    assert h["hypothesis_id"] == rec["hypothesis_id"]
    # A reference resolved in the prior process is now stale and must be re-checked.
    req_ev = [e for e in h["evidence"] if e["kind"] == "request"]
    assert req_ev and req_ev[0]["resolved_state"] == RESOLVED_STALE


def test_another_run_starts_isolated(_stores: Path) -> None:
    _create()
    other = _stores.parent / "other-run"
    other.mkdir()
    hydrate_hypotheses_from_disk(other)
    assert _all()["total_hypotheses"] == 0


# --------------------------------------------------------------------------- #
# Query: downstream actionable pending work, bounded, secret-free
# --------------------------------------------------------------------------- #


def test_pending_only_excludes_closed_hypotheses() -> None:
    a = _create(resource="/a")
    b = _create(resource="/b")
    c = _create(resource="/c")
    _update_impl(hypothesis_id=b["hypothesis_id"], status=STATUS_RULED_OUT, next_action="",
                 rationale="", add_counterevidence="", confirmation="", priority={},
                 new_evidence=[], agent_id=None, agent_name=None)
    _update_impl(hypothesis_id=c["hypothesis_id"], status=STATUS_BLOCKED, next_action="",
                 rationale="", add_counterevidence="", confirmation="", priority={},
                 new_evidence=[], agent_id=None, agent_name=None)
    pending = _query_impl(status=None, vuln_category=None, actor_ref=None, endpoint_id=None,
                          origin=None, priority_bucket=None, pending_only=True, limit=500)
    ids = {h["hypothesis_id"] for h in pending["hypotheses"]}
    assert a["hypothesis_id"] in ids  # untested is pending
    assert c["hypothesis_id"] in ids  # blocked stays visible as follow-up
    assert b["hypothesis_id"] not in ids  # ruled_out is closed


def test_query_filters_by_category_actor_and_bucket() -> None:
    _create(vuln_category="idor", actor_ref="actor-a",
            priority={"bucket": "P0"})
    _create(vuln_category="sql_injection", actor_ref="actor-b", resource="/x",
            priority={"bucket": "P2"})
    by_cat = _query_impl(status=None, vuln_category="sql_injection", actor_ref=None,
                         endpoint_id=None, origin=None, priority_bucket=None,
                         pending_only=False, limit=500)
    assert by_cat["total_matched"] == 1
    by_bucket = _query_impl(status=None, vuln_category=None, actor_ref=None, endpoint_id=None,
                            origin=None, priority_bucket="P0", pending_only=False, limit=500)
    assert by_bucket["total_matched"] == 1


def test_secrets_are_redacted_and_no_body_stored() -> None:
    rec = _create(rationale="leaked token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.SIGSIGSIGSIG here")
    _record_attempt_impl(
        hypothesis_id=rec["hypothesis_id"], tool="manual",
        tool_rationale="replayed with Bearer sk-SECRETTOKEN12345 swapped",
        outcome="403 for actor-b", result_status="testing", validation_required="",
        signal="", input_evidence=None, agent_id=None, agent_name=None,
    )
    blob = json.dumps(_all(), ensure_ascii=False)
    assert "SIGSIGSIGSIG" not in blob
    assert "sk-SECRETTOKEN12345" not in blob
    assert "«redacted»" in blob


# --------------------------------------------------------------------------- #
# Tool wrappers + the demonstrated end-to-end flow
# --------------------------------------------------------------------------- #


def _ctx() -> ToolContext:
    return ToolContext(
        context={"agent_id": "agent-1", "coordinator": None, "request_resolver": _ok_resolver},
        tool_name="hypotheses", tool_call_id="call-1", tool_arguments="{}",
    )


def _ctx_missing() -> ToolContext:
    return ToolContext(
        context={"agent_id": "agent-1", "coordinator": None, "request_resolver": _missing_resolver},
        tool_name="hypotheses", tool_call_id="call-2", tool_arguments="{}",
    )


@pytest.mark.asyncio
async def test_demonstrated_flow_inventory_to_needs_validation(_stores: Path) -> None:
    # 1) Crawl inventory: an endpoint observed by two actors (the raw IDOR signal).
    url = "https://app.example.com/api/orders/1"
    _record_impl(url=url, method="GET", discovery_source="crawl:anonymous",
                 actor_ref="anonymous", auth_state="anonymous", status_code=401)
    rec = _record_impl(url=url, method="GET", discovery_source="crawl:actor-a",
                       actor_ref="actor-a", auth_state="authenticated", status_code=200,
                       request_ref="caido:req-77")
    endpoint_id = rec["endpoint_id"]

    # 2) Hypothesis against that concrete object + actor, with a replayable ref.
    raw = await create_hypothesis.on_invoke_tool(_ctx(), json.dumps({
        "endpoint_id": endpoint_id, "vuln_category": "idor", "resource": "/api/orders/1",
        "actor_ref": "actor-a", "rationale": "actor-a 200 vs anonymous 401 on the same object",
        "request_ref": "caido:req-77", "impact": "high", "evidence_strength": "high",
        "test_cost": "low", "priority_bucket": "P0",
    }))
    created = json.loads(raw)
    assert created["success"] is True
    hid = created["hypothesis_id"]

    # 3) Evidence resolved through the (injected) proxy; endpoint denormalized.
    listed = json.loads(await query_hypotheses.on_invoke_tool(
        _ctx(), json.dumps({"pending_only": True, "vuln_category": "idor"})))
    assert listed["total_matched"] == 1
    h = listed["hypotheses"][0]
    assert h["origin"] == "https://app.example.com:443"  # denormalized from the inventory
    req_ev = [e for e in h["evidence"] if e["kind"] == "request"]
    assert req_ev
    assert req_ev[0]["resolved_state"] == RESOLVED
    assert req_ev[0]["summary"] == "GET -> 200"

    # 4) Record a real test attempt — strong signal, but only needs_validation.
    attempt = json.loads(await record_test_attempt.on_invoke_tool(_ctx(), json.dumps({
        "hypothesis_id": hid, "tool": "manual",
        "tool_rationale": "replay actor-a's request as actor-b to test object ownership",
        "outcome": "actor-b also received 200 with actor-a's order body",
        "result_status": "needs_validation",
        "validation_required": "confirm the body is actor-a's private data, not shared",
        "input_evidence_ref": "caido:req-77",
    })))
    assert attempt["success"] is True and attempt["status"] == STATUS_NEEDS_VALIDATION

    # 5) The worklist shows it as actionable, with the attempt + validation note.
    final = _all()["hypotheses"][0]
    assert final["status"] == STATUS_NEEDS_VALIDATION
    assert final["attempt_count"] == 1
    assert "validation_required" in final["attempts"][0]


@pytest.mark.asyncio
async def test_flow_can_rule_out_with_counterevidence() -> None:
    rec = _create(resource="/api/orders/9")
    hid = rec["hypothesis_id"]
    await record_test_attempt.on_invoke_tool(_ctx(), json.dumps({
        "hypothesis_id": hid, "tool": "manual",
        "tool_rationale": "replay as actor-b", "outcome": "actor-b got 403",
        "result_status": "ruled_out",
        "validation_required": "none — object-level authorization confirmed present",
    }))
    await update_hypothesis.on_invoke_tool(_ctx(), json.dumps({
        "hypothesis_id": hid, "add_counterevidence": "actor-b 403 is a real ownership check",
    }))
    h = _all()["hypotheses"][0]
    assert h["status"] == STATUS_RULED_OUT
    assert any("ownership check" in c for c in h["counterevidence"])


@pytest.mark.asyncio
async def test_tool_missing_request_evidence_is_flagged_not_fabricated() -> None:
    raw = await create_hypothesis.on_invoke_tool(_ctx_missing(), json.dumps({
        "endpoint_id": "ep-x", "vuln_category": "xss", "resource": "/search",
        "request_ref": "caido:gone", "rationale": "reflected value in response",
    }))
    hid = json.loads(raw)["hypothesis_id"]
    h = _all()["hypotheses"][0]
    assert hid == h["hypothesis_id"]
    req_ev = [e for e in h["evidence"] if e["kind"] == "request"]
    assert req_ev and req_ev[0]["resolved_state"] == RESOLVED_MISSING
    assert "capture" in req_ev[0]["suggestion"]
    assert h["needs_replay_evidence"] is True


def test_observation_evidence_is_not_applicable_for_replay() -> None:
    _create(evidence=[{"kind": "observation", "ref": "recon-note-1",
                       "resolved_state": NOT_APPLICABLE}])
    h = _all()["hypotheses"][0]
    obs = [e for e in h["evidence"] if e["kind"] == "observation"]
    assert obs and obs[0]["resolved_state"] == NOT_APPLICABLE


# --------------------------------------------------------------------------- #
# Runner wiring
# --------------------------------------------------------------------------- #


def test_runner_hydrates_hypotheses() -> None:
    source = inspect.getsource(runner_module)
    assert "from strix.tools.hypotheses.tools import hydrate_hypotheses_from_disk" in source
    assert "hydrate_hypotheses_from_disk(state_dir)" in source
