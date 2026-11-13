"""Tests for the targeted race-condition executor (BLACKBOX improvement #11).

Pure helper (success classification) plus orchestration with an INJECTED stateful
concurrent send provider — deterministic, no network. All copies are identical.
"""

from __future__ import annotations

import asyncio
import json
import threading
from typing import TYPE_CHECKING, Any

import pytest

from strix.tools.attack_surface.tools import hydrate_attack_surface_from_disk
from strix.tools.hypotheses.tools import (
    DEFAULT_ATTEMPT_BUDGET,
    STATUS_BLOCKED,
    STATUS_NEEDS_VALIDATION,
    STATUS_TESTING,
    _create_impl,
    budget_status,
    hydrate_hypotheses_from_disk,
    lookup_hypothesis,
)
from strix.tools.race_executor.tools import (
    VERDICT_INCONCLUSIVE,
    VERDICT_NO_RACE,
    VERDICT_RACE_SUSPECTED,
    _is_success,
    _run_race_impl,
)


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _stores(tmp_path: Path) -> Path:
    hydrate_attack_surface_from_disk(tmp_path)
    hydrate_hypotheses_from_disk(tmp_path)
    return tmp_path


def _hyp(**overrides: Any) -> str:
    base: dict[str, Any] = {
        "endpoint_id": "ep1", "vuln_category": "race_conditions", "resource": "/coupon/redeem",
        "actor_ref": "actor-a", "param_name": "", "param_location": "",
        "operation": "POST /coupon/redeem", "rationale": "one-time coupon, redeem not atomic",
        "next_action": "race probe", "priority": {}, "evidence": [],
        "agent_id": None, "agent_name": None,
    }
    base.update(overrides)
    return _create_impl(**base)["hypothesis_id"]


_RAW = (
    "POST /coupon/redeem HTTP/1.1\r\n"
    "Host: app.example.com\r\n"
    "Cookie: session=SECRETVAL\r\n"
    "\r\n"
    '{"coupon":"SAVE10"}'
)
_SCOPE = ["app.example.com"]


# --------------------------------------------------------------------------- #
# Pure helper
# --------------------------------------------------------------------------- #


def test_is_success_default_2xx_and_markers() -> None:
    s2xx = frozenset(range(200, 300))
    assert _is_success({"sent": True, "status": 200, "body": ""}, s2xx, [], [])
    assert not _is_success({"sent": True, "status": 409, "body": ""}, s2xx, [], [])
    # markers override status; anti-markers veto
    assert _is_success({"sent": True, "status": 200, "body": "coupon applied"}, s2xx,
                       ["coupon applied"], [])
    assert not _is_success({"sent": True, "status": 200, "body": "already used"}, s2xx, [],
                           ["already used"])
    assert not _is_success({"sent": False}, s2xx, [], [])


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def _retrieve(raw: str = _RAW, url: str = "https://app.example.com/coupon/redeem",
              found: bool = True):
    async def _fn(_rid: str) -> dict[str, Any] | None:
        return {"found": True, "raw": raw, "url": url, "method": "POST"} if found else None
    return _fn


def _wins_then_fails(k: int):
    """A race: the first k concurrent requests get a 200; the rest get 409 'already
    used'. A lock protects the shared counter across gather's coroutines."""
    lock = threading.Lock()
    state = {"n": 0}

    async def _fn(_c: Any, *, mutated_raw: str, url: str) -> dict[str, Any]:
        with lock:
            state["n"] += 1
            idx = state["n"]
        if idx <= k:
            return {"sent": True, "status": 200, "headers": {}, "body": "coupon applied"}
        return {"sent": True, "status": 409, "headers": {}, "body": "already used"}
    _fn.state = state  # type: ignore[attr-defined]
    return _fn


def _all_fail():
    async def _fn(_c: Any, *, mutated_raw: str, url: str) -> dict[str, Any]:
        return {"sent": True, "status": 409, "headers": {}, "body": "already used"}
    return _fn


def _dead():
    async def _fn(_c: Any, *, mutated_raw: str, url: str) -> dict[str, Any]:
        return {"sent": False}
    return _fn


async def _run(hid: str, **kw: Any) -> dict[str, Any]:
    d: dict[str, Any] = {"request_ref": "r1", "scan_targets": _SCOPE, "concurrency": 10}
    d.update(kw)
    return await _run_race_impl(object(), hypothesis_id=hid, **d)


def test_wrong_category_rejected() -> None:
    hid = _hyp(vuln_category="xss", operation="", param_name="q", param_location="query")
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_all_fail()))
    assert res["success"] is False


def test_out_of_scope_sends_nothing() -> None:
    hid = _hyp()
    send = _wins_then_fails(3)
    res = asyncio.run(_run(hid, retrieve=_retrieve(url="https://evil.test/coupon/redeem"),
                           send=send))
    assert res["result_status"] == STATUS_BLOCKED and res["in_scope"] is False
    assert send.state["n"] == 0


def test_multiple_successes_is_race_suspected() -> None:
    hid = _hyp()
    send = _wins_then_fails(3)   # 3 of 10 concurrent win -> race
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=send,
                           success_markers=["coupon applied"], failure_markers=["already used"]))
    assert res["result_status"] == STATUS_NEEDS_VALIDATION
    assert res["verdict"] == VERDICT_RACE_SUSPECTED and res["successes"] == 3
    assert res["fired"] == 10 and res["sent"] == 10
    assert lookup_hypothesis(hid)["status"] == STATUS_NEEDS_VALIDATION
    assert "SECRETVAL" not in json.dumps(res, default=str)


def test_single_success_is_no_race() -> None:
    hid = _hyp()
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_wins_then_fails(1),
                           success_markers=["coupon applied"], failure_markers=["already used"]))
    assert res["result_status"] == STATUS_TESTING and res["verdict"] == VERDICT_NO_RACE
    assert res["successes"] == 1


def test_zero_success_is_inconclusive_testing() -> None:
    hid = _hyp()
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_all_fail()))
    assert res["result_status"] == STATUS_TESTING and res["verdict"] == VERDICT_INCONCLUSIVE
    assert res["successes"] == 0


def test_no_sends_is_blocked() -> None:
    hid = _hyp()
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_dead()))
    assert res["result_status"] == STATUS_BLOCKED and budget_status(hid)["used"] == 1


def test_budget_exhaustion_blocks() -> None:
    hid = _hyp()
    for _ in range(DEFAULT_ATTEMPT_BUDGET):
        asyncio.run(_run(hid, retrieve=_retrieve(), send=_all_fail()))
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_all_fail()))
    assert res["result_status"] == STATUS_BLOCKED and "budget" in res["outcome"].lower()
