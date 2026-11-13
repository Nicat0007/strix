"""Tests for the targeted rate-limit executor (BLACKBOX improvement #10).

Pure helpers (header set/add, IP rotation, block classification) plus
orchestration with an INJECTED stateful send provider — deterministic, no
network. All replays are identical (a presence test), never a brute-force.
"""

from __future__ import annotations

import asyncio
import json
import re
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
from strix.tools.rate_limit_executor.tools import (
    VERDICT_HEADER_BYPASS,
    VERDICT_LIMITED,
    VERDICT_NO_LIMIT,
    _is_block,
    _rotate_raw,
    _run_rate_limit_impl,
    _set_header,
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
        "endpoint_id": "ep1", "vuln_category": "weak_password_detection", "resource": "/otp",
        "actor_ref": "anonymous", "param_name": "", "param_location": "",
        "operation": "POST /otp/verify", "rationale": "OTP verify, no visible throttle",
        "next_action": "rate-limit probe", "priority": {}, "evidence": [],
        "agent_id": None, "agent_name": None,
    }
    base.update(overrides)
    return _create_impl(**base)["hypothesis_id"]


_RAW = (
    "POST /otp/verify HTTP/1.1\r\n"
    "Host: app.example.com\r\n"
    "Content-Type: application/json\r\n"
    "Cookie: session=SECRETVAL\r\n"
    "\r\n"
    '{"code":"000000"}'
)


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


def test_set_header_replaces_and_adds() -> None:
    added = _set_header(_RAW, "X-Forwarded-For", "1.2.3.4")
    assert "X-Forwarded-For: 1.2.3.4" in added
    replaced = _set_header(added, "X-Forwarded-For", "9.9.9.9")
    assert "9.9.9.9" in replaced and replaced.count("X-Forwarded-For") == 1
    # CRLF in a value cannot smuggle a header
    smug = _set_header(_RAW, "X-Real-IP", "1.1.1.1\r\nEvil: 1")
    assert "\nEvil: 1" not in smug


def test_rotate_raw_sets_all_rotation_headers_distinctly() -> None:
    a = _rotate_raw(_RAW, 0)
    b = _rotate_raw(_RAW, 1)
    for h in ("X-Forwarded-For", "X-Real-IP", "X-Client-IP"):
        assert h in a
    assert a != b   # different index -> different IP


def test_is_block_detects_status_header_and_markers() -> None:
    assert _is_block({"sent": True, "status": 429, "headers": {}, "body": ""}, frozenset({429}), [])
    assert _is_block({"sent": True, "status": 200, "headers": {"Retry-After": "5"}, "body": ""},
                     frozenset({429}), [])
    assert _is_block({"sent": True, "status": 200, "headers": {}, "body": "Too Many requests"},
                     frozenset({429}), [])
    assert not _is_block({"sent": True, "status": 200, "headers": {}, "body": "wrong code"},
                         frozenset({429}), [])
    assert not _is_block({"sent": False}, frozenset({429}), [])


# --------------------------------------------------------------------------- #
# Orchestration — stateful fake senders
# --------------------------------------------------------------------------- #


def _retrieve(raw: str = _RAW, url: str = "https://app.example.com/otp/verify", found: bool = True):
    async def _fn(_rid: str) -> dict[str, Any] | None:
        return {"found": True, "raw": raw, "url": url, "method": "POST"} if found else None
    return _fn


def _never_blocks():
    calls = {"n": 0}

    async def _fn(_c: Any, *, mutated_raw: str, url: str) -> dict[str, Any]:
        calls["n"] += 1
        return {"sent": True, "status": 200, "headers": {}, "body": "wrong code"}
    _fn.state = calls  # type: ignore[attr-defined]
    return _fn


def _blocks_after(k: int, *, bypass_on_rotation: bool = False):
    """Returns 429 once a per-IP counter exceeds k. With bypass_on_rotation, each
    distinct X-Forwarded-For has its own counter, so rotating never trips it."""
    counters: dict[str, int] = {}

    async def _fn(_c: Any, *, mutated_raw: str, url: str) -> dict[str, Any]:
        key = "fixed"
        if bypass_on_rotation:
            m = re.search(r"X-Forwarded-For:\s*([0-9.]+)", mutated_raw)
            key = m.group(1) if m else "none"
        counters[key] = counters.get(key, 0) + 1
        if counters[key] > k:
            return {"sent": True, "status": 429, "headers": {}, "body": "Too many requests"}
        return {"sent": True, "status": 200, "headers": {}, "body": "wrong code"}
    return _fn


_SCOPE = ["app.example.com"]


async def _run(hid: str, **kw: Any) -> dict[str, Any]:
    d: dict[str, Any] = {"request_ref": "r1", "scan_targets": _SCOPE,
                         "attempts": 6, "spacing_s": 0.0}
    d.update(kw)
    return await _run_rate_limit_impl(object(), hypothesis_id=hid, **d)


def test_wrong_category_rejected() -> None:
    hid = _hyp(vuln_category="xss", operation="", param_name="q", param_location="query")
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_never_blocks()))
    assert res["success"] is False


def test_out_of_scope_sends_nothing() -> None:
    hid = _hyp()
    send = _never_blocks()
    res = asyncio.run(_run(hid, retrieve=_retrieve(url="https://evil.test/otp/verify"), send=send))
    assert res["result_status"] == STATUS_BLOCKED and res["in_scope"] is False
    assert send.state["n"] == 0


def test_no_limit_is_needs_validation() -> None:
    hid = _hyp()
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_never_blocks()))
    assert res["result_status"] == STATUS_NEEDS_VALIDATION and res["verdict"] == VERDICT_NO_LIMIT
    assert res["pass1"]["blocked"] == 0 and res["rotated_pass"] is None
    assert lookup_hypothesis(hid)["status"] == STATUS_NEEDS_VALIDATION
    assert "SECRETVAL" not in json.dumps(res, default=str)


def test_limited_is_testing_and_runs_bypass_pass() -> None:
    hid = _hyp()
    # blocks after 3, same for every IP -> rotation does not help -> rate_limited
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_blocks_after(3),
                           test_header_bypass=True))
    assert res["result_status"] == STATUS_TESTING and res["verdict"] == VERDICT_LIMITED
    assert res["pass1"]["first_block_at"] == 4
    assert res["rotated_pass"] is not None   # bypass pass ran because pass1 blocked


def test_header_rotation_bypass_is_needs_validation() -> None:
    hid = _hyp()
    res = asyncio.run(_run(hid, retrieve=_retrieve(),
                           send=_blocks_after(3, bypass_on_rotation=True), test_header_bypass=True))
    assert res["result_status"] == STATUS_NEEDS_VALIDATION
    assert res["verdict"] == VERDICT_HEADER_BYPASS
    assert res["pass1"]["first_block_at"] is not None
    assert res["rotated_pass"]["first_block_at"] is None


def test_no_sends_is_blocked() -> None:
    hid = _hyp()

    async def _dead(_c: Any, *, mutated_raw: str, url: str) -> dict[str, Any]:
        return {"sent": False}

    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_dead))
    assert res["result_status"] == STATUS_BLOCKED and budget_status(hid)["used"] == 1


def test_budget_exhaustion_blocks() -> None:
    hid = _hyp()
    for _ in range(DEFAULT_ATTEMPT_BUDGET):
        asyncio.run(_run(hid, retrieve=_retrieve(), send=_never_blocks()))
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_never_blocks()))
    assert res["result_status"] == STATUS_BLOCKED and "budget" in res["outcome"].lower()
