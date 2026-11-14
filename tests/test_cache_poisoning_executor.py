"""Tests for the targeted cache-poisoning executor (BLACKBOX improvement #16).

Pure helpers (reflection + cache-indicator detection) plus orchestration with an
INJECTED header-aware send provider that models reflection and cache persistence —
deterministic, no network.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import TYPE_CHECKING, Any

import pytest

from strix.tools.attack_surface.tools import hydrate_attack_surface_from_disk
from strix.tools.cache_poisoning_executor.tools import (
    VERDICT_NO_REFLECTION,
    VERDICT_POISONED,
    VERDICT_REFLECTED_UNKEYED,
    _cache_indicators,
    _reflects,
    _run_cache_poisoning_impl,
)
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


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _stores(tmp_path: Path) -> Path:
    hydrate_attack_surface_from_disk(tmp_path)
    hydrate_hypotheses_from_disk(tmp_path)
    return tmp_path


def _hyp(**overrides: Any) -> str:
    base: dict[str, Any] = {
        "endpoint_id": "ep1", "vuln_category": "cache_poisoning", "resource": "/",
        "actor_ref": "anonymous", "param_name": "", "param_location": "",
        "operation": "GET /", "rationale": "CDN-fronted, host reflected in links",
        "next_action": "probe", "priority": {}, "evidence": [],
        "agent_id": None, "agent_name": None,
    }
    base.update(overrides)
    return _create_impl(**base)["hypothesis_id"]


_RAW = (
    "GET / HTTP/1.1\r\n"
    "Host: app.example.com\r\n"
    "Cookie: session=SECRETVAL\r\n"
    "\r\n"
)
_SCOPE = ["app.example.com"]


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


def test_reflects_body_and_headers() -> None:
    assert _reflects({"sent": True, "body": "<a href=//MK/>", "headers": {}}, "MK")
    assert _reflects({"sent": True, "body": "", "headers": {"Location": "https://MK/"}}, "MK")
    assert not _reflects({"sent": True, "body": "nope", "headers": {}}, "MK")
    assert not _reflects({"sent": False}, "MK")


def test_cache_indicators() -> None:
    ind = _cache_indicators({"headers": {"X-Cache": "HIT", "Age": "30", "Server": "nginx"}})
    assert any("x-cache" in i.lower() for i in ind) and not any("server" in i.lower() for i in ind)


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def _retrieve(raw: str = _RAW, url: str = "https://app.example.com/", found: bool = True):
    async def _fn(_rid: str) -> dict[str, Any] | None:
        return {"found": True, "raw": raw, "url": url, "method": "GET"} if found else None
    return _fn


def _marker_in(raw: str, header: str) -> str | None:
    m = re.search(rf"(?im)^{re.escape(header)}:\s*(cp[0-9a-f]+-\d+\.poison\.invalid)", raw)
    return m.group(1) if m else None


def _sender(reflect_header: str | None = None, cached: bool = False, sent: bool = True,
            cache_ind: bool = False):
    """Models a server that reflects the marker from `reflect_header` into the body.
    If cached, a CLEAN request (no injected header) also serves the last-seen
    marker (simulating a poisoned cache entry)."""
    state: dict[str, Any] = {"last_marker": None}

    async def _fn(_c: Any, *, mutated_raw: str, url: str) -> dict[str, Any]:
        if not sent:
            return {"sent": False}
        headers = {"X-Cache": "HIT"} if cache_ind else {}
        injected = _marker_in(mutated_raw, reflect_header) if reflect_header else None
        if injected:
            state["last_marker"] = injected
            return {"sent": True, "status": 200, "headers": headers,
                    "body": f'<link href="//{injected}/x">'}
        # a request WITHOUT the injected reflect_header: this is the clean probe
        # (or a probe for a different header). Serve the cached marker only if cached.
        if cached and state["last_marker"]:
            return {"sent": True, "status": 200, "headers": headers,
                    "body": f'<link href="//{state["last_marker"]}/x">'}
        return {"sent": True, "status": 200, "headers": headers, "body": "<html>clean</html>"}
    return _fn


async def _run(hid: str, **kw: Any) -> dict[str, Any]:
    d: dict[str, Any] = {"request_ref": "r1", "scan_targets": _SCOPE}
    d.update(kw)
    return await _run_cache_poisoning_impl(object(), hypothesis_id=hid, **d)


def test_wrong_category_rejected() -> None:
    hid = _hyp(vuln_category="xss", operation="", param_name="q", param_location="query")
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender()))
    assert res["success"] is False


def test_out_of_scope_sends_nothing() -> None:
    hid = _hyp()
    sends: list[str] = []

    async def _s(_c: Any, *, mutated_raw: str, url: str) -> dict[str, Any]:
        sends.append(mutated_raw)
        return {"sent": True, "status": 200, "headers": {}, "body": "x"}

    res = asyncio.run(_run(hid, retrieve=_retrieve(url="https://evil.test/"), send=_s))
    assert res["result_status"] == STATUS_BLOCKED and sends == []


def test_poisoned_when_clean_request_serves_marker() -> None:
    hid = _hyp()
    send = _sender(reflect_header="X-Forwarded-Host", cached=True, cache_ind=True)
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=send))
    assert res["result_status"] == STATUS_NEEDS_VALIDATION and res["verdict"] == VERDICT_POISONED
    assert "X-Forwarded-Host" in res["poisoned_headers"]
    assert lookup_hypothesis(hid)["status"] == STATUS_NEEDS_VALIDATION
    assert "SECRETVAL" not in json.dumps(res, default=str)


def test_reflected_but_not_cached_is_testing() -> None:
    hid = _hyp()
    send = _sender(reflect_header="X-Forwarded-Host", cached=False)
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=send))
    assert res["result_status"] == STATUS_TESTING and res["verdict"] == VERDICT_REFLECTED_UNKEYED
    assert "X-Forwarded-Host" in res["reflected_headers"] and res["poisoned_headers"] == []


def test_no_reflection_is_testing() -> None:
    hid = _hyp()
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender(reflect_header=None)))
    assert res["result_status"] == STATUS_TESTING and res["verdict"] == VERDICT_NO_REFLECTION


def test_all_sends_fail_is_blocked() -> None:
    hid = _hyp()
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender(sent=False)))
    assert res["result_status"] == STATUS_BLOCKED and budget_status(hid)["used"] == 1


def test_budget_exhaustion_blocks() -> None:
    hid = _hyp()
    for _ in range(DEFAULT_ATTEMPT_BUDGET):
        asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender()))
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender()))
    assert res["result_status"] == STATUS_BLOCKED and "budget" in res["outcome"].lower()
