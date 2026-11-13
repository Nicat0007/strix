"""Tests for the targeted open-redirect executor (BLACKBOX improvement #8).

Pure helpers (browser-lenient redirect-host parse, redirect classification) plus
orchestration with INJECTED retrieve/send providers — deterministic, no network,
no external targets. The default proxy send is contract-based (verify live).
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
from strix.tools.open_redirect_executor.tools import (
    VERDICT_BODY_REDIRECT,
    VERDICT_NO_REDIRECT,
    VERDICT_REDIRECTS,
    _analyze_redirect,
    _redirect_target_host,
    _run_open_redirect_impl,
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
        "endpoint_id": "ep1", "vuln_category": "open_redirect", "resource": "/login",
        "actor_ref": "anonymous", "param_name": "next", "param_location": "query",
        "operation": "", "rationale": "next param used in redirect", "next_action": "probe",
        "priority": {}, "evidence": [], "agent_id": None, "agent_name": None,
    }
    base.update(overrides)
    return _create_impl(**base)["hypothesis_id"]


_RAW = (
    "GET /login?next=/home&x=1 HTTP/1.1\r\n"
    "Host: app.example.com\r\n"
    "Cookie: session=SECRETVAL\r\n"
    "\r\n"
)


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


def test_redirect_host_parses_browser_lenient_bypass_shapes() -> None:
    assert _redirect_target_host("https://tok.evil.test/x") == "tok.evil.test"
    assert _redirect_target_host("//tok.evil.test/x") == "tok.evil.test"
    assert _redirect_target_host("https:/tok.evil.test") == "tok.evil.test"
    assert _redirect_target_host("https:tok.evil.test") == "tok.evil.test"
    assert _redirect_target_host("\\\\tok.evil.test") == "tok.evil.test"
    assert _redirect_target_host("/relative/path") == ""


def test_analyze_location_header_is_strong() -> None:
    v, c, _ = _analyze_redirect(302, {"Location": "https://orcTOK.redirect-check.invalid/"}, "",
                                "orctok")
    assert v == VERDICT_REDIRECTS and c == "high"


def test_analyze_body_meta_and_js_are_medium() -> None:
    meta = '<meta http-equiv="refresh" content="0;url=https://orctok.x.invalid/">'
    v, c, _ = _analyze_redirect(200, {}, meta, "orctok")
    assert v == VERDICT_BODY_REDIRECT and c == "medium"
    js = 'location.href="https://orctok.x.invalid/"'
    v2, _, _ = _analyze_redirect(200, {}, js, "orctok")
    assert v2 == VERDICT_BODY_REDIRECT


def test_analyze_same_site_redirect_is_negative() -> None:
    v, _, _ = _analyze_redirect(302, {"Location": "https://app.example.com/home"}, "", "orctok")
    assert v == VERDICT_NO_REDIRECT


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def _retrieve(raw: str = _RAW, url: str = "https://app.example.com/login", found: bool = True):
    async def _fn(_rid: str) -> dict[str, Any] | None:
        return {"found": True, "raw": raw, "url": url, "method": "GET"} if found else None
    return _fn


def _sender(resp: dict[str, Any] | None = None, sent: bool = True):
    calls: list[dict[str, Any]] = []

    async def _fn(_client: Any, *, mutated_raw: str, url: str) -> dict[str, Any]:
        calls.append({"mutated_raw": mutated_raw, "url": url})
        if not sent:
            return {"sent": False}
        return {"sent": True, **(resp or {"status": 200, "headers": {}, "body": ""})}
    _fn.calls = calls  # type: ignore[attr-defined]
    return _fn


_SCOPE = ["app.example.com"]


async def _run(hid: str, **kw: Any) -> dict[str, Any]:
    d: dict[str, Any] = {"request_ref": "r1", "param_name": "next",
                         "injection_location": "query", "scan_targets": _SCOPE}
    d.update(kw)
    return await _run_open_redirect_impl(object(), hypothesis_id=hid, **d)


def test_wrong_category_rejected() -> None:
    hid = _hyp(vuln_category="xss", param_name="q")
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender()))
    assert res["success"] is False


def test_out_of_scope_sends_nothing() -> None:
    hid = _hyp()
    send = _sender()
    res = asyncio.run(_run(hid, retrieve=_retrieve(url="https://evil.test/login"), send=send))
    assert res["result_status"] == STATUS_BLOCKED and res["in_scope"] is False
    assert send.calls == []


def test_injection_failure_is_blocked_no_budget() -> None:
    hid = _hyp(param_name="absent")
    send = _sender()
    res = asyncio.run(_run(hid, param_name="absent", retrieve=_retrieve(), send=send))
    assert res["result_status"] == STATUS_BLOCKED and send.calls == []
    assert budget_status(hid)["used"] == 0


def test_send_failure_consumes_attempt() -> None:
    hid = _hyp()
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender(sent=False)))
    assert res["result_status"] == STATUS_BLOCKED
    assert budget_status(hid)["used"] == 1


def test_location_redirect_is_needs_validation() -> None:
    hid = _hyp()
    # The sender echoes the marker host (which the executor generates) into Location.
    def _echo_sender():
        calls: list[dict[str, Any]] = []

        async def _fn(_c: Any, *, mutated_raw: str, url: str) -> dict[str, Any]:
            calls.append({"mutated_raw": mutated_raw})
            # the injected marker host appears in the mutated query; reflect it as a redirect
            m = re.search(r"(orc[0-9a-f]+\.redirect-check\.invalid)", mutated_raw)
            host = m.group(1) if m else "none"
            return {"sent": True, "status": 302, "headers": {"Location": f"https://{host}/"},
                    "body": ""}
        _fn.calls = calls  # type: ignore[attr-defined]
        return _fn

    send = _echo_sender()
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=send))
    assert res["result_status"] == STATUS_NEEDS_VALIDATION
    assert res["verdict"] == VERDICT_REDIRECTS and res["confidence"] == "high"
    assert lookup_hypothesis(hid)["status"] == STATUS_NEEDS_VALIDATION
    # the injected query value is url-encoded and the sibling x=1 is untouched
    assert "x=1" in send.calls[0]["mutated_raw"]
    assert "SECRETVAL" not in json.dumps(res, default=str)


def test_no_redirect_is_testing() -> None:
    hid = _hyp()
    res = asyncio.run(_run(hid, retrieve=_retrieve(),
                           send=_sender({"status": 200, "headers": {}, "body": "<html>ok</html>"})))
    assert res["result_status"] == STATUS_TESTING and res["verdict"] == VERDICT_NO_REDIRECT


def test_budget_exhaustion_blocks() -> None:
    hid = _hyp()
    for _ in range(DEFAULT_ATTEMPT_BUDGET):
        asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender()))
    assert budget_status(hid)["remaining"] == 0
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender()))
    assert res["result_status"] == STATUS_BLOCKED and "budget" in res["outcome"].lower()
