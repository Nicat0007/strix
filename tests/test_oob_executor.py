"""Tests for the targeted out-of-band (OAST) executor (BLACKBOX improvement #7).

Layers, explicitly distinguished:

- Pure helpers (scope origin/port/path, payload substitution, single-location
  value injection, interactsh JSONL token correlation) — no transport, no tool.
- Orchestration with INJECTED retrieve/send/oast providers — deterministic
  coverage of scope blocking (no traffic), missing evidence, canary-allocation
  failure, injection failure, send failure, a correlated callback (positive),
  no callback (blind negative, not ruled_out), attempt-budget exhaustion,
  cancellation, and secret handling.

No network, no real interactsh, no external targets. The DEFAULT interactsh
provider and the default proxy send are contract-based and must be verified live
in the sandbox (documented in the module); they are not exercised here, exactly
as the SQLi executor's real-sqlmap path is a separate, skip-guarded concern.
"""

from __future__ import annotations

import asyncio
import json
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
from strix.tools.oob_executor.tools import (
    VERDICT_CALLBACK,
    VERDICT_NO_CALLBACK,
    _build_payload,
    _inject_value,
    _InteractshProvider,
    _parse_interactions,
    _parse_scope,
    _run_oob_impl,
    _scope_check,
)


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _stores(tmp_path: Path) -> Path:
    hydrate_attack_surface_from_disk(tmp_path)
    hydrate_hypotheses_from_disk(tmp_path)
    return tmp_path


def _oob_hypothesis(**overrides: Any) -> str:
    base: dict[str, Any] = {
        "endpoint_id": "ep1", "vuln_category": "ssrf", "resource": "/fetch",
        "actor_ref": "actor-a", "param_name": "url", "param_location": "query",
        "operation": "", "rationale": "url param fetched server-side", "next_action": "oob",
        "priority": {}, "evidence": [], "agent_id": None, "agent_name": None,
    }
    base.update(overrides)
    return _create_impl(**base)["hypothesis_id"]


_RAW_GET = (
    "GET /fetch?url=http://old.example&x=1 HTTP/1.1\r\n"
    "Host: app.example.com\r\n"
    "Cookie: session=SECRETSESSIONVALUE\r\n"
    "\r\n"
)
_RAW_POST_JSON = (
    "POST /import HTTP/1.1\r\n"
    "Host: app.example.com\r\n"
    "Content-Type: application/json\r\n"
    "\r\n"
    '{"src":"http://old","note":"x"}'
)


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


def test_scope_enforces_host_port_path() -> None:
    assert _scope_check("https://app.example.com:8443/fetch", ["app.example.com"])[0]
    assert _scope_check("https://h/api/x", ["https://h/api"])[0]
    assert not _scope_check("https://h/admin", ["https://h/api"])[0]
    assert not _scope_check("https://evil.test/x", ["app.example.com"])[0]
    # no web host at all (white-box path target only)
    assert not _scope_check("https://h/x", ["/home/u/repo"])[0]


def test_parse_scope_skips_pathy_targets() -> None:
    hosts = {e["host"] for e in _parse_scope(["https://a.com:8443/api", "/repo", "10.0.0.5"])}
    assert hosts == {"a.com", "10.0.0.5"}


def test_build_payload_substitutes_and_keeps_structure() -> None:
    assert _build_payload("{OOB_URL}", "tok.oast.fun", "http") == "http://tok.oast.fun/"
    # a single-line template stays single-line (the canary host carries no CRLF)
    assert "\n" not in _build_payload("x={OOB}", "tok.h", "http")
    # a multi-line XXE template keeps its newlines
    xxe = _build_payload('<!DOCTYPE r [<!ENTITY % x SYSTEM "{OOB_URL}">]>\n<r/>', "c.h", "http")
    assert "\n" in xxe and "http://c.h/" in xxe


def test_inject_header_value_cannot_smuggle_a_new_header() -> None:
    raw = "GET / HTTP/1.1\r\nHost: h\r\nX-Fwd: a\r\n\r\n"
    out = _inject_value(raw, "X-Fwd", "header", "v\r\nEvil: 1")
    assert out is not None
    # the CRLF is flattened into the value — no standalone injected header line
    assert "\nEvil: 1" not in out and "X-Fwd: vEvil: 1" in out


def test_inject_value_query_replaces_only_named_param() -> None:
    out = _inject_value(_RAW_GET, "url", "query", "http://c.h/")
    assert out is not None
    # the named param's value is replaced (url-encoded); the sibling x=1 is untouched
    assert "url=http%3A%2F%2Fc.h%2F" in out
    assert "x=1" in out
    # the cookie is untouched by a query injection
    assert "SECRETSESSIONVALUE" in out


def test_inject_value_missing_param_returns_none() -> None:
    assert _inject_value(_RAW_GET, "nope", "query", "v") is None
    assert _inject_value(_RAW_GET, "url", "body", "v") is None  # no body on a GET


def test_inject_value_body_json_and_body_raw() -> None:
    j = _inject_value(_RAW_POST_JSON, "src", "body", "http://c.h/")
    assert j is not None and '"src": "http://c.h/"' in j.replace('"src":"', '"src": "')
    raw = _inject_value(_RAW_POST_JSON, "", "body_raw", "<xml>full</xml>")
    assert raw is not None and raw.endswith("<xml>full</xml>")


def test_parse_interactions_correlates_only_this_token() -> None:
    mine = "oobDEADBEEF"
    jsonl = "\n".join([
        f'{{"protocol":"dns","full-id":"{mine}.abc.oast.fun","remote-address":"1.2.3.4"}}',
        '{"protocol":"http","full-id":"oobOTHER.abc.oast.fun","remote-address":"9.9.9.9"}',
        "not json",
    ])
    out = _parse_interactions(jsonl, mine)
    assert len(out) == 1
    assert out[0]["protocol"] == "dns"
    assert out[0]["remote_address"] == "1.2.3.4"
    assert mine in out[0]["interacted_host"]


# --------------------------------------------------------------------------- #
# Fakes for orchestration
# --------------------------------------------------------------------------- #


class _FakeOast:
    def __init__(self, *, domain: str = "abc.oast.fun", allocate_ok: bool = True,
                 callback: bool = False) -> None:
        self.domain = domain
        self.allocate_ok = allocate_ok
        self.callback = callback
        self.allocated = False
        self.torn = False
        self.polled_token: str | None = None

    async def allocate(self) -> dict[str, Any] | None:
        self.allocated = True
        return {"registered_domain": self.domain} if self.allocate_ok else None

    async def poll(self, token: str, wait_s: float) -> list[dict[str, Any]]:
        self.polled_token = token
        if not self.callback:
            return []
        return [{"protocol": "dns", "interacted_host": f"{token}.{self.domain}",
                 "remote_address": "203.0.113.9", "timestamp": "t"}]

    async def teardown(self) -> None:
        self.torn = True


def _retrieve(raw: str = _RAW_GET, url: str = "https://app.example.com/fetch", found: bool = True):
    async def _fn(_rid: str) -> dict[str, Any] | None:
        if not found:
            return None
        return {"found": True, "raw": raw, "url": url, "method": "GET"}
    return _fn


def _sender(sent: bool = True):
    calls: list[dict[str, Any]] = []

    async def _fn(_client: Any, *, mutated_raw: str, url: str) -> dict[str, Any]:
        calls.append({"mutated_raw": mutated_raw, "url": url})
        return {"sent": sent}
    _fn.calls = calls  # type: ignore[attr-defined]
    return _fn


_SCOPE = ["app.example.com"]


async def _run(hid: str, **kw: Any) -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "request_ref": "r1", "injection_location": "query", "param_name": "url",
        "scan_targets": _SCOPE, "wait_s": 5.0,
    }
    defaults.update(kw)
    return await _run_oob_impl(object(), hypothesis_id=hid, **defaults)


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def test_wrong_category_is_rejected() -> None:
    hid = _oob_hypothesis(vuln_category="xss", param_name="q")
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender(), oast=_FakeOast()))
    assert res["success"] is False and "out-of-band" in res["error"]


def test_out_of_scope_sends_no_traffic_and_allocates_no_canary() -> None:
    hid = _oob_hypothesis()
    oast = _FakeOast()
    send = _sender()
    res = asyncio.run(_run(
        hid, retrieve=_retrieve(url="https://evil.test/fetch"), send=send, oast=oast,
    ))
    assert res["result_status"] == STATUS_BLOCKED and res["in_scope"] is False
    assert oast.allocated is False      # canary never allocated out of scope
    assert send.calls == []             # zero traffic
    assert lookup_hypothesis(hid)["status"] == STATUS_BLOCKED


def test_missing_request_is_blocked() -> None:
    hid = _oob_hypothesis()
    res = asyncio.run(_run(hid, retrieve=_retrieve(found=False), send=_sender(), oast=_FakeOast()))
    assert res["result_status"] == STATUS_BLOCKED and res["ran"] is False


def test_canary_allocation_failure_is_blocked_no_send() -> None:
    hid = _oob_hypothesis()
    send = _sender()
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=send, oast=_FakeOast(allocate_ok=False)))
    assert res["result_status"] == STATUS_BLOCKED
    assert send.calls == []


def test_injection_failure_tears_down_canary_no_send() -> None:
    hid = _oob_hypothesis(param_name="absent")
    oast = _FakeOast()
    send = _sender()
    res = asyncio.run(_run(
        hid, param_name="absent", retrieve=_retrieve(), send=send, oast=oast,
    ))
    assert res["result_status"] == STATUS_BLOCKED
    assert oast.allocated is True and oast.torn is True
    assert send.calls == []
    # a pre-send block consumes no attempt budget
    assert budget_status(hid)["used"] == 0


def test_send_failure_consumes_attempt_and_tears_down() -> None:
    hid = _oob_hypothesis()
    oast = _FakeOast()
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender(sent=False), oast=oast))
    assert res["result_status"] == STATUS_BLOCKED
    assert oast.torn is True
    # dispatch happened (traffic may have left) -> the attempt is consumed
    assert budget_status(hid)["used"] == 1


def test_callback_is_needs_validation_not_confirmed() -> None:
    hid = _oob_hypothesis()
    oast = _FakeOast(callback=True)
    send = _sender()
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=send, oast=oast))
    assert res["result_status"] == STATUS_NEEDS_VALIDATION
    assert res["verdict"] == VERDICT_CALLBACK and res["callback_received"] is True
    assert res["interaction_count"] == 1 and res["protocols"] == ["dns"]
    # the canary the agent-facing result shows is this attempt's unique one
    assert oast.polled_token is not None and oast.polled_token in res["canary"]
    assert send.calls and "url=http%3A" in send.calls[0]["mutated_raw"]
    # recorded on the worklist as needs_validation, never confirmed
    h = lookup_hypothesis(hid)
    assert h["status"] == STATUS_NEEDS_VALIDATION and h["status"] != "confirmed"
    assert oast.torn is True


def test_no_callback_is_testing_not_ruled_out() -> None:
    hid = _oob_hypothesis()
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender(), oast=_FakeOast()))
    assert res["result_status"] == STATUS_TESTING and res["verdict"] == VERDICT_NO_CALLBACK
    assert res["callback_received"] is False
    assert lookup_hypothesis(hid)["status"] == STATUS_TESTING


def test_secrets_never_returned() -> None:
    hid = _oob_hypothesis()
    oast = _FakeOast(callback=True)
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender(), oast=oast))
    assert "SECRETSESSIONVALUE" not in json.dumps(res, default=str)


def test_attempt_budget_exhaustion_is_blocked() -> None:
    hid = _oob_hypothesis()
    # Consume the whole budget with real (completed) attempts.
    for _ in range(DEFAULT_ATTEMPT_BUDGET):
        asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender(), oast=_FakeOast()))
    assert budget_status(hid)["remaining"] == 0
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender(), oast=_FakeOast()))
    assert res["result_status"] == STATUS_BLOCKED and "budget" in res["outcome"].lower()


def test_body_raw_xxe_injection_runs() -> None:
    hid = _oob_hypothesis(vuln_category="xxe", param_name="", param_location="body")
    send = _sender()
    res = asyncio.run(_run(
        hid, injection_location="body_raw", param_name="", retrieve=_retrieve(raw=_RAW_POST_JSON),
        send=send, oast=_FakeOast(callback=True),
    ))
    assert res["result_status"] == STATUS_NEEDS_VALIDATION
    # the XXE default template (a SYSTEM-entity document) was sent as the raw body
    assert "DOCTYPE" in send.calls[0]["mutated_raw"] and "SYSTEM" in send.calls[0]["mutated_raw"]


def test_interactsh_provider_accepts_self_hosted_server_and_token() -> None:
    p = _InteractshProvider(object(), server="https://oast.mine", token="tok")
    assert p._server == "https://oast.mine" and p._token == "tok"


def test_default_provider_reads_interactsh_env(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, str] = {}

    class _Spy:
        def __init__(self, transport: Any, *, server: str = "", token: str = "") -> None:
            captured["server"] = server
            captured["token"] = token

        async def allocate(self) -> dict[str, Any] | None:
            return None

        async def teardown(self) -> None:
            return None

    monkeypatch.setenv("STRIX_INTERACTSH_SERVER", "https://oast.mine")
    monkeypatch.setenv("STRIX_INTERACTSH_TOKEN", "sekret")
    monkeypatch.setattr("strix.tools.oob_executor.tools._InteractshProvider", _Spy)
    hid = _oob_hypothesis()
    # no oast injected -> the default provider is built, reading the env above
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender(), oast=None))
    assert captured["server"] == "https://oast.mine" and captured["token"] == "sekret"
    assert res["result_status"] == STATUS_BLOCKED      # spy allocate() returns None -> blocked
