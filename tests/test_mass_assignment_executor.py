"""Tests for the targeted mass-assignment executor (BLACKBOX improvement #14).

Pure helpers (field build, JSON/form injection, binding classification) plus
orchestration with INJECTED retrieve/send/reread providers — deterministic, no
network. All replays inject the same token-tagged privileged fields.
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
from strix.tools.mass_assignment_executor.tools import (
    VERDICT_ACCEPTED,
    VERDICT_IGNORED,
    _build_fields,
    _classify,
    _inject_fields,
    _run_mass_assignment_impl,
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
        "endpoint_id": "ep1", "vuln_category": "mass_assignment", "resource": "/api/profile",
        "actor_ref": "actor-a", "param_name": "", "param_location": "",
        "operation": "PATCH /api/profile", "rationale": "profile update binds client JSON",
        "next_action": "probe", "priority": {}, "evidence": [],
        "agent_id": None, "agent_name": None,
    }
    base.update(overrides)
    return _create_impl(**base)["hypothesis_id"]


_RAW_JSON = (
    "PATCH /api/profile HTTP/1.1\r\n"
    "Host: app.example.com\r\n"
    "Content-Type: application/json\r\n"
    "Cookie: session=SECRETVAL\r\n"
    "\r\n"
    '{"name":"Bob","bio":"hi"}'
)
_RAW_FORM = (
    "POST /api/profile HTTP/1.1\r\n"
    "Host: app.example.com\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "\r\n"
    "name=Bob&bio=hi"
)
_SCOPE = ["app.example.com"]


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


def test_build_fields_strings_tagged_booleans_true() -> None:
    fields, token_by = _build_fields("tok123", ["custom_flag"])
    assert fields["is_admin"] is True and fields["verified"] is True
    assert token_by["role"] == "strix_role_tok123"
    assert "custom_flag" in token_by           # agent extra treated as a string field
    assert fields["role"] in token_by.values()


def test_inject_into_json_adds_keys() -> None:
    out = _inject_fields(_RAW_JSON, {"role": "admin_tok", "is_admin": True})
    assert out is not None
    body = out.split("\r\n\r\n")[-1] if "\r\n\r\n" in out else out.split("\n\n")[-1]
    obj = json.loads(body)
    assert obj["name"] == "Bob" and obj["role"] == "admin_tok" and obj["is_admin"] is True


def test_inject_into_form_appends_fields() -> None:
    out = _inject_fields(_RAW_FORM, {"role": "admin_tok", "is_admin": True})
    assert out is not None and "role=admin_tok" in out and "is_admin=true" in out
    assert "name=Bob" in out


def test_inject_non_injectable_body_returns_none() -> None:
    raw = "GET /x HTTP/1.1\r\nHost: h\r\n\r\n"           # no body
    assert _inject_fields(raw, {"role": "x"}) is None


def test_classify_binding_by_token() -> None:
    token_by = {"role": "strix_role_T", "status": "strix_status_T"}
    v, bound = _classify('{"role":"strix_role_T","name":"Bob"}', "", token_by)
    assert v == VERDICT_ACCEPTED and bound == ["role"]
    v2, bound2 = _classify('{"name":"Bob"}', "", token_by)
    assert v2 == VERDICT_IGNORED and bound2 == []
    # a hit in the RE-READ counts too
    v3, bound3 = _classify('{"name":"Bob"}', '{"status":"strix_status_T"}', token_by)
    assert v3 == VERDICT_ACCEPTED and bound3 == ["status"]


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def _retrieve(raw: str = _RAW_JSON, url: str = "https://app.example.com/api/profile",
              found: bool = True):
    async def _fn(_rid: str) -> dict[str, Any] | None:
        return {"found": True, "raw": raw, "url": url, "method": "PATCH"} if found else None
    return _fn


def _sender(echo: bool = False, sent: bool = True):
    """If echo, the response body echoes the full mutated request body (so any
    token-tagged injected field is reflected -> bound)."""
    calls: list[dict[str, Any]] = []

    async def _fn(_c: Any, *, mutated_raw: str, url: str) -> dict[str, Any]:
        calls.append({"mutated_raw": mutated_raw})
        if not sent:
            return {"sent": False}
        body = mutated_raw.rsplit("\r\n\r\n", 1)[-1] if "\r\n\r\n" in mutated_raw \
            else mutated_raw.rsplit("\n\n", 1)[-1]
        return {"sent": True, "status": 200, "headers": {}, "body": body if echo else '{"ok":true}'}
    _fn.calls = calls  # type: ignore[attr-defined]
    return _fn


async def _run(hid: str, **kw: Any) -> dict[str, Any]:
    d: dict[str, Any] = {"request_ref": "r1", "scan_targets": _SCOPE}
    d.update(kw)
    return await _run_mass_assignment_impl(object(), hypothesis_id=hid, **d)


def test_wrong_category_rejected() -> None:
    hid = _hyp(vuln_category="xss", operation="", param_name="q", param_location="query")
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender()))
    assert res["success"] is False


def test_out_of_scope_sends_nothing() -> None:
    hid = _hyp()
    send = _sender()
    res = asyncio.run(_run(hid, retrieve=_retrieve(url="https://evil.test/api/profile"), send=send))
    assert res["result_status"] == STATUS_BLOCKED and send.calls == []


def test_non_injectable_body_blocked_no_budget() -> None:
    hid = _hyp()
    send = _sender()
    res = asyncio.run(_run(hid, retrieve=_retrieve(raw="GET /x HTTP/1.1\r\nHost: h\r\n\r\n"),
                           send=send))
    assert res["result_status"] == STATUS_BLOCKED and send.calls == []
    assert budget_status(hid)["used"] == 0


def test_send_failure_consumes_attempt() -> None:
    hid = _hyp()
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender(sent=False)))
    assert res["result_status"] == STATUS_BLOCKED and budget_status(hid)["used"] == 1


def test_bound_field_is_needs_validation() -> None:
    hid = _hyp()
    send = _sender(echo=True)       # the server echoes the injected fields
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=send))
    assert res["result_status"] == STATUS_NEEDS_VALIDATION and res["verdict"] == VERDICT_ACCEPTED
    assert "role" in res["bound_fields"]
    assert lookup_hypothesis(hid)["status"] == STATUS_NEEDS_VALIDATION
    assert "SECRETVAL" not in json.dumps(res, default=str)


def test_no_binding_is_testing() -> None:
    hid = _hyp()
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender(echo=False)))
    assert res["result_status"] == STATUS_TESTING and res["verdict"] == VERDICT_IGNORED


def test_reread_confirms_binding() -> None:
    hid = _hyp()

    async def _reread(_c: Any, read_ref: str) -> str:
        # the re-read object reflects an injected token-tagged field
        return '{"name":"Bob","status":"strix_status_' + "x" + '"}'

    # Make the send NOT echo, so only the re-read can surface a binding. Use a
    # reread that contains a role token matching what the executor injected.
    sent_bodies: list[str] = []

    async def _send(_c: Any, *, mutated_raw: str, url: str) -> dict[str, Any]:
        sent_bodies.append(mutated_raw)
        return {"sent": True, "status": 200, "headers": {}, "body": '{"ok":true}'}

    async def _reread2(_c: Any, read_ref: str) -> str:
        # echo back the exact role token the executor injected this run
        body = sent_bodies[0].split("\r\n\r\n")[-1] if "\r\n\r\n" in sent_bodies[0] \
            else sent_bodies[0].split("\n\n")[-1]
        role = json.loads(body)["role"]
        return json.dumps({"name": "Bob", "role": role})

    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_send, reread=_reread2,
                           read_request_ref="read1"))
    assert res["result_status"] == STATUS_NEEDS_VALIDATION
    assert "role" in res["bound_fields"] and res["re_read"] is True


def test_budget_exhaustion_blocks() -> None:
    hid = _hyp()
    for _ in range(DEFAULT_ATTEMPT_BUDGET):
        asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender()))
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender()))
    assert res["result_status"] == STATUS_BLOCKED and "budget" in res["outcome"].lower()
