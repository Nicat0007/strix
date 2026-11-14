"""Tests for the targeted GraphQL exposure executor (BLACKBOX improvement #15).

Pure helpers (probe bodies, introspection/suggestion/batching detection) plus
orchestration with an INJECTED probe-aware send provider — deterministic, no
network.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any

import pytest

from strix.tools.attack_surface.tools import hydrate_attack_surface_from_disk
from strix.tools.graphql_executor.tools import (
    VERDICT_EXPOSED,
    VERDICT_HARDENED,
    _batching_enabled,
    _introspection_enabled,
    _probe_bodies,
    _run_graphql_impl,
    _suggestions_enabled,
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
        "endpoint_id": "ep1", "vuln_category": "graphql", "resource": "/graphql",
        "actor_ref": "anonymous", "param_name": "", "param_location": "",
        "operation": "POST /graphql", "rationale": "graphql endpoint", "next_action": "probe",
        "priority": {}, "evidence": [], "agent_id": None, "agent_name": None,
    }
    base.update(overrides)
    return _create_impl(**base)["hypothesis_id"]


_RAW = (
    "POST /graphql HTTP/1.1\r\n"
    "Host: app.example.com\r\n"
    "Content-Type: application/json\r\n"
    "Cookie: session=SECRETVAL\r\n"
    "\r\n"
    '{"query":"{me{id}}"}'
)
_SCOPE = ["app.example.com"]


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


def test_probe_bodies_shape() -> None:
    probes = _probe_bodies("tok")
    assert "__schema" in probes["introspection"]
    assert "zzz_tok" in probes["suggestions"]
    assert json.loads(probes["batching"]) == [{"query": "{__typename}"}, {"query": "{__typename}"}]


def test_detection_helpers() -> None:
    assert _introspection_enabled('{"data":{"__schema":{"types":[]}}}')
    assert not _introspection_enabled('{"errors":[{"message":"introspection disabled"}]}')
    assert _suggestions_enabled('{"errors":[{"message":"Cannot query. Did you mean \\"user\\"?"}]}')
    assert _batching_enabled('[{"data":{}},{"data":{}}]')
    assert not _batching_enabled('{"data":{}}')


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def _retrieve(raw: str = _RAW, url: str = "https://app.example.com/graphql", found: bool = True):
    async def _fn(_rid: str) -> dict[str, Any] | None:
        return {"found": True, "raw": raw, "url": url, "method": "POST"} if found else None
    return _fn


def _probe_aware_sender(introspection: bool = False, suggestions: bool = False,
                        batching: bool = False, sent: bool = True):
    calls: list[str] = []

    async def _fn(_c: Any, *, mutated_raw: str, url: str) -> dict[str, Any]:
        calls.append(mutated_raw)
        if not sent:
            return {"sent": False}
        body = mutated_raw.rsplit("\r\n\r\n", 1)[-1] if "\r\n\r\n" in mutated_raw \
            else mutated_raw.rsplit("\n\n", 1)[-1]
        if body.strip().startswith("["):           # batching probe
            resp = '[{"data":{}},{"data":{}}]' if batching else '{"errors":["batching disabled"]}'
        elif "zzz_" in body:                        # suggestion probe
            resp = ('{"errors":[{"message":"Did you mean user?"}]}' if suggestions
                    else '{"errors":[{"message":"unknown field"}]}')
        else:                                        # introspection probe
            resp = ('{"data":{"__schema":{"types":[]}}}' if introspection
                    else '{"errors":[{"message":"introspection disabled"}]}')
        return {"sent": True, "status": 200, "headers": {}, "body": resp}
    _fn.calls = calls  # type: ignore[attr-defined]
    return _fn


async def _run(hid: str, **kw: Any) -> dict[str, Any]:
    d: dict[str, Any] = {"request_ref": "r1", "scan_targets": _SCOPE}
    d.update(kw)
    return await _run_graphql_impl(object(), hypothesis_id=hid, **d)


def test_wrong_category_rejected() -> None:
    hid = _hyp(vuln_category="xss", operation="", param_name="q", param_location="query")
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_probe_aware_sender()))
    assert res["success"] is False


def test_out_of_scope_sends_nothing() -> None:
    hid = _hyp()
    send = _probe_aware_sender(introspection=True)
    res = asyncio.run(_run(hid, retrieve=_retrieve(url="https://evil.test/graphql"), send=send))
    assert res["result_status"] == STATUS_BLOCKED and send.calls == []


def test_introspection_enabled_is_needs_validation() -> None:
    hid = _hyp()
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_probe_aware_sender(introspection=True)))
    assert res["result_status"] == STATUS_NEEDS_VALIDATION and res["verdict"] == VERDICT_EXPOSED
    assert "introspection" in res["enabled_features"]
    assert lookup_hypothesis(hid)["status"] == STATUS_NEEDS_VALIDATION
    assert "SECRETVAL" not in json.dumps(res, default=str)


def test_batching_and_suggestions_detected() -> None:
    hid = _hyp()
    res = asyncio.run(_run(hid, retrieve=_retrieve(),
                           send=_probe_aware_sender(batching=True, suggestions=True)))
    assert res["verdict"] == VERDICT_EXPOSED
    assert set(res["enabled_features"]) == {"batching", "suggestions"}


def test_hardened_is_testing() -> None:
    hid = _hyp()
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_probe_aware_sender()))
    assert res["result_status"] == STATUS_TESTING and res["verdict"] == VERDICT_HARDENED
    assert res["enabled_features"] == []


def test_all_sends_fail_is_blocked() -> None:
    hid = _hyp()
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_probe_aware_sender(sent=False)))
    assert res["result_status"] == STATUS_BLOCKED and budget_status(hid)["used"] == 1


def test_budget_exhaustion_blocks() -> None:
    hid = _hyp()
    for _ in range(DEFAULT_ATTEMPT_BUDGET):
        asyncio.run(_run(hid, retrieve=_retrieve(), send=_probe_aware_sender()))
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_probe_aware_sender()))
    assert res["result_status"] == STATUS_BLOCKED and "budget" in res["outcome"].lower()
