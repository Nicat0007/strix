"""Tests for the targeted SSTI executor (BLACKBOX improvement #9).

Pure helpers (distinct-product probe set, evaluation-vs-reflection classifier)
plus orchestration with INJECTED retrieve/send providers and a fixed probe set —
deterministic, no network, no external targets.
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
from strix.tools.ssti_executor.tools import (
    VERDICT_EVALUATED,
    VERDICT_NO_EVAL,
    VERDICT_REFLECTED_ONLY,
    _build_probes,
    _classify,
    _probe_payload,
    _run_ssti_impl,
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
        "endpoint_id": "ep1", "vuln_category": "ssti", "resource": "/greet",
        "actor_ref": "anonymous", "param_name": "name", "param_location": "query",
        "operation": "", "rationale": "name reflected into a template", "next_action": "probe",
        "priority": {}, "evidence": [], "agent_id": None, "agent_name": None,
    }
    base.update(overrides)
    return _create_impl(**base)["hypothesis_id"]


_RAW = (
    "GET /greet?name=bob&x=1 HTTP/1.1\r\n"
    "Host: app.example.com\r\n"
    "Cookie: session=SECRETVAL\r\n"
    "\r\n"
)

# A fixed, deterministic probe set for the orchestration tests.
_PROBES = [
    {"engine": "jinja2/twig", "expr": "{{111*2222}}", "product": "246642"},
    {"engine": "freemarker/el/spel", "expr": "${333*4444}", "product": "1479852"},
    {"engine": "smarty", "expr": "{555*6666}", "product": "3699630"},
]


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


def test_build_probes_products_are_distinct_and_correct() -> None:
    probes = _build_probes()
    assert len(probes) == 5
    products = [p["product"] for p in probes]
    assert len(set(products)) == 5                       # distinct per engine
    for p in probes:
        # the stated product really is the arithmetic in the expression
        nums = [int(n) for n in re.findall(r"\d+", p["expr"])]
        assert str(nums[0] * nums[1]) == p["product"]


def test_classify_evaluated_requires_product_and_absent_literal() -> None:
    body = "Hello 246642 world"           # jinja product present, no literal expr
    v, ev, refl = _classify(body, _PROBES)
    assert v == VERDICT_EVALUATED and ev == ["jinja2/twig"] and refl == []


def test_classify_reflection_is_not_evaluation() -> None:
    body = "Hello {{111*2222}} world"     # the literal expr echoed back
    v, ev, refl = _classify(body, _PROBES)
    assert v == VERDICT_REFLECTED_ONLY and ev == [] and "jinja2/twig" in refl


def test_classify_no_eval() -> None:
    assert _classify("nothing here", _PROBES)[0] == VERDICT_NO_EVAL


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def _retrieve(raw: str = _RAW, url: str = "https://app.example.com/greet", found: bool = True):
    async def _fn(_rid: str) -> dict[str, Any] | None:
        return {"found": True, "raw": raw, "url": url, "method": "GET"} if found else None
    return _fn


def _sender(body: str = "", sent: bool = True):
    calls: list[dict[str, Any]] = []

    async def _fn(_client: Any, *, mutated_raw: str, url: str) -> dict[str, Any]:
        calls.append({"mutated_raw": mutated_raw})
        if not sent:
            return {"sent": False}
        return {"sent": True, "status": 200, "headers": {}, "body": body}
    _fn.calls = calls  # type: ignore[attr-defined]
    return _fn


_SCOPE = ["app.example.com"]


async def _run(hid: str, **kw: Any) -> dict[str, Any]:
    d: dict[str, Any] = {"request_ref": "r1", "param_name": "name",
                         "injection_location": "query", "scan_targets": _SCOPE, "probes": _PROBES}
    d.update(kw)
    return await _run_ssti_impl(object(), hypothesis_id=hid, **d)


def test_wrong_category_rejected() -> None:
    hid = _hyp(vuln_category="xss", param_name="q")
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender()))
    assert res["success"] is False


def test_out_of_scope_sends_nothing() -> None:
    hid = _hyp()
    send = _sender()
    res = asyncio.run(_run(hid, retrieve=_retrieve(url="https://evil.test/greet"), send=send))
    assert res["result_status"] == STATUS_BLOCKED and res["in_scope"] is False and send.calls == []


def test_injection_failure_blocked_no_budget() -> None:
    hid = _hyp(param_name="absent")
    send = _sender()
    res = asyncio.run(_run(hid, param_name="absent", retrieve=_retrieve(), send=send))
    assert res["result_status"] == STATUS_BLOCKED and send.calls == []
    assert budget_status(hid)["used"] == 0


def test_send_failure_consumes_attempt() -> None:
    hid = _hyp()
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender(sent=False)))
    assert res["result_status"] == STATUS_BLOCKED and budget_status(hid)["used"] == 1


def test_evaluated_is_needs_validation_with_engine() -> None:
    hid = _hyp()
    send = _sender(body="result is 1479852 done")   # freemarker product, no literal
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=send))
    assert res["result_status"] == STATUS_NEEDS_VALIDATION and res["verdict"] == VERDICT_EVALUATED
    assert res["evaluated_engines"] == ["freemarker/el/spel"]
    assert lookup_hypothesis(hid)["status"] == STATUS_NEEDS_VALIDATION
    # the probe payload really was injected (url-encoded) and siblings untouched
    assert "x=1" in send.calls[0]["mutated_raw"]
    assert "SECRETVAL" not in json.dumps(res, default=str)


def test_reflection_only_is_testing() -> None:
    hid = _hyp()
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender(body="echo {{111*2222}} back")))
    assert res["result_status"] == STATUS_TESTING and res["verdict"] == VERDICT_REFLECTED_ONLY


def test_no_eval_is_testing() -> None:
    hid = _hyp()
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender(body="plain page")))
    assert res["result_status"] == STATUS_TESTING and res["verdict"] == VERDICT_NO_EVAL


def test_budget_exhaustion_blocks() -> None:
    hid = _hyp()
    for _ in range(DEFAULT_ATTEMPT_BUDGET):
        asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender()))
    res = asyncio.run(_run(hid, retrieve=_retrieve(), send=_sender()))
    assert res["result_status"] == STATUS_BLOCKED and "budget" in res["outcome"].lower()


def test_probe_payload_contains_all_exprs() -> None:
    payload = _probe_payload(_PROBES)
    for p in _PROBES:
        assert p["expr"] in payload
