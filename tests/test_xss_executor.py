"""Tests for the targeted, browser-backed XSS executor (BLACKBOX #6).

The committed production logic (scope, reflection/context analysis, canary-based
execution proof, verdicts, budget/dispatch, secret exclusion) is exercised with
INJECTED fake HTTP + browser providers so every case is deterministic. The real
agent-browser path is a separate, opt-in integration test
(`tests/test_xss_browser_integration.py`) that skips when no browser is present —
a skipped browser test is never counted as live validation.

Fakes model reality faithfully: the browser "fires" the canary only when the
page itself would execute the injected setter (never from a dialog, a console
message, payload text, or the harness's own read).
"""

from __future__ import annotations

import asyncio
import html
import json
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

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
from strix.tools.xss_executor.tools import (
    V_BLOCKED,
    V_EXEC,
    V_INCONCLUSIVE,
    V_INVALID_SESSION,
    V_NOEXEC,
    V_REFLECTED,
    V_UNSUPPORTED,
    _analyze_context,
    _run_xss_impl,
)


if TYPE_CHECKING:
    from pathlib import Path


_SCOPE = ["http://127.0.0.1:8000"]
_URL = "http://127.0.0.1:8000/app"


@pytest.fixture(autouse=True)
def _stores(tmp_path: Path) -> Path:
    hydrate_hypotheses_from_disk(tmp_path)
    return tmp_path


def _hyp(**over: Any) -> str:
    base: dict[str, Any] = {
        "endpoint_id": "ep1", "vuln_category": "xss", "resource": "/app",
        "actor_ref": "actor-a", "param_name": "q", "param_location": "query", "operation": "",
        "rationale": "reflected q", "next_action": "probe", "priority": {}, "evidence": [],
        "agent_id": None, "agent_name": None,
    }
    base.update(over)
    return _create_impl(**base)["hypothesis_id"]


def _sent_value(url: str, body: str | None) -> str:
    """Pull the one injected `xss=` value out of a query URL or form body."""
    q = parse_qs(urlsplit(url).query)
    if "xss" in q:
        return unquote(q["xss"][0])
    if body:
        qb = parse_qs(body)
        if "xss" in qb:
            return unquote(qb["xss"][0])
    return ""


def _embed(context: str, value: str) -> tuple[str, dict[str, str]]:
    ct = "text/html"
    if context == "html_text":
        return f"<div>{value}</div>", {"Content-Type": ct}
    if context == "attribute":
        return f'<input value="{value}">', {"Content-Type": ct}
    if context == "script":
        return f"<script>var x='{value}'</script>", {"Content-Type": ct}
    if context == "encoded":
        return f"<div>{html.escape(value)}</div>", {"Content-Type": ct}
    if context == "json":
        return json.dumps({"q": value}), {"Content-Type": "application/json"}
    if context == "plain":
        return value, {"Content-Type": "text/plain"}
    return "<div>nothing reflected</div>", {"Content-Type": ct}


def _fake_http(*, context: str = "html_text", base_body: str = "<html>home</html>",
               base_headers: dict[str, str] | None = None, ok: bool = True,
               status: int = 200) -> Any:
    async def http(url: str, *, method: str, headers: dict[str, str],
                   body: str | None) -> dict[str, Any]:
        if not ok:
            return {"ok": False, "status": None, "headers": {}, "body": "", "final_url": url,
                    "error": "fail"}
        value = _sent_value(url, body)
        if value:  # reflection probe
            rbody, rheaders = _embed(context, value)
            return {"ok": True, "status": status, "headers": rheaders, "body": rbody,
                    "final_url": url, "error": ""}
        return {"ok": True, "status": status, "headers": base_headers or {}, "body": base_body,
                "final_url": url, "error": ""}
    return http


def _origin_of(nav_url: str) -> str:
    u = urlsplit(nav_url)
    return f"{u.scheme}://{u.hostname}" + (f":{u.port}" if u.port else "")


def _fake_browser(*, fire_real: bool = True, fire_control: bool = False, origin: str | None = None,
                  final_url: str | None = None, dialog: bool = False, console: bool = False,
                  ok: bool = True, requests: list[str] | None = None) -> Any:
    async def browser(*, nav_url: str, session: str, canary_global: str, canary_token: str,
                      headers: dict[str, str], form_body: str, expect_execution: bool,
                      excluded_origins: list[str] | None = None) -> dict[str, Any]:
        fired = fire_real if expect_execution else fire_control
        return {"ok": ok, "canary_fired": fired,
                "navigated_origin": origin if origin is not None else _origin_of(nav_url),
                "final_url": final_url if final_url is not None else nav_url,
                "dialog_fired": dialog, "console_only": console, "requests": requests or [],
                "error": "" if ok else "nav failed"}
    return browser


async def _run(hid: str, **kw: Any) -> dict[str, Any]:
    params: dict[str, Any] = {
        "hypothesis_id": hid, "url": _URL, "input_location": "query", "param_or_source": "q",
        "rationale": "reflected q looks injectable", "scan_targets": _SCOPE,
        "http": _fake_http(), "browser": _fake_browser(),
        "agent_id": None, "agent_name": None,
    }
    params.update(kw)
    return await _run_xss_impl(**params)


# --------------------------------------------------------------------------- #
# Context analysis (bounded, honest heuristic)
# --------------------------------------------------------------------------- #


def test_context_analysis_classifies_contexts() -> None:
    nonce = "abc123"
    marker = f"zqx{nonce}'\"<>xqz"
    assert _analyze_context(f"<div>{marker}</div>", nonce, "text/html")["primary_context"] == \
        "html_text"
    assert _analyze_context(f'<input value="{marker}">', nonce, "text/html")["primary_context"] == \
        "attribute"
    assert _analyze_context(f"<script>var x='{marker}'</script>", nonce,
                            "text/html")["primary_context"] == "script_string"
    assert _analyze_context(f"<div>{html.escape(marker)}</div>", nonce,
                            "text/html")["primary_context"] == "encoded"
    assert _analyze_context(json.dumps({"q": marker}), nonce,
                            "application/json")["primary_context"] == "json"
    assert _analyze_context(marker, nonce, "text/plain")["primary_context"] == "plain_text"
    assert _analyze_context("<div>nothing</div>", nonce, "text/html")["reflected"] is False


# --------------------------------------------------------------------------- #
# Reflected HTML / attribute execution (needs_validation, never confirmed)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_reflected_html_execution_observed() -> None:
    hid = _hyp()
    res = await _run(hid, http=_fake_http(context="html_text"),
                     browser=_fake_browser(fire_real=True))
    assert res["verdict"] == V_EXEC
    assert res["result_status"] == STATUS_NEEDS_VALIDATION
    assert res["canary_fired"] is True and res["origin_attributed"] is True
    assert lookup_hypothesis(hid)["status"] == STATUS_NEEDS_VALIDATION
    assert "NEVER auto-confirmed" in res["next_action"]
    assert "NOT cross-user impact" in res["next_action"]


@pytest.mark.asyncio
async def test_attribute_context_execution_observed() -> None:
    hid = _hyp()
    res = await _run(hid, http=_fake_http(context="attribute"),
                     browser=_fake_browser(fire_real=True))
    assert res["verdict"] == V_EXEC
    assert res["context"] == "attribute"


# --------------------------------------------------------------------------- #
# Reflection without execution (encoded / json / plain)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_safely_encoded_reflection_is_reflected_without_execution() -> None:
    hid = _hyp()
    res = await _run(hid, http=_fake_http(context="encoded"),
                     browser=_fake_browser(fire_real=False))
    assert res["verdict"] == V_REFLECTED
    assert res["result_status"] == STATUS_TESTING
    assert res["context"] == "encoded"
    assert "does NOT close siblings" in res["next_action"]


@pytest.mark.asyncio
async def test_json_reflection_without_html_execution() -> None:
    hid = _hyp()
    res = await _run(hid, http=_fake_http(context="json"), browser=_fake_browser(fire_real=False))
    assert res["verdict"] == V_REFLECTED
    assert res["context"] == "json"


# --------------------------------------------------------------------------- #
# CSP-blocked execution (CSP left ON, never disabled)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_csp_blocked_execution() -> None:
    hid = _hyp()
    csp = {"Content-Security-Policy": "default-src 'self'"}
    res = await _run(hid, http=_fake_http(context="html_text", base_headers=csp),
                     browser=_fake_browser(fire_real=False))
    assert res["verdict"] == V_BLOCKED
    assert res["csp_present"] is True
    assert "CSP left ON" in res["outcome"]


# --------------------------------------------------------------------------- #
# DOM source->sink + inert DOM negative control
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_dom_source_sink_execution_observed() -> None:
    hid = _hyp(param_location="query", resource="/app")
    res = await _run(hid, input_location="dom", param_or_source="hash", dom_source="hash",
                     http=_fake_http(context="none"), browser=_fake_browser(fire_real=True))
    assert res["verdict"] == V_EXEC  # DOM sink fired even with no server reflection


@pytest.mark.asyncio
async def test_inert_dom_sink_negative_control_is_noexec() -> None:
    hid = _hyp()
    res = await _run(hid, input_location="dom", param_or_source="hash", dom_source="hash",
                     http=_fake_http(context="none"), browser=_fake_browser(fire_real=False))
    assert res["verdict"] == V_NOEXEC
    assert "does NOT rule out DOM XSS" in res["outcome"]
    assert "does NOT close siblings" in res["next_action"]


# --------------------------------------------------------------------------- #
# Proof discipline: dialogs/console/stale/harness do NOT count as execution
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_dialog_and_console_without_canary_are_not_execution() -> None:
    hid = _hyp()
    # A dialog + a console message fired, but the per-attempt canary global did NOT.
    res = await _run(hid, http=_fake_http(context="html_text"),
                     browser=_fake_browser(fire_real=False, dialog=True, console=True))
    assert res["verdict"] != V_EXEC
    assert res["verdict"] == V_REFLECTED  # reflection present, no real execution


@pytest.mark.asyncio
async def test_stale_or_unrelated_canary_is_not_execution() -> None:
    hid = _hyp()
    # Fake never matches our unique token (models a stale/unrelated global).
    res = await _run(hid, http=_fake_http(context="html_text"),
                     browser=_fake_browser(fire_real=False))
    assert res["verdict"] != V_EXEC


@pytest.mark.asyncio
async def test_encoded_control_firing_makes_result_inconclusive() -> None:
    hid = _hyp()
    # The encoded negative control executed -> cannot trust the engine this attempt.
    res = await _run(hid, http=_fake_http(context="html_text"),
                     browser=_fake_browser(fire_real=True, fire_control=True))
    assert res["verdict"] == V_INCONCLUSIVE
    assert "negative control executed" in res["outcome"]


# --------------------------------------------------------------------------- #
# Scope + origin attribution (off-scope execution is not proof)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_out_of_scope_url_blocked_before_dispatch() -> None:
    hid = _hyp(resource="")
    res = await _run(hid, url="http://evil.test/app", http=_fake_http(), browser=_fake_browser())
    assert res["verdict"] == V_BLOCKED and res["in_scope"] is False
    # No dispatch -> no budget consumed.
    assert budget_status(hid)["used"] == 0


@pytest.mark.asyncio
async def test_execution_navigated_off_scope_is_not_counted() -> None:
    hid = _hyp()
    res = await _run(hid, http=_fake_http(context="html_text"),
                     browser=_fake_browser(fire_real=True, origin="http://evil.test",
                                           final_url="http://evil.test/x"))
    assert res["verdict"] == V_INCONCLUSIVE
    assert res["origin_attributed"] is False


# --------------------------------------------------------------------------- #
# Unsupported locations + consistency
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
@pytest.mark.parametrize("loc", ["header", "cookie", "path", "stored"])
async def test_unsupported_locations(loc: str) -> None:
    hid = _hyp()
    res = await _run(hid, input_location=loc)
    assert res["verdict"] == V_UNSUPPORTED
    assert budget_status(hid)["used"] == 0  # no dispatch


@pytest.mark.asyncio
async def test_url_inconsistent_with_hypothesis_resource_errors() -> None:
    hid = _hyp(resource="/orders")
    res = await _run(hid, url="http://127.0.0.1:8000/unrelated")
    assert res["success"] is False and "not consistent" in res["error"]


@pytest.mark.asyncio
async def test_non_xss_hypothesis_rejected() -> None:
    hid = _hyp(vuln_category="idor")
    res = await _run(hid)
    assert res["success"] is False and "not an 'xss'" in res["error"]


# --------------------------------------------------------------------------- #
# Authenticated actor + session expiry + secret exclusion
# --------------------------------------------------------------------------- #


_ACCOUNTS = json.dumps({"principal": "actor-a", "role": "user", "cookie": "session=SECRET-XSS"})


@pytest.mark.asyncio
async def test_authenticated_fixture_runs_with_marker_present() -> None:
    hid = _hyp()
    res = await _run(hid, actor_ref="actor-a", auth_marker="Welcome actor-a",
                     accounts_text=_ACCOUNTS,
                     http=_fake_http(context="html_text", base_body="<p>Welcome actor-a</p>"),
                     browser=_fake_browser(fire_real=True))
    assert res["verdict"] == V_EXEC


@pytest.mark.asyncio
async def test_session_expiry_is_invalid_session() -> None:
    hid = _hyp()
    res = await _run(hid, actor_ref="actor-a", auth_marker="Welcome actor-a",
                     accounts_text=_ACCOUNTS,
                     http=_fake_http(context="html_text", base_body="<p>Please log in</p>"),
                     browser=_fake_browser(fire_real=True))
    assert res["verdict"] == V_INVALID_SESSION
    assert budget_status(hid)["used"] == 1  # dispatched then settled (no refund)


@pytest.mark.asyncio
async def test_missing_actor_session_is_invalid_session() -> None:
    hid = _hyp()
    # Two entries -> no sole-entry fallback, so "ghost" genuinely has no session.
    accounts = "\n".join([
        json.dumps({"principal": "actor-a", "role": "user", "cookie": "session=A"}),
        json.dumps({"principal": "actor-b", "role": "user", "cookie": "session=B"}),
    ])
    res = await _run(hid, actor_ref="ghost", auth_marker="x", accounts_text=accounts,
                     http=_fake_http(), browser=_fake_browser())
    assert res["verdict"] == V_INVALID_SESSION
    assert budget_status(hid)["used"] == 0  # rejected before dispatch


@pytest.mark.asyncio
async def test_no_secrets_in_result_or_hypothesis_record() -> None:
    hid = _hyp()
    res = await _run(hid, actor_ref="actor-a", auth_marker="Welcome actor-a",
                     accounts_text=_ACCOUNTS,
                     http=_fake_http(context="html_text", base_body="<p>Welcome actor-a</p>"),
                     browser=_fake_browser(fire_real=True))
    blob = json.dumps(res) + json.dumps(lookup_hypothesis(hid))
    assert "SECRET-XSS" not in blob and "session=SECRET-XSS" not in blob


# --------------------------------------------------------------------------- #
# Budget, cancellation, baseline failure
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_budget_exhaustion() -> None:
    hid = _hyp()
    for _ in range(DEFAULT_ATTEMPT_BUDGET):
        r = await _run(hid, http=_fake_http(context="html_text"), browser=_fake_browser())
        assert r["verdict"] == V_EXEC
    exhausted = await _run(hid, http=_fake_http(context="html_text"), browser=_fake_browser())
    assert exhausted["verdict"] == V_BLOCKED and "budget exhausted" in exhausted["outcome"]


@pytest.mark.asyncio
async def test_cancellation_after_dispatch_consumes_attempt() -> None:
    hid = _hyp()
    started = asyncio.Event()

    async def hanging_browser(**_kw: Any) -> dict[str, Any]:
        started.set()
        await asyncio.Event().wait()
        return {"ok": True, "canary_fired": False}

    task = asyncio.create_task(_run(hid, http=_fake_http(context="html_text"),
                                    browser=hanging_browser))
    await asyncio.wait_for(started.wait(), timeout=10)
    assert budget_status(hid)["used"] == 1  # reserved + dispatched
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert lookup_hypothesis(hid)["status"] == STATUS_BLOCKED
    assert budget_status(hid)["used"] == 1  # consumed, not refunded


@pytest.mark.asyncio
async def test_baseline_failure_is_inconclusive_not_a_finding() -> None:
    hid = _hyp()
    res = await _run(hid, http=_fake_http(ok=False), browser=_fake_browser())
    assert res["verdict"] == V_INCONCLUSIVE
    assert res["result_status"] == STATUS_BLOCKED
