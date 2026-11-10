"""Tests for the evidence-backed authorization replay executor (BLACKBOX #5).

Layers, explicitly distinguished:

- Pure helpers (header rebuild / no credential bleed, unsupported-auth guard,
  semantic resource/denial/login classification).
- Orchestration with an INJECTED retrieve/replay provider (deterministic) —
  the full verdict matrix: horizontal bypass/denial/both-denied/own-object/
  missing-ownership/generic-200/login-page, vertical bypass/denial/unknown-
  ordering/state-change-guard, scope + excluded-port (zero replay), unsupported
  auth, budget, cancellation, secret exclusion.
- A REAL-HTTP integration test: the committed executor driven by a real
  http.client replay provider against a disposable two-actor app (vulnerable vs
  fixed), plus a scope counter-server proving zero out-of-scope requests. The
  Caido proxy layer is stubbed by the local replay provider — live Caido is not
  exercised here (reported as a gap).

Local fixtures only; no external targets.
"""

from __future__ import annotations

import asyncio
import contextlib
import http.client
import json
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import pytest

from strix.tools.attack_surface.tools import hydrate_attack_surface_from_disk
from strix.tools.authorization_executor.tools import (
    TEST_HORIZONTAL,
    TEST_VERTICAL,
    VERDICT_BASELINE_UNVERIFIED,
    VERDICT_BLOCKED,
    VERDICT_BYPASS,
    VERDICT_DENIED,
    VERDICT_EXPECTED_PUBLIC,
    VERDICT_INSUFFICIENT,
    VERDICT_INVALID_SESSION,
    VERDICT_UNSTABLE,
    _default_replay,
    _has_resource,
    _is_denied,
    _rebuild_headers,
    _run_authz_impl,
    _unsupported_auth,
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
from strix.tools.proxy import caido_api


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _stores(tmp_path: Path) -> Path:
    hydrate_attack_surface_from_disk(tmp_path)
    hydrate_hypotheses_from_disk(tmp_path)
    return tmp_path


def _hyp(category: str = "idor", **over: Any) -> str:
    base: dict[str, Any] = {
        "endpoint_id": "ep1", "vuln_category": category, "resource": "/orders/1",
        "actor_ref": "actor-a", "param_name": "", "param_location": "query", "operation": "",
        "rationale": "object ref", "next_action": "replay", "priority": {}, "evidence": [],
        "agent_id": None, "agent_name": None,
    }
    base.update(over)
    return _create_impl(**base)["hypothesis_id"]


_ACCOUNTS = "\n".join([
    json.dumps({"principal": "actor-b", "role": "user", "cookie": "session=B-SECRET"}),
    json.dumps({"principal": "actor-c", "role": "user", "cookie": "session=C-SECRET"}),
])
_SCOPE = ["https://app.example.com"]
_MARKER = "SECRET-ORDER-A"


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


def test_rebuild_headers_strips_all_auth_no_bleed() -> None:
    captured = {"Host": "h", "Cookie": "session=A", "Authorization": "Bearer A-TOKEN",
                "Accept": "application/json"}
    # Reference (override None) keeps the captured auth exactly.
    assert _rebuild_headers(captured, None) == captured
    # Comparison actor uses a cookie only -> actor-a's Authorization must be GONE.
    swapped = _rebuild_headers(captured, {"Cookie": "session=B"})
    assert swapped["Cookie"] == "session=B"
    assert "Authorization" not in swapped  # no actor-a credential bleed
    assert swapped["Accept"] == "application/json"  # non-auth headers preserved


def test_unsupported_auth_guard() -> None:
    assert _unsupported_auth("GET /x HTTP/1.1\r\nHost: h\r\nX-CSRF-Token: abc\r\n\r\n")
    assert _unsupported_auth("POST /x HTTP/1.1\r\nHost: h\r\nX-Signature: sig\r\n\r\n")
    assert _unsupported_auth("GET /x HTTP/1.1\r\nHost: h\r\nCookie: s=1\r\n\r\n") is None


def test_semantic_classifiers() -> None:
    ok = {"status": 200, "redirect_location": ""}
    assert _has_resource(ok, f"here is {_MARKER} content", _MARKER)
    assert not _has_resource(ok, "generic page, no marker", _MARKER)     # marker absent
    assert not _has_resource({"status": 403}, _MARKER, _MARKER)          # not 2xx
    assert not _has_resource(ok, f"please log in {_MARKER}", _MARKER)    # login page != access
    assert _is_denied({"status": 403, "redirect_location": ""}, "", "")
    assert _is_denied({"status": 302, "redirect_location": "/login"}, "", "")
    assert not _is_denied(ok, "all good", "")


# --------------------------------------------------------------------------- #
# Injected provider for the verdict matrix
# --------------------------------------------------------------------------- #


def _retrieve(url: str = "https://app.example.com/orders/1", *, raw: str | None = None,
              found: bool = True) -> Any:
    netloc = urlsplit(url).netloc
    path_q = urlsplit(url).path + ("?" + urlsplit(url).query if urlsplit(url).query else "")
    default_raw = f"GET {path_q} HTTP/1.1\r\nHost: {netloc}\r\nCookie: session=A-SECRET\r\n\r\n"

    async def retrieve(_rid: str) -> dict[str, Any] | None:
        if not found:
            return None
        effective = raw if raw is not None else default_raw
        method = effective.split(" ", 1)[0] if effective else "GET"  # from the request line
        return {"found": True, "raw": effective, "url": url, "method": method}
    return retrieve


def _resp(status: int, body: str = "", headers: dict[str, str] | None = None) -> dict[str, Any]:
    return {"replayed": True, "status": status, "headers": headers or {}, "body": body,
            "timing_ms": 3}


def _replay(*, reference: dict[str, Any], anonymous: dict[str, Any], comparison: dict[str, Any],
            own: dict[str, Any] | None = None, own_ref: str = "") -> Any:
    seen: list[dict[str, Any]] = []

    async def replay(request_id: str, override: dict[str, str] | None) -> dict[str, Any]:
        seen.append({"request_id": request_id, "override": override})
        if own_ref and request_id == own_ref:
            return own or _resp(200, "own object ok")
        if override is None:
            return reference
        if override == {}:
            return anonymous
        return comparison

    replay.seen = seen  # type: ignore[attr-defined]
    return replay


async def _run(hid: str, **kw: Any) -> dict[str, Any]:
    params: dict[str, Any] = {
        "hypothesis_id": hid, "request_ref": "caido:req-a", "reference_actor": "actor-a",
        "comparison_actor": "actor-b", "test_intent": TEST_HORIZONTAL,
        "resource_marker": _MARKER, "ownership_assertion": "actor-a created order 1 at signup",
        "operation_class": "read", "accounts_text": _ACCOUNTS, "retrieve": _retrieve(),
        "scan_targets": _SCOPE, "agent_id": None, "agent_name": None,
    }
    params.update(kw)
    return await _run_authz_impl(**params)


# --------------------------------------------------------------------------- #
# Horizontal verdict matrix
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_horizontal_genuine_read_bypass() -> None:
    hid = _hyp()
    res = await _run(hid, replay=_replay(
        reference=_resp(200, f"owner view {_MARKER}"),
        anonymous=_resp(403, "denied"),            # endpoint IS auth-gated
        comparison=_resp(200, f"actor-b sees {_MARKER}"),  # leak: b read a's object
    ))
    assert res["verdict"] == VERDICT_BYPASS
    assert res["result_status"] == STATUS_NEEDS_VALIDATION
    assert lookup_hypothesis(hid)["status"] == STATUS_NEEDS_VALIDATION
    assert "NEVER auto-confirmed" in res["next_action"]


@pytest.mark.asyncio
async def test_horizontal_correct_denial() -> None:
    hid = _hyp()
    # A clean denial requires BOTH the comparison session PROVEN valid (its own
    # object returns 200) AND an app-level denial marker — a bare 403 alone is
    # inconclusive (could be WAF/intermediary).
    res = await _run(hid, comparison_own_ref="req-b-own", denied_marker="Access Forbidden",
                     replay=_replay(
                         reference=_resp(200, f"owner view {_MARKER}"),
                         anonymous=_resp(403, "denied"),
                         comparison=_resp(403, "Access Forbidden by policy"),  # app-level denial
                         own=_resp(200, "actor-b own object ok"), own_ref="req-b-own",
                     ))
    assert res["verdict"] == VERDICT_DENIED
    assert res["result_status"] == STATUS_TESTING  # scoped, does not close class
    assert res["semantic"]["comparison_session_verified"] is True
    assert "only to this actor/resource" in res["next_action"]


@pytest.mark.asyncio
async def test_both_actors_same_denial_is_not_a_leak() -> None:
    hid = _hyp()
    # Comparison AND anonymous both get the same 404 — never a leak (comparison
    # session proven valid via its own-object control; "not found" is the app's
    # own denial marker).
    res = await _run(hid, comparison_own_ref="req-b-own", denied_marker="not found",
                     replay=_replay(
                         reference=_resp(200, f"owner {_MARKER}"),
                         anonymous=_resp(404, "not found"),
                         comparison=_resp(404, "not found"),
                         own=_resp(200, "actor-b own object ok"), own_ref="req-b-own",
                     ))
    assert res["verdict"] == VERDICT_DENIED
    assert res["verdict"] != VERDICT_BYPASS


@pytest.mark.asyncio
async def test_public_resource_is_not_a_cross_actor_leak() -> None:
    hid = _hyp()
    # Anonymous ALSO gets the resource -> public content, not an authz boundary.
    res = await _run(hid, replay=_replay(
        reference=_resp(200, f"owner {_MARKER}"),
        anonymous=_resp(200, f"public {_MARKER}"),
        comparison=_resp(200, f"also {_MARKER}"),
    ))
    assert res["verdict"] == VERDICT_DENIED
    assert "reachable anonymously" in res["outcome"] and "not a cross-actor leak" in res["outcome"]


@pytest.mark.asyncio
async def test_generic_200_without_marker_is_insufficient_not_bypass() -> None:
    hid = _hyp()
    res = await _run(hid, replay=_replay(
        reference=_resp(200, f"owner {_MARKER}"),
        anonymous=_resp(403, "denied"),
        comparison=_resp(200, "generic dashboard, no order data here"),  # no marker
    ))
    assert res["verdict"] == VERDICT_INSUFFICIENT  # a generic 200 is NOT a bypass


@pytest.mark.asyncio
async def test_login_page_comparison_is_invalid_session_not_leak() -> None:
    hid = _hyp()
    res = await _run(hid, replay=_replay(
        reference=_resp(200, f"owner {_MARKER}"),
        anonymous=_resp(403, "denied"),
        comparison=_resp(200, "Please log in to continue"),  # 200 login page
    ))
    assert res["verdict"] == VERDICT_INVALID_SESSION


@pytest.mark.asyncio
async def test_own_object_control_failure_is_invalid_session() -> None:
    hid = _hyp()
    res = await _run(hid, comparison_own_ref="req-b-own", replay=_replay(
        reference=_resp(200, f"owner {_MARKER}"),
        anonymous=_resp(403, "denied"),
        comparison=_resp(403, "denied"),
        own=_resp(302, "", {"Location": "/login"}),  # b can't even see its OWN object
        own_ref="req-b-own",
    ))
    assert res["verdict"] == VERDICT_INVALID_SESSION


@pytest.mark.asyncio
async def test_failed_reference_baseline_403_is_unverified_not_invalid_session() -> None:
    # A 403 baseline means the reference actor cannot access the resource, so the
    # boundary cannot be tested — but a 403 is AUTHORIZATION, not authentication,
    # so it must NOT be classified invalid_session. It is inconclusive, and never
    # a vulnerability regardless.
    hid = _hyp()
    res = await _run(hid, replay=_replay(
        reference=_resp(403, "denied"),  # reference not authorized -> cannot test
        anonymous=_resp(403, "denied"),
        comparison=_resp(200, f"has {_MARKER}"),
    ))
    assert res["verdict"] == VERDICT_BASELINE_UNVERIFIED
    assert res["verdict"] not in (VERDICT_INVALID_SESSION, VERDICT_BYPASS)
    assert res["result_status"] == STATUS_BLOCKED
    assert "403 is authorization" in res["outcome"]


@pytest.mark.asyncio
async def test_missing_ownership_evidence_is_insufficient() -> None:
    hid = _hyp()
    res = await _run(hid, ownership_assertion="")
    assert res["verdict"] == VERDICT_INSUFFICIENT
    assert "ownership" in res["outcome"]


@pytest.mark.asyncio
async def test_same_actor_or_missing_marker_is_insufficient() -> None:
    hid = _hyp()
    assert (await _run(hid, comparison_actor="actor-a"))["verdict"] == VERDICT_INSUFFICIENT
    assert (await _run(hid, resource_marker=""))["verdict"] == VERDICT_INSUFFICIENT


# --------------------------------------------------------------------------- #
# Vertical
# --------------------------------------------------------------------------- #


async def _run_v(hid: str, **kw: Any) -> dict[str, Any]:
    base = {"test_intent": TEST_VERTICAL, "ownership_assertion": "",
            "privilege_assertion": "only admin may call this per operator policy"}
    base.update(kw)
    return await _run(hid, **base)


@pytest.mark.asyncio
async def test_vertical_genuine_read_bypass() -> None:
    hid = _hyp(category="broken_function_level_authorization")
    res = await _run_v(hid, replay=_replay(
        reference=_resp(200, f"admin report {_MARKER}"),
        anonymous=_resp(403, "denied"),
        comparison=_resp(200, f"low-priv saw {_MARKER}"),  # privilege escalation (read)
    ))
    assert res["verdict"] == VERDICT_BYPASS


@pytest.mark.asyncio
async def test_vertical_correct_denial() -> None:
    hid = _hyp(category="broken_function_level_authorization")
    res = await _run_v(hid, comparison_own_ref="req-b-own", denied_marker="Access Forbidden",
                       replay=_replay(
                           reference=_resp(200, f"admin {_MARKER}"),
                           anonymous=_resp(403, "denied"),
                           comparison=_resp(403, "Access Forbidden by policy"),
                           own=_resp(200, "low-priv own object ok"), own_ref="req-b-own",
                       ))
    assert res["verdict"] == VERDICT_DENIED


@pytest.mark.asyncio
async def test_vertical_unknown_role_ordering_requires_privilege_assertion() -> None:
    hid = _hyp(category="broken_function_level_authorization")
    res = await _run_v(hid, privilege_assertion="")  # no explicit boundary -> cannot infer
    assert res["verdict"] == VERDICT_INSUFFICIENT
    assert "privilege" in res["outcome"]


@pytest.mark.asyncio
async def test_vertical_state_change_requires_safe_object_and_plan() -> None:
    hid = _hyp(category="broken_function_level_authorization")
    raw = "DELETE /orders/1 HTTP/1.1\r\nHost: app.example.com\r\nCookie: session=A-SECRET\r\n\r\n"
    res = await _run_v(hid, retrieve=_retrieve(raw=raw), replay=_replay(
        reference=_resp(200, _MARKER), anonymous=_resp(403), comparison=_resp(200, _MARKER)))
    assert res["verdict"] == VERDICT_INSUFFICIENT
    assert "state-changing" in res["outcome"] and "MANUAL follow-up" in res["outcome"]
    assert "human" in res["next_action"] and "read-only" in res["next_action"]


# --------------------------------------------------------------------------- #
# Scope, unsupported auth, budget, cancellation, secrets
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_out_of_scope_blocks_before_any_replay() -> None:
    hid = _hyp()
    rep = _replay(reference=_resp(200, _MARKER), anonymous=_resp(403),
                  comparison=_resp(200, _MARKER))
    res = await _run(hid, retrieve=_retrieve(url="https://evil.test/orders/1"), replay=rep)
    assert res["verdict"] == VERDICT_BLOCKED and res["in_scope"] is False
    assert rep.seen == []  # no replay traffic at all


@pytest.mark.asyncio
async def test_excluded_port_blocks_before_any_replay() -> None:
    hid = _hyp()
    rep = _replay(reference=_resp(200, _MARKER), anonymous=_resp(403),
                  comparison=_resp(200, _MARKER))
    res = await _run(hid, scan_targets=["https://app.example.com:443"],
                     retrieve=_retrieve(url="https://app.example.com:8443/orders/1"), replay=rep)
    assert res["verdict"] == VERDICT_BLOCKED and res["in_scope"] is False
    assert rep.seen == []


@pytest.mark.asyncio
async def test_unsupported_auth_blocks() -> None:
    hid = _hyp()
    raw = "GET /orders/1 HTTP/1.1\r\nHost: app.example.com\r\nX-CSRF-Token: a\r\n\r\n"
    res = await _run(hid, retrieve=_retrieve(raw=raw))
    assert res["verdict"] == VERDICT_BLOCKED
    assert "CSRF" in res["outcome"] or "signing" in res["outcome"]


@pytest.mark.asyncio
async def test_missing_comparison_session_is_insufficient() -> None:
    hid = _hyp()
    res = await _run(hid, comparison_actor="ghost")  # not in accounts
    assert res["verdict"] == VERDICT_INSUFFICIENT
    assert "session" in res["outcome"]


@pytest.mark.asyncio
async def test_cumulative_budget_across_calls() -> None:
    hid = _hyp()
    rep = _replay(reference=_resp(200, f"owner {_MARKER}"), anonymous=_resp(403),
                  comparison=_resp(403, "access denied by policy"),
                  own=_resp(200, "own ok"), own_ref="req-b-own")
    for _ in range(DEFAULT_ATTEMPT_BUDGET):
        r = await _run(hid, comparison_own_ref="req-b-own", denied_marker="access denied",
                       replay=rep)
        assert r["verdict"] in (VERDICT_DENIED, VERDICT_BYPASS)
    exhausted = await _run(hid, comparison_own_ref="req-b-own", denied_marker="access denied",
                           replay=rep)
    assert exhausted["verdict"] == VERDICT_BLOCKED and "budget exhausted" in exhausted["outcome"]


@pytest.mark.asyncio
async def test_concurrent_calls_do_not_exceed_budget() -> None:
    hid = _hyp()
    rep = _replay(reference=_resp(200, f"owner {_MARKER}"), anonymous=_resp(403),
                  comparison=_resp(403, "access denied by policy"),
                  own=_resp(200, "own ok"), own_ref="req-b-own")
    results = await asyncio.gather(*[
        _run(hid, comparison_own_ref="req-b-own", denied_marker="access denied", replay=rep)
        for _ in range(DEFAULT_ATTEMPT_BUDGET + 3)
    ])
    ran = sum(1 for r in results if r["verdict"] in (VERDICT_DENIED, VERDICT_BYPASS))
    refused = sum(1 for r in results
                  if r["verdict"] == VERDICT_BLOCKED and "budget exhausted" in r["outcome"])
    assert ran == DEFAULT_ATTEMPT_BUDGET  # reservations are atomic under the lock
    assert refused == 3


@pytest.mark.asyncio
async def test_cancellation_after_dispatch_consumes_the_attempt() -> None:
    # The baseline replay is the first traffic; dispatch is marked just before it,
    # so a cancellation here is POST-dispatch and must CONSUME the attempt (never
    # refund — the request may already have been sent).
    hid = _hyp()
    started = asyncio.Event()

    async def hanging_replay(request_id: str, override: dict[str, str] | None) -> dict[str, Any]:
        if override is None:
            started.set()
            await asyncio.Event().wait()
        return _resp(200)

    task = asyncio.create_task(_run(hid, replay=hanging_replay))
    await asyncio.wait_for(started.wait(), timeout=10)
    assert budget_status(hid)["used"] == 1  # reserved + dispatched
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert lookup_hypothesis(hid)["status"] == STATUS_BLOCKED
    assert budget_status(hid)["used"] == 1  # consumed, NOT refunded


@pytest.mark.asyncio
async def test_cancellation_before_reservation_consumes_nothing() -> None:
    # Cancel during retrieval (before any slot is reserved) -> no budget touched.
    hid = _hyp()
    started = asyncio.Event()

    async def hanging_retrieve(_rid: str) -> dict[str, Any]:
        started.set()
        await asyncio.Event().wait()
        return {"found": True, "raw": "GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
                "url": "https://app.example.com/orders/1", "method": "GET"}

    task = asyncio.create_task(_run(hid, retrieve=hanging_retrieve))
    await asyncio.wait_for(started.wait(), timeout=10)
    assert budget_status(hid)["used"] == 0  # not reserved yet
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert budget_status(hid)["used"] == 0  # nothing reserved -> nothing to account


@pytest.mark.asyncio
async def test_no_secrets_in_result_or_evidence() -> None:
    hid = _hyp()
    res = await _run(hid, replay=_replay(
        reference=_resp(200, f"owner {_MARKER} password=hunter2",
                        {"Set-Cookie": "session=LEAK"}),
        anonymous=_resp(403),
        comparison=_resp(200, f"actor-b {_MARKER} password=hunter2",
                         {"Set-Cookie": "session=LEAK"})))
    blob = json.dumps(res) + json.dumps(lookup_hypothesis(hid))
    assert "B-SECRET" not in blob and "A-SECRET" not in blob  # actor cookies
    assert "hunter2" not in blob and "LEAK" not in blob       # body + set-cookie
    # Sanitized evidence carries only statuses + structural fingerprints.
    assert res["semantic"]["fingerprints"]["comparison"]


# --------------------------------------------------------------------------- #
# REAL HTTP integration (Caido layer stubbed by a local http.client replay)
# --------------------------------------------------------------------------- #


_OOS = Counter()


class _VulnApp(BaseHTTPRequestHandler):
    """actor-a owns order 1, actor-b owns order 2. VULNERABLE: no ownership check
    on /orders/<id> — any logged-in actor reads any order."""
    OWNERSHIP_CHECK = False

    def log_message(self, *_a: Any) -> None:
        return

    def _who(self) -> str | None:
        ck = self.headers.get("Cookie", "")
        if "session=a-sess" in ck:
            return "a"
        if "session=b-sess" in ck:
            return "b"
        return None

    def do_GET(self) -> None:
        who = self._who()
        path = self.path.split("?", 1)[0]
        if path.startswith("/orders/"):
            oid = path.rsplit("/", 1)[-1]
            owner = {"1": "a", "2": "b"}.get(oid)
            if who is None:
                self._send(302, "", {"Location": "/login"})
                return
            if self.OWNERSHIP_CHECK and who != owner:
                self._send(403, "Forbidden")
                return
            self._send(200, f"ORDER-{oid}-SECRET-of-{owner}")
            return
        self._send(200, "ok")

    def _send(self, code: int, body: str, headers: dict[str, str] | None = None) -> None:
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


class _FixedApp(_VulnApp):
    OWNERSHIP_CHECK = True


class _OosApp(BaseHTTPRequestHandler):
    def log_message(self, *_a: Any) -> None:
        return

    def do_GET(self) -> None:
        _OOS[self.path] += 1
        self._send()

    def _send(self) -> None:
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OOS")


@contextlib.contextmanager
def _serve(handler: type[BaseHTTPRequestHandler]) -> Any:
    oos = ThreadingHTTPServer(("127.0.0.1", 0), _OosApp)
    threading.Thread(target=oos.serve_forever, daemon=True).start()
    app = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=app.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{app.server_address[1]}", oos.server_address[1]
    finally:
        app.shutdown()
        oos.shutdown()


def _real_retrieve(origin: str, path_q: str) -> Any:
    netloc = urlsplit(origin).netloc
    raw = f"GET {path_q} HTTP/1.1\r\nHost: {netloc}\r\nCookie: session=a-sess\r\n\r\n"

    async def retrieve(_rid: str) -> dict[str, Any]:
        return {"found": True, "raw": raw, "url": f"{origin}{path_q}", "method": "GET"}
    return retrieve


def _real_replay(origin: str, path_q: str) -> Any:
    """Real HTTP replay with a rebuilt, isolated auth context (no Caido)."""
    async def replay(_rid: str, override: dict[str, str] | None) -> dict[str, Any]:
        u = urlsplit(origin)
        conn = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
        headers = {"Host": u.netloc}
        if override is None:
            headers["Cookie"] = "session=a-sess"       # reference actor-a
        elif override:
            headers.update(override)                    # comparison actor-b (stripped+injected)
        # override == {} -> anonymous (no cookie)
        conn.request("GET", path_q, headers=headers)
        r = conn.getresponse()
        status, body = r.status, r.read(2000).decode(errors="replace")
        loc = r.getheader("Location", "") or ""
        conn.close()
        hdrs = {"Location": loc} if loc else {}
        return {"replayed": True, "status": status, "headers": hdrs, "body": body, "timing_ms": 1}
    return replay


def _real_io_routed(origin: str, mapping: dict[str, str]) -> tuple[Any, Any]:
    """Real HTTP retrieve+replay that routes each request_id to its own path — so
    the comparison actor's OWN-object control can target a different resource
    (e.g. actor-b's order 2) than the test request (actor-a's order 1)."""
    netloc = urlsplit(origin).netloc

    async def retrieve(rid: str) -> dict[str, Any]:
        path = mapping[rid]
        raw = f"GET {path} HTTP/1.1\r\nHost: {netloc}\r\nCookie: session=a-sess\r\n\r\n"
        return {"found": True, "raw": raw, "url": f"{origin}{path}", "method": "GET"}

    async def replay(rid: str, override: dict[str, str] | None) -> dict[str, Any]:
        path = mapping[rid]
        u = urlsplit(origin)
        conn = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
        headers = {"Host": u.netloc}
        if override is None:
            headers["Cookie"] = "session=a-sess"
        elif override:
            headers.update(override)
        conn.request("GET", path, headers=headers)
        r = conn.getresponse()
        status, body = r.status, r.read(2000).decode(errors="replace")
        loc = r.getheader("Location", "") or ""
        conn.close()
        hdrs = {"Location": loc} if loc else {}
        return {"replayed": True, "status": status, "headers": hdrs, "body": body, "timing_ms": 1}
    return retrieve, replay


@pytest.mark.asyncio
async def test_real_http_horizontal_bypass_vs_denied_and_scope(_stores: Path) -> None:
    accounts = json.dumps({"principal": "actor-b", "role": "user", "cookie": "session=b-sess"})

    # 1) VULNERABLE app: actor-b reads actor-a's order 1 -> potential bypass.
    with _serve(_VulnApp) as (origin, _oos_port):
        hid = _hyp()
        res = await _run_authz_impl(
            hypothesis_id=hid, request_ref="r", reference_actor="actor-a",
            comparison_actor="actor-b", test_intent=TEST_HORIZONTAL,
            resource_marker="ORDER-1-SECRET", operation_class="read",
            ownership_assertion="actor-a created order 1", accounts_text=accounts,
            retrieve=_real_retrieve(origin, "/orders/1"), replay=_real_replay(origin, "/orders/1"),
            scan_targets=[origin],
        )
        assert res["verdict"] == VERDICT_BYPASS
        assert res["result_status"] == STATUS_NEEDS_VALIDATION

    # 2) FIXED app: ownership check -> actor-b denied. A clean DENIED requires
    #    the comparison session proven valid: actor-b reads its OWN order 2 (200)
    #    while being denied actor-a's order 1 (403).
    with _serve(_FixedApp) as (origin, _oos_port):
        hid2 = _hyp()
        retrieve2, replay2 = _real_io_routed(origin, {"r": "/orders/1", "own-b": "/orders/2"})
        res2 = await _run_authz_impl(
            hypothesis_id=hid2, request_ref="r", reference_actor="actor-a",
            comparison_actor="actor-b", test_intent=TEST_HORIZONTAL,
            resource_marker="ORDER-1-SECRET", operation_class="read",
            ownership_assertion="actor-a created order 1", accounts_text=accounts,
            comparison_own_ref="own-b", comparison_identity_marker="ORDER-2-SECRET-of-b",
            denied_marker="Forbidden",
            retrieve=retrieve2, replay=replay2, scan_targets=[origin],
        )
        assert res2["verdict"] == VERDICT_DENIED
        assert res2["result_status"] == STATUS_TESTING
        assert res2["semantic"]["comparison_session_verified"] is True

    # 3) Scope: an out-of-scope destination is blocked before any HTTP request.
    _OOS.clear()
    with _serve(_VulnApp) as (origin, oos_port):
        hid3 = _hyp()
        res3 = await _run_authz_impl(
            hypothesis_id=hid3, request_ref="r", reference_actor="actor-a",
            comparison_actor="actor-b", test_intent=TEST_HORIZONTAL, resource_marker="x",
            operation_class="read", ownership_assertion="a", accounts_text=accounts,
            retrieve=_real_retrieve(f"http://127.0.0.1:{oos_port}", "/orders/1"),
            replay=_real_replay(origin, "/orders/1"), scan_targets=[origin],
        )
        assert res3["verdict"] == VERDICT_BLOCKED and res3["in_scope"] is False
        assert sum(_OOS.values()) == 0  # excluded origin received zero requests


# --------------------------------------------------------------------------- #
# Hardening #1 — distinct authenticated principals (no identical-session leak)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_identical_credential_context_is_rejected_without_exposing_creds() -> None:
    # Comparison actor resolves to the SAME session the captured request carries.
    hid = _hyp()
    same = json.dumps({"principal": "actor-b", "role": "user", "cookie": "session=A-SECRET"})
    res = await _run(hid, accounts_text=same, replay=_replay(
        reference=_resp(200, f"owner {_MARKER}"), anonymous=_resp(403),
        comparison=_resp(200, f"b sees {_MARKER}")))
    assert res["verdict"] == VERDICT_INSUFFICIENT
    assert "SAME credential context" in res["outcome"]
    # The shared credential is NEVER echoed back — only a one-way hash is compared.
    assert "A-SECRET" not in json.dumps(res) + json.dumps(lookup_hypothesis(hid))


@pytest.mark.asyncio
async def test_indistinguishable_principals_without_markers_is_insufficient() -> None:
    # Captured request carries NO auth header (empty reference context) and no
    # identity markers are supplied -> distinctness cannot be established.
    hid = _hyp()
    raw = "GET /orders/1 HTTP/1.1\r\nHost: app.example.com\r\n\r\n"
    res = await _run(hid, retrieve=_retrieve(raw=raw), replay=_replay(
        reference=_resp(200, f"owner {_MARKER}"), anonymous=_resp(403),
        comparison=_resp(200, f"b {_MARKER}")))
    assert res["verdict"] == VERDICT_INSUFFICIENT
    assert "distinct authenticated principals" in res["outcome"]


@pytest.mark.asyncio
async def test_identity_markers_are_agent_asserted_not_machine_verified() -> None:
    # Explicit app-identity markers distinguish the actors, but they are AGENT-
    # SUPPLIED assertions — never presented as machine-verified; a bypass stays
    # needs_validation with the real-principal check deferred.
    hid = _hyp()
    raw = "GET /orders/1 HTTP/1.1\r\nHost: app.example.com\r\n\r\n"
    res = await _run(hid, retrieve=_retrieve(raw=raw),
                     reference_identity_marker="user:alice",
                     comparison_identity_marker="user:bob",
                     replay=_replay(
                         reference=_resp(200, f"owner {_MARKER}"), anonymous=_resp(403),
                         comparison=_resp(200, f"bob sees {_MARKER}")))
    assert res["verdict"] == VERDICT_BYPASS
    assert res["result_status"] == STATUS_NEEDS_VALIDATION
    ev = res["semantic"]["identity_evidence"]
    assert ev["distinct_by"] == "agent_asserted_identity_markers"
    assert ev["machine_verified"] is False
    assert ev["identity_confidence"] == "asserted_markers"
    assert "not machine-verified" in res["next_action"]


@pytest.mark.asyncio
async def test_same_principal_different_token_stays_needs_validation_weak_identity() -> None:
    # Two DIFFERENT tokens of the SAME account produce different credential
    # hashes, so the executor cannot tell them apart from two real principals.
    # The result must stay needs_validation and flag the identity as a weak,
    # non-verified signal (hash difference != distinct principal).
    hid = _hyp()
    raw = "GET /orders/1 HTTP/1.1\r\nHost: app.example.com\r\nCookie: session=TOKEN1\r\n\r\n"
    same_user_other_token = json.dumps(
        {"principal": "actor-b", "role": "user", "cookie": "session=TOKEN2"})
    res = await _run(hid, accounts_text=same_user_other_token, retrieve=_retrieve(raw=raw),
                     replay=_replay(
                         reference=_resp(200, f"owner {_MARKER}"), anonymous=_resp(403),
                         comparison=_resp(200, f"still {_MARKER}")))
    assert res["verdict"] == VERDICT_BYPASS
    assert res["result_status"] == STATUS_NEEDS_VALIDATION  # capped, never auto-confirmed
    ev = res["semantic"]["identity_evidence"]
    assert ev["machine_verified"] is False and ev["identity_confidence"] == "weak_hash"
    assert "SAME account" in ev["note"]
    assert "does NOT prove" in res["next_action"]


# --------------------------------------------------------------------------- #
# Hardening #2 — semantic comparison discipline (reflection, truncation, policy)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_reflected_marker_in_request_cannot_prove_access() -> None:
    hid = _hyp()
    raw = (f"GET /orders/1?note={_MARKER} HTTP/1.1\r\nHost: app.example.com\r\n"
           "Cookie: session=A-SECRET\r\n\r\n")
    res = await _run(hid, retrieve=_retrieve(
        url=f"https://app.example.com/orders/1?note={_MARKER}", raw=raw),
        replay=_replay(reference=_resp(200, f"owner {_MARKER}"), anonymous=_resp(403),
                       comparison=_resp(200, f"echo {_MARKER}")))
    assert res["verdict"] == VERDICT_INSUFFICIENT
    assert "reflected" in res["outcome"]


@pytest.mark.asyncio
async def test_truncated_comparison_body_is_inconclusive_not_denial() -> None:
    hid = _hyp()
    truncated = {"replayed": True, "status": 200, "headers": {},
                 "body": "partial response without the marker yet", "body_truncated": True,
                 "timing_ms": 2}
    res = await _run(hid, replay=_replay(
        reference=_resp(200, f"owner {_MARKER}"), anonymous=_resp(403), comparison=truncated))
    assert res["verdict"] == VERDICT_INSUFFICIENT
    assert "truncated" in res["outcome"]


@pytest.mark.asyncio
async def test_anonymous_allowed_by_policy_is_expected_public_not_denied() -> None:
    hid = _hyp()
    res = await _run(hid, anonymous_expectation="allow", replay=_replay(
        reference=_resp(200, f"owner {_MARKER}"),
        anonymous=_resp(200, f"anon may read {_MARKER}"),   # allowed per policy
        comparison=_resp(200, f"b also {_MARKER}")))
    assert res["verdict"] == VERDICT_EXPECTED_PUBLIC   # neutral, NOT a denial
    assert "expected public access" in res["outcome"]
    # The anonymous control must not be read as clearing field-level exposure.
    assert "confidential fields" in res["next_action"]


@pytest.mark.asyncio
async def test_different_objects_sharing_generic_text_is_insufficient() -> None:
    # Both pages share a generic word ("Dashboard") but the comparison response
    # does NOT contain the resource-specific marker -> not a leak, inconclusive.
    hid = _hyp()
    res = await _run(hid, replay=_replay(
        reference=_resp(200, f"Invoice Dashboard {_MARKER}"),
        anonymous=_resp(403, "denied"),
        comparison=_resp(200, "Invoice Dashboard")))  # generic shared text, no marker
    assert res["verdict"] == VERDICT_INSUFFICIENT


# --------------------------------------------------------------------------- #
# Hardening #2b — comparison session validity (no false-negative denial)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_denial_without_session_proof_is_inconclusive_not_false_negative() -> None:
    # Comparison is denied (403) but NO own-object control proves its session is
    # valid -> emitting a clean "denied" could hide a real bypass behind an
    # invalid/expired comparison session. Must be inconclusive, not a safe result.
    hid = _hyp()
    res = await _run(hid, replay=_replay(
        reference=_resp(200, f"owner {_MARKER}"),
        anonymous=_resp(403, "denied"),
        comparison=_resp(403, "Forbidden")))
    assert res["verdict"] == VERDICT_INSUFFICIENT
    assert res["verdict"] != VERDICT_DENIED
    assert "session validity was NOT independently confirmed" in res["outcome"]
    assert res["semantic"]["comparison_session_verified"] is False


@pytest.mark.asyncio
async def test_invalid_comparison_session_does_not_produce_false_negative() -> None:
    # The comparison session is actually invalid: its OWN-object control fails
    # (can't even read its own object). The executor must NOT read the downstream
    # denial as a safe "denied" — it returns invalid_session.
    hid = _hyp()
    res = await _run(hid, comparison_own_ref="req-b-own", replay=_replay(
        reference=_resp(200, f"owner {_MARKER}"),
        anonymous=_resp(403, "denied"),
        comparison=_resp(403, "Forbidden"),               # looks like a denial...
        own=_resp(401, "Unauthorized"), own_ref="req-b-own"))  # ...but session is dead
    assert res["verdict"] == VERDICT_INVALID_SESSION
    assert res["verdict"] not in (VERDICT_DENIED, VERDICT_BYPASS)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("own_resp", "label"),
    [
        (_resp(404, "not found"), "404"),
        (_resp(500, "server error"), "5xx"),
        (_resp(200, "some page but not b's marker"), "missing_marker"),
        ({"replayed": False}, "timeout"),
    ],
)
async def test_own_control_nonauth_failure_is_inconclusive_not_invalid_session(
    own_resp: dict[str, Any], label: str,
) -> None:
    # The own-object control fails for a NON-authentication reason (404 / 5xx /
    # missing semantic marker / timeout). That must NOT be read as a session
    # loss. With the comparison denied, the result is inconclusive (unproven
    # session), never invalid_session and never a clean denial.
    hid = _hyp()
    res = await _run(hid, comparison_own_ref="req-b-own", comparison_identity_marker="b-marker",
                     replay=_replay(
                         reference=_resp(200, f"owner {_MARKER}"),
                         anonymous=_resp(403, "denied"),
                         comparison=_resp(403, "Forbidden"),
                         own=own_resp, own_ref="req-b-own"))
    assert res["verdict"] == VERDICT_INSUFFICIENT, label
    assert res["verdict"] != VERDICT_INVALID_SESSION, label
    assert res["semantic"]["comparison_session_verified"] is False, label
    assert res["semantic"]["comparison_session_state"] == "inconclusive", label


@pytest.mark.asyncio
async def test_valid_authenticated_actor_403_is_denied_not_invalid_session() -> None:
    # A VALID authenticated comparison actor (its own-object control passes) that
    # is denied (403) on the tested resource is a correct authorization denial —
    # it must be classified denied_this_test, never invalid_session.
    hid = _hyp()
    res = await _run(hid, comparison_own_ref="req-b-own", comparison_identity_marker="b-marker",
                     denied_marker="Forbidden",
                     replay=_replay(
                         reference=_resp(200, f"owner {_MARKER}"),
                         anonymous=_resp(403, "denied"),
                         comparison=_resp(403, "Forbidden by access policy"),  # app-level denial
                         own=_resp(200, "b's own object b-marker"),       # session proven valid
                         own_ref="req-b-own"))
    assert res["verdict"] == VERDICT_DENIED
    assert res["verdict"] != VERDICT_INVALID_SESSION
    assert res["semantic"]["comparison_session_verified"] is True
    assert res["semantic"]["comparison_session_state"] == "verified"


@pytest.mark.asyncio
async def test_bare_403_without_app_marker_is_uncertain_not_clean_denial() -> None:
    # Session is PROVEN valid, but the denial is a bare 403 with no app-level
    # denial marker. A 403 can come from a WAF or intermediary, so the meaning is
    # preserved as uncertain — never a clean denied_this_test.
    hid = _hyp()
    res = await _run(hid, comparison_own_ref="req-b-own", comparison_identity_marker="b-marker",
                     replay=_replay(
                         reference=_resp(200, f"owner {_MARKER}"),
                         anonymous=_resp(403, "denied"),
                         comparison=_resp(403, ""),                    # bare 403, no app evidence
                         own=_resp(200, "b's own object b-marker"), own_ref="req-b-own"))
    assert res["verdict"] == VERDICT_INSUFFICIENT
    assert res["verdict"] != VERDICT_DENIED
    assert res["semantic"]["comparison_session_verified"] is True        # session IS valid...
    assert res["semantic"]["comparison_denial_app_established"] is False  # ...denial is not
    assert "application-level denial" in res["outcome"]


@pytest.mark.asyncio
async def test_waf_fingerprinted_403_is_flagged_as_intermediary_not_app_denial() -> None:
    # A 403 carrying WAF/challenge fingerprints is positively NOT the app's
    # authorization decision — even with an app-ish marker it stays uncertain and
    # the outcome names the intermediary.
    hid = _hyp()
    res = await _run(hid, comparison_own_ref="req-b-own", comparison_identity_marker="b-marker",
                     denied_marker="denied",
                     replay=_replay(
                         reference=_resp(200, f"owner {_MARKER}"),
                         anonymous=_resp(403, "denied"),
                         # "attention required" + "cloudflare" style challenge body
                         comparison=_resp(403, "Attention Required! denied __cf_chl captcha"),
                         own=_resp(200, "b's own object b-marker"), own_ref="req-b-own"))
    assert res["verdict"] == VERDICT_INSUFFICIENT
    assert res["semantic"]["comparison_waf_suspected"] is True
    assert res["semantic"]["comparison_denial_app_established"] is False
    assert "intermediary" in res["outcome"]


# --------------------------------------------------------------------------- #
# Hardening #3 — auth freshness after the comparison (mid-test session change)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_session_lost_after_comparison_is_unstable_not_bypass() -> None:
    hid = _hyp()
    ref_calls = {"n": 0}

    async def replay(request_id: str, override: dict[str, str] | None) -> dict[str, Any]:
        if override is None:                       # reference baseline, then re-check
            ref_calls["n"] += 1
            if ref_calls["n"] == 1:
                return _resp(200, f"owner {_MARKER}")  # baseline valid
            return _resp(403, "session expired")       # re-check: env changed mid-test
        if override == {}:
            return _resp(403, "denied")
        return _resp(200, f"b sees {_MARKER}")     # looked like a leak...

    res = await _run(hid, replay=replay)
    assert res["verdict"] == VERDICT_UNSTABLE      # ...but discarded: session not fresh
    assert res["session_lost"] is True


# --------------------------------------------------------------------------- #
# Hardening #4 — baseline marker absent: session loss vs marker mismatch
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_baseline_2xx_without_marker_is_unverified_not_invalid_session() -> None:
    # Reference baseline returns 2xx, no login/auth signal, but the marker is
    # absent -> the marker may simply be wrong / content changed. This is NOT a
    # proven session loss; it is inconclusive (baseline_unverified).
    hid = _hyp()
    res = await _run(hid, replay=_replay(
        reference=_resp(200, "account overview, orders tab, nothing matching here"),
        anonymous=_resp(403, "denied"),
        comparison=_resp(200, f"b sees {_MARKER}")))
    assert res["verdict"] == VERDICT_BASELINE_UNVERIFIED
    assert res["verdict"] != VERDICT_INVALID_SESSION
    assert "WITHOUT the resource_marker" in res["outcome"]


@pytest.mark.asyncio
async def test_baseline_login_page_is_invalid_session() -> None:
    # A concrete auth-loss signal (login page on a 2xx) IS a real session loss.
    hid = _hyp()
    res = await _run(hid, replay=_replay(
        reference=_resp(200, "Please log in to continue"),
        anonymous=_resp(403, "denied"),
        comparison=_resp(200, f"b sees {_MARKER}")))
    assert res["verdict"] == VERDICT_INVALID_SESSION
    assert "authentication-loss evidence" in res["outcome"]


@pytest.mark.asyncio
async def test_baseline_401_is_invalid_session() -> None:
    # A 401 on the reference baseline is a concrete expired-session signal.
    hid = _hyp()
    res = await _run(hid, replay=_replay(
        reference=_resp(401, "Unauthorized"),
        anonymous=_resp(403, "denied"),
        comparison=_resp(200, f"b sees {_MARKER}")))
    assert res["verdict"] == VERDICT_INVALID_SESSION


# --------------------------------------------------------------------------- #
# Hardening #5 — read-only boundary (state changes deferred to manual follow-up)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_missing_operation_class_is_insufficient() -> None:
    hid = _hyp()
    res = await _run(hid, operation_class="")
    assert res["verdict"] == VERDICT_INSUFFICIENT
    assert "operation_class is required" in res["outcome"]


@pytest.mark.asyncio
async def test_get_classified_state_change_is_deferred_not_executed() -> None:
    # A GET the agent explicitly classifies state_change (hidden side effects) is
    # deferred even though the HTTP method looks safe.
    hid = _hyp()
    rep = _replay(reference=_resp(200, _MARKER), anonymous=_resp(403),
                  comparison=_resp(200, _MARKER))
    res = await _run(hid, operation_class="state_change", replay=rep)
    assert res["verdict"] == VERDICT_INSUFFICIENT
    assert "classified state_change" in res["outcome"] and "MANUAL follow-up" in res["outcome"]
    assert rep.seen == []  # deferred BEFORE any traffic


@pytest.mark.asyncio
async def test_operator_test_object_does_not_authorize_a_mutation() -> None:
    hid = _hyp()
    raw = "DELETE /orders/1 HTTP/1.1\r\nHost: app.example.com\r\nCookie: session=A-SECRET\r\n\r\n"
    rep = _replay(reference=_resp(200, _MARKER), anonymous=_resp(403),
                  comparison=_resp(200, _MARKER))
    res = await _run(hid, retrieve=_retrieve(raw=raw), replay=rep,
                     operation_class="state_change", operator_test_object=True,
                     verification_plan="delete the throwaway order then re-create it")
    assert res["verdict"] == VERDICT_INSUFFICIENT
    assert "do not authorize an automated mutation" in res["outcome"]
    assert rep.seen == []  # the free-text plan/object did NOT cause a mutation to be sent


# --------------------------------------------------------------------------- #
# Hardening #6 — the committed PRODUCTION adapter through a mocked Caido boundary
# (real build/parse helpers; only the network send is faked)
# --------------------------------------------------------------------------- #


class _FakeCaidoReq:
    def __init__(self, raw: bytes, host: str, *, is_tls: bool) -> None:
        self.raw = raw
        self.host = host
        self.is_tls = is_tls


class _FakeCaidoResult:
    def __init__(self, req: _FakeCaidoReq) -> None:
        self.request = req


@pytest.mark.asyncio
async def test_production_default_replay_complete_cred_replacement_and_no_follow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = (b"GET /orders/1 HTTP/1.1\r\nHost: app.example.com\r\n"
                b"Cookie: session=A-TOKEN\r\nAuthorization: Bearer A-SECRET\r\n"
                b"Accept: application/json\r\n\r\n")

    async def fake_view_request(_rid: str, *, part: str = "request") -> _FakeCaidoResult:
        return _FakeCaidoResult(_FakeCaidoReq(captured, "app.example.com", is_tls=True))

    sent: list[tuple[bytes, Any]] = []

    async def fake_replay_send_raw(_client: Any, *, raw: bytes, connection: Any) -> dict[str, Any]:
        sent.append((raw, connection))
        # 302 toward an EXCLUDED origin — a correct adapter must NOT follow it.
        return {"session_id": "s", "status": "OK", "elapsed_ms": 4,
                "response_raw": (b"HTTP/1.1 302 Found\r\nLocation: http://excluded.test/\r\n"
                                 b"Content-Type: text/html\r\n\r\nredirecting")}

    async def fake_call_with_client(fn: Any) -> Any:
        return await fn(object())

    # Real build_raw_request / parse_raw_request / parse_raw_response /
    # full_url_from_components are used; only the network boundary is faked.
    monkeypatch.setattr(caido_api, "view_request", fake_view_request)
    monkeypatch.setattr(caido_api, "replay_send_raw", fake_replay_send_raw)
    monkeypatch.setattr(caido_api, "call_with_client", fake_call_with_client)

    result = await _default_replay("req-a", {"Cookie": "session=B-TOKEN"})

    # Exactly one raw send — the adapter does not follow the redirect.
    assert len(sent) == 1
    raw_sent, connection = sent[0]
    # Complete credential replacement: actor-b's cookie present; EVERY actor-a
    # credential (cookie value AND bearer token) gone.
    assert b"session=B-TOKEN" in raw_sent
    assert b"A-TOKEN" not in raw_sent
    assert b"Bearer" not in raw_sent and b"A-SECRET" not in raw_sent
    assert b"Authorization" not in raw_sent
    # Destination consistency: derived from the captured request, not the redirect.
    assert connection.host == "app.example.com"
    assert connection.port == 443
    assert connection.is_tls is True
    # The 302 is returned verbatim (no-follow); excluded.test was never contacted.
    assert result["replayed"] is True
    assert result["status"] == 302


@pytest.mark.asyncio
async def test_real_transport_does_not_follow_redirect_to_excluded_origin() -> None:
    # Allowed origin 302s to an excluded counter-server; the single raw send must
    # not chase it, so the excluded server receives zero requests.
    _OOS.clear()
    oos = ThreadingHTTPServer(("127.0.0.1", 0), _OosApp)
    threading.Thread(target=oos.serve_forever, daemon=True).start()
    oos_url = f"http://127.0.0.1:{oos.server_address[1]}/pwn"

    class _RedirApp(BaseHTTPRequestHandler):
        def log_message(self, *_a: Any) -> None:
            return

        def do_GET(self) -> None:
            self.send_response(302)
            self.send_header("Location", oos_url)
            self.end_headers()
            self.wfile.write(b"")

    app = ThreadingHTTPServer(("127.0.0.1", 0), _RedirApp)
    threading.Thread(target=app.serve_forever, daemon=True).start()
    try:
        origin = f"http://127.0.0.1:{app.server_address[1]}"
        replay = _real_replay(origin, "/orders/1")
        out = await replay("r", {"Cookie": "session=b-sess"})
        assert out["status"] == 302            # returned as-is
        assert sum(_OOS.values()) == 0         # excluded origin never contacted
    finally:
        app.shutdown()
        oos.shutdown()
