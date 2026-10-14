"""Tests for the hardened targeted SQLi executor (BLACKBOX improvement #4).

Layers, explicitly distinguished:

- Pure helpers (scope origin/port/path, injection-marker insertion, auth and
  block classification, sanitized metadata) — no transport, no tool.
- Orchestration with a FAKE transport + injected retrieve/baseline providers and
  canned sqlmap output — deterministic coverage of scope blocking (no traffic),
  missing/stale evidence, auth states, session loss, block classification +
  bounded continuation, bounded output, cancellation, and secret handling.
- A PROXY-CONTRACT test: the committed adapter run against fake view_request/
  repeat_request plus the REAL parse/url helpers (catches the arity/schema bugs).
- REAL end-to-end tests: the committed executor + the actual sqlmap binary (host
  subprocess transport) proving location-isolated marking, an excluded port and
  an out-of-scope redirect receiving ZERO requests. Skipped if sqlmap is absent.

Simulated WAF/challenge fixtures are labelled honestly — they do NOT prove
bypass of a real production WAF. Local fixtures only; no external targets.
"""

from __future__ import annotations

import asyncio
import contextlib
import http.client
import io
import json
import os
import re
import shutil
import signal
import sqlite3
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlsplit

import pytest

from strix.tools.attack_surface.tools import hydrate_attack_surface_from_disk
from strix.tools.hypotheses.tools import (
    STATUS_BLOCKED,
    STATUS_NEEDS_VALIDATION,
    STATUS_TESTING,
    _create_impl,
    hydrate_hypotheses_from_disk,
    lookup_hypothesis,
)
from strix.tools.proxy import caido_api
from strix.tools.sqli_executor.tools import (
    AUTH_ANONYMOUS,
    AUTH_AUTHENTICATED,
    AUTH_EXPIRED,
    AUTH_LOGIN_CHALLENGE,
    AUTH_UNKNOWN,
    BLOCK_APP_DENIAL,
    BLOCK_BROWSER_CHALLENGE,
    BLOCK_INVALID_AUTH,
    BLOCK_RATE_LIMIT,
    BLOCK_WAF,
    VERDICT_INJECTABLE,
    VERDICT_NOT_INJECTABLE,
    _baseline_request,
    _build_sqlmap_argv,
    _classify_auth,
    _classify_block,
    _insert_marker,
    _parse_scope,
    _retrieve_request,
    _run_sqli_impl,
    _sanitized_meta,
    _scope_check,
)


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _stores(tmp_path: Path) -> Path:
    hydrate_attack_surface_from_disk(tmp_path)
    hydrate_hypotheses_from_disk(tmp_path)
    return tmp_path


def _sqli_hypothesis(**overrides: Any) -> str:
    base: dict[str, Any] = {
        "endpoint_id": "ep1", "vuln_category": "sql_injection", "resource": "/item/1",
        "actor_ref": "actor-a", "param_name": "id", "param_location": "query",
        "operation": "", "rationale": "id reflects into an error", "next_action": "sqlmap",
        "priority": {}, "evidence": [], "agent_id": None, "agent_name": None,
    }
    base.update(overrides)
    return _create_impl(**base)["hypothesis_id"]


# --------------------------------------------------------------------------- #
# Scope: origin + port + path, from the authoritative scan targets
# --------------------------------------------------------------------------- #


def test_scope_enforces_host_port_and_path_where_specified() -> None:
    # Bare host authorizes any port/path.
    ok, _ = _scope_check("https://app.example.com:8443/anything", ["app.example.com"])
    assert ok
    # Explicit port restricts to that port.
    assert _scope_check("https://h:443/x", ["https://h:443"])[0]
    assert not _scope_check("https://h:8443/x", ["https://h:443"])[0]
    # Explicit path restricts to that prefix (and /apifoo is not under /api).
    assert _scope_check("https://h/api/users", ["https://h/api"])[0]
    assert not _scope_check("https://h/admin", ["https://h/api"])[0]
    assert not _scope_check("https://h/apifoo", ["https://h/api"])[0]
    # Unknown host, or no authorized web host at all.
    assert not _scope_check("https://evil.test/x", ["app.example.com"])[0]
    assert not _scope_check("https://h/x", ["/home/user/repo"])[0]


def test_parse_scope_skips_pathy_whitebox_targets() -> None:
    entries = _parse_scope(["https://app.example.com:8443/api", "/workspace/repo", "10.0.0.5"])
    hosts = {e["host"] for e in entries}
    assert hosts == {"app.example.com", "10.0.0.5"}
    api = next(e for e in entries if e["host"] == "app.example.com")
    assert api["port"] == 8443 and api["path_prefix"] == "/api" and api["scheme"] == "https"


# --------------------------------------------------------------------------- #
# Injection-marker insertion (location isolation)
# --------------------------------------------------------------------------- #


_RAW = ("GET /item?id=1&page=2 HTTP/1.1\r\nHost: h\r\nCookie: id=99; s=x\r\n"
        "X-Trace: t1\r\n\r\n")


def test_marker_targets_only_the_requested_location() -> None:
    q = _insert_marker(_RAW, "id", "query")
    assert q is not None and "id=1*" in q and "id=99*" not in q  # query id, not cookie id
    c = _insert_marker(_RAW, "id", "cookie")
    assert c is not None and "id=99*" in c and "id=1*" not in c  # cookie id, not query id
    h = _insert_marker(_RAW, "X-Trace", "header")
    assert h is not None and "X-Trace: t1*" in h
    # A parameter absent from the requested location is ambiguous -> None (blocked).
    assert _insert_marker(_RAW, "nope", "query") is None
    assert _insert_marker(_RAW, "id", "body") is None  # no body
    assert _insert_marker(_RAW, "id", "path") is None  # path marking is ambiguous


def test_marker_in_form_body() -> None:
    raw = ("POST /login HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded"
           "\r\n\r\nuser=bob&id=5")
    b = _insert_marker(raw, "id", "body")
    assert b is not None and b.endswith("id=5*")


def test_build_argv_is_detection_only_scope_safe_and_markerless() -> None:
    argv = _build_sqlmap_argv(request_file="/t/j.req", output_dir="/t/o", technique="BEU",
                              level=1, risk=1, timeout_connect=15)
    assert "--ignore-redirects" in argv  # no out-of-scope redirect following
    assert "--ignore-stdin" in argv      # -r actually drives the run
    assert "-p" not in argv              # location isolation is via the `*` marker, not -p
    for forbidden in ("--dump", "--os-shell", "--file-read", "--crawl", "--sql-shell"):
        assert forbidden not in argv
    # Continuation flags appear only when asked.
    backoff = _build_sqlmap_argv(request_file="/t/j.req", output_dir="/t/o", technique="B",
                                 level=1, risk=1, timeout_connect=15, delay=2, threads=1)
    assert backoff[backoff.index("--delay") + 1] == "2"
    assert backoff[backoff.index("--threads") + 1] == "1"
    tam = _build_sqlmap_argv(request_file="/t/j.req", output_dir="/t/o", technique="B",
                             level=1, risk=1, timeout_connect=15, tamper="space2comment")
    assert tam[tam.index("--tamper") + 1] == "space2comment"


# --------------------------------------------------------------------------- #
# Auth + block classification (pure)
# --------------------------------------------------------------------------- #


def _meta(status: int, headers: dict[str, str] | None = None, body: str = "") -> dict[str, Any]:
    return _sanitized_meta({"status": status, "headers": headers or {}, "body": body,
                            "timing_ms": 5})


def test_classify_auth_states() -> None:
    assert _classify_auth(has_session=False, meta=_meta(200), body="hi",
                          marker="", absent_marker="") == AUTH_ANONYMOUS
    assert _classify_auth(has_session=True, meta=_meta(200), body="welcome bob",
                          marker="bob", absent_marker="") == AUTH_AUTHENTICATED
    # 200 + session but no marker is NOT proof of auth.
    assert _classify_auth(has_session=True, meta=_meta(200), body="x",
                          marker="", absent_marker="") == AUTH_UNKNOWN
    assert _classify_auth(has_session=True, meta=_meta(401), body="",
                          marker="", absent_marker="") == AUTH_EXPIRED
    assert _classify_auth(has_session=True, meta=_meta(302, {"Location": "/login"}), body="",
                          marker="", absent_marker="") == AUTH_LOGIN_CHALLENGE


def test_classify_block_distinguishes_evidence() -> None:
    assert _classify_block(_meta(403), "")[0] == BLOCK_APP_DENIAL  # plain 403, low confidence
    assert _classify_block(_meta(403), "")[1] == "low"
    assert _classify_block(_meta(403, {"Server": "cloudflare"}), "")[0] == BLOCK_WAF
    assert _classify_block(_meta(403, {"Server": "cloudflare"}), "")[1] == "low"  # vendor != proof
    assert _classify_block(_meta(429, {"Retry-After": "30"}), "")[0] == BLOCK_RATE_LIMIT
    assert _classify_block(_meta(401), "")[0] == BLOCK_INVALID_AUTH
    assert _classify_block(_meta(503, body="Just a moment..."), "")[0] == BLOCK_BROWSER_CHALLENGE


def test_sanitized_meta_stores_no_secrets() -> None:
    meta = _sanitized_meta({
        "status": 200,
        "headers": {"Set-Cookie": "session=SUPERSECRET", "Authorization": "Bearer SEKRET",
                    "Server": "nginx", "Location": "/next?token=LEAKY"},
        "body": "user=bob password=hunter2", "timing_ms": 7,
    })
    blob = json.dumps(meta)
    assert "SUPERSECRET" not in blob and "SEKRET" not in blob and "hunter2" not in blob
    assert "LEAKY" not in blob  # sensitive redirect query stripped
    assert meta["header_values"].get("server") == "nginx"  # allowlisted value kept
    assert "set-cookie" in meta["header_names"]  # name kept, value not
    assert meta["body_fingerprint"]  # structural hash present


# --------------------------------------------------------------------------- #
# Fake transport + injected retrieve/baseline
# --------------------------------------------------------------------------- #


class _Result:
    def __init__(self, exit_code: int, stdout: bytes) -> None:
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = b""

    def ok(self) -> bool:
        return self.exit_code == 0


_INJECTABLE = (
    "sqlmap identified the following injection point(s) with a total of 42 requests:\n"
    "Parameter: id (GET)\n    Type: boolean-based blind\nthe back-end DBMS is SQLite\n"
)
_CLEAN = "all tested parameters do not appear to be injectable.\n"


class FakeTransport:
    def __init__(self, sqlmap_stdout: str = _CLEAN) -> None:
        self.files: dict[str, bytes] = {}
        self.execs: list[tuple[str, ...]] = []
        self.sqlmap_stdout = sqlmap_stdout
        self.sqlmap_timeout = False
        self.last_sqlmap_cmd = ""

    async def exec(self, *command: str, timeout: float | None = None, shell: bool = False) -> Any:
        self.execs.append(tuple(command))
        argv = list(command)
        if argv[:2] == ["sh", "-lc"] and len(argv) >= 3:
            cmd = argv[2]
            if "head -c" in cmd:  # _read_capped: sh -lc SCRIPT sh src dst cap
                src, dst, cap = argv[4], argv[5], int(argv[6])
                data = self.files.get(src)
                if data is None:
                    return _Result(0, b"MISSING")
                self.files[dst] = data[:cap]
                return _Result(0, str(len(data)).encode())
            if "sqlmap" in cmd:
                self.last_sqlmap_cmd = cmd
                if self.sqlmap_timeout:
                    raise TimeoutError
                m = re.search(r">\s+(\S+)\s+2>&1", cmd)
                if m:
                    self.files[m.group(1)] = self.sqlmap_stdout.encode()
                return _Result(0, b"")
            return _Result(0, b"")
        if argv and argv[0] == "rm":
            for p in argv[2:]:
                self.files.pop(p, None)
            return _Result(0, b"")
        return _Result(0, b"")

    async def read(self, path: Any) -> io.IOBase:
        key = str(path)
        if key not in self.files:
            raise FileNotFoundError(key)
        return io.BytesIO(self.files[key])

    async def write(self, path: Any, data: io.IOBase) -> None:
        self.files[str(path)] = data.read()


def _retrieve(url: str = "https://app.example.com/item?id=1", *, found: bool = True,
              with_cookie: bool = True) -> Any:
    netloc = urlsplit(url).netloc
    path_q = urlsplit(url).path + ("?" + urlsplit(url).query if urlsplit(url).query else "")
    raw = f"GET {path_q} HTTP/1.1\r\nHost: {netloc}\r\n"
    if with_cookie:
        raw += "Cookie: session=SUPER-SECRET-COOKIE\r\n"
    raw += "\r\n"

    async def retrieve(_rid: str) -> dict[str, Any] | None:
        if not found:
            return None
        return {"found": True, "raw": raw, "url": url, "method": "GET", "content_type": ""}
    return retrieve


def _baseline(*responses: dict[str, Any]) -> Any:
    seq = list(responses) or [{"replayed": True, "status": 200, "headers": {"Server": "nginx"},
                               "body": "", "timing_ms": 5}]
    calls = {"n": 0}

    async def baseline(_rid: str) -> dict[str, Any]:
        r = seq[min(calls["n"], len(seq) - 1)]
        calls["n"] += 1
        return r
    return baseline


_SCOPE = ["https://app.example.com"]


async def _run(transport: FakeTransport, hid: str, **kw: Any) -> dict[str, Any]:
    params: dict[str, Any] = {
        "hypothesis_id": hid, "request_ref": "caido:req-1", "param_name": "id",
        "param_location": "query", "retrieve": _retrieve(), "baseline": _baseline(),
        "scan_targets": _SCOPE, "agent_id": None, "agent_name": None,
    }
    params.update(kw)
    return await _run_sqli_impl(transport, **params)


# --------------------------------------------------------------------------- #
# Flow: scope (no traffic), evidence, auth, session loss
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_out_of_scope_blocks_before_any_traffic() -> None:
    hid = _sqli_hypothesis()
    t = FakeTransport()
    # baseline must never be called for an out-of-scope destination.
    called = {"n": 0}

    async def never_baseline(_rid: str) -> dict[str, Any]:
        called["n"] += 1
        return {"replayed": True, "status": 200, "headers": {}, "body": ""}

    res = await _run(t, hid, retrieve=_retrieve(url="https://evil.test/item?id=1"),
                     baseline=never_baseline)
    assert res["result_status"] == STATUS_BLOCKED and res["ran_sqlmap"] is False
    assert res["in_scope"] is False
    assert called["n"] == 0  # no baseline traffic sent out of scope
    assert not any("sqlmap" in str(e) for e in t.execs)


@pytest.mark.asyncio
async def test_excluded_port_blocks_before_traffic() -> None:
    hid = _sqli_hypothesis()
    res = await _run(FakeTransport(), hid, scan_targets=["https://app.example.com:443"],
                     retrieve=_retrieve(url="https://app.example.com:8443/item?id=1"))
    assert res["result_status"] == STATUS_BLOCKED and res["in_scope"] is False


@pytest.mark.asyncio
async def test_missing_request_and_baseline_failure_block() -> None:
    hid = _sqli_hypothesis()
    r1 = await _run(FakeTransport(), hid, retrieve=_retrieve(found=False))
    assert r1["result_status"] == STATUS_BLOCKED and "capture" in r1["suggestion"]
    r2 = await _run(FakeTransport(), hid, baseline=_baseline({"replayed": False}))
    assert r2["result_status"] == STATUS_BLOCKED and r2["ran_sqlmap"] is False


@pytest.mark.asyncio
async def test_param_not_in_location_blocks() -> None:
    hid = _sqli_hypothesis()
    res = await _run(FakeTransport(), hid, param_name="id", param_location="body")
    assert res["result_status"] == STATUS_BLOCKED
    assert "not found in location" in res["outcome"]


@pytest.mark.asyncio
async def test_expired_session_pre_blocks_without_sqlmap() -> None:
    hid = _sqli_hypothesis()
    t = FakeTransport(sqlmap_stdout=_INJECTABLE)
    res = await _run(t, hid, auth_marker="welcome",
                     baseline=_baseline({"replayed": True, "status": 401, "headers": {},
                                         "body": "nope"}))
    assert res["result_status"] == STATUS_BLOCKED
    assert res["auth_state"] == AUTH_EXPIRED
    assert res["intended_actor"] == "actor-a"
    assert not any("sqlmap" in str(e) for e in t.execs)


@pytest.mark.asyncio
async def test_session_lost_mid_test_downgrades_not_sqli() -> None:
    hid = _sqli_hypothesis()
    t = FakeTransport(sqlmap_stdout=_INJECTABLE)  # sqlmap "found" injection...
    res = await _run(
        t, hid, auth_marker="welcome",
        baseline=_baseline(
            {"replayed": True, "status": 200, "headers": {}, "body": "welcome bob"},  # pre: auth
            {"replayed": True, "status": 302, "headers": {"Location": "/login"}, "body": ""},
        ),
    )
    # ...but the session was lost: result is downgraded to blocked, NOT injectable.
    assert res["session_lost"] is True
    assert res["result_status"] == STATUS_BLOCKED
    assert res["verdict"] != VERDICT_INJECTABLE
    assert lookup_hypothesis(hid)["status"] == STATUS_BLOCKED


# --------------------------------------------------------------------------- #
# Verdicts, secrets, bounded output, cancellation
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_injectable_is_needs_validation_clean_stays_open() -> None:
    inj = _sqli_hypothesis(resource="/a")
    r1 = await _run(FakeTransport(sqlmap_stdout=_INJECTABLE), inj)
    assert r1["ran_sqlmap"] is True and r1["result_status"] == STATUS_NEEDS_VALIDATION
    assert r1["verdict"] == VERDICT_INJECTABLE
    assert lookup_hypothesis(inj)["status"] == STATUS_NEEDS_VALIDATION
    clean = _sqli_hypothesis(resource="/b")
    r2 = await _run(FakeTransport(sqlmap_stdout=_CLEAN), clean)
    assert r2["result_status"] == STATUS_TESTING and r2["verdict"] == VERDICT_NOT_INJECTABLE


@pytest.mark.asyncio
async def test_no_secrets_in_output_and_temp_scrubbed() -> None:
    hid = _sqli_hypothesis()
    t = FakeTransport(sqlmap_stdout=_INJECTABLE)
    res = await _run(t, hid)
    blob = json.dumps(res) + json.dumps(lookup_hypothesis(hid))
    assert "SUPER-SECRET-COOKIE" not in blob
    # request / log / output artifacts all scrubbed.
    assert not any(k.endswith((".req", ".log")) for k in t.files)
    assert not any(k.endswith(".capped") for k in t.files)


@pytest.mark.asyncio
async def test_large_output_is_bounded_not_deadlocked() -> None:
    hid = _sqli_hypothesis()
    big = _INJECTABLE + ("x" * 5_000_000)  # 5MB of noise after the verdict
    t = FakeTransport(sqlmap_stdout=big)
    res = await _run(t, hid)
    # Verdict still parsed from the bounded (capped) read; no hang.
    assert res["verdict"] == VERDICT_INJECTABLE
    assert res["result_status"] == STATUS_NEEDS_VALIDATION


class _HangingTransport(FakeTransport):
    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()

    async def exec(self, *command: str, timeout: float | None = None, shell: bool = False) -> Any:
        if command[:2] == ("sh", "-lc") and "sqlmap" in command[2]:
            self.started.set()
            await asyncio.Event().wait()
        return await super().exec(*command, timeout=timeout, shell=shell)


@pytest.mark.asyncio
async def test_cancellation_scrubs_and_records_blocked() -> None:
    hid = _sqli_hypothesis()
    t = _HangingTransport()
    task = asyncio.create_task(_run(t, hid))
    await asyncio.wait_for(t.started.wait(), timeout=10)
    assert any(k.endswith(".req") for k in t.files)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not any(k.endswith((".req", ".log")) for k in t.files)
    assert any(e[0] == "pkill" for e in t.execs)
    assert lookup_hypothesis(hid)["status"] == STATUS_BLOCKED


# --------------------------------------------------------------------------- #
# Block classification + bounded continuation
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_baseline_block_classifies_and_recommends_no_sqlmap() -> None:
    hid = _sqli_hypothesis()
    t = FakeTransport(sqlmap_stdout=_INJECTABLE)
    res = await _run(t, hid, baseline=_baseline(
        {"replayed": True, "status": 429, "headers": {"Retry-After": "30"}, "body": ""}))
    assert res["result_status"] == STATUS_BLOCKED and res["ran_sqlmap"] is False
    assert res["block_classification"]["category"] == BLOCK_RATE_LIMIT
    assert "backoff" in res["recommended_continuation"]
    assert not any("sqlmap" in str(e) for e in t.execs)


@pytest.mark.asyncio
async def test_backoff_continuation_applies_bounded_flags_and_records() -> None:
    hid = _sqli_hypothesis()
    t = FakeTransport(sqlmap_stdout=_INJECTABLE)
    res = await _run(t, hid, continuation="backoff", baseline=_baseline(
        {"replayed": True, "status": 429, "headers": {"Retry-After": "5"}, "body": ""}))
    assert res["ran_sqlmap"] is True
    assert "--delay" in t.last_sqlmap_cmd and "--threads 1" in t.last_sqlmap_cmd
    cont = res["continuation"]
    assert cont["action"] == "backoff" and "budget" in cont and "control_comparison" in cont
    # A block clearing + injectable is NOT a confirmed bypass.
    assert res["result_status"] == STATUS_NEEDS_VALIDATION
    assert "not a confirmed bypass" in json.dumps(res).lower() or \
        "NOT a confirmed bypass" in lookup_hypothesis(hid)["attempts"][-1]["validation_required"]


@pytest.mark.asyncio
async def test_tamper_continuation_allowlist_and_mismatch() -> None:
    hid = _sqli_hypothesis()
    waf_baseline = _baseline({"replayed": True, "status": 403,
                              "headers": {"Server": "cloudflare"}, "body": ""})
    # Disallowed tamper is refused.
    bad = await _run(FakeTransport(), hid, continuation="tamper:load_file", baseline=waf_baseline)
    assert bad["result_status"] == STATUS_BLOCKED and "allowlist" in bad["outcome"]
    # Allowlisted tamper on a WAF-classified block runs with --tamper.
    t = FakeTransport(sqlmap_stdout=_CLEAN)
    ok = await _run(t, hid, continuation="tamper:space2comment",
                    baseline=_baseline({"replayed": True, "status": 403,
                                        "headers": {"Server": "cloudflare"}, "body": ""}))
    assert ok["ran_sqlmap"] is True and "--tamper space2comment" in t.last_sqlmap_cmd
    # backoff does not fit a WAF classification -> refused.
    mism = await _run(FakeTransport(), hid, continuation="backoff",
                      baseline=_baseline({"replayed": True, "status": 403,
                                          "headers": {"Server": "cloudflare"}, "body": ""}))
    assert mism["result_status"] == STATUS_BLOCKED and "does not fit" in mism["outcome"]


@pytest.mark.asyncio
async def test_browser_handoff_does_not_run_sqlmap() -> None:
    hid = _sqli_hypothesis()
    t = FakeTransport(sqlmap_stdout=_INJECTABLE)
    res = await _run(t, hid, continuation="browser_handoff", baseline=_baseline(
        {"replayed": True, "status": 503, "headers": {}, "body": "Just a moment..."}))
    assert res["result_status"] == STATUS_BLOCKED and res["ran_sqlmap"] is False
    assert "browser" in json.dumps(res).lower()
    assert not any("sqlmap" in str(e) for e in t.execs)


# --------------------------------------------------------------------------- #
# Proxy contract (fake network calls, REAL parse/url helpers)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_proxy_adapter_matches_caido_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = b"GET /item?id=1 HTTP/1.1\r\nHost: app.example.com\r\nContent-Type: text/x\r\n\r\n"
    fake_result = SimpleNamespace(
        request=SimpleNamespace(raw=raw, host="app.example.com", is_tls=True),
        response=None,
    )

    async def fake_view(request_id: str, *, part: str = "request") -> Any:
        return fake_result

    async def fake_repeat(request_id: str, *, modifications: Any = None) -> dict[str, Any]:
        return {"session_id": "s", "status": "SENT", "error": None, "elapsed_ms": 7,
                "response_raw": b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nhello bob"}

    # Only the NETWORK calls are faked; parse_raw_request/full_url_from_components/
    # parse_raw_response run for real — this is the committed contract.
    monkeypatch.setattr(caido_api, "view_request", fake_view)
    monkeypatch.setattr(caido_api, "repeat_request", fake_repeat)

    got = await _retrieve_request("1")
    assert got is not None
    assert got["url"] == "https://app.example.com/item?id=1"  # full_url_from_components(3 args)
    assert got["method"] == "GET" and got["content_type"] == "text/x"

    base = await _baseline_request("1")
    assert base["replayed"] is True  # repeat_request schema parsed via response_raw
    assert base["status"] == 200
    assert base["headers"].get("Server") == "nginx"
    assert "bob" in base["body"]


# --------------------------------------------------------------------------- #
# REAL sqlmap against disposable apps (location isolation + scope zero-requests)
# --------------------------------------------------------------------------- #


_DB: dict[str, str] = {}
_QVALS: set[str] = set()
_CVALS: set[str] = set()
_OOS = Counter()


class _App(BaseHTTPRequestHandler):
    def log_message(self, *_a: Any) -> None:
        return

    def do_GET(self) -> None:
        u = urlsplit(self.path)
        idv = (parse_qs(u.query).get("id") or [""])[0]
        _QVALS.add(idv)
        ck = self.headers.get("Cookie", "")
        if "id=" in ck:
            _CVALS.add(ck.split("id=", 1)[1].split(";")[0])
        if u.path == "/redir":  # in-scope page that 302s OUT of scope
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{_DB['oos_port']}/pwned")
            self.end_headers()
            return
        conn = sqlite3.connect(_DB["db"])
        try:
            rows = conn.execute(f"SELECT name FROM items WHERE id = '{idv}'").fetchall()
            body, code = ("found:" + ",".join(r[0] for r in rows) if rows else "none"), 200
        except sqlite3.Error as e:
            body, code = f"SQL error: {e}", 500
        finally:
            conn.close()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


class _Oos(BaseHTTPRequestHandler):
    def log_message(self, *_a: Any) -> None:
        return

    def do_GET(self) -> None:
        _OOS[self.path] += 1
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OOS")


class LocalSubprocessTransport:
    async def exec(self, *command: str, timeout: float | None = None, shell: bool = False) -> Any:
        proc = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout)
        except (TimeoutError, asyncio.CancelledError):
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            await proc.wait()
            raise
        return SimpleNamespace(exit_code=proc.returncode, stdout=out or b"", stderr=err or b"")

    async def read(self, path: Any) -> io.IOBase:
        return open(str(path), "rb")  # noqa: PTH123

    async def write(self, path: Any, data: io.IOBase) -> None:
        p = str(path)
        os.makedirs(os.path.dirname(p), exist_ok=True)  # noqa: PTH103, PTH120
        with open(p, "wb") as fh:  # noqa: PTH123
            fh.write(data.read())


@contextlib.contextmanager
def _serve(tmp: Path) -> Any:
    db = str(tmp / "app.db")
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE items(id INTEGER, name TEXT)")
    conn.executemany("INSERT INTO items VALUES(?,?)", [(1, "alpha")])
    conn.commit()
    conn.close()
    _DB["db"] = db
    oos = ThreadingHTTPServer(("127.0.0.1", 0), _Oos)
    threading.Thread(target=oos.serve_forever, daemon=True).start()
    _DB["oos_port"] = str(oos.server_address[1])
    app = ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=app.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{app.server_address[1]}", oos.server_address[1]
    finally:
        app.shutdown()
        oos.shutdown()


def _local_retrieve(origin: str, path_q: str, cookie: str = "") -> Any:
    netloc = urlsplit(origin).netloc
    raw = f"GET {path_q} HTTP/1.1\r\nHost: {netloc}\r\n" + (f"Cookie: {cookie}\r\n" if cookie
                                                            else "") + "\r\n"

    async def retrieve(_rid: str) -> dict[str, Any]:
        return {"found": True, "raw": raw, "url": f"{origin}{path_q}", "method": "GET",
                "content_type": ""}
    return retrieve


def _local_baseline(origin: str, path_q: str) -> Any:
    async def baseline(_rid: str) -> dict[str, Any]:
        u = urlsplit(origin)
        conn = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
        conn.request("GET", path_q, headers={"Host": u.netloc})
        r = conn.getresponse()
        status = r.status
        r.read()
        conn.close()
        return {"replayed": True, "status": status, "headers": {}, "body": "", "timing_ms": 1}
    return baseline


_REAL = shutil.which("sqlmap") is not None


@pytest.mark.skipif(not _REAL, reason="real sqlmap not installed")
@pytest.mark.asyncio
async def test_real_marker_isolates_location_and_scope_blocks_requests(_stores: Path) -> None:
    transport = LocalSubprocessTransport()
    workdir = str(_stores / "sqli")
    _QVALS.clear()
    _CVALS.clear()
    _OOS.clear()
    with _serve(_stores) as (origin, oos_port):
        scope = [origin]

        # 1) Location isolation: id in BOTH query and cookie; target the QUERY.
        hid = _sqli_hypothesis(resource="/item/1")
        r1 = await _run_sqli_impl(
            transport, hypothesis_id=hid, request_ref="r", param_name="id",
            param_location="query", retrieve=_local_retrieve(origin, "/item?id=1", "id=1"),
            baseline=_local_baseline(origin, "/item?id=1"), scan_targets=scope,
            workdir=workdir, technique="BE", timeout=120.0,
        )
        assert r1["ran_sqlmap"] is True and r1["verdict"] == VERDICT_INJECTABLE
        assert len(_QVALS) > 1   # query id was mutated by sqlmap
        assert len(_CVALS) <= 1  # the same-named cookie was NOT touched

        # 2) Out-of-scope REDIRECT: /redir 302s to the OOS port; --ignore-redirects
        #    means the OOS server receives zero requests.
        _OOS.clear()
        hid2 = _sqli_hypothesis(resource="/redir")
        await _run_sqli_impl(
            transport, hypothesis_id=hid2, request_ref="r", param_name="id",
            param_location="query", retrieve=_local_retrieve(origin, "/redir?id=1"),
            baseline=_local_baseline(origin, "/redir?id=1"), scan_targets=scope,
            workdir=workdir, technique="BE", timeout=120.0,
        )
        assert sum(_OOS.values()) == 0  # request-level scope, not ingestion filtering

        # 3) Excluded PORT: a request to a different port is blocked before traffic.
        _OOS.clear()
        hid3 = _sqli_hypothesis(resource="/item/1")
        r3 = await _run_sqli_impl(
            transport, hypothesis_id=hid3, request_ref="r", param_name="id",
            param_location="query",
            retrieve=_local_retrieve(f"http://127.0.0.1:{oos_port}", "/item?id=1"),
            baseline=_local_baseline(origin, "/item?id=1"),  # never called
            scan_targets=scope, workdir=workdir, technique="BE", timeout=60.0,
        )
        assert r3["result_status"] == STATUS_BLOCKED and r3["in_scope"] is False
        assert sum(_OOS.values()) == 0  # excluded port received nothing

    leftover = [f for f in os.listdir(workdir) if f.endswith((".req", ".log"))] \
        if os.path.isdir(workdir) else []  # noqa: PTH208, PTH112
    assert leftover == []
