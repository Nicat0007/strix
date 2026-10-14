"""Tests for actor-aware crawl execution + direct ingestion (BLACKBOX #2).

Three layers, explicitly distinguished:

- Pure helpers (scope, argv, auth classification, session-reference resolution)
  — no sandbox, no subprocess.
- Orchestration with a FAKE transport that honours the sandbox exec/read/write
  contract but returns canned crawler/auth output — deterministic coverage of
  auth outcomes, scope dropping, partial/timeout, credential non-exposure,
  durable job recording, and resume revalidation.
- Real-execution tests on a HOST subprocess transport running the *real* katana
  against disposable loopback apps: actor isolation / scope / invalid session,
  a two-counter proof that an excluded origin receives zero requests (static),
  and a real process-group kill on cancel. Skipped if katana is absent.
- One DOCKER-gated integration test that runs the committed executor through the
  *actual* sandbox transport (``session.exec``/``read``/``write``) against an app
  started inside a real sandbox container — headless JS/XHR, actor isolation,
  expired session, scope, ingestion. Skipped when Docker is unavailable, leaving
  that validation gap explicit.

No external targets in any layer.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
import re
import shutil
import signal
import subprocess
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from strix.runtime import session_manager
from strix.tools.attack_surface.tools import _query_impl, hydrate_attack_surface_from_disk
from strix.tools.crawl_executor.tools import (
    AUTH_INVALID,
    AUTH_UNKNOWN,
    AUTH_VALID,
    SCOPE_CRAWL_FOLLOW,
    SCOPE_REQUEST_LEVEL,
    STATUS_CANCELLED,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PARTIAL,
    _actor_headers,
    _build_katana_argv,
    _classify_auth,
    _duration_seconds,
    _in_scope,
    _list_jobs_impl,
    _parse_auth_output,
    _parse_origins,
    _run_crawl_impl,
    _scope_regex,
    hydrate_crawl_jobs_from_disk,
)


@pytest.fixture(autouse=True)
def _stores(tmp_path: Path) -> Path:
    """Point both durable stores at a per-test run dir (clears module state)."""
    hydrate_crawl_jobs_from_disk(tmp_path)
    hydrate_attack_surface_from_disk(tmp_path)
    return tmp_path


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


def test_parse_origins_normalizes_and_drops_invalid() -> None:
    # A scheme with no host has no resolvable origin and is dropped with a note;
    # a JSON array form is also accepted.
    origins, diags = _parse_origins('["https://app.example.com", "http://x", "http://"]')
    assert "https://app.example.com:443" in origins
    assert "http://x:80" in origins
    assert not any(o.startswith("https://:") or o.endswith("://") for o in origins)
    assert any("no resolvable host" in d for d in diags)


def test_scope_regex_matches_only_authorized_origins() -> None:
    rx = re.compile(_scope_regex(["https://app.example.com:443"]))
    assert rx.match("https://app.example.com:443/a/b")
    assert not rx.match("https://evil.test:443/a")


def test_in_scope_drops_out_of_scope_and_respects_path_prefix() -> None:
    origins = ["https://app.example.com:443"]
    assert _in_scope("https://app.example.com/api/x", origins, [])
    assert not _in_scope("http://evil.test/x", origins, [])  # out-of-scope redirect target
    assert _in_scope("https://app.example.com/api/x", origins, ["/api"])
    assert not _in_scope("https://app.example.com/other", origins, ["/api"])
    # /apifoo must not match prefix /api
    assert not _in_scope("https://app.example.com/apifoo", origins, ["/api"])


def test_duration_seconds() -> None:
    assert _duration_seconds("90s") == 90
    assert _duration_seconds("2m") == 120
    assert _duration_seconds("1h") == 3600
    assert _duration_seconds("") == 120  # default 2m


def test_build_katana_argv_static_disables_redirects_and_scopes() -> None:
    argv = _build_katana_argv(
        out_path="/workspace/.crawl/j.jsonl",
        origins=["https://app.example.com:443"],
        path_scope=[],
        headers_file="/workspace/.crawl/.j.hdr",
        js_crawl=False,
        depth=2, pages=50, duration="2m", rate_limit=50, concurrency=10,
    )
    assert argv[0] == "katana"
    assert "-jsonl" in argv and "-silent" in argv
    assert argv[argv.index("-cs") + 1].startswith("^(")  # scope regex pinned
    assert argv[argv.index("-d") + 1] == "2"
    assert argv[argv.index("-mdp") + 1] == "50"
    assert argv[argv.index("-H") + 1] == "/workspace/.crawl/.j.hdr"
    # Static crawl disables redirects so a redirect to another origin is never requested.
    assert "-dr" in argv
    assert "-hl" not in argv


def test_build_katana_argv_headless_has_js_flags_and_no_redirect_claim() -> None:
    argv = _build_katana_argv(
        out_path="/workspace/.crawl/j.jsonl",
        origins=["https://app.example.com:443"],
        path_scope=["/api"],
        headers_file=None,
        js_crawl=True,
        depth=2, pages=50, duration="2m", rate_limit=50, concurrency=10,
        chrome_data_dir="/workspace/.crawl/.j.chrome",
    )
    assert "-hl" in argv and "-xhr" in argv and "-nos" in argv
    assert argv[argv.index("-cdd") + 1] == "/workspace/.crawl/.j.chrome"  # marker for cancel pkill
    # path scope is folded into the crawl-scope regex and the seed URL.
    assert "/api" in argv[argv.index("-cs") + 1]
    assert argv[argv.index("-u") + 1].endswith("/api")
    # -dr is NOT added for headless (it does not stop browser-initiated requests).
    assert "-dr" not in argv


def test_classify_auth_200_alone_is_unknown_not_valid() -> None:
    outcome, _ev = _classify_auth(
        has_check=False, status=200, marker_present=None, absent_present=None, redirect=None
    )
    assert outcome == AUTH_UNKNOWN
    outcome2, _ = _classify_auth(
        has_check=True, status=200, marker_present=True, absent_present=False, redirect=None
    )
    assert outcome2 == AUTH_VALID


def test_classify_auth_invalid_paths() -> None:
    assert _classify_auth(has_check=True, status=403, marker_present=None,
                          absent_present=None, redirect=None)[0] == AUTH_INVALID
    assert _classify_auth(has_check=True, status=302, marker_present=None,
                          absent_present=None, redirect="http://app/login")[0] == AUTH_INVALID
    assert _classify_auth(has_check=True, status=200, marker_present=False,
                          absent_present=None, redirect=None)[0] == AUTH_INVALID
    assert _classify_auth(has_check=True, status=200, marker_present=None,
                          absent_present=True, redirect=None)[0] == AUTH_INVALID


def test_actor_headers_matches_and_prefixes_bearer() -> None:
    accounts = "\n".join([
        json.dumps({"principal": "a@example.com", "role": "admin", "token": "eyJabc"}),
        json.dumps({"principal": "b@example.com", "role": "user", "cookie": "session=xyz"}),
    ])
    h_admin, _ = _actor_headers(accounts, "a@example.com")
    assert h_admin["Authorization"] == "Bearer eyJabc"
    h_user, _ = _actor_headers(accounts, "user")  # match by role
    assert h_user["Cookie"] == "session=xyz"
    _, diags = _actor_headers(accounts, "nobody")
    assert any("no session entry" in d for d in diags)


def test_parse_auth_output_tristate() -> None:
    parsed = _parse_auth_output("STATUS=200 REDIRECT= MARKER=1 ABSENT=0")
    assert parsed == {"status": 200, "marker_present": True, "absent_present": False,
                      "redirect": None}
    parsed2 = _parse_auth_output("STATUS=302 REDIRECT=http://x/login MARKER=2 ABSENT=2")
    assert parsed2["marker_present"] is None and parsed2["absent_present"] is None


# --------------------------------------------------------------------------- #
# Fake transport (honours the exec/read/write contract; canned output)
# --------------------------------------------------------------------------- #


class _Result:
    def __init__(self, exit_code: int, stdout: bytes) -> None:
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = b""

    def ok(self) -> bool:
        return self.exit_code == 0


class FakeTransport:
    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.execs: list[tuple[str, ...]] = []
        self.katana_artifact: str | None = None
        self.katana_timeout = False
        self.katana_exit = 0
        self.auth_outputs: list[str] = []
        self.reads: list[tuple[str, int]] = []  # (path, bytes served) — memory-bound probe

    async def exec(self, *command: str, timeout: float | None = None, shell: bool = False) -> Any:
        self.execs.append(tuple(command))
        argv = list(command)
        prog = argv[0]
        if prog == "mkdir":
            return _Result(0, b"")
        if prog == "rm":
            for p in argv[2:]:
                self.files.pop(p, None)
            return _Result(0, b"")
        if prog == "sh":
            # In-sandbox CAP command: sh -lc <script> sh <src> <dst> <cap>.
            # Emulate head -c <cap> <src> > <dst> and print the original size.
            if len(argv) >= 7 and argv[1] == "-lc" and "head -c" in argv[2]:
                src, dst, cap = argv[4], argv[5], int(argv[6])
                data = self.files.get(src)
                if data is None:
                    return _Result(0, b"MISSING")
                self.files[dst] = data[:cap]
                return _Result(0, str(len(data)).encode())
            # Auth-check script: sh <script_path>.
            out = self.auth_outputs.pop(0) if self.auth_outputs else ""
            return _Result(0, out.encode())
        if prog == "katana":
            if self.katana_timeout:
                raise TimeoutError
            out_path = argv[argv.index("-o") + 1]
            if self.katana_artifact is not None:
                self.files[out_path] = self.katana_artifact.encode()
            return _Result(self.katana_exit, b"")
        return _Result(0, b"")

    async def read(self, path: Any) -> io.IOBase:
        key = str(path)
        if key not in self.files:
            raise FileNotFoundError(key)
        data = self.files[key]
        self.reads.append((key, len(data)))
        return io.BytesIO(data)

    async def write(self, path: Any, data: io.IOBase) -> None:
        self.files[str(path)] = data.read()


_ARTIFACT = "\n".join([
    json.dumps({"request": {"method": "GET", "endpoint": "https://app.example.com/public"},
                "response": {"status_code": 200}}),
    json.dumps({"request": {"method": "GET", "endpoint": "https://app.example.com/app/secret-a"},
                "response": {"status_code": 200}}),
    json.dumps({"request": {"method": "GET", "endpoint": "http://evil.test/x"},
                "response": {"status_code": 200}}),  # out-of-scope redirect target
])


def _seed_accounts(transport: FakeTransport, actor: str, cookie: str) -> None:
    transport.files["/workspace/recon/auth_accounts.jsonl"] = json.dumps(
        {"principal": actor, "role": actor, "cookie": cookie}
    ).encode()


@pytest.mark.asyncio
async def test_anonymous_job_ingests_in_scope_and_drops_out_of_scope() -> None:
    t = FakeTransport()
    t.katana_artifact = _ARTIFACT
    result = await _run_crawl_impl(t, actor_ref="anonymous", origins_raw="https://app.example.com")
    assert result["status"] == STATUS_COMPLETED
    assert result["auth_state"] == "anonymous"
    assert result["counts"]["created"] == 2
    assert result["counts"]["out_of_scope_dropped"] == 1
    # downstream query sees the in-scope endpoints, never the evil.test one.
    q = _query_impl(origin=None, actor_ref=None, method=None, param_location=None,
                    test_status=None, test_category=None, limit=500)
    origins = {e["origin"] for e in q["endpoints"]}
    assert origins == {"https://app.example.com:443"}


@pytest.mark.asyncio
async def test_actor_valid_auth_labels_observations_authenticated() -> None:
    t = FakeTransport()
    t.katana_artifact = _ARTIFACT
    _seed_accounts(t, "actor-a", "session=sess-a")
    t.auth_outputs = ["STATUS=200 REDIRECT= MARKER=1 ABSENT=0",   # pre-crawl
                      "STATUS=200 REDIRECT= MARKER=1 ABSENT=0"]   # post-crawl
    result = await _run_crawl_impl(
        t, actor_ref="actor-a", origins_raw="https://app.example.com",
        auth_check_url="https://app.example.com/me", auth_check_marker="actor-a",
        auth_check_absent_marker="Sign in",
    )
    assert result["status"] == STATUS_COMPLETED
    assert result["auth_state"] == "authenticated"
    assert result["auth"]["outcome"] == AUTH_VALID
    assert result["auth"]["session_valid_after"] == AUTH_VALID
    q = _query_impl(origin=None, actor_ref="actor-a", method=None, param_location=None,
                    test_status=None, test_category=None, limit=500)
    obs_states = {o["auth_state"] for e in q["endpoints"] for o in e["observations"]}
    assert obs_states == {"authenticated"}


@pytest.mark.asyncio
async def test_actor_invalid_session_aborts_without_crawling() -> None:
    t = FakeTransport()
    t.katana_artifact = _ARTIFACT
    _seed_accounts(t, "actor-a", "session=EXPIRED")
    t.auth_outputs = ["STATUS=302 REDIRECT=https://app.example.com/login MARKER=0 ABSENT=1"]
    result = await _run_crawl_impl(
        t, actor_ref="actor-a", origins_raw="https://app.example.com",
        auth_check_url="https://app.example.com/me", auth_check_marker="actor-a",
        auth_check_absent_marker="Sign in",
    )
    assert result["status"] == STATUS_FAILED
    assert result["auth"]["outcome"] == AUTH_INVALID
    assert result["success"] is False
    # Nothing was crawled: no katana exec, inventory empty.
    assert not any(e and e[0] == "katana" for e in t.execs)
    q = _query_impl(origin=None, actor_ref=None, method=None, param_location=None,
                    test_status=None, test_category=None, limit=500)
    assert q["total_endpoints"] == 0


@pytest.mark.asyncio
async def test_actor_credentials_without_check_are_unknown_not_authenticated() -> None:
    t = FakeTransport()
    t.katana_artifact = _ARTIFACT
    _seed_accounts(t, "actor-a", "session=sess-a")
    result = await _run_crawl_impl(t, actor_ref="actor-a", origins_raw="https://app.example.com")
    assert result["auth_state"] == AUTH_UNKNOWN
    assert result["auth"]["outcome"] == AUTH_UNKNOWN


@pytest.mark.asyncio
async def test_credentials_never_appear_in_output_or_job_record() -> None:
    t = FakeTransport()
    t.katana_artifact = _ARTIFACT
    _seed_accounts(t, "actor-a", "session=SUPER-SECRET-COOKIE")
    t.auth_outputs = ["STATUS=200 REDIRECT= MARKER=1 ABSENT=0",
                      "STATUS=200 REDIRECT= MARKER=1 ABSENT=0"]
    result = await _run_crawl_impl(
        t, actor_ref="actor-a", origins_raw="https://app.example.com",
        auth_check_url="https://app.example.com/me", auth_check_marker="actor-a",
    )
    assert "SUPER-SECRET-COOKIE" not in json.dumps(result)
    jobs = _list_jobs_impl(actor_ref=None, limit=100)
    assert "SUPER-SECRET-COOKIE" not in json.dumps(jobs)
    # The cookie did reach the sandbox headers file (expected), then was scrubbed.
    assert not any(k.endswith(".hdr") for k in t.files)


@pytest.mark.asyncio
async def test_two_actors_stay_isolated() -> None:
    url = "https://app.example.com/app/dashboard/1"
    for actor, cookie in [("actor-a", "session=a"), ("actor-b", "session=b")]:
        t = FakeTransport()
        t.katana_artifact = json.dumps(
            {"request": {"method": "GET", "endpoint": url}, "response": {"status_code": 200}}
        )
        _seed_accounts(t, actor, cookie)
        t.auth_outputs = ["STATUS=200 REDIRECT= MARKER=1 ABSENT=0",
                          "STATUS=200 REDIRECT= MARKER=1 ABSENT=0"]
        await _run_crawl_impl(
            t, actor_ref=actor, origins_raw="https://app.example.com",
            auth_check_url="https://app.example.com/me", auth_check_marker=actor,
        )
    q = _query_impl(origin=None, actor_ref=None, method=None, param_location=None,
                    test_status=None, test_category=None, limit=500)
    endpoint = q["endpoints"][0]
    assert {o["actor_ref"] for o in endpoint["observations"]} == {"actor-a", "actor-b"}


@pytest.mark.asyncio
async def test_timeout_yields_partial_with_ingested_records() -> None:
    t = FakeTransport()
    # katana "times out" but a partial artifact already exists on disk.
    t.katana_timeout = True
    t.files["/workspace/.crawl/placeholder"] = b""  # ensure dir semantics irrelevant for fake

    # Pre-seed the output file the orchestrator will read (partial write).
    class _PartialTransport(FakeTransport):
        async def exec(self, *command: str, timeout: float | None = None,
                       shell: bool = False) -> Any:
            if command and command[0] == "katana":
                out_path = list(command)[list(command).index("-o") + 1]
                self.files[out_path] = _ARTIFACT.encode()  # partial artifact present
                raise TimeoutError
            return await super().exec(*command, timeout=timeout, shell=shell)

    pt = _PartialTransport()
    result = await _run_crawl_impl(pt, actor_ref="anonymous", origins_raw="https://app.example.com")
    assert result["status"] == STATUS_PARTIAL
    assert result["counts"]["created"] == 2
    assert "time budget" in result["remaining_work"]


@pytest.mark.asyncio
async def test_output_truncation_marks_partial() -> None:
    t = FakeTransport()
    t.katana_artifact = _ARTIFACT
    # Tiny cap forces truncation.
    result = await _run_crawl_impl(
        t, actor_ref="anonymous", origins_raw="https://app.example.com", output_cap=10,
    )
    assert result["output_truncated"] is True
    assert result["status"] == STATUS_PARTIAL


@pytest.mark.asyncio
async def test_job_is_durable_and_resume_flags_authenticated_for_revalidation(
    _stores: Path,
) -> None:
    t = FakeTransport()
    t.katana_artifact = _ARTIFACT
    _seed_accounts(t, "actor-a", "session=sess-a")
    t.auth_outputs = ["STATUS=200 REDIRECT= MARKER=1 ABSENT=0",
                      "STATUS=200 REDIRECT= MARKER=1 ABSENT=0"]
    done = await _run_crawl_impl(
        t, actor_ref="actor-a", origins_raw="https://app.example.com",
        auth_check_url="https://app.example.com/me", auth_check_marker="actor-a",
    )
    # Simulate a resuming process: fresh hydrate from the persisted job file.
    hydrate_crawl_jobs_from_disk(_stores)
    restored = _list_jobs_impl(actor_ref="actor-a", limit=10)
    assert restored["total_jobs"] == 1
    job = restored["jobs"][0]
    assert job["job_id"] == done["job_id"]
    assert job["requires_revalidation"] is True  # authenticated session not trusted post-resume


# --------------------------------------------------------------------------- #
# Real execution: committed executor + real katana against a loopback app
# --------------------------------------------------------------------------- #


class _App(BaseHTTPRequestHandler):
    def log_message(self, *_a: Any) -> None:  # silence
        return

    def _send(self, code: int, body: str, location: str | None = None) -> None:
        self.send_response(code)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self) -> None:
        cookie = self.headers.get("Cookie", "")
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(200, '<a href="/public">p</a><a href="/app">app</a>'
                            '<a href="/external">ext</a>')
        elif path == "/public":
            self._send(200, "public ok")
        elif path == "/login":
            self._send(200, "Sign in please")
        elif path == "/external":
            self._send(302, "", location="http://127.0.0.1:59999/evil-admin")
        elif path == "/app":
            if "session=sess-a" in cookie:
                self._send(200, 'Welcome actor-a <a href="/app/secret-a">s</a>')
            elif "session=sess-b" in cookie:
                self._send(200, 'Welcome actor-b <a href="/app/secret-b">s</a>')
            else:
                self._send(302, "", location="/login")
        elif path.startswith("/app/secret-"):
            who = path.rsplit("-", 1)[-1]
            if f"session=sess-{who}" in cookie:
                self._send(200, f"secret for {who}")
            else:
                self._send(302, "", location="/login")
        else:
            self._send(404, "nope")


class LocalSubprocessTransport:
    """A host stand-in for the sandbox session: real subprocess + real files.
    Same exec/read/write contract the live session satisfies."""

    async def exec(self, *command: str, timeout: float | None = None, shell: bool = False) -> Any:
        # Own process group so a cancel/timeout kills the whole crawl tree
        # (katana + its chrome children), not just the immediate parent.
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
        return open(str(path), "rb")  # noqa: PTH123 — caller closes

    async def write(self, path: Any, data: io.IOBase) -> None:
        p = str(path)
        os.makedirs(os.path.dirname(p), exist_ok=True)  # noqa: PTH103, PTH120
        with open(p, "wb") as fh:  # noqa: PTH123
            fh.write(data.read())


@contextlib.contextmanager
def _serve() -> Any:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _App)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()


_REAL = shutil.which("katana") is not None and shutil.which("curl") is not None


@pytest.mark.skipif(not _REAL, reason="real katana/curl not installed")
@pytest.mark.asyncio
async def test_real_katana_actor_isolation_scope_and_invalid_session(_stores: Path) -> None:
    transport = LocalSubprocessTransport()
    workdir = str(_stores / "crawl")
    accounts = _stores / "auth_accounts.jsonl"
    accounts.write_text(
        "\n".join([
            json.dumps({"principal": "actor-a", "role": "a", "cookie": "session=sess-a"}),
            json.dumps({"principal": "expired", "role": "expired", "cookie": "session=NOPE"}),
        ]),
        encoding="utf-8",
    )
    with _serve() as origin:
        common = {
            "origins_raw": origin,
            "duration": "30s",
            "depth": 2,
            "pages": 50,
            "workdir": workdir,
            "accounts_path": str(accounts),
        }
        # 1) Anonymous: sees /public, never the authenticated-only secret.
        anon = await _run_crawl_impl(transport, actor_ref="anonymous", **common)
        assert anon["status"] == STATUS_COMPLETED

        # 2) actor-a with a valid session: authenticated-only /app/secret-a discovered.
        acc_a = await _run_crawl_impl(
            transport, actor_ref="actor-a",
            auth_check_url=f"{origin}/app", auth_check_marker="Welcome actor-a",
            auth_check_absent_marker="Sign in", **common,
        )
        assert acc_a["auth_state"] == "authenticated"
        assert acc_a["auth"]["outcome"] == AUTH_VALID

        # 3) expired session: invalid, aborts before crawling.
        expired = await _run_crawl_impl(
            transport, actor_ref="expired",
            auth_check_url=f"{origin}/app", auth_check_marker="Welcome",
            auth_check_absent_marker="Sign in", **common,
        )
        assert expired["status"] == STATUS_FAILED
        assert expired["auth"]["outcome"] == AUTH_INVALID

    q = _query_impl(origin=None, actor_ref=None, method=None, param_location=None,
                    test_status=None, test_category=None, limit=500)
    paths_by_actor: dict[str, set[str]] = {}
    for e in q["endpoints"]:
        for o in e["observations"]:
            paths_by_actor.setdefault(str(o["actor_ref"]), set()).add(e["path"])

    # Authenticated-only discovery: the secret is only under actor-a, never anonymous.
    assert any("/app/secret-a" in p for p in paths_by_actor.get("actor-a", set()))
    assert not any("secret" in p for p in paths_by_actor.get("anonymous", set()))
    # Scope handling: the out-of-scope redirect target was never ingested.
    assert all("evil-admin" not in e["path"] and ":59999" not in e["origin"]
               for e in q["endpoints"])
    # Durable job history recorded all three jobs.
    assert _list_jobs_impl(actor_ref=None, limit=100)["total_jobs"] == 3


# --------------------------------------------------------------------------- #
# Item 2 — authentication provenance: session loss does not retroactively label
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_session_loss_downgrades_to_unknown_not_authenticated() -> None:
    t = FakeTransport()
    t.katana_artifact = _ARTIFACT
    _seed_accounts(t, "actor-a", "session=sess-a")
    t.auth_outputs = [
        "STATUS=200 REDIRECT= MARKER=1 ABSENT=0",  # pre-check: valid (crawl authorized)
        "STATUS=302 REDIRECT=https://app.example.com/login MARKER=0 ABSENT=1",  # post: invalid
    ]
    res = await _run_crawl_impl(
        t, actor_ref="actor-a", origins_raw="https://app.example.com",
        auth_check_url="https://app.example.com/me", auth_check_marker="actor-a",
        auth_check_absent_marker="Sign in",
    )
    # Intended actor is still recorded, kept separate from verified auth.
    assert res["intended_actor"] == "actor-a"
    assert res["auth"]["outcome"] == AUTH_VALID  # pre-check was valid
    assert res["auth"]["session_valid_after"] == AUTH_INVALID
    assert res["auth"]["downgraded"] is True
    # The whole crawl is NOT labelled authenticated: observations are 'unknown'.
    assert res["auth_state"] == AUTH_UNKNOWN
    assert res["status"] == STATUS_PARTIAL
    assert "re-crawl" in res["remaining_work"] or "re-provision" in res["remaining_work"]
    q = _query_impl(origin=None, actor_ref="actor-a", method=None, param_location=None,
                    test_status=None, test_category=None, limit=500)
    states = {o["auth_state"] for e in q["endpoints"] for o in e["observations"]}
    assert states == {"unknown"}  # never 'authenticated'


# --------------------------------------------------------------------------- #
# Item 5 — artifact transfer is bounded IN-SANDBOX before the host read
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_artifact_transfer_is_bounded_before_read() -> None:
    t = FakeTransport()
    big = "\n".join(
        json.dumps({"request": {"method": "GET", "endpoint": f"https://app.example.com/p{i}"},
                    "response": {"status_code": 200}})
        for i in range(8000)
    )
    assert len(big) > 500_000  # ~0.5MB+ artifact
    t.katana_artifact = big
    res = await _run_crawl_impl(
        t, actor_ref="anonymous", origins_raw="https://app.example.com", output_cap=1000,
    )
    assert res["output_truncated"] is True
    assert res["status"] == STATUS_PARTIAL
    # The host only ever received <= cap bytes for the artifact (the capped slice),
    # proving the whole file was not buffered before the cap applied.
    artifact_reads = [n for (p, n) in t.reads if p.endswith(".capped")]
    assert artifact_reads and all(n <= 1000 for n in artifact_reads)
    # The raw full output file was never read directly.
    assert all(not p.endswith(f"{res['job_id']}.jsonl") for (p, _n) in t.reads)
    # The truncated final partial JSONL record was handled explicitly.
    job = _list_jobs_impl(actor_ref=None, limit=10)["jobs"][-1]
    assert any("final JSONL record truncated" in d for d in job["diagnostics"])


# --------------------------------------------------------------------------- #
# Item 1 (headless limitation) — reported honestly, not claimed as prevention
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_headless_scope_is_reported_as_crawl_follow_only() -> None:
    t = FakeTransport()
    t.katana_artifact = _ARTIFACT
    static = await _run_crawl_impl(t, actor_ref="anonymous", origins_raw="https://app.example.com")
    assert static["scope_enforcement"] == SCOPE_REQUEST_LEVEL

    t2 = FakeTransport()
    t2.katana_artifact = _ARTIFACT
    headless = await _run_crawl_impl(
        t2, actor_ref="anonymous", origins_raw="https://app.example.com", js_crawl=True,
    )
    assert headless["scope_enforcement"] == SCOPE_CRAWL_FOLLOW
    assert any("cannot prevent browser-initiated out-of-scope" in d
               for d in _list_jobs_impl(actor_ref=None, limit=10)["jobs"][-1]["diagnostics"])


# --------------------------------------------------------------------------- #
# Item 3 — cancellation: orchestrator cleanup + real process-group kill
# --------------------------------------------------------------------------- #


class _HangingTransport(FakeTransport):
    """Hangs at the katana exec until cancelled, so the orchestrator's cancel
    path (cleanup + cancelled persistence) can be exercised deterministically."""

    def __init__(self) -> None:
        super().__init__()
        self.katana_started = asyncio.Event()

    async def exec(self, *command: str, timeout: float | None = None, shell: bool = False) -> Any:
        if command and command[0] == "katana":
            self.katana_started.set()
            await asyncio.Event().wait()  # block until cancelled
        return await super().exec(*command, timeout=timeout, shell=shell)


@pytest.mark.asyncio
async def test_orchestrator_cancellation_cleans_up_and_persists() -> None:
    t = _HangingTransport()
    _seed_accounts(t, "actor-a", "session=sess-a")
    t.auth_outputs = ["STATUS=200 REDIRECT= MARKER=1 ABSENT=0"]  # pre valid, then hang in crawl
    task = asyncio.create_task(_run_crawl_impl(
        t, actor_ref="actor-a", origins_raw="https://app.example.com",
        auth_check_url="https://app.example.com/me", auth_check_marker="actor-a",
    ))
    await asyncio.wait_for(t.katana_started.wait(), timeout=10)
    assert any(k.endswith(".hdr") for k in t.files)  # credential file exists pre-cancel
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # Credential file removed, a cancelled outcome persisted.
    assert not any(k.endswith(".hdr") for k in t.files)
    assert any(e[0] == "pkill" for e in t.execs)  # crawler signalled
    jobs = _list_jobs_impl(actor_ref="actor-a", limit=10)["jobs"]
    assert jobs and jobs[-1]["status"] == STATUS_CANCELLED


@pytest.mark.skipif(os.name != "posix", reason="process-group kill is POSIX-only")
@pytest.mark.asyncio
async def test_local_transport_kills_process_group_on_cancel(_stores: Path) -> None:
    transport = LocalSubprocessTransport()
    pidfile = str(_stores / "cancel.pid")
    task = asyncio.create_task(
        transport.exec("sh", "-lc", f"sleep 300 & echo $! > {pidfile}; wait")
    )
    for _ in range(100):  # wait for the long child to spawn
        await asyncio.sleep(0.05)
        if os.path.exists(pidfile):  # noqa: PTH110
            break
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0.3)
    with open(pidfile) as fh:  # noqa: PTH123
        child_pid = int(fh.read().strip())
    # The whole process group (the long-running child) was killed, not just the shell.
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)


# --------------------------------------------------------------------------- #
# Item 1 — request-level scope proven with a second counter server
# --------------------------------------------------------------------------- #


def _counter_handler(hits: Counter, other: str) -> type[BaseHTTPRequestHandler]:
    class H(BaseHTTPRequestHandler):
        def log_message(self, *_a: Any) -> None:
            return

        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            hits[path] += 1
            if path == "/" and other:
                body = (f'<a href="{other}/offscope-link">x</a><a href="/go-b">r</a>'
                        f'<script>fetch("{other}/xhr-fetch")</script>').encode()
                self._ok(body)
            elif path == "/go-b" and other:
                self.send_response(302)
                self.send_header("Location", f"{other}/redirected")
                self.end_headers()
            else:
                self._ok(b"ok")

        def _ok(self, body: bytes) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
    return H


@contextlib.contextmanager
def _serve_scope_pair() -> Any:
    hits_b: Counter = Counter()
    srv_b = ThreadingHTTPServer(("127.0.0.1", 0), _counter_handler(hits_b, other=""))
    threading.Thread(target=srv_b.serve_forever, daemon=True).start()
    origin_b = f"http://127.0.0.1:{srv_b.server_address[1]}"
    srv_a = ThreadingHTTPServer(("127.0.0.1", 0), _counter_handler(Counter(), other=origin_b))
    threading.Thread(target=srv_a.serve_forever, daemon=True).start()
    origin_a = f"http://127.0.0.1:{srv_a.server_address[1]}"
    try:
        yield origin_a, hits_b
    finally:
        srv_a.shutdown()
        srv_b.shutdown()


@pytest.mark.skipif(not _REAL, reason="real katana not installed")
@pytest.mark.asyncio
async def test_real_static_crawl_makes_no_out_of_scope_requests(_stores: Path) -> None:
    transport = LocalSubprocessTransport()
    with _serve_scope_pair() as (origin_a, hits_b):
        res = await _run_crawl_impl(
            transport, actor_ref="anonymous", origins_raw=origin_a,
            duration="30s", depth=2, pages=50,
            workdir=str(_stores / "crawl"), accounts_path=str(_stores / "none.jsonl"),
        )
        await asyncio.sleep(0.3)  # let any late server threads settle
    assert res["status"] in (STATUS_COMPLETED, STATUS_PARTIAL)
    assert res["scope_enforcement"] == SCOPE_REQUEST_LEVEL
    # The excluded origin received ZERO requests from the executor: the
    # out-of-scope link was not followed, the redirect to it was not followed
    # (-dr), and no JS ran to fetch it. This is request-level prevention, not
    # ingestion filtering.
    assert sum(hits_b.values()) == 0, dict(hits_b)


# --------------------------------------------------------------------------- #
# Item 4 — the committed executor through the ACTUAL sandbox transport (docker)
# --------------------------------------------------------------------------- #


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True,  # noqa: S607
                              timeout=15, check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


_SBX_IMAGE = "strix-sandbox:dev"
_SBX_APP = """
import http.server, socketserver
class App(http.server.BaseHTTPRequestHandler):
    def log_message(self,*a): return
    def s(self,c,b,loc=None):
        self.send_response(c)
        if loc: self.send_header('Location',loc)
        self.send_header('Content-Type','text/html')
        self.end_headers()
        self.wfile.write(b.encode())
    def do_GET(self):
        ck=self.headers.get('Cookie','')
        p=self.path.split('?',1)[0]
        if p=='/': self.s(200,'<a href="/public">p</a><a href="/app">a</a><a href=/external>x</a>')
        elif p=='/public': self.s(200,'public ok')
        elif p=='/login': self.s(200,'Sign in please')
        elif p=='/external': self.s(302,'',loc='http://127.0.0.1:59999/evil-admin')
        elif p=='/app':
            if 'session=sess-a' in ck: self.s(200,'Welcome actor-a <a href="/app/secret-a">s</a>')
            elif 'session=sess-b' in ck: self.s(200,'Welcome actor-b <a href="/app/secret-b">s</a>')
            else: self.s(302,'',loc='/login')
        else: self.s(200,'ok')
socketserver.ThreadingTCPServer.allow_reuse_address=True
socketserver.ThreadingTCPServer(('127.0.0.1',8899),App).serve_forever()
"""


@pytest.mark.skipif(not _docker_available(), reason="docker/sandbox image unavailable")
@pytest.mark.asyncio
async def test_sandbox_transport_end_to_end(_stores: Path) -> None:
    """Drive the committed executor through a REAL sandbox session — the actual
    session.exec/read/write transport — against an app running inside the
    container. This is the only layer that exercises the production transport."""
    scan_id = "pytest-crawl-exec-sbx"
    bundle = await session_manager.create_or_reuse(
        scan_id, image=_SBX_IMAGE, local_sources=[]
    )
    session = bundle["session"]
    try:
        # Transport contract: write -> exec -> read round-trip.
        await session.write(Path("/workspace/app.py"), io.BytesIO(_SBX_APP.encode()))
        accounts = "\n".join([
            json.dumps({"principal": "actor-a", "role": "a", "cookie": "session=sess-a"}),
            json.dumps({"principal": "actor-b", "role": "b", "cookie": "session=sess-b"}),
            json.dumps({"principal": "expired", "role": "x", "cookie": "session=NOPE"}),
        ])
        await session.write(Path("/workspace/recon/auth_accounts.jsonl"),
                            io.BytesIO(accounts.encode()))
        back = await session.exec("cat", "/workspace/recon/auth_accounts.jsonl", shell=False)
        assert b"actor-a" in back.stdout  # read-back through the real transport

        await session.exec(
            "sh", "-lc",
            "cd /workspace && nohup python3 app.py >/workspace/app.log 2>&1 & sleep 2",
            shell=False,
        )
        up = await session.exec(
            "sh", "-lc", "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8899/public",
            shell=False,
        )
        assert up.stdout.strip() == b"200"

        base = {"origins_raw": "http://127.0.0.1:8899", "duration": "40s", "depth": 2, "pages": 50}
        anon = await _run_crawl_impl(session, actor_ref="anonymous", **base)
        assert anon["status"] in (STATUS_COMPLETED, STATUS_PARTIAL)
        assert anon["counts"]["created"] >= 1

        acc_a = await _run_crawl_impl(
            session, actor_ref="actor-a", js_crawl=True,
            auth_check_url="http://127.0.0.1:8899/app", auth_check_marker="Welcome actor-a",
            auth_check_absent_marker="Sign in", **base,
        )
        assert acc_a["auth"]["outcome"] == AUTH_VALID
        assert acc_a["auth_state"] == "authenticated"  # pre AND post valid

        expired = await _run_crawl_impl(
            session, actor_ref="expired",
            auth_check_url="http://127.0.0.1:8899/app", auth_check_marker="Welcome",
            auth_check_absent_marker="Sign in", **base,
        )
        assert expired["status"] == STATUS_FAILED
        assert expired["auth"]["outcome"] == AUTH_INVALID
    finally:
        await session_manager.cleanup(scan_id)

    q = _query_impl(origin=None, actor_ref=None, method=None, param_location=None,
                    test_status=None, test_category=None, limit=500)
    by_actor: dict[str, set[str]] = {}
    for e in q["endpoints"]:
        for o in e["observations"]:
            by_actor.setdefault(str(o["actor_ref"]), set()).add(e["path"])
    # Actor isolation: both actors observed, anonymous never saw an authed-only path.
    assert "actor-a" in by_actor and "anonymous" in by_actor
    assert not any("secret" in p for p in by_actor.get("anonymous", set()))
    # Scope: the out-of-scope redirect target was never ingested.
    assert all(":59999" not in e["origin"] and "evil" not in e["path"] for e in q["endpoints"])
