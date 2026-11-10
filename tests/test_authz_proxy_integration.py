"""OPT-IN live production-proxy integration harness for the authorization
executor (BLACKBOX #5).

This is NOT a mock test. It drives the COMMITTED production proxy adapter
(`strix.tools.proxy.caido_api` + `authorization_executor._default_retrieve/
_default_replay`) against a real, locally-running Caido instance and a
disposable loopback two-actor app. When no live proxy is configured it SKIPS
with an explicit reason naming exactly what the operator must provide — it never
reports success from mocks.

Run it with a live Caido:

    STRIX_AUTHZ_LIVE_PROXY=1 \\
    STRIX_CAIDO_URL=http://127.0.0.1:48080 \\
    venv/bin/python -m pytest tests/test_authz_proxy_integration.py -v

Tiers:

- Tier A (needs: opt-in flag + reachable Caido) exercises the live Caido replay
  transport through the real `caido_api.build_raw_request` + `replay_send_raw` +
  `call_with_client`: complete credential replacement, destination consistency,
  and redirect zero-request (no-follow) proof against loopback servers.

- Tier B (needs: Tier A + a request already captured in the proxy, supplied as
  STRIX_AUTHZ_TEST_REQUEST_REF, plus an accounts file at
  STRIX_AUTHZ_ACCOUNTS_FILE) runs the full `_run_authz_impl` end-to-end with the
  PRODUCTION defaults (`retrieve=None, replay=None` -> `_default_retrieve` /
  `_default_replay`) and asserts the classification controls.

No external targets: every server here binds 127.0.0.1. Nothing is installed or
configured automatically — the operator stands up Caido and points it at the
loopback app themselves.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

from strix.tools.attack_surface.tools import hydrate_attack_surface_from_disk
from strix.tools.authorization_executor.tools import _rebuild_headers, _run_authz_impl
from strix.tools.hypotheses.tools import _create_impl, hydrate_hypotheses_from_disk
from strix.tools.proxy import caido_api


_OPT_IN_ENV = "STRIX_AUTHZ_LIVE_PROXY"
_REQUEST_REF_ENV = "STRIX_AUTHZ_TEST_REQUEST_REF"
_ACCOUNTS_ENV = "STRIX_AUTHZ_ACCOUNTS_FILE"


def _caido_reachable() -> tuple[bool, str]:
    """Probe the live Caido GraphQL endpoint via the SAME guest-login the
    production adapter uses. Returns (ok, reason-if-not)."""
    try:
        caido_api._login_as_guest()  # the real guest-login probe the adapter uses
    except Exception as exc:  # noqa: BLE001
        return False, (f"Caido not reachable at {caido_api.caido_url()} "
                       f"({type(exc).__name__}: {exc})")
    return True, ""


def _require_live_proxy() -> None:
    """Skip unless the operator has explicitly opted in AND a live Caido answers.
    The skip message states precisely what is missing."""
    if os.environ.get(_OPT_IN_ENV) != "1":
        pytest.skip(
            f"live proxy integration is opt-in: set {_OPT_IN_ENV}=1 and run a local Caido "
            f"(default {os.environ.get('STRIX_CAIDO_URL', 'http://127.0.0.1:48080')}; override "
            "with STRIX_CAIDO_URL) to exercise the production adapter end-to-end")
    pytest.importorskip("caido_sdk_client", reason="caido_sdk_client not installed in this venv")
    ok, reason = _caido_reachable()
    if not ok:
        pytest.skip(f"{_OPT_IN_ENV}=1 but no usable live Caido: {reason}. Start Caido and retry.")


# --------------------------------------------------------------------------- #
# Loopback fixtures (127.0.0.1 only) — a two-actor app + a redirect counter
# --------------------------------------------------------------------------- #

_REDIR_HITS: Counter[str] = Counter()


class _TwoActorApp(BaseHTTPRequestHandler):
    """actor-a owns order 1. /redirect 302s to the excluded counter-server."""

    redirect_to = ""  # set per-serve

    def log_message(self, *_a: Any) -> None:
        return

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/redirect":
            self.send_response(302)
            self.send_header("Location", self.redirect_to)
            self.end_headers()
            self.wfile.write(b"")
            return
        ck = self.headers.get("Cookie", "")
        auth = self.headers.get("Authorization", "")
        # Echo which credentials actually arrived so the test can assert the
        # replayed request carried ONLY the intended actor's context.
        body = f"path={path} cookie={ck!r} authorization={auth!r} ORDER-1-SECRET"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())


class _Counter(BaseHTTPRequestHandler):
    def log_message(self, *_a: Any) -> None:
        return

    def do_GET(self) -> None:
        _REDIR_HITS[self.path] += 1
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"EXCLUDED")


@contextlib.contextmanager
def _serve_two_actor() -> Any:
    counter = ThreadingHTTPServer(("127.0.0.1", 0), _Counter)
    threading.Thread(target=counter.serve_forever, daemon=True).start()
    _TwoActorApp.redirect_to = f"http://127.0.0.1:{counter.server_address[1]}/pwn"
    app = ThreadingHTTPServer(("127.0.0.1", 0), _TwoActorApp)
    threading.Thread(target=app.serve_forever, daemon=True).start()
    try:
        yield (f"http://127.0.0.1:{app.server_address[1]}", counter.server_address[1])
    finally:
        app.shutdown()
        counter.shutdown()


# --------------------------------------------------------------------------- #
# Tier A — live Caido replay transport (real build/parse/send helpers)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_live_caido_replay_credential_replacement_and_no_follow() -> None:
    _require_live_proxy()
    _REDIR_HITS.clear()
    with _serve_two_actor() as (origin, _counter_port):
        host = urlsplit(origin).netloc

        # Captured actor-a context (cookie + bearer). The comparison actor uses a
        # cookie only — actor-a's bearer MUST NOT survive the rebuild.
        captured = {"Host": host, "Cookie": "session=A-TOKEN",
                    "Authorization": "Bearer A-SECRET", "Accept": "text/plain"}
        swapped = _rebuild_headers(captured, {"Cookie": "session=B-TOKEN"})

        connection, raw_bytes = caido_api.build_raw_request(
            method="GET", url=f"{origin}/orders/1", headers=swapped, body="")

        # Destination consistency: derived from the captured URL, not any redirect.
        assert connection.host == "127.0.0.1"
        assert connection.port == int(urlsplit(origin).port)
        assert connection.is_tls is False
        # Complete credential replacement on the wire.
        assert b"session=B-TOKEN" in raw_bytes
        assert b"A-TOKEN" not in raw_bytes
        assert b"Bearer" not in raw_bytes and b"A-SECRET" not in raw_bytes

        # Live send through Caido's replay engine (the production transport).
        replay = await caido_api.call_with_client(
            lambda c: caido_api.replay_send_raw(c, raw=raw_bytes, connection=connection))
        assert isinstance(replay, dict) and replay.get("status") != "ERROR"
        parsed = caido_api.parse_raw_response(replay.get("response_raw"))
        assert parsed is not None
        assert parsed["status_code"] == 200
        # The app echoed the arriving credentials: only actor-b's cookie reached it.
        assert "session=B-TOKEN" in parsed["body"]
        assert "A-TOKEN" not in parsed["body"] and "A-SECRET" not in parsed["body"]

        # No-follow: replay the /redirect endpoint (302 -> excluded counter). The
        # production transport performs ONE send and does not chase the redirect.
        _conn2, raw2 = caido_api.build_raw_request(
            method="GET", url=f"{origin}/redirect", headers={"Host": host}, body="")
        replay2 = await caido_api.call_with_client(
            lambda c: caido_api.replay_send_raw(c, raw=raw2, connection=_conn2))
        parsed2 = caido_api.parse_raw_response(replay2.get("response_raw"))
        assert parsed2 is not None and parsed2["status_code"] == 302
        assert sum(_REDIR_HITS.values()) == 0  # excluded origin never contacted


# --------------------------------------------------------------------------- #
# Tier B — full production path end-to-end (needs a captured request ref)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_live_production_run_authz_end_to_end() -> None:
    _require_live_proxy()
    request_ref = os.environ.get(_REQUEST_REF_ENV)
    accounts_file = os.environ.get(_ACCOUNTS_ENV)
    if not request_ref or not accounts_file:
        pytest.skip(
            f"Tier B needs a request already captured in the proxy: set {_REQUEST_REF_ENV} to its "
            f"id and {_ACCOUNTS_ENV} to an auth_accounts.jsonl (reference + comparison actors with "
            "owned_objects). Capture the reference actor's request to your loopback two-actor app "
            "through Caido first, then re-run.")
    accounts_text = ""
    with contextlib.suppress(OSError), Path(accounts_file).open(encoding="utf-8") as fh:
        accounts_text = fh.read()
    if not accounts_text.strip():
        pytest.skip(f"{_ACCOUNTS_ENV}={accounts_file!r} is empty/unreadable")

    state = Path(tempfile.mkdtemp(prefix="authz_live_"))
    hydrate_attack_surface_from_disk(state)
    hydrate_hypotheses_from_disk(state)
    hid = _create_impl(
        endpoint_id="live-ep", vuln_category="idor", resource="(captured)",
        actor_ref="actor-a", param_name="", param_location="query", operation="",
        rationale="live integration", next_action="replay", priority={}, evidence=[],
        agent_id=None, agent_name=None,
    )["hypothesis_id"]

    scope = os.environ.get("STRIX_AUTHZ_SCOPE", "")
    scan_targets = [scope] if scope else None

    # Production defaults: retrieve=None, replay=None -> _default_retrieve /
    # _default_replay against the live proxy. Scope + budget are enforced in
    # Strix before any dispatch, independent of the proxy's own UI scope.
    res = await _run_authz_impl(
        hypothesis_id=hid, request_ref=request_ref, reference_actor="actor-a",
        comparison_actor="actor-b", test_intent="horizontal",
        resource_marker=os.environ.get("STRIX_AUTHZ_MARKER", "ORDER-1-SECRET"),
        operation_class="read", ownership_assertion="actor-a owns it (provisioning)",
        accounts_text=accounts_text, scan_targets=scan_targets,
    )
    # We assert the production path produced a structured, classified result with
    # sanitized evidence — not a specific verdict (that depends on the operator's
    # app). Secrets must never appear in the result.
    assert res["success"] is True
    assert res["verdict"] in {
        "potential_authorization_bypass", "denied_this_test", "insufficient_evidence",
        "invalid_session", "blocked", "unstable_result", "baseline_unverified",
        "expected_public_access",
    }
    blob = str(res)
    for secret in ("A-TOKEN", "B-TOKEN", "A-SECRET", "Authorization", "Set-Cookie"):
        assert secret not in blob, f"secret {secret!r} leaked into the tool result"
