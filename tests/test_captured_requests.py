"""Tests for the durable captured-request import (BLACKBOX #5, Burp continuation).

Covers the Strix-owned opaque-reference layer that snapshots a proxy-captured
request so it has a durable identity (Burp's history has none — selection is
positional offset/regex) and an explicit TLS disposition (Burp history items
carry no scheme). Fidelity/destination establishment, rejection paths, credential
exclusion from agent-facing output, restricted 0600 storage, and resume staleness.

The raw-request fixture mirrors the exact JSON `request` string shape returned
live by Burp's get_proxy_http_history_regex.
"""

from __future__ import annotations

import json
import stat
from typing import TYPE_CHECKING

import pytest

from strix.tools.captured_requests.tools import (
    hydrate_captured_requests_from_disk,
    import_captured_request_impl,
    query_captured_requests_impl,
    resolve_captured_request,
    revalidate_captured_request,
)


if TYPE_CHECKING:
    from pathlib import Path


# Exactly the raw `request` representation Burp's proxy-history regex returns.
_BURP_RAW = (
    "GET /fixture?m=MARKER_CAP_A1 HTTP/1.1\r\n"
    "Accept-Encoding: gzip, deflate, br\r\n"
    "Host: 127.0.0.1:55201\r\n"
    "User-Agent: Python-urllib/3.14\r\n"
    "Cookie: session=TOP-SECRET-COOKIE\r\n"
    "Authorization: Bearer TOP-SECRET-TOKEN\r\n"
    "Connection: keep-alive\r\n\r\n"
)


@pytest.fixture(autouse=True)
def _store(tmp_path: Path) -> Path:
    hydrate_captured_requests_from_disk(tmp_path)
    return tmp_path


def _import(**over: object) -> dict:
    base: dict = {"provider": "burp", "raw_request": _BURP_RAW, "uses_tls": False,
                  "run_id": "run1", "project_id": "proj1"}
    base.update(over)
    return import_captured_request_impl(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Fidelity + destination establishment
# --------------------------------------------------------------------------- #


def test_import_establishes_destination_from_host_header() -> None:
    r = _import()
    assert r["success"] is True
    assert r["method"] == "GET" and r["path"] == "/fixture"
    assert r["host"] == "127.0.0.1" and r["port"] == 55201 and r["uses_tls"] is False
    assert r["ref"].startswith("capreq::burp::run1::proj1::")


def test_uses_tls_must_be_explicit_else_rejected() -> None:
    r = _import(uses_tls=None)
    assert r["success"] is False and r["rejected"] == "tls_unestablished"


def test_unparseable_request_is_rejected() -> None:
    assert _import(raw_request="")["rejected"] == "unparseable_request"
    assert _import(raw_request="not an http request")["rejected"] == "unparseable_request"


def test_destination_override_contradicting_host_header_is_rejected() -> None:
    r = _import(dest_host="evil.example.com")
    assert r["success"] is False and r["rejected"] == "destination_unestablished"


def test_explicit_port_default_derives_from_tls_when_host_header_has_none() -> None:
    raw = ("GET /x HTTP/1.1\r\nHost: api.internal\r\nCookie: s=1\r\n\r\n")
    r = _import(raw_request=raw, uses_tls=True, dest_host="")
    assert r["success"] is True and r["host"] == "api.internal" and r["port"] == 443


# --------------------------------------------------------------------------- #
# Opaque reference: Strix-owned, namespaced, deterministic (not a proxy offset)
# --------------------------------------------------------------------------- #


def test_reference_is_namespaced_and_deterministic() -> None:
    a = _import()
    b = _import()  # same capture -> same ref, deduplicated
    assert a["ref"] == b["ref"] and b["deduplicated"] is True
    # provider and run namespace the reference.
    assert _import(provider="caido")["ref"] != a["ref"]
    assert _import(run_id="run2")["ref"] != a["ref"]
    assert _import(project_id="proj2")["ref"] != a["ref"]


def test_bad_provider_rejected() -> None:
    assert _import(provider="zap")["success"] is False


# --------------------------------------------------------------------------- #
# Credential exclusion from agent-facing output
# --------------------------------------------------------------------------- #


def test_credentials_never_in_import_or_query_output() -> None:
    r = _import()
    blob = json.dumps(r) + json.dumps(query_captured_requests_impl(provider="burp"))
    assert "TOP-SECRET-COOKIE" not in blob
    assert "TOP-SECRET-TOKEN" not in blob
    assert "raw_request" not in r  # raw never surfaced to the agent
    # Header NAMES are surfaced (for triage) but not values.
    assert "Cookie" in r["header_names"] and "Authorization" in r["header_names"]
    assert r["has_auth_headers"] is True


def test_query_returns_sanitized_refs() -> None:
    _import()
    q = query_captured_requests_impl()
    assert q["total"] == 1
    item = q["captured_requests"][0]
    assert set(item) >= {"ref", "provider", "method", "host", "port", "uses_tls", "freshness"}
    assert "raw_request" not in item


# --------------------------------------------------------------------------- #
# Restricted storage
# --------------------------------------------------------------------------- #


def test_snapshot_store_is_mode_0600(_store: Path) -> None:
    _import()
    path = _store / "captured_requests.json"
    assert path.exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


# --------------------------------------------------------------------------- #
# Host-side resolve + resume staleness + revalidation
# --------------------------------------------------------------------------- #


def test_resolve_returns_raw_and_destination_for_replay() -> None:
    ref = _import()["ref"]
    res = resolve_captured_request(ref)
    assert res["success"] is True
    assert res["host"] == "127.0.0.1" and res["port"] == 55201 and res["uses_tls"] is False
    # Host-side resolve DOES expose the raw (for the replay adapter) — this is the
    # only path that may, and it never goes to the model.
    assert res["raw_request"] == _BURP_RAW


def test_resume_downgrades_to_stale_and_resolve_refuses_until_revalidated(_store: Path) -> None:
    ref = _import()["ref"]
    assert resolve_captured_request(ref)["success"] is True
    # Simulate a resume: a fresh process re-hydrates from disk.
    hydrate_captured_requests_from_disk(_store)
    stale = resolve_captured_request(ref)
    assert stale["success"] is False and stale["needs_revalidation"] is True
    q = query_captured_requests_impl()["captured_requests"][0]
    assert q["freshness"] == "stale_after_resume"
    # Revalidation restores usability.
    assert revalidate_captured_request(ref)["success"] is True
    assert resolve_captured_request(ref)["success"] is True


def test_resolve_unknown_ref() -> None:
    assert resolve_captured_request("capreq::burp::x::y::deadbeef")["success"] is False
