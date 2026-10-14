"""Tests for the run-scoped black-box attack-surface inventory.

Exercises the committed production code in ``strix.tools.attack_surface.tools``:
endpoint identity (origin/port/method distinctness), per-object and per-actor
evidence preservation, reference-recorded vs. replay-verified separation and
resume staleness, idempotent crawl ingestion against katana's *real* schema,
secret exclusion beyond headers, malformed-record diagnostics, persistence/
resume round-trips, run isolation, the per-object test-status worklist, and the
real resume wiring driven through ``core/runner.run_strix_scan``.

Local fixtures only; no network, no external-target scans. The katana fixtures
are real records captured from the pinned sandbox katana via a loopback crawl
(large ``body``/``raw`` fields elided), not a guessed shape.
"""

from __future__ import annotations

import inspect
import json
import types
from typing import TYPE_CHECKING, Any

import pytest
from agents import ModelSettings
from agents.tool_context import ToolContext

import strix.core.runner as runner_module
import strix.tools.notes.tools as notes_tools
import strix.tools.todo.tools as todo_tools
from strix.core import runner
from strix.core.agents import AgentCoordinator
from strix.runtime import session_manager
from strix.tools.attack_surface.tools import (
    REPLAY_RECORDED,
    REPLAY_STALE,
    REPLAY_VERIFIED,
    _ingest_impl,
    _query_impl,
    _record_impl,
    _record_test_impl,
    hydrate_attack_surface_from_disk,
    origin_of,
    query_attack_surface,
    record_endpoint,
)


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def inventory_store(tmp_path: Path) -> Path:
    """Point the store at a per-test run state dir (also clears the module store)."""
    hydrate_attack_surface_from_disk(tmp_path)
    return tmp_path


def _record(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "url": "https://shop.example.com/api/orders/1",
        "method": "GET",
        "discovery_source": "katana",
    }
    base.update(overrides)
    return _record_impl(**base)


def _all() -> dict[str, Any]:
    return _query_impl(
        origin=None, actor_ref=None, method=None, param_location=None,
        test_status=None, test_category=None, limit=500,
    )


def _only_endpoint() -> dict[str, Any]:
    result = _all()
    assert result["total_endpoints"] == 1, result
    return result["endpoints"][0]


# --------------------------------------------------------------------------- #
# Identity: origin/port/method distinctness, id-collapse
# --------------------------------------------------------------------------- #


def test_same_host_different_scheme_and_port_stay_distinct() -> None:
    _record(url="https://shop.example.com/", method="GET")
    _record(url="http://shop.example.com/", method="GET")
    _record(url="https://shop.example.com:8443/", method="GET")

    origins = {e["origin"] for e in _all()["endpoints"]}
    assert origins == {
        "https://shop.example.com:443",
        "http://shop.example.com:80",
        "https://shop.example.com:8443",
    }


def test_get_and_post_on_one_path_are_distinct_endpoints() -> None:
    get = _record(url="https://api.example.com/login", method="GET")
    post = _record(url="https://api.example.com/login", method="POST")
    assert get["endpoint_id"] != post["endpoint_id"]
    assert _query_impl(
        origin=None, actor_ref=None, method="POST", param_location=None,
        test_status=None, test_category=None, limit=500,
    )["total_matched"] == 1


def test_origin_of_fills_effective_ports_and_drops_userinfo() -> None:
    assert origin_of("https://h/x") == "https://h:443"
    assert origin_of("http://h/x") == "http://h:80"
    assert origin_of("https://h:8443/x") == "https://h:8443"
    # userinfo must never survive into the stored origin.
    assert origin_of("https://user:pa55word@h/x") == "https://h:443"
    assert origin_of("") is None


# --------------------------------------------------------------------------- #
# Route normalization preserves object-specific evidence (item 2)
# --------------------------------------------------------------------------- #


def test_numeric_ids_share_a_template_but_keep_object_evidence_distinct() -> None:
    first = _record(url="https://api.example.com/users/1", actor_ref="actor-a",
                    auth_state="authenticated", status_code=200)
    second = _record(url="https://api.example.com/users/2", actor_ref="actor-a",
                     auth_state="authenticated", status_code=403)
    other = _record(url="https://api.example.com/orders/1")

    # /users/1 and /users/2 collapse to one template endpoint...
    assert first["endpoint_id"] == second["endpoint_id"]
    assert first["path"] == "/users/{id}"
    assert first["resource"] == "/users/1"
    assert second["resource"] == "/users/2"
    # ...but a different resource stays its own endpoint.
    assert other["endpoint_id"] != first["endpoint_id"]

    users = _query_impl(
        origin=None, actor_ref=None, method=None, param_location=None,
        test_status=None, test_category=None, limit=500,
    )
    endpoint = next(e for e in users["endpoints"] if e["path"] == "/users/{id}")
    # Both concrete objects are recorded, with their own differing observations.
    assert set(endpoint["resources_observed"]) == {"/users/1", "/users/2"}
    by_resource = {(o["resource"], o["status_code"]) for o in endpoint["observations"]}
    assert ("/users/1", 200) in by_resource
    assert ("/users/2", 403) in by_resource


def test_completed_test_on_one_object_does_not_close_its_siblings() -> None:
    # Two objects under one template.
    rec1 = _record(url="https://api.example.com/orders/1", actor_ref="actor-a",
                   auth_state="authenticated")
    _record(url="https://api.example.com/orders/2", actor_ref="actor-a",
            auth_state="authenticated")
    eid = rec1["endpoint_id"]

    # Complete the IDOR test for object 1 only; mark object 2 still pending.
    assert _record_test_impl(
        endpoint_id=eid, actor_ref="actor-a", category="idor", status="completed",
        resource_id="/orders/1", note="", agent_id=None, agent_name=None,
    )["success"] is True
    _record_test_impl(
        endpoint_id=eid, actor_ref="actor-a", category="idor", status="pending",
        resource_id="/orders/2", note="", agent_id=None, agent_name=None,
    )

    endpoint = _only_endpoint()
    rows = endpoint["test_status"]
    # Object-scoped rows are distinct; object 2 is NOT marked completed.
    assert rows["actor-a|idor|/orders/1"]["status"] == "completed"
    assert rows["actor-a|idor|/orders/2"]["status"] == "pending"
    # The worklist still surfaces this endpoint as having pending IDOR work.
    pending = _query_impl(
        origin=None, actor_ref="actor-a", method=None, param_location=None,
        test_status="pending", test_category="idor", limit=500,
    )
    assert pending["total_matched"] == 1


def test_distinct_objects_keep_distinct_request_references() -> None:
    _record(url="https://api.example.com/orders/1", actor_ref="actor-a",
            auth_state="authenticated", request_ref="caido:req-1")
    _record(url="https://api.example.com/orders/2", actor_ref="actor-a",
            auth_state="authenticated", request_ref="caido:req-2")
    endpoint = _only_endpoint()
    refs = {(o["resource"], o.get("request_ref")) for o in endpoint["observations"]}
    assert ("/orders/1", "caido:req-1") in refs
    assert ("/orders/2", "caido:req-2") in refs


def test_distinct_object_count_is_bounded_with_overflow_flag() -> None:
    # Far more concrete ids than the per-endpoint cap.
    for i in range(60):
        _record(url=f"https://api.example.com/items/{i}")
    endpoint = _only_endpoint()
    assert endpoint["resource_overflow"] is True
    # Distinct tracked resources stay bounded (cap + the template bucket).
    assert endpoint["resource_count"] <= 30


# --------------------------------------------------------------------------- #
# Per-actor observations
# --------------------------------------------------------------------------- #


def test_anonymous_and_two_actors_observations_are_all_preserved() -> None:
    url = "https://app.example.com/api/invoices/42"
    _record(url=url, actor_ref="anonymous", auth_state="anonymous", status_code=401)
    _record(url=url, actor_ref="actor-a", auth_state="authenticated", status_code=200)
    _record(url=url, actor_ref="actor-b", auth_state="authenticated", status_code=403)

    endpoint = _only_endpoint()
    by_actor = {o["actor_ref"]: o for o in endpoint["observations"]}
    assert set(by_actor) == {"anonymous", "actor-a", "actor-b"}
    assert by_actor["anonymous"]["status_code"] == 401
    assert by_actor["actor-a"]["status_code"] == 200
    assert by_actor["actor-b"]["status_code"] == 403
    assert endpoint["actors_observed"] == ["actor-a", "actor-b", "anonymous"]


def test_query_by_actor_filters_to_that_actor() -> None:
    _record(url="https://app.example.com/a", actor_ref="actor-a", auth_state="authenticated")
    _record(url="https://app.example.com/b", actor_ref="actor-b", auth_state="authenticated")
    result = _query_impl(
        origin=None, actor_ref="actor-a", method=None, param_location=None,
        test_status=None, test_category=None, limit=500,
    )
    assert result["total_matched"] == 1
    assert result["endpoints"][0]["path"] == "/a"


# --------------------------------------------------------------------------- #
# Reference recorded vs. replay verified; resume staleness (item 1)
# --------------------------------------------------------------------------- #


def test_request_ref_alone_is_recorded_but_not_verified() -> None:
    _record(url="https://api.example.com/orders/1", actor_ref="actor-a",
            auth_state="authenticated", request_ref="caido:req-9")
    endpoint = _only_endpoint()
    obs = next(o for o in endpoint["observations"] if o.get("request_ref") == "caido:req-9")
    assert obs["replay_state"] == REPLAY_RECORDED
    assert obs["requires_validation"] is True
    # The endpoint is not advertised as a verified-replayable request.
    assert endpoint["replay_verified"] is False
    assert endpoint["has_request_ref"] is True
    assert endpoint["references_requiring_validation"] == 1


def test_replay_verified_flag_promotes_the_reference() -> None:
    _record(url="https://api.example.com/orders/1", actor_ref="actor-a",
            auth_state="authenticated", request_ref="caido:req-9")
    # An agent actually replays it and attests verification.
    _record(url="https://api.example.com/orders/1", actor_ref="actor-a",
            auth_state="authenticated", request_ref="caido:req-9", replay_verified=True)
    endpoint = _only_endpoint()
    obs = next(o for o in endpoint["observations"] if o.get("request_ref") == "caido:req-9")
    assert obs["replay_state"] == REPLAY_VERIFIED
    assert obs["requires_validation"] is False
    assert endpoint["replay_verified"] is True
    assert endpoint["references_requiring_validation"] == 0


def test_resume_downgrades_verified_references_to_stale(inventory_store: Path) -> None:
    _record(url="https://api.example.com/orders/1", actor_ref="actor-a",
            auth_state="authenticated", request_ref="caido:req-9", replay_verified=True)
    # Simulate a resuming process: a fresh hydrate from the same persisted file.
    hydrate_attack_surface_from_disk(inventory_store)
    endpoint = _only_endpoint()
    obs = next(o for o in endpoint["observations"] if o.get("request_ref") == "caido:req-9")
    # Freshness did not survive the resume: it must be re-validated.
    assert obs["replay_state"] == REPLAY_STALE
    assert obs["requires_validation"] is True
    assert endpoint["replay_verified"] is False
    assert endpoint["references_requiring_validation"] == 1


# --------------------------------------------------------------------------- #
# Parameters + provenance survive persistence
# --------------------------------------------------------------------------- #


def test_parameter_locations_and_provenance_survive_persistence(inventory_store: Path) -> None:
    _record(
        url="https://api.example.com/search?q=test&page=2",
        method="POST",
        parameters=[
            {"name": "body_field", "location": "body"},
            {"name": "X-Trace", "location": "header"},
        ],
        discovery_source="arjun",
    )
    hydrate_attack_surface_from_disk(inventory_store)  # re-hydrate a fresh store from disk
    endpoint = _only_endpoint()

    params = {(p["name"], p["location"]) for p in endpoint["parameters"]}
    assert ("body_field", "body") in params
    assert ("X-Trace", "header") in params
    # Query-string names were lifted off the URL as query params (names only).
    assert ("q", "query") in params
    assert ("page", "query") in params
    assert "arjun" in endpoint["discovery_sources"]
    assert endpoint["first_discovered_at"]


def test_fresh_store_instance_restores_the_same_run(inventory_store: Path) -> None:
    rec = _record(url="https://api.example.com/keep")
    hydrate_attack_surface_from_disk(inventory_store)  # simulate a resuming process
    assert [e["endpoint_id"] for e in _all()["endpoints"]] == [rec["endpoint_id"]]


def test_another_run_starts_isolated(inventory_store: Path) -> None:
    _record(url="https://api.example.com/run1")
    other_run = inventory_store.parent / "other-run-state"
    other_run.mkdir()
    hydrate_attack_surface_from_disk(other_run)
    assert _all()["total_endpoints"] == 0


# --------------------------------------------------------------------------- #
# Ownership hints are hints, never proof
# --------------------------------------------------------------------------- #


def test_ownership_hints_carry_their_inferred_or_observed_kind() -> None:
    url = "https://app.example.com/me/profile"
    _record(url=url, ownership_hint="'me' implies current user", ownership_hint_kind="inferred")
    _record(url=url, ownership_hint="actor-a 200, actor-b 403", ownership_hint_kind="observed")
    endpoint = _only_endpoint()
    kinds = {(h["hint"], h["kind"]) for h in endpoint["ownership_hints"]}
    assert ("'me' implies current user", "inferred") in kinds
    assert ("actor-a 200, actor-b 403", "observed") in kinds


# --------------------------------------------------------------------------- #
# Crawl ingestion against katana's REAL schema (item 5)
# --------------------------------------------------------------------------- #

# Real records captured from the pinned sandbox katana via a loopback crawl
# (python http.server + a page that fires an XHR). Large body/raw fields elided;
# field names and structure are verbatim. Note each request — including the
# headless XHR POST — is its OWN flat top-level record. There is no
# response.xhr_requests[] array in this katana build.
_KATANA_REAL_JSONL = "\n".join(
    [
        json.dumps({
            "timestamp": "2026-10-03T21:17:32.949226912Z",
            "request": {"method": "GET", "endpoint": "http://127.0.0.1:8099/"},
            "response": {"status_code": 200,
                         "headers": {"Content-Type": "text/html",
                                     "Server": "SimpleHTTP/0.6 Python/3.14.6"}},
        }),
        json.dumps({
            "timestamp": "2026-10-03T21:17:33.943647381Z",
            "request": {"method": "GET", "endpoint": "http://127.0.0.1:8099/page2.html",
                        "tag": "a", "attribute": "href", "source": "http://127.0.0.1:8099/"},
            "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}},
        }),
        json.dumps({  # the fetch() fired in headless mode — its own top-level record
            "timestamp": "2026-10-03T21:17:52.968410697Z",
            "request": {"method": "POST", "endpoint": "http://127.0.0.1:8099/api/data?x=1",
                        "headers": {"Origin": "http://127.0.0.1:8099",
                                    "Referer": "http://127.0.0.1:8099/"}},
            "response": {"status_code": 501,
                         "headers": {"Content-Type": "text/html;charset=utf-8"}},
        }),
        json.dumps({  # headless dedup record with a request but no response
            "request": {"method": "GET", "endpoint": "http://127.0.0.1:8099/page2.html",
                        "tag": "a", "attribute": "href", "source": "http://127.0.0.1:8099/"},
        }),
    ]
)


def _ingest(records: str, source_format: str, **kw: Any) -> dict[str, Any]:
    return _ingest_impl(
        records=records,
        source_format=source_format,
        discovery_source=kw.get("discovery_source"),
        actor_ref=kw.get("actor_ref"),
        auth_state=kw.get("auth_state"),
        agent_id=None,
        agent_name=None,
    )


def test_katana_real_schema_each_request_is_its_own_endpoint() -> None:
    result = _ingest(_KATANA_REAL_JSONL, "katana")
    assert result["success"] is True
    assert result["records_parsed"] == 4
    # GET /, GET /page2.html, POST /api/data = 3 distinct endpoints; the 4th
    # record (another GET /page2.html) merges rather than duplicating.
    assert result["endpoints_created"] == 3
    assert result["endpoints_merged"] == 1
    # The headless XHR POST landed as a normal endpoint, with its query name.
    post = _query_impl(
        origin=None, actor_ref=None, method="POST", param_location=None,
        test_status=None, test_category=None, limit=500,
    )
    assert post["total_matched"] == 1
    endpoint = post["endpoints"][0]
    assert endpoint["path"] == "/api/data"
    assert ("x", "query") in {(p["name"], p["location"]) for p in endpoint["parameters"]}


def test_duplicate_ingestion_is_stable() -> None:
    first = _ingest(_KATANA_REAL_JSONL, "katana")
    second = _ingest(_KATANA_REAL_JSONL, "katana")
    assert first["endpoints_created"] == 3
    assert second["endpoints_created"] == 0
    assert second["endpoints_merged"] == 4
    assert _all()["total_endpoints"] == 3


def test_katana_nested_xhr_is_tolerated_as_a_fallback() -> None:
    # The pinned katana does NOT emit this shape (confirmed via loopback crawl);
    # this only guards the tolerant fallback for other katana builds that nest
    # XHRs under response.xhr_requests[].
    nested = json.dumps({
        "request": {"endpoint": "https://shop.example.com/", "method": "GET"},
        "response": {"status_code": 200,
                     "xhr_requests": [
                         {"endpoint": "https://shop.example.com/api/cart", "method": "POST"}]},
    })
    result = _ingest(nested, "katana")
    assert result["endpoints_created"] == 2
    cart = _query_impl(
        origin=None, actor_ref=None, method="POST", param_location=None,
        test_status=None, test_category=None, limit=500,
    )
    assert cart["endpoints"][0]["path"] == "/api/cart"


def test_assets_ingestion_records_origin_and_class_hint() -> None:
    assets = json.dumps(
        {"url": "https://admin.example.com", "origin": "https://admin.example.com:443",
         "status_code": 200, "class": "admin"}
    )
    result = _ingest(assets, "assets")
    assert result["endpoints_created"] == 1
    endpoint = _only_endpoint()
    assert endpoint["origin"] == "https://admin.example.com:443"
    assert any(h["hint"] == "origin class=admin" and h["kind"] == "inferred"
               for h in endpoint["ownership_hints"])


def test_anonymous_and_authenticated_passes_stay_separate_via_ingestion() -> None:
    record = json.dumps(
        {"url": "https://app.example.com/api/me", "method": "GET", "status_code": 200}
    )
    _ingest(record, "requests", actor_ref="anonymous", auth_state="anonymous")
    _ingest(record, "requests", actor_ref="actor-a", auth_state="authenticated")
    endpoint = _only_endpoint()
    assert {o["actor_ref"] for o in endpoint["observations"]} == {"anonymous", "actor-a"}


def test_malformed_crawler_records_produce_explicit_diagnostics() -> None:
    bad = "\n".join(
        [
            "{not valid json",
            json.dumps({"response": {"status_code": 200}}),  # no request
            json.dumps({"request": {"endpoint": "https://ok.example.com/x", "method": "GET"}}),
        ]
    )
    result = _ingest(bad, "katana")
    assert result["success"] is True
    assert result["endpoints_created"] == 1  # the one good record still landed
    joined = " ".join(result["diagnostics"])
    assert "not valid JSON" in joined
    assert "no 'request' object" in joined


def test_unknown_format_is_rejected() -> None:
    result = _ingest("[]", "burp-xml")
    assert result["success"] is False
    assert "Unknown format" in result["error"]


# --------------------------------------------------------------------------- #
# Secret exclusion beyond headers (item 4)
# --------------------------------------------------------------------------- #


def test_secret_header_values_never_reach_the_inventory() -> None:
    record = json.dumps(
        {
            "url": "https://api.example.com/account",
            "method": "GET",
            "status_code": 200,
            "headers": {
                "Authorization": "Bearer sk-SUPER-SECRET-TOKEN-abcdefgh",
                "Cookie": "session=SECRET-SESSION-VALUE",
                "X-Api-Key": "KEY-SECRET-123",
                "Accept": "application/json",
            },
            "request_ref": "caido:req-123",
        }
    )
    _ingest(record, "proxy", actor_ref="actor-a", auth_state="authenticated")

    endpoint = _only_endpoint()
    blob = json.dumps(endpoint)
    for secret in ("sk-SUPER-SECRET-TOKEN-abcdefgh", "SECRET-SESSION-VALUE", "KEY-SECRET-123"):
        assert secret not in blob
    # Header *names* survive as discovery signal (names are not secrets).
    param_names = {p["name"].lower() for p in endpoint["parameters"]}
    assert {"authorization", "cookie", "x-api-key", "accept"}.issubset(param_names)
    # The reference is kept (it is an opaque id) but recorded as unverified.
    obs = next(o for o in endpoint["observations"] if o.get("request_ref") == "caido:req-123")
    assert obs["replay_state"] == REPLAY_RECORDED
    assert obs["requires_validation"] is True


def test_url_userinfo_and_query_values_are_never_stored() -> None:
    _record_impl(
        url="https://alice:hunter2@api.example.com/orders/1?token=SECRET-QS-VALUE&page=2",
        method="GET",
        discovery_source="manual",
    )
    endpoint = _only_endpoint()
    blob = json.dumps(endpoint)
    assert "hunter2" not in blob  # URL userinfo password
    assert "SECRET-QS-VALUE" not in blob  # sensitive query *value*
    # The query parameter *names* are still captured as discovery signal.
    names = {p["name"] for p in endpoint["parameters"]}
    assert {"token", "page"}.issubset(names)
    # The origin is clean (no userinfo) and there is no raw-url field anywhere.
    assert endpoint["origin"] == "https://api.example.com:443"
    assert "url" not in endpoint


def test_secret_shaped_path_segment_is_collapsed_not_stored() -> None:
    # A reset-token-shaped path segment must not be stored verbatim.
    _record_impl(
        url="https://api.example.com/verify/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SECRETSIG",
        method="GET",
        discovery_source="manual",
    )
    endpoint = _only_endpoint()
    blob = json.dumps(endpoint)
    assert "SECRETSIG" not in blob
    assert "eyJhbGci" not in blob
    assert endpoint["resources_observed"] == ["/verify/{id}"]


def test_ownership_hint_and_note_redact_secret_shapes() -> None:
    rec = _record_impl(
        url="https://api.example.com/x",
        method="GET",
        discovery_source="manual",
        ownership_hint="owner token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.SIGSIGSIG seen",
    )
    _record_test_impl(
        endpoint_id=rec["endpoint_id"], actor_ref="anonymous", category="idor",
        status="blocked", resource_id="", note="blocked by AKIAABCDEFGHIJKLMNOP key",
        agent_id=None, agent_name=None,
    )
    endpoint = _only_endpoint()
    blob = json.dumps(endpoint, ensure_ascii=False)
    assert "SIGSIGSIG" not in blob
    assert "AKIAABCDEFGHIJKLMNOP" not in blob
    assert "«redacted»" in blob


def test_request_ref_that_looks_like_inlined_content_is_dropped() -> None:
    result = _record_impl(
        url="https://api.example.com/x",
        method="GET",
        discovery_source="manual",
        request_ref="GET /x HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer sk-SECRETxyz",
    )
    assert result["success"] is True
    assert "diagnostics" in result
    endpoint = _only_endpoint()
    assert "sk-SECRETxyz" not in json.dumps(endpoint)
    assert all(not o.get("request_ref") for o in endpoint["observations"])


def test_request_ref_carrying_a_secret_token_is_dropped() -> None:
    result = _record_impl(
        url="https://api.example.com/x",
        method="GET",
        discovery_source="manual",
        request_ref="Bearer sk-SECRET-INLINE-TOKEN-xyz",
    )
    assert result["success"] is True
    assert result["request_ref_recorded"] is False
    endpoint = _only_endpoint()
    assert "sk-SECRET-INLINE-TOKEN-xyz" not in json.dumps(endpoint)


# --------------------------------------------------------------------------- #
# Downstream test-status worklist (distinct from coverage lifecycle)
# --------------------------------------------------------------------------- #


def test_test_status_bookkeeping_keyed_to_endpoint_actor_category_object() -> None:
    rec = _record(
        url="https://app.example.com/api/orders/1",
        actor_ref="actor-a",
        auth_state="authenticated",
    )
    eid = rec["endpoint_id"]
    assert _record_test_impl(
        endpoint_id=eid, actor_ref="actor-a", category="idor", status="pending",
        resource_id="1", note="", agent_id=None, agent_name=None,
    )["success"] is True

    pending = _query_impl(
        origin=None, actor_ref="actor-a", method=None, param_location=None,
        test_status="pending", test_category="idor", limit=500,
    )
    assert pending["total_matched"] == 1

    _record_test_impl(
        endpoint_id=eid, actor_ref="actor-a", category="idor", status="completed",
        resource_id="1", note="", agent_id=None, agent_name=None,
    )
    still_pending = _query_impl(
        origin=None, actor_ref="actor-a", method=None, param_location=None,
        test_status="pending", test_category="idor", limit=500,
    )
    assert still_pending["total_matched"] == 0


def test_test_status_rejects_unknown_status() -> None:
    rec = _record(url="https://app.example.com/x")
    result = _record_test_impl(
        endpoint_id=rec["endpoint_id"], actor_ref="anonymous", category="idor",
        status="maybe", resource_id="", note="", agent_id=None, agent_name=None,
    )
    assert result["success"] is False


# --------------------------------------------------------------------------- #
# Query bounding
# --------------------------------------------------------------------------- #


def test_query_output_is_bounded() -> None:
    for i in range(10):
        _record(url=f"https://api.example.com/resource{i}")
    result = _query_impl(
        origin=None, actor_ref=None, method=None, param_location=None,
        test_status=None, test_category=None, limit=3,
    )
    assert result["returned"] == 3
    assert result["total_matched"] == 10
    assert result["truncated"] is True


# --------------------------------------------------------------------------- #
# Tool wrappers + the real resume wiring (item 3)
# --------------------------------------------------------------------------- #


def _ctx() -> ToolContext:
    return ToolContext(
        context={"agent_id": "agent-1", "coordinator": None},
        tool_name="attack_surface",
        tool_call_id="call-1",
        tool_arguments="{}",
    )


@pytest.mark.asyncio
async def test_record_and_query_tools_round_trip() -> None:
    raw = await record_endpoint.on_invoke_tool(
        _ctx(),
        json.dumps(
            {
                "url": "https://api.example.com/api/orders/7",
                "method": "POST",
                "discovery_source": "proxy",
                "parameters": json.dumps([{"name": "qty", "location": "body"}]),
                "actor_ref": "actor-a",
                "auth_state": "authenticated",
                "status_code": 200,
            }
        ),
    )
    created = json.loads(raw)
    assert created["success"] is True and created["method"] == "POST"

    raw_query = await query_attack_surface.on_invoke_tool(
        _ctx(), json.dumps({"origin": "api.example.com", "method": "POST"})
    )
    listed = json.loads(raw_query)
    assert listed["success"] is True
    assert listed["total_matched"] == 1
    assert {p["name"] for p in listed["endpoints"][0]["parameters"]} == {"qty"}


def test_runner_wires_attack_surface_hydration_in_the_unconditional_block() -> None:
    """Lightweight guard that the import + call live in runner.py's hydrate block,
    alongside the behavioral test below."""
    source = inspect.getsource(runner_module)
    assert "from strix.tools.attack_surface.tools import hydrate_attack_surface_from_disk" in source
    assert "hydrate_attack_surface_from_disk(state_dir)" in source


def _runner_settings() -> Any:
    return types.SimpleNamespace(
        llm=types.SimpleNamespace(
            model="openai/gpt-4o",
            reasoning_effort="high",
            force_required_tool_choice=False,
            timeout=300,
            prompt_cache=True,
            extra_headers=None,
        ),
        runtime=types.SimpleNamespace(max_context_images=3),
        negative_knowledge=types.SimpleNamespace(enabled=False),
    )


@pytest.mark.asyncio
async def test_persisted_inventory_is_restored_through_runner_and_queryable(
    monkeypatch: pytest.MonkeyPatch, inventory_store: Path
) -> None:
    """Behavioral: persist an inventory, then drive the real runner hydration
    path (external deps mocked) and query it back through the registered tool.

    This exercises runner.run_strix_scan's unconditional hydrate block — the
    exact wiring a --resume relies on for the inventory — rather than grepping
    the source. A pre-persisted inventory file stands in for a prior run's state.
    """
    # 1) Persist an endpoint into this run's state dir (the file resume reads).
    persisted = _record(
        url="https://api.example.com/api/orders/1",
        actor_ref="actor-a",
        auth_state="authenticated",
        request_ref="caido:req-77",
        replay_verified=True,
    )

    # 2) Mock everything heavy so run_strix_scan reaches hydration and returns,
    #    WITHOUT mocking the inventory hydrate (the behavior under test).
    monkeypatch.setattr(runner, "run_dir_for", lambda _scan_id: inventory_store)
    monkeypatch.setattr(runner, "runtime_state_dir", lambda _run_dir: inventory_store)
    monkeypatch.setattr(runner, "setup_scan_logging", lambda _run_dir: lambda: None)
    monkeypatch.setattr(runner, "set_scan_id", lambda _scan_id: None)
    monkeypatch.setattr(runner, "load_settings", _runner_settings)
    monkeypatch.setattr(runner, "configure_sdk_model_defaults", lambda _s: None)
    monkeypatch.setattr(runner, "uses_chat_completions_tool_schema", lambda _m, _s: False)
    monkeypatch.setattr(todo_tools, "hydrate_todos_from_disk", lambda _d: None)
    monkeypatch.setattr(notes_tools, "hydrate_notes_from_disk", lambda _d: None)

    async def _create_or_reuse(*_a: Any, **_k: Any) -> dict[str, Any]:
        return {"client": object(), "session": object(), "caido_client": None}

    async def _cleanup(*_a: Any, **_k: Any) -> None:
        return None

    monkeypatch.setattr(session_manager, "create_or_reuse", _create_or_reuse)
    monkeypatch.setattr(session_manager, "cleanup", _cleanup)
    monkeypatch.setattr(runner, "build_root_task", lambda _c: "task")
    monkeypatch.setattr(runner, "build_scope_context", lambda _c: "")
    monkeypatch.setattr(runner, "make_model_settings", lambda *_a, **_k: ModelSettings())
    monkeypatch.setattr(runner, "build_strix_agent", lambda **_k: object())
    monkeypatch.setattr(runner, "make_child_factory", lambda **_k: lambda **_kk: object())
    monkeypatch.setattr(runner, "open_agent_session", lambda _root_id, _db: object())

    captured: dict[str, Any] = {}

    async def _root_loop(**_kwargs: Any) -> None:
        # Query through the REGISTERED tool while the run is live.
        raw = await query_attack_surface.on_invoke_tool(_ctx(), json.dumps({}))
        captured["query"] = json.loads(raw)

    monkeypatch.setattr(runner, "run_agent_loop", _root_loop)

    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-test-attack-surface",
        image="img",
        coordinator=AgentCoordinator(),
    )

    # 3) The persisted endpoint came back through runner's hydrate, via the tool.
    result = captured["query"]
    assert result["total_endpoints"] == 1
    endpoint = result["endpoints"][0]
    assert endpoint["endpoint_id"] == persisted["endpoint_id"]
    # Restored provenance is intact...
    assert endpoint["first_discovered_at"]
    assert "actor-a" in endpoint["actors_observed"]
    # ...and the previously-verified reference is now stale after the resume.
    obs = next(o for o in endpoint["observations"] if o.get("request_ref") == "caido:req-77")
    assert obs["replay_state"] == REPLAY_STALE
    assert obs["requires_validation"] is True
