"""Tests for Piece 14 (Per-Endpoint Coverage Grid): check_route_coverage."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from strix.tools.coverage.tools import (
    _CORE_RISK_CLASSES,
    _do_check_route_coverage,
    _normalize_route,
    _record_impl,
    hydrate_coverage_from_disk,
)


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def coverage_store(tmp_path: Path) -> Path:
    hydrate_coverage_from_disk(tmp_path)
    return tmp_path


def _record(**overrides: str) -> dict:
    kwargs = {
        "surface": "/api/orders/{id}",
        "risk_area": "object-level authorization",
        "outcome": "no_issue_found",
        "evidence": "Tested with two accounts.",
        "agent_id": "agent-1",
        "agent_name": "authz-tester",
    }
    kwargs.update(overrides)
    return _record_impl(**kwargs)


def test_route_with_no_coverage_at_all_is_untested_for_every_class() -> None:
    result = _do_check_route_coverage(routes=["/api/orders/{id}"], risk_classes=["idor"])
    assert result["success"] is True
    assert result["untested_count"] == 1
    assert result["grid"][0]["tested"] is False


def test_matching_surface_and_class_is_tested() -> None:
    _record(surface="/api/orders/{id}", risk_area="object-level authorization")
    result = _do_check_route_coverage(routes=["/api/orders/{id}"], risk_classes=["idor"])
    assert result["untested_count"] == 0
    assert result["grid"][0]["tested"] is True
    assert result["grid"][0]["outcome"] == "no_issue_found"


def test_matching_route_but_wrong_class_is_still_untested() -> None:
    """The exact case that matters: a route covered for IDOR must not
    silently count as covered for SQL injection too."""
    _record(surface="/api/orders/{id}", risk_area="object-level authorization")
    result = _do_check_route_coverage(routes=["/api/orders/{id}"], risk_classes=["sql_injection"])
    assert result["untested_count"] == 1
    assert result["grid"][0]["tested"] is False


def test_path_parameter_syntax_mismatch_does_not_cause_a_false_miss() -> None:
    """/orders/{id} (attack_surface.md style) vs /orders/:id (an agent's
    own typed surface) must be recognized as the same route."""
    _record(surface="/orders/:id", risk_area="IDOR")
    result = _do_check_route_coverage(routes=["/orders/{id}"], risk_classes=["idor"])
    assert result["untested_count"] == 0
    assert result["grid"][0]["tested"] is True


def test_normalize_route_collapses_common_placeholder_syntaxes() -> None:
    assert _normalize_route("/orders/{id}") == _normalize_route("/orders/:id")
    assert _normalize_route("/orders/{id}") == _normalize_route("/orders/<id>")
    assert _normalize_route("/orders/{id}/items/{itemId}") == _normalize_route(
        "/orders/:id/items/:itemId"
    )


def test_default_core_risk_classes_used_when_none_specified() -> None:
    result = _do_check_route_coverage(routes=["/api/orders/{id}"], risk_classes=None)
    assert result["risk_classes_considered"] == list(_CORE_RISK_CLASSES)
    assert result["untested_count"] == len(_CORE_RISK_CLASSES)


def test_empty_routes_is_rejected() -> None:
    result = _do_check_route_coverage(routes=[], risk_classes=["idor"])
    assert result["success"] is False


def test_bidirectional_substring_match() -> None:
    """A more specific coverage surface (with a query string) still
    matches a plainer route identifier, and vice versa."""
    _record(surface="/api/orders/{id}?expand=items", risk_area="IDOR")
    result = _do_check_route_coverage(routes=["/api/orders/{id}"], risk_classes=["idor"])
    assert result["grid"][0]["tested"] is True
