"""Tests for list_chain_candidates — the mechanical discloses/requires cross-reference."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from strix.report.state import ReportState, set_global_report_state
from strix.tools.reporting.tool import _do_list_chain_candidates


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def report_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReportState:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="test-run-chains")
    set_global_report_state(state)
    return state


def test_overlapping_discloses_and_requires_surfaces_as_a_candidate(
    report_state: ReportState,
) -> None:
    """The exact scenario the plan asked for: finding A discloses booking_id,
    finding B requires booking_id -> a candidate chain link."""
    report_state.add_vulnerability_report(
        title="Booking receipt discloses internal booking_id",
        severity="low",
        description="The receipt endpoint returns the raw internal booking_id.",
        target="https://app.example.com",
        endpoint="/receipts/{id}",
        discloses=["booking_id"],
        agent_name="InfoDisclosure Agent",
    )
    report_state.add_vulnerability_report(
        title="IDOR on /bookings/{booking_id}",
        severity="medium",
        description="Any authenticated user can fetch any other user's booking by ID.",
        target="https://app.example.com",
        endpoint="/bookings/{booking_id}",
        requires=["booking_id"],
        agent_name="IDOR Agent",
    )

    result = _do_list_chain_candidates()

    assert result["success"] is True
    assert result["reports_considered"] == 2
    assert result["reports_with_chain_fields"] == 2
    (candidate,) = result["candidates"]
    assert candidate["discloses_report_id"] == "vuln-0001"
    assert candidate["requires_report_id"] == "vuln-0002"
    assert candidate["shared_identifiers"] == ["booking_id"]
    assert "note" not in result


def test_non_overlapping_findings_are_not_flagged(report_state: ReportState) -> None:
    report_state.add_vulnerability_report(
        title="Reflected XSS in search",
        severity="medium",
        target="https://app.example.com",
        endpoint="/search",
        discloses=["search_query_echo"],
        agent_name="XSS Agent",
    )
    report_state.add_vulnerability_report(
        title="SQL Injection in login",
        severity="critical",
        target="https://app.example.com",
        endpoint="/api/login",
        requires=["username"],
        agent_name="SQLi Agent",
    )

    result = _do_list_chain_candidates()

    assert result["success"] is True
    assert result["candidates"] == []
    assert result["reports_with_chain_fields"] == 2
    assert "note" in result  # explicitly says the empty result doesn't mean no chains exist


def test_matching_is_case_and_whitespace_insensitive(report_state: ReportState) -> None:
    report_state.add_vulnerability_report(
        title="A", severity="low", discloses=["  Booking_ID  "], agent_name="a"
    )
    report_state.add_vulnerability_report(
        title="B", severity="low", requires=["booking_id"], agent_name="b"
    )

    result = _do_list_chain_candidates()

    assert len(result["candidates"]) == 1

    # But underscore vs space is NOT treated as equivalent - that would be a
    # fuzzier heuristic than "case and whitespace insensitive" ever claimed.
    state2 = ReportState(run_name="test-run-chains-2")
    set_global_report_state(state2)
    state2.add_vulnerability_report(title="C", severity="low", discloses=["booking_id"], agent_name="a")
    state2.add_vulnerability_report(title="D", severity="low", requires=["booking id"], agent_name="b")
    assert _do_list_chain_candidates()["candidates"] == []


def test_untagged_findings_are_counted_but_never_candidates(report_state: ReportState) -> None:
    report_state.add_vulnerability_report(title="Untagged A", severity="low", agent_name="a")
    report_state.add_vulnerability_report(title="Untagged B", severity="low", agent_name="b")

    result = _do_list_chain_candidates()

    assert result["reports_considered"] == 2
    assert result["reports_with_chain_fields"] == 0
    assert result["candidates"] == []


def test_no_report_state_returns_empty_not_an_error() -> None:
    set_global_report_state(None)
    result = _do_list_chain_candidates()
    assert result["success"] is True
    assert result["candidates"] == []
    assert "warning" in result


def test_bidirectional_overlap_produces_two_directional_candidates(
    report_state: ReportState,
) -> None:
    """A discloses X that B requires, AND B discloses Y that A requires -
    two distinct, real chain directions, not a single collapsed row."""
    report_state.add_vulnerability_report(
        title="A", severity="low", discloses=["token_x"], requires=["token_y"], agent_name="a"
    )
    report_state.add_vulnerability_report(
        title="B", severity="low", discloses=["token_y"], requires=["token_x"], agent_name="b"
    )

    result = _do_list_chain_candidates()

    assert len(result["candidates"]) == 2
    pairs = {(c["discloses_report_id"], c["requires_report_id"]) for c in result["candidates"]}
    assert pairs == {("vuln-0001", "vuln-0002"), ("vuln-0002", "vuln-0001")}
