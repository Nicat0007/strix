"""Tests for Piece 9 (Stop-Loss / Marginal Information Gain): the
tool_calls_since_new_info counter, possible_stagnation, and its
appearance in view_agent_graph's rendered ROI line.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from strix.tools.agent_metrics.tools import (
    _STAGNATION_THRESHOLD,
    possible_stagnation,
    record_activity_tick,
    record_tool_call,
    reset_agent_metrics,
    tool_calls_since_new_info,
)
from strix.tools.agents_graph.tools import _agent_roi_suffix
from strix.tools.coverage.tools import _record_impl as coverage_record
from strix.tools.coverage.tools import _update_impl as coverage_update
from strix.tools.coverage.tools import hydrate_coverage_from_disk
from strix.tools.file_context_cache.tools import _record_impl as file_cache_record
from strix.tools.file_context_cache.tools import hydrate_file_context_cache_from_disk


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path) -> None:
    reset_agent_metrics()
    hydrate_coverage_from_disk(tmp_path)
    hydrate_file_context_cache_from_disk(tmp_path / "file_context_cache.json")
    yield
    reset_agent_metrics()


def test_below_threshold_is_not_flagged() -> None:
    for _ in range(_STAGNATION_THRESHOLD - 1):
        record_tool_call("agent-a")
    assert possible_stagnation("agent-a") is None
    assert tool_calls_since_new_info("agent-a") == _STAGNATION_THRESHOLD - 1


def test_agent_hitting_15_plus_tool_calls_with_no_activity_is_flagged() -> None:
    """The exact scenario the plan asked for."""
    for _ in range(_STAGNATION_THRESHOLD):
        record_tool_call("agent-stuck")

    assert possible_stagnation("agent-stuck") == _STAGNATION_THRESHOLD

    for _ in range(5):
        record_tool_call("agent-stuck")
    assert possible_stagnation("agent-stuck") == _STAGNATION_THRESHOLD + 5


def test_new_coverage_entry_resets_the_counter() -> None:
    for _ in range(_STAGNATION_THRESHOLD + 3):
        record_tool_call("agent-b")
    assert possible_stagnation("agent-b") == _STAGNATION_THRESHOLD + 3

    result = coverage_record(
        surface="/api/orders/{id}",
        risk_area="IDOR",
        outcome="no_issue_found",
        evidence="Tested with two accounts; both received 403.",
        agent_id="agent-b",
        agent_name="authz-tester",
    )
    assert result["success"] is True

    assert possible_stagnation("agent-b") is None
    assert tool_calls_since_new_info("agent-b") == 0

    for _ in range(4):
        record_tool_call("agent-b")
    assert tool_calls_since_new_info("agent-b") == 4
    assert possible_stagnation("agent-b") is None


def test_resolving_a_needs_follow_up_also_counts_as_activity() -> None:
    recorded = coverage_record(
        surface="/api/x",
        risk_area="SSRF",
        outcome="needs_follow_up",
        evidence="No credentials to test yet.",
        agent_id="agent-c",
        agent_name="tester-1",
    )
    entry_id = recorded["entry_id"]

    for _ in range(_STAGNATION_THRESHOLD):
        record_tool_call("agent-c")
    assert possible_stagnation("agent-c") == _STAGNATION_THRESHOLD

    updated = coverage_update(
        entry_id=entry_id,
        outcome="ruled_out",
        evidence="Got credentials; the endpoint validates the target host allowlist.",
        agent_id="agent-c",
        agent_name="tester-1",
    )
    assert updated["success"] is True
    assert possible_stagnation("agent-c") is None


def test_new_file_summary_also_counts_as_activity() -> None:
    for _ in range(_STAGNATION_THRESHOLD):
        record_tool_call("agent-d")
    assert possible_stagnation("agent-d") == _STAGNATION_THRESHOLD

    result = file_cache_record(
        file_path="includes/class-base.php",
        content_hash="a" * 64,
        summary="Shared base class for serialization helpers.",
        agent_id="agent-d",
    )
    assert result["success"] is True
    assert possible_stagnation("agent-d") is None


def test_agent_roi_suffix_shows_stagnation_flag_only_once_triggered() -> None:
    for _ in range(_STAGNATION_THRESHOLD - 1):
        record_tool_call("agent-e")
    assert "possible_stagnation" not in _agent_roi_suffix("agent-e")

    record_tool_call("agent-e")
    suffix = _agent_roi_suffix("agent-e")
    assert f"possible_stagnation: {_STAGNATION_THRESHOLD} tool calls" in suffix


def test_activity_tick_ignores_missing_agent_id() -> None:
    record_activity_tick(None)  # must not raise
    assert tool_calls_since_new_info("") == 0
