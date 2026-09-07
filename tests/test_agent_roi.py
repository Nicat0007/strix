"""Tests for Piece 8 (Token ROI Tracking): the per-agent tool-call counter,
the live (non-stale) LLM usage accessor, and view_agent_graph's rendered
ROI line for a simulated multi-tool-call agent.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from agents.tool_context import ToolContext
from agents.usage import Usage

from strix.core.agents import AgentCoordinator
from strix.report.state import ReportState, set_global_report_state
from strix.tools.agent_metrics.tools import (
    get_tool_call_count,
    record_tool_call,
    reset_agent_metrics,
)
from strix.tools.agents_graph.tools import _agent_roi_suffix, view_agent_graph
from strix.tools.coverage.tools import _record_impl, hydrate_coverage_from_disk


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _isolated_metrics(tmp_path: Path) -> None:
    reset_agent_metrics()
    hydrate_coverage_from_disk(tmp_path)
    yield
    set_global_report_state(None)
    reset_agent_metrics()


def test_tool_call_counter_increments_per_agent_independently() -> None:
    for _ in range(5):
        record_tool_call("agent-heavy")
    record_tool_call("agent-light")
    record_tool_call(None)  # must never raise, and must not create a phantom entry

    assert get_tool_call_count("agent-heavy") == 5
    assert get_tool_call_count("agent-light") == 1
    assert get_tool_call_count("agent-never-called") == 0


def test_live_llm_usage_is_not_the_stale_cached_snapshot() -> None:
    """get_live_llm_usage must reflect a record() made after construction -
    the bug this piece's design caught: get_total_llm_usage only reflects
    whatever was cached at save_run_data time, which for a running scan is
    stale for the agent's entire lifetime.
    """
    state = ReportState(run_name="test-run-roi")
    state._llm_usage.record(
        agent_id="agent-3", usage=Usage(requests=1, input_tokens=1000, output_tokens=200, total_tokens=1200)
    )

    live = state.get_live_llm_usage()
    (agent_row,) = [a for a in live["agents"] if a["agent_id"] == "agent-3"]
    assert agent_row["total_tokens"] == 1200

    # The cached snapshot was never synced, so it must NOT show this usage -
    # proves get_total_llm_usage really is the stale one, not a coincidence.
    stale = state.get_total_llm_usage()
    stale_agents = stale.get("agents", [])
    assert not any(a.get("agent_id") == "agent-3" and a.get("total_tokens") for a in stale_agents)


def test_agent_roi_suffix_renders_real_numbers_for_a_multi_tool_call_agent() -> None:
    """The exact scenario the plan asked for: simulate an agent that made
    several tool calls and recorded coverage, then confirm the rendered
    ROI suffix carries the real numbers."""
    agent_id = "agent-authz-tester"

    state = ReportState(run_name="test-run-roi-2")
    state._llm_usage.record(
        agent_id=agent_id,
        usage=Usage(requests=3, input_tokens=40_000, output_tokens=1_200, total_tokens=41_200),
    )
    set_global_report_state(state)

    for _ in range(62):
        record_tool_call(agent_id)

    for i in range(3):
        result = _record_impl(
            surface=f"GET /api/orders/{i}",
            risk_area="IDOR",
            outcome="no_issue_found",
            evidence="Tested with two accounts; both received 403.",
            agent_id=agent_id,
            agent_name="authz-tester",
        )
        assert result["success"] is True

    suffix = _agent_roi_suffix(agent_id)

    assert "tokens: 41,200" in suffix
    assert "tool_calls: 62" in suffix
    assert "coverage: 3 entries total" in suffix
    assert "3 in the last 10 min" in suffix  # all just recorded, all within the window


def test_agent_roi_suffix_handles_no_report_state_and_no_activity_gracefully() -> None:
    # No set_global_report_state call, no tool calls, no coverage - must not raise.
    suffix = _agent_roi_suffix("agent-idle")
    assert "tool_calls: 0" in suffix
    assert "coverage: 0 entries total, 0 in the last 10 min" in suffix
    assert "tokens" not in suffix  # no usage recorded anywhere - omitted, not fabricated as 0


@pytest.mark.asyncio
async def test_view_agent_graph_line_carries_roi_for_active_agents_only() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root-1", "root-agent", None)
    await coordinator.register("child-1", "authz-tester", "root-1")
    await coordinator.set_status("child-1", "completed")

    state = ReportState(run_name="test-run-roi-3")
    state._llm_usage.record(
        agent_id="root-1", usage=Usage(requests=1, input_tokens=500, output_tokens=100, total_tokens=600)
    )
    set_global_report_state(state)
    record_tool_call("root-1")
    record_tool_call("root-1")
    baseline_calls = get_tool_call_count("root-1")

    ctx = ToolContext(
        context={"coordinator": coordinator, "agent_id": "root-1"},
        tool_name="view_agent_graph",
        tool_call_id="call-1",
        tool_arguments="{}",
        run_config=None,
    )
    # NOTE: view_agent_graph is the real, shared module-level FunctionTool
    # singleton. Elsewhere in the full suite, another test's real agent
    # build may have already wrapped it in place via factory.py's
    # (idempotent) _with_bounded_result - so this call to its real
    # on_invoke_tool may itself increment the counter too, which is
    # correct production behavior (calling view_agent_graph is a real
    # tool call), not a bug. Assert >=, not ==, so the test doesn't
    # depend on whether that wrapping happened yet in this process.
    raw = await view_agent_graph.on_invoke_tool(ctx, "{}")
    import json

    result = json.loads(raw)

    assert result["success"] is True
    graph = result["graph_structure"]
    root_line = next(line for line in graph.splitlines() if "root-agent" in line)
    child_line = next(line for line in graph.splitlines() if "authz-tester" in line)

    assert "[running]" in root_line
    assert "tokens: 600" in root_line
    rendered_calls = int(root_line.split("tool_calls: ")[1].split(" ")[0])
    assert rendered_calls >= baseline_calls
    assert "← you" in root_line

    # completed agents get no ROI suffix - the numbers matter for wind-down
    # judgment on a still-running agent, not a finished one.
    assert "[completed]" in child_line
    assert "tool_calls" not in child_line
