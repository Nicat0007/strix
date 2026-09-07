"""Per-agent tool-call counters, for ``view_agent_graph``'s ROI columns.

Every real number here already exists somewhere except one: tokens/cost
come from ``strix.report.usage.LLMUsageLedger`` (already tracked per agent),
and coverage-entry counts come from ``strix.tools.coverage.tools`` (entries
already carry ``agent_id``). The one thing genuinely missing was a
cumulative, per-agent tool-call count — ``TurnToolCallLimiter``
(``strix/config/tool_call_limits.py``) only caps calls within one turn and
resets, so nothing tracked a running total across an agent's whole life.

This module is that counter, nothing else. It is incremented from one
shared choke point every tool call already passes through
(``strix.agents.factory._function_tool_with_error_result``, which wraps
every tool uniformly for error handling), so no new invocation path is
added anywhere.

**In-memory only, not persisted.** Unlike ``coverage``/``notes``, a resumed
scan's counters restart at zero — these numbers exist to inform the
current process's root-agent judgment about wind-down, not to survive a
crash/resume cycle, and persisting them would touch a disk-write path
this metrics-only piece has no reason to add.
"""

from __future__ import annotations

import logging
import threading


logger = logging.getLogger(__name__)

_tool_call_counts: dict[str, int] = {}
_lock = threading.RLock()


def record_tool_call(agent_id: str | None) -> None:
    """Increment *agent_id*'s cumulative tool-call count by one.

    Called unconditionally, before the wrapped tool runs, so a call that
    later errors still counts — an errored or wasted call is still real
    tool-call volume for wind-down judgment purposes. Never raises: this
    runs on every single tool call in the system, so a bug here must never
    take down a real tool invocation.
    """
    if not agent_id:
        return
    try:
        with _lock:
            _tool_call_counts[agent_id] = _tool_call_counts.get(agent_id, 0) + 1
    except Exception:
        logger.exception("record_tool_call failed for agent %s (non-fatal)", agent_id)


def get_tool_call_count(agent_id: str) -> int:
    with _lock:
        return _tool_call_counts.get(agent_id, 0)


def reset_agent_metrics() -> None:
    """Clear all counters. Test-only — a real scan never needs to call this."""
    with _lock:
        _tool_call_counts.clear()
