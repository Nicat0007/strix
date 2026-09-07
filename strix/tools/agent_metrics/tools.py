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
_last_activity_tick: dict[str, int] = {}
_lock = threading.RLock()

#: Piece 9 (Stop-Loss). A first-guess constant, not user-configurable —
#: same precedent as the ROI trailing window's "10 minutes": documented and
#: revisitable once there's real usage to calibrate against, rather than a
#: settings toggle for a single nudge threshold. Neither too small (an
#: agent doing one careful multi-step verification of a single candidate
#: shouldn't get nudged mid-investigation) nor so large it burns a large
#: share of budget before the root agent ever sees the signal.
_STAGNATION_THRESHOLD = 15


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


def record_activity_tick(agent_id: str | None) -> None:
    """Mark that *agent_id* just produced real new information.

    Called from ``coverage/tools.py``'s ``_record_impl``/``_update_impl``
    (a fresh coverage entry, or updating an existing one — e.g. resolving
    someone's ``needs_follow_up`` is real progress too) and
    ``file_context_cache/tools.py``'s ``_record_impl`` — the three places
    "new information" already happens today. Stamps the agent's *current*
    tool-call count as the last-known-progress point; never raises, for the
    same reason ``record_tool_call`` doesn't.

    Deliberately does **not** track "new hypothesis status" or "new
    endpoint discovered" — neither has a per-agent-timestamped event
    anywhere in this codebase today, and inventing one would be new
    tracking machinery, not an extension of what already exists.
    """
    if not agent_id:
        return
    try:
        with _lock:
            _last_activity_tick[agent_id] = _tool_call_counts.get(agent_id, 0)
    except Exception:
        logger.exception("record_activity_tick failed for agent %s (non-fatal)", agent_id)


def tool_calls_since_new_info(agent_id: str) -> int:
    """How many tool calls *agent_id* has made since its last recorded activity tick.

    0 if the agent has never made a tool call. If it has made calls but
    never once recorded new coverage/file-summary activity, this is its
    full tool-call count — correctly read as "no progress yet", not zero.
    """
    with _lock:
        return _tool_call_counts.get(agent_id, 0) - _last_activity_tick.get(agent_id, 0)


def possible_stagnation(agent_id: str) -> int | None:
    """The stagnation count if *agent_id* is past the threshold, else ``None``.

    A plain count past a documented constant — never a score, never a
    verdict that the agent is actually stuck. See
    `coordination/root_agent.md`'s "Reading Agent ROI" for how this is
    meant to be read and acted on (or not) by the root agent.
    """
    count = tool_calls_since_new_info(agent_id)
    return count if count >= _STAGNATION_THRESHOLD else None


def reset_agent_metrics() -> None:
    """Clear all counters. Test-only — a real scan never needs to call this."""
    with _lock:
        _tool_call_counts.clear()
        _last_activity_tick.clear()
