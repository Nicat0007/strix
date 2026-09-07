"""Per-scan file-summary cache — mirrored to ``{state_dir}/file_context_cache.json``.

``custom/source_aware_sast.md``'s Attack Surface Compiler already gives every
subagent a shared, mechanically-built summary of route-shaped files
(``entry_points.md``/``attack_surface.md``), so there is nothing to cache
there — it is computed once by a deterministic script and never re-derived.

What that pipeline cannot cover is a **non-route** file — a shared base
class, a utility module, a trait — that more than one agent's own
``analysis/source_aware_discovery.md`` "Cross-file" escalation independently
leads them into. Understanding what such a file does is LLM-interpretive
work, not something a regex/ast-grep pass can produce, so nothing upstream
of the agent can build it in advance. This module is the shared cache for
*that* summary: exact-content-hash keyed, scoped to one scan (unlike
``negative_knowledge``, which is cross-scan and pattern-keyed), cleared
with the rest of the run's own state.

Host-side tools run in the host process and have no reliable path from the
container's ``/workspace/...`` spelling back to a host filesystem location,
so this tool never reads the file itself. The calling agent already has
full shell access inside the sandbox — it hashes the file itself
(``sha256sum``) and passes the digest in, the same way ``negative_knowledge``
takes agent-named API tokens rather than deriving them from file access.
This keeps the tool a pure key-value store with zero file I/O of its own.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.agent_metrics.tools import record_activity_tick


logger = logging.getLogger(__name__)

_SCHEMA_VERSION = 1
_CONTENT_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")

_store: dict[str, dict[str, Any]] = {}
_lock = threading.RLock()
_path: Path | None = None


def hydrate_file_context_cache_from_disk(state_dir: Path) -> None:
    """Load this run's cache from ``{state_dir}/file_context_cache.json``.

    Called once per process alongside the other ``hydrate_*_from_disk``
    calls in ``core/runner.py`` — scoped to this run's own state directory,
    unlike ``negative_knowledge``'s fixed cross-scan path, since a file
    summary is only trustworthy for as long as this scan's own checkout is
    the one being read.
    """
    global _path  # noqa: PLW0603
    _path = state_dir / "file_context_cache.json"
    with _lock:
        _store.clear()
        if not _path.exists():
            return
        try:
            data = json.loads(_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception(
                "file_context_cache.json at %s is unreadable; starting empty", _path
            )
            return
        entries = data.get("entries") if isinstance(data, dict) else None
        if isinstance(entries, dict):
            _store.update(
                {key: entry for key, entry in entries.items() if isinstance(entry, dict)}
            )
        logger.info("file context cache hydrated from %s (%d entr(ies))", _path, len(_store))


def _persist_locked() -> None:
    """Mirror the cache to disk. Callers must already hold ``_lock``.

    A no-op until hydration has run, matching ``coverage``/``negative_knowledge``'s
    own guard, so a caller that forgets to hydrate can never write into a
    stray path.
    """
    path = _path
    if path is None:
        return
    try:
        payload = json.dumps(
            {"schema_version": _SCHEMA_VERSION, "entries": _store},
            ensure_ascii=False,
            indent=2,
            default=str,
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp:
            tmp.write(payload)
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
    except Exception:
        logger.exception("file context cache persist to %s failed", path)


def _validate_hash(content_hash: str) -> str | None:
    if not _CONTENT_HASH_PATTERN.match(content_hash.strip().lower()):
        return (
            f"Invalid content_hash: {content_hash!r}. Must be a 64-character lowercase "
            "hex sha256 digest (e.g. from `sha256sum <file>` in the sandbox) — every "
            "caller must hash with the same algorithm or lookups will never match."
        )
    return None


def _query_impl(*, file_path: str, content_hash: str) -> dict[str, Any]:
    error = _validate_hash(content_hash)
    if error:
        return {"success": False, "error": error}
    key = content_hash.strip().lower()
    with _lock:
        entry = _store.get(key)
    if entry is None:
        return {"success": True, "hit": False}
    return {
        "success": True,
        "hit": True,
        "summary": entry.get("summary", ""),
        "first_recorded_for_path": entry.get("file_path", file_path),
        "recorded_by": entry.get("recorded_by", ""),
        "created_at": entry.get("created_at", ""),
        "last_confirmed_at": entry.get("last_confirmed_at", ""),
    }


def _record_impl(
    *,
    file_path: str,
    content_hash: str,
    summary: str,
    agent_name: str | None = None,
    agent_id: str | None = None,
) -> dict[str, Any]:
    error = _validate_hash(content_hash)
    if error:
        return {"success": False, "error": error}
    if not file_path.strip():
        return {"success": False, "error": "file_path cannot be empty"}
    if not summary.strip():
        return {
            "success": False,
            "error": "summary cannot be empty - describe what this file is/does, "
            "the part another agent escalating into it would otherwise have to re-derive",
        }

    key = content_hash.strip().lower()
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    with _lock:
        existing = _store.get(key)
        if existing is None:
            _store[key] = {
                "file_path": file_path.strip(),
                "summary": summary.strip(),
                "recorded_by": agent_name or "",
                "created_at": now,
                "last_confirmed_at": now,
            }
            created = True
        else:
            existing["file_path"] = file_path.strip()
            existing["summary"] = summary.strip()
            existing["last_confirmed_at"] = now
            if agent_name:
                existing["recorded_by"] = agent_name
            created = False
        _persist_locked()
    record_activity_tick(agent_id)
    logger.info(
        "file context cache %s: %s (%s)",
        "recorded" if created else "updated",
        file_path.strip(),
        key[:12],
    )
    return {
        "success": True,
        "created": created,
        "message": (
            f"Summary {'recorded' if created else 'updated'} for {file_path.strip()}."
        ),
    }


def _caller_agent_name(ctx: RunContextWrapper) -> str | None:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    agent_id = inner.get("agent_id")
    coordinator = inner.get("coordinator")
    if isinstance(agent_id, str) and coordinator is not None:
        names = getattr(coordinator, "names", {})
        if isinstance(names, dict):
            name = names.get(agent_id)
            if isinstance(name, str):
                return name
    return None


@function_tool(timeout=30)
async def query_file_summary(ctx: RunContextWrapper, file_path: str, content_hash: str) -> str:
    """Check whether another agent already summarized this exact file content.

    Call this at `analysis/source_aware_discovery.md`'s "Progressive
    Context" rung 5 (Cross-file) — right before reading a shared base
    class, utility module, or trait that a candidate escalated you into —
    instead of assuming you're the first agent to need it. Hash the file
    yourself first (`sha256sum <file>` in the sandbox); this tool never
    reads the file, so an out-of-date or wrong hash silently misses rather
    than erroring.

    A hit means the file's *content* was already read and summarized by
    another agent this scan, keyed on the exact bytes — not the path, so a
    duplicate/vendored copy at a different location still hits, and a file
    edited by even one byte since the last summary correctly misses.

    Args:
        file_path: The path you're about to read, for your own reference
            in the response — not part of the lookup key.
        content_hash: The sha256 hex digest of the file's current content,
            computed by you (e.g. `sha256sum <file>`), lowercase, 64 hex
            characters.
    """
    result = await asyncio.to_thread(_query_impl, file_path=file_path, content_hash=content_hash)
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def record_file_summary(
    ctx: RunContextWrapper, file_path: str, content_hash: str, summary: str
) -> str:
    """Save your summary of a shared file for the next agent that reads the same content.

    Call this after reading and understanding a non-route file another
    agent is also likely to escalate into (a shared base class, a utility
    module, a trait) — the same place `query_file_summary` is checked
    first. Keep `summary` focused on what a later agent, investigating a
    *different* candidate, would need to know about this file without
    re-reading it: its purpose, its key methods/behavior, anything
    security-relevant it does or doesn't do. This is a plain description,
    not a finding and not a verdict — record actual candidates through the
    normal reporting/coverage tools regardless of what you write here.

    Recording is an upsert keyed on the exact content hash — recording the
    same content again (a second confirmation, or a minor wording update)
    replaces the existing summary rather than creating a duplicate.

    Args:
        file_path: Where you read this file, for provenance.
        content_hash: The sha256 hex digest of the file's content you just
            read (e.g. `sha256sum <file>`), lowercase, 64 hex characters —
            must match what a later `query_file_summary` call will hash.
        summary: Your description of the file, for a future agent to read
            instead of re-reading and re-interpreting the file itself.
    """
    agent_name = _caller_agent_name(ctx)
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    raw_agent_id = inner.get("agent_id")
    agent_id = raw_agent_id if isinstance(raw_agent_id, str) else None
    result = await asyncio.to_thread(
        _record_impl,
        file_path=file_path,
        content_hash=content_hash,
        summary=summary,
        agent_name=agent_name,
        agent_id=agent_id,
    )
    return json.dumps(result, ensure_ascii=False, default=str)
