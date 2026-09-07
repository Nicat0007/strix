"""Persistent cross-scan ruled-out cache — mirrored to ``~/.strix/negative_knowledge.json``.

``strix.tools.coverage`` answers "what did this scan check, and how did it
close" — but that ledger is scoped to one run and disappears after
``finish_scan``. A verdict like "this WordPress search-replace serializer is
safe because it correctly rewrites ``s:<len>`` headers before writing back"
is not specific to the target it was found on: the same defensive pattern
recurs, verbatim in mechanism if not in code, across every plugin in that
family. Re-deriving it from scratch on every future scan wastes the exact
kind of reasoning this cache exists to carry forward.

The key deliberately is **not** "same file, same target" (that is what
``coverage.json`` already does, and a fresh target is a fresh file every
time) and deliberately is **not** a hash of raw source text (two plugins
implementing the same safe pattern are never byte-identical, so a literal
hash would never match anything — see the module docstring on
``_normalize_tokens`` for why the signature is built from API/function-name
tokens instead). It is ``(framework, vulnerability_class, signature_hash)``,
where ``signature_hash`` is computed here, deterministically, from a small
set of concrete API/function names the recording agent names explicitly —
never a similarity score the model invents, and never the model's own
confidence in the match.

Promotion is deliberate, not automatic. Most ``ruled_out``/``no_issue_found``
coverage entries are target-specific ("this IP allowlists our runner") and
would poison a cross-target cache if mirrored wholesale. Recording here is a
second, explicit tool call an agent makes only when it judges the reasoning
itself — not just the verdict — transfers to a different codebase of the
same framework.

A hit is a strong prior, never a silent skip: the calling skill
(``analysis/counterevidence.md``) still expects a fast confirmation that the
same guard is actually present, unmodified, at the new location before
treating a candidate as closed.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.config import load_settings
from strix.skills import get_available_skills
from strix.utils.target_identity import target_identity


logger = logging.getLogger(__name__)

_DEFAULT_PATH: Path = Path.home() / ".strix" / "negative_knowledge.json"
_SCHEMA_VERSION = 1
_MIN_SIGNATURE_TOKENS = 2
_MAX_EXAMPLE_LOCATIONS = 5
_MAX_RELATED_RESULTS = 10

_store: dict[str, dict[str, Any]] = {}
_lock = threading.RLock()
_path: Path | None = None

#: Restricted to the two coverage outcomes that mean "checked, found safe" —
#: ``needs_follow_up``/``not_applicable``/``reported`` describe states that
#: never generalize as a safety pattern.
VALID_OUTCOMES: tuple[str, ...] = ("ruled_out", "no_issue_found")


def _normalize_framework(framework: str) -> str:
    return " ".join(framework.strip().lower().split())


def _skill_leaf(vulnerability_class: str) -> str:
    return vulnerability_class.strip().lower().rsplit("/", maxsplit=1)[-1]


def _normalize_tokens(tokens: list[str]) -> list[str]:
    """Collapse a signature to a sorted, deduped set of lowercase API names.

    Matching happens on this set, not on the tokens' original order or
    casing — two agents naming the same two functions in a different order
    must hash to the same key. Sorting also means the hash is a pure
    function of the *set* of names, never of how the agent happened to list
    them.
    """
    cleaned = {" ".join(t.strip().lower().split()) for t in tokens if t and t.strip()}
    return sorted(cleaned)


def _signature_hash(tokens: list[str]) -> str:
    joined = "|".join(tokens)
    return "sha256:" + hashlib.sha256(joined.encode("utf-8")).hexdigest()


def _entry_key(framework: str, vulnerability_class: str, signature_hash: str) -> str:
    return f"{framework}||{vulnerability_class}||{signature_hash}"


def _bucket_prefix(framework: str, vulnerability_class: str) -> str:
    return f"{framework}||{vulnerability_class}||"


def _canonical_vulnerability_classes() -> frozenset[str]:
    """Bare names of every ``vulnerabilities/*.md`` skill.

    Reused as the closed vocabulary for ``vulnerability_class`` instead of
    letting the cache invent its own taxonomy — the same skill-name set
    ``strix.report.coverage`` already treats as canonical.
    """
    try:
        entries = get_available_skills().get("vulnerabilities", [])
        return frozenset(entry["name"] for entry in entries if entry.get("name"))
    except OSError:
        logger.warning(
            "could not enumerate vulnerability skills for negative-knowledge validation",
            exc_info=True,
        )
        return frozenset()


def hydrate_negative_knowledge_from_disk(path: Path | None = None) -> None:
    """Load the persistent cache from *path* (default ``~/.strix/...``).

    Called once per process, alongside the other ``hydrate_*_from_disk``
    calls in ``core/runner.py`` — but pointed at a fixed cross-scan path
    instead of the run's own ``.state`` directory, since this is the one
    store meant to outlive a single run.
    """
    global _path  # noqa: PLW0603
    _path = path or _DEFAULT_PATH
    with _lock:
        _store.clear()
        if not _path.exists():
            return
        try:
            data = json.loads(_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception(
                "negative_knowledge.json at %s is unreadable; starting with an empty cache",
                _path,
            )
            return
        entries = data.get("entries") if isinstance(data, dict) else None
        if isinstance(entries, dict):
            _store.update(
                {key: entry for key, entry in entries.items() if isinstance(entry, dict)}
            )
        logger.info("negative knowledge hydrated from %s (%d entr(ies))", _path, len(_store))


def _persist_locked() -> None:
    """Mirror the cache to disk. Callers must already hold ``_lock``.

    A no-op until :func:`hydrate_negative_knowledge_from_disk` has run —
    matching ``strix.tools.coverage.tools``'s own guard — so a test or a
    caller that never hydrates can never accidentally write into a real
    ``~/.strix/negative_knowledge.json`` on the host.
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
        logger.exception("negative knowledge persist to %s failed", path)


def _validate_pattern(
    *, framework: str, vulnerability_class: str, mechanism_signature: list[str]
) -> tuple[str, list[str], str, list[str]]:
    """Checks shared by both querying and recording. Returns errors, never raises."""
    errors: list[str] = []

    norm_framework = _normalize_framework(framework)
    if not norm_framework:
        errors.append(
            "framework cannot be empty - name the technology/platform this pattern applies to "
            "(e.g. 'wordpress-plugin', 'django-rest-framework')"
        )

    norm_class = _skill_leaf(vulnerability_class)
    canonical = _canonical_vulnerability_classes()
    if canonical and norm_class not in canonical:
        errors.append(
            f"Invalid vulnerability_class: {vulnerability_class!r}. Must be one of the "
            f"vulnerabilities/*.md skill names: {sorted(canonical)}"
        )
    elif not canonical and not norm_class:
        errors.append("vulnerability_class cannot be empty")

    tokens = _normalize_tokens(mechanism_signature)
    if len(tokens) < _MIN_SIGNATURE_TOKENS:
        errors.append(
            f"mechanism_signature needs at least {_MIN_SIGNATURE_TOKENS} concrete API/function "
            "name tokens (e.g. ['maybe_unserialize', 'allowed_classes_false']) - name only "
            "library/framework/language built-ins, never project-specific class or variable "
            "names, since built-ins are what actually stays constant across two different "
            "codebases using the same safe pattern. A single generic token would match too "
            "broadly across mechanisms that are not actually the same."
        )

    return norm_framework, tokens, norm_class, errors


def _validate_record_extra(*, mechanism: str, outcome: str, location: str) -> tuple[str, list[str]]:
    errors: list[str] = []
    if not mechanism.strip():
        errors.append(
            "mechanism cannot be empty - explain, in one or two sentences, why this pattern is "
            "safe (what it does, not just that it is fine)"
        )
    normalized_outcome = outcome.strip().lower().replace("-", "_").replace(" ", "_")
    if normalized_outcome not in VALID_OUTCOMES:
        errors.append(f"Invalid outcome: {outcome!r}. Must be one of: {list(VALID_OUTCOMES)}")
    if not location.strip():
        errors.append(
            "location cannot be empty - name the file:line (or file) this was confirmed at, "
            "for this cache entry's own provenance trail"
        )
    return normalized_outcome, errors


def _public_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Strip internal bookkeeping (raw source-target hashes) before returning to an agent."""
    return {
        "framework": entry.get("framework", ""),
        "vulnerability_class": entry.get("vulnerability_class", ""),
        "mechanism_signature": entry.get("mechanism_signature", []),
        "mechanism": entry.get("mechanism", ""),
        "outcome": entry.get("outcome", ""),
        "example_locations": entry.get("example_locations", []),
        "corroborations": entry.get("corroborations", 0),
        "created_at": entry.get("created_at", ""),
        "last_confirmed_at": entry.get("last_confirmed_at", ""),
    }


def _current_source_target_hash() -> str | None:
    """Hash of the current scan's target identity, or ``None`` outside a scan.

    Hashed rather than stored in plaintext so the cache file never becomes a
    readable list of which clients/targets contributed which pattern. Used
    only to dedupe corroboration counting (has this exact target already
    confirmed this pattern before), never surfaced to an agent.
    """
    try:
        from strix.core.inputs import build_scan_targets
        from strix.report.state import get_global_report_state

        state = get_global_report_state()
        if state is None or not state.scan_config:
            return None
        canonical = build_scan_targets(state.scan_config)
        if not canonical:
            return None
        identities = sorted({target_identity(value) for value in canonical})
    except Exception:
        logger.warning(
            "could not resolve source target identity for negative knowledge", exc_info=True
        )
        return None
    joined = "|".join(identities)
    return "sha256:" + hashlib.sha256(joined.encode("utf-8")).hexdigest()


def _query_impl(
    *,
    framework: str,
    vulnerability_class: str,
    mechanism_signature: list[str],
    enabled: bool = True,
) -> dict[str, Any]:
    if not enabled:
        return {
            "success": True,
            "enabled": False,
            "exact_match": None,
            "related_in_bucket": [],
            "bucket_count": 0,
            "message": "Persistent negative knowledge is disabled for this run.",
        }

    norm_framework, tokens, norm_class, errors = _validate_pattern(
        framework=framework,
        vulnerability_class=vulnerability_class,
        mechanism_signature=mechanism_signature,
    )
    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    signature_hash = _signature_hash(tokens)
    key = _entry_key(norm_framework, norm_class, signature_hash)
    prefix = _bucket_prefix(norm_framework, norm_class)

    with _lock:
        exact = _store.get(key)
        exact_out = _public_entry(exact) if exact else None
        related = [
            _public_entry(entry)
            for entry_key, entry in _store.items()
            if entry_key != key and entry_key.startswith(prefix)
        ]

    related.sort(key=lambda e: e["corroborations"], reverse=True)
    related = related[:_MAX_RELATED_RESULTS]

    return {
        "success": True,
        "enabled": True,
        "exact_match": exact_out,
        "related_in_bucket": related,
        "bucket_count": len(related) + (1 if exact_out else 0),
    }


def _record_impl(
    *,
    framework: str,
    vulnerability_class: str,
    mechanism_signature: list[str],
    mechanism: str,
    outcome: str,
    location: str,
    source_target_hash: str | None = None,
    agent_name: str | None = None,
    enabled: bool = True,
) -> dict[str, Any]:
    if not enabled:
        return {
            "success": True,
            "enabled": False,
            "message": (
                "Persistent negative knowledge is disabled for this run "
                "(STRIX_NEGATIVE_KNOWLEDGE=false); nothing was persisted."
            ),
        }

    norm_framework, tokens, norm_class, errors = _validate_pattern(
        framework=framework,
        vulnerability_class=vulnerability_class,
        mechanism_signature=mechanism_signature,
    )
    norm_outcome, extra_errors = _validate_record_extra(
        mechanism=mechanism, outcome=outcome, location=location
    )
    errors.extend(extra_errors)
    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    signature_hash = _signature_hash(tokens)
    key = _entry_key(norm_framework, norm_class, signature_hash)
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    location_clean = location.strip()

    with _lock:
        existing = _store.get(key)
        if existing is None:
            entry: dict[str, Any] = {
                "framework": norm_framework,
                "vulnerability_class": norm_class,
                "mechanism_signature": tokens,
                "signature_hash": signature_hash,
                "mechanism": mechanism.strip(),
                "outcome": norm_outcome,
                "example_locations": [location_clean] if location_clean else [],
                "source_target_hashes": [source_target_hash] if source_target_hash else [],
                "corroborations": 1 if source_target_hash else 0,
                "created_at": now,
                "last_confirmed_at": now,
                "recorded_by": agent_name or "",
            }
            _store[key] = entry
            _persist_locked()
            logger.info("negative knowledge recorded: %s", key)
            return {
                "success": True,
                "enabled": True,
                "created": True,
                "corroborations": entry["corroborations"],
                "message": (
                    f"New negative-knowledge entry recorded for {norm_framework}/{norm_class}."
                ),
            }

        existing["mechanism"] = mechanism.strip()
        existing["outcome"] = norm_outcome
        existing["last_confirmed_at"] = now
        locations = existing.get("example_locations") or []
        if location_clean and location_clean not in locations:
            existing["example_locations"] = [*locations, location_clean][-_MAX_EXAMPLE_LOCATIONS:]
        source_hashes = existing.setdefault("source_target_hashes", [])
        if source_target_hash and source_target_hash not in source_hashes:
            source_hashes.append(source_target_hash)
        existing["corroborations"] = len(source_hashes)
        _persist_locked()
        logger.info(
            "negative knowledge re-confirmed: %s (corroborations=%d)",
            key,
            existing["corroborations"],
        )
        return {
            "success": True,
            "enabled": True,
            "created": False,
            "corroborations": existing["corroborations"],
            "message": (
                f"Existing negative-knowledge entry for {norm_framework}/{norm_class} "
                f"re-confirmed (corroborations={existing['corroborations']})."
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
async def query_negative_knowledge(
    ctx: RunContextWrapper,
    framework: str,
    vulnerability_class: str,
    mechanism_signature: list[str],
) -> str:
    """Check whether a candidate matches a pattern already ruled out on a past scan.

    Call this once you have read enough of the code to name the specific
    API/function calls that make (or would make) a candidate safe — not
    before, since the lookup key depends on those concrete names. A hit
    here is a **strong prior, never a reason to skip verification**: do one
    fast, targeted confirmation that the same guard is actually present and
    unmodified at this location before treating the candidate as closed. A
    plugin can always differ from the pattern in a way that matters (a
    missing check the prior instance had, a reachable path the prior
    instance didn't expose) — this tool narrows where to look, it does not
    replace looking. See ``analysis/counterevidence.md`` for the full
    closure discipline this feeds into.

    Returns two things:

    - ``exact_match``: an entry with the identical
      ``(framework, vulnerability_class, mechanism_signature)`` — the strong
      prior described above, or ``null`` if none exists.
    - ``related_in_bucket``: other ruled-out patterns for the same
      ``framework``/``vulnerability_class`` but a *different* mechanism.
      This is background context only ("this framework/class combination
      has N other known-safe shapes") — it says nothing about whether your
      current candidate is one of them, and never lowers how much you
      verify it.

    Args:
        framework: The technology/platform this candidate belongs to (e.g.
            ``"wordpress-plugin"``, ``"django-rest-framework"``) — should
            match how you'd call ``record_negative_knowledge`` for the same
            code, so use the same normalized spelling.
        vulnerability_class: One of the ``vulnerabilities/*.md`` skill
            names (e.g. ``"insecure_deserialization"``, ``"sql_injection"``,
            ``"idor"``).
        mechanism_signature: The concrete library/framework/language
            built-in API or function names involved in the safety
            mechanism you are checking (e.g.
            ``["maybe_unserialize", "allowed_classes_false"]``). Name only
            built-ins, never project-specific identifiers — those are what
            stay constant across two different codebases using the same
            pattern. At least 2 tokens.
    """
    enabled = load_settings().negative_knowledge.enabled
    result = await asyncio.to_thread(
        _query_impl,
        framework=framework,
        vulnerability_class=vulnerability_class,
        mechanism_signature=mechanism_signature,
        enabled=enabled,
    )
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def record_negative_knowledge(
    ctx: RunContextWrapper,
    framework: str,
    vulnerability_class: str,
    mechanism_signature: list[str],
    mechanism: str,
    outcome: str,
    location: str,
) -> str:
    """Promote a ruled-out/no-issue-found verdict to the persistent cross-scan cache.

    Call this **in addition to**, never instead of, ``record_coverage`` /
    ``update_coverage`` — this cache is a separate, longer-lived store, not
    a replacement for the per-run ledger. Only call it when you consciously
    judge that the *reasoning itself*, not just the verdict, would transfer
    to a different codebase built on the same framework — most
    ``ruled_out``/``no_issue_found`` conclusions are target-specific (a
    firewall rule, an IP allowlist, a config value unique to this
    deployment) and do not belong here. A good candidate for this tool
    looks like "this framework's own API, used this way, is structurally
    safe" rather than "this particular deployment happens to be fine."

    Recording is an upsert keyed on
    ``(framework, vulnerability_class, mechanism_signature)`` — recording
    the same pattern again (from this scan or a future one) updates the
    existing entry and increments ``corroborations`` rather than creating a
    duplicate. ``corroborations`` is a plain count of distinct scans that
    have independently confirmed this exact pattern — never a confidence
    score, and never generated by you; the tool computes it.

    Keep ``mechanism`` framework-generic: describe the mechanism, not this
    engagement or this client's business context, since this cache
    outlives the run it was written in and is read by unrelated future
    scans.

    Args:
        framework: The technology/platform this pattern applies to (e.g.
            ``"wordpress-plugin"``). Use a normalized spelling you'd expect
            to reuse verbatim on a future scan of a similar codebase.
        vulnerability_class: One of the ``vulnerabilities/*.md`` skill
            names (e.g. ``"insecure_deserialization"``).
        mechanism_signature: At least 2 concrete library/framework/language
            built-in API or function names that make this pattern safe
            (e.g. ``["maybe_unserialize", "allowed_classes_false"]``).
            Never project-specific class or variable names — those never
            recur on a different codebase, so including them guarantees
            this entry will never match anything again.
        mechanism: One or two sentences explaining *why* this pattern is
            safe (what it does, not just that it's fine) — this is what a
            future agent reads on a hit.
        outcome: ``ruled_out`` or ``no_issue_found`` — the two coverage
            outcomes that represent "checked, and safe." Anything else
            (``needs_follow_up``, ``not_applicable``, ``reported``) does
            not belong in this cache.
        location: Where you confirmed this on the current target
            (``file:line`` or a file path) — kept as this entry's own
            provenance trail, never used for matching.
    """
    settings = load_settings().negative_knowledge
    agent_name = _caller_agent_name(ctx)
    source_target_hash = _current_source_target_hash() if settings.enabled else None
    result = await asyncio.to_thread(
        _record_impl,
        framework=framework,
        vulnerability_class=vulnerability_class,
        mechanism_signature=mechanism_signature,
        mechanism=mechanism,
        outcome=outcome,
        location=location,
        source_target_hash=source_target_hash,
        agent_name=agent_name,
        enabled=settings.enabled,
    )
    return json.dumps(result, ensure_ascii=False, default=str)
