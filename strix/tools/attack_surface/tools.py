"""Run-scoped black-box attack-surface inventory — mirrored to
``{state_dir}/attack_surface_inventory.json``.

Coverage (`strix/tools/coverage/tools.py`) answers *what did we look at and how
did it close*. This answers the prior question for black-box scans: *what
endpoints exist, what shape do they take, and what has each actor observed
about them* — the structured evidence that recon discovers and that the
authorization / parameter-mutation workflows consume instead of re-deriving it
from free-text `/workspace/recon/*` files on every agent.

Design mirrors the other per-run host-side stores: a module-level dict guarded
by a reentrant lock, atomically mirrored to the run's ``{state_dir}`` so it
survives ``--resume`` (hydrate is unconditional — empty on a fresh run,
populated on resume), and keyed deterministically so repeated ingestion of the
same crawl is idempotent rather than duplicating the inventory.

Identity, de-duplication, and object-specific evidence:

- An **endpoint** is ``(origin, method, normalized_path)``. Origin is
  ``scheme://host:port`` with the effective port, so ``http://h``,
  ``https://h`` and ``https://h:8443`` stay three distinct origins (same rule
  `assets.jsonl` uses). The normalized path is the *template*: numeric / UUID /
  long-hex id segments collapse to ``{id}`` so ``/orders/1`` and ``/orders/2``
  share one endpoint template, while ``/orders/{id}`` and ``/users/{id}`` stay
  distinct.
- The endpoint is the template, but evidence is kept **per concrete object**.
  Each observation, request reference, ownership hint, and test outcome is
  tagged with the concrete ``resource`` path (``/orders/1`` vs ``/orders/2``),
  so a cross-object or cross-actor difference is never flattened and a
  completed test on one object never closes its siblings. The concrete
  resource keeps short/numeric ids distinct but still collapses token-shaped
  segments (long hex, JWT/key shapes) so a secret in a path is never stored.
  Distinct resources per endpoint are bounded; past the cap, further ids fold
  into the template bucket and the endpoint is flagged ``resource_overflow``.
- Parameter **names and locations** are merged into the endpoint (deduped by
  name+location); values are never kept.
- **Observations** are per ``(resource, actor_ref, auth_state, status_code,
  discovery_source)``.

Reference vs. verified replay: a ``request_ref`` is an *opaque pointer* into
existing session/proxy request storage (e.g. a Caido request id). Recording a
reference does **not** assert the request is replayable — an observation with a
reference is ``replay_state="recorded"`` and still ``requires_validation`` until
an agent actually replays it and records ``replay_verified=True``
(``replay_state="verified"``). On ``--resume`` every ``verified`` state is
downgraded to ``stale`` (a prior process's freshness cannot carry across a
resume), so a restored reference always requires re-validation before it is
trusted.

Secrets: this is the *general* inventory, so it stores no values at all — only
names, locations, methods, status codes, content types, timestamps, discovery
sources, concrete resource paths (token-shaped segments collapsed), and the
opaque ``request_ref``. The raw URL (which can carry userinfo and query-string
values) is never stored; only the sanitized ``origin`` + resource path is.
Free-text fields that an agent authors (ownership hints, test notes, discovery
source labels, request references) are run through a secret-shape redactor, and
secret-bearing header values on ingested proxy/manual records are scrubbed
before anything is kept.

Katana ingestion is verified against the schema the pinned sandbox katana
actually emits (see ``_ingest_katana``): each crawled request — including every
XHR/fetch fired in headless mode — is its own flat top-level record
``{"request":{"method","endpoint",...},"response":{"status_code","headers",...}}``.
There is no ``response.xhr_requests[]`` array in that version; the nested shape
is tolerated only as a fallback for other katana builds.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from agents import RunContextWrapper, function_tool

from strix.tools.agent_metrics.tools import record_activity_tick
from strix.utils.target_identity import remote_authority


logger = logging.getLogger(__name__)

_SCHEMA_VERSION = 2

_store: dict[str, dict[str, Any]] = {}
_lock = threading.RLock()
_path: Path | None = None

#: How many endpoints a single query returns before truncating, and how long an
#: opaque request reference may be (a reference, never an inlined request).
_QUERY_LIMIT_DEFAULT = 100
_QUERY_LIMIT_MAX = 500
_REQUEST_REF_MAX = 256
_OWNERSHIP_HINT_MAX = 300
_NOTE_MAX = 500
_SOURCE_MAX = 64
#: Distinct concrete resources tracked per endpoint template before further ids
#: fold into the template bucket (keeps object evidence distinct but bounded).
_MAX_RESOURCES_PER_ENDPOINT = 25
#: Projection bounds, so a single query result can never be unbounded.
_MAX_OBSERVATIONS_RETURNED = 100
_MAX_RESOURCES_RETURNED = 50

VALID_AUTH_STATES: tuple[str, ...] = ("anonymous", "authenticated", "unknown")
VALID_PARAM_LOCATIONS: tuple[str, ...] = ("query", "body", "path", "header", "cookie", "unknown")
VALID_TEST_STATUSES: tuple[str, ...] = ("pending", "completed", "blocked")
VALID_OWNERSHIP_KINDS: tuple[str, ...] = ("inferred", "observed")

#: Replay-reference lifecycle. ``recorded`` = a reference exists but the request
#: has not been proven replayable; ``verified`` = an agent actually replayed it
#: this process; ``stale`` = it was verified in an earlier process and that
#: freshness did not survive a resume. Only ``verified`` means "trust it now".
REPLAY_RECORDED = "recorded"
REPLAY_VERIFIED = "verified"
REPLAY_STALE = "stale"

#: Header/parameter names whose *values* are secrets. The schema never stores a
#: value anywhere, so these are safe to record by name (a login endpoint taking
#: a ``password`` field is discovery signal); this set only drives the explicit
#: scrub of any value a caller tries to smuggle through on a manual/proxy
#: record, so no secret can ever reach the general inventory.
_SECRET_VALUE_KEYS: frozenset[str] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "apikey",
        "x-auth-token",
    }
)

#: Secret-shaped token patterns, redacted out of any agent-authored free text
#: (ownership hints, notes, source labels) and used to reject/collapse
#: secret-bearing request references and path segments.
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"),  # JWT
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),  # Bearer <token>
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"),  # OpenAI/DeepSeek-style key
    re.compile(r"\bAIza[0-9A-Za-z_-]{10,}"),  # Google API key
    re.compile(r"\bAKIA[0-9A-Z]{8,}"),  # AWS access key id
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),  # GitHub token
    re.compile(r"\b[0-9a-fA-F]{32,}\b"),  # long hex blob (session/token-shaped)
)
_REDACTED = "«redacted»"

_NUMERIC_SEGMENT = re.compile(r"^\d+$")
_UUID_SEGMENT = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_LONG_HEX_SEGMENT = re.compile(r"^[0-9a-fA-F]{24,}$")


def _clean(value: str | None, *, lower: bool = False) -> str | None:
    """Strip a caller filter to a non-empty value, or None. Optionally lowercased."""
    if not value or not value.strip():
        return None
    stripped = value.strip()
    return stripped.lower() if lower else stripped


def _contains_secret(text: str) -> bool:
    return any(pattern.search(text) for pattern in _SECRET_PATTERNS)


def _redact_secrets(text: str) -> str:
    """Mask secret-shaped tokens in agent-authored free text, in place of storing
    them verbatim. Defensive: narrows the blast radius of a careless hint/note."""
    out = text
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub(_REDACTED, out)
    return out


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


# --------------------------------------------------------------------------- #
# Persistence (same shape as coverage / file_context_cache)
# --------------------------------------------------------------------------- #


def hydrate_attack_surface_from_disk(state_dir: Path) -> None:
    """Load this run's inventory from ``{state_dir}/attack_surface_inventory.json``.

    Called once per process alongside the other ``hydrate_*_from_disk`` calls in
    ``core/runner.py``. Unconditional: on a fresh run the file does not exist and
    the store starts empty; on ``--resume`` of the same run the persisted
    endpoints — with their original timestamps and provenance — are restored.

    Any replay reference that was ``verified`` in the prior process is downgraded
    to ``stale`` on load: a resumed process cannot assume a previously-replayed
    request is still valid (a session may have expired), so restored references
    always require re-validation before they are trusted.
    """
    global _path  # noqa: PLW0603
    _path = state_dir / "attack_surface_inventory.json"
    with _lock:
        _store.clear()
        if not _path.exists():
            return
        try:
            data = json.loads(_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception(
                "attack_surface_inventory.json at %s is unreadable; starting empty", _path
            )
            return
        entries = data.get("endpoints") if isinstance(data, dict) else None
        if isinstance(entries, dict):
            restored = {key: entry for key, entry in entries.items() if isinstance(entry, dict)}
            for entry in restored.values():
                _mark_references_stale_on_resume(entry)
            _store.update(restored)
        logger.info(
            "attack-surface inventory hydrated from %s (%d endpoint(s))", _path, len(_store)
        )


def _mark_references_stale_on_resume(entry: dict[str, Any]) -> None:
    """Downgrade every previously-verified replay reference to ``stale`` so a
    resumed run re-validates it rather than trusting a prior process's freshness."""
    for observation in entry.get("observations", []):
        if observation.get("replay_state") == REPLAY_VERIFIED:
            observation["replay_state"] = REPLAY_STALE


def lookup_endpoint(endpoint_id: str) -> dict[str, Any] | None:
    """Public, read-only projection of one endpoint by id, or None if unknown.

    Lets another run-scoped store (e.g. the hypothesis worklist) denormalize an
    endpoint's origin/method/path/resources without reaching into private state.
    Observations are omitted — callers that need per-actor detail query directly.
    """
    with _lock:
        entry = _store.get((endpoint_id or "").strip())
        return _public_entry(entry, include_observations=False) if entry else None


def _persist_locked() -> None:
    """Mirror the inventory to disk. Callers must already hold ``_lock``.

    A no-op until hydration has run, matching the other stores' guard, so a
    caller that forgets to hydrate can never write into a stray path. The
    serialize + atomic rename happen in one critical section so a concurrent
    writer cannot roll back another agent's endpoint.
    """
    path = _path
    if path is None:
        return
    try:
        payload = json.dumps(
            {"schema_version": _SCHEMA_VERSION, "endpoints": _store},
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
        logger.exception("attack-surface inventory persist to %s failed", path)


# --------------------------------------------------------------------------- #
# Identity helpers
# --------------------------------------------------------------------------- #


def origin_of(url: str) -> str | None:
    """``scheme://host:port`` for a URL, with the effective port; None if hostless.

    Reuses ``target_identity.remote_authority`` (``host[:port]`` with default
    ports filled in) and prepends the scheme, so scheme and port both stay part
    of the origin identity rather than being flattened onto the bare host.
    ``remote_authority`` drops any userinfo, so a ``user:pass@`` URL never leaks
    its credentials into the stored origin.
    """
    authority = remote_authority(url)
    if not authority:
        return None
    candidate = url if "://" in url else f"//{url}"
    scheme = (urlsplit(candidate).scheme or "https").lower()
    return f"{scheme}://{authority}"


def _normalize_path(path: str) -> str:
    """Template path: collapse numeric / UUID / long-hex id segments to ``{id}``."""
    if not path:
        return "/"
    out: list[str] = []
    for segment in path.split("/"):
        if (
            _NUMERIC_SEGMENT.match(segment)
            or _UUID_SEGMENT.match(segment)
            or _LONG_HEX_SEGMENT.match(segment)
            or (segment and _contains_secret(segment))
        ):
            out.append("{id}")
        else:
            out.append(segment)
    return "/".join(out) or "/"


def _resource_path(path: str) -> str:
    """Concrete object path: keep short/numeric/UUID ids distinct (so ``/orders/1``
    and ``/orders/2`` stay separate objects), but collapse token-shaped segments
    (long hex, JWT/key shapes) to ``{id}`` so a secret in a path is never stored."""
    if not path:
        return "/"
    out: list[str] = []
    for segment in path.split("/"):
        if _UUID_SEGMENT.match(segment):
            out.append(segment)  # a UUID is an identifier, not a secret — keep distinct
        elif _LONG_HEX_SEGMENT.match(segment) or (segment and _contains_secret(segment)):
            out.append("{id}")  # token-shaped segment: collapse, never store verbatim
        else:
            out.append(segment)
    return "/".join(out) or "/"


def _path_of(url: str) -> str:
    candidate = url if "://" in url else f"//{url}"
    return urlsplit(candidate).path or "/"


def _endpoint_identity(url: str, method: str) -> tuple[str, str, str] | None:
    """Return ``(origin, method, template_path)`` or None if the URL is unusable."""
    origin = origin_of(url)
    if origin is None:
        return None
    return origin, method.strip().upper() or "GET", _normalize_path(_path_of(url))


def _endpoint_id(origin: str, method: str, normalized_path: str) -> str:
    key = f"{method} {origin}{normalized_path}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


def _query_param_names(url: str) -> list[str]:
    candidate = url if "://" in url else f"//{url}"
    query = urlsplit(candidate).query
    if not query:
        return []
    return list(parse_qs(query, keep_blank_values=True).keys())


# --------------------------------------------------------------------------- #
# Normalization of caller-supplied parameters (names + locations only)
# --------------------------------------------------------------------------- #


def _coerce_parameters(raw: Any) -> tuple[list[dict[str, str]], list[str]]:
    """Normalize a caller's ``parameters`` into ``[{name, location}]``.

    Accepts a list of ``{"name","location"}`` dicts or a list of bare name
    strings (location defaults to ``query``). Any ``value``/``val`` key is
    dropped so a secret can never be smuggled in. Returns the clean list plus
    per-item diagnostics for anything skipped.
    """
    diagnostics: list[str] = []
    params: list[dict[str, str]] = []
    if raw is None:
        return params, diagnostics
    if not isinstance(raw, list):
        diagnostics.append("parameters must be a list of {name, location} objects or names")
        return params, diagnostics
    for index, item in enumerate(raw):
        if isinstance(item, str):
            name, location = item, "query"
        elif isinstance(item, dict):
            name = str(item.get("name", "")).strip()
            location = str(item.get("location", "query")).strip().lower()
        else:
            diagnostics.append(f"parameter #{index} is not a name string or an object")
            continue
        name = name.strip()
        if not name:
            diagnostics.append(f"parameter #{index} has an empty name")
            continue
        if location not in VALID_PARAM_LOCATIONS:
            location = "unknown"
        params.append({"name": name, "location": location})
    return params, diagnostics


def _merge_parameters(entry: dict[str, Any], new_params: list[dict[str, str]]) -> None:
    existing = entry.setdefault("parameters", [])
    seen = {(p["name"].lower(), p["location"]) for p in existing}
    for param in new_params:
        key = (param["name"].lower(), param["location"])
        if key not in seen:
            seen.add(key)
            existing.append(param)


def _merge_observation(
    entry: dict[str, Any],
    *,
    resource: str,
    actor_ref: str,
    auth_state: str,
    status_code: int | None,
    content_type: str | None,
    discovery_source: str,
    request_ref: str | None,
    replay_verified: bool,
    now: str,
) -> None:
    observations = entry.setdefault("observations", [])
    key = (resource, actor_ref, auth_state, status_code, discovery_source)
    for observation in observations:
        existing_key = (
            observation.get("resource"),
            observation.get("actor_ref"),
            observation.get("auth_state"),
            observation.get("status_code"),
            observation.get("discovery_source"),
        )
        if existing_key == key:
            observation["last_observed_at"] = now
            observation["times_observed"] = int(observation.get("times_observed", 1)) + 1
            if content_type and not observation.get("content_type"):
                observation["content_type"] = content_type
            _apply_replay(observation, request_ref=request_ref, replay_verified=replay_verified,
                          now=now)
            return
    new_observation: dict[str, Any] = {
        "resource": resource,
        "actor_ref": actor_ref,
        "auth_state": auth_state,
        "discovery_source": discovery_source,
        "first_observed_at": now,
        "last_observed_at": now,
        "times_observed": 1,
    }
    if status_code is not None:
        new_observation["status_code"] = status_code
    if content_type:
        new_observation["content_type"] = content_type
    _apply_replay(new_observation, request_ref=request_ref, replay_verified=replay_verified,
                  now=now)
    observations.append(new_observation)


def _apply_replay(
    observation: dict[str, Any], *, request_ref: str | None, replay_verified: bool, now: str
) -> None:
    """Record / upgrade an observation's replay reference and state.

    A reference alone only reaches ``recorded`` (still requires validation);
    ``verified`` is set only when an agent explicitly attests it replayed the
    request this process. ``verified`` never silently downgrades on a later
    reference-only touch.
    """
    if request_ref and not observation.get("request_ref"):
        observation["request_ref"] = request_ref
    has_ref = bool(observation.get("request_ref"))
    if not has_ref:
        return
    if replay_verified:
        observation["replay_state"] = REPLAY_VERIFIED
        observation["replay_verified_at"] = now
    elif observation.get("replay_state") != REPLAY_VERIFIED:
        observation["replay_state"] = REPLAY_RECORDED


# --------------------------------------------------------------------------- #
# Core record / query implementations
# --------------------------------------------------------------------------- #


def _normalize_actor_and_ref(
    *, actor_ref: str | None, auth_state: str | None, request_ref: str | None
) -> tuple[str, str, str, list[str]]:
    """Normalize actor label, auth state, and request reference; collect diagnostics."""
    diagnostics: list[str] = []
    actor = (actor_ref or "anonymous").strip() or "anonymous"
    state = (auth_state or "unknown").strip().lower()
    if state not in VALID_AUTH_STATES:
        diagnostics.append(f"auth_state {auth_state!r} not recognized; recorded as 'unknown'")
        state = "unknown"
    ref = (request_ref or "").strip()
    if ref and (len(ref) > _REQUEST_REF_MAX or "\n" in ref):
        diagnostics.append(
            "request_ref looks like inlined content, not a reference; dropped. Pass a short "
            "id into existing request storage (e.g. a Caido request id)."
        )
        ref = ""
    elif ref and _contains_secret(ref):
        diagnostics.append(
            "request_ref contained a secret-shaped token and was dropped; a reference must be "
            "an opaque id (e.g. a Caido request id), never the request/token itself."
        )
        ref = ""
    return actor, state, ref, diagnostics


def _merge_ownership_hint(
    entry: dict[str, Any], resource: str, hint: str | None, kind: str
) -> None:
    text = _redact_secrets((hint or "").strip())
    if not text:
        return
    normalized_kind = kind.strip().lower()
    if normalized_kind not in VALID_OWNERSHIP_KINDS:
        normalized_kind = "inferred"
    record = {"resource": resource, "hint": text[:_OWNERSHIP_HINT_MAX], "kind": normalized_kind}
    hints = entry.setdefault("ownership_hints", [])
    if record not in hints:
        hints.append(record)


def _resolve_resource(entry: dict[str, Any], resource: str) -> str:
    """Return the concrete resource to record against, folding into the template
    bucket once the per-endpoint distinct-resource cap is reached (keeps object
    evidence distinct but bounded)."""
    resources: list[str] = entry.setdefault("resources", [])
    if resource in resources:
        return resource
    if len(resources) < _MAX_RESOURCES_PER_ENDPOINT:
        resources.append(resource)
        return resource
    entry["resource_overflow"] = True
    template = entry.get("path", resource)
    if template not in resources:
        resources.append(template)
    return template


def _record_impl(
    *,
    url: str,
    method: str,
    parameters: Any = None,
    content_type: str | None = None,
    discovery_source: str,
    actor_ref: str | None = None,
    auth_state: str | None = None,
    status_code: int | None = None,
    request_ref: str | None = None,
    replay_verified: bool = False,
    ownership_hint: str | None = None,
    ownership_hint_kind: str = "inferred",
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    if not discovery_source or not discovery_source.strip():
        return {
            "success": False,
            "error": "discovery_source cannot be empty - name where this came from "
            "(e.g. 'katana', 'httpx', 'arjun', 'proxy', 'manual', 'js-analysis')",
        }

    identity = _endpoint_identity(url, method)
    if identity is None:
        return {"success": False, "error": "the provided url has no resolvable host/origin"}
    origin, norm_method, norm_path = identity
    endpoint_id = _endpoint_id(origin, norm_method, norm_path)
    resource = _resource_path(_path_of(url))

    actor, state, ref, diagnostics = _normalize_actor_and_ref(
        actor_ref=actor_ref, auth_state=auth_state, request_ref=request_ref
    )
    params, param_diags = _coerce_parameters(parameters)
    diagnostics.extend(param_diags)
    # Query-string parameter names carried in the URL are discovery signal too.
    params.extend({"name": name, "location": "query"} for name in _query_param_names(url))

    src = _redact_secrets(discovery_source.strip().lower())[:_SOURCE_MAX]
    now = _now()
    with _lock:
        entry = _store.get(endpoint_id)
        created = entry is None
        if entry is None:
            entry = {
                "endpoint_id": endpoint_id,
                "origin": origin,
                "method": norm_method,
                "path": norm_path,
                "parameters": [],
                "content_types": [],
                "discovery_sources": [],
                "resources": [],
                "observations": [],
                "ownership_hints": [],
                "test_status": {},
                "first_discovered_at": now,
                "last_observed_at": now,
            }
            _store[endpoint_id] = entry

        entry["last_observed_at"] = now
        resolved_resource = _resolve_resource(entry, resource)
        _merge_parameters(entry, params)

        normalized_ct = (content_type or "").strip().lower() or None
        if normalized_ct and normalized_ct not in entry["content_types"]:
            entry["content_types"].append(normalized_ct)
        if src and src not in entry["discovery_sources"]:
            entry["discovery_sources"].append(src)

        _merge_observation(
            entry,
            resource=resolved_resource,
            actor_ref=actor,
            auth_state=state,
            status_code=status_code,
            content_type=normalized_ct,
            discovery_source=src,
            request_ref=ref or None,
            replay_verified=bool(replay_verified),
            now=now,
        )
        _merge_ownership_hint(entry, resolved_resource, ownership_hint, ownership_hint_kind)
        _persist_locked()

    record_activity_tick(agent_id)
    logger.info(
        "attack-surface %s: %s %s%s (resource=%s actor=%s source=%s)",
        "recorded" if created else "merged",
        norm_method,
        origin,
        norm_path,
        resolved_resource,
        actor,
        src,
    )
    result: dict[str, Any] = {
        "success": True,
        "endpoint_id": endpoint_id,
        "created": created,
        "origin": origin,
        "method": norm_method,
        "path": norm_path,
        "resource": resolved_resource,
        # A reference being on file is NOT a replay guarantee — these are
        # separate so a downstream agent never mistakes one for the other.
        "request_ref_recorded": bool(ref),
        "replay_verified": bool(ref) and bool(replay_verified),
    }
    if diagnostics:
        result["diagnostics"] = diagnostics
    return result


def _projected_observation(observation: dict[str, Any]) -> dict[str, Any]:
    """Provenance-preserving projection of one observation. Separates
    reference-recorded from replay-verified, and flags whether it still needs
    validation (anything with a reference that is not currently ``verified``)."""
    view = dict(observation)
    has_ref = bool(observation.get("request_ref"))
    replay_state = observation.get("replay_state") if has_ref else None
    view["replay_state"] = replay_state
    view["requires_validation"] = has_ref and replay_state != REPLAY_VERIFIED
    return view


def _public_entry(entry: dict[str, Any], *, include_observations: bool = True) -> dict[str, Any]:
    """Provenance-preserving projection. Never emits any stored value (there are
    none) — only names, locations, methods, statuses, timestamps, sources, and
    concrete resource paths. Observation/resource lists are bounded."""
    observations = entry.get("observations", [])
    resources = list(entry.get("resources", []))
    view: dict[str, Any] = {
        "endpoint_id": entry.get("endpoint_id"),
        "origin": entry.get("origin"),
        "method": entry.get("method"),
        "path": entry.get("path"),
        "parameters": list(entry.get("parameters", [])),
        "content_types": list(entry.get("content_types", [])),
        "discovery_sources": list(entry.get("discovery_sources", [])),
        "ownership_hints": list(entry.get("ownership_hints", [])),
        "resources_observed": resources[:_MAX_RESOURCES_RETURNED],
        "resource_count": len(resources),
        "resource_overflow": bool(entry.get("resource_overflow")),
        "first_discovered_at": entry.get("first_discovered_at", ""),
        "last_observed_at": entry.get("last_observed_at", ""),
    }
    view["actors_observed"] = sorted(
        {str(o.get("actor_ref")) for o in observations if o.get("actor_ref")}
    )
    view["replay_verified"] = any(
        o.get("request_ref") and o.get("replay_state") == REPLAY_VERIFIED for o in observations
    )
    view["has_request_ref"] = any(o.get("request_ref") for o in observations)
    view["references_requiring_validation"] = sum(
        1
        for o in observations
        if o.get("request_ref") and o.get("replay_state") != REPLAY_VERIFIED
    )
    if include_observations:
        shown = observations[:_MAX_OBSERVATIONS_RETURNED]
        view["observations"] = [_projected_observation(o) for o in shown]
        view["observations_truncated"] = len(observations) > _MAX_OBSERVATIONS_RETURNED
    test_status = entry.get("test_status", {})
    if test_status:
        view["test_status"] = dict(test_status)
    return view


def _query_impl(
    *,
    origin: str | None,
    actor_ref: str | None,
    method: str | None,
    param_location: str | None,
    test_status: str | None,
    test_category: str | None,
    limit: int,
) -> dict[str, Any]:
    bounded_limit = max(1, min(limit or _QUERY_LIMIT_DEFAULT, _QUERY_LIMIT_MAX))
    want_origin = _clean(origin, lower=True)
    want_actor = _clean(actor_ref)
    want_method_clean = _clean(method)
    want_method = want_method_clean.upper() if want_method_clean else None
    want_location = _clean(param_location, lower=True)
    want_status = _clean(test_status, lower=True)
    want_category = _clean(test_category, lower=True)

    with _lock:
        entries = [dict(entry) for entry in _store.values()]

    matched: list[dict[str, Any]] = []
    for entry in entries:
        if want_origin and want_origin not in str(entry.get("origin", "")).lower():
            continue
        if want_method and str(entry.get("method", "")).upper() != want_method:
            continue
        if want_actor:
            actors = {str(o.get("actor_ref")) for o in entry.get("observations", [])}
            if want_actor not in actors:
                continue
        if want_location:
            locations = {str(p.get("location")) for p in entry.get("parameters", [])}
            if want_location not in locations:
                continue
        if (want_status or want_category) and not _test_status_matches(
            entry.get("test_status", {}), want_status, want_category, want_actor
        ):
            continue
        matched.append(entry)

    matched.sort(key=lambda e: str(e.get("first_discovered_at", "")))
    truncated = len(matched) > bounded_limit
    page = matched[:bounded_limit]
    return {
        "success": True,
        "endpoints": [_public_entry(e) for e in page],
        "returned": len(page),
        "total_matched": len(matched),
        "total_endpoints": len(entries),
        "truncated": truncated,
    }


def _test_status_matches(
    test_rows: dict[str, Any],
    want_status: str | None,
    want_category: str | None,
    want_actor: str | None,
) -> bool:
    for key, row in test_rows.items():
        actor, _, rest = str(key).partition("|")
        category, _, _resource = rest.partition("|")
        if want_actor and actor != want_actor:
            continue
        if want_category and category != want_category:
            continue
        if want_status and str(row.get("status", "")).lower() != want_status:
            continue
        return True
    return False


def _record_test_impl(
    *,
    endpoint_id: str,
    actor_ref: str,
    category: str,
    status: str,
    resource_id: str,
    note: str,
    agent_id: str | None,
    agent_name: str | None,
) -> dict[str, Any]:
    key_id = (endpoint_id or "").strip()
    normalized_status = status.strip().lower()
    if normalized_status not in VALID_TEST_STATUSES:
        return {
            "success": False,
            "error": f"Invalid status: {status!r}. Must be one of {list(VALID_TEST_STATUSES)}",
        }
    category_norm = (category or "").strip().lower()
    if not category_norm:
        return {"success": False, "error": "category cannot be empty (e.g. 'idor', 'bfla')"}
    actor = (actor_ref or "anonymous").strip() or "anonymous"
    # A test is scoped to a concrete object so completing one never closes its
    # siblings. An empty resource_id is an explicit template-wide ('*') scope.
    resource_token = _resource_scope(resource_id)

    with _lock:
        entry = _store.get(key_id)
        if entry is None:
            return {
                "success": False,
                "error": f"No endpoint {endpoint_id!r}. Use query_attack_surface to find it.",
            }
        test_rows = entry.setdefault("test_status", {})
        row_key = f"{actor}|{category_norm}|{resource_token}"
        row = test_rows.get(row_key, {})
        row.update(
            {
                "status": normalized_status,
                "actor_ref": actor,
                "category": category_norm,
                "resource": resource_token,
                "updated_at": _now(),
            }
        )
        if note.strip():
            row["note"] = _redact_secrets(note.strip())[:_NOTE_MAX]
        if agent_name:
            row["agent_name"] = agent_name
        test_rows[row_key] = row
        _persist_locked()

    record_activity_tick(agent_id)
    return {
        "success": True,
        "endpoint_id": key_id,
        "actor_ref": actor,
        "category": category_norm,
        "resource": resource_token,
        "status": normalized_status,
    }


def _resource_scope(resource_id: str) -> str:
    """Resolve a caller's ``resource_id`` to a test-row scope token. A path/URL is
    normalized the same way observations are; a bare id is kept as given; empty
    is the explicit template-wide ``*`` scope."""
    value = (resource_id or "").strip()
    if not value:
        return "*"
    if "/" in value:
        return _resource_path(_path_of(value))
    return _redact_secrets(value)[:64]


# --------------------------------------------------------------------------- #
# Crawl / request ingestion adapters (deterministic, unit-tested on fixtures)
# --------------------------------------------------------------------------- #


def _scrub_secret_values(record: dict[str, Any]) -> None:
    """Strip any value under a secret-bearing key from a raw manual/proxy record,
    in place, before the record is turned into parameter names only."""
    headers = record.get("headers")
    if isinstance(headers, dict):
        for key in list(headers.keys()):
            if str(key).strip().lower() in _SECRET_VALUE_KEYS:
                headers[key] = None


def _records_from_text(records: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Parse JSONL (one object per line) or a single JSON array into a list of
    dict records, with a diagnostic for every line/item that is not an object."""
    diagnostics: list[str] = []
    text = records.strip()
    if not text:
        return [], ["no records provided"]
    parsed: list[Any]
    try:
        value = json.loads(text)
        parsed = value if isinstance(value, list) else [value]
    except json.JSONDecodeError:
        parsed = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                parsed.append(json.loads(stripped))
            except json.JSONDecodeError as exc:
                diagnostics.append(f"line {lineno}: not valid JSON ({exc.msg})")
    records_out: list[dict[str, Any]] = []
    for index, item in enumerate(parsed):
        if isinstance(item, dict):
            records_out.append(item)
        else:
            diagnostics.append(f"record #{index} is not a JSON object")
    return records_out, diagnostics


def _ingest_katana(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    """Katana ``-jsonl`` records.

    Verified against the schema the pinned sandbox katana actually emits (via a
    loopback crawl): each crawled request is its own flat top-level record
    ``{"request":{"method","endpoint",...},"response":{"status_code","headers",...}}``,
    and in headless ``-xhr`` mode every XHR/fetch the page fires is emitted as
    its *own* such record (a ``POST`` to the fetched URL), not nested anywhere.
    So the primary path simply reads one endpoint per record.

    ``response.xhr_requests[]`` is NOT present in that version; it is parsed only
    as a tolerant fallback for other katana builds that may nest XHRs that way.
    """
    out: list[dict[str, Any]] = []
    diagnostics: list[str] = []
    for index, record in enumerate(records):
        request = record.get("request")
        if not isinstance(request, dict):
            diagnostics.append(f"katana record #{index} has no 'request' object")
            continue
        endpoint = request.get("endpoint")
        if not isinstance(endpoint, str) or not endpoint:
            diagnostics.append(f"katana record #{index} has no request.endpoint URL")
            continue
        response = record.get("response") if isinstance(record.get("response"), dict) else {}
        out.append(
            {
                "url": endpoint,
                "method": str(request.get("method", "GET")),
                "status_code": _as_status(response.get("status_code")),
                "content_type": _header_value(response.get("headers"), "content-type"),
            }
        )
        # Tolerant fallback only — absent in the pinned katana (each XHR is its
        # own record above). Handle it for other builds without double-counting.
        for xhr_index, xhr in enumerate(response.get("xhr_requests") or []):
            if not isinstance(xhr, dict) or not isinstance(xhr.get("endpoint"), str):
                diagnostics.append(
                    f"katana record #{index} xhr #{xhr_index} has no endpoint; skipped"
                )
                continue
            out.append({"url": xhr["endpoint"], "method": str(xhr.get("method", "GET"))})
    return out, diagnostics


def _ingest_assets(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    """``assets.jsonl`` origin records → one root-path endpoint per origin,
    carrying status and the ``class`` as an inferred ownership/role hint."""
    out: list[dict[str, Any]] = []
    diagnostics: list[str] = []
    for index, record in enumerate(records):
        url = record.get("url") or record.get("origin")
        if not isinstance(url, str) or not url:
            diagnostics.append(f"assets record #{index} has no url/origin")
            continue
        item: dict[str, Any] = {"url": url, "method": "GET"}
        status = _as_status(record.get("status_code"))
        if status is not None:
            item["status_code"] = status
        cls = record.get("class")
        if isinstance(cls, str) and cls.strip():
            item["ownership_hint"] = f"origin class={cls.strip()}"
            item["ownership_hint_kind"] = "inferred"
        out.append(item)
    return out, diagnostics


def _ingest_requests(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    """Manually observed browser/proxy requests:
    ``{url, method, parameters, content_type, status_code, request_ref,
    replay_verified, headers}``. Secret-bearing header values are scrubbed before
    anything is kept."""
    out: list[dict[str, Any]] = []
    diagnostics: list[str] = []
    for index, record in enumerate(records):
        url = record.get("url")
        if not isinstance(url, str) or not url:
            diagnostics.append(f"request record #{index} has no url")
            continue
        _scrub_secret_values(record)
        parameters = record.get("parameters")
        headers = record.get("headers")
        if isinstance(headers, dict):
            header_names = [{"name": str(name), "location": "header"} for name in headers]
            parameters = [*parameters, *header_names] if isinstance(parameters, list) \
                else header_names
        item: dict[str, Any] = {
            "url": url,
            "method": str(record.get("method", "GET")),
            "parameters": parameters,
        }
        status = _as_status(record.get("status_code"))
        if status is not None:
            item["status_code"] = status
        if isinstance(record.get("content_type"), str):
            item["content_type"] = record["content_type"]
        if isinstance(record.get("request_ref"), str):
            item["request_ref"] = record["request_ref"]
        # Ingestion records a reference; it never attests a verified replay.
        item["replay_verified"] = False
        out.append(item)
    return out, diagnostics


_INGEST_ADAPTERS = {
    "katana": _ingest_katana,
    "assets": _ingest_assets,
    "requests": _ingest_requests,
    "proxy": _ingest_requests,
    "manual": _ingest_requests,
}


def _as_status(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _header_value(headers: Any, name: str) -> str | None:
    if not isinstance(headers, dict):
        return None
    for key, value in headers.items():
        if str(key).strip().lower() == name and isinstance(value, str):
            return value.split(";")[0].strip().lower() or None
    return None


def _ingest_impl(
    *,
    records: str,
    source_format: str,
    discovery_source: str | None,
    actor_ref: str | None,
    auth_state: str | None,
    agent_id: str | None,
    agent_name: str | None,
) -> dict[str, Any]:
    fmt = (source_format or "").strip().lower()
    adapter = _INGEST_ADAPTERS.get(fmt)
    if adapter is None:
        return {
            "success": False,
            "error": f"Unknown format {source_format!r}. Must be one of {sorted(_INGEST_ADAPTERS)}",
        }
    raw_records, parse_diags = _records_from_text(records)
    items, adapter_diags = adapter(raw_records)
    diagnostics = [*parse_diags, *adapter_diags]
    source = (discovery_source or fmt).strip().lower() or fmt

    created = 0
    merged = 0
    skipped = 0
    for index, item in enumerate(items):
        result = _record_impl(
            url=item["url"],
            method=item.get("method", "GET"),
            parameters=item.get("parameters"),
            content_type=item.get("content_type"),
            discovery_source=source,
            actor_ref=actor_ref,
            auth_state=auth_state,
            status_code=item.get("status_code"),
            request_ref=item.get("request_ref"),
            replay_verified=bool(item.get("replay_verified", False)),
            ownership_hint=item.get("ownership_hint"),
            ownership_hint_kind=item.get("ownership_hint_kind", "inferred"),
            agent_id=agent_id,
            agent_name=agent_name,
        )
        if not result.get("success"):
            skipped += 1
            diagnostics.append(f"item #{index}: {result.get('error')}")
            continue
        if result.get("created"):
            created += 1
        else:
            merged += 1
        if result.get("diagnostics"):
            diagnostics.extend(f"item #{index}: {d}" for d in result["diagnostics"])

    return {
        "success": True,
        "format": fmt,
        "records_parsed": len(raw_records),
        "endpoints_created": created,
        "endpoints_merged": merged,
        "skipped": skipped,
        "diagnostics": diagnostics,
    }


# --------------------------------------------------------------------------- #
# Agent tools
# --------------------------------------------------------------------------- #


def _caller_identity(ctx: RunContextWrapper) -> tuple[str | None, str | None]:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    raw_agent_id = inner.get("agent_id")
    agent_id = raw_agent_id if isinstance(raw_agent_id, str) else None
    agent_name: str | None = None
    coordinator = inner.get("coordinator")
    if agent_id is not None and coordinator is not None:
        names = getattr(coordinator, "names", {})
        if isinstance(names, dict):
            raw_name = names.get(agent_id)
            agent_name = raw_name if isinstance(raw_name, str) else None
    return agent_id, agent_name


@function_tool(timeout=30)
async def record_endpoint(
    ctx: RunContextWrapper,
    url: str,
    method: str = "GET",
    discovery_source: str = "manual",
    parameters: str = "",
    content_type: str = "",
    actor_ref: str = "",
    auth_state: str = "",
    status_code: int | None = None,
    request_ref: str = "",
    replay_verified: bool = False,
    ownership_hint: str = "",
    ownership_hint_kind: str = "inferred",
) -> str:
    """Record one black-box endpoint observation into the shared attack-surface inventory.

    This is the structured home for what recon discovers — endpoints, their
    methods, their parameters, and what each *actor* saw — so the authorization
    and parameter-mutation workflows can query it instead of re-reading free-text
    `/workspace/recon/*` files. Record as you discover, not in a batch.

    Identity is `(origin, method, template_path)`: the same origin on a different
    scheme/port is a different endpoint, `GET` and `POST` on one path are
    different endpoints, and numeric/UUID id segments collapse in the *template*
    (`/orders/1` and `/orders/2` share one endpoint). But each observation,
    reference, ownership hint, and test outcome is still kept against the
    *concrete* object (`/orders/1` vs `/orders/2`), so object-specific evidence
    is never flattened. Calling this again **merges** rather than duplicating.

    Never pass secrets. The inventory stores only names, locations, methods,
    statuses, content types, timestamps, sources, concrete resource paths, and an
    opaque `request_ref` — never a value, and never the raw URL (its query values
    and any userinfo are dropped).

    Reference vs. verified replay: `request_ref` is a *pointer* into existing
    request storage (e.g. a Caido request id). Passing one does NOT mean the
    request is replayable — it is recorded as `requires_validation` until you
    actually replay it and call again with `replay_verified=True`. A reference
    recorded in an earlier run is treated as stale (needs re-validation) after a
    resume.

    Args:
        url: The endpoint URL (query-string parameter *names* are extracted; the
            values are discarded).
        method: HTTP method (default `GET`).
        discovery_source: Where this came from — `katana`, `httpx`, `arjun`,
            `js-analysis`, `proxy`, `manual`, ...
        parameters: JSON array of `{"name","location"}` objects (or bare name
            strings, defaulting to the query location). Location is one of
            query/body/path/header/cookie. Values are never stored.
        content_type: Observed response content type, if any.
        actor_ref: Which actor observed this — `anonymous`, `actor-a`,
            `actor-b`, ... (a label from account provisioning, never a token).
        auth_state: `anonymous`, `authenticated`, or `unknown` for this
            observation.
        status_code: Observed HTTP status for this actor, if any.
        request_ref: An id into existing request storage. A reference, never raw
            request content; a secret-shaped value is rejected.
        replay_verified: Set True ONLY when you actually replayed `request_ref`
            and confirmed it works this run. Default False (reference recorded
            but unverified).
        ownership_hint: An optional hint about who owns the resource this
            endpoint touches. A hint, never proof.
        ownership_hint_kind: `inferred` (from a URL/keyword pattern) or
            `observed` (from an actual cross-actor response). Defaults to
            `inferred`.
    """
    agent_id, agent_name = _caller_identity(ctx)
    parsed_params: Any = None
    if parameters.strip():
        try:
            parsed_params = json.loads(parameters)
        except json.JSONDecodeError:
            parsed_params = [parameters.strip()]
    result = await asyncio.to_thread(
        _record_impl,
        url=url,
        method=method,
        parameters=parsed_params,
        content_type=content_type or None,
        discovery_source=discovery_source,
        actor_ref=actor_ref or None,
        auth_state=auth_state or None,
        status_code=status_code,
        request_ref=request_ref or None,
        replay_verified=replay_verified,
        ownership_hint=ownership_hint or None,
        ownership_hint_kind=ownership_hint_kind,
        agent_id=agent_id,
        agent_name=agent_name,
    )
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=60)
async def ingest_recon_endpoints(
    ctx: RunContextWrapper,
    records: str,
    source_format: str,
    discovery_source: str = "",
    actor_ref: str = "",
    auth_state: str = "",
) -> str:
    """Bulk-ingest crawler / proxy output into the attack-surface inventory.

    Host-side tools cannot read sandbox `/workspace/*` files, so read the
    artifact in the sandbox yourself (`cat crawl/host.jsonl`) and pass its text
    here. Parsing is deterministic and every malformed record produces an
    explicit diagnostic rather than being silently dropped.

    Formats:
    - `katana` — katana `-jsonl` output. Each record is one request
      (`request.endpoint`/`method` + `response.status_code`/`headers`); in
      headless `-xhr` mode each XHR/fetch is its own such record. (Verified
      against the pinned sandbox katana; a nested `response.xhr_requests[]` is
      tolerated as a fallback for other builds but is not emitted by this one.)
    - `assets` — `assets.jsonl` origin records (one root-path endpoint per
      origin; the `class` becomes an inferred role hint).
    - `requests` / `proxy` / `manual` — a JSON array of
      `{url, method, parameters, content_type, status_code, request_ref,
      headers}` objects you observed manually or pulled from the proxy. Secret
      header values (Authorization, Cookie, X-Api-Key, ...) are scrubbed before
      anything is stored; only header *names* survive. A `request_ref` here is
      recorded as unverified — replay must be confirmed separately.

    Separate anonymous and authenticated passes by calling once per actor with
    the matching `actor_ref`/`auth_state` — the inventory keeps each actor's
    observations distinct. This tool ingests already-captured output; it is not
    an authenticated crawler and does not fetch anything itself.

    Args:
        records: The artifact text — JSONL (one object per line) or a JSON
            array.
        source_format: `katana`, `assets`, `requests`, `proxy`, or `manual`.
        discovery_source: Overrides the recorded source label (defaults to the
            format name).
        actor_ref: Actor label these observations belong to (`anonymous`,
            `actor-a`, ...).
        auth_state: `anonymous`, `authenticated`, or `unknown` for this batch.
    """
    agent_id, agent_name = _caller_identity(ctx)
    result = await asyncio.to_thread(
        _ingest_impl,
        records=records,
        source_format=source_format,
        discovery_source=discovery_source or None,
        actor_ref=actor_ref or None,
        auth_state=auth_state or None,
        agent_id=agent_id,
        agent_name=agent_name,
    )
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def query_attack_surface(
    ctx: RunContextWrapper,
    origin: str | None = None,
    actor_ref: str | None = None,
    method: str | None = None,
    param_location: str | None = None,
    test_status: str | None = None,
    test_category: str | None = None,
    limit: int = _QUERY_LIMIT_DEFAULT,
) -> str:
    """Query the black-box attack-surface inventory for endpoints to work on.

    The authorization (`idor` / `broken_function_level_authorization`) and
    parameter-mutation (`analysis/parameter_mutation_testing`) workflows use this
    to pull a structured worklist instead of re-deriving endpoints from free text.
    Output is bounded and preserves each endpoint's provenance (discovery
    sources, per-actor observations with their concrete resource, per-object test
    status, timestamps). It never returns a stored value because none are kept.

    Each observation carries `replay_state`/`requires_validation`: a `request_ref`
    that has not been replay-verified (or that was verified in a prior run and is
    now stale) is flagged as requiring validation — do not treat it as a known-
    good replayable request.

    Filter combinations are ANDed. Use `test_status='pending'` (optionally with
    `test_category` and `actor_ref`) to find endpoints that still need a given
    test. Test rows are per concrete object, so a completed row for one object
    does not mark its siblings complete.

    Args:
        origin: Case-insensitive substring of `scheme://host:port`.
        actor_ref: Only endpoints observed by this actor.
        method: Exact HTTP method.
        param_location: Only endpoints with a parameter in this location
            (query/body/path/header/cookie).
        test_status: Only endpoints with a test row in this state
            (pending/completed/blocked).
        test_category: Only endpoints with a test row for this category
            (e.g. `idor`), combinable with `test_status`/`actor_ref`.
        limit: Max endpoints to return (capped at 500).
    """
    result = await asyncio.to_thread(
        _query_impl,
        origin=origin,
        actor_ref=actor_ref,
        method=method,
        param_location=param_location,
        test_status=test_status,
        test_category=test_category,
        limit=limit,
    )
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def record_endpoint_test(
    ctx: RunContextWrapper,
    endpoint_id: str,
    category: str,
    status: str,
    actor_ref: str = "anonymous",
    resource_id: str = "",
    note: str = "",
) -> str:
    """Track test progress on an endpoint, keyed to endpoint + actor + category + object.

    This is the attack-surface analogue of the coverage ledger's open/closed
    bookkeeping, at per-object granularity: it lets the inventory say *which
    concrete object still needs which test for which actor*, which is exactly the
    worklist `query_attack_surface(test_status='pending', ...)` returns. It does
    not replace `record_coverage` — file the actual security conclusion there;
    this only tracks the worklist state. Inventory completeness and scan
    lifecycle completion stay separate.

    Pass `resource_id` for the specific object you tested (`/orders/1`, or a bare
    id like `1`). Completing a test on one object never marks its siblings
    complete. Omit `resource_id` only for a genuinely object-independent
    conclusion about the route handler itself (recorded as a template-wide `*`
    scope).

    Args:
        endpoint_id: The id from `query_attack_surface`/`record_endpoint`.
        category: Test category, e.g. `idor`, `bfla`, `mass_assignment`,
            `sql_injection`.
        status: `pending`, `completed`, or `blocked`.
        actor_ref: Actor context for this test (`anonymous`, `actor-a`, ...).
        resource_id: The concrete object tested (a path, URL, or bare id). Empty
            means a template-wide conclusion.
        note: Optional short note (e.g. why it is blocked).
    """
    agent_id, agent_name = _caller_identity(ctx)
    result = await asyncio.to_thread(
        _record_test_impl,
        endpoint_id=endpoint_id,
        actor_ref=actor_ref,
        category=category,
        status=status,
        resource_id=resource_id,
        note=note,
        agent_id=agent_id,
        agent_name=agent_name,
    )
    return json.dumps(result, ensure_ascii=False, default=str)
