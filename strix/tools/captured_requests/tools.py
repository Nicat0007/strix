"""Durable captured-request import — a Strix-owned opaque reference layer over a
proxy's captured traffic (BLACKBOX #5, Burp-integration continuation).

Why this exists (established empirically against Burp Suite's MCP server, v1.1.2):

- Burp's ``get_proxy_http_history`` / ``_regex`` return each item as
  ``{request, response, notes}`` — the raw request has FULL header fidelity and
  the destination host/port are recoverable from its ``Host`` header, but there
  is **no per-item stable id** (selection is by ``count``/``offset``/``regex``,
  which are positional and shift as new traffic arrives) and **no TLS/scheme
  field** (a history item cannot tell you ``usesHttps``).

So an offset/regex is NOT a durable identity. This module snapshots a selected
request LOCALLY and hands back a Strix-owned opaque reference, namespaced by
provider + run + project, that a replay adapter can resolve later and that
survives ``--resume`` with explicit staleness. It is provider-agnostic (Burp,
Caido, or an operator-supplied capture) and does not itself talk to any proxy.

Discipline:

- Raw requests and credentials live ONLY in the run-private, 0600 snapshot store.
  The agent-facing return and every query carry sanitized metadata only
  (method/host/port/tls/path and header NAMES) — never header values, cookies,
  tokens or bodies, and the raw is never logged.
- Fidelity + destination must be established or the import is REJECTED: an
  unparseable request, an underivable destination host, or an unspecified TLS
  disposition (``uses_tls is None``) are refused rather than guessed — because a
  Burp history item does not carry the scheme, the caller must assert it.
- Lifecycle: ``recorded`` -> (replay-adapter) ``verified``; on ``--resume`` any
  non-stale entry is downgraded to ``stale_after_resume`` and must be
  revalidated before reuse (a prior process's capture cannot be trusted).
"""

from __future__ import annotations

import hashlib
import json
import logging
import tempfile
import threading
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.agent_metrics.tools import record_activity_tick
from strix.tools.attack_surface.tools import _redact_secrets


logger = logging.getLogger(__name__)

_SCHEMA_VERSION = 1
_PROVIDERS = ("burp", "caido", "manual")
_FRESH_RECORDED = "recorded"
_FRESH_VERIFIED = "verified"
_FRESH_STALE = "stale_after_resume"
_AUTH_HEADER_NAMES = frozenset({
    "cookie", "authorization", "x-api-key", "api-key", "apikey", "x-auth-token",
    "x-access-token", "x-session-token", "proxy-authorization", "set-cookie",
})

_store: dict[str, dict[str, Any]] = {}
_lock = threading.RLock()
_path: Path | None = None


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


# --------------------------------------------------------------------------- #
# Persistence (run-scoped, restricted 0600 — raw requests live here only)
# --------------------------------------------------------------------------- #


def hydrate_captured_requests_from_disk(state_dir: Path) -> None:
    """Load this run's snapshots from ``{state_dir}/captured_requests.json``.

    On resume, every entry that was ``recorded``/``verified`` in a prior process
    is downgraded to ``stale_after_resume`` — a capture confirmed before a resume
    cannot be trusted afterwards (mirrors the hypotheses/attack-surface resume
    discipline)."""
    global _path  # noqa: PLW0603
    _path = state_dir / "captured_requests.json"
    with _lock:
        _store.clear()
        if not _path.exists():
            return
        try:
            data = json.loads(_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception("captured_requests.json at %s is unreadable; starting empty", _path)
            return
        entries = data.get("entries") if isinstance(data, dict) else None
        if isinstance(entries, dict):
            for key, entry in entries.items():
                if not isinstance(entry, dict):
                    continue
                if entry.get("freshness") in (_FRESH_RECORDED, _FRESH_VERIFIED):
                    entry["freshness"] = _FRESH_STALE
                _store[key] = entry
        logger.info("captured requests hydrated from %s (%d)", _path, len(_store))


def _persist_locked() -> None:
    path = _path
    if path is None:
        return
    try:
        payload = json.dumps(
            {"schema_version": _SCHEMA_VERSION, "entries": _store},
            ensure_ascii=False, indent=2, default=str,
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=str(path.parent),
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as tmp:
            tmp.write(payload)
            tmp_path = Path(tmp.name)
        with suppress(OSError):  # restrict BEFORE publishing (raw requests inside)
            tmp_path.chmod(0o600)
        tmp_path.replace(path)
        with suppress(OSError):
            path.chmod(0o600)
    except Exception:
        logger.exception("captured requests persist to %s failed", path)


# --------------------------------------------------------------------------- #
# Raw-request parsing / fidelity + destination establishment
# --------------------------------------------------------------------------- #


def _parse_raw(raw: str) -> dict[str, Any] | None:
    """Parse a raw HTTP/1.x request into method/path/header-names/Host. Returns
    None if it is not a well-formed request (no request line / no method+target)."""
    text = raw.replace("\r\n", "\n")
    lines = text.split("\n")
    if not lines or not lines[0].strip():
        return None
    parts = lines[0].split(" ")
    # A well-formed request line is "METHOD TARGET HTTP/x.y" — require the version
    # token so arbitrary text is not mistaken for a request.
    if len(parts) < 3 or not parts[0].isalpha() or not parts[-1].upper().startswith("HTTP/"):
        return None
    method, target = parts[0].upper(), parts[1]
    header_names: list[str] = []
    host_header = ""
    for line in lines[1:]:
        if line.strip() == "":
            break
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        header_names.append(name.strip())
        if name.strip().lower() == "host":
            host_header = value.strip()
    return {"method": method, "path": target.split("?", 1)[0] or "/",
            "header_names": header_names, "host_header": host_header}


def _establish_destination(
    parsed: dict[str, Any], dest_host: str, dest_port: int | None, uses_tls: bool,
) -> tuple[str, int] | None:
    """Resolve the destination host+port from the explicit args and the request's
    Host header, requiring consistency. Returns None if the host cannot be
    established (the import is then rejected)."""
    hh = parsed.get("host_header", "")
    hh_host, hh_port = hh, None
    if hh.startswith("[") and "]" in hh:  # IPv6 literal
        hh_host, _, rest = hh[1:].partition("]")
        if rest.startswith(":") and rest[1:].isdigit():
            hh_port = int(rest[1:])
    elif ":" in hh and hh.rsplit(":", 1)[1].isdigit():
        hh_host, hh_port = hh.rsplit(":", 1)[0], int(hh.rsplit(":", 1)[1])
    host = (dest_host or "").strip() or hh_host
    if not host:
        return None
    if dest_host and hh_host and dest_host.strip().lower() != hh_host.lower():
        return None  # explicit host contradicts the captured Host header
    port = dest_port or hh_port or (443 if uses_tls else 80)
    if not (1 <= port <= 65535):
        return None
    return host, port


def _reference(provider: str, run_id: str, project_id: str, digest: str) -> str:
    """A Strix-owned opaque reference, namespaced by provider + run + project.
    Deterministic in the snapshot content (so re-importing the same capture
    dedupes) and NOT a proxy offset/index."""
    return f"capreq::{provider}::{run_id or '-'}::{project_id or '-'}::{digest}"


def _public_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Agent-facing projection — sanitized metadata ONLY. Never the raw request,
    header values, cookies, tokens or body."""
    return {
        "ref": entry["ref"], "provider": entry["provider"], "method": entry["method"],
        "host": entry["host"], "port": entry["port"], "uses_tls": entry["uses_tls"],
        "path": entry["path"], "header_names": entry["header_names"],
        "has_auth_headers": entry["has_auth_headers"], "freshness": entry["freshness"],
        "recorded_at": entry["recorded_at"],
    }


# --------------------------------------------------------------------------- #
# Import / query / resolve / revalidate
# --------------------------------------------------------------------------- #


def import_captured_request_impl(
    *, provider: str, raw_request: str, uses_tls: bool | None,
    dest_host: str = "", dest_port: int | None = None,
    run_id: str = "", project_id: str = "", source_detail: str = "",
) -> dict[str, Any]:
    prov = (provider or "").strip().lower()
    if prov not in _PROVIDERS:
        return {"success": False, "error": f"provider must be one of {_PROVIDERS}"}
    if uses_tls is None:
        return {"success": False, "rejected": "tls_unestablished",
                "error": "uses_tls must be stated explicitly — a proxy history item does not "
                         "carry the scheme, so TLS cannot be inferred; supply True/False"}
    parsed = _parse_raw(raw_request or "")
    if parsed is None:
        return {"success": False, "rejected": "unparseable_request",
                "error": "raw_request is not a well-formed HTTP request (no method + target)"}
    dest = _establish_destination(parsed, dest_host, dest_port, bool(uses_tls))
    if dest is None:
        return {"success": False, "rejected": "destination_unestablished",
                "error": "could not establish a consistent destination host/port from the "
                         "request's Host header and the supplied dest_host/dest_port"}
    host, port = dest
    digest = hashlib.sha256(
        f"{raw_request}\x00{host}\x00{port}\x00{int(bool(uses_tls))}".encode()
    ).hexdigest()[:16]
    ref = _reference(prov, run_id.strip(), project_id.strip(), digest)
    header_names = parsed["header_names"]
    has_auth = any(n.lower() in _AUTH_HEADER_NAMES for n in header_names)
    with _lock:
        existing = _store.get(ref)
        entry = {
            "ref": ref, "provider": prov, "run_id": run_id.strip(),
            "project_id": project_id.strip(), "method": parsed["method"],
            "host": host, "port": port, "uses_tls": bool(uses_tls), "path": parsed["path"],
            "header_names": header_names, "has_auth_headers": has_auth,
            "raw_request": raw_request,  # restricted store ONLY; never returned/logged
            "source_detail": _redact_secrets((source_detail or "").strip())[:200],
            "freshness": _FRESH_RECORDED,
            "recorded_at": existing["recorded_at"] if existing else _now(),
            "reimported": bool(existing),
        }
        _store[ref] = entry
        _persist_locked()
        return {"success": True, "deduplicated": bool(existing), **_public_entry(entry)}


def query_captured_requests_impl(provider: str = "", run_id: str = "") -> dict[str, Any]:
    with _lock:
        items = [
            _public_entry(e) for e in _store.values()
            if (not provider or e["provider"] == provider.strip().lower())
            and (not run_id or e["run_id"] == run_id.strip())
        ]
    return {"success": True, "total": len(items), "captured_requests": items}


def resolve_captured_request(ref: str) -> dict[str, Any]:
    """HOST-SIDE resolver for a replay adapter. Returns the raw request + explicit
    destination for exactly one reference. A ``stale_after_resume`` entry is
    REFUSED until revalidated — a prior process's capture is not trusted."""
    with _lock:
        entry = _store.get((ref or "").strip())
        if entry is None:
            return {"success": False, "error": f"no captured request {ref!r}"}
        if entry["freshness"] == _FRESH_STALE:
            return {"success": False, "needs_revalidation": True,
                    "error": "capture is stale after resume — revalidate before replay"}
        return {"success": True, "ref": entry["ref"], "raw_request": entry["raw_request"],
                "host": entry["host"], "port": entry["port"], "uses_tls": entry["uses_tls"]}


def revalidate_captured_request(ref: str) -> dict[str, Any]:
    """Mark a stale capture as re-verified (the caller asserts it re-confirmed the
    capture is still valid against the live target/proxy after resume)."""
    with _lock:
        entry = _store.get((ref or "").strip())
        if entry is None:
            return {"success": False, "error": f"no captured request {ref!r}"}
        entry["freshness"] = _FRESH_VERIFIED
        entry["revalidated_at"] = _now()
        _persist_locked()
        return {"success": True, **_public_entry(entry)}


# --------------------------------------------------------------------------- #
# Agent tools
# --------------------------------------------------------------------------- #


def _caller(ctx: RunContextWrapper) -> str | None:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    aid = inner.get("agent_id")
    return aid if isinstance(aid, str) else None


@function_tool
async def import_captured_request(
    ctx: RunContextWrapper,
    provider: str,
    raw_request: str,
    uses_tls: bool,
    dest_host: str = "",
    dest_port: int = 0,
    run_id: str = "",
    project_id: str = "",
    source_detail: str = "",
) -> str:
    """Snapshot a proxy-captured request and return a durable Strix-owned opaque
    reference for later replay — NOT the proxy's own offset/index (which is
    positional and unstable).

    Give the full raw HTTP request (as the proxy returned it) and state the TLS
    disposition explicitly (`uses_tls`) — a proxy history item does not carry the
    scheme, so it cannot be inferred and the import is rejected if omitted. The
    destination host/port are taken from the request's Host header unless you
    override them (an inconsistent override is rejected). The raw request and its
    credentials are stored only in this run's private 0600 snapshot and are never
    returned or logged; the response is a sanitized reference + metadata (method/
    host/port/tls/path/header names).

    Args:
        provider: `burp`, `caido`, or `manual`.
        raw_request: the complete raw HTTP/1.x request.
        uses_tls: whether the original destination used HTTPS (required).
        dest_host / dest_port: optional explicit destination; defaults derive from
            the Host header. An override contradicting the Host header is rejected.
        run_id / project_id: identity to namespace the reference by.
        source_detail: a short free-text note on provenance (redacted).
    """
    result = import_captured_request_impl(
        provider=provider, raw_request=raw_request, uses_tls=uses_tls,
        dest_host=dest_host, dest_port=dest_port or None, run_id=run_id,
        project_id=project_id, source_detail=source_detail,
    )
    record_activity_tick(_caller(ctx))
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool
async def query_captured_requests(
    ctx: RunContextWrapper, provider: str = "", run_id: str = ""
) -> str:
    """List imported captured requests as sanitized metadata + their durable
    references (never raw requests or credentials). Optionally filter by provider
    or run_id."""
    return json.dumps(
        query_captured_requests_impl(provider=provider, run_id=run_id),
        ensure_ascii=False, default=str,
    )
