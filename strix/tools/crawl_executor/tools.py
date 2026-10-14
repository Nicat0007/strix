"""Actor-aware crawl execution and direct ingestion into the durable
attack-surface inventory.

Provides the executable path BLACKBOX improvement #1 lacked:

    crawl job (anonymous / actor-A / actor-B)
      -> session-reference-scoped crawler run INSIDE the sandbox
      -> bounded artifact streamed back over the existing sandbox transport
      -> deterministic ingestion (the attack_surface adapters)
      -> durable inventory + a durable job-outcome record
      -> downstream query_attack_surface.

What runs automatically vs. what needs an explicit call:

- Nothing here runs on its own. An agent calls ``run_crawl_job`` (registered as
  a base tool). The discovery / account-provisioning skills instruct when to
  call it (anonymous first, then once per provisioned actor).
- The crawler itself runs in the sandbox via ``session.exec`` with structured
  argv (no shell string), bounded depth/pages/duration, and a hard exec
  timeout. A timeout yields a *partial* job, not a lost one.
- Authenticated jobs depend on operator/agent-provisioned sessions recorded by
  ``reconnaissance/account_provisioning.md`` in ``auth_accounts.jsonl``. This
  module never logs in itself; ``-al`` auto-login is deliberately not used.

Honesty constraints carried from improvement #1 and this slice's limits:

- Credentials (cookie/token) are read from the provisioned session file, written
  to a sandbox-only headers file with tight perms, passed to the crawler by file
  (never on argv), and scrubbed afterwards. They never appear in tool output.
- Crawler output contains response bodies; this module ingests only names /
  methods / statuses / content-types and NEVER returns a body. The artifact is
  removed after ingestion.
- A supplied credential is not proof of authentication. An authenticated job
  runs an explicit application-specific check (a marker string that must be
  present / an "unauthenticated" marker that must be absent) BEFORE crawling.
  HTTP 200 alone is recorded as ``unknown``, never ``valid``. Observations are
  labelled ``authenticated`` only when the check passed; otherwise ``unknown``.
- Scope is enforced at executor level only (crawl-scope regex + a host-side
  in-scope filter that drops out-of-scope redirects/discoveries). This is NOT a
  container network firewall and adds no enforcement to other shell tools.
- Resource-cap overflow in the inventory is preserved, not hidden (improvement
  #1 flags ``resource_overflow``); job completion never implies coverage.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import logging
import re
import shlex
import tempfile
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from agents import RunContextWrapper, function_tool

from strix.tools.attack_surface.tools import (
    _ingest_katana,
    _record_impl,
    _records_from_text,
    origin_of,
)


logger = logging.getLogger(__name__)

_SCHEMA_VERSION = 1

_jobs: dict[str, dict[str, Any]] = {}
_jobs_lock = threading.RLock()
_jobs_path: Path | None = None

# Bounds — clamped, never trusted from the caller.
_DEFAULT_DEPTH = 2
_MAX_DEPTH = 5
_DEFAULT_PAGES = 100
_MAX_PAGES = 2000
_DEFAULT_DURATION = "2m"
_EXEC_TIMEOUT_MARGIN_S = 30.0
_MAX_EXEC_TIMEOUT_S = 1800.0
_DEFAULT_OUTPUT_CAP = 5_000_000
_MAX_OUTPUT_CAP = 50_000_000
_DEFAULT_RATE_LIMIT = 50
_DEFAULT_CONCURRENCY = 10
_DIAG_MAX = 50
_JOB_LIST_MAX = 100

_DEFAULT_ACCOUNTS_PATH = "/workspace/recon/auth_accounts.jsonl"
_WORK_DIR = "/workspace/.crawl"
_CHROME_PATH = "/usr/bin/chromium"

#: A redirect target hinting the session is NOT valid (bounced to a login page).
_LOGIN_HINT = re.compile(r"(?i)(login|signin|sign-in|auth|sso|account/login)")

AUTH_VALID = "valid"
AUTH_INVALID = "invalid"
AUTH_UNKNOWN = "unknown"

STATUS_COMPLETED = "completed"
STATUS_PARTIAL = "partial"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"

#: What scope the executor can actually *enforce at request level*, verified
#: empirically against the installed katana (two-counter loopback test):
#: - static crawl + ``-dr``: the executor issues no out-of-scope requests (the
#:   only leak, a redirect followed to another origin, is closed by -dr).
#: - headless: the browser fetches whatever the page triggers (XHR, subresources,
#:   redirects) to ANY origin; crawl-scope does NOT gate those requests, so the
#:   boundary is only crawl-follow + ingestion filtering, never request-level.
SCOPE_REQUEST_LEVEL = "request-level (static crawl, redirects disabled)"
SCOPE_CRAWL_FOLLOW = (
    "crawl-follow + ingestion filter only (headless browser may issue "
    "out-of-scope XHR/subresource/redirect requests that katana cannot prevent)"
)

#: The CAP script bounds the artifact INSIDE the sandbox before any bytes reach
#: the host: it copies at most ``$3`` bytes of ``$1`` into ``$2`` and prints the
#: original byte size, so the host read of ``$2`` can never exceed the cap even
#: though the transport's read() buffers the whole file it is given.
_CAP_SCRIPT = 'if [ -f "$1" ]; then head -c "$3" "$1" > "$2"; wc -c < "$1"; else echo MISSING; fi'


class CrawlTransport(Protocol):
    """The subset of the sandbox session this executor needs. The live
    ``bundle["session"]`` satisfies it; tests inject a host-side stand-in that
    honours the same contract (real subprocess + real files)."""

    async def exec(self, *command: str, timeout: float | None = ..., shell: bool = ...) -> Any: ...
    async def read(self, path: Path) -> io.IOBase: ...
    async def write(self, path: Path, data: io.IOBase) -> None: ...


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


# --------------------------------------------------------------------------- #
# Durable job store (same shape as coverage / attack_surface)
# --------------------------------------------------------------------------- #


def hydrate_crawl_jobs_from_disk(state_dir: Path) -> None:
    """Load this run's crawl-job history from ``{state_dir}/crawl_jobs.json``.

    Unconditional, alongside the other ``hydrate_*`` calls in ``core/runner``.
    On resume, any job whose crawl was authenticated (or whose auth check passed)
    is flagged ``requires_revalidation``: a prior process's session validity and
    the ephemeral request references it recorded cannot be trusted after a
    resume (mirrors the attack-surface inventory downgrading verified refs to
    stale).
    """
    global _jobs_path  # noqa: PLW0603
    _jobs_path = state_dir / "crawl_jobs.json"
    with _jobs_lock:
        _jobs.clear()
        if not _jobs_path.exists():
            return
        try:
            data = json.loads(_jobs_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception("crawl_jobs.json at %s is unreadable; starting empty", _jobs_path)
            return
        jobs = data.get("jobs") if isinstance(data, dict) else None
        if isinstance(jobs, dict):
            for key, job in jobs.items():
                if not isinstance(job, dict):
                    continue
                if job.get("auth_state") == "authenticated" or job.get("auth", {}).get(
                    "outcome"
                ) == AUTH_VALID:
                    job["requires_revalidation"] = True
                _jobs[key] = job
        logger.info("crawl-job history hydrated from %s (%d job(s))", _jobs_path, len(_jobs))


def _persist_jobs_locked() -> None:
    path = _jobs_path
    if path is None:
        return
    try:
        payload = json.dumps(
            {"schema_version": _SCHEMA_VERSION, "jobs": _jobs},
            ensure_ascii=False,
            indent=2,
            default=str,
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=str(path.parent),
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as tmp:
            tmp.write(payload)
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
    except Exception:
        logger.exception("crawl-job history persist to %s failed", path)


def _store_job(record: dict[str, Any]) -> None:
    with _jobs_lock:
        _jobs[record["job_id"]] = record
        _persist_jobs_locked()


def _list_jobs_impl(*, actor_ref: str | None, limit: int) -> dict[str, Any]:
    bounded = max(1, min(limit or _JOB_LIST_MAX, _JOB_LIST_MAX))
    want_actor = (actor_ref or "").strip() or None
    with _jobs_lock:
        jobs = [dict(j) for j in _jobs.values()]
    if want_actor:
        jobs = [j for j in jobs if j.get("actor_ref") == want_actor]
    jobs.sort(key=lambda j: str(j.get("started_at", "")))
    page = jobs[-bounded:]
    return {
        "success": True,
        "jobs": [_public_job(j) for j in page],
        "returned": len(page),
        "total_jobs": len(jobs),
    }


def _public_job(record: dict[str, Any]) -> dict[str, Any]:
    """Bounded, credential-free projection of a job record."""
    view = {
        k: record.get(k)
        for k in (
            "job_id", "intended_actor", "actor_ref", "auth_state", "status", "origins",
            "path_scope", "scope_enforcement", "started_at", "ended_at", "records_parsed",
            "output_truncated", "remaining_work", "coverage_note", "requires_revalidation",
        )
    }
    view["counts"] = dict(record.get("counts", {}))
    view["auth"] = dict(record.get("auth", {}))
    diags = list(record.get("diagnostics", []))
    view["diagnostics"] = diags[:_DIAG_MAX]
    view["diagnostics_truncated"] = len(diags) > _DIAG_MAX
    return view


# --------------------------------------------------------------------------- #
# Pure helpers (no sandbox) — unit-tested directly
# --------------------------------------------------------------------------- #


def _parse_origins(raw: Any) -> tuple[list[str], list[str]]:
    """Normalize caller origins to canonical ``scheme://host:port`` via
    ``origin_of``; return (origins, diagnostics). Dedup, drop unparseable."""
    diagnostics: list[str] = []
    values: list[str]
    if isinstance(raw, str):
        text = raw.strip()
        if text.startswith("["):
            try:
                parsed = json.loads(text)
                values = [str(v) for v in parsed] if isinstance(parsed, list) else [text]
            except json.JSONDecodeError:
                values = re.split(r"[,\s]+", text)
        else:
            values = re.split(r"[,\s]+", text)
    elif isinstance(raw, list):
        values = [str(v) for v in raw]
    else:
        return [], ["origins must be a URL, comma/space list, or JSON array"]
    origins: list[str] = []
    for value in values:
        candidate = value.strip()
        if not candidate:
            continue
        origin = origin_of(candidate)
        if origin is None:
            diagnostics.append(f"origin {candidate!r} has no resolvable host; dropped")
            continue
        if origin not in origins:
            origins.append(origin)
    return origins, diagnostics


def _normalize_path_scope(raw: Any) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, str):
        parts = re.split(r"[,\s]+", raw.strip())
    elif isinstance(raw, list):
        parts = [str(v) for v in raw]
    else:
        return []
    out: list[str] = []
    for part in parts:
        p = part.strip()
        if not p:
            continue
        if not p.startswith("/"):
            p = "/" + p
        if p not in out:
            out.append(p)
    return out


def _scope_regex(origins: list[str], path_scope: list[str] | None = None) -> str:
    """A katana ``-cs`` regex: an in-scope URL must begin with one authorized
    origin, and — when path prefixes are given — one of those prefixes. This is
    what katana will *follow*; it does not by itself stop a followed redirect
    (``-dr`` does, in static mode)."""
    alts = "|".join(re.escape(o) for o in origins)
    if path_scope:
        prefs = "|".join(re.escape(p.rstrip("/")) for p in path_scope)
        return f"^({alts})({prefs})(/.*)?$"
    return f"^({alts})(/.*)?$"


def _crawl_seeds(origins: list[str], path_scope: list[str]) -> list[str]:
    """Where katana starts. With path scope, seed at each (origin, prefix) pair
    so the crawler never even requests the origin root outside the prefix."""
    if not path_scope:
        return list(origins)
    return [o + p.rstrip("/") for o in origins for p in path_scope]


def _in_scope(url: str, origins: list[str], path_scope: list[str]) -> bool:
    """Host-side scope enforcement: the URL's origin must be authorized and, if
    path prefixes were given, its path must start with one of them. Dropping
    rather than ingesting an out-of-scope URL is how a redirect to another host
    never silently expands authorization."""
    origin = origin_of(url)
    if origin is None or origin not in origins:
        return False
    if not path_scope:
        return True
    candidate = url if "://" in url else f"//{url}"
    path = urlsplit(candidate).path or "/"
    # A prefix matches the exact path or a path under it — never a sibling like
    # /apifoo for prefix /api.
    return any(path == pref.rstrip("/") or path.startswith(pref.rstrip("/") + "/")
               for pref in path_scope)


def _duration_seconds(text: str) -> float:
    """Parse a katana ``-ct`` duration (``90s``/``2m``/``1h``) to seconds."""
    t = (text or "").strip().lower() or _DEFAULT_DURATION
    match = re.fullmatch(r"(\d+)\s*([smhd]?)", t)
    if not match:
        return _duration_seconds(_DEFAULT_DURATION)
    value = int(match.group(1))
    unit = match.group(2) or "s"
    return value * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


def _clamp(value: int | None, default: int, cap: int) -> int:
    if not value or value <= 0:
        return default
    return min(value, cap)


def _build_katana_argv(
    *,
    out_path: str,
    origins: list[str],
    path_scope: list[str],
    headers_file: str | None,
    js_crawl: bool,
    depth: int,
    pages: int,
    duration: str,
    rate_limit: int,
    concurrency: int,
    chrome_data_dir: str | None = None,
) -> list[str]:
    """Structured katana argv (run with ``shell=False`` — no shell string).

    Scope, depth, per-domain page cap, crawl duration and rate limit are all
    pinned here; the caller cannot inject extra flags. ``-dr`` (disable-redirects)
    is set for static crawls so a redirect to an out-of-scope origin is NOT
    requested — the one leak the two-counter test found. It is deliberately NOT
    relied on for headless, where the browser issues requests katana can't gate.
    """
    seeds = _crawl_seeds(origins, path_scope)
    argv: list[str] = [
        "katana",
        "-u", ",".join(seeds),
        "-jsonl", "-silent",
        "-o", out_path,
        "-cs", _scope_regex(origins, path_scope),
        "-d", str(depth),
        "-ct", duration,
        "-mdp", str(pages),
        "-rl", str(rate_limit),
        "-c", str(concurrency),
    ]
    if headers_file:
        argv += ["-H", headers_file]
    if js_crawl:
        argv += ["-hl", "-scp", _CHROME_PATH, "-nos", "-xhr"]
        if chrome_data_dir:
            # Tag chrome's data dir with the job id so cancellation can pkill the
            # browser children by marker.
            argv += ["-cdd", chrome_data_dir]
    else:
        argv += ["-dr"]
    return argv


def _classify_auth(
    *,
    has_check: bool,
    status: int | None,
    marker_present: bool | None,
    absent_present: bool | None,
    redirect: str | None,
) -> tuple[str, dict[str, Any]]:
    """Map an application-specific check to valid / invalid / unknown.

    HTTP 200 alone is never ``valid`` — a marker (or absent-marker) must decide
    it. A login redirect or 401/403 is ``invalid``. No response body is recorded;
    only the status, the two boolean marker results, and a query-stripped
    redirect target."""
    evidence: dict[str, Any] = {
        "status": status,
        "marker_present": marker_present,
        "absent_marker_present": absent_present,
        "redirect": _strip_query(redirect) if redirect else None,
    }
    outcome, reason = _auth_decision(
        has_check=has_check, status=status, marker_present=marker_present,
        absent_present=absent_present, redirect=redirect,
    )
    evidence["reason"] = reason
    return outcome, evidence


def _auth_decision(
    *,
    has_check: bool,
    status: int | None,
    marker_present: bool | None,
    absent_present: bool | None,
    redirect: str | None,
) -> tuple[str, str]:
    is_login_redirect = (
        status is not None and 300 <= status < 400 and redirect and _LOGIN_HINT.search(redirect)
    )
    if not has_check:
        outcome, reason = AUTH_UNKNOWN, "no application-specific check supplied; 200 is not proof"
    elif status in (401, 403):
        outcome, reason = AUTH_INVALID, f"status {status}"
    elif is_login_redirect:
        outcome, reason = AUTH_INVALID, "redirected to a login/auth endpoint"
    elif absent_present:
        outcome, reason = AUTH_INVALID, "unauthenticated marker present"
    elif marker_present is False:
        outcome, reason = AUTH_INVALID, "required marker absent"
    elif marker_present or absent_present is False:
        outcome, reason = AUTH_VALID, "authenticated marker confirmed"
    else:
        outcome, reason = AUTH_UNKNOWN, "check inconclusive"
    return outcome, reason


def _strip_query(url: str) -> str:
    return url.split("?", 1)[0]


def _actor_headers(accounts_text: str, actor_ref: str) -> tuple[dict[str, str], list[str]]:
    """Resolve an actor's session reference to request headers.

    Matches ``auth_accounts.jsonl`` by ``principal`` then ``role``; falls back to
    the sole entry if there is exactly one. Returns a headers dict built from the
    entry's ``token``/``cookie`` and diagnostics. The raw values are used only to
    build the sandbox headers file and are never returned to the agent."""
    diagnostics: list[str] = []
    records, parse_diags = _records_from_text(accounts_text)
    diagnostics.extend(parse_diags)
    want = actor_ref.strip().lower()
    chosen: dict[str, Any] | None = None
    by_principal = [r for r in records if str(r.get("principal", "")).strip().lower() == want]
    by_role = [r for r in records if str(r.get("role", "")).strip().lower() == want]
    if by_principal:
        chosen = by_principal[0]
    elif by_role:
        chosen = by_role[0]
    elif len(records) == 1:
        chosen = records[0]
        diagnostics.append(f"actor {actor_ref!r} not matched by principal/role; used sole entry")
    if chosen is None:
        return {}, [*diagnostics, f"no session entry for actor {actor_ref!r}"]
    headers: dict[str, str] = {}
    token = str(chosen.get("token", "")).strip()
    if token:
        prefixed = token if token.lower().startswith("bearer ") else f"Bearer {token}"
        headers["Authorization"] = prefixed
    cookie = str(chosen.get("cookie", "")).strip()
    if cookie:
        headers["Cookie"] = cookie
    if not headers:
        diagnostics.append(f"session entry for {actor_ref!r} has no token/cookie")
    return headers, diagnostics


def _katana_headers_file(headers: dict[str, str]) -> str:
    return "".join(f"{name}: {value}\n" for name, value in headers.items())


def _curl_config(headers: dict[str, str], url: str, body_path: str) -> str:
    lines = [
        "silent",
        "show-error",
        f'output = "{body_path}"',
        'write-out = "STATUS=%{http_code} REDIRECT=%{redirect_url}\\n"',
        f'url = "{url}"',
    ]
    lines += [f'header = "{name}: {value}"' for name, value in headers.items()]
    return "\n".join(lines) + "\n"


def _auth_check_script(*, conf_path: str, body_path: str, marker: str, absent: str) -> str:
    """A self-cleaning sh script: curl via the config (creds stay in the file),
    grep the body for the two markers in-sandbox so no body reaches the host,
    print a structured line, then remove body + config."""
    q_marker = shlex.quote(marker)
    q_absent = shlex.quote(absent)
    return (
        "#!/bin/sh\n"
        f"OUT=$(curl --config {shlex.quote(conf_path)} 2>/dev/null)\n"
        'M=2; A=2\n'
        f"if [ -n {q_marker} ]; then if grep -qF -- {q_marker} {shlex.quote(body_path)} "
        "2>/dev/null; then M=1; else M=0; fi; fi\n"
        f"if [ -n {q_absent} ]; then if grep -qF -- {q_absent} {shlex.quote(body_path)} "
        "2>/dev/null; then A=1; else A=0; fi; fi\n"
        'printf "%s MARKER=%s ABSENT=%s\\n" "$OUT" "$M" "$A"\n'
        f"rm -f {shlex.quote(body_path)} {shlex.quote(conf_path)}\n"
    )


def _parse_auth_output(text: str) -> dict[str, Any]:
    """Parse the ``STATUS=.. REDIRECT=.. MARKER=.. ABSENT=..`` line. MARKER/ABSENT
    are tri-state: 1=present, 0=absent, 2=not-checked."""
    fields: dict[str, str] = {}
    for token in text.split():
        key, _, value = token.partition("=")
        if key in {"STATUS", "REDIRECT", "MARKER", "ABSENT"}:
            fields[key] = value
    status: int | None = None
    if fields.get("STATUS", "").isdigit():
        status = int(fields["STATUS"])
    marker = {"1": True, "0": False}.get(fields.get("MARKER", "2"))
    absent = {"1": True, "0": False}.get(fields.get("ABSENT", "2"))
    redirect = fields.get("REDIRECT") or None
    return {"status": status, "marker_present": marker, "absent_present": absent,
            "redirect": redirect}


# --------------------------------------------------------------------------- #
# Sandbox orchestration
# --------------------------------------------------------------------------- #


async def _exec(transport: CrawlTransport, *argv: str, timeout: float) -> tuple[int, bytes, bool]:
    """Run argv in the sandbox (``shell=False``). Returns (exit_code, stdout,
    timed_out). A timeout is reported, not raised, so the caller can still ingest
    whatever partial artifact exists."""
    try:
        result = await transport.exec(*argv, timeout=timeout, shell=False)
    except TimeoutError:
        return -1, b"", True
    return int(getattr(result, "exit_code", 1)), bytes(getattr(result, "stdout", b"")), False


async def _write_file(transport: CrawlTransport, path: str, content: str) -> None:
    await transport.write(Path(path), io.BytesIO(content.encode("utf-8")))


async def _read_whole(transport: CrawlTransport, path: str) -> str:
    """Read a (already-bounded) file via the transport. Only used on files known
    to be <= the cap, so the transport buffering the whole thing is fine."""
    try:
        handle = await transport.read(Path(path))
    except FileNotFoundError:
        return ""
    try:
        raw = handle.read()
    finally:
        close = getattr(handle, "close", None)
        if callable(close):
            close()
    data = bytes(raw) if isinstance(raw, (bytes, bytearray)) else str(raw).encode("utf-8")
    return data.decode("utf-8", errors="replace")


async def _read_capped(
    transport: CrawlTransport, path: str, cap: int, workdir: str, tag: str
) -> tuple[str, bool]:
    """Bound the artifact INSIDE the sandbox before transferring it.

    The transport's ``read`` buffers the whole file it is given (the docker
    backend ``cat``s it into memory), so applying the cap after the read would
    not bound host memory. Instead cap the file in-container first (``head -c``)
    and read only that, so the host never receives more than ``cap`` bytes
    regardless of how large the crawl output grew. The original size is returned
    by the same exec, so truncation is detected without a second full read."""
    capped = f"{workdir}/.{tag}.capped"
    _code, stdout, _timed = await _exec(
        transport, "sh", "-lc", _CAP_SCRIPT, "sh", path, capped, str(cap), timeout=60.0
    )
    size_txt = stdout.decode("utf-8", errors="replace").strip()
    if size_txt == "MISSING" or not size_txt.lstrip("-").isdigit():
        await _exec(transport, "rm", "-f", capped, timeout=20.0)
        return "", False
    original_size = int(size_txt)
    text = await _read_whole(transport, capped)
    await _exec(transport, "rm", "-f", capped, timeout=20.0)
    return text, original_size > cap


async def _run_auth_check(
    transport: CrawlTransport,
    *,
    headers: dict[str, str],
    url: str,
    marker: str,
    absent: str,
    workdir: str,
    tag: str,
) -> dict[str, Any]:
    conf_path = f"{workdir}/.{tag}.curl"
    body_path = f"{workdir}/.{tag}.body"
    script_path = f"{workdir}/.{tag}.sh"
    await _write_file(transport, conf_path, _curl_config(headers, url, body_path))
    await _write_file(
        transport, script_path,
        _auth_check_script(conf_path=conf_path, body_path=body_path, marker=marker, absent=absent),
    )
    _code, stdout, timed_out = await _exec(transport, "sh", script_path, timeout=60.0)
    await _exec(transport, "rm", "-f", script_path, timeout=20.0)
    if timed_out:
        return {"status": None, "marker_present": None, "absent_present": None, "redirect": None,
                "error": "auth check timed out"}
    return _parse_auth_output(stdout.decode("utf-8", errors="replace"))


# --------------------------------------------------------------------------- #
# Ingestion of the crawl artifact (scoped), reusing improvement #1's adapters
# --------------------------------------------------------------------------- #


def _ingest_scoped(
    *,
    artifact: str,
    origins: list[str],
    path_scope: list[str],
    actor_ref: str,
    auth_state: str,
    discovery_source: str,
    agent_id: str | None,
    agent_name: str | None,
) -> dict[str, Any]:
    records, parse_diags = _records_from_text(artifact)
    items, adapter_diags = _ingest_katana(records)
    diagnostics = [*parse_diags, *adapter_diags]
    created = merged = skipped = out_of_scope = 0
    for index, item in enumerate(items):
        if not _in_scope(item["url"], origins, path_scope):
            out_of_scope += 1
            continue
        result = _record_impl(
            url=item["url"],
            method=item.get("method", "GET"),
            content_type=item.get("content_type"),
            discovery_source=discovery_source,
            actor_ref=actor_ref,
            auth_state=auth_state,
            status_code=item.get("status_code"),
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
    return {
        "records_parsed": len(records),
        "counts": {"created": created, "merged": merged, "skipped": skipped,
                   "out_of_scope_dropped": out_of_scope},
        "diagnostics": diagnostics,
    }


async def _run_crawl_impl(  # noqa: PLR0912, PLR0915
    transport: CrawlTransport,
    *,
    actor_ref: str,
    origins_raw: Any,
    path_scope_raw: Any = None,
    js_crawl: bool = False,
    auth_check_url: str | None = None,
    auth_check_marker: str = "",
    auth_check_absent_marker: str = "",
    depth: int | None = None,
    pages: int | None = None,
    duration: str = _DEFAULT_DURATION,
    output_cap: int | None = None,
    accounts_path: str = _DEFAULT_ACCOUNTS_PATH,
    workdir: str = _WORK_DIR,
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    started = _now()
    job_id = uuid.uuid4().hex[:12]
    actor = (actor_ref or "anonymous").strip() or "anonymous"
    is_anonymous = actor.lower() == "anonymous"
    origins, origin_diags = _parse_origins(origins_raw)
    path_scope = _normalize_path_scope(path_scope_raw)
    diagnostics = list(origin_diags)

    def _fail(reason: str, auth: dict[str, Any] | None = None) -> dict[str, Any]:
        diagnostics.append(reason)
        return _finalize(
            job_id=job_id, actor=actor, auth_state="anonymous" if is_anonymous else "unknown",
            status=STATUS_FAILED, origins=origins, path_scope=path_scope, started=started,
            ingest=None, auth=auth or {"outcome": AUTH_UNKNOWN, "evidence": {}},
            diagnostics=diagnostics, output_truncated=False,
            scope_enforcement="n/a (no crawl)",
            remaining_work=f"job did not crawl: {reason}",
        )

    if not origins:
        return _fail("no authorized crawl origins supplied")

    depth_c = _clamp(depth, _DEFAULT_DEPTH, _MAX_DEPTH)
    pages_c = _clamp(pages, _DEFAULT_PAGES, _MAX_PAGES)
    cap_c = _clamp(output_cap, _DEFAULT_OUTPUT_CAP, _MAX_OUTPUT_CAP)
    exec_timeout = min(_duration_seconds(duration) + _EXEC_TIMEOUT_MARGIN_S, _MAX_EXEC_TIMEOUT_S)

    await _exec(transport, "mkdir", "-p", workdir, timeout=20.0)

    # 1) Resolve the actor's session reference (never for anonymous).
    headers: dict[str, str] = {}
    base_auth_state = "anonymous"
    auth: dict[str, Any] = {"outcome": AUTH_UNKNOWN, "evidence": {}}
    has_check = bool(auth_check_url and (auth_check_marker or auth_check_absent_marker))
    if not is_anonymous:
        accounts_text, _ = await _read_capped(
            transport, accounts_path, 2_000_000, workdir, f"{job_id}.acc"
        )
        if not accounts_text:
            return _fail(f"no provisioned sessions at {accounts_path} for actor {actor!r}")
        headers, header_diags = _actor_headers(accounts_text, actor)
        diagnostics.extend(header_diags)
        if not headers:
            return _fail(f"actor {actor!r} has no usable session token/cookie")
        base_auth_state = AUTH_UNKNOWN

    headers_file: str | None = None
    if headers:
        headers_file = f"{workdir}/.{job_id}.hdr"
        await _write_file(transport, headers_file, _katana_headers_file(headers))

    out_path = f"{workdir}/{job_id}.jsonl"
    chrome_dir = f"{workdir}/.{job_id}.chrome" if js_crawl else None
    scope_enforcement = SCOPE_CRAWL_FOLLOW if js_crawl else SCOPE_REQUEST_LEVEL
    if js_crawl:
        diagnostics.append(
            "scope: headless/JS crawl cannot prevent browser-initiated out-of-scope requests "
            "(XHR/subresources/redirects); only crawl-follow and ingestion are scope-filtered"
        )

    # 2) Authenticated jobs: verify BEFORE crawling. 200 alone is not proof. A
    #    passing pre-check only AUTHORIZES the crawl — it does not yet license
    #    labelling observations authenticated (that is decided in step 5).
    if headers and has_check:
        pre = await _run_auth_check(
            transport, headers=headers, url=str(auth_check_url),
            marker=auth_check_marker, absent=auth_check_absent_marker,
            workdir=workdir, tag=f"{job_id}.pre",
        )
        outcome, evidence = _classify_auth(has_check=True, **_check_kwargs(pre))
        auth = {"outcome": outcome, "evidence": evidence}
        if outcome == AUTH_INVALID:
            await _scrub(transport, headers_file)
            diagnostics.append("session failed the pre-crawl auth check; not crawling as actor")
            return _finalize(
                job_id=job_id, actor=actor, auth_state=AUTH_UNKNOWN, status=STATUS_FAILED,
                origins=origins, path_scope=path_scope, started=started, ingest=None, auth=auth,
                diagnostics=diagnostics, output_truncated=False,
                scope_enforcement="n/a (no crawl: invalid session)",
                remaining_work="authenticated surface untested: provisioned session was invalid",
            )
    elif headers and not has_check:
        auth["evidence"] = {"reason": "credentials used but no app-specific check supplied"}

    # 3) Crawl (structured argv, bounded, cancellable, hard exec-timeout backstop).
    await _exec(transport, "rm", "-f", out_path, timeout=20.0)
    argv = _build_katana_argv(
        out_path=out_path, origins=origins, path_scope=path_scope, headers_file=headers_file,
        js_crawl=js_crawl, depth=depth_c, pages=pages_c, duration=duration,
        rate_limit=_DEFAULT_RATE_LIMIT, concurrency=_DEFAULT_CONCURRENCY,
        chrome_data_dir=chrome_dir,
    )
    try:
        exit_code, _stdout, timed_out = await _exec(transport, *argv, timeout=exec_timeout)
    except asyncio.CancelledError:
        # Terminate the crawler + children, remove the temp credential/output
        # files, and persist a cancelled outcome — then propagate the cancel.
        await asyncio.shield(
            _cancel_cleanup(
                transport, headers_file=headers_file, out_path=out_path,
                chrome_dir=chrome_dir, job_id=job_id,
            )
        )
        diagnostics.append(
            "crawl cancelled: process signalled, temp credential/output files removed"
        )
        _finalize(
            job_id=job_id, actor=actor, auth_state=base_auth_state, status=STATUS_CANCELLED,
            origins=origins, path_scope=path_scope, started=started, ingest=None, auth=auth,
            diagnostics=diagnostics, output_truncated=False, scope_enforcement=scope_enforcement,
            remaining_work="cancelled before completion; re-run to cover this actor/origin",
        )
        raise

    # 4) Bound the artifact IN-SANDBOX, then transfer only the capped slice, so
    #    the host never buffers more than the cap even though the transport's
    #    read() loads whatever file it is handed.
    artifact, truncated = await _read_capped(transport, out_path, cap_c, workdir, job_id)
    if truncated and artifact and not artifact.endswith("\n"):
        artifact, _, dropped = artifact.rpartition("\n")
        diagnostics.append(
            f"final JSONL record truncated by the {cap_c}-byte output cap; "
            f"dropped {len(dropped)} partial bytes (that record was not ingested)"
        )

    # 5) Session-loss check AFTER crawling, BEFORE labelling. Only valid-pre AND
    #    valid-post lets observations be called authenticated. A valid pre with a
    #    non-valid post means the session dropped at an unknown point, so the
    #    crawl's observations are recorded 'unknown' (uncertain) with follow-up
    #    work — never retroactively relabelled valid.
    applied_auth_state = base_auth_state
    downgraded = False
    if headers and has_check:
        post = await _run_auth_check(
            transport, headers=headers, url=str(auth_check_url),
            marker=auth_check_marker, absent=auth_check_absent_marker,
            workdir=workdir, tag=f"{job_id}.post",
        )
        post_outcome, _ = _classify_auth(has_check=True, **_check_kwargs(post))
        auth["session_valid_after"] = post_outcome
        if auth.get("outcome") == AUTH_VALID and post_outcome == AUTH_VALID:
            applied_auth_state = "authenticated"
        elif auth.get("outcome") == AUTH_VALID:
            applied_auth_state = AUTH_UNKNOWN
            downgraded = True
            diagnostics.append(
                f"session valid before but {post_outcome} after the crawl: it dropped at an "
                f"unknown point, so observations cannot be proven authenticated and are recorded "
                f"'unknown'. Follow-up: re-provision {actor} and re-crawl to confirm."
            )
    auth["applied_auth_state"] = applied_auth_state
    auth["downgraded"] = downgraded

    # 6) Ingest with the VERIFIED (possibly downgraded) auth state. actor_ref
    #    always records the INTENDED actor, separately from the verified state.
    ingest = _ingest_scoped(
        artifact=artifact, origins=origins, path_scope=path_scope, actor_ref=actor,
        auth_state=applied_auth_state, discovery_source=f"crawl:{actor}",
        agent_id=agent_id, agent_name=agent_name,
    )
    diagnostics.extend(ingest["diagnostics"])

    # 7) Scrub the credential file, the body-bearing artifact, and chrome data.
    await _scrub(transport, headers_file)
    await _exec(transport, "rm", "-rf", out_path, timeout=20.0)
    if chrome_dir:
        await _exec(transport, "rm", "-rf", chrome_dir, timeout=20.0)

    status = STATUS_PARTIAL if (timed_out or truncated or downgraded) else STATUS_COMPLETED
    if exit_code != 0 and not timed_out and ingest["records_parsed"] == 0:
        status = STATUS_FAILED
    remaining = _remaining_work(timed_out=timed_out, truncated=truncated, pages=pages_c,
                                created=ingest["counts"]["created"], downgraded=downgraded)
    return _finalize(
        job_id=job_id, actor=actor, auth_state=applied_auth_state, status=status, origins=origins,
        path_scope=path_scope, started=started, ingest=ingest, auth=auth,
        diagnostics=diagnostics, output_truncated=truncated, scope_enforcement=scope_enforcement,
        remaining_work=remaining,
    )


def _check_kwargs(parsed: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": parsed.get("status"),
        "marker_present": parsed.get("marker_present"),
        "absent_present": parsed.get("absent_present"),
        "redirect": parsed.get("redirect"),
    }


async def _scrub(transport: CrawlTransport, path: str | None) -> None:
    if path:
        await _exec(transport, "rm", "-f", path, timeout=20.0)


async def _cancel_cleanup(
    transport: CrawlTransport,
    *,
    headers_file: str | None,
    out_path: str,
    chrome_dir: str | None,
    job_id: str,
) -> None:
    """On cancellation, terminate the crawler process + children and remove temp
    credential/output files. The sandbox ``exec`` is one-shot — cancelling the
    awaiting coroutine does not itself kill the in-container process — so the
    crawler is signalled explicitly by its unique job-id marker (both the output
    path and the chrome data dir carry it). A host transport additionally
    process-group-kills on cancel; this is the belt-and-suspenders for the
    container. Best-effort: each step is guarded and never raises."""
    with contextlib.suppress(Exception):
        await _exec(transport, "pkill", "-f", job_id, timeout=20.0)
    with contextlib.suppress(Exception):
        await _scrub(transport, headers_file)
    with contextlib.suppress(Exception):
        await _exec(transport, "rm", "-rf", out_path, f"{out_path}.capped", timeout=20.0)
    if chrome_dir:
        with contextlib.suppress(Exception):
            await _exec(transport, "rm", "-rf", chrome_dir, timeout=20.0)


def _remaining_work(
    *, timed_out: bool, truncated: bool, pages: int, created: int, downgraded: bool
) -> str:
    if downgraded:
        return ("session dropped mid-crawl; observations recorded 'unknown' — re-provision the "
                "actor and re-crawl to obtain authenticated coverage")
    if timed_out:
        return "crawl hit the time budget; deeper/remaining pages likely untouched"
    if truncated:
        return "crawl output exceeded the read cap; some discovered endpoints not ingested"
    if created >= pages:
        return "per-domain page cap reached; more of this origin may remain uncrawled"
    return "crawl completed within budget; coverage is still per-endpoint, not whole-origin"


def _finalize(
    *,
    job_id: str,
    actor: str,
    auth_state: str,
    status: str,
    origins: list[str],
    path_scope: list[str],
    started: str,
    ingest: dict[str, Any] | None,
    auth: dict[str, Any],
    diagnostics: list[str],
    output_truncated: bool,
    scope_enforcement: str,
    remaining_work: str,
) -> dict[str, Any]:
    record = {
        "job_id": job_id,
        # The actor whose session was used — always known, independent of whether
        # authentication was verified (which lives in auth/auth_state below).
        "intended_actor": actor,
        "actor_ref": actor,
        # The VERIFIED state stamped on this job's observations ('authenticated'
        # only when a check passed before AND after the crawl).
        "auth_state": auth_state,
        "status": status,
        "origins": origins,
        "path_scope": path_scope,
        "scope_enforcement": scope_enforcement,
        "started_at": started,
        "ended_at": _now(),
        "records_parsed": (ingest or {}).get("records_parsed", 0),
        "counts": (ingest or {}).get("counts",
                                     {"created": 0, "merged": 0, "skipped": 0,
                                      "out_of_scope_dropped": 0}),
        "auth": auth,
        "diagnostics": diagnostics,
        "output_truncated": output_truncated,
        "remaining_work": remaining_work,
        # Job completion is NOT coverage: an endpoint existing in the inventory
        # says nothing about whether it was tested (see coverage ledger).
        "coverage_note": "inventory completeness != coverage; untested endpoints remain open",
    }
    _store_job(record)
    return {"success": status not in (STATUS_FAILED, STATUS_CANCELLED), **_public_job(record)}


# --------------------------------------------------------------------------- #
# Agent tools
# --------------------------------------------------------------------------- #


def _caller_identity(ctx: RunContextWrapper) -> tuple[str | None, str | None, Any]:
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
    return agent_id, agent_name, inner.get("sandbox_session")


@function_tool(timeout=1900)
async def run_crawl_job(
    ctx: RunContextWrapper,
    origins: str,
    actor_ref: str = "anonymous",
    path_scope: str = "",
    js_crawl: bool = False,
    auth_check_url: str = "",
    auth_check_marker: str = "",
    auth_check_absent_marker: str = "",
    depth: int | None = None,
    pages: int | None = None,
    duration: str = _DEFAULT_DURATION,
) -> str:
    """Run an actor-aware crawl in the sandbox and ingest it into the attack-surface inventory.

    This is the executable discovery path: it crawls the authorized origins as a
    chosen actor (anonymous, or a provisioned `actor-a`/`actor-b`), streams the
    bounded crawler artifact back over the sandbox transport, and ingests it
    deterministically so `query_attack_surface` immediately has the endpoints —
    no pasting crawler output into tool arguments.

    Actors & sessions: `actor_ref="anonymous"` crawls with no credentials. For a
    named actor, the session is read from `/workspace/recon/auth_accounts.jsonl`
    (written by `account_provisioning`) by `principal` or `role`; its token/cookie
    is passed to the crawler by file and never appears in output. Run one job per
    actor to keep contexts isolated.

    Authentication: supplying a credential is NOT proof of a live session. For an
    authenticated job, pass `auth_check_url` plus `auth_check_marker` (a string
    only an authenticated response contains, e.g. the account's email) and/or
    `auth_check_absent_marker` (a string that only appears when logged out, e.g.
    "Sign in"). The check runs before crawling; HTTP 200 alone yields `unknown`,
    not `valid`. Observations are labelled `authenticated` only when the check
    passes; otherwise `unknown`. The check is re-run after crawling to flag
    session loss. Without a check, a named actor's crawl is recorded `unknown`.

    Scope: only the authorized `origins` (and `path_scope` prefixes, if given) are
    crawled and ingested. Out-of-scope redirects/discoveries are dropped and
    counted, never ingested — this does not add any network firewall to other
    tools.

    Output contains no credentials or response bodies — only ingestion counts,
    the auth outcome with evidence, diagnostics, and remaining-work notes. The
    full endpoint list comes from `query_attack_surface`.

    Args:
        origins: Authorized origin(s) — a URL, comma/space list, or JSON array
            (e.g. `https://app.example.com`). Required.
        actor_ref: `anonymous` (default), or a provisioned actor label/principal.
        path_scope: Optional path prefixes to restrict to (e.g. `/api,/app`).
        js_crawl: Headless crawl to capture JS/XHR-discovered endpoints (slower).
        auth_check_url: URL for the application-specific session check.
        auth_check_marker: String present only when authenticated.
        auth_check_absent_marker: String present only when logged out.
        depth: Max crawl depth (default 2, capped at 5).
        pages: Max pages per domain (default 100, capped at 2000).
        duration: Max crawl wall-clock (`90s`/`2m`/`1h`; default `2m`).
    """
    agent_id, agent_name, session = _caller_identity(ctx)
    if session is None:
        return json.dumps(
            {"success": False, "error": "no sandbox session available for crawl execution"}
        )
    result = await _run_crawl_impl(
        session,
        actor_ref=actor_ref,
        origins_raw=origins,
        path_scope_raw=path_scope,
        js_crawl=js_crawl,
        auth_check_url=auth_check_url or None,
        auth_check_marker=auth_check_marker,
        auth_check_absent_marker=auth_check_absent_marker,
        depth=depth,
        pages=pages,
        duration=duration,
        agent_id=agent_id,
        agent_name=agent_name,
    )
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def list_crawl_jobs(ctx: RunContextWrapper, actor_ref: str = "", limit: int = 50) -> str:
    """List this run's crawl-job history (durable, restored on resume).

    Each entry carries the actor, origins, status (completed/partial/failed),
    ingestion counts, the auth outcome with evidence, and — after a resume —
    `requires_revalidation=true`, meaning the recorded session validity and any
    ephemeral request references must be re-checked before they are trusted.

    Args:
        actor_ref: Optional filter to one actor's jobs.
        limit: Max jobs to return (capped at 100).
    """
    result = await asyncio.to_thread(_list_jobs_impl, actor_ref=actor_ref or None, limit=limit)
    return json.dumps(result, ensure_ascii=False, default=str)
