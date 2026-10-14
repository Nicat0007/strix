"""Targeted SQLi test executor (BLACKBOX improvement #4, hardened).

Explicitly invoked for ONE selected `sql_injection` hypothesis — never an
automatic scanner. Hardened flow:

    hypothesis (worklist #3)
      -> RETRIEVE the concrete stored request through the proxy (NO traffic)
      -> validate origin+port+path against the OPERATOR-authorized scope
         (build_scan_targets) BEFORE any traffic is sent
      -> BASELINE the request (one replay) and classify authentication state
         (anonymous / authenticated / expired / login_challenge / unknown)
      -> if the baseline is BLOCKED (403/429/challenge/...), classify the block
         from sanitized evidence and record a justified, bounded continuation
         recommendation — do NOT run sqlmap
      -> otherwise run sqlmap against exactly ONE location via a `*` injection
         marker (not `-p` alone), detection-only, `--ignore-redirects`, bounded
         time/concurrency, output drained to a file and capped in-sandbox
      -> re-baseline (post); if the session was lost mid-test, downgrade — a
         session failure is never a SQLi result
      -> scrub all temp request/session/log artifacts; record the attempt.

Verified against the installed sqlmap 1.8.4 (not assumed):
- `--ignore-stdin` is required or `-r` is ignored and sqlmap blocks on STDIN.
- `--ignore-redirects` is required to stop sqlmap following a redirect to an
  out-of-scope origin/port (proven: 0 vs 31 out-of-scope requests).
- a `*` injection marker in the request file tests ONLY that location (proven:
  query mutated, a same-named cookie untouched); `-p` alone does not isolate
  locations, so this executor always uses a marker.
- there is NO request-count ceiling flag; this executor enforces hard time,
  concurrency and attempt limits and does NOT claim a request cap.

Hard rules: detection only (no dump/OS/file/crawl/escalation, no credential
attacks, no infra rotation); a positive is `needs_validation`, never
`confirmed`; a 403->200 transition after a continuation is NOT a confirmed
bypass (semantic validation still required); secrets (cookies/auth/bodies) are
never returned and live only in a scrubbed temp file.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import re
import shlex
import uuid
from typing import Any
from urllib.parse import urlsplit

from agents import RunContextWrapper, function_tool

from strix.tools.agent_metrics.tools import record_activity_tick
from strix.tools.attack_surface.tools import _redact_secrets
from strix.tools.crawl_executor.tools import CrawlTransport, _exec, _read_capped, _write_file
from strix.tools.hypotheses.tools import (
    RESOLVED,
    RESOLVED_MISSING,
    RESOLVED_STALE,
    STATUS_BLOCKED,
    STATUS_NEEDS_VALIDATION,
    STATUS_TESTING,
    _record_attempt_impl,
    lookup_hypothesis,
)


logger = logging.getLogger(__name__)

_WORK_DIR = "/workspace/.sqli"
_SQLI_CATEGORY = "sql_injection"

# Bounds — clamped, never trusted from the caller.
_DEFAULT_TIMEOUT_S = 300.0
_MAX_TIMEOUT_S = 900.0
_CONNECT_TIMEOUT_S = 15
_TIME_SEC = 5
_THREADS = 2
_LEVEL = 1
_RISK = 1
_MAX_LEVEL = 3
_MAX_RISK = 2
_OUTPUT_CAP = 2_000_000
_DIAG_MAX = 40
_BODY_SCAN_CAP = 8192
_BACKOFF_DELAY_S = 2
_TECH_CHARS = set("BEUSTQ")
_DEFAULT_TECH = "BEU"
#: A valid HTTP parameter / header name we are willing to mark. Anything else is
#: refused (keeps shell-quoted argv and the marker insertion unambiguous).
_PARAM_RE = re.compile(r"^[A-Za-z0-9_.\-\[\]]{1,128}$")
#: Detection-level representation changes only. No tamper that alters semantics,
#: reads files, or escalates. Agent-selected, one at a time, never automatic.
_TAMPER_ALLOWLIST = frozenset({
    "space2comment", "charencode", "randomcase", "between",
    "apostrophemask", "apostrophenullencode",
})
_VALID_LOCATIONS = ("query", "body", "cookie", "header", "path")

_LOGIN_HINT = re.compile(r"(?i)(login|signin|sign-in|/auth|/sso)")
_CHALLENGE_HINTS = (
    "just a moment", "attention required", "/cdn-cgi/challenge", "__cf_chl",
    "cf-chl", "captcha", "verifying you are human", "ddos-guard",
)
#: Header values we may store (allowlist); every other header is kept by NAME
#: only. Cookies / auth / set-cookie values are NEVER stored.
_HEADER_VALUE_ALLOWLIST = frozenset({
    "server", "via", "retry-after", "content-type", "cf-mitigated", "cf-cache-status",
    "x-cache", "connection", "x-ratelimit-remaining", "x-ratelimit-limit",
    "x-ratelimit-reset", "x-powered-by",
})

VERDICT_INJECTABLE = "injectable"
VERDICT_NOT_INJECTABLE = "not_injectable_this_run"
VERDICT_UNSTABLE = "unstable_target"
VERDICT_CONNECT_FAILED = "connection_failed"
VERDICT_TIMEOUT = "timeout"
VERDICT_INCONCLUSIVE = "inconclusive"
VERDICT_CANCELLED = "cancelled"
VERDICT_BLOCKED = "blocked"

# Authentication states (verified, kept separate from the intended actor).
AUTH_ANONYMOUS = "anonymous"
AUTH_AUTHENTICATED = "authenticated"
AUTH_EXPIRED = "expired"
AUTH_LOGIN_CHALLENGE = "login_challenge"
AUTH_UNKNOWN = "unknown"

# Block categories (evidence-backed; uncertainty preserved).
BLOCK_APP_DENIAL = "application_authorization_denial"
BLOCK_INVALID_AUTH = "invalid_authentication"
BLOCK_RATE_LIMIT = "rate_limit"
BLOCK_WAF = "waf_suspected"
BLOCK_BROWSER_CHALLENGE = "browser_challenge"
BLOCK_UNSTABLE = "unstable_upstream"
BLOCK_UNKNOWN = "unknown_blocking"


def _clean(value: str | None) -> str:
    return _redact_secrets((value or "").strip())


# --------------------------------------------------------------------------- #
# Operator scope — origin + port + path, from build_scan_targets (authoritative)
# --------------------------------------------------------------------------- #


def _parse_scope(scan_targets: list[str] | None) -> list[dict[str, Any]]:
    """Structured authorized entries from the scan's canonical target strings
    (``build_scan_targets`` -> ``build_scope_context.authorized_targets``). Each
    entry enforces whatever the operator specified: a bare host authorizes any
    scheme/port/path on it; a URL with a port restricts to that port; with a path
    restricts to that path prefix. White-box/path targets (no host) contribute
    nothing — this executor is black-box."""
    entries: list[dict[str, Any]] = []
    for raw in scan_targets or []:
        target = str(raw).strip()
        if not target or target.startswith("/"):
            continue
        candidate = target if "://" in target else f"//{target}"
        parts = urlsplit(candidate)
        host = (parts.hostname or "").lower()
        if not host:
            continue
        path = (parts.path or "").rstrip("/")
        entries.append({
            "scheme": (parts.scheme or "").lower() or None,
            "host": host,
            "port": parts.port,
            "path_prefix": path or None,
        })
    return entries


def _url_parts(url: str) -> tuple[str | None, str | None, int | None, str]:
    candidate = url if "://" in url else f"//{url}"
    parts = urlsplit(candidate)
    scheme = (parts.scheme or "").lower() or None
    host = (parts.hostname or "").lower() or None
    port = parts.port
    if port is None and scheme in ("http", "https"):
        port = 443 if scheme == "https" else 80
    return scheme, host, port, (parts.path or "/")


def _scope_check(url: str, scan_targets: list[str] | None) -> tuple[bool, str]:
    """Return (in_scope, reason). Enforces host, and — where the operator
    specified them — scheme, port, and path prefix."""
    entries = _parse_scope(scan_targets)
    if not entries:
        return False, "no operator-authorized web host in scope (black-box executor needs one)"
    u_scheme, u_host, u_port, u_path = _url_parts(url)
    if not u_host:
        return False, "request URL has no resolvable host"
    for e in entries:
        if e["host"] != u_host:
            continue
        if e["scheme"] is not None and e["scheme"] != u_scheme:
            continue
        if e["port"] is not None and e["port"] != u_port:
            continue
        if e["path_prefix"] is not None and not (
            u_path == e["path_prefix"] or u_path.startswith(e["path_prefix"] + "/")
        ):
            continue
        return True, "within operator-authorized scope"
    return False, (
        f"{u_scheme or 'http'}://{u_host}:{u_port}{u_path} does not match any authorized "
        "host/port/path restriction"
    )


# --------------------------------------------------------------------------- #
# sqlmap argv, request-file injection marker, result classification
# --------------------------------------------------------------------------- #


def _sanitize_technique(technique: str) -> str:
    chars = [c for c in (technique or "").upper() if c in _TECH_CHARS]
    return "".join(dict.fromkeys(chars)) or _DEFAULT_TECH


def _build_sqlmap_argv(
    *,
    request_file: str,
    output_dir: str,
    technique: str,
    level: int,
    risk: int,
    timeout_connect: int,
    delay: int = 0,
    threads: int = _THREADS,
    tamper: str | None = None,
) -> list[str]:
    """Structured sqlmap argv — detection only, scope-safe, bounded. The injection
    point is a `*` marker in ``request_file`` (NOT ``-p``), so exactly one input
    location is tested. The caller cannot inject extra flags; tamper is restricted
    to the detection-only allowlist."""
    argv = [
        "sqlmap",
        "-r", request_file,
        "--technique", _sanitize_technique(technique),
        "--level", str(level),
        "--risk", str(risk),
        "--batch",
        "--ignore-stdin",       # else -r is ignored and sqlmap blocks on STDIN
        "--ignore-redirects",   # else a redirect can leave authorized scope
        "--disable-coloring",
        "--flush-session",
        "--fresh-queries",
        "--threads", str(max(1, threads)),
        "--timeout", str(timeout_connect),
        "--time-sec", str(_TIME_SEC),
        "--answers", "crack=N,dict=N,continue=Y,quit=N",
        "--output-dir", output_dir,
        "-v", "1",
    ]
    if delay > 0:
        argv += ["--delay", str(delay)]
    if tamper:
        argv += ["--tamper", tamper]
    return argv


def _insert_marker(raw: str, param: str, location: str) -> str | None:  # noqa: PLR0911, PLR0912
    """Insert a single sqlmap `*` injection marker at ``param`` in ``location``.

    Returns the modified raw request, or None if the parameter is not present in
    that location / the location is ambiguous (caller records blocked). Only the
    intended input is marked, so sqlmap mutates only that one location."""
    try:
        head, sep, body = raw.partition("\r\n\r\n")
        if not sep:
            head, sep, body = raw.partition("\n\n")
        lines = head.split("\n")
        request_line = lines[0]
        header_lines = lines[1:]
    except Exception:  # noqa: BLE001 - malformed raw -> ambiguous
        return None

    def _mark_kv(text: str, key: str, *, sep_char: str = "&") -> str | None:
        # mark key=value -> key=value*  (value may be empty)
        pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(key)}=([^{re.escape(sep_char)}\s]*)")
        m = pattern.search(text)
        if not m:
            return None
        end = m.end()
        return text[:end] + "*" + text[end:]

    if location == "query":
        parts = request_line.split(" ")
        if len(parts) < 2 or "?" not in parts[1]:
            return None
        path, _, query = parts[1].partition("?")
        marked = _mark_kv(query, param)
        if marked is None:
            return None
        parts[1] = f"{path}?{marked}"
        lines[0] = " ".join(parts)
        return "\n".join(lines) + sep + body

    if location == "cookie":
        for i, hl in enumerate(header_lines):
            if hl.lower().startswith("cookie:"):
                name, _, val = hl.partition(":")
                marked = _mark_kv(val, param, sep_char=";")
                if marked is None:
                    return None
                header_lines[i] = f"{name}:{marked}"
                return "\n".join([request_line, *header_lines]) + sep + body
        return None

    if location == "header":
        for i, hl in enumerate(header_lines):
            hname, _, hval = hl.partition(":")
            if hname.strip().lower() == param.lower():
                header_lines[i] = f"{hname}:{hval}*"
                return "\n".join([request_line, *header_lines]) + sep + body
        return None

    if location == "body":
        if not body.strip():
            return None
        # form-encoded first, then a best-effort JSON value.
        marked = _mark_kv(body, param)
        if marked is not None:
            return head + sep + marked
        jm = re.search(rf'("{re.escape(param)}"\s*:\s*)("[^"]*"|[^,}}\s]+)', body)
        if jm:
            end = jm.end()
            return head + sep + body[:end] + "*" + body[end:]
        return None

    # path and anything else: ambiguous by default -> blocked.
    return None


def _classify_sqlmap(stdout: str, timed_out: bool) -> tuple[str, str, list[str]]:
    """Map a detection-only sqlmap run to (result_status, verdict, diagnostics)."""
    low = stdout.lower()
    diagnostics: list[str] = []
    if timed_out:
        return STATUS_BLOCKED, VERDICT_TIMEOUT, ["sqlmap exceeded the time budget"]
    if "unable to connect to the target url" in low or "connection timed out" in low:
        return STATUS_BLOCKED, VERDICT_CONNECT_FAILED, [
            "sqlmap could not reach the target — re-verify the baseline/session"
        ]
    if "target url content is not stable" in low or "page you are trying is not stable" in low:
        return STATUS_BLOCKED, VERDICT_UNSTABLE, [
            "target responses are unstable; a real signal cannot be told from noise — not a finding"
        ]
    if "waf/ips" in low:
        diagnostics.append(
            "sqlmap heuristically detected a WAF/IPS; treat any signal as suspect, not a finding"
        )
    if (
        "the following injection point" in low
        or "is vulnerable" in low
        or "sqlmap identified the following" in low
    ):
        return STATUS_NEEDS_VALIDATION, VERDICT_INJECTABLE, diagnostics
    if "do not appear to be injectable" in low or "might not be injectable" in low:
        return STATUS_TESTING, VERDICT_NOT_INJECTABLE, [
            *diagnostics,
            ("detection-only negative for THIS parameter — does not rule out the parameter, "
             "other techniques, or the vulnerability class; left open for a deeper/manual retest"),
        ]
    return STATUS_BLOCKED, VERDICT_INCONCLUSIVE, [
        *diagnostics, "no clear sqlmap verdict in the detection run"
    ]


_DBMS_RE = re.compile(r"(?i)back-end dbms[:\s]+(?:is\s+)?['\"]?([a-z0-9 .()\-]+?)['\"]?\s*[\r\n]")
_TYPE_RE = re.compile(r"(?i)^\s*Type:\s*(.+?)\s*$", re.MULTILINE)


def _summarize(stdout: str) -> str:
    parts: list[str] = []
    dbms = _DBMS_RE.search(stdout)
    if dbms:
        parts.append(f"dbms={dbms.group(1).strip()[:40]}")
    types = sorted({t.strip()[:40] for t in _TYPE_RE.findall(stdout)})
    if types:
        parts.append("types=" + "; ".join(types[:5]))
    return _redact_secrets("; ".join(parts))[:300]


# --------------------------------------------------------------------------- #
# Authentication + block classification from sanitized baseline metadata
# --------------------------------------------------------------------------- #


def _sanitized_meta(baseline: dict[str, Any]) -> dict[str, Any]:
    """Bounded, secret-free response fingerprint: status, timing, a structural
    body hash, header NAMES, allowlisted header VALUES, and challenge indicators.
    Never cookies/auth/bodies/sensitive redirect queries."""
    status = baseline.get("status")
    headers = baseline.get("headers") or {}
    body = (baseline.get("body") or "")[:_BODY_SCAN_CAP]
    header_names = sorted({str(k).lower() for k in headers})
    allowlisted = {
        str(k).lower(): str(v)[:120]
        for k, v in headers.items()
        if str(k).lower() in _HEADER_VALUE_ALLOWLIST
    }
    low_blob = (body + " " + " ".join(f"{k}:{v}" for k, v in allowlisted.items())).lower()
    challenge = sorted({h for h in _CHALLENGE_HINTS if h in low_blob})
    # Structural fingerprint — status + header-name set + coarse body-length
    # bucket. Stable across payloads, reveals nothing sensitive.
    fp_src = f"{status}|{','.join(header_names)}|{len(body) // 256}"
    fingerprint = hashlib.sha256(fp_src.encode()).hexdigest()[:12]
    location = ""
    for k, v in headers.items():
        if str(k).lower() == "location":
            location = str(v).split("?", 1)[0]  # drop any sensitive redirect query
            break
    return {
        "status": status,
        "timing_ms": baseline.get("timing_ms"),
        "body_fingerprint": fingerprint,
        "header_names": header_names,
        "header_values": allowlisted,
        "challenge_indicators": challenge,
        "redirect_location": location,
    }


def _has_session(raw: str) -> bool:
    low = raw.lower()
    return "\ncookie:" in low or low.startswith("cookie:") or "\nauthorization:" in low


def _classify_auth(  # noqa: PLR0911
    *, has_session: bool, meta: dict[str, Any], body: str,
    marker: str, absent_marker: str,
) -> str:
    status = meta.get("status")
    loc = (meta.get("redirect_location") or "").lower()
    body_l = (body or "")[:_BODY_SCAN_CAP]
    if status in (401, 407):
        return AUTH_EXPIRED
    if status is not None and 300 <= status < 400 and _LOGIN_HINT.search(loc):
        return AUTH_LOGIN_CHALLENGE
    if absent_marker and absent_marker in body_l:
        return AUTH_LOGIN_CHALLENGE if _LOGIN_HINT.search(body_l) else AUTH_EXPIRED
    if status is not None and 200 <= status < 300:
        if not has_session:
            return AUTH_ANONYMOUS
        if marker:
            return AUTH_AUTHENTICATED if marker in body_l else AUTH_EXPIRED
        return AUTH_UNKNOWN  # 200 + session but no marker => cannot prove auth
    return AUTH_UNKNOWN


def _classify_block(meta: dict[str, Any], sqlmap_low: str) -> tuple[str, str, list[str]]:  # noqa: PLR0911
    """Evidence-backed block classification -> (category, confidence, reasons).
    A single 403 / Server header / vendor name is never enough for high
    confidence; uncertainty and reasons are preserved."""
    status = meta.get("status")
    hv = meta.get("header_values") or {}
    reasons: list[str] = []
    if meta.get("challenge_indicators"):
        reasons.append(f"challenge indicators: {meta['challenge_indicators']}")
        return BLOCK_BROWSER_CHALLENGE, "medium", reasons
    if status == 429 or "retry-after" in hv or hv.get("x-ratelimit-remaining") == "0":
        rate_headers = [k for k in hv if "rate" in k or k == "retry-after"]
        reasons.append(f"status={status}, rate headers={rate_headers}")
        return BLOCK_RATE_LIMIT, "medium", reasons
    if status in (401, 407):
        reasons.append(f"status={status} (authentication required)")
        return BLOCK_INVALID_AUTH, "medium", reasons
    server = hv.get("server", "").lower()
    waf_vendor = any(v in server for v in ("cloudflare", "sucuri", "mod_security", "akamai",
                                           "awselb", "incapsula", "big-ip", "barracuda"))
    waf_markers = "request blocked" in sqlmap_low or "waf/ips" in sqlmap_low or \
        "cf-mitigated" in hv
    if status == 403 and (waf_vendor or waf_markers):
        reasons.append(f"status=403 with WAF-suggestive evidence (server={server!r}, "
                       f"sqlmap_waf={'waf/ips' in sqlmap_low})")
        reasons.append("LOW confidence: a vendor header/name does not prove filtering")
        return BLOCK_WAF, "low", reasons
    if status == 403:
        reasons.append("status=403 with no auth/challenge/rate/WAF evidence")
        reasons.append("LOW confidence: a single 403 is likely an application authorization "
                       "denial but cannot be distinguished from silent filtering here")
        return BLOCK_APP_DENIAL, "low", reasons
    if "unable to connect" in sqlmap_low or "not stable" in sqlmap_low:
        reasons.append("sqlmap reported connection/stability trouble")
        return BLOCK_UNSTABLE, "low", reasons
    reasons.append(f"no decisive evidence (status={status})")
    return BLOCK_UNKNOWN, "low", reasons


def _continuation_recommendation(category: str) -> str:
    return {
        BLOCK_INVALID_AUTH: ("re-provision/revalidate the session (account_provisioning), then "
                             "re-run; do not treat this as a SQLi result"),
        BLOCK_RATE_LIMIT: ("retry once with continuation='backoff' (bounded delay + single "
                           "thread); do not rotate infrastructure to evade the limit"),
        BLOCK_BROWSER_CHALLENGE: ("hand off to the agent_browser/session workflow to solve the "
                                  "challenge and recapture a request; this executor cannot"),
        BLOCK_WAF: ("optionally retry once with continuation='tamper:<name>' from the "
                    "detection-only allowlist; a 403->200 change is NOT a confirmed bypass"),
        BLOCK_APP_DENIAL: ("likely a legitimate authorization denial; confirm intended access "
                           "with the operator rather than attempting a bypass"),
        BLOCK_UNSTABLE: "re-establish a stable baseline and retry",
        BLOCK_UNKNOWN: "gather more evidence; re-baseline and retry, or escalate to manual review",
    }.get(category, "re-baseline and retry")


# --------------------------------------------------------------------------- #
# Proxy adapter (contract-verified against caido_api) — retrieve vs baseline
# --------------------------------------------------------------------------- #


def _strip_scheme(ref: str) -> str:
    ref = ref.strip()
    return ref.split(":", 1)[1] if ref.lower().startswith("caido:") else ref


async def _retrieve_request(request_id: str) -> dict[str, Any] | None:
    """Retrieve the stored request via the proxy — NO traffic to the target.
    Returns {found, raw, url, method, content_type} or None if not stored."""
    from strix.tools.proxy import caido_api  # noqa: PLC0415

    result = await caido_api.view_request(request_id, part="request")
    if result is None or getattr(result.request, "raw", None) is None:
        return None
    raw = result.request.raw.decode("utf-8", errors="replace")
    components = caido_api.parse_raw_request(raw)
    # full_url_from_components takes (original, components, modifications).
    url = caido_api.full_url_from_components(result.request, components, {})
    content_type = ""
    for name, value in (components.get("headers") or {}).items():
        if str(name).lower() == "content-type":
            content_type = str(value)
            break
    return {"found": True, "raw": raw, "url": url,
            "method": str(components.get("method", "GET")), "content_type": content_type}


async def _baseline_request(request_id: str) -> dict[str, Any]:
    """Send ONE baseline replay via the proxy and parse the response.
    repeat_request -> {status, response_raw, elapsed_ms, ...}; the status/headers
    live in response_raw (parse_raw_response), NOT as top-level keys."""
    from strix.tools.proxy import caido_api  # noqa: PLC0415

    replay = await caido_api.repeat_request(request_id)
    if not isinstance(replay, dict) or replay.get("status") == "ERROR":
        return {"replayed": False}
    parsed = caido_api.parse_raw_response(replay.get("response_raw"))
    if not parsed:
        return {"replayed": False, "timing_ms": replay.get("elapsed_ms")}
    return {
        "replayed": True,
        "status": parsed.get("status_code"),
        "headers": parsed.get("headers") or {},
        "body": parsed.get("body") or "",
        "timing_ms": replay.get("elapsed_ms"),
    }


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def _record(
    *, hypothesis_id: str, result_status: str, verdict: str, rationale: str,
    outcome: str, validation_required: str, input_evidence: dict[str, Any] | None,
    agent_id: str | None, agent_name: str | None,
) -> None:
    _record_attempt_impl(
        hypothesis_id=hypothesis_id, tool="sqlmap", tool_rationale=rationale,
        outcome=outcome, result_status=result_status, validation_required=validation_required,
        signal=verdict, input_evidence=input_evidence, agent_id=agent_id, agent_name=agent_name,
    )


async def _cancel_cleanup(transport: CrawlTransport, *, paths: list[str], job_id: str) -> None:
    with contextlib.suppress(Exception):
        await _exec(transport, "pkill", "-f", job_id, timeout=20.0)
    for path in paths:
        with contextlib.suppress(Exception):
            await _exec(transport, "rm", "-rf", path, timeout=20.0)


async def _run_sqlmap_bounded(
    transport: CrawlTransport, argv: list[str], *, logfile: str, output_dir: str,
    timeout: float, workdir: str, job_id: str,
) -> tuple[str, bool]:
    """Run sqlmap with output drained to a FILE (no pipe to deadlock), then read
    it back CAPPED in-sandbox (bounded host memory). Returns (log_text, timed_out).
    Raises CancelledError after killing the process + scrubbing on cancellation."""
    command = " ".join(shlex.quote(a) for a in argv) + f" > {shlex.quote(logfile)} 2>&1"
    try:
        _code, _out, timed_out = await _exec(transport, "sh", "-lc", command, timeout=timeout)
    except asyncio.CancelledError:
        await asyncio.shield(
            _cancel_cleanup(transport, paths=[logfile, output_dir], job_id=job_id)
        )
        raise
    text, _truncated = await _read_capped(transport, logfile, _OUTPUT_CAP, workdir, job_id)
    return text, timed_out


async def _run_sqli_impl(  # noqa: PLR0911, PLR0912, PLR0915
    transport: CrawlTransport,
    *,
    hypothesis_id: str,
    request_ref: str,
    param_name: str,
    param_location: str = "query",
    technique: str = _DEFAULT_TECH,
    level: int | None = None,
    risk: int | None = None,
    timeout: float | None = None,
    continuation: str = "",
    auth_marker: str = "",
    auth_absent_marker: str = "",
    retrieve: Any = None,
    baseline: Any = None,
    scan_targets: list[str] | None = None,
    workdir: str = _WORK_DIR,
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    hid = (hypothesis_id or "").strip()
    param = (param_name or "").strip()
    ref = (request_ref or "").strip()
    location = (param_location or "query").strip().lower()
    hypothesis = lookup_hypothesis(hid)
    if hypothesis is None:
        return {"success": False, "error": f"no hypothesis {hypothesis_id!r} (create it first)"}
    if hypothesis.get("vuln_category") != _SQLI_CATEGORY:
        return {"success": False, "error": f"hypothesis {hid} is not '{_SQLI_CATEGORY}'"}
    if not ref:
        return {"success": False, "error": "request_ref is required (a stored proxy request id)"}
    if not _PARAM_RE.match(param):
        return {"success": False, "error": "param_name missing or not a valid parameter name"}
    if location not in _VALID_LOCATIONS:
        return {"success": False, "error": f"param_location must be one of {_VALID_LOCATIONS}"}
    cont = (continuation or "").strip().lower()

    intended_actor = str(hypothesis.get("actor_ref") or "anonymous")
    rationale = (
        f"targeted detection-only sqlmap, {location} parameter {param!r} marked with a `*` "
        f"injection point (location-isolated), on the hypothesis's concrete request; "
        f"intended_actor={intended_actor}"
    )

    def _blocked(outcome: str, validation: str, resolved: str,
                 extra: dict[str, Any] | None = None) -> dict[str, Any]:
        ev = {"kind": "request", "ref": ref[:256], "resolved_state": resolved}
        _record(hypothesis_id=hid, result_status=STATUS_BLOCKED, verdict=VERDICT_BLOCKED,
                rationale=rationale, outcome=outcome, validation_required=validation,
                input_evidence=ev, agent_id=agent_id, agent_name=agent_name)
        out = {"success": True, "hypothesis_id": hid, "ran_sqlmap": False,
               "result_status": STATUS_BLOCKED, "param": param, "param_location": location,
               "intended_actor": intended_actor, "outcome": outcome, "suggestion": validation}
        if extra:
            out.update(extra)
        return out

    retrieve_fn = retrieve or _retrieve_request
    baseline_fn = baseline or _baseline_request

    # 1) RETRIEVE the stored request — NO traffic yet.
    try:
        got = await retrieve_fn(_strip_scheme(ref))
    except Exception:  # noqa: BLE001 - proxy failure degrades to blocked
        return _blocked("proxy unavailable; could not retrieve the stored request",
                        "capture the request in the proxy and attach its id, then retry",
                        RESOLVED_MISSING)
    if not got or not got.get("found") or not got.get("raw"):
        return _blocked("stored request not found for this reference",
                        "capture the request in the proxy and attach its id, then retry",
                        RESOLVED_MISSING)
    raw = str(got["raw"])
    url = str(got.get("url") or "")

    # 2) SCOPE — validate origin+port+path BEFORE any traffic is sent.
    in_scope, scope_reason = _scope_check(url, scan_targets)
    if not in_scope:
        return _blocked(f"destination not in operator scope: {scope_reason}; not testing",
                        "confirm the target (host/port/path) is authorized with the operator",
                        RESOLVED, {"in_scope": False})

    # 3) Insert the location-specific injection marker BEFORE baseline/sqlmap.
    marked_raw = _insert_marker(raw, param, location)
    if marked_raw is None:
        return _blocked(
            f"parameter {param!r} not found in location {location!r}, or the location is "
            "ambiguous (e.g. path/JSON) — cannot isolate the injection point",
            f"re-check the parameter's actual location, or capture a request where {param!r} "
            f"is a {location} parameter",
            RESOLVED)

    # 4) BASELINE (one replay) + authentication state (pre).
    try:
        base_pre = await baseline_fn(_strip_scheme(ref))
    except Exception:  # noqa: BLE001
        base_pre = {"replayed": False}
    if not base_pre.get("replayed"):
        return _blocked("stored request found but the baseline replay did not succeed "
                        "(target unreachable from the proxy) — not a SQLi result",
                        "re-verify connectivity/session and recapture, then retry", RESOLVED_STALE)
    meta_pre = _sanitized_meta(base_pre)
    auth_pre = _classify_auth(has_session=_has_session(raw), meta=meta_pre,
                              body=base_pre.get("body", ""), marker=auth_marker.lower(),
                              absent_marker=auth_absent_marker.lower())

    # Session failure is NEVER a SQLi result.
    if auth_pre in (AUTH_EXPIRED, AUTH_LOGIN_CHALLENGE):
        return _blocked(
            f"authentication invalid before testing (auth_state={auth_pre}, "
            f"status={meta_pre['status']}) — session failure, not a SQLi result",
            "re-provision/revalidate the actor's session, then retry",
            RESOLVED_STALE,
            {"auth_state": auth_pre, "intended_actor": intended_actor, "baseline": meta_pre})

    # 5) If the baseline is a BLOCK (403/429/challenge), classify + recommend;
    #    do not run detection against a blocked response.
    status_pre = meta_pre.get("status")
    is_block = status_pre in (403, 429) or bool(meta_pre.get("challenge_indicators"))
    if is_block and cont not in ("backoff", "tamper", "browser_handoff") and not cont.startswith(
        "tamper:"
    ):
        category, confidence, reasons = _classify_block(meta_pre, "")
        rec = _continuation_recommendation(category)
        return _blocked(
            f"baseline is blocked (status={status_pre}); classified {category} "
            f"(confidence={confidence})",
            rec, RESOLVED,
            {"block_classification": {"category": category, "confidence": confidence,
                                      "reasons": reasons}, "baseline": meta_pre,
             "recommended_continuation": rec})

    # 6) Continuation controls (agent-selected, bounded, evidence-gated).
    delay = 0
    threads = _THREADS
    tamper: str | None = None
    continuation_record: dict[str, Any] | None = None
    if cont:
        category, confidence, _reasons = _classify_block(meta_pre, "")
        if cont == "backoff":
            if category not in (BLOCK_RATE_LIMIT, BLOCK_UNKNOWN):
                return _blocked(f"continuation 'backoff' does not fit the evidence "
                                f"(classified {category})",
                                _continuation_recommendation(category), RESOLVED,
                                {"block_classification": {"category": category}})
            delay, threads = _BACKOFF_DELAY_S, 1
            continuation_record = {"action": "backoff", "why": f"observed {category}",
                                   "changed": f"--delay {delay} --threads 1"}
        elif cont == "browser_handoff":
            return _blocked(
                "handed off to the browser/session workflow — this executor does not solve "
                "browser challenges",
                "use agent_browser to pass the challenge and recapture a fresh request, "
                "then retry run_sqli_test",
                RESOLVED, {"continuation": {"action": "browser_handoff", "why": f"{category}"}})
        elif cont.startswith("tamper:"):
            name = cont.split(":", 1)[1]
            if name not in _TAMPER_ALLOWLIST:
                return _blocked(f"tamper {name!r} is not in the detection-only allowlist "
                                f"{sorted(_TAMPER_ALLOWLIST)}",
                                "choose an allowlisted detection-only tamper", RESOLVED)
            if category not in (BLOCK_WAF, BLOCK_UNKNOWN):
                return _blocked(f"continuation 'tamper' does not fit the evidence "
                                f"(classified {category})",
                                _continuation_recommendation(category), RESOLVED,
                                {"block_classification": {"category": category}})
            tamper = name
            continuation_record = {"action": f"tamper:{name}", "why": f"observed {category}",
                                   "changed": f"--tamper {name}"}
        else:
            return _blocked(f"unknown continuation {cont!r}",
                            "use one of: backoff, tamper:<name>, browser_handoff", RESOLVED)

    # 7) Run sqlmap (bounded, marker-isolated, output drained to a capped file).
    input_evidence = {"kind": "request", "ref": ref[:256], "resolved_state": RESOLVED,
                      "summary": f"{got.get('method', '?')} -> {status_pre}"}
    job_id = f"sqli_{uuid.uuid4().hex[:10]}"
    request_file = f"{workdir}/{job_id}.req"
    logfile = f"{workdir}/{job_id}.log"
    output_dir = f"{workdir}/{job_id}.out"
    paths = [request_file, logfile, output_dir]
    level_c = max(1, min(level or _LEVEL, _MAX_LEVEL))
    risk_c = max(1, min(risk or _RISK, _MAX_RISK))
    exec_timeout = min(timeout or _DEFAULT_TIMEOUT_S, _MAX_TIMEOUT_S)

    await _exec(transport, "mkdir", "-p", workdir, timeout=20.0)
    await _write_file(transport, request_file, marked_raw)
    await _exec(transport, "chmod", "600", request_file, timeout=20.0)
    argv = _build_sqlmap_argv(
        request_file=request_file, output_dir=output_dir, technique=technique,
        level=level_c, risk=risk_c, timeout_connect=_CONNECT_TIMEOUT_S,
        delay=delay, threads=threads, tamper=tamper,
    )
    try:
        stdout, timed_out = await _run_sqlmap_bounded(
            transport, argv, logfile=logfile, output_dir=output_dir,
            timeout=exec_timeout, workdir=workdir, job_id=job_id,
        )
    except asyncio.CancelledError:
        # _run_sqlmap_bounded already scrubbed the log/output; scrub the request.
        await asyncio.shield(_cancel_cleanup(transport, paths=paths, job_id=job_id))
        _record(hypothesis_id=hid, result_status=STATUS_BLOCKED, verdict=VERDICT_CANCELLED,
                rationale=rationale, outcome="sqlmap run cancelled; temp request/session removed",
                validation_required="re-run the targeted test to cover this parameter",
                input_evidence=input_evidence, agent_id=agent_id, agent_name=agent_name)
        raise

    if len(stdout) > _OUTPUT_CAP:
        stdout = stdout[:_OUTPUT_CAP]
    result_status, verdict, diagnostics = _classify_sqlmap(stdout, timed_out)
    summary = _summarize(stdout)

    # 8) POST baseline — detect session loss during testing.
    try:
        base_post = await baseline_fn(_strip_scheme(ref))
    except Exception:  # noqa: BLE001
        base_post = {"replayed": False}
    auth_post = AUTH_UNKNOWN
    if base_post.get("replayed"):
        meta_post = _sanitized_meta(base_post)
        auth_post = _classify_auth(has_session=_has_session(raw), meta=meta_post,
                                   body=base_post.get("body", ""), marker=auth_marker.lower(),
                                   absent_marker=auth_absent_marker.lower())

    for path in paths:
        await _exec(transport, "rm", "-rf", path, timeout=20.0)

    session_lost = auth_pre == AUTH_AUTHENTICATED and auth_post in (
        AUTH_EXPIRED, AUTH_LOGIN_CHALLENGE
    )
    block_classification: dict[str, Any] | None = None
    if session_lost:
        # Downgrade: a lost session is not a SQLi negative or positive.
        result_status, verdict = STATUS_BLOCKED, VERDICT_BLOCKED
        diagnostics = [("session was valid before but lost during testing — results discarded; "
                        "re-provision and retry")]
        summary = ""
    elif result_status == STATUS_BLOCKED and verdict in (
        VERDICT_INCONCLUSIVE, VERDICT_UNSTABLE, VERDICT_CONNECT_FAILED
    ):
        category, confidence, reasons = _classify_block(meta_pre, stdout.lower())
        block_classification = {"category": category, "confidence": confidence, "reasons": reasons}
        diagnostics = [*diagnostics, f"block classified {category} (confidence={confidence})",
                       f"recommended: {_continuation_recommendation(category)}"]

    validation = _validation_for(verdict, continuation_record)
    outcome = _clean(f"sqlmap verdict={verdict}" + (f"; {summary}" if summary else "")
                     + (f"; continuation={continuation_record['action']}"
                        if continuation_record else ""))
    _record(hypothesis_id=hid, result_status=result_status, verdict=verdict, rationale=rationale,
            outcome=outcome, validation_required=validation, input_evidence=input_evidence,
            agent_id=agent_id, agent_name=agent_name)
    record_activity_tick(agent_id)

    result: dict[str, Any] = {
        "success": True, "hypothesis_id": hid, "ran_sqlmap": True, "param": param,
        "param_location": location, "in_scope": True, "intended_actor": intended_actor,
        "auth_state_pre": auth_pre, "auth_state_post": auth_post, "session_lost": session_lost,
        "baseline_status": status_pre, "result_status": result_status, "verdict": verdict,
        "summary": summary, "diagnostics": diagnostics[:_DIAG_MAX],
        "request_cap_enforced": False,
        "note": "detection-only; a positive is needs_validation, never confirmed; a 403->200 "
                "change after a continuation is NOT a confirmed bypass (semantic validation "
                "still required). sqlmap has no request-count flag — time/concurrency/attempt "
                "limits are enforced instead.",
    }
    if continuation_record:
        continuation_record.update({
            "budget": {"extra_attempt": 1, "timeout_s": exec_timeout},
            "control_comparison": {"baseline_status_pre": status_pre,
                                   "auth_pre": auth_pre, "auth_post": auth_post},
            "result": verdict,
            "uncertainty": "a block clearing after this change is not itself a vulnerability",
        })
        result["continuation"] = continuation_record
    if block_classification:
        result["block_classification"] = block_classification
    return result


def _validation_for(verdict: str, continuation: dict[str, Any] | None) -> str:
    if verdict == VERDICT_INJECTABLE:
        base = ("independently validate: reproduce manually and demonstrate real impact "
                "(e.g. extract one sensitive record) before confirming — a scanner signal is "
                "not a finding")
        if continuation:
            base += (". NOTE: this ran with a continuation alternative; a block clearing is NOT "
                     "a confirmed bypass — require semantic evidence of the expected operation")
        return base
    if verdict == VERDICT_NOT_INJECTABLE:
        return ("not closed: a detection-only negative does not rule out the parameter/class — "
                "consider a higher level/risk, other techniques, or manual testing")
    if verdict == VERDICT_BLOCKED:
        return "re-establish a valid session/stable baseline and retry; this run is inconclusive"
    return "re-run with a stable baseline; the run was inconclusive"


# --------------------------------------------------------------------------- #
# Agent tool
# --------------------------------------------------------------------------- #


def _caller_identity(ctx: RunContextWrapper) -> dict[str, Any]:
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
    retrieve = inner.get("sqli_retrieve")
    baseline = inner.get("sqli_baseline")
    return {
        "agent_id": agent_id, "agent_name": agent_name,
        "retrieve": retrieve if callable(retrieve) else None,
        "baseline": baseline if callable(baseline) else None,
        "scan_targets": inner.get("scan_targets"),
        "session": inner.get("sandbox_session"),
    }


@function_tool(timeout=950)
async def run_sqli_test(
    ctx: RunContextWrapper,
    hypothesis_id: str,
    request_ref: str,
    param_name: str,
    param_location: str = "query",
    technique: str = _DEFAULT_TECH,
    level: int | None = None,
    risk: int | None = None,
    timeout: float | None = None,
    continuation: str = "",
    auth_marker: str = "",
    auth_absent_marker: str = "",
) -> str:
    """Run a targeted, detection-only sqlmap test for ONE input location of a SQLi hypothesis.

    Explicitly invoked for a single hypothesis — NOT an automatic scanner. It
    retrieves the hypothesis's stored request through the proxy (no traffic),
    validates the destination's host/port/path against operator-authorized scope
    BEFORE sending anything, isolates the named parameter in the named location
    with a `*` injection marker (so only that input is tested), baselines the
    request and classifies the authentication state, then runs sqlmap in
    detection mode (no dumping/OS/file/exploitation), bounded in time/concurrency,
    with redirects disabled so testing cannot leave scope. It records the attempt
    on the hypothesis automatically.

    Blocks are investigated, not treated as "no vulnerability": a 403/429/
    challenge/expired-session baseline is classified (application denial / invalid
    auth / rate limit / suspected WAF / browser challenge / unstable / unknown)
    from sanitized evidence, and a justified bounded continuation is recommended.
    A session failure is never recorded as a SQLi result. A positive is
    `needs_validation`, never `confirmed`; a 403->200 change after a continuation
    is NOT a confirmed bypass.

    Args:
        hypothesis_id: A `sql_injection` hypothesis id from `query_hypotheses`.
        request_ref: The stored proxy request id to test.
        param_name: The single parameter (or header name) to test.
        param_location: query / body / cookie / header / path — the location
            actually isolated and tested (a same-named input elsewhere is NOT
            touched). If the parameter isn't in that location, the run is blocked.
        technique: sqlmap detection techniques, subset of `BEUSTQ` (default `BEU`).
        level: sqlmap level 1-3 (default 1). risk: 1-2 (default 1).
        timeout: Max wall-clock seconds (default 300, capped 900).
        continuation: After a classified block, an agent-selected bounded
            alternative: `backoff` (rate limit), `tamper:<name>` (suspected WAF;
            detection-only allowlist), or `browser_handoff` (challenge). Empty =
            detect/classify/recommend only.
        auth_marker / auth_absent_marker: optional application-specific strings
            proving an authenticated (resp. logged-out) response; 200 alone is
            not treated as authenticated.
    """
    ident = _caller_identity(ctx)
    if ident["session"] is None:
        return json.dumps({"success": False, "error": "no sandbox session available"})
    result = await _run_sqli_impl(
        ident["session"], hypothesis_id=hypothesis_id, request_ref=request_ref,
        param_name=param_name, param_location=param_location, technique=technique,
        level=level, risk=risk, timeout=timeout, continuation=continuation,
        auth_marker=auth_marker, auth_absent_marker=auth_absent_marker,
        retrieve=ident["retrieve"], baseline=ident["baseline"],
        scan_targets=ident["scan_targets"], agent_id=ident["agent_id"],
        agent_name=ident["agent_name"],
    )
    return json.dumps(result, ensure_ascii=False, default=str)
