"""Targeted out-of-band (OAST) interaction executor (BLACKBOX improvement #7).

Explicitly invoked for ONE selected BLIND / out-of-band hypothesis — never an
automatic scanner. It closes the single biggest black-box gap the other
executors leave open: a vulnerability whose only observable is a *server-initiated
callback* (blind SSRF, blind XXE, blind RCE, OOB SQLi exfil, blind SSTI, blind
deserialization) is invisible to a request/response executor. This one proves
egress deterministically, with a per-attempt unique canary so a callback can
never be confused with another attempt's.

Flow (per call, bounded, single injection):

    hypothesis (worklist #3)
      -> RETRIEVE the concrete stored request through the proxy (NO traffic)
      -> validate origin+port+path against the OPERATOR-authorized scope
         (build_scan_targets) BEFORE any traffic is sent
      -> ALLOCATE a unique OAST canary (interactsh) — a `<token>.<registered>`
         host whose token is unique to THIS attempt
      -> build a class-appropriate payload embedding the canary (or substitute
         the canary into an agent-supplied `{OOB}` / `{OOB_URL}` template)
      -> inject the payload VALUE at exactly ONE named location of the stored
         request and replay it ONCE (the single injection)
      -> wait (bounded) and POLL interactsh, correlating ONLY on this attempt's
         unique token — an interaction for another token is never counted
      -> verdict + sanitized evidence + record on the hypothesis worklist
      -> tear the canary down and scrub.

Hard rules (mirroring the SQLi/authorization executors):
- A positive is `needs_validation`, never `confirmed`: a callback proves the
  input reaches a server-side request-issuing / parser / exec path, NOT the full
  impact of the class — the agent still validates (and an OAST source IP that is
  the tester's OWN egress means a client-side fetch, not server-side SSRF; the
  validation note says so explicitly).
- A blind NEGATIVE (no callback) is `testing`, never `ruled_out`: absence of a
  callback does not disprove the class (egress-filtered target, protocol
  mismatch, delayed/async consumer — see second_order_injection.md).
- Egress-PROOF only: the payload demonstrates a callback; it never dumps data,
  reads files beyond the callback itself, or escalates.
- Scope is checked before ANY traffic, including the canary injection.
- Budget is reserved/settled through the shared hypothesis attempt ledger.
- Secrets (the stored request's cookies/auth/body) are never returned; agent
  free text is secret-redacted. The canary host and inbound interaction
  metadata are our own and safe to surface.

Testability: the interactsh session (allocate/poll/teardown), the request
retrieve, and the single modified-request send are injected so the
orchestration / scope / injection / correlation / classification logic is
deterministically tested with no network. The DEFAULT interactsh provider drives
the sandbox `interactsh-client` and the default send uses the proxy's
`replay_send_raw`; both are contract-based and must be verified live in the
sandbox (see tests + the module-level note), the same standard the real-sqlmap
path in the SQLi executor is held to.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import uuid
from typing import Any, Protocol
from urllib.parse import quote, urlsplit

from agents import RunContextWrapper, function_tool

from strix.tools.agent_metrics.tools import record_activity_tick
from strix.tools.attack_surface.tools import _redact_secrets
from strix.tools.crawl_executor.tools import CrawlTransport, _exec, _read_capped
from strix.tools.hypotheses.tools import (
    DEFAULT_ATTEMPT_BUDGET,
    RESOLVED,
    RESOLVED_MISSING,
    RESOLVED_STALE,
    SLOT_COMPLETED,
    SLOT_FAILED,
    STATUS_BLOCKED,
    STATUS_NEEDS_VALIDATION,
    STATUS_TESTING,
    _record_attempt_impl,
    lookup_hypothesis,
    mark_dispatched,
    reserve_attempt,
    settle_attempt,
)


logger = logging.getLogger(__name__)

_WORK_DIR = "/workspace/.oob"

#: Vulnerability classes whose blind variant is an out-of-band callback. A
#: hypothesis in any other category is refused — this executor only proves egress.
_OOB_CATEGORIES: frozenset[str] = frozenset({
    "ssrf", "xxe", "rce", "sql_injection", "ssti",
    "path_traversal_lfi_rfi", "insecure_deserialization", "nosql_injection",
})

_VALID_LOCATIONS = ("query", "body", "cookie", "header", "body_raw")
#: Locations the first slice does not inject into (ambiguous value boundary).
_UNSUPPORTED_LOCATIONS = ("path",)

# Bounds — clamped, never trusted from the caller.
_DEFAULT_WAIT_S = 20.0
_MAX_WAIT_S = 120.0
_MIN_WAIT_S = 5.0
_SEND_TIMEOUT_S = 40.0
_ALLOC_TIMEOUT_S = 45.0
_OUTPUT_CAP = 2_000_000
_MAX_ATTEMPTS = DEFAULT_ATTEMPT_BUDGET
_DIAG_MAX = 40
_INTERACTIONS_RETURNED = 10

#: A valid HTTP parameter / header name we are willing to inject at. Anything
#: else is refused (keeps the injection boundary unambiguous).
_PARAM_RE = re.compile(r"^[A-Za-z0-9_.\-\[\]]{1,128}$")

#: `{OOB}` -> canary host; `{OOB_URL}` -> `<scheme>://<canary>/`. The default
#: payload per category when the agent supplies no template.
_DEFAULT_TEMPLATE: dict[str, str] = {
    "ssrf": "{OOB_URL}",
    "nosql_injection": "{OOB_URL}",
    "path_traversal_lfi_rfi": "{OOB_URL}",
    "sql_injection": "{OOB_URL}",   # a load_file/OOB stacked probe is agent-built; default is a URL
    "ssti": "{OOB_URL}",
    "rce": "{OOB_URL}",
    "insecure_deserialization": "{OOB_URL}",
    "xxe": (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE r [<!ENTITY % x SYSTEM "{OOB_URL}"> %x;]>\n'
        "<r>oob</r>"
    ),
}

VERDICT_CALLBACK = "oob_callback"
VERDICT_NO_CALLBACK = "no_callback_this_run"
VERDICT_BLOCKED = "blocked"
VERDICT_CANCELLED = "cancelled"


def _clean(value: str | None) -> str:
    return _redact_secrets((value or "").strip())


# --------------------------------------------------------------------------- #
# Operator scope — origin + port + path (identical rule to the SQLi executor)
# --------------------------------------------------------------------------- #


def _parse_scope(scan_targets: list[str] | None) -> list[dict[str, Any]]:
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
# Payload construction + single-location value injection
# --------------------------------------------------------------------------- #


def _build_payload(template: str, canary: str, scheme: str) -> str:
    """Substitute the attempt's unique canary into the template. `{OOB}` is the
    bare host; `{OOB_URL}` is a full URL. CRLF is stripped so our own payload can
    never smuggle a header."""
    canary_url = f"{scheme}://{canary}/"
    out = template.replace("{OOB_URL}", canary_url).replace("{OOB}", canary)
    # Strip CRLF for single-line payloads (prevents our own payload smuggling a
    # header); a multi-line template (e.g. an XXE document) keeps its structure.
    if "\n" not in template:
        out = out.replace("\r", "").replace("\n", "")
    return out


def _split_raw(raw: str) -> tuple[str, str, list[str], str] | None:
    """(request_line, header_block_sep, header_lines, body) or None if malformed."""
    head, sep, body = raw.partition("\r\n\r\n")
    if not sep:
        head, sep, body = raw.partition("\n\n")
    if not sep and "\n" not in raw:
        return None
    lines = head.split("\n")
    if not lines:
        return None
    return lines[0], sep or "\n\n", lines[1:], body


def _replace_kv(text: str, key: str, value: str, *, sep_char: str = "&") -> str | None:
    pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(key)}=([^{re.escape(sep_char)}\s]*)")
    m = pattern.search(text)
    if not m:
        return None
    return text[: m.start(1)] + value + text[m.end(1) :]


def _inject_value(raw: str, param: str, location: str, value: str) -> str | None:
    """Replace the value of ``param`` at ``location`` with ``value`` (already
    canary-substituted). Returns the modified raw request, or None if the
    parameter/location is not present (caller records blocked). Only the one named
    location is touched. ``body_raw`` replaces the entire body with ``value``."""
    parsed = _split_raw(raw)
    if parsed is None:
        return None
    request_line, sep, header_lines, body = parsed

    if location == "body_raw":
        return "\n".join([request_line, *header_lines]) + sep + value

    if location == "query":
        parts = request_line.split(" ")
        if len(parts) < 2 or "?" not in parts[1]:
            return None
        path, _, query = parts[1].partition("?")
        marked = _replace_kv(query, param, quote(value, safe=""))
        if marked is None:
            return None
        parts[1] = f"{path}?{marked}"
        return "\n".join([" ".join(parts), *header_lines]) + sep + body

    if location == "cookie":
        for i, hl in enumerate(header_lines):
            if hl.lower().startswith("cookie:"):
                name, _, val = hl.partition(":")
                marked = _replace_kv(val, param, quote(value, safe=""), sep_char=";")
                if marked is None:
                    return None
                header_lines[i] = f"{name}:{marked}"
                return "\n".join([request_line, *header_lines]) + sep + body
        return None

    if location == "header":
        safe = value.replace("\r", "").replace("\n", "")
        for i, hl in enumerate(header_lines):
            hname, _, _hval = hl.partition(":")
            if hname.strip().lower() == param.lower():
                header_lines[i] = f"{hname}: {safe}"
                return "\n".join([request_line, *header_lines]) + sep + body
        return None

    if location == "body":
        if not body.strip():
            return None
        marked = _replace_kv(body, param, quote(value, safe=""))
        if marked is not None:
            return "\n".join([request_line, *header_lines]) + sep + marked
        jm = re.search(rf'("{re.escape(param)}"\s*:\s*)("[^"]*"|[^,}}\s]+)', body)
        if jm:
            new_body = body[: jm.start(2)] + json.dumps(value) + body[jm.end(2) :]
            return "\n".join([request_line, *header_lines]) + sep + new_body
        return None

    return None


# --------------------------------------------------------------------------- #
# OAST provider (interactsh) + request adapters — injectable for tests
# --------------------------------------------------------------------------- #


class OastProvider(Protocol):
    """Allocate a correlated canary, poll for its interactions, tear it down.
    The live provider drives ``interactsh-client``; tests inject a fake."""

    async def allocate(self) -> dict[str, Any] | None: ...
    async def poll(self, token: str, wait_s: float) -> list[dict[str, Any]]: ...
    async def teardown(self) -> None: ...


_DOMAIN_RE = re.compile(r"\b([a-z0-9]{10,}\.[a-z0-9.\-]+\.(?:oast\.[a-z]+|[a-z0-9.\-]+))\b")


class _InteractshProvider:
    """Default OAST provider: a bounded ``interactsh-client`` session in the
    sandbox, JSON interactions drained to a file. Contract-based against
    interactsh-client's documented interface — VERIFY LIVE in the sandbox (see
    tests/test_oob_executor.py's skip-guarded live path)."""

    def __init__(self, transport: CrawlTransport, *, server: str = "", token: str = "") -> None:
        self._t = transport
        self._server = server.strip()
        self._token = token.strip()
        self._job = f"oob_{uuid.uuid4().hex[:10]}"
        self._outfile = f"{_WORK_DIR}/{self._job}.jsonl"
        self._registered = ""

    async def allocate(self) -> dict[str, Any] | None:
        await _exec(self._t, "mkdir", "-p", _WORK_DIR, timeout=20.0)
        # Launch detached; capture the printed registered domain. -o writes
        # interactions as they arrive; -json makes them machine-readable.
        argv = ["interactsh-client", "-json", "-o", self._outfile]
        if self._server:
            argv += ["-s", self._server]
        if self._token:
            argv += ["-token", self._token]
        inner = " ".join(_shq(a) for a in argv)
        script = (
            f"nohup {inner} > {_shq(self._outfile + '.boot')} 2>&1 &\n"
            f"echo $! > {_shq(self._outfile + '.pid')}\n"
            "sleep 4\n"
            f"cat {_shq(self._outfile + '.boot')}\n"
        )
        _code, out, _timed = await _exec(
            self._t, "sh", "-lc", script, timeout=_ALLOC_TIMEOUT_S
        )
        boot = out.decode("utf-8", errors="replace")
        m = _DOMAIN_RE.search(boot)
        if not m:
            await self.teardown()
            return None
        self._registered = m.group(1)
        return {"registered_domain": self._registered}

    async def poll(self, token: str, wait_s: float) -> list[dict[str, Any]]:
        # interactsh-client polls its server on its own interval; just wait for
        # the bounded window, then read whatever interactions landed in the file.
        await _exec(self._t, "sh", "-lc", f"sleep {int(max(1, wait_s))}", timeout=wait_s + 10)
        text, _truncated = await _read_capped(
            self._t, self._outfile, _OUTPUT_CAP, _WORK_DIR, self._job
        )
        return _parse_interactions(text, token)

    async def teardown(self) -> None:
        with contextlib.suppress(Exception):
            await _exec(self._t, "sh", "-lc", f"pkill -f {_shq(self._job)}", timeout=20.0)
        for suffix in ("", ".boot", ".pid"):
            with contextlib.suppress(Exception):
                await _exec(self._t, "rm", "-f", self._outfile + suffix, timeout=20.0)


def _shq(arg: str) -> str:
    import shlex  # noqa: PLC0415

    return shlex.quote(arg)


def _parse_interactions(text: str, token: str) -> list[dict[str, Any]]:
    """Parse interactsh JSONL, keeping ONLY interactions whose full host carries
    this attempt's unique token. Each kept record is reduced to non-secret
    metadata: protocol, the full interacted host, the remote address, timestamp."""
    tok = token.lower()
    out: list[dict[str, Any]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        full_id = str(rec.get("full-id") or rec.get("unique-id") or rec.get("host") or "")
        if tok not in full_id.lower():
            continue
        out.append({
            "protocol": str(rec.get("protocol") or "unknown").lower(),
            "interacted_host": full_id[:200],
            "remote_address": str(rec.get("remote-address") or "")[:64],
            "timestamp": str(rec.get("timestamp") or "")[:40],
        })
    return out


def _strip_scheme(ref: str) -> str:
    ref = ref.strip()
    return ref.split(":", 1)[1] if ref.lower().startswith("caido:") else ref


async def _retrieve_request(request_id: str) -> dict[str, Any] | None:
    """Retrieve the stored request via the proxy — NO traffic. Returns
    {found, raw, url, method} or None if not stored."""
    from strix.tools.proxy import caido_api  # noqa: PLC0415

    result = await caido_api.view_request(request_id, part="request")
    if result is None or getattr(result.request, "raw", None) is None:
        return None
    raw = result.request.raw.decode("utf-8", errors="replace")
    components = caido_api.parse_raw_request(raw)
    url = caido_api.full_url_from_components(result.request, components, {})
    return {"found": True, "raw": raw, "url": url,
            "method": str(components.get("method", "GET"))}


async def _send_modified(caido_client: Any, *, mutated_raw: str, url: str) -> dict[str, Any]:
    """Send the ONE mutated request through the proxy's replay (scope already
    checked). Contract-based against caido_api.replay_send_raw — VERIFY LIVE."""
    from caido_sdk_client.types import ConnectionInfoInput  # noqa: PLC0415

    from strix.tools.proxy import caido_api  # noqa: PLC0415

    scheme, host, port, _path = _url_parts(url)
    if not host:
        return {"sent": False, "error": "no host"}
    conn = ConnectionInfoInput(host=host, port=port or (443 if scheme == "https" else 80),
                               is_tls=scheme == "https")
    result = await caido_api.replay_send_raw(
        caido_client, raw=mutated_raw.encode("utf-8"), connection=conn
    )
    ok = isinstance(result, dict) and result.get("status") != "ERROR"
    return {"sent": ok, "status": result.get("status") if isinstance(result, dict) else None}


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def _record(
    *, hypothesis_id: str, result_status: str, verdict: str, rationale: str,
    outcome: str, validation_required: str, input_evidence: dict[str, Any] | None,
    agent_id: str | None, agent_name: str | None,
) -> None:
    _record_attempt_impl(
        hypothesis_id=hypothesis_id, tool="interactsh", tool_rationale=rationale,
        outcome=outcome, result_status=result_status, validation_required=validation_required,
        signal=verdict, input_evidence=input_evidence, agent_id=agent_id, agent_name=agent_name,
    )


def _validation_for(verdict: str) -> str:
    if verdict == VERDICT_CALLBACK:
        return ("out-of-band egress is PROVEN for this input, but the class is not yet confirmed: "
                "verify the callback's remote address is the TARGET SERVER, not your own egress "
                "(a client-side fetch produces a callback from the tester's IP, not server-side "
                "SSRF), then demonstrate the class's real impact (internal resource read, file "
                "read, command effect) before confirming — a callback alone is needs_validation")
    if verdict == VERDICT_NO_CALLBACK:
        return ("not closed: no callback this run does NOT rule out the class — the target may "
                "filter egress, the protocol may mismatch, or the consumer may be async/delayed "
                "(see second_order_injection.md). Try another protocol/location or a longer wait")
    return "re-establish a reachable target / working canary and retry; this run was inconclusive"


async def _run_oob_impl(
    transport: CrawlTransport,
    *,
    hypothesis_id: str,
    request_ref: str,
    injection_location: str = "query",
    param_name: str = "",
    payload_template: str = "",
    canary_scheme: str = "http",
    wait_s: float | None = None,
    retrieve: Any = None,
    send: Any = None,
    oast: Any = None,
    caido_client: Any = None,
    scan_targets: list[str] | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    hid = (hypothesis_id or "").strip()
    ref = (request_ref or "").strip()
    location = (injection_location or "query").strip().lower()
    param = (param_name or "").strip()
    scheme = "https" if canary_scheme.strip().lower() == "https" else "http"

    hypothesis = lookup_hypothesis(hid)
    if hypothesis is None:
        return {"success": False, "error": f"no hypothesis {hypothesis_id!r} (create it first)"}
    category = str(hypothesis.get("vuln_category") or "")
    if category not in _OOB_CATEGORIES:
        return {"success": False,
                "error": f"hypothesis {hid} is '{category}', not an out-of-band class "
                         f"({sorted(_OOB_CATEGORIES)})"}
    if not ref:
        return {"success": False, "error": "request_ref is required (a stored proxy request id)"}
    if location in _UNSUPPORTED_LOCATIONS:
        return {"success": False,
                "error": f"injection_location {location!r} is not supported in this slice "
                         f"(supported: {list(_VALID_LOCATIONS)})"}
    if location not in _VALID_LOCATIONS:
        return {"success": False, "error": f"injection_location must be one of {_VALID_LOCATIONS}"}
    if location != "body_raw" and not _PARAM_RE.match(param):
        return {"success": False,
                "error": "param_name is required (and must be a valid name) unless "
                         "injection_location='body_raw'"}

    template = payload_template.strip() or _DEFAULT_TEMPLATE.get(category, "{OOB_URL}")
    intended_actor = str(hypothesis.get("actor_ref") or "anonymous")
    rationale = (
        f"targeted out-of-band egress test for a blind {category} hypothesis; a uniquely-"
        f"correlated interactsh canary injected at {location} "
        f"{('param ' + repr(param)) if location != 'body_raw' else '(raw body)'}; "
        f"intended_actor={intended_actor}"
    )

    def _blocked(outcome: str, validation: str, resolved: str,
                 extra: dict[str, Any] | None = None) -> dict[str, Any]:
        ev = {"kind": "request", "ref": ref[:256], "resolved_state": resolved}
        _record(hypothesis_id=hid, result_status=STATUS_BLOCKED, verdict=VERDICT_BLOCKED,
                rationale=rationale, outcome=outcome, validation_required=validation,
                input_evidence=ev, agent_id=agent_id, agent_name=agent_name)
        out = {"success": True, "hypothesis_id": hid, "ran": False,
               "result_status": STATUS_BLOCKED, "injection_location": location,
               "intended_actor": intended_actor, "outcome": outcome, "suggestion": validation}
        if extra:
            out.update(extra)
        return out

    retrieve_fn = retrieve or _retrieve_request
    send_fn = send or _send_modified

    # 1) RETRIEVE the stored request — NO traffic yet.
    try:
        got = await retrieve_fn(_strip_scheme(ref))
    except Exception:  # noqa: BLE001
        return _blocked("proxy unavailable; could not retrieve the stored request",
                        "capture the request in the proxy and attach its id, then retry",
                        RESOLVED_MISSING)
    if not got or not got.get("found") or not got.get("raw"):
        return _blocked("stored request not found for this reference",
                        "capture the request in the proxy and attach its id, then retry",
                        RESOLVED_MISSING)
    raw = str(got["raw"])
    url = str(got.get("url") or "")

    # 2) SCOPE — validate origin+port+path BEFORE any traffic (incl. the canary).
    in_scope, scope_reason = _scope_check(url, scan_targets)
    if not in_scope:
        return _blocked(f"destination not in operator scope: {scope_reason}; not testing",
                        "confirm the target (host/port/path) is authorized with the operator",
                        RESOLVED, {"in_scope": False})

    # 3) ALLOCATE a unique canary (OAST). Scope is already enforced above. The
    # default provider uses a self-hosted interactsh server when the operator has
    # configured one (STRIX_INTERACTSH_SERVER [+ _TOKEN]) — more reliable and
    # WAF-resistant than the public servers — else interactsh-client's default.
    token = f"oob{uuid.uuid4().hex[:16]}"
    provider: OastProvider = oast or _InteractshProvider(
        transport,
        server=os.environ.get("STRIX_INTERACTSH_SERVER", ""),
        token=os.environ.get("STRIX_INTERACTSH_TOKEN", ""),
    )
    try:
        alloc = await provider.allocate()
    except Exception:  # noqa: BLE001
        alloc = None
    if not alloc or not alloc.get("registered_domain"):
        return _blocked("could not allocate an OAST canary (interactsh unavailable or no "
                        "egress from the sandbox to the interactsh server)",
                        "verify interactsh-client works in the sandbox / set "
                        "STRIX_INTERACTSH_SERVER for a self-hosted server, then retry", RESOLVED)
    canary = f"{token}.{alloc['registered_domain']}"

    # 4) Build the payload and inject it at the single named location.
    payload = _build_payload(template, canary, scheme)
    mutated = _inject_value(raw, param, location, payload)
    if mutated is None:
        await _safe_teardown(provider)
        return _blocked(
            f"could not inject at {location!r} "
            f"({'param ' + repr(param) if location != 'body_raw' else 'raw body'}): not present "
            "or the location is ambiguous",
            "re-check the parameter's actual location, or capture a request that carries it",
            RESOLVED, {"canary_scheme": scheme})

    # 5) Reserve ONE cumulative attempt slot right before the single injection.
    reservation = reserve_attempt(hid, tool="interactsh", max_attempts=_MAX_ATTEMPTS)
    if not reservation.get("reserved"):
        await _safe_teardown(provider)
        return _blocked(
            f"attempt budget exhausted for this hypothesis "
            f"({reservation.get('used')}/{reservation.get('max')} used this run)",
            "do not auto-retry; escalate to manual review or deliberately raise the budget",
            RESOLVED,
            {"attempt_budget": {"used": reservation.get("used"), "max": reservation.get("max"),
                                "remaining": 0}})
    rid = str(reservation["reservation_id"])
    wait = max(_MIN_WAIT_S, min(wait_s or _DEFAULT_WAIT_S, _MAX_WAIT_S))
    input_evidence = {"kind": "request", "ref": ref[:256], "resolved_state": RESOLVED,
                      "summary": f"{got.get('method', '?')} injected at {location}"}

    # Persist dispatch BEFORE sending: once the injection may have left, a cancel
    # must CONSUME the attempt, never refund it.
    mark_dispatched(hid, rid)
    try:
        # 6) Send the ONE mutated request (the single injection).
        try:
            send_result = await asyncio.wait_for(
                send_fn(caido_client, mutated_raw=mutated, url=url), timeout=_SEND_TIMEOUT_S
            )
        except Exception:  # noqa: BLE001 - any send failure degrades to blocked, never a result
            send_result = {"sent": False}
        if not send_result.get("sent"):
            await _safe_teardown(provider)
            settle_attempt(hid, rid, state=SLOT_FAILED)
            return _blocked("the injected request could not be sent (target unreachable from the "
                            "proxy, or the replay failed) — not an OOB result",
                            "re-verify connectivity/session and retry", RESOLVED_STALE,
                            {"canary": canary})

        # 7) Wait (bounded) and poll, correlating ONLY on this attempt's token.
        try:
            interactions = await provider.poll(token, wait)
        except Exception:  # noqa: BLE001
            interactions = []
    except asyncio.CancelledError:
        await asyncio.shield(_safe_teardown(provider))
        settle_attempt(hid, rid, state=SLOT_FAILED)
        _record(hypothesis_id=hid, result_status=STATUS_BLOCKED, verdict=VERDICT_CANCELLED,
                rationale=rationale, outcome="oob test cancelled after dispatch; attempt consumed; "
                "canary torn down", validation_required="re-run the targeted OOB test",
                input_evidence=input_evidence, agent_id=agent_id, agent_name=agent_name)
        raise
    finally:
        await _safe_teardown(provider)

    # 8) Classify on the correlated interactions.
    protocols = sorted({i.get("protocol", "unknown") for i in interactions})
    if interactions:
        result_status, verdict = STATUS_NEEDS_VALIDATION, VERDICT_CALLBACK
        outcome = _clean(f"OOB callback received ({len(interactions)} interaction(s), "
                         f"protocols={protocols}) correlated to this attempt's unique canary")
    else:
        result_status, verdict = STATUS_TESTING, VERDICT_NO_CALLBACK
        outcome = _clean(f"no OOB callback within {int(wait)}s for this attempt's canary")

    validation = _validation_for(verdict)
    settle = settle_attempt(hid, rid, state=SLOT_COMPLETED)
    _record(hypothesis_id=hid, result_status=result_status, verdict=verdict, rationale=rationale,
            outcome=outcome, validation_required=validation, input_evidence=input_evidence,
            agent_id=agent_id, agent_name=agent_name)
    record_activity_tick(agent_id)

    return {
        "success": True, "hypothesis_id": hid, "ran": True, "in_scope": True,
        "vuln_category": category, "injection_location": location, "intended_actor": intended_actor,
        "canary": canary, "canary_scheme": scheme,
        "result_status": result_status, "verdict": verdict,
        "callback_received": bool(interactions),
        "interaction_count": len(interactions),
        "protocols": protocols,
        "interactions": interactions[:_INTERACTIONS_RETURNED],
        "wait_s": wait,
        "attempt_budget": {"used": settle.get("used"), "max": settle.get("max"),
                           "remaining": settle.get("remaining")},
        "note": "a callback proves out-of-band egress, not the full class — a positive is "
                "needs_validation, never confirmed; confirm the source IP is the target server "
                "(not your own egress) and demonstrate real impact. No callback is NOT a negative "
                "for the class (testing, not ruled_out).",
    }


async def _safe_teardown(provider: OastProvider) -> None:
    with contextlib.suppress(Exception):
        await provider.teardown()


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
    retrieve = inner.get("oob_retrieve")
    send = inner.get("oob_send")
    oast = inner.get("oob_oast")
    return {
        "agent_id": agent_id, "agent_name": agent_name,
        "retrieve": retrieve if callable(retrieve) else None,
        "send": send if callable(send) else None,
        "oast": oast,
        "scan_targets": inner.get("scan_targets"),
        "caido_client": inner.get("caido_client"),
        "session": inner.get("sandbox_session"),
    }


@function_tool(timeout=200)
async def run_oob_test(
    ctx: RunContextWrapper,
    hypothesis_id: str,
    request_ref: str,
    injection_location: str = "query",
    param_name: str = "",
    payload_template: str = "",
    canary_scheme: str = "http",
    wait_s: float | None = None,
) -> str:
    """Confirm out-of-band (blind) egress for ONE hypothesis via a correlated OAST callback.

    Explicitly invoked for a single blind/out-of-band hypothesis (blind SSRF,
    XXE, RCE, OOB SQLi, SSTI, deserialization) — NOT an automatic scanner. It
    retrieves the hypothesis's stored request through the proxy (no traffic),
    validates the destination against operator-authorized scope BEFORE sending
    anything, allocates a UNIQUE interactsh canary for this attempt, injects a
    class-appropriate payload (or your `{OOB}`/`{OOB_URL}` template) at exactly
    one named location, replays the request ONCE, then waits and polls interactsh
    correlating ONLY on this attempt's unique token. It records the attempt on the
    hypothesis automatically and tears the canary down afterward.

    A callback is proof of out-of-band egress but is `needs_validation`, never
    `confirmed`: verify the callback came from the TARGET SERVER (not your own
    egress — a client-side fetch calls back from the tester's IP) and demonstrate
    the class's real impact. No callback is `testing`, never `ruled_out` — a blind
    negative does not disprove the class (egress filtering, protocol mismatch,
    async consumer).

    Args:
        hypothesis_id: An out-of-band-class hypothesis id from `query_hypotheses`
            (ssrf / xxe / rce / sql_injection / ssti / path_traversal_lfi_rfi /
            insecure_deserialization / nosql_injection).
        request_ref: The stored proxy request id to inject into and replay.
        injection_location: query / body / cookie / header / body_raw — the single
            location whose value is replaced with the payload. `body_raw` replaces
            the whole body (use for an XXE XML document). `path` is not supported
            in this slice.
        param_name: The parameter / header name to inject at (required unless
            `injection_location='body_raw'`).
        payload_template: Optional. A payload containing `{OOB}` (the bare canary
            host) and/or `{OOB_URL}` (`scheme://canary/`). Empty = a sensible
            default per class (a `{OOB_URL}` for SSRF-like classes; a SYSTEM-entity
            XML document for XXE).
        canary_scheme: `http` (default) or `https` for the `{OOB_URL}` substitution.
        wait_s: Bounded seconds to wait for a callback (default 20, 5-120).
    """
    ident = _caller_identity(ctx)
    if ident["session"] is None:
        return json.dumps({"success": False, "error": "no sandbox session available"})
    result = await _run_oob_impl(
        ident["session"], hypothesis_id=hypothesis_id, request_ref=request_ref,
        injection_location=injection_location, param_name=param_name,
        payload_template=payload_template, canary_scheme=canary_scheme, wait_s=wait_s,
        retrieve=ident["retrieve"], send=ident["send"], oast=ident["oast"],
        caido_client=ident["caido_client"], scan_targets=ident["scan_targets"],
        agent_id=ident["agent_id"], agent_name=ident["agent_name"],
    )
    return json.dumps(result, ensure_ascii=False, default=str)
