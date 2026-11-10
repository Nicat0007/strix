"""Targeted, browser-backed XSS executor (BLACKBOX improvement #6).

Explicitly invoked for ONE selected `xss` hypothesis. The flow is:

    hypothesis (#3) + explicit input location + parameter/source + rationale
      -> validate the request/URL is consistent with the hypothesis's endpoint
      -> scope-check origin/port/path vs operator scope BEFORE any traffic
      -> baseline the target (availability; auth state for an authenticated test)
      -> send ONE unique, inert reflection marker; locate reflections and analyse
         their context (HTML text / attribute / script-string / URL / encoded /
         JSON / plain / unknown) with bounded, honestly-heuristic parsing
      -> build ONE bounded, context-appropriate payload carrying a UNIQUE
         execution canary, plus an encoded negative control
      -> run it in an ISOLATED browser context with normal web security + CSP
         left ON; prove execution only via the canary GLOBAL the page itself
         sets (never console text, a dialog, payload-in-HTML, or the harness's
         own read of the canary)
      -> verdict + sanitized evidence + record on the hypothesis worklist.

First slice: reflected XSS on `query`/`form_body` inputs and a bounded `dom`
source->sink path when the browser runtime supports it. Header/cookie/path
locations and all stored-XSS workflows are explicitly `unsupported` here, and no
persistent writes are performed. A positive is `needs_validation` with execution
evidence — never auto-`confirmed`, and browser execution proves code execution in
THAT tested context, not cross-user impact. No crawling, no payload spraying:
one marker + one payload + one encoded control per attempt.

This module drives the sandbox `agent-browser` CLI (per
`skills/tooling/agent_browser.md`) and an HTTP fetch through the same sandbox,
both injected so the orchestration/verdict logic is deterministically testable.
It never disables CSP or web security to make a test pass.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
import re
import secrets
import uuid
from typing import Any, Protocol
from urllib.parse import quote, urlsplit

from agents import RunContextWrapper, function_tool

from strix.tools.agent_metrics.tools import record_activity_tick
from strix.tools.attack_surface.tools import _redact_secrets
from strix.tools.crawl_executor.tools import CrawlTransport, _actor_headers, _read_capped
from strix.tools.hypotheses.tools import (
    RESOLVED,
    RESOLVED_MISSING,
    SLOT_CANCELLED,
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
from strix.tools.sqli_executor.tools import (
    _BODY_SCAN_CAP,
    _MAX_ATTEMPTS,
    _scope_check,
)


logger = logging.getLogger(__name__)

_XSS_CATEGORY = "xss"
_DEFAULT_ACCOUNTS_PATH = "/workspace/recon/auth_accounts.jsonl"

# Supported input locations in this slice; everything else -> unsupported.
LOC_QUERY = "query"
LOC_FORM = "form_body"
LOC_DOM = "dom"
_SUPPORTED_LOCATIONS = (LOC_QUERY, LOC_FORM, LOC_DOM)
_DEFERRED_LOCATIONS = ("header", "cookie", "path", "stored")

# Heuristic reflection contexts.
CTX_HTML_TEXT = "html_text"
CTX_ATTRIBUTE = "attribute"
CTX_SCRIPT_STRING = "script_string"
CTX_URL = "url"
CTX_ENCODED = "encoded"
CTX_JSON = "json"
CTX_PLAIN = "plain_text"
CTX_UNKNOWN = "unknown"
CTX_NOT_REFLECTED = "not_reflected"

# Verdicts.
V_EXEC = "execution_observed"
V_REFLECTED = "reflected_without_execution"
V_NOEXEC = "no_execution_observed_this_test"
V_BLOCKED = "blocked"
V_INVALID_SESSION = "invalid_session"
V_UNSUPPORTED = "unsupported"
V_INCONCLUSIVE = "inconclusive"

_ENTITY_HINTS = ("&lt;", "&gt;", "&quot;", "&#39;", "&#x27;", "&#x3c;", "&#x3e;", "&amp;")

#: Collection-point bounds. _HTTP_MAX_BYTES aborts an oversized download
#: (streaming limit); _BROWSER_OUT_CAP truncates browser CLI output when read.
_HTTP_MAX_BYTES = 2_000_000
_BROWSER_OUT_CAP = 200_000


# --------------------------------------------------------------------------- #
# Provider contracts (injected; sandbox-backed defaults below)
# --------------------------------------------------------------------------- #


class XssHttp(Protocol):
    async def __call__(
        self, url: str, *, method: str, headers: dict[str, str], body: str | None,
    ) -> dict[str, Any]: ...


class XssBrowser(Protocol):
    async def __call__(
        self, *, nav_url: str, session: str, canary_global: str, canary_token: str,
        headers: dict[str, str], form_body: str, expect_execution: bool,
        excluded_origins: list[str] | None = None,
    ) -> dict[str, Any]: ...


def _clean(value: str | None) -> str:
    return _redact_secrets((value or "").strip())


# --------------------------------------------------------------------------- #
# Reflection marker + bounded, honest context analysis
# --------------------------------------------------------------------------- #


def _nonce() -> str:
    return secrets.token_hex(6)


def _reflection_marker(nonce: str) -> str:
    """A unique, inert reflection probe. Alnum locator (`zqx<nonce>`) plus the four
    canary metacharacters so the analysis can tell raw reflection from encoded
    output. It injects no executable construct (`<>` has no tag name) — reflection
    alone is never treated as XSS; the browser step is the only proof."""
    return f"zqx{nonce}'\"<>xqz"


def _locator(nonce: str) -> str:
    return f"zqx{nonce}"


def _occurrence_context(body: str, idx: int, locator: str) -> tuple[str, bool]:
    """Classify ONE reflection occurrence's HTML context and whether its special
    chars were encoded. Deliberately bounded/heuristic — labelled as such."""
    window_lo = max(0, idx - 600)
    before = body[window_lo:idx]
    span = body[idx:idx + len(locator) + 12]
    encoded = any(h in span for h in _ENTITY_HINTS) and not ("<>" in span or "'\"" in span)

    low_before = before.lower()
    # Inside a <script> block?
    last_script_open = low_before.rfind("<script")
    last_script_close = low_before.rfind("</script")
    if last_script_open != -1 and last_script_open > last_script_close:
        return CTX_SCRIPT_STRING, encoded

    # Inside a tag (an unclosed '<' with no '>' between it and the reflection)?
    last_lt = before.rfind("<")
    last_gt = before.rfind(">")
    if last_lt != -1 and last_lt > last_gt:
        tag_frag = before[last_lt:]
        m = re.search(r"([a-zA-Z-]+)\s*=\s*[\"']?[^\"'=<>]*$", tag_frag)
        attr = (m.group(1).lower() if m else "")
        if attr in ("href", "src", "action", "formaction", "data", "xlink:href"):
            return CTX_URL, encoded
        return CTX_ATTRIBUTE, encoded
    return CTX_HTML_TEXT, encoded


def _analyze_context(body: str, nonce: str, content_type: str) -> dict[str, Any]:
    """Locate the inert marker and classify its reflection context(s). Returns a
    structured, bounded result; `primary_context` drives payload selection but is
    explicitly heuristic and never, by itself, a verdict."""
    capped = (body or "")[:_BODY_SCAN_CAP]
    locator = _locator(nonce)
    ct = (content_type or "").lower()
    occurrences: list[dict[str, Any]] = []
    start = 0
    low = capped.lower()
    loc_low = locator.lower()
    while len(occurrences) < 20:
        i = low.find(loc_low, start)
        if i == -1:
            break
        if "application/json" in ct:
            occurrences.append({"context": CTX_JSON, "encoded": True})
        elif "text/plain" in ct:
            occurrences.append({"context": CTX_PLAIN, "encoded": True})
        else:
            ctx, enc = _occurrence_context(capped, i, locator)
            occurrences.append({"context": (CTX_ENCODED if enc else ctx), "encoded": enc,
                                "structural_context": ctx})
        start = i + len(loc_low)

    if not occurrences:
        return {"reflected": False, "primary_context": CTX_NOT_REFLECTED,
                "occurrences": [], "heuristic": True}
    # Prefer an unencoded, execution-relevant context as primary.
    priority = [CTX_SCRIPT_STRING, CTX_HTML_TEXT, CTX_ATTRIBUTE, CTX_URL,
                CTX_ENCODED, CTX_JSON, CTX_PLAIN, CTX_UNKNOWN]
    ranked = sorted(occurrences,
                    key=lambda o: priority.index(o["context"]) if o["context"] in priority else 99)
    return {"reflected": True, "primary_context": ranked[0]["context"],
            "any_raw": any(not o["encoded"] for o in occurrences),
            "occurrences": occurrences, "heuristic": True}


# --------------------------------------------------------------------------- #
# Bounded, context-appropriate payload carrying a unique execution canary
# --------------------------------------------------------------------------- #


def _build_payload(context: str, canary_global: str, token: str) -> dict[str, Any]:
    """ONE bounded payload per context. If it EXECUTES, it assigns
    ``window[canary_global] = token`` — a value the harness never sets, so the
    global holding the token is proof the page executed injected script. Some
    contexts need a user gesture; that requirement is reported, never silently
    skipped."""
    setter = f"window['{canary_global}']='{token}'"
    if context == CTX_SCRIPT_STRING:
        return {"payload": f"';{setter};//", "interaction_required": ""}
    if context == CTX_ATTRIBUTE:
        return {"payload": f'"><script>{setter}</script>', "interaction_required": ""}
    if context == CTX_URL:
        # javascript: URLs require a navigation/click gesture — reported.
        return {"payload": f"javascript:{setter}", "interaction_required": "click"}
    if context in (CTX_HTML_TEXT, CTX_UNKNOWN):
        return {"payload": f'<img src=x onerror="{setter}">', "interaction_required": ""}
    # encoded / json / plain: execution not expected; still probed honestly.
    return {"payload": f'<img src=x onerror="{setter}">', "interaction_required": "",
            "execution_expected": False}


def _encoded_control(payload: str) -> str:
    """A negative control: the same payload HTML-entity-encoded, which must NOT
    execute. If it fires, the result is inconclusive (the harness/engine is
    misbehaving), never a bypass."""
    return (payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


# --------------------------------------------------------------------------- #
# Sandbox-backed default providers (exercised live only inside the sandbox)
# --------------------------------------------------------------------------- #


async def _exec(transport: CrawlTransport, *argv: str, timeout: float) -> tuple[int, str]:
    try:
        result = await transport.exec(*argv, timeout=timeout, shell=False)
    except Exception:  # noqa: BLE001
        return 1, ""
    code = int(getattr(result, "exit_code", getattr(result, "returncode", 0)) or 0)
    out = getattr(result, "stdout", "") or getattr(result, "output", "") or ""
    if isinstance(out, bytes):
        out = out.decode("utf-8", "replace")
    return code, out


def _header_curl_args(headers: dict[str, str]) -> list[str]:
    args: list[str] = []
    for name, value in headers.items():
        args += ["-H", f"{name}: {value}"]
    return args


def _default_http(transport: CrawlTransport) -> XssHttp:
    """HTTP fetch via the sandbox's curl (honours the sandbox proxy env). Returns
    status/headers/body/final_url; never follows into a different scope (``-i`` is
    captured, redirects are NOT auto-followed: no ``-L``)."""
    async def http(url: str, *, method: str, headers: dict[str, str],
                   body: str | None) -> dict[str, Any]:
        # --max-filesize bounds the DOWNLOAD at collection (a streaming limit that
        # aborts an oversized body); _BODY_SCAN_CAP below is a separate
        # post-buffer truncation applied only for context analysis.
        argv = ["curl", "-sS", "-i", "--max-time", "20", "--max-filesize", str(_HTTP_MAX_BYTES),
                "-X", method, *_header_curl_args(headers)]
        if body is not None:
            argv += ["--data-raw", body]
        argv += [url]
        code, out = await _exec(transport, *argv, timeout=30.0)
        if code != 0 or not out:
            return {"ok": False, "status": None, "headers": {}, "body": "", "final_url": url,
                    "error": "fetch failed"}
        head, _, raw_body = out.partition("\r\n\r\n")
        if not raw_body:
            head, _, raw_body = out.partition("\n\n")
        lines = head.splitlines()
        status = None
        hdrs: dict[str, str] = {}
        if lines and lines[0].startswith("HTTP/"):
            parts = lines[0].split(" ", 2)
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdrs[k.strip()] = v.strip()
        return {"ok": True, "status": status, "headers": hdrs,
                "body": raw_body[:_BODY_SCAN_CAP], "final_url": url, "error": ""}
    return http


def _parse_eval_json(out: str) -> dict[str, Any]:
    """agent-browser `eval` returns its JS result JSON-encoded — a bare object
    comes back as (often pretty-printed, multi-line) JSON. Parse the WHOLE
    payload, then tolerate a second layer (JSON.stringify) and the
    `{success,data,error}` envelope. Bounded at the collection point."""
    text = (out or "").strip()[:_BROWSER_OUT_CAP]
    if not text:
        return {}
    try:
        v: Any = json.loads(text)
    except (ValueError, TypeError):
        try:  # fallback: last non-empty line (single-value outputs)
            v = json.loads(text.splitlines()[-1])
        except (ValueError, TypeError, IndexError):
            return {}
    for _ in range(2):
        if isinstance(v, str):
            try:
                v = json.loads(v)
            except (ValueError, TypeError):
                return {}
        else:
            break
    if isinstance(v, dict) and "c" not in v and isinstance(v.get("data"), dict):
        v = v["data"]
    return v if isinstance(v, dict) else {}


def _parse_requests(out: str) -> list[str]:
    """Best-effort list of request URLs agent-browser recorded (for scope
    attribution / the excluded-origin counter). Bounded."""
    text = (out or "")[:_BROWSER_OUT_CAP]
    urls = re.findall(r"https?://[^\s\"'<>]+", text)
    return urls[:100]


def _form_submit_js(action: str, fields: dict[str, str]) -> str:
    """Synthesize and submit a real POST form (preserves method=POST and the
    body parameter location). Values are injected RAW (the browser encodes on
    submit), so the reflected POST response carries the true payload."""
    parts = [
        "var f=document.createElement('form');", "f.method='POST';",
        f"f.action={json.dumps(action)};",
    ]
    for k, val in fields.items():
        parts.append(
            "(function(){var i=document.createElement('input');i.type='hidden';"
            f"i.name={json.dumps(k)};i.value={json.dumps(val)};f.appendChild(i);}})();"
        )
    parts.append("document.body.appendChild(f);f.submit();")
    return "".join(parts)


def _default_browser(transport: CrawlTransport) -> XssBrowser:
    """Drive the sandbox agent-browser CLI in an ISOLATED session. Normal web
    security + CSP left ON. Request-level scope: before the real navigation, each
    explicitly-excluded origin is armed as a CDP abort route, so an attempted
    out-of-scope request is BLOCKED (not merely detected after the fact). Reads
    ONLY the canary global via `eval` (the read never sets it). Credentials go via
    `--headers`, never echoed. Best-effort session cleanup."""
    async def browser(*, nav_url: str, session: str, canary_global: str, canary_token: str,
                      headers: dict[str, str], form_body: str, expect_execution: bool,
                      excluded_origins: list[str] | None = None) -> dict[str, Any]:
        async def ab(*args: str, timeout: float) -> tuple[int, str]:
            return await _exec(transport, "agent-browser", "--session", session, *args,
                               timeout=timeout)

        launch = ["--json"]
        if headers:
            launch += ["--headers", json.dumps(headers)]
        code, _o = await ab(*launch, "open", "about:blank", timeout=45.0)
        if code != 0:
            await ab("close", timeout=15.0)
            return {"ok": False, "canary_fired": False, "error": "browser launch failed"}
        # Request-level scope: abort known excluded destinations BEFORE navigating.
        for ex in (excluded_origins or []):
            host = ex.rstrip("/")
            await ab("network", "route", f"{host}/**", "--abort", timeout=15.0)
            await ab("network", "route", f"{host}", "--abort", timeout=15.0)
        if form_body:
            await ab("open", nav_url, timeout=45.0)
            with contextlib.suppress(Exception):
                fields = json.loads(form_body)
            js = _form_submit_js(nav_url, fields if isinstance(fields, dict) else {})
            await ab("eval", "-b", base64.b64encode(js.encode()).decode(), timeout=25.0)
        else:
            code, _o = await ab("open", nav_url, timeout=45.0)
            if code != 0:
                await ab("close", timeout=15.0)
                return {"ok": False, "canary_fired": False, "error": "navigation failed"}
        # Settle: let navigation finish AND async handlers (e.g. an <img onerror>
        # after its request fails) run before the canary is read. Without this the
        # oracle reads too early and a real execution looks like "not fired".
        await ab("wait", "--load", "networkidle", timeout=20.0)
        await ab("wait", "600", timeout=5.0)
        probe = (f"(function(){{return {{c:(window['{canary_global}']==='{canary_token}'),"
                 f"origin:location.origin,url:location.href}};}})()")
        _c, out = await ab("eval", "-b", base64.b64encode(probe.encode()).decode(), timeout=25.0)
        _r, reqout = await ab("network", "requests", timeout=15.0)
        await ab("close", timeout=15.0)
        data = _parse_eval_json(out)
        return {"ok": True, "canary_fired": bool(data.get("c")),
                "navigated_origin": str(data.get("origin") or ""),
                "final_url": str(data.get("url") or nav_url),
                "dialog_fired": False, "console_only": False,
                "requests": _parse_requests(reqout), "error": ""}
    return browser


# --------------------------------------------------------------------------- #
# Verdict
# --------------------------------------------------------------------------- #


def _verdict(
    *, reflected: bool, primary_context: str, canary_fired: bool, origin_ok: bool,
    control_fired: bool, csp_present: bool, browser_ok: bool, interaction_required: str,
) -> tuple[str, str, str, str]:
    if not browser_ok:
        return (V_INCONCLUSIVE, STATUS_BLOCKED,
                "the browser did not complete navigation/execution-probe — inconclusive",
                "re-run with a reachable browser runtime; this is not a negative result")
    if control_fired:
        # The encoded negative control must never execute. If it did, trust nothing.
        return (V_INCONCLUSIVE, STATUS_BLOCKED,
                ("the ENCODED negative control executed — the browser/engine result cannot be "
                 "trusted for this attempt; not a bypass"),
                "investigate the harness/runtime; do not report")
    if canary_fired and origin_ok:
        return (V_EXEC, STATUS_NEEDS_VALIDATION,
                ("the injected canary executed in the tested document origin (unique per-attempt "
                 "global set by the page itself, not by a dialog, console message, payload text, "
                 "or the harness read) — code execution proven IN THIS CONTEXT"),
                ("needs_validation: manually confirm real impact (this proves execution in the "
                 "tested input/context, NOT cross-user impact); NEVER auto-confirmed"
                 + (f". Interaction required: {interaction_required}." if interaction_required
                    else "")))
    if canary_fired and not origin_ok:
        return (V_INCONCLUSIVE, STATUS_BLOCKED,
                ("a canary fired but could not be attributed to the tested document origin — "
                 "inconclusive, not counted as proof"),
                "re-run; ensure the execution is attributed to the tested origin")
    if csp_present:
        return (V_BLOCKED, STATUS_BLOCKED,
                ("the payload did not execute and the response carries a Content-Security-Policy "
                 "— execution appears CSP-restricted (CSP left ON; never disabled)"),
                ("record the CSP restriction; a different context/gadget may still apply — scoped "
                 "to this input/context only"))
    if reflected:
        return (V_REFLECTED, STATUS_TESTING,
                (f"the marker reflected (heuristic context: {primary_context}) but the "
                 "context-appropriate payload did NOT execute in the browser — reflection is not "
                 "XSS"),
                ("scoped to this input/context/variant only; try another context/gadget if "
                 "warranted — does NOT close siblings or the XSS class"))
    return (V_NOEXEC, STATUS_TESTING,
            ("no server reflection of the marker and no browser execution this test — note an "
             "absent server reflection does NOT rule out DOM XSS"),
            ("scoped to this input/context/variant only; a DOM source->sink path may still apply "
             "— does NOT close siblings or the XSS class"))


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def _record(*, hid: str, verdict: str, status: str, outcome: str, validation: str,
            evidence: dict[str, Any], rationale: str, agent_id: str | None,
            agent_name: str | None) -> None:
    _record_attempt_impl(
        hypothesis_id=hid, tool="xss_browser_probe", tool_rationale=rationale,
        outcome=_clean(outcome), result_status=status, validation_required=validation,
        signal=verdict, input_evidence=evidence, agent_id=agent_id, agent_name=agent_name,
    )


async def _run_xss_impl(
    *,
    hypothesis_id: str,
    url: str,
    input_location: str,
    param_or_source: str,
    rationale: str,
    actor_ref: str = "",
    auth_marker: str = "",
    dom_source: str = "",
    accounts_text: str = "",
    http: XssHttp | None = None,
    browser: XssBrowser | None = None,
    transport: Any = None,
    scan_targets: list[str] | None = None,
    excluded_origins: list[str] | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    hid = (hypothesis_id or "").strip()
    loc = (input_location or "").strip().lower()
    target = (url or "").strip()
    hypothesis = lookup_hypothesis(hid)
    rtext = (f"targeted XSS probe: location={loc!r} param/source={param_or_source!r} on the "
             "hypothesis's concrete request")

    def _result(verdict: str, status: str, outcome: str, validation: str,
                extra: dict[str, Any] | None = None, record: bool = True) -> dict[str, Any]:
        evidence = {"kind": "xss_attempt", "ref": target[:256], "input_location": loc,
                    "resolved_state": RESOLVED, **((extra or {}).get("_evidence", {}))}
        if record:
            _record(hid=hid, verdict=verdict, status=status, outcome=outcome, validation=validation,
                    evidence=evidence, rationale=rtext, agent_id=agent_id, agent_name=agent_name)
        out = {"success": True, "hypothesis_id": hid, "verdict": verdict, "result_status": status,
               "input_location": loc, "param_or_source": param_or_source, "outcome": outcome,
               "next_action": validation}
        if extra:
            out.update({k: v for k, v in extra.items() if k != "_evidence"})
        return out

    # 1) Explicit subject + consistency.
    if hypothesis is None:
        return {"success": False, "error": f"no hypothesis {hypothesis_id!r}"}
    if hypothesis.get("vuln_category") != _XSS_CATEGORY:
        return {"success": False, "error": f"hypothesis {hid} is not an 'xss' hypothesis"}
    if not target:
        return {"success": False, "error": "url is required (the concrete injection point)"}
    if not param_or_source.strip():
        return {"success": False, "error": "param_or_source is required (the tested input)"}
    if not rationale.strip():
        return {"success": False, "error": "rationale is required"}
    if loc in _DEFERRED_LOCATIONS or loc not in _SUPPORTED_LOCATIONS:
        return _result(V_UNSUPPORTED, STATUS_BLOCKED,
                       f"input location {loc!r} is not supported in this slice "
                       f"(supported: {_SUPPORTED_LOCATIONS}; deferred: {_DEFERRED_LOCATIONS} and "
                       "all stored-XSS workflows)",
                       "defer to a future slice or a manual test; no persistent writes are made")
    res_hint = str(hypothesis.get("resource") or "").strip()
    if res_hint and res_hint not in target and res_hint.lstrip("/") not in target:
        return {"success": False,
                "error": f"url {target!r} is not consistent with the hypothesis resource "
                         f"{res_hint!r}; pass the hypothesis's own endpoint/resource"}

    # 2) Scope BEFORE any traffic.
    in_scope, scope_reason = _scope_check(target, scan_targets)
    if not in_scope:
        return _result(V_BLOCKED, STATUS_BLOCKED,
                       f"destination not in operator scope: {scope_reason}; not testing",
                       "confirm host/port/path authorization with the operator",
                       {"in_scope": False})

    http_fn = http or (_default_http(transport) if transport is not None else None)
    browser_fn = browser or (_default_browser(transport) if transport is not None else None)
    if http_fn is None or browser_fn is None:
        return _result(V_INCONCLUSIVE, STATUS_BLOCKED,
                       "no HTTP/browser runtime available to this executor",
                       "run inside the sandbox (agent-browser + curl) or inject providers")

    # 3) Actor headers (never echoed). Reserve + mark dispatch BEFORE traffic.
    headers: dict[str, str] = {}
    if actor_ref.strip():
        headers, diag = _actor_headers(accounts_text, actor_ref)
        if not headers:
            return _result(V_INVALID_SESSION, STATUS_BLOCKED,
                           f"no usable provisioned session for actor {actor_ref!r}: "
                           f"{'; '.join(diag)}",
                           "provision the actor and record its session, then retry",
                           {"_evidence": {"resolved_state": RESOLVED_MISSING}})

    reservation = reserve_attempt(hid, tool="xss_browser_probe", max_attempts=_MAX_ATTEMPTS)
    if not reservation.get("reserved"):
        return _result(V_BLOCKED, STATUS_BLOCKED,
                       f"attempt budget exhausted ({reservation.get('used')}/"
                       f"{reservation.get('max')} used this run)",
                       "escalate to manual review or deliberately raise the budget",
                       {"attempt_budget": {"used": reservation.get("used"),
                                           "max": reservation.get("max"), "remaining": 0}})
    rid = str(reservation["reservation_id"])
    dispatch = {"on": False}
    session = f"xss-{actor_ref.strip() or 'anon'}-{uuid.uuid4().hex[:8]}"
    try:
        return await _execute(
            hid=hid, target=target, loc=loc, headers=headers, actor_ref=actor_ref.strip(),
            auth_marker=auth_marker.strip(), dom_source=dom_source.strip(),
            http_fn=http_fn, browser_fn=browser_fn, scan_targets=scan_targets,
            excluded_origins=excluded_origins or [], session=session,
            rid=rid, dispatch=dispatch, rtext=rtext, _result=_result,
            agent_id=agent_id, agent_name=agent_name,
        )
    except asyncio.CancelledError:
        settle_attempt(hid, rid, state=SLOT_FAILED if dispatch["on"] else SLOT_CANCELLED)
        _record(hid=hid, verdict=V_BLOCKED, status=STATUS_BLOCKED,
                outcome=("xss probe cancelled after dispatch; attempt consumed"
                         if dispatch["on"] else "xss probe cancelled before dispatch; released"),
                validation="re-run the targeted xss test",
                evidence={"kind": "xss_attempt", "ref": target[:256], "resolved_state": RESOLVED},
                rationale=rtext, agent_id=agent_id, agent_name=agent_name)
        with contextlib.suppress(Exception):
            await _close_session(browser_fn, session)
        raise
    except Exception:  # noqa: BLE001
        settle_attempt(hid, rid, state=SLOT_FAILED)
        return _result(V_INCONCLUSIVE, STATUS_BLOCKED, "xss probe failed unexpectedly",
                       "retry once; if it persists, escalate to manual review")


async def _close_session(browser_fn: XssBrowser, session: str) -> None:
    # Best-effort: the default provider closes its own session; a fake is a no-op.
    close = getattr(browser_fn, "close", None)
    if close is not None:
        with contextlib.suppress(Exception):
            await close(session)


async def _execute(
    *, hid: str, target: str, loc: str, headers: dict[str, str], actor_ref: str,
    auth_marker: str, dom_source: str, http_fn: XssHttp, browser_fn: XssBrowser,
    scan_targets: list[str] | None, excluded_origins: list[str], session: str, rid: str,
    dispatch: dict[str, bool], rtext: str, _result: Any, agent_id: str | None,
    agent_name: str | None,
) -> dict[str, Any]:
    nonce = _nonce()
    token = f"strixxss{secrets.token_hex(8)}"
    canary_global = f"__strix_xss_{nonce}"

    mark_dispatched(hid, rid)
    dispatch["on"] = True

    # Baseline (availability + auth state pre).
    base = await http_fn(target, method="GET", headers=headers, body=None)
    if not base.get("ok"):
        settle_attempt(hid, rid, state=SLOT_COMPLETED)
        return _result(V_INCONCLUSIVE, STATUS_BLOCKED,
                       "baseline fetch of the target did not succeed — cannot test",
                       "re-verify connectivity/session and retry")
    auth_pre = _auth_state(base, headers, auth_marker)
    if actor_ref and auth_marker and auth_pre == "lost":
        settle_attempt(hid, rid, state=SLOT_COMPLETED)
        return _result(V_INVALID_SESSION, STATUS_BLOCKED,
                       f"actor {actor_ref!r} baseline lacks the authentication marker — the "
                       "session looks invalid/expired; not testing authenticated surface",
                       "re-provision the actor's session, then retry")

    # Reflection probe (one inert marker) + context analysis — unless pure DOM.
    analysis: dict[str, Any] = {"reflected": False, "primary_context": CTX_NOT_REFLECTED,
                                "occurrences": [], "heuristic": True}
    if loc in (LOC_QUERY, LOC_FORM):
        marker = _reflection_marker(nonce)
        probe_url, probe_body = _inject(target, loc, marker)
        method = "POST" if loc == LOC_FORM else "GET"
        probe = await http_fn(probe_url, method=method, headers=headers, body=probe_body)
        if probe.get("ok"):
            analysis = _analyze_context(probe.get("body", ""),
                                        nonce, probe.get("headers", {}).get("Content-Type", ""))

    primary = analysis["primary_context"]
    csp_present = _csp_present(base)

    # Build ONE context-appropriate payload + an encoded negative control.
    ctx_for_payload = primary if analysis["reflected"] else CTX_HTML_TEXT
    built = _build_payload(ctx_for_payload, canary_global, token)
    payload, interaction = built["payload"], built.get("interaction_required", "")

    # Build the navigation delivery per location. A reflected POST cannot be
    # delivered by a plain navigation, so form_body execution is flagged
    # interaction-required (the default provider does not synthesize a submit).
    nav_url, form_body = _delivery(target, loc, payload, dom_source)
    ctrl_nav, ctrl_body = _delivery(target, loc, _encoded_control(payload), dom_source)
    if loc == LOC_FORM:
        interaction = interaction or "form_submit"

    # Browser execution: the real payload, then the ENCODED control (must not fire)
    # — each in its OWN isolated session.
    run = await browser_fn(nav_url=nav_url, session=session, canary_global=canary_global,
                           canary_token=token, headers=headers, form_body=form_body,
                           expect_execution=True, excluded_origins=excluded_origins)
    ctrl = await browser_fn(nav_url=ctrl_nav, session=session + "-ctrl",
                            canary_global=canary_global, canary_token=token, headers=headers,
                            form_body=ctrl_body, expect_execution=False,
                            excluded_origins=excluded_origins)

    origin_ok = _origin_ok(run, target, scan_targets)
    canary_fired = bool(run.get("ok") and run.get("canary_fired"))
    control_fired = bool(ctrl.get("ok") and ctrl.get("canary_fired"))
    browser_ok = bool(run.get("ok"))

    verdict, status, outcome, validation = _verdict(
        reflected=analysis["reflected"], primary_context=primary, canary_fired=canary_fired,
        origin_ok=origin_ok, control_fired=control_fired, csp_present=csp_present,
        browser_ok=browser_ok, interaction_required=interaction,
    )
    settle = settle_attempt(hid, rid, state=SLOT_COMPLETED)

    # Post auth re-check for authenticated tests.
    if actor_ref and auth_marker:
        post = await http_fn(target, method="GET", headers=headers, body=None)
        if _auth_state(post, headers, auth_marker) == "lost" and verdict == V_EXEC:
            verdict, status = V_INCONCLUSIVE, STATUS_BLOCKED
            outcome = ("the actor session was lost mid-test; the execution result is uncertain "
                       "and discarded")
            validation = "re-provision the session and re-run"

    evidence = {
        "_evidence": {
            "context_analysis": {"reflected": analysis["reflected"], "primary_context": primary,
                                 "occurrences": analysis["occurrences"], "heuristic": True},
            "canary_attribution": {"fired": canary_fired, "origin_attributed": origin_ok,
                                   "navigated_origin": run.get("navigated_origin", ""),
                                   "proof_source": "page-set unique global (not dialog/console/"
                                                   "text/harness-read)"},
            "negative_control_encoded_fired": control_fired,
            "csp_present": csp_present,
            "interaction_required": interaction,
            "auth_state_pre": auth_pre if actor_ref else "n/a",
        },
    }
    return _result(verdict, status, outcome, validation, {
        **evidence,
        "context": primary, "reflected": analysis["reflected"],
        "canary_fired": canary_fired, "origin_attributed": origin_ok,
        "negative_control_fired": control_fired, "csp_present": csp_present,
        "interaction_required": interaction,
        "attempt_budget": {"used": settle.get("used"), "max": settle.get("max"),
                           "remaining": settle.get("remaining")},
    })


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def _inject(url: str, loc: str, value: str) -> tuple[str, str | None]:
    """Place the probe/payload into the tested location for the HTTP reflection
    probe. Query -> URL; form_body -> request body (one field). No spraying:
    exactly one placement."""
    if loc == LOC_QUERY:
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}xss={quote(value, safe='')}", None
    if loc == LOC_FORM:
        return url, f"xss={quote(value, safe='')}"
    return url, None


def _delivery(url: str, loc: str, value: str, dom_source: str) -> tuple[str, str]:
    """Compute the browser navigation delivery: returns (nav_url, form_body).
    Query -> payload in the URL; dom -> payload in the fragment/search channel the
    sink reads; form_body -> body carried for a (interaction-required) submit."""
    if loc == LOC_QUERY:
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}xss={quote(value, safe='')}", ""
    if loc == LOC_DOM:
        src = (dom_source or "hash").lower()
        if src == "search":
            sep = "&" if "?" in url else "?"
            return f"{url}{sep}xss={quote(value, safe='')}", ""
        return f"{url}#{quote(value, safe='')}", ""
    if loc == LOC_FORM:
        # JSON so the browser form-submit injects the RAW value (browser encodes
        # on submit); the HTTP reflection probe uses _inject's url-encoded form.
        return url, json.dumps({"xss": value})
    return url, ""


def _csp_present(resp: dict[str, Any]) -> bool:
    hdrs = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
    return "content-security-policy" in hdrs


def _auth_state(resp: dict[str, Any], headers: dict[str, str], auth_marker: str) -> str:
    if not headers or not auth_marker:
        return "n/a"
    body = (resp.get("body") or "")[:_BODY_SCAN_CAP]
    status = resp.get("status")
    if status in (401, 403):
        return "lost"
    return "authenticated" if auth_marker.lower() in body.lower() else "lost"


def _origin_ok(run: dict[str, Any], target: str, scan_targets: list[str] | None) -> bool:
    """Attribute execution to the tested document origin, and confirm that origin
    is still in operator scope (a payload that navigated off-scope is not a
    proof)."""
    origin = str(run.get("navigated_origin") or "")
    final = str(run.get("final_url") or "")
    t = urlsplit(target)
    want = f"{t.scheme}://{t.hostname}" + (f":{t.port}" if t.port else "")
    if origin and want and origin.rstrip("/").lower() != want.rstrip("/").lower():
        return False
    if final:
        in_scope, _ = _scope_check(final, scan_targets)
        if not in_scope:
            return False
    return True


# --------------------------------------------------------------------------- #
# Agent tool
# --------------------------------------------------------------------------- #


def _caller(ctx: RunContextWrapper) -> dict[str, Any]:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    raw_agent_id = inner.get("agent_id")
    agent_id = raw_agent_id if isinstance(raw_agent_id, str) else None
    agent_name: str | None = None
    coordinator = inner.get("coordinator")
    if agent_id is not None and coordinator is not None:
        names = getattr(coordinator, "names", {})
        if isinstance(names, dict):
            raw = names.get(agent_id)
            agent_name = raw if isinstance(raw, str) else None
    return {"agent_id": agent_id, "agent_name": agent_name,
            "session": inner.get("sandbox_session"),
            "scan_targets": inner.get("scan_targets"),
            "http": inner.get("xss_http"), "browser": inner.get("xss_browser"),
            "accounts_text": inner.get("xss_accounts_text")}


async def _read_accounts(transport: CrawlTransport, workdir: str, job: str) -> str:
    text, _ = await _read_capped(transport, _DEFAULT_ACCOUNTS_PATH, 2_000_000, workdir, job)
    return text


@function_tool(timeout=300)
async def run_xss_test(
    ctx: RunContextWrapper,
    hypothesis_id: str,
    url: str,
    input_location: str,
    param_or_source: str,
    rationale: str,
    actor_ref: str = "",
    auth_marker: str = "",
    dom_source: str = "",
) -> str:
    """Run ONE targeted, browser-backed XSS test for a selected `xss` hypothesis.

    Not a scanner and not a crawler: one unique inert reflection marker, one
    bounded context-appropriate payload with a unique per-attempt execution
    canary, and one encoded negative control. Execution is proven ONLY by the
    canary global the page itself sets — never by payload text in HTML, a console
    message, a dialog, or the harness's own read of the canary. Normal web
    security and CSP are left ON and never disabled.

    Verdicts: execution_observed (-> needs_validation, never auto-confirmed and
    NOT cross-user impact), reflected_without_execution, no_execution_observed_
    this_test, blocked (incl. CSP), invalid_session, unsupported, inconclusive.
    Negative results apply ONLY to this input/context/variant — they never close
    sibling hypotheses or the XSS class.

    Args:
        hypothesis_id: An `xss` hypothesis id.
        url: The concrete injection-point URL (must be consistent with the
            hypothesis's resource and within operator scope).
        input_location: `query`, `form_body`, or `dom`. Header/cookie/path and all
            stored-XSS workflows are `unsupported` in this slice (no persistent
            writes are made).
        param_or_source: The query/form parameter name, or the DOM source
            (e.g. `hash`/`search`) being tested.
        rationale: Why this test applies (required).
        actor_ref: Optional provisioned actor for an authenticated test (its own
            isolated browser session; credentials never echoed).
        auth_marker: Optional application-specific string proving the actor is
            authenticated (checked before and after).
        dom_source: For `dom` tests, the source channel (default `hash`).
    """
    ident = _caller(ctx)
    accounts_text = ident["accounts_text"]
    if accounts_text is None and actor_ref and ident["session"] is not None:
        with contextlib.suppress(Exception):
            accounts_text = await _read_accounts(
                ident["session"], "/workspace/.xss", f"xss_{uuid.uuid4().hex[:8]}")
    result = await _run_xss_impl(
        hypothesis_id=hypothesis_id, url=url, input_location=input_location,
        param_or_source=param_or_source, rationale=rationale, actor_ref=actor_ref,
        auth_marker=auth_marker, dom_source=dom_source, accounts_text=accounts_text or "",
        http=ident["http"] if callable(ident["http"]) else None,
        browser=ident["browser"] if callable(ident["browser"]) else None,
        transport=ident["session"], scan_targets=ident["scan_targets"],
        agent_id=ident["agent_id"], agent_name=ident["agent_name"],
    )
    record_activity_tick(ident["agent_id"])
    return json.dumps(result, ensure_ascii=False, default=str)
