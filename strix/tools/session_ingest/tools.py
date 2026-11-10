"""Frictionless operator session ingestion.

An authenticated black-box run needs a session in
``/workspace/recon/auth_accounts.jsonl`` (the file ``crawl_executor`` /
``authorization_executor`` read by ``principal``/``role``). Until now the agent
had to hand-parse a free-text operator reply and write that JSONL itself — a
fragile seam that often never completes on a weak model, so the authenticated
surface (where the real IDOR/BFLA/PII/upload/LLM bugs are) stays untested.

This tool closes that seam: the operator pastes whatever they have — a browser
``document.cookie`` string, a raw ``Cookie:`` header, a ``curl`` command copied
from DevTools, or a bearer token — and the tool deterministically parses the
``cookie``/``token`` out of it and appends a correctly-shaped actor entry. The
agent then verifies the session is live with ``run_crawl_job``'s marker check.

Secret values are never returned to the model; only a redacted summary is.
"""

from __future__ import annotations

import io
import json
import logging
import re
import shlex
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)

_ACCOUNTS_PATH = "/workspace/recon/auth_accounts.jsonl"
_RECON_DIR = "/workspace/recon"

# A JWT or an explicit bearer; used to classify a bare blob as a token not a cookie.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}")
_BEARER_RE = re.compile(r"\bBearer\s+([^\s'\"]+)", re.IGNORECASE)
_COOKIE_PAIR_RE = re.compile(r"[A-Za-z0-9_\-.]+=[^;\s]+")


def _redact(value: str) -> str:
    v = value.strip()
    if len(v) <= 8:
        return "****"
    return f"{v[:4]}…{v[-4:]} ({len(v)} chars)"


def _header_value(blob: str, header: str) -> str | None:
    """Pull a ``Header: value`` out of raw text or ``-H "Header: value"`` curl args."""
    m = re.search(rf"(?im)^\s*{re.escape(header)}\s*:\s*(.+?)\s*$", blob)
    if m:
        return m.group(1).strip().strip("'\"")
    m = re.search(rf"(?i)-H\s+['\"]?{re.escape(header)}\s*:\s*([^'\"]+)['\"]?", blob)
    if m:
        return m.group(1).strip()
    return None


def _curl_cookie_flag(blob: str) -> str | None:
    """``-b``/``--cookie`` value from a pasted curl command."""
    try:
        tokens = shlex.split(blob)
    except ValueError:
        return None
    for i, tok in enumerate(tokens):
        if tok in {"-b", "--cookie"} and i + 1 < len(tokens):
            val = tokens[i + 1].strip()
            # ``-b name=value`` only counts as a cookie if it looks like one (not a file)
            if "=" in val:
                return val
    return None


def parse_session_blob(blob: str) -> tuple[dict[str, str], list[str]]:
    """Deterministically extract ``{cookie, token}`` from an operator-pasted blob.

    Pure function (no I/O) so it is unit-testable. Handles, in order: an explicit
    ``Cookie:``/``Authorization:`` header (raw or curl ``-H``), a curl ``-b``
    cookie flag, a bare ``Bearer``/JWT token, and a bare ``k=v; k2=v2`` cookie
    string. Returns the fields and human-readable diagnostics.
    """
    text = (blob or "").strip()
    out: dict[str, str] = {}
    diags: list[str] = []
    if not text:
        return out, ["empty session blob"]

    cookie = _header_value(text, "Cookie") or _curl_cookie_flag(text)
    auth = _header_value(text, "Authorization")

    token = ""
    if auth:
        m = _BEARER_RE.search(auth)
        token = m.group(1) if m else auth.strip()
    elif not cookie:
        # No headers at all: classify the bare blob.
        looks_like_cookie = (
            ";" in text or "=" in text
        ) and not _JWT_RE.fullmatch(text.strip())
        bearer = _BEARER_RE.search(text)
        jwt = _JWT_RE.search(text)
        if bearer:
            token = bearer.group(1)
        elif jwt and not looks_like_cookie:
            token = jwt.group(0)
        elif _COOKIE_PAIR_RE.search(text):
            cookie = text
            diags.append("treated the bare blob as a raw cookie string")
        elif jwt:
            token = jwt.group(0)

    if cookie:
        # Keep only well-formed cookie pairs, joined canonically.
        pairs = _COOKIE_PAIR_RE.findall(cookie)
        if pairs:
            out["cookie"] = "; ".join(pairs)
            diags.append(f"parsed {len(pairs)} cookie pair(s)")
        else:
            diags.append("cookie text had no recognisable name=value pairs")
    if token:
        out["token"] = token.strip()
        diags.append("parsed a bearer/token value")
    if not out:
        diags.append(
            "could not find a cookie or token — paste a browser Cookie string "
            "(name=value; name2=value2), a 'Cookie:'/'Authorization:' header, a "
            "curl command copied from DevTools, or a bearer token"
        )
    return out, diags


def build_entry(
    *, principal: str, role: str, tenant: str, fields: dict[str, str], obtained_via: str
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "principal": principal.strip(),
        "role": role.strip(),
        "obtained_via": obtained_via.strip() or "operator-supplied",
        "owned_objects": [],
    }
    if tenant.strip():
        entry["tenant"] = tenant.strip()
    if fields.get("cookie"):
        entry["cookie"] = fields["cookie"]
    if fields.get("token"):
        entry["token"] = fields["token"]
    return entry


def _append_cmd(entry_json: str, path: str) -> list[str]:
    """Append one JSONL line via base64 so no quoting/special char can corrupt it."""
    import base64

    b64 = base64.b64encode((entry_json + "\n").encode("utf-8")).decode("ascii")
    script = (
        f"mkdir -p {shlex.quote(_RECON_DIR)} && "
        f"printf %s {shlex.quote(b64)} | base64 -d >> {shlex.quote(path)} && "
        f"wc -l < {shlex.quote(path)}"
    )
    return ["sh", "-c", script]


@function_tool(timeout=60)
async def ingest_session(
    ctx: RunContextWrapper,
    principal: str,
    session_blob: str,
    role: str = "citizen",
    tenant: str = "",
) -> str:
    """Turn an operator-pasted session into a provisioned actor the authenticated
    tools can use — the frictionless path past an SSO/login wall.

    When a target is gated behind SSO/login you cannot complete yourself, ask the
    operator (``respond_to_user``) to log in once in their browser and paste back
    ANY of: their ``document.cookie`` string, the ``Cookie:`` header, a ``curl``
    command copied from browser DevTools ("Copy as cURL"), or a bearer token. Pass
    that whole paste as ``session_blob`` and this tool parses it and records the
    actor in ``/workspace/recon/auth_accounts.jsonl`` with the exact fields
    ``run_crawl_job`` / ``run_authorization_test`` read. No need to hand-write that
    JSONL — getting it slightly wrong is why authenticated runs silently never start.

    **After this succeeds, verify the session is live** before hunting with it:
    ``run_crawl_job(origins=..., actor_ref="<principal>", auth_check_url=<an
    authenticated-only page>, auth_check_marker=<text only a logged-in response
    has>, auth_check_absent_marker=<text only a logged-out response has>)``. A
    credential is not proof until that check passes (see
    ``reconnaissance/account_provisioning.md``). For cross-user IDOR/BFLA, ingest a
    **second** actor the same way, then use ``query_cross_actor_access`` /
    ``run_authorization_test``.

    Secret values are never echoed back — only a redacted confirmation.

    Args:
        principal: A stable name for this actor (``citizen-a``, the login/email).
        session_blob: The pasted cookie string / Cookie header / curl command /
            bearer token — whatever the operator gave you, verbatim.
        role: The actor's role (``citizen``, ``staff``, ``admin``), used by the
            authz executor to pick a low- vs high-privilege principal.
        tenant: Optional tenant/org id for multi-tenant targets.
    """
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    session = inner.get("sandbox_session")
    if session is None:
        return json.dumps(
            {"success": False, "error": "no sandbox session in context"}, ensure_ascii=False
        )
    if not principal.strip():
        return json.dumps(
            {"success": False, "error": "principal is required (a stable actor name)"},
            ensure_ascii=False,
        )

    fields, diags = parse_session_blob(session_blob)
    if not fields:
        return json.dumps(
            {"success": False, "error": "no_session_parsed", "diagnostics": diags},
            ensure_ascii=False,
        )

    entry = build_entry(
        principal=principal, role=role, tenant=tenant, fields=fields,
        obtained_via="operator-supplied",
    )
    entry_json = json.dumps(entry, ensure_ascii=False)
    try:
        result = await session.exec(*_append_cmd(entry_json, _ACCOUNTS_PATH), timeout=30, shell=False)
        exit_code = int(getattr(result, "exit_code", 1))
        line_count = bytes(getattr(result, "stdout", b"")).decode("utf-8", "replace").strip()
    except Exception as exc:  # noqa: BLE001 - surface the failure to the agent, don't crash.
        logger.exception("ingest_session write failed")
        return json.dumps(
            {"success": False, "error": f"failed to write auth_accounts.jsonl: {exc}"},
            ensure_ascii=False,
        )
    if exit_code != 0:
        return json.dumps(
            {"success": False, "error": f"sandbox write exited {exit_code}"}, ensure_ascii=False
        )

    redacted = {
        "principal": entry["principal"], "role": entry["role"],
        "has_cookie": "cookie" in entry, "has_token": "token" in entry,
    }
    if "cookie" in entry:
        redacted["cookie_preview"] = _redact(entry["cookie"])
    if "token" in entry:
        redacted["token_preview"] = _redact(entry["token"])
    return json.dumps(
        {
            "success": True,
            "recorded_actor": redacted,
            "accounts_file": _ACCOUNTS_PATH,
            "total_actors": line_count,
            "diagnostics": diags,
            "next_step": (
                f"Verify it is live: run_crawl_job(actor_ref={entry['principal']!r}, "
                "auth_check_url=<authenticated-only page>, auth_check_marker=<logged-in "
                "text>, auth_check_absent_marker=<logged-out text>). A credential is not "
                "proof until that check passes. For cross-user tests, ingest a second actor."
            ),
        },
        ensure_ascii=False,
    )
