"""OPT-IN live sandbox-browser integration for the XSS executor (BLACKBOX #6).

This drives the COMMITTED production path end to end — `run_xss_test`'s default
providers (`_default_http` via `curl`, `_default_browser` via the real
`agent-browser` CLI) over the ACTUAL Docker sandbox session created by
`strix.runtime.session_manager.create_or_reuse` (the same transport production
uses). It is NOT a host-subprocess shim.

It is opt-in and heavy (spins a real sandbox container, ~minutes), so the default
suite SKIPS it unless `STRIX_XSS_LIVE_SANDBOX=1` and Docker + the sandbox image
are present. A skip is reported honestly as a skip — never as live validation.
Nothing is installed automatically.

    STRIX_XSS_LIVE_SANDBOX=1 venv/bin/python -m pytest \\
        tests/test_xss_browser_integration.py -v -s

Proven live (when run): reflected-query execution, encoded reflection without
execution, DOM source->sink execution, CSP-blocked execution (CSP left ON), and
a request-level excluded-origin abort (a subresource to an out-of-scope origin
is blocked before it is sent — counter stays 0, versus >0 without the abort).
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest


_OPT_IN = "STRIX_XSS_LIVE_SANDBOX"
_IMAGE = "strix-sandbox:dev"
_MAIN = 8099
_EXCL = 8098
_ORIGIN = f"http://127.0.0.1:{_MAIN}"
_EXCL_ORIGIN = f"http://127.0.0.1:{_EXCL}"

_FIXTURE = f"""
import http.server, socketserver, threading, html
from urllib.parse import urlsplit, parse_qs
class Main(http.server.BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def _send(self, body, headers=None):
        self.send_response(200)
        for k,v in (headers or {{}}).items(): self.send_header(k,v)
        self.send_header("Content-Type","text/html"); self.end_headers(); self.wfile.write(body.encode())
    def do_GET(self):
        u=urlsplit(self.path); p=u.path; v=parse_qs(u.query).get("xss",[""])[0]
        img='<img src="http://127.0.0.1:{_EXCL}/pwn">'
        if p=="/refl": self._send("<html><body>"+img+"<div>"+v+"</div></body></html>")
        elif p=="/enc": self._send("<html><body><div>"+html.escape(v)+"</div></body></html>")
        elif p=="/csp": self._send("<html><body><div>"+v+"</div></body></html>", {{"Content-Security-Policy":"default-src 'self'"}})
        elif p=="/dom": self._send('<html><body><div id=o></div><script>document.getElementById("o").innerHTML=decodeURIComponent(location.hash.slice(1))</script></body></html>')
        else: self._send("<html><body>home</body></html>")
class Excl(http.server.BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        open("/tmp/excl_hits","a").write("x\\n")
        self.send_response(200); self.end_headers(); self.wfile.write(b"X")
def serve(port,h): socketserver.TCPServer(("127.0.0.1",port),h).serve_forever()
threading.Thread(target=serve,args=({_EXCL},Excl),daemon=True).start()
serve({_MAIN},Main)
"""


def _require_live_sandbox() -> None:
    if os.environ.get(_OPT_IN) != "1":
        pytest.skip(f"opt-in: set {_OPT_IN}=1 (and have Docker + {_IMAGE}) to run the real "
                    "sandbox-browser integration")
    if not shutil.which("docker"):
        pytest.skip("docker CLI not available")
    try:
        imgs = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                              capture_output=True, text=True, timeout=30, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        pytest.skip("docker not usable")
    if _IMAGE not in imgs:
        pytest.skip(f"sandbox image {_IMAGE} not present")


async def _ex(s, *a, timeout=40):
    r = await s.exec(*a, timeout=timeout, shell=False)
    out = getattr(r, "stdout", b"")
    return out.decode("utf-8", "replace") if isinstance(out, bytes) else out


async def _hits(s) -> int:
    out = await _ex(s, "sh", "-lc", "wc -l < /tmp/excl_hits 2>/dev/null || echo 0")
    try:
        return int(out.strip() or "0")
    except ValueError:
        return 0


@pytest.mark.asyncio
async def test_live_sandbox_browser_xss_oracle() -> None:
    _require_live_sandbox()
    from strix.runtime import session_manager
    from strix.tools.hypotheses.tools import _create_impl, hydrate_hypotheses_from_disk
    from strix.tools.xss_executor.tools import _run_xss_impl

    state = Path(tempfile.mkdtemp(prefix="xsslive_"))
    hydrate_hypotheses_from_disk(state)
    bundle = await session_manager.create_or_reuse("xss-pytest-live", image=_IMAGE,
                                                   local_sources=[])
    s = bundle["session"]
    try:
        b64 = base64.b64encode(_FIXTURE.encode()).decode()
        await _ex(s, "sh", "-lc", f"echo {b64} | base64 -d > /tmp/xssfix.py")
        await _ex(s, "sh", "-lc", "rm -f /tmp/excl_hits; nohup python3 /tmp/xssfix.py "
                                  ">/tmp/xssfix.log 2>&1 & sleep 2")

        def hyp(r: str) -> str:
            return _create_impl(endpoint_id="ep", vuln_category="xss", resource=r,
                                actor_ref="anon", param_name="xss", param_location="query",
                                operation="", rationale="live", next_action="probe", priority={},
                                evidence=[], agent_id=None, agent_name=None)["hypothesis_id"]

        async def run(r: str, loc: str, **kw) -> dict:
            return await _run_xss_impl(
                hypothesis_id=hyp(r), url=f"{_ORIGIN}{r}", input_location=loc,
                param_or_source="xss" if loc != "dom" else "hash", rationale="live",
                transport=s, scan_targets=[_ORIGIN],
                dom_source="hash" if loc == "dom" else "", **kw)

        assert (await run("/refl", "query"))["verdict"] == "execution_observed"
        assert (await run("/enc", "query"))["verdict"] == "reflected_without_execution"
        assert (await run("/csp", "query"))["verdict"] == "blocked"
        assert (await run("/dom", "dom"))["verdict"] == "execution_observed"

        before = await _hits(s)
        await run("/refl", "query")
        no_abort = await _hits(s) - before
        mid = await _hits(s)
        await run("/refl", "query", excluded_origins=[_EXCL_ORIGIN])
        with_abort = await _hits(s) - mid
        assert no_abort > 0, "control: the out-of-scope subresource should fire without the abort"
        assert with_abort == 0, "request-level abort must block the out-of-scope subresource"
    finally:
        await session_manager.cleanup("xss-pytest-live")
