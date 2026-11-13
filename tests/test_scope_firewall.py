"""Tests for the opt-in, fail-open scope egress firewall (BLACKBOX #12).

Everything testable without a live sandbox: scope->CIDR resolution (injected
resolver), the iptables script builder, the disabled-is-a-pure-no-op guarantee,
and every fail-open path. The actual iptables install is not exercised here (it
needs a live NET_ADMIN sandbox — verify live), exactly as the other executors'
real-binary paths are a separate concern.
"""

from __future__ import annotations

import asyncio
from typing import Any

from strix.runtime.scope_firewall import (
    _CHAIN,
    apply_scope_egress_firewall,
    build_iptables_script,
    resolve_scope_to_cidrs,
)


def _resolver(mapping: dict[str, list[str]]):
    def _fn(host: str) -> list[str]:
        if host not in mapping:
            raise OSError("no such host")
        return mapping[host]
    return _fn


# --------------------------------------------------------------------------- #
# resolve_scope_to_cidrs
# --------------------------------------------------------------------------- #


def test_resolve_skips_paths_and_wildcards_and_keeps_literal_ips() -> None:
    cidrs, unresolved = resolve_scope_to_cidrs(
        ["https://app.example.com", "/home/u/repo", "*.example.com", "10.0.0.5"],
        resolver=_resolver({"app.example.com": ["93.184.216.34"]}),
    )
    assert "93.184.216.34/32" in cidrs
    assert "10.0.0.5/32" in cidrs           # literal IP passes through, no DNS
    # the path target and the wildcard contribute nothing
    assert all("example.com" not in c for c in cidrs)
    assert unresolved == []


def test_resolve_tracks_unresolved_hosts() -> None:
    cidrs, unresolved = resolve_scope_to_cidrs(
        ["https://down.example.com"], resolver=_resolver({}),
    )
    assert cidrs == [] and unresolved == ["down.example.com"]


def test_resolve_handles_ipv6_and_multiple_addrs() -> None:
    cidrs, _ = resolve_scope_to_cidrs(
        ["h.test"], resolver=_resolver({"h.test": ["1.2.3.4", "2606:4700::1"]}),
    )
    assert "1.2.3.4/32" in cidrs and "2606:4700::1/128" in cidrs


# --------------------------------------------------------------------------- #
# build_iptables_script
# --------------------------------------------------------------------------- #


def test_script_allows_infra_before_dropping() -> None:
    script = build_iptables_script(["1.2.3.4/32", "5.6.7.8/32"])
    lo = script.index("-o lo -j ACCEPT")
    dns = script.index("--dport 53")
    allow = script.index("-d 1.2.3.4/32 -j ACCEPT")
    reject = script.index("-j REJECT")
    # infra + allowlist must come before the catch-all reject
    assert lo < reject and dns < reject and allow < reject
    assert "-d 5.6.7.8/32 -j ACCEPT" in script
    # OUTPUT jump is added idempotently (checked before append)
    assert f"iptables -C OUTPUT -j {_CHAIN}" in script
    # the script never sets a restrictive default policy on OUTPUT itself
    assert "-P OUTPUT DROP" not in script


# --------------------------------------------------------------------------- #
# apply_scope_egress_firewall
# --------------------------------------------------------------------------- #


class _FakeSession:
    def __init__(self, exit_code: int = 0, raises: bool = False) -> None:
        self.exit_code = exit_code
        self.raises = raises
        self.calls: list[tuple[str, ...]] = []

    async def exec(self, *command: str, timeout: float | None = None, shell: bool = False) -> Any:
        self.calls.append(command)
        if self.raises:
            raise RuntimeError("iptables boom")
        return type("R", (), {"exit_code": self.exit_code})()


def test_disabled_is_a_pure_no_op() -> None:
    sess = _FakeSession()
    res = asyncio.run(apply_scope_egress_firewall(sess, ["app.example.com"], enabled=False))
    assert res == {"applied": False, "enabled": False}
    assert sess.calls == []          # nothing is executed when disabled


def test_enabled_but_no_resolvable_ip_fails_open_without_exec() -> None:
    sess = _FakeSession()
    res = asyncio.run(apply_scope_egress_firewall(
        sess, ["https://down.example.com"], enabled=True, resolver=_resolver({}),
    ))
    assert res["applied"] is False and res["fail_open"] is True
    assert sess.calls == []          # never install a deny-all with an empty allowlist


def test_enabled_success_installs_and_reports_cidrs() -> None:
    sess = _FakeSession(exit_code=0)
    res = asyncio.run(apply_scope_egress_firewall(
        sess, ["app.example.com"], enabled=True,
        resolver=_resolver({"app.example.com": ["1.2.3.4"]}),
    ))
    assert res["applied"] is True and res["allowed_cidrs"] == ["1.2.3.4/32"]
    assert len(sess.calls) == 1 and sess.calls[0][0] == "sh"


def test_enabled_exec_error_fails_open() -> None:
    sess = _FakeSession(raises=True)
    res = asyncio.run(apply_scope_egress_firewall(
        sess, ["app.example.com"], enabled=True,
        resolver=_resolver({"app.example.com": ["1.2.3.4"]}),
    ))
    assert res["applied"] is False and res["fail_open"] is True


def test_enabled_nonzero_exit_fails_open() -> None:
    sess = _FakeSession(exit_code=3)
    res = asyncio.run(apply_scope_egress_firewall(
        sess, ["app.example.com"], enabled=True,
        resolver=_resolver({"app.example.com": ["1.2.3.4"]}),
    ))
    assert res["applied"] is False and res["fail_open"] is True


def test_enabled_no_session_fails_open() -> None:
    res = asyncio.run(apply_scope_egress_firewall(None, ["app.example.com"], enabled=True))
    assert res["applied"] is False and res["fail_open"] is True
