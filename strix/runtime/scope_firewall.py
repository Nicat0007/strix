"""Opt-in, fail-open network-layer scope egress allowlist for the sandbox
(BLACKBOX improvement #12).

The recon pipeline and the executors enforce scope by *convention* — an agent is
told not to touch out-of-scope hosts, and the deterministic executors scope-check
before sending. But a raw ``curl`` an agent runs, or a headless browser fetching
whatever a page triggers (§28), can still egress anywhere. On a real bug-bounty
engagement one out-of-scope request can get the operator banned. This module turns
that soft boundary into a hard one at the network layer.

Two hard promises:

- **OFF by default.** When disabled (the default, ``STRIX_SCOPE_FIREWALL`` unset),
  ``apply_scope_egress_firewall`` is a pure no-op: it never execs anything and the
  sandbox's egress is byte-identical to before. So enabling this can never be the
  cause of a regression for anyone who has not opted in.
- **FAIL-OPEN when on.** Any failure — no ``NET_ADMIN``, ``iptables`` missing, a
  target that will not resolve, an exec error, an empty allowlist — logs a warning
  and leaves egress OPEN rather than breaking the scan. A hardening that bricks a
  legitimate scan is worse than one that occasionally does not engage; the
  agent-honoured scope discipline still applies underneath.

EXPERIMENTAL: the iptables install itself cannot be unit-tested without a live
sandbox (the pure allowlist-building / resolution / disabled-no-op / fail-open
logic is). Verify live before relying on it (see tests + README of this change).
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Any, Protocol
from urllib.parse import urlsplit


logger = logging.getLogger(__name__)

_RESOLVE_TIMEOUT_S = 5.0
_APPLY_TIMEOUT_S = 30.0
#: Always-allowed egress the sandbox needs to function regardless of target scope:
#: loopback and (so DNS keeps working) the resolver. DNS is allowed by port, not
#: IP, because the resolver may be a link-local address that rotates.
_CHAIN = "STRIX_EGRESS"


class _ExecLike(Protocol):
    async def exec(self, *command: str, timeout: float | None = ..., shell: bool = ...) -> Any: ...


def _host_of(target: str) -> str | None:
    """Extract a bare host from a target string, or None for a path/white-box
    target or a wildcard (which cannot be resolved to an IP)."""
    t = (target or "").strip()
    if not t or t.startswith("/"):
        return None
    candidate = t if "://" in t else f"//{t}"
    host = (urlsplit(candidate).hostname or "").lower()
    if not host or "*" in host:
        return None
    return host


def resolve_scope_to_cidrs(
    targets: list[str] | None, *, resolver: Any = None
) -> tuple[list[str], list[str]]:
    """Resolve every in-scope host to a list of ``ip/prefix`` CIDRs (``/32`` for
    IPv4, ``/128`` for IPv6), host-side. Returns ``(cidrs, unresolved_hosts)``.

    White-box/path targets and wildcard hosts are skipped (a wildcard cannot be
    pinned to an IP — that is a documented limitation of an IP-level allowlist).
    A literal IP target passes straight through. ``resolver`` is injected in
    tests; the default uses ``socket.getaddrinfo``.
    """
    resolve = resolver or _default_resolver
    cidrs: set[str] = set()
    unresolved: list[str] = []
    for target in targets or []:
        host = _host_of(target)
        if host is None:
            continue
        # A literal IP needs no DNS.
        try:
            ip = ipaddress.ip_address(host)
            cidrs.add(f"{ip}/{ip.max_prefixlen}")
            continue
        except ValueError:
            pass
        try:
            addrs = resolve(host)
        except Exception:  # noqa: BLE001 - any resolver failure -> unresolved, never raise
            addrs = []
        if not addrs:
            unresolved.append(host)
            continue
        for addr in addrs:
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            cidrs.add(f"{ip}/{ip.max_prefixlen}")
    return sorted(cidrs), sorted(set(unresolved))


def _default_resolver(host: str) -> list[str]:
    socket.setdefaulttimeout(_RESOLVE_TIMEOUT_S)
    infos = socket.getaddrinfo(host, None)
    return [info[4][0] for info in infos]


def build_iptables_script(
    allow_cidrs: list[str], *, extra_allow_cidrs: list[str] | None = None
) -> str:
    """Build a self-contained, idempotent shell script that installs a
    default-DROP egress allowlist in a dedicated chain.

    Order matters: loopback, established/related, and DNS are allowed BEFORE the
    default drop so the sandbox stays functional; then each authorized CIDR; then
    everything else is dropped. The script is idempotent (flushes/recreates its own
    chain) and only ever touches its own ``STRIX_EGRESS`` chain plus the jump from
    ``OUTPUT`` — it never sets a restrictive default policy on ``OUTPUT`` itself, so
    a partial failure cannot silently blackhole the box.
    """
    allowed = list(dict.fromkeys([*(allow_cidrs or []), *(extra_allow_cidrs or [])]))
    lines = [
        "set +e",  # fail-open: never abort the script on a single rule error
        f"iptables -F {_CHAIN} 2>/dev/null || true",
        f"iptables -N {_CHAIN} 2>/dev/null || true",
        # keep the box functional
        f"iptables -A {_CHAIN} -o lo -j ACCEPT",
        f"iptables -A {_CHAIN} -m state --state ESTABLISHED,RELATED -j ACCEPT",
        f"iptables -A {_CHAIN} -p udp --dport 53 -j ACCEPT",
        f"iptables -A {_CHAIN} -p tcp --dport 53 -j ACCEPT",
    ]
    lines.extend(f"iptables -A {_CHAIN} -d {cidr} -j ACCEPT" for cidr in allowed)
    # explicit reject for everything else (visible failure for the agent's curl,
    # not a silent hang) then ensure OUTPUT jumps to the chain exactly once.
    lines.append(f"iptables -A {_CHAIN} -j REJECT --reject-with icmp-admin-prohibited")
    lines.append(f"iptables -C OUTPUT -j {_CHAIN} 2>/dev/null || iptables -A OUTPUT -j {_CHAIN}")
    return "\n".join(lines) + "\n"


async def apply_scope_egress_firewall(
    session: _ExecLike | None,
    targets: list[str] | None,
    *,
    enabled: bool,
    extra_allow_cidrs: list[str] | None = None,
    resolver: Any = None,
) -> dict[str, Any]:
    """Install the egress allowlist in the sandbox, or no-op when disabled.

    Returns a small status dict; never raises. When ``enabled`` is False, nothing
    is executed. When True, failures fail OPEN (a warning + ``applied: False``),
    including an empty allowlist (installing a deny-all with no allowed CIDR would
    brick the box, so that case is refused rather than applied).
    """
    if not enabled:
        return {"applied": False, "enabled": False}
    if session is None:
        logger.warning("scope firewall enabled but no sandbox session; leaving egress open")
        return {"applied": False, "enabled": True, "fail_open": True, "reason": "no session"}

    cidrs, unresolved = resolve_scope_to_cidrs(targets, resolver=resolver)
    if not cidrs:
        logger.warning(
            "scope firewall enabled but no in-scope host resolved to an IP "
            "(unresolved=%s); leaving egress OPEN (fail-open) rather than blocking all egress",
            unresolved,
        )
        return {"applied": False, "enabled": True, "fail_open": True,
                "reason": "no resolvable in-scope IPs", "unresolved": unresolved}

    script = build_iptables_script(cidrs, extra_allow_cidrs=extra_allow_cidrs)
    try:
        result = await session.exec("sh", "-lc", script, timeout=_APPLY_TIMEOUT_S, shell=False)
        code = int(getattr(result, "exit_code", 1))
    except Exception:  # fail OPEN: a firewall error must not break the scan
        logger.warning("scope firewall install failed; leaving egress open (fail-open)",
                       exc_info=True)
        return {"applied": False, "enabled": True, "fail_open": True, "reason": "exec error"}
    if code != 0:
        logger.warning("scope firewall install returned %s; egress left open (fail-open)", code)
        return {"applied": False, "enabled": True, "fail_open": True,
                "reason": f"exit {code}", "allowed_cidrs": cidrs, "unresolved": unresolved}
    logger.info("scope egress firewall applied: %d allowed CIDR(s), %d unresolved host(s)",
                len(cidrs), len(unresolved))
    return {"applied": True, "enabled": True, "allowed_cidrs": cidrs, "unresolved": unresolved}
