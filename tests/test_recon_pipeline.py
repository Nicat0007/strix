"""Deterministic checks for the black-box recon pipeline scripts embedded in
``strix/skills/reconnaissance/asset_discovery.md``.

These extract the ACTUAL committed scripts from the skill markdown (by their
``# === strix-recon-* ===`` marker) and run them -- not a hand-copied duplicate
-- so a regression in the skill text fails here. No network: a local mock
stands in for ``nuclei -tags <t> -tl``.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest


SKILL = (
    Path(__file__).resolve().parents[1]
    / "strix" / "skills" / "reconnaissance" / "asset_discovery.md"
)

MARKERS = {
    "normalize": "# === strix-recon-normalize ===",
    "selectors": "# === strix-recon-selectors ===",
    "state": "# === strix-recon-state ===",
    "merge": "# === strix-recon-merge ===",
}


def _extract_scripts() -> dict[str, str]:
    text = SKILL.read_text(encoding="utf-8")
    blocks = re.findall(r"```python\n(.*?)```", text, re.S)
    out: dict[str, str] = {}
    for name, marker in MARKERS.items():
        matches = [b for b in blocks if marker in b]
        assert len(matches) == 1, f"expected exactly one {name} block, got {len(matches)}"
        out[name] = matches[0]
    return out


SCRIPTS = _extract_scripts()


def _write_scripts(d: Path) -> None:
    # The ``recon_`` prefix avoids shadowing stdlib modules -- a file named
    # selectors.py would shadow the stdlib ``selectors`` that subprocess imports.
    for name, code in SCRIPTS.items():
        (d / f"recon_{name}.py").write_text(code, encoding="utf-8")


def _mock_nuclei(d: Path) -> str:
    """Return a shim path usable as STRIX_NUCLEI_BIN; emits fake template lines
    for known product tags and nothing for unknown ones."""
    mock = d / "mock_nuclei.py"
    mock.write_text(
        "import sys\n"
        "KNOWN={'wordpress','nginx','php','apache','laravel','drupal','joomla',"
        "'tomcat','jira','jenkins','gitlab','grafana','spring','kubernetes'}\n"
        "tag=None\n"
        "a=sys.argv\n"
        "for i,x in enumerate(a):\n"
        "    if x=='-tags' and i+1<len(a): tag=a[i+1]\n"
        "if tag in KNOWN:\n"
        "    print(f'http/technologies/{tag}-detect.yaml')\n"
        "    print(f'http/cves/2024/{tag}-x.yaml')\n",
        encoding="utf-8",
    )
    shim = d / "nuclei_shim.sh"
    shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{mock}" "$@"\n', encoding="utf-8")
    shim.chmod(0o755)
    return str(shim)


def hx(inp: str, tech: list[str], status: int = 200, url: str | None = None) -> dict:
    return {"input": inp, "url": url or inp, "status_code": status, "tech": tech}


def _wl(path: Path, rows: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def _lines(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]


def _run(d: Path, script: str, *args: str, nuclei: str | None = None) -> str:
    env = dict(os.environ)
    if nuclei:
        env["STRIX_NUCLEI_BIN"] = nuclei
    r = subprocess.run(
        [sys.executable, str(d / f"recon_{script}.py"), *args],
        cwd=d, env=env, capture_output=True, text=True, check=False,
    )
    assert r.returncode == 0, f"{script} failed: {r.stderr}\n{r.stdout}"
    return r.stdout


def _assets(d: Path) -> list[dict]:
    return _lines(d / "assets.jsonl")


def _selectors(d: Path) -> dict:
    _run(d, "selectors", nuclei=_mock_nuclei(d))
    return json.loads((d / "nuclei_manifest.json").read_text())


@pytest.fixture()
def recon_dir(tmp_path: Path) -> Path:
    _write_scripts(tmp_path)
    return tmp_path


# --- normalization / identity -------------------------------------------------


def test_same_host_https_443_and_8443_are_separate(recon_dir: Path) -> None:
    _wl(recon_dir / "httpx_raw.jsonl", [
        hx("https://svc.example.com", ["WordPress:6.5"]),
        hx("https://svc.example.com:8443", ["nginx"]),
    ])
    _run(recon_dir, "normalize")
    a = {r["origin"]: r for r in _assets(recon_dir)}
    assert set(a) == {"https://svc.example.com:443", "https://svc.example.com:8443"}
    assert a["https://svc.example.com:443"]["tech"] == ["WordPress:6.5"]
    assert a["https://svc.example.com:8443"]["tech"] == ["nginx"]
    assert a["https://svc.example.com:443"]["ports"] == [443]
    assert a["https://svc.example.com:8443"]["ports"] == [8443]


def test_default_ports_casing_ipv6_and_duplicates(recon_dir: Path) -> None:
    _wl(recon_dir / "httpx_raw.jsonl", [
        hx("HTTP://Example.COM", ["nginx"]),
        hx("https://[2001:db8::1]:8443", ["php"]),
        hx("https://dup.example.com", ["nginx"]),
        hx("https://dup.example.com", ["php"]),
    ])
    _run(recon_dir, "normalize")
    a = {r["origin"]: r for r in _assets(recon_dir)}
    assert "http://example.com:80" in a            # default port + lowercased host
    assert "https://[2001:db8::1]:8443" in a        # bracketed IPv6
    assert a["https://dup.example.com:443"]["tech"] == ["nginx", "php"]  # merged dup


def test_host_ports_kept_separate_from_origin(recon_dir: Path) -> None:
    _wl(recon_dir / "httpx_raw.jsonl", [hx("https://h.example.com", ["nginx"])])
    _wl(recon_dir / "naabu.jsonl", [
        {"host": "h.example.com", "ip": "1.2.3.4", "port": 443},
        {"host": "h.example.com", "ip": "1.2.3.4", "port": 22},
        {"host": "h.example.com", "ip": "1.2.3.4", "port": 5432},
    ])
    _run(recon_dir, "normalize")
    assert _assets(recon_dir)[0]["ports"] == [443]
    hp = json.loads((recon_dir / "host_ports.json").read_text())
    assert hp["h.example.com"] == [22, 443, 5432]


def test_waf_joined_per_origin_not_broadcast(recon_dir: Path) -> None:
    _wl(recon_dir / "httpx_raw.jsonl", [
        hx("https://a.example.com", ["nginx"]),
        hx("https://b.example.com", ["nginx"]),
    ])
    (recon_dir / "wafw00f.json").write_text(json.dumps(
        [{"url": "https://a.example.com", "detected": True, "firewall": "Cloudflare"}]))
    _run(recon_dir, "normalize")
    a = {r["origin"]: r for r in _assets(recon_dir)}
    assert a["https://a.example.com:443"]["waf"] == "Cloudflare"
    assert a["https://b.example.com:443"]["waf"] is None   # not broadcast


def test_offhost_redirect_not_promoted(recon_dir: Path) -> None:
    _wl(recon_dir / "httpx_raw.jsonl", [
        hx("https://shop.example.com", [], status=302, url="https://evil.example.net/landing"),
    ])
    _run(recon_dir, "normalize")
    a = _assets(recon_dir)
    assert {r["origin"] for r in a} == {"https://shop.example.com:443"}  # dest not promoted
    assert a[0]["redirected_offhost"] is True
    assert a[0]["observed_origin"] == "https://evil.example.net:443"


def test_probe_state_no_response_vs_empty(recon_dir: Path) -> None:
    (recon_dir / "hosts.txt").write_text("https://up.example.com\nhttps://down.example.com\n")
    _wl(recon_dir / "httpx_raw.jsonl", [hx("https://up.example.com", ["nginx"])])
    _run(recon_dir, "normalize")
    a = {r["origin"]: r for r in _assets(recon_dir)}
    assert a["https://up.example.com:443"]["probe_state"] == "completed"
    assert a["https://down.example.com:443"]["probe_state"] == "no_response"


# --- selectors ----------------------------------------------------------------


def test_no_cross_origin_selector_leakage(recon_dir: Path) -> None:
    _wl(recon_dir / "httpx_raw.jsonl", [
        hx("https://shop.example.com", ["WordPress:6.5", "PHP"]),
        hx("https://api.example.com", []),
    ])
    _run(recon_dir, "normalize")
    m = _selectors(recon_dir)
    for g in m["groups"]:
        if "wordpress" in g["tags"]:
            assert g["origins"] == ["https://shop.example.com:443"]
        if g["origins"] == ["https://api.example.com:443"]:
            assert g["tags"] == []   # API origin never gets wordpress


def test_empty_tech_gets_bounded_baseline_no_tags(recon_dir: Path) -> None:
    _wl(recon_dir / "httpx_raw.jsonl", [hx("https://x.example.com", [])])
    _run(recon_dir, "normalize")
    assert _assets(recon_dir)[0]["probe_state"] == "unknown_tech"
    g = _selectors(recon_dir)["groups"][0]
    assert g["tags"] == []
    assert "http/exposures/" in g["template_paths"]
    assert "http/misconfiguration/" in g["template_paths"]


def test_unresolved_tag_no_broad_scan(recon_dir: Path) -> None:
    _wl(recon_dir / "httpx_raw.jsonl", [hx("https://y.example.com", ["TotallyUnknownFramework"])])
    _run(recon_dir, "normalize")
    g = _selectors(recon_dir)["groups"][0]
    assert g["tags"] == []            # unknown tag dropped, no -tags pass
    assert g["template_paths"]        # baseline still present


def test_default_logins_and_takeovers_conditional(recon_dir: Path) -> None:
    _wl(recon_dir / "httpx_raw.jsonl", [
        hx("https://admin.example.com", ["nginx"]),
        hx("https://www.example.com", ["nginx"]),
    ])
    _run(recon_dir, "normalize")
    rows = _assets(recon_dir)
    for r in rows:
        r["class"] = "admin" if r["host"].startswith("admin") else "marketing"
    _wl(recon_dir / "assets.jsonl", rows)
    m = _selectors(recon_dir)
    for g in m["groups"]:
        if g["origins"] == ["https://admin.example.com:443"]:
            assert "http/default-logins/" in g["template_paths"]
        if g["origins"] == ["https://www.example.com:443"]:
            assert "http/default-logins/" not in g["template_paths"]
            assert "http/takeovers/" not in g["template_paths"]


# --- run-state ----------------------------------------------------------------


def test_state_is_run_specific(recon_dir: Path) -> None:
    def st(*args: str) -> str:
        return _run(recon_dir, "state", *args).strip()

    assert st("get", "run1", "scopeA", "layer2") == "pending"
    st("set", "run1", "scopeA", "layer2", "completed")
    assert st("get", "run1", "scopeA", "layer2") == "completed"
    assert st("get", "run2", "scopeA", "layer2") == "pending"   # other run
    assert st("get", "run1", "scopeB", "layer2") == "pending"   # other scope
    st("set", "run1", "scopeA", "layer4", "skipped")
    assert st("get", "run1", "scopeA", "layer4") == "skipped"


# --- merge / dedup ------------------------------------------------------------


def test_merge_dedups_and_ignores_stale(recon_dir: Path) -> None:
    _wl(recon_dir / "nuclei.jsonl",
        [{"template-id": "STALE", "matched-at": "x", "matcher-name": ""}])
    dup = {"template-id": "wp-login", "matched-at": "https://a/wp", "matcher-name": "status"}
    _wl(recon_dir / "run_g1.jsonl", [dup, dict(dup)])
    _wl(recon_dir / "run_g2.jsonl",
        [{"template-id": "nginx-ver", "matched-at": "https://a:443", "matcher-name": "word"}])
    _run(recon_dir, "merge", "run_g1.jsonl", "run_g2.jsonl")
    out = _lines(recon_dir / "nuclei.jsonl")
    assert sorted(x["template-id"] for x in out) == ["nginx-ver", "wp-login"]
