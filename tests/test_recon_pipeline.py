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
    "nuclei_run": "# === strix-recon-nuclei-run ===",
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
    """Return a shim path usable as STRIX_NUCLEI_BIN. In ``-tl`` listing mode it
    emits fake ``.yaml`` lines: for ``-tags <known>`` two lines (validated),
    for ``-tags <unknown>`` none (invalid), and for ``-t <path>`` a count from
    STRIX_MOCK_TPL_PER_PATH (default 20). Without ``-tl`` (an actual scan) it
    exits 0 writing nothing."""
    mock = d / "mock_nuclei.py"
    mock.write_text(
        "import os, sys\n"
        "KNOWN={'wordpress','nginx','php','apache','laravel','drupal','joomla',"
        "'tomcat','jira','jenkins','gitlab','grafana','spring','kubernetes'}\n"
        "a=sys.argv\n"
        "def val(f):\n"
        "    return a[a.index(f)+1] if f in a and a.index(f)+1 < len(a) else None\n"
        "if '-tl' in a:\n"
        "    if '-tags' in a:\n"
        "        tag=val('-tags')\n"
        "        if tag in KNOWN:\n"
        "            print(f'http/technologies/{tag}-detect.yaml')\n"
        "            print(f'http/cves/2024/{tag}-x.yaml')\n"
        "    elif '-t' in a:\n"
        "        n=int(os.environ.get('STRIX_MOCK_TPL_PER_PATH','20'))\n"
        "        for i in range(n): print(f'http/t/{i}.yaml')\n"
        "    sys.exit(0)\n"
        "sys.exit(0)\n",
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


def _selectors(d: Path, nuclei: str | None = None) -> dict:
    _run(d, "selectors", nuclei=nuclei or _mock_nuclei(d))
    return json.loads((d / "nuclei_manifest.json").read_text())


def _unavailable_nuclei(d: Path) -> str:
    return str(d / "nonexistent_nuclei_bin")   # FileNotFoundError -> unverified/None


def _run_nuclei(d: Path, nuclei: str) -> tuple[list, list, list]:
    _run(d, "nuclei_run", nuclei=nuclei)
    return (
        json.loads((d / "nuclei_commands.json").read_text()),
        json.loads((d / "nuclei_skipped.json").read_text()),
        json.loads((d / "nuclei_layer4_summary.json").read_text()),
    )


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


def test_no_response_port_not_suppressed_by_sibling_origin(recon_dir: Path) -> None:
    # FIX 1: 443 responds 200; 8443 on the SAME host is refused (no httpx line).
    # Tracking by origin (not host) must still emit the 8443 no_response record.
    (recon_dir / "hosts.txt").write_text(
        "https://dual.example.com\nhttps://dual.example.com:8443\n")
    _wl(recon_dir / "httpx_raw.jsonl", [hx("https://dual.example.com", ["nginx"])])
    _run(recon_dir, "normalize")
    a = {r["origin"]: r for r in _assets(recon_dir)}
    assert set(a) == {"https://dual.example.com:443", "https://dual.example.com:8443"}
    assert a["https://dual.example.com:443"]["status_code"] == 200
    assert a["https://dual.example.com:443"]["probe_state"] == "completed"
    assert a["https://dual.example.com:8443"]["probe_state"] == "no_response"


# --- selectors ----------------------------------------------------------------


def test_no_cross_origin_selector_leakage(recon_dir: Path) -> None:
    _wl(recon_dir / "httpx_raw.jsonl", [
        hx("https://shop.example.com", ["WordPress:6.5", "PHP"]),
        hx("https://api.example.com", []),
    ])
    _run(recon_dir, "normalize")
    m = _selectors(recon_dir)
    for g in m["groups"]:
        if "wordpress" in g["tags_validated"]:
            assert g["origins"] == ["https://shop.example.com:443"]
        if g["origins"] == ["https://api.example.com:443"]:
            assert g["tags_validated"] == []   # API origin never gets wordpress
            assert g["tags_unverified"] == []


def test_empty_tech_gets_bounded_baseline_no_tags(recon_dir: Path) -> None:
    _wl(recon_dir / "httpx_raw.jsonl", [hx("https://x.example.com", [])])
    _run(recon_dir, "normalize")
    assert _assets(recon_dir)[0]["probe_state"] == "unknown_tech"
    g = _selectors(recon_dir)["groups"][0]
    assert g["tags_validated"] == []
    assert g["tags_unverified"] == []
    # explicit subdirectory allowlist, not whole parent dirs
    assert "http/exposures/configs/" in g["template_paths"]
    assert "http/misconfiguration/generic/" in g["template_paths"]
    assert "http/exposures/" not in g["template_paths"]


def test_unresolved_tag_no_broad_scan(recon_dir: Path) -> None:
    _wl(recon_dir / "httpx_raw.jsonl", [hx("https://y.example.com", ["TotallyUnknownFramework"])])
    _run(recon_dir, "normalize")
    g = _selectors(recon_dir)["groups"][0]
    assert g["tags_validated"] == []   # unknown tag -> invalid (nuclei available), no -tags
    assert g["tags_unverified"] == []
    assert g["template_paths"]         # baseline still present


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


# --- Layer-4 executor: baseline cap + enforced flags (FIX 2) ------------------


def _flat(cmds: list) -> list[str]:
    return [tok for cmd in cmds for tok in cmd]


def test_baseline_capped_and_flags_enforced(recon_dir: Path) -> None:
    _wl(recon_dir / "httpx_raw.jsonl", [hx("https://x.example.com", [])])  # empty tech
    _run(recon_dir, "normalize")
    mock = _mock_nuclei(recon_dir)
    _selectors(recon_dir, nuclei=mock)
    # 5 baseline paths * 20 templates each = 100 > MAX(50) -> must truncate
    env = dict(os.environ)
    env["STRIX_NUCLEI_BIN"] = mock
    env["STRIX_MOCK_TPL_PER_PATH"] = "20"
    r = subprocess.run(
        [sys.executable, str(recon_dir / "recon_nuclei_run.py")],
        cwd=recon_dir, env=env, capture_output=True, text=True, check=False,
    )
    assert r.returncode == 0, r.stderr
    cmds = json.loads((recon_dir / "nuclei_commands.json").read_text())
    summary = json.loads((recon_dir / "nuclei_layer4_summary.json").read_text())
    skipped = json.loads((recon_dir / "nuclei_skipped.json").read_text())
    assert summary[0]["baseline_total"] <= 50            # hard cap honored
    assert len(summary[0]["baseline_paths_kept"]) == 2    # 2*20=40, 3rd would exceed
    assert any("reached" in s.get("reason", "") for s in skipped)  # truncation logged
    flat = _flat(cmds)
    assert "-rl" in flat and "-c" in flat                 # enforced on actual argv


# --- Layer-4 executor: unverified selectors never execute (FIX 3) -------------


def test_unverified_tag_skipped_when_nuclei_unavailable(recon_dir: Path) -> None:
    _wl(recon_dir / "httpx_raw.jsonl", [hx("https://w.example.com", ["WordPress:6.5"])])
    _run(recon_dir, "normalize")
    bad = _unavailable_nuclei(recon_dir)
    m = _selectors(recon_dir, nuclei=bad)      # nuclei unavailable at build time
    g = m["groups"][0]
    assert g["tags_unverified"] == ["wordpress"]
    assert g["tags_validated"] == []
    cmds, skipped, _ = _run_nuclei(recon_dir, bad)   # still unavailable at exec
    assert not any("wordpress" in tok for tok in _flat(cmds))     # never executed
    assert any(s.get("tag") == "wordpress"
               and s["reason"] == "nuclei unavailable at validation time"
               for s in skipped)


def test_unverified_tag_revalidated_when_nuclei_returns(recon_dir: Path) -> None:
    _wl(recon_dir / "httpx_raw.jsonl", [hx("https://w.example.com", ["WordPress:6.5"])])
    _run(recon_dir, "normalize")
    bad = _unavailable_nuclei(recon_dir)
    m = _selectors(recon_dir, nuclei=bad)            # unverified at build
    assert m["groups"][0]["tags_unverified"] == ["wordpress"]
    cmds, _, _ = _run_nuclei(recon_dir, _mock_nuclei(recon_dir))  # available at exec
    flat = _flat(cmds)
    assert "-tags" in flat and any("wordpress" in tok for tok in flat)  # now executes


def test_validated_tag_normal_path(recon_dir: Path) -> None:
    _wl(recon_dir / "httpx_raw.jsonl", [hx("https://w.example.com", ["WordPress:6.5"])])
    _run(recon_dir, "normalize")
    mock = _mock_nuclei(recon_dir)
    m = _selectors(recon_dir, nuclei=mock)           # available throughout
    assert m["groups"][0]["tags_validated"] == ["wordpress"]
    cmds, skipped, _ = _run_nuclei(recon_dir, mock)
    assert any("wordpress" in tok for tok in _flat(cmds))
    assert not any(s.get("tag") == "wordpress" for s in skipped)
