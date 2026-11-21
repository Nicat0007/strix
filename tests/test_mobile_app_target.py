"""Tests for the mobile_app (.apk) target type — Phase 1 static-APK plumbing.

Verifies host-side classification, staging, whitebox selection, scope and
root-task rendering. Decompilation itself happens in the sandbox entrypoint and
is not exercised here (no Docker).
"""

from __future__ import annotations

from pathlib import Path

from strix.core.inputs import (
    build_root_task,
    build_scope_context,
    is_whitebox_targets,
)
from strix.interface.utils import (
    MOBILE_APP_WORKSPACE_SUBDIR,
    infer_target_type,
    stage_mobile_apps,
)


def test_apk_file_is_classified_as_mobile_app(tmp_path: Path) -> None:
    apk = tmp_path / "myapp.apk"
    apk.write_bytes(b"PK\x03\x04 not-a-real-apk")  # suffix is what classifies it
    ttype, details = infer_target_type(str(apk))
    assert ttype == "mobile_app"
    assert details["target_apk"] == str(apk.resolve())
    assert details["mobile_platform"] == "android"


def test_apk_suffix_wins_over_spec_probe(tmp_path: Path) -> None:
    # A file that could confuse the spec probe must still classify as mobile_app.
    apk = tmp_path / "weird.apk"
    apk.write_text("{}")  # looks JSON-ish, but .apk suffix must win
    ttype, _ = infer_target_type(str(apk))
    assert ttype == "mobile_app"


def test_mobile_app_is_whitebox() -> None:
    assert is_whitebox_targets([{"type": "mobile_app", "details": {"target_apk": "/x/a.apk"}}])
    # a web-only run is still not whitebox
    assert not is_whitebox_targets([{"type": "web_application", "details": {}}])


def test_stage_mobile_apps_copies_and_sets_workspace_path(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"apkbytes")
    target = {"type": "mobile_app", "details": {"target_apk": str(apk)}}
    sources = stage_mobile_apps([target], run_name="run1")
    assert len(sources) == 1
    assert sources[0]["workspace_subdir"] == MOBILE_APP_WORKSPACE_SUBDIR
    expected = f"/workspace/{MOBILE_APP_WORKSPACE_SUBDIR}/app.apk"
    assert target["details"]["workspace_path"] == expected
    # the staged copy actually exists on disk
    assert (Path(sources[0]["source_path"]) / "app.apk").exists()


def test_stage_mobile_apps_empty_when_no_apk() -> None:
    assert stage_mobile_apps([{"type": "web_application", "details": {}}], run_name="r") == []


def test_scope_context_uses_target_apk() -> None:
    cfg = {"targets": [{"type": "mobile_app",
                        "details": {"target_apk": "/x/app.apk",
                                    "workspace_subdir": MOBILE_APP_WORKSPACE_SUBDIR}}]}
    ctx = build_scope_context(cfg)
    entry = next(a for a in ctx["authorized_targets"] if a["type"] == "mobile_app")
    assert entry["value"] == "/x/app.apk"
    assert entry["workspace_path"] == f"/workspace/{MOBILE_APP_WORKSPACE_SUBDIR}"


def test_root_task_renders_mobile_section() -> None:
    cfg = {"targets": [{"type": "mobile_app",
                        "details": {"target_apk": "/x/app.apk",
                                    "workspace_subdir": MOBILE_APP_WORKSPACE_SUBDIR}}]}
    task = build_root_task(cfg)
    assert "Mobile Applications:" in task
    assert "/x/app.apk" in task
    assert "frameworks/android.md" in task
    assert "decompiled" in task.lower()
