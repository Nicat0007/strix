"""Tests for the shared target-identity normalizer.

Mirrors the identity-resolution scenarios in ``test_threat_model_tool.py``
(the original owner of this logic before it moved to
``strix.utils.target_identity``), calling the public function directly.
"""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

from strix.utils.target_identity import target_identity


if TYPE_CHECKING:
    from pathlib import Path


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["/usr/bin/env", "git", *args], cwd=repo, check=True)  # noqa: S603


def _make_repo(tmp_path: Path, name: str = "repo") -> Path:
    repo = tmp_path / name
    repo.mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    (repo / "README.md").write_text("hi\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-qm", "init")
    return repo


def test_blackbox_target_spellings_collapse_to_one_identity() -> None:
    identity = target_identity("https://App.Example.com:443/")
    for spelling in (
        "https://app.example.com",
        "app.example.com",
        "https://app.example.com/",
    ):
        assert target_identity(spelling) == identity


def test_different_hosts_have_different_identities() -> None:
    assert target_identity("https://app.example.com") != target_identity(
        "https://other.example.com"
    )


def test_default_ports_are_implied() -> None:
    assert target_identity("https://app.example.com") == target_identity(
        "https://app.example.com:443"
    )
    assert target_identity("http://app.example.com") == target_identity(
        "http://app.example.com:80"
    )


def test_paths_on_one_host_stay_distinct() -> None:
    assert target_identity("https://example.com/tenant-a") != target_identity(
        "https://example.com/tenant-b"
    )


def test_checkout_and_its_remote_url_are_one_identity(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    _git(repo, "remote", "add", "origin", "https://github.com/acme/billing.git")

    assert target_identity(str(repo)) == target_identity("https://github.com/acme/billing")
    assert target_identity(str(repo)) == target_identity("https://github.com/acme/billing.git")


def test_ssh_and_https_remotes_are_one_identity(tmp_path: Path) -> None:
    over_ssh = _make_repo(tmp_path, "ssh-clone")
    _git(over_ssh, "remote", "add", "origin", "git@github.com:acme/billing.git")

    over_https = _make_repo(tmp_path, "https-clone")
    _git(over_https, "remote", "add", "origin", "https://github.com/acme/billing.git")

    assert target_identity(str(over_ssh)) == target_identity(str(over_https))


def test_different_repositories_on_one_host_stay_separate(tmp_path: Path) -> None:
    first = _make_repo(tmp_path, "billing")
    _git(first, "remote", "add", "origin", "git@github.com:acme/billing.git")

    second = _make_repo(tmp_path, "payments")
    _git(second, "remote", "add", "origin", "git@github.com:acme/payments.git")

    assert target_identity(str(first)) != target_identity(str(second))


def test_repository_subdirectory_shares_the_repository_identity(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    (repo / "src").mkdir()

    assert target_identity(str(repo / "src")) == target_identity(str(repo))


def test_remoteless_repo_falls_back_to_its_toplevel(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    (repo / "src").mkdir()

    # No remote configured: identity falls back to `git rev-parse
    # --show-toplevel`, which a subdirectory resolves to the same value as.
    assert target_identity(str(repo / "src")) == target_identity(str(repo))
    assert target_identity(str(repo)) == str(repo.resolve())


def test_non_git_directory_falls_back_to_its_resolved_path(tmp_path: Path) -> None:
    plain = tmp_path / "not-a-repo"
    plain.mkdir()

    assert target_identity(str(plain)) == str(plain.resolve())
