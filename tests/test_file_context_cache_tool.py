"""Tests for the per-scan, content-hash-keyed file summary cache."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any

import pytest

from strix.tools.file_context_cache.tools import (
    _query_impl,
    _record_impl,
    hydrate_file_context_cache_from_disk,
)


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def file_context_cache_store(tmp_path: Path) -> Path:
    hydrate_file_context_cache_from_disk(tmp_path)
    return tmp_path


def _hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


BASE_CLASS_CONTENT = """\
class SearchReplaceBase {
    function rewrite_length_headers($data) { /* ... */ }
}
"""


def test_two_agents_same_shared_base_class_second_gets_cache_hit() -> None:
    """The exact scenario the plan asked for: agent 1 reads and records a
    shared base class, agent 2 (different candidate, same file content)
    queries and gets the cached summary instead of re-reading it."""
    content_hash = _hash(BASE_CLASS_CONTENT)

    miss = _query_impl(file_path="includes/class-serializer-base.php", content_hash=content_hash)
    assert miss["success"] is True
    assert miss["hit"] is False

    recorded = _record_impl(
        file_path="includes/class-serializer-base.php",
        content_hash=content_hash,
        summary=(
            "Base class for search-replace serialization helpers. "
            "rewrite_length_headers() recalculates PHP-serialized s:<len> "
            "prefixes after find/replace so serialized strings stay valid."
        ),
        agent_name="agent-1-injection-hunter",
    )
    assert recorded["success"] is True
    assert recorded["created"] is True

    hit = _query_impl(
        file_path="includes/other-plugin/vendored-serializer-base.php",  # different path, same content
        content_hash=content_hash,
    )
    assert hit["success"] is True
    assert hit["hit"] is True
    assert "rewrite_length_headers" in hit["summary"]
    assert hit["first_recorded_for_path"] == "includes/class-serializer-base.php"
    assert hit["recorded_by"] == "agent-1-injection-hunter"


def test_different_content_is_a_miss_even_at_the_same_path() -> None:
    path = "includes/class-serializer-base.php"
    _record_impl(file_path=path, content_hash=_hash("v1"), summary="version 1 of the file")

    miss = _query_impl(file_path=path, content_hash=_hash("v2 - one byte different"))
    assert miss["hit"] is False


def test_recording_the_same_content_again_upserts_not_duplicates() -> None:
    content_hash = _hash(BASE_CLASS_CONTENT)
    first = _record_impl(file_path="a.php", content_hash=content_hash, summary="first pass")
    assert first["created"] is True

    second = _record_impl(
        file_path="a.php", content_hash=content_hash, summary="refined summary", agent_name="agent-2"
    )
    assert second["created"] is False

    hit = _query_impl(file_path="a.php", content_hash=content_hash)
    assert hit["summary"] == "refined summary"
    assert hit["recorded_by"] == "agent-2"


def test_rejects_malformed_content_hash() -> None:
    result = _record_impl(file_path="a.php", content_hash="not-a-real-hash", summary="x")
    assert result["success"] is False
    assert "Invalid content_hash" in result["error"]

    query_result = _query_impl(file_path="a.php", content_hash="short")
    assert query_result["success"] is False


def test_rejects_empty_summary_and_empty_path() -> None:
    content_hash = _hash("x")
    assert _record_impl(file_path="a.php", content_hash=content_hash, summary="   ")["success"] is False
    assert _record_impl(file_path="  ", content_hash=content_hash, summary="a real summary")[
        "success"
    ] is False


def test_hydrate_reloads_from_disk(file_context_cache_store: Path) -> None:
    content_hash = _hash(BASE_CLASS_CONTENT)
    _record_impl(file_path="a.php", content_hash=content_hash, summary="a summary")

    hydrate_file_context_cache_from_disk(file_context_cache_store)

    hit = _query_impl(file_path="a.php", content_hash=content_hash)
    assert hit["hit"] is True
    assert hit["summary"] == "a summary"

    on_disk = json.loads((file_context_cache_store / "file_context_cache.json").read_text())
    assert on_disk["schema_version"] == 1
    assert content_hash in on_disk["entries"]


def test_hash_is_case_insensitive_on_lookup() -> None:
    content_hash = _hash("x")
    _record_impl(file_path="a.php", content_hash=content_hash, summary="s")
    hit = _query_impl(file_path="a.php", content_hash=content_hash.upper())
    assert hit["hit"] is True
