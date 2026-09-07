"""Tests for the persistent cross-scan negative-knowledge cache."""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any

import pytest

from strix.tools.negative_knowledge.tools import (
    _query_impl,
    _record_impl,
    _signature_hash,
    hydrate_negative_knowledge_from_disk,
)


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def negative_knowledge_store(tmp_path: Path) -> Path:
    path = tmp_path / "negative_knowledge.json"
    hydrate_negative_knowledge_from_disk(path)
    return path


def _record(**overrides: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "framework": "wordpress-plugin",
        "vulnerability_class": "insecure_deserialization",
        "mechanism_signature": ["maybe_unserialize", "allowed_classes_false"],
        "mechanism": "unserialize() calls are guarded with allowed_classes=false.",
        "outcome": "ruled_out",
        "location": "includes/class-import.php:88",
        "source_target_hash": "sha256:" + "a" * 64,
        "agent_name": "test-agent",
    }
    kwargs.update(overrides)
    return _record_impl(**kwargs)


def _query(**overrides: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "framework": "wordpress-plugin",
        "vulnerability_class": "insecure_deserialization",
        "mechanism_signature": ["maybe_unserialize", "allowed_classes_false"],
    }
    kwargs.update(overrides)
    return _query_impl(**kwargs)


def test_record_persists_and_creates_new_entry(negative_knowledge_store: Path) -> None:
    result = _record()
    assert result["success"] is True
    assert result["created"] is True
    assert result["corroborations"] == 1
    assert negative_knowledge_store.exists()


def test_query_exact_match_is_order_and_case_insensitive() -> None:
    _record()
    result = _query(
        framework="WordPress-Plugin",
        mechanism_signature=["allowed_classes_false", "maybe_unserialize"],
    )
    assert result["exact_match"] is not None
    assert result["exact_match"]["outcome"] == "ruled_out"
    assert result["exact_match"]["corroborations"] == 1


def test_query_with_no_prior_entry_returns_no_exact_match() -> None:
    result = _query()
    assert result["success"] is True
    assert result["exact_match"] is None
    assert result["related_in_bucket"] == []
    assert result["bucket_count"] == 0


def test_exact_match_never_leaks_internal_source_hashes() -> None:
    _record()
    result = _query()
    assert "source_target_hashes" not in result["exact_match"]


def test_corroboration_increments_once_per_distinct_target() -> None:
    _record(source_target_hash="sha256:" + "a" * 64)
    second = _record(source_target_hash="sha256:" + "b" * 64)
    assert second["created"] is False
    assert second["corroborations"] == 2

    # Same target recording again must not double count.
    third = _record(source_target_hash="sha256:" + "b" * 64)
    assert third["corroborations"] == 2


def test_recording_without_a_source_hash_does_not_count_as_corroboration() -> None:
    result = _record(source_target_hash=None)
    assert result["corroborations"] == 0

    again = _record(source_target_hash="sha256:" + "a" * 64)
    assert again["corroborations"] == 1


def test_different_signature_same_bucket_is_related_not_exact() -> None:
    _record()
    _record(
        mechanism_signature=["is_serialized_check", "phar_stream_wrapper_unregister"],
        mechanism="A different, unrelated safe pattern.",
        location="inc/other.php:5",
        source_target_hash="sha256:" + "c" * 64,
    )

    result = _query()
    assert result["exact_match"] is not None
    assert len(result["related_in_bucket"]) == 1
    assert result["related_in_bucket"][0]["mechanism_signature"] == [
        "is_serialized_check",
        "phar_stream_wrapper_unregister",
    ]
    assert result["bucket_count"] == 2


def test_different_framework_never_appears_in_bucket() -> None:
    _record()
    _record(framework="django-rest-framework")

    result = _query(framework="wordpress-plugin")
    assert result["related_in_bucket"] == []


def test_signature_hash_is_pure_function_of_normalized_token_set() -> None:
    assert _signature_hash(["a", "b"]) == _signature_hash(["a", "b"])
    assert _signature_hash(["a", "b"]) != _signature_hash(["a", "c"])


def test_rejects_unknown_vulnerability_class() -> None:
    result = _record(vulnerability_class="not-a-real-skill")
    assert result["success"] is False
    assert any("Invalid vulnerability_class" in e for e in result["errors"])


def test_rejects_fewer_than_two_signature_tokens() -> None:
    result = _record(mechanism_signature=["unserialize"])
    assert result["success"] is False
    assert any("at least 2" in e for e in result["errors"])


def test_rejects_bad_outcome() -> None:
    result = _record(outcome="no_issue_found_probably")
    assert result["success"] is False
    assert any("Invalid outcome" in e for e in result["errors"])


@pytest.mark.parametrize("outcome", ["ruled_out", "no_issue_found"])
def test_accepts_both_eligible_outcomes(outcome: str) -> None:
    assert _record(outcome=outcome)["success"] is True


def test_rejects_empty_mechanism_and_empty_location() -> None:
    result = _record(mechanism="   ", location="")
    assert result["success"] is False
    joined = " ".join(result["errors"])
    assert "mechanism cannot be empty" in joined
    assert "location cannot be empty" in joined


def test_example_locations_cap_at_five_most_recent() -> None:
    for i in range(8):
        _record(location=f"file{i}.php:1", source_target_hash=f"sha256:{i:064d}")
    result = _query()
    assert len(result["exact_match"]["example_locations"]) == 5
    assert result["exact_match"]["example_locations"][-1] == "file7.php:1"


def test_hydrate_reloads_from_disk(negative_knowledge_store: Path) -> None:
    _record()
    hydrate_negative_knowledge_from_disk(negative_knowledge_store)
    result = _query()
    assert result["exact_match"] is not None
    assert result["exact_match"]["corroborations"] == 1


def test_disabled_query_returns_no_match_without_touching_store() -> None:
    _record()
    result = _query_impl(
        framework="wordpress-plugin",
        vulnerability_class="insecure_deserialization",
        mechanism_signature=["maybe_unserialize", "allowed_classes_false"],
        enabled=False,
    )
    assert result["success"] is True
    assert result["enabled"] is False
    assert result["exact_match"] is None


def test_disabled_record_does_not_persist(negative_knowledge_store: Path) -> None:
    result = _record_impl(
        framework="wordpress-plugin",
        vulnerability_class="insecure_deserialization",
        mechanism_signature=["maybe_unserialize", "allowed_classes_false"],
        mechanism="x",
        outcome="ruled_out",
        location="f.php:1",
        enabled=False,
    )
    assert result["success"] is True
    assert result["enabled"] is False
    assert "created" not in result

    hydrate_negative_knowledge_from_disk(negative_knowledge_store)
    assert _query()["exact_match"] is None


def test_persistence_survives_a_fresh_hydrate_across_a_new_entry_and_an_update(
    negative_knowledge_store: Path,
) -> None:
    _record()
    _record(source_target_hash="sha256:" + "b" * 64)

    hydrate_negative_knowledge_from_disk(negative_knowledge_store)

    on_disk = json.loads(negative_knowledge_store.read_text(encoding="utf-8"))
    assert on_disk["schema_version"] == 1
    (entry,) = on_disk["entries"].values()
    assert entry["corroborations"] == 2
    assert len(entry["source_target_hashes"]) == 2


def test_concurrent_records_of_one_signature_all_survive_as_one_entry(
    negative_knowledge_store: Path,
) -> None:
    barrier = threading.Barrier(8)

    def attempt(index: int) -> dict[str, Any]:
        barrier.wait()
        return _record(source_target_hash=f"sha256:{index:064d}")

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(8)))

    assert all(r["success"] for r in results)

    result = _query()
    assert result["bucket_count"] == 1
    assert result["exact_match"]["corroborations"] == 8

    hydrate_negative_knowledge_from_disk(negative_knowledge_store)
    assert _query()["exact_match"]["corroborations"] == 8
