"""Tests for Piece 12 (Security-Sensitive Field Weighting).

parameter_mutation_testing.md's Layer B signal_class engine has no
production Python implementation anywhere (it's a spec an LLM agent
follows at request-time, per Piece 3's own verification precedent) - so
this extracts the actual committed keyword list from the skill file
(never a hand-retyped copy) and implements the documented 5-rule
algorithm exactly, to confirm the spec is internally consistent before
trusting it.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from strix.skills import _qualified_skill_file_for_name


def _extract_patterns() -> list[str]:
    path = _qualified_skill_file_for_name("analysis/parameter_mutation_testing")
    content = path.read_text(encoding="utf-8")
    match = re.search(r"_SECURITY_SENSITIVE_FIELD_PATTERNS = \((.*?)\)\n```", content, re.DOTALL)
    assert match, "could not find the keyword list block in the skill file"
    return re.findall(r'"([^"]+)"', match.group(1))


PATTERNS = _extract_patterns()


def _last_segment(path: str) -> str:
    return path.rsplit(".", 1)[-1].lower()


def _matches_sensitive(path: str) -> bool:
    seg = _last_segment(path)
    return any(p in seg for p in PATTERNS)


def _derive_signal_class(
    *,
    retry_required: bool = False,
    status_changed: bool = False,
    same_key_set: bool = True,
    type_changes: dict[str, Any] | None = None,
    array_length_deltas_nonzero_non_pagination: bool = False,
    value_deltas: dict[str, Any] | None = None,
    out_of_expected_range_any: bool = False,
    beyond_noise: bool = False,
) -> str:
    type_changes = type_changes or {}
    value_deltas = value_deltas or {}
    if retry_required:
        return "inconclusive"
    if status_changed:
        return "status"
    if (not same_key_set) or type_changes or array_length_deltas_nonzero_non_pagination:
        return "structural"
    sensitive_hit = any(_matches_sensitive(k) for k in value_deltas) or any(
        _matches_sensitive(k) for k in type_changes
    )
    if out_of_expected_range_any or beyond_noise or sensitive_hit:
        return "value"
    return "none"


def test_keyword_list_excludes_token_session_and_api_key() -> None:
    assert "token" not in PATTERNS
    assert "session" not in PATTERNS
    assert "api_key" not in PATTERNS


def test_owner_id_change_with_identical_status_and_size_is_value_not_none() -> None:
    """The exact scenario from the design conversation."""
    result = _derive_signal_class(value_deltas={"data.owner_id": {"before": "A", "after": "B"}})
    assert result == "value"


def test_non_sensitive_field_change_alone_is_still_none() -> None:
    result = _derive_signal_class(
        value_deltas={"data.display_name": {"before": "Alice", "after": "Alicia"}}
    )
    assert result == "none"


def test_status_change_takes_precedence_over_a_sensitive_field_hit() -> None:
    """Rule ordering must be preserved - a status change alone already
    explains the diff, per rule 2, ahead of the new rule 4 check."""
    result = _derive_signal_class(
        status_changed=True, value_deltas={"data.owner_id": {"before": "A", "after": "B"}}
    )
    assert result == "status"


def test_matching_is_case_insensitive() -> None:
    result = _derive_signal_class(value_deltas={"data.Owner_ID": {"before": "A", "after": "B"}})
    assert result == "value"


def test_matching_is_scoped_to_the_last_path_segment_only() -> None:
    """A parent key that looks sensitive must not cause a false match when
    the actual changed leaf field does not."""
    result = _derive_signal_class(value_deltas={"role_assignments.count": {"before": 3, "after": 4}})
    assert result == "none"


def test_excluded_token_session_names_do_not_trigger() -> None:
    result = _derive_signal_class(
        value_deltas={"data.session_token": {"before": "abc", "after": "xyz"}}
    )
    assert result == "none"


def test_sensitive_field_in_type_changes_is_subsumed_by_the_structural_rule() -> None:
    """type_changes being non-empty already triggers rule 3 regardless of
    field name - rule 3 takes precedence, the sensitive-field check in
    rule 4 never needs to fire here."""
    result = _derive_signal_class(type_changes={"data.is_admin": ("bool", "null")})
    assert result == "structural"


@pytest.mark.parametrize(
    "pattern",
    ["owner_id", "role", "is_admin", "tenant_id", "price", "status", "permission"],
)
def test_representative_keywords_from_each_category_actually_trigger(pattern: str) -> None:
    result = _derive_signal_class(value_deltas={f"data.{pattern}": {"before": 1, "after": 2}})
    assert result == "value", f"expected keyword {pattern!r} to trigger a value signal"
