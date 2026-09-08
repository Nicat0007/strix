"""Tests for Piece 13 (Cross-Source Correlation).

This piece is a pure textual/judgment fusion rule - unlike Piece 12 or
14, there is no deterministic algorithm to extract and execute, so there
is nothing to unit-test the way test_signal_class_field_weighting.py or
a future coverage-grid test would. What's verifiable, and worth guarding
against a future silent edit, is that the wiring between the three
skill files that make the fusion rule usable actually survives:
observed_id_pattern is defined where it's recorded, referenced where
it's produced, and consumed where it's read.
"""

from __future__ import annotations

from strix.skills import _qualified_skill_file_for_name


def _normalized(name: str) -> str:
    path = _qualified_skill_file_for_name(name)
    return " ".join(path.read_text(encoding="utf-8").split())


def test_mutation_candidates_schema_defines_observed_id_pattern() -> None:
    content = _normalized("analysis/parameter_mutation_testing")
    assert "observed_id_pattern" in content
    assert "sequential" in content
    assert "not derived from source, and not a guess from the parameter's" in content


def test_idor_points_at_where_to_record_the_observation() -> None:
    content = _normalized("vulnerabilities/idor")
    assert "observed_id_pattern" in content
    assert "mutation_candidates.md" in content


def test_candidate_triage_defines_the_fusion_rule_and_a_worked_example() -> None:
    content = _normalized("analysis/candidate_triage")
    assert "Cross-source fusion" in content
    assert "observed_id_pattern: sequential" in content
    assert "evidence_strength: high" in content
    # The worked example's negative branch must survive too - the fusion
    # rule is only meaningful if it can also NOT fire.
    assert "opaque" in content and "AND fails" in content


def test_all_three_skill_files_load_with_balanced_code_fences() -> None:
    for name in (
        "analysis/parameter_mutation_testing",
        "vulnerabilities/idor",
        "analysis/candidate_triage",
    ):
        path = _qualified_skill_file_for_name(name)
        raw = path.read_text(encoding="utf-8")
        assert raw.count("```") % 2 == 0, f"{name} has an unbalanced code fence"
