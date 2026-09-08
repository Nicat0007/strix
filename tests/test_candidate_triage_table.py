"""Tests for Piece 11 (Hypothesis Priority Queue): verifies the actual
markdown lookup table committed in analysis/candidate_triage.md is
internally consistent with the documented generation formula, and checks
the specific edge cases called out in the design conversation plus a
couple more.

This is a skill-only piece with no production Python code — the "code"
under test is the committed markdown table itself, parsed directly from
the file so a future hand-edit that breaks a cell gets caught.
"""

from __future__ import annotations

import re

from strix.skills import _qualified_skill_file_for_name


_SCORE = {
    "impact": {"high": 2, "medium": 1, "low": 0},
    "evidence_strength": {"high": 2, "medium": 1, "low": 0},
    "test_cost": {"low": 2, "medium": 1, "high": 0},  # inverted: cheap is good
}


def _expected_bucket(impact: str, evidence_strength: str, test_cost: str) -> str:
    total = (
        _SCORE["impact"][impact]
        + _SCORE["evidence_strength"][evidence_strength]
        + _SCORE["test_cost"][test_cost]
    )
    if total >= 5:
        return "P0"
    if total >= 3:
        return "P1"
    if total >= 2:
        return "P2"
    return "P3"


def _parse_table_rows() -> list[tuple[str, str, str, str]]:
    path = _qualified_skill_file_for_name("analysis/candidate_triage")
    content = path.read_text(encoding="utf-8")
    row_pattern = re.compile(
        r"^\|\s*(high|medium|low)\s*\|\s*(high|medium|low)\s*\|\s*(high|medium|low)\s*\|\s*(P[0-3])\s*\|$",
        re.MULTILINE,
    )
    rows = row_pattern.findall(content)
    assert rows, "no table rows parsed - the table format in the skill file may have changed"
    return rows


def test_the_full_table_has_exactly_27_rows() -> None:
    rows = _parse_table_rows()
    assert len(rows) == 27, f"expected all 27 impact x evidence x cost combinations, got {len(rows)}"


def test_every_row_in_the_committed_table_matches_the_documented_formula() -> None:
    """Catches a hand-transcription error in the markdown table itself -
    the actual regression this test exists for."""
    rows = _parse_table_rows()
    mismatches = [
        (impact, evidence, cost, bucket, _expected_bucket(impact, evidence, cost))
        for impact, evidence, cost, bucket in rows
        if bucket != _expected_bucket(impact, evidence, cost)
    ]
    assert not mismatches, f"table cells disagree with the generation formula: {mismatches}"


def test_all_27_combinations_are_present_with_no_duplicates() -> None:
    rows = _parse_table_rows()
    keys = [(impact, evidence, cost) for impact, evidence, cost, _ in rows]
    assert len(keys) == len(set(keys)), "duplicate (impact, evidence, cost) row found"
    levels = ["high", "medium", "low"]
    expected_keys = {(i, e, c) for i in levels for e in levels for c in levels}
    assert set(keys) == expected_keys


def _bucket_of(rows: list[tuple[str, str, str, str]], impact: str, evidence: str, cost: str) -> str:
    for row_impact, row_evidence, row_cost, bucket in rows:
        if (row_impact, row_evidence, row_cost) == (impact, evidence, cost):
            return bucket
    raise AssertionError(f"row not found: {impact}/{evidence}/{cost}")


def test_edge_cases_from_the_design_conversation() -> None:
    rows = _parse_table_rows()
    assert _bucket_of(rows, "high", "low", "high") == "P2", (
        "a potentially critical bug must not be buried at P3 just because it's hard to check"
    )
    assert _bucket_of(rows, "high", "low", "low") == "P1", (
        "cheap enough to check regardless of weak evidence, but P0 is reserved for "
        "candidates with real evidence behind them"
    )
    assert _bucket_of(rows, "low", "high", "low") == "P1", (
        "a cheap, well-evidenced check is still worth doing early despite low payoff"
    )
    assert _bucket_of(rows, "high", "high", "high") == "P1", (
        "genuinely strong but expensive - shouldn't jump ahead of equally strong cheaper work"
    )


def test_two_additional_edge_cases() -> None:
    rows = _parse_table_rows()
    # Best possible case must be the top bucket.
    assert _bucket_of(rows, "high", "high", "low") == "P0"
    # Worst possible case must be the bottom bucket.
    assert _bucket_of(rows, "low", "low", "high") == "P3"


def test_low_low_low_is_p2_not_p3_the_least_intuitive_cell() -> None:
    """A zero-cost check should never sit at the very bottom just because
    nobody expects much from it - explicitly called out in the skill file
    as the least intuitive cell, worth its own regression test."""
    rows = _parse_table_rows()
    assert _bucket_of(rows, "low", "low", "low") == "P2"


def test_priority_is_never_used_as_a_gate_language_present() -> None:
    """Confirms the non-negotiable language survives in the file - a
    cheap textual guard against someone editing the table section and
    accidentally dropping the constraint.

    Whitespace-normalized: the file's own ~78-80-char soft-wrap style can
    split a check phrase across lines (the exact false alarm noted
    elsewhere in this project's history for a different file) - comparing
    on raw text with an embedded newline would fail on a wrap change that
    didn't alter the actual words at all.
    """
    path = _qualified_skill_file_for_name("analysis/candidate_triage")
    normalized = " ".join(path.read_text(encoding="utf-8").split())
    assert "never a filter and never a gate" in normalized
    assert "does not override a reason you already have" in normalized
