"""Tests for the durable black-box coverage matrix (BLACKBOX #6 Part B).

Exercises committed production code: the deterministic planner seeded from the
real attack-surface inventory, applicability-vs-execution tracking, and the hard
rules (evidence-required not_applicable, one-negative-never-closes-a-family,
budget-exhaustion-stays-unfinished, new-evidence-reopens, resume-flags-stale,
missing-capability-is-a-gap).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from strix.report.coverage import build_coverage_document
from strix.skills import get_all_skill_names
from strix.tools.attack_surface.tools import _record_impl, hydrate_attack_surface_from_disk
from strix.tools.component_research.tools import hydrate_component_research_from_disk
from strix.tools.coverage_matrix.tools import (
    CAPABILITY,
    FAMILIES,
    FAMILY_MAP,
    assess_impl,
    coverage_gaps_impl,
    hydrate_coverage_matrix_from_disk,
    next_coverage_task_impl,
    plan_coverage_impl,
    query_impl,
)
from strix.tools.hypotheses.tools import hydrate_hypotheses_from_disk


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _stores(tmp_path: Path) -> Path:
    hydrate_attack_surface_from_disk(tmp_path)
    hydrate_hypotheses_from_disk(tmp_path)
    hydrate_coverage_matrix_from_disk(tmp_path)
    return tmp_path


def _endpoint(url: str, method: str = "GET", params: list[dict[str, str]] | None = None,
              **kw: Any) -> None:
    _record_impl(url=url, method=method, parameters=params or [], discovery_source="crawl", **kw)


# --------------------------------------------------------------------------- #
# Family -> capability registry is complete and points at real skills/gaps
# --------------------------------------------------------------------------- #


def test_every_family_has_a_valid_mapping_or_explicit_gap() -> None:
    skills = get_all_skill_names()
    for fam in FAMILIES:
        assert fam in FAMILY_MAP, f"family {fam} missing from FAMILY_MAP"
        entry = FAMILY_MAP[fam]
        assert entry["capability"] in CAPABILITY
        assert entry["prereqs"], f"{fam} has no prerequisites listed"
        skill = entry["skill"]
        if skill:
            assert skill in skills, f"{fam} -> skill {skill!r} does not resolve"
        else:
            # No dedicated skill is only allowed as an EXPLICIT capability gap.
            assert entry["capability"] == "missing", f"{fam} has no skill but isn't a gap"


def test_formerly_missing_families_now_have_a_resolved_methodology() -> None:
    # The five previously-unsupported families are resolved via a concrete
    # agent-driven skill (no dedicated executor) — not left as silent gaps and
    # not manufactured not_applicable.
    skills = get_all_skill_names()
    for fam in ("ldap_injection", "xpath_injection", "parameter_pollution",
                "websocket", "cache_poisoning"):
        entry = FAMILY_MAP[fam]
        assert entry["skill"] == "underserved_families" and entry["skill"] in skills
        assert entry["capability"] == "agent_tools"  # reachable path, no executor
    # No family remains an unresolved capability gap.
    assert not [f for f, e in FAMILY_MAP.items() if e["capability"] == "missing"]


# --------------------------------------------------------------------------- #
# not_applicable needs evidence
# --------------------------------------------------------------------------- #


def test_not_applicable_requires_rationale_and_evidence() -> None:
    bad = assess_impl(surface_type="origin", surface_id="http://t", family="sqli",
                      applicability="not_applicable")
    assert bad["success"] is False and bad["rejected"] == "not_applicable_needs_evidence"
    ok = assess_impl(surface_type="origin", surface_id="http://t", family="sqli",
                     applicability="not_applicable",
                     applicability_rationale="no server-side data layer; static CDN origin",
                     evidence_refs=["probe:home-200-static"])
    assert ok["success"] is True and ok["applicability"] == "not_applicable"


# --------------------------------------------------------------------------- #
# Deterministic planner
# --------------------------------------------------------------------------- #


def test_plan_seeds_every_family_per_origin_as_unknown() -> None:
    _endpoint("http://app.test/home")
    plan_coverage_impl(create_hypotheses=False)
    origin_cells = query_impl(surface_type="origin", limit=1000)["cells"]
    origins = {c["surface_id"] for c in origin_cells}
    assert len(origins) == 1  # one seeded origin
    origin = origins.pop()
    fams = {c["family"] for c in origin_cells if c["surface_id"] == origin}
    assert fams == set(FAMILIES)  # EVERY family explicitly assessed
    assert all(c["applicability"] == "unknown" and c["execution"] == "not_started"
               for c in origin_cells)


def test_signal_creates_unknown_assessment_work_not_applicable() -> None:
    _endpoint("http://app.test/search", params=[{"name": "q", "location": "query"}])
    plan_coverage_impl(create_hypotheses=False)
    # A parameter signal is a RELEVANT TEST SURFACE, not established applicability:
    # the route cell stays unknown with a bounded assessment task + rationale.
    sqli = query_impl(surface_type="route", family="sqli")["cells"]
    assert sqli and sqli[0]["applicability"] == "unknown"
    assert "signal" in sqli[0]["applicability_rationale"] and sqli[0]["planned_checks"]
    # The planner NEVER sets applicable or not_applicable — those are judgements.
    assert query_impl(applicability="applicable")["total"] == 0
    assert query_impl(applicability="not_applicable")["total"] == 0


def test_weak_signal_does_not_establish_prerequisites() -> None:
    # id-param + 2 actors: signals for idor/bfla, but ownership/distinct principals
    # are NOT established — the cells stay unknown and name the assessment needed.
    _endpoint("http://app.test/o?id=1", params=[{"name": "id", "location": "query"}],
              actor_ref="a")
    _endpoint("http://app.test/o?id=1", params=[{"name": "id", "location": "query"}],
              actor_ref="b")
    plan_coverage_impl(create_hypotheses=True)
    idor = query_impl(surface_type="route", family="idor_bola")["cells"]
    assert idor and idor[0]["applicability"] == "unknown"
    assert "NOT proof of ownership" in idor[0]["applicability_rationale"]
    bfla = query_impl(surface_type="route", family="bfla")["cells"]
    assert bfla and "NOT proof of distinct principals" in bfla[0]["applicability_rationale"]
    # idor/bfla are NOT auto-hypothesized from a weak signal (prereqs unmet).
    assert not idor[0]["hypothesis_refs"] and not bfla[0]["hypothesis_refs"]


def test_auto_hypothesis_only_for_probe_trigger_families() -> None:
    _endpoint("http://app.test/s", params=[{"name": "q", "location": "query"}])
    plan_coverage_impl(create_hypotheses=True)
    # sqli/xss get a linked bet (a parameter is a sufficient probe trigger)...
    assert query_impl(surface_type="route", family="sqli")["cells"][0]["hypothesis_refs"]
    assert query_impl(surface_type="route", family="xss")["cells"][0]["hypothesis_refs"]
    # ...command_injection/ssti do NOT (same param, but no confirmed backend/bet).
    assert not query_impl(surface_type="route",
                          family="command_injection")["cells"][0]["hypothesis_refs"]


def test_origin_unknown_families_carry_assessment_work() -> None:
    _endpoint("http://app.test/home")
    plan_coverage_impl(create_hypotheses=False)
    origin_cells = query_impl(surface_type="origin", limit=1000)["cells"]
    # Every origin-level unknown family is actionable (has an assessment task).
    assert all(c["planned_checks"] for c in origin_cells)
    assert all(c["applicability"] == "unknown" for c in origin_cells)


# --------------------------------------------------------------------------- #
# One negative never closes a family / siblings
# --------------------------------------------------------------------------- #


def test_tested_one_route_does_not_cover_siblings_or_family() -> None:
    _endpoint("http://app.test/a", params=[{"name": "q", "location": "query"}])
    _endpoint("http://app.test/b", params=[{"name": "q", "location": "query"}])
    plan_coverage_impl(create_hypotheses=False)
    routes = query_impl(surface_type="route", family="sqli")["cells"]
    assert len(routes) == 2
    first = routes[0]
    assess_impl(surface_type="route", surface_id=first["surface_id"], family="sqli",
                execution="tested")
    # The sibling route and the origin-level sqli cell remain untested.
    others = [c for c in query_impl(surface_type="route", family="sqli")["cells"]
              if c["surface_id"] != first["surface_id"]]
    assert all(c["execution"] != "tested" for c in others)
    origin_sqli = query_impl(surface_type="origin", family="sqli")["cells"][0]
    assert origin_sqli["execution"] != "tested"


# --------------------------------------------------------------------------- #
# Budget exhaustion / blocked stays unfinished
# --------------------------------------------------------------------------- #


def test_blocked_stays_unfinished_and_is_a_gap() -> None:
    _endpoint("http://app.test/x", params=[{"name": "q", "location": "query"}])
    plan_coverage_impl(create_hypotheses=False)
    route = query_impl(surface_type="route", family="sqli")["cells"][0]
    assess_impl(surface_type="route", surface_id=route["surface_id"], family="sqli",
                execution="blocked", remaining_work="attempt budget exhausted")
    gaps = coverage_gaps_impl()
    assert any(g["execution"] == "blocked" for g in gaps["gaps"])
    assert not any(g["execution"] == "tested" for g in gaps["gaps"])


# --------------------------------------------------------------------------- #
# New evidence re-opens a tested route
# --------------------------------------------------------------------------- #


def test_new_parameter_evidence_reopens_tested_route() -> None:
    _endpoint("http://app.test/p", params=[{"name": "id", "location": "query"}])
    plan_coverage_impl(create_hypotheses=False)
    route = query_impl(surface_type="route", family="sqli")["cells"][0]
    assess_impl(surface_type="route", surface_id=route["surface_id"], family="sqli",
                execution="tested")
    # A newly-crawled parameter on the SAME endpoint changes the signal -> reopen.
    _endpoint("http://app.test/p",
              params=[{"name": "id", "location": "query"}, {"name": "sort", "location": "query"}])
    plan_coverage_impl(create_hypotheses=False)
    reopened = query_impl(surface_type="route", family="sqli")["cells"][0]
    assert reopened["execution"] == "in_progress"


# --------------------------------------------------------------------------- #
# Resume preserves planning, flags stale
# --------------------------------------------------------------------------- #


def test_resume_preserves_planning_and_flags_stale(_stores: Path) -> None:
    _endpoint("http://app.test/s", params=[{"name": "q", "location": "query"}])
    plan_coverage_impl(create_hypotheses=False)
    route = query_impl(surface_type="route", family="sqli")["cells"][0]
    assess_impl(surface_type="route", surface_id=route["surface_id"], family="sqli",
                execution="in_progress")
    hydrate_coverage_matrix_from_disk(_stores)  # simulate --resume
    cell = query_impl(surface_type="route", family="sqli")["cells"][0]
    assert cell["planned_checks"] and cell["applicability_rationale"]  # planning preserved
    assert cell["evidence_stale"] is True          # evidence flagged for re-verification


# --------------------------------------------------------------------------- #
# Missing capability is a visible gap; gaps vs tested accounting
# --------------------------------------------------------------------------- #


def test_missing_capability_is_a_gap() -> None:
    assess_impl(surface_type="origin", surface_id="http://t", family="request_smuggling",
                applicability="applicable", capability="missing",
                remaining_work="no executor/skill; needs manual follow-up")
    gaps = coverage_gaps_impl()
    assert any(g["capability"] == "missing" for g in gaps["gaps"])


def test_gaps_vs_tested_accounting() -> None:
    _endpoint("http://app.test/g", params=[{"name": "q", "location": "query"}])
    plan_coverage_impl(create_hypotheses=False)
    route = query_impl(surface_type="route", family="xss")["cells"][0]
    assess_impl(surface_type="route", surface_id=route["surface_id"], family="xss",
                execution="tested", tested_boundaries=["reflected query q, html context"])
    gaps = coverage_gaps_impl()
    assert gaps["tested_cells"] == 1
    assert gaps["gap_count"] > 0  # all the unknown origin cells + other applicable routes remain


# --------------------------------------------------------------------------- #
# next_coverage_task: every family reachable; SQLi/XSS don't starve others
# --------------------------------------------------------------------------- #


def test_next_task_reaches_non_sqli_xss_families_first() -> None:
    # A param endpoint makes sqli/xss route cells in_progress (planner hypotheses).
    _endpoint("http://app.test/s", params=[{"name": "q", "location": "query"}])
    plan_coverage_impl(create_hypotheses=True)
    dispensed = next_coverage_task_impl(count=12)["tasks"]
    fams = [t["family"] for t in dispensed]
    # SQLi/XSS were already progressed, so the first tasks go to OTHER families.
    assert "sqli" not in fams[:6] and "xss" not in fams[:6]
    assert len({*fams}) >= 6  # a spread of families, not one monopolizing
    # Each task names a skill to load (or null = a capability gap) + prerequisites.
    for t in dispensed:
        assert t["prereqs"]
        if t["capability"] == "missing":
            assert t["load_skill"] is None
        else:
            assert t["load_skill"]


def test_next_task_claims_and_advances_without_repeats() -> None:
    _endpoint("http://app.test/h")
    plan_coverage_impl(create_hypotheses=False)
    a = next_coverage_task_impl(count=3)["tasks"]
    b = next_coverage_task_impl(count=3)["tasks"]
    keys_a = {(t["surface_type"], t["surface_id"], t["family"]) for t in a}
    keys_b = {(t["surface_type"], t["surface_id"], t["family"]) for t in b}
    assert keys_a and keys_b and not (keys_a & keys_b)  # no cell dispensed twice


def test_stranded_claim_is_reclaimed_after_resume(_stores: Path) -> None:
    # A claimed-but-unworked cell (no hypothesis/attempt) must not strand forever:
    # a resume flags it stale, and the dispenser re-offers it.
    _endpoint("http://app.test/h")
    plan_coverage_impl(create_hypotheses=False)
    first = next_coverage_task_impl(count=1)["tasks"][0]
    key = (first["surface_type"], first["surface_id"], first["family"])
    # Before resume it's claimed (in_progress) and NOT re-dispensed.
    later = next_coverage_task_impl(count=5)["tasks"]
    assert key not in {(t["surface_type"], t["surface_id"], t["family"]) for t in later}
    # Resume: the worker died without progress -> flagged stale -> reclaimable.
    hydrate_coverage_matrix_from_disk(_stores)
    reoffered = next_coverage_task_impl(count=50)["tasks"]
    assert key in {(t["surface_type"], t["surface_id"], t["family"]) for t in reoffered}


def test_worked_claim_is_not_reclaimed_after_resume(_stores: Path) -> None:
    # A claim that DID make progress (a linked hypothesis) is preserved on resume,
    # not re-offered as fresh work.
    _endpoint("http://app.test/s", params=[{"name": "q", "location": "query"}])
    plan_coverage_impl(create_hypotheses=True)  # sqli/xss route cells get hypotheses
    hydrate_coverage_matrix_from_disk(_stores)
    reoffered = next_coverage_task_impl(count=100)["tasks"]
    keys = {(t["surface_type"], t["surface_id"], t["family"]) for t in reoffered}
    assert ("route", query_impl(surface_type="route", family="sqli")["cells"][0]["surface_id"],
            "sqli") not in keys


def test_next_task_underserved_family_gets_methodology_skill() -> None:
    _endpoint("http://app.test/h")
    plan_coverage_impl(create_hypotheses=False)
    underserved = {"ldap_injection", "xpath_injection", "parameter_pollution",
                   "websocket", "cache_poisoning"}
    seen = False
    for _ in range(60):
        tasks = next_coverage_task_impl(count=1)["tasks"]
        if not tasks:
            break
        if tasks[0]["family"] in underserved:
            # Resolved to a concrete agent-driven skill (no executor), not null.
            assert tasks[0]["load_skill"] == "underserved_families"
            assert tasks[0]["shared_guidance"] == "analysis/family_assessment"
            seen = True
            break
    assert seen


# --------------------------------------------------------------------------- #
# Report: an uninitialized matrix never claims completeness
# --------------------------------------------------------------------------- #


def test_uninitialized_matrix_report_is_not_complete(_stores: Path) -> None:
    hydrate_component_research_from_disk(_stores)  # empty
    # Matrix never planned (fixture hydrated it empty).
    doc = build_coverage_document(run_record={"run_id": "r"}, entries=[], agent_graph={},
                                  vulnerability_reports=[])
    fm = doc["family_coverage_matrix"]
    assert fm["total_cells"] == 0 and fm["planned"] is False
    assert fm["complete"] is False  # no cells != fully tested
    assert doc["summary"]["family_coverage_complete"] is False
    assert "UNASSESSED" in fm["note"]
