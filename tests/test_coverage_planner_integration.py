"""Integrated local fixture: inventory -> plan -> hypothesis -> attempt ->
coverage/report (BLACKBOX #6 Part B).

Drives the REAL stores end to end (attack-surface inventory, the deterministic
coverage planner, the hypotheses worklist, and the coverage-matrix gap report)
with no browser and no network — proving the planner is reachable from the
inventory the blackbox orchestration actually produces, generates linked
hypotheses without duplicate flooding, and that completion reporting exposes the
remaining gaps rather than claiming full coverage.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from strix.report.coverage import build_coverage_document
from strix.tools.attack_surface.tools import _record_impl, hydrate_attack_surface_from_disk
from strix.tools.component_research.tools import (
    hydrate_component_research_from_disk,
    record_component_impl,
)
from strix.tools.coverage_matrix.tools import (
    assess_impl,
    coverage_gaps_impl,
    hydrate_coverage_matrix_from_disk,
    plan_coverage_impl,
    query_impl,
    record_attempt_ref_impl,
)
from strix.tools.hypotheses.tools import (
    STATUS_NEEDS_VALIDATION,
    _record_attempt_impl,
    hydrate_hypotheses_from_disk,
    lookup_hypothesis,
)


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _stores(tmp_path: Path) -> Path:
    hydrate_attack_surface_from_disk(tmp_path)
    hydrate_hypotheses_from_disk(tmp_path)
    hydrate_coverage_matrix_from_disk(tmp_path)
    return tmp_path


@pytest.mark.asyncio
async def test_inventory_to_plan_to_hypothesis_to_attempt_to_report(_stores: Path) -> None:
    # 1) INVENTORY — two actors see an id-bearing endpoint (real recon shape).
    _record_impl(url="http://app.test/orders?id=1", method="GET",
                 parameters=[{"name": "id", "location": "query"}],
                 discovery_source="crawl", actor_ref="actor-a")
    _record_impl(url="http://app.test/orders?id=1", method="GET",
                 parameters=[{"name": "id", "location": "query"}],
                 discovery_source="crawl", actor_ref="actor-b")

    # 2) PLAN — deterministic planner seeds the matrix + bounded linked hypotheses.
    plan = plan_coverage_impl(create_hypotheses=True)
    assert plan["origins"] == 1
    assert plan["hypotheses_created"] >= 1  # executor families got hypotheses
    # Re-planning the same inventory must NOT flood duplicates.
    plan2 = plan_coverage_impl(create_hypotheses=True)
    assert plan2["hypotheses_created"] == 0

    # 3) HYPOTHESIS — the sqli route cell stays UNKNOWN (a signal is not
    #    established applicability) but carries a linked probe bet.
    sqli_cells = query_impl(surface_type="route", family="sqli")["cells"]
    assert sqli_cells and sqli_cells[0]["applicability"] == "unknown"
    assert sqli_cells[0]["hypothesis_refs"]
    hid = sqli_cells[0]["hypothesis_refs"][0]
    assert lookup_hypothesis(hid) is not None
    surface_id = sqli_cells[0]["surface_id"]

    # 4) ATTEMPT — record a real attempt on the hypothesis + link it to the cell.
    _record_attempt_impl(hypothesis_id=hid, tool="sqli_executor",
                         tool_rationale="param id reaches a SQL sink",
                         outcome="boolean oracle observed", result_status=STATUS_NEEDS_VALIDATION,
                         validation_required="extract a real record", signal="oracle",
                         input_evidence=None, agent_id=None, agent_name=None)
    record_attempt_ref_impl("route", surface_id, "sqli", f"attempt:{hid}")
    assess_impl(surface_type="route", surface_id=surface_id, family="sqli", execution="tested",
                tested_boundaries=["id param, boolean oracle"])

    # 5) REPORT — one cell tested; everything else (idor/xss routes, all the
    #    unknown origin families) stays an explicit, visible gap. Never "fully
    #    tested".
    gaps = coverage_gaps_impl()
    assert gaps["tested_cells"] == 1
    assert gaps["gap_count"] > 0
    # The idor family is a SIGNAL here (id param + 2 actors) — unknown, with an
    # assessment task, NOT auto-hypothesized and NOT closed by the sqli test.
    idor = query_impl(surface_type="route", family="idor_bola")["cells"]
    assert idor and idor[0]["applicability"] == "unknown" and idor[0]["execution"] != "tested"
    assert not idor[0]["hypothesis_refs"]

    # 6) RENDERED REPORT — the deterministic coverage document (what the report
    #    path actually writes) exposes the family-matrix gaps + an unresolved
    #    component and stays EXPLICITLY incomplete.
    hydrate_component_research_from_disk(_stores)
    record_component_impl(product="nginx", location="Server @ http://app.test",
                          observed_version="", version_confidence="unknown")  # unresolved
    doc = build_coverage_document(run_record={"run_id": "r"}, entries=[], agent_graph={},
                                  vulnerability_reports=[])
    assert doc["family_coverage_matrix"]["gap_count"] > 0
    assert doc["family_coverage_matrix"]["complete"] is False
    assert doc["summary"]["family_coverage_complete"] is False  # not "fully tested"
    assert doc["component_research"]["total"] >= 1
    assert doc["summary"]["unresolved_components"] >= 1
