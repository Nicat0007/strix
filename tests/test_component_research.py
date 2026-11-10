"""Tests for the component/version advisory-research store (BLACKBOX #6 Part B).

Exercises the uncertainty ladder: a banner match is a candidate, unknown/
conflicting versions stay uncertain, a front-end observation caps at candidate,
`applicable` needs a usable version + in-range affected spec + reachable feature,
`not_applicable` needs evidence, an unavailable research service is
research_pending (never "no CVEs"), and advisories require a sourced URL (no
citations from memory). No secrets stored; whitebox/blackbox evidence distinct.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from strix.tools.component_research.tools import (
    evaluate_version_range,
    hydrate_component_research_from_disk,
    query_impl,
    record_advisory_candidate_impl,
    record_component_impl,
)


if TYPE_CHECKING:
    from pathlib import Path

_LOC = "Server header @ https://app.test"


@pytest.fixture(autouse=True)
def _store(tmp_path: Path) -> Path:
    hydrate_component_research_from_disk(tmp_path)
    return tmp_path


def test_unknown_version_stays_uncertain() -> None:
    r = record_component_impl(product="nginx", location=_LOC, version_confidence="unknown")
    assert r["version_usable"] is False and r["applicability_verdict"] == "uncertain"


def test_usable_version_is_research_pending_until_researched() -> None:
    r = record_component_impl(product="nginx", location=_LOC, observed_version="1.20.1",
                              version_confidence="high", version_evidence="Server: nginx/1.20.1")
    assert r["version_usable"] is True and r["applicability_verdict"] == "research_pending"


def test_conflicting_fingerprint_makes_version_unusable() -> None:
    r = record_component_impl(product="nginx", location=_LOC, observed_version="1.20.1",
                              version_confidence="high",
                              fingerprint_conflicts=["X-Powered-By says Apache"])
    assert r["version_usable"] is False and r["applicability_verdict"] == "uncertain"


def test_advisory_requires_source_url() -> None:
    record_component_impl(product="nginx", location=_LOC, observed_version="1.20.1",
                          version_confidence="high")
    bad = record_advisory_candidate_impl(product="nginx", location=_LOC, advisory_id="CVE-x",
                                         source_url="", retrieved_at="2026-10-17")
    assert bad["success"] is False


def test_version_match_alone_is_only_candidate() -> None:
    record_component_impl(product="nginx", location=_LOC, observed_version="1.20.1",
                          version_confidence="high")
    # Caller over-claims "applicable" with no affected spec / reachable feature.
    r = record_advisory_candidate_impl(
        product="nginx", location=_LOC, advisory_id="CVE-2021-23017",
        source_url="https://nginx.org/security_advisories.html", retrieved_at="2026-10-17",
        applicability_verdict="applicable")
    assert r["recorded_verdict"] == "candidate" and r["downgraded"] is True


def test_applicable_requires_version_affected_and_reachable_feature() -> None:
    record_component_impl(product="nginx", location=_LOC, observed_version="1.20.1",
                          version_confidence="high")
    r = record_advisory_candidate_impl(
        product="nginx", location=_LOC, advisory_id="CVE-2021-23017",
        source_url="https://nginx.org/security_advisories.html", retrieved_at="2026-10-17",
        applicability_verdict="applicable")
    # Still candidate without affected+feature (passed via impl kwargs below).
    assert r["recorded_verdict"] == "candidate"
    ok = record_advisory_candidate_impl(
        product="nginx", location=_LOC, advisory_id="CVE-2021-23017",
        source_url="https://nginx.org/security_advisories.html", retrieved_at="2026-10-17",
        affected_ranges=["<1.21.0"], reachable_feature="resolver directive in use",
        applicability_verdict="applicable")
    assert ok["recorded_verdict"] == "applicable" and ok["downgraded"] is False


def test_frontend_observation_caps_at_candidate() -> None:
    record_component_impl(product="jquery", location="bundle.js @ https://app.test",
                          observed_version="3.4.1", version_confidence="high", is_frontend=True)
    r = record_advisory_candidate_impl(
        product="jquery", location="bundle.js @ https://app.test", advisory_id="CVE-2020-11022",
        source_url="https://blog.jquery.com/2020/04/10/", retrieved_at="2026-10-17",
        affected_ranges=[">=1.2,<3.5.0"], reachable_feature="htmlPrefilter",
        applicability_verdict="applicable")
    assert r["recorded_verdict"] == "candidate"  # frontend != vulnerable backend
    assert "front-end" in r["reason"]


def test_not_applicable_requires_evidence() -> None:
    record_component_impl(product="nginx", location=_LOC, observed_version="1.25.0",
                          version_confidence="high")
    bad = record_advisory_candidate_impl(
        product="nginx", location=_LOC, advisory_id="CVE-2021-23017",
        source_url="https://nginx.org/security_advisories.html", retrieved_at="2026-10-17",
        applicability_verdict="not_applicable")
    assert bad["success"] is False and bad["rejected"] == "not_applicable_needs_evidence"
    ok = record_advisory_candidate_impl(
        product="nginx", location=_LOC, advisory_id="CVE-2021-23017",
        source_url="https://nginx.org/security_advisories.html", retrieved_at="2026-10-17",
        fixed_versions=["1.21.0"], applicability_verdict="not_applicable",
        remaining_verification="observed 1.25.0 > fixed 1.21.0")
    assert ok["recorded_verdict"] == "not_applicable"


def test_research_unavailable_is_pending_not_no_cves() -> None:
    record_component_impl(product="nginx", location=_LOC, observed_version="1.20.1",
                          version_confidence="high")
    r = record_advisory_candidate_impl(
        product="nginx", location=_LOC, advisory_id="pending",
        source_url="https://nginx.org/security_advisories.html", retrieved_at="2026-10-17",
        applicability_verdict="research_pending", research_state="research_unavailable")
    assert r["research_state"] == "research_unavailable"
    assert r["applicability_verdict"] in ("research_pending", "uncertain")


def test_version_range_comparison_is_not_lexicographic() -> None:
    # Lexicographic would wrongly rank "1.9" > "1.10"; numeric comparison must not.
    assert evaluate_version_range("1.9.0", ["<1.10.0"])["in_affected"] is True
    assert evaluate_version_range("1.10.0", ["<1.10.0"])["in_affected"] is False  # boundary
    assert evaluate_version_range("1.9.9", [">=1.2,<3.5.0"])["in_affected"] is True
    assert evaluate_version_range("3.5.0", [">=1.2,<3.5.0"])["in_affected"] is False  # upper bound
    assert evaluate_version_range("", ["<1.10.0"])["in_affected"] is None  # unknown stays unknown
    assert evaluate_version_range("1.9.0", [])["in_affected"] is None  # no range -> uncertain


def test_unsupported_version_syntax_stays_unknown() -> None:
    # Prereleases, build suffixes, wildcards and range operators are NOT silently
    # stripped/misclassified — they are unknown for this numeric evaluator.
    assert evaluate_version_range("1.2.0-rc1", ["<1.2.0"])["in_affected"] is None
    assert evaluate_version_range("1.2.0b1", ["<1.2.0"])["in_affected"] is None
    assert evaluate_version_range("1.2.x", ["<2.0"])["in_affected"] is None
    # An unparseable SPEC (not the observed) also stays uncertain.
    assert evaluate_version_range("1.5.0", ["<2.0.0-beta"])["in_affected"] is None


def test_numeric_padding_equivalence() -> None:
    # 1.2 and 1.2.0 compare equal (numeric padding), not as different strings.
    assert evaluate_version_range("1.2", ["==1.2.0"])["in_affected"] is True
    assert evaluate_version_range("1.2.0", [">=1.2"])["in_affected"] is True
    assert evaluate_version_range("1.2.1", ["==1.2"])["in_affected"] is False


def test_disjoint_affected_ranges() -> None:
    ranges = ["<1.0.0", ">=2.0.0,<3.0.0"]
    assert evaluate_version_range("0.9.0", ranges)["in_affected"] is True   # first range
    assert evaluate_version_range("2.5.0", ranges)["in_affected"] is True   # second range
    assert evaluate_version_range("1.5.0", ranges)["in_affected"] is False  # the gap between


def test_version_outside_range_is_not_applicable() -> None:
    record_component_impl(product="nginx", location=_LOC, observed_version="1.25.0",
                          version_confidence="high")
    r = record_advisory_candidate_impl(
        product="nginx", location=_LOC, advisory_id="CVE-2021-23017",
        source_url="https://nginx.org/security_advisories.html", retrieved_at="2026-10-17",
        affected_ranges=["<1.21.0"], reachable_feature="resolver",
        applicability_verdict="applicable")
    assert r["recorded_verdict"] == "not_applicable"  # 1.25.0 is outside <1.21.0


def test_backport_possible_keeps_in_range_match_uncertain() -> None:
    record_component_impl(product="openssl", location=_LOC, observed_version="1.1.1",
                          version_confidence="high")
    r = record_advisory_candidate_impl(
        product="openssl", location=_LOC, advisory_id="CVE-x",
        source_url="https://www.openssl.org/news/vulnerabilities.html", retrieved_at="2026-10-17",
        affected_ranges=["<1.1.1k"], reachable_feature="TLS",
        applicability_verdict="applicable", distribution_backport_possible=True)
    # In-range by version string, but a distro backport may already carry the fix.
    assert r["recorded_verdict"] == "candidate"
    assert "backport" in r["reason"]


def test_advisory_records_agent_asserted_provenance() -> None:
    record_component_impl(product="nginx", location=_LOC, observed_version="1.20.1",
                          version_confidence="high")
    record_advisory_candidate_impl(
        product="nginx", location=_LOC, advisory_id="CVE-2021-23017",
        source_url="https://nginx.org/security_advisories.html", retrieved_at="2026-10-17")
    adv = query_impl()["components"][0]["advisories"][0]
    assert adv["source_provenance"] == "agent_asserted"  # host did not retrieve the page


def test_resume_flags_version_stale(_store: Path) -> None:
    record_component_impl(product="nginx", location=_LOC, observed_version="1.20.1",
                          version_confidence="high")
    hydrate_component_research_from_disk(_store)
    comp = query_impl()["components"][0]
    assert comp["version_stale_after_resume"] is True
