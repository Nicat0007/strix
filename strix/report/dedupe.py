"""SDK-native vulnerability-report deduplication."""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, Any

from agents.models.interface import ModelTracing
from openai.types.responses import ResponseOutputMessage

from strix.config import load_settings
from strix.config.models import (
    StrixProvider,
    configure_sdk_model_defaults,
)
from strix.core.inputs import make_model_settings
from strix.report.state import get_global_report_state


if TYPE_CHECKING:
    from agents.items import ModelResponse
    from agents.model_settings import ModelSettings
    from agents.models.interface import Model

    from strix.config.settings import DedupeSettings


logger = logging.getLogger(__name__)


def _dedupe_model_settings(
    dedupe: DedupeSettings, model_name: str, request_timeout: float | None
) -> ModelSettings:
    llm = load_settings().llm
    return make_model_settings(
        dedupe.reasoning_effort,
        model_name=model_name,
        force_required_tool_choice=False,
        request_timeout=request_timeout,
        # The main model's headers apply only when dedupe falls back to the main
        # model; a dedicated dedupe model may route to another provider, which
        # must never receive the main endpoint's credentials. A dedicated model
        # gets its own DEDUPE_LLM_EXTRA_HEADERS instead.
        extra_headers=dedupe.extra_headers if dedupe.model else llm.extra_headers,
        has_tools=False,
    )


def resolve_dedupe_model(dedupe: DedupeSettings, model_name: str) -> Model:
    """Resolve the dedupe model, bound to its own endpoint when it has one.

    Credentials can't ride on the request: every model implementation already
    passes its own ``api_key``/``base_url``, so the same keys in ``extra_args``
    collide with them and raise before anything is sent. A provider bound to the
    dedupe endpoint keeps it apart from the main model's process-wide defaults.
    """
    api_key = (dedupe.api_key or "").strip() if dedupe.model else ""
    api_base = (dedupe.api_base or "").strip() if dedupe.model else ""
    if not (api_key or api_base):
        return StrixProvider().get_model(model_name)
    return StrixProvider(api_key=api_key or None, base_url=api_base or None).get_model(model_name)


DEDUPE_SYSTEM_PROMPT = """You are an expert vulnerability report deduplication judge.
Your task is to determine if a candidate vulnerability report describes the SAME vulnerability
as any existing report.

CRITICAL DEDUPLICATION RULES:

1. SAME VULNERABILITY means:
   - Same root cause (e.g., "missing input validation" not just "SQL injection")
   - Same affected component/endpoint/file (exact match or clear overlap)
   - Same exploitation method or attack vector
   - Would be fixed by the same code change/patch

2. NOT DUPLICATES if:
   - Different endpoints even with same vulnerability type (e.g., SQLi in /login vs /search)
   - Different parameters in same endpoint (e.g., XSS in 'name' vs 'comment' field)
   - Different root causes (e.g., stored XSS vs reflected XSS in same field)
   - Different severity levels due to different impact
   - One is authenticated, other is unauthenticated

3. ARE DUPLICATES even if:
   - Titles are worded differently
   - Descriptions have different level of detail
   - PoC uses different payloads but exploits same issue
   - One report is more thorough than another
   - Minor variations in technical analysis

4. DEPENDENCY-CVE reports use package identity:
   - Same CVE and same package/ecosystem is a duplicate
   - Same CVE but different package/ecosystem is NOT a duplicate
   - Same package/ecosystem but different CVE is NOT a duplicate

COMPARISON GUIDELINES:
- Focus on the technical root cause, not surface-level similarities
- Same vulnerability type (SQLi, XSS) doesn't mean duplicate - location matters
- Consider the fix: would fixing one also fix the other?
- When uncertain, lean towards NOT duplicate

FIELDS TO ANALYZE:
- title, description: General vulnerability info
- target, endpoint, method: Exact location of vulnerability
- technical_analysis: Root cause details
- poc_description: How it's exploited
- impact: What damage it can cause

Respond with a single JSON object and nothing else:

{
  "is_duplicate": true,
  "duplicate_id": "vuln-0001",
  "confidence": 0.95,
  "reason": "Both reports describe SQL injection in /api/login via the username parameter"
}

Or, if not a duplicate:

{
  "is_duplicate": false,
  "duplicate_id": "",
  "confidence": 0.90,
  "reason": "Different endpoints: candidate is /api/search, existing is /api/login"
}

Rules:
- ``is_duplicate`` is a boolean.
- ``duplicate_id`` is the exact id from existing reports, or "" if not a duplicate.
- ``confidence`` is a number between 0 and 1.
- ``reason`` is a specific explanation mentioning endpoint/parameter/root cause.
- Output ONLY the JSON object — no surrounding prose, no code fences."""


# Fields that identify WHAT and WHERE the bug is drive the duplication decision;
# the verbose PoC/analysis prose rarely flips a verdict that title + endpoint +
# a short description did not already make. Cap the verbose fields hard (not the
# old uniform 8000) so the comparison input — which is uncached and grows O(n^2)
# across a run — stays small. ``None`` keeps a short identifier field in full.
_COMPARISON_FIELD_CAPS: dict[str, int | None] = {
    "id": None,
    "title": None,
    "endpoint": None,
    "method": None,
    "target": None,
    "cve": None,
    "dependency_metadata": None,
    "description": 1500,
    "impact": 500,
    "technical_analysis": 800,
    "poc_description": 800,
}


def _prepare_report_for_comparison(report: dict[str, Any]) -> dict[str, Any]:
    cleaned: dict[str, Any] = {}
    for field, cap in _COMPARISON_FIELD_CAPS.items():
        value = report.get(field)
        if not value:
            continue
        if cap is not None and isinstance(value, str) and len(value) > cap:
            value = value[:cap] + "...[truncated]"
        cleaned[field] = value
    return cleaned


def _dependency_identity(report: dict[str, Any]) -> tuple[str, str, str] | None:
    metadata = report.get("dependency_metadata")
    if not isinstance(metadata, dict):
        return None

    raw_cve = report.get("cve")
    raw_package = metadata.get("package_name")
    if not raw_cve or not raw_package:
        return None

    cve = str(raw_cve).strip().upper()
    ecosystem = str(metadata.get("package_ecosystem") or "").strip().lower()
    package_name = str(raw_package).strip().lower()
    if not cve or not package_name:
        return None
    return cve, ecosystem, package_name


def _manifest_path(report: dict[str, Any]) -> str:
    metadata = report.get("dependency_metadata")
    if not isinstance(metadata, dict):
        return ""
    return str(metadata.get("manifest_path") or "").strip()


def _distinct_manifest_paths(candidate: dict[str, Any], report: dict[str, Any]) -> bool:
    """Same CVE/package observed in two different manifests is two findings.

    Only applies when both sides carry a manifest_path; a missing path keeps
    the legacy CVE/package/ecosystem identity.
    """
    candidate_path = _manifest_path(candidate)
    report_path = _manifest_path(report)
    return bool(candidate_path and report_path and candidate_path != report_path)


def _report_cve(report: dict[str, Any]) -> str:
    return str(report.get("cve") or "").strip().upper()


def _legacy_report_mentions_package(
    report: dict[str, Any],
    *,
    ecosystem: str,
    package_name: str,
) -> bool:
    fields = [
        "title",
        "description",
        "impact",
        "target",
        "technical_analysis",
        "poc_description",
        "evidence",
    ]
    haystack = " ".join(str(report.get(field) or "") for field in fields).lower()
    package_pattern = rf"(?<![\w@./-]){re.escape(package_name)}(?![\w@./-])"
    if re.search(package_pattern, haystack) is None:
        return False
    if not ecosystem:
        return True
    ecosystem_pattern = rf"(?<![\w@./-]){re.escape(ecosystem)}(?![\w@./-])"
    return re.search(ecosystem_pattern, haystack) is not None


def _check_dependency_duplicate(
    candidate: dict[str, Any],
    existing_reports: list[dict[str, Any]],
) -> dict[str, Any] | None:
    candidate_identity = _dependency_identity(candidate)
    if candidate_identity is None:
        return None

    cve, ecosystem, package_name = candidate_identity
    found_legacy_same_cve = False
    for report in existing_reports:
        report_identity = _dependency_identity(report)
        if report_identity is not None:
            report_cve, report_ecosystem, report_package_name = report_identity
            if (report_cve, report_package_name) != (cve, package_name):
                continue
            if _distinct_manifest_paths(candidate, report):
                continue
            if report_ecosystem == ecosystem:
                return {
                    "is_duplicate": True,
                    "duplicate_id": str(report.get("id") or "")[:64],
                    "confidence": 1.0,
                    "reason": "Same dependency CVE/package identity",
                }
            if not report_ecosystem or not ecosystem:
                return {
                    "is_duplicate": True,
                    "duplicate_id": str(report.get("id") or "")[:64],
                    "confidence": 1.0,
                    "reason": "Same dependency CVE/package identity with missing ecosystem",
                }
            continue

        if _report_cve(report) != cve:
            continue
        found_legacy_same_cve = True
        if _legacy_report_mentions_package(
            report,
            ecosystem=ecosystem,
            package_name=package_name,
        ):
            return {
                "is_duplicate": True,
                "duplicate_id": str(report.get("id") or "")[:64],
                "confidence": 1.0,
                "reason": "Same dependency CVE/package identity in legacy report",
            }

    if found_legacy_same_cve:
        return None

    package_label = f"{ecosystem}/{package_name}" if ecosystem else package_name
    return {
        "is_duplicate": False,
        "duplicate_id": "",
        "confidence": 1.0,
        "reason": f"No existing dependency report for {cve} in {package_label}",
    }


def _parse_dedupe_response(content: str) -> dict[str, Any]:
    text = content.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError(f"No JSON object found in dedupe response: {content[:500]}")
    parsed = json.loads(text[start : end + 1])

    duplicate_id = str(parsed.get("duplicate_id") or "")[:64]
    reason = str(parsed.get("reason") or "")[:500]
    try:
        confidence = float(parsed.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0

    return {
        "is_duplicate": bool(parsed.get("is_duplicate", False)),
        "duplicate_id": duplicate_id,
        "confidence": confidence,
        "reason": reason,
    }


def _extract_text(response: ModelResponse) -> str:
    parts: list[str] = []
    for item in response.output:
        if not isinstance(item, ResponseOutputMessage):
            continue
        for chunk in item.content:
            text = getattr(chunk, "text", None)
            if text:
                parts.append(text)
    return "".join(parts)


_ID_SEGMENT_RE = re.compile(r"\A(?:\d+|[0-9a-f]{8,}|[0-9a-fA-F-]{16,})\Z")
_TITLE_STOPWORDS = frozenset(
    {
        "the", "a", "an", "of", "in", "on", "to", "for", "and", "or", "via", "with",
        "is", "are", "by", "at", "from", "into", "that", "this", "unauthenticated",
        "missing", "improper", "insecure", "allows", "enables", "api", "endpoint",
    }
)


def _normalized_endpoint(report: dict[str, Any]) -> str:
    """Scheme/host-stripped path with id-shaped segments collapsed to ``{id}``."""
    raw = str(report.get("endpoint") or report.get("target") or "").strip().lower()
    if not raw:
        return ""
    path = raw.split("://", 1)[1] if "://" in raw else raw
    if "://" in raw:
        path = path[path.find("/") :] if "/" in path else ""
    path = path.split("?", 1)[0].split("#", 1)[0]
    segs = [s for s in path.split("/") if s]
    norm = "/".join("{id}" if _ID_SEGMENT_RE.match(s) else s for s in segs)
    return f"/{norm}" if norm else ""


def _title_tokens(report: dict[str, Any]) -> set[str]:
    title = str(report.get("title") or "").lower()
    return {t for t in re.split(r"[^a-z0-9]+", title) if len(t) >= 4 and t not in _TITLE_STOPWORDS}


def _plausibly_related(candidate: dict[str, Any], report: dict[str, Any]) -> bool:
    """Could these two be the same finding? Err toward ``True`` — this only prunes
    the LLM comparison for reports that clearly cannot be duplicates (a different
    endpoint AND no shared title/class word), which the judge would call
    'not duplicate' anyway. When either side has no usable endpoint, keep it."""
    cep, rep = _normalized_endpoint(candidate), _normalized_endpoint(report)
    if not cep or not rep or cep == rep:
        return True
    return bool(_title_tokens(candidate) & _title_tokens(report))


async def check_duplicate(
    candidate: dict[str, Any], existing_reports: list[dict[str, Any]]
) -> dict[str, Any]:
    if not existing_reports:
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 1.0,
            "reason": "No existing reports to compare against",
        }

    dependency_duplicate = _check_dependency_duplicate(candidate, existing_reports)
    if dependency_duplicate is not None:
        return dependency_duplicate

    # Structural pre-filter: only LLM-compare against reports that could plausibly
    # be the same finding. Skips the (uncached, O(n^2)) judge call entirely when
    # nothing is related, and shrinks its input when only some are — quality is
    # unchanged because an unrelated report is judged 'not duplicate' regardless.
    related = [r for r in existing_reports if _plausibly_related(candidate, r)]
    if not related:
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 0.9,
            "reason": "No existing report shares the candidate's endpoint or vulnerability class",
        }

    try:
        settings = load_settings()
        dedupe = settings.dedupe
        model_name = (dedupe.model or "").strip() or settings.llm.model
        if not model_name:
            return {
                "is_duplicate": False,
                "duplicate_id": "",
                "confidence": 0.0,
                "reason": "No LLM model configured; skipping dedupe check",
            }

        candidate_cleaned = _prepare_report_for_comparison(candidate)
        existing_cleaned = [_prepare_report_for_comparison(r) for r in related]
        comparison_data = {"candidate": candidate_cleaned, "existing_reports": existing_cleaned}

        user_msg = (
            f"Compare this candidate vulnerability against existing reports:\n\n"
            f"{json.dumps(comparison_data, indent=2)}\n\n"
            f"Respond with ONLY the JSON object described in the system prompt."
        )

        configure_sdk_model_defaults(settings)
        resolved_model = model_name.strip()
        model = resolve_dedupe_model(dedupe, resolved_model)
        response = await model.get_response(
            system_instructions=DEDUPE_SYSTEM_PROMPT,
            input=user_msg,
            model_settings=_dedupe_model_settings(dedupe, resolved_model, settings.llm.timeout),
            tools=[],
            output_schema=None,
            handoffs=[],
            tracing=ModelTracing.DISABLED,
            previous_response_id=None,
            conversation_id=None,
            prompt=None,
        )
        report_state = get_global_report_state()
        if report_state is not None:
            report_state.record_sdk_usage(
                agent_id="dedupe",
                agent_name="dedupe",
                model=resolved_model,
                usage=response.usage,
            )
        content = _extract_text(response)
        if not content:
            return {
                "is_duplicate": False,
                "duplicate_id": "",
                "confidence": 0.0,
                "reason": "Empty response from LLM",
            }

        result = _parse_dedupe_response(content)

        logger.info(
            "Deduplication check: is_duplicate=%s, confidence=%.2f, reason=%s",
            result["is_duplicate"],
            result["confidence"],
            result["reason"][:100],
        )

    except Exception as e:
        logger.exception("Error during vulnerability deduplication check")
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 0.0,
            "reason": f"Deduplication check failed: {e}",
            "error": str(e),
        }
    else:
        return result
