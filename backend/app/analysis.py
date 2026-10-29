
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from auth_engine.context import extract_authorization_context
from auth_engine.detector import ConfusedDeputyDetector
from auth_engine.policy import default_otel_demo_policy

from .schemas import SpanRecord


def analyze_trace(
    spans: list[SpanRecord],
    *,
    service_authority_config: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Analyze one trace using explicitly configured service authority."""
    if not spans:
        raise ValueError("Cannot analyze an empty trace")

    trace_ids = {span.trace_id for span in spans}
    if len(trace_ids) != 1:
        raise ValueError("All spans must belong to the same trace")

    trace_id = next(iter(trace_ids))
    policy = default_otel_demo_policy()

    context = extract_authorization_context(
        spans,
        service_authority_config=service_authority_config,
    )
    evidence_warnings = [
        {
            "field": warning.field,
            "type": warning.warning_type,
            "message": warning.message,
        }
        for warning in context.warnings
    ]

    if not context.has_sufficient_evidence():
        return {
            "trace_id": trace_id,
            "status": "INSUFFICIENT_EVIDENCE",
            "verdict": "INSUFFICIENT_EVIDENCE",
            "findings": [],
            "details": {},
            "evidence_warnings": evidence_warnings,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "errors": [
                {
                    "code": "INSUFFICIENT_EVIDENCE",
                    "message": (
                        "The trace does not contain sufficient evidence "
                        "for analysis."
                    ),
                    "diagnostics": evidence_warnings,
                }
            ],
        }

    result = ConfusedDeputyDetector(policy=policy).analyze(
        context.to_scenario(policy=policy)
    )

    if (
        result.verdict.value == "INSUFFICIENT_EVIDENCE"
        and context.effective_span_name is not None
        and policy.resolve_span(context.effective_span_name) is None
    ):
        evidence_warnings.append(
            {
                "field": "effective_action",
                "type": "unknown",
                "message": result.reason,
            }
        )

    findings: list[dict[str, Any]] = []

    if result.verdict.value == "DETECTED" and result.finding is not None:
        finding = result.finding
        findings.append(
            {
                "finding_id": finding.finding_id,
                "classification": finding.finding_type.value,
                "severity": finding.severity.value,
                "explanation": finding.reason,
                "evidence": finding.evidence,
                "attack_path": finding.attack_path,
                "details": result.details,
            }
        )

    return {
        "trace_id": trace_id,
        "status": result.verdict.value,
        "verdict": result.verdict.value,
        "findings": findings,
        "details": result.details,
        "evidence_warnings": evidence_warnings,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "errors": [],
    }
