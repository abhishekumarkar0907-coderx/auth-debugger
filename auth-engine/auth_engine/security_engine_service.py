"""Backend-facing adapter for authorization analysis of telemetry spans."""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from enum import Enum
from typing import Any

from .context import SpanLike, extract_authorization_context
from .detector import ConfusedDeputyDetector
from .models import AuthorizationScenario


def analyze_spans(
    spans: list[SpanLike],
    *,
    service_authority_config: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Analyze the spans for one trace and return JSON-serializable results."""
    if not isinstance(spans, list):
        raise TypeError("spans must be a list of span records")

    trace_ids: set[str] = set()
    for span in spans:
        if not isinstance(span, SpanLike):
            raise TypeError("each span must satisfy the SpanLike protocol")
        if not isinstance(span.trace_id, str) or not span.trace_id:
            raise ValueError("each span must have a non-empty trace_id")
        if not isinstance(span.span_id, str) or not span.span_id:
            raise ValueError("each span must have a non-empty span_id")
        if not isinstance(span.span_name, str) or not span.span_name:
            raise ValueError("each span must have a non-empty span_name")
        if span.parent_span_id is not None and not isinstance(span.parent_span_id, str):
            raise TypeError("span parent_span_id must be a string or None")
        if span.service_name is not None and not isinstance(span.service_name, str):
            raise TypeError("span service_name must be a string or None")
        if not isinstance(span.status_code, int) or isinstance(span.status_code, bool):
            raise TypeError("span status_code must be an integer")
        if not isinstance(span.attributes, dict):
            raise TypeError("span attributes must be a dictionary")
        trace_ids.add(span.trace_id)

    if len(trace_ids) > 1:
        raise ValueError("spans must belong to a single trace")

    if service_authority_config is not None:
        if not isinstance(service_authority_config, dict):
            raise TypeError("service_authority_config must be a dictionary or None")
        for service, permissions in service_authority_config.items():
            if not isinstance(service, str) or not service:
                raise TypeError("service authority keys must be non-empty strings")
            if not isinstance(permissions, list) or not all(
                isinstance(permission, str) for permission in permissions
            ):
                raise TypeError("service authorities must be lists of strings")

    context = extract_authorization_context(
        spans,
        service_authority_config=service_authority_config,
    )
    if context.has_sufficient_evidence():
        scenario = context.to_scenario()
    else:
        scenario = AuthorizationScenario(trace_id=context.trace_id)

    result = ConfusedDeputyDetector().analyze(scenario)
    return {
        "trace_id": context.trace_id,
        "verdict": result.verdict.value,
        "reason": result.reason,
        "finding": _json_safe(result.finding),
        "details": _json_safe(result.details),
        "context": _json_safe(context),
    }


def _json_safe(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, bytes):
        return value.hex()
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _json_safe(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"Value of type {type(value).__name__} is not JSON-serializable")
