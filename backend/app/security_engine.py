from __future__ import annotations

from typing import Any

from .analysis import analyze_trace
from .schemas import SpanRecord


def analyze_security_trace(
    spans: list[SpanRecord],
    *,
    service_authority_config: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Adapt the existing authorization analysis for API consumers."""
    return analyze_trace(
        spans,
        service_authority_config=service_authority_config,
    )
