"""Backend adapters for authorization security analysis."""

from __future__ import annotations

from typing import Any

from auth_engine.security_engine_service import analyze_spans

from .analysis import analyze_trace
from .schemas import SpanRecord


def analyze_security_spans(
    spans: list[SpanRecord],
    *,
    service_authority_config: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Analyze normalized spans using the Security Engine."""
    return analyze_spans(
        spans,
        service_authority_config=service_authority_config,
    )


def analyze_security_trace(
    spans: list[SpanRecord],
    *,
    service_authority_config: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Analyze normalized spans through the API analysis adapter."""
    return analyze_trace(
        spans,
        service_authority_config=service_authority_config,
    )
