"""Backend bridge to the authorization Security Engine."""

from __future__ import annotations

from typing import Any

from auth_engine.security_engine_service import analyze_spans

from .schemas import SpanRecord


def analyze_security_spans(
    spans: list[SpanRecord],
    *,
    service_authority_config: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Analyze normalized spans and return the engine result unchanged."""
    return analyze_spans(
        spans,
        service_authority_config=service_authority_config,
    )
