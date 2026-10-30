from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class SpanRecord(BaseModel):
    trace_id: str
    span_id: str
    parent_span_id: str | None = None

    service_name: str | None = None
    span_name: str

    start_time_unix_nano: int
    end_time_unix_nano: int
    duration_ms: float

    span_kind: int
    status_code: int

    attributes: dict[str, Any] = Field(default_factory=dict)


class IngestResponse(BaseModel):
    accepted: bool
    resource_spans: int
    spans: int


class TraceSummary(BaseModel):
    trace_id: str
    span_count: int
    services: list[str]


class TraceGraphResponse(BaseModel):
    trace_id: str
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    authority_amplification_hops: list[dict[str, Any]]
    security_analysis: dict[str, Any]
