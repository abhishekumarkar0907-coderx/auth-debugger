from __future__ import annotations

from typing import Annotated

from fastapi import FastAPI, Header, HTTPException, Request

from .otlp import normalize_traces
from .schemas import IngestResponse, SpanRecord, TraceSummary
from .security_engine import analyze_security_spans
from .store import InMemorySpanStore
from auth_engine.graph.adapter import build_graph_from_spans
from auth_engine.graph import find_authority_amplification_hops

app = FastAPI(
    title="Authorization Debugger Backend",
    version="0.1.0",
    description=(
        "OTLP trace ingestion and normalization layer for "
        "Authorization Debugger."
    ),
)

store = InMemorySpanStore(max_spans=5000)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/spans", response_model=list[SpanRecord])
async def recent_spans(limit: int = 100) -> list[SpanRecord]:
    return store.recent(limit)


@app.get(
    "/api/v1/traces",
    response_model=list[TraceSummary],
)
async def trace_summaries() -> list[TraceSummary]:
    return store.trace_summaries()


@app.get(
    "/api/v1/traces/{trace_id}",
    response_model=list[SpanRecord],
)
async def get_trace(trace_id: str) -> list[SpanRecord]:
    spans = store.trace(trace_id)
    if not spans:
        raise HTTPException(status_code=404, detail="Trace not found")
    return spans


@app.get("/api/v1/analysis/{trace_id}")
async def get_trace_analysis(trace_id: str) -> dict[str, object]:
    """Analyze the stored spans for a trace using the Security Engine."""
    spans = store.trace(trace_id)
    if not spans:
        raise HTTPException(status_code=404, detail="Trace not found")
    return analyze_security_spans(spans)


@app.get("/api/v1/traces/{trace_id}/graph")
async def get_trace_graph(trace_id: str) -> dict[str, object]:
    """Build a graph using only spans observed for this trace."""
    from dataclasses import fields, is_dataclass
    from enum import Enum

    spans = store.trace(trace_id)
    if not spans:
        raise HTTPException(status_code=404, detail="Trace not found")

    def json_safe(value: object) -> object:
        if isinstance(value, Enum):
            return value.value
        if is_dataclass(value) and not isinstance(value, type):
            return {
                field.name: json_safe(getattr(value, field.name))
                for field in fields(value)
            }
        if isinstance(value, dict):
            return {str(k): json_safe(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set, frozenset)):
            return [json_safe(v) for v in value]
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        return str(value)

    graph = build_graph_from_spans(spans)
    hops = find_authority_amplification_hops(graph, trace_id=trace_id)
    security_analysis = analyze_security_spans(spans)

    return {
        "trace_id": trace_id,
        "nodes": json_safe(graph.nodes()),
        "edges": json_safe(graph.edges()),
        "authority_amplification_hops": json_safe(hops),
        "security_analysis": security_analysis,
    }


@app.post(
    "/v1/traces",
    response_model=IngestResponse,
)
async def ingest_traces(
    request: Request,
    content_type: Annotated[str | None, Header()] = None,
) -> IngestResponse:
    body = await request.body()

    if not body:
        raise HTTPException(status_code=400, detail="Empty request body")

    # OTLP/HTTP protobuf is the integration target. We accept a content type
    # that contains protobuf to tolerate charset parameters added by proxies.
    if content_type and "protobuf" not in content_type:
        raise HTTPException(
            status_code=415,
            detail=(
                "Authorization Debugger currently expects "
                "OTLP protobuf traces."
            ),
        )

    try:
        resource_span_count, records = normalize_traces(body)
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid OTLP trace payload: {exc}",
        ) from exc

    for record in records:
        store.add(record)

    return IngestResponse(
        accepted=True,
        resource_spans=resource_span_count,
        spans=len(records),
    )
