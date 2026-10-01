from __future__ import annotations

from typing import Annotated

from fastapi import FastAPI, Header, HTTPException, Request

from .otlp import normalize_traces
from .schemas import IngestResponse, SpanRecord, TraceSummary
from .store import InMemorySpanStore


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
