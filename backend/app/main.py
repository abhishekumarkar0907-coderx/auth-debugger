from __future__ import annotations

import logging
import os
from hashlib import sha256
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException, Request

from .otlp import InvalidOTLPTracePayload, normalize_traces
from .schemas import IngestResponse, SpanRecord, TraceSummary
from .security_engine import analyze_security_spans, analyze_security_trace
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
analysis_results: dict[str, dict] = {}
_analysis_signatures: dict[str, str] = {}
SERVICE_AUTHORITY_CONFIG: dict[str, list[str]] = {}
logger = logging.getLogger(__name__)


def _trace_signature(spans: list[SpanRecord]) -> str:
    digest = sha256()
    for span in spans:
        digest.update(span.model_dump_json().encode("utf-8"))
    return digest.hexdigest()


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


@app.post("/api/v1/demo/unauthorized-delegation")
async def load_unauthorized_delegation_demo() -> dict[str, object]:
    if (
        os.getenv("AUTH_DEBUGGER_ENV") != "development"
        or os.getenv("AUTH_DEBUGGER_ENABLE_DEMO_TRACE", "").lower() != "true"
    ):
        raise HTTPException(status_code=404, detail="Demo trace not found")

    trace_id = "demo-unauthorized-delegation-v1"
    store.add(
        SpanRecord(
            trace_id=trace_id,
            span_id="demo-checkout",
            parent_span_id=None,
            service_name="frontend",
            span_name="POST /checkout",
            start_time_unix_nano=1_000_000_000,
            end_time_unix_nano=1_025_000_000,
            duration_ms=25.0,
            span_kind=1,
            status_code=1,
            attributes={
                "enduser.id": "demo-user",
                "authz.principal.id": "demo-user",
                "authz.principal.type": "user",
                "authz.principal.scopes": "orders:read",
                "authz.delegation.from": "demo-user",
                "authz.delegation.to": "checkout-svc",
                "authz.delegation.scopes": "orders:read",
                "authz.credential.type": "user_token",
            },
        )
    )
    store.add(
        SpanRecord(
            trace_id=trace_id,
            span_id="demo-payment",
            parent_span_id="demo-checkout",
            service_name="payment",
            span_name="oteldemo.PaymentService/Charge",
            start_time_unix_nano=1_025_000_000,
            end_time_unix_nano=1_050_000_000,
            duration_ms=25.0,
            span_kind=1,
            status_code=1,
            attributes={
                "enduser.id": "demo-user",
                "authz.principal.id": "demo-user",
                "authz.principal.type": "user",
                "authz.principal.scopes": "orders:read",
                "authz.delegation.from": "checkout-svc",
                "authz.delegation.to": "payment-svc",
                "authz.delegation.scopes": "orders:read,payments:charge",
                "authz.credential.type": "service_credential",
            },
        )
    )
    return {
        "trace_id": trace_id,
        "spans": 2,
        "graph_url": f"/api/v1/traces/{trace_id}/graph",
    }


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
    security_analysis = analyze_security_trace(
        spans,
        service_authority_config=SERVICE_AUTHORITY_CONFIG,
    )

    return {
        "trace_id": trace_id,
        "nodes": json_safe(graph.nodes()),
        "edges": json_safe(graph.edges()),
        "authority_amplification_hops": json_safe(hops),
        "security_analysis": json_safe(security_analysis),
    }


@app.post("/api/v1/analysis/{trace_id}")
async def post_analysis(trace_id: str) -> dict:
    spans = store.trace(trace_id)
    if not spans:
        raise HTTPException(status_code=404, detail="Trace not found")
    try:
        result = analyze_security_trace(
            spans,
            service_authority_config=SERVICE_AUTHORITY_CONFIG,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Security analysis failed for trace %s", trace_id)
        raise HTTPException(
            status_code=500,
            detail="Analysis could not be completed.",
        ) from exc
    analysis_results[trace_id] = result
    _analysis_signatures[trace_id] = _trace_signature(spans)
    return result


@app.get("/api/v1/analysis/{trace_id}")
async def get_analysis(trace_id: str) -> dict:
    spans = store.trace(trace_id)
    if not spans:
        raise HTTPException(status_code=404, detail="Trace not found")
    signature = _trace_signature(spans)
    result = analysis_results.get(trace_id)
    cached_signature = _analysis_signatures.get(trace_id)
    if result is None or (
        cached_signature is not None and cached_signature != signature
    ):
        try:
            result = analyze_security_trace(
                spans,
                service_authority_config=SERVICE_AUTHORITY_CONFIG,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except Exception as exc:
            logger.exception("Security analysis failed for trace %s", trace_id)
            raise HTTPException(
                status_code=500,
                detail="Analysis could not be completed.",
            ) from exc
        analysis_results[trace_id] = result
        _analysis_signatures[trace_id] = signature
    elif cached_signature is None:
        _analysis_signatures[trace_id] = signature
    return result


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
    except InvalidOTLPTracePayload as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        logger.exception("Unexpected failure while normalizing OTLP traces")
        raise HTTPException(
            status_code=500,
            detail="Trace ingestion could not be completed.",
        ) from exc

    for record in records:
        store.add(record)

    return IngestResponse(
        accepted=True,
        resource_spans=resource_span_count,
        spans=len(records),
    )
