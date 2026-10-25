from fastapi.testclient import TestClient

from opentelemetry.proto.common.v1.common_pb2 import KeyValue, AnyValue
from opentelemetry.proto.resource.v1.resource_pb2 import Resource
from opentelemetry.proto.trace.v1.trace_pb2 import ResourceSpans, ScopeSpans, Span
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
)

from app.main import app, store


client = TestClient(app)



def make_payload() -> bytes:
    request = ExportTraceServiceRequest()

    resource_spans = request.resource_spans.add()
    resource_spans.resource.CopyFrom(
        Resource(
            attributes=[
                KeyValue(
                    key="service.name",
                    value=AnyValue(string_value="test-service"),
                )
            ]
        )
    )

    scope_spans = resource_spans.scope_spans.add()
    span = scope_spans.spans.add()

    span.trace_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )
    span.span_id = bytes.fromhex("0011223344556677")
    span.name = "GET /api/test"
    span.start_time_unix_nano = 1_000_000_000
    span.end_time_unix_nano = 1_025_000_000

    span.attributes.extend([
        KeyValue(
            key="authz.principal.id",
            value=AnyValue(string_value="user-123"),
        ),
        KeyValue(
            key="authz.principal.type",
            value=AnyValue(string_value="user"),
        ),
        KeyValue(
            key="authz.principal.scopes",
            value=AnyValue(string_value="read:items,write:items"),
        ),
        KeyValue(
            key="authz.target.resource",
            value=AnyValue(string_value="/api/test"),
        ),
    ])

    return request.SerializeToString()



def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_otlp_ingestion() -> None:
    store._spans.clear()

    response = client.post(
        "/v1/traces",
        content=make_payload(),
        headers={"content-type": "application/x-protobuf"},
    )

    assert response.status_code == 200
    assert response.json()["spans"] == 1

    trace_response = client.get(
        "/api/v1/traces/00112233445566778899aabbccddeeff"
    )

    assert trace_response.status_code == 200
    record = trace_response.json()[0]
    assert record["service_name"] == "test-service"
    assert record["span_name"] == "GET /api/test"
    assert record["duration_ms"] == 25.0

def test_trace_graph_endpoint() -> None:
    store._spans.clear()

    response = client.post(
        "/v1/traces",
        content=make_payload(),
        headers={"content-type": "application/x-protobuf"},
    )

    assert response.status_code == 200

    graph_response = client.get(
        "/api/v1/traces/00112233445566778899aabbccddeeff/graph"
    )

    assert graph_response.status_code == 200
    graph_data = graph_response.json()
    assert graph_data["trace_id"] == "00112233445566778899aabbccddeeff"
    assert isinstance(graph_data["nodes"], list)
    assert isinstance(graph_data["edges"], list)
    assert "authority_amplification_hops" in graph_data

def test_graph_endpoint_reports_empty_hops_for_simple_trace() -> None:
    store._spans.clear()

    response = client.post(
        "/v1/traces",
        content=make_payload(),
        headers={"content-type": "application/x-protobuf"},
    )
    assert response.status_code == 200

    graph_response = client.get(
        "/api/v1/traces/00112233445566778899aabbccddeeff/graph"
    )
    assert graph_response.status_code == 200

    data = graph_response.json()
    assert data["nodes"]
    assert data["edges"]
    assert data["authority_amplification_hops"] == []
