from fastapi.testclient import TestClient

from opentelemetry.proto.common.v1.common_pb2 import KeyValue, AnyValue
from opentelemetry.proto.resource.v1.resource_pb2 import Resource
from opentelemetry.proto.trace.v1.trace_pb2 import ResourceSpans, ScopeSpans, Span
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
)
import pytest

from app.main import analysis_results, app, store
from app.schemas import SpanRecord
from app.store import InMemorySpanStore


client = TestClient(app)



def make_payload(
    *,
    trace_id: bytes = bytes.fromhex("00112233445566778899aabbccddeeff"),
    span_id: bytes = bytes.fromhex("0011223344556677"),
    parent_span_id: bytes = b"",
    start_time_unix_nano: int = 1_000_000_000,
    end_time_unix_nano: int = 1_025_000_000,
    span_names: tuple[str, ...] = ("GET /api/test",),
) -> bytes:
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
    for span_name in span_names:
        span = scope_spans.spans.add()
        span.trace_id = trace_id
        span.span_id = span_id
        span.parent_span_id = parent_span_id
        span.name = span_name
        span.start_time_unix_nano = start_time_unix_nano
        span.end_time_unix_nano = end_time_unix_nano
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


def make_delegation_payload(root_span_name: str) -> bytes:
    request = ExportTraceServiceRequest()
    trace_id = bytes.fromhex("00112233445566778899aabbccddeeff")
    root_span_id = bytes.fromhex("0011223344556677")

    spans = (
        (
            "checkout",
            root_span_id,
            b"",
            root_span_name,
            {
                "authz.principal.id": "demo-user",
                "authz.principal.type": "user",
                "authz.principal.scopes": "orders:read",
                "authz.delegation.from": "demo-user",
                "authz.delegation.to": "checkout-svc",
                "authz.delegation.scopes": "orders:read",
                "authz.credential.type": "user_token",
            },
        ),
        (
            "payment",
            bytes.fromhex("8899aabbccddeeff"),
            root_span_id,
            "oteldemo.PaymentService/Charge",
            {
                "authz.principal.id": "demo-user",
                "authz.principal.type": "user",
                "authz.principal.scopes": "orders:read",
                "authz.delegation.from": "checkout-svc",
                "authz.delegation.to": "payment-svc",
                "authz.delegation.scopes": "orders:read,payments:charge",
                "authz.credential.type": "service_credential",
            },
        ),
    )
    for service_name, span_id, parent_span_id, name, attributes in spans:
        resource_spans = request.resource_spans.add()
        resource_spans.resource.attributes.add(
            key="service.name",
            value=AnyValue(string_value=service_name),
        )
        span = resource_spans.scope_spans.add().spans.add()
        span.trace_id = trace_id
        span.span_id = span_id
        span.parent_span_id = parent_span_id
        span.name = name
        span.start_time_unix_nano = 1_000_000_000
        span.end_time_unix_nano = 1_025_000_000
        span.status.code = 1
        for key, value in attributes.items():
            span.attributes.add(
                key=key,
                value=AnyValue(string_value=value),
            )

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


def test_empty_otlp_payload_returns_400() -> None:
    response = client.post(
        "/v1/traces",
        content=b"",
        headers={"content-type": "application/x-protobuf"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Empty request body"


def test_unsupported_content_type_returns_415() -> None:
    response = client.post(
        "/v1/traces",
        content=b"some payload",
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 415
    assert "OTLP protobuf" in response.json()["detail"]


def test_malformed_protobuf_returns_sanitized_400() -> None:
    response = client.post(
        "/v1/traces",
        content=b"\xff\xff\xff",
        headers={"content-type": "application/x-protobuf"},
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid OTLP trace payload."}
    assert "DecodeError" not in response.text


@pytest.mark.parametrize(
    ("trace_id", "span_id"),
    [
        (b"\x01" * 15, b"\x01" * 8),
        (b"\x01" * 17, b"\x01" * 8),
        (b"\x00" * 16, b"\x01" * 8),
        (b"\x01" * 16, b"\x01" * 7),
        (b"\x01" * 16, b"\x01" * 9),
        (b"\x01" * 16, b"\x00" * 8),
    ],
)
def test_invalid_trace_or_span_id_returns_sanitized_400(
    trace_id: bytes,
    span_id: bytes,
) -> None:
    store._spans.clear()
    response = client.post(
        "/v1/traces",
        content=make_payload(trace_id=trace_id, span_id=span_id),
        headers={"content-type": "application/x-protobuf"},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid OTLP trace payload."}
    assert store.count() == 0


@pytest.mark.parametrize(
    "parent_span_id",
    [b"\x01" * 7, b"\x01" * 9, b"\x00" * 8],
)
def test_invalid_parent_span_id_returns_sanitized_400(
    parent_span_id: bytes,
) -> None:
    store._spans.clear()
    response = client.post(
        "/v1/traces",
        content=make_payload(parent_span_id=parent_span_id),
        headers={"content-type": "application/x-protobuf"},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid OTLP trace payload."}
    assert store.count() == 0


def test_reversed_timestamps_return_sanitized_400() -> None:
    store._spans.clear()
    response = client.post(
        "/v1/traces",
        content=make_payload(
            start_time_unix_nano=2,
            end_time_unix_nano=1,
        ),
        headers={"content-type": "application/x-protobuf"},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid OTLP trace payload."}
    assert store.count() == 0


def test_zero_timestamps_are_accepted() -> None:
    store._spans.clear()
    response = client.post(
        "/v1/traces",
        content=make_payload(start_time_unix_nano=0, end_time_unix_nano=0),
        headers={"content-type": "application/x-protobuf"},
    )
    assert response.status_code == 200
    trace = client.get("/api/v1/traces/00112233445566778899aabbccddeeff")
    assert trace.status_code == 200
    assert trace.json()[0]["start_time_unix_nano"] == 0
    assert trace.json()[0]["end_time_unix_nano"] == 0


def test_normalization_failure_returns_generic_500_without_storing(
    monkeypatch,
    caplog,
) -> None:
    from app import main

    store._spans.clear()

    def fail_normalization(payload: bytes):
        raise RuntimeError("internal normalization detail")

    monkeypatch.setattr(main, "normalize_traces", fail_normalization)
    response = client.post(
        "/v1/traces",
        content=make_payload(),
        headers={"content-type": "application/x-protobuf"},
    )
    assert response.status_code == 500
    assert response.json() == {
        "detail": "Trace ingestion could not be completed."
    }
    assert "internal normalization detail" not in response.text
    assert "Unexpected failure while normalizing OTLP traces" in caplog.text
    assert store.count() == 0


def test_unknown_trace_returns_404() -> None:
    response = client.get(
        "/api/v1/traces/ffffffffffffffffffffffffffffffff"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Trace not found"


def test_same_span_id_in_different_traces_is_preserved() -> None:
    test_store = InMemorySpanStore(max_spans=10)

    first = SpanRecord(
        trace_id="trace-a",
        span_id="same-span",
        span_name="first",
        start_time_unix_nano=100,
        end_time_unix_nano=200,
        duration_ms=0.0001,
        span_kind=1,
        status_code=0,
    )
    second = SpanRecord(
        trace_id="trace-b",
        span_id="same-span",
        span_name="second",
        start_time_unix_nano=300,
        end_time_unix_nano=500,
        duration_ms=0.0002,
        span_kind=1,
        status_code=0,
    )

    test_store.add(first)
    test_store.add(second)

    assert test_store.count() == 2
    assert [span.span_name for span in test_store.trace("trace-a")] == [
        "first"
    ]
    assert [span.span_name for span in test_store.trace("trace-b")] == [
        "second"
    ]


def test_duplicate_spans_in_one_request_count_incoming_records() -> None:
    store._spans.clear()

    response = client.post(
        "/v1/traces",
        content=make_payload(span_names=("first", "replacement")),
        headers={"content-type": "application/x-protobuf"},
    )

    assert response.status_code == 200
    assert response.json()["spans"] == 2
    trace = client.get(
        "/api/v1/traces/00112233445566778899aabbccddeeff"
    )
    assert trace.status_code == 200
    assert len(trace.json()) == 1
    assert trace.json()[0]["span_name"] == "replacement"


def test_duplicate_spans_across_requests_retain_latest_record() -> None:
    store._spans.clear()
    headers = {"content-type": "application/x-protobuf"}

    first = client.post(
        "/v1/traces",
        content=make_payload(span_names=("first",)),
        headers=headers,
    )
    second = client.post(
        "/v1/traces",
        content=make_payload(span_names=("replacement",)),
        headers=headers,
    )

    assert first.status_code == second.status_code == 200
    assert first.json()["spans"] == second.json()["spans"] == 1
    trace = client.get(
        "/api/v1/traces/00112233445566778899aabbccddeeff"
    )
    assert trace.status_code == 200
    assert len(trace.json()) == 1
    assert trace.json()[0]["span_name"] == "replacement"


def test_reingesting_parent_preserves_child_and_security_analysis() -> None:
    store._spans.clear()
    analysis_results.clear()
    headers = {"content-type": "application/x-protobuf"}
    trace_id = "00112233445566778899aabbccddeeff"

    initial = client.post(
        "/v1/traces",
        content=make_delegation_payload("POST /checkout"),
        headers=headers,
    )
    assert initial.status_code == 200
    assert initial.json()["spans"] == 2

    initial_graph = client.get(f"/api/v1/traces/{trace_id}/graph")
    assert initial_graph.status_code == 200
    initial_analysis = initial_graph.json()["security_analysis"]
    assert initial_analysis["verdict"] == "DETECTED"
    assert (
        initial_analysis["findings"][0]["classification"]
        == "UNAUTHORIZED_DELEGATION"
    )

    reingested = client.post(
        "/v1/traces",
        content=make_delegation_payload("POST /checkout/retry"),
        headers=headers,
    )
    assert reingested.status_code == 200
    assert reingested.json()["spans"] == 2

    trace_response = client.get(f"/api/v1/traces/{trace_id}")
    assert trace_response.status_code == 200
    spans = trace_response.json()
    assert len(spans) == 2
    root = next(span for span in spans if span["span_id"] == "0011223344556677")
    child = next(span for span in spans if span["span_id"] == "8899aabbccddeeff")
    assert root["span_name"] == "POST /checkout/retry"
    assert root["parent_span_id"] is None
    assert child["parent_span_id"] == root["span_id"]

    updated_graph = client.get(f"/api/v1/traces/{trace_id}/graph")
    assert updated_graph.status_code == 200
    updated_analysis = updated_graph.json()["security_analysis"]
    assert updated_analysis["verdict"] == initial_analysis["verdict"]
    assert (
        updated_analysis["findings"][0]["classification"]
        == initial_analysis["findings"][0]["classification"]
        == "UNAUTHORIZED_DELEGATION"
    )
