from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
)
from opentelemetry.proto.common.v1.common_pb2 import AnyValue, KeyValue
from opentelemetry.proto.resource.v1.resource_pb2 import Resource

from app import main as backend_main
from app.main import app, store
from app.schemas import SpanRecord


client = TestClient(app, raise_server_exceptions=False)


def make_authorized_trace_payload() -> bytes:
    request = ExportTraceServiceRequest()
    resource_spans = request.resource_spans.add()
    resource_spans.resource.CopyFrom(
        Resource(
            attributes=[
                KeyValue(
                    key="service.name",
                    value=AnyValue(string_value="payment"),
                )
            ]
        )
    )
    span = resource_spans.scope_spans.add().spans.add()
    span.trace_id = bytes.fromhex("00112233445566778899aabbccddeeff")
    span.span_id = bytes.fromhex("0011223344556677")
    span.name = "oteldemo.PaymentService/Charge"
    span.start_time_unix_nano = 1
    span.end_time_unix_nano = 2
    span.status.code = 1
    span.attributes.extend([
        KeyValue(
            key="authz.principal.id",
            value=AnyValue(string_value="user-1"),
        ),
        KeyValue(
            key="authz.principal.scopes",
            value=AnyValue(string_value="payments:charge"),
        ),
    ])
    return request.SerializeToString()


@pytest.fixture(autouse=True)
def clear_store(monkeypatch: pytest.MonkeyPatch) -> None:
    store._spans.clear()
    monkeypatch.delenv("AUTH_DEBUGGER_SERVICE_AUTHORITIES", raising=False)
    monkeypatch.delenv("AUTH_DEBUGGER_DELEGATION_GRANTS", raising=False)


def add_span(
    trace_id: str,
    *,
    span_id: str = "span-1",
    principal_id: str = "user-1",
    scopes: str | list[str] = "payments:charge",
    status_code: int = 1,
    attributes: dict | None = None,
) -> None:
    span_attributes = {
        "authz.principal.id": principal_id,
        "authz.principal.scopes": scopes,
    }
    if attributes:
        span_attributes.update(attributes)
    store.add(
        SpanRecord(
            trace_id=trace_id,
            span_id=span_id,
            service_name="payment",
            span_name="oteldemo.PaymentService/Charge",
            start_time_unix_nano=1,
            end_time_unix_nano=2,
            duration_ms=0.000001,
            span_kind=1,
            status_code=status_code,
            attributes=span_attributes,
        )
    )


def test_graph_api_runs_deterministic_analysis_and_preserves_trace_id() -> None:
    add_span("trace-authorized")

    response = client.get("/api/v1/traces/trace-authorized/graph")

    assert response.status_code == 200
    result = response.json()
    assert result["trace_id"] == "trace-authorized"
    assert result["security_analysis"]["verdict"] == "NOT_DETECTED"
    assert result["security_analysis"]["finding"]["trace_id"] == "trace-authorized"
    assert result["nodes"]
    assert result["edges"]
    assert all(edge["trace_id"] == "trace-authorized" for edge in result["edges"])


def test_ingested_otlp_trace_can_be_analyzed_end_to_end() -> None:
    ingest_response = client.post(
        "/v1/traces",
        content=make_authorized_trace_payload(),
        headers={"content-type": "application/x-protobuf"},
    )

    assert ingest_response.status_code == 200
    assert ingest_response.json()["spans"] == 1

    graph_response = client.get(
        "/api/v1/traces/00112233445566778899aabbccddeeff/graph"
    )

    assert graph_response.status_code == 200
    result = graph_response.json()
    assert result["trace_id"] == "00112233445566778899aabbccddeeff"
    analysis = result["security_analysis"]
    assert analysis["verdict"] == "NOT_DETECTED"
    assert analysis["reason"]
    assert analysis["finding"]["finding_type"] == "NONE"
    assert analysis["finding"]["evidence"]
    assert analysis["finding"]["attack_path"] == []
    assert isinstance(analysis["details"], dict)
    assert isinstance(analysis["context"]["warnings"], list)
    assert (
        analysis["finding"]["trace_id"]
        == "00112233445566778899aabbccddeeff"
    )
    assert result["nodes"]
    assert result["edges"]
    assert all(
        {"id", "type", "label", "metadata"} <= node.keys()
        for node in result["nodes"]
    )
    assert all(
        {"source", "target", "type", "trace_id", "metadata"} <= edge.keys()
        for edge in result["edges"]
    )
    assert all(
        edge["trace_id"] == "00112233445566778899aabbccddeeff"
        for edge in result["edges"]
    )


def test_graph_api_detects_unauthorized_delegation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    add_span(
        "trace-unauthorized-delegation",
        scopes="orders:read",
        attributes={
            "authz.delegation.from": "user-1",
            "authz.delegation.to": "payment",
            "authz.delegation.scopes": ["payments:charge"],
        },
    )
    client_config = {"payment": ["payments:charge"]}
    monkeypatch.setenv(
        "AUTH_DEBUGGER_SERVICE_AUTHORITIES",
        json.dumps(client_config),
    )

    response = client.get(
        "/api/v1/traces/trace-unauthorized-delegation/graph"
    )

    assert response.status_code == 200
    analysis = response.json()["security_analysis"]
    assert analysis["verdict"] == "DETECTED"
    assert analysis["finding"]["finding_type"] == "UNAUTHORIZED_DELEGATION"
    assert analysis["finding"]["trace_id"] == "trace-unauthorized-delegation"
    assert analysis["details"]["unauthorized_expansions"][0]["permissions"] == [
        "payments:charge"
    ]


def test_graph_api_returns_insufficient_evidence_without_outcome() -> None:
    add_span("trace-outcome-unknown", status_code=0)

    response = client.get("/api/v1/traces/trace-outcome-unknown/graph")

    assert response.status_code == 200
    analysis = response.json()["security_analysis"]
    assert analysis["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert "outcome is unknown" in analysis["reason"]


def test_graph_api_returns_insufficient_evidence_for_incomplete_delegation() -> None:
    add_span(
        "trace-incomplete-delegation",
        attributes={"authz.delegation.from": "user-1"},
    )

    response = client.get(
        "/api/v1/traces/trace-incomplete-delegation/graph"
    )

    assert response.status_code == 200
    result = response.json()
    assert result["security_analysis"]["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert "delegation metadata is incomplete" in result["security_analysis"]["reason"]
    assert result["nodes"]


def test_graph_api_does_not_infer_missing_service_authority() -> None:
    add_span("trace-unknown-service-authority", scopes="orders:read")

    response = client.get(
        "/api/v1/traces/trace-unknown-service-authority/graph"
    )

    assert response.status_code == 200
    analysis = response.json()["security_analysis"]
    assert analysis["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert "service's authority is not configured" in analysis["reason"]


def test_graph_api_does_not_mix_traces_with_identical_span_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    add_span(
        "trace-under-analysis",
        span_id="shared-span-id",
        scopes="orders:read",
    )
    add_span(
        "other-trace",
        span_id="shared-span-id",
        scopes="payments:charge",
    )
    monkeypatch.setenv(
        "AUTH_DEBUGGER_SERVICE_AUTHORITIES",
        json.dumps({"payment": ["payments:charge"]}),
    )

    response = client.get("/api/v1/traces/trace-under-analysis/graph")

    assert response.status_code == 200
    result = response.json()
    assert result["trace_id"] == "trace-under-analysis"
    assert result["security_analysis"]["verdict"] == "DETECTED"
    assert result["security_analysis"]["finding"]["trace_id"] == (
        "trace-under-analysis"
    )
    assert all(edge["trace_id"] == "trace-under-analysis" for edge in result["edges"])


def test_graph_api_rejects_malformed_otlp_input() -> None:
    response = client.post(
        "/v1/traces",
        content=b"\xff\xff\xff",
        headers={"content-type": "application/x-protobuf"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid OTLP trace payload."


def test_graph_api_treats_malformed_authority_as_insufficient() -> None:
    add_span(
        "trace-malformed-authority",
        scopes=["payments:charge", 42],
    )

    response = client.get(
        "/api/v1/traces/trace-malformed-authority/graph"
    )

    assert response.status_code == 200
    analysis = response.json()["security_analysis"]
    assert analysis["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert any(
        warning["field"] == "original_authority"
        and warning["warning_type"] == "malformed"
        for warning in analysis["context"]["warnings"]
    )


def test_graph_api_reports_invalid_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    add_span("trace-invalid-config")
    client_config = "{not valid json"
    monkeypatch.setenv("AUTH_DEBUGGER_SERVICE_AUTHORITIES", client_config)

    response = client.get("/api/v1/traces/trace-invalid-config/graph")

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "AUTH_DEBUGGER_SERVICE_AUTHORITIES must be valid JSON"
    )


def test_graph_api_returns_generic_500_for_unexpected_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    add_span("trace-internal-error")

    def fail_extraction(*args, **kwargs):
        raise RuntimeError("internal detail")

    monkeypatch.setattr(
        backend_main,
        "extract_authorization_context",
        fail_extraction,
    )
    response = client.get("/api/v1/traces/trace-internal-error/graph")

    assert response.status_code == 500
    assert response.json()["detail"] == "Trace analysis failed"


def test_graph_api_returns_404_for_missing_trace() -> None:
    response = client.get("/api/v1/traces/not-stored/graph")

    assert response.status_code == 404
    assert response.json()["detail"] == "Trace not found"
