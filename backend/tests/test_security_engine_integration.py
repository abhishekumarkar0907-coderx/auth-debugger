from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app, store
from app.schemas import SpanRecord


client = TestClient(app)
TRACE_ID = "security-integration-trace"
DEMO_TRACE_ID = "demo-unauthorized-delegation-v1"


@pytest.fixture(autouse=True)
def clear_span_store():
    store._spans.clear()
    yield
    store._spans.clear()


def _span(
    *,
    trace_id: str = TRACE_ID,
    span_id: str,
    parent_span_id: str | None,
    service_name: str,
    span_name: str,
    attributes: dict[str, object],
) -> SpanRecord:
    return SpanRecord(
        trace_id=trace_id,
        span_id=span_id,
        parent_span_id=parent_span_id,
        service_name=service_name,
        span_name=span_name,
        start_time_unix_nano=1,
        end_time_unix_nano=2,
        duration_ms=0.000001,
        span_kind=1,
        status_code=1,
        attributes=attributes,
    )


def _unauthorized_expansion_spans(
    trace_id: str = TRACE_ID,
) -> list[SpanRecord]:
    return [
        _span(
            trace_id=trace_id,
            span_id="checkout-span",
            parent_span_id=None,
            service_name="checkout",
            span_name="checkout",
            attributes={
                "authz.principal.id": "user-123",
                "authz.principal.type": "user",
                "authz.principal.scopes": ["orders:read"],
                "authz.delegation.from": "user-123",
                "authz.delegation.to": "checkout",
                "authz.delegation.scopes": [
                    "orders:read",
                    "payments:charge",
                ],
            },
        ),
        _span(
            trace_id=trace_id,
            span_id="payment-span",
            parent_span_id="checkout-span",
            service_name="payment",
            span_name="oteldemo.PaymentService/Charge",
            attributes={
                "authz.delegation.from": "checkout",
                "authz.delegation.to": "payment",
            },
        ),
    ]


def test_graph_reports_unauthorized_expansion_and_preserves_legacy_fields() -> None:
    for span in _unauthorized_expansion_spans():
        store.add(span)

    response = client.get(f"/api/v1/traces/{TRACE_ID}/graph")

    assert response.status_code == 200
    graph_data = response.json()
    assert graph_data["trace_id"] == TRACE_ID
    assert isinstance(graph_data["nodes"], list)
    assert isinstance(graph_data["edges"], list)
    assert isinstance(graph_data["authority_amplification_hops"], list)

    analysis = graph_data["security_analysis"]
    assert analysis["verdict"] == "DETECTED"
    assert analysis["finding"]["finding_type"] == "UNAUTHORIZED_DELEGATION"
    assert analysis["finding"]["verdict"] == "DETECTED"
    assert analysis["details"]["unauthorized_expansions"][0]["permissions"] == [
        "payments:charge"
    ]
    assert any(
        warning["field"] == "delegation.scopes"
        and warning["warning_type"] == "missing"
        for warning in analysis["context"]["warnings"]
    )


def test_graph_keeps_unknown_delegated_authority_insufficient() -> None:
    spans = _unauthorized_expansion_spans()
    spans[0].attributes["authz.delegation.scopes"] = ["orders:read"]
    for span in spans:
        store.add(span)

    response = client.get(f"/api/v1/traces/{TRACE_ID}/graph")

    assert response.status_code == 200
    analysis = response.json()["security_analysis"]
    assert analysis["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert any(
        warning["field"] == "delegation.scopes"
        and warning["warning_type"] == "missing"
        for warning in analysis["context"]["warnings"]
    )


def test_graph_reports_configured_confused_deputy_amplification() -> None:
    from app.main import SERVICE_AUTHORITY_CONFIG

    spans = _unauthorized_expansion_spans()
    spans[0].attributes["authz.delegation.scopes"] = ["orders:read"]
    spans[1].attributes["authz.delegation.scopes"] = ["orders:read"]
    for span in spans:
        store.add(span)

    original_config = SERVICE_AUTHORITY_CONFIG.copy()
    try:
        SERVICE_AUTHORITY_CONFIG["payment"] = ["payments:charge"]

        response = client.get(f"/api/v1/traces/{TRACE_ID}/graph")

        assert response.status_code == 200
        graph = response.json()
        assert graph["trace_id"] == TRACE_ID
        assert graph["security_analysis"]["trace_id"] == TRACE_ID
        assert graph["security_analysis"]["verdict"] == "DETECTED"
        assert graph["security_analysis"]["finding"]["finding_type"] == (
            "CONFUSED_DEPUTY"
        )
        assert len(graph["authority_amplification_hops"]) == 1
        hop = graph["authority_amplification_hops"][0]
        assert hop["trace_id"] == TRACE_ID
        assert hop["from_principal_id"] == "checkout"
        assert hop["to_service_id"] == "payment"
        assert hop["amplified_permissions"] == ["payments:charge"]
    finally:
        SERVICE_AUTHORITY_CONFIG.clear()
        SERVICE_AUTHORITY_CONFIG.update(original_config)


def test_graph_missing_trace_returns_existing_404_response() -> None:
    response = client.get("/api/v1/traces/missing-security-trace/graph")

    assert response.status_code == 404
    assert response.json() == {"detail": "Trace not found"}


def test_standalone_analysis_reports_demo_unauthorized_delegation() -> None:
    for span in _unauthorized_expansion_spans(DEMO_TRACE_ID):
        store.add(span)

    response = client.get(f"/api/v1/analysis/{DEMO_TRACE_ID}")

    assert response.status_code == 200
    analysis = response.json()
    assert analysis["trace_id"] == DEMO_TRACE_ID
    assert analysis["verdict"] == "DETECTED"
    finding = analysis["finding"]
    assert analysis["reason"] == finding["reason"]
    assert finding["verdict"] == "DETECTED"
    assert finding["finding_type"] == "UNAUTHORIZED_DELEGATION"
    assert finding["severity"] == "HIGH"
    assert finding["evidence"]["extraction_evidence"]
    assert finding["attack_path"]
    assert any(
        warning["field"] == "delegation.scopes"
        and warning["warning_type"] == "missing"
        for warning in analysis["context"]["warnings"]
    )


def test_standalone_analysis_unknown_trace_returns_404() -> None:
    response = client.get("/api/v1/analysis/missing-security-trace")

    assert response.status_code == 404
    assert response.json() == {"detail": "Trace not found"}


def test_standalone_analysis_preserves_insufficient_evidence() -> None:
    spans = _unauthorized_expansion_spans()
    spans[0].attributes["authz.delegation.scopes"] = ["orders:read"]
    for span in spans:
        store.add(span)

    response = client.get(f"/api/v1/analysis/{TRACE_ID}")

    assert response.status_code == 200
    analysis = response.json()
    assert analysis["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert analysis["finding"]["finding_type"] == "NONE"
    assert any(
        warning["field"] == "delegation.scopes"
        and warning["warning_type"] == "missing"
        for warning in analysis["context"]["warnings"]
    )


def test_standalone_analysis_does_not_flag_authorized_trace() -> None:
    store.add(
        _span(
            span_id="authorized-payment-span",
            parent_span_id=None,
            service_name="payment",
            span_name="oteldemo.PaymentService/Charge",
            attributes={
                "authz.principal.id": "user-123",
                "authz.principal.type": "user",
                "authz.principal.scopes": ["payments:charge"],
            },
        )
    )

    response = client.get(f"/api/v1/analysis/{TRACE_ID}")

    assert response.status_code == 200
    analysis = response.json()
    assert analysis["verdict"] == "NOT_DETECTED"
    assert analysis["finding"]["finding_type"] == "NONE"
    assert analysis["finding"]["severity"] == "UNSCORED"
