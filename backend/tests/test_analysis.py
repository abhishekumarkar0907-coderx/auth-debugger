from fastapi.testclient import TestClient
import pytest

from app.main import app, store, analysis_results
from app.schemas import SpanRecord

client = TestClient(app)

TRACE_ID = "analysis-test-trace"


def add_test_trace(trace_id: str = TRACE_ID) -> None:
    store.add(
        SpanRecord(
            trace_id=trace_id,
            span_id="analysis-span-001",
            parent_span_id=None,
            service_name="test-service",
            span_name="GET /api/test",
            start_time_unix_nano=1_000_000_000,
            end_time_unix_nano=1_025_000_000,
            duration_ms=25.0,
            span_kind=1,
            status_code=0,
            attributes={},
        )
    )


def setup_function() -> None:
    store._spans.clear()
    analysis_results.clear()


def test_post_analysis_missing_trace_returns_404() -> None:
    response = client.post("/api/v1/analysis/missing-trace")
    assert response.status_code == 404
    assert response.json()["detail"] == "Trace not found"


def test_get_analysis_missing_trace_returns_404() -> None:
    response = client.get("/api/v1/analysis/missing-trace")
    assert response.status_code == 404
    assert response.json()["detail"] == "Trace not found"


def test_get_analysis_cache_miss_analyzes_insufficient_trace() -> None:
    add_test_trace()

    response = client.get(f"/api/v1/analysis/{TRACE_ID}")

    assert response.status_code == 200
    assert response.json()["status"] == "INSUFFICIENT_EVIDENCE"
    assert analysis_results[TRACE_ID] == response.json()


def test_post_analysis_insufficient_evidence_is_preserved() -> None:
    add_test_trace()

    response = client.post(f"/api/v1/analysis/{TRACE_ID}")

    assert response.status_code == 200
    body = response.json()
    assert body["trace_id"] == TRACE_ID
    assert body["status"] == "INSUFFICIENT_EVIDENCE"
    assert body["reason"] == body["finding"]["reason"]
    assert "findings" in body
    assert "analyzed_at" in body
    assert "errors" in body

    saved = client.get(f"/api/v1/analysis/{TRACE_ID}")
    assert saved.status_code == 200
    assert saved.json() == body


def test_unknown_action_has_diagnostic_and_remains_insufficient() -> None:
    from auth_engine.context import extract_authorization_context
    from auth_engine.detector import ConfusedDeputyDetector
    from auth_engine.models import Severity, Verdict
    from auth_engine.policy import default_otel_demo_policy

    trace_id = "unknown-action-trace"
    span = SpanRecord(
        trace_id=trace_id,
        span_id="unknown-action-span",
        parent_span_id=None,
        service_name="unknown-service",
        span_name="UnknownService/DeleteEverything",
        start_time_unix_nano=1_000_000_000,
        end_time_unix_nano=1_025_000_000,
        duration_ms=25.0,
        span_kind=1,
        status_code=1,
        attributes={
            "authz.principal.id": "user-123",
            "authz.principal.type": "user",
            "authz.principal.scopes": "items:read",
        },
    )
    store.add(span)

    policy = default_otel_demo_policy()
    context = extract_authorization_context([span])
    scenario = context.to_scenario(policy=policy)
    assert scenario.effective_operation is not None
    assert scenario.effective_operation.semantic_action is None
    assert scenario.effective_operation.required_authority == frozenset()

    detector_result = ConfusedDeputyDetector(policy=policy).analyze(scenario)
    assert detector_result.verdict is Verdict.INSUFFICIENT_EVIDENCE
    assert detector_result.finding.severity is Severity.UNSCORED

    response = client.post(f"/api/v1/analysis/{trace_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert body["status"] == "INSUFFICIENT_EVIDENCE"
    assert body["findings"] == []
    warning = next(
        item
        for item in body["evidence_warnings"]
        if item["field"] == "effective_action"
    )
    assert warning["type"] == "unknown"
    assert "action requirement mapping is missing" in warning["message"]


def test_repeated_analysis_updates_latest_result() -> None:
    add_test_trace()

    first = client.post(f"/api/v1/analysis/{TRACE_ID}")
    second = client.post(f"/api/v1/analysis/{TRACE_ID}")

    assert first.status_code == 200
    assert second.status_code == 200
    assert client.get(f"/api/v1/analysis/{TRACE_ID}").json() == second.json()
    assert client.get(f"/api/v1/analysis/{TRACE_ID}").json() == second.json()


def test_get_analysis_returns_cached_result() -> None:
    add_test_trace()
    cached = {"trace_id": TRACE_ID, "status": "cached-result"}
    analysis_results[TRACE_ID] = cached

    response = client.get(f"/api/v1/analysis/{TRACE_ID}")

    assert response.status_code == 200
    assert response.json() == cached


def test_analysis_function_is_available() -> None:
    from app.analysis import analyze_trace
    assert callable(analyze_trace)


def test_demo_trace_is_disabled_without_development_opt_in(
    monkeypatch,
) -> None:
    monkeypatch.delenv("AUTH_DEBUGGER_ENV", raising=False)
    monkeypatch.delenv("AUTH_DEBUGGER_ENABLE_DEMO_TRACE", raising=False)

    path = "/api/v1/demo/unauthorized-delegation"
    assert path in app.openapi()["paths"]
    assert "post" in app.openapi()["paths"][path]

    response = client.post("/api/v1/demo/unauthorized-delegation")

    assert response.status_code == 404
    assert not store.trace("demo-unauthorized-delegation-v1")


def test_demo_trace_loads_and_is_detected_in_graph(monkeypatch) -> None:
    monkeypatch.setenv("AUTH_DEBUGGER_ENV", "development")
    monkeypatch.setenv("AUTH_DEBUGGER_ENABLE_DEMO_TRACE", "true")

    loaded = client.post("/api/v1/demo/unauthorized-delegation")
    assert loaded.status_code == 200
    trace_id = loaded.json()["trace_id"]
    assert trace_id == "demo-unauthorized-delegation-v1"

    analysis_response = client.get(f"/api/v1/analysis/{trace_id}")
    assert analysis_response.status_code == 200
    assert analysis_response.json()["verdict"] == "DETECTED"
    assert analysis_response.json()["findings"][0]["classification"] == "UNAUTHORIZED_DELEGATION"

    traces = client.get("/api/v1/traces")
    assert trace_id in {trace["trace_id"] for trace in traces.json()}

    graph = client.get(f"/api/v1/traces/{trace_id}/graph")
    assert graph.status_code == 200
    analysis = graph.json()["security_analysis"]
    assert analysis["verdict"] == "DETECTED"
    assert analysis["findings"][0]["classification"] == "UNAUTHORIZED_DELEGATION"


@pytest.mark.parametrize(
    ("scenario_id", "expected_verdict"),
    [
        ("suspicious-delegation", "DETECTED"),
        ("normal-request", "NOT_DETECTED"),
        ("insufficient-evidence", "INSUFFICIENT_EVIDENCE"),
    ],
)
def test_demo_scenarios_use_deterministic_graph_analysis(
    monkeypatch,
    scenario_id: str,
    expected_verdict: str,
) -> None:
    monkeypatch.setenv("AUTH_DEBUGGER_ENV", "development")
    monkeypatch.setenv("AUTH_DEBUGGER_ENABLE_DEMO_TRACE", "true")

    loaded = client.post(f"/api/v1/demo/scenarios/{scenario_id}")

    assert loaded.status_code == 200
    result = loaded.json()
    assert result["scenario_id"] == scenario_id
    assert result["span_count"] == 3
    assert result["data_source"] == "synthetic_demo"

    graph_response = client.get(
        f"/api/v1/traces/{result['trace_id']}/graph"
    )

    assert graph_response.status_code == 200
    graph = graph_response.json()
    spans = client.get(f"/api/v1/traces/{result['trace_id']}").json()
    assert [span["service_name"] for span in spans] == [
        "api-gateway",
        "order-service",
        "payment",
    ]
    assert spans[1]["parent_span_id"] == spans[0]["span_id"]
    assert spans[2]["parent_span_id"] == spans[1]["span_id"]
    assert graph["security_analysis"]["verdict"] == expected_verdict
    if scenario_id == "suspicious-delegation":
        assert (
            graph["security_analysis"]["finding"]["finding_type"]
            == "UNAUTHORIZED_DELEGATION"
        )
    if scenario_id == "insufficient-evidence":
        assert not any(
            edge["type"] == "delegation" and edge["target"] == "payment"
            for edge in graph["edges"]
        )
        assert any(
            warning["field"] == "delegation.to"
            for warning in graph["security_analysis"]["finding"]["evidence"][
                "extraction_warnings"
            ]
        )


def test_demo_scenarios_are_disabled_without_development_opt_in(
    monkeypatch,
) -> None:
    monkeypatch.delenv("AUTH_DEBUGGER_ENV", raising=False)
    monkeypatch.delenv("AUTH_DEBUGGER_ENABLE_DEMO_TRACE", raising=False)

    response = client.post(
        "/api/v1/demo/scenarios/suspicious-delegation"
    )

    assert response.status_code == 404


def test_post_analysis_detects_unauthorized_delegation_expansion() -> None:
    from app.main import SERVICE_AUTHORITY_CONFIG

    trace_id = "confused-deputy-integration-trace"

    store.add(
        SpanRecord(
            trace_id=trace_id,
            span_id="span-root",
            parent_span_id=None,
            service_name="frontend",
            span_name="POST /checkout",
            start_time_unix_nano=1_000_000_000,
            end_time_unix_nano=1_025_000_000,
            duration_ms=25.0,
            span_kind=1,
            status_code=1,
            attributes={
                "enduser.id": "user-123",
                "authz.principal.id": "user-123",
                "authz.principal.type": "user",
                "authz.principal.scopes": "orders:read",
                "authz.delegation.from": "user-123",
                "authz.delegation.to": "checkout-svc",
                "authz.delegation.scopes": "orders:read",
                "authz.credential.type": "user_token",
            },
        )
    )
    store.add(
        SpanRecord(
            trace_id=trace_id,
            span_id="span-leaf",
            parent_span_id="span-root",
            service_name="payment",
            span_name="oteldemo.PaymentService/Charge",
            start_time_unix_nano=1_025_000_000,
            end_time_unix_nano=1_050_000_000,
            duration_ms=25.0,
            span_kind=1,
            status_code=1,
            attributes={
                "enduser.id": "user-123",
                "authz.principal.id": "user-123",
                "authz.principal.type": "user",
                "authz.principal.scopes": "orders:read",
                "authz.delegation.scopes": "orders:read,payments:charge",
                "authz.delegation.from": "checkout-svc",
                "authz.delegation.to": "payment-svc",
                "authz.credential.type": "service_credential",
            },
        )
    )

    original_config = SERVICE_AUTHORITY_CONFIG.copy()
    try:
        SERVICE_AUTHORITY_CONFIG["payment"] = ["payments:charge"]

        response = client.post(f"/api/v1/analysis/{trace_id}")

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "DETECTED"
        assert len(body["findings"]) >= 1

        graph_response = client.get(
            f"/api/v1/traces/{trace_id}/graph"
        )
        assert graph_response.status_code == 200
        graph_body = graph_response.json()
        assert {
            "trace_id",
            "nodes",
            "edges",
            "authority_amplification_hops",
        } <= graph_body.keys()
        assert graph_body["security_analysis"]["verdict"] == "DETECTED"
        assert graph_body["security_analysis"]["trace_id"] == trace_id
        finding = graph_body["security_analysis"]["findings"][0]
        assert finding["classification"] == "UNAUTHORIZED_DELEGATION"
        assert finding["severity"]
        assert finding["explanation"]
        assert finding["attack_path"]
    finally:
        SERVICE_AUTHORITY_CONFIG.clear()
        SERVICE_AUTHORITY_CONFIG.update(original_config)
