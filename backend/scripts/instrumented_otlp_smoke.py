from __future__ import annotations

import json
import sys
from urllib.request import Request, urlopen

from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
    OTLPSpanExporter,
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.trace import Status, StatusCode


def _provider(service_name: str, endpoint: str) -> TracerProvider:
    provider = TracerProvider(
        resource=Resource.create({"service.name": service_name})
    )
    provider.add_span_processor(
        SimpleSpanProcessor(OTLPSpanExporter(endpoint=endpoint))
    )
    return provider


def _get_json(base_url: str, path: str) -> dict | list:
    request = Request(
        f"{base_url}{path}",
        headers={"Accept": "application/json"},
    )
    with urlopen(request, timeout=10) as response:
        return json.load(response)


def main() -> None:
    base_url = (
        sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8000"
    )
    endpoint = f"{base_url}/v1/traces"
    checkout_provider = _provider("checkout", endpoint)
    payment_provider = _provider("payment", endpoint)
    checkout_tracer = checkout_provider.get_tracer("auth-debugger-smoke")
    payment_tracer = payment_provider.get_tracer("auth-debugger-smoke")

    try:
        with checkout_tracer.start_as_current_span("POST /checkout") as checkout:
            checkout.set_attributes({
                "authz.principal.id": "smoke-user",
                "authz.principal.type": "user",
                "authz.principal.scopes": "orders:read",
                "authz.delegation.from": "smoke-user",
                "authz.delegation.to": "checkout-svc",
                "authz.delegation.scopes": "orders:read",
                "authz.credential.type": "user_token",
            })
            checkout.set_status(Status(StatusCode.OK))

            with payment_tracer.start_as_current_span(
                "oteldemo.PaymentService/Charge"
            ) as payment:
                payment.set_attributes({
                    "authz.principal.id": "smoke-user",
                    "authz.principal.type": "user",
                    "authz.principal.scopes": "orders:read",
                    "authz.delegation.from": "checkout-svc",
                    "authz.delegation.to": "payment",
                    "authz.delegation.scopes": (
                        "orders:read,payments:charge"
                    ),
                    "authz.credential.type": "service_credential",
                })
                payment.set_status(Status(StatusCode.OK))
                trace_id = f"{payment.get_span_context().trace_id:032x}"
                payment_span_id = (
                    f"{payment.get_span_context().span_id:016x}"
                )
                parent_span_id = (
                    f"{payment.parent.span_id:016x}"
                    if payment.parent
                    else None
                )
    finally:
        checkout_provider.shutdown()
        payment_provider.shutdown()

    summary = _get_json(base_url, "/api/v1/traces")
    matching = [
        item for item in summary
        if item["trace_id"] == trace_id
    ]
    assert len(matching) == 1
    assert matching[0]["span_count"] == 2
    assert matching[0]["services"] == ["checkout", "payment"]

    spans = _get_json(base_url, f"/api/v1/traces/{trace_id}")
    assert len(spans) == 2
    assert all(span["trace_id"] == trace_id for span in spans)
    assert all(
        {
            "trace_id",
            "span_id",
            "parent_span_id",
            "service_name",
            "span_name",
            "start_time_unix_nano",
            "end_time_unix_nano",
            "duration_ms",
            "span_kind",
            "status_code",
            "attributes",
        } <= span.keys()
        for span in spans
    )
    assert any(
        span["span_id"] == payment_span_id
        and span["parent_span_id"] == parent_span_id
        and span["service_name"] == "payment"
        for span in spans
    )
    assert any(
        span["span_id"] == parent_span_id
        and span["span_name"] == "POST /checkout"
        and span["service_name"] == "checkout"
        for span in spans
    )

    graph = _get_json(base_url, f"/api/v1/traces/{trace_id}/graph")
    assert graph["trace_id"] == trace_id
    assert {
        "nodes",
        "edges",
        "authority_amplification_hops",
        "security_analysis",
    } <= graph.keys()
    assert graph["security_analysis"]["verdict"] == "DETECTED"
    assert (
        graph["security_analysis"]["finding"]["finding_type"]
        == "UNAUTHORIZED_DELEGATION"
    )

    analysis = _get_json(base_url, f"/api/v1/analysis/{trace_id}")
    assert analysis["trace_id"] == trace_id
    assert analysis["verdict"] == "DETECTED"
    assert analysis["finding"]["finding_type"] == "UNAUTHORIZED_DELEGATION"
    assert analysis["findings"][0]["finding_type"] == "UNAUTHORIZED_DELEGATION"

    print(json.dumps({
        "trace_id": trace_id,
        "ingested_spans": len(spans),
        "parent_span_id": parent_span_id,
        "child_span_id": payment_span_id,
        "graph_verdict": graph["security_analysis"]["verdict"],
        "analysis_verdict": analysis["verdict"],
        "finding_type": analysis["finding"]["finding_type"],
        "api_contract": "compatible",
    }, indent=2))


if __name__ == "__main__":
    main()
