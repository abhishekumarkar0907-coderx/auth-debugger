from __future__ import annotations

import json
import logging
import os
import time
from hashlib import sha256
from typing import Annotated
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Query, Request
from google.protobuf.message import DecodeError
from pydantic import ValidationError
from dataclasses import fields, is_dataclass
from enum import Enum

from auth_engine.context import AuthorizationContext, extract_authorization_context
from auth_engine.delegation_policy import DelegationPolicy
from auth_engine.detector import ConfusedDeputyDetector
from auth_engine.graph import (
    AuthorizationGraph,
    DelegationEdge,
    ExecutionEdge,
    OperationNode,
    PrincipalNode,
    ServiceNode,
)
from auth_engine.models import DetectionResult, FindingType, Verdict
from auth_engine.policy import default_otel_demo_policy

from .otlp import InvalidOTLPTracePayload, normalize_traces
from .schemas import (
    IngestResponse,
    SpanRecord,
    TraceGraphResponse,
    TraceSummary,
)
from .security_engine import analyze_security_spans, analyze_security_trace
from .store import InMemorySpanStore
from auth_engine.graph.adapter import build_graph_from_spans
from auth_engine.graph import find_authority_amplification_hops

from . import ai_explanation

app = FastAPI(
    title="Authorization Debugger Backend",
    version="0.1.0",
    description=(
        "OTLP trace ingestion and normalization layer for "
        "Authorization Debugger."
    ),
)

store = InMemorySpanStore(max_spans=5000)
logger = logging.getLogger(__name__)
action_policy = default_otel_demo_policy()
analysis_results: dict[str, dict] = {}
_analysis_signatures: dict[str, str] = {}
SERVICE_AUTHORITY_CONFIG: dict[str, list[str]] = {}


def _trace_signature(spans: list[SpanRecord]) -> str:
    digest = sha256()
    for span in spans:
        digest.update(span.model_dump_json().encode("utf-8"))
    return digest.hexdigest()


def _configured_service_authorities() -> dict[str, list[str]]:
    configured = dict(SERVICE_AUTHORITY_CONFIG)
    configured.update(_load_service_authorities())
    return configured


def _json_safe(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _json_safe(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


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


@app.post("/api/v1/demo/scenarios/{scenario_id}")
async def load_demo_scenario(scenario_id: str) -> dict[str, str | int]:
    scenarios = {
        "suspicious-delegation": {
            "scopes": "orders:read",
            "final_scopes": "orders:read,payments:charge",
            "incomplete_final_hop": False,
        },
        "normal-request": {
            "scopes": "orders:read,payments:charge",
            "final_scopes": "orders:read,payments:charge",
            "incomplete_final_hop": False,
        },
        "insufficient-evidence": {
            "scopes": "orders:read",
            "final_scopes": "orders:read",
            "incomplete_final_hop": True,
        },
    }
    if (
        os.getenv("AUTH_DEBUGGER_ENV") != "development"
        or os.getenv("AUTH_DEBUGGER_ENABLE_DEMO_TRACE", "").lower() != "true"
    ):
        raise HTTPException(status_code=404, detail="Demo scenario not found")
    scenario = scenarios.get(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Demo scenario not found")

    trace_id = f"demo-{scenario_id}-{uuid4().hex}"
    base_time = time.time_ns()
    span_ids = [uuid4().hex[:16] for _ in range(3)]
    services = ["api-gateway", "order-service", "payment"]
    operations = [
        "POST /checkout",
        "GET /orders/123",
        "oteldemo.PaymentService/Charge",
    ]
    hops = [
        ("demo-user", "api-gateway", scenario["scopes"], "user_token"),
        ("api-gateway", "order-service", scenario["scopes"], "service_credential"),
        (
            "order-service",
            None if scenario["incomplete_final_hop"] else "payment",
            scenario["final_scopes"],
            "service_credential",
        ),
    ]
    for index, (service, operation, hop) in enumerate(
        zip(services, operations, hops, strict=True)
    ):
        delegation_from, delegation_to, delegated_scopes, credential_type = hop
        attributes: dict[str, object] = {
            "authz.principal.id": "demo-user",
            "authz.principal.type": "user",
            "authz.principal.scopes": scenario["scopes"],
            "authz.delegation.from": delegation_from,
            "authz.delegation.scopes": delegated_scopes,
            "authz.credential.type": credential_type,
        }
        if delegation_to is not None:
            attributes["authz.delegation.to"] = delegation_to
        start_time = base_time + index * 1_000_000
        store.add(
            SpanRecord(
                trace_id=trace_id,
                span_id=span_ids[index],
                parent_span_id=span_ids[index - 1] if index else None,
                service_name=service,
                span_name=operation,
                start_time_unix_nano=start_time,
                end_time_unix_nano=start_time + 500_000,
                duration_ms=0.5,
                span_kind=2 if index == 0 else 3,
                status_code=1,
                attributes=attributes,
            )
        )
    return {
        "scenario_id": scenario_id,
        "trace_id": trace_id,
        "span_count": len(services),
        "data_source": "synthetic_demo",
    }


def _load_service_authorities() -> dict[str, list[str]]:
    raw_config = os.getenv("AUTH_DEBUGGER_SERVICE_AUTHORITIES")
    if not raw_config:
        return {}
    try:
        config = json.loads(raw_config)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=503,
            detail="AUTH_DEBUGGER_SERVICE_AUTHORITIES must be valid JSON",
        ) from exc
    if not isinstance(config, dict) or any(
        not isinstance(service, str)
        or not service
        or not isinstance(permissions, list)
        or any(
            not isinstance(permission, str) or not permission.strip()
            for permission in permissions
        )
        for service, permissions in config.items()
    ):
        raise HTTPException(
            status_code=503,
            detail=(
                "AUTH_DEBUGGER_SERVICE_AUTHORITIES must map service names "
                "to arrays of permission strings"
            ),
        )
    return config


def _load_delegation_policy() -> DelegationPolicy:
    raw_grants = os.getenv("AUTH_DEBUGGER_DELEGATION_GRANTS")
    policy = DelegationPolicy()
    if not raw_grants:
        return policy
    try:
        grants = json.loads(raw_grants)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=503,
            detail="AUTH_DEBUGGER_DELEGATION_GRANTS must be valid JSON",
        ) from exc
    if not isinstance(grants, list):
        raise HTTPException(
            status_code=503,
            detail="AUTH_DEBUGGER_DELEGATION_GRANTS must be a JSON array",
        )
    try:
        for grant in grants:
            if (
                not isinstance(grant, dict)
                or not isinstance(grant.get("from_principal"), str)
                or not grant["from_principal"].strip()
                or not isinstance(grant.get("to_principal"), str)
                or not grant["to_principal"].strip()
                or not isinstance(grant.get("permissions"), list)
                or any(
                    not isinstance(permission, str) or not permission.strip()
                    for permission in grant["permissions"]
                )
            ):
                raise ValueError(
                    "Each grant requires from_principal, to_principal, "
                    "and a permissions array"
                )
            policy.register(
                grant["from_principal"],
                grant["to_principal"],
                grant["permissions"],
            )
    except ValueError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Invalid AUTH_DEBUGGER_DELEGATION_GRANTS: {exc}",
        ) from exc
    return policy


def _serialize_finding(result: DetectionResult) -> dict:
    finding = result.finding
    delegated_authority = finding.delegated_authority
    service_authority = finding.service_authority
    return {
        "finding_id": finding.finding_id,
        "verdict": finding.verdict.value,
        "finding_type": finding.finding_type.value,
        "classification": finding.finding_type.value,
        "severity": finding.severity.value,
        "trace_id": finding.trace_id,
        "initiating_principal": (
            {
                "principal_id": finding.initiating_principal.principal_id,
                "principal_type": finding.initiating_principal.principal_type.value,
            }
            if finding.initiating_principal
            else None
        ),
        "effective_action": finding.effective_action,
        "required_authority": sorted(finding.required_authority),
        "delegated_authority": (
            sorted(delegated_authority.permissions)
            if delegated_authority
            else None
        ),
        "service_authority": (
            sorted(service_authority.permissions) if service_authority else None
        ),
        "attack_path": finding.attack_path,
        "evidence": finding.evidence,
        "reason": result.reason,
        "explanation": result.reason,
    }


def _serialize_analysis(
    context: AuthorizationContext,
    result: DetectionResult | None,
    reason_override: str | None = None,
) -> dict:
    if result is None:
        warning_summary = "; ".join(
            warning.message for warning in context.warnings
        )
        reason = reason_override or (
            f"Insufficient evidence: {warning_summary or 'analysis inputs are incomplete'}"
        )
        return {
            "trace_id": context.trace_id,
            "status": Verdict.INSUFFICIENT_EVIDENCE.value,
            "verdict": Verdict.INSUFFICIENT_EVIDENCE.value,
            "reason": reason,
            "finding": {
                "finding_type": FindingType.NONE.value,
                "severity": "UNSCORED",
                "trace_id": context.trace_id,
                "reason": reason,
            },
            "details": {},
            "findings": [],
            "evidence_warnings": [
                {
                    "field": warning.field,
                    "type": warning.warning_type,
                    "message": warning.message,
                }
                for warning in context.warnings
            ],
            "context": {
                "warnings": [
                    {
                        "field": warning.field,
                        "warning_type": warning.warning_type,
                        "message": warning.message,
                        "sources": warning.sources,
                    }
                    for warning in context.warnings
                ],
                "evidence": [
                    {
                        "field": item.field,
                        "value": item.value,
                        "source": item.source,
                        "span_id": item.span_id,
                        "confidence": item.confidence,
                    }
                    for item in context.evidence
                ],
            },
        }

    finding = _serialize_finding(result)
    return {
        "trace_id": context.trace_id,
        "status": result.verdict.value,
        "verdict": result.verdict.value,
        "reason": result.reason,
        "finding": finding,
        "findings": (
            [{**finding, "details": result.details}]
            if result.verdict is Verdict.DETECTED
            else []
        ),
        "details": result.details,
        "evidence_warnings": [
            {
                "field": warning.field,
                "type": warning.warning_type,
                "message": warning.message,
            }
            for warning in context.warnings
        ],
        "context": {
            "warnings": [
                {
                    "field": warning.field,
                    "warning_type": warning.warning_type,
                    "message": warning.message,
                    "sources": warning.sources,
                }
                for warning in context.warnings
            ],
            "evidence": result.finding.evidence,
        },
    }


def _serialize_graph(graph: AuthorizationGraph, trace_id: str) -> tuple[list[dict], list[dict]]:
    nodes = []
    for node in graph.nodes():
        serialized = {
            "id": node.node_id,
            "type": node.node_type.value,
            "label": node.node_id,
            "metadata": node.metadata,
        }
        if isinstance(node, PrincipalNode):
            if node.original_authority is not None:
                serialized["authority"] = sorted(node.original_authority.permissions)
        elif isinstance(node, ServiceNode):
            serialized["label"] = node.service_name or node.node_id
            if node.service_authority is not None:
                serialized["authority"] = sorted(node.service_authority.permissions)
        elif isinstance(node, OperationNode) and node.operation is not None:
            serialized["label"] = (
                node.operation.semantic_action
                or node.operation.raw_span_name
                or node.node_id
            )
            serialized["service"] = node.operation.service
            serialized["required_authority"] = sorted(
                node.operation.required_authority
            )
        nodes.append(serialized)

    edges = []
    for edge in graph.edges(trace_id=trace_id):
        serialized_edge = {
            "source": edge.source_id,
            "target": edge.target_id,
            "type": edge.edge_type.value,
            "trace_id": edge.trace_id,
            "metadata": edge.metadata,
        }
        if isinstance(edge, DelegationEdge):
            serialized_edge.update({
                "delegated_authority": sorted(
                    edge.delegated_authority.permissions
                ),
                "credential_type": edge.credential_type.value,
                "explicit": edge.explicit,
                "step_index": edge.step_index,
            })
        elif isinstance(edge, ExecutionEdge):
            serialized_edge["service_authority"] = (
                sorted(edge.service_authority.permissions)
                if edge.service_authority
                else None
            )
        edges.append(serialized_edge)
    return nodes, edges


@app.get(
    "/api/v1/traces/{trace_id}/graph",
    response_model=TraceGraphResponse,
)
async def trace_graph(trace_id: str) -> TraceGraphResponse:
    spans = store.trace(trace_id)
    if not spans:
        raise HTTPException(status_code=404, detail="Trace not found")

    try:
        context = extract_authorization_context(
            spans,
            service_authority_config=_configured_service_authorities(),
        )
        graph = AuthorizationGraph()
        result: DetectionResult | None = None
        reason_override: str | None = None

        if context.has_sufficient_evidence():
            scenario = context.to_scenario(policy=action_policy)
            graph.load_scenario(scenario)
            delegation_warnings = [
                warning
                for warning in context.warnings
                if warning.field.startswith("delegation.")
            ]
            if context.outcome_success is True:
                result = ConfusedDeputyDetector(
                    policy=action_policy,
                    delegation_policy=_load_delegation_policy(),
                ).analyze(scenario)
                if (
                    delegation_warnings
                    and result.verdict is Verdict.NOT_DETECTED
                ):
                    result = None
                    reason_override = (
                        "Insufficient evidence: delegation metadata is "
                        "incomplete or malformed"
                    )
            elif context.outcome_success is False:
                reason_override = (
                    "Insufficient evidence: the effective operation failed; "
                    "this trace does not establish a completed action"
                )
            else:
                reason_override = (
                    "Insufficient evidence: the effective operation outcome "
                    "is unknown"
                )
        nodes, edges = _serialize_graph(graph, trace_id)
    except HTTPException:
        raise
    except (ValueError, ValidationError) as exc:
        logger.warning(
            "Invalid authorization context for trace %s (%s)",
            trace_id,
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=422,
            detail="Trace contains invalid authorization context",
        ) from exc
    except Exception as exc:
        logger.exception("Failed to analyze trace %s", trace_id)
        raise HTTPException(
            status_code=500,
            detail="Trace analysis failed",
        ) from exc

    return TraceGraphResponse(
        trace_id=trace_id,
        nodes=nodes,
        edges=edges,
        authority_amplification_hops=_json_safe(
            find_authority_amplification_hops(graph, trace_id=trace_id)
        ),
        security_analysis=_serialize_analysis(
            context,
            result,
            reason_override=reason_override,
        ),
    )


@app.get("/api/v1/traces/{trace_id}/explanation")
async def trace_explanation(
    trace_id: str,
    finding_id: Annotated[str, Query(min_length=1, max_length=160)],
) -> dict[str, object]:
    spans = store.trace(trace_id)
    if not spans:
        raise HTTPException(status_code=404, detail="Trace not found")

    try:
        context = extract_authorization_context(
            spans,
            service_authority_config=_configured_service_authorities(),
        )
        if not context.has_sufficient_evidence() or context.outcome_success is not True:
            return {
                "status": "insufficient_evidence",
                "finding_id": finding_id,
                "explanation": None,
                "message": "The deterministic analysis did not provide enough evidence for an AI explanation.",
            }

        scenario = context.to_scenario(policy=action_policy)
        result = ConfusedDeputyDetector(
            policy=action_policy,
            delegation_policy=_load_delegation_policy(),
        ).analyze(scenario)
        if result.verdict is not Verdict.DETECTED:
            return {
                "status": "insufficient_evidence",
                "finding_id": finding_id,
                "explanation": None,
                "message": "No current detected finding is available to explain.",
            }
        if result.finding.finding_id != finding_id:
            raise HTTPException(
                status_code=409,
                detail="The requested finding does not match the current deterministic result",
            )

        finding = ai_explanation.build_finding_context(
            result,
            scenario,
            request_path=[
                ai_explanation.RequestHop(
                    span_id=span.span_id,
                    parent_span_id=span.parent_span_id,
                    service_name=span.service_name,
                    operation=span.span_name,
                )
                for span in spans
            ],
        )
        outcome = await ai_explanation.explain_finding(finding)
    except HTTPException:
        raise
    except (ValueError, ValidationError) as exc:
        raise HTTPException(
            status_code=422,
            detail="Trace contains invalid authorization evidence",
        ) from exc
    except Exception as exc:
        logger.exception("Failed to explain finding %s for trace %s", finding_id, trace_id)
        raise HTTPException(
            status_code=500,
            detail="Finding explanation failed",
        ) from exc

    return {
        "status": outcome.status,
        "finding_id": finding_id,
        "explanation": (
            outcome.explanation.model_dump(mode="json")
            if outcome.explanation
            else None
        ),
        "message": outcome.message,
    }


@app.post("/api/v1/analysis/{trace_id}")
async def post_analysis(trace_id: str) -> dict:
    spans = store.trace(trace_id)
    if not spans:
        raise HTTPException(status_code=404, detail="Trace not found")
    try:
        result = analyze_security_trace(
            spans,
            service_authority_config=_configured_service_authorities(),
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
                service_authority_config=_configured_service_authorities(),
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
    except (InvalidOTLPTracePayload, DecodeError, ValidationError, ValueError) as exc:
        logger.warning("Rejected invalid OTLP trace payload (%s)", type(exc).__name__)
        raise HTTPException(
            status_code=400,
            detail="Invalid OTLP trace payload.",
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
