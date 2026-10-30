from __future__ import annotations

import json
import logging
import os
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException, Request
from google.protobuf.message import DecodeError
from pydantic import ValidationError

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

from .otlp import normalize_traces
from .schemas import (
    IngestResponse,
    SpanRecord,
    TraceGraphResponse,
    TraceSummary,
)
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
logger = logging.getLogger(__name__)
action_policy = default_otel_demo_policy()


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
        "verdict": finding.verdict.value,
        "finding_type": finding.finding_type.value,
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
            "verdict": Verdict.INSUFFICIENT_EVIDENCE.value,
            "reason": reason,
            "finding": {
                "finding_type": FindingType.NONE.value,
                "severity": "UNSCORED",
                "trace_id": context.trace_id,
                "reason": reason,
            },
            "details": {},
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

    return {
        "verdict": result.verdict.value,
        "reason": result.reason,
        "finding": _serialize_finding(result),
        "details": result.details,
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
            service_authority_config=_load_service_authorities(),
        )
        graph = AuthorizationGraph()
        result: DetectionResult | None = None
        reason_override: str | None = None

        delegation_warnings = [
            warning
            for warning in context.warnings
            if warning.field.startswith("delegation.")
        ]
        if context.has_sufficient_evidence():
            scenario = context.to_scenario(policy=action_policy)
            graph.load_scenario(scenario)
            if delegation_warnings:
                reason_override = (
                    "Insufficient evidence: delegation metadata is incomplete "
                    "or malformed"
                )
            elif context.outcome_success is True:
                result = ConfusedDeputyDetector(
                    policy=action_policy,
                    delegation_policy=_load_delegation_policy(),
                ).analyze(scenario)
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
        security_analysis=_serialize_analysis(
            context,
            result,
            reason_override=reason_override,
        ),
    )


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
    except (DecodeError, ValidationError, ValueError) as exc:
        logger.warning("Rejected invalid OTLP trace payload (%s)", type(exc).__name__)
        raise HTTPException(
            status_code=400,
            detail="Invalid OTLP trace payload",
        ) from exc

    for record in records:
        store.add(record)

    return IngestResponse(
        accepted=True,
        resource_spans=resource_span_count,
        spans=len(records),
    )
