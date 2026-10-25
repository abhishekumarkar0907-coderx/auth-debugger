"""
Graph adapter for telemetry spans.

Bridges OpenTelemetry span records to the AuthorizationGraph using the
security context extraction and scenario construction facilities.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from auth_engine.context import SpanLike, extract_authorization_context
from auth_engine.graph.store import AuthorizationGraph

if TYPE_CHECKING:
    from auth_engine.policy import ActionPolicy


def build_graph_from_spans(
    spans: list[SpanLike],
    *,
    policy: ActionPolicy | None = None,
    service_authority_config: dict[str, list[str]] | None = None,
    graph: AuthorizationGraph | None = None,
    strict: bool = False,
) -> AuthorizationGraph:
    """
    Construct an AuthorizationGraph from telemetry spans.

    Groups spans by trace ID, extracts authorization context using
    `auth_engine.context.extract_authorization_context`, converts
    valid contexts to `AuthorizationScenario` objects, and loads them
    into the returned `AuthorizationGraph`.

    Parameters
    ----------
    spans : list[SpanLike]
        Collection of span records conforming to the `SpanLike` protocol.
    policy : ActionPolicy | None
        Optional action-requirement policy mapping.
    service_authority_config : dict[str, list[str]] | None
        Optional configured authority per service name.
    graph : AuthorizationGraph | None
        Optional existing graph to populate. If None, a new graph is created.
    strict : bool
        If True and any trace has insufficient evidence, raises ValueError.
        If False (default), traces with insufficient evidence are safely skipped.

    Returns
    -------
    AuthorizationGraph
        Populated authorization graph containing nodes and directed edges.
    """
    target_graph = graph if graph is not None else AuthorizationGraph()
    if not spans:
        return target_graph

    by_trace: dict[str, list[SpanLike]] = {}
    for span in spans:
        by_trace.setdefault(span.trace_id, []).append(span)

    for trace_spans in by_trace.values():
        ctx = extract_authorization_context(
            trace_spans,
            service_authority_config=service_authority_config,
        )
        if ctx.has_sufficient_evidence():
            scenario = ctx.to_scenario(policy=policy)
            target_graph.load_scenario(scenario)
        elif strict:
            ctx.to_scenario(policy=policy)

    return target_graph
