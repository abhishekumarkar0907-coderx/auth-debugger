"""
Graph models for the authorization-analysis engine.

Defines graph nodes and directed edges representing security principals,
services, operations, delegated authority, and trace contexts.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

from auth_engine.models import (
    Authority,
    AuthoritySource,
    CredentialType,
    DelegationStep,
    Identity,
    Operation,
    PrincipalType,
)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class NodeType(enum.Enum):
    """Category of a node in the authorization graph."""

    PRINCIPAL = "principal"
    SERVICE = "service"
    OPERATION = "operation"
    RESOURCE = "resource"


class EdgeType(enum.Enum):
    """Category of a directed edge in the authorization graph."""

    DELEGATION = "delegation"
    INVOCATION = "invocation"
    EXECUTION = "execution"


# ---------------------------------------------------------------------------
# Graph Nodes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True)
class GraphNode:
    """
    Base node representation in the authorization graph.

    All graph nodes have a unique ``node_id`` and a ``node_type``.
    """

    node_id: str
    node_type: NodeType = NodeType.PRINCIPAL
    metadata: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"Node({self.node_type.value}:{self.node_id})"


@dataclass(frozen=True, kw_only=True)
class PrincipalNode(GraphNode):
    """
    A security principal node (e.g. an initiating user or intermediary agent).
    """

    node_type: NodeType = NodeType.PRINCIPAL
    identity: Identity | None = None
    original_authority: Authority | None = None

    @classmethod
    def from_identity(
        cls,
        identity: Identity,
        authority: Authority | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> PrincipalNode:
        return cls(
            node_id=identity.principal_id,
            node_type=NodeType.PRINCIPAL,
            identity=identity,
            original_authority=authority,
            metadata=metadata or {},
        )


@dataclass(frozen=True, kw_only=True)
class ServiceNode(GraphNode):
    """
    A service node representing a microservice boundary.
    Holds independent service-level authority.
    """

    node_type: NodeType = NodeType.SERVICE
    identity: Identity | None = None
    service_name: str = ""
    service_authority: Authority | None = None

    @classmethod
    def from_identity(
        cls,
        identity: Identity,
        authority: Authority | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ServiceNode:
        svc_name = identity.service_name or identity.principal_id
        return cls(
            node_id=identity.principal_id,
            node_type=NodeType.SERVICE,
            identity=identity,
            service_name=svc_name,
            service_authority=authority,
            metadata=metadata or {},
        )

    @classmethod
    def from_name(
        cls,
        service_name: str,
        authority: Authority | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ServiceNode:
        return cls(
            node_id=service_name,
            node_type=NodeType.SERVICE,
            service_name=service_name,
            service_authority=authority,
            metadata=metadata or {},
        )


@dataclass(frozen=True, kw_only=True)
class OperationNode(GraphNode):
    """
    An operation node representing a downstream action/RPC.
    Carries the permissions required to execute the action.
    """

    node_type: NodeType = NodeType.OPERATION
    operation: Operation | None = None
    service_name: str = ""
    semantic_action: str = ""
    raw_span_name: str | None = None
    required_authority: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_operation(
        cls,
        operation: Operation,
        node_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> OperationNode:
        action = operation.semantic_action or operation.raw_span_name or "unknown"
        nid = node_id or f"op:{operation.service}:{action}"
        return cls(
            node_id=nid,
            node_type=NodeType.OPERATION,
            operation=operation,
            service_name=operation.service,
            semantic_action=action,
            raw_span_name=operation.raw_span_name,
            required_authority=operation.required_authority,
            metadata=metadata or {},
        )


# ---------------------------------------------------------------------------
# Graph Edges
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True)
class GraphEdge:
    """
    Base directed edge in the authorization graph.

    Connects ``source_id`` to ``target_id`` within an optional ``trace_id`` context.
    """

    source_id: str
    target_id: str
    edge_type: EdgeType = EdgeType.INVOCATION
    trace_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        tid_suffix = f" [{self.trace_id}]" if self.trace_id else ""
        return f"{self.source_id} -[:{self.edge_type.value}{tid_suffix}]-> {self.target_id}"


@dataclass(frozen=True, kw_only=True)
class DelegationEdge(GraphEdge):
    """
    A delegation hop between two principals or services.

    Records the delegated authority, credential mechanism, and whether
    the delegation was explicit.
    """

    edge_type: EdgeType = EdgeType.DELEGATION
    delegated_authority: Authority = field(
        default_factory=lambda: Authority.empty(AuthoritySource.DELEGATED)
    )
    credential_type: CredentialType = CredentialType.UNKNOWN
    explicit: bool = True
    step_index: int = 0

    @classmethod
    def from_step(
        cls,
        step: DelegationStep,
        trace_id: str | None = None,
        step_index: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> DelegationEdge:
        return cls(
            source_id=step.from_principal.principal_id,
            target_id=step.to_principal.principal_id,
            edge_type=EdgeType.DELEGATION,
            trace_id=trace_id,
            delegated_authority=step.delegated_authority,
            credential_type=step.credential_type,
            explicit=step.explicit,
            step_index=step_index,
            metadata=metadata or {},
        )


@dataclass(frozen=True, kw_only=True)
class InvocationEdge(GraphEdge):
    """
    A direct call or RPC hop between services or principals.
    """

    edge_type: EdgeType = EdgeType.INVOCATION
    span_id: str | None = None


@dataclass(frozen=True, kw_only=True)
class ExecutionEdge(GraphEdge):
    """
    An execution edge connecting an acting service to a downstream OperationNode.
    Carries the acting service's authority context.
    """

    edge_type: EdgeType = EdgeType.EXECUTION
    operation: Operation | None = None
    service_authority: Authority | None = None
