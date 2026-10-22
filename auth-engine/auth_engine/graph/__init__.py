"""
auth_engine.graph — Authorization Graph and Query Engine.

Provides an in-memory directed graph for modeling authorization relationships,
tracing delegation paths across microservices and AI agents, and detecting
confused-deputy authority amplification hops.
"""

from .models import (
    DelegationEdge,
    EdgeType,
    ExecutionEdge,
    GraphEdge,
    GraphNode,
    InvocationEdge,
    NodeType,
    OperationNode,
    PrincipalNode,
    ServiceNode,
)
from .queries import (
    AmplificationHop,
    CrossTraceHistory,
    DelegationPath,
    find_authority_amplification_hops,
    find_delegation_paths,
    query_cross_trace_history,
)
from .store import AuthorizationGraph

__all__ = [
    # Enums
    "NodeType",
    "EdgeType",
    # Nodes
    "GraphNode",
    "PrincipalNode",
    "ServiceNode",
    "OperationNode",
    # Edges
    "GraphEdge",
    "DelegationEdge",
    "InvocationEdge",
    "ExecutionEdge",
    # Store
    "AuthorizationGraph",
    # Queries & Result Models
    "find_delegation_paths",
    "query_cross_trace_history",
    "find_authority_amplification_hops",
    "DelegationPath",
    "CrossTraceHistory",
    "AmplificationHop",
]
