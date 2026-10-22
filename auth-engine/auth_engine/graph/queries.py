"""
Graph query engine for authorization analysis.

Provides deterministic graph query operations:
- ``find_delegation_paths``: resolves path traversal from initiator to downstream actions
- ``query_cross_trace_history``: traces principal delegation across distinct trace contexts
- ``find_authority_amplification_hops``: pinpoints confused-deputy authority divergence hops
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from auth_engine.models import (
    Authority,
    AuthoritySource,
    CredentialType,
)

from .models import (
    DelegationEdge,
    ExecutionEdge,
    GraphEdge,
    GraphNode,
    NodeType,
    OperationNode,
    PrincipalNode,
    ServiceNode,
)
from .store import AuthorizationGraph


# ---------------------------------------------------------------------------
# Query Result Data Structures
# ---------------------------------------------------------------------------


@dataclass
class DelegationPath:
    """
    A resolved directed path from an initiating principal to a target action.
    """

    initiating_principal_id: str
    target_action: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    trace_id: str | None = None
    cumulative_authority: Authority = field(
        default_factory=lambda: Authority.empty(AuthoritySource.DELEGATED)
    )

    @property
    def hop_count(self) -> int:
        """Total number of edge hops along this path."""
        return len(self.edges)

    @property
    def path_nodes(self) -> list[str]:
        """Ordered list of node IDs along this path."""
        return [node.node_id for node in self.nodes]

    @property
    def summary(self) -> str:
        hops = " -> ".join(self.path_nodes)
        perms = ", ".join(sorted(self.cumulative_authority.permissions)) or "(none)"
        return f"[{self.trace_id or 'any'}] {hops} => {self.target_action} [auth: {perms}]"


@dataclass
class CrossTraceHistory:
    """
    Record of a principal's delegation relationships across multiple trace contexts.
    """

    principal_id: str
    trace_ids: list[str]
    delegations_as_source: list[DelegationEdge]
    delegations_as_target: list[DelegationEdge]
    by_trace: dict[str, list[DelegationEdge]]

    @property
    def total_delegations(self) -> int:
        return len(self.delegations_as_source) + len(self.delegations_as_target)

    @property
    def trace_count(self) -> int:
        return len(self.trace_ids)

    def delegations_in_trace(self, trace_id: str) -> list[DelegationEdge]:
        """Return all delegation edges involving the principal in a specific trace."""
        return self.by_trace.get(trace_id, [])

    def authorities_delegated(self, trace_id: str | None = None) -> list[Authority]:
        """Return authorities handed off by this principal."""
        edges = self.delegations_as_source
        if trace_id is not None:
            edges = [e for e in edges if e.trace_id == trace_id]
        return [e.delegated_authority for e in edges]

    def authorities_received(self, trace_id: str | None = None) -> list[Authority]:
        """Return authorities received by this principal."""
        edges = self.delegations_as_target
        if trace_id is not None:
            edges = [e for e in edges if e.trace_id == trace_id]
        return [e.delegated_authority for e in edges]


@dataclass
class AmplificationHop:
    """
    Identifies a hop where the request authority lacked the required permission,
    but the downstream service possessed and utilized its own broader authority.
    """

    trace_id: str | None
    hop_index: int
    from_principal_id: str
    to_service_id: str
    edge: GraphEdge | None
    required_permissions: frozenset[str]
    request_authority: Authority
    service_authority: Authority
    amplified_permissions: frozenset[str]
    credential_type: CredentialType
    reason: str


# ---------------------------------------------------------------------------
# Query Functions
# ---------------------------------------------------------------------------


def find_delegation_paths(
    graph: AuthorizationGraph,
    initiating_principal_id: str,
    target_action: str,
    trace_id: str | None = None,
    max_depth: int = 20,
) -> list[DelegationPath]:
    """
    Find all directed paths from ``initiating_principal_id`` to ``target_action``.

    Traverses edges in the graph matching ``trace_id`` (or all traces if None).
    Safely terminates on cycles and bounds exploration by ``max_depth``.
    """
    start_node = graph.get_node(initiating_principal_id)
    if start_node is None:
        return []

    # Identify all operation/target nodes that match target_action
    target_node_ids: set[str] = set()
    for node in graph.nodes():
        if isinstance(node, OperationNode):
            if (
                node.semantic_action == target_action
                or node.raw_span_name == target_action
                or node.node_id == target_action
                or target_action in node.required_authority
            ):
                target_node_ids.add(node.node_id)
        elif node.node_id == target_action:
            target_node_ids.add(node.node_id)

    # If no explicit operation node exists matching target_action,
    # also check if any execution edges point to this action
    if not target_node_ids:
        for edge in graph.edges(trace_id=trace_id):
            if isinstance(edge, ExecutionEdge) and edge.operation:
                if (
                    edge.operation.semantic_action == target_action
                    or edge.operation.raw_span_name == target_action
                    or target_action in edge.operation.required_authority
                ):
                    target_node_ids.add(edge.target_id)

    if not target_node_ids:
        return []

    initial_auth = Authority.empty(AuthoritySource.ORIGINAL)
    if isinstance(start_node, PrincipalNode) and start_node.original_authority:
        initial_auth = start_node.original_authority

    discovered_paths: list[DelegationPath] = []

    # DFS path exploration with cycle prevention
    def _dfs(
        current_node: GraphNode,
        current_path_nodes: list[GraphNode],
        current_path_edges: list[GraphEdge],
        current_authority: Authority,
        visited_ids: set[str],
        depth: int,
    ) -> None:
        if depth > max_depth:
            return

        # Check if we reached a target node
        if current_node.node_id in target_node_ids and current_path_edges:
            discovered_paths.append(
                DelegationPath(
                    initiating_principal_id=initiating_principal_id,
                    target_action=target_action,
                    nodes=list(current_path_nodes),
                    edges=list(current_path_edges),
                    trace_id=current_path_edges[0].trace_id if current_path_edges else None,
                    cumulative_authority=current_authority,
                )
            )
            return

        outgoing = graph.get_outgoing_edges(current_node.node_id, trace_id=trace_id)
        # Sort edges deterministically
        sorted_outgoing = sorted(
            outgoing,
            key=lambda e: (e.target_id, e.trace_id or "", getattr(e, "step_index", 0)),
        )

        for edge in sorted_outgoing:
            target_id = edge.target_id
            if target_id in visited_ids:
                # Cycle prevention: skip node already in current path
                continue

            target_node = graph.get_node(target_id)
            if target_node is None:
                continue

            # Compute updated request authority along this hop
            next_auth = current_authority
            if isinstance(edge, DelegationEdge):
                if edge.explicit:
                    next_auth = Authority(
                        permissions=edge.delegated_authority.permissions,
                        source=AuthoritySource.DELEGATED,
                    )
            elif isinstance(edge, ExecutionEdge):
                # Execution edge carries the service execution hop
                pass

            visited_ids.add(target_id)
            current_path_nodes.append(target_node)
            current_path_edges.append(edge)

            _dfs(
                current_node=target_node,
                current_path_nodes=current_path_nodes,
                current_path_edges=current_path_edges,
                current_authority=next_auth,
                visited_ids=visited_ids,
                depth=depth + 1,
            )

            current_path_edges.pop()
            current_path_nodes.pop()
            visited_ids.remove(target_id)

    visited_set = {initiating_principal_id}
    _dfs(
        current_node=start_node,
        current_path_nodes=[start_node],
        current_path_edges=[],
        current_authority=initial_auth,
        visited_ids=visited_set,
        depth=0,
    )

    # Sort paths deterministically
    return sorted(discovered_paths, key=lambda p: (p.hop_count, p.path_nodes))


def query_cross_trace_history(
    graph: AuthorizationGraph,
    principal_id: str,
) -> CrossTraceHistory:
    """
    Find all delegation relationships involving a principal across multiple traces.
    """
    outgoing = graph.get_outgoing_edges(principal_id)
    incoming = graph.get_incoming_edges(principal_id)

    source_delegations: list[DelegationEdge] = []
    target_delegations: list[DelegationEdge] = []
    by_trace: dict[str, list[DelegationEdge]] = {}
    seen_traces: set[str] = set()

    for edge in outgoing:
        if isinstance(edge, DelegationEdge):
            source_delegations.append(edge)
            tid = edge.trace_id or "unspecified"
            seen_traces.add(tid)
            by_trace.setdefault(tid, []).append(edge)

    for edge in incoming:
        if isinstance(edge, DelegationEdge):
            target_delegations.append(edge)
            tid = edge.trace_id or "unspecified"
            seen_traces.add(tid)
            by_trace.setdefault(tid, []).append(edge)

    # Deterministic sorting
    source_delegations.sort(
        key=lambda e: (e.trace_id or "", e.step_index, e.target_id)
    )
    target_delegations.sort(
        key=lambda e: (e.trace_id or "", e.step_index, e.source_id)
    )
    for tid in by_trace:
        by_trace[tid].sort(
            key=lambda e: (e.step_index, e.source_id, e.target_id)
        )

    return CrossTraceHistory(
        principal_id=principal_id,
        trace_ids=sorted(seen_traces),
        delegations_as_source=source_delegations,
        delegations_as_target=target_delegations,
        by_trace=by_trace,
    )


def find_authority_amplification_hops(
    graph: AuthorizationGraph,
    trace_id: str | None = None,
    required_permission: str | frozenset[str] | None = None,
) -> list[AmplificationHop]:
    """
    Identify delegation hops where the request lacks the required permission
    for the downstream action, but the acting service possesses and uses it.
    """
    trace_ids_to_check: list[str | None]
    if trace_id is not None:
        trace_ids_to_check = [trace_id]
    else:
        known_tids = graph.trace_ids()
        trace_ids_to_check = [tid for tid in known_tids] if known_tids else [None]

    amplification_hops: list[AmplificationHop] = []

    for tid in trace_ids_to_check:
        # Determine required permissions for this trace
        required_perms: frozenset[str]
        if required_permission is not None:
            if isinstance(required_permission, str):
                required_perms = frozenset({required_permission})
            else:
                required_perms = frozenset(required_permission)
        else:
            # Discover required permissions from OperationNodes in this trace
            discovered_perms: set[str] = set()
            for edge in graph.edges(trace_id=tid):
                if isinstance(edge, ExecutionEdge) and edge.operation:
                    discovered_perms.update(edge.operation.required_authority)
                    if edge.operation.semantic_action:
                        discovered_perms.add(edge.operation.semantic_action)
            for node in graph.nodes(NodeType.OPERATION):
                if isinstance(node, OperationNode):
                    discovered_perms.update(node.required_authority)
                    if node.semantic_action:
                        discovered_perms.add(node.semantic_action)
            required_perms = frozenset(discovered_perms)

        if not required_perms:
            continue

        # Get all delegation edges for this trace sorted by step_index
        edges = [
            e for e in graph.edges(trace_id=tid)
            if isinstance(e, DelegationEdge)
        ]
        edges.sort(key=lambda e: e.step_index)

        if not edges:
            continue

        # Determine starting authority from initiating principal node
        initiator_id = edges[0].source_id
        initiator_node = graph.get_node(initiator_id)
        current_request_auth = Authority.empty(AuthoritySource.ORIGINAL)
        if isinstance(initiator_node, PrincipalNode) and initiator_node.original_authority:
            current_request_auth = initiator_node.original_authority

        # Walk each delegation step
        for edge in edges:
            if edge.explicit:
                next_request_auth = Authority(
                    permissions=edge.delegated_authority.permissions,
                    source=AuthoritySource.DELEGATED,
                )
            else:
                next_request_auth = current_request_auth

            target_node = graph.get_node(edge.target_id)
            target_service_auth: Authority | None = None
            if isinstance(target_node, ServiceNode):
                target_service_auth = target_node.service_authority

            # If not directly on node, check outgoing execution edges from target
            if target_service_auth is None:
                for out_edge in graph.get_outgoing_edges(edge.target_id, trace_id=tid):
                    if isinstance(out_edge, ExecutionEdge) and out_edge.service_authority:
                        target_service_auth = out_edge.service_authority
                        break

            # Check if this hop introduces a confused-deputy amplification:
            # 1. The request authority at this hop does not satisfy the required permission
            # 2. The target service's independent authority DOES possess the permission
            if target_service_auth is not None:
                has_req = required_perms <= next_request_auth.permissions
                service_can = bool(required_perms & target_service_auth.permissions)

                if not has_req and service_can:
                    amplified = (required_perms & target_service_auth.permissions) - next_request_auth.permissions
                    if amplified:
                        amplification_hops.append(
                            AmplificationHop(
                                trace_id=tid,
                                hop_index=edge.step_index,
                                from_principal_id=edge.source_id,
                                to_service_id=edge.target_id,
                                edge=edge,
                                required_permissions=required_perms,
                                request_authority=next_request_auth,
                                service_authority=target_service_auth,
                                amplified_permissions=frozenset(amplified),
                                credential_type=edge.credential_type,
                                reason=(
                                    f"Service '{edge.target_id}' at hop {edge.step_index} amplified authority: "
                                    f"request lacked {sorted(amplified)} but service possessed it via "
                                    f"{edge.credential_type.value}"
                                ),
                            )
                        )

            current_request_auth = next_request_auth

    # Sort amplification hops deterministically
    return sorted(
        amplification_hops,
        key=lambda h: (h.trace_id or "", h.hop_index, h.to_service_id),
    )
