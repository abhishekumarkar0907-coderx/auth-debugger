"""
In-memory directed graph store for authorization analysis.

Uses Python standard-library data structures (dict, list, set) to provide a
fast, deterministic, zero-dependency graph store for authorization relationships.
"""

from __future__ import annotations

from typing import Any

from auth_engine.models import (
    Authority,
    AuthorizationEvent,
    AuthorizationScenario,
    Identity,
    Operation,
    PrincipalType,
)

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


class AuthorizationGraph:
    """
    In-memory directed authorization graph.

    Maintains nodes (principals, services, operations) and directed edges
    (delegations, invocations, executions) indexed by node ID and trace ID.
    """

    def __init__(self) -> None:
        # node_id -> GraphNode
        self._nodes: dict[str, GraphNode] = {}
        # list of all unique edges
        self._edges: list[GraphEdge] = []
        # source_id -> list of outgoing edges
        self._outgoing: dict[str, list[GraphEdge]] = {}
        # target_id -> list of incoming edges
        self._incoming: dict[str, list[GraphEdge]] = {}
        # trace_id -> list of edges
        self._trace_edges: dict[str, list[GraphEdge]] = {}

    # -----------------------------------------------------------------------
    # Node Management
    # -----------------------------------------------------------------------

    def add_node(self, node: GraphNode, overwrite: bool = False) -> GraphNode:
        """
        Add a node to the graph.

        Safely handles duplicate node IDs:
        - If ``overwrite=False`` and the node already exists, the existing node is
          preserved (and enriched with any missing authority/identity) without error.
        - If ``overwrite=True``, the existing node is replaced.
        """
        existing = self._nodes.get(node.node_id)
        if existing is not None and not overwrite:
            # Safely enrich existing node if the new node has additional context
            enriched = self._enrich_node(existing, node)
            self._nodes[node.node_id] = enriched
            return enriched

        self._nodes[node.node_id] = node
        return node

    def get_node(self, node_id: str) -> GraphNode | None:
        """Retrieve a node by its unique ID. Returns None if not found."""
        return self._nodes.get(node_id)

    def has_node(self, node_id: str) -> bool:
        """Return True if a node with node_id exists in the graph."""
        return node_id in self._nodes

    def nodes(self, node_type: NodeType | None = None) -> list[GraphNode]:
        """
        Return a list of all nodes in deterministic order.
        Optionally filter by NodeType.
        """
        all_nodes = list(self._nodes.values())
        if node_type is not None:
            all_nodes = [n for n in all_nodes if n.node_type == node_type]
        return sorted(all_nodes, key=lambda n: (n.node_type.value, n.node_id))

    @property
    def node_count(self) -> int:
        """Total number of unique nodes in the graph."""
        return len(self._nodes)

    def __len__(self) -> int:
        return len(self._nodes)

    # -----------------------------------------------------------------------
    # Edge Management
    # -----------------------------------------------------------------------

    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        """
        Add a directed edge to the graph.

        Ensures source and target nodes exist (creating placeholder nodes if needed),
        and safely prevents adding duplicate identical edges.
        """
        # Ensure source and target nodes exist in the graph
        if edge.source_id not in self._nodes:
            self._nodes[edge.source_id] = PrincipalNode(node_id=edge.source_id)
        if edge.target_id not in self._nodes:
            self._nodes[edge.target_id] = PrincipalNode(node_id=edge.target_id)

        # Check for duplicate edge
        outgoing = self._outgoing.setdefault(edge.source_id, [])
        for existing in outgoing:
            if self._edges_equal(existing, edge):
                return existing

        # Append new edge
        self._edges.append(edge)
        outgoing.append(edge)
        self._incoming.setdefault(edge.target_id, []).append(edge)

        if edge.trace_id:
            self._trace_edges.setdefault(edge.trace_id, []).append(edge)

        return edge

    def edges(self, trace_id: str | None = None) -> list[GraphEdge]:
        """
        Return all edges in the graph, optionally filtered by trace_id.
        """
        if trace_id is not None:
            return list(self._trace_edges.get(trace_id, []))
        return list(self._edges)

    @property
    def edge_count(self) -> int:
        """Total number of directed edges in the graph."""
        return len(self._edges)

    def trace_ids(self) -> list[str]:
        """Return a sorted list of all unique trace IDs observed in the graph."""
        return sorted(self._trace_edges.keys())

    # -----------------------------------------------------------------------
    # Neighbor Retrieval
    # -----------------------------------------------------------------------

    def get_outgoing_edges(
        self, node_id: str, trace_id: str | None = None
    ) -> list[GraphEdge]:
        """Return all outgoing edges from node_id, optionally filtered by trace_id."""
        edges = self._outgoing.get(node_id, [])
        if trace_id is not None:
            edges = [e for e in edges if e.trace_id == trace_id]
        return edges

    def get_incoming_edges(
        self, node_id: str, trace_id: str | None = None
    ) -> list[GraphEdge]:
        """Return all incoming edges to node_id, optionally filtered by trace_id."""
        edges = self._incoming.get(node_id, [])
        if trace_id is not None:
            edges = [e for e in edges if e.trace_id == trace_id]
        return edges

    def get_successors(
        self, node_id: str, trace_id: str | None = None
    ) -> list[GraphNode]:
        """Return all neighbor nodes that node_id points to via outgoing edges."""
        outgoing = self.get_outgoing_edges(node_id, trace_id=trace_id)
        seen: set[str] = set()
        successors: list[GraphNode] = []
        for edge in outgoing:
            if edge.target_id not in seen and edge.target_id in self._nodes:
                seen.add(edge.target_id)
                successors.append(self._nodes[edge.target_id])
        return sorted(successors, key=lambda n: n.node_id)

    def get_predecessors(
        self, node_id: str, trace_id: str | None = None
    ) -> list[GraphNode]:
        """Return all neighbor nodes that point to node_id via incoming edges."""
        incoming = self.get_incoming_edges(node_id, trace_id=trace_id)
        seen: set[str] = set()
        predecessors: list[GraphNode] = []
        for edge in incoming:
            if edge.source_id not in seen and edge.source_id in self._nodes:
                seen.add(edge.source_id)
                predecessors.append(self._nodes[edge.source_id])
        return sorted(predecessors, key=lambda n: n.node_id)

    def get_neighbors(
        self,
        node_id: str,
        direction: str = "outgoing",
        trace_id: str | None = None,
    ) -> list[GraphNode]:
        """
        Return neighbor nodes for node_id.

        ``direction`` can be "outgoing" (successors), "incoming" (predecessors),
        or "both". Safely returns [] if node_id does not exist.
        """
        if node_id not in self._nodes:
            return []

        if direction == "outgoing":
            return self.get_successors(node_id, trace_id=trace_id)
        elif direction == "incoming":
            return self.get_predecessors(node_id, trace_id=trace_id)
        elif direction == "both":
            succ = self.get_successors(node_id, trace_id=trace_id)
            pred = self.get_predecessors(node_id, trace_id=trace_id)
            seen = {n.node_id for n in succ}
            combined = list(succ)
            for p in pred:
                if p.node_id not in seen:
                    seen.add(p.node_id)
                    combined.append(p)
            return sorted(combined, key=lambda n: n.node_id)
        else:
            raise ValueError(f"Unknown direction '{direction}'; expected 'outgoing', 'incoming', or 'both'")

    # -----------------------------------------------------------------------
    # Scenario & Event Ingestion
    # -----------------------------------------------------------------------

    def load_scenario(self, scenario: AuthorizationScenario) -> None:
        """
        Translate an AuthorizationScenario into graph nodes and directed edges.
        """
        trace_id = scenario.trace_id

        # 1. Initiating Principal
        if scenario.initiating_principal:
            init_node = PrincipalNode.from_identity(
                scenario.initiating_principal,
                authority=scenario.original_authority,
            )
            self.add_node(init_node)

        # 2. Known service identities
        for svc_ident in scenario.service_identities:
            svc_node = ServiceNode.from_identity(svc_ident)
            self.add_node(svc_node)

        # 3. Delegation steps
        for idx, step in enumerate(scenario.delegation_chain):
            from_ident = step.from_principal
            to_ident = step.to_principal

            # Ensure from node
            if from_ident.principal_id not in self._nodes:
                self.add_node(
                    self._create_node_from_identity(from_ident)
                )

            # Ensure to node
            if to_ident.principal_id not in self._nodes:
                self.add_node(
                    self._create_node_from_identity(to_ident)
                )

            # Add delegation edge
            self.add_edge(
                DelegationEdge.from_step(
                    step,
                    trace_id=trace_id,
                    step_index=idx,
                )
            )

        # 4. Effective operation & acting service
        if scenario.effective_operation:
            op = scenario.effective_operation
            op_node = OperationNode.from_operation(op)
            self.add_node(op_node)

            # Identify acting service principal
            acting_service_id = None
            if scenario.delegation_chain:
                acting_service_id = scenario.delegation_chain[-1].to_principal.principal_id
            elif scenario.service_identities:
                for svc in scenario.service_identities:
                    if svc.service_name == op.service or svc.principal_id == op.service:
                        acting_service_id = svc.principal_id
                        break
            if not acting_service_id:
                acting_service_id = op.service

            # Ensure acting service node exists and record its service authority
            acting_node = self._nodes.get(acting_service_id)
            if acting_node is None:
                acting_node = ServiceNode.from_name(
                    service_name=acting_service_id,
                    authority=scenario.acting_service_authority,
                )
                self.add_node(acting_node)
            elif scenario.acting_service_authority and isinstance(acting_node, ServiceNode):
                # Enrich with acting service authority if not already present
                enriched = ServiceNode(
                    node_id=acting_node.node_id,
                    node_type=acting_node.node_type,
                    identity=acting_node.identity,
                    service_name=acting_node.service_name,
                    service_authority=scenario.acting_service_authority,
                    metadata=acting_node.metadata,
                )
                self.add_node(enriched, overwrite=True)

            # Add execution edge
            self.add_edge(
                ExecutionEdge(
                    source_id=acting_service_id,
                    target_id=op_node.node_id,
                    edge_type=EdgeType.EXECUTION,
                    trace_id=trace_id,
                    operation=op,
                    service_authority=scenario.acting_service_authority,
                )
            )

    def load_event(self, event: AuthorizationEvent) -> None:
        """
        Load a normalized AuthorizationEvent into the graph.
        """
        trace_id = event.trace_id

        if event.initiating_principal:
            self.add_node(
                self._create_node_from_identity(
                    event.initiating_principal,
                    authority=event.original_authority,
                )
            )

        if event.acting_principal:
            self.add_node(
                self._create_node_from_identity(
                    event.acting_principal,
                    authority=event.service_authority,
                )
            )

        if event.initiating_principal and event.acting_principal:
            if event.initiating_principal.principal_id != event.acting_principal.principal_id:
                self.add_edge(
                    DelegationEdge(
                        source_id=event.initiating_principal.principal_id,
                        target_id=event.acting_principal.principal_id,
                        edge_type=EdgeType.DELEGATION,
                        trace_id=trace_id,
                        delegated_authority=event.delegated_authority or Authority.empty(),
                    )
                )

        if event.operation and event.acting_principal:
            op_node = OperationNode.from_operation(event.operation)
            self.add_node(op_node)
            self.add_edge(
                ExecutionEdge(
                    source_id=event.acting_principal.principal_id,
                    target_id=op_node.node_id,
                    edge_type=EdgeType.EXECUTION,
                    trace_id=trace_id,
                    operation=event.operation,
                    service_authority=event.service_authority,
                )
            )

    def clear(self) -> None:
        """Clear all nodes and edges from the graph."""
        self._nodes.clear()
        self._edges.clear()
        self._outgoing.clear()
        self._incoming.clear()
        self._trace_edges.clear()

    # -----------------------------------------------------------------------
    # Internal Helpers
    # -----------------------------------------------------------------------

    def _create_node_from_identity(
        self,
        identity: Identity,
        authority: Authority | None = None,
    ) -> GraphNode:
        if identity.principal_type == PrincipalType.SERVICE:
            return ServiceNode.from_identity(identity, authority=authority)
        return PrincipalNode.from_identity(identity, authority=authority)

    def _enrich_node(self, existing: GraphNode, incoming: GraphNode) -> GraphNode:
        """Enrich existing node with incoming properties if missing."""
        if isinstance(existing, ServiceNode) and isinstance(incoming, ServiceNode):
            auth = existing.service_authority or incoming.service_authority
            ident = existing.identity or incoming.identity
            name = existing.service_name or incoming.service_name
            meta = {**existing.metadata, **incoming.metadata}
            return ServiceNode(
                node_id=existing.node_id,
                node_type=existing.node_type,
                identity=ident,
                service_name=name,
                service_authority=auth,
                metadata=meta,
            )
        elif isinstance(existing, PrincipalNode) and isinstance(incoming, PrincipalNode):
            auth = existing.original_authority or incoming.original_authority
            ident = existing.identity or incoming.identity
            meta = {**existing.metadata, **incoming.metadata}
            return PrincipalNode(
                node_id=existing.node_id,
                node_type=existing.node_type,
                identity=ident,
                original_authority=auth,
                metadata=meta,
            )
        return existing

    def _edges_equal(self, a: GraphEdge, b: GraphEdge) -> bool:
        """Check if two directed edges represent the same relationship."""
        if (
            a.source_id != b.source_id
            or a.target_id != b.target_id
            or a.edge_type != b.edge_type
            or a.trace_id != b.trace_id
        ):
            return False

        if isinstance(a, DelegationEdge) and isinstance(b, DelegationEdge):
            return (
                a.step_index == b.step_index
                and a.credential_type == b.credential_type
                and a.delegated_authority.permissions == b.delegated_authority.permissions
            )

        return True
