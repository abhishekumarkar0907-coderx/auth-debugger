"""
Tests for auth_engine.graph — Graph models, In-memory store, and Graph queries.

Covers synthetic tests for:
- Linear delegation paths
- Branching paths
- Disconnected nodes and isolated subgraphs
- Duplicate IDs and cycle handling
- Cross-trace delegation queries
- Authority amplification detection
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from auth_engine.graph import (
    AmplificationHop,
    AuthorizationGraph,
    CrossTraceHistory,
    DelegationEdge,
    DelegationPath,
    EdgeType,
    ExecutionEdge,
    GraphEdge,
    GraphNode,
    InvocationEdge,
    NodeType,
    OperationNode,
    PrincipalNode,
    ServiceNode,
    build_graph_from_spans,
    find_authority_amplification_hops,
    find_delegation_paths,
    query_cross_trace_history,
)
from auth_engine.policy import default_otel_demo_policy
from auth_engine.models import (
    Authority,
    AuthoritySource,
    CredentialType,
    DelegationStep,
    Identity,
    Operation,
    PrincipalType,
)
from tests.fixtures import (
    golden_confused_deputy,
    legitimate_delegated_authorization,
    legitimate_direct_authorization,
    multi_hop_valid_delegation,
    service_privilege_exceeds_request,
)


# ---------------------------------------------------------------------------
# 1. Graph Models Tests
# ---------------------------------------------------------------------------


class TestGraphModels:
    def test_principal_node_from_identity(self):
        ident = Identity("user-01", PrincipalType.USER)
        auth = Authority.original("orders:read")
        node = PrincipalNode.from_identity(ident, authority=auth)

        assert node.node_id == "user-01"
        assert node.node_type == NodeType.PRINCIPAL
        assert node.identity == ident
        assert node.original_authority == auth
        assert "user-01" in str(node)

    def test_service_node_from_identity(self):
        ident = Identity("payment-svc", PrincipalType.SERVICE, service_name="payment")
        auth = Authority.service("payments:charge")
        node = ServiceNode.from_identity(ident, authority=auth)

        assert node.node_id == "payment-svc"
        assert node.node_type == NodeType.SERVICE
        assert node.service_name == "payment"
        assert node.service_authority == auth

    def test_service_node_from_name(self):
        node = ServiceNode.from_name("checkout", authority=Authority.service("orders:write"))
        assert node.node_id == "checkout"
        assert node.service_name == "checkout"
        assert node.service_authority.contains("orders:write")

    def test_operation_node_from_operation(self):
        op = Operation(
            service="payment",
            raw_span_name="oteldemo.PaymentService/Charge",
            semantic_action="payments:charge",
            required_authority=frozenset({"payments:charge"}),
        )
        node = OperationNode.from_operation(op)

        assert node.node_type == NodeType.OPERATION
        assert node.service_name == "payment"
        assert node.semantic_action == "payments:charge"
        assert node.required_authority == frozenset({"payments:charge"})

    def test_delegation_edge_from_step(self):
        u1 = Identity("u1", PrincipalType.USER)
        s1 = Identity("s1", PrincipalType.SERVICE)
        auth = Authority.delegated("orders:read")
        step = DelegationStep(
            from_principal=u1,
            to_principal=s1,
            delegated_authority=auth,
            credential_type=CredentialType.USER_TOKEN,
        )
        edge = DelegationEdge.from_step(step, trace_id="trace-100", step_index=1)

        assert edge.source_id == "u1"
        assert edge.target_id == "s1"
        assert edge.edge_type == EdgeType.DELEGATION
        assert edge.trace_id == "trace-100"
        assert edge.step_index == 1
        assert edge.delegated_authority == auth
        assert edge.credential_type == CredentialType.USER_TOKEN
        assert "trace-100" in str(edge)


# ---------------------------------------------------------------------------
# 2. Graph Store & Duplicate ID Handling Tests
# ---------------------------------------------------------------------------


class TestGraphStore:
    def test_add_and_get_node(self):
        graph = AuthorizationGraph()
        node = PrincipalNode(node_id="user-1")
        graph.add_node(node)

        assert graph.has_node("user-1")
        assert graph.get_node("user-1") == node
        assert graph.node_count == 1

    def test_duplicate_node_id_safely_handled(self):
        graph = AuthorizationGraph()
        # Add initial node
        n1 = PrincipalNode(
            node_id="user-1",
            original_authority=Authority.original("orders:read"),
        )
        graph.add_node(n1)

        # Add duplicate node with same node_id but different metadata/missing authority
        n2 = PrincipalNode(node_id="user-1", metadata={"tag": "duplicate"})
        result = graph.add_node(n2, overwrite=False)

        # Safe handling: does not throw, does not duplicate count
        assert graph.node_count == 1
        # Preserves original authority
        stored = graph.get_node("user-1")
        assert stored.original_authority == Authority.original("orders:read")
        assert stored.metadata.get("tag") == "duplicate"

    def test_duplicate_node_id_with_overwrite(self):
        graph = AuthorizationGraph()
        n1 = PrincipalNode(node_id="user-1", metadata={"v": 1})
        graph.add_node(n1)

        n2 = PrincipalNode(node_id="user-1", metadata={"v": 2})
        graph.add_node(n2, overwrite=True)

        assert graph.node_count == 1
        assert graph.get_node("user-1").metadata["v"] == 2

    def test_duplicate_edge_safely_handled(self):
        graph = AuthorizationGraph()
        e1 = DelegationEdge(
            source_id="u1",
            target_id="s1",
            trace_id="t1",
            step_index=0,
            delegated_authority=Authority.delegated("read"),
        )
        e2 = DelegationEdge(
            source_id="u1",
            target_id="s1",
            trace_id="t1",
            step_index=0,
            delegated_authority=Authority.delegated("read"),
        )

        graph.add_edge(e1)
        graph.add_edge(e2)

        # Edge count should remain 1
        assert graph.edge_count == 1
        assert len(graph.get_outgoing_edges("u1")) == 1
        assert len(graph.get_incoming_edges("s1")) == 1

    def test_nonexistent_node_queries_safe(self):
        graph = AuthorizationGraph()
        assert graph.get_node("non-existent") is None
        assert graph.has_node("non-existent") is False
        assert graph.get_outgoing_edges("non-existent") == []
        assert graph.get_incoming_edges("non-existent") == []
        assert graph.get_successors("non-existent") == []
        assert graph.get_predecessors("non-existent") == []
        assert graph.get_neighbors("non-existent") == []

    def test_explicit_and_implicit_delegation_edges_are_not_duplicates(self):
        graph = AuthorizationGraph()
        common = dict(
            source_id="u-conflict",
            target_id="s-conflict",
            trace_id="t-conflict",
            delegated_authority=Authority.delegated("read"),
        )
        graph.add_edge(DelegationEdge(**common, explicit=True))
        graph.add_edge(DelegationEdge(**common, explicit=False))

        assert graph.edge_count == 2

    def test_neighbor_directions(self):
        graph = AuthorizationGraph()
        graph.add_edge(GraphEdge(source_id="A", target_id="B"))
        graph.add_edge(GraphEdge(source_id="C", target_id="A"))

        assert [n.node_id for n in graph.get_neighbors("A", direction="outgoing")] == ["B"]
        assert [n.node_id for n in graph.get_neighbors("A", direction="incoming")] == ["C"]
        assert [n.node_id for n in graph.get_neighbors("A", direction="both")] == ["B", "C"]

    def test_clear_graph(self):
        graph = AuthorizationGraph()
        graph.add_edge(GraphEdge(source_id="A", target_id="B"))
        assert graph.node_count == 2
        assert graph.edge_count == 1

        graph.clear()
        assert graph.node_count == 0
        assert graph.edge_count == 0


# ---------------------------------------------------------------------------
# 3. Synthetic Linear Path Tests
# ---------------------------------------------------------------------------


class TestLinearPaths:
    @pytest.fixture
    def linear_graph(self) -> AuthorizationGraph:
        graph = AuthorizationGraph()
        # user -> agent -> checkout -> payment -> operation:payments:charge
        user = PrincipalNode(
            node_id="user-001",
            original_authority=Authority.original("orders:read"),
        )
        agent = PrincipalNode(node_id="agent-001")
        checkout = ServiceNode(node_id="checkout-svc", service_name="checkout")
        payment = ServiceNode(
            node_id="payment-svc",
            service_name="payment",
            service_authority=Authority.service("payments:charge"),
        )
        op = OperationNode(
            node_id="op:payment:payments:charge",
            service_name="payment",
            semantic_action="payments:charge",
            required_authority=frozenset({"payments:charge"}),
        )

        graph.add_node(user)
        graph.add_node(agent)
        graph.add_node(checkout)
        graph.add_node(payment)
        graph.add_node(op)

        graph.add_edge(
            DelegationEdge(
                source_id="user-001",
                target_id="agent-001",
                trace_id="trace-linear",
                delegated_authority=Authority.delegated("orders:read"),
                credential_type=CredentialType.USER_TOKEN,
                step_index=0,
            )
        )
        graph.add_edge(
            DelegationEdge(
                source_id="agent-001",
                target_id="checkout-svc",
                trace_id="trace-linear",
                delegated_authority=Authority.delegated("orders:read"),
                credential_type=CredentialType.DELEGATED_TOKEN,
                step_index=1,
            )
        )
        graph.add_edge(
            DelegationEdge(
                source_id="checkout-svc",
                target_id="payment-svc",
                trace_id="trace-linear",
                delegated_authority=Authority.delegated("orders:read"),
                credential_type=CredentialType.SERVICE_CREDENTIAL,
                step_index=2,
            )
        )
        graph.add_edge(
            ExecutionEdge(
                source_id="payment-svc",
                target_id="op:payment:payments:charge",
                trace_id="trace-linear",
            )
        )

        return graph

    def test_find_linear_path(self, linear_graph: AuthorizationGraph):
        paths = find_delegation_paths(
            graph=linear_graph,
            initiating_principal_id="user-001",
            target_action="payments:charge",
            trace_id="trace-linear",
        )

        assert len(paths) == 1
        path = paths[0]
        assert path.initiating_principal_id == "user-001"
        assert path.target_action == "payments:charge"
        assert path.hop_count == 4
        assert path.path_nodes == [
            "user-001",
            "agent-001",
            "checkout-svc",
            "payment-svc",
            "op:payment:payments:charge",
        ]
        assert "user-001 -> agent-001" in path.summary


# ---------------------------------------------------------------------------
# 4. Synthetic Branching Path Tests
# ---------------------------------------------------------------------------


class TestBranchingPaths:
    @pytest.fixture
    def branching_graph(self) -> AuthorizationGraph:
        """
        User delegates to Orchestrator.
        Orchestrator branches to:
          Branch 1: Payment Service -> payments:refund
          Branch 2: Shipping Service -> shipping:ship
          Branch 3: Alt Payment Service -> payments:refund (alternate route)
        """
        graph = AuthorizationGraph()
        graph.add_node(PrincipalNode(node_id="user-branch"))
        graph.add_node(PrincipalNode(node_id="orchestrator"))
        graph.add_node(ServiceNode(node_id="svc-payment", service_name="payment"))
        graph.add_node(ServiceNode(node_id="svc-alt-payment", service_name="alt-payment"))
        graph.add_node(ServiceNode(node_id="svc-shipping", service_name="shipping"))

        op_refund = OperationNode(
            node_id="op:refund",
            service_name="payment",
            semantic_action="payments:refund",
            required_authority=frozenset({"payments:refund"}),
        )
        op_ship = OperationNode(
            node_id="op:ship",
            service_name="shipping",
            semantic_action="shipping:ship",
            required_authority=frozenset({"shipping:ship"}),
        )
        graph.add_node(op_refund)
        graph.add_node(op_ship)

        # Hop 0: User -> Orchestrator
        graph.add_edge(
            DelegationEdge(
                source_id="user-branch",
                target_id="orchestrator",
                trace_id="trace-branch",
                step_index=0,
            )
        )
        # Branch 1: Orchestrator -> Payment -> Refund
        graph.add_edge(
            DelegationEdge(
                source_id="orchestrator",
                target_id="svc-payment",
                trace_id="trace-branch",
                step_index=1,
            )
        )
        graph.add_edge(
            ExecutionEdge(
                source_id="svc-payment",
                target_id="op:refund",
                trace_id="trace-branch",
            )
        )

        # Branch 2: Orchestrator -> Shipping -> Ship
        graph.add_edge(
            DelegationEdge(
                source_id="orchestrator",
                target_id="svc-shipping",
                trace_id="trace-branch",
                step_index=1,
            )
        )
        graph.add_edge(
            ExecutionEdge(
                source_id="svc-shipping",
                target_id="op:ship",
                trace_id="trace-branch",
            )
        )

        # Branch 3: Orchestrator -> Alt-Payment -> Refund
        graph.add_edge(
            DelegationEdge(
                source_id="orchestrator",
                target_id="svc-alt-payment",
                trace_id="trace-branch",
                step_index=1,
            )
        )
        graph.add_edge(
            ExecutionEdge(
                source_id="svc-alt-payment",
                target_id="op:refund",
                trace_id="trace-branch",
            )
        )

        return graph

    def test_branch_selection_by_action(self, branching_graph: AuthorizationGraph):
        # Shipping query should only return the shipping branch
        shipping_paths = find_delegation_paths(
            graph=branching_graph,
            initiating_principal_id="user-branch",
            target_action="shipping:ship",
        )
        assert len(shipping_paths) == 1
        assert shipping_paths[0].path_nodes == [
            "user-branch",
            "orchestrator",
            "svc-shipping",
            "op:ship",
        ]

    def test_multi_path_to_same_action(self, branching_graph: AuthorizationGraph):
        # Refund query should return both payment branch and alt-payment branch
        refund_paths = find_delegation_paths(
            graph=branching_graph,
            initiating_principal_id="user-branch",
            target_action="payments:refund",
        )
        assert len(refund_paths) == 2
        path_targets = [p.path_nodes[2] for p in refund_paths]
        assert "svc-payment" in path_targets
        assert "svc-alt-payment" in path_targets


# ---------------------------------------------------------------------------
# 5. Synthetic Disconnected Nodes Tests
# ---------------------------------------------------------------------------


class TestDisconnectedNodes:
    def test_isolated_nodes_query_empty(self):
        graph = AuthorizationGraph()
        graph.add_node(PrincipalNode(node_id="isolated-user"))
        graph.add_node(OperationNode(node_id="op:isolated", semantic_action="isolated:act"))

        paths = find_delegation_paths(
            graph=graph,
            initiating_principal_id="isolated-user",
            target_action="isolated:act",
        )
        assert paths == []

    def test_disconnected_subgraphs(self):
        graph = AuthorizationGraph()
        # Subgraph 1: UserA -> ServiceA -> OpA
        graph.add_edge(GraphEdge(source_id="UserA", target_id="ServiceA"))
        graph.add_node(OperationNode(node_id="OpA", semantic_action="act:a"))
        graph.add_edge(ExecutionEdge(source_id="ServiceA", target_id="OpA"))

        # Subgraph 2: UserB -> ServiceB -> OpB
        graph.add_edge(GraphEdge(source_id="UserB", target_id="ServiceB"))
        graph.add_node(OperationNode(node_id="OpB", semantic_action="act:b"))
        graph.add_edge(ExecutionEdge(source_id="ServiceB", target_id="OpB"))

        # Query UserA to reach act:b (only in subgraph 2)
        paths = find_delegation_paths(
            graph=graph,
            initiating_principal_id="UserA",
            target_action="act:b",
        )
        assert paths == []

        # Amplification hops on disconnected graph should be empty
        hops = find_authority_amplification_hops(graph, required_permission="act:b")
        assert hops == []


# ---------------------------------------------------------------------------
# 6. Duplicate IDs and Cycle Handling Tests
# ---------------------------------------------------------------------------


class TestDuplicateIdsAndCycles:
    def test_cyclic_graph_terminates(self):
        """Ensure cyclic delegations (e.g. A -> B -> C -> B) do not cause infinite loops."""
        graph = AuthorizationGraph()
        graph.add_node(PrincipalNode(node_id="user-c"))
        graph.add_node(ServiceNode(node_id="svc-b", service_name="b"))
        graph.add_node(ServiceNode(node_id="svc-c", service_name="c"))
        op = OperationNode(node_id="op:act", semantic_action="act:c")
        graph.add_node(op)

        # user-c -> svc-b -> svc-c -> svc-b (cycle)
        graph.add_edge(DelegationEdge(source_id="user-c", target_id="svc-b"))
        graph.add_edge(DelegationEdge(source_id="svc-b", target_id="svc-c"))
        graph.add_edge(DelegationEdge(source_id="svc-c", target_id="svc-b"))  # loop edge
        graph.add_edge(ExecutionEdge(source_id="svc-c", target_id="op:act"))

        paths = find_delegation_paths(
            graph=graph,
            initiating_principal_id="user-c",
            target_action="act:c",
        )
        # Should terminate safely and find the acyclic path
        assert len(paths) == 1
        assert paths[0].path_nodes == ["user-c", "svc-b", "svc-c", "op:act"]


# ---------------------------------------------------------------------------
# 7. Cross-Trace Query Tests
# ---------------------------------------------------------------------------


class TestCrossTraceQueries:
    @pytest.fixture
    def multi_trace_graph(self) -> AuthorizationGraph:
        """
        Sets up 3 distinct traces:
        Trace 1: user-alex -> agent-bot -> service-orders
        Trace 2: user-alex -> agent-bot -> service-payment
        Trace 3: user-charlie -> service-payment
        """
        graph = AuthorizationGraph()

        # Trace 1
        graph.add_edge(
            DelegationEdge(
                source_id="user-alex",
                target_id="agent-bot",
                trace_id="trace-001",
                delegated_authority=Authority.delegated("orders:read"),
                step_index=0,
            )
        )
        graph.add_edge(
            DelegationEdge(
                source_id="agent-bot",
                target_id="service-orders",
                trace_id="trace-001",
                delegated_authority=Authority.delegated("orders:read"),
                step_index=1,
            )
        )

        # Trace 2
        graph.add_edge(
            DelegationEdge(
                source_id="user-alex",
                target_id="agent-bot",
                trace_id="trace-002",
                delegated_authority=Authority.delegated("payments:view"),
                step_index=0,
            )
        )
        graph.add_edge(
            DelegationEdge(
                source_id="agent-bot",
                target_id="service-payment",
                trace_id="trace-002",
                delegated_authority=Authority.delegated("payments:view"),
                step_index=1,
            )
        )

        # Trace 3
        graph.add_edge(
            DelegationEdge(
                source_id="user-charlie",
                target_id="service-payment",
                trace_id="trace-003",
                delegated_authority=Authority.delegated("payments:admin"),
                step_index=0,
            )
        )

        return graph

    def test_query_cross_trace_history_for_alex(
        self, multi_trace_graph: AuthorizationGraph
    ):
        history: CrossTraceHistory = query_cross_trace_history(
            graph=multi_trace_graph,
            principal_id="user-alex",
        )

        assert history.principal_id == "user-alex"
        assert history.trace_ids == ["trace-001", "trace-002"]
        assert history.trace_count == 2
        assert history.total_delegations == 2
        assert len(history.delegations_as_source) == 2
        assert len(history.delegations_as_target) == 0

        # Check authorities delegated across traces
        auths = history.authorities_delegated()
        all_perms = {p for a in auths for p in a.permissions}
        assert all_perms == {"orders:read", "payments:view"}

    def test_query_cross_trace_history_for_agent(
        self, multi_trace_graph: AuthorizationGraph
    ):
        history = query_cross_trace_history(
            graph=multi_trace_graph,
            principal_id="agent-bot",
        )

        assert history.trace_ids == ["trace-001", "trace-002"]
        # Received from user-alex in both traces
        assert len(history.delegations_as_target) == 2
        # Delegated to orders in T1, payment in T2
        assert len(history.delegations_as_source) == 2
        assert history.total_delegations == 4

        # Trace-specific lookups
        t1_delegations = history.delegations_in_trace("trace-001")
        assert len(t1_delegations) == 2

    def test_query_cross_trace_history_nonexistent(
        self, multi_trace_graph: AuthorizationGraph
    ):
        history = query_cross_trace_history(
            graph=multi_trace_graph,
            principal_id="ghost-principal",
        )
        assert history.trace_count == 0
        assert history.total_delegations == 0


# ---------------------------------------------------------------------------
# 8. Authority Amplification Detection Tests
# ---------------------------------------------------------------------------


class TestAuthorityAmplification:
    def test_golden_confused_deputy_amplification_detected(self):
        """
        Load canonical golden_confused_deputy scenario into the graph.
        Verify that find_authority_amplification_hops detects the exact
        checkout -> payment hop where service credentials amplified authority.
        """
        graph = AuthorizationGraph()
        scenario = golden_confused_deputy()
        graph.load_scenario(scenario)

        hops: list[AmplificationHop] = find_authority_amplification_hops(
            graph=graph,
            trace_id="trace-golden-001",
        )

        assert len(hops) == 1
        hop = hops[0]
        assert hop.trace_id == "trace-golden-001"
        assert hop.from_principal_id == "checkout-svc"
        assert hop.to_service_id == "payment-svc"
        assert hop.credential_type == CredentialType.SERVICE_CREDENTIAL
        assert hop.amplified_permissions == frozenset({"payments:charge"})
        assert "amplified authority" in hop.reason
        assert "payments:charge" in hop.reason

    def test_legitimate_direct_authorization_no_amplification(self):
        """User possessed and delegated required payments:charge authority."""
        graph = AuthorizationGraph()
        scenario = legitimate_direct_authorization()
        graph.load_scenario(scenario)

        hops = find_authority_amplification_hops(
            graph=graph,
            trace_id="trace-legit-001",
        )
        assert len(hops) == 0

    def test_legitimate_delegated_authorization_no_amplification(self):
        """Authority was legitimately delegated at checkout -> payment hop."""
        graph = AuthorizationGraph()
        scenario = legitimate_delegated_authorization()
        graph.load_scenario(scenario)

        hops = find_authority_amplification_hops(
            graph=graph,
            trace_id="trace-delegated-001",
        )
        assert len(hops) == 0

    def test_multi_hop_valid_delegation_no_amplification(self):
        """Multi-hop propagation preserving payments:charge authority."""
        graph = AuthorizationGraph()
        scenario = multi_hop_valid_delegation()
        graph.load_scenario(scenario)

        hops = find_authority_amplification_hops(
            graph=graph,
            trace_id="trace-multihop-001",
        )
        assert len(hops) == 0

    def test_service_privilege_exceeds_request_amplification(self):
        """Direct hop from user-123 to payment-svc via service credential."""
        graph = AuthorizationGraph()
        scenario = service_privilege_exceeds_request()
        graph.load_scenario(scenario)

        hops = find_authority_amplification_hops(
            graph=graph,
            trace_id="trace-svcpriv-001",
        )

        assert len(hops) == 1
        assert hops[0].from_principal_id == "user-123"
        assert hops[0].to_service_id == "payment-svc"
        assert hops[0].amplified_permissions == frozenset({"payments:charge"})


# ---------------------------------------------------------------------------
# 9. Graph Adapter Tests
# ---------------------------------------------------------------------------


@dataclass
class SpanStub:
    """Minimal object satisfying SpanLike for adapter testing."""

    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    service_name: str | None = None
    span_name: str = "test-span"
    status_code: int = 1
    attributes: dict[str, Any] = field(default_factory=dict)


class TestGraphAdapter:
    def test_build_graph_from_empty_spans(self):
        graph = build_graph_from_spans([])
        assert isinstance(graph, AuthorizationGraph)
        assert graph.node_count == 0
        assert graph.edge_count == 0

    def test_build_graph_from_representative_spans(self):
        root = SpanStub(
            trace_id="trace-rep-001",
            span_id="span-root",
            service_name="checkout",
            span_name="POST /order",
            attributes={
                "authz.principal.id": "user-123",
                "authz.principal.type": "user",
                "authz.principal.scopes": "orders:read",
                "authz.delegation.from": "user-123",
                "authz.delegation.to": "checkout-svc",
                "authz.credential.type": "user_token",
            },
        )
        leaf = SpanStub(
            trace_id="trace-rep-001",
            span_id="span-leaf",
            parent_span_id="span-root",
            service_name="payment",
            span_name="oteldemo.PaymentService/Charge",
            attributes={
                "authz.principal.id": "user-123",
                "authz.principal.scopes": "orders:read",
                "authz.delegation.from": "checkout-svc",
                "authz.delegation.to": "payment-svc",
                "authz.credential.type": "service_credential",
            },
        )

        graph = build_graph_from_spans(
            [root, leaf],
            policy=default_otel_demo_policy(),
            service_authority_config={"payment": ["payments:charge"]},
        )

        assert isinstance(graph, AuthorizationGraph)
        assert graph.has_node("user-123")
        assert graph.has_node("checkout-svc")
        assert graph.has_node("payment-svc")
        assert graph.trace_ids() == ["trace-rep-001"]

        # Verify delegation path queries operate on the constructed graph
        paths = find_delegation_paths(graph, "user-123", "payments:charge")
        assert len(paths) == 1
        assert paths[0].path_nodes[0] == "user-123"
        assert "checkout-svc" in paths[0].path_nodes
        assert "payment-svc" in paths[0].path_nodes

        # Verify amplification hop detection
        hops = find_authority_amplification_hops(graph, trace_id="trace-rep-001")
        assert len(hops) == 1
        assert hops[0].from_principal_id == "checkout-svc"
        assert hops[0].to_service_id == "payment-svc"

    def test_build_graph_populates_existing_graph(self):
        existing = AuthorizationGraph()
        root = SpanStub(
            trace_id="trace-rep-002",
            span_id="span-root-2",
            service_name="checkout",
            span_name="POST /order",
            attributes={
                "authz.principal.id": "user-456",
                "authz.principal.scopes": "orders:read",
            },
        )
        leaf = SpanStub(
            trace_id="trace-rep-002",
            span_id="span-leaf-2",
            parent_span_id="span-root-2",
            service_name="payment",
            span_name="oteldemo.PaymentService/Charge",
            attributes={
                "authz.principal.id": "user-456",
                "authz.principal.scopes": "orders:read",
            },
        )

        result = build_graph_from_spans([root, leaf], graph=existing)
        assert result is existing
        assert existing.has_node("user-456")

    def test_build_graph_insufficient_evidence_non_strict(self):
        plain = SpanStub(
            trace_id="plain-trace",
            span_id="s1",
            service_name="svc",
            span_name="GET /items",
            attributes={"http.status_code": 200},
        )
        graph = build_graph_from_spans([plain], strict=False)
        assert graph.node_count == 0

    def test_build_graph_insufficient_evidence_strict_raises(self):
        plain = SpanStub(
            trace_id="plain-trace",
            span_id="s1",
            service_name="svc",
            span_name="GET /items",
            attributes={"http.status_code": 200},
        )
        with pytest.raises(ValueError, match="Cannot build AuthorizationScenario"):
            build_graph_from_spans([plain], strict=True)

    def test_build_graph_multi_trace(self):
        span_a = SpanStub(
            trace_id="trace-A",
            span_id="sa-1",
            service_name="svc-a",
            span_name="oteldemo.OrderService/GetOrder",
            attributes={
                "authz.principal.id": "user-A",
                "authz.principal.scopes": "orders:read",
            },
        )
        span_b = SpanStub(
            trace_id="trace-B",
            span_id="sb-1",
            service_name="svc-b",
            span_name="oteldemo.OrderService/GetOrder",
            attributes={
                "authz.principal.id": "user-B",
                "authz.principal.scopes": "orders:read",
            },
        )

        graph = build_graph_from_spans([span_a, span_b])
        assert graph.has_node("user-A")
        assert graph.has_node("user-B")
        assert set(graph.trace_ids()) == {"trace-A", "trace-B"}

def test_graph_json_save_load_round_trip(tmp_path):
    graph = AuthorizationGraph()
    identity = Identity("json-user", PrincipalType.USER)
    node = PrincipalNode.from_identity(
        identity, authority=Authority.original("orders:read")
    )
    graph.add_node(node)

    snapshot = tmp_path / "graph.json"
    graph.save_json(snapshot)
    loaded = AuthorizationGraph.load_json(snapshot)

    assert loaded.node_count == graph.node_count
    assert loaded.get_node("json-user") == node


def test_graph_json_rejects_unsupported_schema(tmp_path):
    import json

    snapshot = tmp_path / "invalid.json"
    snapshot.write_text(
        json.dumps({"schema_version": 999, "nodes": [], "edges": []}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="schema_version"):
        AuthorizationGraph.load_json(snapshot)

def test_delegation_paths_are_deterministic_when_edge_order_changes():
    graph = AuthorizationGraph()
    graph.add_node(PrincipalNode(node_id="order-user"))
    graph.add_node(ServiceNode(node_id="order-service", service_name="orders"))
    graph.add_node(OperationNode(node_id="op:order-test", semantic_action="orders:read"))
    graph.add_edge(DelegationEdge(
        source_id="order-user", target_id="order-service",
        trace_id="trace-order", step_index=0,
    ))
    graph.add_edge(ExecutionEdge(
        source_id="order-service", target_id="op:order-test",
        trace_id="trace-order",
    ))

    reordered = AuthorizationGraph()
    for node in reversed(graph.nodes()):
        reordered.add_node(node)
    for edge in reversed(graph.edges()):
        reordered.add_edge(edge)

    kwargs = {
        "initiating_principal_id": "order-user",
        "target_action": "orders:read",
        "trace_id": "trace-order",
    }
    first = find_delegation_paths(graph=graph, **kwargs)
    second = find_delegation_paths(graph=reordered, **kwargs)
    assert [(p.path_nodes, p.hop_count) for p in first] == [
        (p.path_nodes, p.hop_count) for p in second
    ]
