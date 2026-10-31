"""
Tests for auth_engine.context — authorization-context extraction.

Covers:
    1.  Complete authorization context.
    2.  Missing principal identity.
    3.  Missing requested action.
    4.  Missing original authority.
    5.  Partial delegation information.
    6.  Legitimate credential transitions across different hops.
    7.  Conflicting principal identities.
    8.  Conflicting values for the same logical field and hop.
    9.  Ordinary OTel traces without authorization attributes.
    10. Evidence provenance.
    11. Explicit service-authority configuration.
    12. Empty span input.
    13. enduser.id candidate handling.
    14. Context-to-scenario conversion and detector integration.
    15. Preservation of existing detector behavior.
    16. Malformed scope values.
    17. Incomplete evidence cannot produce a false positive.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from auth_engine.context import (
    ATTR_CREDENTIAL_TYPE,
    ATTR_DELEGATION_FROM,
    ATTR_DELEGATION_SCOPES,
    ATTR_DELEGATION_TO,
    ATTR_ENDUSER_ID,
    ATTR_PRINCIPAL_ID,
    ATTR_PRINCIPAL_SCOPES,
    ATTR_PRINCIPAL_TYPE,
    ATTR_TARGET_RESOURCE,
    AuthorizationContext,
    EvidenceItem,
    ExtractionWarning,
    RawDelegationHop,
    extract_authorization_context,
    _parse_scopes,
)
from auth_engine.detector import ConfusedDeputyDetector
from auth_engine.delegation_policy import DelegationPolicy
from auth_engine.models import (
    Authority,
    AuthorizationScenario,
    CredentialType,
    DelegationStep,
    FindingType,
    Identity,
    Operation,
    PrincipalType,
    Verdict,
)
from auth_engine.policy import ActionPolicy, default_otel_demo_policy


# ---------------------------------------------------------------------------
# Test span — satisfies the SpanLike protocol
# ---------------------------------------------------------------------------


@dataclass
class FakeSpan:
    """Minimal object satisfying the SpanLike protocol for testing."""

    trace_id: str = "trace-001"
    span_id: str = "span-001"
    parent_span_id: str | None = None
    service_name: str | None = "test-service"
    span_name: str = "GET /test"
    status_code: int = 0
    attributes: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helper: build a complete auth-annotated span set
# ---------------------------------------------------------------------------


def _complete_span_set() -> list[FakeSpan]:
    """A trace with all authorization attributes populated."""
    root = FakeSpan(
        trace_id="trace-complete",
        span_id="span-root",
        parent_span_id=None,
        service_name="frontend",
        span_name="POST /checkout",
        status_code=1,
        attributes={
            ATTR_PRINCIPAL_ID: "user-123",
            ATTR_PRINCIPAL_TYPE: "user",
            ATTR_PRINCIPAL_SCOPES: "orders:read",
            ATTR_DELEGATION_FROM: "user-123",
            ATTR_DELEGATION_TO: "checkout-svc",
            ATTR_CREDENTIAL_TYPE: "user_token",
            ATTR_DELEGATION_SCOPES: "orders:read",
        },
    )
    leaf = FakeSpan(
        trace_id="trace-complete",
        span_id="span-leaf",
        parent_span_id="span-root",
        service_name="payment",
        span_name="oteldemo.PaymentService/Charge",
        status_code=1,
        attributes={
            ATTR_PRINCIPAL_ID: "user-123",
            ATTR_PRINCIPAL_TYPE: "user",
            ATTR_PRINCIPAL_SCOPES: "orders:read",
            ATTR_DELEGATION_FROM: "checkout-svc",
            ATTR_DELEGATION_TO: "payment-svc",
            ATTR_CREDENTIAL_TYPE: "service_credential",
            ATTR_DELEGATION_SCOPES: "orders:read",
        },
    )
    return [root, leaf]


# ===================================================================
# 1. COMPLETE AUTHORIZATION CONTEXT
# ===================================================================


class TestCompleteContext:
    """Test with all authorization attributes present."""

    def test_principal_extracted(self):
        ctx = extract_authorization_context(_complete_span_set())
        assert ctx.initiating_principal_id == "user-123"

    def test_principal_type_extracted(self):
        ctx = extract_authorization_context(_complete_span_set())
        assert ctx.initiating_principal_type == "user"

    def test_scopes_extracted(self):
        ctx = extract_authorization_context(_complete_span_set())
        assert ctx.original_scopes == ["orders:read"]

    def test_effective_action_extracted(self):
        ctx = extract_authorization_context(_complete_span_set())
        assert ctx.effective_span_name == "oteldemo.PaymentService/Charge"

    def test_service_name_extracted(self):
        ctx = extract_authorization_context(_complete_span_set())
        assert ctx.acting_service_name == "payment"

    def test_delegation_hops_extracted(self):
        ctx = extract_authorization_context(_complete_span_set())
        assert len(ctx.delegation_hops) == 2

    def test_has_sufficient_evidence(self):
        ctx = extract_authorization_context(_complete_span_set())
        assert ctx.has_sufficient_evidence() is True

    def test_no_conflicting_warnings(self):
        ctx = extract_authorization_context(_complete_span_set())
        conflicts = [w for w in ctx.warnings if w.warning_type == "conflicting"]
        assert len(conflicts) == 0

    def test_evidence_items_recorded(self):
        ctx = extract_authorization_context(_complete_span_set())
        assert len(ctx.evidence) > 0

    def test_trace_id_preserved(self):
        ctx = extract_authorization_context(_complete_span_set())
        assert ctx.trace_id == "trace-complete"

    def test_span_ids_collected(self):
        ctx = extract_authorization_context(_complete_span_set())
        assert "span-root" in ctx.span_ids
        assert "span-leaf" in ctx.span_ids

    @pytest.mark.parametrize(
        ("status_code", "expected_outcome"),
        [(0, None), (1, True), (2, False), (3, None)],
    )
    def test_status_code_maps_to_outcome_and_preserves_evidence(
        self, status_code, expected_outcome
    ):
        spans = _complete_span_set()
        spans[-1].status_code = status_code

        ctx = extract_authorization_context(spans)

        assert ctx.outcome_success is expected_outcome
        outcome_evidence = [item for item in ctx.evidence if item.field == "outcome"]
        assert len(outcome_evidence) == 1
        assert outcome_evidence[0].value == status_code
        assert outcome_evidence[0].source == "span_field:status_code"
        assert outcome_evidence[0].span_id == "span-leaf"


# ===================================================================
# 2. MISSING PRINCIPAL IDENTITY
# ===================================================================


class TestMissingPrincipal:
    """No authz.principal.id or enduser.id on any span."""

    def test_principal_is_none(self):
        spans = [FakeSpan(span_name="GET /api/test")]
        ctx = extract_authorization_context(spans)
        assert ctx.initiating_principal_id is None

    def test_has_missing_warning(self):
        spans = [FakeSpan(span_name="GET /api/test")]
        ctx = extract_authorization_context(spans)
        missing = [
            w for w in ctx.warnings
            if w.field == "initiating_principal.id"
            and w.warning_type == "missing"
        ]
        assert len(missing) == 1

    def test_insufficient_evidence(self):
        spans = [FakeSpan(span_name="GET /api/test")]
        ctx = extract_authorization_context(spans)
        assert ctx.has_sufficient_evidence() is False


# ===================================================================
# 3. MISSING REQUESTED ACTION
# ===================================================================


class TestMissingAction:
    """Principal and scopes present, but span has no resolvable action."""

    def test_action_still_captured_from_span_name(self):
        spans = [
            FakeSpan(
                span_name="GET /api/test",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                },
            )
        ]
        ctx = extract_authorization_context(spans)
        # The span name IS captured, but may not resolve via policy
        assert ctx.effective_span_name == "GET /api/test"

    def test_scenario_has_no_semantic_action(self):
        spans = [
            FakeSpan(
                span_name="GET /api/test",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                },
            )
        ]
        ctx = extract_authorization_context(spans)
        policy = default_otel_demo_policy()
        scenario = ctx.to_scenario(policy=policy)
        # Unknown span name → no semantic action resolved
        assert scenario.effective_operation is not None
        assert scenario.effective_operation.semantic_action is None

    def test_detector_returns_insufficient_for_unknown_action(self):
        """Unknown span → no required_authority → INSUFFICIENT_EVIDENCE."""
        spans = [
            FakeSpan(
                span_name="GET /api/test",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                },
            )
        ]
        ctx = extract_authorization_context(spans)
        policy = default_otel_demo_policy()
        scenario = ctx.to_scenario(policy=policy)
        detector = ConfusedDeputyDetector(policy=policy)
        result = detector.analyze(scenario)
        assert result.verdict == Verdict.INSUFFICIENT_EVIDENCE


# ===================================================================
# 4. MISSING ORIGINAL AUTHORITY
# ===================================================================


class TestMissingAuthority:
    """Principal present but no scopes attribute."""

    def test_scopes_none(self):
        spans = [
            FakeSpan(
                span_name="oteldemo.PaymentService/Charge",
                attributes={ATTR_PRINCIPAL_ID: "user-123"},
            )
        ]
        ctx = extract_authorization_context(spans)
        assert ctx.original_scopes is None

    def test_missing_warning(self):
        spans = [
            FakeSpan(
                span_name="oteldemo.PaymentService/Charge",
                attributes={ATTR_PRINCIPAL_ID: "user-123"},
            )
        ]
        ctx = extract_authorization_context(spans)
        missing = [
            w for w in ctx.warnings
            if w.field == "original_authority"
            and w.warning_type == "missing"
        ]
        assert len(missing) == 1

    def test_insufficient_evidence(self):
        spans = [
            FakeSpan(
                span_name="oteldemo.PaymentService/Charge",
                attributes={ATTR_PRINCIPAL_ID: "user-123"},
            )
        ]
        ctx = extract_authorization_context(spans)
        assert ctx.has_sufficient_evidence() is False

    def test_to_scenario_raises(self):
        spans = [
            FakeSpan(
                span_name="oteldemo.PaymentService/Charge",
                attributes={ATTR_PRINCIPAL_ID: "user-123"},
            )
        ]
        ctx = extract_authorization_context(spans)
        with pytest.raises(ValueError, match="original authority"):
            ctx.to_scenario()


# ===================================================================
# 5. PARTIAL DELEGATION INFORMATION
# ===================================================================


class TestPartialDelegation:
    """Delegation with from but missing to."""

    def test_partial_hop_preserved(self):
        spans = [
            FakeSpan(
                span_name="oteldemo.PaymentService/Charge",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                    ATTR_DELEGATION_FROM: "user-123",
                    # No ATTR_DELEGATION_TO
                },
            )
        ]
        ctx = extract_authorization_context(spans)
        assert len(ctx.delegation_hops) == 1
        assert ctx.delegation_hops[0].from_id == "user-123"
        assert ctx.delegation_hops[0].to_id is None

    def test_missing_to_warning(self):
        spans = [
            FakeSpan(
                span_name="oteldemo.PaymentService/Charge",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                    ATTR_DELEGATION_FROM: "user-123",
                },
            )
        ]
        ctx = extract_authorization_context(spans)
        missing_to = [
            w for w in ctx.warnings
            if w.field == "delegation.to"
            and w.warning_type == "missing"
        ]
        assert len(missing_to) == 1

    def test_incomplete_hop_skipped_in_scenario(self):
        """Incomplete hops should be skipped in to_scenario()."""
        spans = [
            FakeSpan(
                span_name="oteldemo.PaymentService/Charge",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                    ATTR_DELEGATION_FROM: "user-123",
                },
            )
        ]
        ctx = extract_authorization_context(spans)
        scenario = ctx.to_scenario()
        assert len(scenario.delegation_chain) == 0

    def test_incomplete_hop_cannot_be_misread_as_direct_authorization(self):
        spans = [
            FakeSpan(
                span_name="oteldemo.PaymentService/Charge",
                service_name="payment",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "payments:charge",
                    ATTR_DELEGATION_FROM: "user-123",
                    ATTR_DELEGATION_SCOPES: "payments:charge",
                },
            )
        ]
        context = extract_authorization_context(spans)
        scenario = context.to_scenario(policy=default_otel_demo_policy())

        assert scenario.delegation_chain == []
        result = ConfusedDeputyDetector().analyze(scenario)

        assert result.verdict == Verdict.INSUFFICIENT_EVIDENCE
        assert result.finding.finding_type == FindingType.NONE
        assert "Delegation relationship evidence is incomplete" in result.reason


class TestDelegatedScopes:
    def test_explicit_delegated_scopes_are_preserved(self):
        spans = [
            FakeSpan(
                span_name="oteldemo.PaymentService/Charge",
                service_name="payment",
                status_code=1,
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                    ATTR_DELEGATION_FROM: "user-123",
                    ATTR_DELEGATION_TO: "payment",
                    ATTR_DELEGATION_SCOPES: ["payments:charge"],
                },
            )
        ]

        context = extract_authorization_context(spans)
        scenario = context.to_scenario(policy=default_otel_demo_policy())

        assert scenario.delegation_chain[0].delegated_authority.permissions == {
            "payments:charge"
        }

    def test_malformed_delegated_scopes_are_warned(self):
        spans = [
            FakeSpan(
                span_name="oteldemo.PaymentService/Charge",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                    ATTR_DELEGATION_FROM: "user-123",
                    ATTR_DELEGATION_TO: "payment",
                    ATTR_DELEGATION_SCOPES: ["payments:charge", 42],
                },
            )
        ]

        context = extract_authorization_context(spans)

        assert any(
            warning.field == "delegation.authority"
            and warning.warning_type == "malformed"
            for warning in context.warnings
        )


# ===================================================================
# 6. LEGITIMATE CREDENTIAL TRANSITIONS ACROSS HOPS
# ===================================================================


class TestCredentialTransitions:
    """Different credential types on different hops are NOT a conflict."""

    def test_different_credential_types_no_conflict(self):
        spans = [
            FakeSpan(
                span_id="span-1",
                span_name="POST /checkout",
                parent_span_id=None,
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                    ATTR_DELEGATION_FROM: "user-123",
                    ATTR_DELEGATION_TO: "checkout-svc",
                    ATTR_CREDENTIAL_TYPE: "user_token",
                },
            ),
            FakeSpan(
                span_id="span-2",
                span_name="oteldemo.PaymentService/Charge",
                parent_span_id="span-1",
                service_name="payment",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                    ATTR_DELEGATION_FROM: "checkout-svc",
                    ATTR_DELEGATION_TO: "payment-svc",
                    ATTR_CREDENTIAL_TYPE: "service_credential",
                },
            ),
        ]
        ctx = extract_authorization_context(spans)
        # Different cred types on different spans → NOT a conflict
        conflicts = [
            w for w in ctx.warnings
            if w.warning_type == "conflicting"
            and "credential" in w.field
        ]
        assert len(conflicts) == 0

    def test_both_hops_captured(self):
        spans = [
            FakeSpan(
                span_id="span-1",
                span_name="POST /checkout",
                parent_span_id=None,
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                    ATTR_DELEGATION_FROM: "user-123",
                    ATTR_DELEGATION_TO: "checkout-svc",
                    ATTR_CREDENTIAL_TYPE: "user_token",
                },
            ),
            FakeSpan(
                span_id="span-2",
                span_name="oteldemo.PaymentService/Charge",
                parent_span_id="span-1",
                service_name="payment",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                    ATTR_DELEGATION_FROM: "checkout-svc",
                    ATTR_DELEGATION_TO: "payment-svc",
                    ATTR_CREDENTIAL_TYPE: "service_credential",
                },
            ),
        ]
        ctx = extract_authorization_context(spans)
        assert len(ctx.delegation_hops) == 2
        assert ctx.delegation_hops[0].credential_type_raw == "user_token"
        assert ctx.delegation_hops[1].credential_type_raw == "service_credential"


# ===================================================================
# 7. CONFLICTING PRINCIPAL IDENTITIES
# ===================================================================


class TestConflictingPrincipal:
    """Two spans report different authz.principal.id values."""

    def test_principal_is_none_on_conflict(self):
        spans = [
            FakeSpan(
                span_id="s1",
                span_name="POST /checkout",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                },
            ),
            FakeSpan(
                span_id="s2",
                span_name="oteldemo.PaymentService/Charge",
                parent_span_id="s1",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-456",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                },
            ),
        ]
        ctx = extract_authorization_context(spans)
        assert ctx.initiating_principal_id is None

    def test_conflicting_warning_present(self):
        spans = [
            FakeSpan(
                span_id="s1",
                span_name="POST /checkout",
                attributes={ATTR_PRINCIPAL_ID: "user-123"},
            ),
            FakeSpan(
                span_id="s2",
                span_name="GET /api",
                parent_span_id="s1",
                attributes={ATTR_PRINCIPAL_ID: "user-456"},
            ),
        ]
        ctx = extract_authorization_context(spans)
        conflicts = [
            w for w in ctx.warnings
            if w.field == "initiating_principal.id"
            and w.warning_type == "conflicting"
        ]
        assert len(conflicts) == 1

    def test_both_values_preserved_in_evidence(self):
        spans = [
            FakeSpan(
                span_id="s1",
                span_name="POST /checkout",
                attributes={ATTR_PRINCIPAL_ID: "user-123"},
            ),
            FakeSpan(
                span_id="s2",
                span_name="GET /api",
                parent_span_id="s1",
                attributes={ATTR_PRINCIPAL_ID: "user-456"},
            ),
        ]
        ctx = extract_authorization_context(spans)
        pid_evidence = [
            e for e in ctx.evidence
            if e.field == "initiating_principal.id"
        ]
        values = {e.value for e in pid_evidence}
        assert "user-123" in values
        assert "user-456" in values

    def test_insufficient_evidence_on_conflict(self):
        spans = [
            FakeSpan(
                span_id="s1",
                span_name="POST /checkout",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                },
            ),
            FakeSpan(
                span_id="s2",
                span_name="oteldemo.PaymentService/Charge",
                parent_span_id="s1",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-456",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                },
            ),
        ]
        ctx = extract_authorization_context(spans)
        assert ctx.has_sufficient_evidence() is False

    def test_to_scenario_raises_on_conflict(self):
        spans = [
            FakeSpan(
                span_id="s1",
                span_name="POST /checkout",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                },
            ),
            FakeSpan(
                span_id="s2",
                span_name="oteldemo.PaymentService/Charge",
                parent_span_id="s1",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-456",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                },
            ),
        ]
        ctx = extract_authorization_context(spans)
        with pytest.raises(ValueError):
            ctx.to_scenario()


# ===================================================================
# 8. CONFLICTING VALUES FOR SAME LOGICAL FIELD AND HOP
# ===================================================================


class TestConflictingSameHop:
    """Conflicting principal type values across spans."""

    def test_conflicting_principal_type(self):
        spans = [
            FakeSpan(
                span_id="s1",
                span_name="POST /checkout",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_TYPE: "user",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                },
            ),
            FakeSpan(
                span_id="s2",
                span_name="GET /api",
                parent_span_id="s1",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_TYPE: "agent",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                },
            ),
        ]
        ctx = extract_authorization_context(spans)
        conflicts = [
            w for w in ctx.warnings
            if w.field == "initiating_principal.type"
            and w.warning_type == "conflicting"
        ]
        assert len(conflicts) == 1

    def test_conflicting_scopes(self):
        spans = [
            FakeSpan(
                span_id="s1",
                span_name="POST /checkout",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                },
            ),
            FakeSpan(
                span_id="s2",
                span_name="GET /api",
                parent_span_id="s1",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read,payments:charge",
                },
            ),
        ]
        ctx = extract_authorization_context(spans)
        conflicts = [
            w for w in ctx.warnings
            if w.field == "original_authority"
            and w.warning_type == "conflicting"
        ]
        assert len(conflicts) == 1


# ===================================================================
# 9. ORDINARY OTEL TRACES WITHOUT AUTH ATTRIBUTES
# ===================================================================


class TestOrdinaryTraces:
    """Standard OTel Demo traces with no authorization attributes."""

    def _ordinary_spans(self) -> list[FakeSpan]:
        return [
            FakeSpan(
                trace_id="trace-ordinary",
                span_id="span-a",
                span_name="GET /api/products",
                service_name="frontend",
                status_code=0,
                attributes={
                    "http.method": "GET",
                    "http.url": "http://frontend:8080/api/products",
                    "http.status_code": 200,
                },
            ),
            FakeSpan(
                trace_id="trace-ordinary",
                span_id="span-b",
                parent_span_id="span-a",
                span_name="oteldemo.ProductCatalogService/ListProducts",
                service_name="productcatalogservice",
                status_code=0,
                attributes={
                    "rpc.service": "oteldemo.ProductCatalogService",
                    "rpc.method": "ListProducts",
                    "rpc.system": "grpc",
                },
            ),
        ]

    def test_no_principal(self):
        ctx = extract_authorization_context(self._ordinary_spans())
        assert ctx.initiating_principal_id is None

    def test_no_scopes(self):
        ctx = extract_authorization_context(self._ordinary_spans())
        assert ctx.original_scopes is None

    def test_no_delegation(self):
        ctx = extract_authorization_context(self._ordinary_spans())
        assert len(ctx.delegation_hops) == 0

    def test_action_still_extracted(self):
        ctx = extract_authorization_context(self._ordinary_spans())
        # The leaf span name is still captured
        assert ctx.effective_span_name is not None

    def test_insufficient_evidence(self):
        ctx = extract_authorization_context(self._ordinary_spans())
        assert ctx.has_sufficient_evidence() is False

    def test_no_false_positive(self):
        """An ordinary trace must NEVER produce a DETECTED verdict."""
        ctx = extract_authorization_context(self._ordinary_spans())
        assert not ctx.has_sufficient_evidence()
        # Cannot even build a scenario
        with pytest.raises(ValueError):
            ctx.to_scenario()

    def test_missing_warnings_present(self):
        ctx = extract_authorization_context(self._ordinary_spans())
        missing = [w for w in ctx.warnings if w.warning_type == "missing"]
        assert len(missing) >= 2  # principal + authority at minimum


# ===================================================================
# 10. EVIDENCE PROVENANCE
# ===================================================================


class TestEvidenceProvenance:
    """Every extracted value must have proper provenance."""

    def test_principal_provenance(self):
        spans = [
            FakeSpan(
                span_id="span-prov",
                span_name="GET /test",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                },
            )
        ]
        ctx = extract_authorization_context(spans)
        pid_ev = [
            e for e in ctx.evidence
            if e.field == "initiating_principal.id"
        ]
        assert len(pid_ev) == 1
        ev = pid_ev[0]
        assert ev.value == "user-123"
        assert ev.source == f"span_attribute:{ATTR_PRINCIPAL_ID}"
        assert ev.span_id == "span-prov"
        assert ev.confidence == "explicit"

    def test_scope_provenance(self):
        spans = [
            FakeSpan(
                span_id="span-prov",
                span_name="GET /test",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                },
            )
        ]
        ctx = extract_authorization_context(spans)
        scope_ev = [
            e for e in ctx.evidence
            if e.field == "original_authority"
        ]
        assert len(scope_ev) == 1
        ev = scope_ev[0]
        assert ev.source == f"span_attribute:{ATTR_PRINCIPAL_SCOPES}"
        assert ev.span_id == "span-prov"
        assert ev.confidence == "explicit"

    def test_action_provenance(self):
        spans = [
            FakeSpan(
                span_id="span-prov",
                span_name="oteldemo.PaymentService/Charge",
                attributes={ATTR_PRINCIPAL_ID: "user-123"},
            )
        ]
        ctx = extract_authorization_context(spans)
        action_ev = [
            e for e in ctx.evidence
            if e.field == "effective_action"
        ]
        assert len(action_ev) == 1
        assert action_ev[0].source == "span_field:span_name"
        assert action_ev[0].span_id == "span-prov"

    def test_configured_evidence_marked_correctly(self):
        spans = [
            FakeSpan(
                span_id="span-prov",
                span_name="oteldemo.PaymentService/Charge",
                service_name="payment",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                },
            )
        ]
        ctx = extract_authorization_context(
            spans,
            service_authority_config={"payment": ["payments:charge"]},
        )
        svc_ev = [
            e for e in ctx.evidence
            if e.field == "service_authority"
        ]
        assert len(svc_ev) == 1
        ev = svc_ev[0]
        assert ev.confidence == "configured"
        assert ev.source == "config:service_authority"
        assert ev.span_id is None


# ===================================================================
# 11. EXPLICIT SERVICE-AUTHORITY CONFIGURATION
# ===================================================================


class TestServiceAuthorityConfig:
    """Service authority supplied by explicit configuration."""

    def test_config_applied(self):
        spans = [
            FakeSpan(
                span_name="oteldemo.PaymentService/Charge",
                service_name="payment",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                },
            )
        ]
        ctx = extract_authorization_context(
            spans,
            service_authority_config={"payment": ["payments:charge"]},
        )
        assert ctx.service_authority_permissions == ["payments:charge"]

    def test_config_not_applied_when_service_not_matched(self):
        spans = [
            FakeSpan(
                span_name="GET /test",
                service_name="frontend",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                },
            )
        ]
        ctx = extract_authorization_context(
            spans,
            service_authority_config={"payment": ["payments:charge"]},
        )
        assert ctx.service_authority_permissions is None

    def test_no_inference_from_service_name_alone(self):
        """Service name must NOT be used to infer permissions without config."""
        spans = [
            FakeSpan(
                span_name="oteldemo.PaymentService/Charge",
                service_name="payment",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                },
            )
        ]
        ctx = extract_authorization_context(spans)
        assert ctx.service_authority_permissions is None

    def test_scenario_with_service_authority(self):
        spans = [
            FakeSpan(
                span_name="oteldemo.PaymentService/Charge",
                service_name="payment",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                },
            )
        ]
        ctx = extract_authorization_context(
            spans,
            service_authority_config={"payment": ["payments:charge"]},
        )
        policy = default_otel_demo_policy()
        scenario = ctx.to_scenario(policy=policy)
        assert scenario.acting_service_authority is not None
        assert "payments:charge" in scenario.acting_service_authority.permissions


# ===================================================================
# 12. EMPTY SPAN INPUT
# ===================================================================


class TestEmptyInput:
    """Extract from empty span list."""

    def test_returns_context(self):
        ctx = extract_authorization_context([])
        assert isinstance(ctx, AuthorizationContext)

    def test_all_fields_none(self):
        ctx = extract_authorization_context([])
        assert ctx.initiating_principal_id is None
        assert ctx.original_scopes is None
        assert ctx.effective_span_name is None

    def test_warning_present(self):
        ctx = extract_authorization_context([])
        assert any(
            w.field == "input" and w.warning_type == "missing"
            for w in ctx.warnings
        )

    def test_insufficient_evidence(self):
        ctx = extract_authorization_context([])
        assert ctx.has_sufficient_evidence() is False


# ===================================================================
# 13. ENDUSER.ID CANDIDATE HANDLING
# ===================================================================


class TestEnduserIdHandling:
    """enduser.id is a candidate, not automatically the principal."""

    def test_enduser_id_used_when_no_explicit_id(self):
        spans = [
            FakeSpan(
                span_id="s1",
                span_name="GET /test",
                attributes={
                    ATTR_ENDUSER_ID: "user-from-enduser",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                },
            )
        ]
        ctx = extract_authorization_context(spans)
        assert ctx.initiating_principal_id == "user-from-enduser"

    def test_enduser_id_confidence_is_candidate(self):
        spans = [
            FakeSpan(
                span_id="s1",
                span_name="GET /test",
                attributes={
                    ATTR_ENDUSER_ID: "user-from-enduser",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                },
            )
        ]
        ctx = extract_authorization_context(spans)
        pid_ev = [
            e for e in ctx.evidence
            if e.field == "initiating_principal.id"
        ]
        assert len(pid_ev) == 1
        assert pid_ev[0].confidence == "candidate"
        assert pid_ev[0].source == f"span_attribute:{ATTR_ENDUSER_ID}"

    def test_explicit_id_takes_precedence(self):
        """When both authz.principal.id and enduser.id exist,
        the explicit attribute wins."""
        spans = [
            FakeSpan(
                span_id="s1",
                span_name="GET /test",
                attributes={
                    ATTR_PRINCIPAL_ID: "explicit-user",
                    ATTR_ENDUSER_ID: "enduser-user",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                },
            )
        ]
        ctx = extract_authorization_context(spans)
        assert ctx.initiating_principal_id == "explicit-user"

    def test_conflicting_enduser_ids(self):
        """Multiple different enduser.id values are flagged as conflicting."""
        spans = [
            FakeSpan(
                span_id="s1",
                span_name="GET /a",
                attributes={ATTR_ENDUSER_ID: "user-A"},
            ),
            FakeSpan(
                span_id="s2",
                span_name="GET /b",
                parent_span_id="s1",
                attributes={ATTR_ENDUSER_ID: "user-B"},
            ),
        ]
        ctx = extract_authorization_context(spans)
        assert ctx.initiating_principal_id is None
        conflicts = [
            w for w in ctx.warnings
            if w.field == "initiating_principal.id"
            and w.warning_type == "conflicting"
        ]
        assert len(conflicts) == 1


# ===================================================================
# 14. CONTEXT-TO-SCENARIO CONVERSION + DETECTOR INTEGRATION
# ===================================================================


class TestContextToScenario:
    """Full round-trip: spans → context → scenario → detector."""

    def test_missing_delegated_scopes_are_not_inferred_from_original_authority(self):
        """Missing delegation scopes must not silently inherit all user scopes."""
        spans = [
            FakeSpan(
                span_id="span-1",
                span_name="POST /checkout",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read,admin:delete",
                    ATTR_DELEGATION_FROM: "user-123",
                    ATTR_DELEGATION_TO: "checkout-service",
                },
            )
        ]

        ctx = extract_authorization_context(spans)
        scenario = ctx.to_scenario()

        assert len(scenario.delegation_chain) == 1
        delegated_permissions = (
            scenario.delegation_chain[0].delegated_authority.permissions
        )

        assert "admin:delete" not in delegated_permissions

    def test_delegated_scopes_are_extracted_from_span_attributes(self):
        spans = [
            FakeSpan(
                span_id="span-1",
                span_name="POST /checkout",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read,admin:delete",
                    ATTR_DELEGATION_FROM: "user-123",
                    ATTR_DELEGATION_TO: "checkout-service",
                    ATTR_DELEGATION_SCOPES: "orders:read",
                },
            )
        ]

        ctx = extract_authorization_context(spans)
        scenario = ctx.to_scenario()

        assert len(scenario.delegation_chain) == 1
        assert scenario.delegation_chain[0].delegated_authority.permissions == {
            "orders:read"
        }

    def test_missing_service_identity_mapping_is_insufficient(self):
        """A recipient ID is not implicitly equated with the operation service."""
        spans = _complete_span_set()
        ctx = extract_authorization_context(
            spans,
            service_authority_config={"payment": ["payments:charge"]},
        )
        policy = default_otel_demo_policy()
        scenario = ctx.to_scenario(policy=policy)

        detector = ConfusedDeputyDetector(policy=policy)
        result = detector.analyze(scenario)
        assert result.verdict == Verdict.INSUFFICIENT_EVIDENCE
        assert "Cannot verify" in result.reason

    def test_legitimate_authorization_not_detected(self):
        """User has the required authority — should NOT detect."""
        spans = [
            FakeSpan(
                span_id="span-legit",
                span_name="oteldemo.PaymentService/Charge",
                service_name="payment",
                status_code=1,
                attributes={
                    ATTR_PRINCIPAL_ID: "admin-01",
                    ATTR_PRINCIPAL_TYPE: "user",
                    ATTR_PRINCIPAL_SCOPES: "payments:charge,orders:read",
                },
            )
        ]
        ctx = extract_authorization_context(spans)
        policy = default_otel_demo_policy()
        scenario = ctx.to_scenario(policy=policy)

        detector = ConfusedDeputyDetector(policy=policy)
        result = detector.analyze(scenario)
        assert result.verdict == Verdict.NOT_DETECTED

    def test_scenario_evidence_contains_provenance(self):
        spans = _complete_span_set()
        ctx = extract_authorization_context(spans)
        scenario = ctx.to_scenario()
        assert "extraction_evidence" in scenario.evidence
        assert "extraction_warnings" in scenario.evidence

    def test_scenario_identity_correct(self):
        spans = _complete_span_set()
        ctx = extract_authorization_context(spans)
        scenario = ctx.to_scenario()
        assert scenario.initiating_principal is not None
        assert scenario.initiating_principal.principal_id == "user-123"
        assert scenario.initiating_principal.principal_type == PrincipalType.USER

    def test_scenario_authority_correct(self):
        spans = _complete_span_set()
        ctx = extract_authorization_context(spans)
        scenario = ctx.to_scenario()
        assert scenario.original_authority is not None
        assert "orders:read" in scenario.original_authority.permissions


# ===================================================================
# 15. PRESERVATION OF EXISTING DETECTOR BEHAVIOR
# ===================================================================


class TestDetectorPreservation:
    """
    Adding context.py must not change the existing detector's behavior.
    Re-run canonical fixtures through the detector to verify.
    """

    def test_golden_confused_deputy_still_detected(self):
        """The original golden fixture must still produce DETECTED."""
        from tests.fixtures import golden_confused_deputy

        detector = ConfusedDeputyDetector()
        result = detector.analyze(golden_confused_deputy())
        assert result.verdict == Verdict.DETECTED

    def test_legitimate_direct_still_not_detected(self):
        from tests.fixtures import legitimate_direct_authorization

        detector = ConfusedDeputyDetector()
        result = detector.analyze(legitimate_direct_authorization())
        assert result.verdict == Verdict.NOT_DETECTED

    def test_missing_identity_still_insufficient(self):
        from tests.fixtures import missing_initiating_identity

        detector = ConfusedDeputyDetector()
        result = detector.analyze(missing_initiating_identity())
        assert result.verdict == Verdict.INSUFFICIENT_EVIDENCE

    def test_all_fixtures_unchanged(self):
        from tests.fixtures import ALL_FIXTURES

        delegation_policy = DelegationPolicy()
        delegation_policy.register(
            "checkout-svc",
            "payment-svc",
            {"payments:charge"},
        )
        detector = ConfusedDeputyDetector(
            delegation_policy=delegation_policy
        )
        for name, (factory, expected) in ALL_FIXTURES.items():
            result = detector.analyze(factory())
            assert result.verdict == expected, (
                f"Fixture '{name}': expected {expected.value}, "
                f"got {result.verdict.value}"
            )


# ===================================================================
# 16. MALFORMED SCOPE VALUES
# ===================================================================


class TestMalformedScopes:
    """Malformed scope data must be rejected safely."""

    def test_empty_string_scopes(self):
        spans = [
            FakeSpan(
                span_name="GET /test",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "",
                },
            )
        ]
        ctx = extract_authorization_context(spans)
        assert ctx.original_scopes is None

    def test_malformed_json_scopes(self):
        spans = [
            FakeSpan(
                span_name="GET /test",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "[not valid json",
                },
            )
        ]
        ctx = extract_authorization_context(spans)
        assert ctx.original_scopes is None
        malformed = [
            w for w in ctx.warnings
            if w.warning_type == "malformed"
        ]
        assert len(malformed) >= 1

    def test_numeric_scopes_rejected(self):
        spans = [
            FakeSpan(
                span_name="GET /test",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: 12345,
                },
            )
        ]
        ctx = extract_authorization_context(spans)
        assert ctx.original_scopes is None

    def test_partially_malformed_scopes_are_insufficient(self):
        spans = [
            FakeSpan(
                span_name="GET /test",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: ["orders:read", 42],
                },
            )
        ]

        ctx = extract_authorization_context(spans)

        assert ctx.original_scopes == ["orders:read"]
        assert not ctx.has_sufficient_evidence()
        assert any(
            warning.field == "original_authority"
            and warning.warning_type == "malformed"
            for warning in ctx.warnings
        )

    def test_json_array_scopes_parsed(self):
        spans = [
            FakeSpan(
                span_name="GET /test",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: '["orders:read", "cart:modify"]',
                },
            )
        ]
        ctx = extract_authorization_context(spans)
        assert ctx.original_scopes is not None
        assert set(ctx.original_scopes) == {"orders:read", "cart:modify"}

    def test_comma_separated_scopes_parsed(self):
        spans = [
            FakeSpan(
                span_name="GET /test",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read,cart:modify",
                },
            )
        ]
        ctx = extract_authorization_context(spans)
        assert ctx.original_scopes is not None
        assert set(ctx.original_scopes) == {"orders:read", "cart:modify"}

    def test_space_separated_scopes_parsed(self):
        spans = [
            FakeSpan(
                span_name="GET /test",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: "orders:read cart:modify",
                },
            )
        ]
        ctx = extract_authorization_context(spans)
        assert ctx.original_scopes is not None
        assert set(ctx.original_scopes) == {"orders:read", "cart:modify"}

    def test_otel_array_attribute_scopes(self):
        spans = [
            FakeSpan(
                span_name="GET /test",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-123",
                    ATTR_PRINCIPAL_SCOPES: ["orders:read", "cart:modify"],
                },
            )
        ]
        ctx = extract_authorization_context(spans)
        assert ctx.original_scopes is not None
        assert set(ctx.original_scopes) == {"orders:read", "cart:modify"}


# ===================================================================
# 17. INCOMPLETE EVIDENCE CANNOT PRODUCE A FALSE POSITIVE
# ===================================================================


class TestNoFalsePositiveFromIncompleteEvidence:
    """Incomplete contexts must never produce DETECTED."""

    def test_missing_scopes_no_detection(self):
        """Principal present but no scopes → cannot build scenario."""
        spans = [
            FakeSpan(
                span_name="oteldemo.PaymentService/Charge",
                service_name="payment",
                attributes={ATTR_PRINCIPAL_ID: "user-123"},
            )
        ]
        ctx = extract_authorization_context(spans)
        assert not ctx.has_sufficient_evidence()
        with pytest.raises(ValueError):
            ctx.to_scenario()


    def test_missing_principal_no_detection(self):
        """Scopes present but no principal → cannot build scenario."""
        spans = [
            FakeSpan(
                span_name="oteldemo.PaymentService/Charge",
                service_name="payment",
                attributes={ATTR_PRINCIPAL_SCOPES: "orders:read"},
            )
        ]
        ctx = extract_authorization_context(spans)
        assert not ctx.has_sufficient_evidence()
        with pytest.raises(ValueError):
            ctx.to_scenario()

    def test_conflicting_evidence_no_detection(self):
        """Conflicting principal IDs → cannot build scenario."""
        spans = [
            FakeSpan(
                span_id="s1",
                span_name="POST /checkout",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-A",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                },
            ),
            FakeSpan(
                span_id="s2",
                span_name="oteldemo.PaymentService/Charge",
                parent_span_id="s1",
                attributes={
                    ATTR_PRINCIPAL_ID: "user-B",
                    ATTR_PRINCIPAL_SCOPES: "orders:read",
                },
            ),
        ]
        ctx = extract_authorization_context(spans)
        assert not ctx.has_sufficient_evidence()
        with pytest.raises(ValueError):
            ctx.to_scenario()


class TestDelegationScopeEvidence:
    """Missing, malformed, and explicitly empty scopes remain distinct."""

    @staticmethod
    def _extract_delegation(scopes: Any = ...) -> AuthorizationContext:
        attributes = {
            ATTR_PRINCIPAL_ID: "user-123",
            ATTR_PRINCIPAL_SCOPES: "orders:read",
            ATTR_DELEGATION_FROM: "user-123",
            ATTR_DELEGATION_TO: "payment-svc",
        }
        if scopes is not ...:
            attributes[ATTR_DELEGATION_SCOPES] = scopes

        span = FakeSpan(
            span_name="oteldemo.PaymentService/Charge",
            service_name="payment",
            attributes=attributes,
        )
        return extract_authorization_context([span])

    def test_missing_delegation_scopes_remain_unknown(self):
        context = self._extract_delegation()
        scenario = context.to_scenario(policy=default_otel_demo_policy())

        step = scenario.delegation_chain[0]
        assert step.scopes_known is False
        assert step.delegated_authority.permissions == frozenset()
        assert any(
            warning.field == "delegation.scopes"
            and warning.warning_type == "missing"
            for warning in context.warnings
        )

    def test_malformed_delegation_scopes_remain_unknown(self):
        context = self._extract_delegation("[not valid json")
        scenario = context.to_scenario(policy=default_otel_demo_policy())

        step = scenario.delegation_chain[0]
        assert step.scopes_known is False
        assert step.delegated_authority.permissions == frozenset()
        assert any(
            warning.field == "delegation.scopes"
            and warning.warning_type == "malformed"
            for warning in context.warnings
        )

    def test_explicitly_empty_delegation_scopes_are_known(self):
        context = self._extract_delegation([])
        scenario = context.to_scenario(policy=default_otel_demo_policy())

        step = scenario.delegation_chain[0]
        assert step.scopes_known is True
        assert step.delegated_authority.permissions == frozenset()

        result = ConfusedDeputyDetector().analyze(scenario)
        assert result.verdict == Verdict.INSUFFICIENT_EVIDENCE
        assert "Cannot verify" in result.reason


# ===================================================================
# 18. PARSE_SCOPES UNIT TESTS
# ===================================================================


class TestParseScopes:
    """Direct tests for the _parse_scopes helper."""

    def test_single_scope(self):
        assert _parse_scopes("orders:read") == frozenset({"orders:read"})

    def test_comma_separated(self):
        result = _parse_scopes("a,b,c")
        assert result == frozenset({"a", "b", "c"})

    def test_space_separated(self):
        result = _parse_scopes("a b c")
        assert result == frozenset({"a", "b", "c"})

    def test_json_array(self):
        result = _parse_scopes('["a", "b"]')
        assert result == frozenset({"a", "b"})

    def test_python_list(self):
        result = _parse_scopes(["a", "b"])
        assert result == frozenset({"a", "b"})

    def test_empty_string(self):
        assert _parse_scopes("") == frozenset()

    def test_empty_list(self):
        assert _parse_scopes([]) == frozenset()

    def test_malformed_json(self):
        assert _parse_scopes("[broken") == frozenset()

    def test_none(self):
        assert _parse_scopes(None) == frozenset()

    def test_integer(self):
        assert _parse_scopes(42) == frozenset()

    def test_whitespace_trimmed(self):
        result = _parse_scopes("  a , b , c  ")
        assert result == frozenset({"a", "b", "c"})

    def test_list_with_non_strings(self):
        result = _parse_scopes(["a", 123, "b", None])
        assert result == frozenset({"a", "b"})
