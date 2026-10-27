"""
Comprehensive tests for the confused-deputy detector.

Covers all 12+ required test cases plus deterministic repeatability.
"""

from auth_engine.detector import ConfusedDeputyDetector
from auth_engine.models import (
    Authority,
    AuthoritySource,
    AuthorizationScenario,
    CredentialType,
    DelegationStep,
    Finding,
    FindingType,
    Identity,
    Operation,
    PrincipalType,
    Severity,
    Verdict,
)
from auth_engine.policy import ActionPolicy
from auth_engine.delegation_policy import DelegationPolicy

from .fixtures import (
    ALL_FIXTURES,
    AGENT,
    CHECKOUT_SERVICE,
    PAYMENT_SERVICE,
    USER_123,
    direct_call_authorized,
    golden_confused_deputy,
    legitimate_delegated_authorization,
    legitimate_direct_authorization,
    missing_action_requirement,
    missing_effective_operation,
    missing_initiating_identity,
    missing_original_authority,
    multi_hop_valid_delegation,
    service_privilege_exceeds_request,
    unrelated_downstream_operation,
)

# Instantiate the detector once — it is stateless.
DELEGATION_POLICY = DelegationPolicy()
DELEGATION_POLICY.register(
    "checkout-svc",
    "payment-svc",
    {"payments:charge"},
)
DETECTOR = ConfusedDeputyDetector(delegation_policy=DELEGATION_POLICY)


# ===================================================================
# 1. GOLDEN CONFUSED DEPUTY  →  DETECTED
# ===================================================================


class TestGoldenConfusedDeputy:
    """
    The canonical test.

    User authority: orders:read
    Required action: payments:charge
    No delegated payment authority.
    Service has payments:charge.

    Expected: DETECTED
    """

    def test_verdict(self):
        result = DETECTOR.analyze(golden_confused_deputy())
        assert result.verdict == Verdict.DETECTED

    def test_reason_mentions_payments_charge(self):
        result = DETECTOR.analyze(golden_confused_deputy())
        assert "payments:charge" in result.reason

    def test_finding_severity(self):
        result = DETECTOR.analyze(golden_confused_deputy())
        assert result.finding.severity == Severity.HIGH

    def test_finding_type(self):
        result = DETECTOR.analyze(golden_confused_deputy())
        assert result.finding.finding_type == FindingType.CONFUSED_DEPUTY

    def test_finding_has_attack_path(self):
        result = DETECTOR.analyze(golden_confused_deputy())
        assert len(result.finding.attack_path) > 0

    def test_finding_trace_id(self):
        result = DETECTOR.analyze(golden_confused_deputy())
        assert result.finding.trace_id == "trace-golden-001"

    def test_details_structure(self):
        result = DETECTOR.analyze(golden_confused_deputy())
        assert "required_action" in result.details
        assert "request_authority" in result.details
        assert "service_authority" in result.details
        assert "payments:charge" in result.details["required_action"]
        assert "orders:read" in result.details["request_authority"]
        assert "payments:charge" in result.details["service_authority"]

    def test_effective_action_in_finding(self):
        result = DETECTOR.analyze(golden_confused_deputy())
        assert result.finding.effective_action == "payments:charge"

    def test_required_authority_in_finding(self):
        result = DETECTOR.analyze(golden_confused_deputy())
        assert "payments:charge" in result.finding.required_authority

    def test_delegated_authority_in_finding(self):
        result = DETECTOR.analyze(golden_confused_deputy())
        # Request authority at the final hop should only have orders:read
        assert result.finding.delegated_authority is not None
        assert "orders:read" in result.finding.delegated_authority.permissions
        assert "payments:charge" not in result.finding.delegated_authority.permissions


# ===================================================================
# 2. LEGITIMATE DIRECT AUTHORIZATION  →  NOT_DETECTED
# ===================================================================


class TestLegitimateDirectAuthorization:
    """User has payments:charge — no confused deputy."""

    def test_verdict(self):
        result = DETECTOR.analyze(legitimate_direct_authorization())
        assert result.verdict == Verdict.NOT_DETECTED

    def test_reason(self):
        result = DETECTOR.analyze(legitimate_direct_authorization())
        assert "legitimately authorized" in result.reason

    def test_finding_type(self):
        result = DETECTOR.analyze(legitimate_direct_authorization())
        assert result.finding.finding_type == FindingType.NONE


# ===================================================================
# 3. LEGITIMATE DELEGATED AUTHORIZATION  →  NOT_DETECTED
# ===================================================================


class TestLegitimateDelegatedAuthorization:
    """
    User only has orders:read, but payments:charge is explicitly
    delegated at the checkout → payment hop.
    """

    def test_verdict(self):
        result = DETECTOR.analyze(legitimate_delegated_authorization())
        assert result.verdict == Verdict.NOT_DETECTED

    def test_no_false_positive(self):
        """Ensures we do NOT flag this as confused deputy."""
        result = DETECTOR.analyze(legitimate_delegated_authorization())
        assert result.verdict != Verdict.DETECTED


# ===================================================================
# 4. MULTI-HOP VALID DELEGATION  →  NOT_DETECTED
# ===================================================================


class TestMultiHopValidDelegation:
    """Authority propagated correctly across User → Agent → Checkout → Payment."""

    def test_verdict(self):
        result = DETECTOR.analyze(multi_hop_valid_delegation())
        assert result.verdict == Verdict.NOT_DETECTED

    def test_reason_mentions_authorized(self):
        result = DETECTOR.analyze(multi_hop_valid_delegation())
        assert "legitimately authorized" in result.reason


# ===================================================================
# 5. SERVICE PRIVILEGE EXCEEDS REQUEST  →  DETECTED
# ===================================================================


class TestServicePrivilegeExceedsRequest:
    """
    Service has payments:charge.
    Request only has orders:read.
    Credential: service.
    """

    def test_verdict(self):
        result = DETECTOR.analyze(service_privilege_exceeds_request())
        assert result.verdict == Verdict.DETECTED

    def test_reason(self):
        result = DETECTOR.analyze(service_privilege_exceeds_request())
        assert "payments:charge" in result.reason

    def test_no_false_negative(self):
        """Service-level authority must NOT make this legitimate."""
        result = DETECTOR.analyze(service_privilege_exceeds_request())
        assert result.verdict == Verdict.DETECTED


# ===================================================================
# 6. MISSING INITIATING IDENTITY  →  INSUFFICIENT_EVIDENCE
# ===================================================================


class TestMissingInitiatingIdentity:
    def test_verdict(self):
        result = DETECTOR.analyze(missing_initiating_identity())
        assert result.verdict == Verdict.INSUFFICIENT_EVIDENCE

    def test_reason(self):
        result = DETECTOR.analyze(missing_initiating_identity())
        assert "initiating principal" in result.reason.lower()

    def test_finding_type(self):
        result = DETECTOR.analyze(missing_initiating_identity())
        assert result.finding.finding_type == FindingType.NONE


# ===================================================================
# 7. MISSING ORIGINAL AUTHORITY  →  INSUFFICIENT_EVIDENCE
# ===================================================================


class TestMissingOriginalAuthority:
    def test_verdict(self):
        result = DETECTOR.analyze(missing_original_authority())
        assert result.verdict == Verdict.INSUFFICIENT_EVIDENCE

    def test_reason(self):
        result = DETECTOR.analyze(missing_original_authority())
        assert "authority" in result.reason.lower()


# ===================================================================
# 8. MISSING ACTION REQUIREMENT  →  INSUFFICIENT_EVIDENCE
# ===================================================================


class TestMissingActionRequirement:
    def test_verdict(self):
        result = DETECTOR.analyze(missing_action_requirement())
        assert result.verdict == Verdict.INSUFFICIENT_EVIDENCE

    def test_reason(self):
        result = DETECTOR.analyze(missing_action_requirement())
        assert "operation" in result.reason.lower() or "action" in result.reason.lower()


# ===================================================================
# 9. UNRELATED DOWNSTREAM OPERATION  →  NOT_DETECTED
# ===================================================================


class TestUnrelatedDownstreamOperation:
    """products:read action should not trigger a finding."""

    def test_verdict(self):
        result = DETECTOR.analyze(unrelated_downstream_operation())
        assert result.verdict == Verdict.NOT_DETECTED


# ===================================================================
# 10. DETERMINISTIC REPEATABILITY
# ===================================================================


class TestDeterministicRepeatability:
    """Same input must always produce the same verdict and reason."""

    def test_golden_repeat_10_times(self):
        scenario = golden_confused_deputy()
        results = [DETECTOR.analyze(scenario) for _ in range(10)]
        verdicts = {r.verdict for r in results}
        reasons = {r.reason for r in results}
        assert len(verdicts) == 1
        assert Verdict.DETECTED in verdicts
        assert len(reasons) == 1

    def test_legitimate_repeat_10_times(self):
        scenario = legitimate_direct_authorization()
        results = [DETECTOR.analyze(scenario) for _ in range(10)]
        verdicts = {r.verdict for r in results}
        assert len(verdicts) == 1
        assert Verdict.NOT_DETECTED in verdicts

    def test_insufficient_repeat_10_times(self):
        scenario = missing_initiating_identity()
        results = [DETECTOR.analyze(scenario) for _ in range(10)]
        verdicts = {r.verdict for r in results}
        assert len(verdicts) == 1
        assert Verdict.INSUFFICIENT_EVIDENCE in verdicts


# ===================================================================
# 11. NO FALSE POSITIVE ON VALID DELEGATED AUTHORITY
# ===================================================================


class TestNoFalsePositive:
    """
    Ensure that properly delegated authority never results in
    a DETECTED verdict.
    """

    def test_direct_authorized(self):
        result = DETECTOR.analyze(direct_call_authorized())
        assert result.verdict == Verdict.NOT_DETECTED

    def test_all_legitimate_fixtures(self):
        for name, (factory, expected) in ALL_FIXTURES.items():
            if expected == Verdict.NOT_DETECTED:
                result = DETECTOR.analyze(factory())
                assert result.verdict == Verdict.NOT_DETECTED, (
                    f"False positive on fixture: {name}"
                )


# ===================================================================
# 12. NO FALSE NEGATIVE WHEN SERVICE AUTHORITY IS IMPROPERLY USED
# ===================================================================


class TestNoFalseNegative:
    """
    Ensure that scenarios where service authority is used on behalf
    of the user are always flagged.
    """

    def test_all_detected_fixtures(self):
        for name, (factory, expected) in ALL_FIXTURES.items():
            if expected == Verdict.DETECTED:
                result = DETECTOR.analyze(factory())
                assert result.verdict == Verdict.DETECTED, (
                    f"False negative on fixture: {name}"
                )


# ===================================================================
# 13. MISSING EFFECTIVE OPERATION  →  INSUFFICIENT_EVIDENCE
# ===================================================================


class TestMissingEffectiveOperation:
    def test_verdict(self):
        result = DETECTOR.analyze(missing_effective_operation())
        assert result.verdict == Verdict.INSUFFICIENT_EVIDENCE


# ===================================================================
# 14. POLICY LOOKUP — ACTION RESOLVED VIA RAW SPAN NAME
# ===================================================================


class TestPolicyLookup:
    """
    When the operation has only a raw_span_name (no semantic_action or
    explicit required_authority), the detector should use the policy
    to resolve the requirement.
    """

    def test_resolved_from_span(self):
        scenario = AuthorizationScenario(
            trace_id="trace-policy-001",
            initiating_principal=USER_123,
            original_authority=Authority.original("orders:read"),
            delegation_chain=[
                DelegationStep(
                    from_principal=USER_123,
                    to_principal=PAYMENT_SERVICE,
                    delegated_authority=Authority.delegated("orders:read"),
                    credential_type=CredentialType.SERVICE_CREDENTIAL,
                ),
            ],
            effective_operation=Operation(
                service="payment",
                raw_span_name="oteldemo.PaymentService/Charge",
                # No semantic_action, no required_authority
            ),
            acting_service_authority=Authority.service("payments:charge"),
        )
        result = DETECTOR.analyze(scenario)
        # payments:charge is NOT in orders:read, so this is a confused deputy
        assert result.verdict == Verdict.DETECTED

    def test_unknown_span_returns_insufficient(self):
        scenario = AuthorizationScenario(
            trace_id="trace-policy-002",
            initiating_principal=USER_123,
            original_authority=Authority.original("orders:read"),
            effective_operation=Operation(
                service="mystery",
                raw_span_name="com.example.MysteryService/DoThing",
            ),
        )
        result = DETECTOR.analyze(scenario)
        assert result.verdict == Verdict.INSUFFICIENT_EVIDENCE


# ===================================================================
# 15. DIRECT CALL — NO DELEGATION CHAIN
# ===================================================================


class TestDirectCall:
    def test_authorized_direct_call(self):
        result = DETECTOR.analyze(direct_call_authorized())
        assert result.verdict == Verdict.NOT_DETECTED

    def test_unauthorized_direct_call(self):
        scenario = AuthorizationScenario(
            trace_id="trace-direct-unauth",
            initiating_principal=USER_123,
            original_authority=Authority.original("orders:read"),
            delegation_chain=[],
            effective_operation=Operation(
                service="payment",
                semantic_action="payments:charge",
                required_authority=frozenset({"payments:charge"}),
            ),
            acting_service_authority=Authority.service("payments:charge"),
        )
        result = DETECTOR.analyze(scenario)
        assert result.verdict == Verdict.DETECTED


# ===================================================================
# 16. CUSTOM POLICY
# ===================================================================


class TestCustomPolicy:
    def test_custom_policy_mapping(self):
        policy = ActionPolicy()
        policy.register(
            semantic_action="admin:delete",
            required_permissions=["admin:delete"],
            raw_span_names=["AdminService/Delete"],
        )
        detector = ConfusedDeputyDetector(policy=policy)

        scenario = AuthorizationScenario(
            trace_id="trace-custom-001",
            initiating_principal=USER_123,
            original_authority=Authority.original("admin:delete"),
            delegation_chain=[],
            effective_operation=Operation(
                service="admin",
                raw_span_name="AdminService/Delete",
            ),
        )
        result = detector.analyze(scenario)
        assert result.verdict == Verdict.NOT_DETECTED


# ===================================================================
# 17. ALL FIXTURES — META TEST
# ===================================================================


class TestAllFixtures:
    """Run every registered fixture and verify the expected verdict."""

    def test_all(self):
        for name, (factory, expected) in ALL_FIXTURES.items():
            result = DETECTOR.analyze(factory())
            assert result.verdict == expected, (
                f"Fixture '{name}': expected {expected.value}, "
                f"got {result.verdict.value}"
            )


def test_unauthorized_permission_expansion():
    """Reject permissions added without a trusted delegation grant."""
    from auth_engine.models import Authority
    from tests.fixtures import legitimate_delegated_authorization

    scenario = legitimate_delegated_authorization()
    final_step = scenario.delegation_chain[-1]

    scenario.delegation_chain[-1] = type(final_step)(
        from_principal=final_step.from_principal,
        to_principal=final_step.to_principal,
        delegated_authority=Authority(
            permissions=frozenset({
                "orders:read",
                "payments:charge",
                "admin:delete",
            }),
            source=final_step.delegated_authority.source,
        ),
        credential_type=final_step.credential_type,
        explicit=final_step.explicit,
    )

    result = DETECTOR.analyze(scenario)

    assert result.verdict == Verdict.DETECTED
    assert result.finding.finding_type == FindingType.UNAUTHORIZED_DELEGATION

    # The finding must preserve the actual operation's requirements.
    assert result.finding.required_authority == frozenset(
        {"payments:charge"}
    )
    assert result.details["required_action"] == ["payments:charge"]

    # The trusted grant permits payments:charge.
    # Only admin:delete should be reported as unauthorized.
    expansions = result.details["unauthorized_expansions"]

    assert len(expansions) == 1
    assert expansions[0]["permissions"] == ["admin:delete"]

def test_later_trusted_grant_does_not_hide_earlier_expansion():
    """A trusted later hop must not excuse an earlier unauthorized expansion."""
    policy = DelegationPolicy()
    policy.register(
        "checkout-svc",
        "payment-svc",
        {"payments:charge"},
    )
    detector = ConfusedDeputyDetector(delegation_policy=policy)

    scenario = legitimate_delegated_authorization()
    first_step = scenario.delegation_chain[1]

    # Introduce an unauthorized permission at agent -> checkout.
    scenario.delegation_chain[1] = DelegationStep(
        from_principal=first_step.from_principal,
        to_principal=first_step.to_principal,
        delegated_authority=Authority.delegated(
            "orders:read", "admin:delete"
        ),
        credential_type=first_step.credential_type,
        explicit=True,
    )

    result = detector.analyze(scenario)

    assert result.verdict == Verdict.DETECTED
    assert any(
        item["from_principal"] == first_step.from_principal.principal_id
        and "admin:delete" in item["permissions"]
        for item in result.details["unauthorized_expansions"]
    )


def test_missing_authority_is_reported_as_authorization_failure():
    scenario = AuthorizationScenario(
        trace_id="trace-no-authority",
        initiating_principal=USER_123,
        original_authority=Authority.original("orders:read"),
        delegation_chain=[],
        effective_operation=Operation(
            service="payment-svc",
            raw_span_name="oteldemo.PaymentService/Charge",
            semantic_action="payments:charge",
            target_resource=None,
            required_authority=frozenset({"payments:charge"}),
        ),
        acting_service_authority=Authority.service("orders:read"),
    )

    result = DETECTOR.analyze(scenario)

    assert result.verdict == Verdict.DETECTED
    assert "neither the delegated request authority" in result.reason
    assert result.finding.finding_type == FindingType.AUTHORIZATION_FAILURE


def test_neither_authority_has_required_permission():
    scenario = AuthorizationScenario(
        trace_id="trace-no-authority",
        initiating_principal=USER_123,
        original_authority=Authority.original("orders:read"),
        delegation_chain=[],
        effective_operation=Operation(
            service="payment-svc",
            raw_span_name="oteldemo.PaymentService/Charge",
            semantic_action="payments:charge",
            target_resource=None,
            required_authority=frozenset({"payments:charge"}),
        ),
        acting_service_authority=Authority.service("orders:read"),
    )

    result = DETECTOR.analyze(scenario)

    assert result.verdict == Verdict.DETECTED
    assert "neither the delegated request authority" in result.reason
    assert result.details["service_authority"] == ["orders:read"]


def test_restoring_removed_permission_without_grant_is_unauthorized():
    """A later hop cannot restore initially authorized but removed permission."""
    scenario = legitimate_delegated_authorization()
    scenario.original_authority = Authority.original(
        "orders:read", "admin:delete"
    )

    removal_step = scenario.delegation_chain[0]
    first_step = scenario.delegation_chain[1]
    second_step = scenario.delegation_chain[2]

    # User -> agent removes admin:delete from the known original authority.
    scenario.delegation_chain[0] = DelegationStep(
        from_principal=removal_step.from_principal,
        to_principal=removal_step.to_principal,
        delegated_authority=Authority.delegated("orders:read"),
        credential_type=removal_step.credential_type,
        explicit=True,
    )

    # Agent -> checkout keeps the permission removed.
    scenario.delegation_chain[1] = DelegationStep(
        from_principal=first_step.from_principal,
        to_principal=first_step.to_principal,
        delegated_authority=Authority.delegated("orders:read"),
        credential_type=first_step.credential_type,
        explicit=True,
    )

    # Checkout -> payment tries to restore admin:delete.
    scenario.delegation_chain[2] = DelegationStep(
        from_principal=second_step.from_principal,
        to_principal=second_step.to_principal,
        delegated_authority=Authority.delegated(
            "orders:read", "payments:charge", "admin:delete"
        ),
        credential_type=second_step.credential_type,
        explicit=True,
    )

    result = DETECTOR.analyze(scenario)

    assert "admin:delete" in scenario.original_authority.permissions
    assert all(
        "admin:delete" not in step.delegated_authority.permissions
        for step in scenario.delegation_chain[:2]
    )
    assert "admin:delete" in (
        scenario.delegation_chain[2].delegated_authority.permissions
    )
    assert result.verdict == Verdict.DETECTED
    assert result.finding.finding_type == FindingType.UNAUTHORIZED_DELEGATION
    assert any(
        item["from_principal"] == second_step.from_principal.principal_id
        and item["to_principal"] == second_step.to_principal.principal_id
        and "admin:delete" in item["permissions"]
        for item in result.details["unauthorized_expansions"]
    )
    assert all(
        "payments:charge" not in item["permissions"]
        for item in result.details["unauthorized_expansions"]
        if item["from_principal"] == second_step.from_principal.principal_id
        and item["to_principal"] == second_step.to_principal.principal_id
    )


def test_unknown_scope_hop_returns_insufficient_evidence():
    """Unknown delegated scopes must not silently authorize an action."""
    scenario = legitimate_delegated_authorization()
    step = scenario.delegation_chain[1]

    scenario.delegation_chain[1] = DelegationStep(
        from_principal=step.from_principal,
        to_principal=step.to_principal,
        delegated_authority=Authority.delegated("orders:read"),
        credential_type=step.credential_type,
        explicit=True,
        scopes_known=False,
    )

    result = DETECTOR.analyze(scenario)

    assert result.verdict == Verdict.INSUFFICIENT_EVIDENCE
    assert "agent-001 -> checkout-svc" in result.reason
    assert "scope evidence is missing or malformed" in result.reason


def test_unknown_scope_does_not_prove_later_permission_was_added():
    """Unknown prior scopes prevent attributing additions to a later hop."""
    scenario = legitimate_delegated_authorization()
    first_step = scenario.delegation_chain[1]
    second_step = scenario.delegation_chain[2]
    delegation_policy = DelegationPolicy()
    delegation_policy.register(
        first_step.from_principal.principal_id,
        first_step.to_principal.principal_id,
        {"payments:charge"},
    )
    delegation_policy.register(
        second_step.from_principal.principal_id,
        second_step.to_principal.principal_id,
        {"payments:charge"},
    )
    detector = ConfusedDeputyDetector(delegation_policy=delegation_policy)

    scenario.delegation_chain[1] = DelegationStep(
        from_principal=first_step.from_principal,
        to_principal=first_step.to_principal,
        delegated_authority=Authority.delegated("orders:read"),
        credential_type=first_step.credential_type,
        explicit=True,
        scopes_known=False,
    )

    scenario.delegation_chain[2] = DelegationStep(
        from_principal=second_step.from_principal,
        to_principal=second_step.to_principal,
        delegated_authority=Authority.delegated(
            "orders:read", "payments:charge", "admin:delete"
        ),
        credential_type=second_step.credential_type,
        explicit=True,
        scopes_known=True,
    )

    result = detector.analyze(scenario)

    assert result.verdict == Verdict.INSUFFICIENT_EVIDENCE
    assert result.finding.finding_type == FindingType.NONE
    assert "agent-001 -> checkout-svc" in result.reason
    assert "admin:delete" not in result.reason
    assert "unauthorized_expansions" not in result.details


def test_legitimate_delegated_permission_is_not_an_expansion():
    scenario = legitimate_delegated_authorization()

    result = DETECTOR.analyze(scenario)

    assert result.verdict == Verdict.NOT_DETECTED
    assert result.finding.finding_type == FindingType.NONE


def test_unknown_scopes_without_independent_violation_are_insufficient():
    scenario = legitimate_delegated_authorization()
    step = scenario.delegation_chain[1]

    scenario.delegation_chain[1] = DelegationStep(
        from_principal=step.from_principal,
        to_principal=step.to_principal,
        delegated_authority=Authority.empty(),
        credential_type=step.credential_type,
        explicit=True,
        scopes_known=False,
    )

    result = DETECTOR.analyze(scenario)

    assert result.verdict == Verdict.INSUFFICIENT_EVIDENCE
    assert result.finding.finding_type == FindingType.NONE


def test_implicit_delegation_does_not_inherit_permissions():
    scenario = legitimate_delegated_authorization()
    last_step = scenario.delegation_chain[-1]
    scenario.delegation_chain[-1] = DelegationStep(
        from_principal=last_step.from_principal,
        to_principal=last_step.to_principal,
        delegated_authority=last_step.delegated_authority,
        credential_type=last_step.credential_type,
        explicit=False,
    )

    result = DETECTOR.analyze(scenario)

    assert result.verdict == Verdict.INSUFFICIENT_EVIDENCE
    assert "delegation is not explicit" in result.reason


def test_identical_scenarios_produce_identical_results():
    scenario = legitimate_delegated_authorization()

    first = DETECTOR.analyze(scenario)
    second = DETECTOR.analyze(scenario)

    assert first.verdict == second.verdict
    assert first.reason == second.reason
    assert first.details == second.details
    assert first.finding == second.finding
