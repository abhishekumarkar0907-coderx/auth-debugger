"""
Test fixtures for the authorization-analysis engine.

Each fixture builds a complete ``AuthorizationScenario`` representing a
real-world authorization flow.  These are used by test_detector.py.
"""

from __future__ import annotations

from auth_engine.models import (
    Authority,
    AuthoritySource,
    AuthorizationScenario,
    CredentialType,
    DelegationStep,
    Identity,
    Operation,
    PrincipalType,
    Verdict,
)

# ---------------------------------------------------------------------------
# Shared identities
# ---------------------------------------------------------------------------

USER_123 = Identity(
    principal_id="user-123",
    principal_type=PrincipalType.USER,
)

AGENT = Identity(
    principal_id="agent-001",
    principal_type=PrincipalType.AGENT,
    service_name="ai-support-agent",
)

CHECKOUT_SERVICE = Identity(
    principal_id="checkout-svc",
    principal_type=PrincipalType.SERVICE,
    service_name="checkout",
)

PAYMENT_SERVICE = Identity(
    principal_id="payment-svc",
    principal_type=PrincipalType.SERVICE,
    service_name="payment",
)

ORDER_SERVICE = Identity(
    principal_id="order-svc",
    principal_type=PrincipalType.SERVICE,
    service_name="order",
)


# ---------------------------------------------------------------------------
# 1. GOLDEN CONFUSED DEPUTY  (DETECTED)
# ---------------------------------------------------------------------------

def golden_confused_deputy() -> AuthorizationScenario:
    """
    The canonical confused-deputy scenario.

    User has ``orders:read``.
    Payment service has ``payments:charge`` (service-level).
    No ``payments:charge`` was delegated through the request chain.
    The downstream action requires ``payments:charge``.

    Expected: DETECTED
    """
    return AuthorizationScenario(
        trace_id="trace-golden-001",
        initiating_principal=USER_123,
        original_authority=Authority.original("orders:read"),
        delegation_chain=[
            DelegationStep(
                from_principal=USER_123,
                to_principal=AGENT,
                delegated_authority=Authority.delegated("orders:read"),
                credential_type=CredentialType.USER_TOKEN,
            ),
            DelegationStep(
                from_principal=AGENT,
                to_principal=CHECKOUT_SERVICE,
                delegated_authority=Authority.delegated("orders:read"),
                credential_type=CredentialType.DELEGATED_TOKEN,
            ),
            DelegationStep(
                from_principal=CHECKOUT_SERVICE,
                to_principal=PAYMENT_SERVICE,
                delegated_authority=Authority.delegated("orders:read"),
                credential_type=CredentialType.SERVICE_CREDENTIAL,
            ),
        ],
        effective_operation=Operation(
            service="payment",
            raw_span_name="oteldemo.PaymentService/Charge",
            semantic_action="payments:charge",
            required_authority=frozenset({"payments:charge"}),
        ),
        acting_service_authority=Authority.service("payments:charge"),
        evidence={"fixture": "golden_confused_deputy"},
    )


# ---------------------------------------------------------------------------
# 2. LEGITIMATE DIRECT AUTHORIZATION  (NOT_DETECTED)
# ---------------------------------------------------------------------------

def legitimate_direct_authorization() -> AuthorizationScenario:
    """
    User has ``orders:read`` AND ``payments:charge``.
    Authority is properly delegated through the chain.

    Expected: NOT_DETECTED
    """
    return AuthorizationScenario(
        trace_id="trace-legit-001",
        initiating_principal=USER_123,
        original_authority=Authority.original("orders:read", "payments:charge"),
        delegation_chain=[
            DelegationStep(
                from_principal=USER_123,
                to_principal=AGENT,
                delegated_authority=Authority.delegated(
                    "orders:read", "payments:charge"
                ),
                credential_type=CredentialType.USER_TOKEN,
            ),
            DelegationStep(
                from_principal=AGENT,
                to_principal=CHECKOUT_SERVICE,
                delegated_authority=Authority.delegated(
                    "orders:read", "payments:charge"
                ),
                credential_type=CredentialType.DELEGATED_TOKEN,
            ),
            DelegationStep(
                from_principal=CHECKOUT_SERVICE,
                to_principal=PAYMENT_SERVICE,
                delegated_authority=Authority.delegated("payments:charge"),
                credential_type=CredentialType.DELEGATED_TOKEN,
            ),
        ],
        effective_operation=Operation(
            service="payment",
            raw_span_name="oteldemo.PaymentService/Charge",
            semantic_action="payments:charge",
            required_authority=frozenset({"payments:charge"}),
        ),
        acting_service_authority=Authority.service("payments:charge"),
        evidence={"fixture": "legitimate_direct_authorization"},
    )


# ---------------------------------------------------------------------------
# 3. LEGITIMATE DELEGATED AUTHORIZATION  (NOT_DETECTED)
# ---------------------------------------------------------------------------

def legitimate_delegated_authorization() -> AuthorizationScenario:
    """
    User has only ``orders:read``, but ``payments:charge`` is explicitly
    delegated at the checkout → payment hop.

    Expected: NOT_DETECTED
    """
    return AuthorizationScenario(
        trace_id="trace-delegated-001",
        initiating_principal=USER_123,
        original_authority=Authority.original("orders:read"),
        delegation_chain=[
            DelegationStep(
                from_principal=USER_123,
                to_principal=AGENT,
                delegated_authority=Authority.delegated("orders:read"),
                credential_type=CredentialType.USER_TOKEN,
            ),
            DelegationStep(
                from_principal=AGENT,
                to_principal=CHECKOUT_SERVICE,
                delegated_authority=Authority.delegated("orders:read"),
                credential_type=CredentialType.DELEGATED_TOKEN,
            ),
            DelegationStep(
                from_principal=CHECKOUT_SERVICE,
                to_principal=PAYMENT_SERVICE,
                delegated_authority=Authority.delegated(
                    "orders:read", "payments:charge"
                ),
                credential_type=CredentialType.DELEGATED_TOKEN,
                explicit=True,
            ),
        ],
        effective_operation=Operation(
            service="payment",
            raw_span_name="oteldemo.PaymentService/Charge",
            semantic_action="payments:charge",
            required_authority=frozenset({"payments:charge"}),
        ),
        acting_service_authority=Authority.service("payments:charge"),
        evidence={"fixture": "legitimate_delegated_authorization"},
    )


# ---------------------------------------------------------------------------
# 4. MULTI-HOP VALID DELEGATION  (NOT_DETECTED)
# ---------------------------------------------------------------------------

def multi_hop_valid_delegation() -> AuthorizationScenario:
    """
    User has ``orders:read`` and ``payments:charge``.
    Authority is propagated correctly across 4 hops:
    User → Agent → Checkout → Payment.

    Expected: NOT_DETECTED
    """
    return AuthorizationScenario(
        trace_id="trace-multihop-001",
        initiating_principal=USER_123,
        original_authority=Authority.original("orders:read", "payments:charge"),
        delegation_chain=[
            DelegationStep(
                from_principal=USER_123,
                to_principal=AGENT,
                delegated_authority=Authority.delegated(
                    "orders:read", "payments:charge"
                ),
                credential_type=CredentialType.USER_TOKEN,
            ),
            DelegationStep(
                from_principal=AGENT,
                to_principal=CHECKOUT_SERVICE,
                delegated_authority=Authority.delegated(
                    "orders:read", "payments:charge"
                ),
                credential_type=CredentialType.DELEGATED_TOKEN,
            ),
            DelegationStep(
                from_principal=CHECKOUT_SERVICE,
                to_principal=PAYMENT_SERVICE,
                delegated_authority=Authority.delegated("payments:charge"),
                credential_type=CredentialType.DELEGATED_TOKEN,
            ),
        ],
        effective_operation=Operation(
            service="payment",
            raw_span_name="oteldemo.PaymentService/Charge",
            semantic_action="payments:charge",
            required_authority=frozenset({"payments:charge"}),
        ),
        acting_service_authority=Authority.service("payments:charge"),
        evidence={"fixture": "multi_hop_valid_delegation"},
    )


# ---------------------------------------------------------------------------
# 5. SERVICE PRIVILEGE EXCEEDS REQUEST AUTHORITY  (DETECTED)
# ---------------------------------------------------------------------------

def service_privilege_exceeds_request() -> AuthorizationScenario:
    """
    Service has ``payments:charge``.
    Request only has ``orders:read``.
    Service credential used.

    Expected: DETECTED
    """
    return AuthorizationScenario(
        trace_id="trace-svcpriv-001",
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
            semantic_action="payments:charge",
            required_authority=frozenset({"payments:charge"}),
        ),
        acting_service_authority=Authority.service("payments:charge"),
        evidence={"fixture": "service_privilege_exceeds_request"},
    )


# ---------------------------------------------------------------------------
# 6. MISSING INITIATING IDENTITY  (INSUFFICIENT_EVIDENCE)
# ---------------------------------------------------------------------------

def missing_initiating_identity() -> AuthorizationScenario:
    """
    Initiating principal is None.

    Expected: INSUFFICIENT_EVIDENCE
    """
    return AuthorizationScenario(
        trace_id="trace-missing-id-001",
        initiating_principal=None,
        original_authority=Authority.original("orders:read"),
        effective_operation=Operation(
            service="payment",
            semantic_action="payments:charge",
            required_authority=frozenset({"payments:charge"}),
        ),
        evidence={"fixture": "missing_initiating_identity"},
    )


# ---------------------------------------------------------------------------
# 7. MISSING ORIGINAL AUTHORITY  (INSUFFICIENT_EVIDENCE)
# ---------------------------------------------------------------------------

def missing_original_authority() -> AuthorizationScenario:
    """
    Original authority is None.

    Expected: INSUFFICIENT_EVIDENCE
    """
    return AuthorizationScenario(
        trace_id="trace-missing-auth-001",
        initiating_principal=USER_123,
        original_authority=None,
        effective_operation=Operation(
            service="payment",
            semantic_action="payments:charge",
            required_authority=frozenset({"payments:charge"}),
        ),
        evidence={"fixture": "missing_original_authority"},
    )


# ---------------------------------------------------------------------------
# 8. MISSING ACTION REQUIREMENT  (INSUFFICIENT_EVIDENCE)
# ---------------------------------------------------------------------------

def missing_action_requirement() -> AuthorizationScenario:
    """
    Effective operation has no semantic action, raw span name, or
    explicit required authority — we cannot determine what is needed.

    Expected: INSUFFICIENT_EVIDENCE
    """
    return AuthorizationScenario(
        trace_id="trace-missing-action-001",
        initiating_principal=USER_123,
        original_authority=Authority.original("orders:read"),
        effective_operation=Operation(
            service="payment",
            # No semantic_action, no raw_span_name, no required_authority
        ),
        evidence={"fixture": "missing_action_requirement"},
    )


# ---------------------------------------------------------------------------
# 9. UNRELATED DOWNSTREAM OPERATION  (NOT_DETECTED)
# ---------------------------------------------------------------------------

def unrelated_downstream_operation() -> AuthorizationScenario:
    """
    User has ``orders:read``, and the downstream operation is
    ``products:read`` — entirely within the user's authority.

    Expected: NOT_DETECTED
    """
    return AuthorizationScenario(
        trace_id="trace-unrelated-001",
        initiating_principal=USER_123,
        original_authority=Authority.original("orders:read", "products:read"),
        delegation_chain=[
            DelegationStep(
                from_principal=USER_123,
                to_principal=ORDER_SERVICE,
                delegated_authority=Authority.delegated(
                    "orders:read", "products:read"
                ),
                credential_type=CredentialType.USER_TOKEN,
            ),
        ],
        effective_operation=Operation(
            service="product-catalog",
            raw_span_name="oteldemo.ProductCatalogService/GetProduct",
            semantic_action="products:read",
            required_authority=frozenset({"products:read"}),
        ),
        evidence={"fixture": "unrelated_downstream_operation"},
    )


# ---------------------------------------------------------------------------
# 10. MISSING EFFECTIVE OPERATION  (INSUFFICIENT_EVIDENCE)
# ---------------------------------------------------------------------------

def missing_effective_operation() -> AuthorizationScenario:
    """
    Effective operation is None.

    Expected: INSUFFICIENT_EVIDENCE
    """
    return AuthorizationScenario(
        trace_id="trace-missing-op-001",
        initiating_principal=USER_123,
        original_authority=Authority.original("orders:read"),
        effective_operation=None,
        evidence={"fixture": "missing_effective_operation"},
    )


# ---------------------------------------------------------------------------
# 11. NO DELEGATION CHAIN — DIRECT CALL (NOT_DETECTED)
# ---------------------------------------------------------------------------

def direct_call_authorized() -> AuthorizationScenario:
    """
    User directly calls a service with no intermediary delegation.
    User has the required authority.

    Expected: NOT_DETECTED
    """
    return AuthorizationScenario(
        trace_id="trace-direct-001",
        initiating_principal=USER_123,
        original_authority=Authority.original("orders:read"),
        delegation_chain=[],
        effective_operation=Operation(
            service="order",
            semantic_action="orders:read",
            required_authority=frozenset({"orders:read"}),
        ),
        evidence={"fixture": "direct_call_authorized"},
    )


# ---------------------------------------------------------------------------
# Fixture registry
# ---------------------------------------------------------------------------

ALL_FIXTURES: dict[str, tuple[callable, Verdict]] = {
    "golden_confused_deputy": (golden_confused_deputy, Verdict.DETECTED),
    "legitimate_direct_authorization": (
        legitimate_direct_authorization,
        Verdict.NOT_DETECTED,
    ),
    "legitimate_delegated_authorization": (
        legitimate_delegated_authorization,
        Verdict.NOT_DETECTED,
    ),
    "multi_hop_valid_delegation": (
        multi_hop_valid_delegation,
        Verdict.NOT_DETECTED,
    ),
    "service_privilege_exceeds_request": (
        service_privilege_exceeds_request,
        Verdict.DETECTED,
    ),
    "missing_initiating_identity": (
        missing_initiating_identity,
        Verdict.INSUFFICIENT_EVIDENCE,
    ),
    "missing_original_authority": (
        missing_original_authority,
        Verdict.INSUFFICIENT_EVIDENCE,
    ),
    "missing_action_requirement": (
        missing_action_requirement,
        Verdict.INSUFFICIENT_EVIDENCE,
    ),
    "unrelated_downstream_operation": (
        unrelated_downstream_operation,
        Verdict.NOT_DETECTED,
    ),
    "missing_effective_operation": (
        missing_effective_operation,
        Verdict.INSUFFICIENT_EVIDENCE,
    ),
    "direct_call_authorized": (
        direct_call_authorized,
        Verdict.NOT_DETECTED,
    ),
}
