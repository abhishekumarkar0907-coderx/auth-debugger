"""Tests for auth_engine.models — construction, equality, and helpers."""

from auth_engine.models import (
    Authority,
    AuthoritySource,
    AuthorizationEvent,
    AuthorizationScenario,
    CredentialType,
    DelegationStep,
    DetectionResult,
    Finding,
    FindingType,
    Identity,
    Operation,
    PrincipalType,
    Severity,
    Verdict,
)


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


class TestIdentity:
    def test_creation(self):
        ident = Identity(
            principal_id="user-123",
            principal_type=PrincipalType.USER,
        )
        assert ident.principal_id == "user-123"
        assert ident.principal_type == PrincipalType.USER
        assert ident.service_name is None

    def test_creation_with_service(self):
        ident = Identity(
            principal_id="svc-001",
            principal_type=PrincipalType.SERVICE,
            service_name="payment",
        )
        assert ident.service_name == "payment"

    def test_str_user(self):
        ident = Identity("user-1", PrincipalType.USER)
        assert str(ident) == "user:user-1"

    def test_str_service(self):
        ident = Identity("svc-1", PrincipalType.SERVICE, "checkout")
        assert str(ident) == "service:svc-1@checkout"

    def test_frozen(self):
        ident = Identity("u", PrincipalType.USER)
        try:
            ident.principal_id = "changed"  # type: ignore[misc]
            assert False, "Should be frozen"
        except AttributeError:
            pass

    def test_equality(self):
        a = Identity("u1", PrincipalType.USER)
        b = Identity("u1", PrincipalType.USER)
        assert a == b

    def test_hashable(self):
        a = Identity("u1", PrincipalType.USER)
        assert hash(a) is not None
        s = {a, a}
        assert len(s) == 1


# ---------------------------------------------------------------------------
# Authority
# ---------------------------------------------------------------------------


class TestAuthority:
    def test_original_factory(self):
        auth = Authority.original("orders:read", "payments:charge")
        assert auth.source == AuthoritySource.ORIGINAL
        assert auth.permissions == frozenset({"orders:read", "payments:charge"})

    def test_delegated_factory(self):
        auth = Authority.delegated("orders:read")
        assert auth.source == AuthoritySource.DELEGATED

    def test_service_factory(self):
        auth = Authority.service("payments:charge")
        assert auth.source == AuthoritySource.SERVICE

    def test_contains(self):
        auth = Authority.original("orders:read", "payments:charge")
        assert auth.contains("orders:read")
        assert not auth.contains("admin:delete")

    def test_contains_all(self):
        auth = Authority.original("a", "b", "c")
        assert auth.contains_all(frozenset({"a", "b"}))
        assert not auth.contains_all(frozenset({"a", "d"}))

    def test_union(self):
        a = Authority.delegated("orders:read")
        b = Authority.delegated("payments:charge")
        merged = a.union(b)
        assert merged.permissions == frozenset({"orders:read", "payments:charge"})
        assert merged.source == AuthoritySource.DELEGATED

    def test_intersect(self):
        a = Authority.delegated("orders:read", "payments:charge")
        b = Authority.delegated("payments:charge", "admin:delete")
        result = a.intersect(b)
        assert result.permissions == frozenset({"payments:charge"})

    def test_empty(self):
        e = Authority.empty()
        assert len(e.permissions) == 0
        assert e.source == AuthoritySource.DELEGATED

    def test_frozen(self):
        auth = Authority.original("x")
        try:
            auth.permissions = frozenset({"y"})  # type: ignore[misc]
            assert False, "Should be frozen"
        except AttributeError:
            pass


# ---------------------------------------------------------------------------
# DelegationStep
# ---------------------------------------------------------------------------


class TestDelegationStep:
    def test_creation(self):
        step = DelegationStep(
            from_principal=Identity("u1", PrincipalType.USER),
            to_principal=Identity("s1", PrincipalType.SERVICE, "checkout"),
            delegated_authority=Authority.delegated("orders:read"),
            credential_type=CredentialType.USER_TOKEN,
            explicit=True,
        )
        assert step.from_principal.principal_id == "u1"
        assert step.to_principal.service_name == "checkout"
        assert step.credential_type == CredentialType.USER_TOKEN
        assert step.explicit is True

    def test_defaults(self):
        step = DelegationStep(
            from_principal=Identity("u1", PrincipalType.USER),
            to_principal=Identity("s1", PrincipalType.SERVICE),
            delegated_authority=Authority.delegated("x"),
        )
        assert step.credential_type == CredentialType.UNKNOWN
        assert step.explicit is True


# ---------------------------------------------------------------------------
# Operation
# ---------------------------------------------------------------------------


class TestOperation:
    def test_creation(self):
        op = Operation(
            service="payment",
            raw_span_name="oteldemo.PaymentService/Charge",
            semantic_action="payments:charge",
            required_authority=frozenset({"payments:charge"}),
        )
        assert op.service == "payment"
        assert op.semantic_action == "payments:charge"
        assert "payments:charge" in op.required_authority

    def test_minimal(self):
        op = Operation(service="unknown")
        assert op.raw_span_name is None
        assert op.semantic_action is None
        assert len(op.required_authority) == 0


# ---------------------------------------------------------------------------
# AuthorizationEvent
# ---------------------------------------------------------------------------


class TestAuthorizationEvent:
    def test_creation(self):
        evt = AuthorizationEvent(
            trace_id="t1",
            span_id="s1",
            parent_span_id="s0",
        )
        assert evt.trace_id == "t1"
        assert evt.initiating_principal is None
        assert evt.evidence == {}


# ---------------------------------------------------------------------------
# AuthorizationScenario
# ---------------------------------------------------------------------------


class TestAuthorizationScenario:
    def test_creation(self):
        scenario = AuthorizationScenario(trace_id="t1")
        assert scenario.delegation_chain == []
        assert scenario.evidence == {}

    def test_with_full_data(self):
        scenario = AuthorizationScenario(
            trace_id="t1",
            initiating_principal=Identity("u1", PrincipalType.USER),
            original_authority=Authority.original("orders:read"),
            delegation_chain=[],
            effective_operation=Operation(service="x"),
        )
        assert scenario.initiating_principal is not None
        assert scenario.original_authority is not None


# ---------------------------------------------------------------------------
# Verdict & Severity enums
# ---------------------------------------------------------------------------


class TestEnums:
    def test_verdict_values(self):
        assert Verdict.DETECTED.value == "DETECTED"
        assert Verdict.NOT_DETECTED.value == "NOT_DETECTED"
        assert Verdict.INSUFFICIENT_EVIDENCE.value == "INSUFFICIENT_EVIDENCE"

    def test_severity_values(self):
        assert Severity.HIGH.value == "HIGH"
        assert Severity.UNSCORED.value == "UNSCORED"

    def test_principal_type(self):
        assert PrincipalType.USER.value == "user"
        assert PrincipalType.AGENT.value == "agent"
        assert PrincipalType.SERVICE.value == "service"

    def test_authority_source(self):
        assert AuthoritySource.ORIGINAL.value == "original"
        assert AuthoritySource.DELEGATED.value == "delegated"
        assert AuthoritySource.SERVICE.value == "service"

    def test_credential_type(self):
        assert CredentialType.USER_TOKEN.value == "user_token"
        assert CredentialType.SERVICE_CREDENTIAL.value == "service_credential"


# ---------------------------------------------------------------------------
# Finding & DetectionResult
# ---------------------------------------------------------------------------


class TestFinding:
    def test_defaults(self):
        f = Finding()
        assert f.verdict == Verdict.INSUFFICIENT_EVIDENCE
        assert f.finding_id  # UUID auto-generated
        assert f.reason == ""
        assert f.severity == Severity.UNSCORED
        assert f.finding_type == FindingType.NONE

    def test_with_values(self):
        f = Finding(
            verdict=Verdict.DETECTED,
            reason="test reason",
            severity=Severity.HIGH,
        )
        assert f.verdict == Verdict.DETECTED
        assert f.reason == "test reason"


class TestDetectionResult:
    def test_creation(self):
        r = DetectionResult(
            verdict=Verdict.NOT_DETECTED,
            finding=Finding(),
            reason="all good",
        )
        assert r.verdict == Verdict.NOT_DETECTED
        assert r.reason == "all good"
        assert r.details == {}
