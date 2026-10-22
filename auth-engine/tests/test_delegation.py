"""Tests for auth_engine.delegation — chain walking and authority propagation."""

from auth_engine.delegation import (
    authority_at_each_hop,
    build_attack_path,
    compute_request_authority,
)
from auth_engine.models import (
    Authority,
    AuthoritySource,
    CredentialType,
    DelegationStep,
    Identity,
    PrincipalType,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

USER = Identity("user-1", PrincipalType.USER)
AGENT = Identity("agent-1", PrincipalType.AGENT, "ai-agent")
CHECKOUT = Identity("svc-checkout", PrincipalType.SERVICE, "checkout")
PAYMENT = Identity("svc-payment", PrincipalType.SERVICE, "payment")


# ---------------------------------------------------------------------------
# compute_request_authority
# ---------------------------------------------------------------------------


class TestComputeRequestAuthority:
    def test_empty_chain_returns_original(self):
        orig = Authority.original("orders:read")
        result = compute_request_authority(orig, [])
        assert result.permissions == frozenset({"orders:read"})
        assert result.source == AuthoritySource.DELEGATED

    def test_single_hop_narrows(self):
        orig = Authority.original("orders:read", "payments:charge")
        chain = [
            DelegationStep(
                from_principal=USER,
                to_principal=CHECKOUT,
                delegated_authority=Authority.delegated("orders:read"),
                credential_type=CredentialType.USER_TOKEN,
            ),
        ]
        result = compute_request_authority(orig, chain)
        assert result.permissions == frozenset({"orders:read"})

    def test_single_hop_widens_via_explicit_delegation(self):
        orig = Authority.original("orders:read")
        chain = [
            DelegationStep(
                from_principal=USER,
                to_principal=CHECKOUT,
                delegated_authority=Authority.delegated(
                    "orders:read", "payments:charge"
                ),
                credential_type=CredentialType.DELEGATED_TOKEN,
                explicit=True,
            ),
        ]
        result = compute_request_authority(orig, chain)
        assert "payments:charge" in result.permissions

    def test_each_explicit_hop_replaces_current_authority(self):
        orig = Authority.original("orders:read")
        chain = [
            DelegationStep(
                from_principal=USER,
                to_principal=CHECKOUT,
                delegated_authority=Authority.delegated(
                    "orders:read", "payments:charge"
                ),
                credential_type=CredentialType.DELEGATED_TOKEN,
                explicit=True,
            ),
            DelegationStep(
                from_principal=CHECKOUT,
                to_principal=PAYMENT,
                delegated_authority=Authority.delegated("payments:charge"),
                credential_type=CredentialType.DELEGATED_TOKEN,
                explicit=True,
            ),
        ]

        result = compute_request_authority(orig, chain)

        assert result.permissions == frozenset({"payments:charge"})
        assert result.source == AuthoritySource.DELEGATED

    def test_multi_hop_carries_forward(self):
        orig = Authority.original("orders:read", "payments:charge")
        chain = [
            DelegationStep(
                from_principal=USER,
                to_principal=AGENT,
                delegated_authority=Authority.delegated(
                    "orders:read", "payments:charge"
                ),
                credential_type=CredentialType.USER_TOKEN,
            ),
            DelegationStep(
                from_principal=AGENT,
                to_principal=CHECKOUT,
                delegated_authority=Authority.delegated(
                    "orders:read", "payments:charge"
                ),
                credential_type=CredentialType.DELEGATED_TOKEN,
            ),
            DelegationStep(
                from_principal=CHECKOUT,
                to_principal=PAYMENT,
                delegated_authority=Authority.delegated("payments:charge"),
                credential_type=CredentialType.DELEGATED_TOKEN,
            ),
        ]
        result = compute_request_authority(orig, chain)
        assert result.permissions == frozenset({"payments:charge"})

    def test_implicit_step_preserves_current(self):
        orig = Authority.original("orders:read")
        chain = [
            DelegationStep(
                from_principal=USER,
                to_principal=AGENT,
                delegated_authority=Authority.delegated("orders:read"),
                credential_type=CredentialType.USER_TOKEN,
                explicit=True,
            ),
            DelegationStep(
                from_principal=AGENT,
                to_principal=CHECKOUT,
                delegated_authority=Authority.delegated("something:else"),
                credential_type=CredentialType.DELEGATED_TOKEN,
                explicit=False,  # implicit — should NOT override
            ),
        ]
        result = compute_request_authority(orig, chain)
        # Implicit step does not change authority
        assert result.permissions == frozenset({"orders:read"})


# ---------------------------------------------------------------------------
# build_attack_path
# ---------------------------------------------------------------------------


class TestBuildAttackPath:
    def test_empty_chain(self):
        path = build_attack_path(USER, [])
        assert path == ["user:user-1"]

    def test_with_chain(self):
        chain = [
            DelegationStep(
                from_principal=USER,
                to_principal=AGENT,
                delegated_authority=Authority.delegated("orders:read"),
                credential_type=CredentialType.USER_TOKEN,
            ),
        ]
        path = build_attack_path(USER, chain)
        assert len(path) == 2
        assert path[0] == "user:user-1"
        assert "user:user-1" in path[1]
        assert "agent:agent-1@ai-agent" in path[1]

    def test_none_principal(self):
        path = build_attack_path(None, [])
        assert path == []


# ---------------------------------------------------------------------------
# authority_at_each_hop
# ---------------------------------------------------------------------------


class TestAuthorityAtEachHop:
    def test_single_hop(self):
        orig = Authority.original("orders:read")
        chain = [
            DelegationStep(
                from_principal=USER,
                to_principal=CHECKOUT,
                delegated_authority=Authority.delegated("orders:read"),
                credential_type=CredentialType.USER_TOKEN,
            ),
        ]
        hops = authority_at_each_hop(orig, chain)
        assert len(hops) == 1
        principal, auth = hops[0]
        assert principal == CHECKOUT
        assert auth.permissions == frozenset({"orders:read"})

    def test_multi_hop(self):
        orig = Authority.original("a", "b")
        chain = [
            DelegationStep(
                from_principal=USER,
                to_principal=AGENT,
                delegated_authority=Authority.delegated("a", "b"),
                credential_type=CredentialType.USER_TOKEN,
            ),
            DelegationStep(
                from_principal=AGENT,
                to_principal=CHECKOUT,
                delegated_authority=Authority.delegated("a"),
                credential_type=CredentialType.DELEGATED_TOKEN,
            ),
        ]
        hops = authority_at_each_hop(orig, chain)
        assert len(hops) == 2
        assert hops[0][1].permissions == frozenset({"a", "b"})
        assert hops[1][1].permissions == frozenset({"a"})

    def test_empty_chain(self):
        orig = Authority.original("x")
        hops = authority_at_each_hop(orig, [])
        assert hops == []
