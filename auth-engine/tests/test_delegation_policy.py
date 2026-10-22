import pytest

from auth_engine.delegation_policy import DelegationPolicy


def test_registered_grant_permits_authorized_permission():
    policy = DelegationPolicy()
    policy.register("checkout", "payment", {"payments:charge"})

    assert policy.permits(
        "checkout", "payment", frozenset({"payments:charge"})
    )


def test_unregistered_edge_is_not_permitted():
    policy = DelegationPolicy()

    assert not policy.permits(
        "checkout", "payment", frozenset({"payments:charge"})
    )


def test_grant_does_not_permit_unlisted_permission():
    policy = DelegationPolicy()
    policy.register("checkout", "payment", {"payments:charge"})

    assert not policy.permits(
        "checkout", "payment", frozenset({"admin:delete"})
    )


def test_grant_does_not_apply_to_different_edge():
    policy = DelegationPolicy()
    policy.register("checkout", "payment", {"payments:charge"})

    assert not policy.permits(
        "agent", "payment", frozenset({"payments:charge"})
    )


@pytest.mark.parametrize(
    ("from_principal", "to_principal"),
    [("", "payment"), ("checkout", "")],
)
def test_empty_principal_is_rejected(from_principal, to_principal):
    policy = DelegationPolicy()

    with pytest.raises(ValueError):
        policy.register(from_principal, to_principal, {"payments:charge"})


def test_empty_grant_is_rejected():
    policy = DelegationPolicy()

    with pytest.raises(ValueError):
        policy.register("checkout", "payment", set())
