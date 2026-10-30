"""
Delegation-chain analysis.

Walks an ordered list of ``DelegationStep`` objects and computes the
**request authority** legitimately available at each hop.

Key rule:
    At every hop the request authority is the authority that was *explicitly
    delegated* to that hop.  A receiving service's own broader privileges
    never silently enlarge the request authority.
"""

from __future__ import annotations

from .models import (
    Authority,
    AuthoritySource,
    AuthorizationScenario,
    DelegationStep,
    Identity,
)


def compute_request_authority(
    original_authority: Authority,
    delegation_chain: list[DelegationStep],
) -> Authority | None:
    """
    Walk the delegation chain and return the request authority available
    at the *final* hop.

    Algorithm:
        1. Start with the initiating principal's original authority.
        2. At each delegation step the new request authority is the
           authority explicitly delegated in that step.
        3. If a step delegates authority that was *not* present in the
           previous request authority, it is an **explicit delegation
           addition** (e.g. a service adds ``payments:charge`` because
           the delegation policy says so).
        4. A step with unknown scopes or an implicit edge makes the current
           authority unknown; permissions do not propagate without explicit
           delegation evidence.
        5. Return the authority declared at the last known explicit hop, or
           ``None`` when the final authority cannot be established.

    If the delegation chain is empty the original authority is returned
    (tagged as DELEGATED so downstream comparisons work uniformly).
    """
    if not delegation_chain:
        return Authority(
            permissions=original_authority.permissions,
            source=AuthoritySource.DELEGATED,
        )

    current: Authority | None = Authority(
        permissions=original_authority.permissions,
        source=AuthoritySource.DELEGATED,
    )

    for step in delegation_chain:
        if step.explicit and step.scopes_known:
            # The delegated authority at this step becomes the new
            # request authority.  Authority may be narrowed OR
            # widened by explicit delegation.
            current = Authority(
                permissions=step.delegated_authority.permissions,
                source=AuthoritySource.DELEGATED,
            )
        else:
            current = None

    return current


def build_attack_path(
    initiating_principal: Identity | None,
    delegation_chain: list[DelegationStep],
) -> list[str]:
    """
    Build a human-readable list of hop descriptions for the attack path.
    """
    path: list[str] = []
    if initiating_principal:
        path.append(str(initiating_principal))

    for step in delegation_chain:
        if not step.explicit or not step.scopes_known:
            perms = "unknown"
        else:
            perms = ", ".join(sorted(step.delegated_authority.permissions)) or "(none)"
        label = (
            f"{step.from_principal} → {step.to_principal} "
            f"[{step.credential_type.value}] "
            f"delegated=[{perms}]"
        )
        path.append(label)

    return path


def authority_at_each_hop(
    original_authority: Authority,
    delegation_chain: list[DelegationStep],
) -> list[tuple[Identity, Authority | None]]:
    """
    Return the request authority available *to* each principal in the
    delegation chain. Unknown scope evidence or an implicit edge has no
    established request authority and is represented by ``None``. Useful
    for auditing and explanation.
    """
    result: list[tuple[Identity, Authority | None]] = []

    current: Authority | None = Authority(
        permissions=original_authority.permissions,
        source=AuthoritySource.DELEGATED,
    )

    for step in delegation_chain:
        if step.explicit and step.scopes_known:
            current = Authority(
                permissions=step.delegated_authority.permissions,
                source=AuthoritySource.DELEGATED,
            )
        else:
            current = None
        result.append((step.to_principal, current))

    return result
