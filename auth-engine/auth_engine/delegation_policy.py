"""Trusted policy registry for permission expansions during delegation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DelegationGrant:
    """An explicitly authorized permission grant for one delegation edge."""

    from_principal: str
    to_principal: str
    permissions: frozenset[str]


class DelegationPolicy:
    """Registry of trusted permission grants for specific delegation edges."""

    def __init__(self) -> None:
        self._grants: dict[tuple[str, str], frozenset[str]] = {}

    def register(
        self,
        from_principal: str,
        to_principal: str,
        permissions: set[str] | frozenset[str] | list[str],
    ) -> None:
        """Register permissions trusted for a specific delegation edge."""
        if not from_principal or not to_principal:
            raise ValueError("Principal identifiers must not be empty")

        grant = frozenset(permissions)
        if not grant:
            raise ValueError("A delegation grant must contain at least one permission")

        self._grants[(from_principal, to_principal)] = grant

    def permits(
        self,
        from_principal: str,
        to_principal: str,
        permissions: frozenset[str] | set[str],
    ) -> bool:
        """Return whether the trusted registry authorizes every requested permission."""
        grant = self._grants.get((from_principal, to_principal))
        return grant is not None and frozenset(permissions) <= grant
