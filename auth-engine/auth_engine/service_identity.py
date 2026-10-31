"""Identity matching for services named by authorization scenarios."""

from __future__ import annotations

from collections.abc import Iterable

from .models import Identity, PrincipalType


def identifies_service(
    identity: Identity,
    service_name: str,
    known_identities: Iterable[Identity] = (),
) -> bool:
    """Return whether identity evidence ties a principal to a service name."""
    if (
        not identity.principal_id.strip()
        or not service_name.strip()
        or identity.principal_type is not PrincipalType.SERVICE
        or (
            identity.service_name is not None
            and not identity.service_name.strip()
        )
    ):
        return False

    known = tuple(known_identities)
    related = [
        identity,
        *(
            candidate
            for candidate in known
            if candidate.principal_id == identity.principal_id
        ),
    ]
    if any(
        candidate.principal_type is not PrincipalType.SERVICE
        or (
            candidate.service_name is not None
            and not candidate.service_name.strip()
        )
        for candidate in related
    ):
        return False

    service_names = {
        candidate.service_name
        for candidate in related
        if candidate.service_name
    }
    if len(service_names) > 1 or any(
        candidate.principal_id != identity.principal_id
        and candidate.principal_type is PrincipalType.SERVICE
        and candidate.service_name == service_name
        for candidate in known
    ):
        return False
    if service_names:
        return service_name in service_names
    return identity.principal_id == service_name
