"""
Core data models for the authorization-analysis engine.

All models are plain dataclasses with no dependency on web frameworks,
databases, or ML libraries.  They represent the authorization concepts
needed to reason about confused-deputy conditions.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class PrincipalType(enum.Enum):
    """Type of a security principal."""

    USER = "user"
    SERVICE = "service"
    AGENT = "agent"  # e.g. AI / support agent intermediary


class CredentialType(enum.Enum):
    """How authority was conveyed at a delegation hop."""

    USER_TOKEN = "user_token"
    SERVICE_CREDENTIAL = "service_credential"
    DELEGATED_TOKEN = "delegated_token"
    API_KEY = "api_key"
    UNKNOWN = "unknown"


class Verdict(enum.Enum):
    """Deterministic security verdict produced by the detector."""

    DETECTED = "DETECTED"
    NOT_DETECTED = "NOT_DETECTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class FindingType(enum.Enum):
    """Classification of the authorization finding."""

    CONFUSED_DEPUTY = "CONFUSED_DEPUTY"
    UNAUTHORIZED_DELEGATION = "UNAUTHORIZED_DELEGATION"
    AUTHORIZATION_FAILURE = "AUTHORIZATION_FAILURE"
    NONE = "NONE"


class Severity(enum.Enum):
    """Placeholder severity for future policy-driven scoring."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNSCORED = "UNSCORED"


class AuthoritySource(enum.Enum):
    """Where a set of permissions originates."""

    ORIGINAL = "original"       # Belongs to the initiating principal
    DELEGATED = "delegated"     # Explicitly delegated along the request chain
    SERVICE = "service"         # Belongs to the acting service itself


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Identity:
    """A security principal — a user, service, or agent."""

    principal_id: str
    principal_type: PrincipalType
    service_name: str | None = None

    def __str__(self) -> str:
        label = f"{self.principal_type.value}:{self.principal_id}"
        if self.service_name:
            label += f"@{self.service_name}"
        return label


# ---------------------------------------------------------------------------
# Authority
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Authority:
    """
    A set of allowed actions/permissions together with their provenance.

    ``permissions`` is a frozenset of action strings (e.g. ``payments:charge``).
    ``source`` indicates whether this authority is original, delegated, or
    belongs to the service itself.
    """

    permissions: frozenset[str]
    source: AuthoritySource

    # Convenience factories ---------------------------------------------------

    @classmethod
    def original(cls, *perms: str) -> Authority:
        return cls(permissions=frozenset(perms), source=AuthoritySource.ORIGINAL)

    @classmethod
    def delegated(cls, *perms: str) -> Authority:
        return cls(permissions=frozenset(perms), source=AuthoritySource.DELEGATED)

    @classmethod
    def service(cls, *perms: str) -> Authority:
        return cls(permissions=frozenset(perms), source=AuthoritySource.SERVICE)

    # Set helpers -------------------------------------------------------------

    def contains(self, action: str) -> bool:
        return action in self.permissions

    def contains_all(self, actions: frozenset[str]) -> bool:
        return actions <= self.permissions

    def union(self, other: Authority) -> Authority:
        """Merge permissions, keeping *this* authority's source tag."""
        return Authority(
            permissions=self.permissions | other.permissions,
            source=self.source,
        )

    def intersect(self, other: Authority) -> Authority:
        return Authority(
            permissions=self.permissions & other.permissions,
            source=self.source,
        )

    @staticmethod
    def empty(source: AuthoritySource = AuthoritySource.DELEGATED) -> Authority:
        return Authority(permissions=frozenset(), source=source)


# ---------------------------------------------------------------------------
# Delegation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DelegationStep:
    """
    One hop in the delegation chain.

    Records *who* delegated *what* authority to *whom*, through what
    credential mechanism, and whether the delegation was explicit.
    """

    from_principal: Identity
    to_principal: Identity
    delegated_authority: Authority | None = None       # authority handed to the next hop
    credential_type: CredentialType = CredentialType.UNKNOWN
    explicit: bool = True                # False → implicit/inferred


# ---------------------------------------------------------------------------
# Operation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Operation:
    """
    A downstream service action that needs authorization checking.

    ``raw_span_name``  — the original OTel span name
                         (e.g. ``oteldemo.PaymentService/Charge``)
    ``semantic_action`` — the canonical action
                         (e.g. ``payments:charge``)
    ``required_authority`` — the permissions needed to perform this action
    """

    service: str
    raw_span_name: str | None = None
    semantic_action: str | None = None
    target_resource: str | None = None
    required_authority: frozenset[str] = field(default_factory=frozenset)


# ---------------------------------------------------------------------------
# Authorization Event (telemetry-level)
# ---------------------------------------------------------------------------


@dataclass
class AuthorizationEvent:
    """
    A single authorization-relevant event extracted from telemetry.

    This is a normalized representation that sits between the raw OTel span
    and the higher-level ``AuthorizationScenario``.
    """

    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    initiating_principal: Identity | None = None
    acting_principal: Identity | None = None
    operation: Operation | None = None
    original_authority: Authority | None = None
    delegated_authority: Authority | None = None
    service_authority: Authority | None = None
    evidence: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Scenario (analysis-level)
# ---------------------------------------------------------------------------


@dataclass
class AuthorizationScenario:
    """
    A fully assembled analysis scenario for the detector.

    This is what the detection engine receives as input.
    """

    trace_id: str | None = None
    initiating_principal: Identity | None = None
    original_authority: Authority | None = None
    delegation_chain: list[DelegationStep] = field(default_factory=list)
    service_identities: list[Identity] = field(default_factory=list)
    effective_operation: Operation | None = None
    acting_service_authority: Authority | None = None
    evidence: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Finding & Detection Result
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """
    A single confused-deputy finding (or the explicit absence of one).
    """

    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    verdict: Verdict = Verdict.INSUFFICIENT_EVIDENCE
    trace_id: str | None = None
    initiating_principal: Identity | None = None
    delegated_authority: Authority | None = None
    effective_action: str | None = None
    required_authority: frozenset[str] = field(default_factory=frozenset)
    service_authority: Authority | None = None
    attack_path: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    severity: Severity = Severity.UNSCORED
    finding_type: FindingType = FindingType.NONE


@dataclass
class DetectionResult:
    """
    Complete output of the detector for one scenario.
    """

    verdict: Verdict
    finding: Finding
    reason: str
    details: dict[str, Any] = field(default_factory=dict)
