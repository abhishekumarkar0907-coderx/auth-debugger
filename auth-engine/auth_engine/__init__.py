"""
auth_engine — Deterministic confused-deputy authorization analysis engine.
"""

from .models import (
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
from .detector import ConfusedDeputyDetector
from .policy import ActionPolicy, ActionRequirement, default_otel_demo_policy
from .delegation import (
    authority_at_each_hop,
    build_attack_path,
    compute_request_authority,
)
from . import graph

__all__ = [
    # Models
    "Authority",
    "AuthoritySource",
    "AuthorizationEvent",
    "AuthorizationScenario",
    "CredentialType",
    "DelegationStep",
    "DetectionResult",
    "Finding",
    "FindingType",
    "Identity",
    "Operation",
    "PrincipalType",
    "Severity",
    "Verdict",
    # Detector
    "ConfusedDeputyDetector",
    # Policy
    "ActionPolicy",
    "ActionRequirement",
    "default_otel_demo_policy",
    # Delegation
    "authority_at_each_hop",
    "build_attack_path",
    "compute_request_authority",
    # Graph Subpackage
    "graph",
]
