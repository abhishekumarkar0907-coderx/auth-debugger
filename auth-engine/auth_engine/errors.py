"""Custom exceptions for the auth-engine."""


class AuthEngineError(Exception):
    """Base exception for auth-engine errors."""


class InvalidScenarioError(AuthEngineError):
    """Raised when an AuthorizationScenario is structurally invalid."""


class PolicyLookupError(AuthEngineError):
    """Raised when a policy/mapping lookup fails."""


class DelegationChainError(AuthEngineError):
    """Raised when the delegation chain is structurally invalid."""
