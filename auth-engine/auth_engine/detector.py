"""
Confused-deputy detector — the core security reasoning engine.

Takes an ``AuthorizationScenario`` and produces a deterministic
``DetectionResult``.  No LLM, no ML, no heuristics.
"""

from __future__ import annotations

from .delegation import build_attack_path, compute_request_authority
from .models import (
    Authority,
    AuthorizationScenario,
    DetectionResult,
    Finding,
    Operation,
    Severity,
    Verdict,
)
from .policy import ActionPolicy, default_otel_demo_policy


class ConfusedDeputyDetector:
    """
    Deterministic confused-deputy analysis engine.

    Usage::

        detector = ConfusedDeputyDetector()
        result = detector.analyze(scenario)
        assert result.verdict in (Verdict.DETECTED, ...)
    """

    def __init__(self, policy: ActionPolicy | None = None) -> None:
        self._policy = policy or default_otel_demo_policy()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, scenario: AuthorizationScenario) -> DetectionResult:
        """
        Analyze a single authorization scenario and return a deterministic
        ``DetectionResult``.

        Steps:
            1. Validate that required evidence is present.
            2. Determine the required authority for the effective operation.
            3. Walk the delegation chain to compute request authority.
            4. Compare required authority against request authority.
            5. Distinguish between request authority and service authority.
            6. Produce a structured, deterministic verdict.
        """

        # ---- Step 1: Validate required evidence -------------------------

        insufficient = self._check_evidence(scenario)
        if insufficient is not None:
            return insufficient

        # From this point on the type-narrowing guarantees hold.
        assert scenario.initiating_principal is not None
        assert scenario.original_authority is not None
        assert scenario.effective_operation is not None

        # ---- Step 2: Determine required authority -----------------------

        operation = scenario.effective_operation
        required = self._resolve_required_authority(operation)

        if required is None:
            return self._insufficient(
                scenario,
                reason=(
                    f"Cannot determine required authority for operation "
                    f"'{operation.semantic_action or operation.raw_span_name}'; "
                    f"action requirement mapping is missing"
                ),
            )

        # ---- Step 3: Walk delegation chain ------------------------------

        request_authority = compute_request_authority(
            scenario.original_authority,
            scenario.delegation_chain,
        )

        # ---- Step 4 + 5: Compare required vs. request -------------------

        # Collect the acting service's own authority (if provided).
        service_authority = scenario.acting_service_authority

        # Check whether the required permissions are all present in the
        # request authority (i.e., the legitimately delegated chain).
        request_has_required = required <= request_authority.permissions

        if request_has_required:
            # The required authority IS present in the delegated request
            # chain.  No confused-deputy condition.
            return self._not_detected(
                scenario,
                request_authority=request_authority,
                required=required,
                service_authority=service_authority,
            )

        # Required authority is NOT in the request chain.
        # Check whether the service can still perform the action via its
        # own privileges — this is the confused-deputy signal.

        service_has_required = (
            service_authority is not None
            and required <= service_authority.permissions
        )

        if service_has_required:
            return self._detected(
                scenario,
                request_authority=request_authority,
                required=required,
                service_authority=service_authority,
                reason_suffix=(
                    "service used its own service-level authority to perform "
                    "the action on behalf of the initiating principal"
                ),
            )

        # The service also lacks the authority — still a problem (the
        # action should not have been possible at all), but it is a
        # confused-deputy in the sense that there was no legitimate
        # delegation.
        return self._detected(
            scenario,
            request_authority=request_authority,
            required=required,
            service_authority=service_authority,
            reason_suffix=(
                "neither the delegated request authority nor the service's "
                "own authority includes the required permissions"
            ),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_required_authority(
        self, operation: Operation
    ) -> frozenset[str] | None:
        """Determine the permissions required for *operation*."""
        # 1. Explicit field on the operation itself
        if operation.required_authority:
            return operation.required_authority

        # 2. Policy lookup by semantic action
        if operation.semantic_action:
            perms = self._policy.required_permissions_for(
                semantic_action=operation.semantic_action
            )
            if perms is not None:
                return perms

        # 3. Policy lookup by raw span name
        if operation.raw_span_name:
            perms = self._policy.required_permissions_for(
                raw_span_name=operation.raw_span_name
            )
            if perms is not None:
                return perms

        return None

    # ---- Evidence validation --------------------------------------------

    def _check_evidence(
        self, scenario: AuthorizationScenario
    ) -> DetectionResult | None:
        """
        Return an INSUFFICIENT_EVIDENCE result if any critical piece of
        information is missing; otherwise return ``None``.
        """
        if scenario.initiating_principal is None:
            return self._insufficient(
                scenario,
                reason="Initiating principal is missing from the scenario",
            )

        if scenario.original_authority is None:
            return self._insufficient(
                scenario,
                reason="Original authority for the initiating principal is missing",
            )

        if scenario.effective_operation is None:
            return self._insufficient(
                scenario,
                reason="Effective downstream operation is missing from the scenario",
            )

        # The operation must have enough info to resolve required authority.
        op = scenario.effective_operation
        if (
            not op.required_authority
            and op.semantic_action is None
            and op.raw_span_name is None
        ):
            return self._insufficient(
                scenario,
                reason=(
                    "Effective operation has no semantic action, raw span name, "
                    "or explicit required authority"
                ),
            )

        return None

    # ---- Result constructors --------------------------------------------

    def _detected(
        self,
        scenario: AuthorizationScenario,
        *,
        request_authority: Authority,
        required: frozenset[str],
        service_authority: Authority | None,
        reason_suffix: str,
    ) -> DetectionResult:
        required_str = ", ".join(sorted(required))
        request_str = ", ".join(sorted(request_authority.permissions)) or "(none)"
        reason = (
            f"{required_str} required by downstream operation but not present "
            f"in delegated request authority [{request_str}]; "
            f"{reason_suffix}"
        )

        attack_path = build_attack_path(
            scenario.initiating_principal, scenario.delegation_chain
        )

        finding = Finding(
            verdict=Verdict.DETECTED,
            trace_id=scenario.trace_id,
            initiating_principal=scenario.initiating_principal,
            delegated_authority=request_authority,
            effective_action=(
                scenario.effective_operation.semantic_action
                if scenario.effective_operation
                else None
            ),
            required_authority=required,
            service_authority=service_authority,
            attack_path=attack_path,
            evidence=scenario.evidence,
            reason=reason,
            severity=Severity.HIGH,
        )

        return DetectionResult(
            verdict=Verdict.DETECTED,
            finding=finding,
            reason=reason,
            details={
                "required_action": sorted(required),
                "request_authority": sorted(request_authority.permissions),
                "service_authority": (
                    sorted(service_authority.permissions)
                    if service_authority
                    else []
                ),
                "attack_path": attack_path,
            },
        )

    def _not_detected(
        self,
        scenario: AuthorizationScenario,
        *,
        request_authority: Authority,
        required: frozenset[str],
        service_authority: Authority | None,
    ) -> DetectionResult:
        required_str = ", ".join(sorted(required))
        request_str = ", ".join(sorted(request_authority.permissions))
        reason = (
            f"Required authority [{required_str}] is present in the delegated "
            f"request authority [{request_str}]; action is legitimately authorized"
        )

        finding = Finding(
            verdict=Verdict.NOT_DETECTED,
            trace_id=scenario.trace_id,
            initiating_principal=scenario.initiating_principal,
            delegated_authority=request_authority,
            effective_action=(
                scenario.effective_operation.semantic_action
                if scenario.effective_operation
                else None
            ),
            required_authority=required,
            service_authority=service_authority,
            evidence=scenario.evidence,
            reason=reason,
            severity=Severity.UNSCORED,
        )

        return DetectionResult(
            verdict=Verdict.NOT_DETECTED,
            finding=finding,
            reason=reason,
            details={
                "required_action": sorted(required),
                "request_authority": sorted(request_authority.permissions),
            },
        )

    def _insufficient(
        self,
        scenario: AuthorizationScenario,
        *,
        reason: str,
    ) -> DetectionResult:
        finding = Finding(
            verdict=Verdict.INSUFFICIENT_EVIDENCE,
            trace_id=scenario.trace_id,
            initiating_principal=scenario.initiating_principal,
            reason=reason,
            severity=Severity.UNSCORED,
        )

        return DetectionResult(
            verdict=Verdict.INSUFFICIENT_EVIDENCE,
            finding=finding,
            reason=reason,
        )
