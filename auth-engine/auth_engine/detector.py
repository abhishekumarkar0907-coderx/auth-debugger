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
    FindingType,
    Operation,
    Severity,
    Verdict,
)
from .policy import ActionPolicy, default_otel_demo_policy
from .delegation_policy import DelegationPolicy


class ConfusedDeputyDetector:
    """
    Deterministic confused-deputy analysis engine.

    Usage::

        detector = ConfusedDeputyDetector()
        result = detector.analyze(scenario)
        assert result.verdict in (Verdict.DETECTED, ...)
    """

    def __init__(
        self,
        policy: ActionPolicy | None = None,
        delegation_policy: DelegationPolicy | None = None,
    ) -> None:
        self._policy = policy or default_otel_demo_policy()
        self._delegation_policy = delegation_policy or DelegationPolicy()

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

        # Reject explicit permission expansions without a trusted grant.
        unauthorized_expansions = self._find_unauthorized_expansions(scenario)
        if unauthorized_expansions:
            summary = "; ".join(
                f"{from_id} -> {to_id}: {', '.join(sorted(permissions))}"
                for from_id, to_id, permissions in unauthorized_expansions
            )
            result = self._detected(
                scenario,
                request_authority=request_authority,
                required=required,
                service_authority=scenario.acting_service_authority,
                reason_suffix=(
                    "unauthorized permission expansion without a trusted "
                    f"delegation grant ({summary})"
                ),
                finding_type=FindingType.UNAUTHORIZED_DELEGATION,
                reason_override=(
                    "Unauthorized permission expansion detected: "
                    f"{summary}. No matching trusted delegation grant authorizes "
                    "these permissions."
                ),
            )
            result.details["unauthorized_expansions"] = [
                {
                    "from_principal": from_id,
                    "to_principal": to_id,
                    "permissions": sorted(permissions),
                }
                for from_id, to_id, permissions in unauthorized_expansions
            ]
            return result

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
                finding_type=FindingType.CONFUSED_DEPUTY,
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
            finding_type=FindingType.AUTHORIZATION_FAILURE,
            reason_suffix=(
                "neither the delegated request authority nor the service's "
                "own authority includes the required permissions"
            ),
        )

    def _find_unauthorized_expansions(
        self, scenario: AuthorizationScenario
    ) -> list[tuple[str, str, frozenset[str]]]:
        """Find explicit permission additions without a matching trusted grant."""
        assert scenario.original_authority is not None

        current = scenario.original_authority.permissions
        unauthorized = []

        for step in scenario.delegation_chain:
            if not step.explicit:
                continue

            declared = step.delegated_authority.permissions
            additions = declared - current

            unauthorized_additions = frozenset(
                permission
                for permission in additions
                if not self._delegation_policy.permits(
                    step.from_principal.principal_id,
                    step.to_principal.principal_id,
                    frozenset({permission}),
                )
            )

            if unauthorized_additions:
                unauthorized.append((
                    step.from_principal.principal_id,
                    step.to_principal.principal_id,
                    unauthorized_additions,
                ))

            current = declared

        return unauthorized

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

        # Explicit delegation steps require established delegated authority.
        for step in scenario.delegation_chain:
            if step.explicit and step.delegated_authority is None:
                return self._insufficient(
                    scenario,
                    reason=(
                        f"Delegated authority cannot be established for hop "
                        f"{step.from_principal} -> {step.to_principal}; "
                        f"explicit scopes are missing, empty, or malformed"
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
        finding_type: FindingType,
        reason_override: str | None = None,
    ) -> DetectionResult:
        required_str = ", ".join(sorted(required))
        request_str = ", ".join(sorted(request_authority.permissions)) or "(none)"

        if reason_override is not None:
            reason = reason_override
        else:
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
            finding_type=finding_type,
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
            finding_type=FindingType.NONE,
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
            finding_type=FindingType.NONE,
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
