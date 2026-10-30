"""
Confused-deputy detector — the core security reasoning engine.

Takes an ``AuthorizationScenario`` and produces a deterministic
``DetectionResult``.  No LLM, no ML, no heuristics.
"""

from __future__ import annotations

import json
import uuid

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

        # Reject explicit expansions without a grant and independently
        # denied permissions on known delegation edges.
        unauthorized_expansions = self._find_unauthorized_expansions(scenario)
        if unauthorized_expansions:
            summary = "; ".join(
                f"{from_id} -> {to_id}: {', '.join(sorted(permissions))} "
                f"({basis})"
                for from_id, to_id, permissions, basis in unauthorized_expansions
            )
            reason_override = (
                "Unauthorized delegation detected: "
                f"{summary}. Permissions outside a known baseline are not "
                "treated as newly added unless the prior authority is known; "
                "the edge-specific trusted grant does not authorize the "
                "identified permissions."
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
                reason_override=reason_override,
            )
            result.details["unauthorized_expansions"] = [
                {
                    "from_principal": from_id,
                    "to_principal": to_id,
                    "permissions": sorted(permissions),
                    "basis": basis,
                }
                for from_id, to_id, permissions, basis in unauthorized_expansions
            ]
            return result

        # Unknown scopes and inferred delegation cannot establish
        # authorization or denial.
        unknown_scope_hops = [
            (
                step.from_principal.principal_id,
                step.to_principal.principal_id,
                (
                    "scope evidence is missing or malformed"
                    if step.explicit
                    else "delegation is not explicit"
                ),
            )
            for step in scenario.delegation_chain
            if not step.explicit or not step.scopes_known
        ]

        if unknown_scope_hops:
            affected_hops = ", ".join(
                f"{from_id} -> {to_id} ({evidence_status})"
                for from_id, to_id, evidence_status in unknown_scope_hops
            )
            return self._insufficient(
                scenario,
                reason=(
                    "Cannot determine the authorization verdict because "
                    "delegation evidence is incomplete for: "
                    f"{affected_hops}"
                ),
            )

        if request_authority is None:
            return self._insufficient(
                scenario,
                reason=(
                    "Cannot determine the authorization verdict because "
                    "the final delegated request authority is unknown"
                ),
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
                finding_type=FindingType.CONFUSED_DEPUTY,
                reason_suffix=(
                    "service used its own service-level authority to perform "
                    "the action on behalf of the initiating principal"
                ),
            )

        if service_authority is None:
            return self._insufficient(
                scenario,
                reason=(
                    "Cannot determine whether the operation was authorized: "
                    "the acting service's authority is not configured"
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
    ) -> list[tuple[str, str, frozenset[str], str]]:
        """Find ungranted additions and independent explicit-edge violations."""
        assert scenario.original_authority is not None

        # None means the previous hop's authority cannot be established.
        current: frozenset[str] | None = (
            scenario.original_authority.permissions
        )
        unauthorized: list[tuple[str, str, frozenset[str], str]] = []

        for step in scenario.delegation_chain:
            if not step.explicit:
                current = None
                continue

            # Missing or malformed scopes are unknown, not an empty grant.
            if not step.scopes_known:
                current = None
                continue

            declared = step.delegated_authority.permissions

            # We cannot calculate additions without a trustworthy baseline.
            if current is None:
                current = declared
                continue

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
                unauthorized.append(
                    (
                        step.from_principal.principal_id,
                        step.to_principal.principal_id,
                        unauthorized_additions,
                        "known prior authority",
                    )
                )

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

        return None

    # ---- Result constructors --------------------------------------------

    def _detected(
        self,
        scenario: AuthorizationScenario,
        *,
        request_authority: Authority | None,
        required: frozenset[str],
        service_authority: Authority | None,
        reason_suffix: str,
        finding_type: FindingType,
        reason_override: str | None = None,
    ) -> DetectionResult:
        required_str = ", ".join(sorted(required))
        request_str = (
            ", ".join(sorted(request_authority.permissions))
            if request_authority is not None
            else "(unknown)"
        ) or "(none)"

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
            finding_id=self._stable_finding_id(
                scenario, Verdict.DETECTED, finding_type, reason
            ),
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
                "request_authority": (
                    sorted(request_authority.permissions)
                    if request_authority is not None
                    else None
                ),
                "request_authority_known": request_authority is not None,
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
            finding_id=self._stable_finding_id(
                scenario, Verdict.NOT_DETECTED, FindingType.NONE, reason
            ),
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
            finding_id=self._stable_finding_id(
                scenario,
                Verdict.INSUFFICIENT_EVIDENCE,
                FindingType.NONE,
                reason,
            ),
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

    @staticmethod
    def _stable_finding_id(
        scenario: AuthorizationScenario,
        verdict: Verdict,
        finding_type: FindingType,
        reason: str,
    ) -> str:
        """Create a stable identifier from the scenario's security evidence."""
        operation = scenario.effective_operation
        payload = {
            "trace_id": scenario.trace_id,
            "initiating_principal": (
                (
                    scenario.initiating_principal.principal_id,
                    scenario.initiating_principal.principal_type.value,
                    scenario.initiating_principal.service_name,
                )
                if scenario.initiating_principal is not None
                else None
            ),
            "original_authority": (
                sorted(scenario.original_authority.permissions)
                if scenario.original_authority is not None
                else None
            ),
            "delegation_chain": [
                {
                    "from": step.from_principal.principal_id,
                    "from_type": step.from_principal.principal_type.value,
                    "to": step.to_principal.principal_id,
                    "to_type": step.to_principal.principal_type.value,
                    "permissions": sorted(step.delegated_authority.permissions),
                    "credential_type": step.credential_type.value,
                    "explicit": step.explicit,
                    "scopes_known": step.scopes_known,
                }
                for step in scenario.delegation_chain
            ],
            "operation": (
                {
                    "service": operation.service,
                    "span": operation.raw_span_name,
                    "action": operation.semantic_action,
                    "target_resource": operation.target_resource,
                    "required": sorted(operation.required_authority),
                }
                if operation is not None
                else None
            ),
            "service_authority": (
                sorted(scenario.acting_service_authority.permissions)
                if scenario.acting_service_authority is not None
                else None
            ),
            "verdict": verdict.value,
            "finding_type": finding_type.value,
            "reason": reason,
        }
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return str(uuid.uuid5(uuid.NAMESPACE_URL, serialized))
