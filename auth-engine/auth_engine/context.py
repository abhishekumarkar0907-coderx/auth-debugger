"""
Authorization-context extraction from telemetry spans.

Scans span attributes for security-relevant data and produces an
``AuthorizationContext`` — an intermediate representation sitting between
raw OTel spans and the auth-engine's ``AuthorizationScenario``.

Design invariants:
    - Never invents identity, permissions, or delegation relationships.
    - Every extracted value records its provenance (source attribute,
      span ID, confidence level).
    - Missing evidence is recorded as a warning, not a false positive.
    - Conflicting evidence is preserved and flagged; the extractor does
      not silently pick one value.
    - No LLM, ML, or heuristic is involved.
    - No dependency on the backend package.  Incoming spans are accepted
      through the ``SpanLike`` structural protocol.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from .models import (
    Authority,
    AuthoritySource,
    AuthorizationScenario,
    CredentialType,
    DelegationStep,
    Identity,
    Operation,
    PrincipalType,
)
from .policy import ActionPolicy


# ---------------------------------------------------------------------------
# Span protocol — decoupled from backend.app.schemas
# ---------------------------------------------------------------------------


@runtime_checkable
class SpanLike(Protocol):
    """
    Structural interface for an incoming span record.

    Any object with these attributes is accepted.  This avoids importing
    the backend's ``SpanRecord`` Pydantic model.
    """

    trace_id: str
    span_id: str
    parent_span_id: str | None
    service_name: str | None
    span_name: str
    status_code: int
    attributes: dict[str, Any]


# ---------------------------------------------------------------------------
# Recognised span-attribute keys
# ---------------------------------------------------------------------------

# Explicit authorization attributes (custom convention)
ATTR_PRINCIPAL_ID = "authz.principal.id"
ATTR_PRINCIPAL_TYPE = "authz.principal.type"
ATTR_PRINCIPAL_SCOPES = "authz.principal.scopes"
ATTR_DELEGATION_FROM = "authz.delegation.from"
ATTR_DELEGATION_TO = "authz.delegation.to"
ATTR_DELEGATION_SCOPES = "authz.delegation.scopes"
ATTR_CREDENTIAL_TYPE = "authz.credential.type"
ATTR_TARGET_RESOURCE = "authz.target.resource"

# Semi-standard OTel attribute (candidate only — see extraction rules)
ATTR_ENDUSER_ID = "enduser.id"

# Valid PrincipalType values (lowercase, matching the enum)
_VALID_PRINCIPAL_TYPES = frozenset(t.value for t in PrincipalType)

# Valid CredentialType values (lowercase, matching the enum)
_VALID_CREDENTIAL_TYPES = frozenset(t.value for t in CredentialType)


# ---------------------------------------------------------------------------
# Evidence and warning data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceItem:
    """A single piece of extracted evidence with provenance."""

    field: str
    """Logical field this evidence populates (e.g. ``"initiating_principal.id"``)."""

    value: Any
    """The observed or configured value."""

    source: str
    """
    Where the value came from.

    Format: ``"span_attribute:<key>"`` for span attributes,
    ``"config:service_authority"`` for configuration entries.
    """

    span_id: str | None = None
    """Span this evidence was extracted from (``None`` for config-sourced)."""

    confidence: str = "explicit"
    """
    ``"explicit"``   — directly observed in a span attribute designated
                       for this purpose.
    ``"candidate"``  — observed in a span attribute that *may* represent
                       this value but requires corroboration (e.g.
                       ``enduser.id`` on a downstream span).
    ``"configured"`` — supplied via external configuration, not observed
                       in telemetry.
    """


@dataclass(frozen=True)
class ExtractionWarning:
    """A warning about missing, ambiguous, or conflicting evidence."""

    field: str
    """The logical field affected."""

    warning_type: str
    """``"missing"`` | ``"ambiguous"`` | ``"conflicting"`` | ``"malformed"``"""

    message: str
    """Human-readable description."""

    sources: list[str] = field(default_factory=list)
    """Attribute keys or config entries that were examined."""


# ---------------------------------------------------------------------------
# Raw delegation hop — intermediate, pre-conversion representation
# ---------------------------------------------------------------------------


@dataclass
class RawDelegationHop:
    """A delegation hop extracted from span attributes, before validation."""

    from_id: str | None = None
    to_id: str | None = None
    credential_type_raw: str | None = None
    scopes_raw: Any = None
    span_id: str | None = None


# ---------------------------------------------------------------------------
# AuthorizationContext — the main extraction output
# ---------------------------------------------------------------------------


@dataclass
class AuthorizationContext:
    """
    Intermediate representation between raw spans and
    ``AuthorizationScenario``.

    Every field is optional.  Missing values are recorded as warnings,
    not treated as security violations.  Conflicting values are preserved
    so the caller can inspect them.
    """

    trace_id: str
    span_ids: list[str] = field(default_factory=list)

    # ---- Extracted fields (all Optional) --------------------------------

    initiating_principal_id: str | None = None
    initiating_principal_type: str | None = None
    acting_service_name: str | None = None
    original_scopes: list[str] | None = None
    delegation_hops: list[RawDelegationHop] = field(default_factory=list)

    effective_span_name: str | None = None
    effective_service: str | None = None
    target_resource: str | None = None
    outcome_success: bool | None = None

    # ---- Service authority (from config, never from service name) --------

    service_authority_permissions: list[str] | None = None

    # ---- Provenance and quality -----------------------------------------

    evidence: list[EvidenceItem] = field(default_factory=list)
    warnings: list[ExtractionWarning] = field(default_factory=list)

    # ---- Completeness checks --------------------------------------------

    @property
    def has_principal(self) -> bool:
        return self.initiating_principal_id is not None

    @property
    def has_authority(self) -> bool:
        return self.original_scopes is not None and len(self.original_scopes) > 0

    @property
    def has_action(self) -> bool:
        return self.effective_span_name is not None

    @property
    def has_conflicting_evidence(self) -> bool:
        return any(w.warning_type == "conflicting" for w in self.warnings)

    def has_sufficient_evidence(self) -> bool:
        """
        Whether this context has enough evidence to produce a meaningful
        ``AuthorizationScenario``.

        Requires at minimum: principal identity, original authority, and
        an effective action.  Conflicting evidence on critical fields
        (principal identity) disqualifies the context.
        """
        critical_fields = {
            "initiating_principal.id",
            "initiating_principal.type",
            "original_authority",
        }
        for warning in self.warnings:
            if (
                warning.warning_type in {"conflicting", "malformed"}
                and warning.field in critical_fields
            ):
                return False

        return self.has_principal and self.has_authority and self.has_action

    def to_scenario(
        self,
        policy: ActionPolicy | None = None,
    ) -> AuthorizationScenario:
        """
        Convert to an ``AuthorizationScenario`` for the detector.

        Raises ``ValueError`` if required evidence is missing or if
        critical fields have conflicting evidence.  Call
        ``has_sufficient_evidence()`` first to check.

        Does not invent permissions, identities, or delegation steps.
        """
        if not self.has_sufficient_evidence():
            missing_parts = []
            if not self.has_principal:
                missing_parts.append("principal identity")
            if not self.has_authority:
                missing_parts.append("original authority/scopes")
            if not self.has_action:
                missing_parts.append("effective action")
            if self.has_conflicting_evidence:
                missing_parts.append("conflicting evidence on critical fields")
            if any(
                warning.warning_type == "malformed"
                and warning.field
                in {"initiating_principal.id", "initiating_principal.type", "original_authority"}
                for warning in self.warnings
            ):
                missing_parts.append("malformed evidence on critical fields")
            raise ValueError(
                "Cannot build AuthorizationScenario: "
                + ", ".join(missing_parts)
            )

        # ---- Build Identity ------------------------------------------------

        principal_type = PrincipalType.USER  # safe default
        if self.initiating_principal_type is not None:
            raw_type = self.initiating_principal_type.lower()
            if raw_type in _VALID_PRINCIPAL_TYPES:
                principal_type = PrincipalType(raw_type)

        assert self.initiating_principal_id is not None  # guarded above
        initiating_principal = Identity(
            principal_id=self.initiating_principal_id,
            principal_type=principal_type,
        )

        # ---- Build Authority -----------------------------------------------

        assert self.original_scopes is not None  # guarded above
        original_authority = Authority(
            permissions=frozenset(self.original_scopes),
            source=AuthoritySource.ORIGINAL,
        )

        # ---- Build Operation -----------------------------------------------

        assert self.effective_span_name is not None  # guarded above
        semantic_action: str | None = None
        required_authority: frozenset[str] = frozenset()

        if policy is not None:
            semantic_action = policy.resolve_span(self.effective_span_name)
            if semantic_action is not None:
                perms = policy.required_permissions_for(
                    semantic_action=semantic_action
                )
                if perms is not None:
                    required_authority = perms

        effective_operation = Operation(
            service=self.effective_service or "",
            raw_span_name=self.effective_span_name,
            semantic_action=semantic_action,
            target_resource=self.target_resource,
            required_authority=required_authority,
        )

        # ---- Build delegation chain ----------------------------------------

        delegation_chain: list[DelegationStep] = []
        for hop in self.delegation_hops:
            if hop.from_id is None or hop.to_id is None:
                # Incomplete hop — skip rather than invent.
                continue

            cred_type = CredentialType.UNKNOWN
            if hop.credential_type_raw is not None:
                raw_ct = hop.credential_type_raw.lower()
                if raw_ct in _VALID_CREDENTIAL_TYPES:
                    cred_type = CredentialType(raw_ct)

            # Parse delegated scopes and preserve whether the evidence is valid.
            delegated_perms, scopes_known = _parse_scopes_checked(hop.scopes_raw)

            from_principal = Identity(
                principal_id=hop.from_id,
                principal_type=PrincipalType.USER,
            )
            to_principal = Identity(
                principal_id=hop.to_id,
                principal_type=PrincipalType.SERVICE,
            )

            delegation_chain.append(
                DelegationStep(
                    from_principal=from_principal,
                    to_principal=to_principal,
                    delegated_authority=Authority(
                        permissions=delegated_perms,
                        source=AuthoritySource.DELEGATED,
                    ),
                    credential_type=cred_type,
                    explicit=True,
                    scopes_known=scopes_known,
                )
            )

        # ---- Build service authority ---------------------------------------

        acting_service_authority: Authority | None = None
        if self.service_authority_permissions is not None:
            acting_service_authority = Authority(
                permissions=frozenset(self.service_authority_permissions),
                source=AuthoritySource.SERVICE,
            )

        # ---- Build evidence dict -------------------------------------------

        evidence_dict: dict[str, Any] = {
            "extraction_evidence": [
                {
                    "field": e.field,
                    "value": e.value,
                    "source": e.source,
                    "span_id": e.span_id,
                    "confidence": e.confidence,
                }
                for e in self.evidence
            ],
            "extraction_warnings": [
                {
                    "field": w.field,
                    "type": w.warning_type,
                    "message": w.message,
                }
                for w in self.warnings
            ],
        }

        return AuthorizationScenario(
            trace_id=self.trace_id,
            initiating_principal=initiating_principal,
            original_authority=original_authority,
            delegation_chain=delegation_chain,
            effective_operation=effective_operation,
            acting_service_authority=acting_service_authority,
            evidence=evidence_dict,
        )


# ---------------------------------------------------------------------------
# Scope parsing
# ---------------------------------------------------------------------------


def _parse_scopes(raw: Any) -> frozenset[str]:
    """Parse scope values without raising on malformed telemetry.

    Invalid or missing input returns an empty set for compatibility.
    Callers must separately track whether the scope evidence is valid.
    """
    if raw is None:
        return frozenset()

    if isinstance(raw, list):
        return frozenset(
            item.strip()
            for item in raw
            if isinstance(item, str) and item.strip()
        )

    if not isinstance(raw, str):
        return frozenset()

    trimmed = raw.strip()
    if not trimmed:
        return frozenset()

    if trimmed.startswith("["):
        try:
            parsed = json.loads(trimmed)
        except json.JSONDecodeError:
            return frozenset()
        if not isinstance(parsed, list):
            return frozenset()
        if any(not isinstance(item, str) or not item.strip() for item in parsed):
            return frozenset()
        return frozenset(item.strip() for item in parsed)

    if "," in trimmed:
        parts = [part.strip() for part in trimmed.split(",")]
        if any(not part for part in parts):
            return frozenset()
        return frozenset(parts)

    if " " in trimmed:
        return frozenset(trimmed.split())

    return frozenset({trimmed})


def _parse_scopes_checked(raw: Any) -> tuple[frozenset[str], bool]:
    """Parse scopes and indicate whether the raw value is valid evidence.

    An explicitly empty list is valid evidence of an empty grant.
    Missing, blank, malformed, or incorrectly typed values are unknown.
    """
    if isinstance(raw, list):
        if any(not isinstance(item, str) or not item.strip() for item in raw):
            return frozenset(), False
        return frozenset(item.strip() for item in raw), True

    if not isinstance(raw, str) or not raw.strip():
        return frozenset(), False

    trimmed = raw.strip()

    if trimmed.startswith("["):
        try:
            parsed = json.loads(trimmed)
        except json.JSONDecodeError:
            return frozenset(), False

        if not isinstance(parsed, list):
            return frozenset(), False

        if any(not isinstance(item, str) or not item.strip() for item in parsed):
            return frozenset(), False

        return frozenset(item.strip() for item in parsed), True

    if "," in trimmed:
        parts = [part.strip() for part in trimmed.split(",")]
        if any(not part for part in parts):
            return frozenset(), False
        return frozenset(parts), True

    if " " in trimmed:
        return frozenset(trimmed.split()), True

    return frozenset({trimmed}), True


def _has_malformed_scope_items(raw: Any) -> bool:
    if isinstance(raw, list):
        return any(not isinstance(item, str) for item in raw)
    if isinstance(raw, str) and raw.strip().startswith("["):
        try:
            parsed = json.loads(raw.strip())
        except json.JSONDecodeError:
            return True
        return not isinstance(parsed, list) or any(
            not isinstance(item, str) for item in parsed
        )
    return not isinstance(raw, str)


# ---------------------------------------------------------------------------
# Main extraction function
# ---------------------------------------------------------------------------


def extract_authorization_context(
    spans: list[SpanLike],
    *,
    service_authority_config: dict[str, list[str]] | None = None,
) -> AuthorizationContext:
    """
    Extract authorization-relevant context from a list of spans
    belonging to the same trace.

    Parameters
    ----------
    spans
        Span records from a single trace.  Each must satisfy the
        ``SpanLike`` protocol.
    service_authority_config
        Optional mapping of service name → list of permissions that the
        service holds independently.  These are marked as configured
        evidence, never as observed.

    Returns
    -------
    AuthorizationContext
        May be incomplete.  The caller decides whether the context has
        sufficient evidence to proceed to detection.

    This function:
        1. Scans span attributes for known authorization-relevant keys.
        2. Records provenance for every extracted value.
        3. Detects ambiguous or conflicting evidence.
        4. NEVER invents identity, permissions, or delegation.
        5. Returns an AuthorizationContext that may be incomplete.
    """
    if not spans:
        ctx = AuthorizationContext(trace_id="")
        ctx.warnings.append(
            ExtractionWarning(
                field="input",
                warning_type="missing",
                message="No spans provided for extraction",
                sources=[],
            )
        )
        return ctx

    # Use the trace_id from the first span
    trace_id = spans[0].trace_id

    ctx = AuthorizationContext(
        trace_id=trace_id,
        span_ids=[s.span_id for s in spans],
    )

    # ---- Collect candidates from all spans --------------------------------

    principal_id_candidates: list[tuple[str, str, str]] = []
    # (value, source_attr, span_id)

    principal_type_candidates: list[tuple[str, str, str]] = []
    scopes_candidates: list[tuple[Any, str, str]] = []
    delegation_hops: list[RawDelegationHop] = []

    # Track the leaf span (last span, or the one with the deepest depth,
    # approximated by having no children).
    child_spans = {s.parent_span_id for s in spans if s.parent_span_id}
    leaf_spans = [s for s in spans if s.span_id not in child_spans]

    for span in spans:
        attrs = span.attributes

        # ---- Principal identity -----------------------------------------

        explicit_pid = attrs.get(ATTR_PRINCIPAL_ID)
        if explicit_pid is not None and isinstance(explicit_pid, str) and explicit_pid.strip():
            principal_id_candidates.append(
                (explicit_pid.strip(), ATTR_PRINCIPAL_ID, span.span_id)
            )

        # enduser.id — candidate only, not automatically the principal
        enduser_id = attrs.get(ATTR_ENDUSER_ID)
        if enduser_id is not None and isinstance(enduser_id, str) and enduser_id.strip():
            # Only treat as a candidate; provenance is "candidate"
            principal_id_candidates.append(
                (enduser_id.strip(), ATTR_ENDUSER_ID, span.span_id)
            )

        # ---- Principal type ---------------------------------------------

        explicit_ptype = attrs.get(ATTR_PRINCIPAL_TYPE)
        if explicit_ptype is not None and isinstance(explicit_ptype, str) and explicit_ptype.strip():
            principal_type_candidates.append(
                (explicit_ptype.strip().lower(), ATTR_PRINCIPAL_TYPE, span.span_id)
            )

        # ---- Scopes / authority -----------------------------------------

        explicit_scopes = attrs.get(ATTR_PRINCIPAL_SCOPES)
        if explicit_scopes is not None:
            scopes_candidates.append(
                (explicit_scopes, ATTR_PRINCIPAL_SCOPES, span.span_id)
            )

        # ---- Delegation -------------------------------------------------

        deleg_from = attrs.get(ATTR_DELEGATION_FROM)
        deleg_to = attrs.get(ATTR_DELEGATION_TO)
        deleg_scopes = attrs.get(ATTR_DELEGATION_SCOPES)
        cred_type = attrs.get(ATTR_CREDENTIAL_TYPE)
        deleg_scopes = attrs.get(ATTR_DELEGATION_SCOPES)

        if (
            deleg_from is not None
            or deleg_to is not None
            or cred_type is not None
            or deleg_scopes is not None
        ):
            hop = RawDelegationHop(
                from_id=(
                    deleg_from.strip()
                    if isinstance(deleg_from, str) and deleg_from.strip()
                    else None
                ),
                to_id=(
                    deleg_to.strip()
                    if isinstance(deleg_to, str) and deleg_to.strip()
                    else None
                ),
                credential_type_raw=(
                    cred_type.strip()
                    if isinstance(cred_type, str) and cred_type.strip()
                    else None
                ),
                scopes_raw=deleg_scopes,
                span_id=span.span_id,
            )
            delegation_hops.append(hop)

        # ---- Target resource --------------------------------------------

        target_res = attrs.get(ATTR_TARGET_RESOURCE)
        if target_res is not None and isinstance(target_res, str) and target_res.strip():
            if ctx.target_resource is None:
                ctx.target_resource = target_res.strip()
                ctx.evidence.append(
                    EvidenceItem(
                        field="target_resource",
                        value=target_res.strip(),
                        source=f"span_attribute:{ATTR_TARGET_RESOURCE}",
                        span_id=span.span_id,
                        confidence="explicit",
                    )
                )

    # ---- Resolve principal identity ---------------------------------------

    _resolve_principal_identity(ctx, principal_id_candidates)

    # ---- Resolve principal type -------------------------------------------

    _resolve_principal_type(ctx, principal_type_candidates)

    # ---- Resolve scopes ---------------------------------------------------

    _resolve_scopes(ctx, scopes_candidates)

    # ---- Resolve delegation hops ------------------------------------------

    _resolve_delegation(ctx, delegation_hops)

    # ---- Resolve effective action (leaf span) -----------------------------

    _resolve_effective_action(ctx, spans, leaf_spans)

    # ---- Resolve service authority from config ----------------------------

    _resolve_service_authority(ctx, service_authority_config)

    # ---- Check for missing fields -----------------------------------------

    _add_missing_warnings(ctx)

    return ctx


# ---------------------------------------------------------------------------
# Internal resolution helpers
# ---------------------------------------------------------------------------


def _resolve_principal_identity(
    ctx: AuthorizationContext,
    candidates: list[tuple[str, str, str]],
) -> None:
    """Resolve principal identity from candidates with conflict detection."""

    # Separate explicit (authz.principal.id) from candidate (enduser.id)
    explicit = [(v, src, sid) for v, src, sid in candidates if src == ATTR_PRINCIPAL_ID]
    enduser = [(v, src, sid) for v, src, sid in candidates if src == ATTR_ENDUSER_ID]

    # Deduplicate explicit candidates by value
    explicit_values = {v for v, _, _ in explicit}

    if len(explicit_values) > 1:
        # Conflicting explicit principal IDs
        ctx.warnings.append(
            ExtractionWarning(
                field="initiating_principal.id",
                warning_type="conflicting",
                message=(
                    f"Multiple conflicting values for {ATTR_PRINCIPAL_ID}: "
                    f"{sorted(explicit_values)}"
                ),
                sources=[ATTR_PRINCIPAL_ID],
            )
        )
        # Record all as evidence but do NOT set the field
        for v, src, sid in explicit:
            ctx.evidence.append(
                EvidenceItem(
                    field="initiating_principal.id",
                    value=v,
                    source=f"span_attribute:{src}",
                    span_id=sid,
                    confidence="explicit",
                )
            )
        return

    if len(explicit_values) == 1:
        # One consistent explicit value
        value = next(iter(explicit_values))
        ctx.initiating_principal_id = value
        # Record evidence from the first span that provided it
        first = explicit[0]
        ctx.evidence.append(
            EvidenceItem(
                field="initiating_principal.id",
                value=value,
                source=f"span_attribute:{first[1]}",
                span_id=first[2],
                confidence="explicit",
            )
        )
        return

    # No explicit principal ID — check enduser.id candidates
    enduser_values = {v for v, _, _ in enduser}

    if len(enduser_values) > 1:
        # Conflicting enduser.id values
        ctx.warnings.append(
            ExtractionWarning(
                field="initiating_principal.id",
                warning_type="conflicting",
                message=(
                    f"Multiple conflicting values for {ATTR_ENDUSER_ID}: "
                    f"{sorted(enduser_values)}. Cannot determine initiating "
                    f"principal without corroboration."
                ),
                sources=[ATTR_ENDUSER_ID],
            )
        )
        for v, src, sid in enduser:
            ctx.evidence.append(
                EvidenceItem(
                    field="initiating_principal.id",
                    value=v,
                    source=f"span_attribute:{src}",
                    span_id=sid,
                    confidence="candidate",
                )
            )
        return

    if len(enduser_values) == 1:
        # One consistent enduser.id — use as candidate
        value = next(iter(enduser_values))
        ctx.initiating_principal_id = value
        first = enduser[0]
        ctx.evidence.append(
            EvidenceItem(
                field="initiating_principal.id",
                value=value,
                source=f"span_attribute:{first[1]}",
                span_id=first[2],
                confidence="candidate",
            )
        )
        return

    # No identity evidence at all — warning added later by _add_missing_warnings


def _resolve_principal_type(
    ctx: AuthorizationContext,
    candidates: list[tuple[str, str, str]],
) -> None:
    """Resolve principal type from candidates."""
    if not candidates:
        return

    values = {v for v, _, _ in candidates}

    if len(values) > 1:
        ctx.warnings.append(
            ExtractionWarning(
                field="initiating_principal.type",
                warning_type="conflicting",
                message=(
                    f"Multiple conflicting values for {ATTR_PRINCIPAL_TYPE}: "
                    f"{sorted(values)}"
                ),
                sources=[ATTR_PRINCIPAL_TYPE],
            )
        )
        for v, src, sid in candidates:
            ctx.evidence.append(
                EvidenceItem(
                    field="initiating_principal.type",
                    value=v,
                    source=f"span_attribute:{src}",
                    span_id=sid,
                    confidence="explicit",
                )
            )
        return

    value = next(iter(values))
    if value not in _VALID_PRINCIPAL_TYPES:
        ctx.warnings.append(
            ExtractionWarning(
                field="initiating_principal.type",
                warning_type="malformed",
                message=(
                    f"Unrecognised principal type '{value}'; "
                    f"valid types: {sorted(_VALID_PRINCIPAL_TYPES)}"
                ),
                sources=[ATTR_PRINCIPAL_TYPE],
            )
        )
        return

    ctx.initiating_principal_type = value
    first = candidates[0]
    ctx.evidence.append(
        EvidenceItem(
            field="initiating_principal.type",
            value=value,
            source=f"span_attribute:{first[1]}",
            span_id=first[2],
            confidence="explicit",
        )
    )


def _resolve_scopes(
    ctx: AuthorizationContext,
    candidates: list[tuple[Any, str, str]],
) -> None:
    """Resolve principal scopes from candidates."""
    if not candidates:
        return

    parsed_sets: list[tuple[frozenset[str], str, str]] = []
    for raw, src, sid in candidates:
        parsed = _parse_scopes(raw)
        if parsed and _has_malformed_scope_items(raw):
            ctx.warnings.append(
                ExtractionWarning(
                    field="original_authority",
                    warning_type="malformed",
                    message=(
                        f"Some scopes from {ATTR_PRINCIPAL_SCOPES} on span "
                        f"{sid} are malformed"
                    ),
                    sources=[ATTR_PRINCIPAL_SCOPES],
                )
            )
        if not parsed:
            ctx.warnings.append(
                ExtractionWarning(
                    field="original_authority",
                    warning_type="malformed",
                    message=(
                        f"Could not parse scopes from {ATTR_PRINCIPAL_SCOPES} "
                        f"on span {sid}: {raw!r}"
                    ),
                    sources=[ATTR_PRINCIPAL_SCOPES],
                )
            )
            ctx.evidence.append(
                EvidenceItem(
                    field="original_authority",
                    value=raw,
                    source=f"span_attribute:{src}",
                    span_id=sid,
                    confidence="explicit",
                )
            )
            continue
        parsed_sets.append((parsed, src, sid))

    if not parsed_sets:
        return

    # Check for conflicts: different scope sets from different spans
    unique_sets = {ps for ps, _, _ in parsed_sets}

    if len(unique_sets) > 1:
        ctx.warnings.append(
            ExtractionWarning(
                field="original_authority",
                warning_type="conflicting",
                message=(
                    f"Multiple conflicting scope sets for "
                    f"{ATTR_PRINCIPAL_SCOPES}: "
                    f"{[sorted(s) for s in unique_sets]}"
                ),
                sources=[ATTR_PRINCIPAL_SCOPES],
            )
        )
        for ps, src, sid in parsed_sets:
            ctx.evidence.append(
                EvidenceItem(
                    field="original_authority",
                    value=sorted(ps),
                    source=f"span_attribute:{src}",
                    span_id=sid,
                    confidence="explicit",
                )
            )
        return

    # Consistent scopes
    scopes = next(iter(unique_sets))
    ctx.original_scopes = sorted(scopes)
    first = parsed_sets[0]
    ctx.evidence.append(
        EvidenceItem(
            field="original_authority",
            value=sorted(scopes),
            source=f"span_attribute:{first[1]}",
            span_id=first[2],
            confidence="explicit",
        )
    )


def _resolve_delegation(
    ctx: AuthorizationContext,
    hops: list[RawDelegationHop],
) -> None:
    """Process delegation hops with per-hop conflict detection."""
    if not hops:
        return

    # Check for duplicate hops on the same span (conflicting data for
    # the same logical field and hop)
    seen_spans: dict[str | None, list[RawDelegationHop]] = {}
    for hop in hops:
        seen_spans.setdefault(hop.span_id, []).append(hop)

    for sid, span_hops in seen_spans.items():
        if len(span_hops) > 1:
            # Multiple delegation attributes on the same span — this is
            # only a conflict if they disagree on the same field
            from_ids = {h.from_id for h in span_hops if h.from_id is not None}
            to_ids = {h.to_id for h in span_hops if h.to_id is not None}

            if len(from_ids) > 1:
                ctx.warnings.append(
                    ExtractionWarning(
                        field="delegation.from",
                        warning_type="conflicting",
                        message=(
                            f"Conflicting delegation.from on span {sid}: "
                            f"{sorted(from_ids)}"
                        ),
                        sources=[ATTR_DELEGATION_FROM],
                    )
                )
            if len(to_ids) > 1:
                ctx.warnings.append(
                    ExtractionWarning(
                        field="delegation.to",
                        warning_type="conflicting",
                        message=(
                            f"Conflicting delegation.to on span {sid}: "
                            f"{sorted(to_ids)}"
                        ),
                        sources=[ATTR_DELEGATION_TO],
                    )
                )

    ctx.delegation_hops = hops

    # Record evidence for each hop
    for hop in hops:
        if hop.from_id is not None:
            ctx.evidence.append(
                EvidenceItem(
                    field="delegation.from",
                    value=hop.from_id,
                    source=f"span_attribute:{ATTR_DELEGATION_FROM}",
                    span_id=hop.span_id,
                    confidence="explicit",
                )
            )
        else:
            ctx.warnings.append(
                ExtractionWarning(
                    field="delegation.from",
                    warning_type="missing",
                    message=(
                        f"Delegation source missing on span "
                        f"{hop.span_id}"
                    ),
                    sources=[ATTR_DELEGATION_FROM],
                )
            )

        if hop.to_id is not None:
            ctx.evidence.append(
                EvidenceItem(
                    field="delegation.to",
                    value=hop.to_id,
                    source=f"span_attribute:{ATTR_DELEGATION_TO}",
                    span_id=hop.span_id,
                    confidence="explicit",
                )
            )
        else:
            ctx.warnings.append(
                ExtractionWarning(
                    field="delegation.to",
                    warning_type="missing",
                    message=(
                        f"Delegation target missing on span "
                        f"{hop.span_id}"
                    ),
                    sources=[ATTR_DELEGATION_TO],
                )
            )

        if hop.credential_type_raw is not None:
            ctx.evidence.append(
                EvidenceItem(
                    field="delegation.credential_type",
                    value=hop.credential_type_raw,
                    source=f"span_attribute:{ATTR_CREDENTIAL_TYPE}",
                    span_id=hop.span_id,
                    confidence="explicit",
                )
            )
        if hop.scopes_raw is not None:
            parsed_scopes = _parse_scopes(hop.scopes_raw)
            ctx.evidence.append(
                EvidenceItem(
                    field="delegation.authority",
                    value=sorted(parsed_scopes),
                    source=f"span_attribute:{ATTR_DELEGATION_SCOPES}",
                    span_id=hop.span_id,
                    confidence="explicit",
                )
            )
            if _has_malformed_scope_items(hop.scopes_raw):
                ctx.warnings.append(
                    ExtractionWarning(
                        field="delegation.authority",
                        warning_type="malformed",
                        message=(
                            f"Could not parse delegated scopes from "
                            f"{ATTR_DELEGATION_SCOPES} on span {hop.span_id}"
                        ),
                        sources=[ATTR_DELEGATION_SCOPES],
                    )
                )

        scopes, scopes_known = _parse_scopes_checked(hop.scopes_raw)

        if scopes_known:
            ctx.evidence.append(
                EvidenceItem(
                    field="delegation.scopes",
                    value=sorted(scopes),
                    source=f"span_attribute:{ATTR_DELEGATION_SCOPES}",
                    span_id=hop.span_id,
                    confidence="explicit",
                )
            )
        else:
            warning_type = (
                "missing" if hop.scopes_raw is None else "malformed"
            )
            ctx.warnings.append(
                ExtractionWarning(
                    field="delegation.scopes",
                    warning_type=warning_type,
                    message=(
                        f"Delegation scopes {warning_type} on span "
                        f"{hop.span_id}; authorization cannot be inferred "
                        "from this hop"
                    ),
                    sources=[ATTR_DELEGATION_SCOPES],
                )
            )


def _resolve_effective_action(
    ctx: AuthorizationContext,
    all_spans: list[SpanLike],
    leaf_spans: list[SpanLike],
) -> None:
    """Determine the effective downstream action from the leaf span."""
    # Prefer leaf spans (the deepest in the call chain)
    target_spans = leaf_spans if leaf_spans else all_spans

    if not target_spans:
        return

    # Use the last leaf span as the effective operation
    leaf = target_spans[-1]

    ctx.effective_span_name = leaf.span_name
    ctx.effective_service = leaf.service_name
    ctx.evidence.append(
        EvidenceItem(
            field="effective_action",
            value=leaf.span_name,
            source="span_field:span_name",
            span_id=leaf.span_id,
            confidence="explicit",
        )
    )

    if leaf.service_name is not None:
        if ctx.acting_service_name is None:
            ctx.acting_service_name = leaf.service_name
            ctx.evidence.append(
                EvidenceItem(
                    field="acting_service",
                    value=leaf.service_name,
                    source="span_field:service_name",
                    span_id=leaf.span_id,
                    confidence="explicit",
                )
            )

    # Resolve outcome from status_code
    # OTel status codes: 0 = UNSET, 1 = OK, 2 = ERROR
    if leaf.status_code == 1:
        ctx.outcome_success = True
    elif leaf.status_code == 2:
        ctx.outcome_success = False
    else:
        ctx.outcome_success = None

    ctx.evidence.append(
        EvidenceItem(
            field="outcome",
            value=leaf.status_code,
            source="span_field:status_code",
            span_id=leaf.span_id,
            confidence="explicit",
        )
    )


def _resolve_service_authority(
    ctx: AuthorizationContext,
    config: dict[str, list[str]] | None,
) -> None:
    """Apply service authority from explicit configuration."""
    if config is None or ctx.acting_service_name is None:
        return

    perms = config.get(ctx.acting_service_name)
    if perms is not None:
        ctx.service_authority_permissions = list(perms)
        ctx.evidence.append(
            EvidenceItem(
                field="service_authority",
                value=list(perms),
                source="config:service_authority",
                span_id=None,
                confidence="configured",
            )
        )


def _add_missing_warnings(ctx: AuthorizationContext) -> None:
    """Add warnings for fields that could not be extracted."""
    if not ctx.has_principal:
        # Only add if not already warned about conflicts
        existing = {w.field for w in ctx.warnings}
        if "initiating_principal.id" not in existing:
            ctx.warnings.append(
                ExtractionWarning(
                    field="initiating_principal.id",
                    warning_type="missing",
                    message=(
                        f"No {ATTR_PRINCIPAL_ID} or {ATTR_ENDUSER_ID} "
                        f"attribute found on any span"
                    ),
                    sources=[ATTR_PRINCIPAL_ID, ATTR_ENDUSER_ID],
                )
            )

    if not ctx.has_authority:
        existing = {w.field for w in ctx.warnings}
        if "original_authority" not in existing:
            ctx.warnings.append(
                ExtractionWarning(
                    field="original_authority",
                    warning_type="missing",
                    message=(
                        f"No {ATTR_PRINCIPAL_SCOPES} attribute found "
                        f"on any span"
                    ),
                    sources=[ATTR_PRINCIPAL_SCOPES],
                )
            )

    if not ctx.has_action:
        ctx.warnings.append(
            ExtractionWarning(
                field="effective_action",
                warning_type="missing",
                message="No effective action could be determined from spans",
                sources=[],
            )
        )
