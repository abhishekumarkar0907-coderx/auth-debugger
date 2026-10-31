/** Normalized frontend view of the deterministic analysis in the backend graph response. */
export type DeterministicVerdict =
  | 'DETECTED'
  | 'NOT_DETECTED'
  | 'INSUFFICIENT_EVIDENCE';

export type FindingSeverity =
  | 'CRITICAL'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW'
  | 'INFO'
  | 'UNSCORED';

export interface PrincipalView {
  principal_id: string;
  principal_type: 'user' | 'service' | 'agent';
  service_name: string | null;
}

export interface AuthorityView {
  permissions: string[];
  source?: 'original' | 'delegated' | 'service';
}

export interface DeterministicFindingView {
  finding_id: string | null;
  /** Optional detector-supplied category. The UI must not derive one. */
  category?: string | null;
  verdict: DeterministicVerdict | null;
  trace_id: string | null;
  initiating_principal: PrincipalView | null;
  delegated_authority: AuthorityView | null;
  effective_action: string | null;
  required_authority: string[];
  service_authority: AuthorityView | null;
  attack_path: string[];
  evidence: Record<string, unknown>;
  reason: string | null;
  severity: FindingSeverity | null;
}

export interface DeterministicAnalysisView {
  verdict: DeterministicVerdict;
  finding: DeterministicFindingView;
  reason: string;
  details: Record<string, unknown>;
}

/** Optional explanation content deliberately carries no verdict or severity. */
export interface AiExplanationView {
  summary: { text: string; evidence_refs: string[] };
  why_detected: { text: string; evidence_refs: string[] };
  authority_difference: { text: string; evidence_refs: string[] };
  request_path_explanation: { text: string; evidence_refs: string[] };
  limitations: string[];
  remediation: Array<{ text: string; evidence_refs: string[] }>;
}

export type AnalysisPanelState =
  | { kind: 'loading' }
  | { kind: 'empty'; message?: string }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; analysis: DeterministicAnalysisView };

export interface AuthorizationGraphNode {
  id: string;
  type: string;
  label: string;
  metadata: Record<string, unknown>;
  authority?: string[];
  service?: string;
  required_authority?: string[];
}

export interface AuthorizationGraphEdge {
  source: string;
  target: string;
  type: string;
  trace_id: string;
  metadata: Record<string, unknown>;
  delegated_authority?: string[];
  credential_type?: string;
  explicit?: boolean;
  step_index?: number;
  service_authority?: string[] | null;
}

/** Backend GET /api/v1/traces/{trace_id}/graph response. */
export interface TraceGraphResponse {
  trace_id: string;
  nodes: AuthorizationGraphNode[];
  edges: AuthorizationGraphEdge[];
  authority_amplification_hops: unknown[];
  security_analysis: DeterministicAnalysisView | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isString(value: unknown): value is string {
  return typeof value === 'string';
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every(isString);
}

function isVerdict(value: unknown): value is DeterministicVerdict {
  return value === 'DETECTED' || value === 'NOT_DETECTED' || value === 'INSUFFICIENT_EVIDENCE';
}

function isFindingSeverity(value: unknown): value is FindingSeverity {
  return value === 'CRITICAL' || value === 'HIGH' || value === 'MEDIUM' ||
    value === 'LOW' || value === 'INFO' || value === 'UNSCORED';
}

function invalidGraphResponse(): never {
  throw new Error('The backend returned a malformed trace graph response.');
}

function graphNode(value: unknown): AuthorizationGraphNode {
  if (!isRecord(value)) return invalidGraphResponse();
  const { id, type, label, metadata, authority, service, required_authority } = value;
  if (
    !isString(id) ||
    !isString(type) ||
    !isString(label) ||
    !isRecord(metadata) ||
    (authority !== undefined && !isStringArray(authority)) ||
    (service !== undefined && !isString(service)) ||
    (required_authority !== undefined && !isStringArray(required_authority))
  ) {
    return invalidGraphResponse();
  }
  const node: AuthorizationGraphNode = {
    id,
    type,
    label,
    metadata,
  };
  if (authority !== undefined) node.authority = authority;
  if (service !== undefined) node.service = service;
  if (required_authority !== undefined) node.required_authority = required_authority;
  return node;
}

function graphEdge(value: unknown): AuthorizationGraphEdge {
  if (!isRecord(value)) return invalidGraphResponse();
  const {
    source,
    target,
    type,
    trace_id,
    metadata,
    delegated_authority,
    credential_type,
    explicit,
    step_index,
    service_authority,
  } = value;
  if (
    !isString(source) ||
    !isString(target) ||
    !isString(type) ||
    !isString(trace_id) ||
    !isRecord(metadata) ||
    (delegated_authority !== undefined && !isStringArray(delegated_authority)) ||
    (credential_type !== undefined && !isString(credential_type)) ||
    (explicit !== undefined && typeof explicit !== 'boolean') ||
    (step_index !== undefined && (typeof step_index !== 'number' || !Number.isFinite(step_index))) ||
    (service_authority !== undefined && service_authority !== null && !isStringArray(service_authority))
  ) {
    return invalidGraphResponse();
  }
  const edge: AuthorizationGraphEdge = {
    source,
    target,
    type,
    trace_id,
    metadata,
  };
  if (delegated_authority !== undefined) edge.delegated_authority = delegated_authority;
  if (credential_type !== undefined) edge.credential_type = credential_type;
  if (explicit !== undefined) edge.explicit = explicit;
  if (step_index !== undefined) edge.step_index = step_index;
  if (service_authority !== undefined) edge.service_authority = service_authority;
  return edge;
}

function authorityView(value: unknown): AuthorityView | null {
  if (value === null || value === undefined) return null;
  if (isStringArray(value)) return { permissions: value };
  if (isRecord(value) && isStringArray(value.permissions)) {
    const source = value.source;
    return {
      permissions: value.permissions,
      ...(source === 'original' || source === 'delegated' || source === 'service' ? { source } : {}),
    };
  }
  return invalidGraphResponse();
}

function optionalString(value: unknown, fallback: string | null = null): string | null {
  if (value === undefined || value === null) return fallback;
  return isString(value) ? value : invalidGraphResponse();
}

function stringArrayOrEmpty(value: unknown): string[] {
  if (value === undefined || value === null) return [];
  return isStringArray(value) ? value : invalidGraphResponse();
}

function deterministicAnalysis(value: unknown): DeterministicAnalysisView | null {
  if (value === null) return null;
  if (!isRecord(value) || !isVerdict(value.verdict) || !isRecord(value.finding)) {
    return invalidGraphResponse();
  }

  const rawFinding = value.finding;
  const findingVerdict = rawFinding.verdict;
  if (findingVerdict !== undefined && findingVerdict !== null && !isVerdict(findingVerdict)) {
    return invalidGraphResponse();
  }

  let principal: PrincipalView | null = null;
  if (rawFinding.initiating_principal !== undefined && rawFinding.initiating_principal !== null) {
    const rawPrincipal = rawFinding.initiating_principal;
    if (
      !isRecord(rawPrincipal) ||
      !isString(rawPrincipal.principal_id) ||
      (rawPrincipal.principal_type !== 'user' &&
        rawPrincipal.principal_type !== 'service' &&
        rawPrincipal.principal_type !== 'agent')
    ) {
      return invalidGraphResponse();
    }
    principal = {
      principal_id: rawPrincipal.principal_id,
      principal_type: rawPrincipal.principal_type,
      service_name: optionalString(rawPrincipal.service_name),
    };
  }

  if (rawFinding.evidence !== undefined && !isRecord(rawFinding.evidence)) {
    return invalidGraphResponse();
  }
  if (value.details !== undefined && !isRecord(value.details)) return invalidGraphResponse();

  const category = rawFinding.classification ?? rawFinding.finding_type;
  if (category !== undefined && category !== null && !isString(category)) return invalidGraphResponse();

  const rawSeverity = rawFinding.severity;
  if (rawSeverity !== undefined && rawSeverity !== null && !isFindingSeverity(rawSeverity)) {
    return invalidGraphResponse();
  }

  const evidence = rawFinding.evidence;
  if (evidence !== undefined && !isRecord(evidence)) return invalidGraphResponse();
  const details = value.details;
  if (details !== undefined && !isRecord(details)) return invalidGraphResponse();

  const finding: DeterministicFindingView = {
    finding_id: optionalString(rawFinding.finding_id),
    verdict: findingVerdict === undefined || findingVerdict === null ? null : findingVerdict,
    trace_id: optionalString(rawFinding.trace_id),
    initiating_principal: principal,
    delegated_authority: authorityView(rawFinding.delegated_authority),
    effective_action: optionalString(rawFinding.effective_action),
    required_authority: stringArrayOrEmpty(rawFinding.required_authority),
    service_authority: authorityView(rawFinding.service_authority),
    attack_path: stringArrayOrEmpty(rawFinding.attack_path),
    evidence: evidence ?? {},
    reason: optionalString(rawFinding.reason),
    severity: rawSeverity === undefined || rawSeverity === null
      ? null
      : rawSeverity,
    ...(category === undefined || category === null ? {} : { category }),
  };

  const reason = optionalString(value.reason) ?? finding.reason;
  if (!reason) return invalidGraphResponse();
  return {
    verdict: value.verdict,
    finding,
    reason,
    details: details ?? {},
  };
}

/** Validate and adapt the backend graph response; no detector fields are inferred. */
export function adaptTraceGraphResponse(value: unknown): TraceGraphResponse {
  if (
    !isRecord(value) ||
    !isString(value.trace_id) ||
    !Array.isArray(value.nodes) ||
    !Array.isArray(value.edges) ||
    !Array.isArray(value.authority_amplification_hops)
  ) {
    return invalidGraphResponse();
  }

  const nodes = value.nodes.map(graphNode);
  const nodeIds = new Set(nodes.map((node) => node.id));
  if (nodeIds.size !== nodes.length) return invalidGraphResponse();
  const edges = value.edges.map(graphEdge);
  if (edges.some((edge) =>
    !nodeIds.has(edge.source) ||
    !nodeIds.has(edge.target) ||
    edge.trace_id !== value.trace_id
  )) {
    return invalidGraphResponse();
  }

  if (
    isRecord(value.security_analysis) &&
    ((value.security_analysis.trace_id !== undefined &&
      value.security_analysis.trace_id !== value.trace_id) ||
      (isRecord(value.security_analysis.finding) &&
        value.security_analysis.finding.trace_id !== undefined &&
        value.security_analysis.finding.trace_id !== value.trace_id))
  ) {
    return invalidGraphResponse();
  }

  return {
    trace_id: value.trace_id,
    nodes,
    edges,
    authority_amplification_hops: value.authority_amplification_hops,
    security_analysis: deterministicAnalysis(value.security_analysis),
  };
}
