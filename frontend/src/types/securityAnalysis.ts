/**
 * Frontend view shape for one deterministic auth-engine DetectionResult.
 * This mirrors auth-engine dataclasses after JSON serialization; it is not a
 * proposed backend HTTP envelope. Palak's agreed response adapter will map to it.
 */
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
  source: 'original' | 'delegated' | 'service';
}

export interface DeterministicFindingView {
  finding_id: string;
  /** Optional detector-supplied category. The UI must not derive one. */
  category?: string | null;
  verdict: DeterministicVerdict;
  trace_id: string | null;
  initiating_principal: PrincipalView | null;
  delegated_authority: AuthorityView | null;
  effective_action: string | null;
  required_authority: string[];
  service_authority: AuthorityView | null;
  attack_path: string[];
  evidence: Record<string, unknown>;
  reason: string;
  severity: FindingSeverity;
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

/** Backend HTTP response envelope for trace analysis. */
export interface TraceAnalysisEnvelope {
  trace_id: string;
  nodes: unknown[];
  edges: unknown[];
  authority_amplification_hops: unknown[];
  security_analysis: DeterministicAnalysisView | null;
}

/** Adapter mapping the backend response envelope to the frontend deterministic view model. */
export function adaptTraceAnalysisResponse(
  envelope: TraceAnalysisEnvelope | null | undefined,
): DeterministicAnalysisView | null {
  if (!envelope || !envelope.security_analysis) {
    return null;
  }
  return envelope.security_analysis;
}
