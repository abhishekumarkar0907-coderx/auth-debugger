export interface ExplanationClaim {
  text: string;
  evidence_refs: string[];
}

export interface AiExplanation {
  summary: ExplanationClaim;
  why_detected: ExplanationClaim;
  authority_difference: ExplanationClaim;
  request_path_explanation: ExplanationClaim;
  limitations: string[];
  remediation: ExplanationClaim[];
}

export interface AiExplanationResponse {
  status: 'ready' | 'insufficient_evidence' | 'unavailable';
  finding_id: string;
  /** Optional explanatory text only. It never carries a detector decision. */
  explanation?: AiExplanation | null;
  message?: string | null;
}

/** Injected adapter, to be implemented only after Palak confirms the API contract. */
export type AiExplanationLoader = (findingId: string, signal: AbortSignal) => Promise<AiExplanationResponse>;

export type AiExplanationUiState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'ready'; response: AiExplanationResponse }
  | { kind: 'insufficient'; message: string }
  | { kind: 'unavailable'; message: string }
  | { kind: 'timeout'; message: string }
  | { kind: 'error'; message: string };

export function getExplanationUiState(
  response: AiExplanationResponse,
): AiExplanationUiState {
  if (response.status === 'ready' && response.explanation) return { kind: 'ready', response };
  if (response.status === 'insufficient_evidence') {
    return { kind: 'insufficient', message: response.message || 'The analysis did not include enough evidence to explain this finding.' };
  }
  return { kind: 'unavailable', message: response.message || 'AI explanations are currently unavailable.' };
}
