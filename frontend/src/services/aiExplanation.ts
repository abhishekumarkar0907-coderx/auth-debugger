import type { DeterministicVerdict } from '../types/securityAnalysis.ts';

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
  status: 'ready' | 'insufficient_evidence' | 'unavailable' | 'timeout' | 'error';
  finding_id: string;
  /** Optional explanatory text only. It never carries a detector decision. */
  explanation?: AiExplanation | null;
  message?: string | null;
}

/** Loads optional explanatory text without changing deterministic findings. */
export type AiExplanationLoader = (findingId: string, signal: AbortSignal) => Promise<AiExplanationResponse>;

export function shouldRequestExplanation(
  verdict: DeterministicVerdict,
  findingId: string | null,
): findingId is string {
  return verdict === 'DETECTED' && findingId !== null && findingId.length > 0;
}

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
  if (response.status === 'timeout') {
    return { kind: 'timeout', message: response.message || 'The AI provider timed out. The deterministic finding is unchanged.' };
  }
  if (response.status === 'error') {
    return { kind: 'error', message: response.message || 'Could not load the explanation.' };
  }
  return { kind: 'unavailable', message: response.message || 'AI explanations are currently unavailable.' };
}

export function getExplanationFailureState(error: unknown, timedOut: boolean): AiExplanationUiState {
  const status = (error as { status?: number | string } | null)?.status;
  if (timedOut || status === 504 || status === 'timeout') {
    return { kind: 'timeout', message: 'The AI provider timed out. The deterministic finding is unchanged.' };
  }
  if (status === 503 || status === 'unavailable') {
    return { kind: 'unavailable', message: 'The AI provider is not configured or is temporarily unavailable.' };
  }
  return {
    kind: 'error',
    message: error instanceof Error ? error.message : 'Could not load the explanation.',
  };
}
