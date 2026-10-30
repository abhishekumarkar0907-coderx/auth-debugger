import React, { useEffect, useState } from 'react';
import type { AiExplanationLoader, AiExplanationResponse, AiExplanationUiState } from '../services/aiExplanation.ts';
import { getExplanationUiState } from '../services/aiExplanation.ts';
import { renderAiExplanationState } from '../utils/aiExplanationView.ts';
import './AiExplanationPanel.css';

interface AiExplanationPanelProps {
  findingId: string | null;
  loadExplanation: AiExplanationLoader;
}

export const AiExplanationPanel: React.FC<AiExplanationPanelProps> = ({ findingId, loadExplanation }) => {
  const [state, setState] = useState<AiExplanationUiState>({ kind: 'idle' });
  const [retry, setRetry] = useState(0);

  useEffect(() => {
    if (!findingId) {
      setState({ kind: 'idle' });
      return;
    }
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 25_000);
    setState({ kind: 'loading' });
    loadExplanation(findingId, controller.signal)
      .then((response: AiExplanationResponse) => setState(getExplanationUiState(response)))
      .catch((error: unknown) => {
        const status = (error as { status?: number | string })?.status;
        if (controller.signal.aborted) {
          setState({ kind: 'timeout', message: 'The explanation took too long. The deterministic finding is unchanged; you can try again.' });
        } else if (status === 503 || status === 'unavailable') {
          setState({ kind: 'unavailable', message: 'The AI provider is not configured or is temporarily unavailable.' });
        } else if (status === 504 || status === 'timeout') {
          setState({ kind: 'timeout', message: 'The AI provider timed out. The deterministic finding is unchanged.' });
        } else {
          setState({ kind: 'error', message: error instanceof Error ? error.message : 'Could not load the explanation.' });
        }
      })
      .finally(() => window.clearTimeout(timer));
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [findingId, loadExplanation, retry]);

  return (
    <section className="ai-explanation-panel" aria-labelledby="ai-explanation-title" aria-live="polite">
      <header>
        <div><p className="security-eyebrow">EVIDENCE-GROUNDED ASSISTANCE</p><h4 id="ai-explanation-title">AI explanation</h4></div>
        {findingId && <span className="ai-source-verdict">Optional explanation</span>}
      </header>
      {state.kind !== 'ready' && renderAiExplanationState(state, () => setRetry((n) => n + 1))}
      {state.kind === 'ready' && state.response.explanation && (
        <div className="ai-explanation-content">
          <Claim title="Summary" claim={state.response.explanation.summary} />
          <Claim title="Why the detector flagged it" claim={state.response.explanation.why_detected} />
          <Claim title="Authority difference" claim={state.response.explanation.authority_difference} />
          <Claim title="Request path" claim={state.response.explanation.request_path_explanation} />
          {state.response.explanation.limitations.length > 0 && <div><strong>Limitations</strong><ul>{state.response.explanation.limitations.map((item, i) => <li key={i}>{item}</li>)}</ul></div>}
          {state.response.explanation.remediation.length > 0 && <div><strong>Remediation to consider</strong>{state.response.explanation.remediation.map((claim, i) => <Claim key={i} title="" claim={claim} />)}</div>}
          <p className="ai-authority-note">This text explains the deterministic finding; it does not set or change the verdict or severity.</p>
        </div>
      )}
    </section>
  );
};

const Claim: React.FC<{ title: string; claim: { text: string; evidence_refs: string[] } }> = ({ title, claim }) => (
  <div className="ai-claim">{title && <strong>{title}</strong>}<p>{claim.text}</p>{claim.evidence_refs.length > 0 && <small>Evidence: {claim.evidence_refs.join(', ')}</small>}</div>
);
