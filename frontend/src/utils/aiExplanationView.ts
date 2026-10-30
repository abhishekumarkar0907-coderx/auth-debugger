import React from 'react';
import type { AiExplanationUiState } from '../services/aiExplanation.ts';

/** Shared accessible state markup so offline/error states can be tested without a browser. */
export function renderAiExplanationState(
  state: AiExplanationUiState,
  onRetry?: () => void,
): React.ReactNode {
  if (state.kind === 'idle') return React.createElement('p', null, 'Select a deterministic finding to request an explanation.');
  if (state.kind === 'loading') return React.createElement('p', { role: 'status' }, 'Preparing an explanation from the supplied finding and evidence…');
  if (state.kind === 'ready') return null;
  const text = state.message;
  return React.createElement(
    'div',
    { className: `ai-state ai-state-${state.kind}`, role: state.kind === 'error' || state.kind === 'timeout' ? 'alert' : 'status' },
    React.createElement('p', null, text),
    onRetry && (state.kind === 'error' || state.kind === 'timeout')
      ? React.createElement('button', { type: 'button', onClick: onRetry }, 'Try again')
      : null,
  );
}
