import assert from 'node:assert/strict';
import { test } from 'node:test';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import {
  getExplanationUiState,
  type AiExplanationResponse,
} from '../src/services/aiExplanation.ts';
import { renderAiExplanationState } from '../src/utils/aiExplanationView.ts';

const ready: AiExplanationResponse = {
  status: 'ready', finding_id: 'f-1',
  explanation: {
    summary: { text: 'An authority gap was detected.', evidence_refs: ['finding.reason'] },
    why_detected: { text: 'Required authority is absent.', evidence_refs: ['finding.reason'] },
    authority_difference: { text: 'The request has a narrower scope.', evidence_refs: ['finding.reason'] },
    request_path_explanation: { text: 'Path evidence is available.', evidence_refs: ['finding.reason'] },
    limitations: [], remediation: [],
  },
};

test('AI response UI maps ready, insufficient, and provider-unavailable states', () => {
  assert.equal(getExplanationUiState(ready).kind, 'ready');
  assert.equal(getExplanationUiState({ ...ready, status: 'insufficient_evidence', explanation: null }).kind, 'insufficient');
  assert.equal(getExplanationUiState({ ...ready, status: 'unavailable', explanation: null }).kind, 'unavailable');
});

test('loading and error states render accessible feedback and retry affordance', () => {
  const loading = renderToStaticMarkup(React.createElement(React.Fragment, null, renderAiExplanationState({ kind: 'loading' })));
  assert.match(loading, /role="status"/);
  const timeout = renderToStaticMarkup(React.createElement(React.Fragment, null,
    renderAiExplanationState({ kind: 'timeout', message: 'Provider timed out' }, () => undefined)));
  assert.match(timeout, /role="alert"/);
  assert.match(timeout, /Provider timed out/);
  assert.match(timeout, /Try again/);
});

test('AI explanation payload remains optional and has no verdict or severity fields', () => {
  assert.equal('verdict' in ready, false);
  assert.equal('severity' in ready, false);
  assert.equal('classification' in ready, false);
  assert.equal(getExplanationUiState(ready).kind, 'ready');
});
