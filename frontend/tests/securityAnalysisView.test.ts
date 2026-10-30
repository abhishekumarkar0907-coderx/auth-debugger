import assert from 'node:assert/strict';
import { test } from 'node:test';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { renderSecurityAnalysisState } from '../src/components/securityAnalysisView.ts';
import type { AnalysisPanelState, DeterministicAnalysisView } from '../src/types/securityAnalysis.ts';

const actualEngineShape: DeterministicAnalysisView = {
  verdict: 'DETECTED',
  reason: 'payments:charge required but absent from delegated request authority',
  details: { required_action: ['payments:charge'], request_authority: ['orders:read'] },
  finding: {
    finding_id: 'finding-regression-1', verdict: 'DETECTED', trace_id: 'trace-regression-1',
    initiating_principal: { principal_id: 'user-123', principal_type: 'user', service_name: null },
    delegated_authority: { permissions: ['orders:read'], source: 'delegated' },
    effective_action: 'payments:charge', required_authority: ['payments:charge'],
    service_authority: { permissions: ['payments:charge'], source: 'service' },
    attack_path: ['user:user-123', 'checkout → payment [delegated_token]'],
    evidence: { span_id: 'span-42', policy: 'payments:charge' },
    reason: 'payments:charge required but absent from delegated request authority', severity: 'HIGH',
  },
};

function render(state: AnalysisPanelState): string {
  return renderToStaticMarkup(React.createElement(React.Fragment, null, renderSecurityAnalysisState(state)));
}

test('loading state renders an accessible status', () => {
  assert.match(render({ kind: 'loading' }), /role="status"/);
  assert.match(render({ kind: 'loading' }), /Loading deterministic analysis/);
});

test('empty state does not present absence of findings as a clean verdict', () => {
  const html = render({ kind: 'empty' });
  assert.match(html, /No deterministic analysis is available/);
  assert.match(html, /does not mean the trace is safe/);
  assert.doesNotMatch(html, /NOT_DETECTED/);
});

test('API error state is explicit and accessible', () => {
  const html = render({ kind: 'error', message: 'Analysis service unavailable' });
  assert.match(html, /role="alert"/);
  assert.match(html, /Analysis service unavailable/);
});

test('serialized deterministic engine result renders verdict, permissions, path, and evidence', () => {
  const html = render({ kind: 'ready', analysis: actualEngineShape });
  for (const value of ['DETECTED', 'HIGH', 'finding-regression-1', 'user:user-123', 'payments:charge', 'orders:read', 'span-42', 'checkout → payment']) {
    assert.ok(html.includes(value), `Expected panel output to include ${value}`);
  }
  assert.match(html, /deterministic authorization engine/);
});

test('conflicting outer and finding verdicts are surfaced rather than silently chosen', () => {
  const conflicted = { ...actualEngineShape, verdict: 'NOT_DETECTED' as const };
  assert.match(render({ kind: 'ready', analysis: conflicted }), /conflicting deterministic verdicts/i);
});

test('serialized engine result with INSUFFICIENT_EVIDENCE renders safely without null errors', () => {
  const insufficientView: DeterministicAnalysisView = {
    verdict: 'INSUFFICIENT_EVIDENCE',
    reason: 'Effective downstream operation is missing from the scenario',
    details: {},
    finding: {
      finding_id: 'finding-789',
      verdict: 'INSUFFICIENT_EVIDENCE',
      trace_id: 'trace-789',
      initiating_principal: {
        principal_id: 'user-321',
        principal_type: 'user',
        service_name: null,
      },
      delegated_authority: null,
      effective_action: null,
      required_authority: [],
      service_authority: null,
      attack_path: [],
      evidence: {},
      reason: 'Effective downstream operation is missing from the scenario',
      severity: 'UNSCORED',
    },
  };

  const html = render({ kind: 'ready', analysis: insufficientView });
  assert.ok(html.includes('INSUFFICIENT_EVIDENCE'));
  assert.ok(html.includes('UNSCORED'));
  assert.ok(html.includes('user:user-321'));
  assert.ok(html.includes('The backend returned no evidence for this finding.'));
});
