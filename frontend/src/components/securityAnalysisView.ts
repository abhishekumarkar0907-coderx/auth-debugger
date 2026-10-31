import React from 'react';
import type { AnalysisPanelState, DeterministicAnalysisView } from '../types/securityAnalysis.ts';

function text(value: unknown): string {
  if (typeof value === 'string') return value;
  if (value === null || value === undefined) return '';
  return typeof value === 'object' ? JSON.stringify(value) : String(value);
}

function findingMarkup(analysis: DeterministicAnalysisView): React.ReactElement {
  const finding = analysis.finding;
  const evidence = Object.entries(finding.evidence ?? {});
  const principal = finding.initiating_principal;
  const principalLabel = principal
    ? `${principal.principal_type}:${principal.principal_id}${principal.service_name ? `@${principal.service_name}` : ''}`
    : 'Not provided';
  return React.createElement('section', { className: 'security-analysis', 'aria-label': 'Security analysis' },
    React.createElement('header', null,
      React.createElement('h3', null, 'Security analysis'),
      React.createElement('span', { className: `verdict-${analysis.verdict.toLowerCase().replaceAll('_', '-')}` }, analysis.verdict),
      React.createElement('span', { className: 'severity-label' }, finding.severity),
    ),
    analysis.verdict !== finding.verdict
      ? React.createElement('p', { role: 'alert' }, 'The response contains conflicting deterministic verdicts. Review the backend result.')
      : React.createElement('p', null, analysis.reason || finding.reason),
    React.createElement('dl', null,
      React.createElement('dt', null, 'Finding'), React.createElement('dd', null, finding.finding_id),
      React.createElement('dt', null, 'Initiating principal'), React.createElement('dd', null, principalLabel),
      React.createElement('dt', null, 'Action'), React.createElement('dd', null, finding.effective_action || 'Not provided'),
      React.createElement('dt', null, 'Required authority'), React.createElement('dd', null, finding.required_authority.join(', ') || 'Not provided'),
      React.createElement('dt', null, 'Delegated authority'), React.createElement('dd', null, finding.delegated_authority?.permissions.join(', ') || 'Not provided'),
      React.createElement('dt', null, 'Service authority'), React.createElement('dd', null, finding.service_authority?.permissions.join(', ') || 'Not provided'),
    ),
    finding.attack_path.length > 0
      ? React.createElement('ol', { 'aria-label': 'Deterministic attack path' }, ...finding.attack_path.map((hop, index) => React.createElement('li', { key: `${index}-${hop}` }, hop)))
      : null,
    React.createElement('h4', null, 'Evidence'),
    evidence.length > 0
      ? React.createElement('dl', null, ...evidence.flatMap(([key, value]) => [
        React.createElement('dt', { key: `${key}-label` }, key),
        React.createElement('dd', { key: `${key}-value` }, text(value)),
      ]))
      : React.createElement('p', null, 'The backend returned no evidence for this finding.'),
    React.createElement('p', { className: 'analysis-method-note' }, 'Verdict and severity are supplied by the deterministic authorization engine.'),
  );
}

/** Shared markup for the contract-level panel states, independently testable before API agreement. */
export function renderSecurityAnalysisState(state: AnalysisPanelState): React.ReactNode {
  if (state.kind === 'loading') return React.createElement('section', { role: 'status', 'aria-label': 'Security analysis' }, 'Loading deterministic analysis…');
  if (state.kind === 'empty') return React.createElement('section', { 'aria-label': 'Security analysis' }, React.createElement('h3', null, 'Security analysis'), React.createElement('p', null, state.message || 'No deterministic analysis is available for this trace. This does not mean the trace is safe.'));
  if (state.kind === 'error') return React.createElement('section', { role: 'alert', 'aria-label': 'Security analysis error' }, React.createElement('h3', null, 'Security analysis unavailable'), React.createElement('p', null, state.message));
  return findingMarkup(state.analysis);
}
