import React, { useMemo, useState } from 'react';
import type { SpanRecord } from '../types.ts';
import { analyzeTraceMetadata } from '../utils/securityAnalysis.ts';

interface SecurityAnalysisPanelProps {
  traceId: string | null;
  spans: SpanRecord[];
}

const VERDICT_LABELS = {
  DETECTED: 'Finding detected',
  NOT_DETECTED: 'No finding detected',
  INSUFFICIENT_EVIDENCE: 'Insufficient evidence',
} as const;

const VALUE_ROWS = [
  ['Initiating principal', 'principal'],
  ['Acting identity', 'actor'],
  ['Service', 'service'],
  ['Action', 'action'],
  ['Resource', 'resource'],
  ['Outcome', 'outcome'],
  ['Delegation', 'delegation'],
  ['Credential transition', 'credentialTransition'],
  ['Claims / scopes', 'claims'],
] as const;

export const SecurityAnalysisPanel: React.FC<SecurityAnalysisPanelProps> = ({ traceId, spans }) => {
  const [showAllEvidence, setShowAllEvidence] = useState(false);
  const analysis = useMemo(() => analyzeTraceMetadata(spans), [spans]);

  return (
    <section className="security-analysis" aria-labelledby="security-analysis-title">
      <header className="security-analysis-header">
        <div>
          <p className="security-eyebrow">AUTHORIZATION REVIEW</p>
          <h3 id="security-analysis-title">Security analysis</h3>
          <p className="security-trace-id" title={traceId || undefined}>{traceId || 'Select a trace to review its evidence'}</p>
        </div>
        <span className={`verdict-badge verdict-${analysis.verdict.toLowerCase().replaceAll('_', '-')}`}>
          <span className="verdict-dot" aria-hidden="true" />
          {analysis.verdict}
        </span>
      </header>

      <div className={`analysis-summary ${analysis.verdict.toLowerCase().replaceAll('_', '-')}`}>
        <strong>{VERDICT_LABELS[analysis.verdict]}</strong>
        <p>
          {analysis.reason || (analysis.hasDetectorVerdict
            ? 'This verdict was supplied by the authorization detector.'
            : 'No detector result is attached to these spans yet. The interface will not infer a vulnerability from trace data alone.')}
        </p>
      </div>

      <div className="analysis-section">
        <div className="analysis-section-heading">
          <h4>Request context</h4>
          {analysis.severity && <span className="severity-label">{analysis.severity}</span>}
        </div>
        {analysis.findingId && <div className="finding-id"><span>Finding</span><code>{analysis.findingId}</code></div>}
        <dl className="analysis-facts">
          {VALUE_ROWS.map(([label, key]) => {
            const value = analysis[key];
            return value ? <div className="analysis-fact" key={key}><dt>{label}</dt><dd>{value}</dd></div> : null;
          })}
        </dl>
        {VALUE_ROWS.every(([, key]) => !analysis[key]) && (
          <p className="analysis-empty-hint">Identity and operation details will appear here when authorization attributes are present.</p>
        )}
      </div>

      <div className="analysis-section authority-section">
        <h4>Authority at the boundary</h4>
        <div className="authority-columns">
          <AuthorityGroup title="Required for action" values={analysis.requiredAuthority} />
          <AuthorityGroup title="Available to request" values={analysis.requestAuthority} />
          <AuthorityGroup title="Service permissions" values={analysis.serviceAuthority} />
        </div>
        {analysis.attackPath.length > 0 && (
          <ol className="attack-path" aria-label="Delegation path">
            {analysis.attackPath.map((hop, index) => <li key={`${index}-${hop}`}><span>{hop}</span></li>)}
          </ol>
        )}
      </div>

      <div className="analysis-section evidence-section">
        <div className="analysis-section-heading">
          <h4>Trace evidence</h4>
          <span className="evidence-count">{analysis.evidence.length}</span>
        </div>
        {analysis.evidence.length === 0 ? (
          <p className="analysis-empty-hint">No authorization-specific span attributes were found.</p>
        ) : (
          <>
            <dl className="evidence-list">
              {(showAllEvidence ? analysis.evidence : analysis.evidence.slice(0, 6)).map(({ key, value }, index) => (
                <div className="evidence-row" key={`${key}-${index}`}>
                  <dt>{key}</dt>
                  <dd>{typeof value === 'object' && value !== null ? JSON.stringify(value) : String(value)}</dd>
                </div>
              ))}
            </dl>
            {analysis.evidence.length > 6 && (
              <button className="evidence-toggle" type="button" onClick={() => setShowAllEvidence((shown) => !shown)}>
                {showAllEvidence ? 'Show less' : `Show all ${analysis.evidence.length} attributes`}
              </button>
            )}
          </>
        )}
      </div>

      <p className="analysis-method-note">Verdicts come from the deterministic authorization engine. Missing or conflicting detector output stays unconfirmed.</p>
    </section>
  );
};

const AuthorityGroup: React.FC<{ title: string; values: string[] }> = ({ title, values }) => (
  <div className="authority-group">
    <span>{title}</span>
    {values.length > 0 ? (
      <ul>{values.map((value) => <li key={value}>{value}</li>)}</ul>
    ) : <p>Not available</p>}
  </div>
);
