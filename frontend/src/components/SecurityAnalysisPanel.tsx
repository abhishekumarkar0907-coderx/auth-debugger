import React from 'react';
import type { SecurityAnalysis } from '../types.ts';

interface SecurityAnalysisPanelProps {
  analysis: SecurityAnalysis | null;
  error: string | null;
}

function formatJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

export const SecurityAnalysisPanel: React.FC<SecurityAnalysisPanelProps> = ({
  analysis,
  error,
}) => {
  const verdict = analysis?.verdict;
  const warnings = analysis?.context?.warnings ?? [];
  const finding = analysis?.finding;
  const findingType = finding?.finding_type;
  const findingEvidence = finding?.evidence;
  const attackPath = Array.isArray(finding?.attack_path) ? finding.attack_path : [];
  const hasFindingEvidence = findingEvidence !== undefined && findingEvidence !== null;
  const details = analysis?.details;
  const hasDetails = details && Object.keys(details).length > 0;

  return (
    <section className="security-analysis-panel" aria-labelledby="security-analysis-title">
      <div className="security-analysis-heading">
        <div>
          <span className="security-analysis-eyebrow">Security Engine</span>
          <h3 id="security-analysis-title">Authorization analysis</h3>
        </div>
        {verdict ? (
          <span
            className={`security-verdict security-verdict-${verdict.toLowerCase()}`}
            role="status"
          >
            {verdict.replaceAll('_', ' ')}
          </span>
        ) : (
          <span className="security-verdict security-verdict-unavailable" role="status">
            {error ? 'UNAVAILABLE' : 'NO RESULT'}
          </span>
        )}
      </div>

      {analysis ? (
        <>
          {findingType && findingType !== 'NONE' && (
            <p className="security-finding-type">
              Finding <strong>{findingType.replaceAll('_', ' ')}</strong>
            </p>
          )}
          {analysis.reason && <p className="security-analysis-reason">{analysis.reason}</p>}
          {(hasFindingEvidence || attackPath.length > 0) && (
            <details className="security-analysis-details">
              <summary>Finding evidence</summary>
              {attackPath.length > 0 && (
                <>
                  <h4>Attack path</h4>
                  <ol>
                    {attackPath.map((step, index) => (
                      <li key={`${index}-${step}`}>{step}</li>
                    ))}
                  </ol>
                </>
              )}
              {hasFindingEvidence && (
                <>
                  <h4>Supporting evidence</h4>
                  <pre>{formatJson(findingEvidence)}</pre>
                </>
              )}
            </details>
          )}
          {hasDetails && (
            <details className="security-analysis-details">
              <summary>Analysis details</summary>
              <pre>{formatJson(details)}</pre>
            </details>
          )}
          {warnings.length > 0 && (
            <div className="security-evidence-warnings" role="note">
              <h4>Incomplete or ambiguous evidence</h4>
              <ul>
                {warnings.map((warning, index) => (
                  <li key={`${warning.field}-${warning.warning_type}-${index}`}>
                    <strong>{warning.field.replaceAll('_', ' ')}</strong>
                    <span>{warning.message}</span>
                  </li>
                ))}
              </ul>
              <p>Unknown authority is not treated as authorization.</p>
            </div>
          )}
        </>
      ) : (
        <p className="security-analysis-unavailable">
          {error ?? 'Security analysis is not available in this backend response.'}
        </p>
      )}
    </section>
  );
};
