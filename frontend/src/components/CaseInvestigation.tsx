import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  createDemoScenario,
  fetchTraceGraph,
  fetchTraceSpans,
} from '../api.ts';
import type { SpanRecord, TraceGraphResponse } from '../types.ts';
import './CaseInvestigation.css';

const SCENARIOS = [
  {
    id: 'suspicious-delegation',
    marker: 'X',
    title: 'Suspicious delegation',
    description: 'A downstream request receives authority beyond the user’s original scope.',
  },
  {
    id: 'normal-request',
    marker: 'Y',
    title: 'No suspicious pattern',
    description: 'The service chain delegates only authority already present in the request.',
  },
  {
    id: 'insufficient-evidence',
    marker: 'Z',
    title: 'Insufficient evidence',
    description: 'A delegation hop is missing its recipient identity.',
  },
] as const;

type ScenarioId = (typeof SCENARIOS)[number]['id'];
type Selection =
  | { kind: 'span'; spanId: string }
  | { kind: 'call'; childSpanId: string };

interface LoadedScenario {
  traceId: string;
  spans: SpanRecord[];
  graph: TraceGraphResponse;
}

interface CaseInvestigationProps {
  apiBaseUrl: string;
}

function attribute(span: SpanRecord, key: string): string {
  const value = span.attributes[key];
  if (value === undefined || value === null || value === '') return 'Not available in trace';
  return Array.isArray(value) ? value.join(', ') : String(value);
}

export const CaseInvestigation: React.FC<CaseInvestigationProps> = ({ apiBaseUrl }) => {
  const [scenarioId, setScenarioId] = useState<ScenarioId>('suspicious-delegation');
  const [scenarioRun, setScenarioRun] = useState(0);
  const [loadedScenario, setLoadedScenario] = useState<LoadedScenario | null>(null);
  const [selection, setSelection] = useState<Selection | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadScenario = useCallback(async (id: ScenarioId, signal: AbortSignal) => {
    setIsLoading(true);
    setError(null);
    setLoadedScenario(null);
    setSelection(null);
    try {
      const created = await createDemoScenario(id, apiBaseUrl, signal);
      const [spans, graph] = await Promise.all([
        fetchTraceSpans(created.trace_id, apiBaseUrl, signal),
        fetchTraceGraph(created.trace_id, apiBaseUrl, signal),
      ]);
      if (!spans.length || graph.trace_id !== created.trace_id) {
        throw new Error('The backend did not return a complete trace for this scenario.');
      }
      setLoadedScenario({ traceId: created.trace_id, spans, graph });
      setSelection({ kind: 'span', spanId: spans[0].span_id });
    } catch (cause) {
      if (signal.aborted) return;
      setError(cause instanceof Error ? cause.message : 'Unable to load this scenario.');
    } finally {
      if (!signal.aborted) setIsLoading(false);
    }
  }, [apiBaseUrl]);

  useEffect(() => {
    const controller = new AbortController();
    void loadScenario(scenarioId, controller.signal);
    return () => controller.abort();
  }, [loadScenario, scenarioId, scenarioRun]);

  const orderedSpans = useMemo(
    () => loadedScenario
      ? [...loadedScenario.spans].sort((a, b) => a.start_time_unix_nano - b.start_time_unix_nano)
      : [],
    [loadedScenario],
  );
  const selectedSpan = useMemo(() => {
    if (!loadedScenario || !selection) return null;
    const spanId = selection.kind === 'span' ? selection.spanId : selection.childSpanId;
    return loadedScenario.spans.find((span) => span.span_id === spanId) || null;
  }, [loadedScenario, selection]);
  const analysis = loadedScenario?.graph.security_analysis ?? null;

  return (
    <section className="scenario-showcase" aria-label="Synthetic authorization scenarios">
      <header className="showcase-intro">
        <div>
          <p className="showcase-eyebrow">AUTHORIZATION DEBUGGER · INVESTIGATION DEMO</p>
          <h2>Follow the request. Examine the authority.</h2>
          <p>Select a synthetic trace to see what the deterministic authorization engine can conclude.</p>
        </div>
        <span className="showcase-source">Synthetic input · backend analysis</span>
      </header>

      <div className="scenario-selector" role="group" aria-label="Choose an investigation scenario">
        {SCENARIOS.map((scenario) => (
          <button
            type="button"
            key={scenario.id}
            className={`scenario-option ${scenario.id === scenarioId ? 'selected' : ''}`}
            aria-pressed={scenario.id === scenarioId}
            onClick={() => {
              setScenarioId(scenario.id);
              setScenarioRun((run) => run + 1);
            }}
          >
            <span className="scenario-marker">{scenario.marker}</span>
            <span className="scenario-copy">
              <strong>{scenario.title}</strong>
              <small>{scenario.description}</small>
            </span>
          </button>
        ))}
      </div>

      {isLoading && <div className="showcase-state" role="status">Creating synthetic trace and requesting backend analysis…</div>}
      {error && (
        <div className="showcase-state error" role="alert">
          <strong>Scenario unavailable</strong>
          <p>{error}</p>
          <p>Start the backend with the development demo opt-in enabled, then select a scenario to retry.</p>
        </div>
      )}

      {!isLoading && !error && loadedScenario && (
        <>
          <div className="showcase-grid">
            <section className="request-card" aria-labelledby="request-flow-title">
              <div className="showcase-card-heading">
                <div>
                  <p className="showcase-eyebrow">OBSERVED TRACE FLOW</p>
                  <h3 id="request-flow-title">Service request path</h3>
                </div>
                <span className="observed-legend"><i />Observed parent-child spans</span>
              </div>
              <p className="trace-reference">Trace <code>{loadedScenario.traceId}</code></p>

              <div className="request-graph-scroll">
                <svg
                  className="request-graph"
                  viewBox="0 0 100 48"
                  role="group"
                  aria-label="Observed service call path from the backend trace"
                >
                  <defs>
                    <marker id="showcase-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="4" markerHeight="4" orient="auto">
                      <path d="M0 0 L8 4 L0 8 z" />
                    </marker>
                  </defs>
                  {orderedSpans.map((span, index) => {
                    if (!span.parent_span_id) return null;
                    const parentIndex = orderedSpans.findIndex((item) => item.span_id === span.parent_span_id);
                    if (parentIndex < 0) return null;
                    const fromX = orderedSpans.length === 1 ? 50 : 16 + (parentIndex * 68) / (orderedSpans.length - 1);
                    const toX = orderedSpans.length === 1 ? 50 : 16 + (index * 68) / (orderedSpans.length - 1);
                    const active = selection?.kind === 'call' && selection.childSpanId === span.span_id;
                    return (
                      <g
                        key={`call-${span.span_id}`}
                        className={`request-edge ${active ? 'active' : ''}`}
                        role="button"
                        tabIndex={0}
                        aria-label={`Observed call from ${orderedSpans[parentIndex].service_name || 'unknown service'} to ${span.service_name || 'unknown service'}`}
                        onClick={() => setSelection({ kind: 'call', childSpanId: span.span_id })}
                        onKeyDown={(event) => {
                          if (event.key === 'Enter' || event.key === ' ') {
                            event.preventDefault();
                            setSelection({ kind: 'call', childSpanId: span.span_id });
                          }
                        }}
                      >
                        <line className="request-edge-hit" x1={fromX + 8} y1="28" x2={toX - 8} y2="28" />
                        <line x1={fromX + 8} y1="28" x2={toX - 8} y2="28" markerEnd="url(#showcase-arrow)" />
                        <text x={(fromX + toX) / 2} y="17">observed call</text>
                      </g>
                    );
                  })}
                  {orderedSpans.map((span, index) => {
                    const x = orderedSpans.length === 1 ? 50 : 16 + (index * 68) / (orderedSpans.length - 1);
                    const active = selection?.kind === 'span' && selection.spanId === span.span_id;
                    const serviceLabel = span.service_name || 'Unknown service';
                    const displayLabel = serviceLabel.length > 17 ? `${serviceLabel.slice(0, 15)}…` : serviceLabel;
                    return (
                      <g
                        key={span.span_id}
                        className={`request-node ${active ? 'active' : ''}`}
                        role="button"
                        tabIndex={0}
                        aria-label={`${serviceLabel}: ${span.span_name}`}
                        onClick={() => setSelection({ kind: 'span', spanId: span.span_id })}
                        onKeyDown={(event) => {
                          if (event.key === 'Enter' || event.key === ' ') {
                            event.preventDefault();
                            setSelection({ kind: 'span', spanId: span.span_id });
                          }
                        }}
                      >
                        <rect x={x - 9} y="21" width="18" height="14" rx="2" />
                        <text className="request-node-service" x={x} y="26">{displayLabel}</text>
                        <text className="request-node-operation" x={x} y="31">{span.span_name.length > 19 ? `${span.span_name.slice(0, 17)}…` : span.span_name}</text>
                      </g>
                    );
                  })}
                </svg>
              </div>
              <p className="graph-disclaimer">A trace parent-child link confirms observed call structure, not an authorization grant.</p>

              <section className="pipeline-section" aria-label="Analysis pipeline">
                <div className="showcase-card-heading">
                  <div>
                    <p className="showcase-eyebrow">HOW THE ENGINE ANALYZES</p>
                    <h3>Analysis pipeline</h3>
                  </div>
                </div>
                <p className="pipeline-note">The API returns one completed result. These steps describe the analysis, not live progress.</p>
                <ol className="pipeline-steps">
                  {['Receive trace', 'Validate spans', 'Build trace context', 'Extract auth evidence', 'Evaluate configured rules', 'Return finding'].map((step, index) => (
                    <li key={step}><span>{String(index + 1).padStart(2, '0')}</span>{step}</li>
                  ))}
                </ol>
              </section>
            </section>

            <aside className="scenario-evidence">
              {!analysis ? (
                <section className="evidence-card" role="status">
                  <h3>Analysis unavailable</h3>
                  <p>The trace was returned without a deterministic security analysis.</p>
                </section>
              ) : (
                <section className="evidence-card">
                  <p className="showcase-eyebrow">DETERMINISTIC RESULT</p>
                  <div className={`scenario-verdict verdict-${analysis.verdict.toLowerCase().replaceAll('_', '-')}`}>
                    <span>{analysis.verdict}</span>
                    {analysis.finding.severity && <small>{analysis.finding.severity} severity</small>}
                  </div>
                  <p className="verdict-reason">{analysis.reason}</p>
                  {analysis.verdict === 'DETECTED' && (
                    <p className="rule-reference">
                      Triggered finding: <strong>{analysis.finding.category || 'Not supplied by backend'}</strong>
                    </p>
                  )}
                  {analysis.verdict === 'NOT_DETECTED' && (
                    <p className="rule-reference">No configured suspicious-pattern rule was triggered by the analyzed evidence. This does not prove every interaction is safe.</p>
                  )}
                  {analysis.verdict === 'INSUFFICIENT_EVIDENCE' && (
                    <p className="rule-reference">Required authorization evidence is missing or ambiguous; this result is neither a safe nor a malicious classification.</p>
                  )}
                  <dl className="authority-facts">
                    <div><dt>Principal</dt><dd>{analysis.finding.initiating_principal?.principal_id || 'Not available in trace'}</dd></div>
                    <div><dt>Action</dt><dd>{analysis.finding.effective_action || 'Not available in trace'}</dd></div>
                    <div><dt>Required</dt><dd>{analysis.finding.required_authority.join(', ') || 'Not available in analysis'}</dd></div>
                    <div><dt>Delegated</dt><dd>{analysis.finding.delegated_authority?.permissions.join(', ') || 'Not available in analysis'}</dd></div>
                    <div><dt>Finding ID</dt><dd>{analysis.finding.finding_id || 'Not available in analysis'}</dd></div>
                  </dl>
                </section>
              )}

              <section className="evidence-card selected-evidence">
                <p className="showcase-eyebrow">SELECTED TRACE EVIDENCE</p>
                {!selectedSpan ? <p>Select a service or observed call to inspect available evidence.</p> : (
                  <>
                    <h3>{selection?.kind === 'call' ? 'Observed service call' : selectedSpan.service_name || 'Unknown service'}</h3>
                    {selection?.kind === 'call' && (
                      <div className="evidence-route">
                        <span>{loadedScenario.spans.find((span) => span.span_id === selectedSpan.parent_span_id)?.service_name || 'Unknown service'}</span>
                        <b aria-hidden="true">→</b>
                        <span>{selectedSpan.service_name || 'Unknown service'}</span>
                      </div>
                    )}
                    <dl className="authority-facts">
                      <div><dt>Operation</dt><dd>{selectedSpan.span_name || 'Not available in trace'}</dd></div>
                      <div><dt>Trace ID</dt><dd><code>{selectedSpan.trace_id}</code></dd></div>
                      <div><dt>Span ID</dt><dd><code>{selectedSpan.span_id}</code></dd></div>
                      <div><dt>Principal</dt><dd>{attribute(selectedSpan, 'authz.principal.id')}</dd></div>
                      <div><dt>Scopes</dt><dd>{attribute(selectedSpan, 'authz.principal.scopes')}</dd></div>
                      <div><dt>Delegation from</dt><dd>{attribute(selectedSpan, 'authz.delegation.from')}</dd></div>
                      <div><dt>Delegation to</dt><dd>{attribute(selectedSpan, 'authz.delegation.to')}</dd></div>
                      <div><dt>Delegated scopes</dt><dd>{attribute(selectedSpan, 'authz.delegation.scopes')}</dd></div>
                      <div><dt>Credential type</dt><dd>{attribute(selectedSpan, 'authz.credential.type')}</dd></div>
                    </dl>
                  </>
                )}
              </section>
            </aside>
          </div>
          <p className="scenario-disclaimer">
            Synthetic scenario inputs are sent to the configured backend. The verdict and graph above are returned by its deterministic analysis API; they are not production telemetry or an AI-generated decision.
          </p>
        </>
      )}
    </section>
  );
};
