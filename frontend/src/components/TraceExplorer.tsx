import React, { useState, useEffect, useCallback, useMemo } from 'react';
import type { SecurityAnalysis, SpanRecord, TraceSummary } from '../types.ts';
import {
  fetchHealth,
  fetchTraces,
  fetchTraceGraph,
  fetchTraceSpans,
  fetchRecentSpans,
  getInitialApiBaseUrl,
} from '../api.ts';
import { computeTraceMetrics, formatDuration } from '../utils/spanHelpers.ts';
import { COPY, resolveWorkspaceMainState } from '../utils/stateHelpers.ts';
import { TraceList } from './TraceList.tsx';
import { SpanTree } from './SpanTree.tsx';
import { SpanDetail } from './SpanDetail.tsx';
import { SecurityAnalysisPanel } from './SecurityAnalysisPanel.tsx';

export const TraceExplorer: React.FC = () => {
  // Configuration
  const [apiBaseUrl, setApiBaseUrl] = useState<string>(getInitialApiBaseUrl);
  const [isEditingUrl, setIsEditingUrl] = useState<boolean>(false);
  const [tempUrl, setTempUrl] = useState<string>(apiBaseUrl);

  // Backend connection status
  const [backendStatus, setBackendStatus] = useState<'checking' | 'connected' | 'disconnected'>('checking');

  // Traces list state
  const [traces, setTraces] = useState<TraceSummary[]>([]);
  const [isLoadingTraces, setIsLoadingTraces] = useState<boolean>(false);
  const [hasLoadedTraces, setHasLoadedTraces] = useState<boolean>(false);
  const [traceError, setTraceError] = useState<string | null>(null);

  // Selected trace state
  const [selectedTraceId, setSelectedTraceId] = useState<string | null>(null);
  const [spans, setSpans] = useState<SpanRecord[]>([]);
  const [isLoadingSpans, setIsLoadingSpans] = useState<boolean>(false);
  const [spansError, setSpansError] = useState<string | null>(null);
  const [securityAnalysis, setSecurityAnalysis] = useState<SecurityAnalysis | null>(null);
  const [securityAnalysisError, setSecurityAnalysisError] = useState<string | null>(null);

  // Selected span for detailed inspection
  const [selectedSpanId, setSelectedSpanId] = useState<string | null>(null);

  // View mode: 'by-trace' | 'recent-spans'
  const [viewMode, setViewMode] = useState<'by-trace' | 'recent-spans'>('by-trace');
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    try {
      return localStorage.getItem('authorization-debugger-theme') === 'dark' ? 'dark' : 'light';
    } catch {
      return 'light';
    }
  });

  useEffect(() => {
    document.body.dataset.theme = theme;
    try {
      localStorage.setItem('authorization-debugger-theme', theme);
    } catch {
      // The selected theme still works for this session when storage is unavailable.
    }
  }, [theme]);

  // Check backend health
  const checkHealth = useCallback(async (url: string) => {
    try {
      setBackendStatus('checking');
      const res = await fetchHealth(url);
      if (res && res.status === 'ok') {
        setBackendStatus('connected');
      } else {
        setBackendStatus('disconnected');
      }
    } catch {
      setBackendStatus('disconnected');
    }
  }, []);

  // Load traces
  const loadTraces = useCallback(async (url: string) => {
    setIsLoadingTraces(true);
    setTraceError(null);
    try {
      const data = await fetchTraces(url);
      setTraces(data);
      setHasLoadedTraces(true);
      // Auto-select first trace if none selected
      if (data.length > 0 && !selectedTraceId) {
        setSelectedTraceId(data[0].trace_id);
      }
    } catch (err) {
      setTraceError(err instanceof Error ? err.message : String(err));
      setHasLoadedTraces(false);
    } finally {
      setIsLoadingTraces(false);
    }
  }, [selectedTraceId]);

  // Load spans for selected trace
  const loadTraceSpans = useCallback(async (traceId: string, url: string) => {
    setIsLoadingSpans(true);
    setSpansError(null);
    setSecurityAnalysis(null);
    setSecurityAnalysisError(null);
    try {
      const data = await fetchTraceSpans(traceId, url);
      setSpans(data);
      if (data.length > 0) {
        // Default to root span or first span
        const root = data.find((s) => !s.parent_span_id) || data[0];
        setSelectedSpanId(root.span_id);
      } else {
        setSelectedSpanId(null);
      }
      try {
        const graph = await fetchTraceGraph(traceId, url);
        setSecurityAnalysis(graph.security_analysis ?? null);
      } catch (err) {
        setSecurityAnalysisError(err instanceof Error ? err.message : String(err));
      }
    } catch (err) {
      setSpansError(err instanceof Error ? err.message : String(err));
      setSpans([]);
      setSelectedSpanId(null);
      setSecurityAnalysis(null);
    } finally {
      setIsLoadingSpans(false);
    }
  }, []);

  // Load recent spans across all traces
  const loadRecentSpans = useCallback(async (url: string) => {
    setIsLoadingSpans(true);
    setSpansError(null);
    try {
      const data = await fetchRecentSpans(100, url);
      setSpans(data);
      setSecurityAnalysis(null);
      setSecurityAnalysisError(null);
      if (data.length > 0) {
        setSelectedSpanId(data[0].span_id);
      } else {
        setSelectedSpanId(null);
      }
    } catch (err) {
      setSpansError(err instanceof Error ? err.message : String(err));
      setSpans([]);
      setSelectedSpanId(null);
    } finally {
      setIsLoadingSpans(false);
    }
  }, []);

  // Initial load
  useEffect(() => {
    checkHealth(apiBaseUrl);
    loadTraces(apiBaseUrl);
  }, [apiBaseUrl, checkHealth, loadTraces]);

  // Load spans when selected trace changes
  useEffect(() => {
    if (viewMode === 'by-trace' && selectedTraceId) {
      loadTraceSpans(selectedTraceId, apiBaseUrl);
    } else if (viewMode === 'recent-spans') {
      loadRecentSpans(apiBaseUrl);
    }
  }, [selectedTraceId, viewMode, apiBaseUrl, loadTraceSpans, loadRecentSpans]);

  const handleApplyUrl = () => {
    setApiBaseUrl(tempUrl.trim());
    setIsEditingUrl(false);
  };

  const handleResetUrl = () => {
    const defaultUrl = getInitialApiBaseUrl();
    setTempUrl(defaultUrl);
    setApiBaseUrl(defaultUrl);
    setIsEditingUrl(false);
  };

  // Trace metrics
  const metrics = useMemo(() => {
    return computeTraceMetrics(selectedTraceId || 'all-spans', spans);
  }, [selectedTraceId, spans]);

  const selectedSpan = useMemo(() => {
    return spans.find((s) => s.span_id === selectedSpanId) || null;
  }, [spans, selectedSpanId]);

  const workspaceState = resolveWorkspaceMainState({
    traceError,
    spansError,
    isLoadingTraces,
    hasLoadedTraces,
    isLoadingSpans,
    spanCount: spans.length,
    selectedTraceId,
  });

  return (
    <div className="trace-explorer-root" id="trace-explorer-root" data-theme={theme}>
      <aside className="app-rail" aria-label="Workspace navigation">
        <div className="rail-brand" aria-label="Authorization Debugger">
          A
        </div>
        <span className="rail-divider" />
        <button
          type="button"
          className={`rail-button ${viewMode === 'by-trace' ? 'active' : ''}`}
          onClick={() => setViewMode('by-trace')}
          aria-label="Trace explorer"
          title="Trace explorer"
        >
          <svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="4" width="6" height="6" rx="1.5"/><rect x="14" y="4" width="6" height="6" rx="1.5"/><rect x="4" y="14" width="6" height="6" rx="1.5"/><path d="M14 17h6M17 14v6"/></svg>
        </button>
        <button
          type="button"
          className={`rail-button ${viewMode === 'recent-spans' ? 'active' : ''}`}
          onClick={() => setViewMode('recent-spans')}
          aria-label="Recent activity"
          title="Recent activity"
        >
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h10M4 12h7M4 17h10"/><path d="m16 15 2 2 4-5"/></svg>
        </button>
        <span className="rail-spacer" />
        <button
          type="button"
          className="rail-button theme-toggle"
          onClick={() => setTheme((current) => current === 'light' ? 'dark' : 'light')}
          aria-label={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode`}
          title={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode`}
        >
          {theme === 'light' ? (
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20.2 15.3A8.4 8.4 0 0 1 8.7 3.8 8.5 8.5 0 1 0 20.2 15.3Z"/></svg>
          ) : (
            <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.42 1.42m11.3 11.3 1.42 1.42M2 12h2m16 0h2M4.93 19.07l1.42-1.42m11.3-11.3 1.42-1.42"/></svg>
          )}
        </button>
        <button
          type="button"
          className="rail-button"
          onClick={() => setIsEditingUrl(true)}
          aria-label="Backend settings"
          title="Backend settings"
        >
          <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="m19.4 15 .1.1 1.1 1.9-1.6 2.8-2.2-.5a7.8 7.8 0 0 1-1.6.9l-.8 2.1h-3.2l-.8-2.1a7.8 7.8 0 0 1-1.6-.9l-2.2.5L5 17l1.1-1.9a7.8 7.8 0 0 1 0-1.9L5 11.3l1.6-2.8 2.2.5a7.8 7.8 0 0 1 1.6-.9l.8-2.1h3.2l.8 2.1a7.8 7.8 0 0 1 1.6.9l2.2-.5 1.6 2.8-1.1 1.9a7.8 7.8 0 0 1-.1 1.8Z" transform="translate(-1 -1) scale(.92)"/></svg>
        </button>
      </aside>
      <div className="app-shell">
      {/* Top Navigation & Status Bar */}
      <header className="app-header">
        <div className="brand-group">
          <div className="brand-logo">
            <div className="logo-text">
              <span className="workspace-label">AUTHORIZATION DEBUGGER</span>
              <h1 className="logo-title">Investigation workspace</h1>
            </div>
          </div>
        </div>

        <div className="header-controls">
          {/* View mode toggle */}
          <div className="view-mode-toggle" id="view-mode-toggle">
            <button
              type="button"
              className={`mode-btn ${viewMode === 'by-trace' ? 'active' : ''}`}
              onClick={() => setViewMode('by-trace')}
              id="mode-by-trace"
            >
              Trace Explorer
            </button>
            <button
              type="button"
              className={`mode-btn ${viewMode === 'recent-spans' ? 'active' : ''}`}
              onClick={() => setViewMode('recent-spans')}
              id="mode-recent-spans"
            >
              Recent activity
            </button>
          </div>

          {/* Backend Connection & Config Indicator */}
          <div className="backend-config-pill" id="backend-status-pill">
            <span className={`status-dot ${backendStatus}`} />
            <span className="status-label">
              {backendStatus === 'connected' ? 'Service online' : backendStatus === 'checking' ? 'Checking service…' : 'Backend offline'}
            </span>
            <code className="active-url" title={apiBaseUrl || 'Same-origin relative requests proxied by Vite to http://localhost:8000'}>
              {apiBaseUrl ? apiBaseUrl.replace(/^https?:\/\//, '') : 'Vite Proxy (:8000)'}
            </code>
            <button
              type="button"
              className="btn-text-edit"
              onClick={() => {
                setTempUrl(apiBaseUrl);
                setIsEditingUrl(!isEditingUrl);
              }}
              title="Change Backend URL"
              id="btn-edit-backend-url"
            >
              <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="3" />
                <path d="M19.4 15a1.7 1.7 0 0 0 .34 1.88l.06.06-1.7 2.94-.08-.02a1.7 1.7 0 0 0-1.74.4l-.06.06h-3.4l-.03-.08a1.7 1.7 0 0 0-1.37-1.12l-.08-.01-2.94-1.7.02-.08a1.7 1.7 0 0 0-.4-1.74l-.06-.06v-3.4l.08-.03a1.7 1.7 0 0 0 1.12-1.37l.01-.08 1.7-2.94.08.02a1.7 1.7 0 0 0 1.74-.4l.06-.06h3.4l.03.08a1.7 1.7 0 0 0 1.37 1.12l.08.01 2.94 1.7-.02.08a1.7 1.7 0 0 0 .4 1.74l.06.06v3.4z" transform="translate(-1.5 -1.5) scale(.98)" />
              </svg>
            </button>
          </div>
        </div>
      </header>

      {/* Backend URL config dropdown modal */}
      {isEditingUrl && (
        <div className="url-modal-backdrop" onClick={() => setIsEditingUrl(false)}>
          <div className="url-modal-dialog" onClick={(e) => e.stopPropagation()}>
            <h3 className="modal-title">Configure Backend API URL</h3>
            <p className="modal-desc">
              By default, local development uses same-origin relative requests via Vite's proxy (forwarding <code>/api</code> and <code>/health</code> to <code>http://localhost:8000</code>).
            </p>
            <div className="modal-warning-box">
              <span className="warning-icon">⚠️</span>
              <p className="warning-text">
                Direct browser requests to an absolute URL require CORS headers on the destination server. Because the local FastAPI backend does not enable CORS, keeping the default Vite proxy is strongly recommended.
              </p>
            </div>
            <div className="url-input-row">
              <input
                id="backend-url-input"
                type="text"
                value={tempUrl}
                onChange={(e) => setTempUrl(e.target.value)}
                placeholder="Leave blank for Vite proxy (recommended)"
                className="url-text-input"
              />
            </div>
            <div className="modal-actions">
              <button type="button" className="btn-secondary" onClick={handleResetUrl}>
                Reset to Vite Proxy
              </button>
              <button type="button" className="btn-primary" onClick={handleApplyUrl} id="btn-save-backend-url">
                Apply URL
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Main Content Workspace */}
      <main className="explorer-workspace">
        <div className="workspace-panels">
          {/* Left Pane: Trace List */}
          {viewMode === 'by-trace' && (
            <aside className="workspace-sidebar">
              <TraceList
                traces={traces}
                selectedTraceId={selectedTraceId}
                onSelectTrace={(id) => setSelectedTraceId(id)}
                isLoading={isLoadingTraces}
                hasError={!!traceError}
                hasLoaded={hasLoadedTraces}
                onRefresh={() => {
                  checkHealth(apiBaseUrl);
                  loadTraces(apiBaseUrl);
                }}
              />
            </aside>
          )}

          {/* Right Pane: Trace Detail & Spans Explorer */}
          <section className="workspace-main" id="workspace-main-panel">
          {workspaceState === 'trace-error' && (
            <div className="workspace-state-container error-state" id="trace-error-state">
              <div className="state-icon error-icon" aria-hidden="true">!</div>
              <h3 className="state-title">{COPY.ERROR_TITLE}</h3>
              <p className="state-detail">{COPY.ERROR_DETAIL}</p>
              <button
                type="button"
                className="btn-primary btn-retry-main"
                onClick={() => {
                  checkHealth(apiBaseUrl);
                  loadTraces(apiBaseUrl);
                }}
                id="btn-retry-traces"
              >
                {COPY.RETRY_BUTTON}
              </button>
            </div>
          )}

          {workspaceState === 'spans-error' && (
            <div className="workspace-state-container error-state" id="spans-error-state">
              <div className="state-icon error-icon" aria-hidden="true">!</div>
              <h3 className="state-title">{COPY.SPANS_ERROR_TITLE}</h3>
              <p className="state-detail">{COPY.ERROR_DETAIL}</p>
              <button
                type="button"
                className="btn-primary btn-retry-main"
                onClick={() =>
                  viewMode === 'by-trace' && selectedTraceId
                    ? loadTraceSpans(selectedTraceId, apiBaseUrl)
                    : loadRecentSpans(apiBaseUrl)
                }
                id="btn-retry-spans"
              >
                {COPY.RETRY_BUTTON}
              </button>
            </div>
          )}

          {workspaceState === 'initial-loading' && (
            <div className="spans-loading-state" id="initial-loading-indicator">
              <div className="spinner" />
              <p>Loading traces...</p>
            </div>
          )}

          {workspaceState === 'loading-spans' && (
            <div className="spans-loading-state" id="spans-loading-indicator">
              <div className="spinner" />
              <p>Getting the trace details…</p>
            </div>
          )}

          {workspaceState === 'empty-no-traces' && (
            <div className="empty-state-large" id="no-spans-empty-state">
              <div className="empty-icon" aria-hidden="true">↗</div>
              <h3 className="empty-title">{COPY.EMPTY_TITLE}</h3>
              <p className="empty-desc">{COPY.EMPTY_SUBTITLE}</p>
              <div className="onboarding-guide">
                <p className="guide-title">How to send traces to Authorization Debugger:</p>
                <pre className="code-snippet">
                  POST {apiBaseUrl || 'http://localhost:8000'}/v1/traces{'\n'}
                  Content-Type: application/x-protobuf
                </pre>
                <p className="guide-hint">
                  Or run the OpenTelemetry Demo configured to export traces to the backend collector.
                </p>
              </div>
            </div>
          )}

          {workspaceState === 'empty-trace-spans' && (
            <div className="empty-state-large" id="empty-trace-spans-state">
              <div className="empty-icon" aria-hidden="true">↗</div>
              <h3 className="empty-title">No spans found for this trace</h3>
              <p className="empty-desc">
                The in-memory span store holds 0 spans for trace <code>{selectedTraceId}</code>.
              </p>
            </div>
          )}

          {workspaceState === 'spans-view' && (
            <>
              {selectedTraceId && viewMode === 'by-trace' && (
                <div className="trace-summary-header" id="trace-summary-header">
                  <div className="trace-header-info">
                    <span className="trace-label">Selected Trace</span>
                    <h2 className="trace-full-id">
                      <code>{selectedTraceId}</code>
                    </h2>
                  </div>

                  <div className="trace-stats-bar">
                    <div className="stat-pill">
                      <span className="stat-label">Total Spans</span>
                      <span className="stat-value">{metrics.totalSpans}</span>
                    </div>
                    <div className="stat-pill">
                      <span className="stat-label">Duration</span>
                      <span className="stat-value">{formatDuration(metrics.totalDurationMs)}</span>
                    </div>
                    <div className="stat-pill">
                      <span className="stat-label">Services</span>
                      <span className="stat-value">{metrics.services.length}</span>
                    </div>
                    <div className={`stat-pill ${metrics.hasErrors ? 'error-pill' : 'ok-pill'}`}>
                      <span className="stat-label">Status</span>
                      <span className="stat-value">
                        {metrics.hasErrors ? `${metrics.errorCount} Error(s)` : 'All OK'}
                      </span>
                    </div>
                  </div>
                </div>
              )}

              {selectedTraceId && viewMode === 'by-trace' && (
                <SecurityAnalysisPanel
                  analysis={securityAnalysis}
                  error={securityAnalysisError}
                />
              )}

              <div className="spans-layout-split">
                <div className="spans-tree-pane">
                  <SpanTree
                    spans={spans}
                    metrics={metrics}
                    selectedSpanId={selectedSpanId}
                    onSelectSpan={(id) => setSelectedSpanId(id)}
                  />
                </div>
                <div className="spans-detail-sidebar">
                  <SpanDetail
                    span={selectedSpan}
                    onClose={() => setSelectedSpanId(null)}
                  />
                </div>
              </div>
            </>
          )}
          </section>
        </div>
      </main>
      </div>
    </div>
  );
};
