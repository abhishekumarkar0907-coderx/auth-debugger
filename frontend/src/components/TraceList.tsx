import React, { useState, useMemo } from 'react';
import type { TraceSummary } from '../types.ts';
import { COPY, resolveTraceListState } from '../utils/stateHelpers.ts';

interface TraceListProps {
  traces: TraceSummary[];
  selectedTraceId: string | null;
  onSelectTrace: (traceId: string) => void;
  isLoading: boolean;
  hasError: boolean;
  hasLoaded: boolean;
  onRefresh: () => void;
}

export const TraceList: React.FC<TraceListProps> = ({
  traces,
  selectedTraceId,
  onSelectTrace,
  isLoading,
  hasError,
  hasLoaded,
  onRefresh,
}) => {
  const [filterQuery, setFilterQuery] = useState('');

  const filteredTraces = useMemo(() => {
    if (!filterQuery.trim()) return traces;
    const query = filterQuery.toLowerCase().trim();
    return traces.filter(
      (t) =>
        t.trace_id.toLowerCase().includes(query) ||
        t.services.some((s) => s.toLowerCase().includes(query))
    );
  }, [traces, filterQuery]);

  const listState = resolveTraceListState({
    isLoading,
    hasError,
    hasLoaded,
    totalTraces: traces.length,
    filteredTraces: filteredTraces.length,
    filterQuery,
  });

  return (
    <div className="trace-list-pane" id="trace-list-container">
      <div className="pane-header">
        <div className="pane-title-group">
          <h2 className="pane-title">Available Traces</h2>
          <span className="badge-count" id="trace-count-badge">
            {hasError || !hasLoaded ? 0 : traces.length}
          </span>
        </div>
        <button
          type="button"
          className="btn-icon"
          onClick={onRefresh}
          disabled={isLoading}
          title="Refresh Traces"
          id="btn-refresh-traces"
        >
          <svg className={isLoading ? 'spin' : ''} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.2"/>
          </svg>
        </button>
      </div>

      <div className="search-bar-wrapper">
        <input
          id="trace-search-input"
          type="text"
          placeholder="Filter by trace ID or service..."
          value={filterQuery}
          onChange={(e) => setFilterQuery(e.target.value)}
          disabled={hasError || !hasLoaded || traces.length === 0}
          className="search-input"
        />
        {filterQuery && (
          <button
            type="button"
            className="search-clear-btn"
            onClick={() => setFilterQuery('')}
            title="Clear search"
          >
            ×
          </button>
        )}
      </div>

      <div className="trace-items-scroll">
        {listState === 'loading' && (
          <div className="skeleton-list" id="trace-skeleton-list">
            {[1, 2, 3, 4, 5].map((n) => (
              <div key={n} className="skeleton-item" />
            ))}
          </div>
        )}

        {/* When listState === 'error', suppress duplicate error text and keep empty state hidden */}
        {listState === 'error' && null}

        {listState === 'empty' && (
          <div className="empty-state-small" id="trace-list-empty">
            <p className="empty-title">{COPY.EMPTY_TITLE}</p>
            <p className="empty-subtitle">{COPY.EMPTY_SUBTITLE}</p>
          </div>
        )}

        {listState === 'filtered-empty' && (
          <div className="empty-state-small" id="trace-list-filtered-empty">
            <p className="empty-title">No matching traces</p>
            <p className="empty-subtitle">No trace matched "{filterQuery}".</p>
          </div>
        )}

        {listState === 'list' &&
          filteredTraces.map((trace) => {
            const isSelected = trace.trace_id === selectedTraceId;
            return (
              <div
                key={trace.trace_id}
                id={`trace-item-${trace.trace_id}`}
                className={`trace-card ${isSelected ? 'selected' : ''}`}
                onClick={() => onSelectTrace(trace.trace_id)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    onSelectTrace(trace.trace_id);
                  }
                }}
              >
                <div className="trace-card-top">
                  <span className="trace-id-mono" title={trace.trace_id}>
                    {trace.trace_id.slice(0, 12)}...{trace.trace_id.slice(-8)}
                  </span>
                  <span className="badge-spans-count">
                    {trace.span_count} {trace.span_count === 1 ? 'span' : 'spans'}
                  </span>
                </div>
                <div className="trace-services-tags">
                  {trace.services.length > 0 ? (
                    trace.services.map((svc) => (
                      <span key={svc} className="tag-service" title={svc}>
                        {svc}
                      </span>
                    ))
                  ) : (
                    <span className="tag-service-empty">no service name</span>
                  )}
                </div>
              </div>
            );
          })}
      </div>
    </div>
  );
};
