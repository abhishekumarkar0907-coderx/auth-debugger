import React, { useMemo } from 'react';
import type { SpanRecord, TraceMetrics } from '../types.ts';
import {
  buildSpanHierarchy,
  flattenSpanHierarchy,
  formatDuration,
  getSpanKindInfo,
  getStatusCodeInfo,
} from '../utils/spanHelpers.ts';

interface SpanTreeProps {
  spans: SpanRecord[];
  metrics: TraceMetrics;
  selectedSpanId: string | null;
  onSelectSpan: (spanId: string) => void;
}

export const SpanTree: React.FC<SpanTreeProps> = ({
  spans,
  metrics,
  selectedSpanId,
  onSelectSpan,
}) => {
  const flattenedNodes = useMemo(() => {
    const rootNodes = buildSpanHierarchy(spans);
    return flattenSpanHierarchy(rootNodes);
  }, [spans]);

  const traceDurationMs = Math.max(metrics.totalDurationMs, 0.001);
  const traceEarliestStartNs = metrics.earliestStartNs;

  return (
    <div className="span-tree-container" id="span-tree-container">
      <div className="span-tree-header">
        <div className="col-span-info">Span &amp; Service</div>
        <div className="col-span-meta">Kind / Status</div>
        <div className="col-span-timing">Timeline &amp; Duration</div>
      </div>

      <div className="span-tree-body">
        {flattenedNodes.map(({ span, depth }) => {
          const isSelected = span.span_id === selectedSpanId;
          const kindInfo = getSpanKindInfo(span.span_kind);
          const statusInfo = getStatusCodeInfo(span.status_code);

          // Calculate start offset percentage and duration bar width percentage
          const spanOffsetMs = traceEarliestStartNs > 0
            ? Math.max(0, (span.start_time_unix_nano - traceEarliestStartNs) / 1_000_000)
            : 0;
          const startPercent = Math.min(100, Math.max(0, (spanOffsetMs / traceDurationMs) * 100));
          const widthPercent = Math.min(
            100 - startPercent,
            Math.max(1, (span.duration_ms / traceDurationMs) * 100)
          );

          return (
            <div
              key={span.span_id}
              id={`span-row-${span.span_id}`}
              className={`span-row ${isSelected ? 'selected' : ''} ${statusInfo.isError ? 'has-error' : ''}`}
              onClick={() => onSelectSpan(span.span_id)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  onSelectSpan(span.span_id);
                }
              }}
            >
              <div
                className="col-span-info"
                style={{ paddingLeft: `${Math.max(12, depth * 22 + 12)}px` }}
              >
                <div className="tree-depth-indicator">
                  {depth > 0 && <span className="branch-line">└─</span>}
                  <span className="span-name-text" title={span.span_name}>
                    {span.span_name}
                  </span>
                </div>
                <div className="span-sub-info">
                  <span className="span-service-name">
                    {span.service_name || 'unknown-service'}
                  </span>
                  <span className="span-id-mini" title={`Span ID: ${span.span_id}`}>
                    {span.span_id.slice(0, 8)}
                  </span>
                </div>
              </div>

              <div className="col-span-meta">
                <span className={`badge-pill ${kindInfo.badgeClass}`}>
                  {kindInfo.label}
                </span>
                <span className={`badge-pill ${statusInfo.badgeClass}`}>
                  {statusInfo.label}
                </span>
              </div>

              <div className="col-span-timing">
                <div className="timing-bar-track">
                  <div
                    className={`timing-bar-fill ${statusInfo.isError ? 'fill-error' : 'fill-ok'}`}
                    style={{
                      left: `${startPercent.toFixed(1)}%`,
                      width: `${widthPercent.toFixed(1)}%`,
                    }}
                    title={`Start: +${spanOffsetMs.toFixed(2)}ms | Duration: ${formatDuration(span.duration_ms)}`}
                  />
                </div>
                <span className="timing-duration-label">
                  {formatDuration(span.duration_ms)}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
