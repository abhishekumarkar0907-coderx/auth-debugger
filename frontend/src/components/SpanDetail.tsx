import React, { useState } from 'react';
import type { SpanRecord } from '../types.ts';
import {
  formatDuration,
  formatUnixNano,
  getSpanKindInfo,
  getStatusCodeInfo,
} from '../utils/spanHelpers.ts';

interface SpanDetailProps {
  span: SpanRecord | null;
  onClose?: () => void;
}

export const SpanDetail: React.FC<SpanDetailProps> = ({ span, onClose }) => {
  const [activeTab, setActiveTab] = useState<'attributes' | 'raw'>('attributes');
  const [attrFilter, setAttrFilter] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  if (!span) {
    return (
      <div className="span-detail-pane empty" id="span-detail-empty">
        <p className="empty-title">No span selected</p>
        <p className="empty-subtitle">Select a span from the timeline to inspect its attributes, IDs, and timing.</p>
      </div>
    );
  }

  const kindInfo = getSpanKindInfo(span.span_kind);
  const statusInfo = getStatusCodeInfo(span.status_code);
  const startTime = formatUnixNano(span.start_time_unix_nano);
  const endTime = formatUnixNano(span.end_time_unix_nano);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1500);
  };

  const attributesList = Object.entries(span.attributes || {}).filter(([k]) =>
    !attrFilter.trim() || k.toLowerCase().includes(attrFilter.toLowerCase().trim())
  );

  return (
    <div className="span-detail-pane" id={`span-detail-${span.span_id}`}>
      <div className="span-detail-header">
        <div className="detail-title-group">
          <div className="detail-tags-row">
            <span className="detail-service-tag">{span.service_name || 'unnamed-service'}</span>
            <span className={`badge-pill ${kindInfo.badgeClass}`}>{kindInfo.label}</span>
            <span className={`badge-pill ${statusInfo.badgeClass}`}>{statusInfo.label}</span>
          </div>
          <h3 className="detail-span-name" title={span.span_name}>
            {span.span_name}
          </h3>
        </div>
        {onClose && (
          <button
            type="button"
            className="btn-icon close-btn"
            onClick={onClose}
            title="Close Details"
          >
            ×
          </button>
        )}
      </div>

      <div className="detail-content-scroll">
        {/* Core Identifiers */}
        <section className="detail-section">
          <h4 className="section-title">Identifiers</h4>
          <div className="id-grid">
            <div className="id-card">
              <span className="id-label">Trace ID</span>
              <div className="id-value-row">
                <code className="id-code" title={span.trace_id}>{span.trace_id}</code>
                <button
                  type="button"
                  className="btn-copy"
                  onClick={() => copyToClipboard(span.trace_id, 'trace_id')}
                >
                  {copiedKey === 'trace_id' ? 'Copied' : 'Copy'}
                </button>
              </div>
            </div>

            <div className="id-card">
              <span className="id-label">Span ID</span>
              <div className="id-value-row">
                <code className="id-code" title={span.span_id}>{span.span_id}</code>
                <button
                  type="button"
                  className="btn-copy"
                  onClick={() => copyToClipboard(span.span_id, 'span_id')}
                >
                  {copiedKey === 'span_id' ? 'Copied' : 'Copy'}
                </button>
              </div>
            </div>

            <div className="id-card">
              <span className="id-label">Parent Span ID</span>
              <div className="id-value-row">
                {span.parent_span_id ? (
                  <>
                    <code className="id-code" title={span.parent_span_id}>{span.parent_span_id}</code>
                    <button
                      type="button"
                      className="btn-copy"
                      onClick={() => copyToClipboard(span.parent_span_id!, 'parent_span_id')}
                    >
                      {copiedKey === 'parent_span_id' ? 'Copied' : 'Copy'}
                    </button>
                  </>
                ) : (
                  <span className="id-none-label">Root Span (No Parent)</span>
                )}
              </div>
            </div>
          </div>
        </section>

        {/* Timing Information */}
        <section className="detail-section">
          <h4 className="section-title">Timing &amp; Duration</h4>
          <div className="timing-grid">
            <div className="timing-card">
              <span className="timing-label">Duration</span>
              <span className="timing-value duration-highlight">
                {formatDuration(span.duration_ms)}
              </span>
              <span className="timing-subvalue">({span.duration_ms.toFixed(3)} ms)</span>
            </div>

            <div className="timing-card">
              <span className="timing-label">Start Time (UTC)</span>
              <span className="timing-value">{startTime.iso}</span>
              <span className="timing-subvalue">{span.start_time_unix_nano} ns</span>
            </div>

            <div className="timing-card">
              <span className="timing-label">End Time (UTC)</span>
              <span className="timing-value">{endTime.iso}</span>
              <span className="timing-subvalue">{span.end_time_unix_nano} ns</span>
            </div>
          </div>
        </section>

        {/* Attributes Section */}
        <section className="detail-section">
          <div className="section-title-row">
            <div className="tabs-group">
              <button
                type="button"
                className={`tab-btn ${activeTab === 'attributes' ? 'active' : ''}`}
                onClick={() => setActiveTab('attributes')}
              >
                Attributes ({Object.keys(span.attributes || {}).length})
              </button>
              <button
                type="button"
                className={`tab-btn ${activeTab === 'raw' ? 'active' : ''}`}
                onClick={() => setActiveTab('raw')}
              >
                Raw JSON
              </button>
            </div>

            {activeTab === 'attributes' && Object.keys(span.attributes || {}).length > 3 && (
              <input
                type="text"
                placeholder="Filter attributes..."
                value={attrFilter}
                onChange={(e) => setAttrFilter(e.target.value)}
                className="attr-filter-input"
              />
            )}
          </div>

          {activeTab === 'attributes' ? (
            attributesList.length === 0 ? (
              <div className="empty-substate">
                {Object.keys(span.attributes || {}).length === 0 ? (
                  <span>No attributes attached to this span.</span>
                ) : (
                  <span>No attributes match "{attrFilter}".</span>
                )}
              </div>
            ) : (
              <div className="attributes-table-wrapper">
                <table className="attributes-table">
                  <thead>
                    <tr>
                      <th>Key</th>
                      <th>Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {attributesList.map(([key, value]) => (
                      <tr key={key}>
                        <td className="attr-key-cell">
                          <code>{key}</code>
                        </td>
                        <td className="attr-val-cell">
                          {typeof value === 'object' && value !== null ? (
                            <pre className="nested-json">{JSON.stringify(value, null, 2)}</pre>
                          ) : (
                            <span className="attr-val-scalar">{String(value)}</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          ) : (
            <div className="raw-json-wrapper">
              <div className="raw-json-actions">
                <button
                  type="button"
                  className="btn-copy"
                  onClick={() => copyToClipboard(JSON.stringify(span, null, 2), 'raw_json')}
                >
                  {copiedKey === 'raw_json' ? 'Copied JSON' : 'Copy JSON'}
                </button>
              </div>
              <pre className="raw-json-block">{JSON.stringify(span, null, 2)}</pre>
            </div>
          )}
        </section>
      </div>
    </div>
  );
};
