/**
 * Helper functions for processing and formatting OpenTelemetry spans and traces.
 */

import type {
  SpanNode,
  SpanRecord,
  TraceMetrics,
} from '../types.ts';
import {
  SpanKind,
  SPAN_KIND_LABELS,
  StatusCode,
  STATUS_CODE_LABELS,
} from '../types.ts';

/**
 * Format duration in milliseconds to human-readable string.
 */
export function formatDuration(ms: number): string {
  if (ms == null || isNaN(ms)) return '0 ms';
  if (ms < 1) {
    const micros = Math.round(ms * 1000);
    return `${micros} µs`;
  }
  if (ms < 1000) {
    return `${ms.toFixed(2)} ms`;
  }
  const seconds = ms / 1000;
  return `${seconds.toFixed(2)} s`;
}

/**
 * Format unix nano timestamp into formatted local time and ISO string.
 */
export function formatUnixNano(nano: number): { formatted: string; iso: string; relativeMs: (baseNano: number) => string } {
  if (!nano) {
    return {
      formatted: 'N/A',
      iso: 'N/A',
      relativeMs: () => '+0 ms',
    };
  }

  const millis = Math.floor(nano / 1_000_000);
  const date = new Date(millis);
  const iso = date.toISOString();
  const formatted = date.toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    fractionalSecondDigits: 3,
    hour12: false,
  });

  return {
    formatted,
    iso,
    relativeMs: (baseNano: number) => {
      const diffMs = (nano - baseNano) / 1_000_000;
      return `+${diffMs.toFixed(2)} ms`;
    },
  };
}

/**
 * Resolve SpanKind name and badge style.
 */
export function getSpanKindInfo(kind: number): { label: string; badgeClass: string } {
  const label = SPAN_KIND_LABELS[kind] || `KIND_${kind}`;
  switch (kind) {
    case SpanKind.SERVER:
      return { label, badgeClass: 'badge-server' };
    case SpanKind.CLIENT:
      return { label, badgeClass: 'badge-client' };
    case SpanKind.INTERNAL:
      return { label, badgeClass: 'badge-internal' };
    case SpanKind.PRODUCER:
      return { label, badgeClass: 'badge-producer' };
    case SpanKind.CONSUMER:
      return { label, badgeClass: 'badge-consumer' };
    default:
      return { label, badgeClass: 'badge-neutral' };
  }
}

/**
 * Resolve StatusCode name and badge style.
 */
export function getStatusCodeInfo(code: number): { label: string; badgeClass: string; isError: boolean } {
  const label = STATUS_CODE_LABELS[code] || `STATUS_${code}`;
  switch (code) {
    case StatusCode.OK:
      return { label, badgeClass: 'badge-status-ok', isError: false };
    case StatusCode.ERROR:
      return { label, badgeClass: 'badge-status-error', isError: true };
    default:
      return { label: 'UNSET', badgeClass: 'badge-status-unset', isError: false };
  }
}

/**
 * Calculate comprehensive summary metrics for a list of spans in a trace.
 */
export function computeTraceMetrics(traceId: string, spans: SpanRecord[]): TraceMetrics {
  if (!spans || spans.length === 0) {
    return {
      traceId,
      totalSpans: 0,
      services: [],
      totalDurationMs: 0,
      rootSpan: null,
      hasErrors: false,
      errorCount: 0,
      earliestStartNs: 0,
      latestEndNs: 0,
    };
  }

  const serviceSet = new Set<string>();
  let earliestStart = Infinity;
  let latestEnd = -Infinity;
  let errorCount = 0;
  let rootSpan: SpanRecord | null = null;

  for (const span of spans) {
    if (span.service_name) {
      serviceSet.add(span.service_name);
    }
    if (span.start_time_unix_nano < earliestStart) {
      earliestStart = span.start_time_unix_nano;
    }
    if (span.end_time_unix_nano > latestEnd) {
      latestEnd = span.end_time_unix_nano;
    }
    if (span.status_code === StatusCode.ERROR) {
      errorCount++;
    }
    if (!span.parent_span_id) {
      rootSpan = span;
    }
  }

  // Fallback to earliest span if no span explicitly lacked a parent_span_id
  if (!rootSpan && spans.length > 0) {
    rootSpan = spans.reduce((prev, curr) =>
      curr.start_time_unix_nano < prev.start_time_unix_nano ? curr : prev
    );
  }

  const totalDurationMs =
    earliestStart < Infinity && latestEnd > -Infinity
      ? Math.max(0, (latestEnd - earliestStart) / 1_000_000)
      : 0;

  return {
    traceId,
    totalSpans: spans.length,
    services: Array.from(serviceSet).sort(),
    totalDurationMs,
    rootSpan,
    hasErrors: errorCount > 0,
    errorCount,
    earliestStartNs: earliestStart < Infinity ? earliestStart : 0,
    latestEndNs: latestEnd > -Infinity ? latestEnd : 0,
  };
}

/**
 * Build a nested span hierarchy tree based on span_id and parent_span_id.
 */
export function buildSpanHierarchy(spans: SpanRecord[]): SpanNode[] {
  if (!spans || spans.length === 0) return [];

  const spanMap = new Map<string, SpanNode>();
  const rootNodes: SpanNode[] = [];

  // Initialize all nodes
  for (const span of spans) {
    spanMap.set(span.span_id, {
      span,
      depth: 0,
      children: [],
      isRoot: !span.parent_span_id,
    });
  }

  // Link children to parents
  for (const span of spans) {
    const node = spanMap.get(span.span_id)!;
    if (span.parent_span_id && spanMap.has(span.parent_span_id)) {
      const parent = spanMap.get(span.parent_span_id)!;
      parent.children.push(node);
    } else {
      rootNodes.push(node);
    }
  }

  // Calculate depths recursively
  function setDepth(nodes: SpanNode[], currentDepth: number) {
    // Sort children by start time
    nodes.sort((a, b) => a.span.start_time_unix_nano - b.span.start_time_unix_nano);
    for (const node of nodes) {
      node.depth = currentDepth;
      setDepth(node.children, currentDepth + 1);
    }
  }

  setDepth(rootNodes, 0);
  return rootNodes;
}

/**
 * Flatten the tree into an ordered array suitable for list/table rendering with indentation.
 */
export function flattenSpanHierarchy(nodes: SpanNode[]): SpanNode[] {
  const result: SpanNode[] = [];
  function traverse(list: SpanNode[]) {
    for (const node of list) {
      result.push(node);
      if (node.children.length > 0) {
        traverse(node.children);
      }
    }
  }
  traverse(nodes);
  return result;
}
