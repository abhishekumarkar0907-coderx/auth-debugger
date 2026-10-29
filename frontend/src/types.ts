/**
 * Core types for Authorization Debugger Trace Explorer.
 * Synchronized with backend/app/schemas.py Pydantic schemas.
 */

export interface TraceSummary {
  trace_id: string;
  span_count: number;
  services: string[];
}

export interface SpanRecord {
  trace_id: string;
  span_id: string;
  parent_span_id: string | null;

  service_name: string | null;
  span_name: string;

  start_time_unix_nano: number;
  end_time_unix_nano: number;
  duration_ms: number;

  span_kind: number;
  status_code: number;

  attributes: Record<string, unknown>;
}

export interface SecurityEvidenceWarning {
  field: string;
  warning_type: string;
  message: string;
  sources?: string[];
}

export interface SecurityFinding {
  finding_type?: string;
  reason?: string;
  effective_action?: string | null;
  attack_path?: string[];
  [key: string]: unknown;
}

export interface SecurityAnalysis {
  verdict: string;
  reason?: string;
  finding?: SecurityFinding | null;
  details?: Record<string, unknown> | null;
  context?: {
    warnings?: SecurityEvidenceWarning[];
    [key: string]: unknown;
  };
}

export interface TraceGraphResponse {
  security_analysis?: SecurityAnalysis | null;
  [key: string]: unknown;
}

/**
 * OpenTelemetry SpanKind standard numerical codes:
 * 0 = SPAN_KIND_UNSPECIFIED
 * 1 = SPAN_KIND_INTERNAL
 * 2 = SPAN_KIND_SERVER
 * 3 = SPAN_KIND_CLIENT
 * 4 = SPAN_KIND_PRODUCER
 * 5 = SPAN_KIND_CONSUMER
 */
export const SpanKind = {
  UNSPECIFIED: 0,
  INTERNAL: 1,
  SERVER: 2,
  CLIENT: 3,
  PRODUCER: 4,
  CONSUMER: 5,
} as const;

export type SpanKind = typeof SpanKind[keyof typeof SpanKind];

export const SPAN_KIND_LABELS: Record<number, string> = {
  0: 'UNSPECIFIED',
  1: 'INTERNAL',
  2: 'SERVER',
  3: 'CLIENT',
  4: 'PRODUCER',
  5: 'CONSUMER',
};

/**
 * OpenTelemetry StatusCode standard codes:
 * 0 = STATUS_CODE_UNSET
 * 1 = STATUS_CODE_OK
 * 2 = STATUS_CODE_ERROR
 */
export const StatusCode = {
  UNSET: 0,
  OK: 1,
  ERROR: 2,
} as const;

export type StatusCode = typeof StatusCode[keyof typeof StatusCode];

export const STATUS_CODE_LABELS: Record<number, string> = {
  0: 'UNSET',
  1: 'OK',
  2: 'ERROR',
};

/**
 * Hierarchical tree node for span graph/waterfall visualization.
 */
export interface SpanNode {
  span: SpanRecord;
  depth: number;
  children: SpanNode[];
  isRoot: boolean;
}

/**
 * Overall computed metrics for a trace.
 */
export interface TraceMetrics {
  traceId: string;
  totalSpans: number;
  services: string[];
  totalDurationMs: number;
  rootSpan: SpanRecord | null;
  hasErrors: boolean;
  errorCount: number;
  earliestStartNs: number;
  latestEndNs: number;
}
