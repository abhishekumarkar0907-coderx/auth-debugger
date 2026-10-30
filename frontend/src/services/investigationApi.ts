import { fetchHealth, fetchRecentSpans, fetchTraceAnalysis, fetchTraceSpans, fetchTraces } from '../api.ts';
import { DEMO_RECENT_SPANS, DEMO_TRACES, demoAnalysisForTrace, demoSpansForTrace } from '../mocks/demoData.ts';
import type { SpanRecord, TraceAnalysisEnvelope, TraceSummary } from '../types.ts';

export type InvestigationDataSource = 'demo' | 'live';

/**
 * Single data access seam for the workspace. Demo fixtures live under mocks/;
 * switching to the real API does not require changes to view components.
 */
export function createInvestigationApi(source: InvestigationDataSource, baseUrl: string) {
  return {
    health(): Promise<{ status: string }> {
      return source === 'demo' ? Promise.resolve({ status: 'demo' }) : fetchHealth(baseUrl);
    },
    traces(): Promise<TraceSummary[]> {
      return source === 'demo' ? Promise.resolve(DEMO_TRACES) : fetchTraces(baseUrl);
    },
    traceSpans(traceId: string): Promise<SpanRecord[]> {
      return source === 'demo' ? Promise.resolve(demoSpansForTrace(traceId)) : fetchTraceSpans(traceId, baseUrl);
    },
    recentSpans(limit: number): Promise<SpanRecord[]> {
      return source === 'demo'
        ? Promise.resolve(DEMO_RECENT_SPANS.slice(0, limit))
        : fetchRecentSpans(limit, baseUrl);
    },
    analysis(traceId: string): Promise<TraceAnalysisEnvelope | null> {
      return source === 'demo'
        ? Promise.resolve(demoAnalysisForTrace(traceId))
        : fetchTraceAnalysis(traceId, baseUrl);
    },
  };
}
