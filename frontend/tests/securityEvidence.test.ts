import assert from 'node:assert/strict';
import test from 'node:test';
import type { SpanRecord } from '../src/types.ts';
import { findEvidenceSpans, findReferencedSpans } from '../src/utils/securityEvidence.ts';

const spans: SpanRecord[] = [
  {
    trace_id: 'trace-a', span_id: 'span-a', parent_span_id: null,
    service_name: 'gateway', span_name: 'incoming request',
    start_time_unix_nano: 1, end_time_unix_nano: 2, duration_ms: 0.001,
    span_kind: 1, status_code: 0, attributes: {},
  },
  {
    trace_id: 'trace-a', span_id: 'span-b', parent_span_id: 'span-a',
    service_name: 'ledger', span_name: 'export report',
    start_time_unix_nano: 2, end_time_unix_nano: 3, duration_ms: 0.001,
    span_kind: 1, status_code: 0, attributes: {},
  },
];

test('evidence span links resolve only explicit span ID fields against loaded spans', () => {
  const evidence = {
    source_span_id: 'span-a',
    nested: { span_ids: ['span-b', 'not-in-trace'] },
    free_text: 'this mentions span-a but is not a span ID field',
  };

  assert.deepEqual(findEvidenceSpans(evidence, spans).map((span) => span.span_id), ['span-a', 'span-b']);
});

test('AI evidence refs navigate only when their supplied evidence maps to a loaded span', () => {
  const evidence = { source_span_id: 'span-b', note: 'no span reference' };

  assert.deepEqual(findReferencedSpans('span.span-a', evidence, spans).map((span) => span.span_id), ['span-a']);
  assert.deepEqual(findReferencedSpans('evidence.source_span_id', evidence, spans).map((span) => span.span_id), ['span-b']);
  assert.deepEqual(findReferencedSpans('finding.reason', evidence, spans), []);
  assert.deepEqual(findReferencedSpans('span.not-in-trace', evidence, spans), []);
});

test('AI evidence refs support bare evidence keys as well as prefixed references', () => {
  const evidence = { source_span_id: 'span-b' };
  assert.deepEqual(findReferencedSpans('source_span_id', evidence, spans).map((s) => s.span_id), ['span-b']);
});
