import test from 'node:test';
import assert from 'node:assert/strict';
import type { SpanRecord, TraceSummary } from '../src/types.ts';
import { SpanKind, StatusCode } from '../src/types.ts';

test('SpanRecord matches FastAPI backend schema', () => {
  const backendSamplePayload = {
    trace_id: '00112233445566778899aabbccddeeff',
    span_id: '0011223344556677',
    parent_span_id: null,
    service_name: 'test-service',
    span_name: 'GET /api/test',
    start_time_unix_nano: 1_000_000_000,
    end_time_unix_nano: 1_025_000_000,
    duration_ms: 25.0,
    span_kind: SpanKind.SERVER,
    status_code: StatusCode.OK,
    attributes: {
      'service.name': 'test-service',
      'http.status_code': 200,
      'user.id': 'alice',
      'user.role': 'admin',
    },
  };

  const record: SpanRecord = backendSamplePayload;
  assert.equal(record.trace_id, '00112233445566778899aabbccddeeff');
  assert.equal(record.span_id, '0011223344556677');
  assert.equal(record.parent_span_id, null);
  assert.equal(record.service_name, 'test-service');
  assert.equal(record.span_name, 'GET /api/test');
  assert.equal(record.duration_ms, 25.0);
  assert.equal(record.span_kind, 2);
  assert.equal(record.status_code, 1);
  assert.equal(record.attributes['user.role'], 'admin');
});

test('TraceSummary matches FastAPI backend schema', () => {
  const summaryPayload = {
    trace_id: '00112233445566778899aabbccddeeff',
    span_count: 5,
    services: ['cart-service', 'payment-service'],
  };

  const summary: TraceSummary = summaryPayload;
  assert.equal(summary.trace_id, '00112233445566778899aabbccddeeff');
  assert.equal(summary.span_count, 5);
  assert.deepEqual(summary.services, ['cart-service', 'payment-service']);
});
