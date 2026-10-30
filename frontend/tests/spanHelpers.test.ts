import test from 'node:test';
import assert from 'node:assert/strict';
import {
  formatDuration,
  formatUnixNano,
  getSpanKindInfo,
  getStatusCodeInfo,
  computeTraceMetrics,
  buildSpanHierarchy,
  flattenSpanHierarchy,
} from '../src/utils/spanHelpers.ts';
import type { SpanRecord } from '../src/types.ts';
import { SpanKind, StatusCode } from '../src/types.ts';

test('formatDuration formats micro, milli, and seconds correctly', () => {
  assert.equal(formatDuration(0.5), '500 µs');
  assert.equal(formatDuration(25), '25.00 ms');
  assert.equal(formatDuration(1500), '1.50 s');
  assert.equal(formatDuration(0), '0 µs');
  assert.equal(formatDuration(NaN), '0 ms');
});

test('formatUnixNano converts nanoseconds to ISO and relative ms', () => {
  // 1_000_000_000_000_000_000 ns = 2001-09-09T01:46:40.000Z
  const nano = 1_000_000_000_000_000_000;
  const res = formatUnixNano(nano);
  assert.equal(res.iso, '2001-09-09T01:46:40.000Z');

  const baseNano = nano - 50_000_000; // 50ms before
  assert.equal(res.relativeMs(baseNano), '+50.00 ms');
});

test('getSpanKindInfo maps OpenTelemetry span kinds to correct labels and classes', () => {
  assert.deepEqual(getSpanKindInfo(SpanKind.SERVER), {
    label: 'SERVER',
    badgeClass: 'badge-server',
  });
  assert.deepEqual(getSpanKindInfo(SpanKind.CLIENT), {
    label: 'CLIENT',
    badgeClass: 'badge-client',
  });
  assert.deepEqual(getSpanKindInfo(SpanKind.INTERNAL), {
    label: 'INTERNAL',
    badgeClass: 'badge-internal',
  });
  assert.deepEqual(getSpanKindInfo(SpanKind.PRODUCER), {
    label: 'PRODUCER',
    badgeClass: 'badge-producer',
  });
  assert.deepEqual(getSpanKindInfo(SpanKind.CONSUMER), {
    label: 'CONSUMER',
    badgeClass: 'badge-consumer',
  });
  assert.deepEqual(getSpanKindInfo(SpanKind.UNSPECIFIED), {
    label: 'UNSPECIFIED',
    badgeClass: 'badge-neutral',
  });
});

test('getStatusCodeInfo maps OpenTelemetry status codes', () => {
  assert.deepEqual(getStatusCodeInfo(StatusCode.OK), {
    label: 'OK',
    badgeClass: 'badge-status-ok',
    isError: false,
  });
  assert.deepEqual(getStatusCodeInfo(StatusCode.ERROR), {
    label: 'ERROR',
    badgeClass: 'badge-status-error',
    isError: true,
  });
  assert.deepEqual(getStatusCodeInfo(StatusCode.UNSET), {
    label: 'UNSET',
    badgeClass: 'badge-status-unset',
    isError: false,
  });
});

test('computeTraceMetrics accurately aggregates duration, errors, services, and root span', () => {
  const spans: SpanRecord[] = [
    {
      trace_id: 'trace-1',
      span_id: 'span-root',
      parent_span_id: null,
      service_name: 'frontend-proxy',
      span_name: 'GET /checkout',
      start_time_unix_nano: 1_000_000_000,
      end_time_unix_nano: 1_050_000_000,
      duration_ms: 50.0,
      span_kind: SpanKind.SERVER,
      status_code: StatusCode.OK,
      attributes: { 'http.status_code': 200 },
    },
    {
      trace_id: 'trace-1',
      span_id: 'span-child-1',
      parent_span_id: 'span-root',
      service_name: 'order-service',
      span_name: 'POST /orders',
      start_time_unix_nano: 1_010_000_000,
      end_time_unix_nano: 1_030_000_000,
      duration_ms: 20.0,
      span_kind: SpanKind.INTERNAL,
      status_code: StatusCode.OK,
      attributes: {},
    },
    {
      trace_id: 'trace-1',
      span_id: 'span-child-2',
      parent_span_id: 'span-child-1',
      service_name: 'payment-service',
      span_name: 'POST /refund',
      start_time_unix_nano: 1_020_000_000,
      end_time_unix_nano: 1_045_000_000,
      duration_ms: 25.0,
      span_kind: SpanKind.CLIENT,
      status_code: StatusCode.ERROR,
      attributes: { 'error.message': 'unauthorized' },
    },
  ];

  const metrics = computeTraceMetrics('trace-1', spans);

  assert.equal(metrics.traceId, 'trace-1');
  assert.equal(metrics.totalSpans, 3);
  assert.deepEqual(metrics.services, ['frontend-proxy', 'order-service', 'payment-service']);
  assert.equal(metrics.totalDurationMs, 50.0); // 1_050_000_000 - 1_000_000_000 = 50ms
  assert.equal(metrics.hasErrors, true);
  assert.equal(metrics.errorCount, 1);
  assert.equal(metrics.rootSpan?.span_id, 'span-root');
});

test('buildSpanHierarchy and flattenSpanHierarchy construct correct tree structure and depth', () => {
  const spans: SpanRecord[] = [
    {
      trace_id: 't1',
      span_id: 'root',
      parent_span_id: null,
      service_name: 'gateway',
      span_name: 'gateway-span',
      start_time_unix_nano: 100,
      end_time_unix_nano: 500,
      duration_ms: 400,
      span_kind: SpanKind.SERVER,
      status_code: StatusCode.OK,
      attributes: {},
    },
    {
      trace_id: 't1',
      span_id: 'child1',
      parent_span_id: 'root',
      service_name: 'auth',
      span_name: 'auth-check',
      start_time_unix_nano: 150,
      end_time_unix_nano: 250,
      duration_ms: 100,
      span_kind: SpanKind.INTERNAL,
      status_code: StatusCode.OK,
      attributes: {},
    },
    {
      trace_id: 't1',
      span_id: 'grandchild1',
      parent_span_id: 'child1',
      service_name: 'ldap',
      span_name: 'ldap-query',
      start_time_unix_nano: 180,
      end_time_unix_nano: 220,
      duration_ms: 40,
      span_kind: SpanKind.CLIENT,
      status_code: StatusCode.OK,
      attributes: {},
    },
  ];

  const tree = buildSpanHierarchy(spans);
  assert.equal(tree.length, 1);
  assert.equal(tree[0].span.span_id, 'root');
  assert.equal(tree[0].depth, 0);
  assert.equal(tree[0].children.length, 1);
  assert.equal(tree[0].children[0].span.span_id, 'child1');
  assert.equal(tree[0].children[0].depth, 1);
  assert.equal(tree[0].children[0].children.length, 1);
  assert.equal(tree[0].children[0].children[0].span.span_id, 'grandchild1');
  assert.equal(tree[0].children[0].children[0].depth, 2);

  const flattened = flattenSpanHierarchy(tree);
  assert.equal(flattened.length, 3);
  assert.equal(flattened[0].span.span_id, 'root');
  assert.equal(flattened[1].span.span_id, 'child1');
  assert.equal(flattened[2].span.span_id, 'grandchild1');
});
