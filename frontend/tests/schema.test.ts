import test from 'node:test';
import assert from 'node:assert/strict';
import type { DeterministicAnalysisView, SpanRecord, TraceAnalysisEnvelope, TraceSummary } from '../src/types.ts';
import { adaptTraceAnalysisResponse, SpanKind, StatusCode } from '../src/types.ts';

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

test('DeterministicAnalysisView matches auth-engine result schema', () => {
  const analysisPayload: DeterministicAnalysisView = {
    verdict: 'DETECTED',
    reason: 'payments:charge required but absent from delegated request authority',
    details: { required_action: ['payments:charge'], request_authority: ['orders:read'] },
    finding: {
      finding_id: 'finding-123',
      verdict: 'DETECTED',
      trace_id: 'trace-456',
      initiating_principal: {
        principal_id: 'user-789',
        principal_type: 'user',
        service_name: null,
      },
      delegated_authority: { permissions: ['orders:read'], source: 'delegated' },
      effective_action: 'payments:charge',
      required_authority: ['payments:charge'],
      service_authority: { permissions: ['payments:charge'], source: 'service' },
      attack_path: ['user:user-789', 'checkout -> payment'],
      evidence: { span_id: 'span-99' },
      reason: 'payments:charge required but absent from delegated request authority',
      severity: 'HIGH',
    },
  };

  assert.equal(analysisPayload.verdict, 'DETECTED');
  assert.equal(analysisPayload.finding.finding_id, 'finding-123');
  assert.equal(analysisPayload.finding.initiating_principal?.principal_id, 'user-789');
  assert.deepEqual(analysisPayload.finding.required_authority, ['payments:charge']);
  assert.equal(analysisPayload.finding.severity, 'HIGH');
});

test('TraceAnalysisEnvelope and adapter correctly process backend analysis response', () => {
  const backendResponse = {
    trace_id: 'trace-456',
    nodes: [],
    edges: [],
    authority_amplification_hops: [],
    security_analysis: {
      verdict: 'DETECTED' as const,
      reason: 'payments:charge required but absent from delegated request authority',
      details: {
        required_action: ['payments:charge'],
        request_authority: ['orders:read'],
        service_authority: ['payments:charge'],
        attack_path: ['user:user-789', 'checkout -> payment'],
      },
      finding: {
        finding_id: 'finding-123',
        verdict: 'DETECTED' as const,
        trace_id: 'trace-456',
        initiating_principal: {
          principal_id: 'user-789',
          principal_type: 'user' as const,
          service_name: null,
        },
        delegated_authority: {
          permissions: ['orders:read'],
          source: 'delegated' as const,
        },
        effective_action: 'payments:charge',
        required_authority: ['payments:charge'],
        service_authority: {
          permissions: ['payments:charge'],
          source: 'service' as const,
        },
        attack_path: ['user:user-789', 'checkout -> payment'],
        evidence: {
          source_span_id: 'span-42',
        },
        reason: 'payments:charge required but absent from delegated request authority',
        severity: 'HIGH' as const,
      },
    },
  };

  const envelope: TraceAnalysisEnvelope = backendResponse;
  assert.equal(envelope.trace_id, 'trace-456');
  assert.deepEqual(envelope.nodes, []);
  assert.deepEqual(envelope.edges, []);
  assert.deepEqual(envelope.authority_amplification_hops, []);

  const adapted = adaptTraceAnalysisResponse(envelope);
  assert.ok(adapted);
  assert.equal(adapted?.verdict, 'DETECTED');
  assert.equal(adapted?.finding.finding_id, 'finding-123');
  assert.equal(adapted?.finding.evidence.source_span_id, 'span-42');
  assert.deepEqual(adapted?.finding.delegated_authority?.permissions, ['orders:read']);
});

test('TraceAnalysisEnvelope correctly processes INSUFFICIENT_EVIDENCE response', () => {
  const insufficientPayload: TraceAnalysisEnvelope = {
    trace_id: 'trace-789',
    nodes: [],
    edges: [],
    authority_amplification_hops: [],
    security_analysis: {
      verdict: 'INSUFFICIENT_EVIDENCE',
      reason: 'Effective downstream operation is missing from the scenario',
      details: {},
      finding: {
        finding_id: 'finding-789',
        verdict: 'INSUFFICIENT_EVIDENCE',
        trace_id: 'trace-789',
        initiating_principal: {
          principal_id: 'user-321',
          principal_type: 'user',
          service_name: null,
        },
        delegated_authority: null,
        effective_action: null,
        required_authority: [],
        service_authority: null,
        attack_path: [],
        evidence: {},
        reason: 'Effective downstream operation is missing from the scenario',
        severity: 'UNSCORED',
      },
    },
  };

  const adapted = adaptTraceAnalysisResponse(insufficientPayload);
  assert.ok(adapted);
  assert.equal(adapted?.verdict, 'INSUFFICIENT_EVIDENCE');
  assert.equal(adapted?.finding.finding_id, 'finding-789');
  assert.equal(adapted?.finding.initiating_principal?.principal_id, 'user-321');
  assert.equal(adapted?.finding.delegated_authority, null);
  assert.equal(adapted?.finding.effective_action, null);
  assert.deepEqual(adapted?.finding.required_authority, []);
  assert.equal(adapted?.finding.service_authority, null);
  assert.deepEqual(adapted?.finding.attack_path, []);
  assert.deepEqual(adapted?.finding.evidence, {});
  assert.equal(adapted?.finding.severity, 'UNSCORED');
});

test('trace-analysis envelope accepts a nullable finding and adapts it to no result', () => {
  const envelope: TraceAnalysisEnvelope = {
    trace_id: 'trace-without-analysis',
    nodes: [],
    edges: [],
    authority_amplification_hops: [],
    security_analysis: null,
  };
  assert.equal(adaptTraceAnalysisResponse(envelope), null);
});
