import test from 'node:test';
import assert from 'node:assert/strict';
import type { DeterministicAnalysisView, SpanRecord, TraceSummary } from '../src/types.ts';
import { adaptTraceGraphResponse, SpanKind, StatusCode } from '../src/types.ts';

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

test('trace graph adapter consumes the current backend graph and finding response', () => {
  const backendResponse = {
    trace_id: 'trace-456',
    nodes: [
      { id: 'principal-1', type: 'principal', label: 'user-789', metadata: {}, authority: ['orders:read'] },
      { id: 'payment-service', type: 'service', label: 'payment', metadata: {}, authority: ['payments:charge'] },
    ],
    edges: [
      {
        source: 'principal-1', target: 'payment-service', type: 'delegation', trace_id: 'trace-456',
        metadata: {}, delegated_authority: ['orders:read'], credential_type: 'oauth', explicit: true, step_index: 0,
      },
    ],
    authority_amplification_hops: [],
    security_analysis: {
      verdict: 'DETECTED' as const,
      status: 'DETECTED',
      reason: 'payments:charge required but absent from delegated request authority',
      details: {
        required_action: ['payments:charge'],
        request_authority: ['orders:read'],
        service_authority: ['payments:charge'],
        attack_path: ['user:user-789', 'checkout -> payment'],
      },
      finding: {
        finding_id: 'finding-123',
        finding_type: 'CONFUSED_DEPUTY',
        classification: 'CONFUSED_DEPUTY',
        severity: 'HIGH',
        trace_id: 'trace-456',
        initiating_principal: {
          principal_id: 'user-789',
          principal_type: 'user',
        },
        delegated_authority: ['orders:read'],
        effective_action: 'payments:charge',
        required_authority: ['payments:charge'],
        service_authority: ['payments:charge'],
        attack_path: ['user:user-789', 'checkout -> payment'],
        evidence: { source_span_id: 'span-42' },
        reason: 'payments:charge required but absent from delegated request authority',
      },
    },
  };

  const adapted = adaptTraceGraphResponse(backendResponse);
  assert.equal(adapted.trace_id, 'trace-456');
  assert.equal(adapted.nodes.length, 2);
  assert.equal(adapted.edges.length, 1);
  assert.equal(adapted.security_analysis?.verdict, 'DETECTED');
  assert.equal(adapted.security_analysis?.finding.finding_id, 'finding-123');
  assert.equal(adapted.security_analysis?.finding.category, 'CONFUSED_DEPUTY');
  assert.equal(adapted.security_analysis?.finding.evidence.source_span_id, 'span-42');
  assert.deepEqual(adapted.security_analysis?.finding.delegated_authority?.permissions, ['orders:read']);
});

test('trace graph adapter preserves insufficient evidence without inventing a finding id', () => {
  const insufficientPayload = {
    trace_id: 'trace-789',
    nodes: [],
    edges: [],
    authority_amplification_hops: [],
    security_analysis: {
      verdict: 'INSUFFICIENT_EVIDENCE',
      reason: 'Effective downstream operation is missing from the scenario',
      details: {},
      finding: {
        finding_type: 'NONE',
        severity: 'UNSCORED',
        trace_id: 'trace-789',
        initiating_principal: null,
        delegated_authority: null,
        effective_action: null,
        required_authority: [],
        service_authority: null,
        attack_path: [],
        reason: 'Effective downstream operation is missing from the scenario',
      },
    },
  };

  const adapted = adaptTraceGraphResponse(insufficientPayload);
  assert.equal(adapted.security_analysis?.verdict, 'INSUFFICIENT_EVIDENCE');
  assert.equal(adapted.security_analysis?.finding.finding_id, null);
  assert.equal(adapted.security_analysis?.finding.initiating_principal, null);
  assert.equal(adapted.security_analysis?.finding.delegated_authority, null);
  assert.deepEqual(adapted.security_analysis?.finding.evidence, {});
  assert.equal(adapted.security_analysis?.finding.severity, 'UNSCORED');
});

test('graph response accepts a backend null analysis without turning it into a clean verdict', () => {
  const envelope = {
    trace_id: 'trace-without-analysis',
    nodes: [],
    edges: [],
    authority_amplification_hops: [],
    security_analysis: null,
  };
  assert.equal(adaptTraceGraphResponse(envelope).security_analysis, null);
});

test('malformed graph references and finding fields are rejected as API contract errors', () => {
  assert.throws(() => adaptTraceGraphResponse({
    trace_id: 'trace-a',
    nodes: [{ id: 'node-a', type: 'service', label: 'service', metadata: {} }],
    edges: [{ source: 'node-a', target: 'missing-node', type: 'calls', trace_id: 'trace-a', metadata: {} }],
    authority_amplification_hops: [],
    security_analysis: null,
  }), /malformed trace graph response/);
  assert.throws(() => adaptTraceGraphResponse({
    trace_id: 'trace-a',
    nodes: [],
    edges: [],
    authority_amplification_hops: [],
    security_analysis: { verdict: 'DETECTED', finding: null },
  }), /malformed trace graph response/);
});
