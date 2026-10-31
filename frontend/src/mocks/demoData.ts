import type { SpanRecord, TraceSummary, TraceGraphResponse } from '../types.ts';

/** Case walkthrough data is intentionally separate from the backend span schema. */
export type CaseNodeKind = 'person' | 'service' | 'credential' | 'resource' | 'external';

export interface CaseNode {
  id: string;
  label: string;
  kind: CaseNodeKind;
  role: string;
  detail: string;
  suspicious?: boolean;
  x: number;
  y: number;
}

export interface CaseRelationship {
  id: string;
  from: string;
  to: string;
  label: string;
  evidence: string;
  suspicious?: boolean;
}

export interface CaseActivity {
  time: string;
  title: string;
  description: string;
  nodeId: string;
  signal: 'critical' | 'watch' | 'normal';
}

export interface InvestigationCase {
  id: string;
  title: string;
  status: 'Active' | 'Review';
  severity: 'High' | 'Medium' | 'Low';
  verdict: 'DETECTED' | 'NOT_DETECTED';
  updated: string;
  summary: string;
  finding: string;
  nodes: CaseNode[];
  relationships: CaseRelationship[];
  activity: CaseActivity[];
  workflow: string[];
}

export const DEMO_CASES: InvestigationCase[] = [
  {
    id: 'CASE-1042',
    title: 'Unexpected access during invoice export',
    status: 'Active',
    severity: 'High',
    verdict: 'DETECTED',
    updated: 'Today, 10:42 AM',
    summary: 'A reporting worker used a delegated credential to read a finance export outside its approved scope.',
    finding: 'The request identity changed at the worker boundary, then accessed a restricted finance resource without the required export permission.',
    workflow: ['Review the alert', 'Map the request path', 'Confirm the authority gap', 'Record the finding'],
    nodes: [
      { id: 'maya', label: 'Maya Chen', kind: 'person', role: 'User', detail: 'Finance analyst · initiated the export request', x: 10, y: 40 },
      { id: 'portal', label: 'Finance portal', kind: 'service', role: 'Entry API', detail: 'Accepted the user session and forwarded the export request', x: 31, y: 40 },
      { id: 'worker', label: 'Reporting worker', kind: 'service', role: 'Acting service', detail: 'Background worker · requested a delegated identity', suspicious: true, x: 54, y: 40 },
      { id: 'token', label: 'Service token', kind: 'credential', role: 'Delegated credential', detail: 'Token carried reports:read but the request required finance:export', suspicious: true, x: 74, y: 22 },
      { id: 'ledger', label: 'Quarterly ledger', kind: 'resource', role: 'Restricted resource', detail: 'Finance export · access policy requires finance:export', suspicious: true, x: 89, y: 57 },
      { id: 'archive', label: 'Export archive', kind: 'external', role: 'Downstream destination', detail: 'Internal object store · received the export payload', x: 71, y: 78 },
    ],
    relationships: [
      { id: 'r1', from: 'maya', to: 'portal', label: 'sign-in', evidence: 'principal.id = maya.chen@northstar.example' },
      { id: 'r2', from: 'portal', to: 'worker', label: 'queue job', evidence: 'POST /reports/export · request ID req-7f31' },
      { id: 'r3', from: 'worker', to: 'token', label: 'token swap', evidence: 'credential.subject changed to svc-reporting-worker', suspicious: true },
      { id: 'r4', from: 'token', to: 'ledger', label: 'scope mismatch', evidence: 'reports:read present · finance:export required', suspicious: true },
      { id: 'r5', from: 'ledger', to: 'archive', label: 'export write', evidence: '2,418 records · response status 200', suspicious: true },
    ],
    activity: [
      { time: '10:41:52.118', title: 'Export request accepted', description: 'Maya Chen requested the quarterly ledger export from the finance portal.', nodeId: 'maya', signal: 'normal' },
      { time: '10:41:52.204', title: 'Worker assumed delegated identity', description: 'The reporting worker exchanged the user context for a service token.', nodeId: 'worker', signal: 'watch' },
      { time: '10:41:52.231', title: 'Required scope was missing', description: 'The token lacked finance:export when the ledger read was authorized.', nodeId: 'token', signal: 'critical' },
      { time: '10:41:52.407', title: 'Export completed', description: 'The archive received 2,418 records despite the authority mismatch.', nodeId: 'ledger', signal: 'critical' },
    ],
  },
  {
    id: 'CASE-1038',
    title: 'Scheduled report access review',
    status: 'Review',
    severity: 'Low',
    verdict: 'NOT_DETECTED',
    updated: 'Yesterday, 4:16 PM',
    summary: 'A scheduled report read followed the expected service identity and stayed within its granted scope.',
    finding: 'No authorization boundary violation was found in the reviewed request path.',
    workflow: ['Review the alert', 'Map the request path', 'Confirm the authority check', 'Record the outcome'],
    nodes: [
      { id: 'scheduler', label: 'Report scheduler', kind: 'service', role: 'Scheduled job', detail: 'Runs the approved nightly summary job', x: 14, y: 41 },
      { id: 'api', label: 'Reporting API', kind: 'service', role: 'Entry API', detail: 'Validated the service identity and report scope', x: 40, y: 41 },
      { id: 'identity', label: 'Service token', kind: 'credential', role: 'Service identity', detail: 'Short-lived credential with reports:read', x: 64, y: 22 },
      { id: 'summary', label: 'Daily summary', kind: 'resource', role: 'Report data', detail: 'Internal reporting dataset · read permitted', x: 82, y: 58 },
    ],
    relationships: [
      { id: 's1', from: 'scheduler', to: 'api', label: 'request', evidence: 'GET /reports/daily · scheduled job nightly-summary' },
      { id: 's2', from: 'api', to: 'identity', label: 'identity ok', evidence: 'service account matches the registered workload' },
      { id: 's3', from: 'identity', to: 'summary', label: 'read allowed', evidence: 'reports:read granted and required by this resource' },
    ],
    activity: [
      { time: '04:00:00.014', title: 'Scheduled request started', description: 'The nightly summary job ran from its registered workload.', nodeId: 'scheduler', signal: 'normal' },
      { time: '04:00:00.063', title: 'Service identity validated', description: 'The API matched the short-lived credential to the registered service.', nodeId: 'identity', signal: 'normal' },
      { time: '04:00:00.119', title: 'Read completed within scope', description: 'The requested report required and received reports:read.', nodeId: 'summary', signal: 'normal' },
    ],
  },
];

const baseTime = Date.now() * 1_000_000;
const traceIds = ['7a91c4e2bd3048f6a1029d4c6e8b1f53', '2d4b8e13a72c49f0b0653c18d9a274fe'];

function span(
  traceIndex: number,
  index: number,
  parent: string | null,
  service: string,
  name: string,
  duration: number,
  attributes: Record<string, unknown>,
  status = 1,
): SpanRecord {
  const start = baseTime + (traceIndex * 3_000_000_000) + (index * 18_000_000);
  return {
    trace_id: traceIds[traceIndex],
    span_id: `${(traceIndex + 1).toString(16).padStart(2, '0')}${(index + 1).toString(16).padStart(14, '0')}`,
    parent_span_id: parent,
    service_name: service,
    span_name: name,
    start_time_unix_nano: start,
    end_time_unix_nano: start + duration * 1_000_000,
    duration_ms: duration,
    span_kind: index === 0 ? 2 : 3,
    status_code: status,
    attributes,
  };
}

const findingAttributes = {
  'authorization.verdict': 'DETECTED',
  'authorization.reason': 'The delegated service credential did not include the authority required by the finance ledger.',
  'authorization.finding_id': 'AUTHZ-8821',
  'authorization.severity': 'high',
  'authorization.initiating_principal': 'maya.chen@northstar.example',
  'authorization.actor': 'svc-reporting-worker',
  'authorization.acting_service': 'reporting-worker',
  'authorization.effective_action': 'ledger.export.read',
  'authorization.resource': 'finance://quarterly-ledger',
  'authorization.outcome': 'allowed',
  'authorization.delegation': 'maya.chen → finance-portal → reporting-worker',
  'authorization.credential_transition': 'user session → svc-reporting-worker token',
  'authorization.claims': ['reports:read'],
  'authorization.required_authority': ['finance:export'],
  'authorization.request_authority': ['reports:read'],
  'authorization.service_authority': ['reports:read'],
  'authorization.attack_path': ['Maya Chen', 'Finance portal', 'reporting-worker', 'svc-reporting token', 'Quarterly ledger'],
};

const clearAttributes = {
  'authorization.verdict': 'NOT_DETECTED',
  'authorization.reason': 'The service identity and granted scope matched the requested report operation.',
  'authorization.finding_id': 'AUTHZ-8814',
  'authorization.severity': 'low',
  'authorization.initiating_principal': 'nightly-summary-job',
  'authorization.actor': 'svc-reporting',
  'authorization.acting_service': 'reporting-api',
  'authorization.effective_action': 'report.daily.read',
  'authorization.resource': 'reports://daily-summary',
  'authorization.outcome': 'allowed',
  'authorization.claims': ['reports:read'],
  'authorization.required_authority': ['reports:read'],
  'authorization.request_authority': ['reports:read'],
  'authorization.service_authority': ['reports:read'],
};

export const DEMO_SPANS: SpanRecord[][] = [
  [
    span(0, 0, null, 'finance-portal', 'POST /reports/export', 289, { ...findingAttributes, 'http.request_id': 'req-7f31', 'enduser.id': 'maya.chen@northstar.example' }),
    span(0, 1, '0100000000000001', 'reporting-worker', 'queue.consume export-job', 184, { 'messaging.operation': 'process', 'messaging.destination': 'finance-export' }),
    span(0, 2, '0100000000000002', 'identity-broker', 'POST /token/exchange', 42, { ...findingAttributes, 'oauth.grant_type': 'token-exchange', 'authorization.claims': ['reports:read'] }),
    span(0, 3, '0100000000000002', 'ledger-service', 'GET /ledger/quarterly/export', 91, { ...findingAttributes, 'db.operation': 'SELECT', 'db.rows_returned': 2418 }),
    span(0, 4, '0100000000000004', 'object-store', 'PUT /exports/quarterly.csv', 66, { 'storage.object': 'exports/quarterly.csv', 'storage.bytes': 894213 }),
  ],
  [
    span(1, 0, null, 'reporting-api', 'GET /reports/daily', 106, { ...clearAttributes, 'http.request_id': 'req-91aa', 'job.name': 'nightly-summary' }),
    span(1, 1, '0200000000000001', 'identity-broker', 'POST /token/validate', 18, { 'authorization.actor': 'svc-reporting', 'authorization.outcome': 'validated' }),
    span(1, 2, '0200000000000001', 'report-store', 'GET /daily-summary', 54, { ...clearAttributes, 'db.operation': 'SELECT', 'db.rows_returned': 1 }),
  ],
];

export const DEMO_TRACES: TraceSummary[] = DEMO_SPANS.map((spans, index) => ({
  trace_id: traceIds[index],
  span_count: spans.length,
  services: [...new Set(spans.map((item) => item.service_name).filter((name): name is string => !!name))],
}));

export const DEMO_RECENT_SPANS: SpanRecord[] = [...DEMO_SPANS.flat()].sort(
  (a, b) => b.start_time_unix_nano - a.start_time_unix_nano,
);

export function demoSpansForTrace(traceId: string): SpanRecord[] {
  const index = DEMO_TRACES.findIndex((trace) => trace.trace_id === traceId);
  return index < 0 ? [] : DEMO_SPANS[index];
}

export function demoAnalysisForTrace(traceId: string): TraceGraphResponse | null {
  if (traceId === traceIds[0]) {
    return {
      trace_id: traceId,
      nodes: [],
      edges: [],
      authority_amplification_hops: [],
      security_analysis: {
        verdict: 'DETECTED',
        finding: {
          finding_id: 'AUTHZ-8821',
          verdict: 'DETECTED',
          trace_id: traceId,
          initiating_principal: {
            principal_id: 'maya.chen@northstar.example',
            principal_type: 'user',
            service_name: null,
          },
          delegated_authority: {
            permissions: ['reports:read'],
            source: 'delegated',
          },
          effective_action: 'ledger.export.read',
          required_authority: ['finance:export'],
          service_authority: {
            permissions: ['reports:read'],
            source: 'service',
          },
          attack_path: [
            'Maya Chen',
            'Finance portal',
            'reporting-worker',
            'svc-reporting token',
            'Quarterly ledger',
          ],
          evidence: {
            source_span_id: '0100000000000001',
            resource: 'finance://quarterly-ledger',
            reason: 'The delegated service credential did not include the authority required by the finance ledger.',
          },
          reason: 'The delegated service credential did not include the authority required by the finance ledger.',
          severity: 'HIGH',
        },
        reason: 'The delegated service credential did not include the authority required by the finance ledger.',
        details: {
          required_action: ['finance:export'],
          request_authority: ['reports:read'],
          service_authority: ['reports:read'],
        },
      },
    };
  }
  if (traceId === traceIds[1]) {
    return {
      trace_id: traceId,
      nodes: [],
      edges: [],
      authority_amplification_hops: [],
      security_analysis: {
        verdict: 'NOT_DETECTED',
        finding: {
          finding_id: 'AUTHZ-8814',
          verdict: 'NOT_DETECTED',
          trace_id: traceId,
          initiating_principal: {
            principal_id: 'nightly-summary-job',
            principal_type: 'service',
            service_name: 'reporting-api',
          },
          delegated_authority: {
            permissions: ['reports:read'],
            source: 'delegated',
          },
          effective_action: 'report.daily.read',
          required_authority: ['reports:read'],
          service_authority: {
            permissions: ['reports:read'],
            source: 'service',
          },
          attack_path: [],
          evidence: {
            resource: 'reports://daily-summary',
          },
          reason: 'The service identity and granted scope matched the requested report operation.',
          severity: 'LOW',
        },
        reason: 'The service identity and granted scope matched the requested report operation.',
        details: {},
      },
    };
  }
  return null;
}
