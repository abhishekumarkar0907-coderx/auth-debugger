import type { SpanRecord } from '../types.ts';

export type SecurityVerdict = 'DETECTED' | 'NOT_DETECTED' | 'INSUFFICIENT_EVIDENCE';

export interface SecurityAnalysis {
  verdict: SecurityVerdict;
  hasDetectorVerdict: boolean;
  reason: string | null;
  findingId: string | null;
  severity: string | null;
  principal: string | null;
  actor: string | null;
  service: string | null;
  action: string | null;
  resource: string | null;
  outcome: string | null;
  delegation: string | null;
  credentialTransition: string | null;
  claims: string | null;
  requiredAuthority: string[];
  requestAuthority: string[];
  serviceAuthority: string[];
  attackPath: string[];
  evidence: Array<{ key: string; value: unknown }>;
}

const VERDICTS = new Set<SecurityVerdict>([
  'DETECTED',
  'NOT_DETECTED',
  'INSUFFICIENT_EVIDENCE',
]);

const FLAT_KEYS = {
  verdict: ['authorization.verdict', 'auth.verdict', 'security.verdict', 'finding.verdict', 'auth_engine.verdict'],
  reason: ['authorization.reason', 'auth.reason', 'security.reason', 'finding.reason'],
  findingId: ['authorization.finding_id', 'auth.finding_id', 'finding.id'],
  severity: ['authorization.severity', 'auth.severity', 'finding.severity'],
  principal: ['authorization.initiating_principal', 'authorization.principal', 'auth.principal', 'enduser.id', 'user.id', 'principal'],
  actor: ['authorization.actor', 'auth.actor', 'user.actor', 'actor'],
  service: ['authorization.acting_service', 'authorization.service', 'auth.service', 'service_identity', 'service'],
  action: ['authorization.effective_action', 'authorization.action', 'auth.action', 'action'],
  resource: ['authorization.resource', 'auth.resource', 'resource'],
  outcome: ['authorization.outcome', 'auth.outcome', 'outcome'],
  delegation: ['authorization.delegation', 'auth.delegation', 'delegation'],
  credentialTransition: ['authorization.credential_transition', 'auth.credential_transition', 'credential_transition'],
  claims: ['authorization.claims', 'auth.claims', 'authorization.scopes', 'auth.scopes', 'claims', 'scopes'],
  requiredAuthority: ['authorization.required_authority', 'auth.required_authority'],
  requestAuthority: ['authorization.request_authority', 'authorization.delegated_authority', 'auth.request_authority'],
  serviceAuthority: ['authorization.service_authority', 'auth.service_authority'],
  attackPath: ['authorization.attack_path', 'auth.attack_path'],
} as const;

function asRecord(value: unknown): Record<string, unknown> | null {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  if (typeof value === 'string' && value.trim().startsWith('{')) {
    try {
      const parsed: unknown = JSON.parse(value);
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
        ? parsed as Record<string, unknown>
        : null;
    } catch {
      return null;
    }
  }
  return null;
}

function firstValue(records: Array<Record<string, unknown>>, keys: readonly string[]): unknown {
  for (const record of records) {
    for (const key of keys) {
      if (record[key] !== undefined && record[key] !== null && record[key] !== '') return record[key];
    }
  }
  return undefined;
}

function displayValue(value: unknown): string | null {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value);
}

function stringList(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(displayValue).filter((item): item is string => !!item);
  if (typeof value === 'string') {
    if (value.trim().startsWith('[')) {
      try {
        const parsed: unknown = JSON.parse(value);
        if (Array.isArray(parsed)) return parsed.map(displayValue).filter((item): item is string => !!item);
      } catch {
        // Fall back to a delimited string when the value is not valid JSON.
      }
    }
    return value.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean);
  }
  return [];
}

function uniqueRecordValues(spans: SpanRecord[]): Record<string, unknown>[] {
  const records: Record<string, unknown>[] = [];
  for (const span of spans) {
    const attributes = span.attributes || {};
    records.push(attributes);
    for (const key of ['authorization.analysis', 'auth.analysis', 'security.analysis', 'authorization.finding', 'auth.finding', 'finding']) {
      const nested = asRecord(attributes[key]);
      if (nested) {
        records.push(nested);
        const finding = asRecord(nested.finding);
        if (finding) records.push(finding);
        const result = asRecord(nested.result);
        if (result) {
          records.push(result);
          const resultFinding = asRecord(result.finding);
          if (resultFinding) records.push(resultFinding);
          const resultDetails = asRecord(result.details);
          if (resultDetails) records.push(resultDetails);
        }
        const details = asRecord(nested.details);
        if (details) records.push(details);
      }
    }
  }
  return records;
}

export function analyzeTraceMetadata(spans: SpanRecord[]): SecurityAnalysis {
  const records = uniqueRecordValues(spans);
  const foundVerdicts = records
    .flatMap((record) => FLAT_KEYS.verdict.map((key) => record[key]))
    .map((value) => String(value ?? '').toUpperCase())
    .filter((value): value is SecurityVerdict => VERDICTS.has(value as SecurityVerdict));
  const distinctVerdicts = [...new Set(foundVerdicts)];
  const verdict: SecurityVerdict = distinctVerdicts.length === 1 ? distinctVerdicts[0] : 'INSUFFICIENT_EVIDENCE';
  const conflictingVerdicts = distinctVerdicts.length > 1;
  const hasDetectorVerdict = distinctVerdicts.length === 1;

  const evidence = spans.flatMap((span) => Object.entries(span.attributes || {}))
    .filter(([key]) => /^(authorization|auth|security|finding)([._-]|$)/i.test(key) ||
      ['principal', 'actor', 'service', 'service_identity', 'delegation', 'credential_transition', 'resource', 'action', 'claims', 'scopes', 'outcome'].includes(key))
    .map(([key, value]) => ({ key, value }));

  return {
    verdict,
    hasDetectorVerdict: hasDetectorVerdict && !conflictingVerdicts,
    reason: conflictingVerdicts
      ? `Conflicting detector verdicts were attached to this trace: ${distinctVerdicts.join(', ')}.`
      : hasDetectorVerdict ? displayValue(firstValue(records, FLAT_KEYS.reason)) : null,
    findingId: displayValue(firstValue(records, FLAT_KEYS.findingId)),
    severity: displayValue(firstValue(records, FLAT_KEYS.severity)),
    principal: displayValue(firstValue(records, FLAT_KEYS.principal)),
    actor: displayValue(firstValue(records, FLAT_KEYS.actor)),
    service: displayValue(firstValue(records, FLAT_KEYS.service)),
    action: displayValue(firstValue(records, FLAT_KEYS.action)),
    resource: displayValue(firstValue(records, FLAT_KEYS.resource)),
    outcome: displayValue(firstValue(records, FLAT_KEYS.outcome)),
    delegation: displayValue(firstValue(records, FLAT_KEYS.delegation)),
    credentialTransition: displayValue(firstValue(records, FLAT_KEYS.credentialTransition)),
    claims: displayValue(firstValue(records, FLAT_KEYS.claims)),
    requiredAuthority: stringList(firstValue(records, FLAT_KEYS.requiredAuthority)),
    requestAuthority: stringList(firstValue(records, FLAT_KEYS.requestAuthority)),
    serviceAuthority: stringList(firstValue(records, FLAT_KEYS.serviceAuthority)),
    attackPath: stringList(firstValue(records, FLAT_KEYS.attackPath)),
    evidence,
  };
}
