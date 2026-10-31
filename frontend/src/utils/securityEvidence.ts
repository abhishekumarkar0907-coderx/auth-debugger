import type { SpanRecord } from '../types.ts';

const SPAN_REFERENCE_KEY = /^(?:(?:source|parent|client|server|root|destination)_)?span_ids?$/i;

/**
 * Resolve span references only from fields explicitly named as span IDs.
 * Arbitrary text in evidence is never guessed to be an identifier.
 */
export function findEvidenceSpans(value: unknown, spans: SpanRecord[], key = ''): SpanRecord[] {
  const references = new Set<string>();

  const visit = (candidate: unknown, currentKey = ''): void => {
    if (SPAN_REFERENCE_KEY.test(currentKey)) {
      if (typeof candidate === 'string' && candidate.length > 0) references.add(candidate);
      else if (Array.isArray(candidate)) {
        for (const id of candidate) if (typeof id === 'string' && id.length > 0) references.add(id);
      }
    }

    if (Array.isArray(candidate)) {
      candidate.forEach((item) => visit(item, currentKey));
    } else if (candidate && typeof candidate === 'object') {
      Object.entries(candidate as Record<string, unknown>).forEach(([childKey, child]) => visit(child, childKey));
    }
  };

  visit(value, key);
  return spans.filter((span) => references.has(span.span_id));
}

/** Resolve a backend AI evidence reference to spans only when it names supplied evidence. */
export function findReferencedSpans(
  reference: string,
  evidence: Record<string, unknown>,
  spans: SpanRecord[],
): SpanRecord[] {
  if (reference.startsWith('span.')) {
    const id = reference.slice('span.'.length);
    return spans.filter((span) => span.span_id === id);
  }
  const evidencePrefix = 'evidence.';
  if (reference.startsWith(evidencePrefix)) {
    const evidenceKey = reference.slice(evidencePrefix.length);
    return findEvidenceSpans({ [evidenceKey]: evidence[evidenceKey] }, spans, evidenceKey);
  }
  if (reference in evidence) {
    return findEvidenceSpans({ [reference]: evidence[reference] }, spans, reference);
  }
  return [];
}
