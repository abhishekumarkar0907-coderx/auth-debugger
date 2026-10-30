# Frontend security-analysis integration notes

This file defines the **frontend view model** needed to render one deterministic auth-engine result. It is not an API endpoint or a wire-contract proposal. Palak’s agreed backend response will determine the route and the adapter that maps its JSON into these types.

## Deterministic result required by the panel

The view model in `src/types/securityAnalysis.ts` is derived from the existing Python `DetectionResult` and nested `Finding` dataclasses:

```ts
interface DeterministicAnalysisView {
  verdict: 'DETECTED' | 'NOT_DETECTED' | 'INSUFFICIENT_EVIDENCE';
  reason: string;
  details: Record<string, unknown>;
  finding: {
    finding_id: string;
    verdict: 'DETECTED' | 'NOT_DETECTED' | 'INSUFFICIENT_EVIDENCE';
    trace_id: string | null;
    initiating_principal: {
      principal_id: string;
      principal_type: 'user' | 'service' | 'agent';
      service_name: string | null;
    } | null;
    delegated_authority: { permissions: string[]; source: 'original' | 'delegated' | 'service' } | null;
    effective_action: string | null;
    required_authority: string[];
    service_authority: { permissions: string[]; source: 'original' | 'delegated' | 'service' } | null;
    attack_path: string[];
    evidence: Record<string, unknown>;
    reason: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'UNSCORED';
  };
}
```

The selected trace’s existing `SpanRecord[]` remains the source for span names, service names, and parent-child structure. The backend view result supplies the authoritative verdict, principal, permission comparison, attack path, reason, severity, and engine evidence. The model currently has no `classification` field; the frontend must not invent one. `verdict` appears at both result and finding levels in the engine, so inconsistent values should be surfaced as an error.

## Deterministic fields vs. optional AI explanation

The deterministic result above is required and authoritative. `AiExplanationResponse` in `src/services/aiExplanation.ts` is a separate optional UI payload containing only `status`, `finding_id`, optional explanation text/evidence references, and a message. It has no verdict, severity, or classification fields. The AI panel receives a `loadExplanation` function as a dependency; no endpoint is assumed before the backend contract is agreed.

## Panel states

`AnalysisPanelState` distinguishes:

- `loading`: analysis request in progress.
- `empty`: no analysis result exists for the selected trace; render no finding and never translate this state to `NOT_DETECTED`.
- `error`: backend or contract failure; preserve the selected trace and offer retry in the connected view.
- `ready`: render the deterministic result above and its evidence.

## Confirmed backend response envelope

Palak's confirmed response envelope (`GET /api/v1/traces/{trace_id}/analysis`):

```json
{
  "trace_id": "trace-456",
  "nodes": [],
  "edges": [],
  "authority_amplification_hops": [],
  "security_analysis": {
    "verdict": "DETECTED",
    "reason": "payments:charge required but absent from delegated request authority",
    "details": {
      "required_action": ["payments:charge"],
      "request_authority": ["orders:read"],
      "service_authority": ["payments:charge"],
      "attack_path": ["user:user-789", "checkout -> payment"]
    },
    "finding": {
      "finding_id": "finding-123",
      "verdict": "DETECTED",
      "trace_id": "trace-456",
      "initiating_principal": {
        "principal_id": "user-789",
        "principal_type": "user",
        "service_name": null
      },
      "delegated_authority": {
        "permissions": ["orders:read"],
        "source": "delegated"
      },
      "effective_action": "payments:charge",
      "required_authority": ["payments:charge"],
      "service_authority": {
        "permissions": ["payments:charge"],
        "source": "service"
      },
      "attack_path": ["user:user-789", "checkout -> payment"],
      "evidence": {
        "source_span_id": "span-42"
      },
      "reason": "payments:charge required but absent from delegated request authority",
      "severity": "HIGH"
    }
  }
}
```

## Frontend integration status

1. **Envelope & Adapter**: `TraceAnalysisEnvelope` and `adaptTraceAnalysisResponse` implemented in `src/types/securityAnalysis.ts`.
2. **API Client**: `fetchTraceAnalysis` added to `src/api.ts` and `analysis(traceId)` added to `createInvestigationApi` (backed by `demoAnalysisForTrace` in demo mode).
3. **Trace Explorer**: Dispatches `apiClient.analysis(selectedTraceId)` on trace change, tracks `analysisState` (`loading`, `empty`, `error`, `ready`), and passes it to `SecurityAnalysisPanel`.
4. **AI Explanation**: `AiExplanationPanel` mounted alongside deterministic analysis, triggered when finding is ready without blocking the panel.
5. **Schema & API Tests**: `tests/schema.test.ts` and `tests/api.test.ts` test the envelope, route, adapter, and required fields.
