# Frontend security-analysis integration

The live frontend consumes the backend graph route, which returns the authorization graph and deterministic finding together:

```text
GET /api/v1/traces/{trace_id}/graph
```

The response follows `TraceGraphResponse` in `backend/app/schemas.py`:

```json
{
  "trace_id": "trace-456",
  "nodes": [
    { "id": "principal-1", "type": "principal", "label": "user-789", "metadata": {}, "authority": ["orders:read"] }
  ],
  "edges": [
    {
      "source": "principal-1",
      "target": "payment-service",
      "type": "delegation",
      "trace_id": "trace-456",
      "metadata": {},
      "delegated_authority": ["orders:read"],
      "credential_type": "oauth",
      "explicit": true,
      "step_index": 0
    }
  ],
  "authority_amplification_hops": [],
  "security_analysis": {
    "verdict": "DETECTED",
    "reason": "payments:charge required but absent from delegated request authority",
    "finding": {
      "finding_id": "finding-123",
      "verdict": "DETECTED",
      "finding_type": "CONFUSED_DEPUTY",
      "classification": "CONFUSED_DEPUTY",
      "severity": "HIGH",
      "trace_id": "trace-456",
      "initiating_principal": { "principal_id": "user-789", "principal_type": "user" },
      "effective_action": "payments:charge",
      "required_authority": ["payments:charge"],
      "delegated_authority": ["orders:read"],
      "service_authority": ["payments:charge"],
      "attack_path": ["user:user-789", "checkout -> payment"],
      "evidence": { "source_span_id": "span-42" },
      "reason": "payments:charge required but absent from delegated request authority"
    },
    "details": {},
    "findings": []
  }
}
```

The finding fields above reflect the current backend serializer. In particular, authority values are arrays of permissions, not objects with a source label. An insufficient-evidence response can contain a finding summary without `finding_id` or a nested finding verdict. The frontend keeps the top-level verdict authoritative and does not synthesize missing identity, severity, evidence, or finding data. The graph adapter validates nodes, edges, references, and supported finding fields before rendering.

The graph panel and security panel use the response from this route. Span names and hierarchy still come from `GET /api/v1/traces/{trace_id}`. Evidence links navigate only when the evidence field explicitly names a span ID that exists in those loaded spans. Empty graph arrays and `security_analysis: null` are shown as empty/inconclusive data, not a clean verdict; HTTP and malformed-response failures are errors.

`GET /api/v1/analysis/{trace_id}` is a separate deterministic analysis endpoint and is not used by the trace graph view. No live AI explanation endpoint is currently integrated. The hardcoded walkthrough explanation is shown only in Sample Data mode and is labeled sample text; live mode reports explanations unavailable.

The separate case walkthrough uses fictional fixtures from `src/mocks/demoData.ts`; it is sample data and is not populated by the live graph response.
