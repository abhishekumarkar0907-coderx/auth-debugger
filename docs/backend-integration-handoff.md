# Backend integration handoff

## Current implementation

`GET /api/v1/traces/{trace_id}/graph` in `backend/app/main.py` reads spans
already stored for the requested trace. Spans enter the store through
`POST /v1/traces` as OTLP/HTTP protobuf and are normalized by
`backend/app/otlp.py` into the existing `SpanRecord` model.

On success, the graph endpoint returns:

- `trace_id`
- `nodes`
- `edges`
- `authority_amplification_hops`
- `security_analysis`

The first four graph fields remain present. `security_analysis` is produced by
`backend/app/security_engine.py`'s `analyze_security_trace()` adapter, which
uses `backend/app/analysis.py` to analyze the extracted authorization
context. It contains:

- `verdict`: detector verdict string, including `DETECTED`,
  `NOT_DETECTED`, or `INSUFFICIENT_EVIDENCE`
- `status`: same verdict string as `verdict`
- `reason`: detector explanation when available
- `finding`: serialized singular finding, including its type, evidence, and
  attack path; `NONE` is returned for non-detected and insufficient verdicts
- `findings`: a list populated for detected results
- `details`: detector-specific structured details; content depends on verdict
- `context`: extracted authorization context, including evidence and warnings
- `evidence_warnings`, `analyzed_at`, and `errors`: analysis diagnostics and
  metadata

When the trace is not in the in-memory store, the route returns HTTP 404 with
`{"detail": "Trace not found"}`. No other graph-route error response is
explicitly defined in the route code.

The existing frontend fetches this graph route and reads the optional
`security_analysis` property, including `verdict`, `reason`, `finding`, and
`context.warnings`. A missing property is displayed as unavailable, supporting
older backend responses.

## Focused integration coverage

`backend/tests/test_security_engine_integration.py` covers:

1. **Unauthorized delegation expansion:** HTTP 200; `security_analysis.verdict`
   and `finding.verdict` are `DETECTED`, the finding type is
   `UNAUTHORIZED_DELEGATION`, `payments:charge` appears in the unauthorized
   expansions, and the later missing delegation-scope warning remains present.
2. **Incomplete authority without a detected expansion:** HTTP 200;
   verdict remains `INSUFFICIENT_EVIDENCE` and the missing delegation-scope
   warning is preserved.
3. **Missing trace:** HTTP 404 with `{"detail": "Trace not found"}`.

The first test also verifies the legacy graph response fields and their
expected list types. `backend/tests/test_security_engine_integration.py` also
covers the standalone analysis response and authorized traces. Run the full
backend suite to validate those and the OTLP ingestion paths.

## Local setup and focused validation

From `backend/`, install the backend's declared dependencies and make the
sibling engine package importable:

```powershell
python -m pip install -r requirements.txt
$env:PYTHONPATH = "..\auth-engine"
uvicorn app.main:app --reload --port 8000
```

In another backend terminal, the test command is:

```powershell
$env:PYTHONPATH = "..\auth-engine"
python -m pytest -q tests\test_security_engine_integration.py
```

For the demo endpoint, also set `AUTH_DEBUGGER_ENV=development` and
`AUTH_DEBUGGER_ENABLE_DEMO_TRACE=true` in the backend process environment.
The frontend's default Vite proxy forwards `/api` and `/health` to port 8000;
direct browser requests to another origin require that origin to provide CORS
headers.

The repository's `backend/Dockerfile` expects the repository root as the build
context so it can access both backend and engine files:

```powershell
docker build -f backend/Dockerfile .
```

The focused test result above is verified. Docker image construction is not
verified by this handoff.
