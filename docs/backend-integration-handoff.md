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

The first four graph fields remain present. `security_analysis` is returned
unchanged from `backend/app/security_engine.py`'s call to
`auth_engine.security_engine_service.analyze_spans()`. It contains:

- `verdict`: detector verdict string, including `DETECTED`,
  `NOT_DETECTED`, or `INSUFFICIENT_EVIDENCE`
- `reason`: detector explanation
- `finding`: serialized finding, including its type, evidence, and attack path
- `details`: detector-specific structured details; content depends on verdict
- `context`: extracted authorization context, including evidence and warnings

When the trace is not in the in-memory store, the route returns HTTP 404 with
`{"detail": "Trace not found"}`. No other graph-route error response is
explicitly defined in the route code.

The existing frontend fetches this graph route and reads the optional
`security_analysis` property. A missing property is displayed as unavailable,
supporting older backend responses.

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
expected list types. These three focused tests passed together (`3 passed`).
This does not certify other backend/API behavior.

## Comparing Palak's local backend changes

Before merging, compare Palak's local versions of
`backend/app/main.py`, `backend/app/security_engine.py`, and
`backend/tests/test_security_engine_integration.py` with the corresponding
repository versions. Review each diff and retain distinct changes from both
branches. In particular, merge the existing graph handler's span lookup,
graph construction, and response fields with the call to
`analyze_security_spans(spans)` and the `security_analysis` response key.
Do not replace an entire file with either branch's copy. If both versions
change the same behavior or response shape, coordinate with Palak before
resolving that conflict.

## Local setup and focused validation

From `backend/`, install the backend's declared dependencies and make the
sibling engine package importable:

```powershell
python -m pip install -r requirements.txt
$env:PYTHONPATH = "..\auth-engine"
python -m pytest -q tests\test_security_engine_integration.py
```

The repository's `backend/Dockerfile` expects the repository root as the build
context so it can access both backend and engine files:

```powershell
docker build -f backend/Dockerfile .
```

The focused test result above is verified. Docker image construction is not
verified by this handoff.
