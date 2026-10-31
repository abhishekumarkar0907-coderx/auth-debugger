# Authorization Debugger Backend — Milestone 1

This is the first real integration layer for Authorization Debugger.

## Goal

Prove:

```text
OTLP trace payload
      ↓
FastAPI
      ↓
OTLP protobuf parser
      ↓
Normalized spans
      ↓
API response
```

For this milestone the normalized spans are stored in a bounded, process-local
in-memory store (up to 5,000 spans). Data is lost when the backend restarts and
is not shared between worker processes. This milestone intentionally does not
add persistence: the smallest follow-up for single-instance retention is a
SQLite-backed implementation behind the existing store interface and a
persistent data volume. Multi-instance retention would require a shared store
such as PostgreSQL.

The backend API currently has no authentication. Do not expose it directly to
untrusted networks.

## Local setup

From this directory:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e ..\auth-engine
```

To enable the development demo trace, set both opt-in variables in this
terminal before starting the backend:

```powershell
$env:AUTH_DEBUGGER_ENV = "development"
$env:AUTH_DEBUGGER_ENABLE_DEMO_TRACE = "true"
```

Start the backend:

```powershell
uvicorn app.main:app --reload --port 8000
```

Health:

```text
http://localhost:8000/health
```

Swagger:

```text
http://localhost:8000/docs
```

Run tests:

```powershell
$env:PYTHONPATH = "..\auth-engine"
python -m pytest
```

## Instrumented OTLP smoke test

The backend tests construct synthetic OTLP protobuf requests directly. To
verify an instrumented application/exporter over HTTP as well, start the
backend and run the following from the repository root in a separate Python
environment. The extra OpenTelemetry SDK/exporter packages are for this smoke
client only; they are not backend runtime dependencies.

```powershell
python -m venv .venv-otel-smoke
.\.venv-otel-smoke\Scripts\Activate.ps1
python -m pip install opentelemetry-sdk==1.37.0 opentelemetry-exporter-otlp-proto-http==1.37.0
python backend\scripts\instrumented_otlp_smoke.py
```

The client creates nested checkout/payment spans with the OpenTelemetry SDK,
exports them as OTLP/HTTP protobuf to `http://127.0.0.1:8000/v1/traces`, then
checks span retrieval, parent/trace identity, graph generation, the
deterministic unauthorized-delegation finding, and frontend-facing response
fields. This is synthetic application telemetry, not telemetry from a
production or independently instrumented application.

## OTLP endpoint

```text
POST /v1/traces
Content-Type: application/x-protobuf
```

The endpoint accepts OTLP/HTTP protobuf only; OTLP JSON and other content types
are rejected with HTTP 415. Empty bodies and malformed protobuf/span identity
data are rejected without storing any spans.

## Current API

```text
GET  /health
POST /v1/traces
GET  /api/v1/spans
GET  /api/v1/traces
GET  /api/v1/traces/{trace_id}
GET  /api/v1/traces/{trace_id}/graph
GET  /api/v1/analysis/{trace_id}
POST /api/v1/analysis/{trace_id}
POST /api/v1/demo/unauthorized-delegation  # development opt-in required
```

The graph endpoint extracts authorization context from the selected trace,
builds an isolated authorization graph, and runs deterministic analysis.
Unknown operation outcomes and incomplete delegation metadata return
`INSUFFICIENT_EVIDENCE`.

Service permissions and trusted delegation grants are optional explicit
configuration. They are never inferred from service names or trace contents:

```powershell
$env:AUTH_DEBUGGER_SERVICE_AUTHORITIES='{"payment":["payments:charge"]}'
$env:AUTH_DEBUGGER_DELEGATION_GRANTS='[{"from_principal":"user-1","to_principal":"payment","permissions":["payments:charge"]}]'
```

In the Docker Compose integration, build the backend from the repository root
so the image can include the sibling `auth-engine` package.
