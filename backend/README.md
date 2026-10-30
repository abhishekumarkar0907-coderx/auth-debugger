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

For this milestone the normalized spans are stored in a bounded in-memory
store. PostgreSQL will replace this store after the OTLP integration is
verified.

## Local setup

From this directory:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e ..\auth-engine
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
pytest
```

## OTLP endpoint

```text
POST /v1/traces
Content-Type: application/x-protobuf
```

## Current API

```text
GET  /health
POST /v1/traces
GET  /api/v1/spans
GET  /api/v1/traces
GET  /api/v1/traces/{trace_id}
GET  /api/v1/traces/{trace_id}/graph
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
