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
$env:PYTHONPATH = "..\auth-engine"
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
GET  /api/v1/analysis/{trace_id}
POST /api/v1/analysis/{trace_id}
POST /api/v1/demo/unauthorized-delegation  # development opt-in required
```
