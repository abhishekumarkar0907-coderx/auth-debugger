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
```
