# MiniSIEM

## Quick Summary

**Built a MVP SIEM with persistent memory in Python that takes authenticated telemetry events, normalises events based on a strict schema, applies windowed and sequenced-based threat correlation, and produces stateful response policies (cooldowns and quarantine)**

## Table of Contents

[#1. Project Overview](#1-project-overview)

[#2. Architecture Overview](#2-architecture-overview)

[#3. Key Features](#3-key-features)

[#4. How to Run Locally](#4-how-to-run-locally)

[#5. Future Improvements](#5-future-improvements)

## 1. Project Overview

`MiniSIEM` is a MVP, yet realistic Security Information and Event Management (SIEM) system implemented in Python. 

The system runs a hardened data ingestion boundary using HMAC authentication, replay-attack prevention, strict schema validation, idempotency checks, and rate limiting.

Once a telemetry event is accepted, it is normalised for internal review, where it is checked for any suspicious behaviour such as brute-force login attempts, password spraying, success-after failure patterns. The internal correlation engine deals with this.

A response policy is generated based on the result of correlation, which includes cooldown and host quarantine. Both alerts and decision-making artifacts are stored for potential future reviews.

The system adopts SQLite for storing idempotency information and host policy state, simulating real-life persistence of a SIEM system.

## 2. Architecture Overview

```
Security Event Producers
        ↓
Secure Ingestion Gateway (FastAPI)
  ├── HMAC Authentication (raw bytes)
  ├── JSON Schema Validation (sec.event.v1)
  ├── Replay Window Enforcement
  ├── Idempotency (event_id)
  ├── Rate Limiting (per host)
  ├── Audit Logging (accept/reject)
        ↓
Normalization Layer
  ├── SecurityEventV1 (validated schema)
  └── EventRecord (internal minimal form)
        ↓
Correlation Engine
  ├── Rolling Event Store (per host)
  ├── Brute Force Detection
  ├── Success-After-Failures Detection
  ├── Ingest Storm Detection
  ├── Password Spray Logic
  └── Explainable Context Generation
        ↓
Response Policy Engine
  ├── Severity Gating
  ├── Cooldown Suppression
  ├── Quarantine Escalation
  ├── Stateful Decisions (host-based)
  └── SQLite-backed Persistence
        ↓
Detection & Forensics Outputs
  ├── Alerts (engine/out/alerts.jsonl)
  ├── Audit Log (gateway/audit/audit.jsonl)
  ├── Policy State (SQLite)
  └── Observability Endpoints
        ├── GET /alerts/recent
        └── GET /hosts/{host}/state
```

## 3. Key Features

- HMAC authentication, Pydantic schema validation, replay-attack prevention, idempotency checks and rate limiting for secure input ingestion
- Normalised SIEM event schema, whose attributes including `host`, `source`, `action`, `timestamp_utc`
- Correlation engine detecting brute-force login attempts, ingestion storm, password spray and success-after-failures under rolling-window event aggregation
- Stateful response policy engine enforcing cooldowns to prevent input flooding and host quarantine against potential malicious actors
- Alerts and audits saved for forensic traceability
- Idempotency store and host policy store backed by SQLite

## 4. How to Run Locally

Set up your environment:
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Also, set the environment variables according to your needs:
```bash
export ARES_SHARED_SECRET="dev-secret-change-me"
export SEC_USE_SQLITE="1"
export SEC_SQLITE_PATH="engine/out/state.db"
export SEC_REPLAY_WINDOW_SECONDS="120"
export SEC_RATE_LIMIT_PER_MIN="300"
export SEC_COOLDOWN_SECONDS="10"
```

Start the SIEM gateway:
```bash
uvicorn gateway.app.main:app --reload --port 8000
```

On another terminal, set the shared secret to the same value from the above and use `send_webhook.py` for checking the SIEM's functionalities:
```bash
export ARES_SHARED_SECRET="dev-secret-change-me"
curl http:// 127.0.0.1:8000/health
python gateway/tests/send_webhook.py
```

You can inspect the outputs such as alerts and audit logs:
```bash
tail -n 20 engine/out/alerts.jsonl
tail -n 20 gateway/audit/audit.jsonl
```
FastAPI also provides endpoints for observing them:
```bash
curl http://127.0.0.1:8000/alerts/recent?limit=10
curl http://127.0.0.1:8000/hosts/host-bruteforce/state # change host-bruteforce to the host you want to inspect
```

## 5. Future Improvements
- Role-based access control for administrative actions
- More correlation & detection rules (lateral movement, privilege escalation)
- Incident grouping for future reference
- Message-queue-based ingestion for high-volume telemetry

