from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

from gateway.app.audit import AuditLogger
from gateway.app.idempotency import IdempotencyStore
from gateway.app.models import SecurityEventV1
from gateway.app.rate_limit import FixedWindowRateLimiter
from gateway.app.security import (
    SIG_HEADER,
    check_replay_window,
    get_shared_secret,
    sha256_hex,
    verify_signature,
)

from engine.correlator import Correlator
from engine.models import EventRecord
from engine.policy import HostPolicyEngine

app = FastAPI(title="secure-event-correlator", version="0.3.0")

# ---- singletons (MVP in-memory) ----
audit = AuditLogger(file_path="gateway/audit/audit.jsonl")
idempo = IdempotencyStore(ttl_seconds=7 * 24 * 3600)

correlator = Correlator()
policy_engine = HostPolicyEngine(
    cooldown_seconds=int(os.getenv("SEC_COOLDOWN_SECONDS", "120")),
    severity_floor=int(os.getenv("SEC_SEVERITY_FLOOR", "0")),
)

# ---- configurable guards ----
REPLAY_WINDOW_SECONDS = int(os.getenv("SEC_REPLAY_WINDOW_SECONDS", "120"))
RATE_LIMIT_PER_MIN = int(os.getenv("SEC_RATE_LIMIT_PER_MIN", "300"))
rate_limiter = FixedWindowRateLimiter(limit=RATE_LIMIT_PER_MIN, window_seconds=60)


@app.get("/health")
def health():
    return {"status": "ok", "service": "secure-event-correlator"}


@app.post("/ingest")
async def ingest(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    raw = await request.body()
    body_hash = sha256_hex(raw)

    # 1) HMAC auth on raw bytes (SIEM local-friendly)
    sig_header = request.headers.get(SIG_HEADER)
    if not sig_header:
        audit.write({
            "type": "gateway_reject",
            "path": "/ingest",
            "client_ip": client_ip,
            "verification_status": "fail",
            "verification_reason": "missing_signature",
            "body_sha256": body_hash,
        })
        raise HTTPException(status_code=401, detail="missing_signature")

    try:
        secret = get_shared_secret()
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))

    ok, reason = verify_signature(secret, raw, sig_header)
    if not ok:
        audit.write({
            "type": "gateway_reject",
            "path": "/ingest",
            "client_ip": client_ip,
            "verification_status": "fail",
            "verification_reason": reason,
            "body_sha256": body_hash,
        })
        raise HTTPException(status_code=401, detail=reason)

    # 2) Parse + schema validate
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        audit.write({
            "type": "gateway_reject",
            "path": "/ingest",
            "client_ip": client_ip,
            "verification_status": "fail",
            "verification_reason": "invalid_json",
            "body_sha256": body_hash,
        })
        raise HTTPException(status_code=400, detail="invalid_json")

    try:
        event = SecurityEventV1.model_validate(payload)
    except Exception as e:
        audit.write({
            "type": "gateway_reject",
            "path": "/ingest",
            "client_ip": client_ip,
            "verification_status": "fail",
            "verification_reason": "schema_validation_failed",
            "body_sha256": body_hash,
            "error": str(e),
        })
        raise HTTPException(status_code=400, detail="schema_validation_failed")

    # 3) Anti-replay (timestamp_utc)
    ok, reason = check_replay_window(event.timestamp_utc, REPLAY_WINDOW_SECONDS)
    if not ok:
        audit.write({
            "type": "gateway_reject",
            "path": "/ingest",
            "client_ip": client_ip,
            "verification_status": "fail",
            "verification_reason": reason,
            "body_sha256": body_hash,
            "event_id": event.event_id,
            "host": event.host,
            "source": event.source,
        })
        raise HTTPException(status_code=400, detail=reason)

    # 4) Idempotency
    if idempo.seen(event.event_id):
        audit.write({
            "type": "gateway_reject",
            "path": "/ingest",
            "client_ip": client_ip,
            "verification_status": "fail",
            "verification_reason": "duplicate_event_id",
            "body_sha256": body_hash,
            "event_id": event.event_id,
            "host": event.host,
            "source": event.source,
        })
        raise HTTPException(status_code=409, detail="duplicate_event_id")

    # 5) Rate limit (per host)
    ok, reason = rate_limiter.allow(event.host)
    if not ok:
        audit.write({
            "type": "gateway_reject",
            "path": "/ingest",
            "client_ip": client_ip,
            "verification_status": "fail",
            "verification_reason": reason,
            "body_sha256": body_hash,
            "event_id": event.event_id,
            "host": event.host,
            "source": event.source,
        })
        raise HTTPException(status_code=429, detail=reason)

    # Mark idempotency AFTER checks pass
    idempo.mark(event.event_id)

    # 6) Normalize into internal record
    record = EventRecord(
        event_id=event.event_id,
        source=event.source,
        host=event.host,
        category=event.category,
        action=event.action,
        severity=event.severity,
        timestamp_utc=event.timestamp_utc,
        received_time_utc=datetime.now(timezone.utc),
        user=event.user,
        src_ip=event.src_ip,
    )

    # 7) Correlation + Policy
    corr = correlator.evaluate(record)
    policy = policy_engine.evaluate(record, corr)
    final_decision = policy.decision

    # 8) Audit accept + decisions
    audit.write({
        "type": "gateway_accept",
        "path": "/ingest",
        "client_ip": client_ip,
        "verification_status": "pass",
        "verification_reason": "ok",
        "body_sha256": body_hash,
        "event_id": event.event_id,
        "host": event.host,
        "source": event.source,
        "category": event.category,
        "action": event.action,
        "severity": event.severity,
    })

    audit.write({
        "type": "correlation_decision",
        "event_id": corr.event_id,
        "host": corr.host,
        "decision": corr.decision,
        "reasons": corr.reasons,
        "context": corr.context,
    })

    audit.write({
        "type": "policy_decision",
        "event_id": policy.event_id,
        "host": policy.host,
        "decision": policy.decision,
        "reasons": policy.reasons,
        "context": policy.context,
    })

    return JSONResponse({
        "accepted": True,
        "event_id": event.event_id,
        "gateway_reason": "ok",
        "correlation": {
            "decision": corr.decision,
            "reasons": corr.reasons,
            "context": corr.context,
        },
        "policy": {
            "decision": policy.decision,
            "reasons": policy.reasons,
            "context": policy.context,
        },
        "final_decision": final_decision,
    })
