from __future__ import annotations

import json
import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

from gateway.app.audit import AuditLogger
from gateway.app.idempotency import IdempotencyStore
from gateway.app.models import TradingViewSignalEvent
from gateway.app.rate_limit import FixedWindowRateLimiter
from gateway.app.security import (
    SIG_HEADER,
    check_replay_window,
    get_shared_secret,
    sha256_hex,
    verify_signature,
)

from datetime import datetime, timezone
from engine.correlator import Correlator
from engine.models import EventRecord

app = FastAPI(title="ARES Gateway", version="0.2.0")

# MVP singletons (in-memory)
audit = AuditLogger(file_path="gateway/audit/audit.jsonl")
idempo = IdempotencyStore(ttl_seconds=7 * 24 * 3600)
correlator = Correlator()

# Configurable via env, with safe defaults
REPLAY_WINDOW_SECONDS = int(os.getenv("ARES_REPLAY_WINDOW_SECONDS", "120"))
RATE_LIMIT_PER_MIN = int(os.getenv("ARES_RATE_LIMIT_PER_MIN", "60"))
rate_limiter = FixedWindowRateLimiter(limit=RATE_LIMIT_PER_MIN, window_seconds=60)


@app.get("/health")
def health():
    return {"status": "ok", "service": "ares-gateway"}


@app.post("/webhook/tradingview")
async def tradingview_webhook(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    raw = await request.body()
    body_hash = sha256_hex(raw)

    # 1) Verify signature on raw bytes
    try:
        secret = get_shared_secret()
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))

    sig_header = request.headers.get(SIG_HEADER)
    ok, reason = verify_signature(secret, raw, sig_header)

    if not ok:
        audit.write({
            "path": "/webhook/tradingview",
            "client_ip": client_ip,
            "verification_status": "fail",
            "verification_reason": reason,
            "body_sha256": body_hash,
        })
        raise HTTPException(status_code=401, detail=reason)

    # 2) Parse JSON then validate schema
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        audit.write({
            "path": "/webhook/tradingview",
            "client_ip": client_ip,
            "verification_status": "fail",
            "verification_reason": "invalid_json",
            "body_sha256": body_hash,
        })
        raise HTTPException(status_code=400, detail="invalid_json")

    try:
        event = TradingViewSignalEvent.model_validate(payload)
    except Exception as e:
        audit.write({
            "path": "/webhook/tradingview",
            "client_ip": client_ip,
            "verification_status": "fail",
            "verification_reason": "schema_validation_failed",
            "body_sha256": body_hash,
            "error": str(e),
        })
        raise HTTPException(status_code=400, detail="schema_validation_failed")

    # 3) Anti-replay window (based on sent_time_utc)
    ok, reason = check_replay_window(event.sent_time_utc, REPLAY_WINDOW_SECONDS)
    if not ok:
        audit.write({
            "path": "/webhook/tradingview",
            "client_ip": client_ip,
            "verification_status": "fail",
            "verification_reason": reason,
            "body_sha256": body_hash,
            "event_id": event.event_id,
            "strategy_id": event.strategy_id,
            "symbol": event.symbol,
        })
        raise HTTPException(status_code=400, detail=reason)

    # 4) Idempotency
    if idempo.seen(event.event_id):
        audit.write({
            "path": "/webhook/tradingview",
            "client_ip": client_ip,
            "verification_status": "fail",
            "verification_reason": "duplicate_event_id",
            "body_sha256": body_hash,
            "event_id": event.event_id,
            "strategy_id": event.strategy_id,
            "symbol": event.symbol,
        })
        raise HTTPException(status_code=409, detail="duplicate_event_id")

    # 5) Rate limit (per strategy_id)
    ok, reason = rate_limiter.allow(event.strategy_id)
    if not ok:
        audit.write({
            "path": "/webhook/tradingview",
            "client_ip": client_ip,
            "verification_status": "fail",
            "verification_reason": reason,
            "body_sha256": body_hash,
            "event_id": event.event_id,
            "strategy_id": event.strategy_id,
            "symbol": event.symbol,
        })
        raise HTTPException(status_code=429, detail=reason)

    # Mark idempotency AFTER checks pass
    idempo.mark(event.event_id)

    # Correlation step (Day 3)
    record = EventRecord(
        event_id=event.event_id,
        strategy_id=event.strategy_id,
        symbol=event.symbol,
        side=event.side,
        signal_strength=event.signal_strength,
        sent_time_utc=event.sent_time_utc,
        received_time_utc=datetime.now(timezone.utc),
    )

    decision = correlator.evaluate(record)

    # Audit accept (gateway layer)
    audit.write({
        "type": "gateway_accept",
        "path": "/webhook/tradingview",
        "client_ip": client_ip,
        "verification_status": "pass",
        "verification_reason": "ok",
        "body_sha256": body_hash,
        "event_id": event.event_id,
        "strategy_id": event.strategy_id,
        "symbol": event.symbol,
        "side": event.side,
        "signal_strength": event.signal_strength,
    })

    # Audit decision (correlation layer)
    audit.write({
        "type": "correlation_decision",
        "event_id": decision.event_id,
        "strategy_id": decision.strategy_id,
        "symbol": decision.symbol,
        "decision": decision.decision,
        "reasons": decision.reasons,
        "context": decision.context,
        "client_ip": client_ip,
        "body_sha256": body_hash,
    })

    return JSONResponse({
        "accepted": True,
        "event_id": event.event_id,
        "gateway_reason": "ok",
        "correlation": {
            "decision": decision.decision,
            "reasons": decision.reasons,
            "context": decision.context,
        },
    })