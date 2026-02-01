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

from engine.portfolio import PaperPortfolio
from engine.policy import RiskPolicyEngine

app = FastAPI(title="ARES Gateway", version="0.2.0")

# MVP singletons (in-memory)
audit = AuditLogger(file_path="gateway/audit/audit.jsonl")
idempo = IdempotencyStore(ttl_seconds=7 * 24 * 3600)
correlator = Correlator()

# Risk & Decision entities
portfolio = PaperPortfolio()
risk_engine = RiskPolicyEngine(
    portfolio=portfolio,
    max_daily_loss=float(os.getenv("ARES_MAX_DAILY_LOSS", "-200")),
    cooldown_after_loss_seconds=int(os.getenv("ARES_COOLDOWN_SECONDS", "300")),
    default_qty=float(os.getenv("ARES_PAPER_QTY", "1.0")),
)


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

    corr_decision = correlator.evaluate(record)

    # Day 4
    entry_price = payload.get("entry_hint")  # safe: payload already validated; entry_hint may be absent
    policy_decision = risk_engine.evaluate(record, corr_decision, entry_price=entry_price)

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
        "event_id": corr_decision.event_id,
        "strategy_id": corr_decision.strategy_id,
        "symbol": corr_decision.symbol,
        "decision": corr_decision.decision,
        "reasons": corr_decision.reasons,
        "context": corr_decision.context,
        "client_ip": client_ip,
        "body_sha256": body_hash,
    })

    # Risk assessment layer
    audit.write({
        "type": "policy_decision",
        "event_id": policy_decision.event_id,
        "strategy_id": policy_decision.strategy_id,
        "symbol": policy_decision.symbol,
        "decision": policy_decision.decision,
        "reasons": policy_decision.reasons,
        "context": policy_decision.context,
    })


    return JSONResponse({
        "accepted": True,
        "event_id": event.event_id,
        "gateway_reason": "ok",
        "correlation": {
            "decision": corr_decision.decision,
            "reasons": corr_decision.reasons,
            "context": corr_decision.context,
        },
        "policy": {
            "decision": policy_decision.decision,
            "reasons": policy_decision.reasons,
            "context": policy_decision.context,
        },
        "final_decision": policy_decision.decision
    })