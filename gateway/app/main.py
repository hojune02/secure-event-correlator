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

from engine.alert import AlertDeduper, AlertSinkJSONL, build_alert
from pathlib import Path

from engine.persistence.sqlite_store import SQLiteStore

app = FastAPI(title="secure-event-correlator", version="0.3.0")

# Last day - persistence using sqlite
sqlite = None
if os.getenv("SEC_USE_SQLITE", "1") == "1":
    sqlite = SQLiteStore(db_path=os.getenv("SEC_SQLITE_PATH", "engine/out/state.db"))


# ---- singletons (MVP in-memory) ----
audit = AuditLogger(file_path="gateway/audit/audit.jsonl")
idempo = IdempotencyStore(ttl_seconds=7 * 24 * 3600, sqlite_store=sqlite)

correlator = Correlator()
policy_engine = HostPolicyEngine(
    cooldown_seconds=int(os.getenv("SEC_COOLDOWN_SECONDS", "120")),
    severity_floor=int(os.getenv("SEC_SEVERITY_FLOOR", "0")),
    sqlite_store=sqlite,
)

alert_sink = AlertSinkJSONL(out_file="engine/out/alerts.jsonl")
alert_deduper = AlertDeduper(ttl_seconds=int(os.getenv("SEC_ALERT_DEDUP_SECONDS", "300")))


# ---- configurable guards ----
REPLAY_WINDOW_SECONDS = int(os.getenv("SEC_REPLAY_WINDOW_SECONDS", "120"))
RATE_LIMIT_PER_MIN = int(os.getenv("SEC_RATE_LIMIT_PER_MIN", "300"))
rate_limiter = FixedWindowRateLimiter(limit=RATE_LIMIT_PER_MIN, window_seconds=60)


@app.get("/health")
def health():
    return {"status": "ok", "service": "secure-event-correlator"}

@app.get("/alerts/recent")
def alerts_recent(limit: int = 50):
    limit = max(1, min(limit, 200))
    path = Path("engine/out/alerts.jsonl")
    if not path.exists():
        return {"alerts": []}

    # tail last N lines (simple local approach)
    lines: list[str] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                lines.append(line)

    tail = lines[-limit:]
    alerts = []
    for line in tail:
        try:
            alerts.append(json.loads(line))
        except Exception:
            continue
    return {"alerts": alerts}


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

    # optional: opportunistic GC
    if sqlite is not None:
        sqlite.idempo_gc(ttl_seconds=7 * 24 * 3600)


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

    # ---- Alert emission (deduped) ----
    # Map correlation reasons to alert rules
    reason_to_rule = {
        "brute_force_suspected": ("BRUTE_FORCE_V1", 7, 0.75),
        "password_spray_suspected": ("PASSWORD_SPRAY_V1", 8, 0.80),
        "success_after_failures": ("SUCCESS_AFTER_FAILURES_V1", 8, 0.70),
        "ingest_storm": ("INGEST_STORM_V1", 5, 0.60),
    }

    for r in corr.reasons:
        if r not in reason_to_rule:
            continue
        rule_id, sev, conf = reason_to_rule[r]
        if alert_deduper.should_emit(rule_id, record.host, record.user, record.src_ip):
            alert = build_alert(
                rule_id=rule_id,
                host=record.host,
                severity=sev,
                confidence=conf,
                user=record.user,
                src_ip=record.src_ip,
                reasons=[r],
                context=corr.context,
            )
            alert_sink.emit(alert)
            audit.write({
                "type": "alert_emitted",
                "alert_id": alert.alert_id,
                "rule_id": alert.rule_id,
                "host": alert.host,
                "severity": alert.severity,
                "confidence": alert.confidence,
                "reasons": alert.reasons,
            })


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

@app.get("/hosts/{host}/state")
def host_state(host: str):
    return policy_engine.get_state(host)

