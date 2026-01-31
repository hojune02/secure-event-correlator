# ARES MVP Spec (Week 1)

## Goal
Securely ingest TradingView alerts, correlate them over time (SIEM-style),
apply risk/policy controls (SOAR-style), and output a decision:
ALLOW / THROTTLE / BLOCK, with a full audit trail.

## Security requirements (MVP)
1) Authentication: HMAC-SHA256 signature over raw request body
   - Header: X-ARES-SIGNATURE: sha256=<hex>
   - Shared secret in env var: ARES_SHARED_SECRET

2) Anti-replay
   - sent_time_utc must be within ±120 seconds of server time (configurable)

3) Idempotency
   - event_id unique for 7 days (MVP: in-memory; later: SQLite/Redis)

4) Rate limiting
   - per strategy_id: 60 events/min hard cap (MVP; configurable)

5) Audit logging
   - append-only JSONL record for every request (accepted/rejected)
   - include rejection reason codes
