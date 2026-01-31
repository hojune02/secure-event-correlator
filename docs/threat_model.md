# ARES Threat Model (MVP)

## Assets
- Capital safety (even paper mode must avoid runaway behavior)
- Strategy integrity (prevent spoofed events)
- Service availability (avoid alert floods)
- Audit trail integrity (enable forensic replay)

## Threats
1) Spoofed webhook (fake buy/sell events)
2) Replay attack (resubmit old valid events)
3) Event flood / signal storm (DoS or runaway automation)
4) Duplicate delivery (TradingView retries)
5) Malformed payloads (crash attempts / schema abuse)

## Controls (MVP)
- HMAC verification (spoof prevention)
- timestamp window + event_id uniqueness (replay + duplicates)
- per-strategy rate limits + storm detection later (flood control)
- strict schema validation (crash prevention)
- append-only audit logs (forensics)

## Out of scope (Week 1)
- mTLS, WAF, distributed rate limiting
- secrets manager / HSM
- RBAC UI / multi-tenant auth
