# ARES Event Schema (TradingView -> ARES)

## Event Type: tv.signal.v1
TradingView alerts emit events. ARES treats them as untrusted input.

### Required fields
- event_type: "tv.signal.v1"
- event_id: string (UUID recommended)
- strategy_id: string (e.g., "nas100_breakout_v1")
- strategy_version: string (e.g., "1.0.0")
- symbol: string (e.g., "OANDA:XAUUSD", "NASDAQ:NDX", broker-specific is OK)
- timeframe: string (e.g., "5", "15", "60")
- side: "long" | "short"
- signal_strength: number in [0, 1]
- bar_time_utc: ISO8601 string (bar close time that generated signal)
- sent_time_utc: ISO8601 string (alert emission time)

### Optional fields
- volatility_atr: number
- entry_hint: number
- stop_hint: number
- tp_hint: number
- tags: string[]

### Server-added fields (never supplied by TradingView)
- received_time_utc
- client_ip
- verification_status: "pass" | "fail"
- verification_reason: string

## Gateway validation rules (to implement Day 2)
Reject if:
- missing required fields
- invalid types (strict schema)
- sent_time_utc outside allowed window (anti-replay)
- event_id already seen (idempotency)
- strategy_id over rate limit
