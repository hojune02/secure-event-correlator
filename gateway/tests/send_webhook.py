from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from datetime import datetime, timezone, timedelta

import httpx


SIG_HEADER = "X-ARES-SIGNATURE"
SIG_PREFIX = "sha256="


def sign(secret: str, body: bytes) -> str:
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"{SIG_PREFIX}{mac}"


def make_event(event_id: str | None = None, sent_time: datetime | None = None, strategy_id: str = "nas100_breakout_v1", side: str = "long", strength: float = 0.73, entry_hint: float = 2000.0) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "event_type": "tv.signal.v1",
        "event_id": event_id or str(uuid.uuid4()),
        "strategy_id": strategy_id,
        "strategy_version": "1.0.0",
        "symbol": "OANDA:XAUUSD",
        "timeframe": "15",
        "side": side,
        "signal_strength": strength,
        "bar_time_utc": now.isoformat(),
        "sent_time_utc": (sent_time or now).isoformat(),
        "volatility_atr": 12.3,
        "tags": ["mvp", "test"],
        "entry_hint": entry_hint,
    }


def post_event(client: httpx.Client, secret: str, event: dict, tamper_sig: bool = False):
    body = json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = sign(secret, body)
    if tamper_sig:
        sig = sig.replace("a", "b", 1)  # small corruption

    r = client.post(
        "http://127.0.0.1:8000/webhook/tradingview",
        content=body,
        headers={SIG_HEADER: sig, "Content-Type": "application/json"},
        timeout=5.0,
    )
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, r.text



def main():
    secret = os.getenv("ARES_SHARED_SECRET", "")
    if not secret:
        raise RuntimeError("Set ARES_SHARED_SECRET before running tests.")

    with httpx.Client() as client:
        print("1) Valid event")
        eid = str(uuid.uuid4())
        event = make_event(event_id=eid)
        print(post_event(client, secret, event))

        print("\n2) Invalid signature")
        event2 = make_event()
        print(post_event(client, secret, event2, tamper_sig=True))

        print("\n3) Stale timestamp (replay window)")
        old_time = datetime.now(timezone.utc) - timedelta(seconds=9999)
        event3 = make_event(sent_time=old_time)
        print(post_event(client, secret, event3))

        print("\n4) Duplicate event_id")
        event4 = make_event(event_id=eid)
        print(post_event(client, secret, event4))

        print("\n5) Rate limit burst (may need to lower env RATE_LIMIT to see quickly)")
        # Send a burst; if RATE_LIMIT_PER_MIN is 60, this might not trigger unless you spam.
        for i in range(0, 70):
            e = make_event(strategy_id="ratelimit_test_v1")
            code, _ = post_event(client, secret, e)
            if code == 429:
                print(f"Rate limited at request #{i+1}")
                break
        else:
            print("Did not hit rate limit (increase burst or lower RATE_LIMIT).")

        # Day 3: contradictory signals, signal storm, and low-confidence clustering
        
        print("\n6) Contradictory signals test (long then short quickly)")
        e1 = make_event(strategy_id="corr_test_v1", side="long")
        code1, body1 = post_event(client, secret, e1)
        print(code1, body1)

        e2 = make_event(strategy_id="corr_test_v1", side="short")
        code2, body2 = post_event(client, secret, e2)
        print(code2, body2)

        print("\n7) Signal storm test (send 7 quickly)")
        for i in range(7):
            e = make_event(strategy_id="storm_test_v1")
            code, body = post_event(client, secret, e)
            if isinstance(body, dict):
                print(i + 1, code, body.get("correlation", {}).get("decision"), body.get("correlation", {}).get("reasons"))
            else:
                print(i + 1, code, body)

        print("\n8) Low-confidence clustering test (send 8 quickly)")
        for i in range(7):
            e = make_event(strategy_id="LC-clustering_test_v1", strength=0.39) # Low-confidence signal
            code, body = post_event(client, secret, e)
            if isinstance(body, dict):
                print(i + 1, code, body.get("correlation", {}).get("decision"), body.get("correlation", {}).get("reasons"))
            else:
                print(i + 1, code, body)

        print("\n8) Day 4: Cooldown test (loss -> cooldown -> blocked)")

        strat = "policy_cooldown_test_v1"

        # Step 1: Open long at 2000
        e1 = make_event(strategy_id=strat, side="long", entry_hint=2000.0)
        c1, b1 = post_event(client, secret, e1)
        print("open long:", c1, b1.get("final_decision"), b1.get("policy", {}).get("reasons"))

        # Step 2: Flip signal to short at 1990 (close long at loss => cooldown)
        e2 = make_event(strategy_id=strat, side="short", entry_hint=1990.0)
        c2, b2 = post_event(client, secret, e2)
        print("close loss:", c2, b2.get("final_decision"), b2.get("policy", {}).get("reasons"),
              "pnl:", b2.get("policy", {}).get("context", {}).get("closed_pnl"))

        # Step 3: Immediately send another signal (should be BLOCK due to cooldown_active)
        e3 = make_event(strategy_id=strat, side="long", entry_hint=1995.0)
        c3, b3 = post_event(client, secret, e3)
        print("during cooldown:", c3, b3.get("final_decision"), b3.get("policy", {}).get("reasons"),
              "cooldown_until:", b3.get("policy", {}).get("context", {}).get("cooldown_until_utc"))

        print("\n9) Day 4: Kill switch test (exceed max daily loss)")

        strat = "policy_killswitch_test_v1"

        # We'll create repeated losing round-trips:
        # open long 2000, close short 1997 => -3 (if qty=1) per cycle.
        for i in range(3):
            e_open = make_event(strategy_id=strat, side="long", entry_hint=2000.0)
            co, bo = post_event(client, secret, e_open)
            print(f"cycle {i+1} open:", co, bo.get("final_decision"), bo.get("policy", {}).get("reasons"))

            e_close = make_event(strategy_id=strat, side="short", entry_hint=1997.0)
            cc, bc = post_event(client, secret, e_close)
            print(f"cycle {i+1} close:", cc, bc.get("final_decision"), bc.get("policy", {}).get("reasons"),
                  "realised_pnl:", bc.get("policy", {}).get("context", {}).get("realised_pnl"))

        # Check if cooldown is lifted after the applied timeout
        print("\nWaiting for cooldown to be finished\n")
        time.sleep(6)

        # After enough losses, additional events should be blocked by kill switch. Right now kill switch is not active since max_daily_loss is not exceeded.
        e_after = make_event(strategy_id=strat, side="long", entry_hint=2000.0)
        ca, ba = post_event(client, secret, e_after)
        print("after losses:", ca, ba.get("final_decision"), ba.get("policy", {}).get("reasons"))


if __name__ == "__main__":
    main()
