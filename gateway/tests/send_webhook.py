from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timezone, timedelta

import httpx


SIG_HEADER = "X-ARES-SIGNATURE"
SIG_PREFIX = "sha256="


def sign(secret: str, body: bytes) -> str:
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"{SIG_PREFIX}{mac}"


def make_event(
    *,
    event_id: str | None = None,
    timestamp: datetime | None = None,
    host: str = "host-1",
    source: str = "auth",
    category: str = "auth",
    action: str = "login_failed",
    severity: int = 5,
    user: str | None = "alice",
    src_ip: str | None = "10.0.0.5",
) -> dict:
    now = datetime.now(timezone.utc)
    ts = (timestamp or now).isoformat()

    payload = {
        "event_type": "sec.event.v1",
        "event_id": event_id or str(uuid.uuid4()),
        "source": source,
        "host": host,
        "timestamp_utc": ts,
        "category": category,
        "action": action,
        "severity": severity,
        "attributes": {"test": True},
    }
    if user is not None:
        payload["user"] = user
    if src_ip is not None:
        payload["src_ip"] = src_ip
    return payload


def post_event(
    client: httpx.Client,
    secret: str,
    event: dict,
    *,
    tamper_sig: bool = False,
    use_hmac: bool = True,
):
    body = json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json"}

    if use_hmac:
        sig = sign(secret, body)
        if tamper_sig:
            sig = sig.replace("a", "b", 1)
        headers[SIG_HEADER] = sig

    r = client.post(
        "http://127.0.0.1:8000/ingest",
        content=body,
        headers=headers,
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
        event3 = make_event(timestamp=old_time)
        print(post_event(client, secret, event3))

        print("\n4) Duplicate event_id")
        event4 = make_event(event_id=eid)
        print(post_event(client, secret, event4))

        print("\n5) Rate limit burst (per host)")
        # With SEC_RATE_LIMIT_PER_MIN default 300, this may not trigger unless you spam.
        # Lower SEC_RATE_LIMIT_PER_MIN (e.g., 30) to see quickly.
        for i in range(0, 400):
            e = make_event(host="host-ratelimit")
            code, _ = post_event(client, secret, e)
            if code == 429:
                print(f"Rate limited at request #{i+1}")
                break
        else:
            print("Did not hit rate limit (increase burst or lower SEC_RATE_LIMIT_PER_MIN).")

        print("\n6) Brute force detection (8 failed logins within 60s for same user/host)")
        host = "host-bruteforce"
        user = "alice"
        last = None
        for i in range(8):
            e = make_event(host=host, user=user, action="login_failed", severity=6)
            code, body = post_event(client, secret, e)
            last = (code, body)
            if isinstance(body, dict):
                print(
                    i + 1,
                    code,
                    body.get("correlation", {}).get("decision"),
                    body.get("correlation", {}).get("reasons"),
                    body.get("policy", {}).get("decision"),
                    body.get("policy", {}).get("reasons"),
                )
            else:
                print(i + 1, code, body)

        # Optional: demonstrate that policy cooldown suppresses follow-up
        print("\n7) Post-detection suppression (send another event immediately)")
        e_after = make_event(host=host, user=user, action="login_failed", severity=6)
        print(post_event(client, secret, e_after))

        print("\n8) Ingest storm detection (many events quickly)")
        host = "host-storm"
        for i in range(60):
            e = make_event(host=host, source="sysmon", category="process", action="proc_start", severity=3, user=None, src_ip=None)
            code, body = post_event(client, secret, e)
            if i in (0, 10, 20, 40, 59):
                if isinstance(body, dict):
                    print(
                        i + 1,
                        code,
                        body.get("correlation", {}).get("decision"),
                        body.get("correlation", {}).get("reasons"),
                    )
                else:
                    print(i + 1, code, body)


if __name__ == "__main__":
    main()
