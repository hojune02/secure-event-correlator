from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime, timezone
from typing import Tuple


SIG_HEADER = "X-ARES-SIGNATURE"
SIG_PREFIX = "sha256="


def get_shared_secret() -> bytes:
    secret = os.getenv("ARES_SHARED_SECRET", "")
    if not secret:
        raise RuntimeError("ARES_SHARED_SECRET is not set")
    return secret.encode("utf-8")


def compute_signature(secret: bytes, body: bytes) -> str:
    mac = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return mac


def verify_signature(secret: bytes, body: bytes, header_value: str | None) -> Tuple[bool, str]:
    """
    Returns (ok, reason_code)
    """
    if not header_value:
        return False, "missing_signature"

    if not header_value.startswith(SIG_PREFIX):
        return False, "bad_signature_format"

    provided = header_value[len(SIG_PREFIX):].strip()
    expected = compute_signature(secret, body)

    if not hmac.compare_digest(provided, expected):
        return False, "signature_mismatch"

    return True, "ok"


def sha256_hex(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def check_replay_window(sent_time_utc: datetime, window_seconds: int) -> Tuple[bool, str]:
    """
    Reject events too far from server time to reduce replay risk.
    """
    now = datetime.now(timezone.utc)
    delta = abs((now - sent_time_utc).total_seconds())
    if delta > window_seconds:
        return False, "replay_window_exceeded"
    return True, "ok"
