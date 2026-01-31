from __future__ import annotations

from datetime import datetime, timedelta, timezone


class IdempotencyStore:
    """
    MVP in-memory idempotency store.
    Stores event_id -> expiry UTC time.
    """
    def __init__(self, ttl_seconds: int = 7 * 24 * 3600):
        self.ttl = timedelta(seconds=ttl_seconds)
        self._store: dict[str, datetime] = {}

    def seen(self, event_id: str) -> bool:
        self._cleanup()
        return event_id in self._store

    def mark(self, event_id: str) -> None:
        self._cleanup()
        self._store[event_id] = datetime.now(timezone.utc) + self.ttl

    def _cleanup(self) -> None:
        now = datetime.now(timezone.utc)
        expired = [k for k, exp in self._store.items() if exp <= now]
        for k in expired:
            self._store.pop(k, None)
