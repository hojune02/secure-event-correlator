from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional


from engine.persistence.sqlite_store import SQLiteStore



class IdempotencyStore:
    def __init__(self, ttl_seconds: int, sqlite_store: Optional["SQLiteStore"] = None):
        self.ttl = timedelta(seconds=ttl_seconds)
        self._seen: dict[str, datetime] = {}
        self.sqlite = sqlite_store

    def seen(self, event_id: str) -> bool:
        if self.sqlite is not None:
            return self.sqlite.idempo_seen(event_id)

        self._gc()
        return event_id in self._seen

    def mark(self, event_id: str) -> None:
        if self.sqlite is not None:
            self.sqlite.idempo_mark(event_id)
            return

        self._seen[event_id] = datetime.now(timezone.utc)

    def _gc(self) -> None:
        now = datetime.now(timezone.utc)
        cutoff = now - self.ttl
        dead = [k for k, t in self._seen.items() if t < cutoff]
        for k in dead:
            self._seen.pop(k, None)
