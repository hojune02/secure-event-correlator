from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict

from engine.models import EventRecord


class RollingEventStore:
    """
    In-memory rolling event store keyed by host.
    """
    def __init__(self, window_seconds: int):
        self.window = timedelta(seconds=window_seconds)
        self._events: Dict[str, Deque[EventRecord]] = {}

    def add(self, record: EventRecord) -> None:
        q = self._events.get(record.host)
        if q is None:
            q = deque()
            self._events[record.host] = q

        q.append(record)
        self._cleanup_queue(q, now=record.received_time_utc)

    def get_recent(self, host: str) -> list[EventRecord]:
        q = self._events.get(host)
        if not q:
            return []
        self._cleanup_queue(q, now=datetime.now(timezone.utc))
        return list(q)

    def _cleanup_queue(self, q: Deque[EventRecord], now: datetime) -> None:
        cutoff = now - self.window
        while q and q[0].received_time_utc < cutoff:
            q.popleft()
