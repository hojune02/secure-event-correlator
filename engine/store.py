from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, Tuple

from engine.models import EventRecord


Key = Tuple[str, str]  # (strategy_id, symbol)


class RollingEventStore:
    """
    In-memory per-(strategy_id, symbol) rolling store.

    - bounded by time (window_seconds)
    - efficient append/pop with deque
    - cleanup happens on every add (simple + deterministic MVP)
    """
    def __init__(self, window_seconds: int):
        self.window = timedelta(seconds=window_seconds)
        self._events: Dict[Key, Deque[EventRecord]] = {}

    def add(self, record: EventRecord) -> None:
        key = (record.strategy_id, record.symbol)
        q = self._events.get(key)
        if q is None:
            q = deque()
            self._events[key] = q

        q.append(record)
        self._cleanup_queue(q, now=record.received_time_utc)

    def get_recent(self, strategy_id: str, symbol: str) -> list[EventRecord]:
        key = (strategy_id, symbol)
        q = self._events.get(key)
        if not q:
            return []
        # Cleanup against "now" so callers always see fresh view
        self._cleanup_queue(q, now=datetime.now(timezone.utc))
        return list(q)

    def _cleanup_queue(self, q: Deque[EventRecord], now: datetime) -> None:
        cutoff = now - self.window
        while q and q[0].received_time_utc < cutoff:
            q.popleft()
