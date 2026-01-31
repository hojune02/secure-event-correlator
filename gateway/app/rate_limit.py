from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass
class WindowCounter:
    window_start: datetime
    count: int


class FixedWindowRateLimiter:
    """
    MVP: per-key fixed window limiter (e.g., 60 events per 60 seconds per strategy_id).
    """
    def __init__(self, limit: int, window_seconds: int):
        self.limit = limit
        self.window = timedelta(seconds=window_seconds)
        self._counters: dict[str, WindowCounter] = {}

    def allow(self, key: str) -> tuple[bool, str]:
        now = datetime.now(timezone.utc)
        counter = self._counters.get(key)

        if counter is None or (now - counter.window_start) >= self.window:
            self._counters[key] = WindowCounter(window_start=now, count=1)
            return True, "ok"

        if counter.count >= self.limit:
            return False, "rate_limited"

        counter.count += 1
        return True, "ok"
