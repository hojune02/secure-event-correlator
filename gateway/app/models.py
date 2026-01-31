from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional, List

from pydantic import BaseModel, Field, ConfigDict, field_validator


class TradingViewSignalEvent(BaseModel):
    """
    Strict schema for tv.signal.v1
    We treat this as untrusted input and validate aggressively.
    """
    model_config = ConfigDict(extra="forbid")  # reject unknown fields

    event_type: Literal["tv.signal.v1"]
    event_id: str = Field(min_length=8, max_length=128)
    strategy_id: str = Field(min_length=1, max_length=128)
    strategy_version: str = Field(min_length=1, max_length=64)

    symbol: str = Field(min_length=1, max_length=64)
    timeframe: str = Field(min_length=1, max_length=16)

    side: Literal["long", "short"]
    signal_strength: float = Field(ge=0.0, le=1.0)

    bar_time_utc: datetime
    sent_time_utc: datetime

    volatility_atr: Optional[float] = Field(default=None, ge=0.0)
    entry_hint: Optional[float] = None
    stop_hint: Optional[float] = None
    tp_hint: Optional[float] = None
    tags: Optional[List[str]] = None

    @field_validator("bar_time_utc", "sent_time_utc")
    @classmethod
    def ensure_timezone_aware_utc(cls, v: datetime) -> datetime:
        # Require timezone-aware timestamps; normalize to UTC.
        if v.tzinfo is None:
            raise ValueError("timestamp must include timezone info (e.g., Z or +00:00)")
        return v.astimezone(timezone.utc)
