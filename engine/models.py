from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal


DecisionType = Literal["ALLOW", "THROTTLE", "BLOCK"]


@dataclass(frozen=True)
class EventRecord:
    """
    Minimal internal representation for correlation.
    Keep only what's needed for rules and explainability.
    """
    event_id: str
    strategy_id: str
    symbol: str
    side: Literal["long", "short"]
    signal_strength: float
    sent_time_utc: datetime
    received_time_utc: datetime


@dataclass(frozen=True)
class CorrelationDecision:
    """
    Output of the correlator. This is what downstream policy (Day 4)
    and execution (Day 5) will consume.
    """
    event_id: str
    strategy_id: str
    symbol: str
    decision: DecisionType
    reasons: list[str] = field(default_factory=list)
    context: dict = field(default_factory=dict)
