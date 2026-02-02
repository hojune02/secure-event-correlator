from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Optional


DecisionType = Literal["ALLOW", "THROTTLE", "BLOCK"]


@dataclass(frozen=True)
class EventRecord:
    """
    Minimal internal representation for correlation & policy.
    """
    event_id: str
    source: str
    host: str
    category: str
    action: str
    severity: int
    timestamp_utc: datetime
    received_time_utc: datetime

    user: Optional[str] = None
    src_ip: Optional[str] = None


@dataclass(frozen=True)
class CorrelationDecision:
    event_id: str
    host: str
    decision: DecisionType
    reasons: list[str] = field(default_factory=list)
    context: dict = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyDecision:
    event_id: str
    host: str
    decision: DecisionType
    reasons: list[str] = field(default_factory=list)
    context: dict = field(default_factory=dict)
