from __future__ import annotations

from datetime import datetime, timedelta, timezone

from engine.models import CorrelationDecision, EventRecord
from engine.store import RollingEventStore


class Correlator:
    """
    Stateful correlation engine (SIEM-style).
    Given an incoming event, it evaluates recent history and outputs:
    ALLOW / THROTTLE / BLOCK with reasons + context.
    """

    def __init__(
        self,
        store_window_seconds: int = 600,          # keep last 10 minutes
        storm_window_seconds: int = 60,           # count storms in last 60s
        storm_threshold: int = 5,                 # >5 in 60s => THROTTLE/BLOCK
        contradiction_window_seconds: int = 120,  # long->short quickly
        low_conf_window_seconds: int = 180,       # 3 minutes
        low_conf_threshold: int = 4,              # 4 low-conf signals => THROTTLE
        low_conf_strength: float = 0.4,
    ):
        self.store = RollingEventStore(window_seconds=store_window_seconds)

        self.storm_window = timedelta(seconds=storm_window_seconds)
        self.storm_threshold = storm_threshold

        self.contradiction_window = timedelta(seconds=contradiction_window_seconds)

        self.low_conf_window = timedelta(seconds=low_conf_window_seconds)
        self.low_conf_threshold = low_conf_threshold
        self.low_conf_strength = low_conf_strength

    def evaluate(self, record: EventRecord) -> CorrelationDecision:
        """
        Add record to memory, evaluate rules including this record,
        and output a decision.
        """
        self.store.add(record)
        recent = self.store.get_recent(record.strategy_id, record.symbol)

        now = record.received_time_utc
        reasons: list[str] = []
        context: dict = {}

        # Rule 1: signal storm
        storm_cutoff = now - self.storm_window
        storm_events = [e for e in recent if e.received_time_utc >= storm_cutoff]
        storm_count = len(storm_events)
        context["storm_count"] = storm_count
        context["storm_window_seconds"] = int(self.storm_window.total_seconds())

        if storm_count > self.storm_threshold:
            reasons.append("signal_storm")

        # Rule 2: contradictory signals in short window
        contra_cutoff = now - self.contradiction_window
        recent_short_window = [e for e in recent if e.received_time_utc >= contra_cutoff]

        # Find last opposite-side event before current (within window)
        opposite = "short" if record.side == "long" else "long"
        has_opposite = any((e.event_id != record.event_id and e.side == opposite) for e in recent_short_window)
        context["contradiction_window_seconds"] = int(self.contradiction_window.total_seconds())
        context["has_opposite_recent"] = has_opposite

        if has_opposite:
            reasons.append("contradictory_signal")

        # Rule 3: low-confidence clustering
        low_conf_cutoff = now - self.low_conf_window
        low_conf_events = [
            e for e in recent
            if e.received_time_utc >= low_conf_cutoff and e.signal_strength < self.low_conf_strength
        ]
        low_conf_count = len(low_conf_events)
        context["low_conf_count"] = low_conf_count
        context["low_conf_window_seconds"] = int(self.low_conf_window.total_seconds())
        context["low_conf_strength_lt"] = self.low_conf_strength

        if low_conf_count >= self.low_conf_threshold:
            reasons.append("low_conf_cluster")

        # Decision policy (simple MVP)
        # - BLOCK if contradiction + storm (high instability)
        # - THROTTLE if any single suspicious reason
        # - ALLOW otherwise
        decision = "ALLOW"
        if "signal_storm" in reasons and "contradictory_signal" in reasons:
            decision = "BLOCK"
        elif reasons:
            decision = "THROTTLE"

        # Add helpful context for explainability
        context["recent_events_kept"] = len(recent)

        return CorrelationDecision(
            event_id=record.event_id,
            strategy_id=record.strategy_id,
            symbol=record.symbol,
            decision=decision,
            reasons=reasons,
            context=context,
        )
