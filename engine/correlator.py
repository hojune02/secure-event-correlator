from __future__ import annotations

from datetime import datetime, timedelta

from engine.models import CorrelationDecision, EventRecord
from engine.store import RollingEventStore


class Correlator:
    """
    SIEM-style correlation engine.

    Rules implemented (MVP):
    - ingest_storm: too many events from a host in short window
    - brute_force: many login_failed events for same host/user in short window
    """

    def __init__(
        self,
        store_window_seconds: int = 900,     # keep 15 minutes
        storm_window_seconds: int = 30,
        storm_threshold: int = 50,           # 50 events/30s => suspicious
        brute_window_seconds: int = 60,
        brute_threshold: int = 8,            # 8 failed logins in 60s
    ):
        self.store = RollingEventStore(window_seconds=store_window_seconds)

        self.storm_window = timedelta(seconds=storm_window_seconds)
        self.storm_threshold = storm_threshold

        self.brute_window = timedelta(seconds=brute_window_seconds)
        self.brute_threshold = brute_threshold

    def evaluate(self, record: EventRecord) -> CorrelationDecision:
        self.store.add(record)
        recent = self.store.get_recent(record.host)
        now = record.received_time_utc

        reasons: list[str] = []
        context: dict = {}

        # Rule 1: host event storm (generic flood/noise)
        storm_cutoff = now - self.storm_window
        storm_count = sum(1 for e in recent if e.received_time_utc >= storm_cutoff)
        context["storm_count"] = storm_count
        context["storm_window_seconds"] = int(self.storm_window.total_seconds())
        if storm_count > self.storm_threshold:
            reasons.append("ingest_storm")

        # Rule 2: brute force (auth.login_failed burst per user)
        brute_cutoff = now - self.brute_window
        user = record.user or "unknown"
        fail_count = sum(
            1 for e in recent
            if e.received_time_utc >= brute_cutoff
            and e.category == "auth"
            and e.action == "login_failed"
            and (e.user or "unknown") == user
        )
        context["brute_user"] = user
        context["login_failed_count"] = fail_count
        context["brute_window_seconds"] = int(self.brute_window.total_seconds())
        if fail_count >= self.brute_threshold:
            reasons.append("brute_force_suspected")

        # Decision policy
        decision = "ALLOW"
        if "ingest_storm" in reasons and "brute_force_suspected" in reasons:
            decision = "BLOCK"
        elif reasons:
            decision = "THROTTLE"

        context["recent_events_kept"] = len(recent)

        return CorrelationDecision(
            event_id=record.event_id,
            host=record.host,
            decision=decision,
            reasons=reasons,
            context=context,
        )
