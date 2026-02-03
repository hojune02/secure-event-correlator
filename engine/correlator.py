from __future__ import annotations

from datetime import timedelta

from engine.models import CorrelationDecision, EventRecord
from engine.store import RollingEventStore


class Correlator:
    """
    SIEM-style correlation engine.

    Rules (MVP):
    - ingest_storm: too many events from a host in short window
    - brute_force: many login_failed events for same host/user in short window
    - password_spray: many distinct users failing from same src_ip to same host
    - success_after_failures: login_success after repeated failures for same user
    """

    def __init__(
        self,
        store_window_seconds: int = 900,     # keep 15 minutes
        storm_window_seconds: int = 30,
        storm_threshold: int = 50,           # 50 events/30s => suspicious

        brute_window_seconds: int = 60,
        brute_threshold: int = 8,            # 8 failed logins in 60s (same user)

        spray_window_seconds: int = 120,
        spray_unique_users_threshold: int = 5,
        spray_fail_threshold: int = 8,

        success_window_seconds: int = 600,
        success_prior_fail_threshold: int = 6,
    ):
        self.store = RollingEventStore(window_seconds=store_window_seconds)

        self.storm_window = timedelta(seconds=storm_window_seconds)
        self.storm_threshold = storm_threshold

        self.brute_window = timedelta(seconds=brute_window_seconds)
        self.brute_threshold = brute_threshold

        self.spray_window = timedelta(seconds=spray_window_seconds)
        self.spray_unique_users_threshold = spray_unique_users_threshold
        self.spray_fail_threshold = spray_fail_threshold

        self.success_window = timedelta(seconds=success_window_seconds)
        self.success_prior_fail_threshold = success_prior_fail_threshold

    def evaluate(self, record: EventRecord) -> CorrelationDecision:
        self.store.add(record)
        recent = self.store.get_recent(record.host)
        now = record.received_time_utc

        reasons: list[str] = []
        context: dict = {}

        # ---- Rule 1: Host event storm ----
        storm_cutoff = now - self.storm_window
        storm_count = sum(1 for e in recent if e.received_time_utc >= storm_cutoff)
        context["storm_count"] = storm_count
        context["storm_window_seconds"] = int(self.storm_window.total_seconds())
        if storm_count > self.storm_threshold:
            reasons.append("ingest_storm")

        # ---- Rule 2: Brute force (auth.login_failed burst per user) ----
        brute_cutoff = now - self.brute_window
        user = record.user or "unknown"
        fail_events = [
            e for e in recent
            if e.received_time_utc >= brute_cutoff
            and e.category == "auth"
            and e.action == "login_failed"
            and (e.user or "unknown") == user
        ]
        fail_count = len(fail_events)
        context["brute_user"] = user
        context["login_failed_count"] = fail_count
        context["brute_window_seconds"] = int(self.brute_window.total_seconds())
        if fail_count >= self.brute_threshold:
            reasons.append("brute_force_suspected")

        # ---- Rule 3: Password spray (same src_ip, many users failing) ----
        spray_cutoff = now - self.spray_window
        src_ip = record.src_ip
        if src_ip:
            spray_fail_events = [
                e for e in recent
                if e.received_time_utc >= spray_cutoff
                and e.category == "auth"
                and e.action == "login_failed"
                and e.src_ip == src_ip
            ]
            spray_fail_count = len(spray_fail_events)
            spray_users = { (e.user or "unknown") for e in spray_fail_events }
            unique_users = len(spray_users)

            context["spray_src_ip"] = src_ip
            context["spray_fail_count"] = spray_fail_count
            context["spray_unique_users"] = unique_users
            context["spray_window_seconds"] = int(self.spray_window.total_seconds())

            if spray_fail_count >= self.spray_fail_threshold and unique_users >= self.spray_unique_users_threshold:
                reasons.append("password_spray_suspected")

        # ---- Rule 4: Success after failures (potential compromise) ----
        if record.category == "auth" and record.action == "login_success":
            success_cutoff = now - self.success_window
            prior_fail_events = [
                e for e in recent
                if e.received_time_utc >= success_cutoff
                and e.category == "auth"
                and e.action == "login_failed"
                and (e.user or "unknown") == user
            ]
            prior_fails = len(prior_fail_events)
            context["success_user"] = user
            context["success_prior_fail_count"] = prior_fails
            context["success_window_seconds"] = int(self.success_window.total_seconds())
            if prior_fails >= self.success_prior_fail_threshold:
                reasons.append("success_after_failures")

        # decision policy (simple + explainable)
        decision = "ALLOW"
        if "ingest_storm" in reasons and ("brute_force_suspected" in reasons or "password_spray_suspected" in reasons):
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
