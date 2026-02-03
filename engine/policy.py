from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from engine.models import CorrelationDecision, EventRecord, PolicyDecision


@dataclass
class HostPolicyState:
    cooldown_until_utc: Optional[datetime] = None
    quarantine: bool = False


class HostPolicyEngine:
    """
    SIEM response policy gate.

    Controls:
    - cooldown: temporary suppression window after high-confidence suspicion
    - quarantine: hard block mode (manual reset later)
    - severity floor: optionally ignore low severity
    """

    def __init__(
        self,
        cooldown_seconds: int = 120,
        quarantine_on: tuple[str, ...] = ("brute_force_suspected",),
        severity_floor: int = 0,
    ):
        self.cooldown = timedelta(seconds=cooldown_seconds)
        self.quarantine_on = set(quarantine_on)
        self.severity_floor = severity_floor
        self._state: dict[str, HostPolicyState] = {}

    def evaluate(self, record: EventRecord, corr: CorrelationDecision) -> PolicyDecision:
        host = record.host
        st = self._state.get(host)
        if st is None:
            st = HostPolicyState()
            self._state[host] = st

        now = datetime.now(timezone.utc)

        context = {
            "correlation_decision": corr.decision,
            "correlation_reasons": corr.reasons,
            "severity": record.severity,
        }

        # Severity gating (optional)
        if record.severity < self.severity_floor:
            return PolicyDecision(record.event_id, host, "THROTTLE", reasons=["below_severity_floor"], context=context)

        # Hard quarantine overrides everything
        if st.quarantine:
            return PolicyDecision(record.event_id, host, "BLOCK", reasons=["host_quarantined"], context=context)

        # Cooldown active?
        if st.cooldown_until_utc and now < st.cooldown_until_utc:
            context["cooldown_until_utc"] = st.cooldown_until_utc.isoformat()
            return PolicyDecision(record.event_id, host, "BLOCK", reasons=["cooldown_active"], context=context)

        # If correlator BLOCK, treat as block
        if corr.decision == "BLOCK":
            # escalate to quarantine if rule matches
            if any(r in self.quarantine_on for r in corr.reasons):
                st.quarantine = True
                return PolicyDecision(record.event_id, host, "BLOCK", reasons=["quarantine_activated"], context=context)
            # otherwise just block with cooldown
            st.cooldown_until_utc = now + self.cooldown
            context["cooldown_set_until_utc"] = st.cooldown_until_utc.isoformat()
            return PolicyDecision(record.event_id, host, "BLOCK", reasons=["correlation_block"], context=context)

        # If correlator THROTTLE, set cooldown but allow monitoring
        if corr.decision == "THROTTLE":
            st.cooldown_until_utc = now + self.cooldown
            context["cooldown_set_until_utc"] = st.cooldown_until_utc.isoformat()
            return PolicyDecision(record.event_id, host, "THROTTLE", reasons=["suspicious_cooldown_set"], context=context)

        # Correlation ALLOW → policy ALLOW
        return PolicyDecision(record.event_id, host, "ALLOW", reasons=["ok"], context=context)

    def get_state(self, host: str) -> dict:
        st = self._state.get(host)
        if st is None:
            return {"host": host, "cooldown_until_utc": None, "quarantine": False}
        return {
            "host": host,
            "cooldown_until_utc": None if st.cooldown_until_utc is None else st.cooldown_until_utc.isoformat(),
            "quarantine": bool(st.quarantine),
        }

    def list_quarantined(self) -> list[str]:
        return [h for h, st in self._state.items() if st.quarantine]
