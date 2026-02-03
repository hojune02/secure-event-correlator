from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class Alert:
    """
    SIEM-style alert record.
    """
    alert_id: str
    rule_id: str
    host: str
    severity: int
    confidence: float
    created_time_utc: str

    # optional enrichments
    user: Optional[str] = None
    src_ip: Optional[str] = None

    # aggregation / evidence
    first_seen_utc: Optional[str] = None
    last_seen_utc: Optional[str] = None
    count: Optional[int] = None
    reasons: list[str] = field(default_factory=list)
    context: dict = field(default_factory=dict)


class AlertDeduper:
    """
    Prevents spamming repeated alerts for the same signal.

    Keys can be (rule_id, host, user, src_ip).
    """
    def __init__(self, ttl_seconds: int = 300):
        self.ttl = timedelta(seconds=ttl_seconds)
        self._last_emit: dict[str, datetime] = {}

    def _key(self, rule_id: str, host: str, user: Optional[str], src_ip: Optional[str]) -> str:
        return f"{rule_id}|{host}|{user or ''}|{src_ip or ''}"

    def should_emit(self, rule_id: str, host: str, user: Optional[str], src_ip: Optional[str]) -> bool:
        now = datetime.now(timezone.utc)
        k = self._key(rule_id, host, user, src_ip)
        last = self._last_emit.get(k)
        if last is None:
            self._last_emit[k] = now
            return True
        if now - last >= self.ttl:
            self._last_emit[k] = now
            return True
        return False


class AlertSinkJSONL:
    """
    Append-only alert sink. Durable, local-first.
    """
    def __init__(self, out_file: str = "engine/out/alerts.jsonl"):
        self.path = Path(out_file)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, alert: Alert) -> None:
        record = asdict(alert)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")


def build_alert(
    *,
    rule_id: str,
    host: str,
    severity: int,
    confidence: float,
    user: Optional[str],
    src_ip: Optional[str],
    reasons: list[str],
    context: dict,
    first_seen_utc: Optional[str] = None,
    last_seen_utc: Optional[str] = None,
    count: Optional[int] = None,
) -> Alert:
    return Alert(
        alert_id=str(uuid.uuid4()),
        rule_id=rule_id,
        host=host,
        severity=severity,
        confidence=confidence,
        created_time_utc=datetime.now(timezone.utc).isoformat(),
        user=user,
        src_ip=src_ip,
        first_seen_utc=first_seen_utc,
        last_seen_utc=last_seen_utc,
        count=count,
        reasons=reasons,
        context=context,
    )
