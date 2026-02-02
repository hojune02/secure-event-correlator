from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Dict, Any, Literal

from pydantic import BaseModel, Field, ConfigDict, field_validator


class SecurityEventV1(BaseModel):
    """
    Normalized SIEM-style event schema.
    """
    model_config = ConfigDict(extra="forbid")

    event_type: Literal["sec.event.v1"]
    event_id: str = Field(min_length=8, max_length=128)

    source: str = Field(min_length=1, max_length=64)     # e.g., auth/sysmon/zeek
    host: str = Field(min_length=1, max_length=128)

    timestamp_utc: datetime

    category: str = Field(min_length=1, max_length=64)   # auth/process/network
    action: str = Field(min_length=1, max_length=64)     # login_failed/proc_start/...
    severity: int = Field(ge=0, le=10)

    user: Optional[str] = Field(default=None, max_length=128)
    src_ip: Optional[str] = Field(default=None, max_length=64)
    dest_ip: Optional[str] = Field(default=None, max_length=64)
    process_name: Optional[str] = Field(default=None, max_length=256)

    attributes: Optional[Dict[str, Any]] = None

    @field_validator("timestamp_utc")
    @classmethod
    def ensure_timezone_aware_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("timestamp_utc must include timezone info (e.g., Z or +00:00)")
        return v.astimezone(timezone.utc)
