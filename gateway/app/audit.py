from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


class AuditLogger:
    """
    Append-only JSONL logger.
    MVP assumes single-process local dev; later we can add rotation/locking.
    """
    def __init__(self, file_path: str):
        self.path = Path(file_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, record: dict[str, Any]) -> None:
        record.setdefault("received_time_utc", datetime.now(timezone.utc).isoformat())

        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
