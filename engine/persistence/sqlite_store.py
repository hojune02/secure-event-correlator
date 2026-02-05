from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Optional


@dataclass(frozen=True)
class HostState:
    host: str
    cooldown_until_utc: Optional[str]  # ISO8601
    quarantine: bool


class SQLiteStore:
    """
    Minimal persistence for:
    - idempotency (event_id)
    - host policy state (cooldown, quarantine)

    Designed for local SIEM realism.
    """

    def __init__(self, db_path: str = "engine/out/state.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS idempotency (
                    event_id TEXT PRIMARY KEY,
                    first_seen_utc TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS host_policy (
                    host TEXT PRIMARY KEY,
                    cooldown_until_utc TEXT NULL,
                    quarantine INTEGER NOT NULL DEFAULT 0,
                    updated_utc TEXT NOT NULL
                )
                """
            )

    # --------------------
    # Idempotency
    # --------------------
    def idempo_seen(self, event_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("SELECT 1 FROM idempotency WHERE event_id = ? LIMIT 1", (event_id,))
            return cur.fetchone() is not None

    def idempo_mark(self, event_id: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO idempotency(event_id, first_seen_utc) VALUES(?, ?)",
                (event_id, now),
            )

    def idempo_gc(self, ttl_seconds: int) -> int:
        """
        Delete idempotency rows older than TTL. Returns number deleted.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=ttl_seconds)
        cutoff_iso = cutoff.isoformat()
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM idempotency WHERE first_seen_utc < ?", (cutoff_iso,))
            return cur.rowcount

    # --------------------
    # Host policy state
    # --------------------
    def get_host_state(self, host: str) -> HostState:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT cooldown_until_utc, quarantine FROM host_policy WHERE host = ?",
                (host,),
            )
            row = cur.fetchone()
            if row is None:
                return HostState(host=host, cooldown_until_utc=None, quarantine=False)
            cooldown_until_utc, quarantine = row
            return HostState(host=host, cooldown_until_utc=cooldown_until_utc, quarantine=bool(quarantine))

    def set_host_state(self, host: str, cooldown_until_utc: Optional[str], quarantine: bool) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO host_policy(host, cooldown_until_utc, quarantine, updated_utc)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(host) DO UPDATE SET
                    cooldown_until_utc=excluded.cooldown_until_utc,
                    quarantine=excluded.quarantine,
                    updated_utc=excluded.updated_utc
                """,
                (host, cooldown_until_utc, 1 if quarantine else 0, now),
            )
