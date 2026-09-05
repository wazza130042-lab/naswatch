"""
SQLite implementation of the DeviceRepository and AlertRepository interfaces.
Provides robust ACID storage, automated migrations, and in-memory test support.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from naswatch.logging_config import get_logger
from naswatch.storage.models import (
    Alert,
    AlertRuleType,
    AlertSeverity,
    Device,
    DeviceStatus,
    SliceAssignment,
)
from naswatch.storage.repository import AlertRepository, DeviceRepository

logger = get_logger("storage.sqlite")


class SQLiteRepository(DeviceRepository, AlertRepository):
    """Unified SQLite repository for devices and alerts."""

    def __init__(self, db_path: str = "data/inventory.db"):
        self.db_path = db_path
        self._memory_conn: sqlite3.Connection | None = None
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        else:
            self._memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._memory_conn.row_factory = sqlite3.Row
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._memory_conn is not None:
            return self._memory_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def _init_db(self) -> None:
        """Create tables and indexes if they do not exist."""
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS devices (
                    imsi TEXT PRIMARY KEY,
                    imei TEXT NOT NULL UNIQUE,
                    owner_name TEXT NOT NULL,
                    device_model TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    allowed_slices_json TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    notes TEXT DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_devices_imei ON devices(imei);
                CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);

                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    rule_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    imsi TEXT,
                    imei TEXT,
                    cell_id TEXT,
                    target_slice TEXT,
                    mitigation_status TEXT NOT NULL DEFAULT 'NEW',
                    raw_event_json TEXT NOT NULL DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
                CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_type);
                CREATE INDEX IF NOT EXISTS idx_alerts_imsi ON alerts(imsi);
            """)

    # -------------------------------------------------------------------------
    # DeviceRepository Implementation
    # -------------------------------------------------------------------------

    def _row_to_device(self, row: sqlite3.Row) -> Device:
        slices_raw = json.loads(row["allowed_slices_json"])
        allowed_slices: list[SliceAssignment] = []
        for s in slices_raw:
            if isinstance(s, dict):
                allowed_slices.append(
                    SliceAssignment(
                        sst=int(s["sst"]),
                        sd=s.get("sd"),
                        name=s.get("name", ""),
                        description=s.get("description", ""),
                    )
                )
            elif isinstance(s, str):
                # Format: "sst:sd" or "sst"
                parts = s.split(":")
                sst = int(parts[0])
                sd = parts[1] if len(parts) > 1 else None
                allowed_slices.append(SliceAssignment(sst=sst, sd=sd))

        return Device(
            imsi=row["imsi"],
            imei=row["imei"],
            owner_name=row["owner_name"],
            device_model=row["device_model"],
            status=DeviceStatus(row["status"]),
            allowed_slices=allowed_slices,
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            notes=row["notes"] or "",
        )

    def get_by_imsi(self, imsi: str) -> Device | None:
        if not imsi:
            return None
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM devices WHERE imsi = ?", (imsi,))
            row = cur.fetchone()
            if row:
                return self._row_to_device(row)
        return None

    def get_by_imei(self, imei: str) -> Device | None:
        if not imei:
            return None
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM devices WHERE imei = ?", (imei,))
            row = cur.fetchone()
            if row:
                return self._row_to_device(row)
        return None

    def list_all(self, limit: int = 100, offset: int = 0) -> list[Device]:
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM devices ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
            return [self._row_to_device(row) for row in cur.fetchall()]

    def add(self, device: Device) -> bool:
        slices_data = [
            {"sst": s.sst, "sd": s.sd, "name": s.name, "description": s.description}
            for s in device.allowed_slices
        ]
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO devices (
                    imsi, imei, owner_name, device_model, status,
                    allowed_slices_json, created_at, updated_at, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device.imsi,
                    device.imei,
                    device.owner_name,
                    device.device_model,
                    device.status.value,
                    json.dumps(slices_data),
                    device.created_at.isoformat(),
                    device.updated_at.isoformat(),
                    device.notes,
                ),
            )
        return True

    def delete(self, imsi: str) -> bool:
        with self._get_connection() as conn:
            cur = conn.execute("DELETE FROM devices WHERE imsi = ?", (imsi,))
            return cur.rowcount > 0

    def count(self) -> int:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT COUNT(*) FROM devices")
            return cur.fetchone()[0]

    # -------------------------------------------------------------------------
    # AlertRepository Implementation
    # -------------------------------------------------------------------------

    def _row_to_alert(self, row: sqlite3.Row) -> Alert:
        raw_event: dict[str, Any] = json.loads(row["raw_event_json"])
        return Alert(
            id=row["id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            rule_type=AlertRuleType(row["rule_type"]),
            severity=AlertSeverity(row["severity"]),
            title=row["title"],
            description=row["description"],
            imsi=row["imsi"],
            imei=row["imei"],
            cell_id=row["cell_id"],
            target_slice=row["target_slice"],
            mitigation_status=row["mitigation_status"],
            raw_event=raw_event,
        )

    def record_alert(self, alert: Alert) -> bool:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO alerts (
                    id, timestamp, rule_type, severity, title,
                    description, imsi, imei, cell_id, target_slice,
                    mitigation_status, raw_event_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.id,
                    alert.timestamp.isoformat(),
                    alert.rule_type.value,
                    alert.severity.value,
                    alert.title,
                    alert.description,
                    alert.imsi,
                    alert.imei,
                    alert.cell_id,
                    alert.target_slice,
                    alert.mitigation_status,
                    json.dumps(alert.raw_event or {}),
                ),
            )
        return True

    def get_alerts(
        self,
        limit: int = 100,
        severity: str | None = None,
        rule_type: str | None = None,
        offset: int = 0,
    ) -> list[Alert]:
        query = "SELECT * FROM alerts WHERE 1=1"
        params: list[Any] = []

        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())
        if rule_type:
            query += " AND rule_type = ?"
            params.append(rule_type.upper())

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            cur = conn.execute(query, params)
            return [self._row_to_alert(row) for row in cur.fetchall()]

    def get_alert_by_id(self, alert_id: str) -> Alert | None:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
            row = cur.fetchone()
            if row:
                return self._row_to_alert(row)
        return None

    def update_mitigation_status(self, alert_id: str, new_status: str) -> bool:
        with self._get_connection() as conn:
            cur = conn.execute(
                "UPDATE alerts SET mitigation_status = ? WHERE id = ?",
                (new_status.upper(), alert_id),
            )
            return cur.rowcount > 0

    def count_devices(self) -> int:
        return self.count()

    def count_alerts(self) -> int:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT COUNT(*) FROM alerts")
            return cur.fetchone()[0]

    def clear_alerts(self) -> None:
        with self._get_connection() as conn:
            conn.execute("DELETE FROM alerts")

    def clear(self) -> None:
        with self._get_connection() as conn:
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM devices")
