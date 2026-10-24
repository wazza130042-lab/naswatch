"""
PostgreSQL implementation of the NASWatch DeviceRepository and AlertRepository.

Enabled automatically when `NASWATCH_DB_URL` is a `postgres://` or
`postgresql://` URL (see `storage/factory.py`). Mirrors the SQLite
repository interface so the detection engine and API stay engine-agnostic,
and adds tenant (`org_id`) scoping on every query.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
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

logger = get_logger("storage.postgres")

_DEVICE_COLUMNS = (
    "imsi, imei, owner_name, device_model, status, allowed_slices_json, "
    "created_at, updated_at, notes, org_id"
)


class PostgresRepository(DeviceRepository, AlertRepository):
    """psycopg-backed repository for devices and alerts."""

    def __init__(self, db_url: str) -> None:
        self.db_url = db_url
        self._conn = None
        self._init_db()

    def _connect(self):
        if self._conn is None or self._conn.closed:
            import psycopg
            from psycopg.rows import dict_row

            self._conn = psycopg.connect(
                self.db_url, connect_timeout=10, row_factory=dict_row, autocommit=True
            )
        return self._conn

    def _init_db(self) -> None:
        conn = self._connect()
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    imsi TEXT PRIMARY KEY,
                    imei TEXT NOT NULL UNIQUE,
                    owner_name TEXT NOT NULL,
                    device_model TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    allowed_slices_json TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    notes TEXT DEFAULT '',
                    org_id TEXT NOT NULL DEFAULT 'default'
                );
                CREATE INDEX IF NOT EXISTS idx_devices_imei ON devices(imei);
                CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
                CREATE INDEX IF NOT EXISTS idx_devices_org ON devices(org_id);

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
                    raw_event_json TEXT NOT NULL DEFAULT '{}',
                    org_id TEXT NOT NULL DEFAULT 'default',
                    assigned_to_id TEXT,
                    assigned_to_name TEXT,
                    claimed_at TEXT
                );
                ALTER TABLE alerts ADD COLUMN IF NOT EXISTS assigned_to_id TEXT;
                ALTER TABLE alerts ADD COLUMN IF NOT EXISTS assigned_to_name TEXT;
                ALTER TABLE alerts ADD COLUMN IF NOT EXISTS claimed_at TEXT;
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
                CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_type);
                CREATE INDEX IF NOT EXISTS idx_alerts_imsi ON alerts(imsi);
                CREATE INDEX IF NOT EXISTS idx_alerts_org ON alerts(org_id);
            """)
        logger.info("Connected to PostgreSQL repository")

    def _row_to_device(self, row: dict) -> Device:
        allowed_slices: list[SliceAssignment] = []
        for s in json.loads(row["allowed_slices_json"]):
            if isinstance(s, dict):
                allowed_slices.append(
                    SliceAssignment(
                        sst=int(s["sst"]),
                        sd=s.get("sd"),
                        name=s.get("name", ""),
                        description=s.get("description", ""),
                    )
                )
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
            org_id=row["org_id"],
        )

    def _row_to_alert(self, row: dict) -> Alert:
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
            raw_event=json.loads(row["raw_event_json"]),
            org_id=row["org_id"],
            assigned_to_id=row.get("assigned_to_id"),
            assigned_to_name=row.get("assigned_to_name"),
            claimed_at=datetime.fromisoformat(row["claimed_at"]) if row.get("claimed_at") else None,
        )

    # ------------------------------------------------------------------
    # DeviceRepository
    # ------------------------------------------------------------------
    def get_by_imsi(self, imsi: str, org_id: str | None = None) -> Device | None:
        if not imsi:
            return None
        query = "SELECT * FROM devices WHERE imsi = %s"
        params: list[Any] = [imsi]
        if org_id:
            query += " AND org_id = %s"
            params.append(org_id)
        with self._connect() as conn:
            cur = conn.execute(query, params)
            row = cur.fetchone()
        return self._row_to_device(row) if row else None

    def get_by_imei(self, imei: str) -> Device | None:
        if not imei:
            return None
        with self._connect() as conn:
            cur = conn.execute("SELECT * FROM devices WHERE imei = %s", (imei,))
            row = cur.fetchone()
        return self._row_to_device(row) if row else None

    def list_all(self, limit: int = 100, offset: int = 0, org_id: str | None = None) -> list[Device]:
        query = "SELECT * FROM devices"
        params: list[Any] = []
        if org_id:
            query += " WHERE org_id = %s"
            params.append(org_id)
        query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        with self._connect() as conn:
            cur = conn.execute(query, params)
            rows = cur.fetchall()
        return [self._row_to_device(r) for r in rows]

    def add(self, device: Device) -> bool:
        slices_data = [
            {"sst": s.sst, "sd": s.sd, "name": s.name, "description": s.description}
            for s in device.allowed_slices
        ]
        with self._connect() as conn:
            conn.execute(
                f"""
                INSERT INTO devices ({_DEVICE_COLUMNS})
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (imsi) DO UPDATE SET
                    imei = EXCLUDED.imei,
                    owner_name = EXCLUDED.owner_name,
                    device_model = EXCLUDED.device_model,
                    status = EXCLUDED.status,
                    allowed_slices_json = EXCLUDED.allowed_slices_json,
                    updated_at = EXCLUDED.updated_at,
                    notes = EXCLUDED.notes,
                    org_id = EXCLUDED.org_id
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
                    device.org_id,
                ),
            )
        return True

    def delete(self, imsi: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM devices WHERE imsi = %s", (imsi,))
        return cur.rowcount > 0

    def count(self) -> int:
        with self._connect() as conn:
            cur = conn.execute("SELECT COUNT(*) AS c FROM devices")
            row = cur.fetchone()
        return int(row["c"])

    # ------------------------------------------------------------------
    # AlertRepository
    # ------------------------------------------------------------------
    def record_alert(self, alert: Alert, org_id: str | None = None) -> bool:
        target_org = org_id or alert.org_id or "default"
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO alerts (
                    id, timestamp, rule_type, severity, title, description,
                    imsi, imei, cell_id, target_slice, mitigation_status,
                    raw_event_json, org_id, assigned_to_id, assigned_to_name, claimed_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                    target_org,
                    alert.assigned_to_id,
                    alert.assigned_to_name,
                    alert.claimed_at.isoformat() if alert.claimed_at else None,
                ),
            )
        return True

    def get_alerts(
        self,
        limit: int = 100,
        severity: str | None = None,
        rule_type: str | None = None,
        offset: int = 0,
        org_id: str | None = None,
    ) -> list[Alert]:
        query = "SELECT * FROM alerts WHERE 1=1"
        params: list[Any] = []
        if org_id:
            query += " AND org_id = %s"
            params.append(org_id)
        if severity:
            query += " AND severity = %s"
            params.append(severity.upper())
        if rule_type:
            query += " AND rule_type = %s"
            params.append(rule_type.upper())
        query += " ORDER BY timestamp DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        with self._connect() as conn:
            cur = conn.execute(query, params)
            rows = cur.fetchall()
        return [self._row_to_alert(r) for r in rows]

    def get_alert_by_id(self, alert_id: str, org_id: str | None = None) -> Alert | None:
        query = "SELECT * FROM alerts WHERE id = %s"
        params: list[Any] = [alert_id]
        if org_id:
            query += " AND org_id = %s"
            params.append(org_id)
        with self._connect() as conn:
            cur = conn.execute(query, params)
            row = cur.fetchone()
        return self._row_to_alert(row) if row else None

    def update_mitigation_status(
        self, alert_id: str, new_status: str, *, actor_id: str | None = None,
        org_id: str | None = None, admin_override: bool = False,
    ) -> bool:
        status = new_status.upper()
        if status not in {"NEW", "INVESTIGATING", "BLOCKED", "RESOLVED"}:
            return False
        query = "UPDATE alerts SET mitigation_status = %s WHERE id = %s"
        params: list[Any] = [status, alert_id]
        if org_id:
            query += " AND org_id = %s"
            params.append(org_id)
        if actor_id and not admin_override:
            query += " AND assigned_to_id = %s"
            params.append(actor_id)
        with self._connect() as conn:
            cur = conn.execute(query, params)
        return cur.rowcount > 0

    def claim_alert(self, alert_id: str, user_id: str, username: str, org_id: str) -> bool:
        """Atomically claim an unassigned incident; concurrent claims serialize in PostgreSQL."""
        now = datetime.now(UTC).isoformat()
        with self._connect() as conn:
            cur = conn.execute(
                """UPDATE alerts SET assigned_to_id = %s, assigned_to_name = %s, claimed_at = %s,
                   mitigation_status = CASE WHEN mitigation_status = 'NEW' THEN 'INVESTIGATING' ELSE mitigation_status END
                   WHERE id = %s AND org_id = %s AND (assigned_to_id IS NULL OR assigned_to_id = %s)""",
                (user_id, username, now, alert_id, org_id, user_id),
            )
        return cur.rowcount > 0

    def assign_alert(
        self, alert_id: str, user_id: str, username: str, org_id: str, *, allow_reassign: bool = False
    ) -> bool:
        """Assign an incident atomically; reassignment is an administrator action."""
        now = datetime.now(UTC).isoformat()
        owner_clause = "" if allow_reassign else " AND (assigned_to_id IS NULL OR assigned_to_id = %s)"
        params: list[Any] = [user_id, username, now, alert_id, org_id]
        if not allow_reassign:
            params.append(user_id)
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE alerts SET assigned_to_id = %s, assigned_to_name = %s, claimed_at = %s "
                "WHERE id = %s AND org_id = %s" + owner_clause,
                params,
            )
        return cur.rowcount > 0

    def release_alert(
        self, alert_id: str, user_id: str, org_id: str, *, admin_override: bool = False
    ) -> bool:
        owner_clause = "" if admin_override else " AND assigned_to_id = %s"
        params: list[Any] = [alert_id, org_id]
        if not admin_override:
            params.append(user_id)
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE alerts SET assigned_to_id = NULL, assigned_to_name = NULL, claimed_at = NULL, "
                "mitigation_status = CASE WHEN mitigation_status = 'INVESTIGATING' THEN 'NEW' ELSE mitigation_status END "
                "WHERE id = %s AND org_id = %s" + owner_clause,
                params,
            )
        return cur.rowcount > 0

    def count_devices(self) -> int:
        return self.count()

    def count_alerts(self) -> int:
        with self._connect() as conn:
            cur = conn.execute("SELECT COUNT(*) AS c FROM alerts")
            row = cur.fetchone()
        return int(row["c"])

    def clear_alerts(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM alerts")

    def clear(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM devices")
