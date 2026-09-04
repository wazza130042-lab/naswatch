"""
Immutable Audit Log for NASWatch enterprise compliance.

Records all security-significant actions: logins, SOAR actions, device provisioning,
key management, alert status changes. Written to SQLite with SHA-256 integrity hashes.
"""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import uuid
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger("naswatch.audit")


class AuditLogger:
    """Thread-safe SQLite-backed audit trail with row integrity hashing."""

    def __init__(self, db_path: str = "data/inventory.db") -> None:
        self.db_path = db_path
        self._memory_conn: sqlite3.Connection | None = None
        if self.db_path == ":memory:":
            self._memory_conn = sqlite3.connect(":memory:")
            self._memory_conn.row_factory = sqlite3.Row
        self._ensure_table()

    def _connect(self) -> sqlite3.Connection:
        if self._memory_conn is not None:
            return self._memory_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_table(self) -> None:
        conn = self._connect()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id         TEXT PRIMARY KEY,
                timestamp  TEXT NOT NULL,
                actor      TEXT NOT NULL,
                org_id     TEXT NOT NULL DEFAULT 'default',
                action     TEXT NOT NULL,
                resource   TEXT,
                details    TEXT,
                ip_address TEXT,
                integrity  TEXT NOT NULL
            )
        """)
        conn.commit()
        if self._memory_conn is None:
            conn.close()

    def _compute_integrity(self, row_data: dict) -> str:
        """SHA-256 hash of the row content for tamper detection."""
        canonical = json.dumps(row_data, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def log(
        self,
        actor: str,
        action: str,
        resource: str | None = None,
        details: dict[str, Any] | None = None,
        org_id: str = "default",
        ip_address: str | None = None,
    ) -> str:
        """
        Write an audit entry.
        Returns the entry ID.
        """
        entry_id = str(uuid.uuid4())
        ts = datetime.now(UTC).isoformat()
        details_json = json.dumps(details or {})
        row_data = {
            "id": entry_id,
            "timestamp": ts,
            "actor": actor,
            "org_id": org_id,
            "action": action,
            "resource": resource,
            "details": details_json,
            "ip_address": ip_address,
        }
        integrity = self._compute_integrity(row_data)
        conn = self._connect()
        conn.execute(
            "INSERT INTO audit_log VALUES (?,?,?,?,?,?,?,?,?)",
            (entry_id, ts, actor, org_id, action, resource, details_json, ip_address, integrity),
        )
        conn.commit()
        if self._memory_conn is None:
            conn.close()
        logger.info("AUDIT [%s] actor=%s action=%s resource=%s", entry_id, actor, action, resource)
        return entry_id

    def get_entries(
        self,
        org_id: str | None = None,
        actor: str | None = None,
        action: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Query audit log entries with optional filters."""
        query = "SELECT * FROM audit_log WHERE 1=1"
        params: list = []
        if org_id:
            query += " AND org_id=?"
            params.append(org_id)
        if actor:
            query += " AND actor=?"
            params.append(actor)
        if action:
            query += " AND action LIKE ?"
            params.append(f"%{action}%")
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        conn = self._connect()
        rows = conn.execute(query, params).fetchall()
        result = [dict(r) for r in rows]
        if self._memory_conn is None:
            conn.close()
        return result

    def verify_integrity(self, entry_id: str) -> bool:
        """Verify that an audit entry has not been tampered with."""
        conn = self._connect()
        row = conn.execute("SELECT * FROM audit_log WHERE id=?", (entry_id,)).fetchone()
        if self._memory_conn is None:
            conn.close()
        if not row:
            return False
        stored_integrity = row["integrity"]
        row_data = {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "actor": row["actor"],
            "org_id": row["org_id"],
            "action": row["action"],
            "resource": row["resource"],
            "details": row["details"],
            "ip_address": row["ip_address"],
        }
        return self._compute_integrity(row_data) == stored_integrity
