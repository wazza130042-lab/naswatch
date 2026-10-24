"""
Immutable Audit Log for NASWatch enterprise compliance.

Records all security-significant actions: logins, SOAR actions, device provisioning,
key management, alert status changes.

Tamper-evidence:
  - Each row carries an HMAC-SHA256 `integrity` over its own content, keyed with
    `NASWATCH_JWT_SECRET`. Without the key, a forged row cannot be re-signed.
  - Each row also carries a `prev_hash`, chaining every entry to the one before it
    (hash chain). Altering any historical row breaks that row plus every row that
    follows it, making retroactive tampering detectable by `verify_chain()`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from naswatch.auth.jwt_handler import SECRET_KEY
from naswatch.storage.db import SqlBackend

logger = logging.getLogger("naswatch.audit")

_VERSION = "v2"


class AuditLogger:
    """SQL-backed audit trail with a keyed HMAC-SHA256 hash chain."""

    def __init__(self, db_path: str | None = None, db_url: str | None = None) -> None:
        self.backend = SqlBackend(db_path=db_path, db_url=db_url)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        conn, _ = self.backend.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id         TEXT PRIMARY KEY,
                timestamp  TEXT NOT NULL,
                actor      TEXT NOT NULL,
                org_id     TEXT NOT NULL DEFAULT 'default',
                action     TEXT NOT NULL,
                resource   TEXT,
                details    TEXT,
                ip_address TEXT,
                integrity  TEXT NOT NULL,
                prev_hash  TEXT
            )
        """)
        self._ensure_column()
        if self.backend.pg:
            conn, _ = self.backend.execute(
                "ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS seq BIGSERIAL"
            )
        self.backend.commit(conn)
        self.backend.close(conn)
        self._migrate_scheme()

    def _migrate_scheme(self) -> None:
        """
        One-time upgrade: re-sign any rows not yet in the keyed scheme.

        Rows written before keyed HMAC hashing lack the `v2:` version prefix.
        When any exist we re-sign the *entire* chain with the current scheme so
        version-prefix and chain-link invariants hold for all rows.
        """
        conn, cur = self.backend.execute(
            "SELECT COUNT(*) AS c FROM audit_log WHERE integrity NOT LIKE 'v2:%'"
        )
        row = cur.fetchone()
        self.backend.close(conn)
        if not row or int(row["c"]) == 0:
            return
        logger.warning(
            "Migrating %d legacy audit entries to keyed HMAC-SHA256 (v2).",
            int(row["c"]),
        )
        self.rebuild_chain()

    def _ensure_column(self) -> None:
        """Add `prev_hash` to legacy audit tables created before the hash chain landed."""
        if self.backend.pg:
            conn, cur = self.backend.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'audit_log'"
            )
            cols = {r["column_name"] for r in cur.fetchall()}
            self.backend.close(conn)
            if "prev_hash" not in cols:
                conn, _ = self.backend.execute(
                    "ALTER TABLE audit_log ADD COLUMN prev_hash TEXT"
                )
                self.backend.commit(conn)
                self.backend.close(conn)
        else:
            conn, cur = self.backend.execute("PRAGMA table_info(audit_log)")
            cols = {r["name"] for r in cur.fetchall()}
            self.backend.close(conn)
            if "prev_hash" not in cols:
                conn, _ = self.backend.execute(
                    "ALTER TABLE audit_log ADD COLUMN prev_hash TEXT"
                )
                self.backend.commit(conn)
                self.backend.close(conn)

    def _order(self, direction: str = "ASC") -> str:
        return f"ORDER BY {('seq' if self.backend.pg else 'rowid')} {direction}"

    def _canonical(self, row_data: dict) -> str:
        return json.dumps(row_data, sort_keys=True, default=str)

    def _message(self, row_data: dict, prev_hash: str) -> str:
        return f"{self._canonical(row_data)}|prev={prev_hash}"

    def _compute_integrity(self, row_data: dict, prev_hash: str) -> str:
        """Keyed HMAC-SHA256 integrity over the row content + chain link (v2)."""
        digest = hmac.new(SECRET_KEY.encode(), self._message(row_data, prev_hash).encode(), hashlib.sha256)
        return f"{_VERSION}:{digest.hexdigest()}"

    def _legacy_integrity(self, row_data: dict, prev_hash: str) -> str:
        """Un-keyed SHA-256 used by rows written before v2."""
        return hashlib.sha256(self._message(row_data, prev_hash).encode()).hexdigest()

    def _last_integrity(self) -> str:
        conn, cur = self.backend.execute(
            f"SELECT integrity FROM audit_log {self._order('DESC')} LIMIT 1"
        )
        row = cur.fetchone()
        self.backend.close(conn)
        return row["integrity"] if row else ""

    def log(
        self,
        actor: str,
        action: str,
        resource: str | None = None,
        details: dict[str, Any] | None = None,
        org_id: str = "default",
        ip_address: str | None = None,
    ) -> str:
        """Append an audit entry, chaining it to the previous row. Returns the entry ID."""
        entry_id = str(uuid.uuid4())
        ts = datetime.now(UTC).isoformat()
        details_json = json.dumps(details or {})
        prev_hash = self._last_integrity()
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
        integrity = self._compute_integrity(row_data, prev_hash)
        conn, _ = self.backend.execute(
            """
            INSERT INTO audit_log
                (id, timestamp, actor, org_id, action, resource, details,
                 ip_address, integrity, prev_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (entry_id, ts, actor, org_id, action, resource, details_json, ip_address, integrity, prev_hash),
        )
        self.backend.commit(conn)
        self.backend.close(conn)
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
        query += f" {self._order('DESC')} LIMIT ?"
        params.append(limit)
        conn, cur = self.backend.execute(query, params)
        rows = cur.fetchall()
        self.backend.close(conn)
        return [dict(r) for r in rows]

    def _expected_integrity(self, row_data: dict, prev_hash: str, stored: str) -> str:
        """Recompute the expected integrity using the scheme stored in the row."""
        if str(stored).startswith("v2:"):
            return self._compute_integrity(row_data, prev_hash)
        return self._legacy_integrity(row_data, prev_hash)

    def _verify_entry(self, row: Any) -> bool:
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
        return self._expected_integrity(row_data, row["prev_hash"] or "", row["integrity"]) == row["integrity"]

    def verify_integrity(self, entry_id: str, org_id: str | None = None) -> bool:
        """Verify one entry signature, optionally enforcing tenant scope."""
        query = "SELECT * FROM audit_log WHERE id=?"
        params: tuple[str, ...] = (entry_id,)
        if org_id:
            query += " AND org_id=?"
            params = (entry_id, org_id)
        conn, cur = self.backend.execute(query, params)
        row = cur.fetchone()
        self.backend.close(conn)
        if not row:
            return False
        return self._verify_entry(row)

    def verify_chain(self) -> tuple[bool, list[str], int]:
        """
        Verify the entire hash chain.

        Returns (valid, broken_entry_ids, total_entries). Each row must hash to
        its own stored integrity AND link to the recomputed integrity of its
        predecessor, so tampering with any historical row breaks that row plus
        every row that follows it.
        """
        conn, cur = self.backend.execute(
            f"SELECT * FROM audit_log {self._order('ASC')}"
        )
        rows = cur.fetchall()
        self.backend.close(conn)

        broken: list[str] = []
        expected_recomputed_prev = ""
        for row in rows:
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
            recomputed = self._expected_integrity(
                row_data, row["prev_hash"] or "", row["integrity"]
            )
            own_ok = recomputed == row["integrity"]
            link_ok = (row["prev_hash"] or "") == expected_recomputed_prev
            if not own_ok or not link_ok:
                broken.append(row["id"])
            expected_recomputed_prev = recomputed
        return len(broken) == 0, broken, len(rows)

    def count(self) -> int:
        conn, cur = self.backend.execute("SELECT COUNT(*) AS c FROM audit_log")
        row = cur.fetchone()
        self.backend.close(conn)
        return int(row["c"])

    def rebuild_chain(self) -> int:
        """
        Operator-only recovery: re-sign every entry in order into a fresh chain.

        Use ONLY when migrating a database across incompatible audit-schema
        versions or recovering from a known-good source. Rewrites every row's
        `integrity` and `prev_hash`, so any pre-existing tampering evidence is
        discarded. Returns the number of entries re-signed.
        """
        conn, cur = self.backend.execute(
            f"SELECT * FROM audit_log {self._order('ASC')}"
        )
        rows = cur.fetchall()
        self.backend.close(conn)
        if not rows:
            return 0
        logger.warning("Rebuilding audit hash chain across %d entries.", len(rows))
        prev = ""
        for row in rows:
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
            integrity = self._compute_integrity(row_data, prev)
            conn, _ = self.backend.execute(
                "UPDATE audit_log SET integrity = ?, prev_hash = ? WHERE id = ?",
                (integrity, prev, row["id"]),
            )
            self.backend.commit(conn)
            self.backend.close(conn)
            prev = integrity
        return len(rows)
