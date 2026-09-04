"""
API Key management for machine-to-machine (M2M) access.
Keys are stored as SHA-256 hashes; the raw key is only shown once at creation.
"""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
from datetime import UTC, datetime

API_KEY_PREFIX = "nw_"
API_KEY_BYTES = 32


def _hash_key(raw_key: str) -> str:
    """SHA-256 hash of raw API key for safe storage."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_api_key() -> tuple[str, str]:
    """
    Generate a new API key.
    Returns: (raw_key, hashed_key)
    """
    raw = API_KEY_PREFIX + secrets.token_urlsafe(API_KEY_BYTES)
    return raw, _hash_key(raw)


class APIKeyStore:
    """SQLite-backed API key registry."""

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
            CREATE TABLE IF NOT EXISTS api_keys (
                id         TEXT PRIMARY KEY,
                name       TEXT NOT NULL,
                key_hash   TEXT NOT NULL UNIQUE,
                role       TEXT NOT NULL DEFAULT 'viewer',
                org_id     TEXT NOT NULL DEFAULT 'default',
                created_at TEXT NOT NULL,
                expires_at TEXT,
                revoked    INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.commit()
        if self._memory_conn is None:
            conn.close()

    def create_key(self, name: str, role: str = "viewer", org_id: str = "default", expires_at: str | None = None) -> tuple[str, str]:
        """
        Create and store a new API key.
        Returns (raw_key, key_id).
        """
        import uuid
        raw_key, key_hash = generate_api_key()
        key_id = str(uuid.uuid4())
        conn = self._connect()
        conn.execute(
            "INSERT INTO api_keys (id, name, key_hash, role, org_id, created_at, expires_at) VALUES (?,?,?,?,?,?,?)",
            (key_id, name, key_hash, role, org_id, datetime.now(UTC).isoformat(), expires_at),
        )
        conn.commit()
        if self._memory_conn is None:
            conn.close()
        return raw_key, key_id

    def validate_key(self, raw_key: str) -> dict | None:
        """
        Validate a raw API key.
        Returns user-like payload dict if valid, None if invalid/revoked.
        """
        key_hash = _hash_key(raw_key)
        conn = self._connect()
        row = conn.execute(
            "SELECT * FROM api_keys WHERE key_hash=? AND revoked=0", (key_hash,)
        ).fetchone()
        if self._memory_conn is None:
            conn.close()
        if not row:
            return None
        if row["expires_at"]:
            try:
                expiry = datetime.fromisoformat(row["expires_at"])
                if datetime.now(UTC) > expiry.replace(tzinfo=UTC):
                    return None
            except Exception:
                pass
        return {"sub": row["name"], "role": row["role"], "org_id": row["org_id"], "key_id": row["id"]}

    def revoke_key(self, key_id: str) -> bool:
        conn = self._connect()
        cur = conn.execute("UPDATE api_keys SET revoked=1 WHERE id=?", (key_id,))
        conn.commit()
        rowcount = cur.rowcount
        if self._memory_conn is None:
            conn.close()
        return rowcount > 0

    def list_keys(self, org_id: str | None = None) -> list[dict]:
        conn = self._connect()
        if org_id:
            rows = conn.execute("SELECT id,name,role,org_id,created_at,expires_at,revoked FROM api_keys WHERE org_id=?", (org_id,)).fetchall()
        else:
            rows = conn.execute("SELECT id,name,role,org_id,created_at,expires_at,revoked FROM api_keys").fetchall()
        result = [dict(r) for r in rows]
        if self._memory_conn is None:
            conn.close()
        return result
