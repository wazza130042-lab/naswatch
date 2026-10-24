"""
API Key management for machine-to-machine (M2M) access.
Keys are stored as SHA-256 hashes; the raw key is only shown once at creation.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime

from naswatch.storage.db import SqlBackend

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
    """SQL-backed API key registry shared with SQLite or PostgreSQL deployments."""

    def __init__(self, db_path: str = "data/inventory.db", db_url: str | None = None) -> None:
        self.backend = SqlBackend(db_path=db_path, db_url=db_url)
        self._ensure_table()

    def _ensure_table(self) -> None:
        self.backend.executescript("""
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

    def create_key(self, name: str, role: str = "viewer", org_id: str = "default", expires_at: str | None = None) -> tuple[str, str]:
        """
        Create and store a new API key.
        Returns (raw_key, key_id).
        """
        import uuid
        raw_key, key_hash = generate_api_key()
        key_id = str(uuid.uuid4())
        conn, _ = self.backend.execute(
            "INSERT INTO api_keys (id, name, key_hash, role, org_id, created_at, expires_at) VALUES (?,?,?,?,?,?,?)",
            (key_id, name, key_hash, role, org_id, datetime.now(UTC).isoformat(), expires_at),
        )
        self.backend.commit(conn)
        self.backend.close(conn)
        return raw_key, key_id

    def validate_key(self, raw_key: str) -> dict | None:
        """
        Validate a raw API key.
        Returns user-like payload dict if valid, None if invalid/revoked.
        """
        key_hash = _hash_key(raw_key)
        conn, cur = self.backend.execute(
            "SELECT * FROM api_keys WHERE key_hash=? AND revoked=0", (key_hash,)
        )
        row = cur.fetchone()
        self.backend.close(conn)
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
        conn, cur = self.backend.execute("UPDATE api_keys SET revoked=1 WHERE id=?", (key_id,))
        self.backend.commit(conn)
        rowcount = cur.rowcount
        self.backend.close(conn)
        return rowcount > 0

    def list_keys(self, org_id: str | None = None) -> list[dict]:
        conn, cur = self.backend.execute(
            "SELECT id,name,role,org_id,created_at,expires_at,revoked FROM api_keys WHERE org_id=?",
            (org_id,),
        ) if org_id else self.backend.execute(
            "SELECT id,name,role,org_id,created_at,expires_at,revoked FROM api_keys"
        )
        rows = cur.fetchall()
        result = [dict(r) for r in rows]
        self.backend.close(conn)
        return result
