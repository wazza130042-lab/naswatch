"""
Enterprise identity layer for NASWatch.

Provides:
  - UserStore: SQL-backed operator accounts (bcrypt-hashed passwords, RBAC roles,
    tenant org_id) with automatic bootstrap of the initial admin account.
  - RefreshTokenStore: refresh-token lifecycle with rotation and revocation,
    enabling forced sign-out and per-session control.

Both stores transparently back onto SQLite (default) or PostgreSQL
(when a `postgres://` URL is supplied).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any

from naswatch.auth.jwt_handler import (
    REFRESH_TOKEN_EXPIRE_DAYS,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from naswatch.logging_config import get_logger
from naswatch.storage.db import SqlBackend
from naswatch.storage.models import User, UserRole

logger = get_logger("auth.identity")


class _Dialect(SqlBackend):
    """Backward-compatible alias for the shared SQL backend adapter."""


def _row_get(row: Any, key: str, default: Any = None) -> Any:
    """Read ``key`` from a sqlite3.Row or a dict-like row, with a fallback."""
    try:
        return row[key]
    except (KeyError, IndexError, TypeError):
        return default


class UserStore:
    """Operator account registry with bcrypt password storage."""

    def __init__(self, db_path: str | None = None, db_url: str | None = None) -> None:
        self.dialect = _Dialect(db_path=db_path, db_url=db_url)
        self._ensure_schema()
        self.ensure_default_admin()

    def _ensure_schema(self) -> None:
        self.dialect.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer',
                org_id TEXT NOT NULL DEFAULT 'default',
                active INTEGER NOT NULL DEFAULT 1,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                totp_secret TEXT,
                totp_enabled INTEGER NOT NULL DEFAULT 0,
                totp_enrolled_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id);
        """)
        self._migrate_totp()

    def _existing_columns(self) -> set[str]:
        """Return the current column names of the users table."""
        if getattr(self.dialect, "pg", False):
            conn, cur = self.dialect.execute(
                "SELECT column_name AS name FROM information_schema.columns "
                "WHERE table_name = ?",
                ("users",),
            )
        else:
            conn, cur = self.dialect.execute("PRAGMA table_info(users)")
        try:
            rows = cur.fetchall()
        finally:
            self.dialect.close(conn)
        names: set[str] = set()
        for row in rows:
            try:
                names.add(row["name"])
            except (KeyError, IndexError, TypeError):
                names.add(row[1])
        return names

    def _migrate_totp(self) -> None:
        """Add the TOTP columns to an existing install (safe to run every boot)."""
        existing = self._existing_columns()
        for column, column_type in (
            ("totp_secret", "TEXT"),
            ("totp_enabled", "INTEGER NOT NULL DEFAULT 0"),
            ("totp_enrolled_at", "TEXT"),
        ):
            if column not in existing:
                self.dialect.executescript(
                    f"ALTER TABLE users ADD COLUMN {column} {column_type}"
                )
                logger.info("Migrated users table: added column %s", column)

    def ensure_default_admin(self) -> None:
        """Bootstrap the initial administrator account if no users exist."""
        conn, cur = self.dialect.execute("SELECT COUNT(*) AS c FROM users")
        row = cur.fetchone()
        self.dialect.close(conn)
        if int(row["c"]) > 0:
            return
        username = os.environ.get("NASWATCH_ADMIN_EMAIL", "admin@naswatch.io")
        password = os.environ.get("NASWATCH_ADMIN_PASSWORD", "naswatch-admin-password")
        self.create_user(username=username, password=password, role=UserRole.ADMIN, org_id="default")
        logger.warning(
            "Bootstrapped default admin account '%s'. Change the password before production use.",
            username,
        )

    def _row_to_user(self, row: Any) -> User:
        enrolled = _row_get(row, "totp_enrolled_at")
        return User(
            id=row["id"],
            username=row["username"],
            password_hash=row["password_hash"],
            role=UserRole(row["role"]),
            org_id=row["org_id"],
            active=bool(row["active"]),
            must_change_password=bool(row["must_change_password"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            totp_secret=_row_get(row, "totp_secret"),
            totp_enabled=bool(_row_get(row, "totp_enabled", 0)),
            totp_enrolled_at=(
                datetime.fromisoformat(enrolled) if enrolled else None
            ),
        )

    def create_user(self, username: str, password: str, role: UserRole, org_id: str = "default") -> User:
        user = User(
            username=username.strip(),
            password_hash=hash_password(password),
            role=role,
            org_id=org_id or "default",
        )
        now = datetime.now(UTC).isoformat()
        conn, _ = self.dialect.execute(
            """
            INSERT INTO users (id, username, password_hash, role, org_id, active,
                               must_change_password, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (user.id, user.username, user.password_hash, user.role.value, user.org_id,
             1, 0, now, now),
        )
        self.dialect.commit(conn)
        self.dialect.close(conn)
        logger.info("Created user '%s' role=%s org=%s", user.username, user.role.value, user.org_id)
        return user

    def get_by_username(self, username: str) -> User | None:
        conn, cur = self.dialect.execute(
            "SELECT * FROM users WHERE username = ? AND active = 1", (username.strip(),)
        )
        row = cur.fetchone()
        self.dialect.close(conn)
        return self._row_to_user(row) if row else None

    def get_by_id(self, user_id: str) -> User | None:
        conn, cur = self.dialect.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        self.dialect.close(conn)
        return self._row_to_user(row) if row else None

    def authenticate(self, username: str, password: str) -> User | None:
        user = self.get_by_username(username)
        if not user or not user.active:
            logger.warning("Login rejected for username='%s': unknown or deactivated account", username)
            return None
        if not verify_password(password, user.password_hash):
            logger.warning("Login rejected for username='%s': invalid credentials", username)
            return None
        logger.info("Login success username='%s' org=%s role=%s", user.username, user.org_id, user.role.value)
        return user

    def list_users(self, org_id: str | None = None) -> list[User]:
        query = "SELECT * FROM users"
        params: list[Any] = []
        if org_id:
            query += " WHERE org_id = ?"
            params.append(org_id)
        query += " ORDER BY created_at ASC"
        conn, cur = self.dialect.execute(query, params)
        rows = cur.fetchall()
        self.dialect.close(conn)
        return [self._row_to_user(r) for r in rows]

    def count_users(self) -> int:
        conn, cur = self.dialect.execute("SELECT COUNT(*) AS c FROM users")
        row = cur.fetchone()
        self.dialect.close(conn)
        return int(row["c"])

    def update_user(self, user_id: str, role: UserRole | None = None, active: bool | None = None) -> User | None:
        new_role = role.value if role else None
        new_active = None if active is None else (1 if active else 0)
        updates = ["updated_at = ?"]
        params: list[Any] = [datetime.now(UTC).isoformat()]
        if new_role:
            updates.append("role = ?")
            params.append(new_role)
        if new_active is not None:
            updates.append("active = ?")
            params.append(new_active)
        params.append(user_id)
        conn, cur = self.dialect.execute(
            f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params
        )
        self.dialect.commit(conn)
        self.dialect.close(conn)
        return self.get_by_id(user_id)

    def reset_password(self, user_id: str, new_password: str) -> bool:
        hashed = hash_password(new_password)
        conn, _ = self.dialect.execute(
            "UPDATE users SET password_hash = ?, must_change_password = ?, updated_at = ? WHERE id = ?",
            (hashed, 0, datetime.now(UTC).isoformat(), user_id),
        )
        self.dialect.commit(conn)
        self.dialect.close(conn)
        logger.info("Password reset applied for user id=%s", user_id)
        return True

    # ── TOTP second factor ────────────────────────────────────────────
    def set_totp_secret(self, user_id: str, secret: str) -> None:
        """Stage a TOTP secret for an account without switching the factor on.

        The operator must prove possession (submit a valid code) before the
        factor is armed via :meth:`enable_totp`.
        """
        conn, _ = self.dialect.execute(
            "UPDATE users SET totp_secret = ?, totp_enabled = 0, totp_enrolled_at = NULL, "
            "updated_at = ? WHERE id = ?",
            (secret, datetime.now(UTC).isoformat(), user_id),
        )
        self.dialect.commit(conn)
        self.dialect.close(conn)
        logger.info("Staged TOTP enrollment for user id=%s", user_id)

    def enable_totp(self, user_id: str) -> bool:
        """Confirm a staged secret and switch the second factor on."""
        conn, cur = self.dialect.execute(
            "UPDATE users SET totp_enabled = 1, totp_enrolled_at = ?, updated_at = ? "
            "WHERE id = ? AND totp_secret IS NOT NULL",
            (datetime.now(UTC).isoformat(), datetime.now(UTC).isoformat(), user_id),
        )
        self.dialect.commit(conn)
        rowcount = cur.rowcount if hasattr(cur, "rowcount") else 0
        self.dialect.close(conn)
        if rowcount:
            logger.warning("TOTP second factor enabled for user id=%s", user_id)
        return rowcount > 0

    def disable_totp(self, user_id: str) -> None:
        """Remove the stored secret and switch the second factor off."""
        conn, _ = self.dialect.execute(
            "UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_enrolled_at = NULL, "
            "updated_at = ? WHERE id = ?",
            (datetime.now(UTC).isoformat(), user_id),
        )
        self.dialect.commit(conn)
        self.dialect.close(conn)
        logger.warning("TOTP second factor disabled for user id=%s", user_id)

    def delete_user(self, user_id: str) -> bool:
        conn, cur = self.dialect.execute("DELETE FROM users WHERE id = ?", (user_id,))
        self.dialect.commit(conn)
        rowcount = cur.rowcount if hasattr(cur, "rowcount") else 0
        self.dialect.close(conn)
        return rowcount > 0


class RefreshTokenStore:
    """Refresh-token registry with rotation and revocation tracking."""

    def __init__(self, db_path: str | None = None, db_url: str | None = None) -> None:
        self.dialect = _Dialect(db_path=db_path, db_url=db_url)
        self.dialect.executescript("""
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                jti TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                replaced_by TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
        """)

    def store(self, jti: str, user_id: str, expires_at: datetime) -> None:
        conn, _ = self.dialect.execute(
            """
            INSERT INTO refresh_tokens (jti, user_id, issued_at, expires_at, revoked)
            VALUES (?, ?, ?, ?, 0)
            """,
            (jti, user_id, datetime.now(UTC).isoformat(), expires_at.isoformat()),
        )
        self.dialect.commit(conn)
        self.dialect.close(conn)

    def is_valid(self, jti: str) -> bool:
        conn, cur = self.dialect.execute(
            "SELECT * FROM refresh_tokens WHERE jti = ? AND revoked = 0", (jti,)
        )
        row = cur.fetchone()
        self.dialect.close(conn)
        if not row:
            return False
        expiry = datetime.fromisoformat(row["expires_at"])
        return datetime.now(UTC) < expiry

    def revoke(self, jti: str) -> None:
        conn, _ = self.dialect.execute(
            "UPDATE refresh_tokens SET revoked = 1, replaced_by = COALESCE(replaced_by, 'REVOKED') WHERE jti = ?",
            (jti,),
        )
        self.dialect.commit(conn)
        self.dialect.close(conn)

    def rotate(self, old_jti: str, new_jti: str) -> None:
        """Revoke an old refresh token, marking it as replaced by a new one.

        The replacement token is expected to already be persisted (via
        ``issue_new_refresh``), so this only flips the old row's state.
        """
        conn, _ = self.dialect.execute(
            "UPDATE refresh_tokens SET revoked = 1, replaced_by = ? WHERE jti = ?",
            (new_jti, old_jti),
        )
        self.dialect.commit(conn)
        self.dialect.close(conn)
        logger.info("Refresh token rotated: %s -> %s", old_jti[:8], new_jti[:8])

    def revoke_all_for_user(self, user_id: str) -> None:
        conn, _ = self.dialect.execute(
            "UPDATE refresh_tokens SET revoked = 1, replaced_by = COALESCE(replaced_by, 'REVOKED') "
            "WHERE user_id = ? AND revoked = 0",
            (user_id,),
        )
        self.dialect.commit(conn)
        self.dialect.close(conn)
        logger.warning("All refresh sessions revoked for user id=%s", user_id)


def issue_new_refresh(store: RefreshTokenStore, user: User) -> str:
    """Create, persist, and return a new refresh token for a user."""
    token = create_refresh_token(subject=user.username, role=user.role.value, org_id=user.org_id, user_id=user.id)
    payload = decode_token(token)
    store.store(payload["jti"], user.id, datetime.now(UTC) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    return token
