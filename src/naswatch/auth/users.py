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
from naswatch.auth.password_policy import WeakPasswordError, validate_password
from naswatch.logging_config import get_logger
from naswatch.storage.db import SqlBackend
from naswatch.storage.models import User, UserRole

logger = get_logger("auth.identity")


class _Dialect(SqlBackend):
    """Backward-compatible alias for the shared SQL backend adapter."""


class BootstrapAlreadyComplete(RuntimeError):
    """Raised when another request created the first operator already."""


class LastActiveAdminError(RuntimeError):
    """Raised when an update would leave a tenant without an active admin."""


def _guard_last_admin(
    tenant_rows: list[Any], user_id: str, new_role: str | None, new_active: int | None
) -> None:
    target = next((row for row in tenant_rows if row["id"] == user_id), None)
    if not target or target["role"] != UserRole.ADMIN.value or not bool(target["active"]):
        return
    remains_admin = (new_role is None or new_role == UserRole.ADMIN.value) and new_active != 0
    if not remains_admin:
        active_admins = sum(
            1 for row in tenant_rows
            if row["role"] == UserRole.ADMIN.value and bool(row["active"])
        )
        if active_admins <= 1:
            raise LastActiveAdminError("This change would leave the organization without an active administrator.")


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
                last_totp_counter BIGINT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_lower ON users(lower(username));
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
            ("last_totp_counter", "BIGINT"),
        ):
            if column not in existing:
                self.dialect.executescript(
                    f"ALTER TABLE users ADD COLUMN {column} {column_type}"
                )
                logger.info("Migrated users table: added column %s", column)

    def needs_bootstrap(self) -> bool:
        """True while no operator account exists, i.e. first-run setup is needed."""
        return self.count_users() == 0

    def ensure_default_admin(self) -> None:
        """Provision the first administrator **only** when explicitly configured.

        A fresh install starts with an empty account table and no shared secret:
        the operator creates the first administrator through the UI first-run
        screen (or ``scripts/create_admin.py``). For unattended installs
        (containers, CI, infrastructure-as-code) set **both**
        ``NASWATCH_ADMIN_EMAIL`` and ``NASWATCH_ADMIN_PASSWORD`` to seed the
        account on boot.
        """
        if self.count_users() > 0:
            return
        username = (os.environ.get("NASWATCH_ADMIN_EMAIL") or "").strip()
        password = os.environ.get("NASWATCH_ADMIN_PASSWORD") or ""
        if not username or not password:
            logger.info(
                "No operator accounts yet — first-run setup required "
                "(UI first-run screen or scripts/create_admin.py)."
            )
            return
        try:
            self.create_first_admin(username=username, password=password, org_id="default")
        except WeakPasswordError as exc:
            logger.error(
                "Refused to seed administrator %s: NASWATCH_ADMIN_PASSWORD is too weak (%s). "
                "Fix it or create the account via the first-run screen / "
                "scripts/create_admin.py.",
                username,
                exc,
            )
            return
        except BootstrapAlreadyComplete:
            logger.info("Another process created the initial administrator during bootstrap.")
            return
        logger.info("Bootstrapped first administrator %s from environment", username)

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
        username = username.strip().lower()
        problems = validate_password(password, username=username)
        if problems:
            raise WeakPasswordError(" ".join(problems))
        user = User(
            username=username,
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

    def create_first_admin(self, username: str, password: str, org_id: str = "default") -> User:
        """Create the initial admin atomically so concurrent first-run requests cannot race."""
        username = username.strip().lower()
        problems = validate_password(password, username=username)
        if problems:
            raise WeakPasswordError(" ".join(problems))
        user = User(
            username=username,
            password_hash=hash_password(password),
            role=UserRole.ADMIN,
            org_id=org_id or "default",
        )
        now = datetime.now(UTC).isoformat()
        conn = self.dialect.connect()
        insert_sql = """
            INSERT INTO users (id, username, password_hash, role, org_id, active,
                               must_change_password, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 1, 0, ?, ?)
        """
        try:
            if self.dialect.pg:
                with conn.transaction():
                    conn.execute("SELECT pg_advisory_xact_lock(%s)", (781246130,))
                    count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
                    if int(count):
                        raise BootstrapAlreadyComplete("An operator account already exists.")
                    conn.execute(insert_sql.replace("?", "%s"), (
                        user.id, user.username, user.password_hash, user.role.value,
                        user.org_id, now, now,
                    ))
            else:
                conn.execute("BEGIN IMMEDIATE")
                count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
                if int(count):
                    raise BootstrapAlreadyComplete("An operator account already exists.")
                conn.execute(insert_sql, (
                    user.id, user.username, user.password_hash, user.role.value,
                    user.org_id, now, now,
                ))
                conn.commit()
        except Exception:
            if not self.dialect.pg:
                conn.rollback()
            raise
        finally:
            self.dialect.close(conn)
        logger.info("Created initial administrator '%s' for org=%s", user.username, user.org_id)
        return user

    def get_by_username(self, username: str) -> User | None:
        conn, cur = self.dialect.execute(
            "SELECT * FROM users WHERE lower(username) = ? AND active = 1", (username.strip().lower(),)
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
        conn = self.dialect.connect()
        try:
            if self.dialect.pg:
                with conn.transaction():
                    target_row = conn.execute(
                        "SELECT org_id FROM users WHERE id = %s", (user_id,)
                    ).fetchone()
                    if not target_row:
                        return None
                    tenant_rows = conn.execute(
                        "SELECT id, role, active FROM users WHERE org_id = %s ORDER BY id FOR UPDATE",
                        (target_row["org_id"],),
                    ).fetchall()
                    _guard_last_admin(tenant_rows, user_id, new_role, new_active)
                    conn.execute(
                        f"UPDATE users SET {', '.join(updates)} WHERE id = %s".replace("?", "%s"),
                        params,
                    )
                    updated = conn.execute("SELECT * FROM users WHERE id = %s", (user_id,)).fetchone()
            else:
                conn.execute("BEGIN IMMEDIATE")
                target_row = conn.execute("SELECT org_id FROM users WHERE id = ?", (user_id,)).fetchone()
                if not target_row:
                    conn.rollback()
                    return None
                tenant_rows = conn.execute(
                    "SELECT id, role, active FROM users WHERE org_id = ? ORDER BY id",
                    (target_row["org_id"],),
                ).fetchall()
                _guard_last_admin(tenant_rows, user_id, new_role, new_active)
                conn.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
                updated = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
                conn.commit()
            return self._row_to_user(updated) if updated else None
        except Exception:
            if not self.dialect.pg:
                conn.rollback()
            raise
        finally:
            self.dialect.close(conn)

    def reset_password(self, user_id: str, new_password: str) -> bool:
        target = self.get_by_id(user_id)
        problems = validate_password(new_password, username=target.username if target else None)
        if problems:
            raise WeakPasswordError(" ".join(problems))
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
            "last_totp_counter = NULL, "
            "updated_at = ? WHERE id = ?",
            (secret, datetime.now(UTC).isoformat(), user_id),
        )
        self.dialect.commit(conn)
        self.dialect.close(conn)
        logger.info("Staged TOTP enrollment for user id=%s", user_id)

    def complete_totp_enrollment(
        self, user_id: str, secret: str, code: str, *, when: float | None = None
    ) -> bool:
        """Verify a first code and atomically arm the factor for an active user."""
        from naswatch.auth import totp

        counter = totp.matching_counter(secret, code, when=when)
        if counter is None:
            return False
        now = datetime.now(UTC).isoformat()
        conn, cur = self.dialect.execute(
            "UPDATE users SET totp_secret = ?, totp_enabled = 1, totp_enrolled_at = ?, "
            "last_totp_counter = ?, updated_at = ? "
            "WHERE id = ? AND active = 1",
            (secret, now, counter, now, user_id),
        )
        self.dialect.commit(conn)
        rowcount = cur.rowcount if hasattr(cur, "rowcount") else 0
        self.dialect.close(conn)
        if rowcount:
            logger.warning("TOTP second factor enrolled for user id=%s", user_id)
        return rowcount > 0

    def consume_totp_counter(self, user_id: str, counter: int) -> bool:
        """Atomically accept a strictly newer TOTP counter once per account."""
        conn, cur = self.dialect.execute(
            "UPDATE users SET last_totp_counter = ? "
            "WHERE id = ? AND active = 1 AND totp_enabled = 1 "
            "AND totp_secret IS NOT NULL "
            "AND (last_totp_counter IS NULL OR last_totp_counter < ?)",
            (int(counter), user_id, int(counter)),
        )
        self.dialect.commit(conn)
        rowcount = cur.rowcount if hasattr(cur, "rowcount") else 0
        self.dialect.close(conn)
        return rowcount > 0

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
            "last_totp_counter = NULL, updated_at = ? WHERE id = ?",
            (datetime.now(UTC).isoformat(), user_id),
        )
        self.dialect.commit(conn)
        self.dialect.close(conn)
        logger.warning("TOTP second factor disabled for user id=%s", user_id)

    def delete_user(self, user_id: str) -> bool:
        conn = self.dialect.connect()
        try:
            if self.dialect.pg:
                with conn.transaction():
                    target = conn.execute(
                        "SELECT org_id FROM users WHERE id = %s", (user_id,)
                    ).fetchone()
                    if not target:
                        return False
                    rows = conn.execute(
                        "SELECT id, role, active FROM users WHERE org_id = %s ORDER BY id FOR UPDATE",
                        (target["org_id"],),
                    ).fetchall()
                    _guard_last_admin(rows, user_id, "viewer", 0)
                    cursor = conn.execute("DELETE FROM users WHERE id = %s", (user_id,))
                    return cursor.rowcount > 0
            conn.execute("BEGIN IMMEDIATE")
            target = conn.execute("SELECT org_id FROM users WHERE id = ?", (user_id,)).fetchone()
            if not target:
                conn.rollback()
                return False
            rows = conn.execute(
                "SELECT id, role, active FROM users WHERE org_id = ? ORDER BY id",
                (target["org_id"],),
            ).fetchall()
            _guard_last_admin(rows, user_id, "viewer", 0)
            cursor = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            return cursor.rowcount > 0
        except Exception:
            if not self.dialect.pg:
                conn.rollback()
            raise
        finally:
            self.dialect.close(conn)


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


def issue_new_refresh(
    store: RefreshTokenStore, user: User, auth_method: str = "password"
) -> str:
    """Create, persist, and return a new refresh token for a user."""
    token = create_refresh_token(
        subject=user.username,
        role=user.role.value,
        org_id=user.org_id,
        user_id=user.id,
        auth_method=auth_method,
    )
    payload = decode_token(token)
    store.store(payload["jti"], user.id, datetime.now(UTC) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    return token
