#!/usr/bin/env python3
"""One-time, guarded migration of NASWatch SQLite data into PostgreSQL.

The utility refuses to write to a non-empty PostgreSQL target. It copies the
operator and network data, keeps API keys, revokes old refresh sessions, and
archives the SQLite audit rows unchanged because their original chain may not
verify under the currently configured signing key.
"""
from __future__ import annotations

import argparse
import os
import sqlite3
from pathlib import Path


TABLES = ("devices", "alerts", "users", "api_keys", "refresh_tokens")


def _sqlite_rows(source: sqlite3.Connection, table: str) -> tuple[list[str], list[dict]]:
    columns = [row["name"] for row in source.execute(f'PRAGMA table_info("{table}")')]
    if not columns:
        return [], []
    rows = [dict(row) for row in source.execute(f'SELECT * FROM "{table}"')]
    return columns, rows


def migrate(source_path: Path, excluded_usernames: set[str]) -> dict[str, int]:
    db_url = os.environ.get("NASWATCH_DB_URL")
    if not db_url or not db_url.startswith(("postgres://", "postgresql://")):
        raise SystemExit("NASWATCH_DB_URL must point to the PostgreSQL target.")
    if not source_path.is_file():
        raise SystemExit(f"SQLite source file not found: {source_path}")

    # Prepare all canonical PostgreSQL tables with the app's own schemas.
    from naswatch.audit.logger import AuditLogger
    from naswatch.auth.api_keys import APIKeyStore
    from naswatch.auth.users import RefreshTokenStore, UserStore
    from naswatch.storage.postgres_repo import PostgresRepository

    PostgresRepository(db_url=db_url)
    UserStore(db_url=db_url)
    RefreshTokenStore(db_url=db_url)
    APIKeyStore(db_url=db_url)
    AuditLogger(db_url=db_url)

    source = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True)
    source.row_factory = sqlite3.Row
    source.execute("PRAGMA query_only = ON")
    source_table_names = {
        row[0] for row in source.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    counts = {
        table: source.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
        for table in (*TABLES, "audit_log")
        if table in source_table_names
    }
    if "users" not in source_table_names:
        raise SystemExit("The SQLite source has no users table.")

    # Snapshot rows before writing. Password hashes and TOTP secrets move as-is.
    source_data = {
        table: _sqlite_rows(source, table)
        for table in TABLES
        if table in source_table_names
    }
    audit_columns, audit_rows = _sqlite_rows(source, "audit_log") if "audit_log" in source_table_names else ([], [])
    source.close()

    # The source audit chain was already unverified with the active key. Keep
    # every row byte-for-byte in a separate archive and start a fresh chain.
    import psycopg
    from psycopg.rows import dict_row

    pg = psycopg.connect(db_url, connect_timeout=10, row_factory=dict_row, autocommit=True)
    for table in TABLES:
        row = pg.execute(f'SELECT COUNT(*) AS c FROM "{table}"').fetchone()
        if int(row["c"]):
            pg.close()
            raise SystemExit(f"PostgreSQL table {table} is not empty; refusing to overwrite it.")
    row = pg.execute("SELECT COUNT(*) AS c FROM audit_log").fetchone()
    if int(row["c"]):
        pg.close()
        raise SystemExit("PostgreSQL audit_log is not empty; refusing to overwrite it.")
    exists = pg.execute(
        "SELECT to_regclass('public.audit_log_archive') AS table_name"
    ).fetchone()["table_name"]
    if exists:
        row = pg.execute("SELECT COUNT(*) AS c FROM audit_log_archive").fetchone()
        if int(row["c"]):
            pg.close()
            raise SystemExit("PostgreSQL audit_log_archive is not empty; refusing to overwrite it.")

    audit_archive_columns = [
        '"source_order" BIGINT NOT NULL',
        *(f'"{column}" TEXT' for column in audit_columns),
        '"archive_reason" TEXT NOT NULL',
    ]
    pg.execute(
        "CREATE TABLE IF NOT EXISTS audit_log_archive ("
        + ", ".join(audit_archive_columns)
        + ")"
    )

    copied: dict[str, int] = {}
    removed = 0
    try:
        with pg.transaction():
            for table, (columns, rows) in source_data.items():
                if table == "users":
                    before = len(rows)
                    rows = [
                        row for row in rows
                        if row.get("username", "").casefold() not in excluded_usernames
                    ]
                    removed = before - len(rows)
                if table == "refresh_tokens":
                    for row in rows:
                        row["revoked"] = 1
                        if "replaced_by" in row and not row.get("replaced_by"):
                            row["replaced_by"] = "JWT_SECRET_ROTATED"
                if not rows:
                    copied[table] = 0
                    continue
                quoted_columns = ", ".join('"' + column + '"' for column in columns)
                placeholders = ", ".join("%s" for _ in columns)
                sql = f'INSERT INTO "{table}" ({quoted_columns}) VALUES ({placeholders})'
                with pg.cursor() as cursor:
                    cursor.executemany(sql, [tuple(row.get(c) for c in columns) for row in rows])
                copied[table] = len(rows)

            reason = (
                "Copied unchanged from SQLite. Source audit chain did not verify with the active "
                "signing key at migration time; retained as historical reference, not trusted evidence."
            )
            if audit_rows:
                cols = ["source_order", *audit_columns, "archive_reason"]
                quoted_columns = ", ".join('"' + column + '"' for column in cols)
                placeholders = ", ".join("%s" for _ in cols)
                sql = f'INSERT INTO audit_log_archive ({quoted_columns}) VALUES ({placeholders})'
                with pg.cursor() as cursor:
                    cursor.executemany(
                        sql,
                        [
                            (index, *(row.get(c) for c in audit_columns), reason)
                            for index, row in enumerate(audit_rows, start=1)
                        ],
                    )
        copied["audit_log_archive"] = len(audit_rows)
        copied["test_users_removed"] = removed
        copied["refresh_tokens_revoked"] = len(source_data.get("refresh_tokens", ([], []))[1])
    finally:
        pg.close()

    # Only after PostgreSQL commits, remove requested demo users from the retired
    # SQLite database too. The separately created backup remains untouched.
    if excluded_usernames:
        writable = sqlite3.connect(source_path)
        placeholders = ",".join("?" for _ in excluded_usernames)
        usernames = sorted(excluded_usernames)
        writable.execute(
            f"DELETE FROM users WHERE lower(username) IN ({placeholders})",
            [name.lower() for name in usernames],
        )
        writable.commit()
        writable.close()
    return copied


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("data/inventory.db"))
    parser.add_argument(
        "--delete-user",
        action="append",
        default=[],
        help="Remove this exact username from the migrated and retired SQLite user tables.",
    )
    args = parser.parse_args()
    counts = migrate(args.source, {name.casefold() for name in args.delete_user})
    for name, count in counts.items():
        print(f"{name}: {count}")
    print("Migration complete. Existing audit history is preserved in audit_log_archive.")


if __name__ == "__main__":
    main()
