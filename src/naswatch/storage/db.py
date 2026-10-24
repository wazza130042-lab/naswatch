"""
Shared SQL backend adapter for NASWatch (SQLite default, PostgreSQL via URL).

Thin abstraction around sqlite3 / psycopg so that identity and audit stores
can run against either engine without duplicating query logic.
"""

from __future__ import annotations

import os
import sqlite3

from naswatch.logging_config import get_logger

logger = get_logger("storage.backend")


def is_postgres_url(url: str) -> bool:
    return url.startswith("postgres://") or url.startswith("postgresql://")


class SqlBackend:
    """Uniform row-oriented access to SQLite or PostgreSQL."""

    def __init__(self, db_path: str | None = None, db_url: str | None = None) -> None:
        self.db_url = db_url
        self.db_path = db_path or os.environ.get("NASWATCH_DB_PATH", "data/inventory.db")
        self._memory_conn: sqlite3.Connection | None = None
        self._memory = self.db_url is None and self.db_path == ":memory:"
        self._psycopg = None
        self._params = "%s" if self.db_url else "?"

    @property
    def pg(self) -> bool:
        return self.db_url is not None

    def connect(self):
        if self.pg:
            if self._psycopg is None:
                import psycopg
                from psycopg.rows import dict_row

                self._psycopg = psycopg.connect(
                    self.db_url, connect_timeout=10, row_factory=dict_row, autocommit=True
                )
            return self._psycopg
        if self._memory:
            if self._memory_conn is None:
                self._memory_conn = sqlite3.connect(":memory:")
                self._memory_conn.row_factory = sqlite3.Row
            return self._memory_conn
        import pathlib

        pathlib.Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def execute(self, sql: str, params: tuple | list = ()):
        conn = self.connect()
        if self._params == "%s":
            # Escape literal '%' first so psycopg does not treat it as a
            # placeholder, then translate '?' to '%s'.
            sql = sql.replace("%", "%%").replace("?", "%s")
        cur = conn.execute(sql, tuple(params))
        return conn, cur

    def executescript(self, sql: str) -> None:
        """Run one or more `;`-separated DDL/DML statements (both engines)."""
        conn = self.connect()
        for stmt in sql.split(";"):
            stmt = stmt.strip()
            if stmt:
                self.execute(stmt)
        self.commit(conn)
        self.close(conn)

    def commit(self, conn) -> None:
        # Always commit: for a shared in-memory connection an uncommitted write
        # leaves an implicit transaction open, so the next BEGIN IMMEDIATE would
        # fail with "cannot start a transaction within a transaction". Unlike
        # close(), committing does not drop the in-memory database.
        conn.commit()

    def close(self, conn) -> None:
        if not self.pg and not self._memory:
            conn.close()
