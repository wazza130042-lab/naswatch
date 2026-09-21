"""
Repository factory: selects PostgreSQL or SQLite based on `NASWATCH_DB_URL`.

  - `NASWATCH_DB_URL` set to a postgres:// URL  -> PostgresRepository + PG identity stores
  - otherwise                                 -> SQLiteRepository + SQLite identity stores
"""

from __future__ import annotations

import os

from naswatch.storage.postgres_repo import PostgresRepository
from naswatch.storage.sqlite_repo import SQLiteRepository


def _is_postgres(db_url: str | None) -> bool:
    return bool(db_url) and (db_url.startswith("postgres://") or db_url.startswith("postgresql://"))


def get_db_url() -> str | None:
    return os.environ.get("NASWATCH_DB_URL") or None


def get_db_path() -> str:
    return os.environ.get("NASWATCH_DB_PATH", "data/inventory.db")


def create_repository() -> SQLiteRepository | PostgresRepository:
    db_url = get_db_url()
    if _is_postgres(db_url):
        return PostgresRepository(db_url=db_url)
    return SQLiteRepository(db_path=get_db_path())


def create_user_store(db_path: str | None = None, db_url: str | None = None):
    """Create a UserStore backed by the same engine as the main repository."""
    from naswatch.auth.users import UserStore

    url = db_url or get_db_url()
    if _is_postgres(url):
        return UserStore(db_url=url)
    return UserStore(db_path=db_path or get_db_path())


def create_refresh_token_store(db_path: str | None = None, db_url: str | None = None):
    """Create a RefreshTokenStore backed by the same engine as the main repository."""
    from naswatch.auth.users import RefreshTokenStore

    url = db_url or get_db_url()
    if _is_postgres(url):
        return RefreshTokenStore(db_url=url)
    return RefreshTokenStore(db_path=db_path or get_db_path())
