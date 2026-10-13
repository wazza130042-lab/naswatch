"""Cached data-store accessors shared across the UI."""
from __future__ import annotations

import streamlit as st

from naswatch.storage.factory import get_db_path
from naswatch.storage.sqlite_repo import SQLiteRepository


@st.cache_resource
def get_repository(db_path: str | None = None) -> SQLiteRepository:
    return SQLiteRepository(db_path=db_path or get_db_path())


def get_user_store():
    try:
        from naswatch.auth.users import UserStore
        return UserStore(db_path=get_db_path())
    except Exception:
        return None
