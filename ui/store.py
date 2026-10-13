"""Cached data-store accessors shared across the UI."""
from __future__ import annotations

import streamlit as st

from naswatch.storage.sqlite_repo import SQLiteRepository


@st.cache_resource
def get_repository(db_path: str = "data/inventory.db") -> SQLiteRepository:
    return SQLiteRepository(db_path=db_path)


def get_user_store():
    try:
        from naswatch.auth.users import UserStore
        return UserStore(db_path="data/inventory.db")
    except Exception:
        return None
