"""Cached data-store accessors shared across the UI."""
from __future__ import annotations

from typing import Any

import streamlit as st

from naswatch.storage.factory import (
    create_refresh_token_store,
    create_repository,
    create_user_store,
    get_db_path,
    get_db_url,
)
from naswatch.storage.sqlite_repo import SQLiteRepository


@st.cache_resource
def get_repository(db_path: str | None = None) -> Any:
    if db_path is not None:
        return SQLiteRepository(db_path=db_path)
    return create_repository()


def get_user_store():
    try:
        return create_user_store()
    except Exception:
        return None


@st.cache_resource
def get_audit_store():
    """Open the shared audit store for the authorized audit-review page."""
    from naswatch.audit.logger import AuditLogger

    db_url = get_db_url()
    return AuditLogger(db_path=get_db_path() if not db_url else None, db_url=db_url)


def log_ui_action(user: dict, action: str, resource: str, details: dict | None = None) -> str | None:
    """Write a UI-originated security action to the shared tenant audit trail.

    Returns an error string when the action could not be recorded so callers
    can surface the audit failure instead of silently claiming complete logs.
    """
    try:
        get_audit_store().log(
            actor=user.get("username", "unknown"),
            action=action,
            resource=resource,
            details=details or {},
            org_id=user.get("org_id", "default"),
        )
    except Exception as exc:
        message = f"The change completed, but its audit record could not be saved: {exc}"
        try:
            st.session_state["_audit_warning"] = message
        except Exception:
            pass
        return message
    return None


def revoke_user_sessions(user_id: str) -> None:
    """Revoke persisted refresh sessions after a credential or factor reset."""
    try:
        create_refresh_token_store().revoke_all_for_user(user_id)
    except Exception:
        # Do not silently pretend a reset succeeded when its session cleanup failed.
        raise
