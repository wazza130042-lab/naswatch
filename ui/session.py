"""Cookie-backed operator session persistence."""
from __future__ import annotations

from datetime import timedelta

import streamlit as st
import streamlit.components.v1 as components


SESSION_COOKIE = "naswatch_session"
SESSION_TTL_DAYS = 7


def _session_token(user: dict) -> str:
    """Mint a signed access token that identifies the signed-in operator."""
    from naswatch.auth.jwt_handler import create_access_token
    return create_access_token(
        subject=user["username"],
        role=user["role"],
        org_id=user["org_id"],
        user_id=user["id"],
        expires_delta=timedelta(days=SESSION_TTL_DAYS),
    )


def _write_session_cookie(token: str) -> None:
    """Persist the session token in a first-party cookie so a refresh keeps the
    operator signed in. This runs inside Streamlit's same-origin component iframe,
    which is the only place document.cookie can be written from Python."""
    components.html(
        "<script>document.cookie='"
        f"{SESSION_COOKIE}={token}; path=/; max-age={SESSION_TTL_DAYS * 24 * 3600}; SameSite=Lax"
        "';</script>",
        height=0,
        width=0,
    )


def _clear_session_cookie() -> None:
    """Drop the persisted session token (used on sign out)."""
    components.html(
        f"<script>document.cookie='{SESSION_COOKIE}=; path=/; max-age=0; SameSite=Lax';</script>",
        height=0,
        width=0,
    )


def sign_out() -> None:
    """Tear down the operator session (caller must call st.rerun()).

    Never restore the signed-out session again within this session, and defer the
    cookie clear to the next run so its clearing frame actually renders — an
    in-flight st.rerun() would cancel it.
    """
    st.session_state["_signed_out"] = True
    st.session_state["_clear_cookie_pending"] = True
    st.session_state.pop("_persist_session", None)
    # Drop the previous operator's password so it is never resubmitted.
    st.session_state.pop("login_password", None)
    st.session_state.pop("user", None)


def _restore_session() -> None:
    """Rebuild the signed-in user from the session cookie after a page refresh."""
    if "user" in st.session_state:
        return
    # st.context.cookies is a snapshot of the cookies sent with the *initial*
    # page request, so it keeps returning the signed-out token for the rest of
    # the session. Once an operator explicitly signs out we must never
    # resurrect that session again — otherwise the very next rerun (submitting
    # the login form) would silently sign them back in as the previous account.
    if st.session_state.get("_signed_out"):
        return
    try:
        token = st.context.cookies.get(SESSION_COOKIE)
    except Exception:
        token = None
    if not token:
        return
    try:
        from naswatch.auth.jwt_handler import decode_token
        payload = decode_token(token)
    except Exception:
        return
    if payload.get("type") != "access":
        return
    st.session_state["user"] = {
        "id": payload.get("user_id"),
        "username": payload.get("sub"),
        "role": payload.get("role"),
        "org_id": payload.get("org_id"),
    }
