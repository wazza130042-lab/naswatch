"""NASWatch UI — account security (authenticator-app / TOTP enrollment).

Every signed-in operator can arm their own second factor here. It is rendered
from the settings menu in the command bar, so analysts and viewers can secure
their accounts without the User-management permission.
"""
from __future__ import annotations

import streamlit as st

from ui.store import get_user_store, log_ui_action, revoke_user_sessions
from ui.totp_enroll import clear_pending, render_enrollment


def render(ctx):
    user = ctx["user"]
    st.markdown(
        """
        <div class="page-head">
            <div>
                <div class="page-title">Security</div>
                <div class="page-sub">Protect this operator account with a time-based one-time password (authenticator app).</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    store = get_user_store()
    if store is None:
        st.error("Identity store is unavailable.")
        return
    account = store.get_by_id(user["id"])
    if account is None:
        st.error("Your operator account could not be loaded.")
        return

    if account.totp_enabled:
        _render_enabled(store, account)
    else:
        _render_enrollment(store, account)


def _render_enrollment(store, account) -> None:
    st.markdown(
        '<div class="queue-heading"><h3>Set up two-factor authentication</h3>'
        '<span>required</span></div>',
        unsafe_allow_html=True,
    )
    if render_enrollment(
        store,
        account,
        key_prefix="security",
        notice="This instance requires an authenticator app for every operator account.",
    ):
        st.toast("Two-factor authentication enabled.")
        st.rerun()


def _render_enabled(store, account) -> None:
    enrolled = account.totp_enrolled_at
    enrolled_txt = enrolled.strftime("%Y-%m-%d %H:%M") if enrolled else "—"
    updated = account.updated_at.strftime("%Y-%m-%d %H:%M")

    st.markdown(
        f'<div class="asset-kpis">'
        f'<div class="asset-kpi accent-cyan"><div>SECOND FACTOR</div><strong>ON</strong><small>authenticator app</small></div>'
        f'<div class="asset-kpi"><div>ACCOUNT</div><strong>{_short(account.username)}</strong><small>{account.role.value}</small></div>'
        f'<div class="asset-kpi"><div>ENROLLED</div><strong>{enrolled_txt.split(" ")[0]}</strong><small>{enrolled_txt.split(" ")[-1]} UTC</small></div>'
        f'</div>',
        unsafe_allow_html=True,
    )
    st.success(
        "Two-factor authentication is enabled for this account. Signing in now requires a "
        "code from your authenticator app, together with your password."
    )
    st.caption(f"Last changed {updated} UTC")

    with st.expander("Replace your authenticator app"):
        st.caption(
            "Two-factor authentication is required on this instance, so this clears the "
            "current secret and starts a fresh enrolment. Confirm with your password, then "
            "scan a new QR code on your new device."
        )
        with st.form("totp_disable_form"):
            pw = st.text_input("Account password", type="password", key="totp_disable_pw")
            confirmed = st.form_submit_button("Reset & enrol a new device", use_container_width=True)
        if confirmed:
            if _password_ok(account, pw):
                store = get_user_store()
                try:
                    store.disable_totp(account.id)
                    revoke_user_sessions(account.id)
                except Exception:
                    st.error("Could not safely reset the authenticator and revoke active sessions. Try again.")
                else:
                    audit_error = log_ui_action(
                        {"username": account.username, "org_id": account.org_id},
                        "user.totp.reset.self", account.id,
                    )
                    if audit_error:
                        st.error(f"Authenticator reset, but its audit record failed: {audit_error}")
                    clear_pending("security")
                    st.toast("Authenticator reset — enrol your new device.")
                    st.rerun()
            else:
                st.error("That password is incorrect.")


def _password_ok(account, password: str) -> bool:
    try:
        from naswatch.auth.jwt_handler import verify_password

        return bool(password) and verify_password(password, account.password_hash)
    except Exception:
        return False


def _short(value: str, limit: int = 18) -> str:
    text = value or ""
    return text if len(text) <= limit else text[: limit - 1] + "…"
