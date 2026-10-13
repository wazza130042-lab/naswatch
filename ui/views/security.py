"""NASWatch UI — account security (authenticator-app / TOTP enrollment).

Every signed-in operator can arm their own second factor here. It is rendered
from the settings menu in the command bar, so analysts and viewers can secure
their accounts without the User-management permission.
"""
from __future__ import annotations

import io
import os
from datetime import UTC, datetime

import streamlit as st

from naswatch.auth import totp
from ui.store import get_user_store

_ISSUER = os.environ.get("NASWATCH_TOTP_ISSUER", "NASWatch")


def _qr_png(uri: str) -> bytes | None:
    """Render ``uri`` as a PNG QR code, or return None when segno is absent."""
    try:
        import segno
    except Exception:  # pragma: no cover - optional dependency
        return None
    try:
        buffer = io.BytesIO()
        segno.make(uri, error="m").save(buffer, kind="png", scale=6, border=2)
        return buffer.getvalue()
    except Exception:  # pragma: no cover - defensive
        return None


def _pending_secret(user_id: str) -> str:
    """Return (and cache) the secret being enrolled for this operator."""
    secret = st.session_state.get("_totp_enroll_secret")
    if not secret or st.session_state.get("_totp_enroll_uid") != user_id or not totp.is_valid_secret(secret):
        secret = totp.generate_secret()
        st.session_state["_totp_enroll_secret"] = secret
        st.session_state["_totp_enroll_uid"] = user_id
    return secret


def _clear_pending() -> None:
    st.session_state.pop("_totp_enroll_secret", None)
    st.session_state.pop("_totp_enroll_uid", None)


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
        _render_enrollment(account)


def _render_enrollment(account) -> None:
    secret = _pending_secret(account.id)
    uri = totp.provisioning_uri(secret, account.username, issuer=_ISSUER)
    remaining = totp.seconds_remaining()
    server_time = datetime.now(UTC).strftime("%H:%M:%S")

    st.markdown(
        '<div class="queue-heading"><h3>Set up two-factor authentication</h3>'
        '<span>authenticator app</span></div>',
        unsafe_allow_html=True,
    )
    st.caption(
        "1. Scan the QR code (or type the setup key) in Google Authenticator, Authy, "
        "Microsoft Authenticator, 1Password or Bitwarden. 2. Enter the 6-digit code to confirm."
    )

    qr_col, key_col = st.columns([1, 1.6])
    with qr_col:
        png = _qr_png(uri)
        if png:
            st.image(png, caption="Scan with your authenticator app", width=220)
        else:
            st.info("QR rendering unavailable — use the setup key instead.")

    with key_col:
        st.markdown("**Setup key (enter manually if you can't scan)**")
        st.code(totp.format_secret(secret), language=None)
        st.markdown("**otpauth:// setup link**")
        st.code(uri, language=None)
        st.caption(
            f"Account: {account.username} · Server time {server_time} UTC · "
            f"{remaining}s left in this step. Codes are 6 digits and change every 30s; "
            "keep this appliance's clock in sync (NTP)."
        )

    with st.form("totp_enroll_form", clear_on_submit=True):
        code = st.text_input(
            "Enter the 6-digit code from your app to confirm",
            max_chars=6,
            placeholder="123456",
            autocomplete="one-time-code",
        )
        submitted = st.form_submit_button("Enable two-factor authentication", type="primary", use_container_width=True)

    if submitted:
        if totp.verify(secret, code):
            store = get_user_store()
            store.set_totp_secret(account.id, secret)
            store.enable_totp(account.id)
            _clear_pending()
            st.toast("Two-factor authentication enabled.")
            st.rerun()
        else:
            st.error("That code didn't match. Check the app and try the current code again.")

    if st.button("Regenerate setup key", key="totp_regen"):
        _clear_pending()
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

    with st.expander("Turn off two-factor authentication"):
        st.caption("Confirm with your account password to remove the second factor.")
        with st.form("totp_disable_form"):
            pw = st.text_input("Account password", type="password", key="totp_disable_pw")
            confirmed = st.form_submit_button("Disable 2FA", use_container_width=True)
        if confirmed:
            if _password_ok(account, pw):
                store = get_user_store()
                store.disable_totp(account.id)
                _clear_pending()
                st.toast("Two-factor authentication disabled.")
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
