"""Shared authenticator-app (TOTP) enrolment panel.

The forced first-login enrolment (`ui/login.py`), the in-console gate
(``ui/app.py``) and the voluntary Security page (``ui/views/security.py``)
all render the same QR / setup-key / confirm-code flow, so it lives here.

TOTP itself is stdlib-only (`naswatch.auth.totp`); the QR image is optional
(``segno``) and the flow degrades to a manual setup key when it is absent.
"""
from __future__ import annotations

import io
from datetime import UTC, datetime

import streamlit as st

from naswatch.auth import totp

# Issuer shown in the authenticator app entry, e.g. "NASWatch (admin@…)".
_ISSUER = "NASWatch"


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


def clear_pending(key_prefix: str = "totp") -> None:
    """Drop the in-progress (unconfirmed) secret for this enrolment context."""
    st.session_state.pop(f"_{key_prefix}_enroll_secret", None)
    st.session_state.pop(f"_{key_prefix}_enroll_uid", None)


def _pending_secret(user_id: str, key_prefix: str) -> str:
    """Return (and cache) the secret being enrolled for this operator."""
    key = f"_{key_prefix}_enroll_secret"
    owner = f"_{key_prefix}_enroll_uid"
    secret = st.session_state.get(key)
    if not secret or st.session_state.get(owner) != user_id or not totp.is_valid_secret(secret):
        secret = totp.generate_secret()
        st.session_state[key] = secret
        st.session_state[owner] = user_id
    return secret


def render_enrollment(
    store,
    account,
    *,
    key_prefix: str = "totp",
    submit_label: str = "Enable two-factor authentication",
    notice: str | None = None,
    regenerate_label: str = "Regenerate setup key",
) -> bool:
    """Render the QR / setup-key / confirm-code panel.

    Returns ``True`` on the run where the operator proved a code and the factor
    was armed; the caller then decides whether to sign in, rerun or toast.
    """
    secret = _pending_secret(account.id, key_prefix)
    uri = totp.provisioning_uri(secret, account.username, issuer=_ISSUER)
    remaining = totp.seconds_remaining()
    server_time = datetime.now(UTC).strftime("%H:%M:%S")

    with st.container(key=f"{key_prefix}-enrollment", border=True):
        st.markdown("### Set up your authenticator")
        if notice:
            st.info(notice, icon=":material/lock:")

        st.markdown(
            "1. Open an authenticator app and choose **Add account**.  "
            "2. Scan the QR code, or enter the setup key manually.  "
            "3. Enter the app's current six-digit code below."
        )
        st.caption(
            "Works with Google Authenticator, Microsoft Authenticator, Authy, "
            "1Password, and other TOTP apps."
        )

        png = _qr_png(uri)
        if png:
            st.image(png, caption="Scan this code in your authenticator app", width=200)
        else:
            st.warning("QR display is unavailable. Enter the setup key manually.")
        st.markdown("**Manual setup key**")
        st.code(secret, language=None, wrap_lines=True)
        st.caption(
            f"NASWatch server time: {server_time} UTC · code changes in {remaining}s. "
            "Keep your phone's date and time set automatically."
        )
        # The URI is useful for troubleshooting but too long to read inline.
        # Keep it available on demand without crowding the normal setup flow.
        with st.expander("Advanced setup details"):
            st.caption("Use this only if your authenticator supports provisioning links.")
            st.code(uri, language=None, wrap_lines=True)

        with st.form(f"{key_prefix}_enroll_form", clear_on_submit=True):
            code = st.text_input(
                "Verification code",
                max_chars=6,
                placeholder="Enter the 6-digit code from your app",
                autocomplete="one-time-code",
            )
            submitted = st.form_submit_button(submit_label, type="primary", use_container_width=True)

    enabled = False
    if submitted:
        if not totp.verify(secret, code):
            st.error("That code didn't match. Check the app and try the current code again.")
        else:
            try:
                enabled = store.complete_totp_enrollment(account.id, secret, code)
            except Exception:
                st.error("Could not save two-factor setup. Your account is unchanged; please try again.")
            else:
                if enabled:
                    from ui.store import log_ui_action

                    audit_error = log_ui_action(
                        {"username": account.username, "org_id": account.org_id},
                        "user.totp.enroll", account.id,
                    )
                    if audit_error:
                        st.error(f"Two-factor setup completed, but its audit record failed: {audit_error}")
                    clear_pending(key_prefix)
                else:
                    st.error("This account is no longer active. Ask an administrator to restore access.")

    if st.button(regenerate_label, key=f"{key_prefix}_regen"):
        clear_pending(key_prefix)
        st.rerun()

    return enabled
