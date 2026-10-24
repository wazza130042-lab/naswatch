"""Live password-strength feedback for the dashboard account forms.

Wraps :mod:`naswatch.auth.password_policy` so the first-run setup, the User
management *create account* form and the *reset password* form all render the
same meter and the same wording as the API's 422 responses.
"""

from __future__ import annotations

from html import escape

import streamlit as st

from naswatch.auth.password_policy import PasswordStrength, evaluate

# Score 0..4 -> bar colour. Keep in step with the SOC palette.
_COLORS = {
    0: "#EF4444",  # red
    1: "#F97316",  # orange
    2: "#EAB308",  # amber
    3: "#22D3EE",  # cyan
    4: "#34D399",  # green
}

_HINT = "At least 12 characters, mixing letters, numbers and symbols."


def meter_html(strength: PasswordStrength) -> str:
    """Return the HTML bar + label + guidance for ``strength``."""
    color = _COLORS.get(strength.score, _COLORS[0])
    filled = max(0, min(4, strength.score))
    font = "font:11px/1.4 'JetBrains Mono',monospace;"

    bars = []
    for i in range(4):
        background = color if i < filled else "#1E3A5F"
        bars.append(
            f'<span style="flex:1;height:4px;border-radius:2px;background:{background};"></span>'
        )

    parts = [
        '<div style="margin:6px 0 2px;display:flex;gap:5px;align-items:center;">',
        "".join(bars),
        "</div>",
        f'<div style="{font}color:{color};">strength: {escape(strength.label)}</div>',
    ]
    if strength.problems:
        items = "".join(f"<li>{escape(p)}</li>" for p in strength.problems)
        parts.append(
            f'<ul style="margin:2px 0 0;padding-left:16px;color:#F87171;{font}">{items}</ul>'
        )
    elif strength.suggestions:
        items = "".join(f"<li>{escape(s)}</li>" for s in strength.suggestions)
        parts.append(
            f'<ul style="margin:2px 0 0;padding-left:16px;color:#FBBF24;{font}">{items}</ul>'
        )
    return "".join(parts)


def render_password_strength(
    password: str | None,
    *,
    username: str | None = None,
    container=None,
) -> PasswordStrength:
    """Render a live strength meter for ``password`` and return the evaluation.

    Call this on every rerun directly under the password field. When the field
    is empty it shows the policy hint instead of a misleading "very weak" bar.
    """
    strength = evaluate(password, username=username)
    target = container if container is not None else st
    if not password:
        hint_style = "margin:6px 0 2px;font:11px/1.4 'JetBrains Mono',monospace;color:#6F93BF;"
        target.markdown(f'<div style="{hint_style}">{_HINT}</div>', unsafe_allow_html=True)
    else:
        target.markdown(meter_html(strength), unsafe_allow_html=True)
    return strength
