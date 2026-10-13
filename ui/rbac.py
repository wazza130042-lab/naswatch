"""UI access control — single source of truth for role permissions."""
from __future__ import annotations

import streamlit as st


ROLE_PERMISSIONS = {
    "admin":   {"view", "replay", "inject", "mitigate", "provision", "clear", "seed", "users"},
    "analyst": {"view", "replay", "mitigate"},
    "viewer":  {"view"},
}

ROLE_DESCRIPTIONS = {
    "admin":   "Full control of detections, subscribers, and operator accounts.",
    "analyst": "Investigate incidents, replay traffic, and launch response actions.",
    "viewer":  "Read-only access to dashboards, incidents, and inventory.",
}


def get_role() -> str:
    """Return the signed-in operator's role, failing safe to the lowest role."""
    user = st.session_state.get("user")
    role = (user or {}).get("role", "viewer")
    return role if role in ROLE_PERMISSIONS else "viewer"


def has(action: str) -> bool:
    """True when the current role grants `action` (see ROLE_PERMISSIONS)."""
    return action in ROLE_PERMISSIONS.get(get_role(), set())

