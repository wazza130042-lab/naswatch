"""UI helpers backed by the API's single authoritative permission map."""
from __future__ import annotations

import streamlit as st

from naswatch.auth.rbac import ROLE_PERMISSIONS as _ROLE_PERMISSIONS, Role


ROLE_LABELS = {
    "admin": "System administrator",
    "analyst": "SOC analyst",
    "viewer": "Read-only viewer",
    "auditor": "Audit reviewer",
}

ROLE_DESCRIPTIONS = {
    "admin": "Manage NASWatch accounts, API keys, subscriber inventory, system response, and audit records. This role has the broadest access; use it only for named system administrators.",
    "analyst": "Investigate incidents with full packet and subscriber evidence, replay captures, and take response actions on incidents they own. Cannot manage accounts, keys, or subscriber inventory.",
    "viewer": "Monitor overview metrics and incident summaries. Subscriber identifiers, packet evidence, exports, and SOC operations are restricted. Each operator can still manage their own login security.",
    "auditor": "Review this tenant’s audit trail and verify individual record signatures. Cannot view SOC incidents, subscriber data, manage users, or change system data.",
}

# Existing view names map to canonical API permission strings. This keeps UI
# visibility and server authorization tied to one policy source.
_UI_PERMISSION = {
    "view": "dashboard:read",
    "alerts": "alerts:read",
    "evidence": "alerts:evidence",
    "replay": "ingest:write",
    "mitigate": "alerts:mitigate",
    "provision": "devices:write",
    "inventory": "devices:sensitive",
    "reports": "reports:export",
    "users": "users:manage",
    "audit": "audit:read",
    "audit:verify": "audit:verify",
}


def get_role() -> str:
    """Return the signed-in operator's role, failing closed to viewer."""
    user = st.session_state.get("user")
    role = (user or {}).get("role", "viewer")
    return role if role in {item.value for item in Role} else "viewer"


def has(action: str) -> bool:
    """Check a UI capability using the canonical server-side role map."""
    permission = _UI_PERMISSION.get(action)
    if permission is None:
        return False
    try:
        role = Role(get_role())
    except ValueError:
        return False
    return permission in _ROLE_PERMISSIONS.get(role, set())
