"""
Role-Based Access Control (RBAC) for NASWatch enterprise API.

Roles:
  admin   — full access: manage devices, view/mitigate alerts, manage users, API keys
  analyst — view alerts, trigger SOAR actions, download forensic reports
  viewer  — read-only: view alerts and device inventory
"""
from __future__ import annotations

from enum import Enum
from typing import Set

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from naswatch.auth.jwt_handler import decode_token


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


# Permission definitions per role
ROLE_PERMISSIONS: dict[str, Set[str]] = {
    Role.ADMIN: {
        "alerts:read", "alerts:mitigate",
        "devices:read", "devices:write", "devices:delete",
        "users:manage", "apikeys:manage",
        "ingest:write", "audit:read",
    },
    Role.ANALYST: {
        "alerts:read", "alerts:mitigate",
        "devices:read",
        "ingest:write",
    },
    Role.VIEWER: {
        "alerts:read",
        "devices:read",
    },
}

bearer_scheme = HTTPBearer(auto_error=True)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    """FastAPI dependency: decode Bearer token and return the user payload."""
    return decode_token(credentials.credentials)


def require_permission(permission: str):
    """
    FastAPI dependency factory.
    Usage: `user = Depends(require_permission('alerts:mitigate'))`
    """
    def _check(user: dict = Depends(get_current_user)) -> dict:
        role_str = user.get("role", "viewer")
        try:
            role = Role(role_str)
        except ValueError:
            role = Role.VIEWER
        if permission not in ROLE_PERMISSIONS.get(role, set()):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role_str}' does not have permission: '{permission}'.",
            )
        return user
    return _check
