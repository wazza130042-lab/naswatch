"""
Role-Based Access Control (RBAC) for NASWatch enterprise API.

Roles:
  admin   — system administration and security operations
  analyst — incident investigation and response
  viewer  — dashboard and sanitized incident summaries
  auditor — tenant audit records and individual record-signature checks
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
    AUDITOR = "auditor"


# Permission definitions per role
ROLE_PERMISSIONS: dict[str, Set[str]] = {
    Role.ADMIN: {
        "dashboard:read", "alerts:read", "alerts:evidence", "alerts:mitigate",
        "devices:read", "devices:sensitive", "devices:write", "devices:delete",
        "users:manage", "apikeys:manage", "ingest:write", "audit:read",
        "audit:verify", "reports:export",
    },
    Role.ANALYST: {
        "dashboard:read", "alerts:read", "alerts:evidence", "alerts:mitigate",
        "devices:read", "devices:sensitive", "ingest:write", "reports:export",
    },
    Role.VIEWER: {
        "dashboard:read", "alerts:read",
    },
    Role.AUDITOR: {
        "audit:read",
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
