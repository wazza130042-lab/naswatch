"""
OIDC (OpenID Connect) provider integration for NASWatch enterprise SSO.

Validates identity tokens issued by an external identity provider (Keycloak,
Entra ID, Okta, Auth0, ...) via OpenID discovery + JWKS, then provisions or
updates a NASWatch operator account mapped from the token claims.

Environment:
    NASWATCH_OIDC_ISSUER      e.g. https://idp.example.com/realms/naswatch
    NASWATCH_OIDC_CLIENT_ID   OIDC client (audience) that the API belongs to
    NASWATCH_OIDC_CLIENT_SECRET  (optional) used only when introspection is needed
    NASWATCH_OIDC_ADMIN_ROLES comma-separated role/group names that map to ADMIN
    NASWATCH_OIDC_ROLE_CLAIM  claim carrying roles/groups (default: groups)
    NASWATCH_OIDC_TENANT_CLAIM claim carrying the tenant org_id (default: org_id)
    NASWATCH_OIDC_ENFORCED    "true" disables password login (SSO-only org)
"""

from __future__ import annotations

import os
import secrets
from typing import Any

import httpx

from naswatch.logging_config import get_logger

logger = get_logger("auth.oidc")

try:
    import jwt as _pyjwt
except ImportError:
    _pyjwt = None


class OIDCProvider:
    """Client for validating OIDC identity tokens against an external IdP."""

    def __init__(
        self,
        issuer: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        admin_roles: str | None = None,
        role_claim: str | None = None,
        org_claim: str | None = None,
    ) -> None:
        self.issuer = (issuer or os.environ.get("NASWATCH_OIDC_ISSUER") or "").rstrip("/")
        self.client_id = client_id or os.environ.get("NASWATCH_OIDC_CLIENT_ID") or ""
        self.client_secret = client_secret or os.environ.get("NASWATCH_OIDC_CLIENT_SECRET") or ""
        self.admin_roles = {r.strip() for r in (admin_roles or os.environ.get("NASWATCH_OIDC_ADMIN_ROLES", "")).split(",") if r.strip()}
        self.role_claim = role_claim or os.environ.get("NASWATCH_OIDC_ROLE_CLAIM", "groups")
        self.org_claim = org_claim or os.environ.get("NASWATCH_OIDC_TENANT_CLAIM", "org_id")
        self.enabled = bool(self.issuer and self.client_id)
        self._config: dict[str, Any] | None = None
        self._jwks_cache: dict[str, Any] = {}

    def public_config(self) -> dict[str, Any]:
        """Non-secret metadata the UI can use to render a 'Sign in with SSO' button."""
        return {
            "enabled": self.enabled,
            "issuer": self.issuer,
            "client_id": self.client_id,
            "enforced": self.enforced,
        }

    @property
    def enforced(self) -> bool:
        return os.environ.get("NASWATCH_OIDC_ENFORCED", "false").lower() == "true"

    def _discover(self) -> dict[str, Any]:
        if self._config is not None:
            return self._config
        resp = httpx.get(f"{self.issuer}/.well-known/openid-configuration", timeout=10)
        resp.raise_for_status()
        self._config = resp.json()
        return self._config

    def validate_id_token(self, id_token: str) -> dict[str, Any]:
        """Verify signature, issuer, audience and expiry; return claims."""
        if not self.enabled:
            raise ValueError("OIDC is not configured.")
        config = self._discover()
        jwks_uri = config.get("jwks_uri")
        if not jwks_uri:
            raise ValueError("IdP discovery did not expose a jwks_uri.")

        if _pyjwt is not None:
            keys = _pyjwt.PyJWKClient(jwks_uri)
            signing_key = keys.get_signing_key_from_jwt(id_token)
            claims = _pyjwt.decode(
                id_token,
                signing_key.key,
                algorithms=["RS256", "RS384", "RS512", "ES256", "ES384"],
                audience=self.client_id or None,
                issuer=config.get("issuer") or self.issuer or None,
                options={"verify_aud": bool(self.client_id)},
            )
        else:
            claims = self._validate_with_jose(id_token, jwks_uri, config)
        return claims

    def _validate_with_jose(self, id_token: str, jwks_uri: str, config: dict[str, Any]) -> dict[str, Any]:
        from jose import jwt as jose_jwt

        header = jose_jwt.get_unverified_header(id_token)
        jwks = self._fetch_jwks(jwks_uri)
        key = next((k for k in jwks if k.get("kid") == header.get("kid")), None)
        if not key:
            raise ValueError("No matching JWK for token key id.")
        return jose_jwt.decode(
            id_token,
            key,
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384"],
            audience=self.client_id or None,
            issuer=config.get("issuer") or self.issuer or None,
            options={"verify_aud": bool(self.client_id)},
        )

    def _fetch_jwks(self, jwks_uri: str) -> list[dict[str, Any]]:
        resp = httpx.get(jwks_uri, timeout=10)
        resp.raise_for_status()
        return resp.json().get("keys", [])

    def _role_value(self, claims: dict[str, Any]) -> str:
        """Map the token's role/groups claim to a NASWatch role."""
        raw = claims.get(self.role_claim)
        if isinstance(raw, dict):
            members: list[str] = []
            for v in raw.values():
                members.extend([str(x) for x in v] if isinstance(v, list) else [str(v)])
        elif isinstance(raw, list):
            members = [str(x) for x in raw]
        elif raw:
            members = [str(x) for x in str(raw).split(",")]
        else:
            members = []
        lowered = {m.lower() for m in members}
        if lowered & {r.lower() for r in self.admin_roles}:
            return "admin"
        return os.environ.get("NASWATCH_OIDC_DEFAULT_ROLE", "viewer")

    def claims_to_user(self, store, claims: dict[str, Any]):
        """Upsert a NASWatch user derived from validated OIDC claims."""
        from naswatch.storage.models import UserRole

        username = str(claims.get("preferred_username") or claims.get("email") or claims.get("sub"))
        if "@" not in username:
            email = claims.get("email")
            username = email or f"{username}@{self.issuer.split('//')[-1].split('/')[0]}"
        org_id = str(claims.get(self.org_claim) or "default")
        role = UserRole(self._role_value(claims))

        user = store.get_by_username(username)
        if user:
            if user.org_id != org_id:
                store.update_user(user.id, role=role)
            return user
        password = secrets.token_urlsafe(24)  # SSO users have no local password flow
        user = store.create_user(username=username, password=password, role=role, org_id=org_id)
        logger.info("Provisioned OIDC user '%s' role=%s org=%s", username, role.value, org_id)
        return user


def get_oidc_provider() -> OIDCProvider:
    return OIDCProvider()
