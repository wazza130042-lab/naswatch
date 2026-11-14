"""
JWT token creation and validation for NASWatch enterprise API.
HS256 signed tokens with configurable expiry using PyJWT (a declared, required dependency)
and bcrypt/hashlib.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import UTC, datetime, timedelta
from typing import Optional

import jwt
from fastapi import HTTPException, status

try:
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    _HAS_PASSLIB = True
except ImportError:
    _HAS_PASSLIB = False

_CONFIGURED_SECRET = os.environ.get("NASWATCH_JWT_SECRET", "").strip()
_PLACEHOLDER_SECRETS = {
    "CHANGE-THIS-TO-A-RANDOM-256-BIT-KEY",
    "CHANGE-THIS-TO-A-RANDOM-256-BIT-KEY-IN-PRODUCTION",
    "replace-with-at-least-64-random-hex-characters",
}
_PRODUCTION = os.environ.get("NASWATCH_ENV", "development").lower() == "production"
if len(_CONFIGURED_SECRET.encode("utf-8")) >= 32 and _CONFIGURED_SECRET not in _PLACEHOLDER_SECRETS:
    SECRET_KEY: str = _CONFIGURED_SECRET
    # True when the key is a stable, operator-supplied secret (survives restarts).
    SECRET_IS_CONFIGURED: bool = True
elif _PRODUCTION:
    raise RuntimeError(
        "Production requires NASWATCH_JWT_SECRET with at least 32 non-placeholder bytes. "
        "Generate one with `openssl rand -hex 32`."
    )
else:
    # Never sign local tokens with a publicly known fallback. When no stable key
    # is configured, use a process-random key so an accidental dev deployment
    # cannot be forged from a published default. Sessions then expire on restart.
    import logging

    SECRET_KEY = secrets.token_urlsafe(48)
    SECRET_IS_CONFIGURED = False
    logging.getLogger("naswatch.auth").warning(
        "NASWATCH_JWT_SECRET is missing or weak; using a temporary process key. "
        "Set a stable random secret to preserve sessions across restarts."
    )
ALGORITHM: str = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.environ.get("NASWATCH_ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.environ.get("NASWATCH_REFRESH_TOKEN_EXPIRE_DAYS", "30"))


def hash_password(plain: str) -> str:
    """Return secure hash of plain-text password."""
    if _HAS_PASSLIB:
        return pwd_context.hash(plain)
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + plain).encode()).hexdigest()
    return f"sha256${salt}${hashed}"


def verify_password(plain: str, hashed: str) -> bool:
    """Verify plain-text password against stored hash."""
    if _HAS_PASSLIB and not hashed.startswith("sha256$"):
        try:
            return pwd_context.verify(plain, hashed)
        except Exception:
            pass
    if hashed.startswith("sha256$"):
        parts = hashed.split("$")
        if len(parts) == 3:
            salt, stored_hash = parts[1], parts[2]
            computed = hashlib.sha256((salt + plain).encode()).hexdigest()
            return hmac.compare_digest(computed, stored_hash)
    return False


def _jwt_claims(
    subject: str,
    role: str,
    org_id: str,
    token_type: str,
    user_id: str | None,
    jti: str | None,
    auth_method: str = "password",
) -> dict:
    claims = {
        "sub": subject,
        "role": role,
        "org_id": org_id,
        "type": token_type,
        "iat": datetime.now(UTC),
        "auth_method": auth_method,
    }
    if user_id:
        claims["user_id"] = user_id
    if jti:
        claims["jti"] = jti
    return claims


def _encode(payload: dict) -> str:
    """Encode a payload as an HS256 JWT."""
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_access_token(
    subject: str,
    role: str,
    org_id: str,
    expires_delta: Optional[timedelta] = None,
    user_id: str | None = None,
    auth_method: str = "password",
) -> str:
    """Create a short-lived JWT access token."""
    expire = datetime.now(UTC) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = _jwt_claims(subject, role, org_id, "access", user_id, None, auth_method)
    payload["exp"] = expire
    return _encode(payload)


def create_refresh_token(
    subject: str,
    role: str,
    org_id: str,
    user_id: str | None = None,
    auth_method: str = "password",
) -> str:
    """Create a long-lived JWT refresh token carrying a unique jti for rotation/revocation."""
    expire = datetime.now(UTC) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    jti = secrets.token_urlsafe(32)
    payload = _jwt_claims(subject, role, org_id, "refresh", user_id, jti, auth_method)
    payload["exp"] = expire
    return _encode(payload)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token. Raises HTTP 401 on failure."""
    try:
        return jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"require": ["exp", "sub"]},
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
