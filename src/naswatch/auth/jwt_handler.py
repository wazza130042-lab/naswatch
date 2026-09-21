"""
JWT token creation and validation for NASWatch enterprise API.
HS256 signed tokens with configurable expiry using PyJWT and bcrypt/hashlib.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import UTC, datetime, timedelta
from typing import Optional

from fastapi import HTTPException, status

try:
    import jwt
    _HAS_PYJWT = True
except ImportError:
    _HAS_PYJWT = False

try:
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    _HAS_PASSLIB = True
except ImportError:
    _HAS_PASSLIB = False

SECRET_KEY: str = os.environ.get("NASWATCH_JWT_SECRET", "CHANGE-THIS-TO-A-RANDOM-256-BIT-KEY-IN-PRODUCTION")
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
) -> dict:
    claims = {
        "sub": subject,
        "role": role,
        "org_id": org_id,
        "type": token_type,
        "iat": datetime.now(UTC),
    }
    if user_id:
        claims["user_id"] = user_id
    if jti:
        claims["jti"] = jti
    return claims


def _encode(payload: dict) -> str:
    """Encode a payload as a JWT (PyJWT when available, pure-Python fallback otherwise)."""
    if _HAS_PYJWT:
        return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    import base64
    import json

    header_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload, default=str).encode()).decode().rstrip("=")
    sig = hmac.new(SECRET_KEY.encode(), f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def create_access_token(
    subject: str,
    role: str,
    org_id: str,
    expires_delta: Optional[timedelta] = None,
    user_id: str | None = None,
) -> str:
    """Create a short-lived JWT access token."""
    expire = datetime.now(UTC) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = _jwt_claims(subject, role, org_id, "access", user_id, None)
    payload["exp"] = expire
    if _HAS_PYJWT:
        return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    payload["exp"] = int(expire.timestamp())
    payload["iat"] = int(payload["iat"].timestamp())
    return _encode(payload)


def create_refresh_token(subject: str, role: str, org_id: str, user_id: str | None = None) -> str:
    """Create a long-lived JWT refresh token carrying a unique jti for rotation/revocation."""
    expire = datetime.now(UTC) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    jti = secrets.token_urlsafe(32)
    payload = _jwt_claims(subject, role, org_id, "refresh", user_id, jti)
    payload["exp"] = expire
    if _HAS_PYJWT:
        return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    payload["exp"] = int(expire.timestamp())
    payload["iat"] = int(payload["iat"].timestamp())
    return _encode(payload)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token. Raises HTTP 401 on failure."""
    try:
        if _HAS_PYJWT:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload
        import base64
        import json
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Malformed token")
        header_b64, payload_b64, sig_b64 = parts
        sig = hmac.new(SECRET_KEY.encode(), f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
        pad = "=" * ((4 - len(sig_b64) % 4) % 4)
        expected_sig = base64.urlsafe_b64decode(sig_b64 + pad)
        if not hmac.compare_digest(sig, expected_sig):
            raise ValueError("Signature mismatch")
        payload_pad = "=" * ((4 - len(payload_b64) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + payload_pad))
        if payload.get("exp") and datetime.now(UTC).timestamp() > payload["exp"]:
            raise ValueError("Token expired")
        return payload
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
