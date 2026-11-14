"""
NASWatch License Key Validation.

License format: NW-{TIER}-{BASE64_PAYLOAD}-{HMAC_SIGNATURE}

Tiers: COMMUNITY (free), PROFESSIONAL, ENTERPRISE
Features are gated by tier.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
from datetime import UTC, datetime
from enum import Enum
from typing import Any

logger = logging.getLogger("naswatch.licensing")

# The signing secret has NO built-in default. A secret that is published in the source code is
# not a secret: anyone could mint an ENTERPRISE key. Without NASWATCH_LICENSE_SECRET the
# validator fails closed (every key is rejected -> COMMUNITY tier) and keys cannot be generated.
#
# The previous default is rejected explicitly, so a deployment that still sets it cannot be
# forged from the public source either.
_MIN_SECRET_BYTES = 32
_KNOWN_PUBLIC_SECRETS = {"naswatch-signing-secret-v1"}


def _signing_secret() -> bytes | None:
    """Return the license signing secret, or None when it is missing or unusable."""
    secret = os.environ.get("NASWATCH_LICENSE_SECRET", "").strip()
    if not secret or secret in _KNOWN_PUBLIC_SECRETS or len(secret.encode("utf-8")) < _MIN_SECRET_BYTES:
        return None
    return secret.encode("utf-8")


class LicenseTier(str, Enum):
    COMMUNITY = "COMMUNITY"
    PROFESSIONAL = "PROFESSIONAL"
    ENTERPRISE = "ENTERPRISE"


# Feature flags per tier
TIER_FEATURES: dict[str, list[str]] = {
    LicenseTier.COMMUNITY: [
        "detection:basic",          # Rules 1-3
        "dashboard:basic",
        "alerts:export_json",
    ],
    LicenseTier.PROFESSIONAL: [
        "detection:basic",
        "detection:advanced",       # Rules 4-6
        "dashboard:basic",
        "dashboard:advanced",
        "alerts:export_json",
        "api:rest",
        "soar:basic",
        "integrations:pagerduty",
        "integrations:splunk",
    ],
    LicenseTier.ENTERPRISE: [
        "detection:basic",
        "detection:advanced",
        "dashboard:basic",
        "dashboard:advanced",
        "alerts:export_json",
        "api:rest",
        "api:multitenancy",
        "soar:basic",
        "soar:advanced",
        "integrations:pagerduty",
        "integrations:splunk",
        "integrations:sentinel",
        "audit:log",
        "correlation:engine",
        "support:sla",
    ],
}


def generate_license_key(org_name: str, tier: str, seats: int, expires: str | None = None) -> str:
    """
    Generate a NASWatch license key (for use by the licensing server only).
    expires: ISO date string e.g. '2027-01-01' or None for perpetual.

    Raises RuntimeError if NASWATCH_LICENSE_SECRET is not set to a strong value (>= 32 bytes).
    Note: the signature is an HMAC, so every installation that can *validate* keys holds the
    secret and could also *issue* them. Keep generation on a machine you control and treat the
    secret as private; if keys are sold to third parties, switch to asymmetric signatures.
    """
    secret = _signing_secret()
    if secret is None:
        raise RuntimeError(
            "NASWATCH_LICENSE_SECRET must be set to a random value of at least 32 bytes "
            "(e.g. `openssl rand -hex 32`) before license keys can be generated."
        )
    payload = {
        "org": org_name,
        "tier": tier.upper(),
        "seats": seats,
        "expires": expires,
        "issued": datetime.now(UTC).date().isoformat(),
    }
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    sig = hmac.new(
        secret,
        f"{tier.upper()}:{payload_b64}".encode(),
        hashlib.sha256,
    ).hexdigest()[:32]
    return f"NW-{tier.upper()}-{payload_b64}-{sig}"


class LicenseInfo:
    """Parsed and validated license information."""

    def __init__(self, tier: LicenseTier, org: str, seats: int, expires: str | None, features: list[str]) -> None:
        self.tier = tier
        self.org = org
        self.seats = seats
        self.expires = expires
        self.features = features
        self.valid = True

    def has_feature(self, feature: str) -> bool:
        return feature in self.features

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier.value,
            "org": self.org,
            "seats": self.seats,
            "expires": self.expires or "perpetual",
            "features": self.features,
            "valid": self.valid,
        }


_COMMUNITY_LICENSE = LicenseInfo(
    tier=LicenseTier.COMMUNITY,
    org="Community",
    seats=1,
    expires=None,
    features=TIER_FEATURES[LicenseTier.COMMUNITY],
)


def validate_license(license_key: str | None) -> LicenseInfo:
    """
    Validate a NASWatch license key.
    Returns a LicenseInfo object. Falls back to COMMUNITY tier if invalid/missing.
    """
    if not license_key:
        logger.info("No license key provided — running in COMMUNITY tier.")
        return _COMMUNITY_LICENSE

    parts = license_key.strip().split("-", 3)
    if len(parts) != 4 or parts[0] != "NW":
        logger.warning("Invalid license key format.")
        return _COMMUNITY_LICENSE

    secret = _signing_secret()
    if secret is None:
        logger.warning(
            "NASWATCH_LICENSE_SECRET is not set (or is weak/public): license key rejected, "
            "running in COMMUNITY tier."
        )
        return _COMMUNITY_LICENSE

    _, tier_str, payload_b64, provided_sig = parts
    expected_sig = hmac.new(
        secret,
        f"{tier_str}:{payload_b64}".encode(),
        hashlib.sha256,
    ).hexdigest()[:32]

    if not hmac.compare_digest(expected_sig, provided_sig):
        logger.warning("License key signature verification FAILED.")
        return _COMMUNITY_LICENSE

    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode()))
    except Exception:
        return _COMMUNITY_LICENSE

    tier_str_upper = payload.get("tier", "COMMUNITY").upper()
    try:
        tier = LicenseTier(tier_str_upper)
    except ValueError:
        tier = LicenseTier.COMMUNITY

    # Check expiry
    expires = payload.get("expires")
    if expires:
        try:
            exp_date = datetime.strptime(expires, "%Y-%m-%d").replace(tzinfo=UTC)
            if datetime.now(UTC) > exp_date:
                logger.warning("License key EXPIRED on %s. Downgrading to COMMUNITY tier.", expires)
                return _COMMUNITY_LICENSE
        except Exception:
            pass

    logger.info("License validated: %s tier for org '%s'.", tier.value, payload.get("org"))
    return LicenseInfo(
        tier=tier,
        org=payload.get("org", "Unknown"),
        seats=payload.get("seats", 1),
        expires=expires,
        features=TIER_FEATURES.get(tier, TIER_FEATURES[LicenseTier.COMMUNITY]),
    )
