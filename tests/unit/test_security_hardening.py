"""
Regression tests for the security review findings:

  * License signing secret has no public default (fail closed)
  * JWT handling uses the declared PyJWT dependency and rejects bad tokens
  * The audit hash-chain key is stable across restarts
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from datetime import UTC, datetime, timedelta

import jwt as pyjwt
import pytest
from fastapi import HTTPException

from naswatch.audit import logger as audit_logger
from naswatch.auth import jwt_handler
from naswatch.licensing import validator
from naswatch.licensing.validator import (
    LicenseTier,
    generate_license_key,
    validate_license,
)

GOOD_SECRET = "unit-test-license-secret-" + "a" * 24
OLD_PUBLIC_SECRET = "naswatch-signing-secret-v1"


def _forge(secret: str, tier: str = "ENTERPRISE") -> str:
    """Build a key exactly the way the validator expects, using an arbitrary secret."""
    payload = {"org": "Attacker", "tier": tier, "seats": 9999, "expires": None, "issued": "2026-01-01"}
    b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    sig = hmac.new(secret.encode(), f"{tier}:{b64}".encode(), hashlib.sha256).hexdigest()[:32]
    return f"NW-{tier}-{b64}-{sig}"


# --------------------------------------------------------------------------- license
def test_license_roundtrip_with_a_configured_secret(monkeypatch):
    monkeypatch.setenv("NASWATCH_LICENSE_SECRET", GOOD_SECRET)
    info = validate_license(generate_license_key("Acme", "ENTERPRISE", 5))
    assert info.tier == LicenseTier.ENTERPRISE and info.org == "Acme"


def test_key_forged_with_the_old_public_secret_is_rejected(monkeypatch):
    # The attack that worked before: read the default secret from the source and mint a key.
    forged = _forge(OLD_PUBLIC_SECRET)
    monkeypatch.setenv("NASWATCH_LICENSE_SECRET", GOOD_SECRET)
    assert validate_license(forged).tier == LicenseTier.COMMUNITY
    # ...and it must not work even if a deployment is (still) configured with the old default.
    monkeypatch.setenv("NASWATCH_LICENSE_SECRET", OLD_PUBLIC_SECRET)
    assert validate_license(forged).tier == LicenseTier.COMMUNITY


def test_missing_secret_fails_closed(monkeypatch):
    monkeypatch.setenv("NASWATCH_LICENSE_SECRET", GOOD_SECRET)
    key = generate_license_key("Acme", "ENTERPRISE", 5)
    monkeypatch.delenv("NASWATCH_LICENSE_SECRET")
    assert validate_license(key).tier == LicenseTier.COMMUNITY
    with pytest.raises(RuntimeError):
        generate_license_key("Acme", "ENTERPRISE", 5)


def test_weak_secret_is_refused(monkeypatch):
    monkeypatch.setenv("NASWATCH_LICENSE_SECRET", "short")
    with pytest.raises(RuntimeError):
        generate_license_key("Acme", "ENTERPRISE", 5)
    assert validate_license(_forge("short")).tier == LicenseTier.COMMUNITY


def test_expired_and_tampered_keys_still_fall_back(monkeypatch):
    monkeypatch.setenv("NASWATCH_LICENSE_SECRET", GOOD_SECRET)
    expired = generate_license_key("Acme", "ENTERPRISE", 5, expires="2020-01-01")
    assert validate_license(expired).tier == LicenseTier.COMMUNITY
    good = generate_license_key("Acme", "ENTERPRISE", 5)
    assert validate_license(good[:-4] + "FFFF").tier == LicenseTier.COMMUNITY


def test_no_default_secret_is_baked_into_the_module():
    import re

    source = open(validator.__file__, encoding="utf-8").read()
    # No fallback value: an empty default is fine, a non-empty literal is a baked-in secret.
    assert not re.search(r'NASWATCH_LICENSE_SECRET"\s*,\s*"[^"]', source)
    assert not hasattr(validator, "LICENSE_SIGNING_SECRET")


# --------------------------------------------------------------------------- JWT
def _claims(**over):
    now = datetime.now(UTC)
    base = {"sub": "alice", "role": "admin", "org_id": "default", "type": "access",
            "iat": now, "exp": now + timedelta(minutes=5)}
    base.update(over)
    return base


def test_pyjwt_is_the_implementation_and_roundtrips():
    token = jwt_handler.create_access_token("alice", "analyst", "org1")
    claims = jwt_handler.decode_token(token)
    assert claims["sub"] == "alice" and claims["role"] == "analyst" and claims["type"] == "access"
    # Standard library-verifiable: a stock PyJWT call accepts it.
    assert pyjwt.decode(token, jwt_handler.SECRET_KEY, algorithms=["HS256"])["org_id"] == "org1"


def test_tampered_expired_and_alg_none_tokens_are_rejected():
    good = jwt_handler.create_access_token("alice", "admin", "org1")
    head, body, sig = good.split(".")
    for bad in (
        f"{head}.{body}.{sig[:-3]}AAA",                                   # bad signature
        pyjwt.encode(_claims(exp=datetime.now(UTC) - timedelta(minutes=1)),
                     jwt_handler.SECRET_KEY, algorithm="HS256"),          # expired
        pyjwt.encode(_claims(), "some-other-key-" + "x" * 32, algorithm="HS256"),  # wrong key
        pyjwt.encode(_claims(), "", algorithm="none"),                    # alg=none
        "not.a.token",
        "",
    ):
        with pytest.raises(HTTPException) as exc:
            jwt_handler.decode_token(bad)
        assert exc.value.status_code == 401


def test_token_without_expiry_is_rejected():
    no_exp = pyjwt.encode({"sub": "alice", "type": "access"}, jwt_handler.SECRET_KEY, algorithm="HS256")
    with pytest.raises(HTTPException):
        jwt_handler.decode_token(no_exp)


def test_pyjwt_is_declared_as_a_dependency():
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[2]
    assert "pyjwt" in (root / "requirements.txt").read_text().lower()
    assert "pyjwt" in (root / "pyproject.toml").read_text().lower()


# --------------------------------------------------------------------------- audit key
@pytest.fixture
def fresh_key(monkeypatch):
    audit_logger._audit_key.cache_clear()
    for var in ("NASWATCH_AUDIT_KEY", "NASWATCH_AUDIT_KEY_FILE"):
        monkeypatch.delenv(var, raising=False)
    yield
    audit_logger._audit_key.cache_clear()


def test_explicit_audit_key_wins_and_must_be_strong(monkeypatch, fresh_key):
    monkeypatch.setenv("NASWATCH_AUDIT_KEY", "k" * 40)
    assert audit_logger._audit_key() == b"k" * 40
    audit_logger._audit_key.cache_clear()
    monkeypatch.setenv("NASWATCH_AUDIT_KEY", "too-short")
    with pytest.raises(RuntimeError):
        audit_logger._audit_key()


def test_configured_jwt_secret_is_still_used_so_old_chains_verify(monkeypatch, fresh_key):
    monkeypatch.setattr(audit_logger, "SECRET_IS_CONFIGURED", True)
    assert audit_logger._audit_key() == audit_logger.SECRET_KEY.encode()


def test_ephemeral_jwt_secret_gets_a_persistent_audit_key(monkeypatch, tmp_path, fresh_key):
    keyfile = tmp_path / "sub" / "audit.key"
    monkeypatch.setenv("NASWATCH_AUDIT_KEY_FILE", str(keyfile))
    monkeypatch.setattr(audit_logger, "SECRET_IS_CONFIGURED", False)
    first = audit_logger._audit_key()
    assert keyfile.exists() and len(first) >= 32
    if os.name != "nt":  # Windows has no POSIX permission bits
        assert oct(keyfile.stat().st_mode & 0o777) == "0o600"
    audit_logger._audit_key.cache_clear()            # simulate a process restart
    assert audit_logger._audit_key() == first        # same key -> chain still verifies


def test_audit_chain_verifies_across_a_simulated_restart(monkeypatch, tmp_path, fresh_key):
    monkeypatch.setenv("NASWATCH_AUDIT_KEY_FILE", str(tmp_path / "audit.key"))
    monkeypatch.setattr(audit_logger, "SECRET_IS_CONFIGURED", False)
    db = str(tmp_path / "audit.db")
    first = audit_logger.AuditLogger(db_path=db)
    first.log("alice", "LOGIN")
    first.log("alice", "DEVICE_ADD", resource="imsi-1")
    audit_logger._audit_key.cache_clear()            # "restart"
    second = audit_logger.AuditLogger(db_path=db)
    second.log("bob", "LOGIN")
    ok, bad_ids, total = second.verify_chain()
    assert ok and not bad_ids and total == 3
