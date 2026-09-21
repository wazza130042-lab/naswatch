"""
Enterprise-grade feature tests: identity/refresh-token lifecycle, tenant
isolation (org_id scoping), factory engine selection, and the tamper-evident
audit hash chain.
"""

from __future__ import annotations

import hashlib
import sqlite3

import pytest
from fastapi.testclient import TestClient

from naswatch.api.server import app
from naswatch.audit.logger import AuditLogger
from naswatch.auth.users import RefreshTokenStore, UserStore
from naswatch.storage.factory import create_repository, create_user_store
from naswatch.storage.models import (
    Alert,
    AlertRuleType,
    AlertSeverity,
    Device,
    DeviceStatus,
    SliceAssignment,
    UserRole,
)
from naswatch.storage.sqlite_repo import SQLiteRepository


# ---------------------------------------------------------------------------
# Identity: UserStore
# ---------------------------------------------------------------------------
def test_user_store_crud_and_authentication():
    store = UserStore(db_path=":memory:")
    user = store.create_user(
        username="analyst@acme.io",
        password="sup3r-Strong-Pass!",
        role=UserRole.ANALYST,
        org_id="acme",
    )
    assert store.authenticate("analyst@acme.io", "sup3r-Strong-Pass!").id == user.id
    assert store.authenticate("analyst@acme.io", "wrong-password") is None
    assert store.authenticate("nobody@acme.io", "sup3r-Strong-Pass!") is None

    promoted = store.update_user(user.id, role=UserRole.ADMIN)
    assert promoted.role == UserRole.ADMIN
    assert store.reset_password(user.id, "new-Sup3r-Pass!") is True
    assert store.authenticate("analyst@acme.io", "new-Sup3r-Pass!") is not None

    assert store.count_users() >= 1
    assert [u.username for u in store.list_users(org_id="acme")] == ["analyst@acme.io"]
    assert store.delete_user(user.id) is True
    assert store.get_by_id(user.id) is None


def test_user_store_bootstraps_default_admin():
    store = UserStore(db_path=":memory:")
    admin = store.get_by_username("admin@naswatch.io")
    assert admin is not None
    assert admin.role == UserRole.ADMIN
    assert store.authenticate("admin@naswatch.io", "naswatch-admin-password") is not None


# ---------------------------------------------------------------------------
# Identity: RefreshTokenStore rotation & revocation
# ---------------------------------------------------------------------------
def test_refresh_token_lifecycle():
    store = UserStore(db_path=":memory:")
    user = store.create_user("m2m@corp.io", "Strong-Pass!-xyz", UserRole.VIEWER, org_id="corp")
    ref_store = RefreshTokenStore(db_path=":memory:")

    from naswatch.auth.users import issue_new_refresh

    old = issue_new_refresh(ref_store, user)
    old_jti = del_jti(old)

    assert ref_store.is_valid(old_jti)

    new = issue_new_refresh(ref_store, user)
    new_jti = del_jti(new)
    ref_store.rotate(old_jti, new_jti)

    assert not ref_store.is_valid(old_jti), "rotated token must be rejected on reuse"
    assert ref_store.is_valid(new_jti)

    ref_store.revoke_all_for_user(user.id)
    assert not ref_store.is_valid(new_jti)


def del_jti(token: str) -> str:
    from naswatch.auth.jwt_handler import decode_token

    return decode_token(token)["jti"]


# ---------------------------------------------------------------------------
# Tenant isolation across the storage layer
# ---------------------------------------------------------------------------
def test_org_scoped_device_and_alert_isolation():
    repo = SQLiteRepository(db_path=":memory:")
    for org, imsi in (("acme", "111111111111111"), ("globex", "222222222222222")):
        repo.add(Device(
            imsi=imsi, imei=f"86000000000000{imsi[-1]}",
            owner_name=org, device_model="GW", status=DeviceStatus.ACTIVE,
            allowed_slices=[SliceAssignment(sst=1, sd="000001")], org_id=org,
        ))

    assert [d.imsi for d in repo.list_all(org_id="acme")] == ["111111111111111"]
    assert [d.imsi for d in repo.list_all(org_id="globex")] == ["222222222222222"]
    assert len(repo.list_all(org_id="other")) == 0

    alert = Alert(
        rule_type=AlertRuleType.ROGUE_DEVICE, severity=AlertSeverity.HIGH,
        title="T", description="D", imsi="111111111111111", org_id="acme",
    )
    repo.record_alert(alert, org_id="acme")

    assert len(repo.get_alerts(limit=10, org_id="acme")) == 1
    assert len(repo.get_alerts(limit=10, org_id="globex")) == 0
    assert repo.get_alert_by_id(alert.id, org_id="acme") is not None
    assert repo.get_alert_by_id(alert.id, org_id="globex") is None


# ---------------------------------------------------------------------------
# Factory engine selection
# ---------------------------------------------------------------------------
def test_factory_uses_sqlite_by_default(monkeypatch):
    monkeypatch.delenv("NASWATCH_DB_URL", raising=False)
    repo = create_repository()
    assert isinstance(repo, SQLiteRepository)
    store = create_user_store()
    assert store.authenticate("admin@naswatch.io", "naswatch-admin-password") is not None


def test_factory_routes_postgres_url(monkeypatch):
    monkeypatch.setenv("NASWATCH_DB_URL", "postgresql://u:p@127.0.0.1:1/naswatch")
    with pytest.raises(Exception):
        create_user_store()


# ---------------------------------------------------------------------------
# Audit hash chain
# ---------------------------------------------------------------------------
def test_audit_hash_chain_detects_tampering():
    logger = AuditLogger(db_path=":memory:")
    e1 = logger.log("alice", "auth.login", resource="u1", org_id="acme")
    e2 = logger.log("bob", "device.provision", resource="imsi1", org_id="acme")
    e3 = logger.log("alice", "alert.mitigate.block", resource="a1", org_id="acme")

    valid, broken, total = logger.verify_chain()
    assert valid is True and total == 3
    assert logger.verify_integrity(e1) is True

    # Tamper with the middle entry's payload
    logger.backend.execute(
        "UPDATE audit_log SET details = ? WHERE id = ?",
        ('{"tampered": true}', e2),
    )
    conn = logger.backend.connect()
    conn.commit()
    logger.backend.close(conn)

    valid, broken, _ = logger.verify_chain()
    assert valid is False
    assert e2 in broken and e3 in broken, "tampering must break the chain downstream"
    assert logger.verify_integrity(e2) is False


def test_audit_legacy_rows_backfilled_into_chain(tmp_path):
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE audit_log (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            actor TEXT NOT NULL,
            org_id TEXT NOT NULL DEFAULT 'default',
            action TEXT NOT NULL,
            resource TEXT,
            details TEXT,
            ip_address TEXT,
            integrity TEXT NOT NULL
        );
    """)
    row = ("e1", "2026-01-01T00:00:00+00:00", "alice", "default", "auth.login", "u1", "{}", None,
           hashlib.sha256(b"legacy").hexdigest())
    conn.execute(
        "INSERT INTO audit_log VALUES (?,?,?,?,?,?,?,?,?)", row
    )
    conn.commit()
    conn.close()

    logger = AuditLogger(db_path=str(db))
    assert logger.count() == 1
    valid, broken, total = logger.verify_chain()
    assert total == 1 and valid is True, "legacy row must be chained by the backfill migration"
    assert broken == []


# ---------------------------------------------------------------------------
# API surface: new enterprise endpoints
# ---------------------------------------------------------------------------
def test_api_enterprise_endpoints():
    client = TestClient(app)
    r_login = client.post("/api/v1/auth/login", json={
        "username": "admin@naswatch.io", "password": "naswatch-admin-password",
    })
    assert r_login.status_code == 200
    tokens = r_login.json()
    headers = {"Authorization": f"Bearer {tokens['access_token']}",
               "Content-Type": "application/json"}

    r_me = client.get("/api/v1/auth/me", headers=headers)
    assert r_me.status_code == 200
    assert r_me.json()["role"] == "admin"

    r_users = client.get("/api/v1/users", headers=headers)
    assert r_users.status_code == 200
    usernames = [u["username"] for u in r_users.json()["users"]]
    assert "admin@naswatch.io" in usernames

    # Unauthorized role check
    r_users_anon = client.get("/api/v1/users")
    assert r_users_anon.status_code == 401

    # Refresh rotation: second use of the rotated token must be rejected
    refresh = tokens["refresh_token"]
    r_re1 = client.post("/api/v1/auth/refresh",
                        headers={"Authorization": f"Bearer {refresh}"})
    assert r_re1.status_code == 200
    rotated = r_re1.json()["refresh_token"]
    assert rotated != refresh
    r_reuse = client.post("/api/v1/auth/refresh",
                          headers={"Authorization": f"Bearer {refresh}"})
    assert r_reuse.status_code == 401, "replayed refresh token must be rejected"

    # Audit chain integrity across the live store
    r_verify = client.get("/api/v1/audit/verify", headers=headers)
    assert r_verify.status_code == 200
    assert r_verify.json()["valid"] is True


# ---------------------------------------------------------------------------
# SSO / OIDC integration
# ---------------------------------------------------------------------------
def test_oidc_public_config_and_provider_mapping():
    from naswatch.auth.oidc import OIDCProvider

    client = TestClient(app)
    r_cfg = client.get("/api/v1/auth/oidc/config")
    assert r_cfg.status_code == 200
    cfg = r_cfg.json()
    assert cfg["enabled"] is False  # no issuer configured in the default env
    assert "enforced" in cfg

    provider = OIDCProvider(issuer="https://idp.example.test/realms/naswatch",
                            client_id="naswatch-api",
                            admin_roles="naswatch-admins,superadmin",
                            role_claim="realm_access")
    assert provider.enabled is True
    assert provider.enforced is False
    assert provider.issuer == "https://idp.example.test/realms/naswatch"


def test_oidc_assert_rejected_when_unconfigured():
    client = TestClient(app)
    r = client.post("/api/v1/auth/oidc/assert", json={"id_token": "not-a-token"})
    assert r.status_code in (501, 401)


def test_oidc_enforced_blocks_password_login(monkeypatch):
    monkeypatch.setenv("NASWATCH_OIDC_ENFORCED", "true")
    monkeypatch.setattr("naswatch.api.server._oidc", None)
    client = TestClient(app)
    r = client.post("/api/v1/auth/login", json={
        "username": "admin@naswatch.io", "password": "naswatch-admin-password",
    })
    assert r.status_code == 503  # enforced but unconfigured -> explicit misconfig
    monkeypatch.setattr("naswatch.api.server._oidc", None)


# ---------------------------------------------------------------------------
# Observability: auth metrics are exported and increment
# ---------------------------------------------------------------------------
def test_auth_metrics_exported():
    from prometheus_client import REGISTRY

    client = TestClient(app)

    before_fail = REGISTRY.get_sample_value(
        "naswatch_auth_logins_total", {"outcome": "failure", "method": "password"}
    ) or 0.0
    client.post("/api/v1/auth/login", json={
        "username": "admin@naswatch.io", "password": "definitely-wrong",
    })
    after_fail = REGISTRY.get_sample_value(
        "naswatch_auth_logins_total", {"outcome": "failure", "method": "password"}
    ) or 0.0
    assert after_fail == before_fail + 1.0

    before_ok = REGISTRY.get_sample_value(
        "naswatch_auth_logins_total", {"outcome": "success", "method": "password"}
    ) or 0.0
    client.post("/api/v1/auth/login", json={
        "username": "admin@naswatch.io", "password": "naswatch-admin-password",
    })
    after_ok = REGISTRY.get_sample_value(
        "naswatch_auth_logins_total", {"outcome": "success", "method": "password"}
    ) or 0.0
    assert after_ok == before_ok + 1.0
