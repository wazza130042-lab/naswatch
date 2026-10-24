"""
Live PostgreSQL integration tests.

Enabled by setting `NASWATCH_TEST_PG_URL` to a reachable PostgreSQL URL, e.g.:

    export NASWATCH_TEST_PG_URL=postgresql://naswatch@127.0.0.1:5433/naswatch

Tests are skipped when the variable is unset so the default suite stays
dependency-free (SQLite only).
"""

from __future__ import annotations

import os
import uuid

import pytest

from naswatch.audit.logger import AuditLogger
from naswatch.auth.users import RefreshTokenStore, UserStore, issue_new_refresh
from naswatch.storage.models import (
    Alert,
    AlertRuleType,
    AlertSeverity,
    Device,
    DeviceStatus,
    SliceAssignment,
    UserRole,
)
from naswatch.storage.postgres_repo import PostgresRepository

PG_URL = os.environ.get("NASWATCH_TEST_PG_URL")
pytestmark = pytest.mark.skipif(not PG_URL, reason="NASWATCH_TEST_PG_URL not set")


@pytest.fixture()
def pg_repo():
    repo = PostgresRepository(db_url=PG_URL)
    repo.clear()
    yield repo


@pytest.fixture()
def pg_audit():
    """An audit logger over an emptied table.

    Existing rows may have been signed under a different NASWATCH_JWT_SECRET
    (a different CI run, a different local secret), which would fail chain
    verification for reasons unrelated to this code. Clearing first lets the
    test prove the chain over rows it wrote itself.
    """
    aud = AuditLogger(db_url=PG_URL)
    conn, _ = aud.backend.execute("TRUNCATE audit_log")
    aud.backend.commit(conn)
    aud.backend.close(conn)
    return aud


def test_postgres_repository_tenant_scope(pg_repo):
    for org, imsi in (("acme", "111111111111111"), ("globex", "222222222222222")):
        pg_repo.add(Device(
            imsi=imsi, imei=f"86000000000000{imsi[-1]}", owner_name=org,
            device_model="GW", status=DeviceStatus.ACTIVE,
            allowed_slices=[SliceAssignment(sst=1, sd="000001")], org_id=org,
        ))

    assert [d.imsi for d in pg_repo.list_all(org_id="acme")] == ["111111111111111"]
    assert [d.imsi for d in pg_repo.list_all(org_id="globex")] == ["222222222222222"]
    assert len(pg_repo.list_all(org_id="nobody")) == 0
    assert pg_repo.get_by_imsi("222222222222222").org_id == "globex"


def test_postgres_org_scoped_alerts(pg_repo):
    alert = Alert(
        rule_type=AlertRuleType.ROGUE_DEVICE, severity=AlertSeverity.CRITICAL,
        title="Rogue", description="desc", imsi="111111111111111", org_id="acme",
    )
    pg_repo.record_alert(alert, org_id="acme")

    assert len(pg_repo.get_alerts(limit=10, org_id="acme")) == 1
    assert len(pg_repo.get_alerts(limit=10, org_id="globex")) == 0
    assert pg_repo.get_alert_by_id(alert.id, org_id="acme") is not None
    assert pg_repo.get_alert_by_id(alert.id, org_id="globex") is None

    pg_repo.update_mitigation_status(alert.id, "BLOCKED")
    assert pg_repo.get_alert_by_id(alert.id, org_id="acme").mitigation_status == "BLOCKED"


def test_postgres_identity_stores():
    us = UserStore(db_url=PG_URL)
    rs = RefreshTokenStore(db_url=PG_URL)
    username = f"pg-ops-{uuid.uuid4().hex[:8]}@corp.io"
    user = us.create_user(username, "Strong-Pass!-abc", UserRole.ANALYST, org_id="acme")
    assert us.authenticate(username, "Strong-Pass!-abc").id == user.id
    assert us.authenticate(username, "wrong") is None

    old = issue_new_refresh(rs, user)
    old_jti = del_jti(old)
    assert rs.is_valid(old_jti)

    new = issue_new_refresh(rs, user)
    new_jti = del_jti(new)
    rs.rotate(old_jti, new_jti)
    assert not rs.is_valid(old_jti)
    assert rs.is_valid(new_jti)

    rs.revoke_all_for_user(user.id)
    assert not rs.is_valid(new_jti)


def test_postgres_audit_chain(pg_audit):
    aud = pg_audit
    e1 = aud.log("alice", "auth.login", resource="u1", org_id="acme")
    e2 = aud.log("bob", "device.provision", resource="imsi1", org_id="acme")
    valid, broken, total = aud.verify_chain()
    assert valid is True and total >= 2
    assert aud.verify_integrity(e1) is True and aud.verify_integrity(e2) is True


def del_jti(token: str) -> str:
    from naswatch.auth.jwt_handler import decode_token

    return decode_token(token)["jti"]
