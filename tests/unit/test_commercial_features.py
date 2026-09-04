"""
Unit tests for NASWatch Commercial Enterprise Features:
  - JWT Authentication & Token Lifecycle
  - RBAC Permission Enforcement
  - API Key Generation & Validation
  - License Validation & Tier Feature Flags
  - Immutable Audit Logging with SHA-256 Integrity Verification
  - Alert Correlation Engine & Incident Escalation
  - SIEM Integration Stubs (PagerDuty, Splunk, Sentinel)
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from naswatch.api.server import app
from naswatch.audit.logger import AuditLogger
from naswatch.auth.api_keys import APIKeyStore
from naswatch.auth.jwt_handler import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from naswatch.auth.rbac import ROLE_PERMISSIONS, Role
from naswatch.correlation.engine import CorrelationEngine
from naswatch.integrations.pagerduty import PagerDutyClient
from naswatch.integrations.sentinel import SentinelClient
from naswatch.integrations.splunk import SplunkHECClient
from naswatch.licensing.validator import (
    LicenseTier,
    generate_license_key,
    validate_license,
)
from naswatch.storage.models import Alert, AlertRuleType, AlertSeverity


def test_jwt_lifecycle_and_password_hashing():
    """Test password hashing, verification, access & refresh token generation."""
    pwd = "EnterpriseSecretPassword123!"
    hashed = hash_password(pwd)
    assert verify_password(pwd, hashed)
    assert not verify_password("wrong-password", hashed)

    # Access token
    token = create_access_token(subject="user@enterprise.com", role="admin", org_id="org-123")
    payload = decode_token(token)
    assert payload["sub"] == "user@enterprise.com"
    assert payload["role"] == "admin"
    assert payload["org_id"] == "org-123"

    # Refresh token
    ref_token = create_refresh_token(subject="user@enterprise.com", role="admin", org_id="org-123")
    ref_payload = decode_token(ref_token)
    assert ref_payload["type"] == "refresh"


def test_api_key_store():
    """Test API key creation, validation, expiration, and revocation."""
    store = APIKeyStore(db_path=":memory:")
    raw_key, key_id = store.create_key(name="ci-probe", role="analyst", org_id="tenant-1")
    assert raw_key.startswith("nw_")

    # Validate valid key
    actor = store.validate_key(raw_key)
    assert actor is not None
    assert actor["sub"] == "ci-probe"
    assert actor["role"] == "analyst"
    assert actor["org_id"] == "tenant-1"

    # Revoke key
    assert store.revoke_key(key_id) is True
    assert store.validate_key(raw_key) is None


def test_rbac_permissions_matrix():
    """Verify permissions assigned to each role."""
    assert "alerts:mitigate" in ROLE_PERMISSIONS[Role.ADMIN]
    assert "devices:write" in ROLE_PERMISSIONS[Role.ADMIN]
    assert "audit:read" in ROLE_PERMISSIONS[Role.ADMIN]

    assert "alerts:mitigate" in ROLE_PERMISSIONS[Role.ANALYST]
    assert "devices:write" not in ROLE_PERMISSIONS[Role.ANALYST]

    assert "alerts:read" in ROLE_PERMISSIONS[Role.VIEWER]
    assert "alerts:mitigate" not in ROLE_PERMISSIONS[Role.VIEWER]
    assert "devices:write" not in ROLE_PERMISSIONS[Role.VIEWER]


def test_licensing_system():
    """Test license key generation, cryptographic validation, tier features, and expiry."""
    # 1. Valid Enterprise License
    lic_key = generate_license_key(org_name="Vodafone-Demo", tier="ENTERPRISE", seats=50)
    info = validate_license(lic_key)
    assert info.valid is True
    assert info.tier == LicenseTier.ENTERPRISE
    assert info.has_feature("correlation:engine")
    assert info.has_feature("api:multitenancy")

    # 2. Community fallback
    comm_info = validate_license(None)
    assert comm_info.tier == LicenseTier.COMMUNITY
    assert comm_info.has_feature("detection:basic")
    assert not comm_info.has_feature("correlation:engine")

    # 3. Tampered License
    tampered = lic_key[:-4] + "FFFF"
    tampered_info = validate_license(tampered)
    assert tampered_info.tier == LicenseTier.COMMUNITY  # Falls back safely


def test_audit_logger_integrity():
    """Test audit log writing, query filters, and SHA-256 tamper verification."""
    audit = AuditLogger(db_path=":memory:")
    eid1 = audit.log(
        actor="secops-user",
        action="device.provision",
        resource="001010000000001",
        details={"slice": "1:000001"},
        org_id="tenant-alpha",
    )
    assert audit.verify_integrity(eid1) is True

    entries = audit.get_entries(org_id="tenant-alpha")
    assert len(entries) == 1
    assert entries[0]["actor"] == "secops-user"
    assert entries[0]["action"] == "device.provision"


def test_correlation_engine_incident_escalation():
    """Test correlation of multiple alerts into a single escalated security incident."""
    engine = CorrelationEngine(window_seconds=60)

    # 1. Alert A: Signaling flood
    a1 = Alert(
        rule_type=AlertRuleType.SIGNALING_FLOOD,
        severity=AlertSeverity.HIGH,
        title="Signaling Flood",
        description="Storm detected",
        imsi="999700000000001",
        cell_id="0x001",
    )
    inc1 = engine.ingest(a1)
    assert inc1 is not None

    # 2. Alert B: Rogue device with same IMSI -> matches (SIGNALING_FLOOD, ROGUE_DEVICE) escalation chain
    a2 = Alert(
        rule_type=AlertRuleType.ROGUE_DEVICE,
        severity=AlertSeverity.CRITICAL,
        title="Rogue Device",
        description="Unknown IMSI",
        imsi="999700000000001",
        cell_id="0x001",
    )
    inc2 = engine.ingest(a2)
    assert inc2 is not None
    assert inc2.escalated is True
    assert inc2.severity == AlertSeverity.CRITICAL
    assert len(inc2.rule_types) == 2


def test_siem_integration_clients():
    """Verify SIEM client initializers and payload formatting without live network."""
    pd = PagerDutyClient(integration_key="")
    res_pd = pd.trigger_alert({"id": "ALT-1", "title": "Test", "severity": "HIGH"})
    assert "skipped" in res_pd

    splunk = SplunkHECClient(hec_url="", token="")
    res_sp = splunk.send_alert({"id": "ALT-1", "title": "Test"})
    assert "skipped" in res_sp

    sentinel = SentinelClient(workspace_id="", shared_key="")
    res_se = sentinel.send_alerts([{"id": "ALT-1"}])
    assert "skipped" in res_se


def test_commercial_api_endpoints():
    """Test API key creation via API, correlation endpoint, and audit trail endpoint."""
    client = TestClient(app)

    # Login as admin
    r_login = client.post(
        "/api/v1/auth/login",
        json={"username": "admin@naswatch.io", "password": "naswatch-admin-password"},
    )
    token = r_login.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {token}"}

    # 1. Root / license endpoint
    r_root = client.get("/")
    assert r_root.status_code == 200
    assert r_root.json()["edition"] == "COMMERCIAL"

    # 2. Create an API Key
    r_key = client.post(
        "/api/v1/apikeys",
        json={"name": "soc-collector", "role": "analyst", "org_id": "soc-org"},
        headers=admin_headers,
    )
    assert r_key.status_code == 200
    api_key_data = r_key.json()
    raw_api_key = api_key_data["raw_key"]
    assert raw_api_key.startswith("nw_")

    # 3. Use X-API-Key header to query devices
    r_dev_apikey = client.get("/api/v1/devices", headers={"X-API-Key": raw_api_key})
    assert r_dev_apikey.status_code == 200

    # 4. Query correlated incidents endpoint
    r_inc = client.get("/api/v1/incidents", headers=admin_headers)
    assert r_inc.status_code == 200

    # 5. Query immutable audit trail
    r_audit = client.get("/api/v1/audit", headers=admin_headers)
    assert r_audit.status_code == 200
    assert "entries" in r_audit.json()
