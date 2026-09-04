"""
Unit tests for SOAR engine and FastAPI REST endpoints.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from naswatch.api.server import app
from naswatch.mitigation.soar import SOAREngine
from naswatch.storage.models import (
    Alert,
    AlertRuleType,
    AlertSeverity,
    Device,
    DeviceStatus,
    SliceAssignment,
)
from naswatch.storage.sqlite_repo import SQLiteRepository


def test_soar_engine_revocation_and_report():
    """Test SOAR subscriber revocation, quarantine, and report export."""
    repo = SQLiteRepository(db_path=":memory:")
    device = Device(
        imsi="999700000000001",
        imei="860123456789012",
        owner_name="Alice SecOps",
        device_model="5G-Gateway-v2",
        status=DeviceStatus.ACTIVE,
        allowed_slices=[SliceAssignment(sst=1, sd="000001")],
    )
    repo.add(device)

    soar = SOAREngine(device_repo=repo, alert_repo=repo)

    # 1. Quarantine
    q_res = soar.quarantine_device("999700000000001")
    assert q_res["success"] is True
    assert repo.get_by_imsi("999700000000001").status == DeviceStatus.SUSPENDED

    # 2. Revoke
    r_res = soar.revoke_subscriber("999700000000001", reason="SIM Cloned")
    assert r_res["success"] is True
    assert repo.get_by_imsi("999700000000001").status == DeviceStatus.REVOKED

    # 3. Report generation
    alert = Alert(
        rule_type=AlertRuleType.IDENTITY_SPOOFING,
        severity=AlertSeverity.HIGH,
        title="Identity Spoofing Detected",
        description="Observed fake IMEI",
        imsi="999700000000001",
    )
    report = soar.generate_forensic_report(alert)
    assert "Incident Forensic Report" in report
    assert "IDENTITY_SPOOFING" in report


def test_fastapi_rest_endpoints():
    """Test FastAPI /health, /metrics, /api/v1/devices, /api/v1/ingest/event."""
    client = TestClient(app)

    # Health
    r_health = client.get("/health")
    assert r_health.status_code == 200
    assert r_health.json()["status"] == "healthy"

    # Prometheus Metrics
    r_metrics = client.get("/metrics")
    assert r_metrics.status_code == 200
    assert "naswatch_packets_inspected_total" in r_metrics.text

    # Provision Device via API
    dev_payload = {
        "imsi": "999700000000888",
        "imei": "860123456789888",
        "owner_name": "API Test Unit",
        "device_model": "5G-CPE",
        "status": "ACTIVE",
        "allowed_slices": [{"sst": 1, "sd": "000001"}],
    }
    r_add = client.post("/api/v1/devices", json=dev_payload)
    assert r_add.status_code == 200
    assert r_add.json()["success"] is True

    # Ingest Telemetry Event via API
    ingest_payload = {
        "imsi": "999700000000888",
        "imei": "860123456789888",
        "requested_sst": 2,  # Unauthorized slice -> triggers alert
        "requested_sd": "000002",
        "cell_id": "0x000000010",
    }
    r_ingest = client.post("/api/v1/ingest/event", json=ingest_payload)
    assert r_ingest.status_code == 200
    res = r_ingest.json()
    assert res["alerts_count"] >= 1
    assert res["alerts"][0]["rule_type"] == "SLICE_INTRUSION"
