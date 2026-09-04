"""
Unit tests for SQLite repository implementation.
"""

from __future__ import annotations

from naswatch.storage.models import (
    Alert,
    AlertRuleType,
    AlertSeverity,
    Device,
    DeviceStatus,
    SliceAssignment,
)
from naswatch.storage.sqlite_repo import SQLiteRepository


def test_sqlite_device_repository():
    """Test device persistence, lookup, update, and deletion in SQLite."""
    repo = SQLiteRepository(db_path=":memory:")
    assert repo.count() == 0

    device = Device(
        imsi="999700000000001",
        imei="860123456789012",
        owner_name="Alice Security Operations",
        device_model="5G-CPE-v1",
        status=DeviceStatus.ACTIVE,
        allowed_slices=[
            SliceAssignment(sst=1, sd="000001", name="eMBB-Public"),
            SliceAssignment(sst=2, sd="000002", name="uRLLC-Critical"),
        ],
    )
    repo.add(device)
    assert repo.count() == 1

    # Fetch by IMSI
    fetched = repo.get_by_imsi("999700000000001")
    assert fetched is not None
    assert fetched.owner_name == "Alice Security Operations"
    assert len(fetched.allowed_slices) == 2
    assert fetched.is_slice_authorized(1, "000001")
    assert not fetched.is_slice_authorized(3, "000003")

    # Fetch by IMEI
    fetched_imei = repo.get_by_imei("860123456789012")
    assert fetched_imei is not None
    assert fetched_imei.imsi == "999700000000001"

    # Non-existent
    assert repo.get_by_imsi("999000000000000") is None

    # Delete
    assert repo.delete("999700000000001") is True
    assert repo.count() == 0


def test_sqlite_alert_repository():
    """Test alert storage, filtering, and status updates."""
    repo = SQLiteRepository(db_path=":memory:")

    alert1 = Alert(
        rule_type=AlertRuleType.ROGUE_DEVICE,
        severity=AlertSeverity.CRITICAL,
        title="Rogue Device Detected",
        description="Unknown IMSI attached",
        imsi="999700000000999",
        cell_id="0x000000010",
    )
    alert2 = Alert(
        rule_type=AlertRuleType.SLICE_INTRUSION,
        severity=AlertSeverity.MEDIUM,
        title="Slice Intrusion",
        description="Unauthorized slice",
        imsi="999700000000002",
        target_slice="2:000002",
    )

    repo.record_alert(alert1)
    repo.record_alert(alert2)

    assert repo.count_alerts() == 2

    # Filter by severity
    critical_alerts = repo.get_alerts(severity="CRITICAL")
    assert len(critical_alerts) == 1
    assert critical_alerts[0].id == alert1.id

    # Filter by rule
    slice_alerts = repo.get_alerts(rule_type="SLICE_INTRUSION")
    assert len(slice_alerts) == 1
    assert slice_alerts[0].id == alert2.id

    # Update mitigation status
    assert repo.update_mitigation_status(alert1.id, "BLOCKED") is True
    updated = repo.get_alert_by_id(alert1.id)
    assert updated is not None
    assert updated.mitigation_status == "BLOCKED"
