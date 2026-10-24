"""
Unit tests for detection rules and DetectionEngine.
Validates Rogue Device, Identity Spoofing, and Network-Slice Intrusion logic as pure functions.
"""

from __future__ import annotations

from naswatch.detection.engine import DetectionEngine
from naswatch.detection.rules import (
    detect_identity_spoofing,
    detect_rogue_device,
    detect_slice_intrusion,
)
from naswatch.storage.models import (
    AlertRuleType,
    AlertSeverity,
    Device,
    DeviceStatus,
    ParsedSignalingEvent,
)


def test_rogue_device_unknown_imsi():
    """Rule 1: An IMSI not present in the inventory must trigger a CRITICAL Rogue Device alert."""
    event = ParsedSignalingEvent(
        imsi="999700000000999",
        imei="860999999999999",
        cell_id="0x000000010",
        tac=1,
    )
    # known_device is None
    alert = detect_rogue_device(event, known_device=None)
    assert alert is not None
    assert alert.rule_type == AlertRuleType.ROGUE_DEVICE
    assert alert.severity == AlertSeverity.CRITICAL
    assert alert.imsi == "999700000000999"
    assert "unprovisioned" in alert.description.lower() or "rogue" in alert.title.lower()


def test_rogue_device_suspended_subscriber(authorized_device: Device):
    """Rule 1: A suspended/revoked subscriber attempting signaling must trigger an alert."""
    authorized_device.status = DeviceStatus.SUSPENDED
    event = ParsedSignalingEvent(imsi=authorized_device.imsi, imei=authorized_device.imei)

    alert = detect_rogue_device(event, known_device=authorized_device)
    assert alert is not None
    assert alert.rule_type == AlertRuleType.ROGUE_DEVICE
    assert alert.severity == AlertSeverity.CRITICAL
    assert "SUSPENDED" in alert.title


def test_rogue_device_benign_allowed(authorized_device: Device, benign_event: ParsedSignalingEvent):
    """Legitimate active subscriber must not trigger rogue device alert."""
    alert = detect_rogue_device(benign_event, known_device=authorized_device)
    assert alert is None


def test_identity_spoofing_mismatched_imei(authorized_device: Device):
    """Rule 2: Matching IMSI with spoofed/cloned IMEI must trigger a HIGH Identity Spoofing alert."""
    event = ParsedSignalingEvent(
        imsi=authorized_device.imsi,
        imei="869999999999999",  # Spoofed IMEI
        cell_id="0x000000010",
    )

    alert = detect_identity_spoofing(event, known_device=authorized_device)
    assert alert is not None
    assert alert.rule_type == AlertRuleType.IDENTITY_SPOOFING
    assert alert.severity == AlertSeverity.HIGH
    assert alert.imsi == authorized_device.imsi
    assert alert.imei == "869999999999999"
    assert "spoofing" in alert.title.lower() or "unauthorized hardware" in alert.description.lower()


def test_identity_spoofing_clean(authorized_device: Device, benign_event: ParsedSignalingEvent):
    """Legitimate device with matching IMEI must not trigger identity spoofing alert."""
    alert = detect_identity_spoofing(benign_event, known_device=authorized_device)
    assert alert is None


def test_slice_intrusion_unauthorized_sst(authorized_device: Device):
    """Rule 3: Device attempting connection to an unauthorized SST must trigger a MEDIUM Slice Intrusion alert."""
    # Authorized for SST=1, attempts SST=2 (URLLC Critical)
    event = ParsedSignalingEvent(
        imsi=authorized_device.imsi,
        imei=authorized_device.imei,
        requested_sst=2,
        requested_sd="000002",
        cell_id="0x000000010",
    )

    alert = detect_slice_intrusion(event, known_device=authorized_device)
    assert alert is not None
    assert alert.rule_type == AlertRuleType.SLICE_INTRUSION
    assert alert.severity == AlertSeverity.MEDIUM
    assert alert.target_slice == "2:000002"


def test_slice_intrusion_unauthorized_sd(authorized_device: Device):
    """Rule 3: Device matching SST but differing SD must trigger slice intrusion alert."""
    # Authorized for SST=1, SD=000001; attempts SST=1, SD=999999
    event = ParsedSignalingEvent(
        imsi=authorized_device.imsi,
        imei=authorized_device.imei,
        requested_sst=1,
        requested_sd="999999",
    )

    alert = detect_slice_intrusion(event, known_device=authorized_device)
    assert alert is not None
    assert alert.rule_type == AlertRuleType.SLICE_INTRUSION
    assert alert.severity == AlertSeverity.MEDIUM


def test_slice_intrusion_authorized(authorized_device: Device, benign_event: ParsedSignalingEvent):
    """Legitimate slice request must not trigger slice intrusion alert."""
    alert = detect_slice_intrusion(benign_event, known_device=authorized_device)
    assert alert is None


def test_detection_engine_pipeline(memory_repo):
    """End-to-end test of DetectionEngine with injected repository."""
    engine = DetectionEngine(device_repo=memory_repo)

    # 1. Clean event
    clean_event = ParsedSignalingEvent(
        imsi="999700000000001",
        imei="860123456789012",
        requested_sst=1,
        requested_sd="000001",
    )
    alerts = engine.process_event(clean_event)
    assert len(alerts) == 0

    # 2. Rogue IMSI
    rogue_event = ParsedSignalingEvent(
        imsi="999700000000999",
        imei="860999999999999",
    )
    alerts = engine.process_event(rogue_event)
    assert len(alerts) == 1
    assert alerts[0].rule_type == AlertRuleType.ROGUE_DEVICE

    # 3. Spoofed IMEI
    spoof_event = ParsedSignalingEvent(
        imsi="999700000000001",
        imei="869999999999999",
    )
    alerts = engine.process_event(spoof_event)
    assert len(alerts) == 1
    assert alerts[0].rule_type == AlertRuleType.IDENTITY_SPOOFING

    # 4. Slice Intrusion
    slice_event = ParsedSignalingEvent(
        imsi="999700000000002",
        imei="860123456789022",
        requested_sst=4,
        requested_sd="010203",
    )
    alerts = engine.process_event(slice_event)
    assert len(alerts) == 1
    assert alerts[0].rule_type == AlertRuleType.SLICE_INTRUSION


def test_cipher_downgrade_detection():
    """Rule 4: Detect null ciphering (NEA0) / null integrity (NIA0)."""
    from naswatch.detection.rules import detect_cipher_downgrade

    event = ParsedSignalingEvent(
        imsi="999700000000001",
        cipher_algo="NEA0",
        integrity_algo="NIA0",
        cell_id="0x000000010",
    )
    alert = detect_cipher_downgrade(event)
    assert alert is not None
    assert alert.rule_type == AlertRuleType.CIPHER_DOWNGRADE
    assert alert.severity == AlertSeverity.HIGH


def test_false_base_station_detection():
    """Rule 5: Detect unapproved Cell ID / Rogue gNB."""
    from naswatch.detection.rules import detect_false_base_station

    authorized_cells = ["0x000000010", "0x000000020"]

    # Approved cell
    clean_event = ParsedSignalingEvent(cell_id="0x000000010")
    assert detect_false_base_station(clean_event, authorized_cells) is None

    # Rogue cell
    rogue_event = ParsedSignalingEvent(cell_id="0x999999999")
    alert = detect_false_base_station(rogue_event, authorized_cells)
    assert alert is not None
    assert alert.rule_type == AlertRuleType.FALSE_BASE_STATION
    assert alert.severity == AlertSeverity.CRITICAL


def test_signaling_flood_detection(memory_repo):
    """Rule 6: High frequency signaling storm detection."""
    engine = DetectionEngine(
        device_repo=memory_repo,
        flood_threshold=5,
        flood_window_seconds=2.0,
    )

    # Send 6 rapid registration attempts for the same IMSI. The flood rule
    # deliberately only counts registration procedures, so procedure_name must
    # be present to model a real registration storm.
    alerts = []
    for _ in range(6):
        event = ParsedSignalingEvent(
            imsi="999700000000001",
            imei="860123456789012",
            requested_sst=1,
            requested_sd="000001",
            procedure_name="RegistrationRequest",
        )
        alerts.extend(engine.process_event(event))

    flood_alerts = [a for a in alerts if a.rule_type == AlertRuleType.SIGNALING_FLOOD]
    assert len(flood_alerts) >= 1

