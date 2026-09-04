"""
Pure detection rule functions for NASWatch.
Each rule evaluates a ParsedSignalingEvent and an optional Device record,
returning an Alert object if an intrusion is detected, or None if benign.

Zero I/O or DB calls exist within this module for pure unit testability.
"""

from __future__ import annotations

from naswatch.storage.models import (
    Alert,
    AlertRuleType,
    AlertSeverity,
    Device,
    DeviceStatus,
    ParsedSignalingEvent,
)


def detect_rogue_device(
    event: ParsedSignalingEvent,
    known_device: Device | None,
) -> Alert | None:
    """
    Rule 1: Rogue Device Detection
    Trigger: Captured IMSI is not present in authorized inventory or status is REVOKED/SUSPENDED.
    Severity: CRITICAL
    """
    if not event.imsi:
        return None

    # Case A: Unknown IMSI (not in inventory)
    if known_device is None:
        return Alert(
            rule_type=AlertRuleType.ROGUE_DEVICE,
            severity=AlertSeverity.CRITICAL,
            title="CRITICAL: Rogue Device / Unauthorized eSIM Detected",
            description=(
                f"Signaling activity detected from unprovisioned subscriber IMSI '{event.imsi}'. "
                f"Location Cell ID: '{event.cell_id or 'Unknown'}', TAC: {event.tac or 'Unknown'}."
            ),
            imsi=event.imsi,
            imei=event.imei,
            cell_id=event.cell_id,
            target_slice=event.requested_slice_id,
            raw_event={
                "packet_num": event.packet_num,
                "procedure_name": event.procedure_name,
                "source_ip": event.source_ip,
                "dest_ip": event.dest_ip,
                "guti": event.guti,
            },
        )

    # Case B: Provisioned IMSI with REVOKED or SUSPENDED status attempting connection
    if known_device.status in (DeviceStatus.REVOKED, DeviceStatus.SUSPENDED):
        return Alert(
            rule_type=AlertRuleType.ROGUE_DEVICE,
            severity=AlertSeverity.CRITICAL,
            title=f"CRITICAL: {known_device.status.value} Subscriber Access Attempt",
            description=(
                f"Device with IMSI '{event.imsi}' has status '{known_device.status.value}' "
                f"belonging to '{known_device.owner_name}', but attempted 5G network signaling."
            ),
            imsi=event.imsi,
            imei=event.imei,
            cell_id=event.cell_id,
            target_slice=event.requested_slice_id,
            raw_event={
                "packet_num": event.packet_num,
                "procedure_name": event.procedure_name,
                "device_status": known_device.status.value,
                "owner": known_device.owner_name,
            },
        )

    return None


def detect_identity_spoofing(
    event: ParsedSignalingEvent,
    known_device: Device | None,
) -> Alert | None:
    """
    Rule 2: Identity Spoofing / SIM Cloning Detection
    Trigger: IMSI matches inventory, but reported IMEI (PEI) does not match provisioned hardware.
    Severity: HIGH
    """
    if not event.imsi or not event.imei or known_device is None:
        return None

    # Clean IMEIs for normalized comparison (14-16 digits)
    reported_imei = event.imei.strip().replace("-", "").replace(" ", "")
    provisioned_imei = known_device.imei.strip().replace("-", "").replace(" ", "")

    # Compare base 14 digits (TAC + SNR) to handle optional IMEISV software version suffix differences
    reported_base = reported_imei[:14]
    provisioned_base = provisioned_imei[:14]

    if reported_base != provisioned_base:
        return Alert(
            rule_type=AlertRuleType.IDENTITY_SPOOFING,
            severity=AlertSeverity.HIGH,
            title="HIGH: 5G Identity Spoofing / SIM Cloning Detected",
            description=(
                f"Legitimate IMSI '{event.imsi}' (registered to '{known_device.owner_name}') "
                f"was observed transmitting from unauthorized hardware IMEI '{event.imei}'. "
                f"Expected provisioned IMEI: '{known_device.imei}' ({known_device.device_model})."
            ),
            imsi=event.imsi,
            imei=event.imei,
            cell_id=event.cell_id,
            target_slice=event.requested_slice_id,
            raw_event={
                "packet_num": event.packet_num,
                "expected_imei": known_device.imei,
                "observed_imei": event.imei,
                "owner_name": known_device.owner_name,
                "device_model": known_device.device_model,
                "cell_id": event.cell_id,
            },
        )

    return None


def detect_slice_intrusion(
    event: ParsedSignalingEvent,
    known_device: Device | None,
) -> Alert | None:
    """
    Rule 3: Network-Slice Intrusion Detection
    Trigger: Device attempts connection to an S-NSSAI (SST/SD) slice for which it has no entitlement.
    Severity: MEDIUM
    """
    if event.requested_sst is None or known_device is None:
        return None

    # Check if requested slice is authorized
    if not known_device.is_slice_authorized(event.requested_sst, event.requested_sd):
        allowed_desc = ", ".join(
            [s.slice_id for s in known_device.allowed_slices]
        ) or "None (Default Only)"

        return Alert(
            rule_type=AlertRuleType.SLICE_INTRUSION,
            severity=AlertSeverity.MEDIUM,
            title="MEDIUM: Unauthorized 5G Network-Slice Access Attempt",
            description=(
                f"Subscriber IMSI '{event.imsi}' ('{known_device.owner_name}') attempted to access "
                f"Slice S-NSSAI '{event.requested_slice_id}'. "
                f"Provisioned Slices: [{allowed_desc}]."
            ),
            imsi=event.imsi,
            imei=event.imei,
            cell_id=event.cell_id,
            target_slice=event.requested_slice_id,
            raw_event={
                "packet_num": event.packet_num,
                "requested_sst": event.requested_sst,
                "requested_sd": event.requested_sd,
                "allowed_slices": [s.slice_id for s in known_device.allowed_slices],
                "owner_name": known_device.owner_name,
            },
        )

    return None
