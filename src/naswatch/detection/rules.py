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


def detect_cipher_downgrade(
    event: ParsedSignalingEvent,
    known_device: Device | None = None,
) -> Alert | None:
    """
    Rule 4: Bidding-Down / Null Ciphering Downgrade Detection
    Trigger: Signaling session negotiates or requests NEA0 (null ciphering) or NIA0 (null integrity)
             on a non-emergency slice or connection.
    Severity: HIGH
    """
    is_null_cipher = event.cipher_algo in ("NEA0", "0", "EEA0")
    is_null_integrity = event.integrity_algo in ("NIA0", "0", "EIA0")

    if is_null_cipher or is_null_integrity:
        algo_desc = []
        if is_null_cipher:
            algo_desc.append("Null Ciphering (NEA0/No Encryption)")
        if is_null_integrity:
            algo_desc.append("Null Integrity (NIA0/No MAC Protection)")

        return Alert(
            rule_type=AlertRuleType.CIPHER_DOWNGRADE,
            severity=AlertSeverity.HIGH,
            title="HIGH: 5G Security Algorithm Downgrade / Null Ciphering Exploit",
            description=(
                f"Insecure signaling parameters detected from IMSI '{event.imsi or 'Unknown'}'. "
                f"Negotiated Algorithms: {', '.join(algo_desc)}. "
                f"Potential Bidding-Down or MitM / IMSI-Catcher activity at Cell '{event.cell_id or 'Unknown'}'."
            ),
            imsi=event.imsi,
            imei=event.imei,
            cell_id=event.cell_id,
            target_slice=event.requested_slice_id,
            raw_event={
                "packet_num": event.packet_num,
                "cipher_algo": event.cipher_algo,
                "integrity_algo": event.integrity_algo,
                "cell_id": event.cell_id,
            },
        )

    return None


def detect_false_base_station(
    event: ParsedSignalingEvent,
    authorized_cells: list[str] | None = None,
) -> Alert | None:
    """
    Rule 5: False Base Station (Stingray / Rogue gNB / IMSI Catcher) Detection
    Trigger: Cell ID or TAC reported in signaling traffic does not match the network's authorized gNB inventory.
    Severity: CRITICAL
    """
    if not event.cell_id or authorized_cells is None or len(authorized_cells) == 0:
        return None

    if event.cell_id not in authorized_cells:
        return Alert(
            rule_type=AlertRuleType.FALSE_BASE_STATION,
            severity=AlertSeverity.CRITICAL,
            title="CRITICAL: Unauthorized Cell ID / Rogue gNB (IMSI Catcher) Detected",
            description=(
                f"Signaling received from unapproved Cell ID '{event.cell_id}' (TAC: {event.tac or 'Unknown'}). "
                f"Device IMSI '{event.imsi or 'Unknown'}' may be communicating with a False Base Station."
            ),
            imsi=event.imsi,
            imei=event.imei,
            cell_id=event.cell_id,
            target_slice=event.requested_slice_id,
            raw_event={
                "packet_num": event.packet_num,
                "cell_id": event.cell_id,
                "tac": event.tac,
                "source_ip": event.source_ip,
            },
        )

    return None
