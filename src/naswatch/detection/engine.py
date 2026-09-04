"""
Detection Engine orchestrator for NASWatch.
Applies pure detection rules across parsed signaling events using injected device repository.
"""

from __future__ import annotations

from naswatch.detection.rules import (
    detect_identity_spoofing,
    detect_rogue_device,
    detect_slice_intrusion,
)
from naswatch.logging_config import get_logger
from naswatch.storage.models import Alert, ParsedSignalingEvent
from naswatch.storage.repository import DeviceRepository

logger = get_logger("detection.engine")


class DetectionEngine:
    """Orchestrates packet event evaluation against inventory and rule pipelines."""

    def __init__(
        self,
        device_repo: DeviceRepository,
        enable_rogue_rule: bool = True,
        enable_spoofing_rule: bool = True,
        enable_slice_rule: bool = True,
    ):
        self.device_repo = device_repo
        self.enable_rogue_rule = enable_rogue_rule
        self.enable_spoofing_rule = enable_spoofing_rule
        self.enable_slice_rule = enable_slice_rule

    def process_event(self, event: ParsedSignalingEvent) -> list[Alert]:
        """
        Evaluate a parsed 5G signaling event against all active detection rules.

        Args:
            event: The parsed NGAP/NAS signaling event.

        Returns:
            List of generated security alerts (empty if clean traffic).
        """
        alerts: list[Alert] = []

        # If event lacks subscriber identifiers, no rule can evaluate identity
        if not event.imsi and not event.imei:
            return alerts

        # Fetch device from inventory repository
        known_device = None
        if event.imsi:
            known_device = self.device_repo.get_by_imsi(event.imsi)
        elif event.imei:
            known_device = self.device_repo.get_by_imei(event.imei)

        # Rule 1: Rogue Device / Unauthorized eSIM
        if self.enable_rogue_rule:
            rogue_alert = detect_rogue_device(event, known_device)
            if rogue_alert:
                alerts.append(rogue_alert)
                logger.warning(
                    f"Rogue device alert triggered: IMSI={event.imsi}, Cell={event.cell_id}",
                    extra={"extra_fields": {"rule": "ROGUE_DEVICE", "imsi": event.imsi}},
                )

        # If it's a known device, evaluate Spoofing and Slice Intrusion
        if known_device is not None:
            # Rule 2: Identity Spoofing (SIM Cloning / Swapping)
            if self.enable_spoofing_rule:
                spoof_alert = detect_identity_spoofing(event, known_device)
                if spoof_alert:
                    alerts.append(spoof_alert)
                    logger.warning(
                        f"Identity spoofing detected: IMSI={event.imsi}, Reported_IMEI={event.imei}",
                        extra={"extra_fields": {"rule": "IDENTITY_SPOOFING", "imsi": event.imsi}},
                    )

            # Rule 3: Network Slice Intrusion
            if self.enable_slice_rule:
                slice_alert = detect_slice_intrusion(event, known_device)
                if slice_alert:
                    alerts.append(slice_alert)
                    logger.warning(
                        f"Slice intrusion detected: IMSI={event.imsi}, Requested_Slice={event.requested_slice_id}",
                        extra={"extra_fields": {"rule": "SLICE_INTRUSION", "slice": event.requested_slice_id}},
                    )

        return alerts
