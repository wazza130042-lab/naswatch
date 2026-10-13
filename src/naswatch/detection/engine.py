"""
Detection Engine orchestrator for NASWatch.
Applies pure detection rules across parsed signaling events using injected device repository.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

from naswatch.detection.rules import (
    detect_cipher_downgrade,
    detect_false_base_station,
    detect_identity_spoofing,
    detect_rogue_device,
    detect_slice_intrusion,
)
from naswatch.logging_config import get_logger
from naswatch.storage.models import Alert, AlertRuleType, AlertSeverity, ParsedSignalingEvent
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
        enable_cipher_rule: bool = True,
        enable_false_bs_rule: bool = True,
        enable_flood_rule: bool = True,
        authorized_cells: list[str] | None = None,
        flood_threshold: int = 15,
        flood_window_seconds: float = 5.0,
    ):
        self.device_repo = device_repo
        self.enable_rogue_rule = enable_rogue_rule
        self.enable_spoofing_rule = enable_spoofing_rule
        self.enable_slice_rule = enable_slice_rule
        self.enable_cipher_rule = enable_cipher_rule
        self.enable_false_bs_rule = enable_false_bs_rule
        self.enable_flood_rule = enable_flood_rule
        self.authorized_cells = authorized_cells
        self.flood_threshold = flood_threshold
        self.flood_window_seconds = flood_window_seconds

        # Stateful windowed rate tracker: imsi -> deque of timestamps
        self._rate_tracker: dict[str, deque[float]] = defaultdict(deque)

    def _check_signaling_flood(self, event: ParsedSignalingEvent) -> Alert | None:
        """Track initial UE signaling to detect registration storms."""
        if not event.imsi or not self.enable_flood_rule:
            return None
        if event.procedure_name not in {"InitialUEMessage", "RegistrationRequest"}:
            return None

        now = time.time()
        dq = self._rate_tracker[event.imsi]
        dq.append(now)

        # Evict old timestamps outside window
        while dq and (now - dq[0]) > self.flood_window_seconds:
            dq.popleft()

        if len(dq) > self.flood_threshold:
            return Alert(
                rule_type=AlertRuleType.SIGNALING_FLOOD,
                severity=AlertSeverity.HIGH,
                title="HIGH: 5G Signaling Flooding / Registration Storm Detected",
                description=(
                    f"IMSI '{event.imsi}' generated {len(dq)} signaling requests within "
                    f"{self.flood_window_seconds}s (Threshold: {self.flood_threshold}). "
                    f"Potential AMF DoS or misconfigured IoT botnet."
                ),
                imsi=event.imsi,
                imei=event.imei,
                cell_id=event.cell_id,
                target_slice=event.requested_slice_id,
                raw_event={
                    "rate_count": len(dq),
                    "window_seconds": self.flood_window_seconds,
                    "cell_id": event.cell_id,
                },
            )
        return None

    def process_event(self, event: ParsedSignalingEvent) -> list[Alert]:
        """
        Evaluate a parsed 5G signaling event against all active detection rules.

        Args:
            event: The parsed NGAP/NAS signaling event.

        Returns:
            List of generated security alerts (empty if clean traffic).
        """
        alerts: list[Alert] = []

        # If event lacks subscriber identifiers, check cell anomalies
        if not event.imsi and not event.imei:
            if self.enable_false_bs_rule and self.authorized_cells:
                bs_alert = detect_false_base_station(event, self.authorized_cells)
                if bs_alert:
                    alerts.append(bs_alert)
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
                        f"Slice intrusion detected: IMSI={event.imsi}, Requested_Slice={slice_alert.target_slice}",
                        extra={"extra_fields": {"rule": "SLICE_INTRUSION", "slice": slice_alert.target_slice}},
                    )

        # Rule 4: Security Algorithm Downgrade / Null Ciphering
        if self.enable_cipher_rule:
            cipher_alert = detect_cipher_downgrade(event, known_device)
            if cipher_alert:
                alerts.append(cipher_alert)
                logger.warning(
                    f"Cipher downgrade alert: IMSI={event.imsi}, Algo={event.cipher_algo}",
                    extra={"extra_fields": {"rule": "CIPHER_DOWNGRADE", "imsi": event.imsi}},
                )

        # Rule 5: False Base Station (Rogue gNB)
        if self.enable_false_bs_rule and self.authorized_cells:
            bs_alert = detect_false_base_station(event, self.authorized_cells)
            if bs_alert:
                alerts.append(bs_alert)
                logger.warning(
                    f"False base station detected: Cell={event.cell_id}",
                    extra={"extra_fields": {"rule": "FALSE_BASE_STATION", "cell": event.cell_id}},
                )

        # Rule 6: Signaling Flood / Storm
        flood_alert = self._check_signaling_flood(event)
        if flood_alert:
            alerts.append(flood_alert)
            logger.warning(
                f"Signaling flood detected from IMSI={event.imsi}",
                extra={"extra_fields": {"rule": "SIGNALING_FLOOD", "imsi": event.imsi}},
            )

        return alerts
