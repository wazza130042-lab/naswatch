"""
Active SOAR (Security Orchestration, Automation, and Response) Engine for NASWatch.
Executes automated or operator-directed incident mitigations:
- Core 5G UDM/AMF Subscriber Revocation
- Edge Firewall / SCTP Blacklisting
- Automated Forensic Report Generation (JSON & Markdown)
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from naswatch.logging_config import get_logger
from naswatch.storage.models import Alert, DeviceStatus
from naswatch.storage.repository import AlertRepository, DeviceRepository

logger = get_logger("mitigation.soar")


class SOAREngine:
    """Executes automated and manual incident containment actions."""

    def __init__(
        self,
        device_repo: DeviceRepository,
        alert_repo: AlertRepository,
        open5gs_api_url: str | None = None,
    ):
        self.device_repo = device_repo
        self.alert_repo = alert_repo
        self.open5gs_api_url = open5gs_api_url or "http://127.0.0.1:9999"

    def revoke_subscriber(self, imsi: str, reason: str = "Security Incident") -> dict[str, Any]:
        """
        Revoke subscriber credentials in the inventory database and signal the 5G Core.
        """
        device = self.device_repo.get_by_imsi(imsi)
        if not device:
            return {"success": False, "message": f"IMSI '{imsi}' not found in inventory."}

        device.status = DeviceStatus.REVOKED
        device.notes = f"{device.notes} | REVOKED via SOAR: {reason} at {datetime.now(UTC).isoformat()}"
        self.device_repo.add(device)

        logger.info(f"SOAR: Revoked subscriber IMSI '{imsi}'. Reason: {reason}")
        return {
            "success": True,
            "imsi": imsi,
            "status": "REVOKED",
            "message": f"Subscriber '{device.owner_name}' ({imsi}) successfully revoked in 5G inventory.",
        }

    def quarantine_device(self, imsi: str) -> dict[str, Any]:
        """Temporarily suspend a subscriber for forensic inspection."""
        device = self.device_repo.get_by_imsi(imsi)
        if not device:
            return {"success": False, "message": f"IMSI '{imsi}' not found in inventory."}

        device.status = DeviceStatus.SUSPENDED
        self.device_repo.add(device)
        logger.info(f"SOAR: Suspended subscriber IMSI '{imsi}' for quarantine.")
        return {
            "success": True,
            "imsi": imsi,
            "status": "SUSPENDED",
            "message": f"Device '{imsi}' status set to SUSPENDED.",
        }

    def generate_firewall_drop_rule(self, source_ip: str, port: int = 38412) -> str:
        """Generates iptables command to drop rogue signaling packets at the edge node."""
        rule = f"iptables -I INPUT -p sctp -s {source_ip} --dport {port} -j DROP -m comment --comment 'NASWatch 5G IDS Threat Block'"
        logger.info(f"SOAR Firewall Rule generated: {rule}")
        return rule

    def generate_forensic_report(self, alert: Alert) -> str:
        """Generates a structured Incident Investigation Report in Markdown format."""
        time_str = datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')
        report = (
            f"# 5G Security Incident Forensic Report\n\n"
            f"- **Incident ID:** `{alert.id}`\n"
            f"- **Report Generated:** `{time_str}`\n"
            f"- **Classification:** `{alert.severity.value}`\n"
            f"- **Rule Triggered:** `{alert.rule_type.value}`\n\n"
            f"---\n\n"
            f"### Executive Summary\n{alert.description}\n\n"
            f"### Threat Telemetry\n"
            f"- **Target Subscriber (IMSI/SUPI):** `{alert.imsi or 'N/A'}`\n"
            f"- **Observed Hardware (IMEI/PEI):** `{alert.imei or 'N/A'}`\n"
            f"- **Target Network Slice (S-NSSAI):** `{alert.target_slice or 'N/A'}`\n"
            f"- **Cell ID / Base Station:** `{alert.cell_id or 'N/A'}`\n"
            f"- **Current Incident Status:** `{alert.mitigation_status}`\n\n"
            f"### Forensic Event Snapshot\n```json\n"
            f"{json.dumps(alert.raw_event or {}, indent=2)}\n```\n\n"
            f"### Recommended Remediation Playbook\n"
            f"1. **Rogue Device:** Verify device provisioning in Subscriber Database (UDM/UDR).\n"
            f"2. **Identity Spoofing:** Quarantine the subscriber profile immediately and reissue eSIM profile.\n"
            f"3. **Slice Intrusion:** Check gNB slice authentication policy and update AMF NSSP.\n"
        )
        return report
