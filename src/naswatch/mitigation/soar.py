"""
Active SOAR (Security Orchestration, Automation, and Response) Engine for NASWatch.
Executes operator-directed inventory changes and configured response integrations.
- Subscriber inventory revocation and operator-owned core adapter calls
- Edge firewall rule generation for operator review
- Markdown incident report generation
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from urllib.error import HTTPError, URLError
from typing import Any
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from naswatch.logging_config import get_logger
from naswatch.storage.models import Alert, DeviceStatus
from naswatch.storage.repository import AlertRepository, DeviceRepository

logger = get_logger("mitigation.soar")


class _NoRedirectHandler(HTTPRedirectHandler):
    """Do not forward the core adapter bearer token to a redirect target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class SOAREngine:
    """Executes NASWatch-side actions and explicitly configured integrations."""

    def __init__(
        self,
        device_repo: DeviceRepository,
        alert_repo: AlertRepository,
        open5gs_api_url: str | None = None,
    ):
        self.device_repo = device_repo
        self.alert_repo = alert_repo
        # Open5GS does not expose a generic subscriber-revocation HTTP endpoint.
        # Deployments can provide an operator-owned adapter endpoint explicitly.
        self.core_revocation_url = open5gs_api_url or os.environ.get("NASWATCH_CORE_REVOCATION_URL")
        self.core_revocation_token = os.environ.get("NASWATCH_CORE_REVOCATION_TOKEN")

    def revoke_subscriber(
        self, imsi: str, reason: str = "Security Incident", *, org_id: str | None = None
    ) -> dict[str, Any]:
        """
        Revoke a subscriber in NASWatch inventory and, when configured, ask the
        operator's core adapter to apply the corresponding network-side action.

        A successful inventory update alone is deliberately reported as partial;
        it is not evidence that the 5G core denied service.
        """
        device = self.device_repo.get_by_imsi(imsi, org_id=org_id)
        if not device:
            return {
                "success": False,
                "inventory_revoked": False,
                "core_revocation": {"state": "not_attempted"},
                "message": "Subscriber was not found in this organization's inventory.",
            }

        device.status = DeviceStatus.REVOKED
        device.notes = f"{device.notes} | REVOKED via SOAR: {reason} at {datetime.now(UTC).isoformat()}"
        if not self.device_repo.add(device):
            return {
                "success": False,
                "inventory_revoked": False,
                "core_revocation": {"state": "not_attempted"},
                "message": "The subscriber's NASWatch inventory status could not be saved.",
            }

        logger.info(f"SOAR: Revoked subscriber IMSI '{imsi}'. Reason: {reason}")
        core_result = self._request_core_revocation(imsi, reason)
        return {
            "success": core_result["success"],
            "inventory_revoked": True,
            "core_revocation": core_result,
            "imsi": imsi,
            "status": "REVOKED",
            "message": (
                f"Subscriber {imsi} was revoked in NASWatch inventory."
                if not core_result["success"]
                else f"Subscriber {imsi} was revoked in NASWatch inventory and the core adapter confirmed the action."
            ),
        }

    def _request_core_revocation(self, imsi: str, reason: str) -> dict[str, Any]:
        if not self.core_revocation_url:
            return {
                "success": False,
                "state": "not_configured",
                "message": "No operator core-revocation adapter is configured; network access was not blocked.",
            }
        if not self.core_revocation_token:
            return {
                "success": False,
                "state": "misconfigured",
                "message": "The core-revocation adapter URL is set but its token is missing.",
            }
        parsed_url = urlsplit(self.core_revocation_url)
        if parsed_url.scheme not in {"https", "http"} or not parsed_url.hostname or parsed_url.username or parsed_url.password or parsed_url.fragment:
            return {"success": False, "state": "misconfigured", "message": "Adapter URL must be a valid HTTP(S) endpoint without embedded credentials."}
        if parsed_url.scheme != "https" and parsed_url.hostname not in {"localhost", "127.0.0.1", "::1"}:
            return {"success": False, "state": "misconfigured", "message": "Bearer-token adapter URLs must use HTTPS outside loopback."}

        payload = json.dumps({"imsi": imsi, "reason": reason, "source": "NASWatch"}).encode("utf-8")
        request = Request(
            self.core_revocation_url,
            data=payload,
            headers={"Authorization": f"Bearer {self.core_revocation_token}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            opener = build_opener(_NoRedirectHandler)
            with opener.open(request, timeout=5) as response:
                if response.status < 200 or response.status >= 300:
                    return {"success": False, "state": "failed", "message": f"Adapter returned HTTP {response.status}."}
                result = json.loads(response.read(65537))
            if not isinstance(result, dict) or result.get("success") is not True:
                return {"success": False, "state": "failed", "message": "Adapter did not confirm revocation."}
            return {"success": True, "state": "confirmed", "message": "Operator core adapter confirmed revocation."}
        except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            logger.warning("Core subscriber revocation failed: %s", type(exc).__name__)
            return {"success": False, "state": "failed", "message": "Core adapter did not confirm revocation."}

    def quarantine_device(self, imsi: str, *, org_id: str | None = None) -> dict[str, Any]:
        """Temporarily suspend a subscriber for forensic inspection."""
        device = self.device_repo.get_by_imsi(imsi, org_id=org_id)
        if not device:
            return {"success": False, "message": f"IMSI '{imsi}' not found in inventory."}

        device.status = DeviceStatus.SUSPENDED
        if not self.device_repo.add(device):
            return {"success": False, "message": "Subscriber suspension could not be saved in NASWatch inventory."}
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
