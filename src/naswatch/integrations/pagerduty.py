"""
PagerDuty Events API v2 integration for NASWatch alert escalation.
Docs: https://developer.pagerduty.com/docs/events-api-v2/overview/
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

try:
    import urllib.request
except ImportError:
    pass

logger = logging.getLogger("naswatch.integrations.pagerduty")

PAGERDUTY_INTEGRATION_KEY = os.environ.get("PAGERDUTY_INTEGRATION_KEY", "")
PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

# Severity mapping NASWatch -> PagerDuty
SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "info",
    "INFO": "info",
}


class PagerDutyClient:
    """PagerDuty Events API v2 client for alert escalation."""

    def __init__(self, integration_key: str | None = None) -> None:
        self.integration_key = integration_key or PAGERDUTY_INTEGRATION_KEY
        if not self.integration_key:
            logger.warning("PagerDuty integration key not set — alerts will not be escalated.")

    def _post(self, payload: dict) -> dict:
        """HTTP POST to PagerDuty Events API (stdlib only, no requests dependency)."""
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            PAGERDUTY_EVENTS_URL,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read())
        except Exception as exc:  # noqa: BLE001
            logger.error("PagerDuty API call failed: %s", exc)
            return {"error": str(exc)}

    def trigger_alert(self, alert_dict: dict[str, Any], source: str = "NASWatch-IDS") -> dict:
        """
        Trigger a PagerDuty incident for a NASWatch alert.
        Returns PagerDuty API response.
        """
        if not self.integration_key:
            return {"skipped": "no integration key configured"}

        pd_severity = SEVERITY_MAP.get(alert_dict.get("severity", "HIGH"), "error")
        payload = {
            "routing_key": self.integration_key,
            "event_action": "trigger",
            "dedup_key": alert_dict.get("id", ""),
            "payload": {
                "summary": alert_dict.get("title", "NASWatch Security Alert"),
                "source": source,
                "severity": pd_severity,
                "timestamp": alert_dict.get("timestamp", ""),
                "custom_details": {
                    "rule_type": alert_dict.get("rule_type"),
                    "imsi": alert_dict.get("imsi"),
                    "imei": alert_dict.get("imei"),
                    "cell_id": alert_dict.get("cell_id"),
                    "target_slice": alert_dict.get("target_slice"),
                    "description": alert_dict.get("description"),
                    "mitigation_status": alert_dict.get("mitigation_status"),
                },
            },
        }
        logger.info("Triggering PagerDuty incident for alert %s", alert_dict.get("id"))
        return self._post(payload)

    def resolve_alert(self, alert_id: str) -> dict:
        """Resolve a previously triggered PagerDuty incident."""
        if not self.integration_key:
            return {"skipped": "no integration key configured"}
        payload = {
            "routing_key": self.integration_key,
            "event_action": "resolve",
            "dedup_key": alert_id,
        }
        return self._post(payload)
