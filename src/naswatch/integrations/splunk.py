"""
Splunk HTTP Event Collector (HEC) integration.
Docs: https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector
"""
from __future__ import annotations

import json
import logging
import os
import ssl
import urllib.request
from typing import Any

logger = logging.getLogger("naswatch.integrations.splunk")

SPLUNK_HEC_URL = os.environ.get("SPLUNK_HEC_URL", "")  # e.g., https://splunk.corp.com:8088/services/collector
SPLUNK_HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "")
SPLUNK_INDEX = os.environ.get("SPLUNK_INDEX", "naswatch_alerts")
SPLUNK_SOURCE = "naswatch:ids"
SPLUNK_SOURCETYPE = "naswatch:alert"


class SplunkHECClient:
    """Splunk HTTP Event Collector (HEC) client."""

    def __init__(
        self,
        hec_url: str | None = None,
        token: str | None = None,
        index: str = SPLUNK_INDEX,
        verify_ssl: bool = True,
    ) -> None:
        self.hec_url = (hec_url or SPLUNK_HEC_URL).rstrip("/")
        self.token = token or SPLUNK_HEC_TOKEN
        self.index = index
        self.verify_ssl = verify_ssl
        if not self.hec_url or not self.token:
            logger.warning("Splunk HEC URL or token not set — events will not be forwarded.")

    def _post(self, data: dict) -> dict:
        body = json.dumps(data).encode()
        url = self.hec_url + "/event" if not self.hec_url.endswith("/event") else self.hec_url
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Authorization": f"Splunk {self.token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        ctx = ssl.create_default_context() if self.verify_ssl else ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                return json.loads(resp.read())
        except Exception as exc:  # noqa: BLE001
            logger.error("Splunk HEC call failed: %s", exc)
            return {"error": str(exc)}

    def send_alert(self, alert_dict: dict[str, Any]) -> dict:
        """Forward a NASWatch alert to Splunk as a structured HEC event."""
        if not self.hec_url or not self.token:
            return {"skipped": "Splunk HEC not configured"}

        payload = {
            "time": alert_dict.get("timestamp", ""),
            "host": "naswatch-ids",
            "source": SPLUNK_SOURCE,
            "sourcetype": SPLUNK_SOURCETYPE,
            "index": self.index,
            "event": alert_dict,
        }
        logger.info("Forwarding alert %s to Splunk HEC", alert_dict.get("id"))
        return self._post(payload)
