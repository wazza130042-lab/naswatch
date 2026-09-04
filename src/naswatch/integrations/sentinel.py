"""
Microsoft Sentinel (Azure Monitor) Log Analytics Workspace integration.
Uses the Data Collector API / custom log table ingestion.
Docs: https://learn.microsoft.com/azure/sentinel/data-connector-custom-logs
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import urllib.request
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger("naswatch.integrations.sentinel")

SENTINEL_WORKSPACE_ID = os.environ.get("SENTINEL_WORKSPACE_ID", "")
SENTINEL_SHARED_KEY = os.environ.get("SENTINEL_SHARED_KEY", "")
SENTINEL_LOG_TYPE = os.environ.get("SENTINEL_LOG_TYPE", "NASWatchAlerts")


class SentinelClient:
    """Microsoft Sentinel Log Analytics ingestion client."""

    def __init__(
        self,
        workspace_id: str | None = None,
        shared_key: str | None = None,
        log_type: str = SENTINEL_LOG_TYPE,
    ) -> None:
        self.workspace_id = workspace_id or SENTINEL_WORKSPACE_ID
        self.shared_key = shared_key or SENTINEL_SHARED_KEY
        self.log_type = log_type
        if not self.workspace_id or not self.shared_key:
            logger.warning("Sentinel Workspace ID or Shared Key not configured.")

    def _build_signature(self, date: str, content_length: int, method: str, content_type: str, resource: str) -> str:
        x_headers = f"x-ms-date:{date}"
        string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
        bytes_to_hash = string_to_hash.encode("utf-8")
        decoded_key = base64.b64decode(self.shared_key)
        encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
        return f"SharedKey {self.workspace_id}:{encoded_hash}"

    def send_alerts(self, alerts: list[dict[str, Any]]) -> dict:
        """Ingest a batch of NASWatch alerts into a Sentinel custom log table."""
        if not self.workspace_id or not self.shared_key:
            return {"skipped": "Sentinel not configured"}

        body = json.dumps(alerts).encode("utf-8")
        rfc1123_date = datetime.now(UTC).strftime("%a, %d %b %Y %H:%M:%S GMT")
        signature = self._build_signature(rfc1123_date, len(body), "POST", "application/json", "/api/logs")
        url = f"https://{self.workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": signature,
                "Log-Type": self.log_type,
                "x-ms-date": rfc1123_date,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return {"status": resp.status, "log_type": self.log_type, "count": len(alerts)}
        except Exception as exc:  # noqa: BLE001
            logger.error("Sentinel ingestion failed: %s", exc)
            return {"error": str(exc)}
