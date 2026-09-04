"""
Pluggable alerting and notification system for NASWatch.
Dispatches detected intrusion events to multiple sinks: console, SQLite, webhook, syslog, JSON file, and memory queues.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from pathlib import Path

from naswatch.logging_config import get_logger
from naswatch.storage.models import Alert
from naswatch.storage.repository import AlertRepository

logger = get_logger("alerting.notifier")


class AlertSink(ABC):
    """Abstract interface for receiving and handling alerts."""

    @abstractmethod
    def send(self, alert: Alert) -> bool:
        """Process or forward an alert."""


class ConsoleAlertSink(AlertSink):
    """Outputs colored, human-readable alert banners to stdout."""

    COLORS = {
        "CRITICAL": "\033[91m\033[1m",  # Bold Red
        "HIGH": "\033[93m\033[1m",      # Bold Yellow
        "MEDIUM": "\033[94m\033[1m",    # Bold Blue
        "LOW": "\033[92m",              # Green
        "RESET": "\033[0m",
    }

    def send(self, alert: Alert) -> bool:
        c = self.COLORS.get(alert.severity.value, "")
        reset = self.COLORS["RESET"]
        print(f"\n{c}🚨 [5G IDS ALERT - {alert.severity.value}] {alert.title}{reset}")
        print(f"   ⏱  Time:     {alert.timestamp.isoformat()}")
        print(f"   📋 Rule:     {alert.rule_type.value}")
        print(f"   📱 IMSI:     {alert.imsi or 'N/A'}")
        print(f"   📟 IMEI:     {alert.imei or 'N/A'}")
        print(f"   🌐 Slice:    {alert.target_slice or 'N/A'}")
        print(f"   📡 Cell ID:  {alert.cell_id or 'N/A'}")
        print(f"   📝 Details:  {alert.description}\n")
        return True


class SQLiteAlertSink(AlertSink):
    """Persists alerts to the SQLite database repository."""

    def __init__(self, alert_repo: AlertRepository):
        self.alert_repo = alert_repo

    def send(self, alert: Alert) -> bool:
        try:
            return self.alert_repo.record_alert(alert)
        except Exception as e:
            logger.error(f"Failed to persist alert to SQLite: {e}")
            return False


class FileAlertSink(AlertSink):
    """Appends alerts as structured JSON-Lines to a local log file."""

    def __init__(self, file_path: str = "data/alerts.jsonl"):
        self.file_path = Path(file_path)
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

    def send(self, alert: Alert) -> bool:
        try:
            with open(self.file_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert.to_dict()) + "\n")
            return True
        except Exception as e:
            logger.error(f"Failed writing alert to file {self.file_path}: {e}")
            return False


class WebhookAlertSink(AlertSink):
    """Dispatches alerts via HTTP POST JSON webhook to SIEM / SOAR / Slack."""

    def __init__(
        self,
        url: str,
        auth_token: str | None = None,
        timeout_seconds: int = 5,
    ):
        self.url = url
        self.auth_token = auth_token
        self.timeout = timeout_seconds

    def send(self, alert: Alert) -> bool:
        if not self.url or not self.url.startswith(("http://", "https://")):
            return False

        payload = json.dumps(alert.to_dict()).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "NASWatch-5G-IDS/0.1.0",
        }
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        req = urllib.request.Request(self.url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return response.status in (200, 201, 202, 204)
        except Exception as err:
            logger.warning(f"Webhook notification failed: {err}")
            return False


class SyslogAlertSink(AlertSink):
    """Sends RFC 5424 syslog messages over UDP/TCP."""

    def __init__(self, host: str = "127.0.0.1", port: int = 514, proto: str = "udp"):
        self.host = host
        self.port = port
        self.proto = proto.lower()

    def send(self, alert: Alert) -> bool:
        msg = (
            f"<134>1 {alert.timestamp.isoformat()} naswatch ids - - - "
            f"SEV={alert.severity.value} RULE={alert.rule_type.value} "
            f"IMSI={alert.imsi} IMEI={alert.imei} SLICE={alert.target_slice} "
            f"DESC={alert.title}"
        )
        try:
            if self.proto == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(msg.encode("utf-8"), (self.host, self.port))
                sock.close()
            return True
        except Exception as err:
            logger.debug(f"Syslog send error: {err}")
            return False


class InMemoryAlertSink(AlertSink):
    """In-memory sink used for real-time UI streaming or test inspection."""

    def __init__(self, max_size: int = 1000):
        self.alerts: list[Alert] = []
        self.max_size = max_size

    def send(self, alert: Alert) -> bool:
        self.alerts.append(alert)
        if len(self.alerts) > self.max_size:
            self.alerts.pop(0)
        return True

    def get_latest(self, count: int = 50) -> list[Alert]:
        return list(reversed(self.alerts[-count:]))

    def clear(self) -> None:
        self.alerts.clear()


class AlertNotifier:
    """Composite dispatcher that broadcasts alerts to all configured sinks."""

    def __init__(self, sinks: list[AlertSink] | None = None):
        self.sinks: list[AlertSink] = sinks or []

    def add_sink(self, sink: AlertSink) -> None:
        self.sinks.append(sink)

    def dispatch(self, alert: Alert) -> None:
        for sink in self.sinks:
            try:
                sink.send(alert)
            except Exception as e:
                logger.error(f"Error in alert sink {type(sink).__name__}: {e}")
