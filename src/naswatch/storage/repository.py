"""
Abstract Repository interfaces for Device Inventory and Security Alert persistence.
Enables pluggable data backends (SQLite, PostgreSQL, Memory, etc.) without altering the detection engine.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from naswatch.storage.models import Alert, Device


class DeviceRepository(ABC):
    """Abstract interface for querying and modifying authorized 5G device inventory."""

    @abstractmethod
    def get_by_imsi(self, imsi: str) -> Device | None:
        """Fetch an authorized device record by its IMSI/SUPI."""

    @abstractmethod
    def get_by_imei(self, imei: str) -> Device | None:
        """Fetch an authorized device record by its IMEI/PEI."""

    @abstractmethod
    def list_all(self, limit: int = 100, offset: int = 0) -> list[Device]:
        """List all devices in the authorized inventory."""

    @abstractmethod
    def add(self, device: Device) -> bool:
        """Insert or replace a device in the inventory."""

    @abstractmethod
    def delete(self, imsi: str) -> bool:
        """Remove a device by IMSI."""

    @abstractmethod
    def count(self) -> int:
        """Return the total count of registered devices."""


class AlertRepository(ABC):
    """Abstract interface for recording and retrieving security alerts."""

    @abstractmethod
    def record_alert(self, alert: Alert) -> bool:
        """Persist a newly detected security alert."""

    @abstractmethod
    def get_alerts(
        self,
        limit: int = 100,
        severity: str | None = None,
        rule_type: str | None = None,
        offset: int = 0,
    ) -> list[Alert]:
        """Retrieve recent alerts filtered by criteria."""

    @abstractmethod
    def get_alert_by_id(self, alert_id: str) -> Alert | None:
        """Fetch a specific alert by its UUID."""

    @abstractmethod
    def update_mitigation_status(self, alert_id: str, new_status: str) -> bool:
        """Update incident mitigation status (e.g. BLOCKED, INVESTIGATING, RESOLVED)."""

    @abstractmethod
    def count(self) -> int:
        """Return total alerts recorded."""

    @abstractmethod
    def clear(self) -> None:
        """Clear all alerts (primarily for testing/reset)."""
