"""
Alert Correlation Engine for NASWatch.

Groups related alerts into security incidents based on:
  - Same IMSI within a time window
  - Same Cell ID within a time window
  - Sequential rule progression (e.g., Flood followed by Rogue Device)

This prevents alert fatigue by collapsing redundant flood alerts into 1 incident.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from naswatch.storage.models import Alert, AlertRuleType, AlertSeverity

logger = logging.getLogger("naswatch.correlation")

# Maximum gap between alerts to consider them the same incident (seconds)
CORRELATION_WINDOW_SECONDS = 300  # 5 minutes

# Severity escalation map: if these rules co-occur within the window, escalate
ESCALATION_CHAINS: list[tuple[AlertRuleType, AlertRuleType]] = [
    (AlertRuleType.SIGNALING_FLOOD, AlertRuleType.ROGUE_DEVICE),
    (AlertRuleType.SIGNALING_FLOOD, AlertRuleType.IDENTITY_SPOOFING),
    (AlertRuleType.FALSE_BASE_STATION, AlertRuleType.CIPHER_DOWNGRADE),
    (AlertRuleType.ROGUE_DEVICE, AlertRuleType.SLICE_INTRUSION),
]


class CorrelatedIncident:
    """A group of related alerts forming a security incident."""

    def __init__(self, incident_id: str, alerts: list[Alert]) -> None:
        self.incident_id = incident_id
        self.alerts = alerts
        self.first_seen: datetime = min(a.timestamp for a in alerts)
        self.last_seen: datetime = max(a.timestamp for a in alerts)
        self.rule_types: set[AlertRuleType] = {a.rule_type for a in alerts}
        self.imsis: set[str] = {a.imsi for a in alerts if a.imsi}
        self.cell_ids: set[str] = {a.cell_id for a in alerts if a.cell_id}
        self.escalated: bool = self._check_escalation()
        self.severity: AlertSeverity = self._compute_severity()

    def _check_escalation(self) -> bool:
        """Check if this incident matches a known escalation chain."""
        for rule_a, rule_b in ESCALATION_CHAINS:
            if rule_a in self.rule_types and rule_b in self.rule_types:
                return True
        return False

    def _compute_severity(self) -> AlertSeverity:
        """Take the highest severity among all alerts, escalate if multi-rule chain."""
        severity_order = [AlertSeverity.CRITICAL, AlertSeverity.HIGH, AlertSeverity.MEDIUM, AlertSeverity.LOW, AlertSeverity.INFO]
        for sev in severity_order:
            for a in self.alerts:
                if a.severity == sev:
                    return AlertSeverity.CRITICAL if self.escalated else sev
        return AlertSeverity.INFO

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "alert_count": len(self.alerts),
            "rule_types": [r.value for r in self.rule_types],
            "imsis": list(self.imsis),
            "cell_ids": list(self.cell_ids),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "severity": self.severity.value,
            "escalated": self.escalated,
            "alert_ids": [a.id for a in self.alerts],
        }


class CorrelationEngine:
    """
    Stateful alert correlation engine.
    Groups alerts from the same IMSI or Cell ID within a sliding time window.
    """

    def __init__(self, window_seconds: int = CORRELATION_WINDOW_SECONDS) -> None:
        self.window_seconds = window_seconds
        # imsi -> list of alerts in current window
        self._imsi_buckets: defaultdict[str, list[Alert]] = defaultdict(list)
        # cell_id -> list of alerts in current window
        self._cell_buckets: defaultdict[str, list[Alert]] = defaultdict(list)
        self._incidents: list[CorrelatedIncident] = []
        self._incident_counter = 0

    def _evict_old(self) -> None:
        """Remove alerts outside the correlation window."""
        cutoff = datetime.now(UTC) - timedelta(seconds=self.window_seconds)
        for key in list(self._imsi_buckets.keys()):
            self._imsi_buckets[key] = [a for a in self._imsi_buckets[key] if a.timestamp >= cutoff]
            if not self._imsi_buckets[key]:
                del self._imsi_buckets[key]
        for key in list(self._cell_buckets.keys()):
            self._cell_buckets[key] = [a for a in self._cell_buckets[key] if a.timestamp >= cutoff]
            if not self._cell_buckets[key]:
                del self._cell_buckets[key]

    def ingest(self, alert: Alert) -> CorrelatedIncident | None:
        """
        Ingest a new alert into the correlation engine.
        Returns a CorrelatedIncident if the alert correlates with existing ones, None otherwise.
        """
        self._evict_old()

        correlated: list[Alert] = [alert]

        if alert.imsi:
            bucket = self._imsi_buckets[alert.imsi]
            if bucket:
                correlated.extend(bucket)
            bucket.append(alert)

        if alert.cell_id:
            bucket = self._cell_buckets[alert.cell_id]
            if bucket:
                for a in bucket:
                    if a not in correlated:
                        correlated.append(a)
            bucket.append(alert)

        if len(correlated) > 1 or alert.imsi or alert.cell_id:
            self._incident_counter += 1
            incident_id = f"INC-{self._incident_counter:06d}"
            incident = CorrelatedIncident(incident_id=incident_id, alerts=correlated)
            self._incidents.append(incident)
            if incident.escalated:
                logger.warning(
                    "ESCALATED INCIDENT %s: %d alerts, rules=%s, IMSIs=%s",
                    incident_id, len(correlated), incident.rule_types, incident.imsis,
                )
            return incident
        return None

    def get_incidents(self, limit: int = 100) -> list[CorrelatedIncident]:
        return self._incidents[-limit:]
