"""
Alert Correlation Engine for NASWatch.

Groups related alerts into security incidents based on:
  - Same IMSI within a time window
  - Same Cell ID within a time window
  - Sequential rule progression (e.g., Flood followed by Rogue Device)

Alerts that share an IMSI or a Cell ID (within the same organization) and arrive within
``window_seconds`` of the incident's last activity are added to ONE incident, which keeps its
ID. Incidents that bridge two previously separate ones merge them. This is what prevents
alert fatigue: a registration storm of 500 alerts is one incident with ``alert_count == 500``,
not 500 incidents.

Time is measured with the alerts' own timestamps (not the wall clock), so replaying an old
capture correlates the same way live traffic does.
"""
from __future__ import annotations

import logging
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Any

from naswatch.storage.models import Alert, AlertRuleType, AlertSeverity

logger = logging.getLogger("naswatch.correlation")

# Maximum gap between alerts to consider them the same incident (seconds)
CORRELATION_WINDOW_SECONDS = 300  # 5 minutes

# Incident history kept in memory (oldest incidents fall off first)
MAX_INCIDENT_HISTORY = 10_000

# Severity escalation map: if these rules co-occur within the window, escalate
ESCALATION_CHAINS: list[tuple[AlertRuleType, AlertRuleType]] = [
    (AlertRuleType.SIGNALING_FLOOD, AlertRuleType.ROGUE_DEVICE),
    (AlertRuleType.SIGNALING_FLOOD, AlertRuleType.IDENTITY_SPOOFING),
    (AlertRuleType.FALSE_BASE_STATION, AlertRuleType.CIPHER_DOWNGRADE),
    (AlertRuleType.ROGUE_DEVICE, AlertRuleType.SLICE_INTRUSION),
]

_SEVERITY_ORDER = [
    AlertSeverity.CRITICAL,
    AlertSeverity.HIGH,
    AlertSeverity.MEDIUM,
    AlertSeverity.LOW,
    AlertSeverity.INFO,
]


def _utc(ts: datetime) -> datetime:
    return ts if ts.tzinfo is not None else ts.replace(tzinfo=UTC)


class CorrelatedIncident:
    """A group of related alerts forming a security incident."""

    def __init__(self, incident_id: str, alerts: list[Alert]) -> None:
        self.incident_id = incident_id
        self.alerts: list[Alert] = []
        self._alert_ids: set[str] = set()
        self.org_id: str = alerts[0].org_id if alerts else "default"
        for alert in alerts:
            self._append(alert)
        self._refresh()

    # -- mutation -------------------------------------------------------------
    def _append(self, alert: Alert) -> bool:
        if alert.id in self._alert_ids:
            return False
        self._alert_ids.add(alert.id)
        self.alerts.append(alert)
        return True

    def _refresh(self) -> None:
        self.first_seen: datetime = min(_utc(a.timestamp) for a in self.alerts)
        self.last_seen: datetime = max(_utc(a.timestamp) for a in self.alerts)
        self.rule_types: set[AlertRuleType] = {a.rule_type for a in self.alerts}
        self.imsis: set[str] = {a.imsi for a in self.alerts if a.imsi}
        self.cell_ids: set[str] = {a.cell_id for a in self.alerts if a.cell_id}
        self.escalated: bool = self._check_escalation()
        self.severity: AlertSeverity = self._compute_severity()

    def add_alert(self, alert: Alert) -> bool:
        """Add an alert to this incident. Returns True if it escalated as a result."""
        was_escalated = self.escalated
        if self._append(alert):
            self._refresh()
        return self.escalated and not was_escalated

    def merge(self, other: CorrelatedIncident) -> bool:
        """Absorb another incident. Returns True if this incident became escalated."""
        was_escalated = self.escalated
        changed = False
        for alert in other.alerts:
            changed |= self._append(alert)
        if changed:
            self._refresh()
        return self.escalated and not was_escalated

    # -- evaluation -----------------------------------------------------------
    def _check_escalation(self) -> bool:
        """Check if this incident matches a known escalation chain."""
        for rule_a, rule_b in ESCALATION_CHAINS:
            if rule_a in self.rule_types and rule_b in self.rule_types:
                return True
        return False

    def _compute_severity(self) -> AlertSeverity:
        """Take the highest severity among all alerts, escalate if multi-rule chain."""
        present = {a.severity for a in self.alerts}
        for sev in _SEVERITY_ORDER:
            if sev in present:
                return AlertSeverity.CRITICAL if self.escalated else sev
        return AlertSeverity.INFO

    def matches(self, alert: Alert) -> bool:
        """True if the alert shares a subscriber or cell with this incident (same tenant)."""
        if alert.org_id != self.org_id:
            return False
        return bool(
            (alert.imsi and alert.imsi in self.imsis)
            or (alert.cell_id and alert.cell_id in self.cell_ids)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "org_id": self.org_id,
            "alert_count": len(self.alerts),
            "rule_types": sorted(r.value for r in self.rule_types),
            "imsis": sorted(self.imsis),
            "cell_ids": sorted(self.cell_ids),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "severity": self.severity.value,
            "escalated": self.escalated,
            "alert_ids": [a.id for a in self.alerts],
        }


class CorrelationEngine:
    """
    Stateful alert correlation engine.

    Open incidents (still inside the correlation window) are updated in place as related
    alerts arrive; all incidents stay available through ``get_incidents`` up to a bounded
    history size.
    """

    def __init__(
        self,
        window_seconds: int = CORRELATION_WINDOW_SECONDS,
        max_history: int = MAX_INCIDENT_HISTORY,
    ) -> None:
        self.window_seconds = window_seconds
        self._open: list[CorrelatedIncident] = []
        self._incidents: deque[CorrelatedIncident] = deque(maxlen=max_history)
        self._incident_counter = 0

    def _close_expired(self, reference: datetime) -> None:
        cutoff = reference - timedelta(seconds=self.window_seconds)
        self._open = [i for i in self._open if i.last_seen >= cutoff]

    def ingest(self, alert: Alert) -> CorrelatedIncident | None:
        """
        Add an alert to the incident it belongs to (creating one if needed) and return it.

        Returns None only for alerts that carry neither an IMSI nor a Cell ID, since there is
        nothing to correlate them on.
        """
        if not (alert.imsi or alert.cell_id):
            return None

        self._close_expired(_utc(alert.timestamp))
        matches = [i for i in self._open if i.matches(alert)]

        if not matches:
            self._incident_counter += 1
            incident = CorrelatedIncident(f"INC-{self._incident_counter:06d}", [alert])
            self._open.append(incident)
            self._incidents.append(incident)
            newly_escalated = incident.escalated
        else:
            incident = matches[0]
            newly_escalated = incident.add_alert(alert)
            for other in matches[1:]:  # the alert bridges incidents: merge them into the oldest
                newly_escalated |= incident.merge(other)
                self._open.remove(other)
                try:
                    self._incidents.remove(other)
                except ValueError:
                    pass

        if newly_escalated:
            logger.warning(
                "ESCALATED INCIDENT %s: %d alerts, rules=%s, IMSIs=%s",
                incident.incident_id,
                len(incident.alerts),
                sorted(r.value for r in incident.rule_types),
                sorted(incident.imsis),
            )
        return incident

    def get_incidents(self, limit: int = 100, org_id: str | None = None) -> list[CorrelatedIncident]:
        """Most recent incidents, optionally restricted to one organization (tenant)."""
        incidents = list(self._incidents)
        if org_id is not None:
            incidents = [i for i in incidents if i.org_id == org_id]
        return incidents[-limit:]
