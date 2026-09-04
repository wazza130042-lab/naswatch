"""
NASWatch: Passive 5G Control-Plane Intrusion Detection System.

Detects:
- Rogue Devices / Unauthorized eSIMs (Unregistered IMSI/SUPI)
- Identity Spoofing / SIM Cloning (IMSI-IMEI Mismatch)
- Network-Slice Intrusion (Unauthorized S-NSSAI access)
"""

__version__ = "0.1.0"
__author__ = "NASWatch Security Engineering Team"

from naswatch.detection.engine import DetectionEngine
from naswatch.storage.models import (
    Alert,
    AlertRuleType,
    AlertSeverity,
    Device,
    ParsedSignalingEvent,
    SliceAssignment,
)
from naswatch.storage.sqlite_repo import SQLiteRepository

__all__ = [
    "Alert",
    "AlertRuleType",
    "AlertSeverity",
    "DetectionEngine",
    "Device",
    "ParsedSignalingEvent",
    "SQLiteRepository",
    "SliceAssignment",
]
