"""
Domain data models for NASWatch 5G IDS.
Clean dataclasses representing devices, network slices, signaling events, and security alerts.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class AlertSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AlertRuleType(str, Enum):
    ROGUE_DEVICE = "ROGUE_DEVICE"
    IDENTITY_SPOOFING = "IDENTITY_SPOOFING"
    SLICE_INTRUSION = "SLICE_INTRUSION"
    CIPHER_DOWNGRADE = "CIPHER_DOWNGRADE"
    SIGNALING_FLOOD = "SIGNALING_FLOOD"
    FALSE_BASE_STATION = "FALSE_BASE_STATION"


class DeviceStatus(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    SUSPENDED = "SUSPENDED"


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    AUDITOR = "auditor"


@dataclass
class SliceAssignment:
    """Represents an authorized S-NSSAI (Single Network Slice Selection Assistance Information)."""
    sst: int  # Slice / Service Type (1: eMBB, 2: URLLC, 3: MIoT, 4: V2X, etc.)
    sd: str | None = None  # Slice Differentiator (3 octets, e.g. "000001" or "010203")
    name: str = ""
    description: str = ""

    @property
    def slice_id(self) -> str:
        """Formatted canonical representation of S-NSSAI: SST:SD or SST."""
        if self.sd:
            # Normalize SD: uppercase without 0x prefix, zero-padded to 6 characters
            clean_sd = self.sd.replace("0x", "").replace(":", "").upper().zfill(6)
            return f"{self.sst}:{clean_sd}"
        return f"{self.sst}"

    def matches(self, sst: int, sd: str | None = None) -> bool:
        """Check if target SST and SD match this slice assignment."""
        if self.sst != sst:
            return False
        if self.sd is None or sd is None:
            # If either has no differentiator, SST match qualifies if SD is wildcard/not specified
            return self.sd is None and sd is None
        clean_sd1 = self.sd.replace("0x", "").replace(":", "").upper().zfill(6)
        clean_sd2 = sd.replace("0x", "").replace(":", "").upper().zfill(6)
        return clean_sd1 == clean_sd2


@dataclass
class Device:
    """Represents a provisioned subscriber / SIM / eSIM identity in the authorized inventory."""
    imsi: str  # International Mobile Subscriber Identity / 5G SUPI
    imei: str  # International Mobile Equipment Identity / PEI
    owner_name: str
    device_model: str
    status: DeviceStatus = DeviceStatus.ACTIVE
    allowed_slices: list[SliceAssignment] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    notes: str = ""
    org_id: str = "default"  # Multi-tenant ownership scope

    def is_slice_authorized(self, sst: int, sd: str | None = None) -> bool:
        """Verify whether this device is authorized to attach to the given S-NSSAI slice."""
        for slice_assignment in self.allowed_slices:
            if slice_assignment.matches(sst, sd):
                return True
        return False


@dataclass
class ParsedSignalingEvent:
    """Decoded 5G NGAP/NAS signaling parameters extracted from packet stream."""
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    packet_num: int | None = None
    source_ip: str = "0.0.0.0"
    dest_ip: str = "0.0.0.0"
    protocol: str = "NGAP/NAS"
    procedure_code: int | None = None
    procedure_name: str | None = None
    ran_ue_ngap_id: int | None = None
    amf_ue_ngap_id: int | None = None
    imsi: str | None = None  # IMSI or extracted SUPI
    imei: str | None = None  # IMEI or PEI
    guti: str | None = None
    requested_sst: int | None = None
    requested_sd: str | None = None
    cell_id: str | None = None
    tac: int | None = None
    cipher_algo: str | None = None  # e.g., NEA0 (Null), NEA1, NEA2, NEA3
    integrity_algo: str | None = None  # e.g., NIA0 (Null), NIA1, NIA2, NIA3
    raw_payload_hex: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def requested_slice_id(self) -> str | None:
        if self.requested_sst is None:
            return None
        if self.requested_sd:
            clean_sd = self.requested_sd.replace("0x", "").replace(":", "").upper().zfill(6)
            return f"{self.requested_sst}:{clean_sd}"
        return f"{self.requested_sst}"


@dataclass
class Alert:
    """Security Incident alert produced by the detection rules engine."""
    rule_type: AlertRuleType
    severity: AlertSeverity
    title: str
    description: str
    imsi: str | None = None
    imei: str | None = None
    cell_id: str | None = None
    target_slice: str | None = None
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    mitigation_status: str = "NEW"  # NEW, INVESTIGATING, BLOCKED, RESOLVED
    raw_event: dict[str, Any] | None = None
    org_id: str = "default"  # Multi-tenant ownership scope
    assigned_to_id: str | None = None
    assigned_to_name: str | None = None
    claimed_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "rule_type": self.rule_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "imsi": self.imsi,
            "imei": self.imei,
            "cell_id": self.cell_id,
            "target_slice": self.target_slice,
            "mitigation_status": self.mitigation_status,
            "raw_event": self.raw_event or {},
            "org_id": self.org_id,
            "assigned_to_id": self.assigned_to_id,
            "assigned_to_name": self.assigned_to_name,
            "claimed_at": self.claimed_at.isoformat() if self.claimed_at else None,
        }


@dataclass
class User:
    """Authenticated operator account with an RBAC role and tenant scope."""
    username: str
    password_hash: str
    role: UserRole
    org_id: str = "default"
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    active: bool = True
    must_change_password: bool = False
    # TOTP second factor (RFC 6238). The secret is only materialised while
    # enrollment is pending or when the factor is switched on.
    totp_secret: str | None = None
    totp_enabled: bool = False
    totp_enrolled_at: datetime | None = None

    def to_dict(self, include_secret: bool = False) -> dict[str, Any]:
        data = {
            "id": self.id,
            "username": self.username,
            "role": self.role.value,
            "org_id": self.org_id,
            "active": self.active,
            "must_change_password": self.must_change_password,
            "totp_enabled": self.totp_enabled,
            "totp_enrolled_at": self.totp_enrolled_at.isoformat() if self.totp_enrolled_at else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
        if include_secret:
            data["password_hash"] = self.password_hash
            data["totp_secret"] = self.totp_secret
        return data
