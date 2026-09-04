"""Detection module for NASWatch."""

from naswatch.detection.engine import DetectionEngine
from naswatch.detection.rules import (
    detect_identity_spoofing,
    detect_rogue_device,
    detect_slice_intrusion,
)

__all__ = [
    "DetectionEngine",
    "detect_identity_spoofing",
    "detect_rogue_device",
    "detect_slice_intrusion",
]
