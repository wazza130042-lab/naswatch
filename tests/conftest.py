"""
Pytest configuration and shared test fixtures for NASWatch.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from naswatch.storage.models import (
    Device,
    DeviceStatus,
    ParsedSignalingEvent,
    SliceAssignment,
)
from naswatch.storage.sqlite_repo import SQLiteRepository


@pytest.fixture
def memory_repo() -> SQLiteRepository:
    """Provides a fresh in-memory SQLite repository for testing."""
    repo = SQLiteRepository(db_path=":memory:")
    # Seed standard test device inventory
    dev1 = Device(
        imsi="999700000000001",
        imei="860123456789012",
        owner_name="Alice Security Operations",
        device_model="5G-CPE-Industrial-v2",
        status=DeviceStatus.ACTIVE,
        allowed_slices=[
            SliceAssignment(sst=1, sd="000001", name="eMBB-Public"),
        ],
    )
    dev2 = Device(
        imsi="999700000000002",
        imei="860123456789022",
        owner_name="Bob Fleet Logistics",
        device_model="IoT-Tracker-5G",
        status=DeviceStatus.ACTIVE,
        allowed_slices=[
            SliceAssignment(sst=1, sd="000001", name="eMBB-Public"),
        ],
    )
    dev3 = Device(
        imsi="999700000000003",
        imei="860123456789033",
        owner_name="Charlie Ex-Employee",
        device_model="Pixel-8-Pro",
        status=DeviceStatus.SUSPENDED,
        allowed_slices=[
            SliceAssignment(sst=1, sd="000001", name="eMBB-Public"),
        ],
    )
    repo.add(dev1)
    repo.add(dev2)
    repo.add(dev3)
    return repo


@pytest.fixture
def authorized_device() -> Device:
    """Single authorized device fixture."""
    return Device(
        imsi="999700000000001",
        imei="860123456789012",
        owner_name="Alice Security Operations",
        device_model="5G-CPE-Industrial-v2",
        status=DeviceStatus.ACTIVE,
        allowed_slices=[
            SliceAssignment(sst=1, sd="000001", name="eMBB-Public"),
        ],
    )


@pytest.fixture
def benign_event() -> ParsedSignalingEvent:
    """Event representing legitimate subscriber traffic."""
    return ParsedSignalingEvent(
        timestamp=datetime.now(UTC),
        packet_num=1,
        source_ip="192.168.56.10",
        dest_ip="192.168.56.20",
        imsi="999700000000001",
        imei="860123456789012",
        requested_sst=1,
        requested_sd="000001",
        cell_id="0x000000010",
        tac=1,
    )


@pytest.fixture(autouse=True)
def _provision_bootstrap_admin(monkeypatch):
    """Run tests against a provisioned install (env-seeded first administrator).

    A real fresh install starts with no accounts and shows the UI first-run
    setup; unattended installs seed the account from the environment. Tests use
    the environment path so ``UserStore`` has a known admin to authenticate as.
    """
    monkeypatch.setenv("NASWATCH_ADMIN_EMAIL", "admin@naswatch.io")
    monkeypatch.setenv("NASWATCH_ADMIN_PASSWORD", "naswatch-admin-password")
