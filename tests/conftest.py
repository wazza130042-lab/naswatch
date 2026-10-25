"""
Pytest configuration and shared test fixtures for NASWatch.
"""

from __future__ import annotations

import os
import tempfile
import time
from datetime import UTC, datetime

# Pin environment before any naswatch module is imported. ``jwt_handler`` reads
# NASWATCH_JWT_SECRET once at import time and derives SECRET_KEY from it; the
# audit hash chain is HMAC-keyed with that same key. Without a stable secret the
# suite would sign each run with a random process key, so the audit chain in a
# persisted DB could never verify — and the tests would write to the developer's
# real data/ store. pytest imports conftest before the test modules, so setting
# these here takes effect before those modules import naswatch.
os.environ.setdefault("NASWATCH_JWT_SECRET", "test-secret-" + "0" * 32)
_TEST_DB_DIR = tempfile.mkdtemp(prefix="naswatch-tests-")
os.environ.setdefault("NASWATCH_DB_PATH", os.path.join(_TEST_DB_DIR, "inventory.db"))

import pytest  # noqa: E402

from naswatch.storage.models import (  # noqa: E402
    Device,
    DeviceStatus,
    ParsedSignalingEvent,
    SliceAssignment,
)
from naswatch.storage.sqlite_repo import SQLiteRepository  # noqa: E402


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


@pytest.fixture
def enrolled_admin_login():
    """Return credentials for a test admin with a fresh TOTP factor armed."""
    from naswatch.api import server
    from naswatch.auth import totp

    store = server.get_user_store()
    admin = store.get_by_username("admin@naswatch.io")
    if admin is None:
        from naswatch.storage.models import UserRole

        admin = store.create_user(
            "admin@naswatch.io", "naswatch-admin-password", UserRole.ADMIN
        )
    secret = totp.generate_secret()
    # Only the current step is accepted, so make sure the request that follows this
    # fixture still lands in the step the code was minted for.
    now = time.time()
    if now % totp.STEP_SECONDS > totp.STEP_SECONDS - 2:
        time.sleep(totp.STEP_SECONDS - (now % totp.STEP_SECONDS) + 0.2)
        now = time.time()
    # Arm the factor directly (no code is consumed) so the returned code can be used
    # straight away: an enrolment code would already be spent by the replay guard.
    store.set_totp_secret(admin.id, secret)
    assert store.enable_totp(admin.id) is True
    return {
        "username": admin.username,
        "password": "naswatch-admin-password",
        "totp_code": totp.hotp(secret, totp.counter_for(now)),
    }
