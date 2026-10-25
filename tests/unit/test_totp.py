"""Tests for the RFC 6238 TOTP second factor and its identity-store wiring."""
from __future__ import annotations

import base64
import sqlite3

from naswatch.auth import totp
from naswatch.auth.users import UserStore
from naswatch.storage.models import UserRole

# RFC 6238 Appendix B — key is the ASCII string below, SHA-1.
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
RFC_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


def test_migration_adds_totp_columns(tmp_path):
    """An existing install gains the TOTP columns on the next boot."""
    db_file = tmp_path / "legacy.db"
    _legacy_user_db(str(db_file))

    store = UserStore(db_path=str(db_file))
    assert {"totp_secret", "totp_enabled", "totp_enrolled_at", "last_totp_counter"} <= store._existing_columns()

    legacy = store.get_by_id("legacy-1")
    assert legacy is not None
    assert legacy.totp_enabled is False
    assert legacy.totp_secret is None

    # The migrated account can now arm a second factor like a fresh one.
    secret = totp.generate_secret()
    store.set_totp_secret("legacy-1", secret)
    assert store.enable_totp("legacy-1") is True
    assert store.get_by_id("legacy-1").totp_enabled is True


def test_rfc6238_vectors():
    """Our HOTP matches the published RFC 6238 SHA-1 test vectors."""
    for unix_time, expected in RFC_VECTORS:
        assert totp.hotp(RFC_SECRET, unix_time // 30, digits=8) == expected


def test_generate_and_validate_secret():
    secret = totp.generate_secret()
    assert len(secret) == 32
    assert totp.is_valid_secret(secret)
    assert not totp.is_valid_secret("!!!")
    assert not totp.is_valid_secret("")
    assert not totp.is_valid_secret("ABCD")  # too short


def test_secret_is_case_and_separator_insensitive():
    secret = totp.generate_secret()
    spaced = " ".join(secret[i : i + 4] for i in range(0, len(secret), 4))
    now = 1_700_000_000
    assert totp.hotp(secret.lower(), totp.counter_for(now)) == totp.hotp(spaced, totp.counter_for(now))


def test_current_code_roundtrip():
    secret = totp.generate_secret()
    when = 1_700_000_000
    code = totp.current_code(secret, when=when)
    assert len(code) == 6 and code.isdigit()
    assert totp.verify(secret, code, when=when)
    assert not totp.verify(secret, "000000", when=when)
    assert not totp.verify(secret, "", when=when)
    assert not totp.verify("", code, when=when)
    assert not totp.verify(secret, "12345", when=when)
    assert not totp.verify(secret, "12x456", when=when)
    assert not totp.verify(secret, "１２３４５６", when=when)


def test_matching_counter_returns_the_accepted_time_step():
    secret = totp.generate_secret()
    when = 1_700_000_000
    same_step = totp.current_code(secret, when=when)
    previous_step = totp.current_code(secret, when=when - 30)
    assert totp.matching_counter(secret, same_step, when=when) == totp.counter_for(when)
    assert totp.matching_counter(secret, previous_step, when=when, window=1) == totp.counter_for(when - 30)
    assert totp.matching_counter(secret, "12x456", when=when) is None


def test_expired_code_is_rejected_by_default():
    """A code dies when the authenticator rolls over, without opting into drift."""
    secret = totp.generate_secret()
    step = 30
    shown_at = 1_700_000_020  # step N, 10s in
    code = totp.current_code(secret, when=shown_at)
    rollover = shown_at + (step - shown_at % step)  # first second of step N+1
    assert rollover == 1_700_000_040 and shown_at % step == 10

    assert totp.verify(secret, code, when=shown_at)
    assert totp.verify(secret, code, when=rollover - 1)
    assert not totp.verify(secret, code, when=rollover)
    assert not totp.verify(secret, code, when=rollover + 10)  # the reported case
    assert not totp.verify(secret, code, when=rollover + 29)


def test_verify_tolerates_one_step_of_drift_when_opted_in():
    secret = totp.generate_secret()
    when = 1_700_000_000  # well inside a 30s step, so +/-30s shifts one step

    same_step = totp.current_code(secret, when=when)
    one_step_back = totp.current_code(secret, when=when - 30)
    two_steps_back = totp.current_code(secret, when=when - 60)

    assert totp.verify(secret, same_step, when=when, window=1)
    assert totp.verify(secret, one_step_back, when=when, window=1)
    assert not totp.verify(secret, two_steps_back, when=when, window=1)
    # ... but two steps of drift is accepted with window=2
    assert totp.verify(secret, two_steps_back, when=when, window=2)


def test_format_and_uri():
    secret = totp.generate_secret()
    grouped = totp.format_secret(secret, group=4)
    assert grouped.replace(" ", "") == secret
    uri = totp.provisioning_uri(secret, "admin@naswatch.io", issuer="NASWatch")
    assert uri.startswith("otpauth://totp/")
    assert f"secret={secret}" in uri
    assert "issuer=NASWatch" in uri
    assert "digits=6" in uri and "period=30" in uri


def _legacy_user_db(path: str) -> None:
    """Create a pre-2FA users table with one row."""
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE users (
            id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'viewer',
            org_id TEXT NOT NULL DEFAULT 'default', active INTEGER NOT NULL DEFAULT 1,
            must_change_password INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "INSERT INTO users (id, username, password_hash, role, org_id, active, "
        "must_change_password, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("legacy-1", "legacy@naswatch.io", "hash", "admin", "default", 1, 0,
         "2020-01-01T00:00:00+00:00", "2020-01-01T00:00:00+00:00"),
    )
    conn.commit()
    conn.close()


def test_user_store_totp_lifecycle():
    store = UserStore(db_path=":memory:")
    user = store.create_user("ops@naswatch.io", "correct-horse-battery", UserRole.ANALYST)
    assert user.totp_enabled is False

    secret = totp.generate_secret()
    store.set_totp_secret(user.id, secret)
    staged = store.get_by_id(user.id)
    assert staged.totp_secret == secret
    assert staged.totp_enabled is False  # not armed until a code is proven

    assert store.enable_totp(user.id) is True
    armed = store.get_by_id(user.id)
    assert armed.totp_enabled is True
    assert armed.totp_enrolled_at is not None
    assert totp.verify(armed.totp_secret, totp.current_code(armed.totp_secret))

    store.disable_totp(user.id)
    cleared = store.get_by_id(user.id)
    assert cleared.totp_enabled is False
    assert cleared.totp_secret is None
    assert cleared.totp_enrolled_at is None


def test_enrollment_and_login_counters_are_single_use():
    store = UserStore(db_path=":memory:")
    user = store.create_user("single-use@naswatch.io", "another-Strong-Pass!", UserRole.ANALYST)
    secret = totp.generate_secret()
    code = totp.current_code(secret)
    assert store.complete_totp_enrollment(user.id, secret, code) is True

    counter = totp.matching_counter(secret, code)
    assert counter is not None
    assert store.consume_totp_counter(user.id, counter) is False
    assert store.consume_totp_counter(user.id, counter + 1) is True
    assert store.consume_totp_counter(user.id, counter + 1) is False


def test_to_dict_hides_totp_secret():
    store = UserStore(db_path=":memory:")
    user = store.create_user("viewer@naswatch.io", "another-long-passphrase", UserRole.VIEWER)
    store.set_totp_secret(user.id, totp.generate_secret())
    fresh = store.get_by_id(user.id)

    public = fresh.to_dict()
    assert public["totp_enabled"] is False
    assert "totp_secret" not in public

    private = fresh.to_dict(include_secret=True)
    assert public and "totp_secret" not in public
    assert public.get("totp_secret") is None
    assert "totp_secret" in private


# The migration of a pre-existing table is covered by
# ``test_migration_adds_totp_columns`` and ``_legacy_user_db`` above.
