"""Tests for the shared password-strength policy and its store enforcement."""
from __future__ import annotations

import pytest

from naswatch.auth.password_policy import (
    WeakPasswordError,
    evaluate,
    validate_password,
)
from naswatch.auth.users import UserStore
from naswatch.storage.models import UserRole

# Passwords used elsewhere in the suite and docs: the policy must keep accepting
# them so a rule change cannot silently lock operators out.
EXISTING_PASSWORDS = [
    "naswatch-admin-password",
    "change-me-in-production",
    "sup3r-Strong-Pass!",
    "new-Sup3r-Pass!",
    "Strong-Pass!-xyz",
    "Strong-Pass!-abc",
    "correct-horse-battery",
    "another-long-passphrase",
]


@pytest.mark.parametrize("password", EXISTING_PASSWORDS)
def test_existing_passwords_still_accepted(password):
    assert validate_password(password, username="admin@naswatch.io") == []


def test_strong_passphrase_scores_highest():
    strength = evaluate("Tr0ub4dor&-correct-horse-battery-staple")
    assert strength.ok is True
    assert strength.score == 4
    assert strength.label == "strong"
    assert strength.problems == ()


def test_short_password_rejected():
    strength = evaluate("Ab1!x")
    assert strength.ok is False
    assert 0 < strength.score <= 1
    assert any("at least 12" in p for p in strength.problems)


def test_single_character_class_rejected():
    # A long but lowercase-only passphrase is still only one class.
    strength = evaluate("correcthorsebattery")
    assert strength.ok is False
    assert any("two of" in p for p in strength.problems)


@pytest.mark.parametrize("password", ["password123", "letmein!", "qwerty", "Password1!"])
def test_common_passwords_rejected(password):
    strength = evaluate(password)
    assert strength.ok is False
    assert any("commonly used" in p for p in strength.problems)


def test_password_matching_account_name_rejected():
    username = "Admin-LocalPart-99@naswatch.io"
    strength = evaluate("Admin-LocalPart-99", username=username)
    assert strength.ok is False
    assert any("same as the account name" in p for p in strength.problems)


def test_over_72_bytes_rejected():
    # bcrypt only hashes the first 72 bytes, so longer input is a foot-gun.
    strength = evaluate("Aa1!" * 20)  # 80 bytes
    assert strength.ok is False
    assert any("at most 72" in p for p in strength.problems)


def test_suggestions_flag_username_and_sequences():
    strength = evaluate("MyAdmin-abcd-Phrase-99", username="admin@naswatch.io")
    assert strength.ok is True
    assert any("account name" in s for s in strength.suggestions)
    assert any("abcd" in s for s in strength.suggestions)
    assert strength.score < 4  # docked, but still allowed


def test_empty_password_problems():
    assert evaluate("").ok is False
    assert validate_password(None) != []


# ---------------------------------------------------------------------------
# Store enforcement — the single choke point for every account-creation path.
# ---------------------------------------------------------------------------
def test_store_rejects_weak_password_on_create():
    store = UserStore(db_path=":memory:")
    with pytest.raises(WeakPasswordError):
        store.create_user("weak@naswatch.io", "password", UserRole.ANALYST)
    assert store.get_by_username("weak@naswatch.io") is None


def test_store_rejects_weak_password_on_reset():
    store = UserStore(db_path=":memory:")
    user = store.create_user("strong@naswatch.io", "correct-horse-battery", UserRole.ANALYST)
    with pytest.raises(WeakPasswordError):
        store.reset_password(user.id, "short")
    # The original password is untouched after a rejected reset.
    assert store.authenticate("strong@naswatch.io", "correct-horse-battery") is not None


def test_store_accepts_strong_password():
    store = UserStore(db_path=":memory:")
    user = store.create_user("ok@naswatch.io", "correct-horse-battery", UserRole.VIEWER)
    assert store.authenticate("ok@naswatch.io", "correct-horse-battery").id == user.id
