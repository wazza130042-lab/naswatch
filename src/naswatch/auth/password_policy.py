"""Password-strength policy shared by every NASWatch account entry point.

The REST API, the dashboard (first-run setup and User management) and
``scripts/create_admin.py`` all validate through :func:`validate_password`, so
the rule can never drift between surfaces. ``UserStore`` enforces it too, as a
last line of defence.

The policy is deliberately passphrase-friendly — a long mixed phrase beats a
short, symbol-studded one — and blocks the weaknesses that actually get
accounts cracked:

* shorter than ``min_length`` (default 12) or longer than bcrypt's 72-byte
  input limit (bcrypt silently ignores anything past byte 72);
* a well-known / breached-style password (``password``, ``qwerty``, ...);
* the account name itself;
* fewer than two character classes (lowercase / uppercase / digits / symbols).

Weaker-but-allowed patterns (repeats, sequences, containing the account name or
a dictionary word) dock points and are surfaced as hints instead of blocking, so
the caller can show a strength meter and still let the operator through.
"""

from __future__ import annotations

MIN_LENGTH = 12
MAX_BYTES = 72  # bcrypt hashes only the first 72 bytes of input
MIN_CLASSES = 2

# Exact (squashed) values that are too common to accept, plus their digit-stripped
# stems so "password123" / "password!" are caught too.
WEAK_PASSWORDS = frozenset(
    {
        "password", "passw0rd", "passphrase", "letmein", "welcome", "welcome1",
        "admin", "administrator", "root", "toor", "changeme", "changeit",
        "secret", "naswatch", "iloveyou", "monkey", "dragon", "sunshine",
        "princess", "football", "baseball", "superman", "trustno1", "master",
        "login", "guest", "test", "demo", "default", "letmein1", "password1",
        "abc123", "qwerty", "asdfgh", "zxcvbn", "qwerty123", "asdfghjkl",
        "zxcvbnm", "1q2w3e4r", "qazwsx", "asdf1234",
    }
)

# Keyboard / alphabet / digit runs that make a password guessable.
_SEQUENCES = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)

_LABELS = {0: "very weak", 1: "weak", 2: "fair", 3: "good", 4: "strong"}


class WeakPasswordError(ValueError):
    """Raised when a password fails the strength policy."""


class PasswordStrength:
    """Result of :func:`evaluate` for one candidate password."""

    __slots__ = ("ok", "score", "label", "problems", "suggestions")

    def __init__(self, ok: bool, score: int, label: str,
                 problems: list[str], suggestions: list[str]) -> None:
        self.ok = ok
        self.score = score
        self.label = label
        self.problems = problems
        self.suggestions = suggestions

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"PasswordStrength(ok={self.ok}, score={self.score}, label={self.label!r})"


def _classes(password: str) -> int:
    """Count how many of lowercase / uppercase / digit / symbol are present."""
    classes = 0
    if any(ch.islower() for ch in password):
        classes += 1
    if any(ch.isupper() for ch in password):
        classes += 1
    if any(ch.isdigit() for ch in password):
        classes += 1
    if any(not ch.isalnum() for ch in password):
        classes += 1
    return classes


def _squash(password: str) -> str:
    """Lowercase and drop everything but letters/digits (defeats l33t padding)."""
    return "".join(ch for ch in password.lower() if ch.isalnum())


def _local_part(username: str | None) -> str:
    return (username or "").split("@")[0].strip().lower()


def _has_sequence(password: str) -> bool:
    """True when the password contains a 4-character alphabet/keyboard run."""
    lowered = password.lower()
    for seq in _SEQUENCES:
        for i in range(len(seq) - 3):
            chunk = seq[i : i + 4]
            if chunk in lowered or chunk[::-1] in lowered:
                return True
    return False


def _has_repeat(password: str) -> bool:
    """True when one character repeats three or more times in a row."""
    for i in range(len(password) - 2):
        if password[i] == password[i + 1] == password[i + 2]:
            return True
    return False


def _is_common(password: str) -> bool:
    squashed = _squash(password)
    if not squashed:
        return False
    stem = squashed.rstrip("0123456789")
    return squashed in WEAK_PASSWORDS or stem in WEAK_PASSWORDS


def evaluate(
    password: str | None,
    *,
    username: str | None = None,
    min_length: int = MIN_LENGTH,
) -> PasswordStrength:
    """Score ``password`` and list any hard problems.

    ``username`` enables the "password equals the account name" check and the
    "don't reuse your account name" hint.
    """
    pw = password or ""
    problems: list[str] = []
    suggestions: list[str] = []

    if len(pw) < min_length:
        problems.append(f"Use at least {min_length} characters.")
    if len(pw.encode("utf-8")) > MAX_BYTES:
        problems.append(f"Use at most {MAX_BYTES} characters (longer isn't fully hashed).")

    classes = _classes(pw)
    if pw and classes < MIN_CLASSES:
        problems.append("Mix at least two of: lowercase, uppercase, digits, symbols.")

    if pw and _is_common(pw):
        problems.append("This is a commonly used password; choose something unique.")

    lowered = pw.lower()
    local = _local_part(username)
    if pw and local and lowered == local:
        problems.append("The password cannot be the same as the account name.")

    # Soft signals: dock points and hint, but never block.
    if local and len(local) >= 4 and local in lowered:
        suggestions.append("Avoid including your account name in the password.")
    if pw and "password" in lowered and not _is_common(pw):
        suggestions.append("Avoid dictionary words like 'password'.")
    if pw and _has_sequence(pw):
        suggestions.append("Avoid runs like 'abcd' or '1234'.")
    if pw and _has_repeat(pw):
        suggestions.append("Avoid repeating the same character.")

    score = 0
    if len(pw) >= min_length:
        score += 1
    if len(pw) >= 16:
        score += 1
    if len(pw) >= 20:
        score += 1
    if classes >= 3:
        score += 1
    if _is_common(pw):
        score -= 2
    if local and len(local) >= 4 and local in lowered:
        score -= 1
    if pw and _has_sequence(pw):
        score -= 1
    if pw and _has_repeat(pw):
        score -= 1
    score = max(0, min(4, score))
    if problems:
        score = min(score, 1)

    # De-duplicate suggestions while preserving order.
    suggestions = list(dict.fromkeys(suggestions))
    return PasswordStrength(
        ok=not problems,
        score=score,
        label=_LABELS[score],
        problems=tuple(problems),
        suggestions=tuple(suggestions),
    )


def validate_password(
    password: str | None,
    *,
    username: str | None = None,
    min_length: int = MIN_LENGTH,
) -> list[str]:
    """Return the hard problems for ``password`` (empty list means accepted)."""
    return list(evaluate(password, username=username, min_length=min_length).problems)
