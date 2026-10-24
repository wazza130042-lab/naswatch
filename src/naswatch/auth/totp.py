"""Time-based one-time passwords (TOTP, RFC 6238) for operator 2FA.

Implemented with the standard library only, so an operator installation needs
no extra packages and no outbound network access. The codes are the same ones
any authenticator app (Google Authenticator, Authy, Microsoft Authenticator,
1Password, Bitwarden, FreeOTP, ...) produces for the same shared secret.

Time synchronisation
--------------------
TOTP derives the code from the **Unix time** divided into 30-second steps. The
server clock and the phone clock therefore have to agree. We accept one step of
drift in either direction (``window=1``, i.e. +/-30s) to tolerate the usual NTP
error. For a stationary appliance keep NTP (``systemd-timesyncd``/``chronyd``)
enabled; the enrollment screen shows the live server time so an operator can
spot a badly skewed clock immediately.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

DIGITS = 6
STEP_SECONDS = 30
DEFAULT_ISSUER = "NASWatch"
_ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


def generate_secret(length: int = 20) -> str:
    """Return a fresh random Base32 secret (20 bytes = 160 bits, RFC 4226)."""
    return base64.b32encode(secrets.token_bytes(length)).decode("ascii").rstrip("=")


def is_valid_secret(secret: str | None) -> bool:
    """True when ``secret`` decodes as Base32 and is long enough to be secure."""
    try:
        raw = _secret_bytes(secret)
    except (TypeError, ValueError, binascii.Error):
        return False
    return len(raw) >= 10


def _secret_bytes(secret: str | None) -> bytes:
    """Decode a (possibly spaced/lowercase/dash-grouped) Base32 secret."""
    if not secret:
        raise ValueError("empty TOTP secret")
    cleaned = "".join(ch for ch in str(secret).upper() if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    if not cleaned:
        raise ValueError("no Base32 characters in TOTP secret")
    padding = "=" * ((8 - len(cleaned) % 8) % 8)
    return base64.b32decode(cleaned + padding, casefold=True)


def hotp(secret: str, counter: int, digits: int = DIGITS, algorithm: str = "SHA1") -> str:
    """Return the HMAC-based one-time password for ``counter`` (RFC 4226)."""
    digestmod = _ALGORITHMS.get(algorithm.upper())
    if digestmod is None:
        raise ValueError(f"unsupported TOTP algorithm: {algorithm!r}")
    key = _secret_bytes(secret)
    message = struct.pack(">Q", int(counter))
    digest = hmac.new(key, message, digestmod).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10 ** digits)).zfill(digits)


def current_code(secret: str, when: float | None = None, step: int = STEP_SECONDS, digits: int = DIGITS) -> str:
    """Return the code valid at ``when`` (defaults to now), as the app would show."""
    moment = time.time() if when is None else when
    return hotp(secret, int(moment // step), digits)


def counter_for(when: float | None = None, step: int = STEP_SECONDS) -> int:
    """Return the TOTP time-step counter covering ``when``."""
    moment = time.time() if when is None else when
    return int(moment // step)


def verify(
    secret: str | None,
    code: str | None,
    when: float | None = None,
    window: int = 1,
    step: int = STEP_SECONDS,
    digits: int = DIGITS,
) -> bool:
    """Check ``code`` against the TOTP for ``when``, tolerating +/- ``window`` steps.

    Comparisons are constant-time and the previous/next step is accepted so a
    modest clock skew between the appliance and the operator's phone does not
    lock them out.
    """
    return matching_counter(secret, code, when=when, window=window, step=step, digits=digits) is not None


def matching_counter(
    secret: str | None,
    code: str | None,
    when: float | None = None,
    window: int = 1,
    step: int = STEP_SECONDS,
    digits: int = DIGITS,
) -> int | None:
    """Return the matching time-step counter, or ``None`` for an invalid code.

    Only an exact ASCII digit string is accepted. Returning the matched counter
    lets the identity store atomically reject reuse of an already-consumed OTP.
    """
    if not secret or not isinstance(code, str) or step <= 0 or digits <= 0:
        return None
    candidate = code
    if len(candidate) != digits or not candidate.isascii() or not candidate.isdecimal():
        return None
    moment = time.time() if when is None else when
    base = int(moment // step)
    matched: int | None = None
    for offset in range(-abs(int(window)), abs(int(window)) + 1):
        counter = base + offset
        if counter < 0:
            continue
        try:
            expected = hotp(secret, counter, digits)
        except ValueError:
            return None
        equal = hmac.compare_digest(expected, candidate)
        if equal and (matched is None or abs(offset) < abs(matched - base)):
            matched = counter
    return matched


def seconds_remaining(when: float | None = None, step: int = STEP_SECONDS) -> int:
    """Seconds until the current code rolls over (for the countdown hint)."""
    moment = time.time() if when is None else when
    return int(step - (moment % step))


def provisioning_uri(
    secret: str,
    account: str,
    issuer: str = DEFAULT_ISSUER,
    digits: int = DIGITS,
    step: int = STEP_SECONDS,
) -> str:
    """Return the ``otpauth://totp/...`` URI an authenticator app scans/setups.

    ``account`` is normally the operator email and ``issuer`` the tenant/SOC
    name, matching the label shown inside the app.
    """
    label = quote(f"{issuer}:{account}", safe="")
    params = urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": digits,
            "period": step,
        }
    )
    return f"otpauth://totp/{label}?{params}"


def format_secret(secret: str, group: int = 4) -> str:
    """Group the secret into readable blocks for manual entry."""
    cleaned = secret.strip()
    return " ".join(cleaned[i : i + group] for i in range(0, len(cleaned), group))
