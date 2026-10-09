"""Hashing helpers used to keep replayable client values out of the database.

The client sends an HWID that is already an HMAC output. The server applies a
second, independent HMAC with its own pepper before persisting it, so a stolen
``hwid_hash`` column value is not the value the client presents.
"""

import hashlib
import hmac
import secrets

HMAC_ALGORITHM = "sha256"
SESSION_ID_BYTES = 32


def sha256_hex(value: str) -> str:
    """Return the hex SHA-256 digest of ``value``."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def derive_stored_hwid(pepper: str, client_hwid: str) -> str:
    """Return the server-side HMAC-SHA256 of a client-supplied HWID."""
    if not pepper:
        raise ValueError("pepper must not be empty")
    if not client_hwid:
        raise ValueError("client hwid must not be empty")
    return hmac.new(
        pepper.encode("utf-8"), client_hwid.strip().lower().encode("utf-8"), HMAC_ALGORITHM
    ).hexdigest()


def constant_time_equals(left: str, right: str) -> bool:
    """Compare two strings in constant time without raising on odd input."""
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def generate_session_id() -> str:
    """Return a fresh URL-safe session identifier."""
    return secrets.token_urlsafe(SESSION_ID_BYTES)
