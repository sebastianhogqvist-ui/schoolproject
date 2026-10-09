"""License key generation, canonicalization, hashing and masking.

The canonical form is ``XXXX-XXXX-XXXX-XXXX``. Only the HMAC-SHA256 of a
canonical key is ever persisted, so a database leak cannot be replayed
against a client and cannot be reversed into a usable key.
"""

import hashlib
import hmac
import secrets

KEY_GROUP_SIZE = 4
KEY_GROUPS = 4
KEY_LENGTH = KEY_GROUP_SIZE * KEY_GROUPS
KEY_ENTROPY_BITS = KEY_LENGTH * 5
KEY_SEPARATOR = "-"
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_STRIPPED_CHARACTERS = " \t\r\n\v\f\u00a0" + KEY_SEPARATOR
MASKED_PREFIX_GROUP = "XXXX"
MASKED_MIDDLE_GROUP = "****"
MASKED_GROUPS = (MASKED_PREFIX_GROUP, MASKED_MIDDLE_GROUP, MASKED_MIDDLE_GROUP)


def generate_license_key() -> str:
    """Return a fresh 80-bit license key in canonical dashed form."""
    body = "".join(secrets.choice(ALPHABET) for _ in range(KEY_LENGTH))
    return KEY_SEPARATOR.join(
        body[index * KEY_GROUP_SIZE : (index + 1) * KEY_GROUP_SIZE] for index in range(KEY_GROUPS)
    )


def normalize_license_key(raw: str) -> str:
    """Canonicalize user input to ``XXXX-XXXX-XXXX-XXXX``.

    Whitespace, case and separator placement are normalized away; length and
    alphabet are then checked exactly, so prefixes and near-misses are
    rejected with :class:`ValueError` rather than silently truncated.
    """
    if not isinstance(raw, str):
        raise ValueError("license key must be a string")

    body = "".join(ch for ch in raw.strip().upper() if ch not in _STRIPPED_CHARACTERS)
    if len(body) != KEY_LENGTH:
        raise ValueError(f"license key must contain exactly {KEY_LENGTH} characters")
    if any(ch not in ALPHABET for ch in body):
        raise ValueError("license key contains characters outside the allowed alphabet")

    return KEY_SEPARATOR.join(
        body[index * KEY_GROUP_SIZE : (index + 1) * KEY_GROUP_SIZE] for index in range(KEY_GROUPS)
    )


def hash_license_key(pepper: str, key: str) -> str:
    """Return the hex HMAC-SHA256 of the canonical key under ``pepper``."""
    canonical = normalize_license_key(key)
    if not pepper:
        raise ValueError("pepper must not be empty")
    return hmac.new(pepper.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def mask_license_key(key: str) -> str:
    """Return a log/UI-safe rendering, e.g. ``XXXX-****-****-7899``.

    Only the final group survives, which is enough for a human to match a key
    against a support ticket without exposing a usable key.
    """
    try:
        canonical = normalize_license_key(key)
    except ValueError:
        return KEY_SEPARATOR.join((*MASKED_GROUPS, MASKED_MIDDLE_GROUP))
    groups = canonical.split(KEY_SEPARATOR)
    return KEY_SEPARATOR.join((*MASKED_GROUPS, groups[-1]))
