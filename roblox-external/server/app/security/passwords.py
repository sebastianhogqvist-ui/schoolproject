"""Administrator password hashing using argon2id.

The ``BCRYPT_*`` setting names are kept for familiarity with the C++ side, but
they map onto argon2id's ``time_cost`` (t), ``memory_cost`` (m) and
``parallelism`` (p) parameters. Hashes are self-describing, so
:func:`needs_rehash` detects parameter drift without a lookup table.
"""

import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from app.config import Settings, get_settings

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 1024

# A random value that no operator can ever type, hashed once per cost profile so that
# "unknown username" costs the same as "wrong password" and cannot be timed apart.
_DUMMY_PASSWORD = secrets.token_urlsafe(32)
_dummy_cache: dict[tuple[int, int, int], str] = {}


def _hasher(settings: Settings | None = None) -> PasswordHasher:
    """Build an argon2id hasher from the configured cost parameters."""
    config = settings or get_settings()
    return PasswordHasher(
        time_cost=config.BCRYPT_TIME_COST,
        memory_cost=config.BCRYPT_MEMORY_COST,
        parallelism=config.BCRYPT_PARALLELISM,
        hash_len=32,
        salt_len=16,
    )


def hash_password(password: str, settings: Settings | None = None) -> str:
    """Hash a plaintext password, rejecting passwords too weak to be worth storing."""
    if not password:
        raise ValueError("password must not be empty")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"password must be at most {MAX_PASSWORD_LENGTH} characters")
    return _hasher(settings).hash(password)


def verify_password(password_hash: str, password: str, settings: Settings | None = None) -> bool:
    """Return whether ``password`` matches ``password_hash``.

    Never raises and never reveals *why* a check failed, so the caller cannot
    accidentally turn it into a username-enumeration oracle.
    """
    if not password_hash or not password:
        return False
    try:
        return _hasher(settings).verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str, settings: Settings | None = None) -> bool:
    """Return whether ``password_hash`` was made with outdated cost parameters."""
    if not password_hash:
        return True
    try:
        return _hasher(settings).check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def dummy_hash(settings: Settings | None = None) -> str:
    """Return a real argon2id hash of a random value, for timing equalisation.

    Verification against it always fails, and it costs the same key derivation as
    a genuine check, so an attacker cannot enumerate usernames by response time.
    """
    config = settings or get_settings()
    profile = (config.BCRYPT_TIME_COST, config.BCRYPT_MEMORY_COST, config.BCRYPT_PARALLELISM)
    cached = _dummy_cache.get(profile)
    if cached is None:
        cached = _hasher(config).hash(_DUMMY_PASSWORD)
        _dummy_cache[profile] = cached
    return cached
