"""Short-lived JWT service tokens for inter-service authentication.

Service tokens prove the caller is a trusted internal service, not an
external client. They are signed with the same JWT secret as client and
admin tokens but carry ``typ == "service"`` so they can never be confused
with a client or admin token. Token nonces are generated with the
``secrets`` module, never ``random``.

Replay protection is provided via a short TTL (default 300s) and a
per-process nonce store that tracks consumed JWT IDs (jti).
"""

import secrets
import threading
import time
from collections import OrderedDict
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from jwt import InvalidTokenError

from app.config import Settings
from app.security.tokens import TokenError

SERVICE_TOKEN_TYPE: str = "service"
SERVICE_TOKEN_AUDIENCE_SUFFIX: str = "service"

REQUIRED_SERVICE_CLAIMS: tuple[str, ...] = ("exp", "iat", "sub", "typ", "jti", "scope")

# In-memory store for consumed service token JTIs to prevent replay within TTL
_jti_store: OrderedDict[str, float] = OrderedDict()
_jti_lock = threading.Lock()
_JTI_TTL_SECONDS = 300  # Match default SERVICE_TOKEN_TTL_SECONDS
_MAX_JTI_STORE_SIZE = 10000


def _cleanup_jti_store(now: float) -> None:
    """Remove expired JTIs from the store."""
    cutoff = now - _JTI_TTL_SECONDS
    while _jti_store and next(iter(_jti_store.values())) <= cutoff:
        _jti_store.popitem(last=False)
    # Enforce max size as fallback
    while len(_jti_store) > _MAX_JTI_STORE_SIZE:
        _jti_store.popitem(last=False)


def _check_and_record_jti(jti: str, now: float) -> bool:
    """Return True if JTI is new (not replayed), False if already seen."""
    with _jti_lock:
        _cleanup_jti_store(now)
        if jti in _jti_store:
            return False
        _jti_store[jti] = now
        return True


def generate_service_token() -> str:
    """Return a cryptographically random service token nonce."""
    return secrets.token_hex(32)


def encode_service_token(
    token: str,
    ttl_seconds: int,
    settings: Settings,
    extra_claims: dict[str, Any] | None = None,
    scope: str | None = None,
) -> tuple[str, str, datetime]:
    """Sign ``token`` as a short-lived service JWT.

    Args:
        token: The service token nonce.
        ttl_seconds: Time-to-live in seconds.
        settings: Application settings.
        extra_claims: Optional additional claims to embed (e.g., client sid, lid).
        scope: Optional scope string (e.g., "license:activate", "session:validate").

    Returns:
        Tuple of (encoded_jwt, jti, expires_at).
    """
    if not token:
        raise TokenError("service token must not be empty")
    if ttl_seconds <= 0:
        raise TokenError("ttl must be greater than zero")

    issued_at = datetime.now(UTC).replace(microsecond=0)
    expires_at = issued_at + timedelta(seconds=ttl_seconds)
    jti = secrets.token_hex(16)

    # Service tokens use a distinct audience to prevent cross-service confusion
    service_audience = f"{settings.jwt_audience}:{SERVICE_TOKEN_AUDIENCE_SUFFIX}"

    claims: dict[str, Any] = {
        "iss": settings.jwt_issuer,
        "aud": service_audience,
        "sub": token,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": expires_at,
        "jti": jti,
        "typ": SERVICE_TOKEN_TYPE,
    }
    if scope:
        claims["scope"] = scope
    if extra_claims:
        reserved = {"iss", "aud", "sub", "iat", "nbf", "exp", "jti", "typ", "scope"}
        overlap = reserved & set(extra_claims)
        if overlap:
            raise TokenError(f"extra_claims must not override {sorted(overlap)}")
        claims.update(extra_claims)

    encoded = jwt.encode(
        claims,
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
        headers={"typ": "JWT"},
    )
    return encoded, jti, expires_at


def decode_service_token(token: str, settings: Settings) -> dict[str, Any]:
    """Verify a service token and return its claims.

    Raises :class:`TokenError` for malformed, tampered, expired, wrong-type,
    or otherwise invalid tokens. Also enforces replay protection via JTI tracking.
    """
    if not token or not isinstance(token, str):
        raise TokenError("service token is missing")

    service_audience = f"{settings.jwt_audience}:{SERVICE_TOKEN_AUDIENCE_SUFFIX}"

    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            audience=service_audience,
            issuer=settings.jwt_issuer,
            options={
                "require": list(REQUIRED_SERVICE_CLAIMS),
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True,
                "verify_signature": True,
            },
        )
    except InvalidTokenError as exc:
        raise TokenError(f"service token rejected: {type(exc).__name__}") from None

    if claims.get("typ") != SERVICE_TOKEN_TYPE:
        raise TokenError("service token type mismatch")
    if not claims.get("jti"):
        raise TokenError("service token is missing its jti")

    # Replay protection: reject if JTI was already consumed
    now = time.time()
    jti = claims["jti"]
    if not _check_and_record_jti(jti, now):
        raise TokenError("service token replay detected")

    return claims


def reset_jti_store() -> None:
    """Clear the JTI replay store. Intended for tests only."""
    with _jti_lock:
        _jti_store.clear()
