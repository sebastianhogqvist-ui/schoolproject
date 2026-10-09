"""Stateless JWT issuance and verification for client and admin sessions.

Verification pins the algorithm list from settings, validates issuer and
audience, and requires the registered claims, so an attacker cannot downgrade
the algorithm or replay a client token against an admin endpoint. Tokens are
never logged.
"""

from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import uuid4

import jwt
from jwt import InvalidTokenError

from app.config import Settings
from app.security.crypto import generate_session_id

TokenType = Literal["client", "admin"]

CLIENT_TOKEN_TYPE: TokenType = "client"
ADMIN_TOKEN_TYPE: TokenType = "admin"

REQUIRED_CLAIMS: tuple[str, ...] = ("exp", "iat", "sub", "typ")
SESSION_ID_CLAIM = "sid"
LICENSE_ID_CLAIM = "lid"
USERNAME_CLAIM = "preferred_username"


class TokenError(Exception):
    """Raised for any token that fails issuance-policy or verification checks.

    The message is intentionally coarse; the specific reason is never echoed
    back to a client to avoid turning the endpoint into an oracle.
    """


def _issue(
    *,
    subject: str,
    typ: TokenType,
    ttl_seconds: int,
    settings: Settings,
    extra_claims: dict[str, Any] | None,
) -> tuple[str, str, datetime]:
    """Build and sign a token, returning ``(token, jti, expires_at)``."""
    if not subject:
        raise TokenError("subject must not be empty")
    if ttl_seconds <= 0:
        raise TokenError("ttl must be greater than zero")

    issued_at = datetime.now(UTC).replace(microsecond=0)
    expires_at = issued_at + timedelta(seconds=ttl_seconds)
    jti = generate_session_id()

    claims: dict[str, Any] = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "sub": str(subject),
        "iat": issued_at,
        "nbf": issued_at,
        "exp": expires_at,
        "jti": jti,
        "typ": typ,
    }
    if extra_claims:
        reserved = {"iss", "aud", "sub", "iat", "nbf", "exp", "jti", "typ"}
        overlap = reserved & set(extra_claims)
        if overlap:
            raise TokenError(f"extra_claims must not override {sorted(overlap)}")
        claims.update(extra_claims)

    token = jwt.encode(
        claims,
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
        headers={"typ": "JWT"},
    )
    return token, jti, expires_at


def create_access_token(
    *,
    subject: str,
    session_id: str,
    license_id: int,
    ttl_seconds: int,
    settings: Settings,
    extra_claims: dict[str, Any] | None = None,
) -> tuple[str, str, datetime]:
    """Issue a client session token bound to a license and session id."""
    if not session_id:
        raise TokenError("session_id must not be empty")
    claims: dict[str, Any] = {SESSION_ID_CLAIM: session_id, LICENSE_ID_CLAIM: int(license_id)}
    if extra_claims:
        claims.update(extra_claims)
    return _issue(
        subject=subject,
        typ=CLIENT_TOKEN_TYPE,
        ttl_seconds=ttl_seconds,
        settings=settings,
        extra_claims=claims,
    )


def create_admin_token(
    *,
    admin_id: int,
    username: str,
    ttl_seconds: int,
    settings: Settings,
) -> tuple[str, str, datetime]:
    """Issue an admin console token bound to an admin account."""
    return _issue(
        subject=str(admin_id),
        typ=ADMIN_TOKEN_TYPE,
        ttl_seconds=ttl_seconds,
        settings=settings,
        extra_claims={USERNAME_CLAIM: username},
    )


def decode_token(
    token: str,
    settings: Settings,
    *,
    expected_type: TokenType,
) -> dict[str, Any]:
    """Verify a token and return its claims.

    Raises :class:`TokenError` for malformed, tampered, expired, wrong-audience,
    wrong-issuer and wrong-type tokens alike.
    """
    if not token or not isinstance(token, str):
        raise TokenError("token is missing")

    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={
                "require": list(REQUIRED_CLAIMS),
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True,
                "verify_signature": True,
            },
        )
    except InvalidTokenError as exc:
        raise TokenError(f"token rejected: {type(exc).__name__}") from None

    if claims.get("typ") != expected_type:
        raise TokenError("token type mismatch")
    if not claims.get("jti"):
        raise TokenError("token is missing its jti")
    if expected_type == CLIENT_TOKEN_TYPE and (
        not claims.get(SESSION_ID_CLAIM) or claims.get(LICENSE_ID_CLAIM) is None
    ):
        raise TokenError("client token is missing session binding")
    return claims


def new_jti() -> str:
    """Return a fallback unique token id for callers that do not need a session id."""
    return uuid4().hex
