"""FastAPI dependencies: settings, DB session, auth, rate limiting, client IP."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import Settings, get_settings
from app.db import DbSession
from app.errors import AppError, ErrorCode
from app.interservice import decode_service_token
from app.models import Admin
from app.ratelimit import limiter
from app.repositories import admins as admin_repo
from app.repositories import licenses as license_repo
from app.repositories import sessions as session_repo
from app.services import auth as auth_svc
from app.services import license as license_svc
from app.services.license import SessionContext

__all__ = [
    "Settings",
    "admin_api_rate_limit",
    "admin_dep",
    "admin_login_rate_limit",
    "admin_service_dep",
    "auth_rate_limit",
    "bearer_scheme",
    "client_dep",
    "client_ip",
    "client_user_agent",
    "integrity_rate_limit",
    "iso",
    "keyauth_rate_limit",
    "security_event_rate_limit",
    "service_dep",
    "settings_dep",
    "unix",
    "wire",
]


def settings_dep() -> Settings:
    """Cached settings accessor usable as a FastAPI dependency."""
    return get_settings()


_settings_dep = Depends(settings_dep)


def client_ip(request: Request) -> str:
    """Best-effort client IP. Only honors X-Forwarded-For when trusted."""
    settings = (
        request.app.state.settings
        if hasattr(request, 'app') and hasattr(request.app, 'state')
        else None
    )
    if settings and settings.TRUST_X_FORWARDED_FOR:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            candidate = forwarded.split(",")[0].strip()
            if candidate:
                return candidate
    client = request.client
    return client.host if client is not None else "-"


def client_user_agent(request: Request) -> str:
    """The User-Agent header value, defaulting to an empty string."""
    return request.headers.get("user-agent") or ""


bearer_scheme = HTTPBearer(auto_error=False)
_bearer = Depends(bearer_scheme)


async def admin_dep(
    session: DbSession,
    credentials: HTTPAuthorizationCredentials | None = _bearer,
    settings: Settings = _settings_dep,
) -> Admin:
    """Resolve and return the admin named by the bearer token, or raise."""
    if credentials is None:
        raise AppError(ErrorCode.AUTH_REQUIRED)
    return auth_svc.resolve_admin(session, credentials.credentials, settings)


async def client_dep(
    session: DbSession,
    credentials: HTTPAuthorizationCredentials | None = _bearer,
    settings: Settings = _settings_dep,
) -> SessionContext:
    """Resolve and return the client session named by the bearer token, or raise."""
    if credentials is None:
        raise AppError(ErrorCode.SESSION_MISSING)
    return license_svc.resolve_session(session, credentials.credentials, settings)


async def service_dep(
    session: DbSession,
    credentials: HTTPAuthorizationCredentials | None = _bearer,
    settings: Settings = _settings_dep,
) -> SessionContext:
    """Resolve client session from an inter-service token."""
    if credentials is None:
        raise AppError(ErrorCode.SESSION_MISSING)
    claims = decode_service_token(credentials.credentials, settings)
    session_id = claims.get("sid")
    if not session_id:
        raise AppError(ErrorCode.SESSION_INVALID)
    session_id = str(session_id)
    # Look up session and license in DB
    row = session_repo.get_active_by_jti(session, session_id)
    if row is None:
        raise AppError(ErrorCode.SESSION_INVALID)
    license_row = license_repo.get_by_id(session, row.license_id)
    if license_row is None:
        raise AppError(ErrorCode.SESSION_INVALID)
    return SessionContext(session_id=session_id, row=row, license=license_row, claims=claims)


async def admin_service_dep(
    session: DbSession,
    credentials: HTTPAuthorizationCredentials | None = _bearer,
    settings: Settings = _settings_dep,
) -> Admin:
    """Resolve admin from an inter-service token (sid=admin:{id}, lid=0)."""
    if credentials is None:
        raise AppError(ErrorCode.AUTH_REQUIRED)
    claims = decode_service_token(credentials.credentials, settings)
    sid = str(claims.get("sid") or claims.get("sub") or "")
    if not sid.startswith("admin:"):
        raise AppError(ErrorCode.ADMIN_AUTH_FAILED)
    try:
        admin_id = int(sid.split(":", 1)[1])
    except (ValueError, IndexError):
        raise AppError(ErrorCode.ADMIN_AUTH_FAILED) from None
    admin_row = admin_repo.get_by_id(session, admin_id)
    if admin_row is None:
        raise AppError(ErrorCode.ADMIN_AUTH_FAILED)
    return admin_row


def _rate_limit_key(request: Request, group: str, settings: Settings) -> str:
    """Construct a rate limit key that avoids collisions.

    For authenticated endpoints, prefer session/admin identity over IP.
    For unauthenticated endpoints, use IP with a fallback to a unique request identifier.
    """
    # Try to get authenticated identity first
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        # Try to decode as client token to get session_id
        try:
            from app.security.tokens import CLIENT_TOKEN_TYPE, decode_token
            claims = decode_token(token, settings, expected_type=CLIENT_TOKEN_TYPE)
            session_id = claims.get("sid")
            if session_id:
                return f"{group}:session:{session_id}"
        except Exception:  # noqa: S110
            pass
        # Try to decode as admin token
        try:
            from app.security.tokens import ADMIN_TOKEN_TYPE, decode_token
            claims = decode_token(token, settings, expected_type=ADMIN_TOKEN_TYPE)
            admin_id = claims.get("sub")
            if admin_id:
                return f"{group}:admin:{admin_id}"
        except Exception:  # noqa: S110
            pass

    # Fall back to IP-based key
    ip = client_ip(request)
    if ip == "-":
        # No IP available - use a unique request identifier to avoid collisions
        # This prevents all unknown-IP requests from sharing one bucket
        import uuid
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        return f"{group}:anon:{request_id}"
    return f"{group}:ip:{ip}"


def _rate_limit_for(group: str) -> Any:
    """Build a per-request dependency that enforces a sliding-window limit."""
    attr = {
        "auth": "RATE_LIMIT_AUTH_PER_MINUTE",
        "admin_login": "RATE_LIMIT_ADMIN_LOGIN_PER_MINUTE",
        "admin_api": "RATE_LIMIT_ADMIN_API_PER_MINUTE",
        "keyauth": "RATE_LIMIT_KEYAUTH_PER_MINUTE",
        "security_event": "RATE_LIMIT_SECURITY_EVENT_PER_MINUTE",
        "integrity": "RATE_LIMIT_INTEGRITY_PER_MINUTE",
    }[group]

    async def _guard(request: Request) -> None:
        settings = request.app.state.settings
        if not settings.RATE_LIMIT_ENABLED:
            return
        key = _rate_limit_key(request, group, settings)
        decision = limiter.check(key, getattr(settings, attr))
        if not decision.allowed:
            raise AppError(ErrorCode.RATE_LIMITED, retry_after=decision.retry_after)

    return _guard


auth_rate_limit = _rate_limit_for("auth")
admin_login_rate_limit = _rate_limit_for("admin_login")
admin_api_rate_limit = _rate_limit_for("admin_api")
keyauth_rate_limit = _rate_limit_for("keyauth")
security_event_rate_limit = _rate_limit_for("security_event")
integrity_rate_limit = _rate_limit_for("integrity")


def iso(value: datetime | None) -> str | None:
    """Render a datetime as an RFC 3339 string, or ``None`` when null."""
    return value.isoformat() if value is not None else None


def unix(value: datetime | None) -> int | None:
    """Render a datetime as a unix-seconds integer, or ``None`` when null."""
    return int(value.timestamp()) if value is not None else None


def wire(value: Any) -> Any:
    """Recursively convert datetimes to RFC 3339 strings for JSON output."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): wire(val) for key, val in value.items()}
    if isinstance(value, list):
        return [wire(item) for item in value]
    if isinstance(value, tuple):
        return [wire(item) for item in value]
    return value
