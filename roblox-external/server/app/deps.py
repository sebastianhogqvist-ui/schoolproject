"""FastAPI dependencies: settings, DB session, auth, rate limiting, client IP."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import Settings, get_settings
from app.db import DbSession
from app.errors import AppError, ErrorCode
from app.models import Admin
from app.ratelimit import limiter
from app.services import auth as auth_svc
from app.services import license as license_svc
from app.services.license import SessionContext

__all__ = [
    "Settings",
    "admin_api_rate_limit",
    "admin_dep",
    "admin_login_rate_limit",
    "auth_rate_limit",
    "bearer_scheme",
    "client_dep",
    "client_ip",
    "client_user_agent",
    "iso",
    "settings_dep",
    "unix",
    "wire",
]


def settings_dep() -> Settings:
    """Cached settings accessor usable as a FastAPI dependency."""
    return get_settings()


def client_ip(request: Request) -> str:
    """Best-effort client IP, honouring X-Forwarded-For when present."""
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
) -> Admin:
    """Resolve and return the admin named by the bearer token, or raise."""
    if credentials is None:
        raise AppError(ErrorCode.AUTH_REQUIRED)
    return auth_svc.resolve_admin(session, credentials.credentials, get_settings())


async def client_dep(
    session: DbSession,
    credentials: HTTPAuthorizationCredentials | None = _bearer,
) -> SessionContext:
    """Resolve and return the client session named by the bearer token, or raise."""
    if credentials is None:
        raise AppError(ErrorCode.SESSION_MISSING)
    return license_svc.resolve_session(session, credentials.credentials, get_settings())


def _rate_limit_for(group: str) -> Any:
    """Build a per-request dependency that enforces a sliding-window limit."""
    attr = {
        "auth": "RATE_LIMIT_AUTH_PER_MINUTE",
        "admin_login": "RATE_LIMIT_ADMIN_LOGIN_PER_MINUTE",
        "admin_api": "RATE_LIMIT_ADMIN_API_PER_MINUTE",
    }[group]

    async def _guard(request: Request) -> None:
        settings = request.app.state.settings
        if not settings.RATE_LIMIT_ENABLED:
            return
        decision = limiter.check(f"{group}:{client_ip(request)}", getattr(settings, attr))
        if not decision.allowed:
            raise AppError(ErrorCode.RATE_LIMITED, retry_after=decision.retry_after)

    return _guard


auth_rate_limit = _rate_limit_for("auth")
admin_login_rate_limit = _rate_limit_for("admin_login")
admin_api_rate_limit = _rate_limit_for("admin_api")


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
