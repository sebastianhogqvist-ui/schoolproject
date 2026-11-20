"""Gateway service: single public entry point for all client traffic.

The gateway validates client JWTs, creates short-lived service tokens with
embedded client context (sid, lid), and proxies authenticated requests to
backend services via HTTP.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import Depends, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app import __version__
from app.config import Settings, get_settings
from app.db import DbSession, configure_database
from app.deps import client_dep, client_ip, client_user_agent, settings_dep
from app.errors import AppError, ErrorCode
from app.interservice import encode_service_token, generate_service_token
from app.schemas import (
    ActivateRequest,
    AdminLoginRequest,
    IntegrityManifestSubmission,
    SecurityEventSubmission,
    SuccessResponse,
    ValidateRequest,
    success,
)
from app.service_registry import ServiceInfo, ServiceRegistry
from app.services import auth as auth_svc
from app.services.license import SessionContext

logger = logging.getLogger("app.gateway")

_bearer = Depends(HTTPBearer(auto_error=False))
_settings_dep = Depends(settings_dep)
_client_dep = Depends(client_dep)

_PROXY_ALLOWED_HEADERS = {
    "content-type",
    "authorization",
    "accept",
    "accept-encoding",
    "accept-language",
    "user-agent",
    "x-client-build",
    "x-client-version",
}

# Headers that should never be forwarded to clients (internal/debug info)
_PROXY_STRIP_RESPONSE_HEADERS = {
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-aspnetmvc-action",
    "x-aspnetmvc-controller",
    "x-generator",
    "x-drupal-cache",
    "x-drupal-cached",
    "x-varnish",
    "x-served-by",
    "x-cache",
    "x-cache-hits",
    "x-request-id",
    "x-correlation-id",
    "x-runtime",
    "x-forwarded-for",
    "x-real-ip",
    "via",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-forwarded-port",
}


def _scope_for_path(path: str) -> str:
    """Map a request path to a service token scope."""
    if path.startswith("/v1/licenses/activate"):
        return "license:activate"
    if path.startswith("/v1/licenses/"):
        return "license:read"
    if path.startswith("/v1/sessions/validate"):
        return "session:validate"
    if path.startswith("/v1/sessions/logout"):
        return "session:logout"
    if path.startswith("/v1/sessions/"):
        return "session:manage"
    if path.startswith("/v1/security/event"):
        return "security:event"
    if path.startswith("/v1/security/"):
        return "security:read"
    if path.startswith("/v1/integrity/challenge"):
        return "integrity:challenge"
    if path.startswith("/v1/integrity/check"):
        return "integrity:check"
    if path.startswith("/v1/integrity/"):
        return "integrity:manage"
    if path.startswith("/v1/admin/login"):
        return "admin:login"
    if path.startswith("/v1/admin/"):
        return "admin:manage"
    return "service:generic"


def make_service_token(
    client_context: tuple[str, int] | None,
    settings: Settings,
    scope: str | None = None,
) -> str:
    """Create a short-lived service token, optionally embedding client context.

    Args:
        client_context: Optional (sid, lid) tuple from a validated client token.
        settings: Application settings.
        scope: Optional scope string for the token.

    Returns:
        Encoded service JWT string.
    """
    token = generate_service_token()
    extra_claims: dict[str, Any] = {}
    if client_context:
        sid, lid = client_context
        extra_claims["sid"] = sid
        extra_claims["lid"] = lid
    encoded, _, _ = encode_service_token(
        token=token,
        ttl_seconds=settings.SERVICE_TOKEN_TTL_SECONDS,
        settings=settings,
        extra_claims=extra_claims,
        scope=scope,
    )
    return encoded


def make_admin_service_token(admin_id: int, settings: Settings, scope: str | None = None) -> str:
    """Create a service token for admin context."""
    token = generate_service_token()
    extra_claims = {"sid": f"admin:{admin_id}", "lid": 0}
    encoded, _, _ = encode_service_token(
        token=token,
        ttl_seconds=settings.SERVICE_TOKEN_TTL_SECONDS,
        settings=settings,
        extra_claims=extra_claims,
        scope=scope or "admin:manage",
    )
    return encoded


def service_backend(service_name: str, settings: Settings) -> str:
    """Look up a backend service URL from the registry.

    Args:
        service_name: Name of the service to discover.
        settings: Application settings.

    Returns:
        Base URL for the service (e.g., "http://127.0.0.1:18000").

    Raises:
        AppError: If the service is not registered or has expired.
    """
    registry = ServiceRegistry(settings.SERVICE_REGISTRY_PATH)
    info: ServiceInfo | None = registry.discover(service_name)
    if info is None:
        raise AppError(ErrorCode.INTERNAL_ERROR, "backend service unavailable")
    if info.host not in ("127.0.0.1", "localhost", "::1"):
        raise AppError(ErrorCode.INTERNAL_ERROR, "backend service unavailable")
    return f"http://{info.host}:{info.port}"


async def _proxy_request(
    request: Request,
    backend_url: str,
    service_token: str,
) -> Response:
    """Forward the request to a backend service.

    All exceptions are caught and converted to a generic error response
    to avoid leaking backend implementation details.
    """
    client = request.app.state.http_client
    path = request.url.path
    query = request.url.query
    url = f"{backend_url}{path}"
    if query:
        url += f"?{query}"

    headers: dict[str, str] = {}
    for key, value in request.headers.items():
        if key.lower() in _PROXY_ALLOWED_HEADERS:
            headers[key] = value
    headers["authorization"] = f"Bearer {service_token}"
    headers.pop("host", None)

    body = await request.body()

    try:
        response = await client.request(
            method=request.method,
            url=url,
            headers=headers,
            content=body,
            timeout=httpx.Timeout(connect=5.0, read=25.0, write=10.0, pool=5.0),
        )
    except httpx.TimeoutException as exc:
        logger.warning("proxy request timeout: %s", exc)
        raise AppError(ErrorCode.INTERNAL_ERROR, "backend timeout") from None
    except httpx.ConnectError as exc:
        logger.warning("proxy connection failed: %s", exc)
        raise AppError(ErrorCode.INTERNAL_ERROR, "backend unavailable") from None
    except httpx.RequestError as exc:
        logger.error("proxy request failed: %s", exc)
        raise AppError(ErrorCode.INTERNAL_ERROR, "backend communication failed") from None
    except Exception:  # Safety net for any unexpected errors
        logger.exception("unexpected proxy error")
        raise AppError(ErrorCode.INTERNAL_ERROR, "internal gateway error") from None

    # Sanitize response headers
    response_headers: dict[str, str] = {}
    for key, value in response.headers.items():
        key_lower = key.lower()
        if key_lower not in _PROXY_STRIP_RESPONSE_HEADERS:
            response_headers[key] = value

    # For error responses from backend, return a generic error to avoid leaking details
    if response.status_code >= 500:
        logger.warning("backend returned %d error", response.status_code)
        raise AppError(ErrorCode.INTERNAL_ERROR, "backend error")

    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=response_headers,
        media_type=response.headers.get("content-type"),
    )


async def _admin_auth(
    request: Request,
    session: DbSession,
    credentials: HTTPAuthorizationCredentials | None = _bearer,
    settings: Settings = _settings_dep,
) -> Any:
    """Validate admin token and return admin row."""
    if credentials is None:
        raise AppError(ErrorCode.AUTH_REQUIRED)
    admin_obj = auth_svc.resolve_admin(session, credentials.credentials, settings)
    return admin_obj


_admin_auth_dep = Depends(_admin_auth)


def create_gateway_app(settings: Settings | None = None) -> FastAPI:
    """Create the gateway FastAPI application."""
    if settings is None:
        settings = get_settings()
    settings.validate_runtime()
    configure_database(settings.DATABASE_URL)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.http_client = httpx.AsyncClient()
        logger.info("gateway http client started")
        yield
        await app.state.http_client.aclose()
        logger.info("gateway http client closed")

    app = FastAPI(
        title="nullforge-gateway",
        version=__version__,
        lifespan=lifespan,
    )
    app.state.settings = settings

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1", "http://localhost"],
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=True,
    )

    # Health endpoint - direct response, no proxy
    @app.get("/health", response_model=SuccessResponse)
    async def health() -> SuccessResponse:
        return success({"status": "ok"})

    # ===== LICENSE ROUTES =====

    @app.post("/v1/licenses/activate")
    async def activate(
        payload: ActivateRequest,
        request: Request,
        session: DbSession,
        settings: Settings = _settings_dep,
    ) -> Response:
        """Activate a license - no client auth required (entry point)."""
        backend_url = service_backend("license", settings)
        service_token = make_service_token(None, settings, scope=_scope_for_path(request.url.path))
        return await _proxy_request(request, backend_url, service_token)

    @app.get("/v1/licenses/status")
    async def license_status(
        request: Request,
        context: SessionContext = _client_dep,
        settings: Settings = _settings_dep,
    ) -> Response:
        backend_url = service_backend("license", settings)
        service_token = make_service_token(
            (context.session_id, context.license.id),
            settings,
            scope=_scope_for_path(request.url.path),
        )
        return await _proxy_request(request, backend_url, service_token)

    # ===== SESSION ROUTES =====

    @app.post("/v1/sessions/validate")
    async def validate_session(
        payload: ValidateRequest,
        request: Request,
        context: SessionContext = _client_dep,
        settings: Settings = _settings_dep,
    ) -> Response:
        backend_url = service_backend("session", settings)
        service_token = make_service_token(
            (context.session_id, context.license.id),
            settings,
            scope=_scope_for_path(request.url.path),
        )
        return await _proxy_request(request, backend_url, service_token)

    @app.post("/v1/sessions/logout")
    async def logout_session(
        request: Request,
        context: SessionContext = _client_dep,
        settings: Settings = _settings_dep,
    ) -> Response:
        backend_url = service_backend("session", settings)
        service_token = make_service_token(
            (context.session_id, context.license.id),
            settings,
            scope=_scope_for_path(request.url.path),
        )
        return await _proxy_request(request, backend_url, service_token)

    # ===== SECURITY ROUTES =====

    @app.post("/v1/security/event")
    async def security_event(
        payload: SecurityEventSubmission,
        request: Request,
        context: SessionContext = _client_dep,
        settings: Settings = _settings_dep,
    ) -> Response:
        backend_url = service_backend("security", settings)
        service_token = make_service_token(
            (context.session_id, context.license.id),
            settings,
            scope=_scope_for_path(request.url.path),
        )
        return await _proxy_request(request, backend_url, service_token)

    @app.get("/v1/security/status")
    async def security_status(
        request: Request,
        context: SessionContext = _client_dep,
        settings: Settings = _settings_dep,
    ) -> Response:
        backend_url = service_backend("security", settings)
        service_token = make_service_token(
            (context.session_id, context.license.id),
            settings,
            scope=_scope_for_path(request.url.path),
        )
        return await _proxy_request(request, backend_url, service_token)

    # ===== INTEGRITY ROUTES =====

    @app.post("/v1/integrity/challenge")
    async def integrity_challenge(
        request: Request,
        context: SessionContext = _client_dep,
        settings: Settings = _settings_dep,
    ) -> Response:
        backend_url = service_backend("integrity", settings)
        service_token = make_service_token(
            (context.session_id, context.license.id),
            settings,
            scope=_scope_for_path(request.url.path),
        )
        return await _proxy_request(request, backend_url, service_token)

    @app.post("/v1/integrity/check")
    async def integrity_check(
        payload: IntegrityManifestSubmission,
        request: Request,
        context: SessionContext = _client_dep,
        settings: Settings = _settings_dep,
    ) -> Response:
        backend_url = service_backend("integrity", settings)
        service_token = make_service_token(
            (context.session_id, context.license.id),
            settings,
            scope=_scope_for_path(request.url.path),
        )
        return await _proxy_request(request, backend_url, service_token)

    # ===== ADMIN ROUTES =====

    @app.post("/v1/admin/login", response_model=SuccessResponse)
    async def admin_login(
        payload: AdminLoginRequest,
        request: Request,
        session: DbSession,
        settings: Settings = _settings_dep,
    ) -> SuccessResponse:
        """Admin login - returns admin token directly, no proxy needed."""
        token = auth_svc.authenticate_admin(
            session,
            username=payload.username,
            password=payload.password,
            settings=settings,
            ip=client_ip(request),
            user_agent=client_user_agent(request),
        )
        data = {
            "session_token": token.token,
            "expires_at": token.expires_at.isoformat(),
            "exp": int(token.expires_at.timestamp()),
            "username": token.admin.username,
            "is_superuser": bool(token.admin.is_superuser),
        }
        return success(data)

    @app.api_route("/v1/admin/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def admin_proxy(
        path: str,
        request: Request,
        admin: Any = _admin_auth_dep,
        settings: Settings = _settings_dep,
    ) -> Response:
        """Proxy all other admin routes to admin backend."""
        backend_url = service_backend("admin", settings)
        full_path = f"/v1/admin/{path}"
        service_token = make_admin_service_token(
            admin.id, settings, scope=_scope_for_path(full_path)
        )
        return await _proxy_request(request, backend_url, service_token)

    return app
