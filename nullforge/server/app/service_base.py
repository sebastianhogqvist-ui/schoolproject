"""Base service application factory for backend services.

All backend services (license, session, security, integrity, admin) share this
factory which provides: service-token authentication middleware, registry
registration, CORS restricted to localhost, and consistent error handling.
"""

from __future__ import annotations

import logging
import secrets
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import Settings, get_settings
from app.db import configure_database
from app.errors import CODE_HTTP_STATUS, AppError, ErrorCode
from app.interservice import SERVICE_TOKEN_TYPE, decode_service_token
from app.service_registry import ServiceRegistry

logger = logging.getLogger("app.service_base")


class _BodySizeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Any) -> JSONResponse:
        settings: Settings = request.app.state.settings
        body = await request.body()
        if len(body) > settings.MAX_REQUEST_BODY_BYTES:
            return JSONResponse(
                status_code=CODE_HTTP_STATUS[ErrorCode.VALIDATION_ERROR],
                content=AppError(ErrorCode.VALIDATION_ERROR, "request body is too large").to_dict(),
            )
        return await call_next(request)


class _ServiceAuthMiddleware(BaseHTTPMiddleware):
    """Validate service JWT on every request except health endpoints."""

    async def dispatch(self, request: Request, call_next: Any) -> JSONResponse:
        # Skip auth for health endpoints
        if request.url.path.startswith("/health"):
            return await call_next(request)

        auth_header = request.headers.get("authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=CODE_HTTP_STATUS[ErrorCode.SESSION_MISSING],
                content=AppError(ErrorCode.SESSION_MISSING).to_dict(),
            )

        service_token = auth_header.split(" ", 1)[1]
        settings: Settings = request.app.state.settings

        try:
            claims = decode_service_token(service_token, settings)
        except Exception:
            return JSONResponse(
                status_code=CODE_HTTP_STATUS[ErrorCode.SESSION_INVALID],
                content=AppError(ErrorCode.SESSION_INVALID).to_dict(),
            )

        if claims.get("typ") != SERVICE_TOKEN_TYPE:
            return JSONResponse(
                status_code=CODE_HTTP_STATUS[ErrorCode.SESSION_INVALID],
                content=AppError(ErrorCode.SESSION_INVALID).to_dict(),
            )

        # Extract client context from service token
        request.state.sid = str(claims.get("sid") or claims.get("sub") or "")
        request.state.lid = int(claims.get("lid") or 0)

        return await call_next(request)


def _service_port(service_name: str, settings: Settings) -> int:
    """Pick a random port within the service's configured range.

    Random ports prevent collisions at startup but are NOT a security
    mechanism: the service registry is how services discover each other.
    """
    port_map = {
        "license": (settings.LICENSE_PORT_RANGE_START, settings.LICENSE_PORT_RANGE_END),
        "session": (settings.SESSION_PORT_RANGE_START, settings.SESSION_PORT_RANGE_END),
        "security": (settings.SECURITY_PORT_RANGE_START, settings.SECURITY_PORT_RANGE_END),
        "integrity": (settings.INTEGRITY_PORT_RANGE_START, settings.INTEGRITY_PORT_RANGE_END),
        "admin": (settings.ADMIN_PORT_RANGE_START, settings.ADMIN_PORT_RANGE_END),
    }
    if service_name not in port_map:
        return settings.SERVER_PORT
    start, end = port_map[service_name]
    return start + secrets.randbelow(end - start + 1)


def create_service_app(
    service_name: str,
    routers: list,
    settings: Settings | None = None,
) -> FastAPI:
    """Create a backend service FastAPI application.

    Args:
        service_name: Name of the service (e.g., "license", "session").
        routers: List of APIRouter instances to mount.
        settings: Optional Settings instance; if omitted, uses cached settings.

    Returns:
        Configured FastAPI application.
    """
    if settings is None:
        settings = get_settings()
    settings.validate_runtime()
    configure_database(settings.DATABASE_URL)

    app = FastAPI(
        title=f"nullforge-{service_name}",
        docs_url=None,
        redoc_url=None,
    )
    app.state.settings = settings
    app.state.service_name = service_name
    app.state.service_port = _service_port(service_name, settings)

    # CORS restricted to localhost only
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1", "http://localhost"],
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=True,
    )
    app.add_middleware(_BodySizeMiddleware)
    app.add_middleware(_ServiceAuthMiddleware)

    for router in routers:
        app.include_router(router)

    @app.on_event("startup")
    async def _startup() -> None:
        registry = ServiceRegistry(settings.SERVICE_REGISTRY_PATH)
        port = app.state.service_port
        registry.register(
            name=service_name,
            host=settings.SERVICE_HOST,
            port=port,
            ttl_seconds=settings.SERVICE_TOKEN_TTL_SECONDS * 2,
        )
        logger.info("service %s registered at %s:%d", service_name, settings.SERVICE_HOST, port)

    @app.exception_handler(AppError)
    async def handle_app_error(request: Request, exc: AppError) -> JSONResponse:
        logger.warning(
            "app error",
            extra={"app_code": exc.code.value, "app_path": request.url.path},
        )
        headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after else {}
        return JSONResponse(status_code=exc.http_status, content=exc.to_dict(), headers=headers)

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=CODE_HTTP_STATUS[ErrorCode.VALIDATION_ERROR],
            content=AppError(
                ErrorCode.VALIDATION_ERROR, "request payload failed validation"
            ).to_dict(),
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        if exc.status_code == 400:
            code = ErrorCode.VALIDATION_ERROR
        elif exc.status_code == 403:
            code = ErrorCode.FORBIDDEN
        else:
            code = ErrorCode.INTERNAL_ERROR
        return JSONResponse(
            status_code=CODE_HTTP_STATUS[code],
            content=AppError(code, str(exc.detail) if exc.detail else None).to_dict(),
        )

    @app.exception_handler(Exception)
    async def handle_generic_error(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled error", extra={"app_path": request.url.path})
        return JSONResponse(
            status_code=CODE_HTTP_STATUS[ErrorCode.INTERNAL_ERROR],
            content=AppError(ErrorCode.INTERNAL_ERROR).to_dict(),
        )

    return app


def get_service_context(request: Request) -> tuple[str, int]:
    """Extract (sid, lid) from request.state, raise AppError if missing.

    Returns:
        Tuple of (session_id, license_id).
    """
    sid = getattr(request.state, "sid", None)
    lid = getattr(request.state, "lid", None)
    if not sid or not lid:
        raise AppError(ErrorCode.SESSION_INVALID, "service token missing client context")
    return sid, lid
