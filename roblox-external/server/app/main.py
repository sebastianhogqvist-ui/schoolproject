"""FastAPI application factory for the license server."""
from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware

from app import __version__
from app.api.v1 import admin, health, integrity, keyauth, licenses, security, sessions
from app.config import Settings, get_settings
from app.db import configure_database
from app.errors import AppError, ErrorCode

logger = logging.getLogger("app.main")


def _error_response(
    request: Request, code: ErrorCode, message: str | None = None, *, retry_after: int | None = None
) -> JSONResponse:
    error = AppError(code, message, retry_after=retry_after)
    headers = {"Retry-After": str(error.retry_after)} if error.retry_after else {}
    return JSONResponse(status_code=error.http_status, content=error.to_dict(), headers=headers)


class _BodySizeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Any) -> JSONResponse:
        settings: Settings = request.app.state.settings
        body = await request.body()
        if len(body) > settings.MAX_REQUEST_BODY_BYTES:
            return _error_response(request, ErrorCode.VALIDATION_ERROR, "request body is too large")
        return await call_next(request)


class _MaintenanceMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Any) -> JSONResponse:
        settings: Settings = request.app.state.settings
        if settings.MAINTENANCE_MODE and not request.url.path.startswith("/health"):
            return _error_response(
                request, ErrorCode.SERVICE_MAINTENANCE, "service is in maintenance mode"
            )
        return await call_next(request)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the FastAPI application, wiring routes, middleware and handlers."""
    if settings is None:
        settings = get_settings()
    settings.validate_runtime()
    configure_database(settings.DATABASE_URL)

    app = FastAPI(
        title="roblox-license-server",
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
    )
    app.state.settings = settings

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ALLOWED_ORIGINS,
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=True,
    )
    app.add_middleware(_MaintenanceMiddleware)
    app.add_middleware(_BodySizeMiddleware)

    app.include_router(health.router)
    app.include_router(licenses.router)
    app.include_router(sessions.router)
    app.include_router(admin.router)
    app.include_router(keyauth.router)
    app.include_router(integrity.router)
    app.include_router(security.router)

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
        return _error_response(
            request, ErrorCode.VALIDATION_ERROR, "request payload failed validation"
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        if exc.status_code == 400:
            code = ErrorCode.VALIDATION_ERROR
        elif exc.status_code == 403:
            code = ErrorCode.FORBIDDEN
        else:
            code = ErrorCode.INTERNAL_ERROR
        return _error_response(request, code, str(exc.detail) if exc.detail else None)

    @app.exception_handler(Exception)
    async def handle_generic_error(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled error", extra={"app_path": request.url.path})
        return _error_response(request, ErrorCode.INTERNAL_ERROR)

    return app


app = create_app()
