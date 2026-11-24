"""FastAPI application factory for the license server.

This module builds the FastAPI application used by the nullforge license
server. It provides:

- error-response builders that turn AppError instances into JSONResponses;
- two single-purpose middleware classes (body size and maintenance mode);
- a monolithic application factory that registers every route and handler;
- a modal application factory that dispatches to monolith, gateway, or
  per-service backend factories based on SERVICE_MODE;
- a module-level ``app`` instance created from the default settings.

Every function here is small and single-purpose so that the factory logic is
easy to read, test, and maintain.
"""

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
from app.api.v1.services import admin as admin_svc
from app.api.v1.services import integrity as integrity_svc
from app.api.v1.services import licenses as licenses_svc
from app.api.v1.services import security as security_svc
from app.api.v1.services import sessions as sessions_svc
from app.config import Settings, get_settings
from app.db import configure_database
from app.errors import AppError, ErrorCode

logger = logging.getLogger("app.main")


# ---------------------------------------------------------------------------
# Error-response helpers
# ---------------------------------------------------------------------------


def build_app_error(
    request: Request,
    code: ErrorCode,
    message: str | None = None,
    *,
    retry_after: int | None = None,
) -> AppError:
    """Build an AppError from a code, optional message, and retry delay.

    Parameters
    ----------
    request : Request
        The incoming request that triggered the error. It is accepted for
        signature compatibility with the other error helpers and for future
        logging use, but it is not dereferenced here.
    code : ErrorCode
        The stable machine-readable error code.
    message : str | None
        Optional human-readable message. When None, the canonical safe
        message for the code is used.
    retry_after : int | None
        Optional number of seconds after which the client may retry.

    Returns
    -------
    AppError
        The constructed error instance carrying the HTTP status and headers.
    """
    error = AppError(code, message, retry_after=retry_after)
    return error


def build_headers(
    error: AppError,
) -> dict[str, str]:
    """Build the response headers for an AppError.

    A Retry-After header is emitted only when the error carries a
    retry_after value. Otherwise an empty header mapping is returned.

    Parameters
    ----------
    error : AppError
        The error whose retry_after value controls the headers.

    Returns
    -------
    dict[str, str]
        The header mapping, containing Retry-After when applicable.
    """
    has_retry_after = error.retry_after is not None
    if has_retry_after:
        retry_value = str(error.retry_after)
        headers = {
            "Retry-After": retry_value,
        }
    else:
        headers = {}
    return headers


def build_json_response(
    request: Request,
    error: AppError,
    headers: dict[str, str],
) -> JSONResponse:
    """Build a JSONResponse from an AppError and its headers.

    Parameters
    ----------
    request : Request
        The incoming request. Accepted for signature symmetry with the other
        builders and for future correlation-ID logging.
    error : AppError
        The error providing status code, content, and retry information.
    headers : dict[str, str]
        The response headers produced by :func:`build_headers`.

    Returns
    -------
    JSONResponse
        The JSON error response ready to return from a handler or middleware.
    """
    status_code = error.http_status
    content = error.to_dict()
    response = JSONResponse(
        status_code=status_code,
        content=content,
        headers=headers,
    )
    return response


def _error_response(
    request: Request,
    code: ErrorCode,
    message: str | None = None,
    *,
    retry_after: int | None = None,
) -> JSONResponse:
    """Build a JSON error response for a request.

    This is the public-facing composition of :func:`build_app_error`,
    :func:`build_headers`, and :func:`build_json_response`. It exists so that
    existing call sites keep a single entry point while the underlying work is
    split into single-purpose functions.

    Parameters
    ----------
    request : Request
        The incoming request that triggered the error.
    code : ErrorCode
        The stable machine-readable error code.
    message : str | None
        Optional human-readable message.
    retry_after : int | None
        Optional number of seconds after which the client may retry.

    Returns
    -------
    JSONResponse
        The JSON error response.
    """
    error = build_app_error(
        request,
        code,
        message,
        retry_after=retry_after,
    )
    headers = build_headers(error)
    response = build_json_response(
        request,
        error,
        headers,
    )
    return response


# ---------------------------------------------------------------------------
# Body size middleware
# ---------------------------------------------------------------------------


class _BodySizeMiddleware(BaseHTTPMiddleware):
    """Reject requests whose body exceeds MAX_REQUEST_BODY_BYTES."""

    async def read_body(
        self,
        request: Request,
    ) -> bytes:
        """Read the entire request body into memory.

        Parameters
        ----------
        request : Request
            The incoming request.

        Returns
        -------
        bytes
            The raw body bytes.
        """
        body = await request.body()
        return body

    async def check_size(
        self,
        request: Request,
        body: bytes,
    ) -> bool:
        """Return True when the body exceeds the configured byte limit.

        Parameters
        ----------
        request : Request
            The incoming request, used to access application state settings.
        body : bytes
            The body bytes previously read by :meth:`read_body`.

        Returns
        -------
        bool
            True when len(body) > MAX_REQUEST_BODY_BYTES.
        """
        settings: Settings = request.app.state.settings
        limit = settings.MAX_REQUEST_BODY_BYTES
        size = len(body)
        exceeds = size > limit
        return exceeds

    async def build_error(
        self,
        request: Request,
    ) -> JSONResponse:
        """Build the oversized-body error response.

        Parameters
        ----------
        request : Request
            The incoming request that triggered the error.

        Returns
        -------
        JSONResponse
            The validation error response.
        """
        response = _error_response(
            request,
            ErrorCode.VALIDATION_ERROR,
            "request body is too large",
        )
        return response

    async def proceed(
        self,
        request: Request,
        call_next: Any,
    ) -> JSONResponse:
        """Continue processing the request through the downstream middleware.

        Parameters
        ----------
        request : Request
            The incoming request.
        call_next : Any
            The next middleware or route handler in the chain.

        Returns
        -------
        JSONResponse
            The downstream response.
        """
        response = await call_next(request)
        return response

    async def dispatch(
        self,
        request: Request,
        call_next: Any,
    ) -> JSONResponse:
        """Dispatch a request through the body-size check.

        The body is read, its size is checked against the configured limit,
        and either an error is returned or the request proceeds downstream.

        Parameters
        ----------
        request : Request
            The incoming request.
        call_next : Any
            The next middleware or route handler in the chain.

        Returns
        -------
        JSONResponse
            An error response when the body is too large, otherwise the
            downstream response.
        """
        body = await self.read_body(request)
        exceeds = await self.check_size(request, body)
        if exceeds:
            response = await self.build_error(request)
            return response
        response = await self.proceed(request, call_next)
        return response


# ---------------------------------------------------------------------------
# Maintenance middleware
# ---------------------------------------------------------------------------


class _MaintenanceMiddleware(BaseHTTPMiddleware):
    """Reject requests when the service is in maintenance mode.

    The /health path is exempt so that load balancers can still probe the
    service while it is under maintenance.
    """

    async def check_mode(
        self,
        request: Request,
    ) -> bool:
        """Return True when maintenance mode is enabled.

        Parameters
        ----------
        request : Request
            The incoming request, used to access application state settings.

        Returns
        -------
        bool
            True when settings.MAINTENANCE_MODE is True.
        """
        settings: Settings = request.app.state.settings
        enabled = settings.MAINTENANCE_MODE
        return enabled

    async def check_health_exemption(
        self,
        request: Request,
    ) -> bool:
        """Return True when the request path is exempt from maintenance.

        Only paths starting with /health are exempt.

        Parameters
        ----------
        request : Request
            The incoming request.

        Returns
        -------
        bool
            True when the path starts with /health.
        """
        path = request.url.path
        prefix = "/health"
        exempt = path.startswith(prefix)
        return exempt

    async def build_error(
        self,
        request: Request,
    ) -> JSONResponse:
        """Build the maintenance-mode error response.

        Parameters
        ----------
        request : Request
            The incoming request that triggered the error.

        Returns
        -------
        JSONResponse
            The service-maintenance error response.
        """
        response = _error_response(
            request,
            ErrorCode.SERVICE_MAINTENANCE,
            "service is in maintenance mode",
        )
        return response

    async def proceed(
        self,
        request: Request,
        call_next: Any,
    ) -> JSONResponse:
        """Continue processing the request through the downstream middleware.

        Parameters
        ----------
        request : Request
            The incoming request.
        call_next : Any
            The next middleware or route handler in the chain.

        Returns
        -------
        JSONResponse
            The downstream response.
        """
        response = await call_next(request)
        return response

    async def dispatch(
        self,
        request: Request,
        call_next: Any,
    ) -> JSONResponse:
        """Dispatch a request through the maintenance-mode check.

        When maintenance mode is enabled and the path is not exempt, an error
        is returned. Otherwise the request proceeds downstream.

        Parameters
        ----------
        request : Request
            The incoming request.
        call_next : Any
            The next middleware or route handler in the chain.

        Returns
        -------
        JSONResponse
            An error response when maintenance blocks the request, otherwise
            the downstream response.
        """
        maintenance_enabled = await self.check_mode(request)
        path_exempt = await self.check_health_exemption(request)
        not_exempt = not path_exempt
        blocked = maintenance_enabled and not_exempt
        if blocked:
            response = await self.build_error(request)
            return response
        response = await self.proceed(request, call_next)
        return response


# ---------------------------------------------------------------------------
# Monolith application factory helpers
# ---------------------------------------------------------------------------


def load_settings(
    settings: Settings | None,
) -> Settings:
    """Resolve the settings instance for the application factory.

    When no settings are supplied the cached defaults are loaded from the
    environment via :func:`get_settings`.

    Parameters
    ----------
    settings : Settings | None
        The caller-supplied settings, or None to load defaults.

    Returns
    -------
    Settings
        The settings to use for the application.
    """
    if settings is None:
        resolved = get_settings()
    else:
        resolved = settings
    return resolved


def validate_runtime(
    settings: Settings,
) -> None:
    """Run runtime validation on the settings.

    This performs the fail-fast secret and pepper checks beyond pydantic's
    static constraints.

    Parameters
    ----------
    settings : Settings
        The settings to validate.

    Raises
    ------
    RuntimeError
        When the configuration is insecure.
    """
    settings.validate_runtime()


def configure_db(
    settings: Settings,
) -> None:
    """Configure the database connection from the settings.

    Parameters
    ----------
    settings : Settings
        The settings providing DATABASE_URL.
    """
    database_url = settings.DATABASE_URL
    configure_database(database_url)


def create_fastapi_app() -> FastAPI:
    """Create the bare FastAPI application instance.

    Returns
    -------
    FastAPI
        The unconfigured application with title, version, and docs URLs.
    """
    app = FastAPI(
        title="nullforge-license-server",
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
    )
    return app


def set_state(
    app: FastAPI,
    settings: Settings,
) -> None:
    """Attach the settings to the application state.

    Parameters
    ----------
    app : FastAPI
        The application instance.
    settings : Settings
        The settings to store on app.state.settings.
    """
    app.state.settings = settings


def add_cors(
    app: FastAPI,
    settings: Settings,
) -> None:
    """Add the CORS middleware to the application.

    Parameters
    ----------
    app : FastAPI
        The application instance.
    settings : Settings
        The settings providing CORS_ALLOWED_ORIGINS.
    """
    origins = settings.CORS_ALLOWED_ORIGINS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_methods=[
            "*",
        ],
        allow_headers=[
            "*",
        ],
        allow_credentials=True,
    )


def add_maintenance(
    app: FastAPI,
) -> None:
    """Add the maintenance-mode middleware to the application.

    Parameters
    ----------
    app : FastAPI
        The application instance.
    """
    app.add_middleware(_MaintenanceMiddleware)


def add_body_size(
    app: FastAPI,
) -> None:
    """Add the body-size middleware to the application.

    Parameters
    ----------
    app : FastAPI
        The application instance.
    """
    app.add_middleware(_BodySizeMiddleware)


def register_health(
    app: FastAPI,
) -> None:
    """Register the health router with the application.

    Parameters
    ----------
    app : FastAPI
        The application instance.
    """
    app.include_router(health.router)


def register_licenses(
    app: FastAPI,
) -> None:
    """Register the licenses router with the application.

    Parameters
    ----------
    app : FastAPI
        The application instance.
    """
    app.include_router(licenses.router)


def register_sessions(
    app: FastAPI,
) -> None:
    """Register the sessions router with the application.

    Parameters
    ----------
    app : FastAPI
        The application instance.
    """
    app.include_router(sessions.router)


def register_admin(
    app: FastAPI,
) -> None:
    """Register the admin router with the application.

    Parameters
    ----------
    app : FastAPI
        The application instance.
    """
    app.include_router(admin.router)


def conditional_keyauth(
    app: FastAPI,
    settings: Settings,
) -> None:
    """Conditionally register the keyauth router.

    The router is registered only when KEYAUTH_ENABLED is True.

    Parameters
    ----------
    app : FastAPI
        The application instance.
    settings : Settings
        The settings providing KEYAUTH_ENABLED.
    """
    enabled = settings.KEYAUTH_ENABLED
    if enabled:
        app.include_router(keyauth.router)


def register_integrity(
    app: FastAPI,
) -> None:
    """Register the integrity router with the application.

    Parameters
    ----------
    app : FastAPI
        The application instance.
    """
    app.include_router(integrity.router)


def register_security(
    app: FastAPI,
) -> None:
    """Register the security router with the application.

    Parameters
    ----------
    app : FastAPI
        The application instance.
    """
    app.include_router(security.router)


# Exception handler factories for the monolith app


def register_error_handler_app_error(
    app: FastAPI,
) -> None:
    """Register the AppError exception handler.

    Logs a warning with the app code and path, then returns a JSON error
    response with a Retry-After header when applicable.

    Parameters
    ----------
    app : FastAPI
        The application instance.
    """

    @app.exception_handler(AppError)
    async def handle_app_error(
        request: Request,
        exc: AppError,
    ) -> JSONResponse:
        logger.warning(
            "app error",
            extra={
                "app_code": exc.code.value,
                "app_path": request.url.path,
            },
        )
        has_retry_after = exc.retry_after is not None
        if has_retry_after:
            retry_value = str(exc.retry_after)
            headers = {
                "Retry-After": retry_value,
            }
        else:
            headers = {}
        status_code = exc.http_status
        content = exc.to_dict()
        response = JSONResponse(
            status_code=status_code,
            content=content,
            headers=headers,
        )
        return response


def register_error_handler_validation(
    app: FastAPI,
) -> None:
    """Register the request validation exception handler.

    Parameters
    ----------
    app : FastAPI
        The application instance.
    """

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        response = _error_response(
            request,
            ErrorCode.VALIDATION_ERROR,
            "request payload failed validation",
        )
        return response


def register_error_handler_http(
    app: FastAPI,
) -> None:
    """Register the Starlette HTTP exception handler.

    Maps 400 to VALIDATION_ERROR, 403 to FORBIDDEN, and everything else to
    INTERNAL_ERROR.

    Parameters
    ----------
    app : FastAPI
        The application instance.
    """

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_error(
        request: Request,
        exc: StarletteHTTPException,
    ) -> JSONResponse:
        if exc.status_code == 400:
            code = ErrorCode.VALIDATION_ERROR
        elif exc.status_code == 403:
            code = ErrorCode.FORBIDDEN
        else:
            code = ErrorCode.INTERNAL_ERROR
        has_detail = exc.detail is not None
        if has_detail:
            message = str(exc.detail)
        else:
            message = None
        response = _error_response(
            request,
            code,
            message,
        )
        return response


def register_error_handler_generic(
    app: FastAPI,
) -> None:
    """Register the catch-all exception handler.

    Logs the full exception and returns an internal error response.

    Parameters
    ----------
    app : FastAPI
        The application instance.
    """

    @app.exception_handler(Exception)
    async def handle_generic_error(
        request: Request,
        exc: Exception,
    ) -> JSONResponse:
        logger.exception(
            "unhandled error",
            extra={"app_path": request.url.path},
        )
        response = _error_response(
            request,
            ErrorCode.INTERNAL_ERROR,
        )
        return response


def register_error_handlers(
    app: FastAPI,
) -> None:
    """Register all exception handlers for the monolith application.

    Parameters
    ----------
    app : FastAPI
        The application instance.
    """
    register_error_handler_app_error(app)
    register_error_handler_validation(app)
    register_error_handler_http(app)
    register_error_handler_generic(app)


def return_app(
    app: FastAPI,
) -> FastAPI:
    """Return the fully built application instance.

    Parameters
    ----------
    app : FastAPI
        The application instance.

    Returns
    -------
    FastAPI
        The same application instance.
    """
    return app


def create_monolith_app(
    settings: Settings | None = None,
) -> FastAPI:
    """Build the monolithic FastAPI application with all routes.

    Parameters
    ----------
    settings : Settings | None
        Optional pre-loaded settings. When None, defaults are loaded.

    Returns
    -------
    FastAPI
        The fully configured monolithic application.
    """
    resolved_settings = load_settings(settings)
    validate_runtime(resolved_settings)
    configure_db(resolved_settings)

    app = create_fastapi_app()
    set_state(app, resolved_settings)
    add_cors(app, resolved_settings)
    add_maintenance(app)
    add_body_size(app)

    register_health(app)
    register_licenses(app)
    register_sessions(app)
    register_admin(app)
    conditional_keyauth(app, resolved_settings)
    register_integrity(app)
    register_security(app)

    register_error_handlers(app)

    final_app = return_app(app)
    return final_app


# ---------------------------------------------------------------------------
# Modal application factory helpers
# ---------------------------------------------------------------------------


def load_settings_create_app(
    settings: Settings | None,
) -> Settings:
    """Resolve the settings instance for create_app.

    Parameters
    ----------
    settings : Settings | None
        The caller-supplied settings, or None to load defaults.

    Returns
    -------
    Settings
        The settings to use.
    """
    if settings is None:
        resolved = get_settings()
    else:
        resolved = settings
    return resolved


def resolve_mode(
    settings: Settings,
) -> str:
    """Read the SERVICE_MODE value from the settings.

    Parameters
    ----------
    settings : Settings
        The settings instance.

    Returns
    -------
    str
        The configured service mode string.
    """
    mode = settings.SERVICE_MODE
    return mode


def dispatch_monolith(
    settings: Settings,
) -> FastAPI:
    """Build and return the monolithic application.

    Parameters
    ----------
    settings : Settings
        The settings instance.

    Returns
    -------
    FastAPI
        The monolithic application.
    """
    app = create_monolith_app(settings)
    return app


def dispatch_gateway(
    settings: Settings,
) -> FastAPI:
    """Build and return the gateway application.

    Parameters
    ----------
    settings : Settings
        The settings instance.

    Returns
    -------
    FastAPI
        The gateway application.
    """
    from app.gateway import create_gateway_app

    app = create_gateway_app(settings)
    return app


def dispatch_backend(
    settings: Settings,
) -> FastAPI:
    """Build and return the backend service application.

    Builds a per-service router map, selects the routers for the configured
    mode, and calls the service-app factory.

    Parameters
    ----------
    settings : Settings
        The settings instance.

    Returns
    -------
    FastAPI
        The backend service application.
    """
    from app.service_base import create_service_app

    router_map = build_router_map()
    mode = settings.SERVICE_MODE
    routers = select_routers(router_map, mode)
    app = call_create_service_app(mode, routers, settings)
    return app


def build_router_map() -> dict[str, list]:
    """Build the mapping from service mode to router lists.

    Returns
    -------
    dict[str, list]
        The router map keyed by service mode name.
    """
    license_routers = [licenses_svc.router]
    session_routers = [sessions_svc.router]
    security_routers = [security_svc.router]
    integrity_routers = [integrity_svc.router]
    admin_routers = [admin_svc.router]

    router_map: dict[str, list] = {
        "license": license_routers,
        "session": session_routers,
        "security": security_routers,
        "integrity": integrity_routers,
        "admin": admin_routers,
    }
    return router_map


def select_routers(
    router_map: dict[str, list],
    mode: str,
) -> list:
    """Select the routers for a given service mode.

    Parameters
    ----------
    router_map : dict[str, list]
        The mapping from mode to router lists.
    mode : str
        The service mode.

    Returns
    -------
    list
        The router list for the mode, or an empty list when unknown.
    """
    default_routers: list = []
    routers = router_map.get(mode, default_routers)
    return routers


def call_create_service_app(
    mode: str,
    routers: list,
    settings: Settings,
) -> FastAPI:
    """Call the per-service application factory.

    Parameters
    ----------
    mode : str
        The service mode.
    routers : list
        The routers to register.
    settings : Settings
        The settings instance.

    Returns
    -------
    FastAPI
        The backend service application.
    """
    app = create_service_app(mode, routers, settings)
    return app


def create_app(
    settings: Settings | None = None,
) -> FastAPI:
    """Build the FastAPI application based on SERVICE_MODE.

    Parameters
    ----------
    settings : Settings | None
        Optional pre-loaded settings. When None, defaults are loaded.

    Returns
    -------
    FastAPI
        The application for the configured service mode.
    """
    resolved_settings = load_settings_create_app(settings)
    mode = resolve_mode(resolved_settings)

    is_monolith = mode == "monolith"
    is_gateway = mode == "gateway"

    if is_monolith:
        app = dispatch_monolith(resolved_settings)
    elif is_gateway:
        app = dispatch_gateway(resolved_settings)
    else:
        app = dispatch_backend(resolved_settings)

    return app


app = create_app()
