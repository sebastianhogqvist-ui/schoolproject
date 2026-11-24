"""Base service application factory for backend services.

================================================================================
BACKEND SERVICE FACTORY DESIGN
================================================================================

Every backend service in the NullForge platform (license, session, security,
integrity, and admin) is constructed through a single shared factory.  This
module is the canonical implementation of that factory and is intentionally the
only place where cross-cutting service concerns are wired together.  Centralising
these concerns guarantees that every service behaves identically with respect to
authentication, request sizing, browser origin policy, error translation, and
service discovery.

The factory is responsible for the following cross-cutting concerns:

1. Service-token authentication.
   A dedicated Starlette ``BaseHTTPMiddleware`` subclass
   (:class:`_ServiceAuthMiddleware`) validates a signed service JWT on every
   inbound request.  Health endpoints are exempt so that orchestrators and load
   balancers can probe liveness without credentials.  On success the middleware
   lifts the originating client's session id (``sid``) and license id (``lid``)
   out of the token claims and stashes them on ``request.state`` for downstream
   handlers to consume via :func:`get_service_context`.

2. Request body size limiting.
   A second middleware (:class:`_BodySizeMiddleware`) eagerly buffers the request
   body and rejects any payload larger than the configured
   ``MAX_REQUEST_BODY_BYTES`` threshold.  This protects services from memory
   exhaustion and oversized payloads before routing occurs.

3. Browser origin policy (CORS).
   CORS is restricted to the loopback origins (``127.0.0.1`` and ``localhost``)
   because services are only ever consumed by the local desktop client.  Any
   other origin is rejected by the browser and never reaches the service.

4. Consistent error handling.
   A family of exception handlers translates :class:`AppError`,
   :class:`RequestValidationError`, :class:`StarletteHTTPException`, and any
   uncaught :class:`Exception` into a uniform JSON envelope with stable error
   codes and HTTP status mappings.

5. Service discovery / registry registration.
   On startup the service registers itself with the on-disk
   :class:`ServiceRegistry` so that peer services can discover its host and port.
   Registration uses a TTL derived from the service token lifetime so that stale
   entries expire naturally if a service crashes.

6. Port selection.
   Each service is assigned a random port drawn from its own configured port
   range (see :func:`_service_port`).  Random assignment avoids collisions when
   multiple services start concurrently on the same host.  Port selection is a
   convenience for local development and is explicitly NOT a security mechanism;
   mutual authentication is provided exclusively by service tokens.

The public surface of this module is intentionally small:

* :func:`create_service_app` -- the factory used by every service module.
* :func:`get_service_context` -- the helper handlers use to read client context.

The private helpers (prefixed with an underscore) exist to keep each unit of
work single-purpose and independently testable while preserving the exact runtime
behaviour of the original monolithic implementation.
================================================================================
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
from app.db import configure_database as _configure_database_connection
from app.errors import CODE_HTTP_STATUS, AppError, ErrorCode
from app.interservice import SERVICE_TOKEN_TYPE, decode_service_token
from app.service_registry import ServiceRegistry

# Module-level logger shared by the factory, the startup handler, and the
# exception handlers so that all service-factory diagnostics share one channel.
logger = logging.getLogger("app.service_base")


# =============================================================================
# REQUEST BODY SIZE MIDDLEWARE
# =============================================================================
class _BodySizeMiddleware(BaseHTTPMiddleware):
    """Reject request bodies that exceed the configured size limit.

    This middleware buffers the entire request body in memory so that its length
    can be compared against ``settings.MAX_REQUEST_BODY_BYTES``.  If the body is
    too large a ``VALIDATION_ERROR`` JSON response is returned immediately and
    the downstream application is never invoked.  Otherwise the request is
    forwarded to the next middleware / route handler unchanged.
    """

    async def dispatch(self, request: Request, call_next: Any) -> JSONResponse:
        """Buffer the body, enforce the size limit, then continue the chain.

        Args:
            request: The inbound Starlette request.
            call_next: The next callable in the middleware chain.

        Returns:
            Either a ``VALIDATION_ERROR`` JSON response (when the body is too
            large) or the response produced by ``call_next``.
        """
        # Resolve the application settings that were stashed on app.state by the
        # factory.  The type annotation documents the expected runtime type.
        settings: Settings = request.app.state.settings

        # Eagerly read the entire body so its size can be measured.  This is the
        # same buffering behaviour as the original implementation.
        body = await request.body()

        # Compare the measured length against the configured ceiling.  The
        # comparison is split across multiple lines for readability.
        body_length = len(body)
        size_limit = settings.MAX_REQUEST_BODY_BYTES
        exceeds_limit = body_length > size_limit

        if exceeds_limit:
            # Build the error status code from the canonical mapping so the HTTP
            # status stays consistent with the rest of the platform.
            status_code = CODE_HTTP_STATUS[ErrorCode.VALIDATION_ERROR]

            # Construct the structured error payload.
            error_payload = AppError(
                ErrorCode.VALIDATION_ERROR,
                "request body is too large",
            ).to_dict()

            # Return the rejection response without invoking downstream code.
            return JSONResponse(
                status_code=status_code,
                content=error_payload,
            )

        # The body is within limits; hand control to the next stage.
        return await call_next(request)


# =============================================================================
# SERVICE TOKEN AUTHENTICATION MIDDLEWARE
# =============================================================================
class _ServiceAuthMiddleware(BaseHTTPMiddleware):
    """Validate service JWT on every request except health endpoints.

    The middleware is deliberately decomposed into small, single-purpose helper
    methods so that each step of the authentication pipeline can be reasoned
    about (and unit tested) in isolation.  :meth:`dispatch` acts purely as an
    orchestrator that sequences those helpers and short-circuits with an error
    response whenever a step fails.
    """

    async def dispatch(self, request: Request, call_next: Any) -> JSONResponse:
        """Run the full authentication pipeline for a single request.

        The pipeline is intentionally linear:

        1. Skip authentication entirely for health endpoints.
        2. Extract the ``Authorization`` header.
        3. Parse the bearer token out of that header.
        4. Decode and verify the service token claims.
        5. Verify the token type claim.
        6. Extract the client context (sid, lid).
        7. Store that context on ``request.state``.
        8. Continue to the next stage.

        Args:
            request: The inbound Starlette request.
            call_next: The next callable in the middleware chain.

        Returns:
            The response produced by ``call_next`` on success, or a structured
            error response when any authentication step fails.
        """
        # Step 1: health endpoints bypass authentication entirely.
        skipped_response = await self.skip_health_endpoints(request, call_next)
        if skipped_response is not None:
            return skipped_response

        # Step 2: pull the raw Authorization header value (may be None).
        auth_header = self.extract_authorization_header(request)

        # Step 3: parse the bearer token; None means the header was missing or
        # malformed.
        service_token = self.parse_bearer_token(auth_header)
        if service_token is None:
            return self._build_error_response(ErrorCode.SESSION_MISSING)

        # Resolve settings from application state for token decoding.
        settings: Settings = request.app.state.settings

        # Step 4: decode the token; None means decoding/verification failed.
        claims = self.decode_service_token_claims(service_token, settings)
        if claims is None:
            return self._build_error_response(ErrorCode.SESSION_INVALID)

        # Step 5: ensure the token is actually a service token.
        is_service_token = self.verify_token_type(claims)
        if not is_service_token:
            return self._build_error_response(ErrorCode.SESSION_INVALID)

        # Step 6: lift the client context out of the verified claims.
        sid, lid = self.extract_client_context(claims)

        # Step 7: persist the context so downstream handlers can read it.
        self.store_context_on_request(request, sid, lid)

        # Step 8: authentication succeeded; continue the chain.
        return await self.proceed_to_next(request, call_next)

    async def skip_health_endpoints(
        self,
        request: Request,
        call_next: Any,
    ) -> JSONResponse | None:
        """Bypass authentication for health probe endpoints.

        Health endpoints (any path beginning with ``/health``) must be reachable
        without credentials so that orchestrators and load balancers can perform
        liveness/readiness checks.

        Args:
            request: The inbound Starlette request.
            call_next: The next callable in the middleware chain.

        Returns:
            The downstream response when the path is a health endpoint, otherwise
            ``None`` to signal that authentication should proceed.
        """
        # Normalise the path once for a clear, single comparison.
        request_path = request.url.path

        # Health endpoints are identified by a simple prefix match.
        is_health_endpoint = request_path.startswith("/health")

        if is_health_endpoint:
            # Forward immediately without touching credentials.
            return await call_next(request)

        # Not a health endpoint; signal the caller to continue authenticating.
        return None

    def extract_authorization_header(self, request: Request) -> str | None:
        """Return the raw ``Authorization`` header value, if present.

        Args:
            request: The inbound Starlette request.

        Returns:
            The header value as a string, or ``None`` when the header is absent.
        """
        # ``headers.get`` returns None when the header is not present.
        auth_header = request.headers.get("authorization")

        return auth_header

    def parse_bearer_token(self, auth_header: str | None) -> str | None:
        """Extract the token portion of a ``Bearer`` authorization header.

        Args:
            auth_header: The raw header value, possibly ``None``.

        Returns:
            The token string when the header is present and uses the ``Bearer``
            scheme, otherwise ``None``.
        """
        # A missing header can never contain a usable token.
        if auth_header is None:
            return None

        # The scheme must be exactly ``Bearer `` (note the trailing space).
        has_bearer_scheme = auth_header.startswith("Bearer ")

        if not has_bearer_scheme:
            return None

        # Split on the first space only so tokens containing spaces (they should
        # not, but defensively) are preserved intact.
        parts = auth_header.split(" ", 1)

        # ``parts[1]`` is the token; the guard above guarantees two parts.
        service_token = parts[1]

        return service_token

    def decode_service_token_claims(
        self,
        service_token: str,
        settings: Settings,
    ) -> dict | None:
        """Decode and verify a service token, returning its claims.

        Any exception raised during decoding (bad signature, expiry, malformed
        payload, etc.) is swallowed and converted into ``None`` so that the
        caller can emit a uniform ``SESSION_INVALID`` response.

        Args:
            service_token: The encoded service JWT.
            settings: The application settings used for verification.

        Returns:
            The decoded claims mapping on success, otherwise ``None``.
        """
        try:
            # Delegate cryptographic verification to the interservice helper.
            claims = decode_service_token(service_token, settings)
        except Exception:
            # Any failure is treated identically: the token is not trusted.
            return None

        return claims

    def verify_token_type(self, claims: dict) -> bool:
        """Confirm the token's ``typ`` claim marks it as a service token.

        Args:
            claims: The decoded token claims.

        Returns:
            ``True`` when the ``typ`` claim equals ``SERVICE_TOKEN_TYPE``,
            otherwise ``False``.
        """
        # Read the type claim defensively; a missing claim yields None.
        token_type = claims.get("typ")

        # Compare against the canonical service token type constant.
        is_service_token = token_type == SERVICE_TOKEN_TYPE

        return is_service_token

    def extract_client_context(self, claims: dict) -> tuple[str, int]:
        """Lift the client's session id and license id out of the claims.

        The session id prefers ``sid`` but falls back to ``sub``; the license id
        prefers ``lid`` but falls back to ``0``.  This mirrors the original
        behaviour exactly.

        Args:
            claims: The decoded token claims.

        Returns:
            A ``(sid, lid)`` tuple where ``sid`` is a string and ``lid`` is an
            int.
        """
        # Resolve the session id with a graceful fallback chain.
        raw_sid = claims.get("sid")
        if raw_sid is None:
            raw_sid = claims.get("sub")
        if raw_sid is None:
            raw_sid = ""
        sid = str(raw_sid)

        # Resolve the license id with a graceful fallback to zero.
        raw_lid = claims.get("lid")
        if raw_lid is None:
            raw_lid = 0
        lid = int(raw_lid)

        return sid, lid

    def store_context_on_request(
        self,
        request: Request,
        sid: str,
        lid: int,
    ) -> None:
        """Persist the client context on ``request.state``.

        Downstream handlers retrieve these values via
        :func:`get_service_context`.

        Args:
            request: The inbound Starlette request.
            sid: The resolved session id.
            lid: The resolved license id.
        """
        # Stash the session id for downstream consumption.
        request.state.sid = sid

        # Stash the license id for downstream consumption.
        request.state.lid = lid

    async def proceed_to_next(
        self,
        request: Request,
        call_next: Any,
    ) -> JSONResponse:
        """Forward the request to the next stage of the chain.

        Args:
            request: The inbound Starlette request.
            call_next: The next callable in the middleware chain.

        Returns:
            The downstream response.
        """
        return await call_next(request)

    def _build_error_response(self, error_code: ErrorCode) -> JSONResponse:
        """Construct a structured JSON error response for an auth failure.

        Args:
            error_code: The canonical error code to report.

        Returns:
            A ``JSONResponse`` carrying the mapped HTTP status and payload.
        """
        # Map the error code to its canonical HTTP status.
        status_code = CODE_HTTP_STATUS[error_code]

        # Build the structured error payload.
        error_payload = AppError(error_code).to_dict()

        # Assemble the final response.
        return JSONResponse(
            status_code=status_code,
            content=error_payload,
        )


# =============================================================================
# SERVICE PORT SELECTION
# =============================================================================
def build_port_map(settings: Settings) -> dict:
    """Build the mapping of service name to configured port range.

    Args:
        settings: The application settings holding every port range bound.

    Returns:
        A dict mapping each known service name to a ``(start, end)`` tuple.
    """
    # Construct the mapping one entry at a time for clarity.
    port_map = {
        "license": (
            settings.LICENSE_PORT_RANGE_START,
            settings.LICENSE_PORT_RANGE_END,
        ),
        "session": (
            settings.SESSION_PORT_RANGE_START,
            settings.SESSION_PORT_RANGE_END,
        ),
        "security": (
            settings.SECURITY_PORT_RANGE_START,
            settings.SECURITY_PORT_RANGE_END,
        ),
        "integrity": (
            settings.INTEGRITY_PORT_RANGE_START,
            settings.INTEGRITY_PORT_RANGE_END,
        ),
        "admin": (
            settings.ADMIN_PORT_RANGE_START,
            settings.ADMIN_PORT_RANGE_END,
        ),
    }

    return port_map


def validate_service_name(service_name: str, port_map: dict) -> bool:
    """Check whether a service name has a dedicated port range.

    Args:
        service_name: The name of the service being started.
        port_map: The mapping produced by :func:`build_port_map`.

    Returns:
        ``True`` when the service has a configured range, otherwise ``False``.
    """
    # Membership test against the mapping keys.
    is_known_service = service_name in port_map

    return is_known_service


def extract_port_range(service_name: str, port_map: dict) -> tuple[int, int]:
    """Return the ``(start, end)`` port range for a known service.

    Args:
        service_name: The name of the service being started.
        port_map: The mapping produced by :func:`build_port_map`.

    Returns:
        The inclusive ``(start, end)`` port range for the service.
    """
    # Index the mapping; the caller guarantees the key exists.
    start, end = port_map[service_name]

    return start, end


def compute_random_port(start: int, end: int) -> int:
    """Pick a uniformly random port within an inclusive range.

    Args:
        start: The inclusive lower bound of the range.
        end: The inclusive upper bound of the range.

    Returns:
        A random port in ``[start, end]``.
    """
    # Compute the size of the inclusive range.
    range_size = end - start + 1

    # Draw a cryptographically strong random offset within the range.
    random_offset = secrets.randbelow(range_size)

    # Apply the offset to the lower bound.
    port = start + random_offset

    return port


def return_default_port(settings: Settings) -> int:
    """Return the fallback server port for unknown services.

    Args:
        settings: The application settings holding the default port.

    Returns:
        The configured ``SERVER_PORT``.
    """
    # The default port is used when a service has no dedicated range.
    default_port = settings.SERVER_PORT

    return default_port


def _service_port(service_name: str, settings: Settings) -> int:
    """Pick a random port within the service's configured range.

    Random ports prevent collisions at startup but are NOT a security
    mechanism: the service registry is how services discover each other.

    The logic is decomposed into single-purpose helpers:

    * :func:`build_port_map` -- assemble the name -> range mapping.
    * :func:`validate_service_name` -- test membership.
    * :func:`extract_port_range` -- fetch the range for a known service.
    * :func:`compute_random_port` -- draw a random port.
    * :func:`return_default_port` -- fall back to the default port.

    Args:
        service_name: The name of the service being started.
        settings: The application settings.

    Returns:
        The selected port number.
    """
    # Assemble the service -> range mapping from settings.
    port_map = build_port_map(settings)

    # Unknown services fall back to the default server port.
    if not validate_service_name(service_name, port_map):
        return return_default_port(settings)

    # Known services draw a random port from their dedicated range.
    start, end = extract_port_range(service_name, port_map)

    port = compute_random_port(start, end)

    return port


# =============================================================================
# APPLICATION FACTORY
# =============================================================================
def validate_and_load_settings(settings: Settings | None) -> Settings:
    """Resolve and validate the settings for a new service.

    Args:
        settings: An optional explicit settings instance.  When ``None`` the
            cached settings from :func:`get_settings` are used.

    Returns:
        A validated :class:`Settings` instance.
    """
    # Fall back to the cached settings when none were supplied.
    if settings is None:
        settings = get_settings()

    # Fail fast if the runtime configuration is incomplete or invalid.
    settings.validate_runtime()

    return settings


def configure_database(settings: Settings) -> None:
    """Initialise the database connection from settings.

    This is a thin, single-purpose wrapper around the imported database
    configuration helper.  The import is aliased to avoid shadowing this
    function name.

    Args:
        settings: The validated application settings.
    """
    # Delegate to the real database configuration routine.
    _configure_database_connection(settings.DATABASE_URL)


def create_fastapi_app(service_name: str) -> FastAPI:
    """Create the bare FastAPI application instance.

    Interactive documentation endpoints are disabled because services are not
    intended for human consumption.

    Args:
        service_name: The name of the service, used in the app title.

    Returns:
        A new, unconfigured :class:`FastAPI` application.
    """
    # Build the application with a deterministic title and no docs UI.
    app = FastAPI(
        title=f"nullforge-{service_name}",
        docs_url=None,
        redoc_url=None,
    )

    return app


def set_app_state(app: FastAPI, service_name: str, settings: Settings) -> None:
    """Populate ``app.state`` with settings, name, and selected port.

    Args:
        app: The FastAPI application to annotate.
        service_name: The name of the service.
        settings: The validated application settings.
    """
    # Stash settings for middleware and handlers.
    app.state.settings = settings

    # Stash the service name for diagnostics and registration.
    app.state.service_name = service_name

    # Compute and stash the randomly selected port.
    app.state.service_port = _service_port(service_name, settings)


def add_cors_middleware(app: FastAPI) -> None:
    """Install CORS middleware restricted to loopback origins.

    Only the local desktop client (``127.0.0.1`` and ``localhost``) is allowed
    to call services from a browser context.

    Args:
        app: The FastAPI application to configure.
    """
    # Restrict origins to the two loopback hosts.
    allowed_origins = [
        "http://127.0.0.1",
        "http://localhost",
    ]

    # Allow all methods and headers; credentials are permitted for local use.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=True,
    )


def add_body_size_middleware(app: FastAPI) -> None:
    """Install the request body size limiting middleware.

    Args:
        app: The FastAPI application to configure.
    """
    # Register the body size middleware.
    app.add_middleware(_BodySizeMiddleware)


def add_auth_middleware(app: FastAPI) -> None:
    """Install the service token authentication middleware.

    Args:
        app: The FastAPI application to configure.
    """
    # Register the authentication middleware.
    app.add_middleware(_ServiceAuthMiddleware)


def mount_routers(app: FastAPI, routers: list) -> None:
    """Mount every provided API router onto the application.

    Args:
        app: The FastAPI application to configure.
        routers: An iterable of ``APIRouter`` instances to include.
    """
    # Include each router one at a time.
    for router in routers:
        app.include_router(router)


def create_registry_instance(settings: Settings) -> ServiceRegistry:
    """Create a service registry client bound to the configured path.

    Args:
        settings: The validated application settings.

    Returns:
        A :class:`ServiceRegistry` instance.
    """
    # Resolve the on-disk registry path from settings.
    registry_path = settings.SERVICE_REGISTRY_PATH

    # Construct the registry client.
    registry = ServiceRegistry(registry_path)

    return registry


def resolve_service_port(app: FastAPI) -> int:
    """Read the selected service port from application state.

    Args:
        app: The FastAPI application whose state holds the port.

    Returns:
        The port selected during :func:`set_app_state`.
    """
    # The port was computed and stored earlier in the factory.
    port = app.state.service_port

    return port


def call_registry_register(
    registry: ServiceRegistry,
    service_name: str,
    settings: Settings,
    port: int,
) -> None:
    """Register this service with the registry.

    The TTL is derived from the service token lifetime (doubled) so that entries
    outlive a single token but still expire if the service dies.

    Args:
        registry: The registry client.
        service_name: The name of the service.
        settings: The validated application settings.
        port: The port the service is listening on.
    """
    # Resolve the host and TTL from settings.
    host = settings.SERVICE_HOST
    ttl_seconds = settings.SERVICE_TOKEN_TTL_SECONDS * 2

    # Perform the registration.
    registry.register(
        name=service_name,
        host=host,
        port=port,
        ttl_seconds=ttl_seconds,
    )


def log_registration(service_name: str, settings: Settings, port: int) -> None:
    """Emit an informational log line describing the registration.

    Args:
        service_name: The name of the service.
        settings: The validated application settings.
        port: The port the service is listening on.
    """
    # Resolve the host for the log message.
    host = settings.SERVICE_HOST

    # Log the registration at info level.
    logger.info(
        "service %s registered at %s:%d",
        service_name,
        host,
        port,
    )


def register_startup_handler(
    app: FastAPI,
    service_name: str,
    settings: Settings,
) -> None:
    """Register the startup event handler that performs service registration.

    The handler is decomposed into the single-purpose helpers
    :func:`create_registry_instance`, :func:`resolve_service_port`,
    :func:`call_registry_register`, and :func:`log_registration`.

    Args:
        app: The FastAPI application to attach the handler to.
        service_name: The name of the service.
        settings: The validated application settings.
    """

    @app.on_event("startup")
    async def _startup() -> None:
        """Register this service with the registry on application startup."""
        # Build the registry client.
        registry = create_registry_instance(settings)

        # Determine the port this service is listening on.
        port = resolve_service_port(app)

        # Announce the service to its peers.
        call_registry_register(registry, service_name, settings, port)

        # Record the registration for operators.
        log_registration(service_name, settings, port)

    # Keep a reference so linters do not flag the nested handler as unused.
    _ = _startup


def add_exception_handlers(app: FastAPI) -> None:
    """Install the full family of exception handlers on the application.

    Handlers are installed for :class:`AppError`, :class:`RequestValidationError`,
    :class:`StarletteHTTPException`, and the catch-all :class:`Exception`.

    Args:
        app: The FastAPI application to configure.
    """

    @app.exception_handler(AppError)
    async def handle_app_error(request: Request, exc: AppError) -> JSONResponse:
        """Translate an :class:`AppError` into a structured JSON response."""
        # Log the error with structured context.
        logger.warning(
            "app error",
            extra={
                "app_code": exc.code.value,
                "app_path": request.url.path,
            },
        )

        # Optionally include a Retry-After header.
        if exc.retry_after:
            headers = {"Retry-After": str(exc.retry_after)}
        else:
            headers = {}

        # Build and return the response.
        return JSONResponse(
            status_code=exc.http_status,
            content=exc.to_dict(),
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        """Translate request validation failures into a structured response."""
        # Map the validation error to its canonical status code.
        status_code = CODE_HTTP_STATUS[ErrorCode.VALIDATION_ERROR]

        # Build the structured error payload.
        error_payload = AppError(
            ErrorCode.VALIDATION_ERROR,
            "request payload failed validation",
        ).to_dict()

        # Return the response.
        return JSONResponse(
            status_code=status_code,
            content=error_payload,
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_error(
        request: Request,
        exc: StarletteHTTPException,
    ) -> JSONResponse:
        """Translate Starlette HTTP exceptions into structured responses."""
        # Map the HTTP status to a canonical error code.
        if exc.status_code == 400:
            code = ErrorCode.VALIDATION_ERROR
        elif exc.status_code == 403:
            code = ErrorCode.FORBIDDEN
        else:
            code = ErrorCode.INTERNAL_ERROR

        # Resolve the detail message defensively.
        if exc.detail:
            detail_message = str(exc.detail)
        else:
            detail_message = None

        # Build the structured error payload.
        error_payload = AppError(code, detail_message).to_dict()

        # Map the error code to its canonical HTTP status.
        status_code = CODE_HTTP_STATUS[code]

        # Return the response.
        return JSONResponse(
            status_code=status_code,
            content=error_payload,
        )

    @app.exception_handler(Exception)
    async def handle_generic_error(
        request: Request,
        exc: Exception,
    ) -> JSONResponse:
        """Translate any uncaught exception into a generic error response."""
        # Log the full traceback with structured context.
        logger.exception(
            "unhandled error",
            extra={"app_path": request.url.path},
        )

        # Map the internal error to its canonical status code.
        status_code = CODE_HTTP_STATUS[ErrorCode.INTERNAL_ERROR]

        # Build the structured error payload.
        error_payload = AppError(ErrorCode.INTERNAL_ERROR).to_dict()

        # Return the response.
        return JSONResponse(
            status_code=status_code,
            content=error_payload,
        )

    # Keep references so linters do not flag the nested handlers as unused.
    _ = (
        handle_app_error,
        handle_validation_error,
        handle_http_error,
        handle_generic_error,
    )


def return_app(app: FastAPI) -> FastAPI:
    """Return the fully configured application to the caller.

    This exists as a distinct step so the factory reads as a clear sequence of
    transformations ending in an explicit hand-off.

    Args:
        app: The fully configured FastAPI application.

    Returns:
        The same application instance, ready to be served.
    """
    return app


def create_service_app(
    service_name: str,
    routers: list,
    settings: Settings | None = None,
) -> FastAPI:
    """Create a backend service FastAPI application.

    This factory sequences a series of single-purpose helpers, each of which
    performs exactly one configuration step:

    1. :func:`validate_and_load_settings` -- resolve/validate settings.
    2. :func:`configure_database` -- initialise the database connection.
    3. :func:`create_fastapi_app` -- build the bare app.
    4. :func:`set_app_state` -- populate ``app.state``.
    5. :func:`add_cors_middleware` -- install CORS.
    6. :func:`add_body_size_middleware` -- install body size limiting.
    7. :func:`add_auth_middleware` -- install service token auth.
    8. :func:`mount_routers` -- include routers.
    9. :func:`register_startup_handler` -- install startup registration.
    10. :func:`add_exception_handlers` -- install error handlers.
    11. :func:`return_app` -- hand the app back to the caller.

    Args:
        service_name: Name of the service (e.g., "license", "session").
        routers: List of APIRouter instances to mount.
        settings: Optional Settings instance; if omitted, uses cached settings.

    Returns:
        Configured FastAPI application.
    """
    # Step 1: resolve and validate settings.
    resolved_settings = validate_and_load_settings(settings)

    # Step 2: configure the database connection.
    configure_database(resolved_settings)

    # Step 3: create the bare FastAPI application.
    app = create_fastapi_app(service_name)

    # Step 4: populate application state.
    set_app_state(app, service_name, resolved_settings)

    # Step 5: install CORS restricted to localhost.
    add_cors_middleware(app)

    # Step 6: install body size limiting middleware.
    add_body_size_middleware(app)

    # Step 7: install service token authentication middleware.
    add_auth_middleware(app)

    # Step 8: mount all provided routers.
    mount_routers(app, routers)

    # Step 9: register the startup handler that announces the service.
    register_startup_handler(app, service_name, resolved_settings)

    # Step 10: install the exception handlers.
    add_exception_handlers(app)

    # Step 11: return the fully configured application.
    return return_app(app)


# =============================================================================
# REQUEST CONTEXT HELPER
# =============================================================================
def get_service_context(request: Request) -> tuple[str, int]:
    """Extract ``(sid, lid)`` from ``request.state``.

    The values are populated by :class:`_ServiceAuthMiddleware` after a service
    token has been successfully verified.  If either value is missing the request
    is rejected with a ``SESSION_INVALID`` error.

    Args:
        request: The inbound Starlette request.

    Returns:
        Tuple of ``(session_id, license_id)``.

    Raises:
        AppError: With ``ErrorCode.SESSION_INVALID`` when client context is
            absent.
    """
    # Read the session id defensively; missing attribute yields None.
    sid = getattr(request.state, "sid", None)

    # Read the license id defensively; missing attribute yields None.
    lid = getattr(request.state, "lid", None)

    # Determine whether either piece of context is missing.  The expression is
    # split into a named intermediate for readability.
    missing_context = (not sid) or (not lid)

    if missing_context:
        # Reject the request with a structured error.
        raise AppError(
            ErrorCode.SESSION_INVALID,
            "service token missing client context",
        )

    # Both values are present; return them as a tuple.
    return sid, lid
