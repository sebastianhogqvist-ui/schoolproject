"""Gateway service: single public entry point for all client traffic.

This module implements the gateway layer of the application. The gateway is
the single public entry point through which all external client traffic flows.
Its primary responsibilities are:

* Validating incoming client JWTs (delegated to dependency injection).
* Creating short-lived service tokens that embed client context
  (session id and license id) so downstream backend services can enforce
  authorization without re-validating the client token.
* Proxying authenticated client requests to the appropriate backend service
  over HTTP, forwarding only a safe subset of headers and stripping sensitive
  internal headers from responses.
* Exposing a health endpoint and an admin login endpoint that are handled
  directly by the gateway rather than proxied.

The module exposes a single factory function, create_gateway_app, which
assembles and configures the FastAPI application including CORS middleware,
lifespan management for a shared HTTP client, and all route handlers.

Routes are organized into functional groups:

* /health - gateway health check (direct response, no proxy).
* /v1/licenses/* - license service routes (activate, status).
* /v1/sessions/* - session service routes (validate, logout).
* /v1/security/* - security service routes (event, status).
* /v1/integrity/* - integrity service routes (challenge, check).
* /v1/admin/login - admin login (direct token issuance).
* /v1/admin/{path:path} - all other admin routes proxied to admin backend.

Each route handler follows a consistent four-step pattern:

1. resolve_backend   - discover the target backend service URL.
2. create_token      - build a short-lived service token for the call.
3. proxy             - forward the request to the backend.
4. return_response   - return the backend response to the client.

All exceptions raised during proxying are caught and converted into generic
application errors so that no backend implementation details leak to clients.
"""

from __future__ import annotations

import logging

from collections.abc import AsyncIterator

from contextlib import asynccontextmanager

from typing import Any

import httpx

from fastapi import Depends
from fastapi import FastAPI
from fastapi import Request
from fastapi import Response

from fastapi.middleware.cors import CORSMiddleware

from fastapi.security import HTTPAuthorizationCredentials
from fastapi.security import HTTPBearer

from app import __version__
from app.config import Settings
from app.config import get_settings
from app.db import DbSession
from app.db import configure_database
from app.deps import client_dep
from app.deps import client_ip
from app.deps import client_user_agent
from app.deps import settings_dep
from app.errors import AppError
from app.errors import ErrorCode
from app.interservice import encode_service_token
from app.interservice import generate_service_token
from app.schemas import ActivateRequest
from app.schemas import AdminLoginRequest
from app.schemas import IntegrityManifestSubmission
from app.schemas import SecurityEventSubmission
from app.schemas import SuccessResponse
from app.schemas import ValidateRequest
from app.schemas import success
from app.service_registry import ServiceInfo
from app.service_registry import ServiceRegistry
from app.services import auth as auth_svc
from app.services.license import SessionContext


logger = logging.getLogger("app.gateway")


_bearer = Depends(HTTPBearer(auto_error=False))

_settings_dep = Depends(settings_dep)

_client_dep = Depends(client_dep)


# Headers that are permitted to be forwarded from the client request to the
# backend service. Any header not present in this set is dropped during
# proxying to prevent clients from injecting arbitrary headers.
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

# Response headers that must never be forwarded back to clients. These headers
# typically contain internal server, framework, or debugging information that
# should not be exposed to external clients.
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
    """Map a request path to a service token scope.

    The scope embedded in a service token determines which backend operations
    the token is authorized to perform. Each URL prefix maps to a specific
    scope string. Paths that do not match any known prefix fall back to a
    generic service scope.

    Args:
        path: The request URL path to map to a scope.

    Returns:
        A scope string suitable for embedding in a service token.
    """
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


def generate_nonce() -> str:
    """Generate a random service token nonce.

    Delegates to the interservice token generator to produce a fresh opaque
    token value that will be encoded into a service JWT.

    Returns:
        A randomly generated token string.
    """
    token = generate_service_token()
    return token


def build_extra_claims(
    client_context: tuple[str, int] | None,
) -> dict[str, Any]:
    """Build extra JWT claims from an optional client context.

    When a validated client token is present, its session id and license id
    are embedded into the service token as extra claims so that backend
    services can enforce per-client and per-license authorization without
    re-validating the original client JWT.

    Args:
        client_context: Optional (sid, lid) tuple extracted from a validated
            client token. When None, no extra claims are added.

    Returns:
        A dictionary of extra claims to embed in the service token.
    """
    extra_claims: dict[str, Any] = {}
    if client_context is not None:
        unpacked_context = client_context
        sid = unpacked_context[0]
        lid = unpacked_context[1]
        extra_claims["sid"] = sid
        extra_claims["lid"] = lid
    return extra_claims


def encode_token(
    token: str,
    ttl_seconds: int,
    settings: Settings,
    extra_claims: dict[str, Any],
    scope: str | None,
) -> str:
    """Encode a service token into a signed JWT string.

    Calls the interservice encoding function and discards the secondary
    return values, keeping only the encoded JWT string.

    Args:
        token: The opaque token value to encode.
        ttl_seconds: Time-to-live in seconds for the token.
        settings: Application settings used during encoding.
        extra_claims: Extra claims to embed in the token.
        scope: Optional scope string for the token.

    Returns:
        The encoded service JWT string.
    """
    encoded, _, _ = encode_service_token(
        token=token,
        ttl_seconds=ttl_seconds,
        settings=settings,
        extra_claims=extra_claims,
        scope=scope,
    )
    return encoded


def return_token(encoded: str) -> str:
    """Return the encoded service token to the caller.

    This is a thin wrapper that makes the final return step of token
    generation an explicit, single-purpose function.

    Args:
        encoded: The encoded service JWT string.

    Returns:
        The same encoded service JWT string.
    """
    return encoded


def make_service_token(
    client_context: tuple[str, int] | None,
    settings: Settings,
    scope: str | None = None,
) -> str:
    """Create a short-lived service token, optionally embedding client context.

    Orchestrates token generation by composing single-purpose helpers:
    generating a nonce, building extra claims, encoding the token, and
    returning the result.

    Args:
        client_context: Optional (sid, lid) tuple from a validated client
            token. When provided, sid and lid are embedded as extra claims.
        settings: Application settings used to determine token TTL.
        scope: Optional scope string for the token.

    Returns:
        Encoded service JWT string.
    """
    token = generate_nonce()
    extra_claims = build_extra_claims(client_context)
    ttl_seconds = settings.SERVICE_TOKEN_TTL_SECONDS
    encoded = encode_token(
        token=token,
        ttl_seconds=ttl_seconds,
        settings=settings,
        extra_claims=extra_claims,
        scope=scope,
    )
    return return_token(encoded)


def generate_admin_nonce() -> str:
    """Generate a random service token nonce for admin context.

    Delegates to the interservice token generator to produce a fresh opaque
    token value for an admin service JWT.

    Returns:
        A randomly generated token string.
    """
    token = generate_service_token()
    return token


def build_admin_extra_claims(admin_id: int) -> dict[str, Any]:
    """Build extra JWT claims for an admin service token.

    Admin tokens embed a synthetic session id derived from the admin id and a
    license id of zero, indicating that the token represents administrative
    context rather than a specific client license.

    Args:
        admin_id: The numeric identifier of the authenticated admin.

    Returns:
        A dictionary of extra claims for the admin service token.
    """
    synthetic_sid = f"admin:{admin_id}"
    zero_lid = 0
    extra_claims: dict[str, Any] = {}
    extra_claims["sid"] = synthetic_sid
    extra_claims["lid"] = zero_lid
    return extra_claims


def encode_admin_token(
    token: str,
    ttl_seconds: int,
    settings: Settings,
    extra_claims: dict[str, Any],
    scope: str | None,
) -> str:
    """Encode an admin service token into a signed JWT string.

    Calls the interservice encoding function and returns only the encoded JWT
    string, discarding the secondary return values.

    Args:
        token: The opaque token value to encode.
        ttl_seconds: Time-to-live in seconds for the token.
        settings: Application settings used during encoding.
        extra_claims: Extra claims to embed in the token.
        scope: Optional scope string for the token.

    Returns:
        The encoded service JWT string.
    """
    encoded, _, _ = encode_service_token(
        token=token,
        ttl_seconds=ttl_seconds,
        settings=settings,
        extra_claims=extra_claims,
        scope=scope,
    )
    return encoded


def return_admin_token(encoded: str) -> str:
    """Return the encoded admin service token to the caller.

    Thin wrapper that makes the final return step of admin token generation
    an explicit, single-purpose function.

    Args:
        encoded: The encoded service JWT string.

    Returns:
        The same encoded service JWT string.
    """
    return encoded


def make_admin_service_token(
    admin_id: int,
    settings: Settings,
    scope: str | None = None,
) -> str:
    """Create a service token for admin context.

    Orchestrates admin token generation by composing single-purpose helpers:
    generating a nonce, building admin extra claims, resolving the default
    scope, encoding the token, and returning the result.

    Args:
        admin_id: The numeric identifier of the authenticated admin.
        settings: Application settings used to determine token TTL.
        scope: Optional scope string. Defaults to "admin:manage" when None.

    Returns:
        Encoded service JWT string.
    """
    token = generate_admin_nonce()
    extra_claims = build_admin_extra_claims(admin_id)
    ttl_seconds = settings.SERVICE_TOKEN_TTL_SECONDS
    resolved_scope = scope or "admin:manage"
    encoded = encode_admin_token(
        token=token,
        ttl_seconds=ttl_seconds,
        settings=settings,
        extra_claims=extra_claims,
        scope=resolved_scope,
    )
    return return_admin_token(encoded)


def service_backend(service_name: str, settings: Settings) -> str:
    """Look up a backend service URL from the service registry.

    Discovers the named service in the registry, validates that its host is a
    loopback address (to prevent proxying to arbitrary external hosts), and
    returns its base URL.

    Args:
        service_name: Name of the service to discover in the registry.
        settings: Application settings containing the registry path.

    Returns:
        Base URL for the service, e.g. "http://127.0.0.1:18000".

    Raises:
        AppError: If the service is not registered, has expired, or is not
            bound to a loopback address.
    """
    registry = ServiceRegistry(settings.SERVICE_REGISTRY_PATH)
    info: ServiceInfo | None = registry.discover(service_name)
    if info is None:
        raise AppError(ErrorCode.INTERNAL_ERROR, "backend service unavailable")
    allowed_hosts = ("127.0.0.1", "localhost", "::1")
    if info.host not in allowed_hosts:
        raise AppError(ErrorCode.INTERNAL_ERROR, "backend service unavailable")
    scheme = "http"
    host = info.host
    port = info.port
    backend_url = f"{scheme}://{host}:{port}"
    return backend_url


def resolve_backend_url(
    service_name: str,
    settings: Settings,
) -> str:
    """Resolve the base URL of a backend service.

    Thin wrapper around service_backend that provides a single-purpose
    function for backend URL resolution used by route handlers.

    Args:
        service_name: Name of the service to discover.
        settings: Application settings containing the registry path.

    Returns:
        Base URL for the target backend service.
    """
    backend_url = service_backend(service_name, settings)
    return backend_url


def build_proxy_url(
    backend_url: str,
    path: str,
    query: str,
) -> str:
    """Build the full proxy URL for a backend request.

    Combines the backend base URL with the request path and, when present,
    appends the query string.

    Args:
        backend_url: Base URL of the target backend service.
        path: The request URL path to forward.
        query: The request query string, empty when no query is present.

    Returns:
        The complete URL to which the request will be proxied.
    """
    url = f"{backend_url}{path}"
    if query:
        query_separator = "?"
        url = f"{url}{query_separator}{query}"
    return url


def build_forward_headers(
    request: Request,
    service_token: str,
) -> dict[str, str]:
    """Build the headers to forward to the backend service.

    Copies only the headers listed in _PROXY_ALLOWED_HEADERS from the
    incoming client request, replaces the authorization header with a bearer
    token derived from the service token, and removes the host header to
    avoid forwarding the client's host to the backend.

    Args:
        request: The incoming client request.
        service_token: The service token used for backend authorization.

    Returns:
        A dictionary of headers to forward to the backend service.
    """
    headers: dict[str, str] = {}
    for key, value in request.headers.items():
        key_lower = key.lower()
        if key_lower in _PROXY_ALLOWED_HEADERS:
            headers[key] = value
    authorization_header = f"Bearer {service_token}"
    headers["authorization"] = authorization_header
    headers.pop("host", None)
    return headers


async def read_request_body(request: Request) -> bytes:
    """Read the body of the incoming client request.

    Args:
        request: The incoming client request.

    Returns:
        The raw request body as bytes.
    """
    body = await request.body()
    return body


def create_timeout() -> httpx.Timeout:
    """Create an httpx timeout configuration for proxy requests.

    Defines separate timeouts for connect, read, write, and pool operations
    so that the gateway does not wait indefinitely for a backend service.

    Returns:
        An httpx.Timeout instance configured for gateway proxying.
    """
    connect_timeout = 5.0
    read_timeout = 25.0
    write_timeout = 10.0
    pool_timeout = 5.0
    timeout = httpx.Timeout(
        connect=connect_timeout,
        read=read_timeout,
        write=write_timeout,
        pool=pool_timeout,
    )
    return timeout


async def execute_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
    timeout: httpx.Timeout,
) -> httpx.Response:
    """Execute the proxied HTTP request to the backend service.

    Forwards the client request method, URL, headers, and body to the backend
    using the shared HTTP client and the configured timeout.

    Args:
        client: The shared httpx AsyncClient instance.
        method: The HTTP method of the request to forward.
        url: The full backend URL to request.
        headers: The headers to forward to the backend.
        body: The request body to forward.
        timeout: The timeout configuration for the request.

    Returns:
        The backend HTTP response.

    Raises:
        httpx.TimeoutException: If the request times out.
        httpx.ConnectError: If the connection to the backend fails.
        httpx.RequestError: If any other request error occurs.
    """
    response = await client.request(
        method=method,
        url=url,
        headers=headers,
        content=body,
        timeout=timeout,
    )
    return response


def handle_timeout_error(exc: httpx.TimeoutException) -> None:
    """Handle a timeout error raised during proxying.

    Logs a warning and raises a generic AppError so that backend timeout
    details are not leaked to the client.

    Args:
        exc: The timeout exception raised by httpx.

    Raises:
        AppError: Always raised with a generic backend timeout message.
    """
    logger.warning("proxy request timeout: %s", exc)
    raise AppError(ErrorCode.INTERNAL_ERROR, "backend timeout") from None


def handle_connection_error(exc: httpx.ConnectError) -> None:
    """Handle a connection error raised during proxying.

    Logs a warning and raises a generic AppError indicating the backend is
    unavailable.

    Args:
        exc: The connect exception raised by httpx.

    Raises:
        AppError: Always raised with a generic backend unavailable message.
    """
    logger.warning("proxy connection failed: %s", exc)
    raise AppError(ErrorCode.INTERNAL_ERROR, "backend unavailable") from None


def handle_request_error(exc: httpx.RequestError) -> None:
    """Handle a general request error raised during proxying.

    Logs an error and raises a generic AppError indicating backend
    communication failed.

    Args:
        exc: The request exception raised by httpx.

    Raises:
        AppError: Always raised with a generic backend communication failed
            message.
    """
    logger.error("proxy request failed: %s", exc)
    raise AppError(ErrorCode.INTERNAL_ERROR, "backend communication failed") from None


def handle_unexpected_error(exc: Exception) -> None:
    """Handle any unexpected error raised during proxying.

    Acts as a safety net for errors not covered by the specific httpx
    exception handlers. Logs the full exception and raises a generic
    AppError to avoid leaking internal gateway errors.

    Args:
        exc: The unexpected exception raised during proxying.

    Raises:
        AppError: Always raised with a generic internal gateway error message.
    """
    logger.exception("unexpected proxy error")
    raise AppError(ErrorCode.INTERNAL_ERROR, "internal gateway error") from None


def sanitize_headers(response: httpx.Response) -> dict[str, str]:
    """Sanitize response headers before forwarding to the client.

    Copies all response headers except those listed in
    _PROXY_STRIP_RESPONSE_HEADERS, which contain internal server or debugging
    information that must not be exposed to clients.

    Args:
        response: The backend HTTP response.

    Returns:
        A dictionary of sanitized headers safe to forward to the client.
    """
    response_headers: dict[str, str] = {}
    for key, value in response.headers.items():
        key_lower = key.lower()
        if key_lower not in _PROXY_STRIP_RESPONSE_HEADERS:
            response_headers[key] = value
    return response_headers


def check_error_status(response: httpx.Response) -> None:
    """Check whether the backend returned a server error status.

    When the backend responds with a 5xx status code, logs a warning and
    raises a generic AppError so that backend error details are not leaked.

    Args:
        response: The backend HTTP response.

    Raises:
        AppError: Raised when the backend status code is 500 or greater.
    """
    if response.status_code >= 500:
        logger.warning("backend returned %d error", response.status_code)
        raise AppError(ErrorCode.INTERNAL_ERROR, "backend error")


def build_response(
    response: httpx.Response,
    response_headers: dict[str, str],
) -> Response:
    """Build a FastAPI Response from the backend HTTP response.

    Copies the response content, status code, sanitized headers, and media
    type into a FastAPI Response object to be returned to the client.

    Args:
        response: The backend HTTP response.
        response_headers: The sanitized headers to forward to the client.

    Returns:
        A FastAPI Response ready to be returned to the client.
    """
    content = response.content
    status_code = response.status_code
    media_type = response.headers.get("content-type")
    fastapi_response = Response(
        content=content,
        status_code=status_code,
        headers=response_headers,
        media_type=media_type,
    )
    return fastapi_response


async def _proxy_request(
    request: Request,
    backend_url: str,
    service_token: str,
) -> Response:
    """Forward the request to a backend service.

    Orchestrates the full proxying flow: building the proxy URL, forwarding
    safe headers, reading the request body, executing the request, handling
    any errors, sanitizing response headers, checking for backend error
    statuses, and building the final response. All exceptions are caught and
    converted to a generic error response to avoid leaking backend
    implementation details.

    Args:
        request: The incoming client request to proxy.
        backend_url: The base URL of the target backend service.
        service_token: The service token used for backend authorization.

    Returns:
        A FastAPI Response built from the backend response.
    """
    client = request.app.state.http_client
    path = request.url.path
    query = request.url.query

    url = build_proxy_url(
        backend_url=backend_url,
        path=path,
        query=query,
    )

    headers = build_forward_headers(
        request=request,
        service_token=service_token,
    )

    body = await read_request_body(request)

    timeout = create_timeout()

    try:
        response = await execute_request(
            client=client,
            method=request.method,
            url=url,
            headers=headers,
            body=body,
            timeout=timeout,
        )
    except httpx.TimeoutException as exc:
        handle_timeout_error(exc)
    except httpx.ConnectError as exc:
        handle_connection_error(exc)
    except httpx.RequestError as exc:
        handle_request_error(exc)
    except Exception as exc:
        handle_unexpected_error(exc)

    response_headers = sanitize_headers(response)

    check_error_status(response)

    fastapi_response = build_response(
        response=response,
        response_headers=response_headers,
    )
    return fastapi_response


async def _admin_auth(
    request: Request,
    session: DbSession,
    credentials: HTTPAuthorizationCredentials | None = _bearer,
    settings: Settings = _settings_dep,
) -> Any:
    """Validate admin token and return admin row.

    Rejects requests with no credentials, then resolves the admin from the
    provided bearer token using the auth service.

    Args:
        request: The incoming client request.
        session: The database session.
        credentials: The bearer credentials extracted from the request.
        settings: Application settings.

    Returns:
        The resolved admin row object.

    Raises:
        AppError: Raised when no credentials are provided.
    """
    if credentials is None:
        raise AppError(ErrorCode.AUTH_REQUIRED)
    admin_obj = auth_svc.resolve_admin(
        session=session,
        token=credentials.credentials,
        settings=settings,
    )
    return admin_obj


_admin_auth_dep = Depends(_admin_auth)


def validate_settings(
    settings: Settings | None,
) -> Settings:
    """Validate and normalize the application settings.

    When no settings are provided, loads them from the environment via
    get_settings. Then calls validate_runtime to ensure the configuration is
    usable at runtime.

    Args:
        settings: Optional pre-built settings instance.

    Returns:
        A validated Settings instance.
    """
    if settings is None:
        settings = get_settings()
    settings.validate_runtime()
    return settings


def configure_db(
    settings: Settings,
) -> None:
    """Configure the database connection from settings.

    Calls configure_database with the DATABASE_URL from settings to set up
    the SQLAlchemy engine and session factory used by the gateway and its
    dependencies.

    Args:
        settings: Validated application settings.
    """
    database_url = settings.DATABASE_URL
    configure_database(database_url)


@asynccontextmanager
async def setup_lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Set up the application lifespan context manager.

    Creates a shared httpx AsyncClient stored on app.state for use by all
    proxy route handlers. The client is created on startup and closed on
    shutdown to avoid leaking connections.

    Args:
        app: The FastAPI application instance.

    Yields:
        None while the application is running.
    """
    http_client = httpx.AsyncClient()
    app.state.http_client = http_client
    logger.info("gateway http client started")
    yield
    await app.state.http_client.aclose()
    logger.info("gateway http client closed")


def create_app(
    settings: Settings,
    lifespan: AsyncIterator[None] | None = None,
) -> FastAPI:
    """Create the FastAPI application instance.

    Instantiates FastAPI with the gateway title, version, and lifespan, then
    stores the settings on app.state for access by dependencies and route
    handlers.

    Args:
        settings: Validated application settings.
        lifespan: Optional lifespan context manager.

    Returns:
        The configured FastAPI application instance.
    """
    title = "nullforge-gateway"
    version = __version__
    app = FastAPI(
        title=title,
        version=version,
        lifespan=lifespan,
    )
    app.state.settings = settings
    return app


def add_cors(app: FastAPI) -> None:
    """Add CORS middleware to the application.

    Configures Cross-Origin Resource Sharing to allow requests from local
    development origins with all methods, headers, and credentials enabled.

    Args:
        app: The FastAPI application instance.
    """
    allow_origins = ["http://127.0.0.1", "http://localhost"]
    allow_methods = ["*"]
    allow_headers = ["*"]
    allow_credentials = True
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_methods=allow_methods,
        allow_headers=allow_headers,
        allow_credentials=allow_credentials,
    )


def _resolve_license_backend(
    settings: Settings,
) -> str:
    """Resolve the license backend service URL.

    Args:
        settings: Validated application settings.

    Returns:
        The base URL of the license backend service.
    """
    backend_url = resolve_backend_url(
        service_name="license",
        settings=settings,
    )
    return backend_url


def _resolve_session_backend(
    settings: Settings,
) -> str:
    """Resolve the session backend service URL.

    Args:
        settings: Validated application settings.

    Returns:
        The base URL of the session backend service.
    """
    backend_url = resolve_backend_url(
        service_name="session",
        settings=settings,
    )
    return backend_url


def _resolve_security_backend(
    settings: Settings,
) -> str:
    """Resolve the security backend service URL.

    Args:
        settings: Validated application settings.

    Returns:
        The base URL of the security backend service.
    """
    backend_url = resolve_backend_url(
        service_name="security",
        settings=settings,
    )
    return backend_url


def _resolve_integrity_backend(
    settings: Settings,
) -> str:
    """Resolve the integrity backend service URL.

    Args:
        settings: Validated application settings.

    Returns:
        The base URL of the integrity backend service.
    """
    backend_url = resolve_backend_url(
        service_name="integrity",
        settings=settings,
    )
    return backend_url


def _resolve_admin_backend(
    settings: Settings,
) -> str:
    """Resolve the admin backend service URL.

    Args:
        settings: Validated application settings.

    Returns:
        The base URL of the admin backend service.
    """
    backend_url = resolve_backend_url(
        service_name="admin",
        settings=settings,
    )
    return backend_url


def _create_activate_token(
    settings: Settings,
    request: Request,
) -> str:
    """Create a service token for the license activate route.

    No client context is embedded because activate is an entry point that does
    not require prior client authentication.

    Args:
        settings: Validated application settings.
        request: The incoming client request.

    Returns:
        An encoded service token scoped to license:activate.
    """
    path = request.url.path
    scope = _scope_for_path(path)
    service_token = make_service_token(
        client_context=None,
        settings=settings,
        scope=scope,
    )
    return service_token


def _create_license_status_token(
    settings: Settings,
    context: SessionContext,
    request: Request,
) -> str:
    """Create a service token for the license status route.

    Embeds the client session id and license id from the validated client
    context.

    Args:
        settings: Validated application settings.
        context: The validated client session context.
        request: The incoming client request.

    Returns:
        An encoded service token scoped to license:read.
    """
    session_id = context.session_id
    license_id = context.license.id
    client_context = (session_id, license_id)
    path = request.url.path
    scope = _scope_for_path(path)
    service_token = make_service_token(
        client_context=client_context,
        settings=settings,
        scope=scope,
    )
    return service_token


def _create_session_token(
    settings: Settings,
    context: SessionContext,
    request: Request,
) -> str:
    """Create a service token for session routes.

    Embeds the client session id and license id from the validated client
    context.

    Args:
        settings: Validated application settings.
        context: The validated client session context.
        request: The incoming client request.

    Returns:
        An encoded service token scoped according to the request path.
    """
    session_id = context.session_id
    license_id = context.license.id
    client_context = (session_id, license_id)
    path = request.url.path
    scope = _scope_for_path(path)
    service_token = make_service_token(
        client_context=client_context,
        settings=settings,
        scope=scope,
    )
    return service_token


def _create_security_token(
    settings: Settings,
    context: SessionContext,
    request: Request,
) -> str:
    """Create a service token for security routes.

    Embeds the client session id and license id from the validated client
    context.

    Args:
        settings: Validated application settings.
        context: The validated client session context.
        request: The incoming client request.

    Returns:
        An encoded service token scoped according to the request path.
    """
    session_id = context.session_id
    license_id = context.license.id
    client_context = (session_id, license_id)
    path = request.url.path
    scope = _scope_for_path(path)
    service_token = make_service_token(
        client_context=client_context,
        settings=settings,
        scope=scope,
    )
    return service_token


def _create_integrity_token(
    settings: Settings,
    context: SessionContext,
    request: Request,
) -> str:
    """Create a service token for integrity routes.

    Embeds the client session id and license id from the validated client
    context.

    Args:
        settings: Validated application settings.
        context: The validated client session context.
        request: The incoming client request.

    Returns:
        An encoded service token scoped according to the request path.
    """
    session_id = context.session_id
    license_id = context.license.id
    client_context = (session_id, license_id)
    path = request.url.path
    scope = _scope_for_path(path)
    service_token = make_service_token(
        client_context=client_context,
        settings=settings,
        scope=scope,
    )
    return service_token


def _create_admin_proxy_token(
    settings: Settings,
    admin: Any,
    full_path: str,
) -> str:
    """Create a service token for admin proxy routes.

    Embeds an admin-derived session id and a zero license id into the token.

    Args:
        settings: Validated application settings.
        admin: The authenticated admin row object.
        full_path: The full request path used to determine the scope.

    Returns:
        An encoded service token scoped according to the admin path.
    """
    admin_id = admin.id
    scope = _scope_for_path(full_path)
    service_token = make_admin_service_token(
        admin_id=admin_id,
        settings=settings,
        scope=scope,
    )
    return service_token


async def _proxy_activate_request(
    request: Request,
    backend_url: str,
    service_token: str,
) -> Response:
    """Proxy the license activate request to the backend.

    Args:
        request: The incoming client request.
        backend_url: The license backend base URL.
        service_token: The service token for backend authorization.

    Returns:
        The backend response forwarded to the client.
    """
    proxy_response = await _proxy_request(
        request=request,
        backend_url=backend_url,
        service_token=service_token,
    )
    return proxy_response


async def _proxy_license_status_request(
    request: Request,
    backend_url: str,
    service_token: str,
) -> Response:
    """Proxy the license status request to the backend.

    Args:
        request: The incoming client request.
        backend_url: The license backend base URL.
        service_token: The service token for backend authorization.

    Returns:
        The backend response forwarded to the client.
    """
    proxy_response = await _proxy_request(
        request=request,
        backend_url=backend_url,
        service_token=service_token,
    )
    return proxy_response


async def _proxy_session_request(
    request: Request,
    backend_url: str,
    service_token: str,
) -> Response:
    """Proxy a session request to the backend.

    Args:
        request: The incoming client request.
        backend_url: The session backend base URL.
        service_token: The service token for backend authorization.

    Returns:
        The backend response forwarded to the client.
    """
    proxy_response = await _proxy_request(
        request=request,
        backend_url=backend_url,
        service_token=service_token,
    )
    return proxy_response


async def _proxy_security_request(
    request: Request,
    backend_url: str,
    service_token: str,
) -> Response:
    """Proxy a security request to the backend.

    Args:
        request: The incoming client request.
        backend_url: The security backend base URL.
        service_token: The service token for backend authorization.

    Returns:
        The backend response forwarded to the client.
    """
    proxy_response = await _proxy_request(
        request=request,
        backend_url=backend_url,
        service_token=service_token,
    )
    return proxy_response


async def _proxy_integrity_request(
    request: Request,
    backend_url: str,
    service_token: str,
) -> Response:
    """Proxy an integrity request to the backend.

    Args:
        request: The incoming client request.
        backend_url: The integrity backend base URL.
        service_token: The service token for backend authorization.

    Returns:
        The backend response forwarded to the client.
    """
    proxy_response = await _proxy_request(
        request=request,
        backend_url=backend_url,
        service_token=service_token,
    )
    return proxy_response


async def _proxy_admin_request(
    request: Request,
    backend_url: str,
    service_token: str,
) -> Response:
    """Proxy an admin request to the backend.

    Args:
        request: The incoming client request.
        backend_url: The admin backend base URL.
        service_token: The service token for backend authorization.

    Returns:
        The backend response forwarded to the client.
    """
    proxy_response = await _proxy_request(
        request=request,
        backend_url=backend_url,
        service_token=service_token,
    )
    return proxy_response


def _return_response(proxy_response: Response) -> Response:
    """Return the proxied response to the client.

    Thin wrapper that makes the final return step of a route handler an
    explicit, single-purpose function.

    Args:
        proxy_response: The response received from the backend.

    Returns:
        The same response to be sent to the client.
    """
    return proxy_response


def add_routes_for_each_group(
    app: FastAPI,
    settings: Settings,
) -> None:
    """Register all route handlers on the application.

    Adds the health endpoint and route handlers for each functional group:
    license, session, security, integrity, and admin routes. Each route
    handler follows the resolve_backend -> create_token -> proxy ->
    return_response pattern.

    Args:
        app: The FastAPI application instance.
        settings: Validated application settings.
    """

    # Health endpoint - direct response, no proxy.
    @app.get("/health", response_model=SuccessResponse)
    async def health() -> SuccessResponse:
        """Return a health check success response."""
        return success({"status": "ok"})

    # ===== LICENSE ROUTES =====

    @app.post("/v1/licenses/activate")
    async def activate(
        payload: ActivateRequest,
        request: Request,
        session: DbSession,
        settings_param: Settings = _settings_dep,
    ) -> Response:
        """Activate a license - no client auth required (entry point).

        Resolves the license backend URL, creates a service token without
        client context, proxies the request, and returns the response.
        """
        backend_url = _resolve_license_backend(settings=settings_param)
        service_token = _create_activate_token(
            settings=settings_param,
            request=request,
        )
        proxy_response = await _proxy_activate_request(
            request=request,
            backend_url=backend_url,
            service_token=service_token,
        )
        return _return_response(proxy_response)

    @app.get("/v1/licenses/status")
    async def license_status(
        request: Request,
        context: SessionContext = _client_dep,
        settings_param: Settings = _settings_dep,
    ) -> Response:
        """Proxy license status request to the license backend.

        Resolves the license backend URL, creates a service token embedding
        client context, proxies the request, and returns the response.
        """
        backend_url = _resolve_license_backend(settings=settings_param)
        service_token = _create_license_status_token(
            settings=settings_param,
            context=context,
            request=request,
        )
        proxy_response = await _proxy_license_status_request(
            request=request,
            backend_url=backend_url,
            service_token=service_token,
        )
        return _return_response(proxy_response)

    # ===== SESSION ROUTES =====

    @app.post("/v1/sessions/validate")
    async def validate_session(
        payload: ValidateRequest,
        request: Request,
        context: SessionContext = _client_dep,
        settings_param: Settings = _settings_dep,
    ) -> Response:
        """Proxy session validate request to the session backend.

        Resolves the session backend URL, creates a service token embedding
        client context, proxies the request, and returns the response.
        """
        backend_url = _resolve_session_backend(settings=settings_param)
        service_token = _create_session_token(
            settings=settings_param,
            context=context,
            request=request,
        )
        proxy_response = await _proxy_session_request(
            request=request,
            backend_url=backend_url,
            service_token=service_token,
        )
        return _return_response(proxy_response)

    @app.post("/v1/sessions/logout")
    async def logout_session(
        request: Request,
        context: SessionContext = _client_dep,
        settings_param: Settings = _settings_dep,
    ) -> Response:
        """Proxy session logout request to the session backend.

        Resolves the session backend URL, creates a service token embedding
        client context, proxies the request, and returns the response.
        """
        backend_url = _resolve_session_backend(settings=settings_param)
        service_token = _create_session_token(
            settings=settings_param,
            context=context,
            request=request,
        )
        proxy_response = await _proxy_session_request(
            request=request,
            backend_url=backend_url,
            service_token=service_token,
        )
        return _return_response(proxy_response)

    # ===== SECURITY ROUTES =====

    @app.post("/v1/security/event")
    async def security_event(
        payload: SecurityEventSubmission,
        request: Request,
        context: SessionContext = _client_dep,
        settings_param: Settings = _settings_dep,
    ) -> Response:
        """Proxy security event request to the security backend.

        Resolves the security backend URL, creates a service token embedding
        client context, proxies the request, and returns the response.
        """
        backend_url = _resolve_security_backend(settings=settings_param)
        service_token = _create_security_token(
            settings=settings_param,
            context=context,
            request=request,
        )
        proxy_response = await _proxy_security_request(
            request=request,
            backend_url=backend_url,
            service_token=service_token,
        )
        return _return_response(proxy_response)

    @app.get("/v1/security/status")
    async def security_status(
        request: Request,
        context: SessionContext = _client_dep,
        settings_param: Settings = _settings_dep,
    ) -> Response:
        """Proxy security status request to the security backend.

        Resolves the security backend URL, creates a service token embedding
        client context, proxies the request, and returns the response.
        """
        backend_url = _resolve_security_backend(settings=settings_param)
        service_token = _create_security_token(
            settings=settings_param,
            context=context,
            request=request,
        )
        proxy_response = await _proxy_security_request(
            request=request,
            backend_url=backend_url,
            service_token=service_token,
        )
        return _return_response(proxy_response)

    # ===== INTEGRITY ROUTES =====

    @app.post("/v1/integrity/challenge")
    async def integrity_challenge(
        request: Request,
        context: SessionContext = _client_dep,
        settings_param: Settings = _settings_dep,
    ) -> Response:
        """Proxy integrity challenge request to the integrity backend.

        Resolves the integrity backend URL, creates a service token embedding
        client context, proxies the request, and returns the response.
        """
        backend_url = _resolve_integrity_backend(settings=settings_param)
        service_token = _create_integrity_token(
            settings=settings_param,
            context=context,
            request=request,
        )
        proxy_response = await _proxy_integrity_request(
            request=request,
            backend_url=backend_url,
            service_token=service_token,
        )
        return _return_response(proxy_response)

    @app.post("/v1/integrity/check")
    async def integrity_check(
        payload: IntegrityManifestSubmission,
        request: Request,
        context: SessionContext = _client_dep,
        settings_param: Settings = _settings_dep,
    ) -> Response:
        """Proxy integrity check request to the integrity backend.

        Resolves the integrity backend URL, creates a service token embedding
        client context, proxies the request, and returns the response.
        """
        backend_url = _resolve_integrity_backend(settings=settings_param)
        service_token = _create_integrity_token(
            settings=settings_param,
            context=context,
            request=request,
        )
        proxy_response = await _proxy_integrity_request(
            request=request,
            backend_url=backend_url,
            service_token=service_token,
        )
        return _return_response(proxy_response)

    # ===== ADMIN ROUTES =====

    @app.post("/v1/admin/login", response_model=SuccessResponse)
    async def admin_login(
        payload: AdminLoginRequest,
        request: Request,
        session: DbSession,
        settings_param: Settings = _settings_dep,
    ) -> SuccessResponse:
        """Admin login - returns admin token directly, no proxy needed.

        Authenticates the admin using username and password, extracts client
        IP and user agent from the request, builds a success response payload
        containing the session token and metadata, and returns it directly.
        """
        ip = client_ip(request)
        user_agent = client_user_agent(request)
        token = auth_svc.authenticate_admin(
            session=session,
            username=payload.username,
            password=payload.password,
            settings=settings_param,
            ip=ip,
            user_agent=user_agent,
        )
        session_token = token.token
        expires_at_iso = token.expires_at.isoformat()
        expires_at_epoch = int(token.expires_at.timestamp())
        username = token.admin.username
        is_superuser = bool(token.admin.is_superuser)
        data = {
            "session_token": session_token,
            "expires_at": expires_at_iso,
            "exp": expires_at_epoch,
            "username": username,
            "is_superuser": is_superuser,
        }
        return success(data)

    @app.api_route(
        "/v1/admin/{path:path}",
        methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    )
    async def admin_proxy(
        path: str,
        request: Request,
        admin: Any = _admin_auth_dep,
        settings_param: Settings = _settings_dep,
    ) -> Response:
        """Proxy all other admin routes to admin backend.

        Resolves the admin backend URL, constructs the full path, creates an
        admin service token, proxies the request, and returns the response.
        """
        backend_url = _resolve_admin_backend(settings=settings_param)
        path_prefix = "/v1/admin/"
        full_path = f"{path_prefix}{path}"
        service_token = _create_admin_proxy_token(
            settings=settings_param,
            admin=admin,
            full_path=full_path,
        )
        proxy_response = await _proxy_admin_request(
            request=request,
            backend_url=backend_url,
            service_token=service_token,
        )
        return _return_response(proxy_response)


def create_gateway_app(
    settings: Settings | None = None,
) -> FastAPI:
    """Create the gateway FastAPI application.

    Orchestrates application construction by composing single-purpose setup
    functions: validating settings, configuring the database, setting up the
    lifespan, creating the app, adding CORS middleware, and registering all
    route handlers.

    Args:
        settings: Optional pre-built settings instance. When None, settings
            are loaded from the environment.

    Returns:
        The fully configured FastAPI application instance.
    """
    validated_settings = validate_settings(settings)
    configure_db(settings=validated_settings)
    lifespan = setup_lifespan
    app = create_app(
        settings=validated_settings,
        lifespan=lifespan,
    )
    add_cors(app)
    add_routes_for_each_group(
        app=app,
        settings=validated_settings,
    )
    return app
