"""
Application settings, sourced exclusively from the environment.

Configuration philosophy
------------------------

This module defines the :class:`Settings` pydantic model, which is the single
source of truth for all runtime configuration of the license server. Every
setting is sourced from the environment (via a ``.env`` file or actual
environment variables). There are no implicit secrets: security-sensitive
values such as the JWT secret and the cryptographic peppers have no defaults,
so a misconfigured deployment fails loudly at startup instead of silently
falling back to a guessable value.

The design goals are:

* Defence in depth.  :meth:`Settings.validate_runtime` performs additional
  runtime checks (secret length, pepper distinctness) beyond the static
  pydantic field constraints.
* Fail-fast validation.  Invalid values raise :class:`ValueError` during
  model construction, before the application ever starts serving requests.
* Secret handling.  Sensitive values use :class:`pydantic.SecretStr` so their
  plaintext is not accidentally logged or serialized.
* Single cached accessor.  :func:`get_settings` returns a process-wide cached
  :class:`Settings` instance via :func:`functools.lru_cache`, so configuration
  is parsed exactly once per process.

Field groups
~~~~~~~~~~~~

Database configuration
    ``DATABASE_URL`` — connection string (defaults to a local SQLite file).

Server configuration
    ``SERVER_HOST`` and ``SERVER_PORT`` — bind address and port for the API.

JWT configuration
    ``LICENSE_JWT_SECRET``, ``JWT_ALGORITHM``, ``JWT_ISSUER``,
    ``JWT_AUDIENCE`` — signing secret and token claims.

Session configuration
    ``SESSION_TTL_SECONDS`` and ``ADMIN_SESSION_TTL_SECONDS`` — session
    lifetimes in seconds.

Pepper configuration
    ``LICENSE_KEY_PEPPER``, ``HWID_PEPPER``, ``INTEGRITY_PEPPER`` —
    cryptographic peppers used for HMAC operations.

Admin credentials
    ``ADMIN_USERNAME`` and ``ADMIN_PASSWORD`` — optional admin account.

Rate limiting
    ``RATE_LIMIT_*`` fields — per-endpoint request limits.

CORS configuration
    ``CORS_ALLOWED_ORIGINS`` — allowed cross-origin origins (JSON array or
    comma-separated list).

Maintenance and logging
    ``MAINTENANCE_MODE``, ``LOG_LEVEL``, ``MAX_REQUEST_BODY_BYTES``.

Bcrypt configuration
    ``BCRYPT_TIME_COST``, ``BCRYPT_MEMORY_COST``, ``BCRYPT_PARALLELISM``.

KeyAuth configuration
    ``KEYAUTH_ENABLED``, ``KEYAUTH_OWNER_ID``, ``KEYAUTH_APP_SECRET``,
    ``KEYAUTH_APP_NAME`` — optional KeyAuth integration.

Multi-service architecture
    ``SERVICE_MODE``, ``SERVICE_REGISTRY_PATH``, ``SERVICE_TOKEN_TTL_SECONDS``,
    service host, gateway port, and per-service port ranges.

Trust headers
    ``TRUST_X_FORWARDED_FOR`` — whether to trust ``X-Forwarded-For``.

Database connection pool
    ``DB_POOL_*`` — pool settings for non-SQLite databases.

Anti-tampering configuration
    ``ANTI_TAMPER_*`` — enforcement mode, thresholds, retention, client build
    enforcement, nonce TTL, and clock skew tolerance.

Usage
-----

Load the settings once::

    from app.config import get_settings
    settings = get_settings()
    settings.validate_runtime()

Access secrets through their accessor properties rather than reading the raw
``SecretStr`` fields directly, to keep plaintext handling explicit and
auditable.
"""

import json
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# Minimum allowed length, in characters, for the LICENSE_JWT_SECRET value.
# A short JWT secret is weak and trivially brute-forced, so deployments must
# provide a sufficiently long secret. This constant is referenced by both the
# pydantic Field constraint and the runtime validation logic.
MIN_JWT_SECRET_LENGTH = 32

# Minimum allowed length, in characters, for every cryptographic pepper.
# Peppers are HMAC keys; short peppers weaken the derived values they protect.
MIN_PEPPER_LENGTH = 16

# The only supported JWT signing algorithm. Restricting this to HS256 prevents
# algorithm confusion attacks (for example, switching to "none" or RS256).
_ALGORITHMS: tuple[Literal["HS256"], ...] = ("HS256",)

# The standard logging level names accepted by LOG_LEVEL. Using a frozenset
# makes membership tests O(1) and signals that the collection is constant.
VALID_LOG_LEVELS: frozenset[str] = frozenset(
    {
        "CRITICAL",
        "ERROR",
        "WARNING",
        "INFO",
        "DEBUG",
        "NOTSET",
    }
)

# The allowed anti-tamper enforcement modes. "monitor" observes violations
# without blocking, "restrict" applies restrictions, and "enforce" blocks.
ENFORCEMENT_MODE_ALLOWED: frozenset[str] = frozenset(
    {
        "monitor",
        "restrict",
        "enforce",
    }
)

# The allowed service mode values. Each mode runs a different subset of the
# license server's capabilities. "monolith" runs everything in one process.
SERVICE_MODE_ALLOWED: frozenset[str] = frozenset(
    {
        "gateway",
        "license",
        "session",
        "security",
        "integrity",
        "admin",
        "monolith",
    }
)

# ---------------------------------------------------------------------------
# Module-level helper functions (single-purpose validation, error building,
# normalization, and runtime checking). Keeping these at module scope lets the
# Settings classmethods call them by name without scoping issues.
# ---------------------------------------------------------------------------


def build_client_build_empty_error(field_name: str) -> str:
    """Build the error message for an empty client build value.

    Parameters
    ----------
    field_name : str
        The name of the field being validated, included in the message so
        operators can identify the offending environment variable.

    Returns
    -------
    str
        The formatted error message.
    """
    error_message = f"{field_name} must not be empty"
    return error_message


def is_client_build_value_empty(value: str) -> bool:
    """Return True when the client build value is empty after stripping.

    Parameters
    ----------
    value : str
        The raw client build string supplied via the environment.

    Returns
    -------
    bool
        True if the stripped value has zero length, False otherwise.
    """
    stripped = value.strip()
    is_empty = not stripped
    return is_empty


def is_origin_value_a_string(value: object) -> bool:
    """Return True when the origin value is a string instance.

    Non-string values (for example lists already parsed by pydantic) are
    returned unchanged by the validator, so this helper isolates the type
    check.

    Parameters
    ----------
    value : object
        The raw value read from the environment.

    Returns
    -------
    bool
        True if value is an instance of str.
    """
    return isinstance(value, str)


def strip_origin_raw_value(value: str) -> str:
    """Strip surrounding whitespace from a raw origin string.

    Parameters
    ----------
    value : str
        The raw origin string.

    Returns
    -------
    str
        The stripped string.
    """
    raw = value.strip()
    return raw


def is_origin_raw_value_empty(raw: str) -> bool:
    """Return True when a raw origin string is empty after stripping.

    Parameters
    ----------
    raw : str
        The stripped origin string.

    Returns
    -------
    bool
        True if the string has zero length.
    """
    return not raw


def build_origins_empty_default() -> list[str]:
    """Build the default empty origins list for blank input.

    Returns
    -------
    list[str]
        A new empty list.
    """
    return []


def is_origin_raw_value_a_json_array(raw: str) -> bool:
    """Return True when a raw origin string looks like a JSON array.

    Parameters
    ----------
    raw : str
        The stripped origin string.

    Returns
    -------
    bool
        True if the string starts with "[".
    """
    return raw.startswith("[")


def parse_origin_json_array(raw: str) -> list[str]:
    """Parse a JSON array string into a list of origin strings.

    Parameters
    ----------
    raw : str
        A JSON-encoded array of origin strings.

    Returns
    -------
    list[str]
        The parsed list of origins.
    """
    parsed = json.loads(raw)
    return parsed


def split_origin_comma_list(raw: str) -> list[str]:
    """Split a comma-separated origin string into a cleaned list of origins.

    Each segment is stripped and empty segments are discarded.

    Parameters
    ----------
    raw : str
        A comma-separated list of origin strings.

    Returns
    -------
    list[str]
        The cleaned list of origins.
    """
    split_parts = raw.split(",")
    cleaned = [origin.strip() for origin in split_parts if origin.strip()]
    return cleaned


def strip_log_level_value(value: str) -> str:
    """Strip surrounding whitespace from a log level string.

    Parameters
    ----------
    value : str
        The raw log level string.

    Returns
    -------
    str
        The stripped string.
    """
    stripped = value.strip()
    return stripped


def upper_log_level_value(value: str) -> str:
    """Uppercase a log level string for case-insensitive comparison.

    Parameters
    ----------
    value : str
        The log level string (already stripped).

    Returns
    -------
    str
        The uppercased string.
    """
    uppercased = value.upper()
    return uppercased


def is_log_level_valid(level: str) -> bool:
    """Return True when a log level is one of the standard logging names.

    Parameters
    ----------
    level : str
        The stripped, uppercased log level.

    Returns
    -------
    bool
        True if level is a member of VALID_LOG_LEVELS.
    """
    return level in VALID_LOG_LEVELS


def build_log_level_invalid_error() -> str:
    """Build the error message for an invalid log level.

    Returns
    -------
    str
        The error message.
    """
    return "LOG_LEVEL must be a standard logging level name"


def is_positive_integer(value: int) -> bool:
    """Return True when an integer is strictly greater than zero.

    Parameters
    ----------
    value : int
        The integer to check.

    Returns
    -------
    bool
        True if value > 0.
    """
    return value > 0


def build_non_positive_error(field_name: str) -> str:
    """Build the error message for a non-positive integer value.

    Parameters
    ----------
    field_name : str
        The name of the field being validated.

    Returns
    -------
    str
        The error message.
    """
    return "must be greater than zero"


def is_enforcement_mode_allowed(value: str) -> bool:
    """Return True when an enforcement mode is one of the allowed values.

    Parameters
    ----------
    value : str
        The enforcement mode string.

    Returns
    -------
    bool
        True if value is in ENFORCEMENT_MODE_ALLOWED.
    """
    return value in ENFORCEMENT_MODE_ALLOWED


def sorted_enforcement_modes() -> list[str]:
    """Return the allowed enforcement modes in sorted order.

    Sorting produces a deterministic error message.

    Returns
    -------
    list[str]
        Sorted allowed enforcement modes.
    """
    return sorted(ENFORCEMENT_MODE_ALLOWED)


def build_enforcement_mode_invalid_error(allowed: list[str]) -> str:
    """Build the error message for an invalid enforcement mode.

    Parameters
    ----------
    allowed : list[str]
        The sorted list of allowed modes.

    Returns
    -------
    str
        The error message.
    """
    return f"ANTI_TAMPER_ENFORCEMENT_MODE must be one of {allowed}"


def is_service_mode_allowed(value: str) -> bool:
    """Return True when a service mode is one of the allowed values.

    Parameters
    ----------
    value : str
        The service mode string.

    Returns
    -------
    bool
        True if value is in SERVICE_MODE_ALLOWED.
    """
    return value in SERVICE_MODE_ALLOWED


def sorted_service_modes() -> list[str]:
    """Return the allowed service modes in sorted order.

    Returns
    -------
    list[str]
        Sorted allowed service modes.
    """
    return sorted(SERVICE_MODE_ALLOWED)


def build_service_mode_invalid_error(allowed: list[str]) -> str:
    """Build the error message for an invalid service mode.

    Parameters
    ----------
    allowed : list[str]
        The sorted list of allowed modes.

    Returns
    -------
    str
        The error message.
    """
    return f"SERVICE_MODE must be one of {allowed}"


def is_integer_non_negative(value: int) -> bool:
    """Return True when an integer is not negative (>= 0).

    Parameters
    ----------
    value : int
        The integer to check.

    Returns
    -------
    bool
        True if value >= 0.
    """
    return value >= 0


def build_non_negative_error(field_name: str) -> str:
    """Build the error message for a negative integer value.

    Parameters
    ----------
    field_name : str
        The name of the field being validated.

    Returns
    -------
    str
        The error message.
    """
    return "must not be negative"


def build_jwt_secret_empty_problem() -> str:
    """Build the problem message for an empty JWT secret.

    Returns
    -------
    str
        The problem message.
    """
    return "LICENSE_JWT_SECRET is empty"


def build_jwt_secret_too_short_problem(min_length: int) -> str:
    """Build the problem message for a JWT secret that is too short.

    Parameters
    ----------
    min_length : int
        The required minimum length.

    Returns
    -------
    str
        The problem message.
    """
    return f"LICENSE_JWT_SECRET must be at least {min_length} characters"


def check_jwt_secret(settings: "Settings") -> list[str]:
    """Check the JWT secret for emptiness and minimum length.

    Splits the original combined check into an explicit if/else: an empty
    secret reports the empty problem; otherwise the length is checked.

    Parameters
    ----------
    settings : Settings
        The settings instance to check.

    Returns
    -------
    list[str]
        A list of problem messages found for the JWT secret.
    """
    problems: list[str] = []
    jwt_secret = settings.jwt_secret
    is_empty = not jwt_secret
    if is_empty:
        problem = build_jwt_secret_empty_problem()
        problems.append(problem)
    else:
        secret_length = len(jwt_secret)
        is_too_short = secret_length < MIN_JWT_SECRET_LENGTH
        if is_too_short:
            problem = build_jwt_secret_too_short_problem(
                MIN_JWT_SECRET_LENGTH
            )
            problems.append(problem)
    return problems


def build_pepper_empty_problem(name: str) -> str:
    """Build the problem message for an empty pepper.

    Parameters
    ----------
    name : str
        The field name of the pepper.

    Returns
    -------
    str
        The problem message.
    """
    return f"{name} is empty"


def build_pepper_too_short_problem(name: str, min_length: int) -> str:
    """Build the problem message for a pepper that is too short.

    Parameters
    ----------
    name : str
        The field name of the pepper.
    min_length : int
        The required minimum length.

    Returns
    -------
    str
        The problem message.
    """
    return f"{name} must be at least {min_length} characters"


def check_peppers(settings: "Settings") -> list[str]:
    """Check all peppers for emptiness and minimum length.

    Parameters
    ----------
    settings : Settings
        The settings instance to check.

    Returns
    -------
    list[str]
        A list of problem messages found for the peppers.
    """
    problems: list[str] = []
    pepper_names = (
        "LICENSE_KEY_PEPPER",
        "HWID_PEPPER",
        "INTEGRITY_PEPPER",
    )
    for name in pepper_names:
        secret_field = getattr(settings, name)
        pepper_value = secret_field.get_secret_value()
        is_empty = not pepper_value
        if is_empty:
            problem = build_pepper_empty_problem(name)
            problems.append(problem)
        else:
            pepper_length = len(pepper_value)
            is_too_short = pepper_length < MIN_PEPPER_LENGTH
            if is_too_short:
                problem = build_pepper_too_short_problem(
                    name, MIN_PEPPER_LENGTH
                )
                problems.append(problem)
    return problems


def check_peppers_distinct(settings: "Settings") -> list[str]:
    """Check that the JWT secret differs from all peppers.

    Parameters
    ----------
    settings : Settings
        The settings instance to check.

    Returns
    -------
    list[str]
        A list of problem messages (empty when the JWT secret differs from
        every pepper or is not set).
    """
    problems: list[str] = []
    jwt_secret = settings.jwt_secret
    license_key_pepper = settings.license_key_pepper
    hwid_pepper = settings.hwid_pepper
    integrity_pepper = settings.integrity_pepper

    jwt_secret_is_set = bool(jwt_secret)
    if jwt_secret_is_set:
        peppers = {
            license_key_pepper,
            hwid_pepper,
            integrity_pepper,
        }
        jwt_secret_matches_pepper = jwt_secret in peppers
        if jwt_secret_matches_pepper:
            problem = "LICENSE_JWT_SECRET must differ from the peppers"
            problems.append(problem)
    return problems


def check_all_problems(settings: "Settings") -> list[str]:
    """Run every runtime check and collect all problems found.

    Parameters
    ----------
    settings : Settings
        The settings instance to check.

    Returns
    -------
    list[str]
        The combined list of problems from all checks.
    """
    problems: list[str] = []
    jwt_problems = check_jwt_secret(settings)
    for problem in jwt_problems:
        problems.append(problem)
    pepper_problems = check_peppers(settings)
    for problem in pepper_problems:
        problems.append(problem)
    distinct_problems = check_peppers_distinct(settings)
    for problem in distinct_problems:
        problems.append(problem)
    return problems


def build_runtime_error_message(problems: list[str]) -> str:
    """Build the final RuntimeError message from a list of problems.

    Parameters
    ----------
    problems : list[str]
        The collected problem messages.

    Returns
    -------
    str
        The formatted error message.
    """
    joined = "; ".join(problems)
    message = "insecure configuration: " + joined
    return message


def raise_if_problems(problems: list[str]) -> None:
    """Raise a RuntimeError when any problems are present.

    Parameters
    ----------
    problems : list[str]
        The collected problem messages.

    Raises
    ------
    RuntimeError
        When the problems list is non-empty.
    """
    has_problems = len(problems) > 0
    if has_problems:
        message = build_runtime_error_message(problems)
        raise RuntimeError(message)


def collect_port_ranges(settings: "Settings") -> tuple[tuple[int, int], ...]:
    """Collect every service port range as (start, end) pairs.

    Parameters
    ----------
    settings : Settings
        The settings instance.

    Returns
    -------
    tuple[tuple[int, int], ...]
        A tuple of (start, end) port range pairs.
    """
    license_range = (
        settings.LICENSE_PORT_RANGE_START,
        settings.LICENSE_PORT_RANGE_END,
    )
    session_range = (
        settings.SESSION_PORT_RANGE_START,
        settings.SESSION_PORT_RANGE_END,
    )
    security_range = (
        settings.SECURITY_PORT_RANGE_START,
        settings.SECURITY_PORT_RANGE_END,
    )
    integrity_range = (
        settings.INTEGRITY_PORT_RANGE_START,
        settings.INTEGRITY_PORT_RANGE_END,
    )
    admin_range = (
        settings.ADMIN_PORT_RANGE_START,
        settings.ADMIN_PORT_RANGE_END,
    )
    ranges = (
        license_range,
        session_range,
        security_range,
        integrity_range,
        admin_range,
    )
    return ranges


def build_port_range_error(start: int, end: int) -> str:
    """Build the error message for a port range where start exceeds end.

    Parameters
    ----------
    start : int
        The range start.
    end : int
        The range end.

    Returns
    -------
    str
        The error message.
    """
    return f"port range start {start} must not exceed end {end}"


def validate_port_ranges(ranges: tuple[tuple[int, int], ...]) -> None:
    """Validate that every port range start does not exceed its end.

    Parameters
    ----------
    ranges : tuple[tuple[int, int], ...]
        The (start, end) port range pairs.

    Raises
    ------
    ValueError
        When any start is greater than its corresponding end.
    """
    for start, end in ranges:
        start_exceeds_end = start > end
        if start_exceeds_end:
            error_message = build_port_range_error(start, end)
            raise ValueError(error_message)


class Settings(BaseSettings):
    """Runtime configuration for the license server.

    Field groups (in declaration order):

    Database configuration
        DATABASE_URL

    Server configuration
        SERVER_HOST, SERVER_PORT

    JWT configuration
        LICENSE_JWT_SECRET, JWT_ALGORITHM, JWT_ISSUER, JWT_AUDIENCE

    Session configuration
        SESSION_TTL_SECONDS, ADMIN_SESSION_TTL_SECONDS

    Pepper configuration
        LICENSE_KEY_PEPPER, HWID_PEPPER, INTEGRITY_PEPPER

    Admin credentials
        ADMIN_USERNAME, ADMIN_PASSWORD

    Rate limiting
        RATE_LIMIT_AUTH_PER_MINUTE, RATE_LIMIT_ADMIN_LOGIN_PER_MINUTE,
        RATE_LIMIT_ADMIN_API_PER_MINUTE, RATE_LIMIT_KEYGEN_PER_MINUTE,
        RATE_LIMIT_KEYAUTH_PER_MINUTE, RATE_LIMIT_SECURITY_EVENT_PER_MINUTE,
        RATE_LIMIT_INTEGRITY_PER_MINUTE

    CORS configuration
        CORS_ALLOWED_ORIGINS

    Maintenance and logging
        MAINTENANCE_MODE, LOG_LEVEL, MAX_REQUEST_BODY_BYTES

    Bcrypt configuration
        BCRYPT_TIME_COST, BCRYPT_MEMORY_COST, BCRYPT_PARALLELISM

    KeyAuth configuration
        KEYAUTH_ENABLED, KEYAUTH_OWNER_ID, KEYAUTH_APP_SECRET,
        KEYAUTH_APP_NAME

    Multi-service architecture
        SERVICE_MODE, SERVICE_REGISTRY_PATH, SERVICE_TOKEN_TTL_SECONDS,
        SERVICE_HOST, GATEWAY_PORT, LICENSE_PORT_RANGE_START/END,
        SESSION_PORT_RANGE_START/END, SECURITY_PORT_RANGE_START/END,
        INTEGRITY_PORT_RANGE_START/END, ADMIN_PORT_RANGE_START/END

    Trust headers
        TRUST_X_FORWARDED_FOR

    Database connection pool
        DB_POOL_SIZE, DB_MAX_OVERFLOW, DB_POOL_TIMEOUT, DB_POOL_RECYCLE

    Anti-tampering configuration
        ANTI_TAMPER_ENABLED, ANTI_TAMPER_ENFORCEMENT_MODE,
        ANTI_TAMPER_AUTO_RESTRICT_THRESHOLD, ANTI_TAMPER_BAN_THRESHOLD,
        ANTI_TAMPER_RESTRICTION_HOURS, ANTI_TAMPER_RETENTION_DAYS,
        ANTI_TAMPER_MIN_CLIENT_BUILD, ANTI_TAMPER_REQUIRE_CLIENT_BUILD,
        ANTI_TAMPER_NONCE_TTL_SECONDS, ANTI_TAMPER_MAX_CLOCK_SKEW_SECONDS
    """

    model_config = SettingsConfigDict(
        env_file=(".env", "../../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ------------------------------------------------------------------
    # Database configuration
    # ------------------------------------------------------------------

    DATABASE_URL: str = "sqlite:///./license.db"

    # ------------------------------------------------------------------
    # Server configuration
    # ------------------------------------------------------------------

    SERVER_HOST: str = "127.0.0.1"
    SERVER_PORT: int = 8080

    # ------------------------------------------------------------------
    # JWT configuration
    # ------------------------------------------------------------------

    LICENSE_JWT_SECRET: SecretStr = Field(min_length=MIN_JWT_SECRET_LENGTH)
    JWT_ALGORITHM: Literal["HS256"] = "HS256"
    JWT_ISSUER: str = "roblox-license-server"
    JWT_AUDIENCE: str = "roblox-license-client"

    # ------------------------------------------------------------------
    # Session configuration
    # ------------------------------------------------------------------

    SESSION_TTL_SECONDS: int = 900
    ADMIN_SESSION_TTL_SECONDS: int = 1800

    # ------------------------------------------------------------------
    # Pepper configuration
    # ------------------------------------------------------------------

    LICENSE_KEY_PEPPER: SecretStr = Field(min_length=MIN_PEPPER_LENGTH)
    HWID_PEPPER: SecretStr = Field(min_length=MIN_PEPPER_LENGTH)
    INTEGRITY_PEPPER: SecretStr = Field(min_length=MIN_PEPPER_LENGTH)

    # ------------------------------------------------------------------
    # Admin credentials
    # ------------------------------------------------------------------

    ADMIN_USERNAME: str | None = None
    ADMIN_PASSWORD: SecretStr | None = None

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_AUTH_PER_MINUTE: int = 10
    RATE_LIMIT_ADMIN_LOGIN_PER_MINUTE: int = 5
    RATE_LIMIT_ADMIN_API_PER_MINUTE: int = 120
    RATE_LIMIT_KEYGEN_PER_MINUTE: int = 30
    RATE_LIMIT_KEYAUTH_PER_MINUTE: int = 15
    RATE_LIMIT_SECURITY_EVENT_PER_MINUTE: int = 10
    RATE_LIMIT_INTEGRITY_PER_MINUTE: int = 20

    # ------------------------------------------------------------------
    # CORS configuration
    # ------------------------------------------------------------------

    CORS_ALLOWED_ORIGINS: Annotated[list[str], NoDecode] = Field(
        default_factory=list
    )

    # ------------------------------------------------------------------
    # Maintenance and logging
    # ------------------------------------------------------------------

    MAINTENANCE_MODE: bool = False
    LOG_LEVEL: str = "INFO"
    MAX_REQUEST_BODY_BYTES: int = 16384

    # ------------------------------------------------------------------
    # Bcrypt configuration
    # ------------------------------------------------------------------

    BCRYPT_TIME_COST: int = 4
    BCRYPT_MEMORY_COST: int = 65536
    BCRYPT_PARALLELISM: int = 4

    # ------------------------------------------------------------------
    # KeyAuth configuration
    # ------------------------------------------------------------------

    KEYAUTH_ENABLED: bool = False
    KEYAUTH_OWNER_ID: str | None = None
    KEYAUTH_APP_SECRET: SecretStr | None = None
    KEYAUTH_APP_NAME: str | None = None

    # ------------------------------------------------------------------
    # Multi-service architecture
    # ------------------------------------------------------------------

    SERVICE_MODE: str = "gateway"
    SERVICE_REGISTRY_PATH: str = "runtime/services.json"
    SERVICE_TOKEN_TTL_SECONDS: int = 300
    SERVICE_HOST: str = "127.0.0.1"
    GATEWAY_PORT: int = 8080
    LICENSE_PORT_RANGE_START: int = 18000
    LICENSE_PORT_RANGE_END: int = 18999
    SESSION_PORT_RANGE_START: int = 19000
    SESSION_PORT_RANGE_END: int = 19999
    SECURITY_PORT_RANGE_START: int = 20000
    SECURITY_PORT_RANGE_END: int = 20999
    INTEGRITY_PORT_RANGE_START: int = 21000
    INTEGRITY_PORT_RANGE_END: int = 21999
    ADMIN_PORT_RANGE_START: int = 22000
    ADMIN_PORT_RANGE_END: int = 22999

    # ------------------------------------------------------------------
    # Trust headers
    # ------------------------------------------------------------------

    TRUST_X_FORWARDED_FOR: bool = False

    # ------------------------------------------------------------------
    # Database connection pool
    # ------------------------------------------------------------------

    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 1800

    # ------------------------------------------------------------------
    # Anti-tampering configuration
    # ------------------------------------------------------------------

    ANTI_TAMPER_ENABLED: bool = True
    ANTI_TAMPER_ENFORCEMENT_MODE: str = "monitor"
    ANTI_TAMPER_AUTO_RESTRICT_THRESHOLD: int = 5
    ANTI_TAMPER_BAN_THRESHOLD: int = 10
    ANTI_TAMPER_RESTRICTION_HOURS: int = 24
    ANTI_TAMPER_RETENTION_DAYS: int = 30
    ANTI_TAMPER_MIN_CLIENT_BUILD: str = "1.0.0"
    ANTI_TAMPER_REQUIRE_CLIENT_BUILD: bool = False
    ANTI_TAMPER_NONCE_TTL_SECONDS: int = 300
    ANTI_TAMPER_MAX_CLOCK_SKEW_SECONDS: int = 120

    # ------------------------------------------------------------------
    # Field validators: ANTI_TAMPER_MIN_CLIENT_BUILD
    # ------------------------------------------------------------------

    @field_validator("ANTI_TAMPER_MIN_CLIENT_BUILD")
    @classmethod
    def _non_empty_client_build(cls, value: str) -> str:
        """Validate that ANTI_TAMPER_MIN_CLIENT_BUILD is not empty.

        Splits the original combined check into: empty detection, error
        message building, and the validator itself. The value is returned
        unchanged (not stripped) to preserve the original behaviour.

        Parameters
        ----------
        cls : type[Settings]
            The model class (conventional pydantic classmethod parameter).
        value : str
            The raw client build string.

        Returns
        -------
        str
            The original value when it is non-empty.

        Raises
        ------
        ValueError
            When the value is empty or whitespace-only.
        """
        field_name = "ANTI_TAMPER_MIN_CLIENT_BUILD"
        is_empty = is_client_build_value_empty(value)
        if is_empty:
            error_message = build_client_build_empty_error(field_name)
            raise ValueError(error_message)
        return value

    # ------------------------------------------------------------------
    # Field validators: CORS_ALLOWED_ORIGINS
    # ------------------------------------------------------------------

    @field_validator("CORS_ALLOWED_ORIGINS", mode="before")
    @classmethod
    def _parse_origins(cls, value: object) -> object:
        """Accept a JSON array or a comma-separated list from the environment.

        Splits the original combined parser into: type check, stripping,
        emptiness check, JSON-array detection, JSON parsing, comma splitting,
        and the validator itself. Behaviour is identical to the original.

        Parameters
        ----------
        cls : type[Settings]
            The model class.
        value : object
            The raw environment value.

        Returns
        -------
        object
            The original value when it is not a string; an empty list for blank
            input; a parsed list for JSON arrays; or a cleaned list for
            comma-separated input.
        """
        is_string = is_origin_value_a_string(value)
        if not is_string:
            return value
        raw = strip_origin_raw_value(value)
        is_empty = is_origin_raw_value_empty(raw)
        if is_empty:
            empty_list = build_origins_empty_default()
            return empty_list
        is_json = is_origin_raw_value_a_json_array(raw)
        if is_json:
            parsed = parse_origin_json_array(raw)
            return parsed
        origins = split_origin_comma_list(raw)
        return origins

    # ------------------------------------------------------------------
    # Field validators: LOG_LEVEL
    # ------------------------------------------------------------------

    @field_validator("LOG_LEVEL")
    @classmethod
    def _normalize_log_level(cls, value: str) -> str:
        """Normalize and validate a LOG_LEVEL value.

        Splits the original into: stripping, uppercasing, validity check, error
        building, and the validator itself.

        Parameters
        ----------
        cls : type[Settings]
            The model class.
        value : str
            The raw log level string.

        Returns
        -------
        str
            The stripped, uppercased log level.

        Raises
        ------
        ValueError
            When the level is not a standard logging level name.
        """
        stripped = strip_log_level_value(value)
        uppercased = upper_log_level_value(stripped)
        is_valid = is_log_level_valid(uppercased)
        if not is_valid:
            error_message = build_log_level_invalid_error()
            raise ValueError(error_message)
        return uppercased

    # ------------------------------------------------------------------
    # Field validators: positive integer fields (split per field)
    # ------------------------------------------------------------------

    @field_validator("SERVER_PORT")
    @classmethod
    def _validate_server_port_positive(cls, value: int) -> int:
        """Validate that SERVER_PORT is greater than zero.

        Parameters
        ----------
        cls : type[Settings]
            The model class.
        value : int
            The configured server port.

        Returns
        -------
        int
            The value unchanged when valid.

        Raises
        ------
        ValueError
            When the value is not greater than zero.
        """
        is_positive = is_positive_integer(value)
        if not is_positive:
            error_message = build_non_positive_error("SERVER_PORT")
            raise ValueError(error_message)
        return value

    @field_validator("SESSION_TTL_SECONDS")
    @classmethod
    def _validate_session_ttl_positive(cls, value: int) -> int:
        """Validate that SESSION_TTL_SECONDS is greater than zero.

        Parameters
        ----------
        cls : type[Settings]
            The model class.
        value : int
            The configured session TTL.

        Returns
        -------
        int
            The value unchanged when valid.

        Raises
        ------
        ValueError
            When the value is not greater than zero.
        """
        is_positive = is_positive_integer(value)
        if not is_positive:
            error_message = build_non_positive_error("SESSION_TTL_SECONDS")
            raise ValueError(error_message)
        return value

    @field_validator("ADMIN_SESSION_TTL_SECONDS")
    @classmethod
    def _validate_admin_session_ttl_positive(cls, value: int) -> int:
        """Validate that ADMIN_SESSION_TTL_SECONDS is greater than zero.

        Parameters
        ----------
        cls : type[Settings]
            The model class.
        value : int
            The configured admin session TTL.

        Returns
        -------
        int
            The value unchanged when valid.

        Raises
        ------
        ValueError
            When the value is not greater than zero.
        """
        is_positive = is_positive_integer(value)
        if not is_positive:
            error_message = build_non_positive_error(
                "ADMIN_SESSION_TTL_SECONDS"
            )
            raise ValueError(error_message)
        return value

    # ------------------------------------------------------------------
    # Field validators: ANTI_TAMPER_ENFORCEMENT_MODE
    # ------------------------------------------------------------------

    @field_validator("ANTI_TAMPER_ENFORCEMENT_MODE")
    @classmethod
    def _enforcement_mode(cls, value: str) -> str:
        """Validate that ANTI_TAMPER_ENFORCEMENT_MODE is one of the allowed modes.

        Parameters
        ----------
        cls : type[Settings]
            The model class.
        value : str
            The configured enforcement mode.

        Returns
        -------
        str
            The value unchanged when valid.

        Raises
        ------
        ValueError
            When the value is not an allowed enforcement mode.
        """
        allowed = sorted_enforcement_modes()
        is_allowed = is_enforcement_mode_allowed(value)
        if not is_allowed:
            error_message = build_enforcement_mode_invalid_error(allowed)
            raise ValueError(error_message)
        return value

    # ------------------------------------------------------------------
    # Field validators: SERVICE_MODE
    # ------------------------------------------------------------------

    @field_validator("SERVICE_MODE")
    @classmethod
    def _service_mode(cls, value: str) -> str:
        """Validate that SERVICE_MODE is one of the allowed modes.

        Parameters
        ----------
        cls : type[Settings]
            The model class.
        value : str
            The configured service mode.

        Returns
        -------
        str
            The value unchanged when valid.

        Raises
        ------
        ValueError
            When the value is not an allowed service mode.
        """
        allowed = sorted_service_modes()
        is_allowed = is_service_mode_allowed(value)
        if not is_allowed:
            error_message = build_service_mode_invalid_error(allowed)
            raise ValueError(error_message)
        return value

    # ------------------------------------------------------------------
    # Field validators: non-negative integer fields (split per field)
    # ------------------------------------------------------------------

    @field_validator("MAX_REQUEST_BODY_BYTES")
    @classmethod
    def _validate_max_request_body_bytes_non_negative(cls, value: int) -> int:
        """Validate that MAX_REQUEST_BODY_BYTES is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error("MAX_REQUEST_BODY_BYTES")
            raise ValueError(error_message)
        return value

    @field_validator("RATE_LIMIT_AUTH_PER_MINUTE")
    @classmethod
    def _validate_rate_limit_auth_per_minute_non_negative(cls, value: int) -> int:
        """Validate that RATE_LIMIT_AUTH_PER_MINUTE is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error(
                "RATE_LIMIT_AUTH_PER_MINUTE"
            )
            raise ValueError(error_message)
        return value

    @field_validator("RATE_LIMIT_ADMIN_LOGIN_PER_MINUTE")
    @classmethod
    def _validate_rate_limit_admin_login_per_minute_non_negative(
        cls, value: int
    ) -> int:
        """Validate that RATE_LIMIT_ADMIN_LOGIN_PER_MINUTE is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error(
                "RATE_LIMIT_ADMIN_LOGIN_PER_MINUTE"
            )
            raise ValueError(error_message)
        return value

    @field_validator("RATE_LIMIT_ADMIN_API_PER_MINUTE")
    @classmethod
    def _validate_rate_limit_admin_api_per_minute_non_negative(
        cls, value: int
    ) -> int:
        """Validate that RATE_LIMIT_ADMIN_API_PER_MINUTE is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error(
                "RATE_LIMIT_ADMIN_API_PER_MINUTE"
            )
            raise ValueError(error_message)
        return value

    @field_validator("RATE_LIMIT_KEYGEN_PER_MINUTE")
    @classmethod
    def _validate_rate_limit_keygen_per_minute_non_negative(
        cls, value: int
    ) -> int:
        """Validate that RATE_LIMIT_KEYGEN_PER_MINUTE is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error(
                "RATE_LIMIT_KEYGEN_PER_MINUTE"
            )
            raise ValueError(error_message)
        return value

    @field_validator("BCRYPT_TIME_COST")
    @classmethod
    def _validate_bcrypt_time_cost_non_negative(cls, value: int) -> int:
        """Validate that BCRYPT_TIME_COST is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error("BCRYPT_TIME_COST")
            raise ValueError(error_message)
        return value

    @field_validator("BCRYPT_MEMORY_COST")
    @classmethod
    def _validate_bcrypt_memory_cost_non_negative(cls, value: int) -> int:
        """Validate that BCRYPT_MEMORY_COST is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error("BCRYPT_MEMORY_COST")
            raise ValueError(error_message)
        return value

    @field_validator("BCRYPT_PARALLELISM")
    @classmethod
    def _validate_bcrypt_parallelism_non_negative(cls, value: int) -> int:
        """Validate that BCRYPT_PARALLELISM is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error("BCRYPT_PARALLELISM")
            raise ValueError(error_message)
        return value

    @field_validator("ANTI_TAMPER_AUTO_RESTRICT_THRESHOLD")
    @classmethod
    def _validate_anti_tamper_auto_restrict_threshold_non_negative(
        cls, value: int
    ) -> int:
        """Validate that ANTI_TAMPER_AUTO_RESTRICT_THRESHOLD is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error(
                "ANTI_TAMPER_AUTO_RESTRICT_THRESHOLD"
            )
            raise ValueError(error_message)
        return value

    @field_validator("ANTI_TAMPER_BAN_THRESHOLD")
    @classmethod
    def _validate_anti_tamper_ban_threshold_non_negative(
        cls, value: int
    ) -> int:
        """Validate that ANTI_TAMPER_BAN_THRESHOLD is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error(
                "ANTI_TAMPER_BAN_THRESHOLD"
            )
            raise ValueError(error_message)
        return value

    @field_validator("ANTI_TAMPER_RESTRICTION_HOURS")
    @classmethod
    def _validate_anti_tamper_restriction_hours_non_negative(
        cls, value: int
    ) -> int:
        """Validate that ANTI_TAMPER_RESTRICTION_HOURS is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error(
                "ANTI_TAMPER_RESTRICTION_HOURS"
            )
            raise ValueError(error_message)
        return value

    @field_validator("ANTI_TAMPER_RETENTION_DAYS")
    @classmethod
    def _validate_anti_tamper_retention_days_non_negative(
        cls, value: int
    ) -> int:
        """Validate that ANTI_TAMPER_RETENTION_DAYS is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error(
                "ANTI_TAMPER_RETENTION_DAYS"
            )
            raise ValueError(error_message)
        return value

    @field_validator("ANTI_TAMPER_NONCE_TTL_SECONDS")
    @classmethod
    def _validate_anti_tamper_nonce_ttl_seconds_non_negative(
        cls, value: int
    ) -> int:
        """Validate that ANTI_TAMPER_NONCE_TTL_SECONDS is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error(
                "ANTI_TAMPER_NONCE_TTL_SECONDS"
            )
            raise ValueError(error_message)
        return value

    @field_validator("ANTI_TAMPER_MAX_CLOCK_SKEW_SECONDS")
    @classmethod
    def _validate_anti_tamper_max_clock_skew_seconds_non_negative(
        cls, value: int
    ) -> int:
        """Validate that ANTI_TAMPER_MAX_CLOCK_SKEW_SECONDS is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error(
                "ANTI_TAMPER_MAX_CLOCK_SKEW_SECONDS"
            )
            raise ValueError(error_message)
        return value

    @field_validator("RATE_LIMIT_KEYAUTH_PER_MINUTE")
    @classmethod
    def _validate_rate_limit_keyauth_per_minute_non_negative(
        cls, value: int
    ) -> int:
        """Validate that RATE_LIMIT_KEYAUTH_PER_MINUTE is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error(
                "RATE_LIMIT_KEYAUTH_PER_MINUTE"
            )
            raise ValueError(error_message)
        return value

    @field_validator("RATE_LIMIT_SECURITY_EVENT_PER_MINUTE")
    @classmethod
    def _validate_rate_limit_security_event_per_minute_non_negative(
        cls, value: int
    ) -> int:
        """Validate that RATE_LIMIT_SECURITY_EVENT_PER_MINUTE is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error(
                "RATE_LIMIT_SECURITY_EVENT_PER_MINUTE"
            )
            raise ValueError(error_message)
        return value

    @field_validator("RATE_LIMIT_INTEGRITY_PER_MINUTE")
    @classmethod
    def _validate_rate_limit_integrity_per_minute_non_negative(
        cls, value: int
    ) -> int:
        """Validate that RATE_LIMIT_INTEGRITY_PER_MINUTE is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error(
                "RATE_LIMIT_INTEGRITY_PER_MINUTE"
            )
            raise ValueError(error_message)
        return value

    @field_validator("GATEWAY_PORT")
    @classmethod
    def _validate_gateway_port_non_negative(cls, value: int) -> int:
        """Validate that GATEWAY_PORT is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error("GATEWAY_PORT")
            raise ValueError(error_message)
        return value

    @field_validator("LICENSE_PORT_RANGE_START")
    @classmethod
    def _validate_license_port_range_start_non_negative(cls, value: int) -> int:
        """Validate that LICENSE_PORT_RANGE_START is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error(
                "LICENSE_PORT_RANGE_START"
            )
            raise ValueError(error_message)
        return value

    @field_validator("LICENSE_PORT_RANGE_END")
    @classmethod
    def _validate_license_port_range_end_non_negative(cls, value: int) -> int:
        """Validate that LICENSE_PORT_RANGE_END is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error(
                "LICENSE_PORT_RANGE_END"
            )
            raise ValueError(error_message)
        return value

    @field_validator("SESSION_PORT_RANGE_START")
    @classmethod
    def _validate_session_port_range_start_non_negative(
        cls, value: int
    ) -> int:
        """Validate that SESSION_PORT_RANGE_START is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error(
                "SESSION_PORT_RANGE_START"
            )
            raise ValueError(error_message)
        return value

    @field_validator("SESSION_PORT_RANGE_END")
    @classmethod
    def _validate_session_port_range_end_non_negative(
        cls, value: int
    ) -> int:
        """Validate that SESSION_PORT_RANGE_END is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error(
                "SESSION_PORT_RANGE_END"
            )
            raise ValueError(error_message)
        return value

    @field_validator("SECURITY_PORT_RANGE_START")
    @classmethod
    def _validate_security_port_range_start_non_negative(
        cls, value: int
    ) -> int:
        """Validate that SECURITY_PORT_RANGE_START is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error(
                "SECURITY_PORT_RANGE_START"
            )
            raise ValueError(error_message)
        return value

    @field_validator("SECURITY_PORT_RANGE_END")
    @classmethod
    def _validate_security_port_range_end_non_negative(
        cls, value: int
    ) -> int:
        """Validate that SECURITY_PORT_RANGE_END is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error(
                "SECURITY_PORT_RANGE_END"
            )
            raise ValueError(error_message)
        return value

    @field_validator("INTEGRITY_PORT_RANGE_START")
    @classmethod
    def _validate_integrity_port_range_start_non_negative(
        cls, value: int
    ) -> int:
        """Validate that INTEGRITY_PORT_RANGE_START is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error(
                "INTEGRITY_PORT_RANGE_START"
            )
            raise ValueError(error_message)
        return value

    @field_validator("INTEGRITY_PORT_RANGE_END")
    @classmethod
    def _validate_integrity_port_range_end_non_negative(
        cls, value: int
    ) -> int:
        """Validate that INTEGRITY_PORT_RANGE_END is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error(
                "INTEGRITY_PORT_RANGE_END"
            )
            raise ValueError(error_message)
        return value

    @field_validator("ADMIN_PORT_RANGE_START")
    @classmethod
    def _validate_admin_port_range_start_non_negative(
        cls, value: int
    ) -> int:
        """Validate that ADMIN_PORT_RANGE_START is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error(
                "ADMIN_PORT_RANGE_START"
            )
            raise ValueError(error_message)
        return value

    @field_validator("ADMIN_PORT_RANGE_END")
    @classmethod
    def _validate_admin_port_range_end_non_negative(
        cls, value: int
    ) -> int:
        """Validate that ADMIN_PORT_RANGE_END is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error(
                "ADMIN_PORT_RANGE_END"
            )
            raise ValueError(error_message)
        return value

    @field_validator("DB_POOL_SIZE")
    @classmethod
    def _validate_db_pool_size_non_negative(cls, value: int) -> int:
        """Validate that DB_POOL_SIZE is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error("DB_POOL_SIZE")
            raise ValueError(error_message)
        return value

    @field_validator("DB_MAX_OVERFLOW")
    @classmethod
    def _validate_db_max_overflow_non_negative(cls, value: int) -> int:
        """Validate that DB_MAX_OVERFLOW is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error("DB_MAX_OVERFLOW")
            raise ValueError(error_message)
        return value

    @field_validator("DB_POOL_TIMEOUT")
    @classmethod
    def _validate_db_pool_timeout_non_negative(cls, value: int) -> int:
        """Validate that DB_POOL_TIMEOUT is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error("DB_POOL_TIMEOUT")
            raise ValueError(error_message)
        return value

    @field_validator("DB_POOL_RECYCLE")
    @classmethod
    def _validate_db_pool_recycle_non_negative(cls, value: int) -> int:
        """Validate that DB_POOL_RECYCLE is not negative."""
        is_non_negative = is_integer_non_negative(value)
        if not is_non_negative:
            error_message = build_non_negative_error("DB_POOL_RECYCLE")
            raise ValueError(error_message)
        return value

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def jwt_algorithm(self) -> str:
        """The pinned signing algorithm.

        Returns
        -------
        str
            The value of JWT_ALGORITHM.
        """
        return self.JWT_ALGORITHM

    @property
    def jwt_issuer(self) -> str:
        """The expected ``iss`` claim.

        Returns
        -------
        str
            The value of JWT_ISSUER.
        """
        return self.JWT_ISSUER

    @property
    def jwt_audience(self) -> str:
        """The expected ``aud`` claim.

        Returns
        -------
        str
            The value of JWT_AUDIENCE.
        """
        return self.JWT_AUDIENCE

    @property
    def jwt_secret(self) -> str:
        """The raw JWT signing secret, for handing to PyJWT.

        Returns
        -------
        str
            The plaintext secret value from LICENSE_JWT_SECRET.
        """
        return self.LICENSE_JWT_SECRET.get_secret_value()

    @property
    def license_key_pepper(self) -> str:
        """The raw license key pepper, for HMAC operations.

        Returns
        -------
        str
            The plaintext pepper value from LICENSE_KEY_PEPPER.
        """
        return self.LICENSE_KEY_PEPPER.get_secret_value()

    @property
    def hwid_pepper(self) -> str:
        """The raw HWID pepper, for HMAC operations.

        Returns
        -------
        str
            The plaintext pepper value from HWID_PEPPER.
        """
        return self.HWID_PEPPER.get_secret_value()

    @property
    def integrity_pepper(self) -> str:
        """The raw integrity manifest pepper, for HMAC operations.

        Returns
        -------
        str
            The plaintext pepper value from INTEGRITY_PEPPER.
        """
        return self.INTEGRITY_PEPPER.get_secret_value()

    @property
    def keyauth_owner_id(self) -> str | None:
        """The KeyAuth owner ID for license verification.

        Returns
        -------
        str | None
            The value of KEYAUTH_OWNER_ID.
        """
        return self.KEYAUTH_OWNER_ID

    @property
    def keyauth_app_name(self) -> str | None:
        """The KeyAuth application name.

        Returns
        -------
        str | None
            The value of KEYAUTH_APP_NAME.
        """
        return self.KEYAUTH_APP_NAME

    @property
    def keyauth_app_secret(self) -> str | None:
        """The KeyAuth application secret. Never log this value.

        Splits the original conditional into an explicit if/else block with
        named intermediate variables.

        Returns
        -------
        str | None
            The plaintext secret value, or None when not configured.
        """
        secret_field = self.KEYAUTH_APP_SECRET
        is_none = secret_field is None
        if is_none:
            return None
        secret_value = secret_field.get_secret_value()
        return secret_value

    @property
    def min_client_build(self) -> str:
        """The oldest client build string the server will accept.

        Returns
        -------
        str
            The value of ANTI_TAMPER_MIN_CLIENT_BUILD.
        """
        return self.ANTI_TAMPER_MIN_CLIENT_BUILD

    @property
    def is_sqlite(self) -> bool:
        """Whether the configured database is SQLite.

        Returns
        -------
        bool
            True when DATABASE_URL starts with "sqlite".
        """
        starts_with_sqlite = self.DATABASE_URL.startswith("sqlite")
        return starts_with_sqlite

    # ------------------------------------------------------------------
    # Runtime validation: validate_runtime (split into focused checks)
    # ------------------------------------------------------------------

    def validate_runtime(self) -> None:
        """Fail loudly on missing or weak secrets; safe to call more than once.

        Splits the original monolithic method into: check_jwt_secret,
        check_peppers, check_peppers_distinct, check_all_problems,
        build_runtime_error_message, and raise_if_problems.

        Side effects
        ------------
        Raises :class:`RuntimeError` when any insecurity is detected.
        """
        problems = check_all_problems(self)
        raise_if_problems(problems)

    # ------------------------------------------------------------------
    # Model validator: port ranges ordered
    # ------------------------------------------------------------------

    @model_validator(mode="after")
    def _port_ranges_ordered(self) -> "Settings":
        """Ensure every service port range start does not exceed its end.

        Splits the original into: collecting ranges, validating ranges, and
        the model validator itself.

        Parameters
        ----------
        self : Settings
            The model instance being validated.

        Returns
        -------
        Settings
            The instance unchanged when valid.
        """
        ranges = collect_port_ranges(self)
        validate_port_ranges(ranges)
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide cached settings accessor.

    Parses the environment exactly once per process and caches the resulting
    :class:`Settings` instance. Subsequent calls return the same object.

    Returns
    -------
    Settings
        The cached settings instance.
    """
    settings = Settings()
    return settings
