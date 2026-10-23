"""Application settings, sourced exclusively from the environment.

Secrets have no defaults on purpose: a misconfigured deployment must fail
loudly at startup rather than silently fall back to a guessable value. Use
:meth:`Settings.validate_runtime` for defence in depth once values are loaded.
"""

import json
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

MIN_JWT_SECRET_LENGTH = 32
MIN_PEPPER_LENGTH = 16

_ALGORITHMS: tuple[Literal["HS256"], ...] = ("HS256",)


class Settings(BaseSettings):
    """Runtime configuration for the license server."""

    model_config = SettingsConfigDict(
        env_file=(".env", "../../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    DATABASE_URL: str = "sqlite:///./license.db"

    SERVER_HOST: str = "127.0.0.1"
    SERVER_PORT: int = 8080

    LICENSE_JWT_SECRET: SecretStr = Field(min_length=MIN_JWT_SECRET_LENGTH)
    JWT_ALGORITHM: Literal["HS256"] = "HS256"
    JWT_ISSUER: str = "roblox-license-server"
    JWT_AUDIENCE: str = "roblox-license-client"

    SESSION_TTL_SECONDS: int = 900
    ADMIN_SESSION_TTL_SECONDS: int = 1800

    LICENSE_KEY_PEPPER: SecretStr = Field(min_length=MIN_PEPPER_LENGTH)
    HWID_PEPPER: SecretStr = Field(min_length=MIN_PEPPER_LENGTH)
    INTEGRITY_PEPPER: SecretStr = Field(min_length=MIN_PEPPER_LENGTH)

    ADMIN_USERNAME: str | None = None
    ADMIN_PASSWORD: SecretStr | None = None

    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_AUTH_PER_MINUTE: int = 10
    RATE_LIMIT_ADMIN_LOGIN_PER_MINUTE: int = 5
    RATE_LIMIT_ADMIN_API_PER_MINUTE: int = 120
    RATE_LIMIT_KEYGEN_PER_MINUTE: int = 30

    CORS_ALLOWED_ORIGINS: Annotated[list[str], NoDecode] = Field(default_factory=list)

    MAINTENANCE_MODE: bool = False
    LOG_LEVEL: str = "INFO"
    MAX_REQUEST_BODY_BYTES: int = 16384

    BCRYPT_TIME_COST: int = 3
    BCRYPT_MEMORY_COST: int = 65536
    BCRYPT_PARALLELISM: int = 4

    KEYAUTH_OWNER_ID: str | None = None
    KEYAUTH_APP_SECRET: SecretStr | None = None
    KEYAUTH_APP_NAME: str | None = None

    # Anti-tampering configuration
    ANTI_TAMPER_ENABLED: bool = True
    ANTI_TAMPER_ENFORCEMENT_MODE: str = "monitor"
    ANTI_TAMPER_AUTO_RESTRICT_THRESHOLD: int = 5
    ANTI_TAMPER_BAN_THRESHOLD: int = 10
    ANTI_TAMPER_RESTRICTION_HOURS: int = 24
    ANTI_TAMPER_RETENTION_DAYS: int = 30

    # Client build/version enforcement (anti-downgrade)
    # The loader echoes its build string; the server rejects builds older than
    # this. Set REQUIRE_CLIENT_BUILD=false to observe without enforcing.
    ANTI_TAMPER_MIN_CLIENT_BUILD: str = "1.0.0"
    ANTI_TAMPER_REQUIRE_CLIENT_BUILD: bool = False

    # Anti-replay: how long a server-issued nonce stays valid, and how long a
    # client-supplied timestamp may be skewed from server time.
    ANTI_TAMPER_NONCE_TTL_SECONDS: int = 300
    ANTI_TAMPER_MAX_CLOCK_SKEW_SECONDS: int = 120

    # Per-endpoint rate limits for the new anti-tamper surface.
    RATE_LIMIT_KEYAUTH_PER_MINUTE: int = 15
    RATE_LIMIT_SECURITY_EVENT_PER_MINUTE: int = 10
    RATE_LIMIT_INTEGRITY_PER_MINUTE: int = 20

    @field_validator("ANTI_TAMPER_MIN_CLIENT_BUILD")
    @classmethod
    def _non_empty_client_build(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("ANTI_TAMPER_MIN_CLIENT_BUILD must not be empty")
        return value

    @field_validator("CORS_ALLOWED_ORIGINS", mode="before")
    @classmethod
    def _parse_origins(cls, value: object) -> object:
        """Accept a JSON array or a comma-separated list from the environment."""
        if not isinstance(value, str):
            return value
        raw = value.strip()
        if not raw:
            return []
        if raw.startswith("["):
            return json.loads(raw)
        return [origin.strip() for origin in raw.split(",") if origin.strip()]

    @field_validator("LOG_LEVEL")
    @classmethod
    def _normalize_log_level(cls, value: str) -> str:
        level = value.strip().upper()
        if level not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"}:
            raise ValueError("LOG_LEVEL must be a standard logging level name")
        return level

    @field_validator("SERVER_PORT", "SESSION_TTL_SECONDS", "ADMIN_SESSION_TTL_SECONDS")
    @classmethod
    def _positive(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("must be greater than zero")
        return value

    @field_validator("ANTI_TAMPER_ENFORCEMENT_MODE")
    @classmethod
    def _enforcement_mode(cls, value: str) -> str:
        allowed = {"monitor", "restrict", "enforce"}
        if value not in allowed:
            raise ValueError(f"ANTI_TAMPER_ENFORCEMENT_MODE must be one of {sorted(allowed)}")
        return value

    @field_validator(
        "MAX_REQUEST_BODY_BYTES",
        "RATE_LIMIT_AUTH_PER_MINUTE",
        "RATE_LIMIT_ADMIN_LOGIN_PER_MINUTE",
        "RATE_LIMIT_ADMIN_API_PER_MINUTE",
        "RATE_LIMIT_KEYGEN_PER_MINUTE",
        "BCRYPT_TIME_COST",
        "BCRYPT_MEMORY_COST",
        "BCRYPT_PARALLELISM",
        "ANTI_TAMPER_AUTO_RESTRICT_THRESHOLD",
        "ANTI_TAMPER_BAN_THRESHOLD",
        "ANTI_TAMPER_RESTRICTION_HOURS",
        "ANTI_TAMPER_RETENTION_DAYS",
        "ANTI_TAMPER_NONCE_TTL_SECONDS",
        "ANTI_TAMPER_MAX_CLOCK_SKEW_SECONDS",
        "RATE_LIMIT_KEYAUTH_PER_MINUTE",
        "RATE_LIMIT_SECURITY_EVENT_PER_MINUTE",
        "RATE_LIMIT_INTEGRITY_PER_MINUTE",
    )
    @classmethod
    def _non_negative(cls, value: int) -> int:
        if value < 0:
            raise ValueError("must not be negative")
        return value

    @property
    def jwt_algorithm(self) -> str:
        """The pinned signing algorithm."""
        return self.JWT_ALGORITHM

    @property
    def jwt_issuer(self) -> str:
        """The expected ``iss`` claim."""
        return self.JWT_ISSUER

    @property
    def jwt_audience(self) -> str:
        """The expected ``aud`` claim."""
        return self.JWT_AUDIENCE

    @property
    def jwt_secret(self) -> str:
        """The raw JWT signing secret, for handing to PyJWT."""
        return self.LICENSE_JWT_SECRET.get_secret_value()

    @property
    def license_key_pepper(self) -> str:
        """The raw license key pepper, for HMAC operations."""
        return self.LICENSE_KEY_PEPPER.get_secret_value()

    @property
    def hwid_pepper(self) -> str:
        """The raw HWID pepper, for HMAC operations."""
        return self.HWID_PEPPER.get_secret_value()

    @property
    def integrity_pepper(self) -> str:
        """The raw integrity manifest pepper, for HMAC operations."""
        return self.INTEGRITY_PEPPER.get_secret_value()

    @property
    def keyauth_owner_id(self) -> str | None:
        """The KeyAuth owner ID for license verification."""
        return self.KEYAUTH_OWNER_ID

    @property
    def keyauth_app_name(self) -> str | None:
        """The KeyAuth application name."""
        return self.KEYAUTH_APP_NAME

    @property
    def keyauth_app_secret(self) -> str | None:
        """The KeyAuth application secret. Never log this value."""
        if self.KEYAUTH_APP_SECRET is None:
            return None
        return self.KEYAUTH_APP_SECRET.get_secret_value()

    @property
    def min_client_build(self) -> str:
        """The oldest client build string the server will accept."""
        return self.ANTI_TAMPER_MIN_CLIENT_BUILD

    @property
    def is_sqlite(self) -> bool:
        """Whether the configured database is SQLite."""
        return self.DATABASE_URL.startswith("sqlite")

    def validate_runtime(self) -> None:
        """Fail loudly on missing or weak secrets; safe to call more than once."""
        problems: list[str] = []

        jwt_secret = self.jwt_secret
        if not jwt_secret:
            problems.append("LICENSE_JWT_SECRET is empty")
        elif len(jwt_secret) < MIN_JWT_SECRET_LENGTH:
            problems.append(
                f"LICENSE_JWT_SECRET must be at least {MIN_JWT_SECRET_LENGTH} characters"
            )

        for name in ("LICENSE_KEY_PEPPER", "HWID_PEPPER", "INTEGRITY_PEPPER"):
            pepper = getattr(self, name).get_secret_value()
            if not pepper:
                problems.append(f"{name} is empty")
            elif len(pepper) < MIN_PEPPER_LENGTH:
                problems.append(f"{name} must be at least {MIN_PEPPER_LENGTH} characters")

        if self.jwt_secret and self.jwt_secret in {
            self.license_key_pepper, self.hwid_pepper, self.integrity_pepper,
        }:
            problems.append("LICENSE_JWT_SECRET must differ from the peppers")

        if problems:
            raise RuntimeError("insecure configuration: " + "; ".join(problems))


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide cached settings accessor."""
    return Settings()
