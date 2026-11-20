"""Canonical error contract for the license server.

Every failure surfaced to a client is an :class:`AppError` carrying a stable
machine-readable :class:`ErrorCode` and a message that is safe to show to an
untrusted third party: no SQL, no filesystem paths, no stack traces, no
secrets, and no internal identifiers.
"""

from enum import StrEnum
from typing import Any


class ErrorCode(StrEnum):
    """Stable, wire-visible error codes. Never renumber or rename a member."""

    LICENSE_NOT_FOUND = "LICENSE_NOT_FOUND"
    LICENSE_REVOKED = "LICENSE_REVOKED"
    LICENSE_SUSPENDED = "LICENSE_SUSPENDED"
    LICENSE_EXPIRED = "LICENSE_EXPIRED"
    HWID_MISMATCH = "HWID_MISMATCH"
    KEY_MALFORMED = "KEY_MALFORMED"
    RATE_LIMITED = "RATE_LIMITED"
    SESSION_MISSING = "SESSION_MISSING"
    SESSION_INVALID = "SESSION_INVALID"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    FORBIDDEN = "FORBIDDEN"
    ADMIN_AUTH_FAILED = "ADMIN_AUTH_FAILED"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    SERVICE_MAINTENANCE = "SERVICE_MAINTENANCE"
    DATABASE_UNAVAILABLE = "DATABASE_UNAVAILABLE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


CODE_HTTP_STATUS: dict[ErrorCode, int] = {
    ErrorCode.LICENSE_NOT_FOUND: 404,
    ErrorCode.LICENSE_REVOKED: 403,
    ErrorCode.LICENSE_SUSPENDED: 403,
    ErrorCode.LICENSE_EXPIRED: 403,
    ErrorCode.HWID_MISMATCH: 409,
    ErrorCode.KEY_MALFORMED: 400,
    ErrorCode.RATE_LIMITED: 429,
    ErrorCode.SESSION_MISSING: 401,
    ErrorCode.SESSION_INVALID: 401,
    ErrorCode.SESSION_EXPIRED: 401,
    ErrorCode.AUTH_REQUIRED: 401,
    ErrorCode.FORBIDDEN: 403,
    ErrorCode.ADMIN_AUTH_FAILED: 401,
    ErrorCode.VALIDATION_ERROR: 422,
    ErrorCode.SERVICE_MAINTENANCE: 503,
    ErrorCode.DATABASE_UNAVAILABLE: 503,
    ErrorCode.INTERNAL_ERROR: 500,
}

SAFE_MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.LICENSE_NOT_FOUND: "License key not found.",
    ErrorCode.LICENSE_REVOKED: "This license has been revoked.",
    ErrorCode.LICENSE_SUSPENDED: "This license is suspended.",
    ErrorCode.LICENSE_EXPIRED: "This license has expired.",
    ErrorCode.HWID_MISMATCH: "License is bound to a different device.",
    ErrorCode.KEY_MALFORMED: "License key format is invalid.",
    ErrorCode.RATE_LIMITED: "Too many requests. Please retry later.",
    ErrorCode.SESSION_MISSING: "No active session. Authenticate first.",
    ErrorCode.SESSION_INVALID: "Session is invalid.",
    ErrorCode.SESSION_EXPIRED: "Session has expired. Authenticate again.",
    ErrorCode.AUTH_REQUIRED: "Authentication is required.",
    ErrorCode.FORBIDDEN: "You are not allowed to perform this action.",
    ErrorCode.ADMIN_AUTH_FAILED: "Invalid administrator credentials.",
    ErrorCode.VALIDATION_ERROR: "Request payload failed validation.",
    ErrorCode.SERVICE_MAINTENANCE: "Service is temporarily unavailable.",
    ErrorCode.DATABASE_UNAVAILABLE: "Service is temporarily unavailable.",
    ErrorCode.INTERNAL_ERROR: "An internal error occurred.",
}

_SENSITIVE_WORDS = (
    "password",
    "secret",
    "pepper",
    "token",
    "authorization",
    "apikey",
    "api_key",
)
_INTERNAL_MARKERS = ("select ", "insert ", "update ", "sqlite", "traceback", "line ")
_MAX_MESSAGE_LENGTH = 300


def _sanitize(message: str) -> str:
    """Normalize a message so it can never leak internals to a client."""
    collapsed = " ".join(message.split())
    lowered = collapsed.lower()
    for needle in _SENSITIVE_WORDS:
        if needle in lowered:
            return SAFE_MESSAGES[ErrorCode.INTERNAL_ERROR]
    if any(bad in lowered for bad in _INTERNAL_MARKERS):
        return SAFE_MESSAGES[ErrorCode.INTERNAL_ERROR]
    return collapsed[:_MAX_MESSAGE_LENGTH]


class AppError(Exception):
    """An error with a stable code, an HTTP status and a user-safe message."""

    def __init__(
        self,
        code: ErrorCode,
        message: str | None = None,
        *,
        retry_after: int | None = None,
    ) -> None:
        self.code = ErrorCode(code)
        self.http_status = CODE_HTTP_STATUS[self.code]
        self.safe_message = _sanitize(message) if message else SAFE_MESSAGES[self.code]
        self.retry_after = retry_after
        super().__init__(f"{self.code.value}: {self.safe_message}")

    def to_dict(self) -> dict[str, Any]:
        """Render the wire representation, including ``retry_after`` when set."""
        error: dict[str, Any] = {"code": self.code.value, "message": self.safe_message}
        if self.retry_after is not None:
            error["retry_after"] = self.retry_after
        return {"success": False, "error": error}


def error_response(code: ErrorCode | str, message: str | None = None) -> dict[str, Any]:
    """Build the canonical failure envelope for a code (and optional message)."""
    return AppError(ErrorCode(code), message).to_dict()


def success_response(data: Any = None) -> dict[str, Any]:
    """Build the canonical success envelope."""
    return {"success": True, "data": data}
