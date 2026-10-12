"""Pydantic schemas: validated request bodies and the success/error envelopes.

The business layer returns plain dicts/dataclasses; these schemas only document
and constrain the HTTP layer. The wire envelope is
``{"success": True/False, "data" | "error": ...}`` so a single client parser
handles every response.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


class SuccessResponse(BaseModel):
    """Canonical OK envelope."""

    success: bool = True
    data: Any = None


class ErrorResponse(BaseModel):
    """Canonical failure envelope."""

    success: bool = False
    error: dict[str, Any]


def success(data: Any = None) -> SuccessResponse:
    """Build a success envelope around ``data``."""
    return SuccessResponse(success=True, data=data)


class ActivateRequest(BaseModel):
    """Body for POST /v1/licenses/activate."""

    key: str = Field(..., min_length=1, max_length=256)
    hwid: str = Field(..., min_length=1, max_length=1024)


class ValidateRequest(BaseModel):
    """Body for POST /v1/sessions/validate."""

    hwid: str = Field(..., min_length=1, max_length=1024)


class AdminLoginRequest(BaseModel):
    """Body for POST /v1/admin/login."""

    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=1024)


class LicenseCreateRequest(BaseModel):
    """Body for POST /v1/admin/licenses."""

    expires_in_days: int | None = Field(default=None, ge=1, le=3650)
    custom_expires_at: datetime | None = None
    note: str | None = Field(default=None, max_length=640)
    metadata: dict[str, Any] | None = None

    @field_validator("metadata")
    @classmethod
    def _metadata_size(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is not None and len(json.dumps(value, default=str).encode("utf-8")) > 4096:
            raise ValueError("metadata is too large")
        return value


class LicenseListRequest(BaseModel):
    """Query parameters for admin license listing."""

    status: str | None = None
    query: str | None = Field(default=None, max_length=64)
    page: int = Field(1, ge=1)
    page_size: int = Field(50, ge=1, le=200)

class KeyAuthActivateRequest(BaseModel):
    """Body for POST /v1/keyauth/activate.

    ``client_build`` is echoed by the loader and enforced server-side so an
    older, weaker loader cannot be downgraded into use.
    """

    key: str = Field(..., min_length=1, max_length=256)
    hwid: str = Field(..., min_length=20, max_length=1024)
    client_build: str = Field(..., min_length=1, max_length=32)

    @field_validator("client_build")
    @classmethod
    def _clean_build(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned or len(cleaned) > 32:
            raise ValueError("client_build must be 1-32 characters")
        return cleaned


class AuthenticatedContextRequest(BaseModel):
    """Body for server-authority calls that carry a bearer token in headers.

    ``nonce`` binds the request to a single use so an identical payload cannot
    be replayed after the nonce window closes.
    """

    nonce: str | None = Field(default=None, max_length=64)
    client_build: str | None = Field(default=None, max_length=32)


class SecurityEventSubmission(BaseModel):
    """Body for POST /v1/security/event — a client-reported suspicious signal.

    The server never trusts the submitted ``level``; it is clamped and the
    enforcement engine derives the real level from cumulative server history.
    """

    level: int = Field(default=1, ge=0, le=3)
    category: str = Field(..., min_length=1, max_length=32)
    rule: str = Field(..., min_length=1, max_length=64)
    reason: str = Field(..., min_length=1, max_length=255)
    evidence: dict[str, Any] | None = None

    @field_validator("category", "rule", "reason")
    @classmethod
    def _no_newlines(cls, value: str) -> str:
        """Reject control characters so log/DB fields cannot be injected into."""
        if any(ch in value for ch in "\r\n\t\x00"):
            raise ValueError("must not contain control characters")
        return value.strip()

    @field_validator("evidence")
    @classmethod
    def _evidence_size(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is not None and len(json.dumps(value, default=str).encode("utf-8")) > 4096:
            raise ValueError("evidence is too large")
        return value


class IntegrityFileRecord(BaseModel):
    """One client-reported file hash."""

    path: str = Field(..., min_length=1, max_length=512)
    digest: str = Field(..., min_length=8, max_length=128)
    size: int = Field(default=-1)


class IntegrityManifestSubmission(BaseModel):
    """Body for POST /v1/integrity/check — a signed client integrity manifest.

    ``nonce`` is issued by GET /v1/integrity/challenge and is single-use, so a
    captured manifest cannot be replayed.
    """

    nonce: str = Field(..., min_length=8, max_length=128)
    client_build: str = Field(..., min_length=1, max_length=32)
    generated_at: str = Field(..., min_length=1, max_length=40)
    files: list[IntegrityFileRecord] = Field(default_factory=list, max_length=200)
    signature: str = Field(..., min_length=16, max_length=128)


class SecurityEventResolveRequest(BaseModel):
    """Body for POST /v1/admin/security/events/{event_id}/resolve."""

    status: str = Field(..., min_length=1, max_length=32)
    note: str | None = Field(default=None, max_length=255)


__all__ = [
    "ActivateRequest",
    "AdminLoginRequest",
    "AuthenticatedContextRequest",
    "ErrorResponse",
    "IntegrityFileRecord",
    "IntegrityManifestSubmission",
    "KeyAuthActivateRequest",
    "LicenseCreateRequest",
    "LicenseListRequest",
    "SecurityEventResolveRequest",
    "SecurityEventSubmission",
    "SuccessResponse",
    "ValidateRequest",
    "success",
]
