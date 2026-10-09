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

class IntegrityCheckRequest(BaseModel):
    """Body for POST /v1/integrity/check."""

    hwid: str = Field(..., min_length=1, max_length=1024)
    checks: list[str] = Field(default_factory=list, max_length=50)


class SecurityEventRequest(BaseModel):
    """Body for POST /v1/security/event."""

    level: int = Field(..., ge=0, le=3)
    category: str = Field(..., min_length=1, max_length=32)
    rule: str = Field(..., min_length=1, max_length=64)
    reason: str = Field(..., min_length=1, max_length=255)


class LicenseStatusRequest(BaseModel):
    """Body for POST /v1/keyauth/status."""

    session_token: str | None = None
