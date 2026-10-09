"""KeyAuth integration endpoints for license validation.

These endpoints proxy license-key validation through the KeyAuth API server-side,
so the app secret never touches the browser.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request

from app.config import Settings
from app.deps import iso, settings_dep, unix
from app.schemas import ActivateRequest, SuccessResponse, ValidateRequest, success
from app.services import keyauth as keyauth_svc

router = APIRouter(prefix="/v1/keyauth", tags=["keyauth"])

_settings_dep = Depends(settings_dep)


@router.post("/activate")
async def keyauth_activate(
    payload: ActivateRequest,
    request: Request,
    settings: Settings = _settings_dep,
) -> SuccessResponse:
    """Validate a license key through KeyAuth and return the result.

    The app secret is used entirely server-side; it is never sent to the client.
    """
    result = await keyauth_svc.validate_license_key(
        settings,
        raw_key=payload.key,
        hwid=payload.hwid,
    )
    data: dict[str, Any] = result.to_dict()
    if result.success:
        data["expires_at"] = iso(result.data.get("session_expires_at")) if result.data else None
        data["exp"] = unix(result.data.get("session_expires_at")) if result.data else None
    return success(data)


@router.post("/session/validate")
async def keyauth_validate_session(
    payload: ValidateRequest,
    request: Request,
    settings: Settings = _settings_dep,
) -> SuccessResponse:
    """Validate the current KeyAuth session.

    Re-initializes with KeyAuth to confirm the service is reachable and the
    app configuration is valid.
    """
    result = await keyauth_svc.validate_session(settings)
    return success(result.to_dict())


@router.post("/heartbeat")
async def keyauth_heartbeat(
    request: Request,
    settings: Settings = _settings_dep,
) -> SuccessResponse:
    """Check whether the KeyAuth service is reachable."""
    result = await keyauth_svc.heartbeat(settings)
    return success(result.to_dict())
