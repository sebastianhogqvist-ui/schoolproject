"""Client-facing license endpoints: activate and status."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request

from app.config import Settings
from app.db import DbSession
from app.deps import (
    auth_rate_limit,
    client_dep,
    client_ip,
    client_user_agent,
    iso,
    settings_dep,
    unix,
)
from app.schemas import ActivateRequest, SuccessResponse, success
from app.services import license as license_svc

router = APIRouter(prefix="/v1/licenses", tags=["licenses"])

_settings_dep = Depends(settings_dep)
_client_dep = Depends(client_dep)
_auth_rl = Depends(auth_rate_limit)


@router.post("/activate")
async def activate(
    payload: ActivateRequest,
    request: Request,
    session: DbSession,
    settings: Settings = _settings_dep,
    _rate_limited: None = _auth_rl,
) -> SuccessResponse:
    """Bind a license key to a device and issue a session token."""
    result = license_svc.activate(
        session,
        raw_key=payload.key,
        client_hwid=payload.hwid,
        ip=client_ip(request),
        user_agent=client_user_agent(request),
        settings=settings,
    )
    data: dict[str, Any] = {
        "license_id": int(result.license_id),
        "session_token": result.session_token,
        "expires_at": iso(result.session_expires_at),
        "exp": unix(result.session_expires_at),
        "activation_type": result.activation_type,
        "bound": True,
        "license_expires_at": iso(result.expires_at),
        "license_exp": unix(result.expires_at),
        "status": result.status.value if hasattr(result.status, "value") else str(result.status),
    }
    return success(data)


@router.get("/status")
async def license_status(
    session: DbSession,
    context: Any = _client_dep,
    _rate_limited: None = _auth_rl,
) -> SuccessResponse:
    """Return the status document for the caller's active session/license."""
    payload = license_svc.license_status(context)
    payload["expires_at"] = iso(context.row.expires_at)
    payload["exp"] = unix(context.row.expires_at)
    return success(payload)
