"""Session service backend routes (service-to-service).

These routes are mounted on the session backend and expect a service token
with embedded client context (sid, lid).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request

from app.config import Settings
from app.db import DbSession
from app.deps import client_ip, client_user_agent, iso, service_dep, settings_dep, unix, wire
from app.schemas import SuccessResponse, ValidateRequest, success
from app.services import license as license_svc

router = APIRouter(prefix="/v1/sessions", tags=["session-service"])

_service_dep = Depends(service_dep)
_settings_dep = Depends(settings_dep)


@router.post("/validate")
async def validate(
    payload: ValidateRequest,
    request: Request,
    session: DbSession,
    context: Any = _service_dep,
    settings: Settings = _settings_dep,
) -> SuccessResponse:
    """Refresh the session and the license's last_validated_at timestamp."""
    result = license_svc.validate(
        session,
        context,
        ip=client_ip(request),
        user_agent=client_user_agent(request),
    )
    data = wire(result)
    data["expires_at"] = iso(context.row.expires_at)
    data["exp"] = unix(context.row.expires_at)
    return success(data)


@router.post("/logout")
async def logout(
    request: Request,
    session: DbSession,
    context: Any = _service_dep,
    settings: Settings = _settings_dep,
) -> SuccessResponse:
    """Revoke the presented session token."""
    license_svc.logout(
        session,
        context,
        ip=client_ip(request),
        user_agent=client_user_agent(request),
    )
    return success({})
