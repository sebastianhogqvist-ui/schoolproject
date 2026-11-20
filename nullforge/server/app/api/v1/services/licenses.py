"""License service backend routes (service-to-service).

These routes are mounted on the license backend and expect a service token
with embedded client context (sid, lid) instead of a client JWT.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request

from app.config import Settings
from app.db import DbSession
from app.deps import client_ip, client_user_agent, iso, service_dep, settings_dep, unix
from app.schemas import ActivateRequest, SuccessResponse, success
from app.services import license as license_svc

router = APIRouter(prefix="/v1/licenses", tags=["license-service"])

_settings_dep = Depends(settings_dep)
_service_dep = Depends(service_dep)


@router.post("/activate")
async def activate(
    payload: ActivateRequest,
    request: Request,
    session: DbSession,
    settings: Settings = _settings_dep,
) -> SuccessResponse:
    """Bind a license key to a device and issue a session token.

    Activation does not require an existing client session - it creates one.
    The gateway forwards this without client auth, so no service_dep is used.
    """
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
    context: Any = _service_dep,
    settings: Settings = _settings_dep,
) -> SuccessResponse:
    """Return the status document for the caller's active session/license."""
    payload = license_svc.license_status(context)
    payload["expires_at"] = iso(context.row.expires_at)
    payload["exp"] = unix(context.row.expires_at)
    return success(payload)
