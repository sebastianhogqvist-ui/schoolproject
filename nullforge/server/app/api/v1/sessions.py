"""Client-facing session endpoints: validate and logout."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request

from app.db import DbSession
from app.deps import (
    auth_rate_limit,
    client_dep,
    client_ip,
    client_user_agent,
    iso,
    unix,
    wire,
)
from app.schemas import SuccessResponse, ValidateRequest, success
from app.services import license as license_svc

router = APIRouter(prefix="/v1/sessions", tags=["sessions"])

_client_dep = Depends(client_dep)
_auth_rl = Depends(auth_rate_limit)


@router.post("/validate")
async def validate(
    payload: ValidateRequest,
    request: Request,
    session: DbSession,
    context: Any = _client_dep,
    _rate_limited: None = _auth_rl,
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
    context: Any = _client_dep,
    _rate_limited: None = _auth_rl,
) -> SuccessResponse:
    """Revoke the presented session token."""
    license_svc.logout(
        session,
        context,
        ip=client_ip(request),
        user_agent=client_user_agent(request),
    )
    return success({})
