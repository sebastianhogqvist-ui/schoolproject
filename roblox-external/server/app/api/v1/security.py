"""Security event reporting and enforcement status endpoints."""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Request

from app.config import Settings
from app.db import DbSession
from app.deps import (
    client_dep,
    client_ip,
    client_user_agent,
    security_event_rate_limit,
    settings_dep,
)
from app.schemas import SecurityEventSubmission, SuccessResponse, success
from app.services import security_events as security_events_svc

router = APIRouter(prefix="/v1/security", tags=["security"])

_client_dep = Depends(client_dep)
_security_rl = Depends(security_event_rate_limit)
_settings_dep = Depends(settings_dep)


@router.post("/event", response_model=SuccessResponse)
async def report_security_event(
    payload: SecurityEventSubmission,
    request: Request,
    session: DbSession,
    context: Any = _client_dep,
    settings: Settings = _settings_dep,
    _rate_limited: None = _security_rl,
) -> SuccessResponse:
    """Record a client-reported security event and apply enforcement policy."""
    result = security_events_svc.record_event(
        session,
        settings=settings,
        license_id=context.license.id,
        session_id=context.session_id,
        level=payload.level,
        category=payload.category,
        rule=payload.rule,
        reason=payload.reason,
        ip=client_ip(request),
        user_agent=client_user_agent(request),
        evidence=json.dumps(payload.evidence) if payload.evidence else None,
    )
    session.commit()
    return success({
        "event_id": result.event_id,
        "level": result.level,
        "action_taken": result.action_taken,
        "restriction_expires_at": result.restriction_expires_at.isoformat()
        if result.restriction_expires_at
        else None,
    })


@router.get("/status", response_model=SuccessResponse)
async def security_status(
    request: Request,
    session: DbSession,
    context: Any = _client_dep,
    settings: Settings = _settings_dep,
) -> SuccessResponse:
    """Return the current enforcement posture for the authenticated license."""
    status = security_events_svc.get_enforcement_status(
        session, settings, license_id=context.license.id
    )
    return success(status.to_dict())
