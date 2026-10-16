"""File integrity verification endpoints."""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Request

from app.config import Settings
from app.db import DbSession
from app.deps import client_dep, client_ip, client_user_agent, integrity_rate_limit, settings_dep
from app.errors import AppError, ErrorCode
from app.schemas import IntegrityManifestSubmission, SuccessResponse, success
from app.services import integrity as integrity_svc

router = APIRouter(prefix="/v1/integrity", tags=["integrity"])

_client_dep = Depends(client_dep)
_integrity_rl = Depends(integrity_rate_limit)
_settings_dep = Depends(settings_dep)


@router.get("/challenge", response_model=SuccessResponse)
async def integrity_challenge(
    request: Request,
    session: DbSession,
    context: Any = _client_dep,
    settings: Settings = _settings_dep,
    _rate_limited: None = _integrity_rl,
) -> SuccessResponse:
    """Issue a single-use nonce for an integrity manifest submission."""
    record = integrity_svc.nonce_store.issue(
        ttl_seconds=settings.ANTI_TAMPER_NONCE_TTL_SECONDS
    )
    return success({
        "nonce": record.nonce,
        "expires_in": settings.ANTI_TAMPER_NONCE_TTL_SECONDS,
    })


@router.post("/check", response_model=SuccessResponse)
async def integrity_check(
    payload: IntegrityManifestSubmission,
    request: Request,
    session: DbSession,
    context: Any = _client_dep,
    settings: Settings = _settings_dep,
    _rate_limited: None = _integrity_rl,
) -> SuccessResponse:
    """Verify a signed client integrity manifest against server expectations."""
    raw_manifest = json.dumps({
        "nonce": payload.nonce,
        "client_build": payload.client_build,
        "generated_at": payload.generated_at,
        "files": [f.model_dump() for f in payload.files],
        "signature": payload.signature,
    })
    assessment = integrity_svc.assess_manifest(
        raw_manifest=raw_manifest,
        nonce=payload.nonce,
        client_build=payload.client_build,
        settings=settings,
        pepper=settings.license_key_pepper,
        store=integrity_svc.nonce_store,
        expected_hashes=integrity_svc.load_expected_hashes(settings),
    )
    if not assessment.accepted:
        # Record as a security event if integrity is violated
        from app.services import security_events as security_events_svc
        security_events_svc.record_event(
            session,
            settings=settings,
            license_id=context.license.id,
            session_id=context.session_id,
            level=assessment.level,
            category="integrity",
            rule=assessment.rule,
            reason=assessment.reason,
            ip=client_ip(request),
            user_agent=client_user_agent(request),
            evidence=json.dumps(
                {"mismatches": assessment.mismatches, "missing": assessment.missing}
            ),
        )
        session.commit()
        if assessment.level >= 3 and settings.ANTI_TAMPER_ENFORCEMENT_MODE == "enforce":
            raise AppError(ErrorCode.FORBIDDEN, "Integrity violation detected")
    return success(assessment.to_dict())
