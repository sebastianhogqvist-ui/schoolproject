"""Operator-facing license administration endpoints."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request

from app.config import Settings
from app.db import DbSession
from app.deps import (
    admin_api_rate_limit,
    admin_dep,
    admin_login_rate_limit,
    client_ip,
    client_user_agent,
    iso,
    settings_dep,
    unix,
    wire,
)
from app.errors import AppError, ErrorCode
from app.schemas import (
    AdminLoginRequest,
    LicenseCreateRequest,
    LicenseListRequest,
    SuccessResponse,
    success,
)
from app.services import admin as admin_svc
from app.services import auth as auth_svc
from app.states import LicenseStatus

router = APIRouter(prefix="/v1/admin", tags=["admin"])

_admin_settings_dep = Depends(settings_dep)
_admin_login_rl = Depends(admin_login_rate_limit)
_admin_api_rl = Depends(admin_api_rate_limit)
_admin_dep = Depends(admin_dep)
_list_params_dep = Depends()


def _resolve_status(raw: str | None) -> LicenseStatus | None:
    if not raw:
        return None
    try:
        return LicenseStatus(raw)
    except ValueError:
        raise AppError(ErrorCode.VALIDATION_ERROR, f"unknown status {raw!r}") from None


@router.post("/login")
async def login(
    payload: AdminLoginRequest,
    request: Request,
    session: DbSession,
    settings: Settings = _admin_settings_dep,
    _rate_limited: None = _admin_login_rl,
) -> SuccessResponse:
    token = auth_svc.authenticate_admin(
        session,
        username=payload.username,
        password=payload.password,
        settings=settings,
        ip=client_ip(request),
        user_agent=client_user_agent(request),
    )
    data = {
        "session_token": token.token,
        "expires_at": iso(token.expires_at),
        "exp": unix(token.expires_at),
        "username": token.admin.username,
        "is_superuser": bool(token.admin.is_superuser),
    }
    return success(data)


@router.post("/licenses")
async def create_license(
    payload: LicenseCreateRequest,
    request: Request,
    session: DbSession,
    admin: Any = _admin_dep,
    _rate_limited: None = _admin_api_rl,
    settings: Settings = _admin_settings_dep,
) -> SuccessResponse:
    row, plaintext = admin_svc.create_license(
        session,
        admin,
        expires_in_days=payload.expires_in_days,
        custom_expires_at=payload.custom_expires_at,
        note=payload.note,
        metadata=payload.metadata,
        ip=client_ip(request),
        user_agent=client_user_agent(request),
        settings=settings,
    )
    data = admin_svc.serialize_license(row)
    data = wire(data)
    data["key"] = plaintext
    data["license_id"] = int(row.id)
    return success(data)


@router.get("/licenses")
async def list_licenses(
    request: Request,
    session: DbSession,
    admin: Any = _admin_dep,
    _rate_limited: None = _admin_api_rl,
    params: LicenseListRequest = _list_params_dep,
) -> SuccessResponse:
    pagination, rows = admin_svc.list_licenses(
        session,
        status=_resolve_status(params.status),
        query=params.query,
        page=params.page,
        page_size=params.page_size,
    )
    data = {
        "pagination": wire(pagination),
        "licenses": [wire(r) for r in rows],
    }
    return success(data)


@router.get("/licenses/{license_id}")
async def license_detail(
    license_id: int,
    request: Request,
    session: DbSession,
    admin: Any = _admin_dep,
    _rate_limited: None = _admin_api_rl,
    params: LicenseListRequest = _list_params_dep,
) -> SuccessResponse:
    detail = admin_svc.license_detail(
        session, license_id, page=params.page, page_size=params.page_size
    )
    return success(wire(detail))


@router.post("/licenses/{license_id}/suspend")
async def suspend_license(
    license_id: int,
    request: Request,
    session: DbSession,
    admin: Any = _admin_dep,
    _rate_limited: None = _admin_api_rl,
) -> SuccessResponse:
    row = admin_svc.suspend(
        session, admin, license_id, ip=client_ip(request), user_agent=client_user_agent(request)
    )
    return success(wire(admin_svc.serialize_license(row)))


@router.post("/licenses/{license_id}/unsuspend")
async def unsuspend_license(
    license_id: int,
    request: Request,
    session: DbSession,
    admin: Any = _admin_dep,
    _rate_limited: None = _admin_api_rl,
) -> SuccessResponse:
    row = admin_svc.unsuspend(
        session, admin, license_id, ip=client_ip(request), user_agent=client_user_agent(request)
    )
    return success(wire(admin_svc.serialize_license(row)))


@router.post("/licenses/{license_id}/revoke")
async def revoke_license(
    license_id: int,
    request: Request,
    session: DbSession,
    admin: Any = _admin_dep,
    _rate_limited: None = _admin_api_rl,
) -> SuccessResponse:
    row = admin_svc.revoke(
        session, admin, license_id, ip=client_ip(request), user_agent=client_user_agent(request)
    )
    return success(wire(admin_svc.serialize_license(row)))


@router.post("/licenses/{license_id}/reset-hwid")
async def reset_hwid(
    license_id: int,
    request: Request,
    session: DbSession,
    admin: Any = _admin_dep,
    _rate_limited: None = _admin_api_rl,
) -> SuccessResponse:
    row = admin_svc.reset_hwid(
        session, admin, license_id, ip=client_ip(request), user_agent=client_user_agent(request)
    )
    return success(wire(admin_svc.serialize_license(row)))


@router.delete("/licenses/{license_id}")
async def delete_license(
    license_id: int,
    request: Request,
    session: DbSession,
    admin: Any = _admin_dep,
    _rate_limited: None = _admin_api_rl,
) -> SuccessResponse:
    admin_svc.delete_license(
        session, admin, license_id, ip=client_ip(request), user_agent=client_user_agent(request)
    )
    return success({})
