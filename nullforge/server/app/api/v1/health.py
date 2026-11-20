"""Liveness, readiness and heartbeat endpoints."""
from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import text

from app.db import SessionLocal
from app.schemas import SuccessResponse, success

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> SuccessResponse:
    """Liveness probe: the process is up and importable."""
    return success({"status": "ok"})


@router.get("/health/live")
async def liveness() -> SuccessResponse:
    """Alias for orchestrators that look for a dedicated live probe."""
    return success({"status": "ok"})


@router.get("/health/ready")
async def readiness() -> SuccessResponse:
    """Readiness probe: a database session can be opened and queried."""
    with SessionLocal() as session:
        session.execute(text("SELECT 1"))
    return success({"status": "ready"})


@router.get("/v1/health/heartbeat")
async def heartbeat() -> SuccessResponse:
    """Client heartbeat entrypoint; mirrors /health."""
    return success({"status": "ok"})
