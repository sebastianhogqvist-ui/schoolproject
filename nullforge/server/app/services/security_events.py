"""Anti-tampering security event lifecycle.

This service is the single entry point for recording a client-originated
security event.  It generates the event id, delegates persistence to the
repository, consults the :mod:`~app.services.enforcement` engine for an
appropriate graduated action, and commits everything in one transaction.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.logging_config import get_logger
from app.models import SECURITY_LEVEL_MEDIUM, SecurityEvent, utcnow
from app.repositories import licenses as license_repo
from app.repositories import security_events as security_event_repo
from app.services import audit_service, enforcement

logger = get_logger("security_events")

TARGET_LICENSE = "LICENSE"


@dataclass(frozen=True, slots=True)
class EventRecordResult:
    """What recording one security event produced."""

    event_id: str
    level: int
    category: str
    rule: str
    action_taken: str
    restriction_expires_at: datetime | None = None
    license_status: str | None = None


@dataclass(frozen=True, slots=True)
class EnforcementStatus:
    """The current anti-tampering posture for a single license."""

    level: int
    event_count: int
    active_count: int
    status: str
    restriction_expires_at: datetime | None = None
    license_status: str | None = None
    last_event_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-serialisable view."""
        return {
            "level": self.level,
            "event_count": self.event_count,
            "active_count": self.active_count,
            "status": self.status,
            "restriction_expires_at": self.restriction_expires_at.isoformat()
            if self.restriction_expires_at
            else None,
            "license_status": self.license_status,
            "last_event_at": self.last_event_at.isoformat() if self.last_event_at else None,
        }


def _now() -> datetime:
    """Return the current UTC timestamp."""
    return utcnow()


def record_event(
    session: Session,
    *,
    settings: Settings,
    license_id: int | None = None,
    session_id: str | None = None,
    level: int,
    category: str,
    rule: str,
    reason: str,
    ip: str,
    user_agent: str,
    evidence: str | None = None,
    now: datetime | None = None,
) -> EventRecordResult:
    """Record a security event and apply enforcement policy in one transaction.

    The enforcement engine decides whether the cumulative event count warrants
    a graduated action (warn / restrict / ban) and mutates the license row
    accordingly before commit.
    """
    moment = now or _now()
    event_id = str(uuid.uuid4())

    if not settings.ANTI_TAMPER_ENABLED:
        security_event_repo.record_event(
            session,
            event_id=event_id,
            license_id=license_id,
            session_id=session_id,
            level=level,
            category=category,
            rule=rule,
            reason=reason,
            ip=ip,
            user_agent=user_agent,
            evidence=evidence,
            action_taken="NONE",
        )
        session.flush()
        audit_service.record_and_commit(
            session,
            actor_type=audit_service.ACTOR_SYSTEM,
            action="SYSTEM_SECURITY_EVENT",
            target_type=TARGET_LICENSE,
            success=True,
            ip=ip,
            user_agent=user_agent,
            actor_id=str(license_id) if license_id else None,
            target_id=str(license_id) if license_id else None,
            metadata={
                "event_id": event_id[:8],
                "level": level,
                "category": category,
                "rule": rule,
                "action": "NONE",
            },
        )
        return EventRecordResult(
            event_id=event_id,
            level=level,
            category=category,
            rule=rule,
            action_taken="NONE",
        )

    license_row = (
        license_repo.get_by_id(session, license_id) if license_id else None
    )

    decision = enforcement.evaluate_and_enforce(
        session,
        settings=settings,
        license_id=license_id,
        license_row=license_row,
        level=level,
        category=category,
        rule=rule,
        ip=ip,
        user_agent=user_agent,
        now=moment,
    )

    security_event_repo.record_event(
        session,
        event_id=event_id,
        license_id=license_id,
        session_id=session_id,
        level=level,
        category=category,
        rule=rule,
        reason=reason,
        ip=ip,
        user_agent=user_agent,
        evidence=evidence,
        action_taken=decision.action.value,
    )
    session.flush()

    audit_service.record_and_commit(
        session,
        actor_type=audit_service.ACTOR_SYSTEM,
        action="SYSTEM_SECURITY_EVENT",
        target_type=TARGET_LICENSE,
        success=True,
        ip=ip,
        user_agent=user_agent,
        actor_id=str(license_id) if license_id else None,
        target_id=str(license_id) if license_id else None,
        metadata={
            "event_id": event_id[:8],
            "level": level,
            "category": category,
            "rule": rule,
            "action": decision.action.value,
        },
    )

    logger.info(
        "security event recorded",
        extra={
            "app_event_id": event_id[:8],
            "app_level": level,
            "app_category": category,
            "app_rule": rule,
            "app_action": decision.action.value,
        },
    )

    return EventRecordResult(
        event_id=event_id,
        level=level,
        category=category,
        rule=rule,
        action_taken=decision.action.value,
        restriction_expires_at=decision.restriction_expires_at,
        license_status=decision.license_status,
    )


def get_enforcement_status(
    session: Session,
    settings: Settings,
    *,
    license_id: int,
    now: datetime | None = None,
) -> EnforcementStatus:
    """Return the current enforcement posture for ``license_id``."""
    moment = now or _now()
    retention_window = timedelta(days=settings.ANTI_TAMPER_RETENTION_DAYS)

    event_count = security_event_repo.count_recent(
        session, license_id, min_level=0, window=retention_window
    )
    active_count = security_event_repo.count_unresolved_recent(
        session, license_id, min_level=SECURITY_LEVEL_MEDIUM, window=retention_window
    )

    level = enforcement.compute_level(settings, active_count)
    status = enforcement.enforcement_status_label(level)
    restriction_expires_at = enforcement.get_restriction_expiry(
        session, license_id, now=moment
    )

    license_row = license_repo.get_by_id(session, license_id)
    license_status = license_row.status if license_row is not None else None

    last_row = session.scalar(
        select(SecurityEvent.created_at)
        .where(SecurityEvent.license_id == license_id)
        .order_by(SecurityEvent.id.desc())
        .limit(1)
    )

    return EnforcementStatus(
        level=level,
        event_count=event_count,
        active_count=active_count,
        status=status,
        restriction_expires_at=restriction_expires_at,
        license_status=license_status,
        last_event_at=last_row,
    )


def list_events(
    session: Session,
    *,
    license_id: int | None = None,
    session_id: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[SecurityEvent], int]:
    """Page security events by license or session.

    At least one of ``license_id`` or ``session_id`` must be provided; when
    neither is supplied an empty result is returned.
    """
    if license_id is not None:
        return security_event_repo.list_for_license(
            session, license_id, page=page, page_size=page_size
        )
    if session_id is not None:
        return security_event_repo.list_for_session(
            session, session_id, page=page, page_size=page_size
        )
    return [], 0


__all__ = [
    "EnforcementStatus",
    "EventRecordResult",
    "get_enforcement_status",
    "list_events",
    "record_event",
]
