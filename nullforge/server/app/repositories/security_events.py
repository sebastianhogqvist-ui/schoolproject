"""Data access for :class:`~app.models.SecurityEvent`.

Every statement is built with the SQLAlchemy expression language so values are
always bound as parameters.  Security events are append-only: rows are never
updated in place; resolution is a new field on the same row written by the
enforcement engine.
"""

from datetime import datetime, timedelta
from typing import Any, cast

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.models import SecurityEvent, utcnow

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200


def record_event(
    session: Session,
    *,
    event_id: str,
    license_id: int | None,
    session_id: str | None,
    level: int,
    category: str,
    rule: str,
    reason: str,
    ip: str,
    user_agent: str,
    action_taken: str | None = None,
    evidence: str | None = None,
    status: str | None = None,
) -> SecurityEvent:
    """Stage one security-event row. The caller commits."""
    row = SecurityEvent(
        event_id=event_id,
        license_id=license_id,
        session_id=session_id,
        level=level,
        category=category,
        rule=rule,
        reason=reason,
        ip=ip,
        user_agent=user_agent,
        action_taken=action_taken,
        evidence=evidence,
        status=status or "CONFIRMED",
    )
    session.add(row)
    return row


def get_by_event_id(session: Session, event_id: str) -> SecurityEvent | None:
    """Fetch a security event by its UUID, or ``None``."""
    return session.scalar(select(SecurityEvent).where(SecurityEvent.event_id == event_id))


def list_for_license(
    session: Session,
    license_id: int,
    *,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    since: datetime | None = None,
) -> tuple[list[SecurityEvent], int]:
    """Return one page of a license's events, newest first.

    ``since`` narrows the query to events created at or after the given
    timestamp, which is how the enforcement engine counts recent violations.
    """
    if page < 1:
        raise ValueError("page must be at least one")
    if not 1 <= page_size <= MAX_PAGE_SIZE:
        raise ValueError(f"page_size must be between 1 and {MAX_PAGE_SIZE}")

    stmt = select(SecurityEvent).where(SecurityEvent.license_id == license_id)
    if since is not None:
        stmt = stmt.where(SecurityEvent.created_at >= since)

    total = int(session.scalar(stmt.with_only_columns(func.count()).order_by(None)) or 0)
    rows = list(
        session.scalars(
            stmt.order_by(SecurityEvent.id.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    )
    return rows, total


def list_for_session(
    session: Session,
    session_id: str,
    *,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> tuple[list[SecurityEvent], int]:
    """Return one page of a session's events, newest first."""
    if page < 1:
        raise ValueError("page must be at least one")
    if not 1 <= page_size <= MAX_PAGE_SIZE:
        raise ValueError(f"page_size must be between 1 and {MAX_PAGE_SIZE}")

    stmt = select(SecurityEvent).where(SecurityEvent.session_id == session_id)
    total = int(session.scalar(stmt.with_only_columns(func.count()).order_by(None)) or 0)
    rows = list(
        session.scalars(
            stmt.order_by(SecurityEvent.id.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    )
    return rows, total


def count_recent(
    session: Session,
    license_id: int,
    *,
    min_level: int = 0,
    window: timedelta | None = None,
) -> int:
    """Count a license's events at or above ``min_level`` within ``window``."""
    cutoff = utcnow() - (window or timedelta(days=30))
    total = session.scalar(
        select(func.count())
        .select_from(SecurityEvent)
        .where(
            SecurityEvent.license_id == license_id,
            SecurityEvent.level >= min_level,
            SecurityEvent.created_at >= cutoff,
        )
    )
    return int(total or 0)


def count_unresolved_recent(
    session: Session,
    license_id: int,
    *,
    min_level: int = 0,
    window: timedelta | None = None,
) -> int:
    """Count unresolved events at or above ``min_level`` within ``window``.

    An event is unresolved unless its status is ``DISMISSED`` or
    ``FALSE_POSITIVE``.
    """
    cutoff = utcnow() - (window or timedelta(days=30))
    total = session.scalar(
        select(func.count())
        .select_from(SecurityEvent)
        .where(
            SecurityEvent.license_id == license_id,
            SecurityEvent.level >= min_level,
            SecurityEvent.created_at >= cutoff,
            SecurityEvent.status.notin_(("DISMISSED", "FALSE_POSITIVE")),
        )
    )
    return int(total or 0)


def resolve_event(
    session: Session,
    row: SecurityEvent,
    *,
    status: str,
    resolved_by: str | None = None,
    now: datetime | None = None,
) -> SecurityEvent:
    """Mark an event as resolved, stamping the timestamp and resolver."""
    moment = now or utcnow()
    row.status = status
    row.resolved_at = moment
    row.resolved_by = resolved_by
    return row


def delete_older_than(session: Session, cutoff: datetime) -> int:
    """Permanently remove events older than ``cutoff``. Returns the count deleted."""
    result = session.execute(
        delete(SecurityEvent).where(SecurityEvent.created_at < cutoff)
    )
    return int(cast(Any, result).rowcount or 0)


def purge_expired_retention(session: Session, retention_days: int) -> int:
    """Delete every event older than the configured retention window."""
    cutoff = utcnow() - timedelta(days=retention_days)
    return delete_older_than(session, cutoff)
