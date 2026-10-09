"""Data access for the audit trail."""

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AuditLog, utcnow

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200
MAX_SEARCH_LENGTH = 64


def record(
    session: Session,
    *,
    actor_type: str,
    action: str,
    target_type: str,
    success: bool,
    ip: str,
    user_agent: str,
    actor_id: str | None = None,
    target_id: str | None = None,
    metadata_json: str | None = None,
    created_at: datetime | None = None,
) -> AuditLog:
    """Append one audit row. The caller commits."""
    row = AuditLog(
        actor_type=actor_type,
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        success=success,
        ip=ip,
        user_agent=user_agent,
        metadata_json=metadata_json,
        created_at=created_at or utcnow(),
    )
    session.add(row)
    return row


def list_audit(
    session: Session,
    *,
    actor_type: str | None = None,
    action: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    success: bool | None = None,
    query: str | None = None,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> tuple[list[AuditLog], int]:
    """Return one page of audit rows, newest first, plus the total match count."""
    if page < 1:
        raise ValueError("page must be at least one")
    if not 1 <= page_size <= MAX_PAGE_SIZE:
        raise ValueError(f"page_size must be between 1 and {MAX_PAGE_SIZE}")

    conditions = []
    if actor_type is not None:
        conditions.append(AuditLog.actor_type == actor_type)
    if action is not None:
        conditions.append(AuditLog.action == action)
    if target_type is not None:
        conditions.append(AuditLog.target_type == target_type)
    if target_id is not None:
        conditions.append(AuditLog.target_id == str(target_id))
    if success is not None:
        conditions.append(AuditLog.success == success)

    term = (query or "").strip()
    if term:
        term = term[:MAX_SEARCH_LENGTH]
        conditions.append(AuditLog.action.ilike(f"%{term}%"))

    count_stmt = select(func.count()).select_from(AuditLog)
    list_stmt = select(AuditLog)
    for condition in conditions:
        count_stmt = count_stmt.where(condition)
        list_stmt = list_stmt.where(condition)

    total = int(session.scalar(count_stmt) or 0)
    rows = list(
        session.scalars(
            list_stmt.order_by(AuditLog.id.desc()).offset((page - 1) * page_size).limit(page_size)
        )
    )
    return rows, total
