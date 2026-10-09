"""Data access for server-side sessions.

A JWT alone cannot be withdrawn, so every client token names a row here. The
row is the revocation point: logout, HWID reset, suspend and revoke all mark it
revoked rather than waiting for the token to expire.
"""

from datetime import datetime
from typing import Any, cast

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.models import SessionRecord, utcnow

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200


def create_session(
    session: Session,
    *,
    jti: str,
    license_id: int,
    hwid_hash: str,
    expires_at: datetime,
) -> SessionRecord:
    """Stage a new session row bound to a license and device."""
    row = SessionRecord(
        jti=jti, license_id=license_id, hwid_hash=hwid_hash, expires_at=expires_at
    )
    session.add(row)
    return row


def get_by_jti(session: Session, jti: str) -> SessionRecord | None:
    """Fetch a session by its token id."""
    return session.scalar(select(SessionRecord).where(SessionRecord.jti == jti))


def get_active_by_jti(session: Session, jti: str) -> SessionRecord | None:
    """Fetch a session only if it is neither revoked nor past its expiry."""
    now = utcnow()
    return session.scalar(
        select(SessionRecord).where(
            SessionRecord.jti == jti,
            SessionRecord.revoked_at.is_(None),
            SessionRecord.expires_at > now,
        )
    )


def touch(session: Session, row: SessionRecord, *, now: datetime | None = None) -> None:
    """Record activity against a session so idle windows are auditable."""
    row.last_seen_at = now or utcnow()


def revoke(session: Session, row: SessionRecord, *, now: datetime | None = None) -> None:
    """Revoke a single session."""
    row.revoked_at = now or utcnow()


def revoke_all_for_license(
    session: Session, license_id: int, *, now: datetime | None = None
) -> int:
    """Revoke every live session for a license; returns how many were revoked.

    Uses a single UPDATE so the operation is atomic and does not depend on how
    many rows happen to match.
    """
    moment = now or utcnow()
    result = session.execute(
        update(SessionRecord)
        .where(SessionRecord.license_id == license_id, SessionRecord.revoked_at.is_(None))
        .values(revoked_at=moment)
        .execution_options(synchronize_session="fetch")
    )
    return int(cast(Any, result).rowcount or 0)


def count_active(session: Session, license_id: int) -> int:
    """Count the license's live sessions."""
    now = utcnow()
    total = session.scalar(
        select(func.count())
        .select_from(SessionRecord)
        .where(
            SessionRecord.license_id == license_id,
            SessionRecord.revoked_at.is_(None),
            SessionRecord.expires_at > now,
        )
    )
    return int(total or 0)
