"""Data access for :class:`~app.models.License`.

Every statement is built with the SQLAlchemy expression language, so values are
always bound as parameters and can never be concatenated into SQL. There is no
plaintext key column to read back: lookups go through ``key_hash``.
"""

from datetime import datetime

from sqlalchemy import ColumnElement, Select, func, or_, select
from sqlalchemy.orm import Session

from app.models import License, utcnow
from app.states import LicenseStatus

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200
MAX_QUERY_LENGTH = 64


def get_by_id(session: Session, license_id: int) -> License | None:
    """Fetch a license by primary key."""
    return session.get(License, license_id)


def get_by_key_hash(session: Session, key_hash: str) -> License | None:
    """Fetch a license by its HMAC-SHA256 key hash (an exact match, never a prefix)."""
    return session.scalar(select(License).where(License.key_hash == key_hash))


def add_license(
    session: Session,
    *,
    key_hash: str,
    expires_at: datetime | None = None,
    note: str | None = None,
    metadata_json: str | None = None,
) -> License:
    """Stage a new license row.

    The caller commits and retries with a fresh key on :class:`IntegrityError`,
    which is the only way a duplicate key hash can surface given the UNIQUE
    index.
    """
    license_row = License(
        key_hash=key_hash,
        status=LicenseStatus.UNACTIVATED.value,
        expires_at=expires_at,
        note=note,
        metadata_json=metadata_json,
    )
    session.add(license_row)
    return license_row


def _search_clause(query: str) -> ColumnElement[bool] | None:
    """Build a parameterized search over the fields an operator can see.

    Only the HMAC and the note are searchable: the plaintext key does not exist
    in this table, so a key cannot be "found" by typing it.
    """
    term = query.strip()
    if not term:
        return None
    if term.isdigit():
        return License.id == int(term)
    return or_(License.note.ilike(f"%{term}%"), License.key_hash.ilike(f"{term}%"))


def list_licenses(
    session: Session,
    *,
    status: LicenseStatus | None = None,
    query: str | None = None,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> tuple[list[License], int]:
    """Return one page of licenses plus the total match count.

    Ordering is by descending id so pagination is stable while rows are added.
    """
    if page < 1:
        raise ValueError("page must be at least one")
    if not 1 <= page_size <= MAX_PAGE_SIZE:
        raise ValueError(f"page_size must be between 1 and {MAX_PAGE_SIZE}")

    filters = []
    if status is not None:
        filters.append(License.status == LicenseStatus(status).value)

    clause = _search_clause(query or "")
    if clause is not None:
        filters.append(clause)

    count_stmt = select(func.count()).select_from(License)
    list_stmt: Select[tuple[License]] = select(License)
    for condition in filters:
        count_stmt = count_stmt.where(condition)
        list_stmt = list_stmt.where(condition)

    total = int(session.scalar(count_stmt) or 0)
    rows: list[License] = list(
        session.scalars(
            list_stmt.order_by(License.id.desc()).offset((page - 1) * page_size).limit(page_size)
        )
    )
    return rows, total


def set_status(
    license_row: License,
    target: LicenseStatus,
    *,
    now: datetime | None = None,
) -> License:
    """Move a license to ``target``, stamping the matching timestamp column.

    The caller is responsible for :func:`app.states.assert_transition` and for
    committing.
    """
    moment = now or utcnow()
    resolved = LicenseStatus(target)
    license_row.status = resolved.value
    license_row.updated_at = moment
    if resolved is LicenseStatus.SUSPENDED:
        license_row.suspended_at = moment
    elif resolved is LicenseStatus.REVOKED:
        license_row.revoked_at = moment
        license_row.suspended_at = None
    return license_row


def clear_hwid(license_row: License, *, now: datetime | None = None) -> None:
    """Unbind the license from its device so the next activation rebinds."""
    moment = now or utcnow()
    license_row.hwid_hash = None
    license_row.updated_at = moment


def mark_validated(license_row: License, *, now: datetime | None = None) -> None:
    """Record that the license passed a validation check."""
    license_row.last_validated_at = now or utcnow()


def delete_license(session: Session, license_row: License) -> None:
    """Delete a license; activations and sessions cascade at the database level."""
    session.delete(license_row)
