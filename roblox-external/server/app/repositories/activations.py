"""Data access for the append-only activation trail."""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import License, LicenseActivation

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200


def record_activation(
    session: Session,
    *,
    license_id: int,
    hwid_hash: str,
    activation_type: str,
    ip: str,
    user_agent: str,
) -> LicenseActivation:
    """Append one activation/authentication attempt to the trail."""
    row = LicenseActivation(
        license_id=license_id,
        hwid_hash=hwid_hash,
        activation_type=activation_type,
        ip=ip,
        user_agent=user_agent,
    )
    session.add(row)
    return row


def increment_count(session: Session, license_row: License) -> int:
    """Increment and return the license's activation counter."""
    license_row.activation_count = int(license_row.activation_count or 0) + 1
    return license_row.activation_count


def list_for_license(
    session: Session,
    license_id: int,
    *,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> tuple[list[LicenseActivation], int]:
    """Return one page of a license's activation trail, newest first."""
    if page < 1:
        raise ValueError("page must be at least one")
    if not 1 <= page_size <= MAX_PAGE_SIZE:
        raise ValueError(f"page_size must be between 1 and {MAX_PAGE_SIZE}")

    total = int(
        session.scalar(
            select(func.count())
            .select_from(LicenseActivation)
            .where(LicenseActivation.license_id == license_id)
        )
        or 0
    )
    rows = list(
        session.scalars(
            select(LicenseActivation)
            .where(LicenseActivation.license_id == license_id)
            .order_by(LicenseActivation.id.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    )
    return rows, total
