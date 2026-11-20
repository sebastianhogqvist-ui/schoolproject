"""Data access for administrator accounts."""

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Admin, utcnow


def get_by_username(session: Session, username: str) -> Admin | None:
    """Fetch an admin by exact username."""
    return session.scalar(select(Admin).where(Admin.username == username))


def get_by_id(session: Session, admin_id: int) -> Admin | None:
    """Fetch an admin by primary key."""
    return session.get(Admin, admin_id)


def add_admin(
    session: Session,
    *,
    username: str,
    password_hash: str,
    is_superuser: bool = False,
) -> Admin:
    """Stage a new admin account. The caller commits."""
    row = Admin(
        username=username,
        password_hash=password_hash,
        is_active=True,
        is_superuser=is_superuser,
    )
    session.add(row)
    return row


def count_admins(session: Session) -> int:
    """Count admin accounts, used to decide whether bootstrap is still needed."""
    return int(session.scalar(select(func.count()).select_from(Admin)) or 0)


def record_login(session: Session, admin: Admin, *, now: datetime | None = None) -> None:
    """Stamp the last successful login."""
    admin.last_login_at = now or utcnow()
