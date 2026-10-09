"""SQLAlchemy 2.0 ORM models.

Storage rules enforced by the schema itself:

* ``licenses.key_hash`` holds only the hex HMAC-SHA256 of a canonical key, so
  the table can never leak a usable license.
* ``hwid_hash`` columns hold a second, server-side HMAC of the client value, so
  a stolen row is not replayable against a client.
* ``admins.password_hash`` holds an argon2id hash.
* ``audit_logs.metadata_json`` is for non-sensitive context only; tokens,
  passwords, peppers and raw HWIDs must never be written there.
"""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from app.db import Base

HASH_LENGTH = 64
KEY_HASH_LENGTH = 64
PASSWORD_HASH_LENGTH = 255
IP_LENGTH = 45
USER_AGENT_LENGTH = 256
NOTE_LENGTH = 255
SHORT_CODE_LENGTH = 32
CODE_LENGTH = 64
USERNAME_LENGTH = 64

ACTIVATION_TYPES = ("ACTIVATE", "AUTHENTICATE", "REAUTHENTICATE")
ACTOR_TYPES = ("ADMIN", "CLIENT", "SYSTEM")
DEFAULT_LICENSE_STATUS = "UNACTIVATED"

# Security event severity levels (0-3, graduated)
SECURITY_LEVEL_INFO = 0
SECURITY_LEVEL_LOW = 1
SECURITY_LEVEL_MEDIUM = 2
SECURITY_LEVEL_CRITICAL = 3
SECURITY_LEVELS = (
    SECURITY_LEVEL_INFO, SECURITY_LEVEL_LOW, SECURITY_LEVEL_MEDIUM, SECURITY_LEVEL_CRITICAL
)

# Security event lifecycle states
EVENT_STATUS_CONFIRMED = "CONFIRMED"
EVENT_STATUS_DISMISSED = "DISMISSED"
EVENT_STATUS_FALSE_POSITIVE = "FALSE_POSITIVE"
EVENT_STATUSES = (EVENT_STATUS_CONFIRMED, EVENT_STATUS_DISMISSED, EVENT_STATUS_FALSE_POSITIVE)

# Actions the enforcement engine can take when recording an event
ACTION_WARN = "WARN"
ACTION_RESTRICT = "RESTRICT"
ACTION_BAN = "BAN"
ACTION_NONE = "NONE"
ACTIONS = (ACTION_NONE, ACTION_WARN, ACTION_RESTRICT, ACTION_BAN)


class UtcDateTime(TypeDecorator[datetime]):
    """A ``DateTime(timezone=True)`` that always round-trips as aware UTC.

    SQLite has no native timestamptz and hands back naive values, which would
    make ``row.expires_at <= datetime.now(UTC)`` raise TypeError. Normalizing
    on the way in and out keeps every timestamp comparable.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        """Normalize an outgoing timestamp to aware UTC."""
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        """Re-attach UTC to a timestamp that lost its offset in storage."""
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def utcnow() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


class License(Base):
    """A license key. Only the HMAC of the key is stored, never the key itself."""

    __tablename__ = "licenses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key_hash: Mapped[str] = mapped_column(
        String(KEY_HASH_LENGTH), unique=True, index=True, nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(SHORT_CODE_LENGTH), index=True, nullable=False, default=DEFAULT_LICENSE_STATUS
    )
    hwid_hash: Mapped[str | None] = mapped_column(String(HASH_LENGTH), nullable=True)
    note: Mapped[str | None] = mapped_column(String(NOTE_LENGTH), nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, default=utcnow, server_default=func.now()
    )
    activated_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True, index=True)
    last_validated_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    activation_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    suspended_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    restricted_until: Mapped[datetime | None] = mapped_column(
        UtcDateTime, nullable=True, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime,
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        server_default=func.now(),
    )

    activations: Mapped[list["LicenseActivation"]] = relationship(
        back_populates="license", cascade="all, delete-orphan", passive_deletes=True
    )
    sessions: Mapped[list["SessionRecord"]] = relationship(
        back_populates="license", cascade="all, delete-orphan", passive_deletes=True
    )

    def __repr__(self) -> str:
        """Render without leaking the key hash."""
        return f"<License id={self.id} status={self.status!r} activations={self.activation_count}>"


class LicenseActivation(Base):
    """Append-only audit trail of every activate/authenticate attempt."""

    __tablename__ = "license_activations"
    __table_args__ = (
        Index("ix_license_activations_license_id_created_at", "license_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    license_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("licenses.id", ondelete="CASCADE"), nullable=False, index=True
    )
    hwid_hash: Mapped[str] = mapped_column(String(HASH_LENGTH), nullable=False)
    activation_type: Mapped[str] = mapped_column(String(SHORT_CODE_LENGTH), nullable=False)
    ip: Mapped[str] = mapped_column(String(IP_LENGTH), nullable=False)
    user_agent: Mapped[str] = mapped_column(String(USER_AGENT_LENGTH), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, default=utcnow, server_default=func.now()
    )

    license: Mapped[License] = relationship(back_populates="activations")

    def __repr__(self) -> str:
        """Render without leaking the HWID hash."""
        return (
            f"<LicenseActivation id={self.id} license_id={self.license_id} "
            f"type={self.activation_type!r}>"
        )


class SessionRecord(Base):
    """A server-side session backing a client JWT, so it can be revoked."""

    __tablename__ = "sessions"
    __table_args__ = (Index("ix_sessions_license_id_revoked_at", "license_id", "revoked_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    jti: Mapped[str] = mapped_column(String(HASH_LENGTH), unique=True, index=True, nullable=False)
    license_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("licenses.id", ondelete="CASCADE"), nullable=False, index=True
    )
    hwid_hash: Mapped[str] = mapped_column(String(HASH_LENGTH), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, default=utcnow, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, default=utcnow, server_default=func.now()
    )
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)

    license: Mapped[License] = relationship(back_populates="sessions")

    def __repr__(self) -> str:
        """Render without leaking the session id or HWID hash."""
        revoked = self.revoked_at is not None
        return f"<SessionRecord id={self.id} license_id={self.license_id} revoked={revoked}>"


class Admin(Base):
    """An administrator account. ``password_hash`` is argon2id, never plaintext."""

    __tablename__ = "admins"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(
        String(USERNAME_LENGTH), unique=True, index=True, nullable=False
    )
    password_hash: Mapped[str] = mapped_column(String(PASSWORD_HASH_LENGTH), nullable=False)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="1"
    )
    is_superuser: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="0"
    )
    created_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, default=utcnow, server_default=func.now()
    )
    last_login_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)

    def __repr__(self) -> str:
        """Render without leaking the password hash."""
        return f"<Admin id={self.id} username={self.username!r} active={self.is_active}>"


class AuditLog(Base):
    """Structured audit trail for admin, client and system actions.

    ``metadata_json`` must hold non-sensitive context only. Never store tokens,
    passwords, peppers, plaintext keys or raw HWIDs here.
    """

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor_type: Mapped[str] = mapped_column(String(SHORT_CODE_LENGTH), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(CODE_LENGTH), nullable=True)
    action: Mapped[str] = mapped_column(String(CODE_LENGTH), index=True, nullable=False)
    target_type: Mapped[str] = mapped_column(String(SHORT_CODE_LENGTH), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(CODE_LENGTH), index=True, nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, index=True, nullable=False)
    ip: Mapped[str] = mapped_column(String(IP_LENGTH), nullable=False)
    user_agent: Mapped[str] = mapped_column(String(USER_AGENT_LENGTH), nullable=False)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, default=utcnow, server_default=func.now(), index=True
    )

    def __repr__(self) -> str:
        """Render without leaking metadata contents."""
        return f"<AuditLog id={self.id} action={self.action!r} success={self.success}>"


class SecurityEvent(Base):
    """Structured security event log for anti-tampering detection.

    Each row records one client-side integrity violation (or server-side
    suspicion).  The enforcement engine consults counts of recent events to
    decide whether a license moves up a graduated enforcement level.
    """

    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_security_events_license_id_created_at", "license_id", "created_at"),
        Index("ix_security_events_session_id", "session_id"),
        Index("ix_security_events_level_created_at", "level", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(36), unique=True, index=True, nullable=False)
    license_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("licenses.id", ondelete="SET NULL"), nullable=True, index=True
    )
    session_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    level: Mapped[int] = mapped_column(Integer, nullable=False)  # 0-3
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    rule: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    ip: Mapped[str] = mapped_column(String(IP_LENGTH), nullable=False)
    user_agent: Mapped[str] = mapped_column(String(USER_AGENT_LENGTH), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=EVENT_STATUS_CONFIRMED)
    action_taken: Mapped[str | None] = mapped_column(String(32), nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, default=utcnow, server_default=func.now()
    )
    resolved_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    resolved_by: Mapped[str | None] = mapped_column(String(USERNAME_LENGTH), nullable=True)

    license_ref: Mapped["License"] = relationship(
        "License", foreign_keys=[license_id], lazy="selectin"
    )

    def __repr__(self) -> str:
        """Render a short, non-leaking identifier."""
        return (
            f"<SecurityEvent id={self.id} license_id={self.license_id} "
            f"level={self.level} category={self.category!r} rule={self.rule!r}>"
        )


__all__: list[str] = [
    "ACTIONS",
    "ACTION_BAN",
    "ACTION_NONE",
    "ACTION_RESTRICT",
    "ACTION_WARN",
    "ACTIVATION_TYPES",
    "ACTOR_TYPES",
    "EVENT_STATUSES",
    "EVENT_STATUS_CONFIRMED",
    "EVENT_STATUS_DISMISSED",
    "EVENT_STATUS_FALSE_POSITIVE",
    "SECURITY_LEVELS",
    "SECURITY_LEVEL_CRITICAL",
    "SECURITY_LEVEL_INFO",
    "SECURITY_LEVEL_LOW",
    "SECURITY_LEVEL_MEDIUM",
    "Admin",
    "AuditLog",
    "Base",
    "License",
    "LicenseActivation",
    "SecurityEvent",
    "SessionRecord",
    "UtcDateTime",
    "utcnow",
]
